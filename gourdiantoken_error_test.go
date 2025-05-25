// File: gourdiantoken_error_test.go

package gourdiantoken

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	testSymmetricKey = "test-secret-32-bytes-long-1234567890"
)

func testRedisOptions() *redis.Options {
	return &redis.Options{
		Addr:     "127.0.0.1:6379",
		Password: "GourdianRedisSecret",
		DB:       0,
	}
}

func TestRevocationErrors(t *testing.T) {
	// Setup Redis if available
	client := redis.NewClient(testRedisOptions())
	_, err := client.Ping(context.Background()).Result()
	if err != nil {
		t.Skip("Redis not available, skipping revocation tests")
	}

	tests := []struct {
		name        string
		setupFn     func(*JWTMaker) string
		revokeFn    func(*JWTMaker, string) error
		expectedErr string
	}{
		{
			name: "Revoke token without exp claim",
			setupFn: func(m *JWTMaker) string {
				token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
					"jti": uuid.New().String(),
					"sub": uuid.New().String(),
					"usr": "user",
					"sid": uuid.New().String(),
					"iat": time.Now().Unix(),
					"typ": AccessToken,
					"rls": []string{"admin"},
				})
				tokenString, _ := token.SignedString([]byte(m.config.SymmetricKey))
				return tokenString
			},
			revokeFn:    func(m *JWTMaker, s string) error { return m.RevokeAccessToken(context.Background(), s) },
			expectedErr: "token missing exp claim",
		},
		{
			name: "Revoke invalid token string",
			setupFn: func(m *JWTMaker) string {
				return "invalid.token.string"
			},
			revokeFn:    func(m *JWTMaker, s string) error { return m.RevokeAccessToken(context.Background(), s) },
			expectedErr: "invalid token",
		},
		{
			name: "Revoke when revocation disabled",
			setupFn: func(m *JWTMaker) string {
				m.config.RevocationEnabled = false
				token, _ := m.CreateAccessToken(context.Background(), uuid.New(), "user", []string{"admin"}, uuid.New())
				return token.Token
			},
			revokeFn:    func(m *JWTMaker, s string) error { return m.RevokeAccessToken(context.Background(), s) },
			expectedErr: "access token revocation is not enabled",
		},
	}

	maker, err := DefaultGourdianTokenMaker(context.Background(), testSymmetricKey, testRedisOptions())
	require.NoError(t, err)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokenString := tt.setupFn(maker.(*JWTMaker))
			err := tt.revokeFn(maker.(*JWTMaker), tokenString)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.expectedErr)
		})
	}
}

func TestRotationErrors(t *testing.T) {
	// Setup Redis if available
	client := redis.NewClient(testRedisOptions())
	_, err := client.Ping(context.Background()).Result()
	if err != nil {
		t.Skip("Redis not available, skipping rotation tests")
	}

	tests := []struct {
		name        string
		setupFn     func(*JWTMaker) string
		expectedErr string
	}{
		{
			name: "Rotation with invalid token",
			setupFn: func(m *JWTMaker) string {
				return "invalid.token.string"
			},
			expectedErr: "invalid token",
		},
		{
			name: "Rotation reuse too soon",
			setupFn: func(m *JWTMaker) string {
				token, _ := m.CreateRefreshToken(context.Background(), uuid.New(), "user", uuid.New())
				_, _ = m.RotateRefreshToken(context.Background(), token.Token) // First rotation succeeds
				return token.Token                                             // Try to rotate same token again
			},
			expectedErr: "token reused too soon",
		},
		{
			name: "Rotation when disabled",
			setupFn: func(m *JWTMaker) string {
				m.config.RotationEnabled = false
				token, _ := m.CreateRefreshToken(context.Background(), uuid.New(), "user", uuid.New())
				return token.Token
			},
			expectedErr: "token rotation not enabled",
		},
	}

	maker, err := DefaultGourdianTokenMaker(context.Background(), testSymmetricKey, testRedisOptions())
	require.NoError(t, err)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokenString := tt.setupFn(maker.(*JWTMaker))
			_, err := maker.RotateRefreshToken(context.Background(), tokenString)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.expectedErr)
		})
	}
}

func TestRedisConnectionErrors(t *testing.T) {
	tests := []struct {
		name        string
		config      GourdianTokenConfig
		redisOpts   *redis.Options
		expectedErr string
	}{
		{
			name: "Redis required but not provided",
			config: GourdianTokenConfig{
				Algorithm:             "HS256",
				SigningMethod:         Symmetric,
				SymmetricKey:          "test-secret-32-bytes-long-1234567890",
				RotationEnabled:       true,
				AccessExpiryDuration:  30 * time.Minute,
				RefreshExpiryDuration: 24 * time.Hour,
			},
			redisOpts:   nil,
			expectedErr: "redis options required",
		},
		{
			name: "Invalid Redis connection",
			config: GourdianTokenConfig{
				Algorithm:             "HS256",
				SigningMethod:         Symmetric,
				SymmetricKey:          "test-secret-32-bytes-long-1234567890",
				RotationEnabled:       true,
				AccessExpiryDuration:  30 * time.Minute,
				RefreshExpiryDuration: 24 * time.Hour,
			},
			redisOpts:   &redis.Options{Addr: "invalid-redis-url:9999"},
			expectedErr: "redis connection failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewGourdianTokenMaker(context.Background(), tt.config, tt.redisOpts)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.expectedErr)
		})
	}
}

func TestTokenCreationErrors(t *testing.T) {
	maker, err := DefaultGourdianTokenMaker(context.Background(), testSymmetricKey, nil)
	require.NoError(t, err)

	t.Run("Create access token with empty user ID", func(t *testing.T) {
		_, err := maker.CreateAccessToken(context.Background(), uuid.Nil, "user", []string{"admin"}, uuid.New())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid user ID")
	})

	t.Run("Create access token with empty roles", func(t *testing.T) {
		_, err := maker.CreateAccessToken(context.Background(), uuid.New(), "user", []string{}, uuid.New())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "at least one role must be provided")
	})

	t.Run("Create access token with empty role string", func(t *testing.T) {
		_, err := maker.CreateAccessToken(context.Background(), uuid.New(), "user", []string{""}, uuid.New())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "roles cannot contain empty strings")
	})

	t.Run("Create refresh token with empty user ID", func(t *testing.T) {
		_, err := maker.CreateRefreshToken(context.Background(), uuid.Nil, "user", uuid.New())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid user ID")
	})

	t.Run("Create token with long username", func(t *testing.T) {
		longUsername := make([]byte, 1025)
		for i := range longUsername {
			longUsername[i] = 'a'
		}
		_, err := maker.CreateAccessToken(context.Background(), uuid.New(), string(longUsername), []string{"admin"}, uuid.New())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "username too long")
	})
}

func TestAlgorithmMismatchErrors(t *testing.T) {
	// Create token with HS256
	maker1, err := DefaultGourdianTokenMaker(context.Background(), testSymmetricKey, nil)
	require.NoError(t, err)

	token, err := maker1.CreateAccessToken(context.Background(), uuid.New(), "user", []string{"admin"}, uuid.New())
	require.NoError(t, err)

	// Try to verify with RS256
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	config2 := GourdianTokenConfig{
		Algorithm:             "RS256",
		SigningMethod:         Asymmetric,
		PrivateKeyPath:        "",
		PublicKeyPath:         "",
		AccessExpiryDuration:  30 * time.Minute,
		RefreshExpiryDuration: 24 * time.Hour,
	}
	maker2 := &JWTMaker{
		config:        config2,
		signingMethod: jwt.SigningMethodRS256,
		privateKey:    privateKey,
		publicKey:     &privateKey.PublicKey,
	}

	_, err = maker2.VerifyAccessToken(context.Background(), token.Token)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected signing method")
}
