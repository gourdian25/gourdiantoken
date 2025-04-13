// gourdiantoken_error_test.go
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
				m.config.AccessToken.RevocationEnabled = false
				token, _ := m.CreateAccessToken(context.Background(), uuid.New(), "user", []string{"admin"}, uuid.New())
				return token.Token
			},
			revokeFn:    func(m *JWTMaker, s string) error { return m.RevokeAccessToken(context.Background(), s) },
			expectedErr: "access token revocation is not enabled",
		},
	}

	config := DefaultGourdianTokenConfig("test-secret-32-bytes-long-1234567890")
	config.AccessToken.RevocationEnabled = true
	maker, err := NewGourdianTokenMaker(context.Background(), config, testRedisOptions())
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
				m.config.RefreshToken.RotationEnabled = false
				token, _ := m.CreateRefreshToken(context.Background(), uuid.New(), "user", uuid.New())
				return token.Token
			},
			expectedErr: "token rotation not enabled",
		},
	}

	config := DefaultGourdianTokenConfig("test-secret-32-bytes-long-1234567890")
	config.RefreshToken.RotationEnabled = true
	maker, err := NewGourdianTokenMaker(context.Background(), config, testRedisOptions())
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
				Algorithm:     "HS256",
				SigningMethod: Symmetric,
				SymmetricKey:  "test-secret-32-bytes-long-1234567890",
				RefreshToken: RefreshTokenConfig{
					RotationEnabled: true,
				},
			},
			redisOpts:   nil,
			expectedErr: "redis options required",
		},
		{
			name: "Invalid Redis connection",
			config: GourdianTokenConfig{
				Algorithm:     "HS256",
				SigningMethod: Symmetric,
				SymmetricKey:  "test-secret-32-bytes-long-1234567890",
				RefreshToken: RefreshTokenConfig{
					RotationEnabled: true,
				},
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
	config := DefaultGourdianTokenConfig("test-secret-32-bytes-long-1234567890")
	maker, err := NewGourdianTokenMaker(context.Background(), config, nil)
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
	config1 := DefaultGourdianTokenConfig("test-secret-32-bytes-long-1234567890")
	maker1, err := NewGourdianTokenMaker(context.Background(), config1, nil)
	require.NoError(t, err)

	token, err := maker1.CreateAccessToken(context.Background(), uuid.New(), "user", []string{"admin"}, uuid.New())
	require.NoError(t, err)

	// Try to verify with RS256
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	config2 := GourdianTokenConfig{
		Algorithm:     "RS256",
		SigningMethod: Asymmetric,
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

// func TestFilePermissionErrors(t *testing.T) {
// 	// Create test files with restrictive permissions
// 	privPath := "test_private_restricted.pem"
// 	pubPath := "test_public_restricted.pem"
// 	_ = os.WriteFile(privPath, []byte("test"), 0000) // No permissions
// 	_ = os.WriteFile(pubPath, []byte("test"), 0000)
// 	defer os.Remove(privPath)
// 	defer os.Remove(pubPath)

// 	config := GourdianTokenConfig{
// 		Algorithm:      "RS256",
// 		SigningMethod:  Asymmetric,
// 		PrivateKeyPath: privPath,
// 		PublicKeyPath:  pubPath,
// 	}

// 	_, err := NewGourdianTokenMaker(context.Background(), config, nil)
// 	require.Error(t, err)
// 	assert.Contains(t, err.Error(), "failed to stat file")
// }

// func TestKeyParsingErrors(t *testing.T) {
// 	// Setup test files
// 	privPath := "test_invalid_priv.pem"
// 	pubPath := "test_invalid_pub.pem"
// 	_ = os.WriteFile(privPath, []byte("invalid private pem"), 0644)
// 	_ = os.WriteFile(pubPath, []byte("invalid public pem"), 0644)
// 	defer os.Remove(privPath)
// 	defer os.Remove(pubPath)

// 	tests := []struct {
// 		name        string
// 		config      GourdianTokenConfig
// 		expectedErr string
// 	}{
// 		{
// 			name: "Invalid private key format",
// 			config: GourdianTokenConfig{
// 				Algorithm:      "RS256",
// 				SigningMethod:  Asymmetric,
// 				PrivateKeyPath: privPath,
// 				PublicKeyPath:  pubPath,
// 			},
// 			expectedErr: "failed to parse RSA private key",
// 		},
// 		{
// 			name: "Invalid public key format",
// 			config: GourdianTokenConfig{
// 				Algorithm:      "RS256",
// 				SigningMethod:  Asymmetric,
// 				PrivateKeyPath: "testdata/private.pem", // Valid private key
// 				PublicKeyPath:  pubPath,                // Invalid public key
// 			},
// 			expectedErr: "failed to parse RSA public key",
// 		},
// 		{
// 			name: "Key algorithm mismatch",
// 			config: GourdianTokenConfig{
// 				Algorithm:      "ES256",
// 				SigningMethod:  Asymmetric,
// 				PrivateKeyPath: "testdata/private.pem", // RSA key but ES256 algorithm
// 				PublicKeyPath:  "testdata/public.pem",
// 			},
// 			expectedErr: "failed to parse ECDSA private key",
// 		},
// 	}

// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			_, err := NewGourdianTokenMaker(context.Background(), tt.config, nil)
// 			require.Error(t, err)
// 			assert.Contains(t, err.Error(), tt.expectedErr)
// 		})
// 	}
// }
// func TestTokenValidationErrors(t *testing.T) {
// 	tests := []struct {
// 		name        string
// 		tokenModFn  func(*jwt.Token)
// 		expectedErr string
// 	}{
// 		{
// 			name: "Malformed token string",
// 			tokenModFn: func(t *jwt.Token) {
// 				// No modification needed - we'll pass invalid string directly
// 			},
// 			expectedErr: "token contains an invalid number of segments",
// 		},
// 		{
// 			name: "Missing required claim: jti",
// 			tokenModFn: func(t *jwt.Token) {
// 				delete(t.Claims.(jwt.MapClaims), "jti")
// 			},
// 			expectedErr: "missing required claim: jti",
// 		},
// 		{
// 			name: "Invalid UUID format in jti",
// 			tokenModFn: func(t *jwt.Token) {
// 				t.Claims.(jwt.MapClaims)["jti"] = "invalid-uuid"
// 			},
// 			expectedErr: "invalid token ID",
// 		},
// 		{
// 			name: "Token issued in future",
// 			tokenModFn: func(t *jwt.Token) {
// 				t.Claims.(jwt.MapClaims)["iat"] = time.Now().Add(time.Hour).Unix()
// 			},
// 			expectedErr: "token issued in the future",
// 		},
// 		{
// 			name: "Expired token",
// 			tokenModFn: func(t *jwt.Token) {
// 				t.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(-time.Hour).Unix()
// 			},
// 			expectedErr: "token has expired",
// 		},
// 		{
// 			name: "Wrong token type",
// 			tokenModFn: func(t *jwt.Token) {
// 				t.Claims.(jwt.MapClaims)["typ"] = "invalid-type"
// 			},
// 			expectedErr: "invalid token type",
// 		},
// 		{
// 			name: "Missing roles in access token",
// 			tokenModFn: func(t *jwt.Token) {
// 				delete(t.Claims.(jwt.MapClaims), "rls")
// 			},
// 			expectedErr: "missing roles claim",
// 		},
// 		{
// 			name: "Empty roles in access token",
// 			tokenModFn: func(t *jwt.Token) {
// 				t.Claims.(jwt.MapClaims)["rls"] = []string{}
// 			},
// 			expectedErr: "at least one role must be provided",
// 		},
// 	}

// 	config := DefaultGourdianTokenConfig("test-secret-32-bytes-long-1234567890")
// 	maker, err := NewGourdianTokenMaker(context.Background(), config, nil)
// 	require.NoError(t, err)

// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
// 				"jti": uuid.New().String(),
// 				"sub": uuid.New().String(),
// 				"usr": "user",
// 				"sid": uuid.New().String(),
// 				"iat": time.Now().Unix(),
// 				"exp": time.Now().Add(time.Hour).Unix(),
// 				"typ": AccessToken,
// 				"rls": []string{"admin"},
// 			})

// 			if tt.tokenModFn != nil {
// 				tt.tokenModFn(token)
// 			}

// 			tokenString, err := token.SignedString([]byte(config.SymmetricKey))
// 			require.NoError(t, err)

// 			_, err = maker.VerifyAccessToken(context.Background(), tokenString)
// 			require.Error(t, err)
// 			assert.Contains(t, err.Error(), tt.expectedErr)
// 		})
// 	}
// }

// func TestConfigurationErrors(t *testing.T) {
// 	tests := []struct {
// 		name        string
// 		config      GourdianTokenConfig
// 		expectedErr string
// 	}{
// 		{
// 			name: "Unsupported algorithm",
// 			config: GourdianTokenConfig{
// 				Algorithm:     "XYZ999",
// 				SigningMethod: Symmetric,
// 				SymmetricKey:  "test-secret-32-bytes-long-1234567890",
// 			},
// 			expectedErr: "unsupported algorithm",
// 		},
// 		{
// 			name: "Algorithm/signing method mismatch",
// 			config: GourdianTokenConfig{
// 				Algorithm:     "RS256",
// 				SigningMethod: Symmetric,
// 				SymmetricKey:  "test-secret-32-bytes-long-1234567890",
// 			},
// 			expectedErr: "algorithm not compatible",
// 		},
// 		{
// 			name: "Symmetric key too short",
// 			config: GourdianTokenConfig{
// 				Algorithm:     "HS256",
// 				SigningMethod: Symmetric,
// 				SymmetricKey:  "too-short",
// 			},
// 			expectedErr: "symmetric key must be at least 32 bytes",
// 		},
// 		{
// 			name: "Missing private key for asymmetric",
// 			config: GourdianTokenConfig{
// 				Algorithm:      "RS256",
// 				SigningMethod:  Asymmetric,
// 				PublicKeyPath:  "testdata/public.pem",
// 				PrivateKeyPath: "",
// 			},
// 			expectedErr: "private and public key paths are required",
// 		},
// 		{
// 			name: "None algorithm disabled",
// 			config: GourdianTokenConfig{
// 				Algorithm:     "none",
// 				SigningMethod: Symmetric,
// 			},
// 			expectedErr: "unsecured tokens are disabled",
// 		},
// 	}

// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			_, err := NewGourdianTokenMaker(context.Background(), tt.config, nil)
// 			require.Error(t, err)
// 			assert.Contains(t, err.Error(), tt.expectedErr)
// 		})
// 	}
// }
