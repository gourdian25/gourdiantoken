package gourdiantoken

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test Helper Functions

func testRedisOptions() *redis.Options {
	return &redis.Options{
		Addr:     "localhost:6379",      // Connect to your container
		Password: "GourdianRedisSecret", // No password
		DB:       0,                     // Default DB
	}
}

func generateTempRSAPair(t *testing.T) (privatePath, publicPath string) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	privateBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateBytes,
	}

	privatePath = filepath.Join(t.TempDir(), "private.pem")
	err = os.WriteFile(privatePath, pem.EncodeToMemory(privateBlock), 0600)
	require.NoError(t, err)

	publicBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	require.NoError(t, err)
	publicBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicBytes,
	}

	publicPath = filepath.Join(t.TempDir(), "public.pem")
	err = os.WriteFile(publicPath, pem.EncodeToMemory(publicBlock), 0600)
	require.NoError(t, err)

	return privatePath, publicPath
}

func generateTempECDSAPair(t *testing.T) (privatePath, publicPath string) {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	privateBytes, err := x509.MarshalECPrivateKey(privateKey)
	require.NoError(t, err)
	privateBlock := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privateBytes,
	}

	privatePath = filepath.Join(t.TempDir(), "ec_private.pem")
	err = os.WriteFile(privatePath, pem.EncodeToMemory(privateBlock), 0600)
	require.NoError(t, err)

	publicBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	require.NoError(t, err)
	publicBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicBytes,
	}

	publicPath = filepath.Join(t.TempDir(), "ec_public.pem")
	err = os.WriteFile(publicPath, pem.EncodeToMemory(publicBlock), 0600)
	require.NoError(t, err)

	return privatePath, publicPath
}

func generateTempCertificate(t *testing.T) (privatePath, publicPath string) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour),
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	privateBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateBytes,
	}

	privatePath = filepath.Join(t.TempDir(), "cert_private.pem")
	err = os.WriteFile(privatePath, pem.EncodeToMemory(privateBlock), 0600)
	require.NoError(t, err)

	certBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	}

	publicPath = filepath.Join(t.TempDir(), "cert_public.pem")
	err = os.WriteFile(publicPath, pem.EncodeToMemory(certBlock), 0600)
	require.NoError(t, err)

	return privatePath, publicPath
}

// Test Cases

func TestTokenRotation_ReuseInterval(t *testing.T) {
	config := DefaultGourdianTokenConfig("test-secret-32-bytes-long-1234567890")
	config.RefreshToken.RotationEnabled = true
	config.RefreshToken.ReuseInterval = time.Minute  // Set to non-zero
	config.RefreshToken.MaxLifetime = 24 * time.Hour // Ensure sufficient expiration time

	maker, err := NewGourdianTokenMaker(config, testRedisOptions())
	require.NoError(t, err)

	// Create initial token
	userID := uuid.New()
	username := "testuser"
	sessionID := uuid.New()
	tokenResp, err := maker.CreateRefreshToken(context.Background(), userID, username, sessionID)
	require.NoError(t, err)

	// First rotation should work
	_, err = maker.RotateRefreshToken(tokenResp.Token)
	require.NoError(t, err)

	// Verify old token is now invalid
	_, err = maker.VerifyRefreshToken(tokenResp.Token)
	require.Error(t, err)

	// Immediate reuse attempt should fail with "reused too soon"
	_, err = maker.RotateRefreshToken(tokenResp.Token)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "token reused too soon")

	// Create a new token with same user/session
	tokenResp2, err := maker.CreateRefreshToken(context.Background(), userID, username, sessionID)
	require.NoError(t, err)

	// Rotate it immediately - should fail with "too soon"
	_, err = maker.RotateRefreshToken(tokenResp2.Token)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "token reused too soon")

	// Wait longer than reuse interval and try again (should work)
	time.Sleep(2 * time.Second)                     // Short sleep for testing
	config.RefreshToken.ReuseInterval = time.Second // Reduce interval for test

	maker, err = NewGourdianTokenMaker(config, testRedisOptions())
	require.NoError(t, err)

	tokenResp3, err := maker.CreateRefreshToken(context.Background(), userID, username, sessionID)
	require.NoError(t, err)

	_, err = maker.RotateRefreshToken(tokenResp3.Token)
	require.NoError(t, err)
}

func TestTokenRotation(t *testing.T) {
	redisOpts := testRedisOptions()

	t.Run("Successful Rotation", func(t *testing.T) {
		// Test with working Redis
		if _, err := redis.NewClient(redisOpts).Ping(context.Background()).Result(); err != nil {
			t.Skip("Redis not available, skipping test")
		}
		config := DefaultGourdianTokenConfig("test-secret-32-bytes-long-1234567890")
		config.RefreshToken.RotationEnabled = true
		maker, err := NewGourdianTokenMaker(config, redisOpts)
		require.NoError(t, err)

		// Create initial token
		oldToken, err := maker.CreateRefreshToken(context.Background(), uuid.New(), "user", uuid.New())
		require.NoError(t, err)

		// Rotate token
		newToken, err := maker.RotateRefreshToken(oldToken.Token)
		require.NoError(t, err)

		// Verify old token is invalid
		_, err = maker.VerifyRefreshToken(oldToken.Token)
		assert.Error(t, err)

		// Verify new token works
		_, err = maker.VerifyRefreshToken(newToken.Token)
		assert.NoError(t, err)
	})

	t.Run("Rotation Reuse Protection", func(t *testing.T) {
		config := DefaultGourdianTokenConfig("test-secret-32-bytes-long-1234567890")
		config.RefreshToken.RotationEnabled = true
		config.RefreshToken.ReuseInterval = time.Minute
		maker, err := NewGourdianTokenMaker(config, redisOpts)
		require.NoError(t, err)

		token, err := maker.CreateRefreshToken(context.Background(), uuid.New(), "user", uuid.New())
		require.NoError(t, err)

		// First rotation should work
		_, err = maker.RotateRefreshToken(token.Token)
		require.NoError(t, err)

		// Immediate second rotation attempt should fail
		_, err = maker.RotateRefreshToken(token.Token)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "token reused too soon")
	})

	t.Run("Redis Failure", func(t *testing.T) {
		config := DefaultGourdianTokenConfig("test-secret-32-bytes-long-1234567890")
		config.RefreshToken.RotationEnabled = true

		// Use invalid Redis options
		badRedisOpts := &redis.Options{Addr: "localhost:9999"}
		maker, err := NewGourdianTokenMaker(config, badRedisOpts)
		require.NoError(t, err) // Should still create maker

		token, err := maker.CreateRefreshToken(context.Background(), uuid.New(), "user", uuid.New())
		require.NoError(t, err)

		// Rotation should fail
		_, err = maker.RotateRefreshToken(token.Token)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "redis error")
	})
}

func TestClaimValidation(t *testing.T) {
	config := DefaultGourdianTokenConfig("test-secret-32-bytes-long-1234567890")
	maker, err := NewGourdianTokenMaker(config, testRedisOptions())
	require.NoError(t, err)

	t.Run("Missing Required Claims", func(t *testing.T) {
		tests := []struct {
			name   string
			claims jwt.MapClaims
			error  string
		}{
			{"Missing JTI", jwt.MapClaims{"sub": uuid.New().String(), "usr": "test", "sid": uuid.New().String(), "typ": "access"}, "missing required claim: jti"},
			{"Missing SUB", jwt.MapClaims{"jti": uuid.New().String(), "usr": "test", "sid": uuid.New().String(), "typ": "access"}, "missing required claim: sub"},
			{"Missing TYP", jwt.MapClaims{"jti": uuid.New().String(), "sub": uuid.New().String(), "usr": "test", "sid": uuid.New().String()}, "missing required claim: typ"},
			{"Missing USR", jwt.MapClaims{"jti": uuid.New().String(), "sub": uuid.New().String(), "sid": uuid.New().String(), "typ": "access"}, "missing required claim: usr"},
			{"Missing SID", jwt.MapClaims{"jti": uuid.New().String(), "sub": uuid.New().String(), "usr": "test", "typ": "access"}, "missing required claim: sid"},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				token := jwt.NewWithClaims(jwt.SigningMethodHS256, tt.claims)
				tokenString, _ := token.SignedString([]byte(config.SymmetricKey))
				_, err := maker.VerifyAccessToken(tokenString)
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.error)
			})
		}
	})

	t.Run("Invalid UUID Formats", func(t *testing.T) {
		tests := []struct {
			name  string
			claim string
			value interface{}
			error string
		}{
			{"Invalid JTI", "jti", "not-a-uuid", "invalid token ID"},
			{"Invalid SUB", "sub", 12345, "invalid user ID"},
			{"Invalid SID", "sid", false, "invalid session ID"},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				claims := jwt.MapClaims{
					"jti":    uuid.New().String(),
					"sub":    uuid.New().String(),
					"usr":    "testuser",
					"sid":    uuid.New().String(),
					"iat":    time.Now().Unix(),
					"exp":    time.Now().Add(time.Hour).Unix(),
					"typ":    AccessToken,
					tt.claim: tt.value,
				}
				token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
				tokenString, _ := token.SignedString([]byte(config.SymmetricKey))
				_, err := maker.VerifyAccessToken(tokenString)
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.error)
			})
		}
	})
}

func TestEdgeCases(t *testing.T) {
	t.Run("Empty Token String", func(t *testing.T) {
		config := DefaultGourdianTokenConfig("test-secret-32-bytes-long-1234567890")
		maker, err := NewGourdianTokenMaker(config, testRedisOptions())
		require.NoError(t, err)

		_, err = maker.VerifyAccessToken("")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "token contains an invalid number of segments")
	})

	t.Run("Malformed Token", func(t *testing.T) {
		config := DefaultGourdianTokenConfig("test-secret-32-bytes-long-1234567890")
		maker, err := NewGourdianTokenMaker(config, testRedisOptions())
		require.NoError(t, err)

		_, err = maker.VerifyAccessToken("header.claims.signature")
		assert.Error(t, err)
	})

	t.Run("Expired Token", func(t *testing.T) {
		config := DefaultGourdianTokenConfig("test-secret-32-bytes-long-1234567890")
		config.AccessToken.Duration = -time.Hour // Force expired
		maker, err := NewGourdianTokenMaker(config, testRedisOptions())
		require.NoError(t, err)

		token, err := maker.CreateAccessToken(context.Background(), uuid.New(), "user", "role", uuid.New())
		require.NoError(t, err)

		_, err = maker.VerifyAccessToken(token.Token)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "token has expired")
	})

	t.Run("Future Issued At", func(t *testing.T) {
		config := DefaultGourdianTokenConfig("test-secret-32-bytes-long-1234567890")
		maker, err := NewGourdianTokenMaker(config, testRedisOptions())
		require.NoError(t, err)

		claims := AccessTokenClaims{
			ID:        uuid.New(),
			Subject:   uuid.New(),
			Username:  "user",
			SessionID: uuid.New(),
			IssuedAt:  time.Now().Add(time.Hour), // Future
			ExpiresAt: time.Now().Add(2 * time.Hour),
			TokenType: AccessToken,
			Role:      "role",
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, toMapClaims(claims))
		tokenString, _ := token.SignedString([]byte(config.SymmetricKey))

		_, err = maker.VerifyAccessToken(tokenString)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "token issued in the future")
	})
}

func TestNewGourdianTokenMaker(t *testing.T) {
	t.Run("Symmetric HS256", func(t *testing.T) {
		config := DefaultGourdianTokenConfig("test-secret-32-bytes-long-1234567890")
		maker, err := NewGourdianTokenMaker(config, testRedisOptions())
		require.NoError(t, err)
		assert.NotNil(t, maker)
	})

	t.Run("Asymmetric RSA", func(t *testing.T) {
		privatePath, publicPath := generateTempRSAPair(t)
		config := GourdianTokenConfig{
			Algorithm:      "RS256",
			SigningMethod:  Asymmetric,
			PrivateKeyPath: privatePath,
			PublicKeyPath:  publicPath,
			AccessToken: AccessTokenConfig{
				Duration:    time.Hour,
				MaxLifetime: 24 * time.Hour,
			},
		}
		maker, err := NewGourdianTokenMaker(config, testRedisOptions())
		require.NoError(t, err)
		assert.NotNil(t, maker)
	})

	t.Run("Asymmetric ECDSA", func(t *testing.T) {
		privatePath, publicPath := generateTempECDSAPair(t)
		config := GourdianTokenConfig{
			Algorithm:      "ES256",
			SigningMethod:  Asymmetric,
			PrivateKeyPath: privatePath,
			PublicKeyPath:  publicPath,
			AccessToken: AccessTokenConfig{
				Duration:    time.Hour,
				MaxLifetime: 24 * time.Hour,
			},
		}
		maker, err := NewGourdianTokenMaker(config, testRedisOptions())
		require.NoError(t, err)
		assert.NotNil(t, maker)
	})

	t.Run("Invalid Config - Symmetric Key Too Short", func(t *testing.T) {
		config := DefaultGourdianTokenConfig("short")
		_, err := NewGourdianTokenMaker(config, testRedisOptions())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "symmetric key must be at least 32 bytes")
	})

	t.Run("Invalid Config - Missing Key Paths", func(t *testing.T) {
		config := GourdianTokenConfig{
			Algorithm:     "RS256",
			SigningMethod: Asymmetric,
		}
		_, err := NewGourdianTokenMaker(config, testRedisOptions())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "private and public key paths are required")
	})

	t.Run("Invalid Config - Unsupported Algorithm", func(t *testing.T) {
		config := GourdianTokenConfig{
			Algorithm:     "FOO256",
			SigningMethod: Symmetric,
			SymmetricKey:  "test-secret-32-bytes-long-1234567890",
		}
		_, err := NewGourdianTokenMaker(config, testRedisOptions())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "algorithm FOO256 not compatible with symmetric signing")
	})

	t.Run("Invalid Config - Insecure Key Permissions", func(t *testing.T) {
		privatePath, publicPath := generateTempRSAPair(t)
		// Make the private key world-readable
		err := os.Chmod(privatePath, 0644)
		require.NoError(t, err)

		config := GourdianTokenConfig{
			Algorithm:      "RS256",
			SigningMethod:  Asymmetric,
			PrivateKeyPath: privatePath,
			PublicKeyPath:  publicPath,
		}
		_, err = NewGourdianTokenMaker(config, testRedisOptions())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "insecure private key file permissions")
	})

	t.Run("Invalid Config - Mixed Key Configuration", func(t *testing.T) {
		privatePath, publicPath := generateTempRSAPair(t)
		config := GourdianTokenConfig{
			Algorithm:      "HS256",
			SigningMethod:  Symmetric,
			SymmetricKey:   "test-secret-32-bytes-long-1234567890",
			PrivateKeyPath: privatePath, // Should cause error for symmetric
			PublicKeyPath:  publicPath,  // Should cause error for symmetric
		}
		_, err := NewGourdianTokenMaker(config, testRedisOptions())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "private and public key paths must be empty for symmetric signing")
	})

	t.Run("Invalid Config - Algorithm/Signing Method Mismatch", func(t *testing.T) {
		config := GourdianTokenConfig{
			Algorithm:     "RS256", // RSA algorithm
			SigningMethod: Symmetric,
			SymmetricKey:  "test-secret-32-bytes-long-1234567890",
		}
		_, err := NewGourdianTokenMaker(config, testRedisOptions())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "algorithm RS256 not compatible with symmetric signing")
	})

	t.Run("Rotation Enabled Without Redis", func(t *testing.T) {
		config := DefaultGourdianTokenConfig("test-secret-32-bytes-long-1234567890")
		config.RefreshToken.RotationEnabled = true
		_, err := NewGourdianTokenMaker(config, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "redis options required for token rotation")
	})

	t.Run("Valid Rotation Configuration", func(t *testing.T) {
		config := DefaultGourdianTokenConfig("test-secret-32-bytes-long-1234567890")
		config.RefreshToken.RotationEnabled = true
		maker, err := NewGourdianTokenMaker(config, testRedisOptions())
		require.NoError(t, err)
		assert.NotNil(t, maker)
		assert.NotNil(t, maker.(*JWTMaker).redisClient)
	})
}

func TestCreateAndVerifyAccessToken(t *testing.T) {
	// Setup symmetric maker
	symmetricConfig := DefaultGourdianTokenConfig("test-secret-32-bytes-long-1234567890")
	symmetricMaker, err := NewGourdianTokenMaker(symmetricConfig, testRedisOptions())
	require.NoError(t, err)

	// Setup asymmetric maker
	privatePath, publicPath := generateTempRSAPair(t)
	asymmetricConfig := GourdianTokenConfig{
		Algorithm:      "RS256",
		SigningMethod:  Asymmetric,
		PrivateKeyPath: privatePath,
		PublicKeyPath:  publicPath,
		AccessToken: AccessTokenConfig{
			Duration:    time.Hour,
			MaxLifetime: 24 * time.Hour,
		},
	}
	asymmetricMaker, err := NewGourdianTokenMaker(asymmetricConfig, testRedisOptions())
	require.NoError(t, err)

	testCases := []struct {
		name  string
		maker GourdianTokenMaker
	}{
		{"Symmetric", symmetricMaker},
		{"Asymmetric", asymmetricMaker},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			userID := uuid.New()
			username := "testuser"
			role := "admin"
			sessionID := uuid.New()

			// Test CreateAccessToken
			resp, err := tc.maker.CreateAccessToken(context.Background(), userID, username, role, sessionID)
			require.NoError(t, err)
			assert.NotEmpty(t, resp.Token)
			assert.Equal(t, userID, resp.Subject)
			assert.Equal(t, username, resp.Username)
			assert.Equal(t, sessionID, resp.SessionID)
			assert.Equal(t, role, resp.Role)
			assert.True(t, time.Now().Before(resp.ExpiresAt))
			assert.True(t, time.Now().After(resp.IssuedAt))

			// Test VerifyAccessToken
			claims, err := tc.maker.VerifyAccessToken(resp.Token)
			require.NoError(t, err)
			assert.Equal(t, userID, claims.Subject)
			assert.Equal(t, username, claims.Username)
			assert.Equal(t, sessionID, claims.SessionID)
			assert.Equal(t, role, claims.Role)
			assert.Equal(t, AccessToken, claims.TokenType)
			assert.True(t, time.Now().Before(claims.ExpiresAt))
			assert.True(t, time.Now().After(claims.IssuedAt))
		})
	}

	t.Run("Invalid Token - Tampered", func(t *testing.T) {
		resp, err := symmetricMaker.CreateAccessToken(context.Background(), uuid.New(), "user", "role", uuid.New())
		require.NoError(t, err)

		// Tamper with the token
		tamperedToken := resp.Token[:len(resp.Token)-4] + "abcd"

		_, err = symmetricMaker.VerifyAccessToken(tamperedToken)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid token")
	})

	t.Run("Invalid Token - Expired", func(t *testing.T) {
		// Create a token with very short lifetime
		config := DefaultGourdianTokenConfig("test-secret-32-bytes-long-1234567890")
		config.AccessToken.Duration = time.Millisecond
		maker, err := NewGourdianTokenMaker(config, testRedisOptions())
		require.NoError(t, err)

		resp, err := maker.CreateAccessToken(context.Background(), uuid.New(), "user", "role", uuid.New())
		require.NoError(t, err)

		// Wait for it to expire
		time.Sleep(10 * time.Millisecond)

		_, err = maker.VerifyAccessToken(resp.Token)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "expired")
	})

	t.Run("Invalid Token - Wrong Type", func(t *testing.T) {
		// Create a refresh token but try to verify as access token
		resp, err := symmetricMaker.CreateRefreshToken(context.Background(), uuid.New(), "user", uuid.New())
		require.NoError(t, err)

		_, err = symmetricMaker.VerifyAccessToken(resp.Token)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid token type")
	})
}

func TestCreateAndVerifyRefreshToken(t *testing.T) {
	// Setup symmetric maker
	symmetricConfig := DefaultGourdianTokenConfig("test-secret-32-bytes-long-1234567890")
	symmetricMaker, err := NewGourdianTokenMaker(symmetricConfig, testRedisOptions())
	require.NoError(t, err)

	// Setup asymmetric maker
	privatePath, publicPath := generateTempRSAPair(t)
	asymmetricConfig := GourdianTokenConfig{
		Algorithm:      "RS256",
		SigningMethod:  Asymmetric,
		PrivateKeyPath: privatePath,
		PublicKeyPath:  publicPath,
		RefreshToken: RefreshTokenConfig{
			Duration:        24 * time.Hour,
			MaxLifetime:     7 * 24 * time.Hour,
			RotationEnabled: true,
		},
	}
	asymmetricMaker, err := NewGourdianTokenMaker(asymmetricConfig, testRedisOptions())
	require.NoError(t, err)

	testCases := []struct {
		name  string
		maker GourdianTokenMaker
	}{
		{"Symmetric", symmetricMaker},
		{"Asymmetric", asymmetricMaker},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			userID := uuid.New()
			username := "testuser"
			sessionID := uuid.New()

			// Test CreateRefreshToken
			resp, err := tc.maker.CreateRefreshToken(context.Background(), userID, username, sessionID)
			require.NoError(t, err)
			assert.NotEmpty(t, resp.Token)
			assert.Equal(t, userID, resp.Subject)
			assert.Equal(t, username, resp.Username)
			assert.Equal(t, sessionID, resp.SessionID)
			assert.True(t, time.Now().Before(resp.ExpiresAt))
			assert.True(t, time.Now().After(resp.IssuedAt))

			// Test VerifyRefreshToken
			claims, err := tc.maker.VerifyRefreshToken(resp.Token)
			require.NoError(t, err)
			assert.Equal(t, userID, claims.Subject)
			assert.Equal(t, username, claims.Username)
			assert.Equal(t, sessionID, claims.SessionID)
			assert.Equal(t, RefreshToken, claims.TokenType)
			assert.True(t, time.Now().Before(claims.ExpiresAt))
			assert.True(t, time.Now().After(claims.IssuedAt))
		})
	}

	t.Run("Invalid Token - Tampered", func(t *testing.T) {
		resp, err := symmetricMaker.CreateRefreshToken(context.Background(), uuid.New(), "user", uuid.New())
		require.NoError(t, err)

		// Tamper with the token
		tamperedToken := resp.Token[:len(resp.Token)-4] + "abcd"

		_, err = symmetricMaker.VerifyRefreshToken(tamperedToken)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid token")
	})

	t.Run("Invalid Token - Expired", func(t *testing.T) {
		// Create a token with very short lifetime
		config := DefaultGourdianTokenConfig("test-secret-32-bytes-long-1234567890")
		config.RefreshToken.Duration = time.Millisecond
		maker, err := NewGourdianTokenMaker(config, testRedisOptions())
		require.NoError(t, err)

		resp, err := maker.CreateRefreshToken(context.Background(), uuid.New(), "user", uuid.New())
		require.NoError(t, err)

		// Wait for it to expire
		time.Sleep(10 * time.Millisecond)

		_, err = maker.VerifyRefreshToken(resp.Token)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "expired")
	})

	t.Run("Invalid Token - Wrong Type", func(t *testing.T) {
		// Create an access token but try to verify as refresh token
		resp, err := symmetricMaker.CreateAccessToken(context.Background(), uuid.New(), "user", "role", uuid.New())
		require.NoError(t, err)

		_, err = symmetricMaker.VerifyRefreshToken(resp.Token)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid token type")
	})
}

func TestKeyParsing(t *testing.T) {
	t.Run("RSA PKCS8 Private Key", func(t *testing.T) {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		privateBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
		require.NoError(t, err)

		privateBlock := &pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: privateBytes,
		}

		key, err := parseRSAPrivateKey(pem.EncodeToMemory(privateBlock))
		require.NoError(t, err)
		assert.NotNil(t, key)
	})

	t.Run("RSA Certificate Public Key", func(t *testing.T) {
		_, publicPath := generateTempCertificate(t)
		publicBytes, err := os.ReadFile(publicPath)
		require.NoError(t, err)

		key, err := parseRSAPublicKey(publicBytes)
		require.NoError(t, err)
		assert.NotNil(t, key)

	})

	t.Run("Invalid RSA Private Key", func(t *testing.T) {
		block := &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: []byte("invalid key data"),
		}

		_, err := parseRSAPrivateKey(pem.EncodeToMemory(block))
		require.Error(t, err)
	})

	t.Run("Invalid RSA Public Key", func(t *testing.T) {
		block := &pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: []byte("invalid key data"),
		}

		_, err := parseRSAPublicKey(pem.EncodeToMemory(block))
		require.Error(t, err)
	})

	t.Run("ECDSA PKCS8 Private Key", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		privateBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
		require.NoError(t, err)

		privateBlock := &pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: privateBytes,
		}

		key, err := parseECDSAPrivateKey(pem.EncodeToMemory(privateBlock))
		require.NoError(t, err)
		assert.NotNil(t, key)
	})

	t.Run("Invalid ECDSA Private Key", func(t *testing.T) {
		block := &pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: []byte("invalid key data"),
		}

		_, err := parseECDSAPrivateKey(pem.EncodeToMemory(block))
		require.Error(t, err)
	})

	t.Run("Invalid ECDSA Public Key", func(t *testing.T) {
		block := &pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: []byte("invalid key data"),
		}

		_, err := parseECDSAPublicKey(pem.EncodeToMemory(block))
		require.Error(t, err)
	})
}

func TestTokenClaimsValidation(t *testing.T) {
	config := DefaultGourdianTokenConfig("test-secret-32-bytes-long-1234567890")
	maker, err := NewGourdianTokenMaker(config, testRedisOptions())
	require.NoError(t, err)

	t.Run("Missing Required Claim", func(t *testing.T) {
		// Create a token missing the "sub" claim
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"jti": uuid.New().String(),
			"usr": "testuser",
			"sid": uuid.New().String(),
			"iat": time.Now().Unix(),
			"exp": time.Now().Add(time.Hour).Unix(),
			"typ": AccessToken,
			"rol": "admin",
		})

		tokenString, err := token.SignedString([]byte(config.SymmetricKey))
		require.NoError(t, err)

		_, err = maker.VerifyAccessToken(tokenString)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "missing required claim: sub")
	})

	t.Run("Invalid Token Type", func(t *testing.T) {
		// Create a token with wrong type
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"jti": uuid.New().String(),
			"sub": uuid.New().String(),
			"usr": "testuser",
			"sid": uuid.New().String(),
			"iat": time.Now().Unix(),
			"exp": time.Now().Add(time.Hour).Unix(),
			"typ": "invalid",
			"rol": "admin",
		})

		tokenString, err := token.SignedString([]byte(config.SymmetricKey))
		require.NoError(t, err)

		_, err = maker.VerifyAccessToken(tokenString)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid token type")
	})

	t.Run("Token From Future", func(t *testing.T) {
		// Create a token with iat in the future
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"jti": uuid.New().String(),
			"sub": uuid.New().String(),
			"usr": "testuser",
			"sid": uuid.New().String(),
			"iat": time.Now().Add(time.Hour).Unix(),
			"exp": time.Now().Add(2 * time.Hour).Unix(),
			"typ": AccessToken,
			"rol": "admin",
		})

		tokenString, err := token.SignedString([]byte(config.SymmetricKey))
		require.NoError(t, err)

		_, err = maker.VerifyAccessToken(tokenString)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "token issued in the future")
	})
}

func TestDefaultConfig(t *testing.T) {
	t.Run("Valid Default Config", func(t *testing.T) {
		config := DefaultGourdianTokenConfig("test-secret-32-bytes-long-1234567890")
		assert.Equal(t, "HS256", config.Algorithm)
		assert.Equal(t, Symmetric, config.SigningMethod)
		assert.Equal(t, 30*time.Minute, config.AccessToken.Duration)
		assert.Equal(t, 24*time.Hour, config.AccessToken.MaxLifetime)
		assert.Equal(t, []string{"HS256"}, config.AccessToken.AllowedAlgorithms)
		assert.Equal(t, []string{"jti", "sub", "exp", "iat", "typ", "rol"}, config.AccessToken.RequiredClaims)
		assert.Equal(t, 7*24*time.Hour, config.RefreshToken.Duration)
		assert.Equal(t, 30*24*time.Hour, config.RefreshToken.MaxLifetime)
		assert.Equal(t, time.Minute, config.RefreshToken.ReuseInterval)
		assert.False(t, config.RefreshToken.RotationEnabled)
	})

	t.Run("Invalid Key Length", func(t *testing.T) {
		config := DefaultGourdianTokenConfig("short")
		_, err := NewGourdianTokenMaker(config, testRedisOptions())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "symmetric key must be at least 32 bytes")
	})
}

func TestTokenRotation_EdgeCases(t *testing.T) {
	t.Run("Rotation with Disabled Config", func(t *testing.T) {
		config := DefaultGourdianTokenConfig("test-secret-32-bytes-long-1234567890")
		config.RefreshToken.RotationEnabled = false
		maker, err := NewGourdianTokenMaker(config, testRedisOptions())
		require.NoError(t, err)

		resp, err := maker.CreateRefreshToken(context.Background(), uuid.New(), "user", uuid.New())
		require.NoError(t, err)

		_, err = maker.RotateRefreshToken(resp.Token)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "token rotation not enabled")
	})

	t.Run("Rotation with Invalid Token", func(t *testing.T) {
		config := DefaultGourdianTokenConfig("test-secret-32-bytes-long-1234567890")
		config.RefreshToken.RotationEnabled = true
		maker, err := NewGourdianTokenMaker(config, testRedisOptions())
		require.NoError(t, err)

		_, err = maker.RotateRefreshToken("invalid.token.string")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid token")
	})
}
func TestConfigValidation(t *testing.T) {
	t.Run("Valid Symmetric Config", func(t *testing.T) {
		config := GourdianTokenConfig{
			Algorithm:      "HS256",
			SigningMethod:  Symmetric,
			SymmetricKey:   "test-secret-32-bytes-long-1234567890",
			PrivateKeyPath: "",
			PublicKeyPath:  "",
			AccessToken:    AccessTokenConfig{Duration: time.Hour},
			RefreshToken:   RefreshTokenConfig{Duration: 24 * time.Hour},
		}
		err := validateConfig(&config)
		assert.NoError(t, err)
	})

	t.Run("Valid Asymmetric Config", func(t *testing.T) {
		privatePath, publicPath := generateTempRSAPair(t)
		config := GourdianTokenConfig{
			Algorithm:      "RS256",
			SigningMethod:  Asymmetric,
			SymmetricKey:   "",
			PrivateKeyPath: privatePath,
			PublicKeyPath:  publicPath,
			AccessToken:    AccessTokenConfig{Duration: time.Hour},
			RefreshToken:   RefreshTokenConfig{Duration: 24 * time.Hour},
		}
		err := validateConfig(&config)
		assert.NoError(t, err)
	})

	t.Run("Invalid Config - Mixed Key Configuration", func(t *testing.T) {
		privatePath, publicPath := generateTempRSAPair(t)
		config := GourdianTokenConfig{
			Algorithm:      "HS256",
			SigningMethod:  Symmetric,
			SymmetricKey:   "test-secret-32-bytes-long-1234567890",
			PrivateKeyPath: privatePath, // This should cause validation to fail
			PublicKeyPath:  publicPath,  // This should cause validation to fail
			AccessToken: AccessTokenConfig{
				Duration:    time.Hour,
				MaxLifetime: 24 * time.Hour,
			},
		}
		_, err := NewGourdianTokenMaker(config, testRedisOptions())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "private and public key paths must be empty for symmetric signing")
	})

	t.Run("Invalid Algorithm for Method", func(t *testing.T) {
		config := GourdianTokenConfig{
			Algorithm:     "RS256", // RSA algorithm
			SigningMethod: Symmetric,
			SymmetricKey:  "test-secret-32-bytes-long-1234567890",
			AccessToken:   AccessTokenConfig{Duration: time.Hour},
		}
		err := validateConfig(&config)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "algorithm RS256 not compatible with symmetric signing")
	})
}
