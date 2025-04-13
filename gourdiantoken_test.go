// gourdiantoken_test.go

package gourdiantoken

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestTokenEdgeCases tests various edge cases in token creation and validation
func TestTokenEdgeCases(t *testing.T) {
	t.Run("Token with Empty UUID", func(t *testing.T) {
		config := DefaultGourdianTokenConfig(testSymmetricKey)
		maker, err := NewGourdianTokenMaker(context.Background(), config, nil)
		require.NoError(t, err)

		emptyUUID := uuid.UUID{}
		_, err = maker.CreateAccessToken(context.Background(), emptyUUID, "user", []string{"role"}, uuid.New())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid user ID")
	})

	t.Run("Token with Empty Roles", func(t *testing.T) {
		config := DefaultGourdianTokenConfig(testSymmetricKey)
		maker, err := NewGourdianTokenMaker(context.Background(), config, nil)
		require.NoError(t, err)

		_, err = maker.CreateAccessToken(context.Background(), uuid.New(), "user", []string{}, uuid.New())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "at least one role must be provided")
	})

	t.Run("Token with Empty Role String", func(t *testing.T) {
		config := DefaultGourdianTokenConfig(testSymmetricKey)
		maker, err := NewGourdianTokenMaker(context.Background(), config, nil)
		require.NoError(t, err)

		_, err = maker.CreateAccessToken(context.Background(), uuid.New(), "user", []string{""}, uuid.New())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "roles cannot contain empty strings")
	})

	t.Run("Token with Very Long Username", func(t *testing.T) {
		config := DefaultGourdianTokenConfig(testSymmetricKey)
		maker, err := NewGourdianTokenMaker(context.Background(), config, nil)
		require.NoError(t, err)

		longUsername := strings.Repeat("a", 1025)
		_, err = maker.CreateAccessToken(context.Background(), uuid.New(), longUsername, []string{"role"}, uuid.New())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "username too long")
	})
}

// TestSecurityScenarios tests various security-related scenarios
func TestSecurityScenarios(t *testing.T) {
	t.Run("Algorithm Confusion Attack", func(t *testing.T) {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		rsaClaims := jwt.MapClaims{
			"jti": uuid.New().String(),
			"sub": uuid.New().String(),
			"usr": "user",
			"sid": uuid.New().String(),
			"iat": time.Now().Unix(),
			"exp": time.Now().Add(time.Hour).Unix(),
			"typ": string(AccessToken),
			"rls": []string{"role"},
		}
		rsaToken := jwt.NewWithClaims(jwt.SigningMethodRS256, rsaClaims)
		rsaTokenString, err := rsaToken.SignedString(privateKey)
		require.NoError(t, err)

		hmacConfig := DefaultGourdianTokenConfig(testSymmetricKey)
		hmacMaker, err := NewGourdianTokenMaker(context.Background(), hmacConfig, nil)
		require.NoError(t, err)

		_, err = hmacMaker.VerifyAccessToken(context.Background(), rsaTokenString)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unexpected signing method")
	})

	t.Run("None Algorithm Attack", func(t *testing.T) {
		claims := jwt.MapClaims{
			"jti": uuid.New().String(),
			"sub": uuid.New().String(),
			"usr": "user",
			"sid": uuid.New().String(),
			"iat": time.Now().Unix(),
			"exp": time.Now().Add(time.Hour).Unix(),
			"typ": string(AccessToken),
			"rls": []string{"role"},
		}
		token := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
		tokenString, err := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
		require.NoError(t, err)

		config := DefaultGourdianTokenConfig(testSymmetricKey)
		maker, err := NewGourdianTokenMaker(context.Background(), config, nil)
		require.NoError(t, err)

		_, err = maker.VerifyAccessToken(context.Background(), tokenString)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unexpected signing method")
	})

	t.Run("Token Replay Attack", func(t *testing.T) {
		client := redisTestClient(t)
		defer client.Close()

		config := DefaultGourdianTokenConfig(testSymmetricKey)
		config.AccessToken.RevocationEnabled = true
		maker, err := NewGourdianTokenMaker(context.Background(), config, testRedisOptions())
		require.NoError(t, err)

		token, err := maker.CreateAccessToken(context.Background(), uuid.New(), "user", []string{"role"}, uuid.New())
		require.NoError(t, err)

		// Verify token works initially
		_, err = maker.VerifyAccessToken(context.Background(), token.Token)
		require.NoError(t, err)

		// Verify token again (should still work)
		_, err = maker.VerifyAccessToken(context.Background(), token.Token)
		require.NoError(t, err)

		// Revoke the token
		err = maker.RevokeAccessToken(context.Background(), token.Token)
		require.NoError(t, err)

		// Try to use revoked token
		_, err = maker.VerifyAccessToken(context.Background(), token.Token)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "token has been revoked")
	})
}

// TestTokenRotation_ReuseInterval tests token rotation with reuse intervals
func TestTokenRotation_ReuseInterval(t *testing.T) {
	client := redisTestClient(t)
	defer client.Close()

	config := DefaultGourdianTokenConfig(testSymmetricKey)
	config.RefreshToken.RotationEnabled = true
	config.RefreshToken.ReuseInterval = time.Second
	config.RefreshToken.MaxLifetime = time.Hour

	maker, err := NewGourdianTokenMaker(context.Background(), config, testRedisOptions())
	require.NoError(t, err)

	token, err := maker.CreateRefreshToken(context.Background(), uuid.New(), "user", uuid.New())
	require.NoError(t, err)

	// First rotation should work
	_, err = maker.RotateRefreshToken(context.Background(), token.Token)
	require.NoError(t, err)

	// Immediate reuse should fail
	_, err = maker.RotateRefreshToken(context.Background(), token.Token)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "token reused too soon")

	// Wait longer than reuse interval and try again
	time.Sleep(2 * time.Second)
	newToken, err := maker.CreateRefreshToken(context.Background(), uuid.New(), "user", uuid.New())
	require.NoError(t, err)

	_, err = maker.RotateRefreshToken(context.Background(), newToken.Token)
	require.NoError(t, err)
}

// TestCreateAndVerifyRefreshToken tests refresh token creation and verification
func TestCreateAndVerifyRefreshToken(t *testing.T) {
	// Setup symmetric maker
	symmetricConfig := DefaultGourdianTokenConfig(testSymmetricKey)
	symmetricMaker, err := NewGourdianTokenMaker(context.Background(), symmetricConfig, testRedisOptions())
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
	asymmetricMaker, err := NewGourdianTokenMaker(context.Background(), asymmetricConfig, testRedisOptions())
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
			claims, err := tc.maker.VerifyRefreshToken(context.Background(), resp.Token)
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

		_, err = symmetricMaker.VerifyRefreshToken(context.Background(), tamperedToken)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid token")
	})

	t.Run("Invalid Token - Expired", func(t *testing.T) {
		// Create a token with very short lifetime
		config := DefaultGourdianTokenConfig(testSymmetricKey)
		config.RefreshToken.Duration = time.Millisecond
		maker, err := NewGourdianTokenMaker(context.Background(), config, testRedisOptions())
		require.NoError(t, err)

		resp, err := maker.CreateRefreshToken(context.Background(), uuid.New(), "user", uuid.New())
		require.NoError(t, err)

		// Wait for it to expire
		time.Sleep(10 * time.Millisecond)

		_, err = maker.VerifyRefreshToken(context.Background(), resp.Token)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "expired")
	})

	t.Run("Invalid Token - Wrong Type", func(t *testing.T) {
		// Create an access token but try to verify as refresh token
		resp, err := symmetricMaker.CreateAccessToken(context.Background(), uuid.New(), "user", []string{"role"}, uuid.New())
		require.NoError(t, err)

		_, err = symmetricMaker.VerifyRefreshToken(context.Background(), resp.Token)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid token type")
	})
}

// TestKeyParsing tests various key parsing scenarios
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

// TestTokenClaimsValidation tests various token claim validation scenarios
func TestTokenClaimsValidation(t *testing.T) {
	config := DefaultGourdianTokenConfig(testSymmetricKey)
	maker, err := NewGourdianTokenMaker(context.Background(), config, testRedisOptions())
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
			"rls": []string{"admin"},
		})

		tokenString, err := token.SignedString([]byte(config.SymmetricKey))
		require.NoError(t, err)

		_, err = maker.VerifyAccessToken(context.Background(), tokenString)
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
			"rls": []string{"admin"},
		})

		tokenString, err := token.SignedString([]byte(config.SymmetricKey))
		require.NoError(t, err)

		_, err = maker.VerifyAccessToken(context.Background(), tokenString)
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
			"rls": []string{"admin"},
		})

		tokenString, err := token.SignedString([]byte(config.SymmetricKey))
		require.NoError(t, err)

		_, err = maker.VerifyAccessToken(context.Background(), tokenString)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "token issued in the future")
	})

	t.Run("Invalid Roles Claim", func(t *testing.T) {
		// Create a token with invalid roles claim
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"jti": uuid.New().String(),
			"sub": uuid.New().String(),
			"usr": "testuser",
			"sid": uuid.New().String(),
			"iat": time.Now().Unix(),
			"exp": time.Now().Add(time.Hour).Unix(),
			"typ": AccessToken,
			"rls": "not-an-array",
		})

		tokenString, err := token.SignedString([]byte(config.SymmetricKey))
		require.NoError(t, err)

		_, err = maker.VerifyAccessToken(context.Background(), tokenString)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid roles type")
	})
}

// TestDefaultConfig tests the default configuration
func TestDefaultConfig(t *testing.T) {
	t.Run("Valid Default Config", func(t *testing.T) {
		config := DefaultGourdianTokenConfig(testSymmetricKey)
		assert.Equal(t, "HS256", config.Algorithm)
		assert.Equal(t, Symmetric, config.SigningMethod)
		assert.Equal(t, 30*time.Minute, config.AccessToken.Duration)
		assert.Equal(t, 24*time.Hour, config.AccessToken.MaxLifetime)
		assert.Equal(t, []string{"HS256"}, config.AccessToken.AllowedAlgorithms)
		assert.Equal(t, []string{"jti", "sub", "exp", "iat", "typ", "rls"}, config.AccessToken.RequiredClaims)
		assert.Equal(t, 7*24*time.Hour, config.RefreshToken.Duration)
		assert.Equal(t, 30*24*time.Hour, config.RefreshToken.MaxLifetime)
		assert.Equal(t, time.Minute, config.RefreshToken.ReuseInterval)
		assert.False(t, config.RefreshToken.RotationEnabled)
	})

	t.Run("Invalid Key Length", func(t *testing.T) {
		config := DefaultGourdianTokenConfig("short")
		_, err := NewGourdianTokenMaker(context.Background(), config, testRedisOptions())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "symmetric key must be at least 32 bytes")
	})
}

// TestTokenRotation_EdgeCases tests edge cases in token rotation
func TestTokenRotation_EdgeCases(t *testing.T) {
	t.Run("Rotation with Disabled Config", func(t *testing.T) {
		config := DefaultGourdianTokenConfig(testSymmetricKey)
		config.RefreshToken.RotationEnabled = false
		maker, err := NewGourdianTokenMaker(context.Background(), config, testRedisOptions())
		require.NoError(t, err)

		resp, err := maker.CreateRefreshToken(context.Background(), uuid.New(), "user", uuid.New())
		require.NoError(t, err)

		_, err = maker.RotateRefreshToken(context.Background(), resp.Token)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "token rotation not enabled")
	})

	t.Run("Rotation with Invalid Token", func(t *testing.T) {
		config := DefaultGourdianTokenConfig(testSymmetricKey)
		config.RefreshToken.RotationEnabled = true
		maker, err := NewGourdianTokenMaker(context.Background(), config, testRedisOptions())
		require.NoError(t, err)

		_, err = maker.RotateRefreshToken(context.Background(), "invalid.token.string")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid token")
	})

	t.Run("Rotation with Expired Token", func(t *testing.T) {
		config := DefaultGourdianTokenConfig(testSymmetricKey)
		config.RefreshToken.RotationEnabled = true
		config.RefreshToken.Duration = time.Millisecond // Very short expiration
		maker, err := NewGourdianTokenMaker(context.Background(), config, testRedisOptions())
		require.NoError(t, err)

		token, err := maker.CreateRefreshToken(context.Background(), uuid.New(), "user", uuid.New())
		require.NoError(t, err)

		// Wait for token to expire
		time.Sleep(10 * time.Millisecond)

		_, err = maker.RotateRefreshToken(context.Background(), token.Token)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "expired")
	})
}

// TestConfigValidation tests configuration validation
func TestConfigValidation(t *testing.T) {
	t.Run("Valid Symmetric Config", func(t *testing.T) {
		config := GourdianTokenConfig{
			Algorithm:      "HS256",
			SigningMethod:  Symmetric,
			SymmetricKey:   testSymmetricKey,
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
			SymmetricKey:   testSymmetricKey,
			PrivateKeyPath: privatePath, // This should cause validation to fail
			PublicKeyPath:  publicPath,  // This should cause validation to fail
			AccessToken: AccessTokenConfig{
				Duration:    time.Hour,
				MaxLifetime: 24 * time.Hour,
			},
		}
		_, err := NewGourdianTokenMaker(context.Background(), config, testRedisOptions())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "private and public key paths must be empty for symmetric signing")
	})

	t.Run("Invalid Algorithm for Method", func(t *testing.T) {
		config := GourdianTokenConfig{
			Algorithm:     "RS256", // RSA algorithm
			SigningMethod: Symmetric,
			SymmetricKey:  testSymmetricKey,
			AccessToken:   AccessTokenConfig{Duration: time.Hour},
		}
		err := validateConfig(&config)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "algorithm RS256 not compatible with symmetric signing")
	})
}

// TestHelpers tests helper functions
func TestHelpers(t *testing.T) {
	t.Run("validateConfig", func(t *testing.T) {
		t.Run("Valid Symmetric Config", func(t *testing.T) {
			config := GourdianTokenConfig{
				Algorithm:     "HS256",
				SigningMethod: Symmetric,
				SymmetricKey:  testSymmetricKey,
				AccessToken:   AccessTokenConfig{Duration: time.Hour},
			}
			assert.NoError(t, validateConfig(&config))
		})

		t.Run("Invalid Symmetric Key Length", func(t *testing.T) {
			config := GourdianTokenConfig{
				Algorithm:     "HS256",
				SigningMethod: Symmetric,
				SymmetricKey:  "short",
				AccessToken:   AccessTokenConfig{Duration: time.Hour},
			}
			assert.Error(t, validateConfig(&config))
			assert.Contains(t, validateConfig(&config).Error(), "symmetric key must be at least 32 bytes")
		})

		t.Run("Valid Asymmetric Config", func(t *testing.T) {
			privatePath, publicPath := generateTempRSAPair(t)
			config := GourdianTokenConfig{
				Algorithm:      "RS256",
				SigningMethod:  Asymmetric,
				PrivateKeyPath: privatePath,
				PublicKeyPath:  publicPath,
				AccessToken:    AccessTokenConfig{Duration: time.Hour},
			}
			assert.NoError(t, validateConfig(&config))
		})

		t.Run("Missing Key Paths", func(t *testing.T) {
			config := GourdianTokenConfig{
				Algorithm:     "RS256",
				SigningMethod: Asymmetric,
				AccessToken:   AccessTokenConfig{Duration: time.Hour},
			}
			assert.Error(t, validateConfig(&config))
			assert.Contains(t, validateConfig(&config).Error(), "private and public key paths are required")
		})
	})

	t.Run("toMapClaims", func(t *testing.T) {
		now := time.Now()
		accessClaims := AccessTokenClaims{
			ID:        uuid.New(),
			Subject:   uuid.New(),
			Username:  "testuser",
			SessionID: uuid.New(),
			IssuedAt:  now,
			ExpiresAt: now.Add(time.Hour),
			TokenType: AccessToken,
			Roles:     []string{"admin"},
		}

		refreshClaims := RefreshTokenClaims{
			ID:        uuid.New(),
			Subject:   uuid.New(),
			Username:  "testuser",
			SessionID: uuid.New(),
			IssuedAt:  now,
			ExpiresAt: now.Add(24 * time.Hour),
			TokenType: RefreshToken,
		}

		t.Run("AccessTokenClaims", func(t *testing.T) {
			claims := toMapClaims(accessClaims)
			assert.Equal(t, accessClaims.ID.String(), claims["jti"])
			assert.Equal(t, accessClaims.Subject.String(), claims["sub"])
			assert.Equal(t, accessClaims.Username, claims["usr"])
			assert.Equal(t, accessClaims.SessionID.String(), claims["sid"])
			assert.Equal(t, accessClaims.IssuedAt.Unix(), claims["iat"])
			assert.Equal(t, accessClaims.ExpiresAt.Unix(), claims["exp"])
			assert.Equal(t, string(accessClaims.TokenType), claims["typ"])
			assert.Equal(t, accessClaims.Roles, claims["rls"])
		})

		t.Run("RefreshTokenClaims", func(t *testing.T) {
			claims := toMapClaims(refreshClaims)
			assert.Equal(t, refreshClaims.ID.String(), claims["jti"])
			assert.Equal(t, refreshClaims.Subject.String(), claims["sub"])
			assert.Equal(t, refreshClaims.Username, claims["usr"])
			assert.Equal(t, refreshClaims.SessionID.String(), claims["sid"])
			assert.Equal(t, refreshClaims.IssuedAt.Unix(), claims["iat"])
			assert.Equal(t, refreshClaims.ExpiresAt.Unix(), claims["exp"])
			assert.Equal(t, string(refreshClaims.TokenType), claims["typ"])
			assert.Nil(t, claims["rls"]) // Refresh tokens shouldn't have roles
		})

		t.Run("Invalid Type", func(t *testing.T) {
			assert.Panics(t, func() {
				toMapClaims("invalid type")
			}, "should panic on unsupported claims type")
		})

	})
}

// TestRevocation tests token revocation functionality
func TestRevocation(t *testing.T) {
	client := redisTestClient(t)
	defer client.Close()

	t.Run("Access Token Revocation", func(t *testing.T) {
		config := DefaultGourdianTokenConfig(testSymmetricKey)
		config.AccessToken.RevocationEnabled = true
		maker, err := NewGourdianTokenMaker(context.Background(), config, testRedisOptions())
		require.NoError(t, err)

		token, err := maker.CreateAccessToken(context.Background(), uuid.New(), "user", []string{"role"}, uuid.New())
		require.NoError(t, err)

		// Verify token works initially
		_, err = maker.VerifyAccessToken(context.Background(), token.Token)
		require.NoError(t, err)

		// Revoke the token
		err = maker.RevokeAccessToken(context.Background(), token.Token)
		require.NoError(t, err)

		// Verify token is now revoked
		_, err = maker.VerifyAccessToken(context.Background(), token.Token)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "token has been revoked")
	})

	t.Run("Refresh Token Revocation", func(t *testing.T) {
		config := DefaultGourdianTokenConfig(testSymmetricKey)
		config.RefreshToken.RevocationEnabled = true
		maker, err := NewGourdianTokenMaker(context.Background(), config, testRedisOptions())
		require.NoError(t, err)

		token, err := maker.CreateRefreshToken(context.Background(), uuid.New(), "user", uuid.New())
		require.NoError(t, err)

		// Verify token works initially
		_, err = maker.VerifyRefreshToken(context.Background(), token.Token)
		require.NoError(t, err)

		// Revoke the token
		err = maker.RevokeRefreshToken(context.Background(), token.Token)
		require.NoError(t, err)

		// Verify token is now revoked
		_, err = maker.VerifyRefreshToken(context.Background(), token.Token)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "token has been revoked")
	})

	t.Run("Revocation Not Enabled", func(t *testing.T) {
		config := DefaultGourdianTokenConfig(testSymmetricKey)
		maker, err := NewGourdianTokenMaker(context.Background(), config, testRedisOptions())
		require.NoError(t, err)

		token, err := maker.CreateAccessToken(context.Background(), uuid.New(), "user", []string{"role"}, uuid.New())
		require.NoError(t, err)

		err = maker.RevokeAccessToken(context.Background(), token.Token)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "access token revocation is not enabled")
	})

	t.Run("Revocation with Invalid Token", func(t *testing.T) {
		config := DefaultGourdianTokenConfig(testSymmetricKey)
		config.AccessToken.RevocationEnabled = true
		maker, err := NewGourdianTokenMaker(context.Background(), config, testRedisOptions())
		require.NoError(t, err)

		err = maker.RevokeAccessToken(context.Background(), "invalid.token.string")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid token")
	})
}

func TestTokenValidation(t *testing.T) {
	ctx := context.Background()
	config := DefaultGourdianTokenConfig(testSymmetricKey)
	maker := createTestMaker(t, config)

	t.Run("InvalidTokenType", func(t *testing.T) {
		// Create an access token but claim it's a refresh token
		claims := AccessTokenClaims{
			ID:        uuid.New(),
			Subject:   uuid.New(),
			Username:  "invalid-type",
			SessionID: uuid.New(),
			IssuedAt:  time.Now(),
			ExpiresAt: time.Now().Add(time.Hour),
			TokenType: RefreshToken, // Wrong type
			Roles:     []string{"user"},
		}

		token := jwt.NewWithClaims(maker.signingMethod, toMapClaims(claims))
		tokenString, err := token.SignedString(maker.privateKey)
		assert.NoError(t, err)

		_, err = maker.VerifyAccessToken(ctx, tokenString)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid token type: expected access")
	})

	t.Run("FutureIssuedAt", func(t *testing.T) {
		// Create a token with iat in the future
		claims := AccessTokenClaims{
			ID:        uuid.New(),
			Subject:   uuid.New(),
			Username:  "future-iat",
			SessionID: uuid.New(),
			IssuedAt:  time.Now().Add(time.Hour),
			ExpiresAt: time.Now().Add(2 * time.Hour),
			TokenType: AccessToken,
			Roles:     []string{"user"},
		}

		token := jwt.NewWithClaims(maker.signingMethod, toMapClaims(claims))
		tokenString, err := token.SignedString(maker.privateKey)
		assert.NoError(t, err)

		_, err = maker.VerifyAccessToken(ctx, tokenString)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "token issued in the future")
	})

	t.Run("InvalidUUIDs", func(t *testing.T) {
		// Create a token with invalid UUID strings
		claims := jwt.MapClaims{
			"jti": "not-a-uuid",
			"sub": uuid.New().String(),
			"usr": "invalid-uuid",
			"sid": uuid.New().String(),
			"iat": time.Now().Unix(),
			"exp": time.Now().Add(time.Hour).Unix(),
			"typ": string(AccessToken),
			"rls": []string{"user"},
		}

		token := jwt.NewWithClaims(maker.signingMethod, claims)
		tokenString, err := token.SignedString(maker.privateKey)
		assert.NoError(t, err)

		_, err = maker.VerifyAccessToken(ctx, tokenString)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid token ID")
	})
}

func TestTokenRevocation(t *testing.T) {
	ctx := context.Background()

	t.Run("AccessTokenRevocation", func(t *testing.T) {
		config := DefaultGourdianTokenConfig(testSymmetricKey)
		config.AccessToken.RevocationEnabled = true
		maker := createTestMaker(t, config)

		accessToken, err := maker.CreateAccessToken(ctx, uuid.New(), "revoke-test", []string{"user"}, uuid.New())
		assert.NoError(t, err)

		// Verify token works before revocation
		_, err = maker.VerifyAccessToken(ctx, accessToken.Token)
		assert.NoError(t, err)

		// Revoke the token
		err = maker.RevokeAccessToken(ctx, accessToken.Token)
		assert.NoError(t, err)

		// Verify token is now rejected
		_, err = maker.VerifyAccessToken(ctx, accessToken.Token)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "token has been revoked")
	})

	t.Run("RefreshTokenRevocation", func(t *testing.T) {
		config := DefaultGourdianTokenConfig(testSymmetricKey)
		config.RefreshToken.RevocationEnabled = true
		maker := createTestMaker(t, config)

		refreshToken, err := maker.CreateRefreshToken(ctx, uuid.New(), "revoke-test", uuid.New())
		assert.NoError(t, err)

		// Verify token works before revocation
		_, err = maker.VerifyRefreshToken(ctx, refreshToken.Token)
		assert.NoError(t, err)

		// Revoke the token
		err = maker.RevokeRefreshToken(ctx, refreshToken.Token)
		assert.NoError(t, err)

		// Verify token is now rejected
		_, err = maker.VerifyRefreshToken(ctx, refreshToken.Token)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "token has been revoked")
	})

	t.Run("RevocationDisabled", func(t *testing.T) {
		config := DefaultGourdianTokenConfig(testSymmetricKey)
		config.AccessToken.RevocationEnabled = false
		maker := createTestMaker(t, config)

		accessToken, err := maker.CreateAccessToken(ctx, uuid.New(), "revoke-test", []string{"user"}, uuid.New())
		assert.NoError(t, err)

		err = maker.RevokeAccessToken(ctx, accessToken.Token)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "access token revocation is not enabled")
	})
}

func TestRefreshTokenRotation(t *testing.T) {
	ctx := context.Background()

	t.Run("SuccessfulRotation", func(t *testing.T) {
		config := DefaultGourdianTokenConfig(testSymmetricKey)
		config.RefreshToken.RotationEnabled = true
		maker := createTestMaker(t, config)

		userID := uuid.New()
		sessionID := uuid.New()

		// Create initial refresh token
		oldToken, err := maker.CreateRefreshToken(ctx, userID, "rotation-test", sessionID)
		assert.NoError(t, err)

		// Rotate the token
		newToken, err := maker.RotateRefreshToken(ctx, oldToken.Token)
		assert.NoError(t, err)
		assert.NotEqual(t, oldToken.Token, newToken.Token)
		assert.Equal(t, userID, newToken.Subject)
		assert.Equal(t, sessionID, newToken.SessionID)

		// Verify the new token works
		_, err = maker.VerifyRefreshToken(ctx, newToken.Token)
		assert.NoError(t, err)

		// Old token should be marked as rotated and rejected if used again
		_, err = maker.RotateRefreshToken(ctx, oldToken.Token)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "token reused too soon")
	})

	t.Run("RotationDisabled", func(t *testing.T) {
		config := DefaultGourdianTokenConfig(testSymmetricKey)
		config.RefreshToken.RotationEnabled = false
		maker := createTestMaker(t, config)

		refreshToken, err := maker.CreateRefreshToken(ctx, uuid.New(), "rotation-test", uuid.New())
		assert.NoError(t, err)

		_, err = maker.RotateRefreshToken(ctx, refreshToken.Token)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "token rotation not enabled")
	})

	t.Run("ReuseProtection", func(t *testing.T) {
		config := DefaultGourdianTokenConfig(testSymmetricKey)
		config.RefreshToken.RotationEnabled = true
		config.RefreshToken.ReuseInterval = time.Minute
		maker := createTestMaker(t, config)

		userID := uuid.New()
		sessionID := uuid.New()

		// Create and rotate token
		oldToken, err := maker.CreateRefreshToken(ctx, userID, "reuse-test", sessionID)
		assert.NoError(t, err)

		_, err = maker.RotateRefreshToken(ctx, oldToken.Token)
		assert.NoError(t, err)

		// Immediate reuse attempt should fail
		_, err = maker.RotateRefreshToken(ctx, oldToken.Token)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "token reused too soon")
	})
}

func TestTokenMakerInitialization(t *testing.T) {
	t.Run("DefaultSymmetricConfig", func(t *testing.T) {
		config := DefaultGourdianTokenConfig(testSymmetricKey)
		maker := createTestMaker(t, config)
		assert.NotNil(t, maker)
		assert.Equal(t, jwt.SigningMethodHS256, maker.signingMethod)
	})

	t.Run("SymmetricWithDifferentAlgorithms", func(t *testing.T) {
		testCases := []struct {
			algorithm string
			method    jwt.SigningMethod
		}{
			{"HS256", jwt.SigningMethodHS256},
			{"HS384", jwt.SigningMethodHS384},
			{"HS512", jwt.SigningMethodHS512},
		}

		for _, tc := range testCases {
			t.Run(tc.algorithm, func(t *testing.T) {
				config := DefaultGourdianTokenConfig(testSymmetricKey)
				config.Algorithm = tc.algorithm
				maker := createTestMaker(t, config)
				assert.Equal(t, tc.method, maker.signingMethod)
			})
		}
	})

	t.Run("AsymmetricRSA", func(t *testing.T) {
		privatePath, publicPath := generateTempRSAPair(t)
		defer os.Remove(privatePath)
		defer os.Remove(publicPath)

		testCases := []struct {
			algorithm string
			method    jwt.SigningMethod
		}{
			{"RS256", jwt.SigningMethodRS256},
			{"RS384", jwt.SigningMethodRS384},
			{"RS512", jwt.SigningMethodRS512},
			{"PS256", jwt.SigningMethodPS256},
			{"PS384", jwt.SigningMethodPS384},
			{"PS512", jwt.SigningMethodPS512},
		}

		for _, tc := range testCases {
			t.Run(tc.algorithm, func(t *testing.T) {
				config := DefaultGourdianTokenConfig("")
				config.SigningMethod = Asymmetric
				config.Algorithm = tc.algorithm
				config.PrivateKeyPath = privatePath
				config.PublicKeyPath = publicPath
				maker := createTestMaker(t, config)
				assert.Equal(t, tc.method, maker.signingMethod)
				assert.IsType(t, &rsa.PrivateKey{}, maker.privateKey)
				assert.IsType(t, &rsa.PublicKey{}, maker.publicKey)
			})
		}
	})

	t.Run("AsymmetricECDSA", func(t *testing.T) {
		privatePath, publicPath := generateTempECDSAPair(t)
		defer os.Remove(privatePath)
		defer os.Remove(publicPath)

		testCases := []struct {
			algorithm string
			method    jwt.SigningMethod
		}{
			{"ES256", jwt.SigningMethodES256},
			{"ES384", jwt.SigningMethodES384},
			{"ES512", jwt.SigningMethodES512},
		}

		for _, tc := range testCases {
			t.Run(tc.algorithm, func(t *testing.T) {
				config := DefaultGourdianTokenConfig("")
				config.SigningMethod = Asymmetric
				config.Algorithm = tc.algorithm
				config.PrivateKeyPath = privatePath
				config.PublicKeyPath = publicPath
				maker := createTestMaker(t, config)
				assert.Equal(t, tc.method, maker.signingMethod)
				assert.IsType(t, &ecdsa.PrivateKey{}, maker.privateKey)
				assert.IsType(t, &ecdsa.PublicKey{}, maker.publicKey)
			})
		}
	})

	t.Run("AsymmetricEdDSA", func(t *testing.T) {
		privatePath, publicPath := generateTempEdDSAKeys(t)
		defer os.Remove(privatePath)
		defer os.Remove(publicPath)

		config := DefaultGourdianTokenConfig("")
		config.SigningMethod = Asymmetric
		config.Algorithm = "EdDSA"
		config.PrivateKeyPath = privatePath
		config.PublicKeyPath = publicPath
		maker := createTestMaker(t, config)
		assert.Equal(t, jwt.SigningMethodEdDSA, maker.signingMethod)
		assert.IsType(t, ed25519.PrivateKey{}, maker.privateKey)
		assert.IsType(t, ed25519.PublicKey{}, maker.publicKey)
	})

	t.Run("InvalidConfigurations", func(t *testing.T) {
		testCases := []struct {
			name        string
			config      GourdianTokenConfig
			expectedErr string
		}{
			{
				name: "EmptySymmetricKey",
				config: GourdianTokenConfig{
					SigningMethod: Symmetric,
					Algorithm:     "HS256",
					SymmetricKey:  "",
				},
				expectedErr: "symmetric key is required",
			},
			{
				name: "ShortSymmetricKey",
				config: GourdianTokenConfig{
					SigningMethod: Symmetric,
					Algorithm:     "HS256",
					SymmetricKey:  "too-short",
				},
				expectedErr: "symmetric key must be at least 32 bytes",
			},
			{
				name: "AsymmetricMissingPrivateKey",
				config: GourdianTokenConfig{
					SigningMethod:  Asymmetric,
					Algorithm:      "RS256",
					PublicKeyPath:  "public.pem",
					PrivateKeyPath: "",
				},
				expectedErr: "private and public key paths are required",
			},
			{
				name: "UnsupportedAlgorithm",
				config: GourdianTokenConfig{
					SigningMethod: Symmetric,
					Algorithm:     "UNSUPPORTED",
					SymmetricKey:  testSymmetricKey,
				},
				expectedErr: "algorithm UNSUPPORTED not compatible with symmetric signing",
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				ctx := context.Background()
				_, err := NewGourdianTokenMaker(ctx, tc.config, testRedisOptions())
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectedErr)
			})
		}
	})
}

// TestCreateAndVerifyAccessToken tests access token creation and verification
func TestCreateAndVerifyAccessToken(t *testing.T) {
	// Setup symmetric maker
	symmetricConfig := DefaultGourdianTokenConfig(testSymmetricKey)
	symmetricMaker, err := NewGourdianTokenMaker(context.Background(), symmetricConfig, testRedisOptions())
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
	asymmetricMaker, err := NewGourdianTokenMaker(context.Background(), asymmetricConfig, testRedisOptions())
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
			roles := []string{"admin"}
			sessionID := uuid.New()

			// Test CreateAccessToken
			resp, err := tc.maker.CreateAccessToken(context.Background(), userID, username, roles, sessionID)
			require.NoError(t, err)
			assert.NotEmpty(t, resp.Token)
			assert.Equal(t, userID, resp.Subject)
			assert.Equal(t, username, resp.Username)
			assert.Equal(t, sessionID, resp.SessionID)
			assert.Equal(t, roles, resp.Roles)
			assert.True(t, time.Now().Before(resp.ExpiresAt))
			assert.True(t, time.Now().After(resp.IssuedAt))

			// Test VerifyAccessToken
			claims, err := tc.maker.VerifyAccessToken(context.Background(), resp.Token)
			require.NoError(t, err)
			assert.Equal(t, userID, claims.Subject)
			assert.Equal(t, username, claims.Username)
			assert.Equal(t, sessionID, claims.SessionID)
			assert.Equal(t, roles, claims.Roles)
			assert.Equal(t, AccessToken, claims.TokenType)
			assert.True(t, time.Now().Before(claims.ExpiresAt))
			assert.True(t, time.Now().After(claims.IssuedAt))
		})
	}

	t.Run("Invalid Token - Tampered", func(t *testing.T) {
		resp, err := symmetricMaker.CreateAccessToken(context.Background(), uuid.New(), "user", []string{"role"}, uuid.New())
		require.NoError(t, err)

		// Tamper with the token
		tamperedToken := resp.Token[:len(resp.Token)-4] + "abcd"

		_, err = symmetricMaker.VerifyAccessToken(context.Background(), tamperedToken)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid token")
	})

	t.Run("Invalid Token - Expired", func(t *testing.T) {
		// Create a token with very short lifetime
		config := DefaultGourdianTokenConfig(testSymmetricKey)
		config.AccessToken.Duration = time.Millisecond
		maker, err := NewGourdianTokenMaker(context.Background(), config, testRedisOptions())
		require.NoError(t, err)

		resp, err := maker.CreateAccessToken(context.Background(), uuid.New(), "user", []string{"role"}, uuid.New())
		require.NoError(t, err)

		// Wait for it to expire
		time.Sleep(10 * time.Millisecond)

		_, err = maker.VerifyAccessToken(context.Background(), resp.Token)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "expired")
	})

	t.Run("Invalid Token - Wrong Type", func(t *testing.T) {
		// Create a refresh token but try to verify as access token
		resp, err := symmetricMaker.CreateRefreshToken(context.Background(), uuid.New(), "user", uuid.New())
		require.NoError(t, err)

		_, err = symmetricMaker.VerifyAccessToken(context.Background(), resp.Token)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid token type")
	})
}

// TestEnhancedTokenRotation tests advanced token rotation scenarios
func TestEnhancedTokenRotation(t *testing.T) {
	client := redisTestClient(t)
	defer client.Close()

	t.Run("Concurrent Rotation Attempts", func(t *testing.T) {
		config := DefaultGourdianTokenConfig(testSymmetricKey)
		config.RefreshToken.RotationEnabled = true
		config.RefreshToken.ReuseInterval = time.Second
		maker, err := NewGourdianTokenMaker(context.Background(), config, testRedisOptions())
		require.NoError(t, err)

		token, err := maker.CreateRefreshToken(context.Background(), uuid.New(), "user", uuid.New())
		require.NoError(t, err)

		var wg sync.WaitGroup
		results := make(chan error, 10)

		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, err := maker.RotateRefreshToken(context.Background(), token.Token)
				results <- err
			}()
		}

		wg.Wait()
		close(results)

		var successCount, failureCount int
		for err := range results {
			if err == nil {
				successCount++
			} else {
				failureCount++
				assert.Contains(t, err.Error(), "token reused too soon")
			}
		}

		assert.Equal(t, 1, successCount)
		assert.Equal(t, 9, failureCount)
	})

	t.Run("Rotation with Different Sessions", func(t *testing.T) {
		config := DefaultGourdianTokenConfig(testSymmetricKey)
		config.RefreshToken.RotationEnabled = true
		maker, err := NewGourdianTokenMaker(context.Background(), config, testRedisOptions())
		require.NoError(t, err)

		userID := uuid.New()
		session1 := uuid.New()
		token1, err := maker.CreateRefreshToken(context.Background(), userID, "user", session1)
		require.NoError(t, err)

		session2 := uuid.New()
		token2, err := maker.CreateRefreshToken(context.Background(), userID, "user", session2)
		require.NoError(t, err)

		_, err = maker.RotateRefreshToken(context.Background(), token1.Token)
		require.NoError(t, err)

		_, err = maker.RotateRefreshToken(context.Background(), token2.Token)
		require.NoError(t, err)
	})

	t.Run("Rotation Chain", func(t *testing.T) {
		config := DefaultGourdianTokenConfig(testSymmetricKey)
		config.RefreshToken.RotationEnabled = true
		maker, err := NewGourdianTokenMaker(context.Background(), config, testRedisOptions())
		require.NoError(t, err)

		// Create initial token
		token, err := maker.CreateRefreshToken(context.Background(), uuid.New(), "user", uuid.New())
		require.NoError(t, err)

		// Rotate multiple times
		for i := 0; i < 5; i++ {
			token, err = maker.RotateRefreshToken(context.Background(), token.Token)
			require.NoError(t, err)
		}

		// Verify the last rotated token
		_, err = maker.VerifyRefreshToken(context.Background(), token.Token)
		require.NoError(t, err)
	})
}

// TestNewGourdianTokenMaker tests the token maker initialization
func TestNewGourdianTokenMaker(t *testing.T) {
	t.Run("Symmetric HS256", func(t *testing.T) {
		config := DefaultGourdianTokenConfig(testSymmetricKey)
		maker, err := NewGourdianTokenMaker(context.Background(), config, testRedisOptions())
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
		maker, err := NewGourdianTokenMaker(context.Background(), config, testRedisOptions())
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
		maker, err := NewGourdianTokenMaker(context.Background(), config, testRedisOptions())
		require.NoError(t, err)
		assert.NotNil(t, maker)
	})

	t.Run("Invalid Config - Symmetric Key Too Short", func(t *testing.T) {
		config := DefaultGourdianTokenConfig("short")
		_, err := NewGourdianTokenMaker(context.Background(), config, testRedisOptions())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "symmetric key must be at least 32 bytes")
	})

	t.Run("Invalid Config - Missing Key Paths", func(t *testing.T) {
		config := GourdianTokenConfig{
			Algorithm:     "RS256",
			SigningMethod: Asymmetric,
		}
		_, err := NewGourdianTokenMaker(context.Background(), config, testRedisOptions())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "private and public key paths are required")
	})

	t.Run("Invalid Config - Unsupported Algorithm", func(t *testing.T) {
		config := GourdianTokenConfig{
			Algorithm:     "FOO256",
			SigningMethod: Symmetric,
			SymmetricKey:  testSymmetricKey,
		}
		_, err := NewGourdianTokenMaker(context.Background(), config, testRedisOptions())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not compatible with symmetric signing")
	})

	t.Run("Invalid Config - Insecure Key Permissions", func(t *testing.T) {
		privatePath, publicPath := generateTempRSAPair(t)

		// Make the private key too permissive (world-writable)
		require.NoError(t, os.Chmod(privatePath, 0777))

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

		_, err := NewGourdianTokenMaker(context.Background(), config, testRedisOptions())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "insecure private key file permissions")
	})

	t.Run("Invalid Config - Mixed Key Configuration", func(t *testing.T) {
		privatePath, publicPath := generateTempRSAPair(t)
		config := GourdianTokenConfig{
			Algorithm:      "HS256",
			SigningMethod:  Symmetric,
			SymmetricKey:   testSymmetricKey,
			PrivateKeyPath: privatePath, // Should cause error for symmetric
			PublicKeyPath:  publicPath,  // Should cause error for symmetric
		}
		_, err := NewGourdianTokenMaker(context.Background(), config, testRedisOptions())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "private and public key paths must be empty for symmetric signing")
	})

	t.Run("Invalid Config - Algorithm/Signing Method Mismatch", func(t *testing.T) {
		config := GourdianTokenConfig{
			Algorithm:     "RS256", // RSA algorithm
			SigningMethod: Symmetric,
			SymmetricKey:  testSymmetricKey,
		}
		_, err := NewGourdianTokenMaker(context.Background(), config, testRedisOptions())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "algorithm RS256 not compatible with symmetric signing")
	})

	t.Run("Rotation Enabled Without Redis", func(t *testing.T) {
		config := DefaultGourdianTokenConfig(testSymmetricKey)
		config.RefreshToken.RotationEnabled = true
		_, err := NewGourdianTokenMaker(context.Background(), config, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "redis options required for token rotation/revocation")
	})

	t.Run("Valid Rotation Configuration", func(t *testing.T) {
		config := DefaultGourdianTokenConfig(testSymmetricKey)
		config.RefreshToken.RotationEnabled = true
		maker, err := NewGourdianTokenMaker(context.Background(), config, testRedisOptions())
		require.NoError(t, err)
		assert.NotNil(t, maker)
		assert.NotNil(t, maker.(*JWTMaker).redisClient)
	})
}

// TestRedisConnectionLoss tests behavior when Redis connection is lost
func TestRedisConnectionLoss(t *testing.T) {
	// Create a mock Redis client that will fail all operations
	failingRedisOpts := &redis.Options{
		Addr: "localhost:9999", // Non-existent Redis server
	}

	t.Run("Rotation with Redis Down", func(t *testing.T) {
		config := DefaultGourdianTokenConfig(testSymmetricKey)
		config.RefreshToken.RotationEnabled = true

		// Create maker with failing Redis options
		maker, err := NewGourdianTokenMaker(context.Background(), config, failingRedisOpts)
		require.NoError(t, err)

		// Create a valid token
		token, err := maker.CreateRefreshToken(context.Background(), uuid.New(), "user", uuid.New())
		require.NoError(t, err)

		// Try to rotate - should fail immediately since Redis is unreachable
		_, err = maker.RotateRefreshToken(context.Background(), token.Token)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "connection refused") // Or other connection error
	})

	t.Run("Revocation with Redis Down", func(t *testing.T) {
		config := DefaultGourdianTokenConfig(testSymmetricKey)
		config.AccessToken.RevocationEnabled = true

		// Create maker with failing Redis options
		maker, err := NewGourdianTokenMaker(context.Background(), config, failingRedisOpts)
		require.NoError(t, err)

		// Create a valid token
		token, err := maker.CreateAccessToken(context.Background(), uuid.New(), "user", []string{"role"}, uuid.New())
		require.NoError(t, err)

		// Try to revoke - should fail immediately since Redis is unreachable
		err = maker.RevokeAccessToken(context.Background(), token.Token)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "connection refused") // Or other connection error
	})
}

func TestTokenCreationAndVerification(t *testing.T) {
	ctx := context.Background()

	t.Run("SymmetricHS256", func(t *testing.T) {
		config := DefaultGourdianTokenConfig(testSymmetricKey)
		maker := createTestMaker(t, config)

		userID := uuid.New()
		sessionID := uuid.New()
		roles := []string{"admin", "user"}

		t.Run("CreateAndVerifyAccessToken", func(t *testing.T) {
			accessToken, err := maker.CreateAccessToken(ctx, userID, "testuser", roles, sessionID)
			assert.NoError(t, err)
			assert.NotEmpty(t, accessToken.Token)

			claims, err := maker.VerifyAccessToken(ctx, accessToken.Token)
			assert.NoError(t, err)
			assert.Equal(t, userID, claims.Subject)
			assert.Equal(t, "testuser", claims.Username)
			assert.Equal(t, sessionID, claims.SessionID)
			assert.Equal(t, roles, claims.Roles)
			assert.Equal(t, AccessToken, claims.TokenType)
		})

		t.Run("CreateAndVerifyRefreshToken", func(t *testing.T) {
			refreshToken, err := maker.CreateRefreshToken(ctx, userID, "testuser", sessionID)
			assert.NoError(t, err)
			assert.NotEmpty(t, refreshToken.Token)

			claims, err := maker.VerifyRefreshToken(ctx, refreshToken.Token)
			assert.NoError(t, err)
			assert.Equal(t, userID, claims.Subject)
			assert.Equal(t, "testuser", claims.Username)
			assert.Equal(t, sessionID, claims.SessionID)
			assert.Equal(t, RefreshToken, claims.TokenType)
		})
	})

	t.Run("AsymmetricRS256", func(t *testing.T) {
		privatePath, publicPath := generateTempRSAPair(t)
		defer os.Remove(privatePath)
		defer os.Remove(publicPath)

		config := DefaultGourdianTokenConfig("")
		config.SigningMethod = Asymmetric
		config.Algorithm = "RS256"
		config.PrivateKeyPath = privatePath
		config.PublicKeyPath = publicPath
		maker := createTestMaker(t, config)

		userID := uuid.New()
		sessionID := uuid.New()
		roles := []string{"admin"}

		t.Run("CreateAndVerifyAccessToken", func(t *testing.T) {
			accessToken, err := maker.CreateAccessToken(ctx, userID, "rsa-user", roles, sessionID)
			assert.NoError(t, err)
			assert.NotEmpty(t, accessToken.Token)

			claims, err := maker.VerifyAccessToken(ctx, accessToken.Token)
			assert.NoError(t, err)
			assert.Equal(t, userID, claims.Subject)
			assert.Equal(t, "rsa-user", claims.Username)
			assert.Equal(t, sessionID, claims.SessionID)
			assert.Equal(t, roles, claims.Roles)
		})
	})

	t.Run("InvalidTokens", func(t *testing.T) {
		config := DefaultGourdianTokenConfig(testSymmetricKey)
		maker := createTestMaker(t, config)

		t.Run("ExpiredToken", func(t *testing.T) {
			// Create a token that expired 1 hour ago
			claims := AccessTokenClaims{
				ID:        uuid.New(),
				Subject:   uuid.New(),
				Username:  "expired",
				SessionID: uuid.New(),
				IssuedAt:  time.Now().Add(-2 * time.Hour),
				ExpiresAt: time.Now().Add(-1 * time.Hour),
				TokenType: AccessToken,
				Roles:     []string{"user"},
			}

			token := jwt.NewWithClaims(maker.signingMethod, toMapClaims(claims))
			tokenString, err := token.SignedString(maker.privateKey)
			assert.NoError(t, err)

			_, err = maker.VerifyAccessToken(ctx, tokenString)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "token has expired")
		})

		t.Run("InvalidSignature", func(t *testing.T) {
			// Create a valid token
			accessToken, err := maker.CreateAccessToken(ctx, uuid.New(), "testuser", []string{"user"}, uuid.New())
			assert.NoError(t, err)

			// Tamper with the token by changing a character in the signature
			tamperedToken := accessToken.Token[:len(accessToken.Token)-2] + "XX"

			_, err = maker.VerifyAccessToken(ctx, tamperedToken)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "signature is invalid")
		})

		t.Run("MissingRequiredClaims", func(t *testing.T) {
			// Create a token missing the 'exp' claim
			claims := jwt.MapClaims{
				"jti": uuid.New().String(),
				"sub": uuid.New().String(),
				"usr": "testuser",
				"sid": uuid.New().String(),
				"iat": time.Now().Unix(),
				"typ": string(AccessToken),
				"rls": []string{"user"},
			}

			token := jwt.NewWithClaims(maker.signingMethod, claims)
			tokenString, err := token.SignedString(maker.privateKey)
			assert.NoError(t, err)

			_, err = maker.VerifyAccessToken(ctx, tokenString)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "missing required claim: exp")
		})
	})
}

// TestClaimValidation tests various claim validation scenarios
func TestClaimValidation(t *testing.T) {
	config := DefaultGourdianTokenConfig(testSymmetricKey)
	maker, err := NewGourdianTokenMaker(context.Background(), config, testRedisOptions())
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
			{"Missing RLS", jwt.MapClaims{"jti": uuid.New().String(), "sub": uuid.New().String(), "usr": "test", "typ": "access", "sid": uuid.New().String(), "iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix()}, "missing roles claim in access token"}}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				token := jwt.NewWithClaims(jwt.SigningMethodHS256, tt.claims)
				tokenString, _ := token.SignedString([]byte(config.SymmetricKey))
				_, err := maker.VerifyAccessToken(context.Background(), tokenString)
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
					"rls":    []string{"role"},
					tt.claim: tt.value,
				}
				token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
				tokenString, _ := token.SignedString([]byte(config.SymmetricKey))
				_, err := maker.VerifyAccessToken(context.Background(), tokenString)
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.error)
			})
		}
	})

	t.Run("Invalid Timestamps", func(t *testing.T) {
		tests := []struct {
			name  string
			claim string
			value interface{}
			error string
		}{
			{"Invalid IAT", "iat", "not-a-number", "invalid timestamp format"},
			{"Invalid EXP", "exp", "not-a-number", "invalid timestamp format"},
			{"Missing IAT", "iat", nil, "missing required claim: iat"},
			{"Missing EXP", "exp", nil, "missing required claim: exp"},
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
					"rls":    []string{"role"},
					tt.claim: tt.value,
				}
				token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
				tokenString, _ := token.SignedString([]byte(config.SymmetricKey))
				_, err := maker.VerifyAccessToken(context.Background(), tokenString)
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.error)
			})
		}
	})
}

// // TestEdgeCases tests various edge cases in token handling
// func TestEdgeCases(t *testing.T) {
// 	t.Run("Empty Token String", func(t *testing.T) {
// 		config := DefaultGourdianTokenConfig(testSymmetricKey)
// 		maker, err := NewGourdianTokenMaker(context.Background(), config, testRedisOptions())
// 		require.NoError(t, err)

// 		_, err = maker.VerifyAccessToken(context.Background(), "")
// 		assert.Error(t, err)
// 		assert.Contains(t, err.Error(), "token contains an invalid number of segments")
// 	})

// 	t.Run("Malformed Token", func(t *testing.T) {
// 		config := DefaultGourdianTokenConfig(testSymmetricKey)
// 		maker, err := NewGourdianTokenMaker(context.Background(), config, testRedisOptions())
// 		require.NoError(t, err)

// 		_, err = maker.VerifyAccessToken(context.Background(), "header.claims.signature")
// 		assert.Error(t, err)
// 	})

// 	t.Run("Expired Token", func(t *testing.T) {
// 		config := DefaultGourdianTokenConfig(testSymmetricKey)
// 		config.AccessToken.Duration = -time.Hour // Force expired
// 		maker, err := NewGourdianTokenMaker(context.Background(), config, testRedisOptions())
// 		require.NoError(t, err)

// 		token, err := maker.CreateAccessToken(
// 			context.Background(),
// 			uuid.New(),
// 			"user",
// 			[]string{"role"},
// 			uuid.New(),
// 		)
// 		require.NoError(t, err)

// 		_, err = maker.VerifyAccessToken(context.Background(), token.Token)
// 		require.Error(t, err)
// 		assert.Contains(t, err.Error(), "expired")
// 	})

// 	t.Run("Future Issued At", func(t *testing.T) {
// 		config := DefaultGourdianTokenConfig(testSymmetricKey)
// 		maker, err := NewGourdianTokenMaker(context.Background(), config, testRedisOptions())
// 		require.NoError(t, err)

// 		claims := AccessTokenClaims{
// 			ID:        uuid.New(),
// 			Subject:   uuid.New(),
// 			Username:  "user",
// 			SessionID: uuid.New(),
// 			IssuedAt:  time.Now().Add(time.Hour), // Future
// 			ExpiresAt: time.Now().Add(2 * time.Hour),
// 			TokenType: AccessToken,
// 			Roles:     []string{"role"},
// 		}

// 		token := jwt.NewWithClaims(jwt.SigningMethodHS256, toMapClaims(claims))
// 		tokenString, _ := token.SignedString([]byte(config.SymmetricKey))

// 		_, err = maker.VerifyAccessToken(context.Background(), tokenString)
// 		assert.Error(t, err)
// 		assert.Contains(t, err.Error(), "token issued in the future")
// 	})

// 	t.Run("Token with Empty Signature", func(t *testing.T) {
// 		config := DefaultGourdianTokenConfig(testSymmetricKey)
// 		maker, err := NewGourdianTokenMaker(context.Background(), config, testRedisOptions())
// 		require.NoError(t, err)

// 		claims := AccessTokenClaims{
// 			ID:        uuid.New(),
// 			Subject:   uuid.New(),
// 			Username:  "user",
// 			SessionID: uuid.New(),
// 			IssuedAt:  time.Now(),
// 			ExpiresAt: time.Now().Add(time.Hour),
// 			TokenType: AccessToken,
// 			Roles:     []string{"role"},
// 		}

// 		token := jwt.NewWithClaims(jwt.SigningMethodHS256, toMapClaims(claims))

// 		// Manually construct token parts
// 		header := `{"alg":"HS256","typ":"JWT"}`
// 		payload, err := token.Claims.(jwt.MapClaims).MarshalJSON()
// 		require.NoError(t, err)

// 		// Encode header and payload without signature
// 		headerEncoded := jwt.EncodeSegment([]byte(header))
// 		payloadEncoded := jwt.EncodeSegment(payload)
// 		tokenString := headerEncoded + "." + payloadEncoded + "."

// 		_, err = maker.VerifyAccessToken(context.Background(), tokenString)
// 		assert.Error(t, err)
// 		assert.Contains(t, err.Error(), "signature is invalid") // Changed expected error
// 	})
// }

// // TestRedisCleanup tests the background cleanup processes
// func TestRedisCleanup(t *testing.T) {
// 	client := testRedisClient(t)
// 	defer client.Close()

// 	ctx, cancel := context.WithCancel(context.Background())
// 	defer cancel()

// 	t.Run("Cleanup Rotated Tokens", func(t *testing.T) {
// 		config := DefaultGourdianTokenConfig(testSymmetricKey)
// 		config.RefreshToken.RotationEnabled = true
// 		maker, err := NewGourdianTokenMaker(ctx, config, testRedisOptions())
// 		require.NoError(t, err)

// 		// Create a rotated token entry with short TTL
// 		err = maker.redisClient.Set(ctx, "rotated:test-token", "1", time.Second).Err()
// 		require.NoError(t, err)

// 		// Wait for cleanup cycle
// 		time.Sleep(2 * time.Second)

// 		// Verify the entry was cleaned up
// 		exists, err := maker.redisClient.Exists(ctx, "rotated:test-token").Result()
// 		require.NoError(t, err)
// 		assert.Equal(t, int64(0), exists)
// 	})

// 	t.Run("Cleanup Revoked Tokens", func(t *testing.T) {
// 		config := DefaultGourdianTokenConfig(testSymmetricKey)
// 		config.AccessToken.RevocationEnabled = true
// 		maker, err := NewGourdianTokenMaker(ctx, config, testRedisOptions())
// 		require.NoError(t, err)

// 		// Create a revoked token entry with short TTL
// 		err = maker.redisClient.Set(ctx, "revoked:access:test-token", "1", time.Second).Err()
// 		require.NoError(t, err)

// 		// Wait for cleanup cycle
// 		time.Sleep(2 * time.Second)

// 		// Verify the entry was cleaned up
// 		exists, err := maker.redisClient.Exists(ctx, "revoked:access:test-token").Result()
// 		require.NoError(t, err)
// 		assert.Equal(t, int64(0), exists)
// 	})
// }
