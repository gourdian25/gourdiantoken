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
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
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

func createTestMaker(t *testing.T, config GourdianTokenConfig) *JWTMaker {
	t.Helper()

	ctx := context.Background()
	maker, err := NewGourdianTokenMaker(ctx, config, testRedisOptions())
	require.NoError(t, err)
	return maker.(*JWTMaker)
}

func redisTestClient(t *testing.T) *redis.Client {
	client := redis.NewClient(testRedisOptions())
	_, err := client.Ping(context.Background()).Result()
	if err != nil {
		t.Skip("Redis not available, skipping test")
	}
	return client
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

func generateTempEdDSAKeys(t *testing.T) (privateKeyPath, publicKeyPath string) {
	t.Helper()

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	// Create temp files
	privateKeyFile, err := os.CreateTemp("", "ed25519-private-*.pem")
	require.NoError(t, err)
	defer privateKeyFile.Close()

	publicKeyFile, err := os.CreateTemp("", "ed25519-public-*.pem")
	require.NoError(t, err)
	defer publicKeyFile.Close()

	// Encode private key
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	require.NoError(t, err)
	privateKeyBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyBytes,
	}
	err = pem.Encode(privateKeyFile, privateKeyBlock)
	require.NoError(t, err)

	// Encode public key
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	require.NoError(t, err)
	publicKeyBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}
	err = pem.Encode(publicKeyFile, publicKeyBlock)
	require.NoError(t, err)

	return privateKeyFile.Name(), publicKeyFile.Name()
}

func generateRSAKey(bits int) *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		panic(err)
	}
	return key
}

func generateECDSAKey(curve elliptic.Curve) *ecdsa.PrivateKey {
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		panic(err)
	}
	return key
}

func writeTempKeyFiles(t testing.TB, key interface{}) (privatePath, publicPath string) {
	t.Helper()
	tempDir := t.TempDir()

	switch k := key.(type) {
	case *rsa.PrivateKey:
		privateBytes := x509.MarshalPKCS1PrivateKey(k)
		privateBlock := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: privateBytes}
		privatePath = filepath.Join(tempDir, "private.pem")
		require.NoError(t, os.WriteFile(privatePath, pem.EncodeToMemory(privateBlock), 0600))

		publicBytes, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
		require.NoError(t, err)
		publicBlock := &pem.Block{Type: "PUBLIC KEY", Bytes: publicBytes}
		publicPath = filepath.Join(tempDir, "public.pem")
		require.NoError(t, os.WriteFile(publicPath, pem.EncodeToMemory(publicBlock), 0644))

	case *ecdsa.PrivateKey:
		privateBytes, err := x509.MarshalECPrivateKey(k)
		require.NoError(t, err)
		privateBlock := &pem.Block{Type: "EC PRIVATE KEY", Bytes: privateBytes}
		privatePath = filepath.Join(tempDir, "ec_private.pem")
		require.NoError(t, os.WriteFile(privatePath, pem.EncodeToMemory(privateBlock), 0600))

		publicBytes, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
		require.NoError(t, err)
		publicBlock := &pem.Block{Type: "PUBLIC KEY", Bytes: publicBytes}
		publicPath = filepath.Join(tempDir, "ec_public.pem")
		require.NoError(t, os.WriteFile(publicPath, pem.EncodeToMemory(publicBlock), 0644))
	}

	return privatePath, publicPath
}

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

		require.Equal(t, 10, successCount+failureCount)
		require.GreaterOrEqual(t, failureCount, 8)

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
