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
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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

func TestTokenEdgeCases(t *testing.T) {
	t.Run("Token with Empty UUID", func(t *testing.T) {
		maker, err := DefaultGourdianTokenMaker(context.Background(), testSymmetricKey, nil)
		require.NoError(t, err)

		emptyUUID := uuid.UUID{}
		_, err = maker.CreateAccessToken(context.Background(), emptyUUID, "user", []string{"role"}, uuid.New())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid user ID")
	})

	t.Run("Token with Empty Roles", func(t *testing.T) {
		maker, err := DefaultGourdianTokenMaker(context.Background(), testSymmetricKey, nil)
		require.NoError(t, err)

		_, err = maker.CreateAccessToken(context.Background(), uuid.New(), "user", []string{}, uuid.New())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "at least one role must be provided")
	})

	t.Run("Token with Empty Role String", func(t *testing.T) {
		maker, err := DefaultGourdianTokenMaker(context.Background(), testSymmetricKey, nil)
		require.NoError(t, err)

		_, err = maker.CreateAccessToken(context.Background(), uuid.New(), "user", []string{""}, uuid.New())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "roles cannot contain empty strings")
	})

	t.Run("Token with Very Long Username", func(t *testing.T) {
		maker, err := DefaultGourdianTokenMaker(context.Background(), testSymmetricKey, nil)
		require.NoError(t, err)

		longUsername := strings.Repeat("a", 1025)
		_, err = maker.CreateAccessToken(context.Background(), uuid.New(), longUsername, []string{"role"}, uuid.New())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "username too long")
	})
}

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

		hmacMaker, err := DefaultGourdianTokenMaker(context.Background(), testSymmetricKey, nil)
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

		maker, err := DefaultGourdianTokenMaker(context.Background(), testSymmetricKey, nil)
		require.NoError(t, err)

		_, err = maker.VerifyAccessToken(context.Background(), tokenString)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unexpected signing method")
	})

	t.Run("Token Replay Attack", func(t *testing.T) {
		client := redisTestClient(t)
		defer client.Close()

		maker, err := DefaultGourdianTokenMaker(context.Background(), testSymmetricKey, testRedisOptions())
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

func TestCreateAndVerifyRefreshToken(t *testing.T) {
	// Setup symmetric maker
	symmetricMaker, err := DefaultGourdianTokenMaker(context.Background(), testSymmetricKey, testRedisOptions())
	require.NoError(t, err)

	// Setup asymmetric maker
	privatePath, publicPath := generateTempRSAPair(t)
	asymmetricConfig := GourdianTokenConfig{
		Algorithm:                "RS256",
		SigningMethod:            Asymmetric,
		PrivateKeyPath:           privatePath,
		PublicKeyPath:            publicPath,
		RotationEnabled:          true,
		AccessExpiryDuration:     time.Hour,
		AccessMaxLifetimeExpiry:  24 * time.Hour,
		RefreshExpiryDuration:    24 * time.Hour,
		RefreshMaxLifetimeExpiry: 7 * 24 * time.Hour,
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
		config.RefreshExpiryDuration = time.Millisecond
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

func TestDefaultConfig(t *testing.T) {
	t.Run("Valid Default Config", func(t *testing.T) {
		config := DefaultGourdianTokenConfig(testSymmetricKey)
		assert.Equal(t, "HS256", config.Algorithm)
		assert.Equal(t, Symmetric, config.SigningMethod)
		assert.Equal(t, 30*time.Minute, config.AccessExpiryDuration)
		assert.Equal(t, 24*time.Hour, config.AccessMaxLifetimeExpiry)
		assert.Equal(t, []string{"HS256", "RS256", "ES256", "PS256"}, config.AllowedAlgorithms)
		assert.Equal(t, []string{"iss", "aud", "nbf", "mle"}, config.RequiredClaims)
		assert.Equal(t, 7*24*time.Hour, config.RefreshExpiryDuration)
		assert.Equal(t, 30*24*time.Hour, config.RefreshMaxLifetimeExpiry)
		assert.Equal(t, 5*time.Minute, config.RefreshReuseInterval)
		assert.False(t, config.RotationEnabled)
	})

	t.Run("Invalid Key Length", func(t *testing.T) {
		config := DefaultGourdianTokenConfig("short")
		_, err := NewGourdianTokenMaker(context.Background(), config, testRedisOptions())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "symmetric key must be at least 32 bytes")
	})
}

func TestTokenRotation_EdgeCases(t *testing.T) {
	t.Run("Rotation with Disabled Config", func(t *testing.T) {
		config := DefaultGourdianTokenConfig(testSymmetricKey)
		config.RotationEnabled = false
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
		config.RotationEnabled = true
		maker, err := NewGourdianTokenMaker(context.Background(), config, testRedisOptions())
		require.NoError(t, err)

		_, err = maker.RotateRefreshToken(context.Background(), "invalid.token.string")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid token")
	})

	t.Run("Rotation with Expired Token", func(t *testing.T) {
		config := DefaultGourdianTokenConfig(testSymmetricKey)
		config.RotationEnabled = true
		config.RefreshExpiryDuration = time.Millisecond // Very short expiration
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

func TestConfigValidation(t *testing.T) {
	t.Run("Valid Symmetric Config", func(t *testing.T) {
		config := GourdianTokenConfig{
			Algorithm:                "HS256",
			SigningMethod:            Symmetric,
			SymmetricKey:             testSymmetricKey,
			PrivateKeyPath:           "",
			PublicKeyPath:            "",
			AccessExpiryDuration:     time.Hour,
			AccessMaxLifetimeExpiry:  24 * time.Hour,
			RefreshExpiryDuration:    24 * time.Hour,
			RefreshMaxLifetimeExpiry: 7 * 24 * time.Hour,
		}
		err := validateConfig(&config)
		assert.NoError(t, err)
	})

	t.Run("Valid Asymmetric Config", func(t *testing.T) {
		privatePath, publicPath := generateTempRSAPair(t)
		config := GourdianTokenConfig{
			Algorithm:                "RS256",
			SigningMethod:            Asymmetric,
			SymmetricKey:             "",
			PrivateKeyPath:           privatePath,
			PublicKeyPath:            publicPath,
			AccessExpiryDuration:     time.Hour,
			AccessMaxLifetimeExpiry:  24 * time.Hour,
			RefreshExpiryDuration:    24 * time.Hour,
			RefreshMaxLifetimeExpiry: 7 * 24 * time.Hour,
		}
		err := validateConfig(&config)
		assert.NoError(t, err)
	})

	t.Run("Invalid Config - Mixed Key Configuration", func(t *testing.T) {
		privatePath, publicPath := generateTempRSAPair(t)
		config := GourdianTokenConfig{
			Algorithm:               "HS256",
			SigningMethod:           Symmetric,
			SymmetricKey:            testSymmetricKey,
			PrivateKeyPath:          privatePath, // This should cause validation to fail
			PublicKeyPath:           publicPath,  // This should cause validation to fail
			AccessExpiryDuration:    time.Hour,
			AccessMaxLifetimeExpiry: 24 * time.Hour,
		}
		_, err := NewGourdianTokenMaker(context.Background(), config, testRedisOptions())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "private and public key paths must be empty for symmetric signing")
	})

	t.Run("Invalid Algorithm for Method", func(t *testing.T) {
		config := GourdianTokenConfig{
			Algorithm:            "RS256", // RSA algorithm
			SigningMethod:        Symmetric,
			SymmetricKey:         testSymmetricKey,
			AccessExpiryDuration: time.Hour,
		}
		err := validateConfig(&config)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "algorithm RS256 not compatible with symmetric signing")
	})
}

func TestTokenRotation_ReuseInterval(t *testing.T) {
	client := redisTestClient(t)
	defer client.Close()

	config := DefaultGourdianTokenConfig(testSymmetricKey)
	config.RotationEnabled = true
	config.RefreshReuseInterval = time.Second
	// Ensure refresh duration is less than max lifetime
	config.RefreshExpiryDuration = 30 * time.Minute
	config.RefreshMaxLifetimeExpiry = time.Hour

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

func TestTokenClaimsValidation(t *testing.T) {
	config := DefaultGourdianTokenConfig(testSymmetricKey)
	maker, err := NewGourdianTokenMaker(context.Background(), config, testRedisOptions())
	require.NoError(t, err)

	// Common claims that satisfy all required claims
	baseClaims := jwt.MapClaims{
		"iss": config.Issuer,
		"aud": config.Audience,
		"nbf": time.Now().Unix(),
		"mle": time.Now().Add(time.Hour).Unix(),
	}

	t.Run("Missing Required Claim", func(t *testing.T) {
		claims := jwt.MapClaims{}
		for k, v := range baseClaims {
			claims[k] = v
		}
		claims["jti"] = uuid.New().String()
		claims["usr"] = "testuser"
		claims["sid"] = uuid.New().String()
		claims["iat"] = time.Now().Unix()
		claims["exp"] = time.Now().Add(time.Hour).Unix()
		claims["typ"] = string(AccessToken)
		claims["rls"] = []string{"admin"}
		// Remove one required claim - now removing "sub" which is actually checked first
		delete(claims, "sub")

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err := token.SignedString([]byte(config.SymmetricKey))
		require.NoError(t, err)

		_, err = maker.VerifyAccessToken(context.Background(), tokenString)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "missing required claim: sub")
	})

	t.Run("Invalid Token Type", func(t *testing.T) {
		claims := jwt.MapClaims{}
		for k, v := range baseClaims {
			claims[k] = v
		}
		claims["jti"] = uuid.New().String()
		claims["sub"] = uuid.New().String()
		claims["usr"] = "testuser"
		claims["sid"] = uuid.New().String()
		claims["iat"] = time.Now().Unix()
		claims["exp"] = time.Now().Add(time.Hour).Unix()
		claims["typ"] = "invalid" // Invalid type
		claims["rls"] = []string{"admin"}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err := token.SignedString([]byte(config.SymmetricKey))
		require.NoError(t, err)

		_, err = maker.VerifyAccessToken(context.Background(), tokenString)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid token type")
	})

	t.Run("Token From Future", func(t *testing.T) {
		claims := jwt.MapClaims{}
		for k, v := range baseClaims {
			claims[k] = v
		}
		claims["jti"] = uuid.New().String()
		claims["sub"] = uuid.New().String()
		claims["usr"] = "testuser"
		claims["sid"] = uuid.New().String()
		claims["iat"] = time.Now().Add(time.Hour).Unix() // Future iat
		claims["exp"] = time.Now().Add(2 * time.Hour).Unix()
		claims["typ"] = string(AccessToken)
		claims["rls"] = []string{"admin"}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err := token.SignedString([]byte(config.SymmetricKey))
		require.NoError(t, err)

		_, err = maker.VerifyAccessToken(context.Background(), tokenString)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "token issued in the future")
	})

	t.Run("Invalid Roles Claim", func(t *testing.T) {
		claims := jwt.MapClaims{}
		for k, v := range baseClaims {
			claims[k] = v
		}
		claims["jti"] = uuid.New().String()
		claims["sub"] = uuid.New().String()
		claims["usr"] = "testuser"
		claims["sid"] = uuid.New().String()
		claims["iat"] = time.Now().Unix()
		claims["exp"] = time.Now().Add(time.Hour).Unix()
		claims["typ"] = string(AccessToken)
		claims["rls"] = "not-an-array" // Invalid roles type

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err := token.SignedString([]byte(config.SymmetricKey))
		require.NoError(t, err)

		_, err = maker.VerifyAccessToken(context.Background(), tokenString)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid roles type")
	})
}
