package gourdiantoken

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func BenchmarkCreateAccessToken(b *testing.B) {
	// Setup symmetric maker
	symmetricConfig := DefaultGourdianTokenConfig("test-secret-32-bytes-long-1234567890")
	symmetricMaker, _ := NewGourdianTokenMaker(symmetricConfig, testRedisOptions())

	// Setup asymmetric maker
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	asymmetricConfig := GourdianTokenConfig{
		Algorithm:     "RS256",
		SigningMethod: Asymmetric,
		AccessToken: AccessTokenConfig{
			Duration: time.Hour,
		},
	}
	asymmetricMaker := &JWTMaker{
		config:        asymmetricConfig,
		signingMethod: jwt.SigningMethodRS256,
		privateKey:    privateKey,
		publicKey:     &privateKey.PublicKey,
	}

	userID := uuid.New()
	username := "benchuser"
	role := "user"
	sessionID := uuid.New()

	b.Run("Symmetric", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := symmetricMaker.CreateAccessToken(context.Background(), userID, username, role, sessionID)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("Asymmetric", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := asymmetricMaker.CreateAccessToken(context.Background(), userID, username, role, sessionID)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkVerifyAccessToken(b *testing.B) {
	// Setup symmetric maker
	symmetricConfig := DefaultGourdianTokenConfig("test-secret-32-bytes-long-1234567890")
	symmetricMaker, _ := NewGourdianTokenMaker(symmetricConfig, testRedisOptions())

	// Setup asymmetric maker
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	asymmetricConfig := GourdianTokenConfig{
		Algorithm:     "RS256",
		SigningMethod: Asymmetric,
		AccessToken: AccessTokenConfig{
			Duration: time.Hour,
		},
	}
	asymmetricMaker := &JWTMaker{
		config:        asymmetricConfig,
		signingMethod: jwt.SigningMethodRS256,
		privateKey:    privateKey,
		publicKey:     &privateKey.PublicKey,
	}

	userID := uuid.New()
	username := "benchuser"
	role := "user"
	sessionID := uuid.New()

	symToken, _ := symmetricMaker.CreateAccessToken(context.Background(), userID, username, role, sessionID)
	asymToken, _ := asymmetricMaker.CreateAccessToken(context.Background(), userID, username, role, sessionID)

	b.Run("Symmetric", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := symmetricMaker.VerifyAccessToken(symToken.Token)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("Asymmetric", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := asymmetricMaker.VerifyAccessToken(asymToken.Token)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkTokenOperations(b *testing.B) {
	// Setup for different key sizes and algorithms
	benchmarks := []struct {
		name       string
		keySize    int
		algorithm  string
		signingKey interface{}
	}{
		{"HMAC-256", 32, "HS256", []byte("test-secret-32-bytes-long-1234567890")},
		{"HMAC-384", 48, "HS384", []byte("test-secret-48-bytes-long-123456789012345678901234")},
		{"HMAC-512", 64, "HS512", []byte("test-secret-64-bytes-long-123456789012345678901234567890123456789012345678901234")},
		{"RSA-2048", 2048, "RS256", generateRSAKey(2048)},
		{"RSA-4096", 4096, "RS256", generateRSAKey(4096)},
		{"ECDSA-P256", 256, "ES256", generateECDSAKey(elliptic.P256())},
		{"ECDSA-P384", 384, "ES384", generateECDSAKey(elliptic.P384())},
	}

	for _, bb := range benchmarks {
		b.Run(bb.name, func(b *testing.B) {
			var maker GourdianTokenMaker
			var err error

			switch k := bb.signingKey.(type) {
			case []byte:
				config := DefaultGourdianTokenConfig(string(k))
				config.Algorithm = bb.algorithm
				config.AccessToken.Duration = time.Hour // Set longer duration for benchmarks
				maker, err = NewGourdianTokenMaker(config, nil)
			case *rsa.PrivateKey:
				privatePath, publicPath := writeTempKeyFiles(b, k)
				config := GourdianTokenConfig{
					Algorithm:      bb.algorithm,
					SigningMethod:  Asymmetric,
					PrivateKeyPath: privatePath,
					PublicKeyPath:  publicPath,
					AccessToken: AccessTokenConfig{
						Duration:    24 * time.Hour, // Longer duration for asymmetric
						MaxLifetime: 7 * 24 * time.Hour,
					},
				}
				maker, err = NewGourdianTokenMaker(config, nil)
			case *ecdsa.PrivateKey:
				privatePath, publicPath := writeTempKeyFiles(b, k)
				config := GourdianTokenConfig{
					Algorithm:      bb.algorithm,
					SigningMethod:  Asymmetric,
					PrivateKeyPath: privatePath,
					PublicKeyPath:  publicPath,
					AccessToken: AccessTokenConfig{
						Duration:    24 * time.Hour, // Longer duration for asymmetric
						MaxLifetime: 7 * 24 * time.Hour,
					},
				}
				maker, err = NewGourdianTokenMaker(config, nil)
			}
			require.NoError(b, err)

			jwtMaker, ok := maker.(*JWTMaker)
			if !ok {
				b.Fatal("expected *JWTMaker implementation")
			}

			userID := uuid.New()
			username := "benchuser"
			role := "admin"
			sessionID := uuid.New()

			b.Run("Create", func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					_, err := jwtMaker.CreateAccessToken(context.Background(), userID, username, role, sessionID)
					if err != nil {
						b.Fatal(err)
					}
				}
			})

			// Create a fresh token right before verification to ensure it's not expired
			token, err := jwtMaker.CreateAccessToken(context.Background(), userID, username, role, sessionID)
			require.NoError(b, err)

			b.Run("Verify", func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					_, err := jwtMaker.VerifyAccessToken(token.Token)
					if err != nil {
						b.Fatal(err)
					}
				}
			})
		})
	}
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
