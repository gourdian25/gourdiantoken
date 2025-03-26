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
	"github.com/redis/go-redis/v9"
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

func BenchmarkRedisTokenRotation(b *testing.B) {

	// At the start of the benchmark
	conn := redis.NewClient(testRedisOptions())
	if _, err := conn.Ping(context.Background()).Result(); err != nil {
		b.Skip("Redis not available, skipping benchmark")
	}
	conn.Close()
	config := DefaultGourdianTokenConfig("test-secret-32-bytes-long-1234567890")
	config.RefreshToken.RotationEnabled = true

	// Test with different Redis configurations
	testCases := []struct {
		name      string
		redisOpts *redis.Options
	}{
		{"LocalRedis", testRedisOptions()}, // Using the helper function here
		// You could add more test cases with different Redis configurations if needed
		// For example:
		// {"RedisWithPassword", &redis.Options{Addr: "localhost:6379", Password: "otherpassword"}},
	}

	for _, tc := range testCases {
		b.Run(tc.name, func(b *testing.B) {
			maker, err := NewGourdianTokenMaker(config, tc.redisOpts)
			if err != nil {
				b.Fatalf("Failed to create token maker: %v", err)
			}

			userID := uuid.New()
			username := "benchuser"
			sessionID := uuid.New()

			// Pre-create tokens to rotate
			tokens := make([]string, b.N)
			for i := 0; i < b.N; i++ {
				token, err := maker.CreateRefreshToken(context.Background(), userID, username, sessionID)
				if err != nil {
					b.Fatalf("Failed to create refresh token: %v", err)
				}
				tokens[i] = token.Token
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err := maker.RotateRefreshToken(context.Background(), tokens[i])
				if err != nil {
					b.Fatalf("Failed to rotate token: %v", err)
				}
			}
		})
	}
}

func BenchmarkTokenRotation(b *testing.B) {
	config := DefaultGourdianTokenConfig("test-secret-32-bytes-long-1234567890")
	config.RefreshToken.RotationEnabled = true
	maker, _ := NewGourdianTokenMaker(config, testRedisOptions())

	userID := uuid.New()
	username := "benchuser"
	sessionID := uuid.New()

	// Pre-create tokens to rotate
	tokens := make([]string, b.N)
	for i := 0; i < b.N; i++ {
		token, _ := maker.CreateRefreshToken(context.Background(), userID, username, sessionID)
		tokens[i] = token.Token
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := maker.RotateRefreshToken(context.Background(), tokens[i])
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRefreshTokenOperations(b *testing.B) {
	config := DefaultGourdianTokenConfig("test-secret-32-bytes-long-1234567890")
	maker, _ := NewGourdianTokenMaker(config, testRedisOptions())

	userID := uuid.New()
	username := "benchuser"
	sessionID := uuid.New()

	b.Run("Create", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := maker.CreateRefreshToken(context.Background(), userID, username, sessionID)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	// Create a fresh token for verification
	token, _ := maker.CreateRefreshToken(context.Background(), userID, username, sessionID)

	b.Run("Verify", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := maker.VerifyRefreshToken(token.Token)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkConcurrentTokenCreation(b *testing.B) {
	config := DefaultGourdianTokenConfig("test-secret-32-bytes-long-1234567890")
	maker, _ := NewGourdianTokenMaker(config, nil)

	b.RunParallel(func(pb *testing.PB) {
		userID := uuid.New()
		username := "benchuser"
		role := "user"
		sessionID := uuid.New()

		for pb.Next() {
			_, err := maker.CreateAccessToken(context.Background(), userID, username, role, sessionID)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkTokenParsing(b *testing.B) {
	config := DefaultGourdianTokenConfig("test-secret-32-bytes-long-1234567890")
	maker, _ := NewGourdianTokenMaker(config, nil)

	userID := uuid.New()
	username := "benchuser"
	role := "user"
	sessionID := uuid.New()

	token, _ := maker.CreateAccessToken(context.Background(), userID, username, role, sessionID)

	b.Run("WithValidation", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := maker.VerifyAccessToken(token.Token)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("WithoutValidation", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _, err := new(jwt.Parser).ParseUnverified(token.Token, jwt.MapClaims{})
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkTokenSizeImpact(b *testing.B) {
	config := DefaultGourdianTokenConfig("test-secret-32-bytes-long-1234567890")
	maker, _ := NewGourdianTokenMaker(config, nil)

	testCases := []struct {
		name     string
		username string
		role     string
		extra    map[string]interface{}
	}{
		{"Small", "user", "guest", nil},
		{"Medium", "user.with.middlename", "admin", map[string]interface{}{"department": "engineering"}},
		{"Large", "user.with.very.long.name.and.multiple.parts", "super-admin",
			map[string]interface{}{
				"department":  "engineering",
				"teams":       []string{"backend", "infra", "security"},
				"permissions": []string{"read", "write", "delete", "admin"},
			}},
	}

	for _, tc := range testCases {
		b.Run(tc.name, func(b *testing.B) {
			userID := uuid.New()
			sessionID := uuid.New()

			for i := 0; i < b.N; i++ {
				_, err := maker.CreateAccessToken(context.Background(), userID, tc.username, tc.role, sessionID)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkVerificationWithKeySizes(b *testing.B) {
	keySizes := []struct {
		name    string
		size    int
		algo    string
		genFunc func() interface{}
	}{
		{"RSA-1024", 1024, "RS256", func() interface{} { return generateRSAKey(1024) }},
		{"RSA-2048", 2048, "RS256", func() interface{} { return generateRSAKey(2048) }},
		{"RSA-4096", 4096, "RS256", func() interface{} { return generateRSAKey(4096) }},
		{"ECDSA-P256", 256, "ES256", func() interface{} { return generateECDSAKey(elliptic.P256()) }},
		{"ECDSA-P384", 384, "ES384", func() interface{} { return generateECDSAKey(elliptic.P384()) }},
		{"ECDSA-P521", 521, "ES512", func() interface{} { return generateECDSAKey(elliptic.P521()) }},
	}

	for _, ks := range keySizes {
		b.Run(ks.name, func(b *testing.B) {
			privatePath, publicPath := writeTempKeyFiles(b, ks.genFunc())
			config := GourdianTokenConfig{
				Algorithm:      ks.algo,
				SigningMethod:  Asymmetric,
				PrivateKeyPath: privatePath,
				PublicKeyPath:  publicPath,
				AccessToken: AccessTokenConfig{
					Duration: time.Hour,
				},
			}
			maker, _ := NewGourdianTokenMaker(config, nil)

			userID := uuid.New()
			username := "benchuser"
			role := "user"
			sessionID := uuid.New()

			token, _ := maker.CreateAccessToken(context.Background(), userID, username, role, sessionID)

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err := maker.VerifyAccessToken(token.Token)
				if err != nil {
					b.Fatal(err)
				}
			}
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
