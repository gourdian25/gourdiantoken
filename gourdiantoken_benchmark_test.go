// File: gourdiantoken_benchmark_test.go

package gourdiantoken

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

func BenchmarkCreateAccessToken(b *testing.B) {
	// Setup symmetric maker
	symmetricConfig := DefaultGourdianTokenConfig("test-secret-32-bytes-long-1234567890")
	symmetricMaker, _ := NewGourdianTokenMaker(context.Background(), symmetricConfig, nil)

	// Setup asymmetric maker
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	privatePath, publicPath := writeTempKeyFiles(b, privateKey)
	asymmetricConfig := GourdianTokenConfig{
		Algorithm:                "RS256",
		SigningMethod:            Asymmetric,
		PrivateKeyPath:           privatePath,
		PublicKeyPath:            publicPath,
		AccessExpiryDuration:     time.Hour,
		AccessMaxLifetimeExpiry:  24 * time.Hour,
		RefreshExpiryDuration:    7 * 24 * time.Hour,
		RefreshMaxLifetimeExpiry: 30 * 24 * time.Hour,
	}
	asymmetricMaker, _ := NewGourdianTokenMaker(context.Background(), asymmetricConfig, nil)

	userID := uuid.New()
	username := "benchuser"
	roles := []string{"user"}
	sessionID := uuid.New()

	b.Run("Symmetric", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := symmetricMaker.CreateAccessToken(context.Background(), userID, username, roles, sessionID)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("Asymmetric", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := asymmetricMaker.CreateAccessToken(context.Background(), userID, username, roles, sessionID)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkVerifyAccessToken(b *testing.B) {
	// Setup symmetric maker
	symmetricConfig := DefaultGourdianTokenConfig("test-secret-32-bytes-long-1234567890")
	symmetricMaker, _ := NewGourdianTokenMaker(context.Background(), symmetricConfig, nil)

	// Setup asymmetric maker
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	privatePath, publicPath := writeTempKeyFiles(b, privateKey)
	asymmetricConfig := GourdianTokenConfig{
		Algorithm:                "RS256",
		SigningMethod:            Asymmetric,
		PrivateKeyPath:           privatePath,
		PublicKeyPath:            publicPath,
		AccessExpiryDuration:     time.Hour,
		AccessMaxLifetimeExpiry:  24 * time.Hour,
		RefreshExpiryDuration:    7 * 24 * time.Hour,
		RefreshMaxLifetimeExpiry: 30 * 24 * time.Hour,
	}
	asymmetricMaker, _ := NewGourdianTokenMaker(context.Background(), asymmetricConfig, nil)

	userID := uuid.New()
	username := "benchuser"
	roles := []string{"user"}
	sessionID := uuid.New()

	symToken, _ := symmetricMaker.CreateAccessToken(context.Background(), userID, username, roles, sessionID)
	asymToken, _ := asymmetricMaker.CreateAccessToken(context.Background(), userID, username, roles, sessionID)

	b.Run("Symmetric", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := symmetricMaker.VerifyAccessToken(context.Background(), symToken.Token)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("Asymmetric", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := asymmetricMaker.VerifyAccessToken(context.Background(), asymToken.Token)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkRedisTokenRotation(b *testing.B) {
	conn := redis.NewClient(testRedisOptions())
	if _, err := conn.Ping(context.Background()).Result(); err != nil {
		b.Skip("Redis not available, skipping benchmark")
	}
	if conn.Close() != nil {
		b.Fatal("Failed to close Redis connection")
	}

	config := DefaultGourdianTokenConfig("test-secret-32-bytes-long-1234567890")
	config.RotationEnabled = true

	testCases := []struct {
		name      string
		redisOpts *redis.Options
	}{
		{"LocalRedis", testRedisOptions()},
	}

	for _, tc := range testCases {
		b.Run(tc.name, func(b *testing.B) {
			maker, err := NewGourdianTokenMaker(context.Background(), config, tc.redisOpts)
			if err != nil {
				b.Fatalf("Failed to create token maker: %v", err)
			}

			userID := uuid.New()
			username := "benchuser"
			sessionID := uuid.New()

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

func BenchmarkTokenRevocation(b *testing.B) {
	conn := redis.NewClient(testRedisOptions())
	if _, err := conn.Ping(context.Background()).Result(); err != nil {
		b.Skip("Redis not available, skipping benchmark")
	}
	if conn.Close() != nil {
		b.Fatal("Failed to close Redis connection")
	}

	config := DefaultGourdianTokenConfig("test-secret-32-bytes-long-1234567890")
	config.RevocationEnabled = true
	maker, _ := NewGourdianTokenMaker(context.Background(), config, testRedisOptions())

	userID := uuid.New()
	username := "benchuser"
	roles := []string{"user"}
	sessionID := uuid.New()

	tokens := make([]string, b.N)
	for i := 0; i < b.N; i++ {
		token, _ := maker.CreateAccessToken(context.Background(), userID, username, roles, sessionID)
		tokens[i] = token.Token
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := maker.RevokeAccessToken(context.Background(), tokens[i])
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkConcurrentTokenCreation(b *testing.B) {
	config := DefaultGourdianTokenConfig("test-secret-32-bytes-long-1234567890")
	maker, _ := NewGourdianTokenMaker(context.Background(), config, nil)

	b.RunParallel(func(pb *testing.PB) {
		userID := uuid.New()
		username := "benchuser"
		roles := []string{"user"}
		sessionID := uuid.New()

		for pb.Next() {
			_, err := maker.CreateAccessToken(context.Background(), userID, username, roles, sessionID)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkTokenSizeImpact(b *testing.B) {
	config := DefaultGourdianTokenConfig("test-secret-32-bytes-long-1234567890")
	maker, _ := NewGourdianTokenMaker(context.Background(), config, nil)

	testCases := []struct {
		name     string
		username string
		roles    []string
		extra    map[string]interface{}
	}{
		{"Small", "user", []string{"guest"}, nil},
		{"Medium", "user.with.middlename", []string{"admin"}, map[string]interface{}{"department": "engineering"}},
		{"Large", "user.with.very.long.name.and.multiple.parts", []string{"super-admin", "auditor"},
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
				_, err := maker.CreateAccessToken(context.Background(), userID, tc.username, tc.roles, sessionID)
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
				Algorithm:                ks.algo,
				SigningMethod:            Asymmetric,
				PrivateKeyPath:           privatePath,
				PublicKeyPath:            publicPath,
				AccessExpiryDuration:     time.Hour,
				AccessMaxLifetimeExpiry:  24 * time.Hour,
				RefreshExpiryDuration:    7 * 24 * time.Hour,
				RefreshMaxLifetimeExpiry: 30 * 24 * time.Hour,
			}
			maker, _ := NewGourdianTokenMaker(context.Background(), config, nil)

			userID := uuid.New()
			username := "benchuser"
			roles := []string{"user"}
			sessionID := uuid.New()

			token, _ := maker.CreateAccessToken(context.Background(), userID, username, roles, sessionID)

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err := maker.VerifyAccessToken(context.Background(), token.Token)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkVerifyRefreshToken(b *testing.B) {
	config := DefaultGourdianTokenConfig("test-secret-32-bytes-long-1234567890")
	maker, _ := NewGourdianTokenMaker(context.Background(), config, nil)

	userID := uuid.New()
	username := "benchuser"
	sessionID := uuid.New()

	token, _ := maker.CreateRefreshToken(context.Background(), userID, username, sessionID)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := maker.VerifyRefreshToken(context.Background(), token.Token)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRotateRefreshToken_RedisReuseInterval(b *testing.B) {
	opts := testRedisOptions()
	config := DefaultGourdianTokenConfig("test-secret-32-bytes-long-1234567890")
	config.RotationEnabled = true
	config.RefreshReuseInterval = 2 * time.Second

	maker, err := NewGourdianTokenMaker(context.Background(), config, opts)
	require.NoError(b, err)

	userID := uuid.New()
	username := "benchuser"
	sessionID := uuid.New()

	token, err := maker.CreateRefreshToken(context.Background(), userID, username, sessionID)
	require.NoError(b, err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = maker.RotateRefreshToken(context.Background(), token.Token)
		time.Sleep(config.RefreshReuseInterval) // simulate delay to avoid reuse error
	}
}

func BenchmarkRevokeAndVerifyToken_Redis(b *testing.B) {
	opts := testRedisOptions()
	config := DefaultGourdianTokenConfig("test-secret-32-bytes-long-1234567890")
	config.RevocationEnabled = true

	maker, err := NewGourdianTokenMaker(context.Background(), config, opts)
	require.NoError(b, err)

	userID := uuid.New()
	username := "benchuser"
	roles := []string{"user"}
	sessionID := uuid.New()

	token, err := maker.CreateAccessToken(context.Background(), userID, username, roles, sessionID)
	require.NoError(b, err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = maker.RevokeAccessToken(context.Background(), token.Token)
		_, _ = maker.VerifyAccessToken(context.Background(), token.Token)
	}
}

func BenchmarkWithMultipleRoles(b *testing.B) {
	config := DefaultGourdianTokenConfig("test-secret-32-bytes-long-1234567890")
	maker, _ := NewGourdianTokenMaker(context.Background(), config, nil)

	userID := uuid.New()
	username := "benchuser"
	sessionID := uuid.New()
	roles := make([]string, 100)
	for i := range roles {
		roles[i] = "role" + uuid.NewString()
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := maker.CreateAccessToken(context.Background(), userID, username, roles, sessionID)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifyAccessTokenParallel(b *testing.B) {
	ctx := context.Background()
	maker, err := NewGourdianTokenMaker(ctx, DefaultGourdianTokenConfig(testSymmetricKey), nil)
	require.NoError(b, err)

	userID := uuid.New()
	username := "benchmark-user"
	sessionID := uuid.New()
	roles := []string{"admin", "editor"}

	accessToken, err := maker.CreateAccessToken(ctx, userID, username, roles, sessionID)
	require.NoError(b, err)
	token := accessToken.Token

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := maker.VerifyAccessToken(ctx, token)
			if err != nil {
				b.Errorf("verification failed: %v", err)
			}
		}
	})
}

func BenchmarkCreateAccessTokenParallel(b *testing.B) {
	ctx := context.Background()
	maker, _ := NewGourdianTokenMaker(ctx, DefaultGourdianTokenConfig(testSymmetricKey), nil)
	userID := uuid.New()
	sessionID := uuid.New()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _ = maker.CreateAccessToken(ctx, userID, "testuser", []string{"admin"}, sessionID)
		}
	})
}

func BenchmarkCreateRefreshTokenParallel(b *testing.B) {
	ctx := context.Background()
	maker, _ := NewGourdianTokenMaker(ctx, DefaultGourdianTokenConfig(testSymmetricKey), nil)
	userID := uuid.New()
	sessionID := uuid.New()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _ = maker.CreateRefreshToken(ctx, userID, "testuser", sessionID)
		}
	})
}

func BenchmarkVerifyRefreshTokenParallel(b *testing.B) {
	ctx := context.Background()
	maker, _ := NewGourdianTokenMaker(ctx, DefaultGourdianTokenConfig(testSymmetricKey), nil)
	userID := uuid.New()
	sessionID := uuid.New()
	tokenResp, _ := maker.CreateRefreshToken(ctx, userID, "testuser", sessionID)
	token := tokenResp.Token

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _ = maker.VerifyRefreshToken(ctx, token)
		}
	})
}

func BenchmarkRotateRefreshTokenParallel(b *testing.B) {
	ctx := context.Background()
	config := DefaultGourdianTokenConfig(testSymmetricKey)
	config.RotationEnabled = true
	maker, _ := NewGourdianTokenMaker(ctx, config, testRedisOptions())

	userID := uuid.New()
	sessionID := uuid.New()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			tokenResp, _ := maker.CreateRefreshToken(ctx, userID, "testuser", sessionID)
			_, _ = maker.RotateRefreshToken(ctx, tokenResp.Token)
		}
	})
}

func BenchmarkTokenRevocationParallel(b *testing.B) {
	ctx := context.Background()
	config := DefaultGourdianTokenConfig(testSymmetricKey)
	config.RevocationEnabled = true
	maker, _ := NewGourdianTokenMaker(ctx, config, testRedisOptions())

	userID := uuid.New()
	sessionID := uuid.New()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			tokenResp, _ := maker.CreateAccessToken(ctx, userID, "user", []string{"admin"}, sessionID)
			_ = maker.RevokeAccessToken(ctx, tokenResp.Token)
			_, _ = maker.VerifyAccessToken(ctx, tokenResp.Token)
		}
	})
}

func BenchmarkTokenOperations(b *testing.B) {
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
				config.AccessExpiryDuration = time.Hour
				maker, err = NewGourdianTokenMaker(context.Background(), config, nil)
			case *rsa.PrivateKey, *ecdsa.PrivateKey:
				privatePath, publicPath := writeTempKeyFiles(b, k)
				config := GourdianTokenConfig{
					Algorithm:                bb.algorithm,
					SigningMethod:            Asymmetric,
					PrivateKeyPath:           privatePath,
					PublicKeyPath:            publicPath,
					AccessExpiryDuration:     time.Hour,
					AccessMaxLifetimeExpiry:  24 * time.Hour,
					RefreshExpiryDuration:    7 * 24 * time.Hour,
					RefreshMaxLifetimeExpiry: 30 * 24 * time.Hour,
				}
				maker, err = NewGourdianTokenMaker(context.Background(), config, nil)
			}
			require.NoError(b, err)

			userID := uuid.New()
			username := "benchuser"
			roles := []string{"admin"}
			sessionID := uuid.New()

			b.Run("Create", func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					_, err := maker.CreateAccessToken(context.Background(), userID, username, roles, sessionID)
					if err != nil {
						b.Fatal(err)
					}
				}
			})

			token, err := maker.CreateAccessToken(context.Background(), userID, username, roles, sessionID)
			require.NoError(b, err)

			b.Run("Verify", func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					_, err := maker.VerifyAccessToken(context.Background(), token.Token)
					if err != nil {
						b.Fatal(err)
					}
				}
			})
		})
	}
}

func BenchmarkCreateRefreshToken(b *testing.B) {
	// Symmetric setup
	symmetricConfig := DefaultGourdianTokenConfig("test-secret-32-bytes-long-1234567890")
	symmetricMaker, err := NewGourdianTokenMaker(context.Background(), symmetricConfig, nil)
	if err != nil {
		b.Fatalf("failed to create symmetric maker: %v", err)
	}

	// Asymmetric setup
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatalf("failed to generate RSA key: %v", err)
	}

	privatePath, publicPath := writeTempKeyFiles(b, privateKey)

	defer func() {
		if err := os.Remove(privatePath); err != nil {
			b.Fatalf("failed to remove private key file: %v", err)
		}
	}()

	defer func() {
		if err := os.Remove(publicPath); err != nil {
			b.Fatalf("failed to remove private key file: %v", err)
		}
	}()

	asymmetricConfig := GourdianTokenConfig{
		Algorithm:                "RS256",
		SigningMethod:            Asymmetric,
		PrivateKeyPath:           privatePath,
		PublicKeyPath:            publicPath,
		Issuer:                   "benchmark",
		Audience:                 []string{"benchmark"},
		AllowedAlgorithms:        []string{"RS256"},
		RequiredClaims:           []string{"iss", "aud", "exp", "iat"},
		AccessExpiryDuration:     time.Hour,
		AccessMaxLifetimeExpiry:  24 * time.Hour,
		RefreshExpiryDuration:    7 * 24 * time.Hour,
		RefreshMaxLifetimeExpiry: 30 * 24 * time.Hour,
	}
	asymmetricMaker, err := NewGourdianTokenMaker(context.Background(), asymmetricConfig, nil)
	if err != nil {
		b.Fatalf("failed to create asymmetric maker: %v", err)
	}

	userID := uuid.New()
	username := "benchuser"
	sessionID := uuid.New()

	b.Run("Symmetric", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := symmetricMaker.CreateRefreshToken(context.Background(), userID, username, sessionID)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("Asymmetric", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := asymmetricMaker.CreateRefreshToken(context.Background(), userID, username, sessionID)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}
