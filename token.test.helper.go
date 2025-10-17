// File: token.test.helper.go


package gourdiantoken

import (
	"context"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func setupTestMaker(t *testing.T) *JWTMaker {
	t.Helper()

	config := GourdianTokenConfig{
		SigningMethod:            Symmetric,
		Algorithm:                "HS256",
		SymmetricKey:             "test-secret-key-that-is-at-least-32-bytes-long",
		Issuer:                   "test.com",
		Audience:                 []string{"api.test.com"},
		AllowedAlgorithms:        []string{"HS256"},
		RequiredClaims:           []string{"iss", "aud", "nbf", "mle"},
		AccessExpiryDuration:     30 * time.Minute,
		AccessMaxLifetimeExpiry:  24 * time.Hour,
		RefreshExpiryDuration:    7 * 24 * time.Hour,
		RefreshMaxLifetimeExpiry: 30 * 24 * time.Hour,
		RefreshReuseInterval:     5 * time.Minute,
		CleanupInterval:          1 * time.Hour,
		RevocationEnabled:        false,
		RotationEnabled:          false,
	}

	maker, err := NewGourdianTokenMaker(context.Background(), config, nil)
	require.NoError(t, err)

	return maker.(*JWTMaker)
}

func setupTestMakerWithRepo(t *testing.T) *JWTMaker {
	t.Helper()

	repo := NewMemoryTokenRepository(1 * time.Minute)

	config := GourdianTokenConfig{
		SigningMethod:            Symmetric,
		Algorithm:                "HS256",
		SymmetricKey:             "test-secret-key-that-is-at-least-32-bytes-long",
		Issuer:                   "test.com",
		Audience:                 []string{"api.test.com"},
		AllowedAlgorithms:        []string{"HS256"},
		RequiredClaims:           []string{"iss", "aud", "nbf", "mle"},
		AccessExpiryDuration:     30 * time.Minute,
		AccessMaxLifetimeExpiry:  24 * time.Hour,
		RefreshExpiryDuration:    7 * 24 * time.Hour,
		RefreshMaxLifetimeExpiry: 30 * 24 * time.Hour,
		RefreshReuseInterval:     5 * time.Minute,
		CleanupInterval:          1 * time.Hour,
		RevocationEnabled:        true,
		RotationEnabled:          true,
	}

	maker, err := NewGourdianTokenMaker(context.Background(), config, repo)
	require.NoError(t, err)

	return maker.(*JWTMaker)
}

type TestRepositoryFactory func(t *testing.T) (TokenRepository, func())

func getTestRepositoryFactories() map[string]TestRepositoryFactory {

	return map[string]TestRepositoryFactory{
		"Memory": func(t *testing.T) (TokenRepository, func()) {
			repo := NewMemoryTokenRepository(1 * time.Minute)
			cleanup := func() {
				if memRepo, ok := repo.(*MemoryTokenRepository); ok {
					_ = memRepo.Close()
				}
			}
			return repo, cleanup
		},

		"Redis": func(t *testing.T) (TokenRepository, func()) {
			redisAddr := "localhost:6379"
			redisPassword := "redis_password"

			client := redis.NewClient(&redis.Options{
				Addr:     redisAddr,
				Password: redisPassword,
				DB:       15,
			})

			ctx := context.Background()
			err := client.Ping(ctx).Err()
			require.NoError(t, err)

			err = client.FlushDB(ctx).Err()
			require.NoError(t, err)

			repo, err := NewRedisTokenRepository(client)
			require.NoError(t, err)

			cleanup := func() {
				ctx := context.Background()
				if err := client.FlushDB(ctx).Err(); err != nil {
					t.Logf("cleanup Redis FlushDB error: %v", err)
				}
				if err := client.Close(); err != nil {
					t.Logf("cleanup Redis Close error: %v", err)
				}
			}
			return repo, cleanup
		},

		"MongoDB": func(t *testing.T) (TokenRepository, func()) {
			mongoURI := "mongodb://root:mongo_password@localhost:27017"

			ctx := context.Background()
			client, err := mongo.Connect(ctx, options.Client().ApplyURI(mongoURI))
			require.NoError(t, err)

			err = client.Ping(ctx, nil)
			require.NoError(t, err)

			db := client.Database("gourdian_test")

			_ = db.Collection("revoked_tokens").Drop(ctx)
			_ = db.Collection("rotated_tokens").Drop(ctx)

			repo, err := NewMongoTokenRepository(db, false)
			require.NoError(t, err)

			cleanup := func() {
				ctx := context.Background()
				_, _ = db.Collection("revoked_tokens").DeleteMany(ctx, bson.M{})
				_, _ = db.Collection("rotated_tokens").DeleteMany(ctx, bson.M{})

				if err := client.Disconnect(ctx); err != nil {
					t.Logf("cleanup MongoDB Disconnect error: %v", err)
				}
			}
			return repo, cleanup
		},

		"GORM": func(t *testing.T) (TokenRepository, func()) {
			postgresDSN := "host=localhost user=postgres_user password=postgres_password dbname=postgres_db port=5432 sslmode=disable"

			db, err := gorm.Open(postgres.Open(postgresDSN), &gorm.Config{})
			require.NoError(t, err)

			_ = db.Exec("TRUNCATE TABLE revoked_tokens RESTART IDENTITY CASCADE")
			_ = db.Exec("TRUNCATE TABLE rotated_tokens RESTART IDENTITY CASCADE")

			repo, err := NewGormTokenRepository(db)
			require.NoError(t, err)

			cleanup := func() {
				_ = db.Exec("TRUNCATE TABLE revoked_tokens RESTART IDENTITY CASCADE")
				_ = db.Exec("TRUNCATE TABLE rotated_tokens RESTART IDENTITY CASCADE")

				if gormRepo, ok := repo.(*GormTokenRepository); ok {
					if err := gormRepo.Close(); err != nil {
						t.Logf("cleanup GORM Close error: %v", err)
					}
				}
			}
			return repo, cleanup
		},
	}
}

func setupTestMakerWithConfig(t *testing.T, config GourdianTokenConfig, repo TokenRepository) *JWTMaker {
	t.Helper()

	if config.SigningMethod == "" {
		config.SigningMethod = Symmetric
	}
	if config.Algorithm == "" {
		config.Algorithm = "HS256"
	}
	if config.SymmetricKey == "" {
		config.SymmetricKey = "test-secret-key-that-is-at-least-32-bytes-long"
	}
	if config.Issuer == "" {
		config.Issuer = "test.com"
	}
	if config.Audience == nil {
		config.Audience = []string{"api.test.com"}
	}
	if config.AllowedAlgorithms == nil {
		config.AllowedAlgorithms = []string{"HS256"}
	}
	if config.RequiredClaims == nil {
		config.RequiredClaims = []string{"iss", "aud", "nbf", "mle"}
	}
	if config.AccessExpiryDuration == 0 {
		config.AccessExpiryDuration = 30 * time.Minute
	}
	if config.AccessMaxLifetimeExpiry == 0 {
		config.AccessMaxLifetimeExpiry = 24 * time.Hour
	}
	if config.RefreshExpiryDuration == 0 {
		config.RefreshExpiryDuration = 7 * 24 * time.Hour
	}
	if config.RefreshMaxLifetimeExpiry == 0 {
		config.RefreshMaxLifetimeExpiry = 30 * 24 * time.Hour
	}
	if config.CleanupInterval == 0 {
		config.CleanupInterval = 1 * time.Hour
	}

	if repo != nil {
		config.RevocationEnabled = true
		config.RotationEnabled = true
	}

	maker, err := NewGourdianTokenMaker(context.Background(), config, repo)
	require.NoError(t, err)

	return maker.(*JWTMaker)
}

func DefaultTestConfig() GourdianTokenConfig {
	return GourdianTokenConfig{
		SigningMethod:            Symmetric,
		Algorithm:                "HS256",
		SymmetricKey:             "test-secret-key-that-is-at-least-32-bytes-long",
		Issuer:                   "test.com",
		Audience:                 []string{"api.test.com"},
		AllowedAlgorithms:        []string{"HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA"},
		RequiredClaims:           []string{"iss", "aud", "nbf", "mle"},
		AccessExpiryDuration:     30 * time.Minute,
		AccessMaxLifetimeExpiry:  24 * time.Hour,
		RefreshExpiryDuration:    7 * 24 * time.Hour,
		RefreshMaxLifetimeExpiry: 30 * 24 * time.Hour,
		RefreshReuseInterval:     5 * time.Minute,
		CleanupInterval:          1 * time.Hour,
		RevocationEnabled:        false,
		RotationEnabled:          false,
	}
}
