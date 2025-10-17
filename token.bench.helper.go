// File: token.bench.helper.go


package gourdiantoken

import (
	"context"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// ============================================================================
// BENCHMARK HELPER FUNCTIONS
// ============================================================================

func setupBenchMaker(b *testing.B) *JWTMaker {
	b.Helper()

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

	maker, _ := NewGourdianTokenMaker(context.Background(), config, nil)
	return maker.(*JWTMaker)
}

func setupBenchMakerWithRepo(b *testing.B) *JWTMaker {
	b.Helper()

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

	maker, _ := NewGourdianTokenMaker(context.Background(), config, repo)
	return maker.(*JWTMaker)
}

type BenchRepositoryFactory func(b *testing.B) (TokenRepository, func())

func getBenchRepositoryFactories() map[string]BenchRepositoryFactory {

	return map[string]BenchRepositoryFactory{
		"Memory": func(b *testing.B) (TokenRepository, func()) {
			repo := NewMemoryTokenRepository(1 * time.Minute)
			cleanup := func() {
				if memRepo, ok := repo.(*MemoryTokenRepository); ok {
					if err := memRepo.Close(); err != nil {
						println("Memory cleanup error:", err.Error())
					}
				}
			}
			return repo, cleanup
		},

		"Redis": func(b *testing.B) (TokenRepository, func()) {
			redisAddr := "localhost:6379"
			redisPassword := "redis_password"

			client := redis.NewClient(&redis.Options{
				Addr:     redisAddr,
				Password: redisPassword,
				DB:       15,
			})

			ctx := context.Background()

			if err := client.Ping(ctx).Err(); err != nil {
				println("Redis connection error:", err.Error())
				return nil, func() {}
			}

			_ = client.FlushDB(ctx).Err()

			repo, err := NewRedisTokenRepository(client)
			if err != nil {
				println("Redis repository creation error:", err.Error())
				return nil, func() {}
			}

			cleanup := func() {
				ctx := context.Background()
				if err := client.FlushDB(ctx).Err(); err != nil {
					println("Redis FlushDB error:", err.Error())
				}
				if err := client.Close(); err != nil {
					println("Redis Close error:", err.Error())
				}
			}
			return repo, cleanup
		},

		"MongoDB": func(b *testing.B) (TokenRepository, func()) {
			mongoURI := "mongodb://root:mongo_password@localhost:27017"

			ctx := context.Background()
			client, err := mongo.Connect(ctx, options.Client().ApplyURI(mongoURI))
			if err != nil {
				println("MongoDB connection error:", err.Error())
				return nil, func() {}
			}

			if err := client.Ping(ctx, nil); err != nil {
				println("MongoDB ping error:", err.Error())
				return nil, func() {}
			}

			db := client.Database("gourdian_bench")

			_ = db.Collection("revoked_tokens").Drop(ctx)
			_ = db.Collection("rotated_tokens").Drop(ctx)

			repo, err := NewMongoTokenRepository(db, false)
			if err != nil {
				println("MongoDB repository creation error:", err.Error())
				return nil, func() {}
			}

			cleanup := func() {
				ctx := context.Background()
				_, _ = db.Collection("revoked_tokens").DeleteMany(ctx, bson.M{})
				_, _ = db.Collection("rotated_tokens").DeleteMany(ctx, bson.M{})

				if err := client.Disconnect(ctx); err != nil {
					println("MongoDB Disconnect error:", err.Error())
				}
			}
			return repo, cleanup
		},

		"GORM": func(b *testing.B) (TokenRepository, func()) {
			postgresDSN := "host=localhost user=postgres_user password=postgres_password dbname=postgres_db port=5432 sslmode=disable"

			db, err := gorm.Open(postgres.Open(postgresDSN), &gorm.Config{})
			if err != nil {
				println("GORM connection error:", err.Error())
				return nil, func() {}
			}

			_ = db.Exec("TRUNCATE TABLE revoked_tokens RESTART IDENTITY CASCADE")
			_ = db.Exec("TRUNCATE TABLE rotated_tokens RESTART IDENTITY CASCADE")

			repo, err := NewGormTokenRepository(db)
			if err != nil {
				println("GORM repository creation error:", err.Error())
				return nil, func() {}
			}

			cleanup := func() {
				_ = db.Exec("TRUNCATE TABLE revoked_tokens RESTART IDENTITY CASCADE")
				_ = db.Exec("TRUNCATE TABLE rotated_tokens RESTART IDENTITY CASCADE")

				if gormRepo, ok := repo.(*GormTokenRepository); ok {
					if err := gormRepo.Close(); err != nil {
						println("GORM Close error:", err.Error())
					}
				}
			}
			return repo, cleanup
		},
	}
}
