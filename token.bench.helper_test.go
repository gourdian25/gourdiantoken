// File: token.bench.helper_test.go

package gourdiantoken

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
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
			// See token.test.helper_test.go's MongoDB factory for why this is 27018 and
			// includes directConnection=true.
			mongoURI := "mongodb://root:mongo_password@localhost:27018/?directConnection=true"

			ctx := context.Background()
			client, err := mongo.Connect(options.Client().ApplyURI(mongoURI))
			if err != nil {
				println("MongoDB connection error:", err.Error())
				return nil, func() {}
			}

			if err := client.Ping(ctx, nil); err != nil {
				println("MongoDB ping error:", err.Error())
				return nil, func() {}
			}

			db := client.Database("gourdiantoken_bench")

			_ = db.Collection(mongoRevokedCollectionName).Drop(ctx)
			_ = db.Collection(mongoRotatedCollectionName).Drop(ctx)

			repo, err := NewMongoTokenRepository(db, false)
			if err != nil {
				println("MongoDB repository creation error:", err.Error())
				return nil, func() {}
			}

			cleanup := func() {
				ctx := context.Background()
				_, _ = db.Collection(mongoRevokedCollectionName).DeleteMany(ctx, bson.M{})
				_, _ = db.Collection(mongoRotatedCollectionName).DeleteMany(ctx, bson.M{})

				if err := client.Disconnect(ctx); err != nil {
					println("MongoDB Disconnect error:", err.Error())
				}
			}
			return repo, cleanup
		},

		"Postgres": func(b *testing.B) (TokenRepository, func()) {
			postgresDSN := "host=localhost user=postgres_user password=postgres_password dbname=gourdiantoken_test port=5432 sslmode=disable"

			ctx := context.Background()
			pool, err := pgxpool.New(ctx, postgresDSN)
			if err != nil {
				println("Postgres connection error:", err.Error())
				return nil, func() {}
			}
			if err := pool.Ping(ctx); err != nil {
				println("Postgres ping error:", err.Error())
				pool.Close()
				return nil, func() {}
			}

			_, _ = pool.Exec(ctx, "TRUNCATE TABLE gourdiantoken_revoked_tokens RESTART IDENTITY CASCADE")
			_, _ = pool.Exec(ctx, "TRUNCATE TABLE gourdiantoken_rotated_tokens RESTART IDENTITY CASCADE")

			repo, err := NewPostgresTokenRepository(ctx, pool)
			if err != nil {
				println("Postgres repository creation error:", err.Error())
				return nil, func() {}
			}

			cleanup := func() {
				ctx := context.Background()
				_, _ = pool.Exec(ctx, "TRUNCATE TABLE gourdiantoken_revoked_tokens RESTART IDENTITY CASCADE")
				_, _ = pool.Exec(ctx, "TRUNCATE TABLE gourdiantoken_rotated_tokens RESTART IDENTITY CASCADE")

				if pgRepo, ok := repo.(*PostgresTokenRepository); ok {
					if err := pgRepo.Close(); err != nil {
						println("Postgres Close error:", err.Error())
					}
				}
			}
			return repo, cleanup
		},
	}
}
