// File: token.test.helper_test.go

package gourdiantoken

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
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
			if err := client.Ping(ctx).Err(); err != nil {
				_ = client.Close()
				t.Skipf("Redis not available at %s, skipping: %v", redisAddr, err)
			}

			err := client.FlushDB(ctx).Err()
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
			// Port 27018, not the Mongo default 27017: on this project's dev machine, Docker
			// Desktop's own port-forwarding for 27017 got stuck pointing at an orphaned
			// standalone (non-replica-set, no-auth) mongod left over from an earlier failed
			// container attempt, and persisted across container recreation, `wsl --shutdown`,
			// and a full Docker Desktop restart. Moving to 27018 sidesteps it entirely — see
			// plan.md's "Mongo verification gap" section for the full diagnosis.
			//
			// directConnection=true: the single-node replica set member is registered under
			// its own container-internal hostname (e.g. "9698c87b448c:27017"), which only
			// resolves inside Docker's network — the host running these tests can't resolve
			// it. Without directConnection, the driver does full replica-set topology
			// discovery/monitoring using that unresolvable hostname (from the `hosts` list in
			// the server's `hello` reply) and ends up stuck in ReplicaSetNoPrimary. Reconfiguring
			// the member's hostname to match the host-side port doesn't work either — rs.reconfig
			// performs the same "does this host map to this node" self-connectivity check as
			// rs.initiate, and the node only ever listens on its container-internal port.
			// directConnection=true sidesteps all of this: the driver uses only the one
			// connection dialed here for every operation, which is exactly right for a
			// single-node dev/test replica set with no failover to discover anyway. Sessions/
			// transactions still work fine over a direct connection since the server itself is
			// genuinely part of an initialized replica set.
			mongoURI := "mongodb://root:mongo_password@localhost:27018/?directConnection=true"

			ctx := context.Background()
			client, err := mongo.Connect(options.Client().ApplyURI(mongoURI))
			require.NoError(t, err)

			if err := client.Ping(ctx, nil); err != nil {
				_ = client.Disconnect(ctx)
				t.Skipf("MongoDB not available at %s, skipping: %v", mongoURI, err)
			}

			db := client.Database("gourdiantoken_test")

			_ = db.Collection(mongoRevokedCollectionName).Drop(ctx)
			_ = db.Collection(mongoRotatedCollectionName).Drop(ctx)
			_ = db.Collection(mongoTenantRevocationsCollectionName).Drop(ctx)

			repo, err := NewMongoTokenRepository(db, false)
			require.NoError(t, err)

			cleanup := func() {
				ctx := context.Background()
				_, _ = db.Collection(mongoRevokedCollectionName).DeleteMany(ctx, bson.M{})
				_, _ = db.Collection(mongoRotatedCollectionName).DeleteMany(ctx, bson.M{})
				_, _ = db.Collection(mongoTenantRevocationsCollectionName).DeleteMany(ctx, bson.M{})

				if err := client.Disconnect(ctx); err != nil {
					t.Logf("cleanup MongoDB Disconnect error: %v", err)
				}
			}
			return repo, cleanup
		},

		"Postgres": func(t *testing.T) (TokenRepository, func()) {
			postgresDSN := "host=localhost user=postgres_user password=postgres_password dbname=gourdiantoken_test port=5432 sslmode=disable"

			ctx := context.Background()
			pool, err := pgxpool.New(ctx, postgresDSN)
			require.NoError(t, err)

			if err := pool.Ping(ctx); err != nil {
				pool.Close()
				t.Skipf("PostgreSQL not available, skipping: %v", err)
			}

			// NewPostgresTokenRepository no longer applies schema itself
			// (see its own doc comment) -- gourdiantoken_test's role
			// (postgres_user) is a superuser in this test environment, so
			// applying it directly here keeps the suite self-contained
			// without needing a real migration tool.
			require.NoError(t, applyPostgresSchema(ctx, pool))

			_, _ = pool.Exec(ctx, "TRUNCATE TABLE gourdiantoken_revoked_tokens RESTART IDENTITY CASCADE")
			_, _ = pool.Exec(ctx, "TRUNCATE TABLE gourdiantoken_rotated_tokens RESTART IDENTITY CASCADE")
			_, _ = pool.Exec(ctx, "TRUNCATE TABLE gourdiantoken_tenant_revocations")

			repo, err := NewPostgresTokenRepository(ctx, pool)
			require.NoError(t, err)

			cleanup := func() {
				ctx := context.Background()
				_, _ = pool.Exec(ctx, "TRUNCATE TABLE gourdiantoken_revoked_tokens RESTART IDENTITY CASCADE")
				_, _ = pool.Exec(ctx, "TRUNCATE TABLE gourdiantoken_rotated_tokens RESTART IDENTITY CASCADE")
				_, _ = pool.Exec(ctx, "TRUNCATE TABLE gourdiantoken_tenant_revocations")

				if pgRepo, ok := repo.(*PostgresTokenRepository); ok {
					if err := pgRepo.Close(); err != nil {
						t.Logf("cleanup Postgres Close error: %v", err)
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
