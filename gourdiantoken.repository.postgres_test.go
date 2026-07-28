// File: gourdiantoken.repository.postgres_test.go

package gourdiantoken

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

// TestNewPostgresTokenRepository_NilPool exercises the repository
// constructor's own nil check directly. NewGourdianTokenMakerWithPostgres
// has its own, earlier nil check that returns before ever reaching this
// one, so this path is otherwise never exercised.
func TestNewPostgresTokenRepository_NilPool(t *testing.T) {
	_, err := NewPostgresTokenRepository(context.Background(), nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "pgx pool cannot be nil")
}

// TestNewPostgresTokenRepository_PingFailure exercises the ping-failure
// branch: pgxpool.New only parses config and never dials eagerly, so
// pointing it at an address nothing listens on lets the pool construct
// successfully while Ping fails immediately.
func TestNewPostgresTokenRepository_PingFailure(t *testing.T) {
	pool, err := pgxpool.New(context.Background(), "host=127.0.0.1 port=1 user=nobody dbname=nowhere sslmode=disable connect_timeout=1")
	require.NoError(t, err)
	defer pool.Close()

	_, err = NewPostgresTokenRepository(context.Background(), pool)
	require.Error(t, err)
	require.Contains(t, err.Error(), "database connection failed")
}

// TestNewGourdianTokenMakerWithPostgres_WrapsRepositoryError exercises the
// factory's own error-wrapping branch when NewPostgresTokenRepository
// fails, distinct from calling NewPostgresTokenRepository directly (see
// TestNewPostgresTokenRepository_PingFailure).
func TestNewGourdianTokenMakerWithPostgres_WrapsRepositoryError(t *testing.T) {
	pool, err := pgxpool.New(context.Background(), "host=127.0.0.1 port=1 user=nobody dbname=nowhere sslmode=disable connect_timeout=1")
	require.NoError(t, err)
	defer pool.Close()

	config := DefaultTestConfig()
	config.RevocationEnabled = true
	config.RotationEnabled = true

	_, err = NewGourdianTokenMakerWithPostgres(context.Background(), config, pool)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to initialize Postgres token repository")
}

// TestApplyPostgresSchema_AcquireFailure exercises applyPostgresSchema's
// connection-acquire error branch: a closed pool fails Acquire immediately
// with a clean, non-panicking error.
func TestApplyPostgresSchema_AcquireFailure(t *testing.T) {
	factories := getTestRepositoryFactories()
	repo, cleanup := factories["Postgres"](t)
	defer cleanup()

	pgRepo := repo.(*PostgresTokenRepository)
	pgRepo.pool.Close()

	err := applyPostgresSchema(context.Background(), pgRepo.pool)
	require.Error(t, err)
	require.Contains(t, err.Error(), "acquire connection")
}

// TestPostgresRepository_OperationsAfterPoolClosed exercises every
// PostgresTokenRepository method's underlying-database-error branch by
// closing the pool out from under an otherwise-valid repository — pgx
// returns a clean "closed pool" error rather than panicking, so every
// method's own error-wrapping path is reachable deterministically without
// needing to simulate a live connection dropping mid-operation.
// TestPostgresRepository_Stats_RotatedCountFails and
// TestPostgresRepository_CleanupAll_RotatedCleanupFails reach the specific
// late-stage error branches in Stats/CleanupAll that only fire once every
// prior call in the sequence has already succeeded — unreachable via the
// closed-pool technique in TestPostgresRepository_OperationsAfterPoolClosed,
// since closing the pool fails every call including the first.
func TestPostgresRepository_Stats_RotatedCountFails(t *testing.T) {
	factories := getTestRepositoryFactories()
	repo, cleanup := factories["Postgres"](t)
	defer cleanup()

	pgRepo := repo.(*PostgresTokenRepository)
	ctx := context.Background()

	_, err := pgRepo.pool.Exec(ctx, "DROP TABLE gourdiantoken_rotated_tokens")
	require.NoError(t, err)

	_, err = pgRepo.Stats(ctx)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to count rotated tokens")
}

func TestPostgresRepository_CleanupAll_RotatedCleanupFails(t *testing.T) {
	factories := getTestRepositoryFactories()
	repo, cleanup := factories["Postgres"](t)
	defer cleanup()

	pgRepo := repo.(*PostgresTokenRepository)
	ctx := context.Background()

	_, err := pgRepo.pool.Exec(ctx, "DROP TABLE gourdiantoken_rotated_tokens")
	require.NoError(t, err)

	err = pgRepo.CleanupAll(ctx)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to cleanup rotated tokens")
}

// TestPostgresRepository_Stats_TenantRevocationCountFails mirrors
// TestPostgresRepository_Stats_RotatedCountFails: CountTenantRevocations is the last of
// Stats' five count queries, so only dropping its own table (leaving every earlier table
// intact) reaches this specific branch.
func TestPostgresRepository_Stats_TenantRevocationCountFails(t *testing.T) {
	factories := getTestRepositoryFactories()
	repo, cleanup := factories["Postgres"](t)
	defer cleanup()

	pgRepo := repo.(*PostgresTokenRepository)
	ctx := context.Background()

	_, err := pgRepo.pool.Exec(ctx, "DROP TABLE gourdiantoken_tenant_revocations")
	require.NoError(t, err)

	_, err = pgRepo.Stats(ctx)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to count tenant revocations")
}

// TestPostgresRepository_CleanupAll_TenantRevocationCleanupFails mirrors
// TestPostgresRepository_CleanupAll_RotatedCleanupFails: CleanupExpiredTenantRevocations is
// the last of CleanupAll's four cleanup calls, so only dropping its own table reaches this
// specific branch.
func TestPostgresRepository_CleanupAll_TenantRevocationCleanupFails(t *testing.T) {
	factories := getTestRepositoryFactories()
	repo, cleanup := factories["Postgres"](t)
	defer cleanup()

	pgRepo := repo.(*PostgresTokenRepository)
	ctx := context.Background()

	_, err := pgRepo.pool.Exec(ctx, "DROP TABLE gourdiantoken_tenant_revocations")
	require.NoError(t, err)

	err = pgRepo.CleanupAll(ctx)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to cleanup tenant revocations")
}

func TestPostgresRepository_OperationsAfterPoolClosed(t *testing.T) {
	factories := getTestRepositoryFactories()
	repo, cleanup := factories["Postgres"](t)
	defer cleanup()

	pgRepo := repo.(*PostgresTokenRepository)
	ctx := context.Background()

	// Seed data through the still-open pool so GetRotationTTL's non-empty
	// path below has a real row to (fail to) read.
	require.NoError(t, pgRepo.MarkTokenRotated(ctx, "closed-pool-token", time.Hour))

	pgRepo.pool.Close()

	err := pgRepo.MarkTokenRevoke(ctx, AccessToken, "x", time.Hour)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to mark token as revoked")

	_, err = pgRepo.IsTokenRevoked(ctx, AccessToken, "x")
	require.Error(t, err)
	require.Contains(t, err.Error(), "database error")

	err = pgRepo.MarkTokenRotated(ctx, "x", time.Hour)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to mark token as rotated")

	_, err = pgRepo.MarkTokenRotatedAtomic(ctx, "x", time.Hour)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to mark token as rotated")

	_, err = pgRepo.IsTokenRotated(ctx, "x")
	require.Error(t, err)
	require.Contains(t, err.Error(), "database error")

	_, err = pgRepo.GetRotationTTL(ctx, "closed-pool-token")
	require.Error(t, err)
	require.Contains(t, err.Error(), "database error")

	err = pgRepo.CleanupExpiredRevokedTokens(ctx, AccessToken)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to cleanup expired revoked tokens")

	err = pgRepo.CleanupExpiredRotatedTokens(ctx)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to cleanup expired rotated tokens")

	err = pgRepo.RevokeTenant(ctx, "acme-corp", time.Hour)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to revoke tenant")

	_, err = pgRepo.GetTenantRevocationEpoch(ctx, "acme-corp")
	require.Error(t, err)
	require.Contains(t, err.Error(), "database error")

	err = pgRepo.CleanupExpiredTenantRevocations(ctx)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to cleanup expired tenant revocations")

	_, err = pgRepo.Stats(ctx)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to count revoked tokens")

	err = pgRepo.CleanupAll(ctx)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to cleanup access tokens")
}
