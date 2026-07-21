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

	_, err = pgRepo.Stats(ctx)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to count revoked tokens")

	err = pgRepo.CleanupAll(ctx)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to cleanup access tokens")
}
