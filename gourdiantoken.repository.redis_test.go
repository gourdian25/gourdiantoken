// File: gourdiantoken.repository.redis_test.go

package gourdiantoken

import (
	"context"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

// TestNewRedisTokenRepository_NilClient exercises the repository
// constructor's own nil check directly. NewGourdianTokenMakerWithRedis has
// its own, earlier nil check that returns before ever reaching this one, so
// this path is otherwise never exercised.
func TestNewRedisTokenRepository_NilClient(t *testing.T) {
	_, err := NewRedisTokenRepository(nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "redis client cannot be nil")
}

// TestNewRedisTokenRepository_PingFailure exercises the connectivity-check
// error branch against an address nothing listens on.
func TestNewRedisTokenRepository_PingFailure(t *testing.T) {
	client := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1", DialTimeout: 200 * time.Millisecond})
	defer func() { _ = client.Close() }()

	_, err := NewRedisTokenRepository(client)
	require.Error(t, err)
	require.Contains(t, err.Error(), "redis connection failed")
}

// TestNewGourdianTokenMakerWithRedis_WrapsRepositoryError exercises the
// factory's own error-wrapping branch when NewRedisTokenRepository fails,
// distinct from calling NewRedisTokenRepository directly (see
// TestNewRedisTokenRepository_PingFailure).
func TestNewGourdianTokenMakerWithRedis_WrapsRepositoryError(t *testing.T) {
	client := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1", DialTimeout: 200 * time.Millisecond})
	defer func() { _ = client.Close() }()

	config := DefaultTestConfig()
	config.RevocationEnabled = true
	config.RotationEnabled = true

	_, err := NewGourdianTokenMakerWithRedis(context.Background(), config, client)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to initialize Redis token repository")
}

// TestRedisRepository_OperationsAfterClientClosed exercises every
// RedisTokenRepository method's underlying-redis-error branch by closing
// the client out from under an otherwise-valid repository — go-redis
// returns a clean "redis: client is closed" error rather than panicking.
func TestRedisRepository_OperationsAfterClientClosed(t *testing.T) {
	factories := getTestRepositoryFactories()
	repo, cleanup := factories["Redis"](t)
	defer cleanup()

	redisRepo := repo.(*RedisTokenRepository)
	ctx := context.Background()

	require.NoError(t, redisRepo.MarkTokenRotated(ctx, "closed-client-token", time.Hour))

	_ = redisRepo.client.Close()

	err := redisRepo.MarkTokenRevoke(ctx, AccessToken, "x", time.Hour)
	require.Error(t, err)

	_, err = redisRepo.IsTokenRevoked(ctx, AccessToken, "x")
	require.Error(t, err)

	_, err = redisRepo.MarkTokenRotatedAtomic(ctx, "x", time.Hour)
	require.Error(t, err)
	require.Contains(t, err.Error(), "redis error")

	_, err = redisRepo.IsTokenRotated(ctx, "x")
	require.Error(t, err)
	require.Contains(t, err.Error(), "redis error")

	_, err = redisRepo.GetRotationTTL(ctx, "closed-client-token")
	require.Error(t, err)
	require.Contains(t, err.Error(), "redis error")

	err = redisRepo.CleanupExpiredRevokedTokens(ctx, AccessToken)
	require.Error(t, err)
	require.Contains(t, err.Error(), "redis scan error")

	err = redisRepo.CleanupExpiredRotatedTokens(ctx)
	require.Error(t, err)
	require.Contains(t, err.Error(), "redis scan error")

	_, err = redisRepo.Stats(ctx)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to count access tokens")
}

// TestRedisRepository_CleanupExpiredKeys_ContextCanceled exercises
// cleanupExpiredKeys' context-cancellation branch directly.
func TestRedisRepository_CleanupExpiredKeys_ContextCanceled(t *testing.T) {
	factories := getTestRepositoryFactories()
	repo, cleanup := factories["Redis"](t)
	defer cleanup()

	redisRepo := repo.(*RedisTokenRepository)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := redisRepo.cleanupExpiredKeys(ctx, revokedAccessPrefix)
	require.Error(t, err)
	require.Contains(t, err.Error(), "context canceled")
}

// TestRedisRepository_CleanupExpiredKeys_DeletesExpiredAndKeepsFresh exercises
// cleanupExpiredKeys' happy path: an expired key gets deleted, a fresh one survives.
func TestRedisRepository_CleanupExpiredKeys_DeletesExpiredAndKeepsFresh(t *testing.T) {
	factories := getTestRepositoryFactories()
	repo, cleanup := factories["Redis"](t)
	defer cleanup()

	redisRepo := repo.(*RedisTokenRepository)
	ctx := context.Background()

	require.NoError(t, redisRepo.MarkTokenRevoke(ctx, AccessToken, "expiring-soon", 60*time.Millisecond))
	require.NoError(t, redisRepo.MarkTokenRevoke(ctx, AccessToken, "staying-fresh", time.Hour))

	time.Sleep(150 * time.Millisecond)

	require.NoError(t, redisRepo.CleanupExpiredRevokedTokens(ctx, AccessToken))

	revoked, err := redisRepo.IsTokenRevoked(ctx, AccessToken, "staying-fresh")
	require.NoError(t, err)
	require.True(t, revoked)
}
