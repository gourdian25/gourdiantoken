// File: gourdiantoken.repository.coverage_test.go

package gourdiantoken

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestNewMemoryTokenRepository_DefaultCleanupInterval exercises the
// cleanupInterval<=0 fallback-to-default branch, never hit by the rest of
// the suite since every other caller passes a positive interval.
func TestNewMemoryTokenRepository_DefaultCleanupInterval(t *testing.T) {
	repo := NewMemoryTokenRepository(0)
	memRepo, ok := repo.(*MemoryTokenRepository)
	require.True(t, ok)
	require.NoError(t, memRepo.Close())
}

// TestMarkTokenRotatedAtomic_ReMarksAfterExpiry exercises the branch where
// an existing rotation entry is present but has already expired:
// MarkTokenRotatedAtomic must fall through and re-mark (returning true
// again) rather than reporting a false conflict, since
// TestMarkTokenRotatedAtomic_AllBackends only ever exercises the
// still-valid-entry conflict path.
//
// Memory and Redis only: Postgres and MongoDB both implement the atomic
// mark as an unconditional INSERT/upsert ... ON CONFLICT (token_hash) DO
// NOTHING — inherited unchanged from the original GORM implementation —
// which treats any existing row as a conflict regardless of whether it has
// logically expired, so a same-token re-mark after expiry incorrectly
// reports false there. Narrow in practice (requires the exact same token
// string to be rotated again after its rotation record's full TTL, which
// is RefreshMaxLifetimeExpiry — typically weeks — without cleanup having
// run yet), but a real cross-backend inconsistency worth fixing separately
// rather than as a side effect of a coverage pass.
func TestMarkTokenRotatedAtomic_ReMarksAfterExpiry(t *testing.T) {
	factories := getTestRepositoryFactories()

	for _, name := range []string{"Memory", "Redis"} {
		factory := factories[name]
		t.Run(name, func(t *testing.T) {
			repo, cleanup := factory(t)
			defer cleanup()

			ctx := context.Background()
			token := "re-mark-after-expiry-" + name

			marked, err := repo.MarkTokenRotatedAtomic(ctx, token, 60*time.Millisecond)
			require.NoError(t, err)
			require.True(t, marked)

			time.Sleep(150 * time.Millisecond)

			marked, err = repo.MarkTokenRotatedAtomic(ctx, token, time.Hour)
			require.NoError(t, err)
			require.True(t, marked, "expired rotation entry should be re-markable")
		})
	}
}

// TestRedisGetRotationTTL_NoExpiry exercises the PTTL == -1 branch (key
// exists but carries no TTL) — never produced by this repository's own API,
// since every write always sets an expiry, so the key is set directly
// through the raw client.
func TestRedisGetRotationTTL_NoExpiry(t *testing.T) {
	factories := getTestRepositoryFactories()
	repo, cleanup := factories["Redis"](t)
	defer cleanup()

	redisRepo := repo.(*RedisTokenRepository)
	ctx := context.Background()
	token := "no-expiry-token"
	key := rotatedPrefix + hashToken(token)

	require.NoError(t, redisRepo.client.Set(ctx, key, "1", 0).Err())

	ttl, err := redisRepo.GetRotationTTL(ctx, token)
	require.NoError(t, err)
	require.Equal(t, time.Duration(0), ttl)
}

// TestRedisCleanupExpiredKeys_MultipleBatches forces cleanupExpiredKeys'
// SCAN loop to iterate more than one cursor batch (batchSize is 100),
// exercising the newCursor != 0 continuation branch.
func TestRedisCleanupExpiredKeys_MultipleBatches(t *testing.T) {
	factories := getTestRepositoryFactories()
	repo, cleanup := factories["Redis"](t)
	defer cleanup()

	redisRepo := repo.(*RedisTokenRepository)
	ctx := context.Background()

	for i := 0; i < 250; i++ {
		token := fmt.Sprintf("batch-token-%d", i)
		require.NoError(t, redisRepo.MarkTokenRevoke(ctx, AccessToken, token, time.Hour))
	}

	require.NoError(t, redisRepo.CleanupExpiredRevokedTokens(ctx, AccessToken))
}
