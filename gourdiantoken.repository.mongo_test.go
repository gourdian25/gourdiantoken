// File: gourdiantoken.repository.mongo_test.go

package gourdiantoken

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestMongoRepository_MarkTokenRotatedAtomic_ConcurrentDuplicate_WithTransactions is the
// Phase 4 item 1 regression test for the MarkTokenRotatedAtomic duplicate-key fix.
//
// Before the fix, mongo.IsDuplicateKeyError was checked *inside* the transaction callback
// passed to withTransaction, and swallowed via `return nil`. That's risky under
// useTransactions=true because a write error surfaced to the driver mid-transaction can
// cause the server to abort the transaction regardless of the callback's return value,
// making commit behavior driver-version-dependent instead of the clean "false, nil"
// outcome callers expect for "someone else already rotated this token concurrently".
//
// This test exercises that exact path: N goroutines race to call MarkTokenRotatedAtomic
// with the *same* token against a repository constructed with useTransactions=true.
// Exactly one call must report success (true, nil); every other call must report
// (false, nil) — never a raw duplicate-key error leaking through, and never more than
// one success. To verify this test would have caught the pre-fix bug, temporarily revert
// the duplicate-key-detection boundary move in gourdiantoken.repository.mongo.imp.go's
// MarkTokenRotatedAtomic and confirm this test fails.
func TestMongoRepository_MarkTokenRotatedAtomic_ConcurrentDuplicate_WithTransactions(t *testing.T) {
	factories := getTestRepositoryFactories()
	repo, cleanup := factories["MongoDB"](t)
	defer cleanup()

	baseRepo := repo.(*MongoTokenRepository)
	txnRepo, err := NewMongoTokenRepository(baseRepo.revokedCollection.Database(), true)
	require.NoError(t, err)

	const concurrency = 10
	token := "concurrent-rotation-regression-token"
	ttl := 1 * time.Hour

	var wg sync.WaitGroup
	results := make([]bool, concurrency)
	errs := make([]error, concurrency)

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			marked, err := txnRepo.MarkTokenRotatedAtomic(context.Background(), token, ttl)
			results[idx] = marked
			errs[idx] = err
		}(i)
	}
	wg.Wait()

	successCount := 0
	for i := 0; i < concurrency; i++ {
		require.NoError(t, errs[i], "MarkTokenRotatedAtomic must never surface a raw duplicate-key error to the caller (call %d)", i)
		if results[i] {
			successCount++
		}
	}

	require.Equal(t, 1, successCount, fmt.Sprintf("exactly one of %d concurrent MarkTokenRotatedAtomic calls for the same token should succeed", concurrency))

	rotated, err := txnRepo.IsTokenRotated(context.Background(), token)
	require.NoError(t, err)
	require.True(t, rotated, "token should be recorded as rotated after the race")
}
