// File: gourdiantoken.repository.mongo_test.go

package gourdiantoken

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// TestNewMongoTokenRepository_NilDatabase exercises the repository
// constructor's own nil check directly. NewGourdianTokenMakerWithMongo has
// its own, earlier nil check that returns before ever reaching this one, so
// this path is otherwise never exercised.
func TestNewMongoTokenRepository_NilDatabase(t *testing.T) {
	_, err := NewMongoTokenRepository(nil, false)
	require.Error(t, err)
	require.Contains(t, err.Error(), "database cannot be nil")
}

// TestNewMongoTokenRepository_PingFailure exercises the connectivity-check
// error branch against an address nothing listens on. mongo.Connect only
// validates the URI and never dials eagerly, so this constructs
// successfully while Ping fails immediately.
func TestNewMongoTokenRepository_PingFailure(t *testing.T) {
	client, err := mongo.Connect(options.Client().
		ApplyURI("mongodb://127.0.0.1:1/?connectTimeoutMS=200&serverSelectionTimeoutMS=200"))
	require.NoError(t, err)
	defer func() { _ = client.Disconnect(context.Background()) }()

	_, err = NewMongoTokenRepository(client.Database("nowhere"), false)
	require.Error(t, err)
	require.Contains(t, err.Error(), "mongodb connection failed")
}

// TestNewGourdianTokenMakerWithMongo_WrapsRepositoryError exercises the
// factory's own error-wrapping branch when NewMongoTokenRepository fails,
// distinct from calling NewMongoTokenRepository directly (see
// TestNewMongoTokenRepository_PingFailure).
func TestNewGourdianTokenMakerWithMongo_WrapsRepositoryError(t *testing.T) {
	client, err := mongo.Connect(options.Client().
		ApplyURI("mongodb://127.0.0.1:1/?connectTimeoutMS=200&serverSelectionTimeoutMS=200"))
	require.NoError(t, err)
	defer func() { _ = client.Disconnect(context.Background()) }()

	config := DefaultTestConfig()
	config.RevocationEnabled = true
	config.RotationEnabled = true

	_, err = NewGourdianTokenMakerWithMongo(context.Background(), config, client.Database("nowhere"))
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to initialize MongoDB token repository")
}

// TestMongoRepository_OperationsAfterDisconnected exercises every
// MongoTokenRepository method's underlying-database-error branch by
// disconnecting the client out from under an otherwise-valid repository —
// the driver returns a clean "client is disconnected" error rather than
// panicking.
func TestMongoRepository_OperationsAfterDisconnected(t *testing.T) {
	factories := getTestRepositoryFactories()
	repo, cleanup := factories["MongoDB"](t)
	defer cleanup()

	mongoRepo := repo.(*MongoTokenRepository)
	ctx := context.Background()

	require.NoError(t, mongoRepo.MarkTokenRotated(ctx, "disconnected-token", time.Hour))

	require.NoError(t, mongoRepo.revokedCollection.Database().Client().Disconnect(ctx))

	err := mongoRepo.MarkTokenRevoke(ctx, AccessToken, "x", time.Hour)
	require.Error(t, err)

	_, err = mongoRepo.IsTokenRevoked(ctx, AccessToken, "x")
	require.Error(t, err)

	err = mongoRepo.MarkTokenRotated(ctx, "x", time.Hour)
	require.Error(t, err)

	_, err = mongoRepo.MarkTokenRotatedAtomic(ctx, "x", time.Hour)
	require.Error(t, err)

	_, err = mongoRepo.IsTokenRotated(ctx, "x")
	require.Error(t, err)

	_, err = mongoRepo.GetRotationTTL(ctx, "disconnected-token")
	require.Error(t, err)

	err = mongoRepo.CleanupExpiredRevokedTokens(ctx, AccessToken)
	require.Error(t, err)

	err = mongoRepo.CleanupExpiredRotatedTokens(ctx)
	require.Error(t, err)

	err = mongoRepo.RevokeTenant(ctx, "acme-corp", time.Hour)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to revoke tenant")

	_, err = mongoRepo.GetTenantRevocationEpoch(ctx, "acme-corp")
	require.Error(t, err)
	require.Contains(t, err.Error(), "mongodb error")

	err = mongoRepo.CleanupExpiredTenantRevocations(ctx)
	require.Error(t, err)

	_, err = mongoRepo.Stats(ctx)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to count revoked tokens")

	err = mongoRepo.CleanupAll(ctx)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to cleanup access tokens")
}

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
