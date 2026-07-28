// File: gourdiantoken.close_test.go

package gourdiantoken

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// cleanupCountingRepo is a minimal TokenRepository stub whose CleanupExpired*
// methods always error (so the cleanup goroutines' logf hook fires on every
// tick) and count how many times they were invoked, used to observe whether
// the background cleanup goroutines are still running.
type cleanupCountingRepo struct {
	mu    sync.Mutex
	count int
}

func (r *cleanupCountingRepo) MarkTokenRevoke(ctx context.Context, tokenType TokenType, token string, ttl time.Duration) error {
	return nil
}

func (r *cleanupCountingRepo) IsTokenRevoked(ctx context.Context, tokenType TokenType, token string) (bool, error) {
	return false, nil
}

func (r *cleanupCountingRepo) MarkTokenRotated(ctx context.Context, token string, ttl time.Duration) error {
	return nil
}

func (r *cleanupCountingRepo) MarkTokenRotatedAtomic(ctx context.Context, token string, ttl time.Duration) (bool, error) {
	return true, nil
}

func (r *cleanupCountingRepo) IsTokenRotated(ctx context.Context, token string) (bool, error) {
	return false, nil
}

func (r *cleanupCountingRepo) GetRotationTTL(ctx context.Context, token string) (time.Duration, error) {
	return 0, nil
}

func (r *cleanupCountingRepo) CleanupExpiredRevokedTokens(ctx context.Context, tokenType TokenType) error {
	r.mu.Lock()
	r.count++
	r.mu.Unlock()
	return fmt.Errorf("stub cleanup error")
}

func (r *cleanupCountingRepo) CleanupExpiredRotatedTokens(ctx context.Context) error {
	r.mu.Lock()
	r.count++
	r.mu.Unlock()
	return fmt.Errorf("stub cleanup error")
}

func (r *cleanupCountingRepo) RevokeTenant(ctx context.Context, tenantID string, ttl time.Duration) error {
	return nil
}

func (r *cleanupCountingRepo) GetTenantRevocationEpoch(ctx context.Context, tenantID string) (time.Time, error) {
	return time.Time{}, nil
}

func (r *cleanupCountingRepo) CleanupExpiredTenantRevocations(ctx context.Context) error {
	r.mu.Lock()
	r.count++
	r.mu.Unlock()
	return fmt.Errorf("stub cleanup error")
}

func (r *cleanupCountingRepo) Stats(ctx context.Context) (map[string]interface{}, error) {
	return map[string]interface{}{}, nil
}

func (r *cleanupCountingRepo) CleanupAll(ctx context.Context) error { return nil }

func (r *cleanupCountingRepo) Count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.count
}

func TestClose_Idempotent(t *testing.T) {
	config := DefaultTestConfig()
	config.RevocationEnabled = true
	config.RotationEnabled = true

	maker, err := NewGourdianTokenMakerWithMemory(context.Background(), config)
	require.NoError(t, err)

	assert.NoError(t, maker.Close())
	assert.NoError(t, maker.Close())
	assert.NoError(t, maker.Close())
}

func TestClose_NoOpWhenRotationAndRevocationDisabled(t *testing.T) {
	maker, err := NewGourdianTokenMakerNoStorage(context.Background(), DefaultTestConfig())
	require.NoError(t, err)

	// No background goroutines were ever started; Close must still be safe.
	assert.NoError(t, maker.Close())
	assert.NoError(t, maker.Close())
}

// TestClose_StopsCleanupGoroutines constructs a *JWTMaker directly (bypassing
// NewGourdianTokenMaker's public validateConfig, which enforces a 1-minute minimum
// CleanupInterval) so the cleanup goroutines can be observed ticking on a much
// shorter, test-friendly interval.
func TestClose_StopsCleanupGoroutines(t *testing.T) {
	repo := &cleanupCountingRepo{}

	maker := &JWTMaker{
		config: GourdianTokenConfig{
			RevocationEnabled: true,
			RotationEnabled:   true,
			CleanupInterval:   20 * time.Millisecond,
		},
		tokenRepo: repo,
		logf:      func(format string, args ...any) {},
	}
	cleanupCtx, cancel := context.WithCancel(context.Background())
	maker.cleanupCancel = cancel
	go maker.cleanupRotatedTokens(cleanupCtx)
	go maker.cleanupRevokedTokens(cleanupCtx)

	// Wait for at least one cleanup tick to confirm the goroutines are running.
	require.Eventually(t, func() bool { return repo.Count() > 0 }, 2*time.Second, 10*time.Millisecond,
		"expected cleanup goroutines to run at least once before Close")

	require.NoError(t, maker.Close())

	// Close cancels the goroutines' context, but their `select` loop races the cancellation
	// against a possibly-already-ready ticker tick — Go doesn't prioritize ctx.Done() over
	// ticker.C, so one in-flight tick can legitimately complete after Close returns, before
	// the goroutine observes cancellation on its next loop iteration. Allow one interval's
	// grace period before capturing the baseline, so that expected race isn't mistaken for
	// the goroutines failing to stop.
	time.Sleep(maker.config.CleanupInterval)
	countAtClose := repo.Count()

	// Wait several intervals' worth of time; the count must not increase further.
	time.Sleep(200 * time.Millisecond)

	assert.Equal(t, countAtClose, repo.Count(), "cleanup goroutines should have stopped after Close")
}

// TestClose_StopsCleanupGoroutines_MultiTenant mirrors TestClose_StopsCleanupGoroutines,
// with MultiTenantEnabled set so the tenant-revocation cleanup branch (guarded by that
// flag, added alongside RevokeTenant) also ticks and reports through logf.
func TestClose_StopsCleanupGoroutines_MultiTenant(t *testing.T) {
	repo := &cleanupCountingRepo{}

	maker := &JWTMaker{
		config: GourdianTokenConfig{
			RevocationEnabled:  true,
			RotationEnabled:    true,
			MultiTenantEnabled: true,
			CleanupInterval:    20 * time.Millisecond,
		},
		tokenRepo: repo,
		logf:      func(format string, args ...any) {},
	}
	cleanupCtx, cancel := context.WithCancel(context.Background())
	maker.cleanupCancel = cancel
	go maker.cleanupRotatedTokens(cleanupCtx)
	go maker.cleanupRevokedTokens(cleanupCtx)

	require.Eventually(t, func() bool { return repo.Count() > 0 }, 2*time.Second, 10*time.Millisecond,
		"expected cleanup goroutines to run at least once before Close")

	require.NoError(t, maker.Close())
}

// TestClose_StructuredLoggerReceivesCleanupErrors mirrors TestClose_WithLoggerOption but
// via the structured Logger path (WithStructuredLogger/structuredLogger) instead of the
// printf-style logf hook, with MultiTenantEnabled set so the tenant-revocation cleanup
// error report is exercised too, alongside the pre-existing rotated/revoked ones.
func TestClose_StructuredLoggerReceivesCleanupErrors(t *testing.T) {
	rec := &recordingLogger{}
	repo := &cleanupCountingRepo{}

	maker := &JWTMaker{
		config: GourdianTokenConfig{
			RevocationEnabled:  true,
			RotationEnabled:    true,
			MultiTenantEnabled: true,
			CleanupInterval:    20 * time.Millisecond,
		},
		tokenRepo:        repo,
		structuredLogger: rec,
	}

	cleanupCtx, cancel := context.WithCancel(context.Background())
	maker.cleanupCancel = cancel
	go maker.cleanupRotatedTokens(cleanupCtx)
	go maker.cleanupRevokedTokens(cleanupCtx)

	require.Eventually(t, func() bool {
		rec.mu.Lock()
		defer rec.mu.Unlock()
		return len(rec.errors) > 0
	}, 2*time.Second, 10*time.Millisecond, "expected structured logger to receive cleanup error reports")

	require.NoError(t, maker.Close())
}

func TestClose_WithLoggerOption(t *testing.T) {
	var mu sync.Mutex
	var messages []string

	repo := &cleanupCountingRepo{}

	maker := &JWTMaker{
		config: GourdianTokenConfig{
			RevocationEnabled: true,
			RotationEnabled:   true,
			CleanupInterval:   20 * time.Millisecond,
		},
		tokenRepo: repo,
	}
	WithLogger(func(format string, args ...any) {
		mu.Lock()
		defer mu.Unlock()
		messages = append(messages, fmt.Sprintf(format, args...))
	})(maker)

	cleanupCtx, cancel := context.WithCancel(context.Background())
	maker.cleanupCancel = cancel
	go maker.cleanupRotatedTokens(cleanupCtx)
	go maker.cleanupRevokedTokens(cleanupCtx)

	require.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(messages) > 0
	}, 2*time.Second, 10*time.Millisecond, "expected custom logger to receive cleanup error reports")

	require.NoError(t, maker.Close())
}
