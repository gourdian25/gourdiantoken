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

	closer, ok := maker.(GourdianTokenMakerCloser)
	require.True(t, ok, "*JWTMaker should implement GourdianTokenMakerCloser")

	assert.NoError(t, closer.Close())
	assert.NoError(t, closer.Close())
	assert.NoError(t, closer.Close())
}

func TestClose_NoOpWhenRotationAndRevocationDisabled(t *testing.T) {
	maker, err := NewGourdianTokenMakerNoStorage(context.Background(), DefaultTestConfig())
	require.NoError(t, err)

	closer, ok := maker.(GourdianTokenMakerCloser)
	require.True(t, ok)

	// No background goroutines were ever started; Close must still be safe.
	assert.NoError(t, closer.Close())
	assert.NoError(t, closer.Close())
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

	countAtClose := repo.Count()
	// Wait several intervals' worth of time; the count must not increase further.
	time.Sleep(200 * time.Millisecond)

	assert.Equal(t, countAtClose, repo.Count(), "cleanup goroutines should have stopped after Close")
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
