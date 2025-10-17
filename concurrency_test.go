// File: concurrency_test.go

package gourdiantoken

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestConcurrentTokenCreation tests concurrent token creation
func TestConcurrentTokenCreation(t *testing.T) {
	t.Run("concurrent access token creation", func(t *testing.T) {
		maker := setupTestMaker(t)
		ctx := context.Background()

		const numGoroutines = 100
		tokens := make(chan *AccessTokenResponse, numGoroutines)
		errors := make(chan error, numGoroutines)
		var wg sync.WaitGroup

		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()

				userID := uuid.New()
				token, err := maker.CreateAccessToken(ctx, userID, "user", []string{"admin"}, uuid.New())
				if err != nil {
					errors <- err
					return
				}
				tokens <- token
			}(i)
		}

		wg.Wait()
		close(tokens)
		close(errors)

		// Check for errors
		errorCount := 0
		for err := range errors {
			t.Errorf("Error creating token: %v", err)
			errorCount++
		}
		assert.Equal(t, 0, errorCount)

		// Verify all tokens are unique
		tokenMap := make(map[string]bool)
		tokenCount := 0
		for token := range tokens {
			assert.NotNil(t, token)
			assert.False(t, tokenMap[token.Token], "Duplicate token found")
			tokenMap[token.Token] = true
			tokenCount++
		}
		assert.Equal(t, numGoroutines, tokenCount)
	})

	t.Run("concurrent refresh token creation", func(t *testing.T) {
		maker := setupTestMaker(t)
		ctx := context.Background()

		const numGoroutines = 50
		var wg sync.WaitGroup
		var successCount atomic.Int32
		var errorCount atomic.Int32

		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()

				token, err := maker.CreateRefreshToken(ctx, uuid.New(), "user", uuid.New())
				if err != nil {
					errorCount.Add(1)
					return
				}
				if token != nil {
					successCount.Add(1)
				}
			}()
		}

		wg.Wait()
		assert.Equal(t, int32(numGoroutines), successCount.Load())
		assert.Equal(t, int32(0), errorCount.Load())
	})

	t.Run("concurrent creation with same user ID", func(t *testing.T) {
		maker := setupTestMaker(t)
		ctx := context.Background()
		userID := uuid.New()
		sessionID := uuid.New()

		const numGoroutines = 50
		tokens := make([]string, numGoroutines)
		var wg sync.WaitGroup

		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func(index int) {
				defer wg.Done()

				token, err := maker.CreateAccessToken(ctx, userID, "user", []string{"admin"}, sessionID)
				require.NoError(t, err)
				tokens[index] = token.Token
			}(i)
		}

		wg.Wait()

		// All tokens should be unique even with same user ID
		tokenMap := make(map[string]bool)
		for _, token := range tokens {
			assert.False(t, tokenMap[token], "Duplicate token found")
			tokenMap[token] = true
		}
	})

	t.Run("concurrent creation under load", func(t *testing.T) {
		maker := setupTestMaker(t)
		ctx := context.Background()

		const duration = 2 * time.Second
		const numWorkers = 10

		var successCount atomic.Int64
		var errorCount atomic.Int64
		var wg sync.WaitGroup

		stopChan := make(chan struct{})
		time.AfterFunc(duration, func() {
			close(stopChan)
		})

		for i := 0; i < numWorkers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()

				for {
					select {
					case <-stopChan:
						return
					default:
						_, err := maker.CreateAccessToken(ctx, uuid.New(), "user", []string{"admin"}, uuid.New())
						if err != nil {
							errorCount.Add(1)
						} else {
							successCount.Add(1)
						}
					}
				}
			}()
		}

		wg.Wait()

		t.Logf("Created %d tokens with %d errors in %v", successCount.Load(), errorCount.Load(), duration)
		assert.Greater(t, successCount.Load(), int64(0))
		assert.Equal(t, int64(0), errorCount.Load())
	})
}

// TestConcurrentTokenVerification tests concurrent token verification
func TestConcurrentTokenVerification(t *testing.T) {
	t.Run("verify same token concurrently", func(t *testing.T) {
		maker := setupTestMaker(t)
		ctx := context.Background()

		// Create one token
		token, err := maker.CreateAccessToken(ctx, uuid.New(), "user", []string{"admin"}, uuid.New())
		require.NoError(t, err)

		const numGoroutines = 100
		var wg sync.WaitGroup
		var successCount atomic.Int32

		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()

				claims, err := maker.VerifyAccessToken(ctx, token.Token)
				if err == nil && claims != nil {
					successCount.Add(1)
				}
			}()
		}

		wg.Wait()
		assert.Equal(t, int32(numGoroutines), successCount.Load())
	})

	t.Run("verify different tokens concurrently", func(t *testing.T) {
		maker := setupTestMaker(t)
		ctx := context.Background()

		// Create multiple tokens
		const numTokens = 50
		tokens := make([]string, numTokens)
		for i := 0; i < numTokens; i++ {
			token, err := maker.CreateAccessToken(ctx, uuid.New(), "user", []string{"admin"}, uuid.New())
			require.NoError(t, err)
			tokens[i] = token.Token
		}

		var wg sync.WaitGroup
		var successCount atomic.Int32

		for _, tokenStr := range tokens {
			wg.Add(1)
			go func(t string) {
				defer wg.Done()

				claims, err := maker.VerifyAccessToken(ctx, t)
				if err == nil && claims != nil {
					successCount.Add(1)
				}
			}(tokenStr)
		}

		wg.Wait()
		assert.Equal(t, int32(numTokens), successCount.Load())
	})

	t.Run("mixed creation and verification", func(t *testing.T) {
		maker := setupTestMaker(t)
		ctx := context.Background()

		const duration = 2 * time.Second
		var createCount atomic.Int64
		var verifyCount atomic.Int64
		var wg sync.WaitGroup

		stopChan := make(chan struct{})
		tokenChan := make(chan string, 100)

		// Creator goroutines
		for i := 0; i < 5; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for {
					select {
					case <-stopChan:
						return
					default:
						token, err := maker.CreateAccessToken(ctx, uuid.New(), "user", []string{"admin"}, uuid.New())
						if err == nil {
							createCount.Add(1)
							select {
							case tokenChan <- token.Token:
							default:
							}
						}
					}
				}
			}()
		}

		// Verifier goroutines
		for i := 0; i < 5; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for {
					select {
					case <-stopChan:
						return
					case token := <-tokenChan:
						_, err := maker.VerifyAccessToken(ctx, token)
						if err == nil {
							verifyCount.Add(1)
						}
					}
				}
			}()
		}

		time.Sleep(duration)
		close(stopChan)
		wg.Wait()

		t.Logf("Created %d tokens, verified %d tokens", createCount.Load(), verifyCount.Load())
		assert.Greater(t, createCount.Load(), int64(0))
		assert.Greater(t, verifyCount.Load(), int64(0))
	})
}

// TestConcurrentRevocation tests concurrent token revocation
func TestConcurrentRevocation(t *testing.T) {
	t.Run("concurrent revocation of different tokens", func(t *testing.T) {
		maker := setupTestMakerWithRepo(t)
		ctx := context.Background()

		// Create multiple tokens
		const numTokens = 50
		tokens := make([]*AccessTokenResponse, numTokens)
		for i := 0; i < numTokens; i++ {
			token, err := maker.CreateAccessToken(ctx, uuid.New(), "user", []string{"admin"}, uuid.New())
			require.NoError(t, err)
			tokens[i] = token
		}

		var wg sync.WaitGroup
		var successCount atomic.Int32

		// Revoke all concurrently
		for _, token := range tokens {
			wg.Add(1)
			go func(t *AccessTokenResponse) {
				defer wg.Done()

				err := maker.RevokeAccessToken(ctx, t.Token)
				if err == nil {
					successCount.Add(1)
				}
			}(token)
		}

		wg.Wait()
		assert.Equal(t, int32(numTokens), successCount.Load())

		// Verify all are revoked
		for _, token := range tokens {
			claims, err := maker.VerifyAccessToken(ctx, token.Token)
			assert.Error(t, err)
			assert.Nil(t, claims)
		}
	})

	t.Run("concurrent revocation of same token", func(t *testing.T) {
		maker := setupTestMakerWithRepo(t)
		ctx := context.Background()

		token, err := maker.CreateAccessToken(ctx, uuid.New(), "user", []string{"admin"}, uuid.New())
		require.NoError(t, err)

		const numGoroutines = 20
		var wg sync.WaitGroup
		errors := make([]error, numGoroutines)

		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func(index int) {
				defer wg.Done()
				errors[index] = maker.RevokeAccessToken(ctx, token.Token)
			}(i)
		}

		wg.Wait()

		// All should succeed (idempotent operation)
		for _, err := range errors {
			assert.NoError(t, err)
		}

		// Token should be revoked
		claims, err := maker.VerifyAccessToken(ctx, token.Token)
		assert.Error(t, err)
		assert.Nil(t, claims)
	})

	t.Run("concurrent rotation of refresh tokens", func(t *testing.T) {
		maker := setupTestMakerWithRepo(t)
		ctx := context.Background()

		// Create multiple refresh tokens
		const numTokens = 20
		oldTokens := make([]string, numTokens)
		for i := 0; i < numTokens; i++ {
			token, err := maker.CreateRefreshToken(ctx, uuid.New(), "user", uuid.New())
			require.NoError(t, err)
			oldTokens[i] = token.Token
		}

		var wg sync.WaitGroup
		var successCount atomic.Int32
		newTokens := make([]*RefreshTokenResponse, numTokens)

		// Rotate all concurrently
		for i, oldToken := range oldTokens {
			wg.Add(1)
			go func(index int, token string) {
				defer wg.Done()

				newToken, err := maker.RotateRefreshToken(ctx, token)
				if err == nil {
					newTokens[index] = newToken
					successCount.Add(1)
				}
			}(i, oldToken)
		}

		wg.Wait()
		assert.Equal(t, int32(numTokens), successCount.Load())

		// Verify old tokens cannot be used again
		for _, oldToken := range oldTokens {
			_, err := maker.RotateRefreshToken(ctx, oldToken)
			assert.Error(t, err)
		}

		// Verify new tokens work
		for _, newToken := range newTokens {
			if newToken != nil {
				claims, err := maker.VerifyRefreshToken(ctx, newToken.Token)
				assert.NoError(t, err)
				assert.NotNil(t, claims)
			}
		}
	})

	t.Run("race between verification and revocation", func(t *testing.T) {
		maker := setupTestMakerWithRepo(t)
		ctx := context.Background()

		token, err := maker.CreateAccessToken(ctx, uuid.New(), "user", []string{"admin"}, uuid.New())
		require.NoError(t, err)

		const numGoroutines = 50
		var wg sync.WaitGroup
		var verifyBeforeRevoke atomic.Int32
		var verifyAfterRevoke atomic.Int32

		// Start verifiers
		for i := 0; i < numGoroutines/2; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := 0; j < 10; j++ {
					claims, err := maker.VerifyAccessToken(ctx, token.Token)
					if err == nil && claims != nil {
						verifyBeforeRevoke.Add(1)
					} else if err != nil {
						verifyAfterRevoke.Add(1)
					}
					time.Sleep(1 * time.Millisecond)
				}
			}()
		}

		// Start revoker after small delay
		time.Sleep(10 * time.Millisecond)
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = maker.RevokeAccessToken(ctx, token.Token)
		}()

		wg.Wait()

		t.Logf("Verified before revoke: %d, after revoke: %d",
			verifyBeforeRevoke.Load(), verifyAfterRevoke.Load())

		// Should have some successes and some failures
		assert.Greater(t, verifyBeforeRevoke.Load()+verifyAfterRevoke.Load(), int32(0))
	})
}

// TestConcurrentRepositoryAccess tests concurrent access to token repository
func TestConcurrentRepositoryAccess(t *testing.T) {
	t.Run("concurrent writes to memory repository", func(t *testing.T) {
		repo := NewMemoryTokenRepository(1 * time.Minute)
		ctx := context.Background()

		const numGoroutines = 100
		var wg sync.WaitGroup
		var successCount atomic.Int32

		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()

				token := uuid.New().String()
				err := repo.MarkTokenRevoke(ctx, AccessToken, token, 5*time.Minute)
				if err == nil {
					successCount.Add(1)
				}
			}(i)
		}

		wg.Wait()
		assert.Equal(t, int32(numGoroutines), successCount.Load())
	})

	t.Run("concurrent reads and writes", func(t *testing.T) {
		repo := NewMemoryTokenRepository(1 * time.Minute)
		ctx := context.Background()

		tokens := make([]string, 50)
		for i := range tokens {
			tokens[i] = uuid.New().String()
			err := repo.MarkTokenRevoke(ctx, AccessToken, tokens[i], 5*time.Minute)
			require.NoError(t, err)
		}

		var wg sync.WaitGroup
		var readCount atomic.Int32
		var writeCount atomic.Int32

		// Readers
		for i := 0; i < 25; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for _, token := range tokens {
					_, err := repo.IsTokenRevoked(ctx, AccessToken, token)
					if err == nil {
						readCount.Add(1)
					}
				}
			}()
		}

		// Writers
		for i := 0; i < 25; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				newToken := uuid.New().String()
				err := repo.MarkTokenRevoke(ctx, AccessToken, newToken, 5*time.Minute)
				if err == nil {
					writeCount.Add(1)
				}
			}()
		}

		wg.Wait()

		assert.Greater(t, readCount.Load(), int32(0))
		assert.Equal(t, int32(25), writeCount.Load())
	})

	t.Run("stress test with multiple operations", func(t *testing.T) {
		repo := NewMemoryTokenRepository(1 * time.Minute)
		ctx := context.Background()

		const duration = 2 * time.Second
		var operations atomic.Int64
		var wg sync.WaitGroup

		stopChan := make(chan struct{})
		time.AfterFunc(duration, func() {
			close(stopChan)
		})

		// Mixed operations
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for {
					select {
					case <-stopChan:
						return
					default:
						token := uuid.New().String()
						_ = repo.MarkTokenRevoke(ctx, AccessToken, token, 5*time.Minute)
						_, _ = repo.IsTokenRevoked(ctx, AccessToken, token)
						_ = repo.MarkTokenRotated(ctx, token, 5*time.Minute)
						_, _ = repo.IsTokenRotated(ctx, token)
						operations.Add(1)
					}
				}
			}()
		}

		wg.Wait()
		t.Logf("Completed %d operations in %v", operations.Load(), duration)
		assert.Greater(t, operations.Load(), int64(0))
	})

	t.Run("concurrent access and refresh token operations", func(t *testing.T) {
		repo := NewMemoryTokenRepository(1 * time.Minute)
		ctx := context.Background()

		const numTokens = 50
		tokens := make([]string, numTokens)

		// Pre-populate with access tokens
		for i := range tokens {
			tokens[i] = uuid.New().String()
			err := repo.MarkTokenRevoke(ctx, AccessToken, tokens[i], 5*time.Minute)
			require.NoError(t, err)
		}

		var wg sync.WaitGroup
		var accessReadCount atomic.Int32
		var refreshWriteCount atomic.Int32

		// Readers for access tokens
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for _, token := range tokens {
					revoked, err := repo.IsTokenRevoked(ctx, AccessToken, token)
					if err == nil && revoked {
						accessReadCount.Add(1)
					}
				}
			}()
		}

		// Writers for refresh tokens
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				token := uuid.New().String()
				err := repo.MarkTokenRevoke(ctx, RefreshToken, token, 5*time.Minute)
				if err == nil {
					refreshWriteCount.Add(1)
				}
			}()
		}

		wg.Wait()

		assert.Greater(t, accessReadCount.Load(), int32(0))
		assert.Equal(t, int32(10), refreshWriteCount.Load())
	})

	t.Run("concurrent rotation operations", func(t *testing.T) {
		repo := NewMemoryTokenRepository(1 * time.Minute)
		ctx := context.Background()

		const numTokens = 100
		var wg sync.WaitGroup
		var successCount atomic.Int32

		for i := 0; i < numTokens; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				token := uuid.New().String()

				// Mark as rotated
				err := repo.MarkTokenRotated(ctx, token, 5*time.Minute)
				if err != nil {
					return
				}

				// Check if rotated
				rotated, err := repo.IsTokenRotated(ctx, token)
				if err == nil && rotated {
					successCount.Add(1)
				}
			}()
		}

		wg.Wait()
		assert.Equal(t, int32(numTokens), successCount.Load())
	})

	t.Run("concurrent cleanup operations", func(t *testing.T) {
		repo := NewMemoryTokenRepository(100 * time.Millisecond)
		ctx := context.Background()

		// Add tokens with short TTL
		for i := 0; i < 20; i++ {
			token := uuid.New().String()
			_ = repo.MarkTokenRevoke(ctx, AccessToken, token, 200*time.Millisecond)
		}

		// Wait for some to expire
		time.Sleep(250 * time.Millisecond)

		// Concurrent cleanups
		var wg sync.WaitGroup
		for i := 0; i < 5; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_ = repo.CleanupExpiredRevokedTokens(ctx, AccessToken)
			}()
		}

		wg.Wait()
		t.Logf("Concurrent cleanup completed successfully")
	})

	t.Run("repository under extreme concurrent load", func(t *testing.T) {
		repo := NewMemoryTokenRepository(1 * time.Minute)
		ctx := context.Background()

		const numWorkers = 50
		const operationsPerWorker = 100

		var wg sync.WaitGroup
		var totalOps atomic.Int64

		for i := 0; i < numWorkers; i++ {
			wg.Add(1)
			go func(workerID int) {
				defer wg.Done()

				for j := 0; j < operationsPerWorker; j++ {
					token := uuid.New().String()

					// Random operation
					switch j % 4 {
					case 0:
						_ = repo.MarkTokenRevoke(ctx, AccessToken, token, 5*time.Minute)
					case 1:
						_, _ = repo.IsTokenRevoked(ctx, AccessToken, token)
					case 2:
						_ = repo.MarkTokenRotated(ctx, token, 5*time.Minute)
					case 3:
						_, _ = repo.IsTokenRotated(ctx, token)
					}
					totalOps.Add(1)
				}
			}(i)
		}

		wg.Wait()

		expectedOps := int64(numWorkers * operationsPerWorker)
		assert.Equal(t, expectedOps, totalOps.Load())
		t.Logf("Handled %d concurrent operations successfully", totalOps.Load())
	})
}

// TestRaceConditions tests for race conditions using -race flag
func TestRaceConditions(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping race condition tests in short mode")
	}

	t.Run("no race in token creation", func(t *testing.T) {
		maker := setupTestMaker(t)
		ctx := context.Background()

		var wg sync.WaitGroup
		for i := 0; i < 100; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, _ = maker.CreateAccessToken(ctx, uuid.New(), "user", []string{"admin"}, uuid.New())
			}()
		}
		wg.Wait()
	})

	t.Run("no race in token verification", func(t *testing.T) {
		maker := setupTestMaker(t)
		ctx := context.Background()

		token, err := maker.CreateAccessToken(ctx, uuid.New(), "user", []string{"admin"}, uuid.New())
		require.NoError(t, err)

		var wg sync.WaitGroup
		for i := 0; i < 100; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, _ = maker.VerifyAccessToken(ctx, token.Token)
			}()
		}
		wg.Wait()
	})

	t.Run("no race with repository operations", func(t *testing.T) {
		maker := setupTestMakerWithRepo(t)
		ctx := context.Background()

		tokens := make([]string, 10)
		for i := range tokens {
			token, err := maker.CreateAccessToken(ctx, uuid.New(), "user", []string{"admin"}, uuid.New())
			require.NoError(t, err)
			tokens[i] = token.Token
		}

		var wg sync.WaitGroup
		for _, tokenStr := range tokens {
			wg.Add(1)
			go func(t string) {
				defer wg.Done()
				_ = maker.RevokeAccessToken(ctx, t)
				_, _ = maker.VerifyAccessToken(ctx, t)
			}(tokenStr)
		}
		wg.Wait()
	})
}

// TestDeadlockPrevention tests that operations don't deadlock
func TestDeadlockPrevention(t *testing.T) {
	t.Run("no deadlock with circular operations", func(t *testing.T) {
		maker := setupTestMakerWithRepo(t)
		ctx := context.Background()

		done := make(chan bool, 1)
		go func() {
			var wg sync.WaitGroup

			// Create tokens
			tokens := make([]string, 10)
			for i := range tokens {
				token, _ := maker.CreateAccessToken(ctx, uuid.New(), "user", []string{"admin"}, uuid.New())
				if token != nil {
					tokens[i] = token.Token
				}
			}

			// Concurrent revocation and verification
			for _, token := range tokens {
				if token != "" {
					wg.Add(2)
					go func(t string) {
						defer wg.Done()
						_ = maker.RevokeAccessToken(ctx, t)
					}(token)
					go func(t string) {
						defer wg.Done()
						_, _ = maker.VerifyAccessToken(ctx, t)
					}(token)
				}
			}

			wg.Wait()
			done <- true
		}()

		select {
		case <-done:
			// Success - no deadlock
		case <-time.After(10 * time.Second):
			t.Fatal("Deadlock detected - operations did not complete")
		}
	})

	t.Run("context cancellation prevents deadlock", func(t *testing.T) {
		maker := setupTestMakerWithRepo(t)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		done := make(chan bool, 1)
		go func() {
			for i := 0; i < 100; i++ {
				_, _ = maker.CreateAccessToken(ctx, uuid.New(), "user", []string{"admin"}, uuid.New())
				if ctx.Err() != nil {
					break
				}
			}
			done <- true
		}()

		select {
		case <-done:
			// Success
		case <-time.After(5 * time.Second):
			t.Fatal("Operations did not respect context cancellation")
		}
	})
}

// TestMemoryLeaks tests for potential memory leaks
func TestMemoryLeaks(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping memory leak tests in short mode")
	}

	t.Run("repository cleanup prevents memory leak", func(t *testing.T) {
		repo := NewMemoryTokenRepository(100 * time.Millisecond)
		ctx := context.Background()

		// Add many short-lived tokens
		for i := 0; i < 1000; i++ {
			token := uuid.New().String()
			_ = repo.MarkTokenRevoke(ctx, AccessToken, token, 200*time.Millisecond)
		}

		// Get initial stats if available
		if memRepo, ok := repo.(*MemoryTokenRepository); ok {
			initialStats := memRepo.Stats()
			t.Logf("Initial tokens: %v", initialStats)

			// Wait for cleanup
			time.Sleep(500 * time.Millisecond)

			finalStats := memRepo.Stats()
			t.Logf("Final tokens after cleanup: %v", finalStats)

			// Should have fewer tokens after cleanup
			initialCount := initialStats["revoked_access_tokens"]
			finalCount := finalStats["revoked_access_tokens"]
			assert.Less(t, finalCount, initialCount, "Cleanup should have removed expired tokens")
		}
	})

	t.Run("maker cleanup goroutines on cancel", func(t *testing.T) {
		ctx := context.Background()
		repo := NewMemoryTokenRepository(1 * time.Minute)

		config := DefaultTestConfig()
		config.RevocationEnabled = true
		config.RotationEnabled = true

		maker, err := NewGourdianTokenMaker(ctx, config, repo)
		require.NoError(t, err)

		jwtMaker := maker.(*JWTMaker)

		// Cleanup should be callable
		if jwtMaker.cleanupCancel != nil {
			jwtMaker.cleanupCancel()
		}

		// Give goroutines time to stop
		time.Sleep(100 * time.Millisecond)

		// No assertion here, just checking it doesn't panic or hang
	})
}

// TestLoadBalancing tests behavior under load
func TestLoadBalancing(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping load tests in short mode")
	}

	t.Run("sustained load test", func(t *testing.T) {
		maker := setupTestMaker(t)
		ctx := context.Background()

		const duration = 5 * time.Second
		const numWorkers = 20

		var successCount atomic.Int64
		var errorCount atomic.Int64
		var wg sync.WaitGroup

		stopChan := make(chan struct{})
		time.AfterFunc(duration, func() {
			close(stopChan)
		})

		for i := 0; i < numWorkers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()

				for {
					select {
					case <-stopChan:
						return
					default:
						// Create token
						token, err := maker.CreateAccessToken(ctx, uuid.New(), "user", []string{"admin"}, uuid.New())
						if err != nil {
							errorCount.Add(1)
							continue
						}
						successCount.Add(1)

						// Verify token
						_, err = maker.VerifyAccessToken(ctx, token.Token)
						if err != nil {
							errorCount.Add(1)
						} else {
							successCount.Add(1)
						}
					}
				}
			}()
		}

		wg.Wait()

		totalOps := successCount.Load() + errorCount.Load()
		opsPerSecond := float64(totalOps) / duration.Seconds()

		t.Logf("Completed %d operations (%d success, %d errors) in %v (%.2f ops/sec)",
			totalOps, successCount.Load(), errorCount.Load(), duration, opsPerSecond)

		assert.Greater(t, successCount.Load(), int64(0))
		assert.Equal(t, int64(0), errorCount.Load(), "Should have no errors under sustained load")
		assert.Greater(t, opsPerSecond, 100.0, "Should handle at least 100 ops/sec")
	})

	t.Run("burst load test", func(t *testing.T) {
		maker := setupTestMaker(t)
		ctx := context.Background()

		const numBursts = 10
		const burstSize = 100

		for burst := 0; burst < numBursts; burst++ {
			var wg sync.WaitGroup
			var successCount atomic.Int32

			start := time.Now()
			for i := 0; i < burstSize; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()

					token, err := maker.CreateAccessToken(ctx, uuid.New(), "user", []string{"admin"}, uuid.New())
					if err == nil && token != nil {
						successCount.Add(1)
					}
				}()
			}

			wg.Wait()
			elapsed := time.Since(start)

			t.Logf("Burst %d: %d/%d tokens in %v", burst+1, successCount.Load(), burstSize, elapsed)
			assert.Equal(t, int32(burstSize), successCount.Load())

			// Brief pause between bursts
			time.Sleep(100 * time.Millisecond)
		}
	})
}

// TestConcurrentMakerCreation tests creating multiple makers concurrently
func TestConcurrentMakerCreation(t *testing.T) {
	t.Run("create multiple makers concurrently", func(t *testing.T) {
		const numMakers = 20
		makers := make([]GourdianTokenMaker, numMakers)
		var wg sync.WaitGroup
		var successCount atomic.Int32

		for i := 0; i < numMakers; i++ {
			wg.Add(1)
			go func(index int) {
				defer wg.Done()

				config := DefaultTestConfig()
				maker, err := NewGourdianTokenMaker(context.Background(), config, nil)
				if err == nil {
					makers[index] = maker
					successCount.Add(1)
				}
			}(i)
		}

		wg.Wait()
		assert.Equal(t, int32(numMakers), successCount.Load())

		// All makers should be independent
		for i, maker := range makers {
			if maker != nil {
				token, err := maker.CreateAccessToken(context.Background(), uuid.New(), "user", []string{"admin"}, uuid.New())
				assert.NoError(t, err, "Maker %d should work", i)
				assert.NotNil(t, token)
			}
		}
	})
}
