// File: gourdiantoken_concurrency_test.go

package gourdiantoken

import (
	"context"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestConcurrentTokenOperations(t *testing.T) {
	maker, err := DefaultGourdianTokenMaker(context.Background(), testSymmetricKey, testRedisOptions())
	require.NoError(t, err)

	var wg sync.WaitGroup
	userID := uuid.New()
	sessionID := uuid.New()

	// Test concurrent token creation
	t.Run("Concurrent Creation", func(t *testing.T) {
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, err := maker.CreateAccessToken(context.Background(), userID, "user", []string{"admin"}, sessionID)
				require.NoError(t, err)
			}()
		}
		wg.Wait()
	})

	// Test concurrent verification
	t.Run("Concurrent Verification", func(t *testing.T) {
		token, err := maker.CreateAccessToken(context.Background(), userID, "user", []string{"admin"}, sessionID)
		require.NoError(t, err)

		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, err := maker.VerifyAccessToken(context.Background(), token.Token)
				require.NoError(t, err)
			}()
		}
		wg.Wait()
	})

	// In the concurrent rotation test, modify the maker creation to ensure fresh config
	t.Run("Concurrent Rotation", func(t *testing.T) {
		// Create a new maker with fresh config for this test
		config := DefaultGourdianTokenConfig(testSymmetricKey)
		config.RotationEnabled = true
		maker, err := NewGourdianTokenMaker(context.Background(), config, testRedisOptions())
		require.NoError(t, err)

		refreshToken, err := maker.CreateRefreshToken(context.Background(), userID, "user", sessionID)
		require.NoError(t, err)

		var successCount int
		var mu sync.Mutex
		var wg sync.WaitGroup

		for i := 0; i < 5; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, err := maker.RotateRefreshToken(context.Background(), refreshToken.Token)
				if err == nil {
					mu.Lock()
					successCount++
					mu.Unlock()
				}
			}()
		}
		wg.Wait()

		require.Equal(t, 1, successCount, "only one rotation should succeed")
	})
}
