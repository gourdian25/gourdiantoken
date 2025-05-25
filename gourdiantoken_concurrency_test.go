// gourdiantoken_concurrency_test.go
package gourdiantoken

import (
	"context"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestConcurrentTokenOperations(t *testing.T) {
	config := DefaultGourdianTokenConfig(testSymmetricKey)
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

	// Test concurrent rotation
	t.Run("Concurrent Rotation", func(t *testing.T) {
		config.RotationEnabled = true
		refreshToken, err := maker.CreateRefreshToken(context.Background(), userID, "user", sessionID)
		require.NoError(t, err)

		// Only one rotation should succeed
		var successCount int
		var mu sync.Mutex

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
