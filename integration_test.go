// File: integration_test.go


package gourdiantoken

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCompleteTokenLifecycle tests the entire lifecycle of tokens
func TestCompleteTokenLifecycle(t *testing.T) {
	t.Run("complete access token lifecycle", func(t *testing.T) {
		maker := setupTestMakerWithRepo(t)
		ctx := context.Background()

		userID := uuid.New()
		sessionID := uuid.New()
		username := "testuser"
		roles := []string{"admin", "user"}

		// Step 1: Create token
		token, err := maker.CreateAccessToken(ctx, userID, username, roles, sessionID)
		require.NoError(t, err)
		require.NotNil(t, token)
		assert.NotEmpty(t, token.Token)
		t.Logf("Step 1: Created token")

		// Step 2: Verify token works
		claims, err := maker.VerifyAccessToken(ctx, token.Token)
		require.NoError(t, err)
		assert.Equal(t, userID, claims.Subject)
		assert.Equal(t, username, claims.Username)
		assert.Equal(t, roles, claims.Roles)
		t.Logf("Step 2: Verified token")

		// Step 3: Use token multiple times
		for i := 0; i < 5; i++ {
			claims, err := maker.VerifyAccessToken(ctx, token.Token)
			require.NoError(t, err)
			assert.NotNil(t, claims)
		}
		t.Logf("Step 3: Used token multiple times")

		// Step 4: Revoke token
		err = maker.RevokeAccessToken(ctx, token.Token)
		require.NoError(t, err)
		t.Logf("Step 4: Revoked token")

		// Step 5: Verify token is now invalid
		claims, err = maker.VerifyAccessToken(ctx, token.Token)
		assert.Error(t, err)
		assert.Nil(t, claims)
		assert.Contains(t, err.Error(), "revoked")
		t.Logf("Step 5: Confirmed token is revoked")

		// Step 6: Cannot revoke again (but should not error)
		err = maker.RevokeAccessToken(ctx, token.Token)
		assert.NoError(t, err) // Idempotent
		t.Logf("Step 6: Confirmed revocation is idempotent")
	})

	t.Run("complete refresh token lifecycle with rotation", func(t *testing.T) {
		maker := setupTestMakerWithRepo(t)
		ctx := context.Background()

		userID := uuid.New()
		sessionID := uuid.New()
		username := "testuser"

		// Step 1: Create initial refresh token
		token1, err := maker.CreateRefreshToken(ctx, userID, username, sessionID)
		require.NoError(t, err)
		t.Logf("Step 1: Created initial refresh token")

		// Step 2: Verify it works
		claims1, err := maker.VerifyRefreshToken(ctx, token1.Token)
		require.NoError(t, err)
		assert.Equal(t, userID, claims1.Subject)
		t.Logf("Step 2: Verified initial token")

		// Step 3: Rotate token
		token2, err := maker.RotateRefreshToken(ctx, token1.Token)
		require.NoError(t, err)
		require.NotNil(t, token2)
		assert.NotEqual(t, token1.Token, token2.Token)
		t.Logf("Step 3: Rotated to new token")

		// Step 4: Old token cannot be used
		_, err = maker.VerifyRefreshToken(ctx, token1.Token)
		assert.Error(t, err)
		t.Logf("Step 4: Old token rejected")

		// Step 5: New token works
		claims2, err := maker.VerifyRefreshToken(ctx, token2.Token)
		require.NoError(t, err)
		assert.Equal(t, userID, claims2.Subject)
		assert.Equal(t, sessionID, claims2.SessionID)
		t.Logf("Step 5: New token works")

		// Step 6: Cannot rotate old token again - FIXED EXPECTATION
		_, err = maker.RotateRefreshToken(ctx, token1.Token)
		assert.Error(t, err)
		// Changed from "already been rotated" to match actual error message
		assert.Contains(t, err.Error(), "token has been rotated",
			"Error should indicate token was rotated")
		t.Logf("Step 6: Cannot reuse old token")

		// Step 7: Rotate new token
		token3, err := maker.RotateRefreshToken(ctx, token2.Token)
		require.NoError(t, err)
		t.Logf("Step 7: Rotated to third token")

		// Step 8: Revoke final token
		err = maker.RevokeRefreshToken(ctx, token3.Token)
		require.NoError(t, err)
		t.Logf("Step 8: Revoked final token")

		// Step 9: Verify revocation
		_, err = maker.VerifyRefreshToken(ctx, token3.Token)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "revoked")
		t.Logf("Step 9: Confirmed final token is revoked")
	})
}

// TestTokenRotationFlow tests the complete token rotation flow
func TestTokenRotationFlow(t *testing.T) {
	t.Run("rotation chain maintains user session", func(t *testing.T) {
		maker := setupTestMakerWithRepo(t)
		ctx := context.Background()

		userID := uuid.New()
		sessionID := uuid.New()
		username := "testuser"

		// Create initial token
		currentToken, err := maker.CreateRefreshToken(ctx, userID, username, sessionID)
		require.NoError(t, err)

		// Rotate 10 times
		for i := 0; i < 10; i++ {
			// Verify current token
			claims, err := maker.VerifyRefreshToken(ctx, currentToken.Token)
			require.NoError(t, err)
			assert.Equal(t, userID, claims.Subject)
			assert.Equal(t, sessionID, claims.SessionID)
			assert.Equal(t, username, claims.Username)

			// Rotate to new token
			newToken, err := maker.RotateRefreshToken(ctx, currentToken.Token)
			require.NoError(t, err)
			require.NotNil(t, newToken)

			// Verify session continuity
			assert.Equal(t, userID, newToken.Subject)
			assert.Equal(t, sessionID, newToken.SessionID)
			assert.Equal(t, username, newToken.Username)

			currentToken = newToken

			// Small delay
			time.Sleep(10 * time.Millisecond)
		}

		t.Logf("Successfully rotated token 10 times maintaining session")
	})

	t.Run("rotation with reuse interval enforcement", func(t *testing.T) {
		config := DefaultTestConfig()
		config.RefreshReuseInterval = 1 * time.Second
		repo := NewMemoryTokenRepository(1 * time.Minute)
		maker := setupTestMakerWithConfig(t, config, repo)
		ctx := context.Background()

		// Create token
		token, err := maker.CreateRefreshToken(ctx, uuid.New(), "user", uuid.New())
		require.NoError(t, err)

		// Rotate once
		newToken, err := maker.RotateRefreshToken(ctx, token.Token)
		require.NoError(t, err)
		require.NotNil(t, newToken)

		// Try to rotate old token immediately - should fail
		_, err = maker.RotateRefreshToken(ctx, token.Token)
		assert.Error(t, err)

		// Wait for reuse interval
		time.Sleep(1100 * time.Millisecond)

		// Should still fail (already rotated) - FIXED EXPECTATION
		_, err = maker.RotateRefreshToken(ctx, token.Token)
		assert.Error(t, err)
		// Changed from "already been rotated" to match actual error message
		assert.Contains(t, err.Error(), "token has been rotated",
			"Error should indicate token was rotated")
	})

	t.Run("parallel rotation attempts detected", func(t *testing.T) {
		maker := setupTestMakerWithRepo(t)
		ctx := context.Background()

		token, err := maker.CreateRefreshToken(ctx, uuid.New(), "user", uuid.New())
		require.NoError(t, err)

		// Try to rotate same token concurrently
		results := make(chan error, 3)
		for i := 0; i < 3; i++ {
			go func() {
				_, err := maker.RotateRefreshToken(ctx, token.Token)
				results <- err
			}()
		}

		// Collect results
		successCount := 0
		errorCount := 0
		for i := 0; i < 3; i++ {
			err := <-results
			if err == nil {
				successCount++
			} else {
				errorCount++
			}
		}

		// Only one should succeed
		assert.Equal(t, 1, successCount, "Only one rotation should succeed")
		assert.Equal(t, 2, errorCount, "Other attempts should fail")
	})
}

// TestRevocationFlow tests the complete revocation flow
func TestRevocationFlow(t *testing.T) {
	t.Run("revoke and verify across multiple operations", func(t *testing.T) {
		maker := setupTestMakerWithRepo(t)
		ctx := context.Background()

		// Create multiple tokens
		tokens := make([]*AccessTokenResponse, 5)
		for i := range tokens {
			token, err := maker.CreateAccessToken(ctx, uuid.New(), "user", []string{"admin"}, uuid.New())
			require.NoError(t, err)
			tokens[i] = token
		}

		// Verify all work
		for _, token := range tokens {
			claims, err := maker.VerifyAccessToken(ctx, token.Token)
			require.NoError(t, err)
			assert.NotNil(t, claims)
		}

		// Revoke some tokens
		err := maker.RevokeAccessToken(ctx, tokens[1].Token)
		require.NoError(t, err)
		err = maker.RevokeAccessToken(ctx, tokens[3].Token)
		require.NoError(t, err)

		// Verify revocation status
		for i, token := range tokens {
			claims, err := maker.VerifyAccessToken(ctx, token.Token)
			if i == 1 || i == 3 {
				assert.Error(t, err)
				assert.Nil(t, claims)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, claims)
			}
		}
	})

	t.Run("revocation persists across restarts", func(t *testing.T) {
		repo := NewMemoryTokenRepository(1 * time.Minute)

		config := DefaultTestConfig()
		maker1 := setupTestMakerWithConfig(t, config, repo)
		ctx := context.Background()

		// Create and revoke token
		token, err := maker1.CreateAccessToken(ctx, uuid.New(), "user", []string{"admin"}, uuid.New())
		require.NoError(t, err)

		err = maker1.RevokeAccessToken(ctx, token.Token)
		require.NoError(t, err)

		// Create new maker instance with same repository
		maker2 := setupTestMakerWithConfig(t, config, repo)

		// Revocation should still be effective
		claims, err := maker2.VerifyAccessToken(ctx, token.Token)
		assert.Error(t, err)
		assert.Nil(t, claims)
		assert.Contains(t, err.Error(), "revoked")
	})

	t.Run("revocation without repository returns error", func(t *testing.T) {
		maker := setupTestMaker(t) // No repository
		ctx := context.Background()

		token, err := maker.CreateAccessToken(ctx, uuid.New(), "user", []string{"admin"}, uuid.New())
		require.NoError(t, err)

		err = maker.RevokeAccessToken(ctx, token.Token)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "revocation is not enabled")
	})
}

// TestRepository_AllImplementations tests all repository implementations
func TestRepository_AllImplementations(t *testing.T) {
	testCases := []struct {
		name string
		repo func() TokenRepository
	}{
		{
			name: "MemoryTokenRepository",
			repo: func() TokenRepository {
				return NewMemoryTokenRepository(1 * time.Minute)
			},
		},
		// Add other repositories when testing with actual databases
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			repo := tc.repo()
			ctx := context.Background()

			// Test revocation operations
			t.Run("revocation operations", func(t *testing.T) {
				token := uuid.New().String()

				// Mark as revoked
				err := repo.MarkTokenRevoke(ctx, AccessToken, token, 5*time.Minute)
				assert.NoError(t, err)

				// Check if revoked
				revoked, err := repo.IsTokenRevoked(ctx, AccessToken, token)
				assert.NoError(t, err)
				assert.True(t, revoked)

				// Different token should not be revoked
				otherToken := uuid.New().String()
				revoked, err = repo.IsTokenRevoked(ctx, AccessToken, otherToken)
				assert.NoError(t, err)
				assert.False(t, revoked)
			})

			// Test rotation operations
			t.Run("rotation operations", func(t *testing.T) {
				token := uuid.New().String()

				// Mark as rotated
				err := repo.MarkTokenRotated(ctx, token, 5*time.Minute)
				assert.NoError(t, err)

				// Check if rotated
				rotated, err := repo.IsTokenRotated(ctx, token)
				assert.NoError(t, err)
				assert.True(t, rotated)

				// Get TTL
				ttl, err := repo.GetRotationTTL(ctx, token)
				assert.NoError(t, err)
				assert.Greater(t, ttl, time.Duration(0))
				assert.LessOrEqual(t, ttl, 5*time.Minute)
			})

			// Test cleanup operations
			t.Run("cleanup operations", func(t *testing.T) {
				// Create expired tokens
				expiredToken := uuid.New().String()
				err := repo.MarkTokenRevoke(ctx, AccessToken, expiredToken, 1*time.Millisecond)
				assert.NoError(t, err)

				// Wait for expiration
				time.Sleep(10 * time.Millisecond)

				// Cleanup
				err = repo.CleanupExpiredRevokedTokens(ctx, AccessToken)
				assert.NoError(t, err)

				// Should not be found
				revoked, err := repo.IsTokenRevoked(ctx, AccessToken, expiredToken)
				assert.NoError(t, err)
				assert.False(t, revoked)
			})
		})
	}
}

// TestCrossRepositoryCompatibility tests maker with different repositories
func TestCrossRepositoryCompatibility(t *testing.T) {
	t.Run("same token works with different repository instances", func(t *testing.T) {
		repo1 := NewMemoryTokenRepository(1 * time.Minute)
		config := DefaultTestConfig()
		maker := setupTestMakerWithConfig(t, config, repo1)
		ctx := context.Background()

		// Create token with first repository
		token, err := maker.CreateAccessToken(ctx, uuid.New(), "user", []string{"admin"}, uuid.New())
		require.NoError(t, err)

		// Revoke with first repository
		err = maker.RevokeAccessToken(ctx, token.Token)
		require.NoError(t, err)

		// Verify revocation works
		claims, err := maker.VerifyAccessToken(ctx, token.Token)
		assert.Error(t, err)
		assert.Nil(t, claims)
	})

	t.Run("tokens remain valid when switching from no repo to repo", func(t *testing.T) {
		// Create maker without repository
		maker1 := setupTestMaker(t)
		ctx := context.Background()

		token, err := maker1.CreateAccessToken(ctx, uuid.New(), "user", []string{"admin"}, uuid.New())
		require.NoError(t, err)

		// Create new maker with repository
		repo := NewMemoryTokenRepository(1 * time.Minute)
		config := DefaultTestConfig()
		maker2 := setupTestMakerWithConfig(t, config, repo)

		// Token should still be valid (not in revocation list)
		claims, err := maker2.VerifyAccessToken(ctx, token.Token)
		assert.NoError(t, err)
		assert.NotNil(t, claims)
	})
}

// TestEndToEndScenarios tests realistic use cases
func TestEndToEndScenarios(t *testing.T) {
	t.Run("user login and session management", func(t *testing.T) {
		maker := setupTestMakerWithRepo(t)
		ctx := context.Background()

		userID := uuid.New()
		sessionID := uuid.New()

		// User logs in - gets both tokens
		accessToken, err := maker.CreateAccessToken(ctx, userID, "user@example.com", []string{"user"}, sessionID)
		require.NoError(t, err)

		refreshToken, err := maker.CreateRefreshToken(ctx, userID, "user@example.com", sessionID)
		require.NoError(t, err)

		// User makes API calls with access token
		for i := 0; i < 10; i++ {
			claims, err := maker.VerifyAccessToken(ctx, accessToken.Token)
			require.NoError(t, err)
			assert.Equal(t, userID, claims.Subject)
			assert.Equal(t, sessionID, claims.SessionID)
		}

		// Access token expires, user refreshes with refresh token
		newRefreshToken, err := maker.RotateRefreshToken(ctx, refreshToken.Token)
		require.NoError(t, err)

		// Create new access token
		newAccessToken, err := maker.CreateAccessToken(ctx, userID, "user@example.com", []string{"user"}, sessionID)
		require.NoError(t, err)

		// Continue using new access token
		claims, err := maker.VerifyAccessToken(ctx, newAccessToken.Token)
		require.NoError(t, err)
		assert.Equal(t, sessionID, claims.SessionID)

		// User logs out - revoke all tokens
		err = maker.RevokeAccessToken(ctx, newAccessToken.Token)
		require.NoError(t, err)
		err = maker.RevokeRefreshToken(ctx, newRefreshToken.Token)
		require.NoError(t, err)

		// Tokens no longer work
		_, err = maker.VerifyAccessToken(ctx, newAccessToken.Token)
		assert.Error(t, err)
		_, err = maker.VerifyRefreshToken(ctx, newRefreshToken.Token)
		assert.Error(t, err)

		t.Logf("Complete user session lifecycle successful")
	})

	t.Run("user login with rapid token refreshes", func(t *testing.T) {
		maker := setupTestMakerWithRepo(t)
		ctx := context.Background()

		userID := uuid.New()
		sessionID := uuid.New()

		// Initial refresh token
		currentRefreshToken, err := maker.CreateRefreshToken(ctx, userID, "user", sessionID)
		require.NoError(t, err)

		// Simulate rapid refresh attempts (e.g., multiple clients)
		for i := 0; i < 10; i++ {
			// Create new access token
			accessToken, err := maker.CreateAccessToken(ctx, userID, "user", []string{"user"}, sessionID)
			require.NoError(t, err)
			assert.NotNil(t, accessToken)

			// Verify it works
			_, err = maker.VerifyAccessToken(ctx, accessToken.Token)
			require.NoError(t, err)

			// Rotate refresh token
			newRefreshToken, err := maker.RotateRefreshToken(ctx, currentRefreshToken.Token)
			require.NoError(t, err)
			currentRefreshToken = newRefreshToken

			time.Sleep(10 * time.Millisecond)
		}

		t.Logf("Rapid refresh scenario successful")
	})

	t.Run("user session with network interruption simulation", func(t *testing.T) {
		maker := setupTestMakerWithRepo(t)
		ctx := context.Background()

		userID := uuid.New()
		sessionID := uuid.New()

		// Create tokens
		accessToken, err := maker.CreateAccessToken(ctx, userID, "user", []string{"user"}, sessionID)
		require.NoError(t, err)
		refreshToken, err := maker.CreateRefreshToken(ctx, userID, "user", sessionID)
		require.NoError(t, err)

		// Simulate network interruption - context timeout
		timeoutCtx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
		defer cancel()
		time.Sleep(10 * time.Millisecond)

		// Operations during "network issue" should fail
		_, err = maker.CreateAccessToken(timeoutCtx, userID, "user", []string{"user"}, sessionID)
		assert.Error(t, err)

		// After "network recovery" - operations should work
		_, err = maker.VerifyAccessToken(context.Background(), accessToken.Token)
		assert.NoError(t, err)

		// Can still rotate refresh token
		_, err = maker.RotateRefreshToken(context.Background(), refreshToken.Token)
		assert.NoError(t, err)

		t.Logf("Network interruption recovery successful")
	})

	t.Run("user session with invalid token attempts", func(t *testing.T) {
		maker := setupTestMakerWithRepo(t)
		ctx := context.Background()

		userID := uuid.New()
		sessionID := uuid.New()

		// Create valid token
		validToken, err := maker.CreateAccessToken(ctx, userID, "user", []string{"user"}, sessionID)
		require.NoError(t, err)

		// Multiple invalid token attempts (potential attack)
		invalidTokens := []string{
			"invalid.token.1",
			"hacker.attempt.2",
			"malicious.token.3",
			"",
			validToken.Token + "corrupted",
		}

		for _, invalidToken := range invalidTokens {
			_, err := maker.VerifyAccessToken(ctx, invalidToken)
			assert.Error(t, err)
		}

		// Valid token should still work after attack attempts
		claims, err := maker.VerifyAccessToken(ctx, validToken.Token)
		assert.NoError(t, err)
		assert.NotNil(t, claims)

		t.Logf("System resilient to invalid token attempts")
	})

	t.Run("multi-device user session", func(t *testing.T) {
		maker := setupTestMakerWithRepo(t)
		ctx := context.Background()

		userID := uuid.New()

		// User logs in on device 1
		session1 := uuid.New()
		device1AccessToken, err := maker.CreateAccessToken(ctx, userID, "user", []string{"user"}, session1)
		require.NoError(t, err)
		device1RefreshToken, err := maker.CreateRefreshToken(ctx, userID, "user", session1)
		require.NoError(t, err)

		// User logs in on device 2
		session2 := uuid.New()
		device2AccessToken, err := maker.CreateAccessToken(ctx, userID, "user", []string{"user"}, session2)
		require.NoError(t, err)
		device2RefreshToken, err := maker.CreateRefreshToken(ctx, userID, "user", session2)
		require.NoError(t, err)

		// Both devices can use their tokens
		claims1, err := maker.VerifyAccessToken(ctx, device1AccessToken.Token)
		require.NoError(t, err)
		assert.Equal(t, session1, claims1.SessionID)

		claims2, err := maker.VerifyAccessToken(ctx, device2AccessToken.Token)
		require.NoError(t, err)
		assert.Equal(t, session2, claims2.SessionID)

		// User logs out from device 1
		err = maker.RevokeAccessToken(ctx, device1AccessToken.Token)
		require.NoError(t, err)
		err = maker.RevokeRefreshToken(ctx, device1RefreshToken.Token)
		require.NoError(t, err)

		// Device 1 tokens don't work
		_, err = maker.VerifyAccessToken(ctx, device1AccessToken.Token)
		assert.Error(t, err)

		// Device 2 tokens still work
		claims2, err = maker.VerifyAccessToken(ctx, device2AccessToken.Token)
		require.NoError(t, err)
		assert.Equal(t, session2, claims2.SessionID)

		// Device 2 can refresh its token
		newDevice2RefreshToken, err := maker.RotateRefreshToken(ctx, device2RefreshToken.Token)
		require.NoError(t, err)
		assert.NotNil(t, newDevice2RefreshToken)
		assert.Equal(t, session2, newDevice2RefreshToken.SessionID)

		t.Logf("Multi-device session management successful")
	})

	t.Run("multi-device with cross-device token usage attempt", func(t *testing.T) {
		maker := setupTestMakerWithRepo(t)
		ctx := context.Background()

		userID := uuid.New()

		// Device 1 session
		session1 := uuid.New()
		device1Token, err := maker.CreateAccessToken(ctx, userID, "user", []string{"user"}, session1)
		require.NoError(t, err)

		// Device 2 session
		session2 := uuid.New()
		device2Token, err := maker.CreateAccessToken(ctx, userID, "user", []string{"user"}, session2)
		require.NoError(t, err)

		// Verify each token has its own session
		claims1, err := maker.VerifyAccessToken(ctx, device1Token.Token)
		require.NoError(t, err)
		assert.Equal(t, session1, claims1.SessionID)

		claims2, err := maker.VerifyAccessToken(ctx, device2Token.Token)
		require.NoError(t, err)
		assert.Equal(t, session2, claims2.SessionID)
		assert.NotEqual(t, claims1.SessionID, claims2.SessionID)

		// Both tokens belong to same user but different sessions
		assert.Equal(t, claims1.Subject, claims2.Subject)
		assert.NotEqual(t, claims1.SessionID, claims2.SessionID)

		t.Logf("Cross-device session isolation verified")
	})

	t.Run("token refresh with role elevation", func(t *testing.T) {
		maker := setupTestMakerWithRepo(t)
		ctx := context.Background()

		userID := uuid.New()
		sessionID := uuid.New()

		// User starts with basic role
		token1, err := maker.CreateAccessToken(ctx, userID, "user", []string{"user"}, sessionID)
		require.NoError(t, err)

		claims1, err := maker.VerifyAccessToken(ctx, token1.Token)
		require.NoError(t, err)
		assert.Equal(t, []string{"user"}, claims1.Roles)

		// User gets elevated permissions
		token2, err := maker.CreateAccessToken(ctx, userID, "user", []string{"user", "admin"}, sessionID)
		require.NoError(t, err)

		claims2, err := maker.VerifyAccessToken(ctx, token2.Token)
		require.NoError(t, err)
		assert.Contains(t, claims2.Roles, "admin")

		// Old token still has old roles
		claims1Again, err := maker.VerifyAccessToken(ctx, token1.Token)
		require.NoError(t, err)
		assert.NotContains(t, claims1Again.Roles, "admin")

		// Revoke old token to enforce new permissions
		err = maker.RevokeAccessToken(ctx, token1.Token)
		require.NoError(t, err)

		t.Logf("Role elevation scenario successful")
	})

	t.Run("security breach - revoke all user sessions", func(t *testing.T) {
		maker := setupTestMakerWithRepo(t)
		ctx := context.Background()

		userID := uuid.New()

		// User has multiple sessions
		sessions := make([]uuid.UUID, 3)
		accessTokens := make([]*AccessTokenResponse, 3)
		refreshTokens := make([]*RefreshTokenResponse, 3)

		for i := range sessions {
			sessions[i] = uuid.New()

			at, err := maker.CreateAccessToken(ctx, userID, "user", []string{"user"}, sessions[i])
			require.NoError(t, err)
			accessTokens[i] = at

			rt, err := maker.CreateRefreshToken(ctx, userID, "user", sessions[i])
			require.NoError(t, err)
			refreshTokens[i] = rt
		}

		// All tokens work initially
		for _, token := range accessTokens {
			claims, err := maker.VerifyAccessToken(ctx, token.Token)
			require.NoError(t, err)
			assert.Equal(t, userID, claims.Subject)
		}

		// Security breach detected - revoke all tokens
		for _, token := range accessTokens {
			err := maker.RevokeAccessToken(ctx, token.Token)
			require.NoError(t, err)
		}
		for _, token := range refreshTokens {
			err := maker.RevokeRefreshToken(ctx, token.Token)
			require.NoError(t, err)
		}

		// All tokens now invalid
		for _, token := range accessTokens {
			_, err := maker.VerifyAccessToken(ctx, token.Token)
			assert.Error(t, err)
		}
		for _, token := range refreshTokens {
			_, err := maker.VerifyRefreshToken(ctx, token.Token)
			assert.Error(t, err)
		}

		t.Logf("Bulk revocation for security breach successful")
	})

	t.Run("token theft detection via rotation", func(t *testing.T) {
		maker := setupTestMakerWithRepo(t)
		ctx := context.Background()

		userID := uuid.New()
		sessionID := uuid.New()

		// Create refresh token
		refreshToken, err := maker.CreateRefreshToken(ctx, userID, "user", sessionID)
		require.NoError(t, err)

		// Legitimate user rotates token
		newToken, err := maker.RotateRefreshToken(ctx, refreshToken.Token)
		require.NoError(t, err)

		// Attacker tries to use stolen old token - FIXED EXPECTATION
		_, err = maker.RotateRefreshToken(ctx, refreshToken.Token)
		assert.Error(t, err)
		// Changed from "already been rotated" to match actual error message
		assert.Contains(t, err.Error(), "token has been rotated",
			"Error should indicate token was rotated")

		// System detects attempted reuse - could trigger security alert
		t.Logf("Token theft detected through rotation mechanism")

		// New token still works for legitimate user
		claims, err := maker.VerifyRefreshToken(ctx, newToken.Token)
		require.NoError(t, err)
		assert.Equal(t, userID, claims.Subject)
	})
}

// TestComplexWorkflows tests complex real-world workflows
func TestComplexWorkflows(t *testing.T) {
	t.Run("long running session with periodic refreshes", func(t *testing.T) {
		config := DefaultTestConfig()
		// Use more reasonable durations for testing
		config.AccessExpiryDuration = 2 * time.Second
		config.RefreshExpiryDuration = 30 * time.Second
		repo := NewMemoryTokenRepository(1 * time.Minute)
		maker := setupTestMakerWithConfig(t, config, repo)
		ctx := context.Background()

		userID := uuid.New()
		sessionID := uuid.New()

		// Initial tokens
		currentAccessToken, err := maker.CreateAccessToken(ctx, userID, "user", []string{"user"}, sessionID)
		require.NoError(t, err)
		currentRefreshToken, err := maker.CreateRefreshToken(ctx, userID, "user", sessionID)
		require.NoError(t, err)

		// Simulate long session with periodic refreshes
		for i := 0; i < 3; i++ {
			// Use access token immediately after creation (should work)
			claims, err := maker.VerifyAccessToken(ctx, currentAccessToken.Token)
			require.NoError(t, err, "Token should be valid immediately after creation")
			assert.Equal(t, sessionID, claims.SessionID)

			// Wait for access token to expire (but not too long for test stability)
			time.Sleep(2100 * time.Millisecond) // Just over 2 seconds

			// Access token should be expired now
			_, err = maker.VerifyAccessToken(ctx, currentAccessToken.Token)
			assert.Error(t, err, "Token should be expired after waiting")
			if err != nil {
				assert.Contains(t, err.Error(), "expired", "Error should indicate token expired")
			}

			// Rotate refresh token and create new access token
			newRefreshToken, err := maker.RotateRefreshToken(ctx, currentRefreshToken.Token)
			require.NoError(t, err)

			newAccessToken, err := maker.CreateAccessToken(ctx, userID, "user", []string{"user"}, sessionID)
			require.NoError(t, err)

			currentAccessToken = newAccessToken
			currentRefreshToken = newRefreshToken
		}

		t.Logf("Successfully maintained session through refresh cycles")
	})

	t.Run("concurrent users with high activity", func(t *testing.T) {
		maker := setupTestMakerWithRepo(t)
		ctx := context.Background()

		const numUsers = 20
		const actionsPerUser = 10

		type userSession struct {
			userID       uuid.UUID
			sessionID    uuid.UUID
			accessToken  *AccessTokenResponse
			refreshToken *RefreshTokenResponse
		}

		sessions := make([]*userSession, numUsers)

		// Create sessions for all users
		for i := range sessions {
			userID := uuid.New()
			sessionID := uuid.New()

			at, err := maker.CreateAccessToken(ctx, userID, "user", []string{"user"}, sessionID)
			require.NoError(t, err)

			rt, err := maker.CreateRefreshToken(ctx, userID, "user", sessionID)
			require.NoError(t, err)

			sessions[i] = &userSession{
				userID:       userID,
				sessionID:    sessionID,
				accessToken:  at,
				refreshToken: rt,
			}
		}

		// Each user performs multiple actions
		for _, session := range sessions {
			for j := 0; j < actionsPerUser; j++ {
				claims, err := maker.VerifyAccessToken(ctx, session.accessToken.Token)
				require.NoError(t, err)
				assert.Equal(t, session.userID, claims.Subject)
			}
		}

		// Some users rotate tokens
		for i := 0; i < numUsers/2; i++ {
			newRT, err := maker.RotateRefreshToken(ctx, sessions[i].refreshToken.Token)
			require.NoError(t, err)
			sessions[i].refreshToken = newRT
		}

		// Some users log out
		for i := 0; i < numUsers/4; i++ {
			err := maker.RevokeAccessToken(ctx, sessions[i].accessToken.Token)
			require.NoError(t, err)
			err = maker.RevokeRefreshToken(ctx, sessions[i].refreshToken.Token)
			require.NoError(t, err)
		}

		t.Logf("Successfully managed %d concurrent user sessions", numUsers)
	})

	t.Run("graceful degradation without repository", func(t *testing.T) {
		maker := setupTestMaker(t) // No repository
		ctx := context.Background()

		// Can still create and verify tokens
		token, err := maker.CreateAccessToken(ctx, uuid.New(), "user", []string{"user"}, uuid.New())
		require.NoError(t, err)

		claims, err := maker.VerifyAccessToken(ctx, token.Token)
		require.NoError(t, err)
		assert.NotNil(t, claims)

		// Revocation returns error but doesn't crash
		err = maker.RevokeAccessToken(ctx, token.Token)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not enabled")

		// Rotation returns error but doesn't crash
		refreshToken, err := maker.CreateRefreshToken(ctx, uuid.New(), "user", uuid.New())
		require.NoError(t, err)

		_, err = maker.RotateRefreshToken(ctx, refreshToken.Token)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not enabled")

		t.Logf("System gracefully degrades without repository")
	})
}

// TestErrorRecovery tests recovery from error conditions
func TestErrorRecovery(t *testing.T) {
	t.Run("recovery from invalid token attempts", func(t *testing.T) {
		maker := setupTestMaker(t)
		ctx := context.Background()

		// Try multiple invalid tokens
		invalidTokens := []string{
			"invalid",
			"also.invalid",
			"still.not.valid",
			"",
			"way.too.many.parts.in.this.token",
		}

		for _, invalid := range invalidTokens {
			_, err := maker.VerifyAccessToken(ctx, invalid)
			assert.Error(t, err)
		}

		// System should still work with valid token
		token, err := maker.CreateAccessToken(ctx, uuid.New(), "user", []string{"user"}, uuid.New())
		require.NoError(t, err)

		claims, err := maker.VerifyAccessToken(ctx, token.Token)
		require.NoError(t, err)
		assert.NotNil(t, claims)

		t.Logf("System recovered from multiple invalid token attempts")
	})

	t.Run("recovery from context timeout", func(t *testing.T) {
		maker := setupTestMaker(t)

		// Cause timeout
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
		defer cancel()
		time.Sleep(10 * time.Millisecond)

		_, err := maker.CreateAccessToken(ctx, uuid.New(), "user", []string{"user"}, uuid.New())
		assert.Error(t, err)

		// System should work with valid context
		validCtx := context.Background()
		token, err := maker.CreateAccessToken(validCtx, uuid.New(), "user", []string{"user"}, uuid.New())
		require.NoError(t, err)
		assert.NotNil(t, token)

		t.Logf("System recovered from context timeout")
	})

	t.Run("handle rapid successive operations", func(t *testing.T) {
		maker := setupTestMakerWithRepo(t)
		ctx := context.Background()

		userID := uuid.New()
		sessionID := uuid.New()

		// Create, verify, revoke in rapid succession
		for i := 0; i < 10; i++ {
			token, err := maker.CreateAccessToken(ctx, userID, "user", []string{"user"}, sessionID)
			require.NoError(t, err)

			claims, err := maker.VerifyAccessToken(ctx, token.Token)
			require.NoError(t, err)
			assert.NotNil(t, claims)

			err = maker.RevokeAccessToken(ctx, token.Token)
			require.NoError(t, err)

			_, err = maker.VerifyAccessToken(ctx, token.Token)
			assert.Error(t, err)
		}

		t.Logf("Handled rapid successive operations successfully")
	})
}

// TestDataConsistency tests data consistency across operations
func TestDataConsistency(t *testing.T) {
	t.Run("session ID consistency across token lifecycle", func(t *testing.T) {
		maker := setupTestMakerWithRepo(t)
		ctx := context.Background()

		userID := uuid.New()
		sessionID := uuid.New()

		// Create access token
		accessToken, err := maker.CreateAccessToken(ctx, userID, "user", []string{"user"}, sessionID)
		require.NoError(t, err)
		assert.Equal(t, sessionID, accessToken.SessionID)

		// Verify session ID in claims
		claims, err := maker.VerifyAccessToken(ctx, accessToken.Token)
		require.NoError(t, err)
		assert.Equal(t, sessionID, claims.SessionID)

		// Create refresh token with same session
		refreshToken, err := maker.CreateRefreshToken(ctx, userID, "user", sessionID)
		require.NoError(t, err)
		assert.Equal(t, sessionID, refreshToken.SessionID)

		// Rotate refresh token - session should be maintained
		newRefreshToken, err := maker.RotateRefreshToken(ctx, refreshToken.Token)
		require.NoError(t, err)
		assert.Equal(t, sessionID, newRefreshToken.SessionID)

		t.Logf("Session ID remained consistent throughout lifecycle")
	})

	t.Run("user ID consistency", func(t *testing.T) {
		maker := setupTestMaker(t)
		ctx := context.Background()

		userID := uuid.New()

		// Create multiple tokens for same user
		tokens := make([]*AccessTokenResponse, 5)
		for i := range tokens {
			token, err := maker.CreateAccessToken(ctx, userID, "user", []string{"user"}, uuid.New())
			require.NoError(t, err)
			tokens[i] = token
		}

		// All should have same user ID
		for _, token := range tokens {
			assert.Equal(t, userID, token.Subject)

			claims, err := maker.VerifyAccessToken(ctx, token.Token)
			require.NoError(t, err)
			assert.Equal(t, userID, claims.Subject)
		}

		t.Logf("User ID consistent across all tokens")
	})
}
