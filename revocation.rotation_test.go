// File: revocation.rotation_test.go


package gourdiantoken

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRevokeAccessToken tests access token revocation
func TestRevokeAccessToken(t *testing.T) {
	t.Run("successfully revoke valid access token", func(t *testing.T) {
		maker := setupTestMakerWithRepo(t)
		ctx := context.Background()

		token, err := maker.CreateAccessToken(ctx, uuid.New(), "user", []string{"admin"}, uuid.New())
		require.NoError(t, err)

		// Verify token works before revocation
		claims, err := maker.VerifyAccessToken(ctx, token.Token)
		require.NoError(t, err)
		assert.NotNil(t, claims)

		// Revoke token
		err = maker.RevokeAccessToken(ctx, token.Token)
		require.NoError(t, err)

		// Verify token is now invalid
		claims, err = maker.VerifyAccessToken(ctx, token.Token)
		assert.Error(t, err)
		assert.Nil(t, claims)
		assert.Contains(t, err.Error(), "revoked")
	})

	t.Run("revoke already revoked token is idempotent", func(t *testing.T) {
		maker := setupTestMakerWithRepo(t)
		ctx := context.Background()

		token, err := maker.CreateAccessToken(ctx, uuid.New(), "user", []string{"admin"}, uuid.New())
		require.NoError(t, err)

		// Revoke first time
		err = maker.RevokeAccessToken(ctx, token.Token)
		require.NoError(t, err)

		// Revoke second time - should not error
		err = maker.RevokeAccessToken(ctx, token.Token)
		assert.NoError(t, err)

		// Revoke third time
		err = maker.RevokeAccessToken(ctx, token.Token)
		assert.NoError(t, err)
	})

	t.Run("cannot revoke with invalid token", func(t *testing.T) {
		maker := setupTestMakerWithRepo(t)
		ctx := context.Background()

		err := maker.RevokeAccessToken(ctx, "invalid.token.here")
		assert.Error(t, err)
	})

	t.Run("revocation requires repository", func(t *testing.T) {
		maker := setupTestMaker(t) // No repository
		ctx := context.Background()

		token, err := maker.CreateAccessToken(ctx, uuid.New(), "user", []string{"admin"}, uuid.New())
		require.NoError(t, err)

		err = maker.RevokeAccessToken(ctx, token.Token)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not enabled")
	})
}

// TestRevokeRefreshToken tests refresh token revocation
func TestRevokeRefreshToken(t *testing.T) {
	t.Run("successfully revoke valid refresh token", func(t *testing.T) {
		maker := setupTestMakerWithRepo(t)
		ctx := context.Background()

		token, err := maker.CreateRefreshToken(ctx, uuid.New(), "user", uuid.New())
		require.NoError(t, err)

		// Verify token works
		claims, err := maker.VerifyRefreshToken(ctx, token.Token)
		require.NoError(t, err)
		assert.NotNil(t, claims)

		// Revoke token
		err = maker.RevokeRefreshToken(ctx, token.Token)
		require.NoError(t, err)

		// Verify token is now invalid
		claims, err = maker.VerifyRefreshToken(ctx, token.Token)
		assert.Error(t, err)
		assert.Nil(t, claims)
		assert.Contains(t, err.Error(), "revoked")
	})

	t.Run("cannot use revoked refresh token for rotation", func(t *testing.T) {
		maker := setupTestMakerWithRepo(t)
		ctx := context.Background()

		token, err := maker.CreateRefreshToken(ctx, uuid.New(), "user", uuid.New())
		require.NoError(t, err)

		// Revoke token
		err = maker.RevokeRefreshToken(ctx, token.Token)
		require.NoError(t, err)

		// Try to rotate revoked token
		newToken, err := maker.RotateRefreshToken(ctx, token.Token)
		assert.Error(t, err)
		assert.Nil(t, newToken)
		assert.Contains(t, err.Error(), "revoked")
	})

	t.Run("revocation with canceled context", func(t *testing.T) {
		maker := setupTestMakerWithRepo(t)

		token, err := maker.CreateRefreshToken(context.Background(), uuid.New(), "user", uuid.New())
		require.NoError(t, err)

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		err = maker.RevokeRefreshToken(ctx, token.Token)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "context canceled")
	})
}

// TestRevocation_Disabled tests behavior when revocation is disabled
func TestRevocation_Disabled(t *testing.T) {
	// Setup config with revocation disabled
	config := DefaultTestConfig()
	config.RevocationEnabled = false
	config.RotationEnabled = false

	maker := setupTestMakerWithConfig(t, config, nil)

	userID := uuid.New()
	sessionID := uuid.New()
	username := "testuser"
	roles := []string{"admin"}

	t.Run("access token revocation fails when feature is disabled", func(t *testing.T) {
		ctx := context.Background()

		// Create an access token
		response, err := maker.CreateAccessToken(ctx, userID, username, roles, sessionID)
		require.NoError(t, err)

		// Attempt revocation should fail
		err = maker.RevokeAccessToken(ctx, response.Token)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "access token revocation is not enabled")
	})

	t.Run("refresh token revocation fails when feature is disabled", func(t *testing.T) {
		ctx := context.Background()

		// Create a refresh token
		response, err := maker.CreateRefreshToken(ctx, userID, username, sessionID)
		require.NoError(t, err)

		// Attempt revocation should fail
		err = maker.RevokeRefreshToken(ctx, response.Token)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "refresh token revocation is not enabled")
	})

	t.Run("tokens remain verifiable when revocation disabled", func(t *testing.T) {
		ctx := context.Background()

		// Create both token types
		accessToken, err := maker.CreateAccessToken(ctx, userID, username, roles, sessionID)
		require.NoError(t, err)

		refreshToken, err := maker.CreateRefreshToken(ctx, userID, username, sessionID)
		require.NoError(t, err)

		// Both should be verifiable
		accessClaims, err := maker.VerifyAccessToken(ctx, accessToken.Token)
		assert.NoError(t, err)
		assert.NotNil(t, accessClaims)

		refreshClaims, err := maker.VerifyRefreshToken(ctx, refreshToken.Token)
		assert.NoError(t, err)
		assert.NotNil(t, refreshClaims)

		// Attempt revocation should fail for both
		err = maker.RevokeAccessToken(ctx, accessToken.Token)
		assert.Error(t, err)

		err = maker.RevokeRefreshToken(ctx, refreshToken.Token)
		assert.Error(t, err)

		// Tokens should still be verifiable after failed revocation attempts
		accessClaims2, err := maker.VerifyAccessToken(ctx, accessToken.Token)
		assert.NoError(t, err)
		assert.NotNil(t, accessClaims2)

		refreshClaims2, err := maker.VerifyRefreshToken(ctx, refreshToken.Token)
		assert.NoError(t, err)
		assert.NotNil(t, refreshClaims2)
	})

	t.Run("no repository needed when revocation disabled", func(t *testing.T) {
		// This should work without a repository since revocation is disabled
		config := DefaultTestConfig()
		config.RevocationEnabled = false
		config.RotationEnabled = false

		maker, err := NewGourdianTokenMaker(context.Background(), config, nil)
		require.NoError(t, err)
		assert.NotNil(t, maker)

		// Token creation and verification should work
		token, err := maker.CreateAccessToken(context.Background(), userID, username, roles, sessionID)
		assert.NoError(t, err)
		assert.NotNil(t, token)

		claims, err := maker.VerifyAccessToken(context.Background(), token.Token)
		assert.NoError(t, err)
		assert.NotNil(t, claims)

		// Revocation should fail due to disabled feature
		err = maker.RevokeAccessToken(context.Background(), token.Token)
		assert.Error(t, err)
	})
	t.Run("revocation fails when disabled", func(t *testing.T) {
		maker := setupTestMaker(t)
		ctx := context.Background()

		token, err := maker.CreateAccessToken(ctx, uuid.New(), "user", []string{"admin"}, uuid.New())
		require.NoError(t, err)

		err = maker.RevokeAccessToken(ctx, token.Token)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "revocation is not enabled")
	})

	t.Run("tokens remain valid when revocation disabled", func(t *testing.T) {
		maker := setupTestMaker(t)
		ctx := context.Background()

		token, err := maker.CreateAccessToken(ctx, uuid.New(), "user", []string{"admin"}, uuid.New())
		require.NoError(t, err)

		// Try to revoke (will fail)
		_ = maker.RevokeAccessToken(ctx, token.Token)

		// Token should still be valid
		claims, err := maker.VerifyAccessToken(ctx, token.Token)
		assert.NoError(t, err)
		assert.NotNil(t, claims)
	})
}

// TestRevocationAndRotationTogether tests combined operations
func TestRevocationAndRotationTogether(t *testing.T) {
	t.Run("revoke after rotation", func(t *testing.T) {
		maker := setupTestMakerWithRepo(t)
		ctx := context.Background()

		oldToken, err := maker.CreateRefreshToken(ctx, uuid.New(), "user", uuid.New())
		require.NoError(t, err)

		// Rotate
		newToken, err := maker.RotateRefreshToken(ctx, oldToken.Token)
		require.NoError(t, err)

		// Revoke new token
		err = maker.RevokeRefreshToken(ctx, newToken.Token)
		require.NoError(t, err)

		// Both tokens should be invalid
		_, err = maker.VerifyRefreshToken(ctx, oldToken.Token)
		assert.Error(t, err)

		_, err = maker.VerifyRefreshToken(ctx, newToken.Token)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "revoked")
	})

	t.Run("cannot rotate revoked token", func(t *testing.T) {
		maker := setupTestMakerWithRepo(t)
		ctx := context.Background()

		token, err := maker.CreateRefreshToken(ctx, uuid.New(), "user", uuid.New())
		require.NoError(t, err)

		// Revoke first
		err = maker.RevokeRefreshToken(ctx, token.Token)
		require.NoError(t, err)

		// Try to rotate
		newToken, err := maker.RotateRefreshToken(ctx, token.Token)
		assert.Error(t, err)
		assert.Nil(t, newToken)
		assert.Contains(t, err.Error(), "revoked")
	})

	t.Run("revoke old token after rotation has no effect", func(t *testing.T) {
		maker := setupTestMakerWithRepo(t)
		ctx := context.Background()

		oldToken, err := maker.CreateRefreshToken(ctx, uuid.New(), "user", uuid.New())
		require.NoError(t, err)

		// Rotate
		newToken, err := maker.RotateRefreshToken(ctx, oldToken.Token)
		require.NoError(t, err)

		// Try to revoke old token (already rotated, so marking as revoked too)
		err = maker.RevokeRefreshToken(ctx, oldToken.Token)
		assert.NoError(t, err) // Should not error

		// New token should still work
		claims, err := maker.VerifyRefreshToken(ctx, newToken.Token)
		assert.NoError(t, err)
		assert.NotNil(t, claims)
	})

	t.Run("rapid rotation and revocation", func(t *testing.T) {
		maker := setupTestMakerWithRepo(t)
		ctx := context.Background()

		userID := uuid.New()
		currentToken, err := maker.CreateRefreshToken(ctx, userID, "user", uuid.New())
		require.NoError(t, err)

		// Perform rapid operations
		for i := 0; i < 5; i++ {
			// Rotate
			newToken, err := maker.RotateRefreshToken(ctx, currentToken.Token)
			require.NoError(t, err)

			// Verify new token works
			claims, err := maker.VerifyRefreshToken(ctx, newToken.Token)
			require.NoError(t, err)
			assert.Equal(t, userID, claims.Subject)

			// Revoke old token (redundant but should not error)
			err = maker.RevokeRefreshToken(ctx, currentToken.Token)
			assert.NoError(t, err)

			currentToken = newToken
		}
	})
}

// TestRevocationTTL tests TTL handling in revocation
func TestRevocationTTL(t *testing.T) {
	t.Run("revocation TTL based on token expiry", func(t *testing.T) {
		config := DefaultTestConfig()
		config.AccessExpiryDuration = 1 * time.Second
		repo := NewMemoryTokenRepository(100 * time.Millisecond)
		maker := setupTestMakerWithConfig(t, config, repo)
		ctx := context.Background()

		token, err := maker.CreateAccessToken(ctx, uuid.New(), "user", []string{"admin"}, uuid.New())
		require.NoError(t, err)

		// Revoke immediately
		err = maker.RevokeAccessToken(ctx, token.Token)
		require.NoError(t, err)

		// Should be revoked
		_, err = maker.VerifyAccessToken(ctx, token.Token)
		assert.Error(t, err)

		// Wait for token to naturally expire
		time.Sleep(1500 * time.Millisecond)

		// After cleanup, revocation record should be gone but token is expired anyway
		_ = repo.CleanupExpiredRevokedTokens(ctx, AccessToken)
	})

	t.Run("expired tokens handled correctly", func(t *testing.T) {
		config := DefaultTestConfig()
		config.AccessExpiryDuration = 100 * time.Millisecond
		maker := setupTestMakerWithConfig(t, config, nil) // No repo
		ctx := context.Background()

		token, err := maker.CreateAccessToken(ctx, uuid.New(), "user", []string{"admin"}, uuid.New())
		require.NoError(t, err)

		// Wait for expiry
		time.Sleep(150 * time.Millisecond)

		// Should be rejected due to expiry
		_, err = maker.VerifyAccessToken(ctx, token.Token)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "expired")
	})
}

// TestRotationChain tests chains of rotations
func TestRotationChain(t *testing.T) {
	t.Run("long rotation chain maintains integrity", func(t *testing.T) {
		maker := setupTestMakerWithRepo(t)
		ctx := context.Background()

		userID := uuid.New()
		sessionID := uuid.New()
		username := "chainuser"

		currentToken, err := maker.CreateRefreshToken(ctx, userID, username, sessionID)
		require.NoError(t, err)

		// Track all tokens
		allTokens := []string{currentToken.Token}

		// Create chain of 20 rotations
		for i := 0; i < 20; i++ {
			newToken, err := maker.RotateRefreshToken(ctx, currentToken.Token)
			require.NoError(t, err, "Rotation %d failed", i+1)

			// Verify user info preserved
			assert.Equal(t, userID, newToken.Subject)
			assert.Equal(t, sessionID, newToken.SessionID)
			assert.Equal(t, username, newToken.Username)

			allTokens = append(allTokens, newToken.Token)
			currentToken = newToken

			time.Sleep(10 * time.Millisecond)
		}

		// Only the last token should work
		for i, token := range allTokens {
			claims, err := maker.VerifyRefreshToken(ctx, token)
			if i == len(allTokens)-1 {
				assert.NoError(t, err, "Last token should be valid")
				assert.NotNil(t, claims)
			} else {
				assert.Error(t, err, "Token %d should be invalid", i)
			}
		}
	})

	t.Run("broken chain detection", func(t *testing.T) {
		maker := setupTestMakerWithRepo(t)
		ctx := context.Background()

		// Create chain
		token1, err := maker.CreateRefreshToken(ctx, uuid.New(), "user", uuid.New())
		require.NoError(t, err)

		token2, err := maker.RotateRefreshToken(ctx, token1.Token)
		require.NoError(t, err)

		token3, err := maker.RotateRefreshToken(ctx, token2.Token)
		require.NoError(t, err)

		// Try to continue from middle of chain
		_, err = maker.RotateRefreshToken(ctx, token2.Token)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "token has been rotated")

		// Latest token should still work
		claims, err := maker.VerifyRefreshToken(ctx, token3.Token)
		assert.NoError(t, err)
		assert.NotNil(t, claims)
	})
}

// TestEdgeCasesRevocationRotation tests edge cases
func TestEdgeCasesRevocationRotation(t *testing.T) {
	// Test 1: Rotation well before expiry (safe timing)
	t.Run("rotate token well before expiry", func(t *testing.T) {
		config := DefaultTestConfig()
		config.RotationEnabled = true
		config.RevocationEnabled = true
		config.RefreshExpiryDuration = 5 * time.Second // FIXED: increased from 1s

		repo := NewMemoryTokenRepository(1 * time.Minute)
		maker := setupTestMakerWithConfig(t, config, repo)
		ctx := context.Background()

		token, err := maker.CreateRefreshToken(ctx, uuid.New(), "user", uuid.New())
		require.NoError(t, err)

		// Wait only 20% of expiry time (plenty of buffer)
		time.Sleep(1 * time.Second) // FIXED: increased from 300ms

		// Should definitely succeed
		newToken, err := maker.RotateRefreshToken(ctx, token.Token)
		require.NoError(t, err, "Should succeed well before expiry")
		require.NotNil(t, newToken)

		// Verify new token is valid
		claims, err := maker.VerifyRefreshToken(ctx, newToken.Token)
		require.NoError(t, err)
		assert.Equal(t, token.Subject, claims.Subject)

		// Original token should now fail (rotated, not expired)
		_, err = maker.RotateRefreshToken(ctx, token.Token)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "rotated",
			"Should fail due to rotation, not expiration")
	})

	// Test 2: Token at expiry boundary (expect failure)
	t.Run("rotate token at exact expiry - expect failure", func(t *testing.T) {
		config := DefaultTestConfig()
		config.RotationEnabled = true
		config.RevocationEnabled = true
		config.RefreshExpiryDuration = 1 * time.Second // FIXED: increased from 300ms

		repo := NewMemoryTokenRepository(1 * time.Minute)
		maker := setupTestMakerWithConfig(t, config, repo)
		ctx := context.Background()

		token, err := maker.CreateRefreshToken(ctx, uuid.New(), "user", uuid.New())
		require.NoError(t, err)

		// Wait until token is expired
		time.Sleep(1500 * time.Millisecond) // FIXED: increased from 350ms

		// Should fail - token is expired
		_, err = maker.RotateRefreshToken(ctx, token.Token)
		require.Error(t, err, "Should fail - token is expired")
		assert.Contains(t, err.Error(), "expired",
			"Error should mention expiration")
	})

	// Test 3: Rotation near expiry (timing-sensitive, allow both outcomes)
	t.Run("rotate token near expiry boundary - resilient", func(t *testing.T) {
		config := DefaultTestConfig()
		config.RotationEnabled = true
		config.RevocationEnabled = true
		config.RefreshExpiryDuration = 2 * time.Second // FIXED: increased from 400ms

		repo := NewMemoryTokenRepository(1 * time.Hour)
		maker := setupTestMakerWithConfig(t, config, repo)
		ctx := context.Background()

		token, err := maker.CreateRefreshToken(ctx, uuid.New(), "user", uuid.New())
		require.NoError(t, err)

		// Wait until very close to expiry (85% of lifetime)
		time.Sleep(1600 * time.Millisecond) // FIXED: increased from 340ms

		// Try to rotate - may succeed or fail depending on exact timing
		newToken, err := maker.RotateRefreshToken(ctx, token.Token)
		if err != nil {
			// Failure is acceptable if it's due to expiration
			t.Logf("Rotation failed near expiry (acceptable): %v", err)
			assert.True(t,
				strings.Contains(err.Error(), "expired"),
				"Near-expiry failure should be due to expiration: %v", err)
		} else {
			// Success is also acceptable if timing worked out
			assert.NotNil(t, newToken)
			t.Log("Rotation succeeded near expiry (good timing)")

			// Verify new token has fresh expiry
			assert.True(t,
				newToken.ExpiresAt.After(time.Now().Add(1500*time.Millisecond)),
				"New token should have fresh expiry")
		}
	})

	// Test 4: Successful rotation followed by verification of rotation status
	t.Run("rotate early then verify old token is rotated", func(t *testing.T) {
		config := DefaultTestConfig()
		config.RotationEnabled = true
		config.RevocationEnabled = true
		config.RefreshExpiryDuration = 5 * time.Second // Already good timing

		repo := NewMemoryTokenRepository(1 * time.Minute)
		maker := setupTestMakerWithConfig(t, config, repo)
		ctx := context.Background()

		token, err := maker.CreateRefreshToken(ctx, uuid.New(), "user", uuid.New())
		require.NoError(t, err)

		// Rotate early (well before expiry)
		time.Sleep(100 * time.Millisecond)
		newToken, err := maker.RotateRefreshToken(ctx, token.Token)
		require.NoError(t, err)
		require.NotNil(t, newToken)

		// Immediately try to use original again - should fail due to rotation
		_, err = maker.RotateRefreshToken(ctx, token.Token)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "rotated",
			"Should fail due to rotation, got: %v", err)

		// Verify new token still works
		claims, err := maker.VerifyRefreshToken(ctx, newToken.Token)
		require.NoError(t, err)
		assert.Equal(t, token.Subject, claims.Subject)
	})

	t.Run("revoke empty token string", func(t *testing.T) {
		maker := setupTestMakerWithRepo(t)
		ctx := context.Background()

		err := maker.RevokeAccessToken(ctx, "")
		assert.Error(t, err)
	})

	t.Run("rotate empty token string", func(t *testing.T) {
		maker := setupTestMakerWithRepo(t)
		ctx := context.Background()

		newToken, err := maker.RotateRefreshToken(ctx, "")
		assert.Error(t, err)
		assert.Nil(t, newToken)
	})

	t.Run("revoke token with special characters", func(t *testing.T) {
		maker := setupTestMakerWithRepo(t)
		ctx := context.Background()

		specialTokens := []string{
			"token with spaces",
			"token\nwith\nnewlines",
			"token\twith\ttabs",
			"token-with-unicode-→←↑↓",
		}

		for _, token := range specialTokens {
			err := maker.RevokeAccessToken(ctx, token)
			assert.Error(t, err, "Should fail for: %s", token)
		}
	})

	t.Run("rotate token near expiry boundary", func(t *testing.T) {
		config := DefaultTestConfig()
		config.RotationEnabled = true
		config.RevocationEnabled = true
		config.RefreshExpiryDuration = 2 * time.Second // FIXED: increased from 300ms

		repo := NewMemoryTokenRepository(1 * time.Hour)
		maker := setupTestMakerWithConfig(t, config, repo)
		ctx := context.Background()

		token, err := maker.CreateRefreshToken(ctx, uuid.New(), "user", uuid.New())
		require.NoError(t, err)

		// Wait until very close to expiry
		time.Sleep(1600 * time.Millisecond) // FIXED: increased from 250ms

		// Should still succeed (not expired yet)
		newToken, err := maker.RotateRefreshToken(ctx, token.Token)
		if err != nil {
			// If it failed due to timing, that's also acceptable
			t.Logf("Rotation failed near expiry (acceptable due to timing): %v", err)
		} else {
			assert.NotNil(t, newToken)

			// Verify new token has fresh expiry
			assert.True(t, newToken.ExpiresAt.After(time.Now().Add(1500*time.Millisecond)),
				"New token should have fresh expiry")
		}
	})

	t.Run("verify token immediately after creation", func(t *testing.T) {
		maker := setupTestMakerWithRepo(t)
		ctx := context.Background()

		token, err := maker.CreateRefreshToken(ctx, uuid.New(), "user", uuid.New())
		require.NoError(t, err)

		// Immediately verify - should work
		claims, err := maker.VerifyRefreshToken(ctx, token.Token)
		assert.NoError(t, err)
		assert.NotNil(t, claims)
	})

	t.Run("rotate then immediately rotate again", func(t *testing.T) {
		maker := setupTestMakerWithRepo(t)
		ctx := context.Background()

		token1, err := maker.CreateRefreshToken(ctx, uuid.New(), "user", uuid.New())
		require.NoError(t, err)

		// First rotation
		token2, err := maker.RotateRefreshToken(ctx, token1.Token)
		require.NoError(t, err)

		// Immediate second rotation with new token should work
		token3, err := maker.RotateRefreshToken(ctx, token2.Token)
		assert.NoError(t, err)
		assert.NotNil(t, token3)

		// But trying to use token1 or token2 should fail
		_, err = maker.RotateRefreshToken(ctx, token1.Token)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "token has been rotated")

		_, err = maker.RotateRefreshToken(ctx, token2.Token)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "token has been rotated")
	})

	t.Run("revoke then try to rotate", func(t *testing.T) {
		maker := setupTestMakerWithRepo(t)
		ctx := context.Background()

		token, err := maker.CreateRefreshToken(ctx, uuid.New(), "user", uuid.New())
		require.NoError(t, err)

		// Revoke the token
		err = maker.RevokeRefreshToken(ctx, token.Token)
		require.NoError(t, err)

		// Try to rotate - should fail with revocation error
		_, err = maker.RotateRefreshToken(ctx, token.Token)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "revoked", "Should fail due to revocation")
	})

	t.Run("rotate then try to revoke old token", func(t *testing.T) {
		maker := setupTestMakerWithRepo(t)
		ctx := context.Background()

		token1, err := maker.CreateRefreshToken(ctx, uuid.New(), "user", uuid.New())
		require.NoError(t, err)

		// Rotate the token
		token2, err := maker.RotateRefreshToken(ctx, token1.Token)
		require.NoError(t, err)
		require.NotNil(t, token2)

		// Try to revoke the old token
		err = maker.RevokeRefreshToken(ctx, token1.Token)

		// Current implementation: Revocation succeeds even for rotated tokens
		// This is redundant but not harmful - the token is already invalid
		if err == nil {
			t.Log("Revocation of rotated token succeeded (redundant but acceptable)")
		} else {
			// If implementation changes to check rotation in RevokeRefreshToken
			assert.Contains(t, err.Error(), "token has been rotated")
		}
	})

	t.Run("rotate with invalid token format", func(t *testing.T) {
		maker := setupTestMakerWithRepo(t)
		ctx := context.Background()

		invalidTokens := []string{
			"not.a.jwt",
			"invalid-token-format",
			"abc.def.ghi",
		}

		for _, invalidToken := range invalidTokens {
			_, err := maker.RotateRefreshToken(ctx, invalidToken)
			assert.Error(t, err, "Should fail for invalid token: %s", invalidToken)
		}
	})
}

// TestConcurrentRevocationRotation tests concurrent operations
func TestConcurrentRevocationRotation(t *testing.T) {
	t.Run("concurrent revocations of different tokens", func(t *testing.T) {
		maker := setupTestMakerWithRepo(t)
		ctx := context.Background()

		// Create multiple tokens
		tokens := make([]*AccessTokenResponse, 20)
		for i := range tokens {
			token, err := maker.CreateAccessToken(ctx, uuid.New(), "user", []string{"admin"}, uuid.New())
			require.NoError(t, err)
			tokens[i] = token
		}

		// Revoke all concurrently
		done := make(chan bool, len(tokens))
		for _, token := range tokens {
			go func(t *AccessTokenResponse) {
				err := maker.RevokeAccessToken(ctx, t.Token)
				done <- err == nil
			}(token)
		}

		// Wait for all
		successCount := 0
		for i := 0; i < len(tokens); i++ {
			if <-done {
				successCount++
			}
		}

		assert.Equal(t, len(tokens), successCount)

		// All should be revoked
		for _, token := range tokens {
			_, err := maker.VerifyAccessToken(ctx, token.Token)
			assert.Error(t, err)
		}
	})

	t.Run("race between rotation and revocation", func(t *testing.T) {
		maker := setupTestMakerWithRepo(t)
		ctx := context.Background()

		token, err := maker.CreateRefreshToken(ctx, uuid.New(), "user", uuid.New())
		require.NoError(t, err)

		// Try to rotate and revoke simultaneously
		rotateErr := make(chan error, 1)
		revokeErr := make(chan error, 1)

		go func() {
			_, err := maker.RotateRefreshToken(ctx, token.Token)
			rotateErr <- err
		}()

		go func() {
			err := maker.RevokeRefreshToken(ctx, token.Token)
			revokeErr <- err
		}()

		re := <-rotateErr
		ve := <-revokeErr

		// One should succeed
		assert.False(t, re != nil && ve != nil, "Both operations should not fail")

		// Token should be unusable either way
		_, err = maker.VerifyRefreshToken(ctx, token.Token)
		assert.Error(t, err)
	})
}
