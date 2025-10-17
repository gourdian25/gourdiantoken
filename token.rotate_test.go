// File: token.rotate_test.go


package gourdiantoken

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRotateRefreshToken_Success(t *testing.T) {
	// Common setup
	ctx := context.Background()
	config := DefaultTestConfig()
	config.RotationEnabled = true
	config.RevocationEnabled = true
	repo := NewMemoryTokenRepository(1 * time.Hour)
	maker := setupTestMakerWithConfig(t, config, repo)

	userID := uuid.New()
	sessionID := uuid.New()
	username := "testuser"

	t.Run("basic rotation produces new valid token", func(t *testing.T) {
		// Create initial token
		oldToken, err := maker.CreateRefreshToken(ctx, userID, username, sessionID)
		require.NoError(t, err)

		// Rotate token
		newToken, err := maker.RotateRefreshToken(ctx, oldToken.Token)
		require.NoError(t, err)
		require.NotNil(t, newToken)

		// Verify tokens are different
		assert.NotEqual(t, oldToken.Token, newToken.Token)

		// Verify new token is valid
		claims, err := maker.VerifyRefreshToken(ctx, newToken.Token)
		require.NoError(t, err)
		assert.Equal(t, userID, claims.Subject)
		assert.Equal(t, username, claims.Username)
		assert.Equal(t, sessionID, claims.SessionID)

		// Verify old token is marked as rotated
		rotated, err := repo.IsTokenRotated(ctx, oldToken.Token)
		assert.NoError(t, err)
		assert.True(t, rotated, "old token should be marked as rotated")
	})

	t.Run("old token cannot be verified after rotation", func(t *testing.T) {
		oldToken, err := maker.CreateRefreshToken(ctx, userID, username, sessionID)
		require.NoError(t, err)

		_, err = maker.RotateRefreshToken(ctx, oldToken.Token)
		require.NoError(t, err)

		// After fix: Old token should fail verification because it's been rotated
		_, err = maker.VerifyRefreshToken(ctx, oldToken.Token)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "token has been rotated",
			"error should indicate token was rotated")
	})

	t.Run("rotated token cannot be rotated again", func(t *testing.T) {
		oldToken, err := maker.CreateRefreshToken(ctx, userID, username, sessionID)
		require.NoError(t, err)

		_, err = maker.RotateRefreshToken(ctx, oldToken.Token)
		require.NoError(t, err)

		// Attempt second rotation should fail
		_, err = maker.RotateRefreshToken(ctx, oldToken.Token)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "token has been rotated")
	})

	t.Run("user context is preserved across rotation", func(t *testing.T) {
		oldToken, err := maker.CreateRefreshToken(ctx, userID, username, sessionID)
		require.NoError(t, err)

		newToken, err := maker.RotateRefreshToken(ctx, oldToken.Token)
		require.NoError(t, err)

		// Verify all user context is preserved
		assert.Equal(t, oldToken.Subject, newToken.Subject)
		assert.Equal(t, oldToken.Username, newToken.Username)
		assert.Equal(t, oldToken.SessionID, newToken.SessionID)
		assert.Equal(t, oldToken.Issuer, newToken.Issuer)
		assert.Equal(t, oldToken.Audience, newToken.Audience)
		assert.Equal(t, oldToken.TokenType, newToken.TokenType)

		// Verify new timestamps
		assert.True(t, newToken.IssuedAt.After(oldToken.IssuedAt))
		assert.True(t, newToken.ExpiresAt.After(oldToken.ExpiresAt))
		assert.True(t, newToken.MaxLifetimeExpiry.After(oldToken.MaxLifetimeExpiry))
	})

	t.Run("multiple sequential rotations create unique tokens", func(t *testing.T) {
		// Create initial token
		tokens := make([]*RefreshTokenResponse, 6)
		tokens[0], _ = maker.CreateRefreshToken(ctx, userID, username, sessionID)

		// Perform 5 rotations
		for i := 1; i < 6; i++ {
			var err error
			tokens[i], err = maker.RotateRefreshToken(ctx, tokens[i-1].Token)
			require.NoError(t, err)
			time.Sleep(10 * time.Millisecond) // Ensure timestamp differences
		}

		// Verify all tokens are unique
		tokenStrings := make(map[string]bool)
		for i, token := range tokens {
			assert.False(t, tokenStrings[token.Token], "Token %d is duplicate", i)
			tokenStrings[token.Token] = true
		}
		assert.Len(t, tokenStrings, 6)

		// Verify user context remains consistent
		for i := 1; i < 6; i++ {
			assert.Equal(t, tokens[0].Subject, tokens[i].Subject)
			assert.Equal(t, tokens[0].Username, tokens[i].Username)
			assert.Equal(t, tokens[0].SessionID, tokens[i].SessionID)
		}
	})
}

func TestRotateRefreshToken_Errors(t *testing.T) {
	ctx := context.Background()
	config := DefaultTestConfig()
	config.RotationEnabled = true
	config.RevocationEnabled = true
	repo := NewMemoryTokenRepository(1 * time.Hour)
	maker := setupTestMakerWithConfig(t, config, repo)

	userID := uuid.New()
	sessionID := uuid.New()

	t.Run("rotation fails when disabled", func(t *testing.T) {
		disabledConfig := DefaultTestConfig()
		disabledConfig.RotationEnabled = false
		disabledMaker := setupTestMakerWithConfig(t, disabledConfig, nil)

		token, err := disabledMaker.CreateRefreshToken(ctx, userID, "user", sessionID)
		require.NoError(t, err)

		_, err = disabledMaker.RotateRefreshToken(ctx, token.Token)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "token rotation not enabled")
	})

	t.Run("rotation fails with invalid token", func(t *testing.T) {
		_, err := maker.RotateRefreshToken(ctx, "invalid-token")
		assert.Error(t, err)
	})

	t.Run("rotation fails with expired token", func(t *testing.T) {
		expiredConfig := DefaultTestConfig()
		expiredConfig.RotationEnabled = true
		expiredConfig.RefreshExpiryDuration = 1 * time.Millisecond
		expiredMaker := setupTestMakerWithConfig(t, expiredConfig, repo)

		token, err := expiredMaker.CreateRefreshToken(ctx, userID, "user", sessionID)
		require.NoError(t, err)

		time.Sleep(10 * time.Millisecond) // Wait for expiration

		_, err = expiredMaker.RotateRefreshToken(ctx, token.Token)
		assert.Error(t, err)
	})

	t.Run("rotation fails with revoked token", func(t *testing.T) {
		token, err := maker.CreateRefreshToken(ctx, userID, "user", sessionID)
		require.NoError(t, err)

		// Revoke the token
		err = maker.RevokeRefreshToken(ctx, token.Token)
		require.NoError(t, err)

		// Attempt rotation
		_, err = maker.RotateRefreshToken(ctx, token.Token)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "token has been revoked")
	})
}

func TestRotateRefreshToken_ConcurrencySafety(t *testing.T) {
	ctx := context.Background()
	config := DefaultTestConfig()
	config.RotationEnabled = true
	repo := NewMemoryTokenRepository(1 * time.Hour)
	maker := setupTestMakerWithConfig(t, config, repo)

	t.Run("concurrent rotation attempts on same token", func(t *testing.T) {
		token, err := maker.CreateRefreshToken(ctx, uuid.New(), "user", uuid.New())
		require.NoError(t, err)

		// Attempt concurrent rotations
		done := make(chan error, 5)
		for i := 0; i < 5; i++ {
			go func() {
				_, err := maker.RotateRefreshToken(ctx, token.Token)
				done <- err
			}()
		}

		// Collect results
		successCount := 0
		for i := 0; i < 5; i++ {
			err := <-done
			if err == nil {
				successCount++
			}
		}

		// Only one rotation should succeed
		assert.Equal(t, 1, successCount, "Only one concurrent rotation should succeed")
	})
}

func TestRotateRefreshToken_AlreadyRotated(t *testing.T) {
	config := DefaultTestConfig()
	config.RotationEnabled = true
	config.RevocationEnabled = true

	repo := NewMemoryTokenRepository(1 * time.Hour)
	maker := setupTestMakerWithConfig(t, config, repo)

	userID := uuid.New()
	sessionID := uuid.New()
	username := "testuser"

	t.Run("rejects already rotated token", func(t *testing.T) {
		response, err := maker.CreateRefreshToken(context.Background(), userID, username, sessionID)
		require.NoError(t, err)

		// First rotation should succeed
		newToken1, err := maker.RotateRefreshToken(context.Background(), response.Token)
		assert.NoError(t, err)
		assert.NotNil(t, newToken1)

		// Second rotation with same old token should fail
		// Error comes from VerifyRefreshToken which is called first
		newToken2, err := maker.RotateRefreshToken(context.Background(), response.Token)
		assert.Error(t, err)
		assert.Nil(t, newToken2)
		assert.Contains(t, err.Error(), "token has been rotated")
	})

	t.Run("cannot rotate already rotated token", func(t *testing.T) {
		maker := setupTestMakerWithRepo(t)
		ctx := context.Background()

		token, err := maker.CreateRefreshToken(ctx, uuid.New(), "user", uuid.New())
		require.NoError(t, err)

		// First rotation succeeds
		newToken, err := maker.RotateRefreshToken(ctx, token.Token)
		require.NoError(t, err)
		require.NotNil(t, newToken)

		// Second rotation with old token fails
		_, err = maker.RotateRefreshToken(ctx, token.Token)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "token has been rotated")
	})

	t.Run("rotation detection persists", func(t *testing.T) {
		maker := setupTestMakerWithRepo(t)
		ctx := context.Background()

		token, err := maker.CreateRefreshToken(ctx, uuid.New(), "user", uuid.New())
		require.NoError(t, err)

		// Rotate
		_, err = maker.RotateRefreshToken(ctx, token.Token)
		require.NoError(t, err)

		// Wait and try again
		time.Sleep(100 * time.Millisecond)

		_, err = maker.RotateRefreshToken(ctx, token.Token)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "token has been rotated")
	})
}

func TestRotateRefreshToken_ReuseInterval(t *testing.T) {
	config := DefaultTestConfig()
	config.RotationEnabled = true
	config.RevocationEnabled = true
	config.RefreshReuseInterval = 2 * time.Second

	repo := NewMemoryTokenRepository(1 * time.Hour)
	maker := setupTestMakerWithConfig(t, config, repo)

	userID := uuid.New()
	sessionID := uuid.New()
	username := "testuser"

	t.Run("reuse interval prevents immediate re-rotation of same token", func(t *testing.T) {
		ctx := context.Background()

		token1, err := maker.CreateRefreshToken(ctx, userID, username, sessionID)
		require.NoError(t, err)

		// First rotation should succeed immediately
		_, err = maker.RotateRefreshToken(ctx, token1.Token)
		require.NoError(t, err)

		// Try to rotate token1 again immediately - should fail
		_, err = maker.RotateRefreshToken(ctx, token1.Token)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "token has been rotated")

		// Wait for reuse interval to pass
		time.Sleep(config.RefreshReuseInterval + 100*time.Millisecond)

		// Even after waiting, token1 should still be marked as rotated
		_, err = maker.RotateRefreshToken(ctx, token1.Token)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "token has been rotated")
	})

	t.Run("reuse interval allows rotation of different tokens", func(t *testing.T) {
		ctx := context.Background()

		token1, err := maker.CreateRefreshToken(ctx, userID, username, sessionID)
		require.NoError(t, err)

		token2, err := maker.CreateRefreshToken(ctx, userID, username, sessionID)
		require.NoError(t, err)

		// Rotate token1
		_, err = maker.RotateRefreshToken(ctx, token1.Token)
		require.NoError(t, err)

		// Immediately try to rotate token2 - should succeed
		_, err = maker.RotateRefreshToken(ctx, token2.Token)
		assert.NoError(t, err, "different tokens should not affect each other's rotation")
	})

	t.Run("reuse interval scenario with multiple rotations", func(t *testing.T) {
		ctx := context.Background()

		token1, err := maker.CreateRefreshToken(ctx, userID, username, sessionID)
		require.NoError(t, err)

		// Use token1 to get token2
		token2, err := maker.RotateRefreshToken(ctx, token1.Token)
		require.NoError(t, err)

		// Immediately use token2 to get token3
		token3, err := maker.RotateRefreshToken(ctx, token2.Token)
		assert.NoError(t, err)
		assert.NotNil(t, token3)

		// But token1 should still be marked as rotated
		_, err = maker.RotateRefreshToken(ctx, token1.Token)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "token has been rotated")
	})

	t.Run("zero reuse interval behavior", func(t *testing.T) {
		zeroIntervalConfig := DefaultTestConfig()
		zeroIntervalConfig.RotationEnabled = true
		zeroIntervalConfig.RevocationEnabled = true
		zeroIntervalConfig.RefreshReuseInterval = 0

		zeroIntervalRepo := NewMemoryTokenRepository(1 * time.Hour)
		zeroIntervalMaker := setupTestMakerWithConfig(t, zeroIntervalConfig, zeroIntervalRepo)

		ctx := context.Background()

		token1, err := zeroIntervalMaker.CreateRefreshToken(ctx, userID, username, sessionID)
		require.NoError(t, err)

		// First rotation
		token2, err := zeroIntervalMaker.RotateRefreshToken(ctx, token1.Token)
		require.NoError(t, err)

		// Immediately try to rotate again with same old token
		_, err = zeroIntervalMaker.RotateRefreshToken(ctx, token1.Token)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "token has been rotated")

		// Rotating with the new token should work immediately
		token3, err := zeroIntervalMaker.RotateRefreshToken(ctx, token2.Token)
		assert.NoError(t, err, "with zero reuse interval, should allow immediate rotation of new token")
		assert.NotNil(t, token3)
	})

	t.Run("reuse within interval is blocked", func(t *testing.T) {
		config := DefaultTestConfig()
		config.RefreshReuseInterval = 2 * time.Second
		repo := NewMemoryTokenRepository(1 * time.Minute)
		maker := setupTestMakerWithConfig(t, config, repo)
		ctx := context.Background()

		token, err := maker.CreateRefreshToken(ctx, uuid.New(), "user", uuid.New())
		require.NoError(t, err)

		// Rotate
		newToken, err := maker.RotateRefreshToken(ctx, token.Token)
		require.NoError(t, err)
		require.NotNil(t, newToken)

		// Try to rotate old token immediately - should fail
		_, err = maker.RotateRefreshToken(ctx, token.Token)
		assert.Error(t, err)
	})

	t.Run("reuse after interval still blocked if already rotated", func(t *testing.T) {
		config := DefaultTestConfig()
		config.RefreshReuseInterval = 500 * time.Millisecond
		repo := NewMemoryTokenRepository(1 * time.Minute)
		maker := setupTestMakerWithConfig(t, config, repo)
		ctx := context.Background()

		token, err := maker.CreateRefreshToken(ctx, uuid.New(), "user", uuid.New())
		require.NoError(t, err)

		// Rotate
		_, err = maker.RotateRefreshToken(ctx, token.Token)
		require.NoError(t, err)

		// Wait for reuse interval to pass
		time.Sleep(600 * time.Millisecond)

		// Should still fail - token was already rotated
		_, err = maker.RotateRefreshToken(ctx, token.Token)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "token has been rotated")
	})

	t.Run("zero reuse interval allows immediate detection", func(t *testing.T) {
		config := DefaultTestConfig()
		config.RefreshReuseInterval = 0
		repo := NewMemoryTokenRepository(1 * time.Minute)
		maker := setupTestMakerWithConfig(t, config, repo)
		ctx := context.Background()

		token, err := maker.CreateRefreshToken(ctx, uuid.New(), "user", uuid.New())
		require.NoError(t, err)

		// Rotate
		_, err = maker.RotateRefreshToken(ctx, token.Token)
		require.NoError(t, err)

		// Immediate reuse attempt should fail
		_, err = maker.RotateRefreshToken(ctx, token.Token)
		assert.Error(t, err)
	})
}

func TestRotation_Disabled(t *testing.T) {
	// Setup config with rotation disabled
	config := DefaultTestConfig()
	config.RotationEnabled = false
	config.RevocationEnabled = false

	maker := setupTestMakerWithConfig(t, config, nil)

	userID := uuid.New()
	sessionID := uuid.New()
	username := "testuser"

	t.Run("rotation fails when feature is disabled", func(t *testing.T) {
		ctx := context.Background()

		// Create a refresh token
		response, err := maker.CreateRefreshToken(ctx, userID, username, sessionID)
		require.NoError(t, err)

		// Attempt rotation should fail
		newToken, err := maker.RotateRefreshToken(ctx, response.Token)
		assert.Error(t, err)
		assert.Nil(t, newToken)
		assert.Contains(t, err.Error(), "token rotation not enabled")
	})

	t.Run("rotation fails even with valid token when disabled", func(t *testing.T) {
		ctx := context.Background()

		// Create a valid refresh token
		response, err := maker.CreateRefreshToken(ctx, userID, username, sessionID)
		require.NoError(t, err)

		// Verify the token is valid
		claims, err := maker.VerifyRefreshToken(ctx, response.Token)
		assert.NoError(t, err)
		assert.NotNil(t, claims)

		// But rotation should still fail
		newToken, err := maker.RotateRefreshToken(ctx, response.Token)
		assert.Error(t, err)
		assert.Nil(t, newToken)
		assert.Contains(t, err.Error(), "token rotation not enabled")
	})

	t.Run("no repository needed when rotation disabled", func(t *testing.T) {
		// This should work without a repository since rotation is disabled
		config := DefaultTestConfig()
		config.RotationEnabled = false
		config.RevocationEnabled = false

		maker, err := NewGourdianTokenMaker(context.Background(), config, nil)
		require.NoError(t, err)
		assert.NotNil(t, maker)

		// Create token should work
		token, err := maker.CreateRefreshToken(context.Background(), userID, username, sessionID)
		assert.NoError(t, err)
		assert.NotNil(t, token)

		// Rotation should fail due to disabled feature
		newToken, err := maker.RotateRefreshToken(context.Background(), token.Token)
		assert.Error(t, err)
		assert.Nil(t, newToken)
	})

	t.Run("rotation fails when disabled", func(t *testing.T) {
		maker := setupTestMaker(t) // No repository, rotation disabled
		ctx := context.Background()

		token, err := maker.CreateRefreshToken(ctx, uuid.New(), "user", uuid.New())
		require.NoError(t, err)

		newToken, err := maker.RotateRefreshToken(ctx, token.Token)
		assert.Error(t, err)
		assert.Nil(t, newToken)
		assert.Contains(t, err.Error(), "token rotation not enabled")
	})

	t.Run("tokens still verify when rotation disabled", func(t *testing.T) {
		maker := setupTestMaker(t)
		ctx := context.Background()

		token, err := maker.CreateRefreshToken(ctx, uuid.New(), "user", uuid.New())
		require.NoError(t, err)

		// Should still be able to verify
		claims, err := maker.VerifyRefreshToken(ctx, token.Token)
		assert.NoError(t, err)
		assert.NotNil(t, claims)
	})
}

func TestRotateRefreshToken_FeatureDisabled(t *testing.T) {
	// Setup config with rotation disabled
	config := DefaultTestConfig()
	config.RotationEnabled = false

	maker := setupTestMakerWithConfig(t, config, nil)

	userID := uuid.New()
	sessionID := uuid.New()
	username := "testuser"

	t.Run("returns error when rotation is disabled", func(t *testing.T) {
		response, err := maker.CreateRefreshToken(context.Background(), userID, username, sessionID)
		require.NoError(t, err)

		newToken, err := maker.RotateRefreshToken(context.Background(), response.Token)
		assert.Error(t, err)
		assert.Nil(t, newToken)
		assert.Contains(t, err.Error(), "token rotation not enabled")
	})
}

func TestRotationAndRevocation_Integration(t *testing.T) {
	config := DefaultTestConfig()
	config.RotationEnabled = true
	config.RevocationEnabled = true

	repo := NewMemoryTokenRepository(1 * time.Hour)
	maker := setupTestMakerWithConfig(t, config, repo)

	userID := uuid.New()
	sessionID := uuid.New()
	username := "testuser"
	roles := []string{"admin"}

	t.Run("rotation and revocation work together", func(t *testing.T) {
		ctx := context.Background()

		// Create access and refresh tokens
		accessToken, err := maker.CreateAccessToken(ctx, userID, username, roles, sessionID)
		require.NoError(t, err)

		refreshToken, err := maker.CreateRefreshToken(ctx, userID, username, sessionID)
		require.NoError(t, err)

		// Revoke access token
		err = maker.RevokeAccessToken(ctx, accessToken.Token)
		require.NoError(t, err)

		// Verify access token is revoked
		_, err = maker.VerifyAccessToken(ctx, accessToken.Token)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "revoked")

		// Rotate refresh token
		newRefreshToken, err := maker.RotateRefreshToken(ctx, refreshToken.Token)
		require.NoError(t, err)

		// Verify old refresh token cannot be rotated again
		// Error comes from VerifyRefreshToken check
		_, err = maker.RotateRefreshToken(ctx, refreshToken.Token)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "token has been rotated")

		// Verify new refresh token works
		newClaims, err := maker.VerifyRefreshToken(ctx, newRefreshToken.Token)
		assert.NoError(t, err)
		assert.NotNil(t, newClaims)

		// Create new access token using the new refresh token context
		newAccessToken, err := maker.CreateAccessToken(ctx, userID, username, roles, sessionID)
		require.NoError(t, err)

		// Verify new access token works
		_, err = maker.VerifyAccessToken(ctx, newAccessToken.Token)
		assert.NoError(t, err)
	})

	t.Run("cannot rotate revoked refresh token", func(t *testing.T) {
		ctx := context.Background()

		// Create refresh token
		refreshToken, err := maker.CreateRefreshToken(ctx, userID, username, sessionID)
		require.NoError(t, err)

		// Revoke the refresh token
		err = maker.RevokeRefreshToken(ctx, refreshToken.Token)
		require.NoError(t, err)

		// Attempt to rotate revoked token should fail
		newToken, err := maker.RotateRefreshToken(ctx, refreshToken.Token)
		assert.Error(t, err)
		assert.Nil(t, newToken)
		assert.Contains(t, err.Error(), "revoked")
	})
}

func TestRotateRefreshToken_InvalidInput(t *testing.T) {
	config := DefaultTestConfig()
	config.RotationEnabled = true
	config.RevocationEnabled = true

	repo := NewMemoryTokenRepository(1 * time.Hour)
	maker := setupTestMakerWithConfig(t, config, repo)

	t.Run("fails with empty token", func(t *testing.T) {
		ctx := context.Background()

		newToken, err := maker.RotateRefreshToken(ctx, "")
		assert.Error(t, err)
		assert.Nil(t, newToken)
	})

	t.Run("fails with malformed token", func(t *testing.T) {
		ctx := context.Background()

		newToken, err := maker.RotateRefreshToken(ctx, "malformed.token.here")
		assert.Error(t, err)
		assert.Nil(t, newToken)
	})

	t.Run("fails with access token instead of refresh token", func(t *testing.T) {
		ctx := context.Background()

		userID := uuid.New()
		sessionID := uuid.New()
		username := "testuser"
		roles := []string{"admin"}

		// Create access token
		accessToken, err := maker.CreateAccessToken(ctx, userID, username, roles, sessionID)
		require.NoError(t, err)

		// Try to rotate access token as refresh token
		newToken, err := maker.RotateRefreshToken(ctx, accessToken.Token)
		assert.Error(t, err)
		assert.Nil(t, newToken)
		assert.Contains(t, err.Error(), "invalid token")
	})
}

func TestRotateRefreshToken_ContextCancellation(t *testing.T) {
	// Setup config with rotation enabled
	config := DefaultTestConfig()
	config.RotationEnabled = true
	config.RevocationEnabled = true // Keep enabled for realistic scenario

	// Use actual MemoryTokenRepository instead of mock
	repo := NewMemoryTokenRepository(1 * time.Hour)
	maker := setupTestMakerWithConfig(t, config, repo)

	userID := uuid.New()
	sessionID := uuid.New()
	username := "testuser"

	t.Run("returns error when context is canceled at beginning", func(t *testing.T) {
		response, err := maker.CreateRefreshToken(context.Background(), userID, username, sessionID)
		require.NoError(t, err)

		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		newToken, err := maker.RotateRefreshToken(ctx, response.Token)
		assert.Error(t, err)
		assert.Nil(t, newToken)
		assert.Contains(t, err.Error(), "context canceled")
	})

	t.Run("succeeds with valid context", func(t *testing.T) {
		response, err := maker.CreateRefreshToken(context.Background(), userID, username, sessionID)
		require.NoError(t, err)

		newToken, err := maker.RotateRefreshToken(context.Background(), response.Token)
		assert.NoError(t, err)
		assert.NotNil(t, newToken)
		assert.NotEqual(t, response.Token, newToken.Token)

		// Verify the old token is marked as rotated
		rotated, err := repo.IsTokenRotated(context.Background(), response.Token)
		assert.NoError(t, err)
		assert.True(t, rotated, "old token should be marked as rotated")

		// Verify new token can be verified
		claims, err := maker.VerifyRefreshToken(context.Background(), newToken.Token)
		assert.NoError(t, err)
		assert.NotNil(t, claims)
		assert.Equal(t, userID, claims.Subject)
	})
}
