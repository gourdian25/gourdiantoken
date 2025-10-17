// File: token.revocation_test.go


package gourdiantoken

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRevokeAccessToken_ContextCancellation(t *testing.T) {
	// Setup config with revocation enabled
	config := DefaultTestConfig()
	config.RevocationEnabled = true

	// Use actual MemoryTokenRepository instead of mock
	repo := NewMemoryTokenRepository(1 * time.Hour)
	maker := setupTestMakerWithConfig(t, config, repo)

	userID := uuid.New()
	sessionID := uuid.New()
	username := "testuser"
	roles := []string{"admin"}

	t.Run("returns error when context is canceled", func(t *testing.T) {
		// Create token first
		response, err := maker.CreateAccessToken(context.Background(), userID, username, roles, sessionID)
		require.NoError(t, err)

		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		err = maker.RevokeAccessToken(ctx, response.Token)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "context canceled")
	})

	t.Run("succeeds with valid context", func(t *testing.T) {
		response, err := maker.CreateAccessToken(context.Background(), userID, username, roles, sessionID)
		require.NoError(t, err)

		err = maker.RevokeAccessToken(context.Background(), response.Token)
		assert.NoError(t, err)

		// Verify the token is actually revoked
		revoked, err := repo.IsTokenRevoked(context.Background(), AccessToken, response.Token)
		assert.NoError(t, err)
		assert.True(t, revoked, "token should be marked as revoked")
	})
}

func TestRevokeRefreshToken_ContextCancellation(t *testing.T) {
	// Setup config with revocation enabled
	config := DefaultTestConfig()
	config.RevocationEnabled = true

	// Use actual MemoryTokenRepository instead of mock
	repo := NewMemoryTokenRepository(1 * time.Hour)
	maker := setupTestMakerWithConfig(t, config, repo)

	userID := uuid.New()
	sessionID := uuid.New()
	username := "testuser"

	t.Run("returns error when context is canceled", func(t *testing.T) {
		response, err := maker.CreateRefreshToken(context.Background(), userID, username, sessionID)
		require.NoError(t, err)

		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		err = maker.RevokeRefreshToken(ctx, response.Token)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "context canceled")
	})

	t.Run("succeeds with valid context", func(t *testing.T) {
		response, err := maker.CreateRefreshToken(context.Background(), userID, username, sessionID)
		require.NoError(t, err)

		err = maker.RevokeRefreshToken(context.Background(), response.Token)
		assert.NoError(t, err)

		// Verify the token is actually revoked
		revoked, err := repo.IsTokenRevoked(context.Background(), RefreshToken, response.Token)
		assert.NoError(t, err)
		assert.True(t, revoked, "token should be marked as revoked")
	})
}

func TestRevokeAccessToken_FeatureDisabled(t *testing.T) {
	// Setup config with revocation disabled
	config := DefaultTestConfig()
	config.RevocationEnabled = false

	maker := setupTestMakerWithConfig(t, config, nil)

	userID := uuid.New()
	sessionID := uuid.New()
	username := "testuser"
	roles := []string{"admin"}

	t.Run("returns error when revocation is disabled", func(t *testing.T) {
		response, err := maker.CreateAccessToken(context.Background(), userID, username, roles, sessionID)
		require.NoError(t, err)

		err = maker.RevokeAccessToken(context.Background(), response.Token)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "access token revocation is not enabled")
	})
}

func TestRevokeRefreshToken_FeatureDisabled(t *testing.T) {
	// Setup config with revocation disabled
	config := DefaultTestConfig()
	config.RevocationEnabled = false

	maker := setupTestMakerWithConfig(t, config, nil)

	userID := uuid.New()
	sessionID := uuid.New()
	username := "testuser"

	t.Run("returns error when revocation is disabled", func(t *testing.T) {
		response, err := maker.CreateRefreshToken(context.Background(), userID, username, sessionID)
		require.NoError(t, err)

		err = maker.RevokeRefreshToken(context.Background(), response.Token)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "refresh token revocation is not enabled")
	})
}
