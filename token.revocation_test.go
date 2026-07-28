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

	userID := uuid.NewString()
	sessionID := uuid.NewString()
	username := "testuser"
	roles := []string{"admin"}

	t.Run("returns error when context is canceled", func(t *testing.T) {
		// Create token first
		response, err := maker.CreateAccessToken(context.Background(), userID, username, roles, sessionID, "")
		require.NoError(t, err)

		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		err = maker.RevokeAccessToken(ctx, response.Token)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "context canceled")
	})

	t.Run("succeeds with valid context", func(t *testing.T) {
		response, err := maker.CreateAccessToken(context.Background(), userID, username, roles, sessionID, "")
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

	userID := uuid.NewString()
	sessionID := uuid.NewString()
	username := "testuser"

	t.Run("returns error when context is canceled", func(t *testing.T) {
		response, err := maker.CreateRefreshToken(context.Background(), userID, username, sessionID, "")
		require.NoError(t, err)

		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		err = maker.RevokeRefreshToken(ctx, response.Token)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "context canceled")
	})

	t.Run("succeeds with valid context", func(t *testing.T) {
		response, err := maker.CreateRefreshToken(context.Background(), userID, username, sessionID, "")
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

	userID := uuid.NewString()
	sessionID := uuid.NewString()
	username := "testuser"
	roles := []string{"admin"}

	t.Run("returns error when revocation is disabled", func(t *testing.T) {
		response, err := maker.CreateAccessToken(context.Background(), userID, username, roles, sessionID, "")
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

	userID := uuid.NewString()
	sessionID := uuid.NewString()
	username := "testuser"

	t.Run("returns error when revocation is disabled", func(t *testing.T) {
		response, err := maker.CreateRefreshToken(context.Background(), userID, username, sessionID, "")
		require.NoError(t, err)

		err = maker.RevokeRefreshToken(context.Background(), response.Token)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "refresh token revocation is not enabled")
	})
}

func TestRevokeTenant_ContextCancellation(t *testing.T) {
	config := DefaultTestConfig()
	config.MultiTenantEnabled = true

	repo := NewMemoryTokenRepository(1 * time.Hour)
	maker := setupTestMakerWithConfig(t, config, repo)

	t.Run("returns error when context is canceled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		err := maker.RevokeTenant(ctx, "acme-corp")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "context canceled")
	})

	t.Run("succeeds with valid context", func(t *testing.T) {
		err := maker.RevokeTenant(context.Background(), "acme-corp")
		assert.NoError(t, err)

		epoch, err := repo.GetTenantRevocationEpoch(context.Background(), "acme-corp")
		assert.NoError(t, err)
		assert.False(t, epoch.IsZero(), "revocation epoch should be recorded")
	})
}

func TestRevokeTenant_MultiTenantDisabled(t *testing.T) {
	// MultiTenantEnabled defaults to false.
	config := DefaultTestConfig()
	repo := NewMemoryTokenRepository(1 * time.Hour)
	maker := setupTestMakerWithConfig(t, config, repo)

	err := maker.RevokeTenant(context.Background(), "acme-corp")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrMultiTenantDisabled)
}

// TestJWTMakerRevokeTenant_EmptyTenantID is named distinctly from
// TestRevokeTenant_EmptyTenantID in gourdiantoken.repository_test.go (which exercises the
// same precondition at the TokenRepository level directly) to avoid a package-level name
// collision.
func TestJWTMakerRevokeTenant_EmptyTenantID(t *testing.T) {
	config := DefaultTestConfig()
	config.MultiTenantEnabled = true

	repo := NewMemoryTokenRepository(1 * time.Hour)
	maker := setupTestMakerWithConfig(t, config, repo)

	err := maker.RevokeTenant(context.Background(), "")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrTenantIDRequired)
}

func TestRevokeTenant_RevocationDisabled(t *testing.T) {
	config := DefaultTestConfig()
	config.MultiTenantEnabled = true
	config.RevocationEnabled = false

	// repo=nil: setupTestMakerWithConfig only forces RevocationEnabled/RotationEnabled to
	// true when a repo is supplied, so this is the only way to exercise
	// MultiTenantEnabled=true with RevocationEnabled=false.
	maker := setupTestMakerWithConfig(t, config, nil)

	err := maker.RevokeTenant(context.Background(), "acme-corp")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "tenant revocation is not enabled")
}

// TestRevokeTenant_EndToEndEpoch exercises the full bulk-revocation story: a token issued
// for a tenant before that tenant's revocation epoch fails verification (and, for refresh
// tokens, rotation) after the epoch is recorded, while a token issued after the epoch
// succeeds, and a different tenant's pre-existing token is entirely unaffected.
func TestRevokeTenant_EndToEndEpoch(t *testing.T) {
	config := DefaultTestConfig()
	config.MultiTenantEnabled = true

	repo := NewMemoryTokenRepository(1 * time.Hour)
	maker := setupTestMakerWithConfig(t, config, repo)
	ctx := context.Background()

	const tenantID = "acme-corp"
	const otherTenantID = "other-tenant"

	preAccess, err := maker.CreateAccessToken(ctx, uuid.NewString(), "user", []string{"admin"}, uuid.NewString(), tenantID)
	require.NoError(t, err)
	preRefresh, err := maker.CreateRefreshToken(ctx, uuid.NewString(), "user", uuid.NewString(), tenantID)
	require.NoError(t, err)

	otherTenantAccess, err := maker.CreateAccessToken(ctx, uuid.NewString(), "user", []string{"admin"}, uuid.NewString(), otherTenantID)
	require.NoError(t, err)

	// Sanity: everything verifies fine before any revocation.
	_, err = maker.VerifyAccessToken(ctx, preAccess.Token)
	require.NoError(t, err)
	_, err = maker.VerifyRefreshToken(ctx, preRefresh.Token)
	require.NoError(t, err)

	require.NoError(t, maker.RevokeTenant(ctx, tenantID))

	// Pre-epoch access token now fails verification.
	_, err = maker.VerifyAccessToken(ctx, preAccess.Token)
	assert.ErrorIs(t, err, ErrTenantRevoked)

	// Pre-epoch refresh token now fails both verification and rotation.
	_, err = maker.VerifyRefreshToken(ctx, preRefresh.Token)
	assert.ErrorIs(t, err, ErrTenantRevoked)

	_, err = maker.RotateRefreshToken(ctx, preRefresh.Token)
	assert.ErrorIs(t, err, ErrTenantRevoked)

	// A different tenant's pre-existing token is entirely unaffected.
	_, err = maker.VerifyAccessToken(ctx, otherTenantAccess.Token)
	assert.NoError(t, err)

	// Sleep past the next whole second: the epoch is recorded with (at best) sub-second
	// precision, but a token's "iat" claim is second-granular (see toMapClaims), so a token
	// minted within the same wall-clock second as RevokeTenant could still floor to
	// at-or-before the epoch even though it was genuinely issued afterward. This margin is
	// what the real Stage 3 design decision (max(AccessExpiryDuration,
	// RefreshExpiryDuration) TTL) already assumes callers tolerate.
	time.Sleep(1100 * time.Millisecond)

	postAccess, err := maker.CreateAccessToken(ctx, uuid.NewString(), "user", []string{"admin"}, uuid.NewString(), tenantID)
	require.NoError(t, err)
	_, err = maker.VerifyAccessToken(ctx, postAccess.Token)
	assert.NoError(t, err, "a token issued after the revocation epoch should verify successfully")
}
