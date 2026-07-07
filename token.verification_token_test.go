// File: token.verification_token_test.go

package gourdiantoken

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// verificationConfig returns a base config with verification tokens enabled, suitable
// as a starting point for setupTestMakerWithConfig (which fills in the remaining
// Access/Refresh fields with defaults and, when a repo is passed, forces
// RevocationEnabled/RotationEnabled to true).
func verificationConfig() GourdianTokenConfig {
	return GourdianTokenConfig{
		VerificationTokensEnabled:         true,
		VerificationDefaultExpiryDuration: 5 * time.Minute,
		VerificationMaxExpiryDuration:     1 * time.Hour,
		VerificationAllowedUseCases:       []string{"2fa-pending", "password-reset"},
	}
}

func TestVerificationToken_FullLifecycle(t *testing.T) {
	repo := NewMemoryTokenRepository(1 * time.Minute)
	maker := setupTestMakerWithConfig(t, verificationConfig(), repo)
	ctx := context.Background()
	userID := uuid.NewString()

	token, err := maker.CreateVerificationToken(ctx, userID, "2fa-pending", 0, map[string]interface{}{"username": "alice"})
	require.NoError(t, err)
	assert.NotEmpty(t, token.Token)
	assert.Equal(t, userID, token.Subject)
	assert.Equal(t, "2fa-pending", token.UseCase)
	assert.Equal(t, VerificationToken, token.TokenType)

	claims, err := maker.VerifyVerificationToken(ctx, token.Token)
	require.NoError(t, err)
	assert.Equal(t, userID, claims.Subject)
	assert.Equal(t, "2fa-pending", claims.UseCase)
	assert.Equal(t, "alice", claims.Metadata["username"])

	// Verifying again before marking used must still succeed: callers may check a
	// verification token more than once before deliberately consuming it.
	_, err = maker.VerifyVerificationToken(ctx, token.Token)
	require.NoError(t, err)

	require.NoError(t, maker.MarkVerificationTokenUsed(ctx, token.Token))

	_, err = maker.VerifyVerificationToken(ctx, token.Token)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTokenAlreadyUsed)
}

func TestVerificationToken_TTLDefaulting(t *testing.T) {
	maker := setupTestMakerWithConfig(t, verificationConfig(), nil)
	ctx := context.Background()

	token, err := maker.CreateVerificationToken(ctx, uuid.NewString(), "2fa-pending", 0, nil)
	require.NoError(t, err)

	expectedExpiry := token.IssuedAt.Add(5 * time.Minute)
	assert.WithinDuration(t, expectedExpiry, token.ExpiresAt, time.Second)
}

func TestVerificationToken_TTLWithinMaxHonored(t *testing.T) {
	maker := setupTestMakerWithConfig(t, verificationConfig(), nil)
	ctx := context.Background()

	token, err := maker.CreateVerificationToken(ctx, uuid.NewString(), "2fa-pending", 20*time.Minute, nil)
	require.NoError(t, err)

	expectedExpiry := token.IssuedAt.Add(20 * time.Minute)
	assert.WithinDuration(t, expectedExpiry, token.ExpiresAt, time.Second)
}

func TestVerificationToken_TTLExceedsMaxRejected(t *testing.T) {
	maker := setupTestMakerWithConfig(t, verificationConfig(), nil)
	ctx := context.Background()

	_, err := maker.CreateVerificationToken(ctx, uuid.NewString(), "2fa-pending", 2*time.Hour, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds maximum allowed")
}

func TestVerificationToken_UseCaseWhitelist(t *testing.T) {
	t.Run("allowed use case succeeds at create and verify", func(t *testing.T) {
		maker := setupTestMakerWithConfig(t, verificationConfig(), nil)
		ctx := context.Background()

		token, err := maker.CreateVerificationToken(ctx, uuid.NewString(), "password-reset", 0, nil)
		require.NoError(t, err)

		claims, err := maker.VerifyVerificationToken(ctx, token.Token)
		require.NoError(t, err)
		assert.Equal(t, "password-reset", claims.UseCase)
	})

	t.Run("disallowed use case rejected at create", func(t *testing.T) {
		maker := setupTestMakerWithConfig(t, verificationConfig(), nil)
		ctx := context.Background()

		_, err := maker.CreateVerificationToken(ctx, uuid.NewString(), "email-verify", 0, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not in the allowed list")
	})

	t.Run("empty whitelist allows any non-empty use case", func(t *testing.T) {
		config := verificationConfig()
		config.VerificationAllowedUseCases = nil
		maker := setupTestMakerWithConfig(t, config, nil)
		ctx := context.Background()

		token, err := maker.CreateVerificationToken(ctx, uuid.NewString(), "anything-goes", 0, nil)
		require.NoError(t, err)

		claims, err := maker.VerifyVerificationToken(ctx, token.Token)
		require.NoError(t, err)
		assert.Equal(t, "anything-goes", claims.UseCase)
	})

	t.Run("empty use case rejected at create", func(t *testing.T) {
		maker := setupTestMakerWithConfig(t, verificationConfig(), nil)
		ctx := context.Background()

		_, err := maker.CreateVerificationToken(ctx, uuid.NewString(), "", 0, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "use case cannot be empty")
	})

	t.Run("use case removed from whitelist after issuance rejected at verify", func(t *testing.T) {
		config := verificationConfig()
		maker := setupTestMakerWithConfig(t, config, nil)
		ctx := context.Background()

		token, err := maker.CreateVerificationToken(ctx, uuid.NewString(), "password-reset", 0, nil)
		require.NoError(t, err)

		// Tighten the whitelist after issuance to simulate config drift.
		maker.config.VerificationAllowedUseCases = []string{"2fa-pending"}

		_, err = maker.VerifyVerificationToken(ctx, token.Token)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not in the allowed list")
	})
}

func TestVerificationToken_MetadataRoundtrip(t *testing.T) {
	t.Run("non-trivial metadata roundtrips", func(t *testing.T) {
		maker := setupTestMakerWithConfig(t, verificationConfig(), nil)
		ctx := context.Background()

		metadata := map[string]interface{}{
			"username": "alice",
			"attempt":  float64(3), // JSON numbers decode as float64
			"nested":   map[string]interface{}{"ip": "10.0.0.1"},
		}

		token, err := maker.CreateVerificationToken(ctx, uuid.NewString(), "2fa-pending", 0, metadata)
		require.NoError(t, err)

		claims, err := maker.VerifyVerificationToken(ctx, token.Token)
		require.NoError(t, err)
		assert.Equal(t, "alice", claims.Metadata["username"])
		assert.Equal(t, float64(3), claims.Metadata["attempt"])
		assert.Equal(t, map[string]interface{}{"ip": "10.0.0.1"}, claims.Metadata["nested"])
	})

	t.Run("nil metadata roundtrips as empty, no phantom mtd claim", func(t *testing.T) {
		maker := setupTestMakerWithConfig(t, verificationConfig(), nil)
		ctx := context.Background()

		token, err := maker.CreateVerificationToken(ctx, uuid.NewString(), "2fa-pending", 0, nil)
		require.NoError(t, err)

		claims, err := maker.VerifyVerificationToken(ctx, token.Token)
		require.NoError(t, err)
		assert.Empty(t, claims.Metadata)
	})
}

func TestVerificationToken_FeatureDisabled(t *testing.T) {
	maker := setupTestMakerWithConfig(t, DefaultTestConfig(), nil)
	ctx := context.Background()

	_, err := maker.CreateVerificationToken(ctx, uuid.NewString(), "2fa-pending", 0, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "verification tokens are not enabled")

	_, err = maker.VerifyVerificationToken(ctx, "irrelevant-token-string")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "verification tokens are not enabled")

	err = maker.MarkVerificationTokenUsed(ctx, "irrelevant-token-string")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "verification tokens are not enabled")
}

func TestVerificationToken_SingleUseRequiresRevocationEnabled(t *testing.T) {
	// VerificationTokensEnabled without RevocationEnabled: creation/verification work,
	// but MarkVerificationTokenUsed fails explicitly rather than silently no-op'ing.
	maker := setupTestMakerWithConfig(t, verificationConfig(), nil)
	ctx := context.Background()

	token, err := maker.CreateVerificationToken(ctx, uuid.NewString(), "2fa-pending", 0, nil)
	require.NoError(t, err)

	_, err = maker.VerifyVerificationToken(ctx, token.Token)
	require.NoError(t, err)

	err = maker.MarkVerificationTokenUsed(ctx, token.Token)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "revocation is not enabled")
}

func TestVerificationToken_EmptySubjectRejected(t *testing.T) {
	maker := setupTestMakerWithConfig(t, verificationConfig(), nil)
	ctx := context.Background()

	_, err := maker.CreateVerificationToken(ctx, "", "2fa-pending", 0, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "user ID cannot be empty")
}
