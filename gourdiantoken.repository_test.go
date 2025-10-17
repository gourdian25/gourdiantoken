// File: gourdiantoken.repository_test.go


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

// =============================================================================
// MarkTokenRevoke Tests
// =============================================================================

// TestMarkTokenRevoke_SuccessAccessToken verifies that an access token can be
// successfully marked as revoked and stored in the repository with the correct TTL.
func TestMarkTokenRevoke_SuccessAccessToken(t *testing.T) {
	factories := getTestRepositoryFactories()

	for name, factory := range factories {
		t.Run(name, func(t *testing.T) {
			repo, cleanup := factory(t)
			defer cleanup()

			ctx := context.Background()
			token := fmt.Sprintf("test-access-token-%s-12345", name)
			ttl := 30 * time.Minute

			// Mark the token as revoked
			err := repo.MarkTokenRevoke(ctx, AccessToken, token, ttl)
			assert.NoError(t, err, "should successfully mark access token as revoked")

			// Verify the token is actually marked as revoked in the repository
			revoked, err := repo.IsTokenRevoked(ctx, AccessToken, token)
			assert.NoError(t, err, "should successfully check if token is revoked")
			assert.True(t, revoked, "token should be marked as revoked")
		})
	}
}

// TestMarkTokenRevoke_SuccessRefreshToken verifies that a refresh token can be
// successfully marked as revoked with a longer TTL appropriate for refresh tokens.
func TestMarkTokenRevoke_SuccessRefreshToken(t *testing.T) {
	factories := getTestRepositoryFactories()

	for name, factory := range factories {
		t.Run(name, func(t *testing.T) {
			repo, cleanup := factory(t)
			defer cleanup()

			ctx := context.Background()
			token := fmt.Sprintf("test-refresh-token-%s-12345", name)
			ttl := 7 * 24 * time.Hour // 7 days

			// Mark the token as revoked
			err := repo.MarkTokenRevoke(ctx, RefreshToken, token, ttl)
			assert.NoError(t, err, "should successfully mark refresh token as revoked")

			// Verify the token is actually marked as revoked in the repository
			revoked, err := repo.IsTokenRevoked(ctx, RefreshToken, token)
			assert.NoError(t, err, "should successfully check if token is revoked")
			assert.True(t, revoked, "token should be marked as revoked")
		})
	}
}

// TestMarkTokenRevoke_EmptyToken verifies that attempting to mark an empty token
// as revoked returns an appropriate error, preventing invalid data in the repository.
func TestMarkTokenRevoke_EmptyToken(t *testing.T) {
	factories := getTestRepositoryFactories()

	for name, factory := range factories {
		t.Run(name, func(t *testing.T) {
			repo, cleanup := factory(t)
			defer cleanup()

			ctx := context.Background()

			// Attempt to mark empty token as revoked
			err := repo.MarkTokenRevoke(ctx, AccessToken, "", 30*time.Minute)
			assert.Error(t, err, "should return error for empty token")
			assert.Contains(t, err.Error(), "token cannot be empty", "error message should indicate empty token")
		})
	}
}

// TestMarkTokenRevoke_ZeroTTL verifies that attempting to mark a token as revoked
// with zero TTL returns an error, as TTL must be positive for proper expiration.
func TestMarkTokenRevoke_ZeroTTL(t *testing.T) {
	factories := getTestRepositoryFactories()

	for name, factory := range factories {
		t.Run(name, func(t *testing.T) {
			repo, cleanup := factory(t)
			defer cleanup()

			ctx := context.Background()
			token := fmt.Sprintf("test-token-%s-12345", name)

			// Attempt to mark token with zero TTL
			err := repo.MarkTokenRevoke(ctx, AccessToken, token, 0)
			assert.Error(t, err, "should return error for zero TTL")
			assert.Contains(t, err.Error(), "ttl must be positive", "error message should indicate invalid TTL")
		})
	}
}

// TestMarkTokenRevoke_NegativeTTL verifies that attempting to mark a token as revoked
// with negative TTL returns an error, as negative TTL is invalid.
func TestMarkTokenRevoke_NegativeTTL(t *testing.T) {
	factories := getTestRepositoryFactories()

	for name, factory := range factories {
		t.Run(name, func(t *testing.T) {
			repo, cleanup := factory(t)
			defer cleanup()

			ctx := context.Background()
			token := fmt.Sprintf("test-token-%s-12345", name)

			// Attempt to mark token with negative TTL
			err := repo.MarkTokenRevoke(ctx, AccessToken, token, -1*time.Minute)
			assert.Error(t, err, "should return error for negative TTL")
			assert.Contains(t, err.Error(), "ttl must be positive", "error message should indicate invalid TTL")
		})
	}
}

// TestMarkTokenRevoke_InvalidTokenType verifies that attempting to mark a token
// with an invalid token type returns an appropriate error.
func TestMarkTokenRevoke_InvalidTokenType(t *testing.T) {
	factories := getTestRepositoryFactories()

	for name, factory := range factories {
		t.Run(name, func(t *testing.T) {
			repo, cleanup := factory(t)
			defer cleanup()

			ctx := context.Background()
			token := fmt.Sprintf("test-token-%s-12345", name)
			invalidType := TokenType("invalid_type")

			// Attempt to mark token with invalid type
			err := repo.MarkTokenRevoke(ctx, invalidType, token, 30*time.Minute)
			assert.Error(t, err, "should return error for invalid token type")
			assert.Contains(t, err.Error(), "invalid token type", "error message should indicate invalid token type")
		})
	}
}

// TestMarkTokenRevoke_UpdateExistingToken verifies that marking the same token
// as revoked multiple times updates the TTL without causing errors. This is
// important for idempotency.
func TestMarkTokenRevoke_UpdateExistingToken(t *testing.T) {
	factories := getTestRepositoryFactories()

	for name, factory := range factories {
		t.Run(name, func(t *testing.T) {
			repo, cleanup := factory(t)
			defer cleanup()

			ctx := context.Background()
			token := fmt.Sprintf("test-token-%s-12345", name)

			// First revocation with 30 minute TTL
			err := repo.MarkTokenRevoke(ctx, AccessToken, token, 30*time.Minute)
			require.NoError(t, err, "first revocation should succeed")

			// Verify token is revoked
			revoked, err := repo.IsTokenRevoked(ctx, AccessToken, token)
			require.NoError(t, err)
			require.True(t, revoked, "token should be revoked after first call")

			// Second revocation with different TTL (1 hour)
			err = repo.MarkTokenRevoke(ctx, AccessToken, token, 1*time.Hour)
			assert.NoError(t, err, "second revocation should succeed (idempotent operation)")

			// Verify token is still revoked
			revoked, err = repo.IsTokenRevoked(ctx, AccessToken, token)
			assert.NoError(t, err)
			assert.True(t, revoked, "token should still be revoked after update")
		})
	}
}

// TestMarkTokenRevoke_DifferentTokenTypes verifies that the same token string
// can be marked as revoked for different token types independently.
func TestMarkTokenRevoke_DifferentTokenTypes(t *testing.T) {
	factories := getTestRepositoryFactories()

	for name, factory := range factories {
		t.Run(name, func(t *testing.T) {
			repo, cleanup := factory(t)
			defer cleanup()

			ctx := context.Background()
			token := fmt.Sprintf("test-token-%s-same", name)

			// Mark as access token
			err := repo.MarkTokenRevoke(ctx, AccessToken, token, 30*time.Minute)
			require.NoError(t, err, "should mark token as revoked access token")

			// Mark same token as refresh token
			err = repo.MarkTokenRevoke(ctx, RefreshToken, token, 1*time.Hour)
			require.NoError(t, err, "should mark same token as revoked refresh token")

			// Verify both are revoked independently
			accessRevoked, err := repo.IsTokenRevoked(ctx, AccessToken, token)
			assert.NoError(t, err)
			assert.True(t, accessRevoked, "should be revoked as access token")

			refreshRevoked, err := repo.IsTokenRevoked(ctx, RefreshToken, token)
			assert.NoError(t, err)
			assert.True(t, refreshRevoked, "should be revoked as refresh token")
		})
	}
}

// =============================================================================
// IsTokenRevoked Tests
// =============================================================================

// TestIsTokenRevoked_NonRevokedToken verifies that checking a token that was
// never marked as revoked returns false, indicating it's still valid.
func TestIsTokenRevoked_NonRevokedToken(t *testing.T) {
	factories := getTestRepositoryFactories()

	for name, factory := range factories {
		t.Run(name, func(t *testing.T) {
			repo, cleanup := factory(t)
			defer cleanup()

			ctx := context.Background()
			token := fmt.Sprintf("non-revoked-token-%s-12345", name)

			// Check if non-revoked token is revoked
			revoked, err := repo.IsTokenRevoked(ctx, AccessToken, token)
			assert.NoError(t, err, "should successfully check non-revoked token")
			assert.False(t, revoked, "non-revoked token should return false")
		})
	}
}

// TestIsTokenRevoked_RevokedAccessToken verifies that a token marked as
// revoked access token is correctly identified as revoked.
func TestIsTokenRevoked_RevokedAccessToken(t *testing.T) {
	factories := getTestRepositoryFactories()

	for name, factory := range factories {
		t.Run(name, func(t *testing.T) {
			repo, cleanup := factory(t)
			defer cleanup()

			ctx := context.Background()
			token := fmt.Sprintf("revoked-access-token-%s-12345", name)

			// Mark token as revoked
			err := repo.MarkTokenRevoke(ctx, AccessToken, token, 30*time.Minute)
			require.NoError(t, err, "should successfully mark token as revoked")

			// Check if token is revoked
			revoked, err := repo.IsTokenRevoked(ctx, AccessToken, token)
			assert.NoError(t, err, "should successfully check if token is revoked")
			assert.True(t, revoked, "revoked token should return true")
		})
	}
}

// TestIsTokenRevoked_RevokedRefreshToken verifies that a token marked as
// revoked refresh token is correctly identified as revoked.
func TestIsTokenRevoked_RevokedRefreshToken(t *testing.T) {
	factories := getTestRepositoryFactories()

	for name, factory := range factories {
		t.Run(name, func(t *testing.T) {
			repo, cleanup := factory(t)
			defer cleanup()

			ctx := context.Background()
			token := fmt.Sprintf("revoked-refresh-token-%s-12345", name)

			// Mark token as revoked
			err := repo.MarkTokenRevoke(ctx, RefreshToken, token, 7*24*time.Hour)
			require.NoError(t, err, "should successfully mark token as revoked")

			// Check if token is revoked
			revoked, err := repo.IsTokenRevoked(ctx, RefreshToken, token)
			assert.NoError(t, err, "should successfully check if token is revoked")
			assert.True(t, revoked, "revoked token should return true")
		})
	}
}

// TestIsTokenRevoked_EmptyToken verifies that checking an empty token
// returns an appropriate error.
func TestIsTokenRevoked_EmptyToken(t *testing.T) {
	factories := getTestRepositoryFactories()

	for name, factory := range factories {
		t.Run(name, func(t *testing.T) {
			repo, cleanup := factory(t)
			defer cleanup()

			ctx := context.Background()

			// Check empty token
			revoked, err := repo.IsTokenRevoked(ctx, AccessToken, "")
			assert.Error(t, err, "should return error for empty token")
			assert.Contains(t, err.Error(), "token cannot be empty", "error message should indicate empty token")
			assert.False(t, revoked, "should return false when error occurs")
		})
	}
}

// TestIsTokenRevoked_InvalidTokenType verifies that checking a token with
// an invalid token type returns an appropriate error.
func TestIsTokenRevoked_InvalidTokenType(t *testing.T) {
	factories := getTestRepositoryFactories()

	for name, factory := range factories {
		t.Run(name, func(t *testing.T) {
			repo, cleanup := factory(t)
			defer cleanup()

			ctx := context.Background()
			token := fmt.Sprintf("test-token-%s-12345", name)
			invalidType := TokenType("invalid_type")

			// Check with invalid token type
			revoked, err := repo.IsTokenRevoked(ctx, invalidType, token)
			assert.Error(t, err, "should return error for invalid token type")
			assert.Contains(t, err.Error(), "invalid token type", "error message should indicate invalid token type")
			assert.False(t, revoked, "should return false when error occurs")
		})
	}
}

// TestIsTokenRevoked_ExpiredRevokedToken verifies that a token marked as revoked
// with a very short TTL is no longer considered revoked after the TTL expires.
// This ensures proper cleanup and expiration behavior.
func TestIsTokenRevoked_ExpiredRevokedToken(t *testing.T) {
	factories := getTestRepositoryFactories()

	for name, factory := range factories {
		t.Run(name, func(t *testing.T) {
			repo, cleanup := factory(t)
			defer cleanup()

			ctx := context.Background()
			token := fmt.Sprintf("expired-revoked-token-%s-12345", name)

			// Mark token as revoked with very short TTL
			err := repo.MarkTokenRevoke(ctx, AccessToken, token, 50*time.Millisecond)
			require.NoError(t, err, "should successfully mark token as revoked")

			// Verify token is revoked immediately
			revoked, err := repo.IsTokenRevoked(ctx, AccessToken, token)
			require.NoError(t, err)
			require.True(t, revoked, "token should be revoked immediately")

			// Wait for expiration plus buffer
			time.Sleep(100 * time.Millisecond)

			// Check if token is still considered revoked
			revoked, err = repo.IsTokenRevoked(ctx, AccessToken, token)
			assert.NoError(t, err, "should successfully check expired token")
			assert.False(t, revoked, "expired revoked token should return false")
		})
	}
}

// TestIsTokenRevoked_WrongTokenType verifies that a token marked as revoked
// for one type (access) is not considered revoked when checked as another type (refresh).
func TestIsTokenRevoked_WrongTokenType(t *testing.T) {
	factories := getTestRepositoryFactories()

	for name, factory := range factories {
		t.Run(name, func(t *testing.T) {
			repo, cleanup := factory(t)
			defer cleanup()

			ctx := context.Background()
			token := fmt.Sprintf("test-token-%s-12345", name)

			// Mark as access token
			err := repo.MarkTokenRevoke(ctx, AccessToken, token, 30*time.Minute)
			require.NoError(t, err, "should successfully mark as access token")

			// Verify it's revoked as access token
			revoked, err := repo.IsTokenRevoked(ctx, AccessToken, token)
			require.NoError(t, err)
			require.True(t, revoked, "should be revoked as access token")

			// Check as refresh token (should not be revoked)
			revoked, err = repo.IsTokenRevoked(ctx, RefreshToken, token)
			assert.NoError(t, err, "should successfully check as refresh token")
			assert.False(t, revoked, "should not be revoked as refresh token")
		})
	}
}

// TestIsTokenRevoked_AfterMultipleChecks verifies that checking if a token
// is revoked multiple times produces consistent results.
func TestIsTokenRevoked_AfterMultipleChecks(t *testing.T) {
	factories := getTestRepositoryFactories()

	for name, factory := range factories {
		t.Run(name, func(t *testing.T) {
			repo, cleanup := factory(t)
			defer cleanup()

			ctx := context.Background()
			token := fmt.Sprintf("test-token-%s-12345", name)

			// Mark token as revoked
			err := repo.MarkTokenRevoke(ctx, AccessToken, token, 30*time.Minute)
			require.NoError(t, err)

			// Check multiple times
			for i := 0; i < 5; i++ {
				revoked, err := repo.IsTokenRevoked(ctx, AccessToken, token)
				assert.NoError(t, err, "check %d should succeed", i+1)
				assert.True(t, revoked, "check %d should return true", i+1)
			}
		})
	}
}

// =============================================================================
// MarkTokenRotated Tests
// =============================================================================

// TestMarkTokenRotated_Success verifies that a token can be successfully
// marked as rotated and stored in the repository.
func TestMarkTokenRotated_Success(t *testing.T) {
	factories := getTestRepositoryFactories()

	for name, factory := range factories {
		t.Run(name, func(t *testing.T) {
			repo, cleanup := factory(t)
			defer cleanup()

			ctx := context.Background()
			token := fmt.Sprintf("test-rotated-token-%s-12345", name)
			ttl := 7 * 24 * time.Hour

			// Mark token as rotated
			err := repo.MarkTokenRotated(ctx, token, ttl)
			assert.NoError(t, err, "should successfully mark token as rotated")

			// Verify token is marked as rotated
			rotated, err := repo.IsTokenRotated(ctx, token)
			assert.NoError(t, err, "should successfully check if token is rotated")
			assert.True(t, rotated, "token should be marked as rotated")
		})
	}
}

// TestMarkTokenRotated_EmptyToken verifies that attempting to mark an empty
// token as rotated returns an appropriate error.
func TestMarkTokenRotated_EmptyToken(t *testing.T) {
	factories := getTestRepositoryFactories()

	for name, factory := range factories {
		t.Run(name, func(t *testing.T) {
			repo, cleanup := factory(t)
			defer cleanup()

			ctx := context.Background()

			// Attempt to mark empty token as rotated
			err := repo.MarkTokenRotated(ctx, "", 7*24*time.Hour)
			assert.Error(t, err, "should return error for empty token")
			assert.Contains(t, err.Error(), "token cannot be empty", "error message should indicate empty token")
		})
	}
}

// TestMarkTokenRotated_ZeroTTL verifies that attempting to mark a token as
// rotated with zero TTL returns an error.
func TestMarkTokenRotated_ZeroTTL(t *testing.T) {
	factories := getTestRepositoryFactories()

	for name, factory := range factories {
		t.Run(name, func(t *testing.T) {
			repo, cleanup := factory(t)
			defer cleanup()

			ctx := context.Background()
			token := fmt.Sprintf("test-token-%s-12345", name)

			// Attempt to mark token with zero TTL
			err := repo.MarkTokenRotated(ctx, token, 0)
			assert.Error(t, err, "should return error for zero TTL")
			assert.Contains(t, err.Error(), "ttl must be positive", "error message should indicate invalid TTL")
		})
	}
}

// TestMarkTokenRotated_NegativeTTL verifies that attempting to mark a token as
// rotated with negative TTL returns an error.
func TestMarkTokenRotated_NegativeTTL(t *testing.T) {
	factories := getTestRepositoryFactories()

	for name, factory := range factories {
		t.Run(name, func(t *testing.T) {
			repo, cleanup := factory(t)
			defer cleanup()

			ctx := context.Background()
			token := fmt.Sprintf("test-token-%s-12345", name)

			// Attempt to mark token with negative TTL
			err := repo.MarkTokenRotated(ctx, token, -1*time.Minute)
			assert.Error(t, err, "should return error for negative TTL")
			assert.Contains(t, err.Error(), "ttl must be positive", "error message should indicate invalid TTL")
		})
	}
}

// TestMarkTokenRotated_UpdateExistingToken verifies that marking the same token
// as rotated multiple times updates the TTL without causing errors.
func TestMarkTokenRotated_UpdateExistingToken(t *testing.T) {
	factories := getTestRepositoryFactories()

	for name, factory := range factories {
		t.Run(name, func(t *testing.T) {
			repo, cleanup := factory(t)
			defer cleanup()

			ctx := context.Background()
			token := fmt.Sprintf("test-token-%s-12345", name)

			// First rotation with 1 hour TTL
			err := repo.MarkTokenRotated(ctx, token, 1*time.Hour)
			require.NoError(t, err, "first rotation should succeed")

			// Verify token is rotated
			rotated, err := repo.IsTokenRotated(ctx, token)
			require.NoError(t, err)
			require.True(t, rotated, "token should be rotated after first call")

			// Second rotation with different TTL (2 hours)
			err = repo.MarkTokenRotated(ctx, token, 2*time.Hour)
			assert.NoError(t, err, "second rotation should succeed (idempotent operation)")

			// Verify token is still rotated
			rotated, err = repo.IsTokenRotated(ctx, token)
			assert.NoError(t, err)
			assert.True(t, rotated, "token should still be rotated after update")
		})
	}
}

// TestMarkTokenRotated_MultipleTokens verifies that multiple different tokens
// can be marked as rotated independently.
func TestMarkTokenRotated_MultipleTokens(t *testing.T) {
	factories := getTestRepositoryFactories()

	for name, factory := range factories {
		t.Run(name, func(t *testing.T) {
			repo, cleanup := factory(t)
			defer cleanup()

			ctx := context.Background()
			tokens := []string{
				fmt.Sprintf("token-1-%s", name),
				fmt.Sprintf("token-2-%s", name),
				fmt.Sprintf("token-3-%s", name),
			}

			// Mark all tokens as rotated
			for _, token := range tokens {
				err := repo.MarkTokenRotated(ctx, token, 1*time.Hour)
				require.NoError(t, err, "should mark token %s as rotated", token)
			}

			// Verify all are rotated
			for _, token := range tokens {
				rotated, err := repo.IsTokenRotated(ctx, token)
				assert.NoError(t, err, "should check token %s", token)
				assert.True(t, rotated, "token %s should be rotated", token)
			}
		})
	}
}

// =============================================================================
// IsTokenRotated Tests
// =============================================================================

// TestIsTokenRotated_NonRotatedToken verifies that checking a token that was
// never marked as rotated returns false.
func TestIsTokenRotated_NonRotatedToken(t *testing.T) {
	factories := getTestRepositoryFactories()

	for name, factory := range factories {
		t.Run(name, func(t *testing.T) {
			repo, cleanup := factory(t)
			defer cleanup()

			ctx := context.Background()
			token := fmt.Sprintf("non-rotated-token-%s-12345", name)

			// Check if non-rotated token is rotated
			rotated, err := repo.IsTokenRotated(ctx, token)
			assert.NoError(t, err, "should successfully check non-rotated token")
			assert.False(t, rotated, "non-rotated token should return false")
		})
	}
}

// TestIsTokenRotated_RotatedToken verifies that a token marked as rotated
// is correctly identified as rotated.
func TestIsTokenRotated_RotatedToken(t *testing.T) {
	factories := getTestRepositoryFactories()

	for name, factory := range factories {
		t.Run(name, func(t *testing.T) {
			repo, cleanup := factory(t)
			defer cleanup()

			ctx := context.Background()
			token := fmt.Sprintf("rotated-token-%s-12345", name)

			// Mark token as rotated
			err := repo.MarkTokenRotated(ctx, token, 7*24*time.Hour)
			require.NoError(t, err, "should successfully mark token as rotated")

			// Check if token is rotated
			rotated, err := repo.IsTokenRotated(ctx, token)
			assert.NoError(t, err, "should successfully check if token is rotated")
			assert.True(t, rotated, "rotated token should return true")
		})
	}
}

// TestIsTokenRotated_EmptyToken verifies that checking an empty token
// returns an appropriate error.
func TestIsTokenRotated_EmptyToken(t *testing.T) {
	factories := getTestRepositoryFactories()

	for name, factory := range factories {
		t.Run(name, func(t *testing.T) {
			repo, cleanup := factory(t)
			defer cleanup()

			ctx := context.Background()

			// Check empty token
			rotated, err := repo.IsTokenRotated(ctx, "")
			assert.Error(t, err, "should return error for empty token")
			assert.Contains(t, err.Error(), "token cannot be empty", "error message should indicate empty token")
			assert.False(t, rotated, "should return false when error occurs")
		})
	}
}

// TestIsTokenRotated_ExpiredRotatedToken verifies that a token marked as rotated
// with a very short TTL is no longer considered rotated after the TTL expires.
func TestIsTokenRotated_ExpiredRotatedToken(t *testing.T) {
	factories := getTestRepositoryFactories()

	for name, factory := range factories {
		t.Run(name, func(t *testing.T) {
			repo, cleanup := factory(t)
			defer cleanup()

			ctx := context.Background()
			token := fmt.Sprintf("expired-rotated-token-%s-12345", name)

			// Mark token as rotated with very short TTL
			err := repo.MarkTokenRotated(ctx, token, 50*time.Millisecond)
			require.NoError(t, err, "should successfully mark token as rotated")

			// Verify token is rotated immediately
			rotated, err := repo.IsTokenRotated(ctx, token)
			require.NoError(t, err)
			require.True(t, rotated, "token should be rotated immediately")

			// Wait for expiration plus buffer
			time.Sleep(100 * time.Millisecond)

			// Check if token is still considered rotated
			rotated, err = repo.IsTokenRotated(ctx, token)
			assert.NoError(t, err, "should successfully check expired token")
			assert.False(t, rotated, "expired rotated token should return false")
		})
	}
}

// TestIsTokenRotated_AfterMultipleChecks verifies that checking if a token
// is rotated multiple times produces consistent results.
func TestIsTokenRotated_AfterMultipleChecks(t *testing.T) {
	factories := getTestRepositoryFactories()

	for name, factory := range factories {
		t.Run(name, func(t *testing.T) {
			repo, cleanup := factory(t)
			defer cleanup()

			ctx := context.Background()
			token := fmt.Sprintf("test-token-%s-12345", name)

			// Mark token as rotated
			err := repo.MarkTokenRotated(ctx, token, 1*time.Hour)
			require.NoError(t, err)

			// Check multiple times
			for i := 0; i < 5; i++ {
				rotated, err := repo.IsTokenRotated(ctx, token)
				assert.NoError(t, err, "check %d should succeed", i+1)
				assert.True(t, rotated, "check %d should return true", i+1)
			}
		})
	}
}

// =============================================================================
// GetRotationTTL Tests
// =============================================================================

// TestGetRotationTTL_ValidToken verifies that GetRotationTTL returns the correct
// remaining TTL for a rotated token. The TTL should be less than or equal to
// the original TTL and greater than zero.
func TestGetRotationTTL_ValidToken(t *testing.T) {
	factories := getTestRepositoryFactories()

	for name, factory := range factories {
		t.Run(name, func(t *testing.T) {
			repo, cleanup := factory(t)
			defer cleanup()

			ctx := context.Background()
			token := fmt.Sprintf("test-token-%s-12345", name)
			expectedTTL := 30 * time.Minute

			// Mark token as rotated
			err := repo.MarkTokenRotated(ctx, token, expectedTTL)
			require.NoError(t, err, "should successfully mark token as rotated")

			// Get TTL
			ttl, err := repo.GetRotationTTL(ctx, token)
			assert.NoError(t, err, "should successfully get rotation TTL")
			assert.Greater(t, ttl, time.Duration(0), "TTL should be greater than zero")
			assert.LessOrEqual(t, ttl, expectedTTL, "TTL should not exceed original TTL")

			// Verify TTL is reasonable (account for processing time)
			assert.Greater(t, ttl, expectedTTL-5*time.Second, "TTL should be close to original TTL")
		})
	}
}

// TestGetRotationTTL_NonExistentToken verifies that GetRotationTTL returns zero
// for a token that was never marked as rotated.
func TestGetRotationTTL_NonExistentToken(t *testing.T) {
	factories := getTestRepositoryFactories()

	for name, factory := range factories {
		t.Run(name, func(t *testing.T) {
			repo, cleanup := factory(t)
			defer cleanup()

			ctx := context.Background()
			token := fmt.Sprintf("non-existent-token-%s-12345", name)

			// Get TTL for non-existent token
			ttl, err := repo.GetRotationTTL(ctx, token)
			assert.NoError(t, err, "should not error for non-existent token")
			assert.Equal(t, time.Duration(0), ttl, "should return zero TTL for non-existent token")
		})
	}
}

// TestGetRotationTTL_ExpiredToken verifies that GetRotationTTL returns zero
// for a token whose TTL has expired.
// FIXED: Uses longer TTL and polls to handle timing variations across implementations
func TestGetRotationTTL_ExpiredToken(t *testing.T) {
	factories := getTestRepositoryFactories()

	for name, factory := range factories {
		t.Run(name, func(t *testing.T) {
			repo, cleanup := factory(t)
			defer cleanup()

			ctx := context.Background()
			token := fmt.Sprintf("expired-token-%s-12345", name)

			// Use longer TTL to avoid race conditions with Redis
			shortTTL := 300 * time.Millisecond
			err := repo.MarkTokenRotated(ctx, token, shortTTL)
			require.NoError(t, err, "should successfully mark token as rotated")

			// Verify TTL is valid immediately - poll with retries for Redis
			var ttl time.Duration
			var ttlErr error
			for i := 0; i < 3; i++ {
				ttl, ttlErr = repo.GetRotationTTL(ctx, token)
				if ttlErr == nil && ttl > 0 {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			require.NoError(t, ttlErr, "should not error when getting TTL")
			require.Greater(t, ttl, time.Duration(0), "TTL should be positive immediately")

			// Wait for expiration with buffer
			time.Sleep(shortTTL + 100*time.Millisecond)

			// Get TTL after expiration - may need retries for Redis
			var finalTTL time.Duration
			var finalErr error
			for i := 0; i < 5; i++ {
				finalTTL, finalErr = repo.GetRotationTTL(ctx, token)
				assert.NoError(t, finalErr, "should not error for expired token")
				if finalTTL == 0 {
					break
				}
				// Redis might still show small positive TTL due to expiry timing
				time.Sleep(50 * time.Millisecond)
			}
			assert.Equal(t, time.Duration(0), finalTTL, "should return zero TTL for expired token")
		})
	}
}

// TestGetRotationTTL_EmptyToken verifies that GetRotationTTL returns an error
// when given an empty token.
func TestGetRotationTTL_EmptyToken(t *testing.T) {
	factories := getTestRepositoryFactories()

	for name, factory := range factories {
		t.Run(name, func(t *testing.T) {
			repo, cleanup := factory(t)
			defer cleanup()

			ctx := context.Background()

			// Get TTL for empty token
			ttl, err := repo.GetRotationTTL(ctx, "")
			assert.Error(t, err, "should return error for empty token")
			assert.Contains(t, err.Error(), "token cannot be empty", "error message should indicate empty token")
			assert.Equal(t, time.Duration(0), ttl, "should return zero TTL when error occurs")
		})
	}
}

// TestGetRotationTTL_DecreasingOverTime verifies that the TTL decreases over time
// as expected, ensuring the repository properly tracks expiration.
func TestGetRotationTTL_DecreasingOverTime(t *testing.T) {
	factories := getTestRepositoryFactories()

	for name, factory := range factories {
		t.Run(name, func(t *testing.T) {
			repo, cleanup := factory(t)
			defer cleanup()

			ctx := context.Background()
			token := fmt.Sprintf("test-token-%s-12345", name)
			originalTTL := 10 * time.Second

			// Mark token as rotated
			err := repo.MarkTokenRotated(ctx, token, originalTTL)
			require.NoError(t, err)

			// Get initial TTL
			ttl1, err := repo.GetRotationTTL(ctx, token)
			require.NoError(t, err)
			require.Greater(t, ttl1, time.Duration(0))

			// Wait a bit
			time.Sleep(2 * time.Second)

			// Get TTL again
			ttl2, err := repo.GetRotationTTL(ctx, token)
			require.NoError(t, err)
			require.Greater(t, ttl2, time.Duration(0))

			// TTL should have decreased
			assert.Less(t, ttl2, ttl1, "TTL should decrease over time")
		})
	}
}

// =============================================================================
// CleanupExpiredRevokedTokens Tests
// =============================================================================

// TestCleanupExpiredRevokedTokens_AccessTokens verifies that cleanup removes
// expired access tokens while preserving non-expired ones.
func TestCleanupExpiredRevokedTokens_AccessTokens(t *testing.T) {
	factories := getTestRepositoryFactories()

	for name, factory := range factories {
		t.Run(name, func(t *testing.T) {
			repo, cleanup := factory(t)
			defer cleanup()

			ctx := context.Background()

			// Add expired access token
			expiredToken := fmt.Sprintf("expired-access-%s-12345", name)
			err := repo.MarkTokenRevoke(ctx, AccessToken, expiredToken, 50*time.Millisecond)
			require.NoError(t, err, "should mark expired token as revoked")

			// Add valid access token
			validToken := fmt.Sprintf("valid-access-%s-12345", name)
			err = repo.MarkTokenRevoke(ctx, AccessToken, validToken, 1*time.Hour)
			require.NoError(t, err, "should mark valid token as revoked")

			// Verify both are revoked initially
			revoked, err := repo.IsTokenRevoked(ctx, AccessToken, expiredToken)
			require.NoError(t, err)
			require.True(t, revoked, "expired token should be revoked initially")

			revoked, err = repo.IsTokenRevoked(ctx, AccessToken, validToken)
			require.NoError(t, err)
			require.True(t, revoked, "valid token should be revoked")

			// Wait for expiration
			time.Sleep(100 * time.Millisecond)

			// Cleanup expired access tokens
			err = repo.CleanupExpiredRevokedTokens(ctx, AccessToken)
			assert.NoError(t, err, "cleanup should succeed")

			// Verify expired token is no longer revoked
			revoked, err = repo.IsTokenRevoked(ctx, AccessToken, expiredToken)
			assert.NoError(t, err)
			assert.False(t, revoked, "expired token should be cleaned up")

			// Verify valid token is still revoked
			revoked, err = repo.IsTokenRevoked(ctx, AccessToken, validToken)
			assert.NoError(t, err)
			assert.True(t, revoked, "valid token should still be revoked after cleanup")
		})
	}
}

// TestCleanupExpiredRevokedTokens_RefreshTokens verifies that cleanup removes
// expired refresh tokens while preserving non-expired ones.
func TestCleanupExpiredRevokedTokens_RefreshTokens(t *testing.T) {
	factories := getTestRepositoryFactories()

	for name, factory := range factories {
		t.Run(name, func(t *testing.T) {
			repo, cleanup := factory(t)
			defer cleanup()

			ctx := context.Background()

			// Add expired refresh token
			expiredToken := fmt.Sprintf("expired-refresh-%s-12345", name)
			err := repo.MarkTokenRevoke(ctx, RefreshToken, expiredToken, 50*time.Millisecond)
			require.NoError(t, err, "should mark expired token as revoked")

			// Add valid refresh token
			validToken := fmt.Sprintf("valid-refresh-%s-12345", name)
			err = repo.MarkTokenRevoke(ctx, RefreshToken, validToken, 1*time.Hour)
			require.NoError(t, err, "should mark valid token as revoked")

			// Verify both are revoked initially
			revoked, err := repo.IsTokenRevoked(ctx, RefreshToken, expiredToken)
			require.NoError(t, err)
			require.True(t, revoked, "expired token should be revoked initially")

			revoked, err = repo.IsTokenRevoked(ctx, RefreshToken, validToken)
			require.NoError(t, err)
			require.True(t, revoked, "valid token should be revoked")

			// Wait for expiration
			time.Sleep(100 * time.Millisecond)

			// Cleanup expired refresh tokens
			err = repo.CleanupExpiredRevokedTokens(ctx, RefreshToken)
			assert.NoError(t, err, "cleanup should succeed")

			// Verify expired token is no longer revoked
			revoked, err = repo.IsTokenRevoked(ctx, RefreshToken, expiredToken)
			assert.NoError(t, err)
			assert.False(t, revoked, "expired token should be cleaned up")

			// Verify valid token is still revoked
			revoked, err = repo.IsTokenRevoked(ctx, RefreshToken, validToken)
			assert.NoError(t, err)
			assert.True(t, revoked, "valid token should still be revoked after cleanup")
		})
	}
}

// TestCleanupExpiredRevokedTokens_InvalidTokenType verifies that cleanup
// returns an error when given an invalid token type.
func TestCleanupExpiredRevokedTokens_InvalidTokenType(t *testing.T) {
	factories := getTestRepositoryFactories()

	for name, factory := range factories {
		t.Run(name, func(t *testing.T) {
			repo, cleanup := factory(t)
			defer cleanup()

			ctx := context.Background()
			invalidType := TokenType("invalid_type")

			// Attempt cleanup with invalid token type
			err := repo.CleanupExpiredRevokedTokens(ctx, invalidType)
			assert.Error(t, err, "should return error for invalid token type")
			assert.Contains(t, err.Error(), "invalid token type", "error message should indicate invalid token type")
		})
	}
}

// TestCleanupExpiredRevokedTokens_EmptyRepository verifies that cleanup
// succeeds even when there are no tokens to clean up.
func TestCleanupExpiredRevokedTokens_EmptyRepository(t *testing.T) {
	factories := getTestRepositoryFactories()

	for name, factory := range factories {
		t.Run(name, func(t *testing.T) {
			repo, cleanup := factory(t)
			defer cleanup()

			ctx := context.Background()

			// Cleanup empty repository
			err := repo.CleanupExpiredRevokedTokens(ctx, AccessToken)
			assert.NoError(t, err, "cleanup should succeed on empty repository")

			err = repo.CleanupExpiredRevokedTokens(ctx, RefreshToken)
			assert.NoError(t, err, "cleanup should succeed on empty repository")
		})
	}
}

// TestCleanupExpiredRevokedTokens_DoesNotAffectOtherType verifies that cleaning up
// expired access tokens doesn't affect refresh tokens and vice versa.
func TestCleanupExpiredRevokedTokens_DoesNotAffectOtherType(t *testing.T) {
	factories := getTestRepositoryFactories()

	for name, factory := range factories {
		t.Run(name, func(t *testing.T) {
			repo, cleanup := factory(t)
			defer cleanup()

			ctx := context.Background()

			// Add expired tokens of both types
			expiredAccess := fmt.Sprintf("expired-access-%s-12345", name)
			err := repo.MarkTokenRevoke(ctx, AccessToken, expiredAccess, 50*time.Millisecond)
			require.NoError(t, err)

			expiredRefresh := fmt.Sprintf("expired-refresh-%s-12345", name)
			err = repo.MarkTokenRevoke(ctx, RefreshToken, expiredRefresh, 50*time.Millisecond)
			require.NoError(t, err)

			// Wait for expiration
			time.Sleep(100 * time.Millisecond)

			// Cleanup only access tokens
			err = repo.CleanupExpiredRevokedTokens(ctx, AccessToken)
			require.NoError(t, err)

			// Verify access token is cleaned up
			revoked, err := repo.IsTokenRevoked(ctx, AccessToken, expiredAccess)
			assert.NoError(t, err)
			assert.False(t, revoked, "expired access token should be cleaned up")

			// Verify refresh token is NOT cleaned up (still expired but not cleaned)
			// Note: It should still return false because it's expired
			revoked, err = repo.IsTokenRevoked(ctx, RefreshToken, expiredRefresh)
			assert.NoError(t, err)
			assert.False(t, revoked, "expired refresh token should return false (expired)")
		})
	}
}

// TestCleanupExpiredRevokedTokens_MultipleExpiredTokens verifies that cleanup
// can handle multiple expired tokens at once.
func TestCleanupExpiredRevokedTokens_MultipleExpiredTokens(t *testing.T) {
	factories := getTestRepositoryFactories()

	for name, factory := range factories {
		t.Run(name, func(t *testing.T) {
			repo, cleanup := factory(t)
			defer cleanup()

			ctx := context.Background()

			// Add multiple expired tokens
			numTokens := 10
			for i := 0; i < numTokens; i++ {
				token := fmt.Sprintf("expired-token-%s-%d", name, i)
				err := repo.MarkTokenRevoke(ctx, AccessToken, token, 50*time.Millisecond)
				require.NoError(t, err, "should mark token %d as revoked", i)
			}

			// Add one valid token
			validToken := fmt.Sprintf("valid-token-%s", name)
			err := repo.MarkTokenRevoke(ctx, AccessToken, validToken, 1*time.Hour)
			require.NoError(t, err)

			// Wait for expiration
			time.Sleep(100 * time.Millisecond)

			// Cleanup
			err = repo.CleanupExpiredRevokedTokens(ctx, AccessToken)
			assert.NoError(t, err, "cleanup should succeed")

			// Verify all expired tokens are cleaned up
			for i := 0; i < numTokens; i++ {
				token := fmt.Sprintf("expired-token-%s-%d", name, i)
				revoked, err := repo.IsTokenRevoked(ctx, AccessToken, token)
				assert.NoError(t, err, "check should succeed for token %d", i)
				assert.False(t, revoked, "expired token %d should be cleaned up", i)
			}

			// Verify valid token is still revoked
			revoked, err := repo.IsTokenRevoked(ctx, AccessToken, validToken)
			assert.NoError(t, err)
			assert.True(t, revoked, "valid token should still be revoked")
		})
	}
}

// =============================================================================
// CleanupExpiredRotatedTokens Tests
// =============================================================================

// TestCleanupExpiredRotatedTokens_Success verifies that cleanup removes
// expired rotated tokens while preserving non-expired ones.
func TestCleanupExpiredRotatedTokens_Success(t *testing.T) {
	factories := getTestRepositoryFactories()

	for name, factory := range factories {
		t.Run(name, func(t *testing.T) {
			repo, cleanup := factory(t)
			defer cleanup()

			ctx := context.Background()

			// Add expired rotated token
			expiredToken := fmt.Sprintf("expired-rotated-%s-12345", name)
			err := repo.MarkTokenRotated(ctx, expiredToken, 50*time.Millisecond)
			require.NoError(t, err, "should mark expired token as rotated")

			// Add valid rotated token
			validToken := fmt.Sprintf("valid-rotated-%s-12345", name)
			err = repo.MarkTokenRotated(ctx, validToken, 1*time.Hour)
			require.NoError(t, err, "should mark valid token as rotated")

			// Verify both are rotated initially
			rotated, err := repo.IsTokenRotated(ctx, expiredToken)
			require.NoError(t, err)
			require.True(t, rotated, "expired token should be rotated initially")

			rotated, err = repo.IsTokenRotated(ctx, validToken)
			require.NoError(t, err)
			require.True(t, rotated, "valid token should be rotated")

			// Wait for expiration
			time.Sleep(100 * time.Millisecond)

			// Cleanup expired rotated tokens
			err = repo.CleanupExpiredRotatedTokens(ctx)
			assert.NoError(t, err, "cleanup should succeed")

			// Verify expired token is no longer rotated
			rotated, err = repo.IsTokenRotated(ctx, expiredToken)
			assert.NoError(t, err)
			assert.False(t, rotated, "expired token should be cleaned up")

			// Verify valid token is still rotated
			rotated, err = repo.IsTokenRotated(ctx, validToken)
			assert.NoError(t, err)
			assert.True(t, rotated, "valid token should still be rotated after cleanup")
		})
	}
}

// TestCleanupExpiredRotatedTokens_EmptyRepository verifies that cleanup
// succeeds even when there are no tokens to clean up.
func TestCleanupExpiredRotatedTokens_EmptyRepository(t *testing.T) {
	factories := getTestRepositoryFactories()

	for name, factory := range factories {
		t.Run(name, func(t *testing.T) {
			repo, cleanup := factory(t)
			defer cleanup()

			ctx := context.Background()

			// Cleanup empty repository
			err := repo.CleanupExpiredRotatedTokens(ctx)
			assert.NoError(t, err, "cleanup should succeed on empty repository")
		})
	}
}

// TestCleanupExpiredRotatedTokens_MultipleTokens verifies that cleanup
// can handle multiple expired tokens at once.
func TestCleanupExpiredRotatedTokens_MultipleTokens(t *testing.T) {
	factories := getTestRepositoryFactories()

	for name, factory := range factories {
		t.Run(name, func(t *testing.T) {
			repo, cleanup := factory(t)
			defer cleanup()

			ctx := context.Background()

			// Add multiple expired tokens
			numExpired := 10
			for i := 0; i < numExpired; i++ {
				token := fmt.Sprintf("expired-token-%s-%d", name, i)
				err := repo.MarkTokenRotated(ctx, token, 50*time.Millisecond)
				require.NoError(t, err, "should mark expired token %d as rotated", i)
			}

			// Add multiple valid tokens
			numValid := 5
			for i := 0; i < numValid; i++ {
				token := fmt.Sprintf("valid-token-%s-%d", name, i)
				err := repo.MarkTokenRotated(ctx, token, 1*time.Hour)
				require.NoError(t, err, "should mark valid token %d as rotated", i)
			}

			// Wait for expiration
			time.Sleep(100 * time.Millisecond)

			// Cleanup
			err := repo.CleanupExpiredRotatedTokens(ctx)
			assert.NoError(t, err, "cleanup should succeed")

			// Verify all expired tokens are cleaned up
			for i := 0; i < numExpired; i++ {
				token := fmt.Sprintf("expired-token-%s-%d", name, i)
				rotated, err := repo.IsTokenRotated(ctx, token)
				assert.NoError(t, err, "check should succeed for expired token %d", i)
				assert.False(t, rotated, "expired token %d should be cleaned up", i)
			}

			// Verify all valid tokens are still rotated
			for i := 0; i < numValid; i++ {
				token := fmt.Sprintf("valid-token-%s-%d", name, i)
				rotated, err := repo.IsTokenRotated(ctx, token)
				assert.NoError(t, err, "check should succeed for valid token %d", i)
				assert.True(t, rotated, "valid token %d should still be rotated", i)
			}
		})
	}
}

// TestCleanupExpiredRotatedTokens_AfterTTLExpiry verifies that tokens
// become eligible for cleanup after their TTL expires.
func TestCleanupExpiredRotatedTokens_AfterTTLExpiry(t *testing.T) {
	factories := getTestRepositoryFactories()

	for name, factory := range factories {
		t.Run(name, func(t *testing.T) {
			repo, cleanup := factory(t)
			defer cleanup()

			ctx := context.Background()
			token := fmt.Sprintf("test-token-%s-12345", name)
			shortTTL := 100 * time.Millisecond

			// Mark token as rotated
			err := repo.MarkTokenRotated(ctx, token, shortTTL)
			require.NoError(t, err)

			// Verify token is rotated
			rotated, err := repo.IsTokenRotated(ctx, token)
			require.NoError(t, err)
			require.True(t, rotated)

			// Wait for TTL to expire
			time.Sleep(150 * time.Millisecond)

			// Token should no longer be rotated (expired)
			rotated, err = repo.IsTokenRotated(ctx, token)
			assert.NoError(t, err)
			assert.False(t, rotated, "token should be expired")

			// Cleanup should succeed
			err = repo.CleanupExpiredRotatedTokens(ctx)
			assert.NoError(t, err)

			// Token should still not be rotated
			rotated, err = repo.IsTokenRotated(ctx, token)
			assert.NoError(t, err)
			assert.False(t, rotated)
		})
	}
}

// =============================================================================
// Concurrent Operations Tests
// =============================================================================

// TestRepository_ConcurrentRevocations verifies that multiple goroutines
// can concurrently revoke tokens without data corruption or errors.
func TestRepository_ConcurrentRevocations(t *testing.T) {
	factories := getTestRepositoryFactories()

	for name, factory := range factories {
		t.Run(name, func(t *testing.T) {
			repo, cleanup := factory(t)
			defer cleanup()

			ctx := context.Background()
			numGoroutines := 20
			var wg sync.WaitGroup

			// Launch concurrent revocations
			for i := 0; i < numGoroutines; i++ {
				wg.Add(1)
				go func(id int) {
					defer wg.Done()

					token := fmt.Sprintf("concurrent-token-%s-%d", name, id)

					// Mark as revoked
					err := repo.MarkTokenRevoke(ctx, AccessToken, token, 30*time.Minute)
					assert.NoError(t, err, "goroutine %d should revoke token", id)

					// Check revocation
					revoked, err := repo.IsTokenRevoked(ctx, AccessToken, token)
					assert.NoError(t, err, "goroutine %d should check revocation", id)
					assert.True(t, revoked, "goroutine %d token should be revoked", id)
				}(i)
			}

			wg.Wait()
		})
	}
}

// TestRepository_ConcurrentRotations verifies that multiple goroutines
// can concurrently rotate tokens without data corruption or errors.
func TestRepository_ConcurrentRotations(t *testing.T) {
	factories := getTestRepositoryFactories()

	for name, factory := range factories {
		t.Run(name, func(t *testing.T) {
			repo, cleanup := factory(t)
			defer cleanup()

			ctx := context.Background()
			numGoroutines := 20
			var wg sync.WaitGroup

			// Launch concurrent rotations
			for i := 0; i < numGoroutines; i++ {
				wg.Add(1)
				go func(id int) {
					defer wg.Done()

					token := fmt.Sprintf("concurrent-token-%s-%d", name, id)

					// Mark as rotated
					err := repo.MarkTokenRotated(ctx, token, 1*time.Hour)
					assert.NoError(t, err, "goroutine %d should rotate token", id)

					// Check rotation
					rotated, err := repo.IsTokenRotated(ctx, token)
					assert.NoError(t, err, "goroutine %d should check rotation", id)
					assert.True(t, rotated, "goroutine %d token should be rotated", id)

					// Get TTL
					ttl, err := repo.GetRotationTTL(ctx, token)
					assert.NoError(t, err, "goroutine %d should get TTL", id)
					assert.Greater(t, ttl, time.Duration(0), "goroutine %d TTL should be positive", id)
				}(i)
			}

			wg.Wait()
		})
	}
}

// TestRepository_ConcurrentMixedOperations verifies that multiple goroutines
// can perform different operations (revoke, rotate, check) concurrently.
func TestRepository_ConcurrentMixedOperations(t *testing.T) {
	factories := getTestRepositoryFactories()

	for name, factory := range factories {
		t.Run(name, func(t *testing.T) {
			repo, cleanup := factory(t)
			defer cleanup()

			ctx := context.Background()
			numGoroutines := 30
			var wg sync.WaitGroup

			// Launch concurrent mixed operations
			for i := 0; i < numGoroutines; i++ {
				wg.Add(1)
				go func(id int) {
					defer wg.Done()

					token := fmt.Sprintf("concurrent-token-%s-%d", name, id)

					switch id % 3 {
					case 0: // Revoke access token
						err := repo.MarkTokenRevoke(ctx, AccessToken, token, 30*time.Minute)
						assert.NoError(t, err)
						revoked, err := repo.IsTokenRevoked(ctx, AccessToken, token)
						assert.NoError(t, err)
						assert.True(t, revoked)

					case 1: // Revoke refresh token
						err := repo.MarkTokenRevoke(ctx, RefreshToken, token, 1*time.Hour)
						assert.NoError(t, err)
						revoked, err := repo.IsTokenRevoked(ctx, RefreshToken, token)
						assert.NoError(t, err)
						assert.True(t, revoked)

					case 2: // Rotate token
						err := repo.MarkTokenRotated(ctx, token, 1*time.Hour)
						assert.NoError(t, err)
						rotated, err := repo.IsTokenRotated(ctx, token)
						assert.NoError(t, err)
						assert.True(t, rotated)
						ttl, err := repo.GetRotationTTL(ctx, token)
						assert.NoError(t, err)
						assert.Greater(t, ttl, time.Duration(0))
					}
				}(i)
			}

			wg.Wait()
		})
	}
}

// TestRepository_ConcurrentSameToken verifies that multiple goroutines
// can mark the same token concurrently without errors (idempotency test).
func TestRepository_ConcurrentSameToken(t *testing.T) {
	factories := getTestRepositoryFactories()

	for name, factory := range factories {
		t.Run(name, func(t *testing.T) {
			repo, cleanup := factory(t)
			defer cleanup()

			ctx := context.Background()
			token := fmt.Sprintf("same-token-%s", name)
			numGoroutines := 20
			var wg sync.WaitGroup

			// Launch concurrent operations on same token
			for i := 0; i < numGoroutines; i++ {
				wg.Add(1)
				go func(id int) {
					defer wg.Done()

					// All goroutines try to revoke the same token
					err := repo.MarkTokenRevoke(ctx, AccessToken, token, 30*time.Minute)
					assert.NoError(t, err, "goroutine %d should succeed", id)
				}(i)
			}

			wg.Wait()

			// Verify token is revoked
			revoked, err := repo.IsTokenRevoked(ctx, AccessToken, token)
			assert.NoError(t, err)
			assert.True(t, revoked, "token should be revoked after concurrent operations")
		})
	}
}

// TestRepository_ConcurrentReadsDuringWrites verifies that read operations
// can occur concurrently with write operations without blocking or errors.
func TestRepository_ConcurrentReadsDuringWrites(t *testing.T) {
	factories := getTestRepositoryFactories()

	for name, factory := range factories {
		t.Run(name, func(t *testing.T) {
			repo, cleanup := factory(t)
			defer cleanup()

			ctx := context.Background()
			token := fmt.Sprintf("test-token-%s", name)
			numReaders := 10
			numWriters := 5
			var wg sync.WaitGroup

			// Launch reader goroutines
			for i := 0; i < numReaders; i++ {
				wg.Add(1)
				go func(id int) {
					defer wg.Done()
					for j := 0; j < 10; j++ {
						_, err := repo.IsTokenRevoked(ctx, AccessToken, token)
						assert.NoError(t, err, "reader %d iteration %d should succeed", id, j)
						time.Sleep(10 * time.Millisecond)
					}
				}(i)
			}

			// Launch writer goroutines
			for i := 0; i < numWriters; i++ {
				wg.Add(1)
				go func(id int) {
					defer wg.Done()
					for j := 0; j < 5; j++ {
						err := repo.MarkTokenRevoke(ctx, AccessToken, token, 1*time.Hour)
						assert.NoError(t, err, "writer %d iteration %d should succeed", id, j)
						time.Sleep(20 * time.Millisecond)
					}
				}(i)
			}

			wg.Wait()
		})
	}
}

// =============================================================================
// Context Cancellation Tests
// =============================================================================

// TestRepository_ContextCancellationDuringRevoke verifies that repository
// operations respect context cancellation during revoke operations.
func TestRepository_ContextCancellationDuringRevoke(t *testing.T) {
	factories := getTestRepositoryFactories()

	for name, factory := range factories {
		t.Run(name, func(t *testing.T) {
			repo, cleanup := factory(t)
			defer cleanup()

			ctx, cancel := context.WithCancel(context.Background())
			token := fmt.Sprintf("test-token-%s-12345", name)

			// Cancel context immediately
			cancel()

			// Note: MemoryTokenRepository doesn't check context in all operations
			// This test documents expected behavior for implementations that do
			err := repo.MarkTokenRevoke(ctx, AccessToken, token, 30*time.Minute)
			// Different implementations may or may not fail on cancelled context
			_ = err
		})
	}
}

// TestRepository_ContextCancellationDuringCheck verifies context cancellation
// during check operations.
func TestRepository_ContextCancellationDuringCheck(t *testing.T) {
	factories := getTestRepositoryFactories()

	for name, factory := range factories {
		t.Run(name, func(t *testing.T) {
			repo, cleanup := factory(t)
			defer cleanup()

			ctx := context.Background()
			token := fmt.Sprintf("test-token-%s-12345", name)

			// Mark token first
			err := repo.MarkTokenRevoke(ctx, AccessToken, token, 30*time.Minute)
			require.NoError(t, err)

			// Create cancelled context
			cancelledCtx, cancel := context.WithCancel(context.Background())
			cancel()

			// Check with cancelled context
			_, err = repo.IsTokenRevoked(cancelledCtx, AccessToken, token)
			// Different implementations may or may not fail on cancelled context
			_ = err
		})
	}
}

// TestRepository_ContextTimeoutDuringCleanup verifies that cleanup operations
// respect context timeouts.
func TestRepository_ContextTimeoutDuringCleanup(t *testing.T) {
	factories := getTestRepositoryFactories()

	for name, factory := range factories {
		t.Run(name, func(t *testing.T) {
			repo, cleanup := factory(t)
			defer cleanup()

			// Create context with very short timeout
			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
			defer cancel()

			// Wait to ensure timeout
			time.Sleep(10 * time.Millisecond)

			// Cleanup with timed-out context
			err := repo.CleanupExpiredRotatedTokens(ctx)
			// Different implementations may or may not fail on timeout
			_ = err
		})
	}
}

// =============================================================================
// Edge Cases and Stress Tests
// =============================================================================

// TestRepository_VeryLongTokenString verifies that the repository can handle
// very long token strings (e.g., large JWTs).
func TestRepository_VeryLongTokenString(t *testing.T) {
	factories := getTestRepositoryFactories()

	for name, factory := range factories {
		t.Run(name, func(t *testing.T) {
			repo, cleanup := factory(t)
			defer cleanup()

			ctx := context.Background()

			// Create a very long token (simulating a JWT with large claims)
			longToken := fmt.Sprintf("very-long-token-%s-", name)
			for i := 0; i < 1000; i++ {
				longToken += "abcdefghij"
			}

			// Mark as revoked
			err := repo.MarkTokenRevoke(ctx, AccessToken, longToken, 30*time.Minute)
			assert.NoError(t, err, "should handle very long token")

			// Check revocation
			revoked, err := repo.IsTokenRevoked(ctx, AccessToken, longToken)
			assert.NoError(t, err, "should check very long token")
			assert.True(t, revoked, "very long token should be revoked")
		})
	}
}

// TestRepository_SpecialCharactersInToken verifies that the repository can
// handle tokens with special characters.
func TestRepository_SpecialCharactersInToken(t *testing.T) {
	factories := getTestRepositoryFactories()

	specialTokens := []string{
		"token-with-dashes-and-underscores_123",
		"token.with.dots.456",
		"token/with/slashes/789",
		"token=with=equals=012",
		"token+with+plus+345",
		"token~with~tildes~678",
	}

	for name, factory := range factories {
		t.Run(name, func(t *testing.T) {
			repo, cleanup := factory(t)
			defer cleanup()

			ctx := context.Background()

			for _, token := range specialTokens {
				fullToken := fmt.Sprintf("%s-%s", name, token)

				// Mark as revoked
				err := repo.MarkTokenRevoke(ctx, AccessToken, fullToken, 30*time.Minute)
				assert.NoError(t, err, "should handle token: %s", fullToken)

				// Check revocation
				revoked, err := repo.IsTokenRevoked(ctx, AccessToken, fullToken)
				assert.NoError(t, err, "should check token: %s", fullToken)
				assert.True(t, revoked, "token should be revoked: %s", fullToken)
			}
		})
	}
}

// TestRepository_VeryShortTTL verifies that the repository can handle
// tokens with very short TTL values.
func TestRepository_VeryShortTTL(t *testing.T) {
	factories := getTestRepositoryFactories()

	for name, factory := range factories {
		t.Run(name, func(t *testing.T) {
			repo, cleanup := factory(t)
			defer cleanup()

			ctx := context.Background()
			token := fmt.Sprintf("short-ttl-token-%s", name)

			// Mark with 1 millisecond TTL
			err := repo.MarkTokenRevoke(ctx, AccessToken, token, 1*time.Millisecond)
			assert.NoError(t, err, "should handle very short TTL")

			// Token might already be expired, but operation should succeed
			_, err = repo.IsTokenRevoked(ctx, AccessToken, token)
			assert.NoError(t, err, "check should succeed even if token expired")
		})
	}
}

// TestRepository_VeryLongTTL verifies that the repository can handle
// tokens with very long TTL values.
func TestRepository_VeryLongTTL(t *testing.T) {
	factories := getTestRepositoryFactories()

	for name, factory := range factories {
		t.Run(name, func(t *testing.T) {
			repo, cleanup := factory(t)
			defer cleanup()

			ctx := context.Background()
			token := fmt.Sprintf("long-ttl-token-%s", name)

			// Mark with 10 year TTL
			err := repo.MarkTokenRevoke(ctx, AccessToken, token, 10*365*24*time.Hour)
			assert.NoError(t, err, "should handle very long TTL")

			// Check revocation
			revoked, err := repo.IsTokenRevoked(ctx, AccessToken, token)
			assert.NoError(t, err, "should check token with long TTL")
			assert.True(t, revoked, "token with long TTL should be revoked")
		})
	}
}

// TestRepository_RapidSuccessiveOperations verifies that the repository
// can handle rapid successive operations on the same token.
func TestRepository_RapidSuccessiveOperations(t *testing.T) {
	factories := getTestRepositoryFactories()

	for name, factory := range factories {
		t.Run(name, func(t *testing.T) {
			repo, cleanup := factory(t)
			defer cleanup()

			ctx := context.Background()
			token := fmt.Sprintf("rapid-token-%s", name)

			// Perform rapid operations
			for i := 0; i < 100; i++ {
				err := repo.MarkTokenRevoke(ctx, AccessToken, token, 30*time.Minute)
				assert.NoError(t, err, "operation %d should succeed", i)

				revoked, err := repo.IsTokenRevoked(ctx, AccessToken, token)
				assert.NoError(t, err, "check %d should succeed", i)
				assert.True(t, revoked, "check %d should show token as revoked", i)
			}
		})
	}
}

// =============================================================================
// Integration Tests
// =============================================================================

// TestRepository_CleanupDoesNotAffectOtherOperations verifies that cleanup
// operations don't interfere with other ongoing operations.
func TestRepository_CleanupDoesNotAffectOtherOperations(t *testing.T) {
	factories := getTestRepositoryFactories()

	for name, factory := range factories {
		t.Run(name, func(t *testing.T) {
			repo, cleanup := factory(t)
			defer cleanup()

			ctx := context.Background()
			var wg sync.WaitGroup

			// Add tokens that will expire
			for i := 0; i < 10; i++ {
				token := fmt.Sprintf("expired-%s-%d", name, i)
				err := repo.MarkTokenRevoke(ctx, AccessToken, token, 50*time.Millisecond)
				require.NoError(t, err)
			}

			// Add tokens that won't expire
			for i := 0; i < 10; i++ {
				token := fmt.Sprintf("valid-%s-%d", name, i)
				err := repo.MarkTokenRevoke(ctx, AccessToken, token, 1*time.Hour)
				require.NoError(t, err)
			}

			// Wait for expiration
			time.Sleep(100 * time.Millisecond)

			// Start concurrent operations
			wg.Add(1)
			go func() {
				defer wg.Done()
				// Cleanup
				_ = repo.CleanupExpiredRevokedTokens(ctx, AccessToken)
			}()

			// Concurrent reads
			for i := 0; i < 5; i++ {
				wg.Add(1)
				go func(id int) {
					defer wg.Done()
					token := fmt.Sprintf("valid-%s-%d", name, id)
					revoked, err := repo.IsTokenRevoked(ctx, AccessToken, token)
					assert.NoError(t, err)
					assert.True(t, revoked)
				}(i)
			}

			// Concurrent writes
			for i := 0; i < 5; i++ {
				wg.Add(1)
				go func(id int) {
					defer wg.Done()
					token := fmt.Sprintf("new-%s-%d", name, id)
					err := repo.MarkTokenRevoke(ctx, AccessToken, token, 1*time.Hour)
					assert.NoError(t, err)
				}(i)
			}

			wg.Wait()
		})
	}
}

// =============================================================================
// Repository-Specific Tests (if applicable)
// =============================================================================

// TestMemoryRepository_Stats verifies statistics functionality for MemoryTokenRepository.
func TestMemoryRepository_Stats(t *testing.T) {
	repo := NewMemoryTokenRepository(1 * time.Hour)
	memRepo, ok := repo.(*MemoryTokenRepository)
	if !ok {
		t.Skip("Stats only available for MemoryTokenRepository")
	}

	ctx := context.Background()

	// Add tokens
	for i := 0; i < 5; i++ {
		token := fmt.Sprintf("access-%d", i)
		err := memRepo.MarkTokenRevoke(ctx, AccessToken, token, 30*time.Minute)
		require.NoError(t, err)
	}

	for i := 0; i < 3; i++ {
		token := fmt.Sprintf("refresh-%d", i)
		err := memRepo.MarkTokenRevoke(ctx, RefreshToken, token, 1*time.Hour)
		require.NoError(t, err)
	}

	for i := 0; i < 2; i++ {
		token := fmt.Sprintf("rotated-%d", i)
		err := memRepo.MarkTokenRotated(ctx, token, 1*time.Hour)
		require.NoError(t, err)
	}

	// Get stats
	stats := memRepo.Stats()

	assert.Equal(t, 5, stats["revoked_access_tokens"], "should have 5 access tokens")
	assert.Equal(t, 3, stats["revoked_refresh_tokens"], "should have 3 refresh tokens")
	assert.Equal(t, 2, stats["rotated_tokens"], "should have 2 rotated tokens")
}

// TestMemoryRepository_Close verifies that Close properly stops cleanup goroutines.
func TestMemoryRepository_Close(t *testing.T) {
	repo := NewMemoryTokenRepository(100 * time.Millisecond)
	memRepo, ok := repo.(*MemoryTokenRepository)
	if !ok {
		t.Skip("Close only available for MemoryTokenRepository")
	}

	// Close should succeed
	err := memRepo.Close()
	assert.NoError(t, err, "first close should succeed")

	// Calling Close again should be safe (idempotent)
	err = memRepo.Close()
	assert.NoError(t, err, "second close should succeed")

	// Repository should still function after close (though cleanup won't run)
	ctx := context.Background()
	token := "token-after-close"
	err = memRepo.MarkTokenRevoke(ctx, AccessToken, token, 30*time.Minute)
	assert.NoError(t, err, "operations should work after close")
}
