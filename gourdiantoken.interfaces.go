// File: gourdiantoken.interfaces.go

package gourdiantoken

import (
	"context"
	"time"
)

// TokenRepository defines the interface for persistent token storage operations.
// Implementations must handle token revocation, rotation tracking, and cleanup of expired tokens.
//
// Thread Safety:
//
//	All methods must be safe for concurrent use by multiple goroutines.
//	MarkTokenRotatedAtomic must provide atomic compare-and-swap semantics.
//
// Implementation Considerations:
//   - Use efficient storage (Redis recommended for production)
//   - Implement proper TTL handling to prevent memory leaks
//   - Consider using token hashes rather than storing full tokens
//   - Ensure MarkTokenRotatedAtomic is truly atomic to prevent race conditions
//   - Implementations may enforce a minimum TTL floor (e.g. the Redis implementation clamps
//     any TTL below 100ms up to 100ms, as a safeguard against near-zero-TTL races). This is
//     implementation-specific and not part of the interface contract — the in-memory, Postgres,
//     and MongoDB implementations currently apply no such floor.
type TokenRepository interface {
	// MarkTokenRevoke marks a token as revoked with a time-to-live.
	// The token should be stored until TTL expires, after which it can be cleaned up.
	//
	// Parameters:
	//   - ctx: Context for cancellation and timeout
	//   - tokenType: Type of token (AccessToken or RefreshToken)
	//   - token: The JWT token string to revoke
	//   - ttl: Time-to-live duration (should match token's remaining lifetime)
	//
	// Returns:
	//   - error: If revocation fails or context is cancelled
	MarkTokenRevoke(ctx context.Context, tokenType TokenType, token string, ttl time.Duration) error

	// IsTokenRevoked checks if a token has been revoked.
	//
	// Parameters:
	//   - ctx: Context for cancellation and timeout
	//   - tokenType: Type of token (AccessToken or RefreshToken)
	//   - token: The JWT token string to check
	//
	// Returns:
	//   - bool: true if token is revoked, false otherwise
	//   - error: If check fails or context is cancelled
	IsTokenRevoked(ctx context.Context, tokenType TokenType, token string) (bool, error)

	// MarkTokenRotated marks a refresh token as rotated (non-atomic).
	// Use MarkTokenRotatedAtomic instead for production systems.
	//
	// Parameters:
	//   - ctx: Context for cancellation and timeout
	//   - token: The JWT token string to mark as rotated
	//   - ttl: Time-to-live duration
	//
	// Returns:
	//   - error: If marking fails or context is cancelled
	MarkTokenRotated(ctx context.Context, token string, ttl time.Duration) error

	// MarkTokenRotatedAtomic atomically marks a token as rotated using compare-and-swap.
	// This prevents race conditions where multiple requests try to rotate the same token.
	//
	// Parameters:
	//   - ctx: Context for cancellation and timeout
	//   - token: The JWT token string to mark as rotated
	//   - ttl: Time-to-live duration
	//
	// Returns:
	//   - bool: true if successfully marked (first caller), false if already marked
	//   - error: If operation fails or context is cancelled
	MarkTokenRotatedAtomic(ctx context.Context, token string, ttl time.Duration) (bool, error)

	// IsTokenRotated checks if a refresh token has been rotated.
	//
	// Parameters:
	//   - ctx: Context for cancellation and timeout
	//   - token: The JWT token string to check
	//
	// Returns:
	//   - bool: true if token has been rotated, false otherwise
	//   - error: If check fails or context is cancelled
	IsTokenRotated(ctx context.Context, token string) (bool, error)

	// GetRotationTTL retrieves the remaining time-to-live for a rotated token entry.
	//
	// Parameters:
	//   - ctx: Context for cancellation and timeout
	//   - token: The JWT token string
	//
	// Returns:
	//   - time.Duration: Remaining TTL (0 if not found or expired)
	//   - error: If retrieval fails or context is cancelled
	GetRotationTTL(ctx context.Context, token string) (time.Duration, error)

	// CleanupExpiredRevokedTokens removes expired revoked tokens from storage.
	// Should be called periodically by background cleanup goroutines.
	//
	// Parameters:
	//   - ctx: Context for cancellation and timeout
	//   - tokenType: Type of tokens to clean up
	//
	// Returns:
	//   - error: If cleanup fails or context is cancelled
	CleanupExpiredRevokedTokens(ctx context.Context, tokenType TokenType) error

	// CleanupExpiredRotatedTokens removes expired rotation markers from storage.
	// Should be called periodically by background cleanup goroutines.
	//
	// Parameters:
	//   - ctx: Context for cancellation and timeout
	//
	// Returns:
	//   - error: If cleanup fails or context is cancelled
	CleanupExpiredRotatedTokens(ctx context.Context) error

	// RevokeTenant records a revocation epoch for tenantID: any access/refresh token
	// issued at-or-before this moment is considered dead, without enumerating individual
	// tokens (see GourdianTokenMaker.RevokeTenant's doc comment for the full rationale).
	// Calling this again for the same tenantID overwrites the previous epoch with a newer
	// one — the revocation cutoff always moves forward, never backward.
	//
	// Parameters:
	//   - ctx: Context for cancellation and timeout
	//   - tenantID: The tenant to revoke (must not be empty)
	//   - ttl: Time-to-live for the revocation record — implementations should not need
	//     it to outlive the longest-lived pre-epoch token that could still be checked
	//     against it (see max(AccessExpiryDuration, RefreshExpiryDuration) in
	//     JWTMaker.RevokeTenant)
	//
	// Returns:
	//   - error: If tenantID is empty, ttl is invalid, or the operation fails
	RevokeTenant(ctx context.Context, tenantID string, ttl time.Duration) error

	// GetTenantRevocationEpoch returns the moment tenantID was last revoked via
	// RevokeTenant, or the zero time.Time if the tenant has no active revocation record
	// (never revoked, or the record has expired).
	//
	// Parameters:
	//   - ctx: Context for cancellation and timeout
	//   - tenantID: The tenant to look up (must not be empty)
	//
	// Returns:
	//   - time.Time: The revocation epoch, or the zero value if none/expired
	//   - error: If tenantID is empty or the operation fails
	GetTenantRevocationEpoch(ctx context.Context, tenantID string) (time.Time, error)

	// CleanupExpiredTenantRevocations removes expired tenant revocation records from
	// storage. Should be called periodically by background cleanup goroutines, alongside
	// CleanupExpiredRevokedTokens/CleanupExpiredRotatedTokens.
	//
	// Parameters:
	//   - ctx: Context for cancellation and timeout
	//
	// Returns:
	//   - error: If cleanup fails or context is cancelled
	CleanupExpiredTenantRevocations(ctx context.Context) error

	// Stats returns implementation-defined counters describing the repository's current
	// storage state (e.g. counts of revoked/rotated/tenant-revocation entries). Key names
	// and value types are not part of the interface contract — callers that need a stable
	// shape across backends should not depend on specific keys being present.
	//
	// Parameters:
	//   - ctx: Context for cancellation and timeout
	//
	// Returns:
	//   - map[string]interface{}: Implementation-defined statistics
	//   - error: If retrieval fails or context is cancelled
	Stats(ctx context.Context) (map[string]interface{}, error)

	// CleanupAll runs every CleanupExpired* operation this repository supports
	// (revoked tokens, rotated tokens, tenant revocations) in one call. Intended for
	// callers that want a single cleanup entry point rather than invoking each
	// CleanupExpired* method individually — the background cleanup goroutines started by
	// JWTMaker do not use this method themselves (they call the individual CleanupExpired*
	// methods so partial failures are reported independently).
	//
	// Parameters:
	//   - ctx: Context for cancellation and timeout
	//
	// Returns:
	//   - error: If any underlying cleanup operation fails
	CleanupAll(ctx context.Context) error
}

// GourdianTokenMaker is the main interface for token operations.
// Implementations handle token creation, verification, revocation, rotation,
// stopping background cleanup goroutines, and short-lived single-use
// verification tokens, with support for multiple signing algorithms and
// security features.
//
// Thread Safety:
//
//	All methods are safe for concurrent use by multiple goroutines.
//
// Context Handling:
//
//	All methods accept a context.Context for cancellation and timeout support.
//	Operations will return an error if the context is cancelled.
type GourdianTokenMaker interface {
	// CreateAccessToken generates a new signed access token with the specified claims.
	//
	// Parameters:
	//   - ctx: Context for cancellation and timeout
	//   - userID: The user's unique identifier (must not be empty)
	//   - username: Human-readable username (max 1024 characters)
	//   - roles: Authorization roles (must contain at least one non-empty role)
	//   - sessionID: Session identifier for tracking (may be empty for sessionless tokens)
	//   - tenantID: Tenant identifier (carried in the "tid" claim). Must be non-empty when
	//     GourdianTokenConfig.MultiTenantEnabled is true, and must be empty otherwise —
	//     pass "" if you don't use multi-tenancy.
	//
	// Returns:
	//   - *AccessTokenResponse: Generated token with metadata
	//   - error: If token creation fails, parameters are invalid, or context is cancelled
	//
	// Example:
	//
	//	token, err := maker.CreateAccessToken(
	//	    ctx,
	//	    "123e4567-e89b-12d3-a456-426614174000",
	//	    "john.doe",
	//	    []string{"user", "admin"},
	//	    sessionID,
	//	    "",
	//	)
	CreateAccessToken(ctx context.Context, userID string, username string, roles []string, sessionID string, tenantID string) (*AccessTokenResponse, error)

	// CreateRefreshToken generates a new signed refresh token.
	//
	// Parameters:
	//   - ctx: Context for cancellation and timeout
	//   - userID: The user's unique identifier (must not be empty)
	//   - username: Human-readable username (max 1024 characters)
	//   - sessionID: Session identifier for tracking (may be empty for sessionless tokens)
	//   - tenantID: Tenant identifier (carried in the "tid" claim). Same contract as
	//     CreateAccessToken's tenantID parameter — pass "" if you don't use multi-tenancy.
	//
	// Returns:
	//   - *RefreshTokenResponse: Generated token with metadata
	//   - error: If token creation fails, parameters are invalid, or context is cancelled
	//
	// Example:
	//
	//	token, err := maker.CreateRefreshToken(
	//	    ctx,
	//	    userID,
	//	    "john.doe",
	//	    sessionID,
	//	    "",
	//	)
	CreateRefreshToken(ctx context.Context, userID string, username string, sessionID string, tenantID string) (*RefreshTokenResponse, error)

	// VerifyAccessToken validates an access token and returns its claims.
	// Checks signature, expiration, revocation status, and required claims.
	//
	// Validation includes:
	//   - Cryptographic signature verification
	//   - Expiration time check
	//   - Not-before time check
	//   - Maximum lifetime check
	//   - Revocation status (if enabled)
	//   - Required claims presence
	//   - Token type validation
	//
	// Parameters:
	//   - ctx: Context for cancellation and timeout
	//   - tokenString: The JWT token string to verify
	//
	// Returns:
	//   - *AccessTokenClaims: Parsed and validated token claims
	//   - error: If token is invalid, expired, revoked, or context is cancelled
	//
	// Example:
	//
	//	claims, err := maker.VerifyAccessToken(ctx, tokenString)
	//	if err != nil {
	//	    // Token is invalid, expired, or revoked
	//	    return err
	//	}
	//	// Use claims.Roles for authorization
	VerifyAccessToken(ctx context.Context, tokenString string) (*AccessTokenClaims, error)

	// VerifyRefreshToken validates a refresh token and returns its claims.
	// Checks signature, expiration, revocation status, rotation status, and required claims.
	//
	// Validation includes:
	//   - Cryptographic signature verification
	//   - Expiration time check
	//   - Not-before time check
	//   - Maximum lifetime check
	//   - Revocation status (if enabled)
	//   - Rotation status (if enabled)
	//   - Required claims presence
	//   - Token type validation
	//
	// Parameters:
	//   - ctx: Context for cancellation and timeout
	//   - tokenString: The JWT token string to verify
	//
	// Returns:
	//   - *RefreshTokenClaims: Parsed and validated token claims
	//   - error: If token is invalid, expired, revoked, rotated, or context is cancelled
	//
	// Example:
	//
	//	claims, err := maker.VerifyRefreshToken(ctx, tokenString)
	//	if err != nil {
	//	    // Token is invalid, require re-authentication
	//	    return err
	//	}
	VerifyRefreshToken(ctx context.Context, tokenString string) (*RefreshTokenClaims, error)

	// RevokeAccessToken marks an access token as revoked, preventing further use.
	// Requires RevocationEnabled to be true in the configuration.
	//
	// Parameters:
	//   - ctx: Context for cancellation and timeout
	//   - token: The JWT token string to revoke
	//
	// Returns:
	//   - error: If revocation is disabled, token is invalid, or operation fails
	//
	// Use Cases:
	//   - User logout
	//   - Token compromise
	//   - Administrative revocation
	//
	// Example:
	//
	//	err := maker.RevokeAccessToken(ctx, tokenString)
	RevokeAccessToken(ctx context.Context, token string) error

	// RevokeRefreshToken marks a refresh token as revoked, preventing further use.
	// Requires RevocationEnabled to be true in the configuration.
	//
	// Parameters:
	//   - ctx: Context for cancellation and timeout
	//   - token: The JWT token string to revoke
	//
	// Returns:
	//   - error: If revocation is disabled, token is invalid, or operation fails
	//
	// Example:
	//
	//	err := maker.RevokeRefreshToken(ctx, tokenString)
	RevokeRefreshToken(ctx context.Context, token string) error

	// RotateRefreshToken exchanges an old refresh token for a new one.
	// The old token is atomically marked as rotated and cannot be reused.
	// Requires RotationEnabled to be true in the configuration.
	//
	// Rotation Process:
	//   1. Verifies the old token is valid
	//   2. Atomically marks the old token as rotated
	//   3. Creates a new refresh token with the same user/session
	//
	// Security Benefits:
	//   - Prevents token reuse attacks
	//   - Detects token theft (multiple rotation attempts)
	//   - Limits token lifetime even if compromised
	//
	// Parameters:
	//   - ctx: Context for cancellation and timeout
	//   - oldToken: The current refresh token to rotate
	//
	// Returns:
	//   - *RefreshTokenResponse: New refresh token with updated expiration
	//   - error: If rotation is disabled, old token is invalid/rotated, or operation fails
	//
	// Example:
	//
	//	newToken, err := maker.RotateRefreshToken(ctx, oldTokenString)
	//	if err != nil {
	//	    // Token already rotated or invalid, possible attack
	//	    return err
	//	}
	//	// Return newToken to client
	RotateRefreshToken(ctx context.Context, oldToken string) (*RefreshTokenResponse, error)

	// RevokeTenant bulk-revokes every access/refresh token for tenantID by recording a
	// revocation epoch, rather than enumerating and marking individual tokens: any token
	// whose "iat" is at-or-before this moment is rejected by VerifyAccessToken/
	// VerifyRefreshToken from this point on, including ones the repository has never
	// individually seen (this also covers access tokens, which this package never persists
	// a record of unless separately revoked via RevokeAccessToken). Requires
	// GourdianTokenConfig.MultiTenantEnabled, RevocationEnabled, and a TokenRepository.
	//
	// Use Cases:
	//   - Tenant offboarding or suspension
	//   - Responding to a suspected tenant-wide credential compromise
	//
	// Parameters:
	//   - ctx: Context for cancellation and timeout
	//   - tenantID: The tenant to revoke (must not be empty)
	//
	// Returns:
	//   - error: If multi-tenancy or revocation is disabled, tenantID is empty, or the
	//     operation fails
	//
	// Example:
	//
	//	err := maker.RevokeTenant(ctx, "acme-corp")
	RevokeTenant(ctx context.Context, tenantID string) error

	// Close stops any background cleanup goroutines started by the maker.
	// Safe to call multiple times.
	//
	// Example:
	//
	//	maker, err := gourdiantoken.NewGourdianTokenMaker(ctx, config, tokenRepo)
	//	if err != nil {
	//	    log.Fatal(err)
	//	}
	//	defer maker.Close()
	Close() error

	// CreateVerificationToken generates a new signed, short-lived, single-use,
	// use-case-scoped verification token (e.g. a 2FA-pending-verification step between
	// password check and full session issuance, or password-reset / email-verify flows).
	// Requires GourdianTokenConfig.VerificationTokensEnabled.
	//
	// A ttl <= 0 falls back to GourdianTokenConfig.VerificationDefaultExpiryDuration; a ttl
	// exceeding VerificationMaxExpiryDuration (when configured) is rejected.
	//
	// Example:
	//
	//	token, err := maker.CreateVerificationToken(ctx, userID, "2fa-pending", 5*time.Minute, nil)
	CreateVerificationToken(ctx context.Context, userID string, useCase string, ttl time.Duration, metadata map[string]interface{}) (*VerificationTokenResponse, error)

	// VerifyVerificationToken validates a verification token and returns its claims.
	// Checks signature, expiration, single-use status (if enabled), and use-case whitelist.
	VerifyVerificationToken(ctx context.Context, tokenString string) (*VerificationTokenClaims, error)

	// MarkVerificationTokenUsed marks a verification token as used, so a subsequent
	// VerifyVerificationToken call on the same token fails. Single-use enforcement (a
	// verification token can only be successfully verified once) requires RevocationEnabled
	// plus a TokenRepository, since this is implemented by revoking the token via the same
	// mechanism used for access/refresh revocation; returns an error otherwise.
	MarkVerificationTokenUsed(ctx context.Context, token string) error
}
