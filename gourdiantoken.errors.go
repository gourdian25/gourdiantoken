// File: gourdiantoken.errors.go

package gourdiantoken

import (
	"errors"

	"github.com/golang-jwt/jwt/v5"
)

// Sentinel errors for use with errors.Is. Wrapped error messages preserve their
// original text ahead of the sentinel (e.g. "token has been revoked: %w"), so
// existing callers doing string matching continue to work unchanged.
var (
	// ErrTokenRevoked indicates the token was explicitly revoked before expiration.
	ErrTokenRevoked = errors.New("token has been revoked")

	// ErrTokenRotated indicates the refresh token has already been rotated and reused.
	ErrTokenRotated = errors.New("token has been rotated")

	// ErrTokenExpired is an alias for jwt.ErrTokenExpired. golang-jwt's default
	// validator already produces this sentinel during jwt.Parse, so no new error
	// value is needed here — it's re-exported for callers who only import gourdiantoken.
	ErrTokenExpired = jwt.ErrTokenExpired

	// ErrInvalidSignature is an alias for jwt.ErrTokenSignatureInvalid, for the same
	// reason as ErrTokenExpired.
	ErrInvalidSignature = jwt.ErrTokenSignatureInvalid

	// ErrInvalidToken indicates the token failed parsing or structural validation.
	ErrInvalidToken = errors.New("invalid token")

	// ErrInvalidClaims indicates the token's claims are malformed or of the wrong type.
	ErrInvalidClaims = errors.New("invalid token claims")

	// ErrTokenRepositoryRequired indicates RotationEnabled or RevocationEnabled was
	// set without providing a TokenRepository.
	ErrTokenRepositoryRequired = errors.New("token repository required")

	// ErrMissingExpClaim indicates a token being revoked has no "exp" claim, so its
	// TTL in the repository cannot be computed.
	ErrMissingExpClaim = errors.New("token missing exp claim")

	// ErrTokenMaxLifetimeExceeded indicates the token's "mle" (max lifetime expiry)
	// claim has passed. This is a gourdiantoken-specific absolute expiry check with
	// no golang-jwt equivalent.
	ErrTokenMaxLifetimeExceeded = errors.New("token exceeded maximum lifetime")

	// ErrTokenAlreadyUsed is a plain alias for ErrTokenRevoked (same precedent as
	// ErrTokenExpired/ErrInvalidSignature above), exposed under a name that reads naturally
	// for verification-token callers ("this token was already used"). Single-use
	// enforcement for verification tokens is implemented by calling the same
	// MarkTokenRevoke/IsTokenRevoked machinery used for access/refresh revocation (see
	// MarkVerificationTokenUsed), so errors.Is(err, ErrTokenAlreadyUsed) and
	// errors.Is(err, ErrTokenRevoked) behave identically — this is a zero-new-logic alias.
	ErrTokenAlreadyUsed = ErrTokenRevoked

	// ErrTenantIDRequired indicates CreateAccessToken/CreateRefreshToken was called with
	// an empty tenantID while GourdianTokenConfig.MultiTenantEnabled is true, or that a
	// token being verified is missing its "tid" claim under the same config.
	ErrTenantIDRequired = errors.New("tenant ID is required when MultiTenantEnabled is true")

	// ErrTenantIDNotAllowed indicates CreateAccessToken/CreateRefreshToken was called with
	// a non-empty tenantID while GourdianTokenConfig.MultiTenantEnabled is false. Rejected
	// outright rather than silently ignored, so a caller relying on tenant isolation never
	// mistakes a misconfigured maker for one that's actually enforcing it.
	ErrTenantIDNotAllowed = errors.New("tenant ID must be empty when MultiTenantEnabled is false")
)
