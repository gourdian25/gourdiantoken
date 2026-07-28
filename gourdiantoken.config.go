// File: gourdiantoken.config.go

// Package gourdiantoken provides a comprehensive JWT token management system with support
// for access and refresh tokens, token rotation, revocation, and multiple signing algorithms.
//
// Features:
//   - Symmetric (HMAC) and Asymmetric (RSA, ECDSA, EdDSA) signing methods
//   - Token rotation with atomic operations to prevent race conditions
//   - Token revocation with background cleanup
//   - Configurable expiry durations and maximum lifetimes
//   - Context-aware operations for cancellation support
//   - Comprehensive validation and security checks
package gourdiantoken

import (
	"time"
)

// TokenType represents the type of JWT token (access, refresh, or verification).
// Access tokens are short-lived and used for API authorization.
// Refresh tokens are longer-lived and used to obtain new access tokens.
// Verification tokens are short-lived, single-use, use-case-scoped tokens.
type TokenType string

const (
	// AccessToken represents a short-lived token used for API authorization.
	// Typically includes user roles and permissions.
	AccessToken TokenType = "access"

	// RefreshToken represents a long-lived token used to obtain new access tokens.
	// Should be stored securely and rotated regularly.
	RefreshToken TokenType = "refresh"

	// VerificationToken represents a short-lived, single-use token scoped to a specific
	// "use case" (e.g. a pending 2FA verification step, a password reset link, or an
	// email verification link). Unlike AccessToken/RefreshToken, its lifetime is set
	// per-call rather than fixed by configuration alone. Requires
	// GourdianTokenConfig.VerificationTokensEnabled; single-use enforcement additionally
	// requires RevocationEnabled plus a TokenRepository.
	VerificationToken TokenType = "verification"
)

// SigningMethod represents the cryptographic approach for signing tokens.
type SigningMethod string

const (
	// Symmetric uses HMAC-based algorithms (HS256, HS384, HS512) with a shared secret key.
	// Simpler to set up but requires secure key distribution.
	Symmetric SigningMethod = "symmetric"

	// Asymmetric uses public-key algorithms (RS256, ES256, PS256, EdDSA) with key pairs.
	// More secure for distributed systems where tokens are verified by multiple services.
	Asymmetric SigningMethod = "asymmetric"
)

// Claim key constants for the standard claims referenced by GourdianTokenConfig.RequiredClaims.
const (
	// ClaimIssuer is the JWT "iss" claim key.
	ClaimIssuer = "iss"

	// ClaimAudience is the JWT "aud" claim key.
	ClaimAudience = "aud"

	// ClaimNotBefore is the JWT "nbf" claim key.
	ClaimNotBefore = "nbf"

	// ClaimMaxLifetimeExpiry is the "mle" (max lifetime expiry) claim key, a gourdiantoken-specific
	// absolute expiry claim distinct from the standard "exp" claim.
	ClaimMaxLifetimeExpiry = "mle"

	// ClaimUseCase is the "uc" (use case) claim key, present only on VerificationTokenClaims.
	ClaimUseCase = "uc"
)

// GourdianTokenConfig holds the configuration for token generation, validation, and lifecycle management.
// All duration fields must be positive values. Zero or negative durations will cause validation errors.
//
// Security Considerations:
//   - SymmetricKey must be at least 32 bytes for HMAC algorithms
//   - PrivateKeyPEM should be sourced from a secret store (env var, mounted Secret,
//     secret-manager SDK) rather than committed to a file in the repo
//   - Algorithm must match the SigningMethod (e.g., HS256 for Symmetric, RS256 for Asymmetric)
//   - Consider enabling both RotationEnabled and RevocationEnabled for production systems
type GourdianTokenConfig struct {
	// RotationEnabled determines whether refresh token rotation is enforced.
	// When enabled, each refresh token can only be used once to obtain a new token.
	// Prevents token reuse attacks and improves security.
	RotationEnabled bool

	// RevocationEnabled determines whether tokens can be explicitly revoked before expiration.
	// When enabled, requires a TokenRepository to track revoked tokens.
	// Essential for logout functionality and compromised token mitigation.
	RevocationEnabled bool

	// Algorithm specifies the JWT signing algorithm.
	// Supported: HS256, HS384, HS512, RS256, RS384, RS512, ES256, ES384, ES512, PS256, PS384, PS512, EdDSA.
	// Must match the SigningMethod (e.g., "HS256" requires Symmetric method).
	Algorithm string

	// SymmetricKey is the Base64-encoded secret key for HMAC algorithms.
	// Required when SigningMethod is Symmetric. Must be at least 32 bytes.
	// Keep this value secret and rotate it periodically.
	SymmetricKey string

	// PrivateKeyPEM is the PEM-encoded private key bytes.
	// Required when SigningMethod is Asymmetric. Callers own how these bytes are
	// obtained (an env var, a mounted Kubernetes Secret read once at startup, a
	// secret-manager SDK call, etc.) — gourdiantoken never reads a key from disk itself.
	PrivateKeyPEM []byte

	// PublicKeyPEM is the PEM-encoded public key or certificate bytes.
	// Required when SigningMethod is Asymmetric.
	// Used for token verification and can be distributed to services that need to validate tokens.
	PublicKeyPEM []byte

	// Issuer identifies the token issuer (e.g., "auth.example.com").
	// Included in the "iss" claim and validated during token verification.
	Issuer string

	// Audience specifies the intended recipients of the token (e.g., ["api.example.com"]).
	// Included in the "aud" claim. Validators should check this matches their service identifier.
	Audience []string

	// AllowedAlgorithms is a whitelist of acceptable algorithms for token verification.
	// Helps prevent algorithm confusion attacks. If empty, all supported algorithms are allowed.
	AllowedAlgorithms []string

	// RequiredClaims lists mandatory claims that must be present in tokens.
	// Standard required claims include: "iss", "aud", "nbf", "mle".
	RequiredClaims []string

	// SigningMethod specifies whether to use Symmetric (HMAC) or Asymmetric (RSA/ECDSA) signing.
	SigningMethod SigningMethod

	// AccessExpiryDuration is the time until an access token expires after issuance.
	// Typical values: 15-30 minutes. Shorter durations improve security but increase refresh frequency.
	AccessExpiryDuration time.Duration

	// AccessMaxLifetimeExpiry is the absolute maximum validity period from token creation.
	// Even if refreshed, tokens cannot be valid beyond this time.
	// Must be greater than or equal to AccessExpiryDuration.
	AccessMaxLifetimeExpiry time.Duration

	// RefreshExpiryDuration is the time until a refresh token expires after issuance.
	// Typical values: 7-30 days. Balance between security and user convenience.
	RefreshExpiryDuration time.Duration

	// RefreshMaxLifetimeExpiry is the absolute maximum validity period from token creation.
	// Enforces periodic re-authentication. Must be greater than or equal to RefreshExpiryDuration.
	RefreshMaxLifetimeExpiry time.Duration

	// RefreshReuseInterval is the minimum time between refresh token reuse attempts.
	// Helps detect suspicious activity. Set to 0 to disable. Typical value: 5 minutes.
	RefreshReuseInterval time.Duration

	// CleanupInterval determines how often expired tokens are removed from storage.
	// Prevents database bloat. Typical values: 1-6 hours. Must be at least 1 minute.
	CleanupInterval time.Duration

	// VerificationTokensEnabled determines whether CreateVerificationToken, VerifyVerificationToken,
	// and MarkVerificationTokenUsed are active. Defaults to false: every config that predates
	// this field is unaffected, and validateConfig only checks the Verification* fields below
	// when this is true. Single-use enforcement additionally requires RevocationEnabled plus a
	// TokenRepository.
	VerificationTokensEnabled bool

	// VerificationAllowedUseCases is a whitelist of acceptable "use case" strings for
	// verification tokens (e.g. "2fa-pending", "password-reset", "email-verify"). If empty,
	// any non-empty use case is accepted, mirroring the AllowedAlgorithms convention.
	VerificationAllowedUseCases []string

	// VerificationDefaultExpiryDuration is the verification token lifetime used when
	// CreateVerificationToken is called with ttl <= 0. Must be positive when
	// VerificationTokensEnabled is true. Typical values: 5-15 minutes.
	VerificationDefaultExpiryDuration time.Duration

	// VerificationMaxExpiryDuration is the ceiling a caller-supplied ttl in
	// CreateVerificationToken may not exceed; requests above it are rejected. Zero means no
	// ceiling. Must be >= VerificationDefaultExpiryDuration (when both are set) when
	// VerificationTokensEnabled is true.
	VerificationMaxExpiryDuration time.Duration

	// MultiTenantEnabled determines whether CreateAccessToken/CreateRefreshToken require a
	// non-empty tenantID (carried in the "tid" claim) and whether VerifyAccessToken/
	// VerifyRefreshToken require the token to carry one. Defaults to false: every config
	// that predates this field is unaffected, and a tenantID passed while this is false is
	// rejected outright (ErrTenantIDNotAllowed) rather than silently ignored. Opt-in rather
	// than always-on so this library stays usable by any single-tenant consumer too.
	MultiTenantEnabled bool
}

// NewGourdianTokenConfig creates a new token configuration with all parameters explicitly specified.
// This constructor provides full control over all configuration options.
//
// Parameters:
//   - signingMethod: Cryptographic method (Symmetric or Asymmetric)
//   - rotationEnabled: Enable refresh token rotation to prevent reuse
//   - revocationEnabled: Enable explicit token revocation before expiration
//   - audience: List of intended token recipients (e.g., ["api.example.com"])
//   - allowedAlgorithms: Whitelist of acceptable signing algorithms
//   - requiredClaims: List of mandatory claims that must be present
//   - algorithm: JWT signing algorithm (must match signingMethod)
//   - symmetricKey: Secret key for HMAC (required if signingMethod is Symmetric)
//   - privateKeyPEM: PEM-encoded private key bytes (required if signingMethod is Asymmetric)
//   - publicKeyPEM: PEM-encoded public key bytes (required if signingMethod is Asymmetric)
//   - issuer: Token issuer identifier
//   - accessExpiryDuration: Access token lifetime (e.g., 30 minutes)
//   - accessMaxLifetimeExpiry: Maximum access token validity (e.g., 24 hours)
//   - refreshExpiryDuration: Refresh token lifetime (e.g., 7 days)
//   - refreshMaxLifetimeExpiry: Maximum refresh token validity (e.g., 30 days)
//   - refreshReuseInterval: Minimum time between reuse attempts (e.g., 5 minutes)
//   - cleanupInterval: Frequency of expired token cleanup (e.g., 6 hours)
//
// Returns:
//   - GourdianTokenConfig: Fully configured token configuration
//
// Example:
//
//	config := NewGourdianTokenConfig(
//	    gourdiantoken.Symmetric,
//	    true, true,
//	    []string{"api.example.com"},
//	    []string{"HS256", "HS384"},
//	    []string{"iss", "aud", "nbf", "mle"},
//	    "HS256",
//	    "your-secret-key-min-32-bytes-long",
//	    nil, nil,
//	    "auth.example.com",
//	    30*time.Minute, 24*time.Hour,
//	    7*24*time.Hour, 30*24*time.Hour,
//	    5*time.Minute, 6*time.Hour,
//	)
//
// Deprecated: use DefaultGourdianTokenConfig plus struct-literal field assignment
// instead. NewGourdianTokenConfig will be removed in a future major version.
func NewGourdianTokenConfig(
	signingMethod SigningMethod,
	rotationEnabled, revocationEnabled bool,
	audience, allowedAlgorithms, requiredClaims []string,
	algorithm, symmetricKey string,
	privateKeyPEM, publicKeyPEM []byte,
	issuer string,
	accessExpiryDuration, accessMaxLifetimeExpiry, refreshExpiryDuration, refreshMaxLifetimeExpiry, refreshReuseInterval, cleanupInterval time.Duration,
) GourdianTokenConfig {
	return GourdianTokenConfig{
		RevocationEnabled:        revocationEnabled,
		RotationEnabled:          rotationEnabled,
		SigningMethod:            signingMethod,
		Audience:                 audience,
		AllowedAlgorithms:        allowedAlgorithms,
		RequiredClaims:           requiredClaims,
		Algorithm:                algorithm,
		SymmetricKey:             symmetricKey,
		PrivateKeyPEM:            privateKeyPEM,
		PublicKeyPEM:             publicKeyPEM,
		Issuer:                   issuer,
		AccessExpiryDuration:     accessExpiryDuration,
		AccessMaxLifetimeExpiry:  accessMaxLifetimeExpiry,
		RefreshExpiryDuration:    refreshExpiryDuration,
		RefreshMaxLifetimeExpiry: refreshMaxLifetimeExpiry,
		RefreshReuseInterval:     refreshReuseInterval,
		CleanupInterval:          cleanupInterval,
	}
}

// DefaultGourdianTokenConfig creates a token configuration with sensible defaults for quick setup.
// Uses symmetric HMAC-SHA256 signing with moderate security settings suitable for development and testing.
//
// Default Configuration:
//   - Algorithm: HS256 (HMAC-SHA256)
//   - SigningMethod: Symmetric
//   - RevocationEnabled: false
//   - RotationEnabled: false
//   - Issuer: "gourdian.com"
//   - AllowedAlgorithms: ["HS256", "HS384", "HS512", "RS256", "ES256", "PS256"]
//   - RequiredClaims: ["iss", "aud", "nbf", "mle"]
//   - AccessExpiryDuration: 30 minutes
//   - AccessMaxLifetimeExpiry: 24 hours
//   - RefreshExpiryDuration: 7 days
//   - RefreshMaxLifetimeExpiry: 30 days
//   - RefreshReuseInterval: 5 minutes
//   - CleanupInterval: 6 hours
//
// Parameters:
//   - symmetricKey: The secret key for HMAC signing (must be at least 32 bytes)
//
// Returns:
//   - GourdianTokenConfig: Pre-configured token configuration with defaults
//
// Security Note:
//
//	For production systems, consider:
//	- Using a stronger algorithm (HS384 or HS512)
//	- Enabling RevocationEnabled and RotationEnabled
//	- Reducing AccessExpiryDuration to 15 minutes
//	- Using asymmetric signing for distributed systems
//
// Example:
//
//	config := DefaultGourdianTokenConfig("your-secret-key-at-least-32-bytes")
func DefaultGourdianTokenConfig(symmetricKey string) GourdianTokenConfig {
	return GourdianTokenConfig{
		RevocationEnabled:        false,
		RotationEnabled:          false,
		SigningMethod:            Symmetric,
		Algorithm:                "HS256",
		SymmetricKey:             symmetricKey,
		Issuer:                   "gourdian.com",
		Audience:                 nil,
		AllowedAlgorithms:        []string{"HS256", "HS384", "HS512", "RS256", "ES256", "PS256"},
		RequiredClaims:           []string{"iss", "aud", "nbf", "mle"},
		AccessExpiryDuration:     30 * time.Minute,
		AccessMaxLifetimeExpiry:  24 * time.Hour,
		RefreshExpiryDuration:    7 * 24 * time.Hour,
		RefreshMaxLifetimeExpiry: 30 * 24 * time.Hour,
		RefreshReuseInterval:     5 * time.Minute,
		CleanupInterval:          6 * time.Hour,
	}
}
