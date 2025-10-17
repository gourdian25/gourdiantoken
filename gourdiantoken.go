// File: gourdiantoken.go


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
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// TokenType represents the type of JWT token (access or refresh).
// Access tokens are short-lived and used for API authorization.
// Refresh tokens are longer-lived and used to obtain new access tokens.
type TokenType string

const (
	// AccessToken represents a short-lived token used for API authorization.
	// Typically includes user roles and permissions.
	AccessToken TokenType = "access"

	// RefreshToken represents a long-lived token used to obtain new access tokens.
	// Should be stored securely and rotated regularly.
	RefreshToken TokenType = "refresh"
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

// GourdianTokenConfig holds the configuration for token generation, validation, and lifecycle management.
// All duration fields must be positive values. Zero or negative durations will cause validation errors.
//
// Security Considerations:
//   - SymmetricKey must be at least 32 bytes for HMAC algorithms
//   - Private key files should have 0600 permissions
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

	// PrivateKeyPath is the file path to the PEM-encoded private key.
	// Required when SigningMethod is Asymmetric.
	// File should have restrictive permissions (0600 recommended).
	PrivateKeyPath string

	// PublicKeyPath is the file path to the PEM-encoded public key or certificate.
	// Required when SigningMethod is Asymmetric.
	// Used for token verification and can be distributed to services that need to validate tokens.
	PublicKeyPath string

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
//   - privateKeyPath: Path to private key file (required if signingMethod is Asymmetric)
//   - publicKeyPath: Path to public key file (required if signingMethod is Asymmetric)
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
//	    "", "",
//	    "auth.example.com",
//	    30*time.Minute, 24*time.Hour,
//	    7*24*time.Hour, 30*24*time.Hour,
//	    5*time.Minute, 6*time.Hour,
//	)
func NewGourdianTokenConfig(
	signingMethod SigningMethod,
	rotationEnabled, revocationEnabled bool,
	audience, allowedAlgorithms, requiredClaims []string,
	algorithm, symmetricKey, privateKeyPath, publicKeyPath, issuer string,
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
		PrivateKeyPath:           privateKeyPath,
		PublicKeyPath:            publicKeyPath,
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
		PrivateKeyPath:           "",
		PublicKeyPath:            "",
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

// AccessTokenClaims represents the claims contained in an access token JWT.
// Access tokens are short-lived and include authorization information (roles).
//
// Standard JWT Claims:
//   - jti: JWT ID (unique token identifier)
//   - sub: Subject (user UUID)
//   - iss: Issuer (authentication service)
//   - aud: Audience (intended recipients)
//   - iat: Issued At (token creation time)
//   - exp: Expiration Time
//   - nbf: Not Before (optional, token not valid before this time)
//
// Custom Claims:
//   - sid: Session ID (for tracking user sessions)
//   - usr: Username (human-readable identifier)
//   - rls: Roles (authorization roles for RBAC)
//   - typ: Token Type (always "access" for access tokens)
//   - mle: Maximum Lifetime Expiry (absolute expiration)
type AccessTokenClaims struct {
	// ID is the unique token identifier (UUIDv4) used for tracking and revocation.
	ID uuid.UUID `json:"jti"`

	// Subject is the user's unique identifier (UUID).
	Subject uuid.UUID `json:"sub"`

	// SessionID uniquely identifies the user's session (UUIDv4).
	// Used to invalidate all tokens when a session ends.
	SessionID uuid.UUID `json:"sid"`

	// Username is the human-readable username for logging and display purposes.
	Username string `json:"usr"`

	// Issuer identifies the service that created this token (e.g., "auth.example.com").
	Issuer string `json:"iss"`

	// Audience lists the services that should accept this token (e.g., ["api.example.com"]).
	Audience []string `json:"aud"`

	// Roles contains the authorization roles for role-based access control (RBAC).
	// Must contain at least one role.
	Roles []string `json:"rls"`

	// IssuedAt is the timestamp when this token was created (UTC).
	IssuedAt time.Time `json:"iat"`

	// ExpiresAt is the timestamp when this token expires (UTC).
	ExpiresAt time.Time `json:"exp"`

	// NotBefore is the optional timestamp before which the token is not valid (UTC).
	NotBefore time.Time `json:"nbf"`

	// MaxLifetimeExpiry is the absolute expiration time regardless of refreshes (RFC3339 format).
	MaxLifetimeExpiry time.Time `json:"mle"`

	// TokenType is always "access" for access tokens.
	TokenType TokenType `json:"typ"`
}

// RefreshTokenClaims represents the claims contained in a refresh token JWT.
// Refresh tokens are long-lived and used to obtain new access tokens without re-authentication.
//
// Standard JWT Claims:
//   - jti: JWT ID (unique token identifier)
//   - sub: Subject (user UUID)
//   - iss: Issuer (authentication service)
//   - aud: Audience (intended recipients)
//   - iat: Issued At (token creation time)
//   - exp: Expiration Time
//   - nbf: Not Before (optional, token not valid before this time)
//
// Custom Claims:
//   - sid: Session ID (for tracking user sessions)
//   - usr: Username (human-readable identifier)
//   - typ: Token Type (always "refresh" for refresh tokens)
//   - mle: Maximum Lifetime Expiry (absolute expiration)
//
// Note: Refresh tokens do not include roles since they're only used to obtain new access tokens.
type RefreshTokenClaims struct {
	// ID is the unique token identifier (UUIDv4) used for tracking and rotation.
	ID uuid.UUID `json:"jti"`

	// Subject is the user's unique identifier (UUID).
	Subject uuid.UUID `json:"sub"`

	// SessionID uniquely identifies the user's session (UUIDv4).
	SessionID uuid.UUID `json:"sid"`

	// Username is the human-readable username.
	Username string `json:"usr"`

	// Issuer identifies the service that created this token.
	Issuer string `json:"iss"`

	// Audience lists the services that should accept this token.
	Audience []string `json:"aud"`

	// IssuedAt is the timestamp when this token was created (UTC).
	IssuedAt time.Time `json:"iat"`

	// ExpiresAt is the timestamp when this token expires (UTC).
	ExpiresAt time.Time `json:"exp"`

	// NotBefore is the optional timestamp before which the token is not valid (UTC).
	NotBefore time.Time `json:"nbf"`

	// MaxLifetimeExpiry is the absolute expiration time (RFC3339 format).
	MaxLifetimeExpiry time.Time `json:"mle"`

	// TokenType is always "refresh" for refresh tokens.
	TokenType TokenType `json:"typ"`
}

// AccessTokenResponse contains the generated access token and its associated metadata.
// This is returned after successful token creation and includes all information needed
// for the client to use the token.
type AccessTokenResponse struct {
	// Subject is the user's unique identifier (UUID).
	Subject uuid.UUID `json:"sub"`

	// SessionID uniquely identifies the user's session (UUID).
	SessionID uuid.UUID `json:"sid"`

	// Token is the signed JWT string ready for use in Authorization headers.
	Token string `json:"tok"`

	// Issuer identifies the authentication service.
	Issuer string `json:"iss"`

	// Username is the human-readable username.
	Username string `json:"usr"`

	// Roles contains the authorization roles for this token.
	Roles []string `json:"rls"`

	// Audience lists the intended recipients of this token.
	Audience []string `json:"aud"`

	// IssuedAt is when the token was created (RFC3339 format).
	IssuedAt time.Time `json:"iat"`

	// ExpiresAt is when the token expires (RFC3339 format).
	ExpiresAt time.Time `json:"exp"`

	// NotBefore is when the token becomes valid (RFC3339 format).
	NotBefore time.Time `json:"nbf"`

	// MaxLifetimeExpiry is the absolute expiration time (RFC3339 format).
	MaxLifetimeExpiry time.Time `json:"mle"`

	// TokenType is always "access".
	TokenType TokenType `json:"typ"`
}

// RefreshTokenResponse contains the generated refresh token and its associated metadata.
// This is returned after successful refresh token creation or rotation.
type RefreshTokenResponse struct {
	// Subject is the user's unique identifier (UUID).
	Subject uuid.UUID `json:"sub"`

	// SessionID uniquely identifies the user's session (UUID).
	SessionID uuid.UUID `json:"sid"`

	// Token is the signed JWT string that can be used to obtain new access tokens.
	Token string `json:"tok"`

	// Issuer identifies the authentication service.
	Issuer string `json:"iss"`

	// Username is the human-readable username.
	Username string `json:"usr"`

	// Audience lists the intended recipients of this token.
	Audience []string `json:"aud"`

	// IssuedAt is when the token was created (RFC3339 format).
	IssuedAt time.Time `json:"iat"`

	// ExpiresAt is when the token expires (RFC3339 format).
	ExpiresAt time.Time `json:"exp"`

	// NotBefore is when the token becomes valid (RFC3339 format).
	NotBefore time.Time `json:"nbf"`

	// MaxLifetimeExpiry is the absolute expiration time (RFC3339 format).
	MaxLifetimeExpiry time.Time `json:"mle"`

	// TokenType is always "refresh".
	TokenType TokenType `json:"typ"`
}

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
}

// GourdianTokenMaker is the main interface for token operations.
// Implementations handle token creation, verification, revocation, and rotation
// with support for multiple signing algorithms and security features.
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
	//   - userID: The user's unique identifier (must not be uuid.Nil)
	//   - username: Human-readable username (max 1024 characters)
	//   - roles: Authorization roles (must contain at least one non-empty role)
	//   - sessionID: Session identifier for tracking
	//
	// Returns:
	//   - *AccessTokenResponse: Generated token with metadata
	//   - error: If token creation fails, parameters are invalid, or context is cancelled
	//
	// Example:
	//
	//	token, err := maker.CreateAccessToken(
	//	    ctx,
	//	    uuid.MustParse("123e4567-e89b-12d3-a456-426614174000"),
	//	    "john.doe",
	//	    []string{"user", "admin"},
	//	    sessionUUID,
	//	)
	CreateAccessToken(ctx context.Context, userID uuid.UUID, username string, roles []string, sessionID uuid.UUID) (*AccessTokenResponse, error)

	// CreateRefreshToken generates a new signed refresh token.
	//
	// Parameters:
	//   - ctx: Context for cancellation and timeout
	//   - userID: The user's unique identifier (must not be uuid.Nil)
	//   - username: Human-readable username (max 1024 characters)
	//   - sessionID: Session identifier for tracking
	//
	// Returns:
	//   - *RefreshTokenResponse: Generated token with metadata
	//   - error: If token creation fails, parameters are invalid, or context is cancelled
	//
	// Example:
	//
	//	token, err := maker.CreateRefreshToken(
	//	    ctx,
	//	    userUUID,
	//	    "john.doe",
	//	    sessionUUID,
	//	)
	CreateRefreshToken(ctx context.Context, userID uuid.UUID, username string, sessionID uuid.UUID) (*RefreshTokenResponse, error)

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
}

// JWTMaker is the concrete implementation of GourdianTokenMaker.
// Handles JWT token lifecycle with configurable security features and multiple signing algorithms.
//
// Thread Safety:
//
//	Safe for concurrent use. Internal state is immutable after initialization.
//
// Lifecycle:
//   - Create with NewGourdianTokenMaker or DefaultGourdianTokenMaker
//   - Automatically starts background cleanup goroutines if rotation/revocation enabled
//   - Cleanup goroutines stop when the maker is garbage collected
type JWTMaker struct {
	// config holds the immutable configuration for token operations.
	config GourdianTokenConfig

	// signingMethod is the JWT signing algorithm instance (e.g., HS256, RS256).
	signingMethod jwt.SigningMethod

	// privateKey holds the cryptographic key for signing (HMAC secret or private key).
	privateKey interface{}

	// publicKey holds the verification key (HMAC secret or public key).
	publicKey interface{}

	// tokenRepo provides persistent storage for revocation and rotation tracking.
	tokenRepo TokenRepository

	// cleanupCancel cancels background cleanup goroutines.
	cleanupCancel context.CancelFunc
}

// NewGourdianTokenMaker creates a new GourdianTokenMaker with the specified configuration and token repository.
// This is the main constructor that provides full control over token maker initialization.
//
// Initialization Process:
//  1. Validates the configuration for security and consistency
//  2. Checks algorithm and signing method compatibility
//  3. Initializes cryptographic keys (loads from files for asymmetric)
//  4. Sets up background cleanup goroutines if rotation/revocation enabled
//  5. Returns a fully configured token maker ready for use
//
// Background Operations:
//
//	If rotation or revocation is enabled, background goroutines are started to:
//	- Clean up expired revoked tokens (prevents memory leaks)
//	- Clean up expired rotation markers (prevents memory leaks)
//	These goroutines run at intervals specified by config.CleanupInterval
//
// Parameters:
//   - ctx: Context for initialization. If cancelled, initialization fails immediately.
//   - config: Token maker configuration (see GourdianTokenConfig for details)
//   - tokenRepo: Repository for token storage. Required if RevocationEnabled or RotationEnabled is true.
//     Can be nil for stateless operation (revocation and rotation must be disabled).
//
// Returns:
//   - GourdianTokenMaker: Configured token maker instance ready for production use
//   - error: If configuration is invalid, keys cannot be loaded, context is cancelled,
//     or repository is required but nil
//
// Configuration Validation:
//   - Checks signing method matches algorithm (e.g., HS256 requires Symmetric)
//   - Validates key files exist and have secure permissions (0600 for private keys)
//   - Ensures durations are positive and logical (expiry < max lifetime)
//   - Verifies required parameters are provided for the chosen signing method
//
// Example (Symmetric with rotation and revocation):
//
//	config := gourdiantoken.GourdianTokenConfig{
//	    SigningMethod: gourdiantoken.Symmetric,
//	    Algorithm: "HS256",
//	    SymmetricKey: "your-secret-key-at-least-32-bytes-long",
//	    Issuer: "auth.example.com",
//	    Audience: []string{"api.example.com"},
//	    RevocationEnabled: true,
//	    RotationEnabled: true,
//	    AccessExpiryDuration: 30 * time.Minute,
//	    AccessMaxLifetimeExpiry: 24 * time.Hour,
//	    RefreshExpiryDuration: 7 * 24 * time.Hour,
//	    RefreshMaxLifetimeExpiry: 30 * 24 * time.Hour,
//	    CleanupInterval: 6 * time.Hour,
//	}
//
//	maker, err := gourdiantoken.NewGourdianTokenMaker(ctx, config, tokenRepo)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
// Example (Asymmetric with RSA):
//
//	config := gourdiantoken.GourdianTokenConfig{
//	    SigningMethod: gourdiantoken.Asymmetric,
//	    Algorithm: "RS256",
//	    PrivateKeyPath: "/path/to/private.pem",
//	    PublicKeyPath: "/path/to/public.pem",
//	    Issuer: "auth.example.com",
//	    RevocationEnabled: false,
//	    RotationEnabled: false,
//	    AccessExpiryDuration: 15 * time.Minute,
//	    RefreshExpiryDuration: 7 * 24 * time.Hour,
//	}
//
//	maker, err := gourdiantoken.NewGourdianTokenMaker(ctx, config, nil)
func NewGourdianTokenMaker(ctx context.Context, config GourdianTokenConfig, tokenRepo TokenRepository) (GourdianTokenMaker, error) {
	// Check context cancellation first
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context canceled: %w", err)
	}

	// Validate configuration
	if err := validateConfig(&config); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	if err := validateAlgorithmAndMethod(&config); err != nil {
		return nil, fmt.Errorf("invalid algorithm/method combination: %w", err)
	}

	// Check repository requirements
	if (config.RotationEnabled || config.RevocationEnabled) && tokenRepo == nil {
		return nil, fmt.Errorf("token repository required for token rotation/revocation")
	}

	maker := &JWTMaker{
		config: config,
	}

	// Set repository if any feature requiring it is enabled
	if config.RotationEnabled || config.RevocationEnabled {
		maker.tokenRepo = tokenRepo

		// Create a cleanup context
		cleanupCtx, cancel := context.WithCancel(context.Background())
		maker.cleanupCancel = cancel

		// Check context again before starting goroutines
		if err := ctx.Err(); err != nil {
			cancel()
			return nil, fmt.Errorf("context canceled: %w", err)
		}

		// Set up background cleanup if needed
		if config.RotationEnabled {
			go maker.cleanupRotatedTokens(cleanupCtx)
		}
		if config.RevocationEnabled {
			go maker.cleanupRevokedTokens(cleanupCtx)
		}
	}

	// Initialize signing method
	if err := maker.initializeSigningMethod(); err != nil {
		if maker.cleanupCancel != nil {
			maker.cleanupCancel()
		}
		return nil, fmt.Errorf("failed to initialize signing method: %w", err)
	}

	// Initialize cryptographic keys
	if err := maker.initializeKeys(); err != nil {
		if maker.cleanupCancel != nil {
			maker.cleanupCancel()
		}
		return nil, fmt.Errorf("failed to initialize keys: %w", err)
	}

	return maker, nil
}

// DefaultGourdianTokenMaker creates a token maker with sensible defaults for quick setup.
// Uses symmetric HMAC-SHA256 signing with minimal configuration required.
//
// Default Configuration:
//   - Algorithm: HS256 (HMAC-SHA256)
//   - Issuer: "gourdian.com"
//   - AllowedAlgorithms: ["HS256", "RS256", "ES256", "PS256"]
//   - RequiredClaims: ["iss", "aud", "nbf", "mle"]
//   - AccessExpiryDuration: 30 minutes
//   - AccessMaxLifetimeExpiry: 24 hours
//   - RefreshExpiryDuration: 7 days
//   - RefreshMaxLifetimeExpiry: 30 days
//   - RefreshReuseInterval: 5 minutes
//   - CleanupInterval: 6 hours
//
// Automatic Feature Detection:
//   - If tokenRepo is provided: RevocationEnabled and RotationEnabled are set to true
//   - If tokenRepo is nil: RevocationEnabled and RotationEnabled are set to false
//
// Parameters:
//   - ctx: Context for initialization (cancellation support)
//   - symmetricKey: Secret key for HMAC signing (must be at least 32 bytes)
//   - tokenRepo: Optional token repository. If provided, enables revocation and rotation.
//     Pass nil for stateless operation without these features.
//
// Returns:
//   - GourdianTokenMaker: Configured token maker with default settings
//   - error: If initialization fails or context is cancelled
//
// Use Cases:
//   - Rapid prototyping and development
//   - Simple authentication systems
//   - Microservices with symmetric signing
//   - Getting started with JWT tokens
//
// Security Considerations:
//
//	For production systems, consider using NewGourdianTokenMaker with:
//	- Asymmetric signing for distributed systems
//	- Shorter access token durations (15 minutes)
//	- Custom audience and issuer values
//	- Stricter allowed algorithms list
//
// Example (Stateless - no repository):
//
//	maker, err := gourdiantoken.DefaultGourdianTokenMaker(
//	    ctx,
//	    "your-secret-key-at-least-32-bytes-long",
//	    nil, // No token repository, stateless operation
//	)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	// Revocation and rotation are disabled
//
// Example (With repository - rotation and revocation enabled):
//
//	redisRepo := NewRedisTokenRepository(redisClient)
//	maker, err := gourdiantoken.DefaultGourdianTokenMaker(
//	    ctx,
//	    "your-secret-key-at-least-32-bytes-long",
//	    redisRepo, // Token repository provided
//	)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	// Revocation and rotation are automatically enabled
func DefaultGourdianTokenMaker(
	ctx context.Context,
	symmetricKey string,
	tokenRepo TokenRepository,
) (GourdianTokenMaker, error) {
	config := GourdianTokenConfig{
		RevocationEnabled:        false,
		RotationEnabled:          false,
		Algorithm:                "HS256",
		SymmetricKey:             symmetricKey,
		PrivateKeyPath:           "",
		PublicKeyPath:            "",
		Issuer:                   "gourdian.com",
		Audience:                 nil,
		AllowedAlgorithms:        []string{"HS256", "RS256", "ES256", "PS256"},
		RequiredClaims:           []string{"iss", "aud", "nbf", "mle"},
		SigningMethod:            Symmetric,
		AccessExpiryDuration:     30 * time.Minute,
		AccessMaxLifetimeExpiry:  24 * time.Hour,
		RefreshExpiryDuration:    7 * 24 * time.Hour,
		RefreshMaxLifetimeExpiry: 30 * 24 * time.Hour,
		RefreshReuseInterval:     5 * time.Minute,
		CleanupInterval:          6 * time.Hour,
	}

	if tokenRepo != nil {
		config.RevocationEnabled = true
		config.RotationEnabled = true
	}
	return NewGourdianTokenMaker(ctx, config, tokenRepo)
}

// CreateAccessToken generates a new signed access token with the specified claims.
// Access tokens are short-lived and include user identity, session, and authorization roles.
//
// Token Structure:
//   - Header: Algorithm and token type
//   - Payload: User claims (ID, username, roles, timestamps)
//   - Signature: Cryptographic signature for verification
//
// Automatic Claims:
//   - jti: Unique token identifier (auto-generated UUIDv4)
//   - iat: Issued at timestamp (current time)
//   - exp: Expiration time (iat + AccessExpiryDuration)
//   - nbf: Not before time (current time)
//   - mle: Maximum lifetime expiry (iat + AccessMaxLifetimeExpiry)
//   - iss: Issuer from configuration
//   - aud: Audience from configuration
//   - typ: Token type ("access")
//
// Validation:
//   - userID must not be uuid.Nil
//   - username must not exceed 1024 characters
//   - roles must contain at least one non-empty string
//   - sessionID can be any UUID (including Nil for sessionless tokens)
//
// Parameters:
//   - ctx: Context for cancellation. Checks are performed before signing and during I/O.
//   - userID: The user's unique identifier (UUID, must not be Nil)
//   - username: Human-readable username (max 1024 characters, can be empty)
//   - roles: List of authorization roles (must contain at least one non-empty role)
//   - sessionID: Session identifier (UUID, can be Nil for sessionless operation)
//
// Returns:
//   - *AccessTokenResponse: Complete token response with signed JWT and metadata
//   - error: If parameters are invalid, signing fails, or context is cancelled
//
// Example (Basic usage):
//
//	userUUID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")
//	sessionUUID := uuid.New()
//
//	token, err := maker.CreateAccessToken(
//	    ctx,
//	    userUUID,
//	    "john.doe",
//	    []string{"user", "admin"},
//	    sessionUUID,
//	)
//	if err != nil {
//	    return fmt.Errorf("failed to create token: %w", err)
//	}
//
//	// Use token.Token in Authorization header
//	fmt.Printf("Token: %s\n", token.Token)
//	fmt.Printf("Expires: %s\n", token.ExpiresAt)
//
// Example (Multiple roles):
//
//	token, err := maker.CreateAccessToken(
//	    ctx,
//	    userUUID,
//	    "admin@example.com",
//	    []string{"user", "admin", "moderator"},
//	    sessionUUID,
//	)
//
// Example (With context timeout):
//
//	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
//	defer cancel()
//
//	token, err := maker.CreateAccessToken(ctx, userUUID, username, roles, sessionUUID)
func (maker *JWTMaker) CreateAccessToken(ctx context.Context, userID uuid.UUID, username string, roles []string, sessionID uuid.UUID) (*AccessTokenResponse, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context canceled: %w", err)
	}

	if userID == uuid.Nil {
		return nil, fmt.Errorf("invalid user ID: cannot be empty")
	}
	if len(roles) == 0 {
		return nil, fmt.Errorf("at least one role must be provided")
	}
	if len(username) > 1024 {
		return nil, fmt.Errorf("username too long: max 1024 characters")
	}

	// Validate roles are non-empty strings
	for _, role := range roles {
		if role == "" {
			return nil, fmt.Errorf("roles cannot contain empty strings")
		}
	}

	tokenID, err := uuid.NewRandom()
	if err != nil {
		return nil, fmt.Errorf("failed to generate token ID: %w", err)
	}

	now := time.Now()
	claims := AccessTokenClaims{
		ID:                tokenID,
		Subject:           userID,
		SessionID:         sessionID,
		Username:          username,
		Issuer:            maker.config.Issuer,
		Audience:          maker.config.Audience,
		Roles:             roles,
		IssuedAt:          now,
		ExpiresAt:         now.Add(maker.config.AccessExpiryDuration),
		NotBefore:         now,
		MaxLifetimeExpiry: now.Add(maker.config.AccessMaxLifetimeExpiry),
		TokenType:         AccessToken,
	}

	token := jwt.NewWithClaims(maker.signingMethod, toMapClaims(claims))

	// Check context before CPU-intensive signing operation
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context canceled before signing: %w", err)
	}

	signedToken, err := token.SignedString(maker.privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign access token: %w", err)
	}

	response := &AccessTokenResponse{
		Subject:           claims.Subject,
		SessionID:         claims.SessionID,
		Token:             signedToken,
		Issuer:            claims.Issuer,
		Username:          claims.Username,
		Roles:             roles,
		Audience:          claims.Audience,
		IssuedAt:          claims.IssuedAt,
		ExpiresAt:         claims.ExpiresAt,
		NotBefore:         claims.NotBefore,
		MaxLifetimeExpiry: claims.MaxLifetimeExpiry,
		TokenType:         claims.TokenType,
	}

	return response, nil
}

// CreateRefreshToken generates a new signed refresh token for obtaining new access tokens.
// Refresh tokens are long-lived and do not include authorization roles.
//
// Token Structure:
//   - Header: Algorithm and token type
//   - Payload: User identity and session (no roles)
//   - Signature: Cryptographic signature for verification
//
// Automatic Claims:
//   - jti: Unique token identifier (auto-generated UUIDv4)
//   - iat: Issued at timestamp (current time)
//   - exp: Expiration time (iat + RefreshExpiryDuration)
//   - nbf: Not before time (current time)
//   - mle: Maximum lifetime expiry (iat + RefreshMaxLifetimeExpiry)
//   - iss: Issuer from configuration
//   - aud: Audience from configuration
//   - typ: Token type ("refresh")
//
// Validation:
//   - userID must not be uuid.Nil
//   - username must not exceed 1024 characters
//   - sessionID can be any UUID (including Nil)
//
// Parameters:
//   - ctx: Context for cancellation
//   - userID: The user's unique identifier (UUID, must not be Nil)
//   - username: Human-readable username (max 1024 characters)
//   - sessionID: Session identifier (UUID)
//
// Returns:
//   - *RefreshTokenResponse: Complete token response with signed JWT and metadata
//   - error: If parameters are invalid, signing fails, or context is cancelled
//
// Security Best Practices:
//   - Store refresh tokens securely (httpOnly cookies, secure storage)
//   - Use token rotation to prevent reuse
//   - Implement refresh token revocation for logout
//   - Monitor for suspicious refresh patterns
//
// Example (Create refresh token):
//
//	refreshToken, err := maker.CreateRefreshToken(
//	    ctx,
//	    userUUID,
//	    "john.doe",
//	    sessionUUID,
//	)
//	if err != nil {
//	    return fmt.Errorf("failed to create refresh token: %w", err)
//	}
//
//	// Store securely (e.g., httpOnly cookie)
//	http.SetCookie(w, &http.Cookie{
//	    Name:     "refresh_token",
//	    Value:    refreshToken.Token,
//	    Expires:  refreshToken.ExpiresAt,
//	    HttpOnly: true,
//	    Secure:   true,
//	    SameSite: http.SameSiteStrictMode,
//	})
//
// Example (Create token pair):
//
//	accessToken, err := maker.CreateAccessToken(ctx, userUUID, username, roles, sessionUUID)
//	if err != nil {
//	    return err
//	}
//
//	refreshToken, err := maker.CreateRefreshToken(ctx, userUUID, username, sessionUUID)
//	if err != nil {
//	    return err
//	}
//
//	return &TokenPair{
//	    AccessToken:  accessToken.Token,
//	    RefreshToken: refreshToken.Token,
//	}
func (maker *JWTMaker) CreateRefreshToken(ctx context.Context, userID uuid.UUID, username string, sessionID uuid.UUID) (*RefreshTokenResponse, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context canceled: %w", err)
	}

	if userID == uuid.Nil {
		return nil, fmt.Errorf("invalid user ID: cannot be empty")
	}
	if len(username) > 1024 {
		return nil, fmt.Errorf("username too long: max 1024 characters")
	}

	tokenID, err := uuid.NewRandom()
	if err != nil {
		return nil, fmt.Errorf("failed to generate token ID: %w", err)
	}

	now := time.Now()
	claims := RefreshTokenClaims{
		ID:                tokenID,
		Subject:           userID,
		SessionID:         sessionID,
		Username:          username,
		Issuer:            maker.config.Issuer,
		Audience:          maker.config.Audience,
		IssuedAt:          now,
		ExpiresAt:         now.Add(maker.config.RefreshExpiryDuration),
		NotBefore:         now,
		MaxLifetimeExpiry: now.Add(maker.config.RefreshMaxLifetimeExpiry),
		TokenType:         RefreshToken,
	}

	token := jwt.NewWithClaims(maker.signingMethod, toMapClaims(claims))

	// Check context before CPU-intensive signing operation
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context canceled before signing: %w", err)
	}

	signedToken, err := token.SignedString(maker.privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign refresh token: %w", err)
	}

	response := &RefreshTokenResponse{
		Subject:           claims.Subject,
		SessionID:         claims.SessionID,
		Token:             signedToken,
		Issuer:            claims.Issuer,
		Username:          claims.Username,
		Audience:          claims.Audience,
		IssuedAt:          claims.IssuedAt,
		ExpiresAt:         claims.ExpiresAt,
		NotBefore:         claims.NotBefore,
		MaxLifetimeExpiry: claims.MaxLifetimeExpiry,
		TokenType:         claims.TokenType,
	}

	return response, nil
}

// VerifyAccessToken validates an access token and returns its claims if valid.
// Performs comprehensive security checks including signature, expiration, and revocation.
//
// Validation Steps:
//  1. Check context cancellation
//  2. Check revocation status (if RevocationEnabled)
//  3. Verify cryptographic signature
//  4. Validate token structure and algorithm
//  5. Check all timestamps (iat, exp, nbf, mle)
//  6. Verify required claims are present
//  7. Validate token type is "access"
//  8. Parse and return claims
//
// Checks Performed:
//   - Signature matches expected algorithm
//   - Token has not expired (exp > now)
//   - Token is not used before valid time (nbf <= now)
//   - Token has not exceeded maximum lifetime (mle > now)
//   - Token has not been revoked (if revocation enabled)
//   - All required claims are present
//   - Token type is "access" (not "refresh")
//
// Parameters:
//   - ctx: Context for cancellation. Checked multiple times during verification.
//   - tokenString: The JWT token string to verify (from Authorization header)
//
// Returns:
//   - *AccessTokenClaims: Parsed and validated token claims with all user information
//   - error: If token is invalid, expired, revoked, or any validation check fails
//
// Error Scenarios:
//   - Invalid signature: Token has been tampered with
//   - Expired: Token lifetime has ended
//   - Revoked: Token was explicitly invalidated
//   - Wrong type: Refresh token used where access token expected
//   - Missing claims: Token structure is incomplete
//   - Future issued: Token claims to be issued in the future
//   - Context cancelled: Operation was cancelled by caller
//
// Example (Verify and use claims):
//
//	claims, err := maker.VerifyAccessToken(ctx, tokenString)
//	if err != nil {
//	    return nil, fmt.Errorf("invalid token: %w", err)
//	}
//
//	// Use claims for authorization
//	if !hasRole(claims.Roles, "admin") {
//	    return fmt.Errorf("insufficient permissions")
//	}
//
//	// Access user information
//	fmt.Printf("User: %s (%s)\n", claims.Username, claims.Subject)
//	fmt.Printf("Session: %s\n", claims.SessionID)
//	fmt.Printf("Roles: %v\n", claims.Roles)
//
// Example (HTTP middleware):
//
//	func authMiddleware(next http.Handler) http.Handler {
//	    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
//	        authHeader := r.Header.Get("Authorization")
//	        if authHeader == "" {
//	            http.Error(w, "missing authorization", http.StatusUnauthorized)
//	            return
//	        }
//
//	        token := strings.TrimPrefix(authHeader, "Bearer ")
//	        claims, err := maker.VerifyAccessToken(r.Context(), token)
//	        if err != nil {
//	            http.Error(w, "invalid token", http.StatusUnauthorized)
//	            return
//	        }
//
//	        // Add claims to context
//	        ctx := context.WithValue(r.Context(), "user_claims", claims)
//	        next.ServeHTTP(w, r.WithContext(ctx))
//	    })
//	}
func (maker *JWTMaker) VerifyAccessToken(ctx context.Context, tokenString string) (*AccessTokenClaims, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context canceled: %w", err)
	}

	if maker.config.RevocationEnabled && maker.tokenRepo != nil {
		revoked, err := maker.tokenRepo.IsTokenRevoked(ctx, AccessToken, tokenString)
		if err != nil {
			return nil, fmt.Errorf("failed to check token revocation: %w", err)
		}
		if revoked {
			return nil, fmt.Errorf("token has been revoked")
		}
	}

	// Verify token signature and basic structure
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Check context during parsing
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("context canceled during parsing: %w", err)
		}

		if token.Method.Alg() != maker.signingMethod.Alg() {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return maker.publicKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("invalid token: %v", err)
	}

	// Check context before claims processing
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context canceled during claims processing: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token claims")
	}

	if err := validateTokenClaims(claims, AccessToken, maker.config.RequiredClaims); err != nil {
		return nil, err
	}

	accessClaims, err := mapToAccessClaims(claims)
	if err != nil {
		return nil, err
	}

	if _, ok := claims["rls"]; !ok {
		return nil, fmt.Errorf("missing roles claim in access token")
	}

	return accessClaims, nil
}

// VerifyRefreshToken validates a refresh token and returns its claims if valid.
// Performs comprehensive security checks including signature, expiration, revocation, and rotation.
//
// Validation Steps:
//  1. Check context cancellation
//  2. Check revocation status (if RevocationEnabled)
//  3. Check rotation status (if RotationEnabled)
//  4. Verify cryptographic signature
//  5. Validate token structure and algorithm
//  6. Check all timestamps (iat, exp, nbf, mle)
//  7. Verify required claims are present
//  8. Validate token type is "refresh"
//  9. Parse and return claims
//
// Checks Performed:
//   - Signature matches expected algorithm
//   - Token has not expired (exp > now)
//   - Token is not used before valid time (nbf <= now)
//   - Token has not exceeded maximum lifetime (mle > now)
//   - Token has not been revoked (if revocation enabled)
//   - Token has not been rotated (if rotation enabled)
//   - All required claims are present
//   - Token type is "refresh" (not "access")
//
// Parameters:
//   - ctx: Context for cancellation
//   - tokenString: The JWT refresh token string to verify
//
// Returns:
//   - *RefreshTokenClaims: Parsed and validated token claims
//   - error: If token is invalid, expired, revoked, rotated, or any validation check fails
//
// Error Scenarios:
//   - Invalid signature: Token has been tampered with
//   - Expired: Token lifetime has ended
//   - Revoked: Token was explicitly invalidated
//   - Rotated: Token has been used to obtain a new token (rotation enabled)
//   - Wrong type: Access token used where refresh token expected
//   - Missing claims: Token structure is incomplete
//   - Context cancelled: Operation was cancelled
//
// Use Cases:
//   - Validating refresh token before rotation
//   - Checking refresh token validity before issuing new access token
//   - Verifying refresh token in logout operations
//
// Example (Refresh access token):
//
//	// Verify the refresh token
//	refreshClaims, err := maker.VerifyRefreshToken(ctx, refreshTokenString)
//	if err != nil {
//	    return nil, fmt.Errorf("invalid refresh token: %w", err)
//	}
//
//	// Create new access token with same user/session
//	newAccessToken, err := maker.CreateAccessToken(
//	    ctx,
//	    refreshClaims.Subject,
//	    refreshClaims.Username,
//	    []string{"user"}, // Load roles from database
//	    refreshClaims.SessionID,
//	)
//
// Example (With rotation):
//
//	// Automatically rotates the token if rotation is enabled
//	newRefreshToken, err := maker.RotateRefreshToken(ctx, oldRefreshTokenString)
//	if err != nil {
//	    return fmt.Errorf("rotation failed: %w", err)
//	}
//
//	// Old token is now invalid, use new token
func (maker *JWTMaker) VerifyRefreshToken(ctx context.Context, tokenString string) (*RefreshTokenClaims, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context canceled: %w", err)
	}

	if maker.config.RevocationEnabled && maker.tokenRepo != nil {
		revoked, err := maker.tokenRepo.IsTokenRevoked(ctx, RefreshToken, tokenString)
		if err != nil {
			return nil, fmt.Errorf("failed to check token revocation: %w", err)
		}
		if revoked {
			return nil, fmt.Errorf("token has been revoked")
		}
	}

	if maker.config.RotationEnabled && maker.tokenRepo != nil {
		rotated, err := maker.tokenRepo.IsTokenRotated(ctx, tokenString)
		if err != nil {
			return nil, fmt.Errorf("failed to check token rotation: %w", err)
		}
		if rotated {
			return nil, fmt.Errorf("token has been rotated and is no longer valid")
		}
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Check context during parsing
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("context canceled during parsing: %w", err)
		}

		if token.Method.Alg() != maker.signingMethod.Alg() {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return maker.publicKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("invalid token: %v", err)
	}

	// Check context before claims processing
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context canceled during claims processing: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token claims")
	}

	if err := validateTokenClaims(claims, RefreshToken, maker.config.RequiredClaims); err != nil {
		return nil, err
	}

	return mapToRefreshClaims(claims)
}

// RevokeAccessToken marks an access token as revoked, preventing its further use.
// The token will fail verification even if it hasn't expired yet.
// Requires RevocationEnabled to be true in the configuration.
//
// Revocation Process:
//  1. Parses the token to extract expiration time
//  2. Calculates time-to-live (TTL) until natural expiration
//  3. Stores token hash in repository with TTL
//  4. Token verification will now fail for this token
//  5. Token is automatically removed from storage after TTL expires
//
// Storage Considerations:
//   - Tokens are stored with TTL matching their remaining lifetime
//   - After natural expiration, revoked tokens are cleaned up
//   - Only the token hash is stored (not the full token)
//   - Cleanup runs automatically at CleanupInterval
//
// Parameters:
//   - ctx: Context for cancellation and timeout
//   - token: The JWT token string to revoke
//
// Returns:
//   - error: If revocation is disabled, token is invalid, repository operation fails,
//     or context is cancelled
//
// Use Cases:
//   - User logout (revoke current access token)
//   - Security breach (revoke compromised token)
//   - Administrative action (revoke specific user's tokens)
//   - Password change (revoke all existing tokens)
//
// Limitations:
//   - Requires RevocationEnabled = true
//   - Requires TokenRepository
//   - Adds latency to token verification (repository lookup)
//   - Requires distributed storage for multi-instance systems
//
// Example (Logout - revoke access token):
//
//	err := maker.RevokeAccessToken(ctx, accessTokenString)
//	if err != nil {
//	    return fmt.Errorf("failed to revoke token: %w", err)
//	}
//
//	// Token is now invalid and will fail verification
//	fmt.Println("User logged out successfully")
//
// Example (Revoke all session tokens):
//
//	// Get all tokens for a session from your database
//	tokens, err := db.GetSessionTokens(ctx, sessionID)
//	if err != nil {
//	    return err
//	}
//
//	// Revoke each token
//	for _, token := range tokens {
//	    if err := maker.RevokeAccessToken(ctx, token); err != nil {
//	        log.Printf("Failed to revoke token: %v", err)
//	    }
//	}
//
// Example (Security breach response):
//
//	// Revoke access token immediately
//	if err := maker.RevokeAccessToken(ctx, compromisedToken); err != nil {
//	    log.Printf("Failed to revoke compromised token: %v", err)
//	}
//
//	// Also revoke refresh token to prevent new access tokens
//	if err := maker.RevokeRefreshToken(ctx, refreshToken); err != nil {
//	    log.Printf("Failed to revoke refresh token: %v", err)
//	}
func (maker *JWTMaker) RevokeAccessToken(ctx context.Context, token string) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("context canceled: %w", err)
	}

	if !maker.config.RevocationEnabled || maker.tokenRepo == nil {
		return fmt.Errorf("access token revocation is not enabled")
	}

	// Parse the token to extract expiration time
	parsed, err := jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		// Check context during parsing
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("context canceled during parsing: %w", err)
		}
		return maker.publicKey, nil
	})
	if err != nil || !parsed.Valid {
		return fmt.Errorf("invalid token: %w", err)
	}

	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return fmt.Errorf("invalid token claims")
	}

	exp := getUnixTime(claims["exp"])
	if exp == 0 {
		return fmt.Errorf("token missing exp claim")
	}
	ttl := time.Until(time.Unix(exp, 0))

	// Check context before database operation
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("context canceled before revocation: %w", err)
	}

	return maker.tokenRepo.MarkTokenRevoke(ctx, AccessToken, token, ttl)
}

// RevokeRefreshToken marks a refresh token as revoked, preventing its further use.
// The token cannot be used to obtain new access tokens after revocation.
// Requires RevocationEnabled to be true in the configuration.
//
// Revocation Process:
//  1. Parses the token to extract expiration time
//  2. Calculates time-to-live (TTL) until natural expiration
//  3. Stores token hash in repository with TTL
//  4. Token verification will now fail for this token
//  5. Token is automatically removed from storage after TTL expires
//
// Impact:
//   - Prevents token from being used in RotateRefreshToken
//   - Prevents token from being verified successfully
//   - Existing access tokens remain valid until they expire
//   - User must re-authenticate to get new refresh token
//
// Parameters:
//   - ctx: Context for cancellation and timeout
//   - token: The JWT refresh token string to revoke
//
// Returns:
//   - error: If revocation is disabled, token is invalid, repository operation fails,
//     or context is cancelled
//
// Use Cases:
//   - User logout (revoke refresh token to prevent new access tokens)
//   - Forced re-authentication (after password change)
//   - Security incident response
//   - Session termination
//
// Best Practices:
//   - Always revoke both access and refresh tokens during logout
//   - Revoke refresh tokens after password changes
//   - Monitor failed verification attempts (may indicate stolen tokens)
//   - Use short-lived refresh tokens if revocation is disabled
//
// Example (Complete logout):
//
//	// Revoke both access and refresh tokens
//	if err := maker.RevokeAccessToken(ctx, accessToken); err != nil {
//	    log.Printf("Failed to revoke access token: %v", err)
//	}
//
//	if err := maker.RevokeRefreshToken(ctx, refreshToken); err != nil {
//	    return fmt.Errorf("failed to revoke refresh token: %w", err)
//	}
//
//	fmt.Println("Logged out successfully")
//
// Example (Password change - revoke all user tokens):
//
//	// Get all refresh tokens for user
//	tokens, err := db.GetUserRefreshTokens(ctx, userID)
//	if err != nil {
//	    return err
//	}
//
//	// Revoke each refresh token
//	for _, token := range tokens {
//	    if err := maker.RevokeRefreshToken(ctx, token); err != nil {
//	        log.Printf("Failed to revoke token: %v", err)
//	    }
//	}
//
//	// User must re-authenticate on all devices
func (maker *JWTMaker) RevokeRefreshToken(ctx context.Context, token string) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("context canceled: %w", err)
	}

	if !maker.config.RevocationEnabled || maker.tokenRepo == nil {
		return fmt.Errorf("refresh token revocation is not enabled")
	}

	parsed, err := jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		// Check context during parsing
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("context canceled during parsing: %w", err)
		}
		return maker.publicKey, nil
	})
	if err != nil || !parsed.Valid {
		return fmt.Errorf("invalid token: %w", err)
	}

	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return fmt.Errorf("invalid token claims")
	}

	exp := getUnixTime(claims["exp"])
	if exp == 0 {
		return fmt.Errorf("token missing exp claim")
	}
	ttl := time.Until(time.Unix(exp, 0))

	// Check context before database operation
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("context canceled before revocation: %w", err)
	}

	return maker.tokenRepo.MarkTokenRevoke(ctx, RefreshToken, token, ttl)
}

// RotateRefreshToken exchanges an old refresh token for a new one with extended expiration.
// The old token is atomically marked as rotated and cannot be reused, preventing token theft.
// Requires RotationEnabled to be true in the configuration.
//
// Rotation Process:
//  1. Verifies the old token is valid (signature, expiration, not revoked/rotated)
//  2. Atomically marks the old token as rotated using compare-and-swap
//  3. If already rotated (by another request), returns error
//  4. Creates a new refresh token with the same user and session
//  5. Returns the new token with fresh expiration time
//
// Atomicity Guarantee:
//
//	Uses MarkTokenRotatedAtomic to ensure only ONE concurrent request succeeds.
//	If multiple requests attempt to rotate the same token simultaneously, only the first
//	succeeds and others receive an error. This detects token theft attempts.
//
// Security Benefits:
//   - Prevents token reuse attacks
//   - Detects concurrent rotation attempts (possible token theft)
//   - Limits blast radius of compromised tokens
//   - Enforces one-time use of refresh tokens
//
// Parameters:
//   - ctx: Context for cancellation and timeout
//   - oldToken: The current refresh token to rotate (will be invalidated)
//
// Returns:
//   - *RefreshTokenResponse: New refresh token with extended expiration
//   - error: If rotation is disabled, old token is invalid/already rotated,
//     atomic operation fails, or context is cancelled
//
// Error Scenarios:
//   - Token already rotated: Possible replay attack, invalidate session
//   - Token invalid/expired: Require re-authentication
//   - Rotation disabled: Feature not configured
//   - Repository error: Storage system unavailable
//
// Security Implications:
//
//	If rotation fails due to "already rotated":
//	- Indicates possible token theft
//	- Consider invalidating the entire session
//	- Alert security monitoring systems
//	- Require full re-authentication
//
// Example (Token refresh endpoint):
//
//	func refreshTokenHandler(w http.ResponseWriter, r *http.Request) {
//	    // Get refresh token from cookie or body
//	    oldToken := r.Header.Get("X-Refresh-Token")
//
//	    // Rotate the token
//	    newRefresh, err := maker.RotateRefreshToken(r.Context(), oldToken)
//	    if err != nil {
//	        if strings.Contains(err.Error(), "rotated") {
//	            // Possible token theft detected
//	            log.Printf("Token reuse detected for token: %v", err)
//	            http.Error(w, "security violation", http.StatusForbidden)
//	            return
//	        }
//	        http.Error(w, "invalid token", http.StatusUnauthorized)
//	        return
//	    }
//
//	    // Create new access token
//	    claims, _ := maker.VerifyRefreshToken(r.Context(), newRefresh.Token)
//	    accessToken, err := maker.CreateAccessToken(
//	        r.Context(),
//	        claims.Subject,
//	        claims.Username,
//	        getUserRoles(claims.Subject), // Load from DB
//	        claims.SessionID,
//	    )
//
//	    // Return new token pair
//	    json.NewEncoder(w).Encode(map[string]string{
//	        "access_token":  accessToken.Token,
//	        "refresh_token": newRefresh.Token,
//	    })
//	}
//
// Example (With security monitoring):
//
//	newToken, err := maker.RotateRefreshToken(ctx, oldToken)
//	if err != nil {
//	    if strings.Contains(err.Error(), "rotated") {
//	        // Token theft detected
//	        securityLog.Alert("Token reuse attempt detected", map[string]interface{}{
//	            "token_prefix": oldToken[:10],
//	            "ip_address":   clientIP,
//	            "timestamp":    time.Now(),
//	        })
//
//	        // Revoke all user tokens
//	        revokeAllUserTokens(ctx, userID)
//	        return nil, fmt.Errorf("security violation: session terminated")
//	    }
//	    return nil, err
//	}
//
// Example (Race condition handling):
//
//	// Multiple concurrent requests with same token
//	var wg sync.WaitGroup
//	results := make(chan error, 3)
//
//	for i := 0; i < 3; i++ {
//	    wg.Add(1)
//	    go func() {
//	        defer wg.Done()
//	        _, err := maker.RotateRefreshToken(ctx, sameToken)
//	        results <- err
//	    }()
//	}
//
//	wg.Wait()
//	close(results)
//
//	// Only one should succeed, others should get "already rotated" error
//	successCount := 0
//	for err := range results {
//	    if err == nil {
//	        successCount++
//	    }
//	}
//	// successCount should be exactly 1
func (maker *JWTMaker) RotateRefreshToken(ctx context.Context, oldToken string) (*RefreshTokenResponse, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context canceled: %w", err)
	}

	if !maker.config.RotationEnabled {
		return nil, fmt.Errorf("token rotation not enabled")
	}

	claims, err := maker.VerifyRefreshToken(ctx, oldToken)
	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	// Check context before database operations
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context canceled before rotation check: %w", err)
	}

	// ATOMIC OPERATION: Only one goroutine will succeed here
	marked, err := maker.tokenRepo.MarkTokenRotatedAtomic(ctx, oldToken, maker.config.RefreshMaxLifetimeExpiry)
	if err != nil {
		return nil, fmt.Errorf("repository error: %w", err)
	}

	if !marked {
		// Token was already rotated by another goroutine
		return nil, fmt.Errorf("token has been rotated")
	}

	// Check context before creating new token
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context canceled before creating new token: %w", err)
	}

	newToken, err := maker.CreateRefreshToken(ctx, claims.Subject, claims.Username, claims.SessionID)
	if err != nil {
		return nil, err
	}

	return newToken, nil
}

// cleanupRotatedTokens is a background goroutine that periodically removes expired rotation markers.
// Runs automatically when RotationEnabled is true and stops when the context is cancelled.
//
// Purpose:
//   - Prevents memory/storage leaks from accumulated rotation markers
//   - Removes entries for tokens that have naturally expired
//   - Maintains repository performance over time
//
// Behavior:
//   - Runs at intervals specified by config.CleanupInterval
//   - Each cleanup has a 30-second timeout
//   - Continues running until context cancellation
//   - Logs errors but continues operation
//
// Parameters:
//   - ctx: Context for cancellation (cancelled when maker is garbage collected)
//
// Notes:
//   - Started automatically by NewGourdianTokenMaker
//   - Should not be called directly
//   - Errors are logged to stdout (implement custom logging as needed)
func (maker *JWTMaker) cleanupRotatedTokens(ctx context.Context) {
	ticker := time.NewTicker(maker.config.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if maker.tokenRepo == nil {
				continue
			}

			// Create a timeout context for cleanup operation
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			if err := maker.tokenRepo.CleanupExpiredRotatedTokens(cleanupCtx); err != nil {
				fmt.Printf("Error cleaning up rotated tokens: %v\n", err)
			}
			cancel()
		}
	}
}

// cleanupRevokedTokens is a background goroutine that periodically removes expired revoked tokens.
// Runs automatically when RevocationEnabled is true and stops when the context is cancelled.
//
// Purpose:
//   - Prevents memory/storage leaks from accumulated revoked tokens
//   - Removes entries for tokens that have naturally expired
//   - Maintains repository performance over time
//
// Behavior:
//   - Runs at intervals specified by config.CleanupInterval
//   - Cleans up both access and refresh tokens
//   - Each cleanup has a 30-second timeout
//   - Continues running until context cancellation
//   - Logs errors but continues operation
//
// Parameters:
//   - ctx: Context for cancellation (cancelled when maker is garbage collected)
//
// Notes:
//   - Started automatically by NewGourdianTokenMaker
//   - Should not be called directly
//   - Errors are logged to stdout (implement custom logging as needed)
func (maker *JWTMaker) cleanupRevokedTokens(ctx context.Context) {
	ticker := time.NewTicker(maker.config.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if maker.tokenRepo == nil {
				continue
			}

			for _, tokenType := range []TokenType{AccessToken, RefreshToken} {
				// Create a timeout context for cleanup operation
				cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				if err := maker.tokenRepo.CleanupExpiredRevokedTokens(cleanupCtx, tokenType); err != nil {
					fmt.Printf("Error cleaning up revoked %s tokens: %v\n", tokenType, err)
				}
				cancel()
			}
		}
	}
}

// initializeSigningMethod sets up the JWT signing algorithm based on configuration.
// Validates that the algorithm is in the allowed list and creates the signing method instance.
//
// Supported Algorithms:
//   - HMAC: HS256, HS384, HS512 (symmetric)
//   - RSA: RS256, RS384, RS512 (asymmetric)
//   - RSA-PSS: PS256, PS384, PS512 (asymmetric, recommended)
//   - ECDSA: ES256, ES384, ES512 (asymmetric)
//   - EdDSA: EdDSA (asymmetric, modern)
//
// Security:
//   - "none" algorithm is explicitly rejected for security
//   - Validates algorithm is in AllowedAlgorithms list
//   - Ensures algorithm matches the signing method type
//
// Returns:
//   - error: If algorithm is unsupported, not allowed, or insecure
//
// Notes:
//   - Called internally during initialization
//   - Should not be called directly by users
func (maker *JWTMaker) initializeSigningMethod() error {
	if len(maker.config.AllowedAlgorithms) > 0 {
		allowed := false
		for _, alg := range maker.config.AllowedAlgorithms {
			if alg == maker.config.Algorithm {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("configured algorithm %s not in allowed algorithms list",
				maker.config.Algorithm)
		}
	}

	switch maker.config.Algorithm {
	case "HS256":
		maker.signingMethod = jwt.SigningMethodHS256
	case "HS384":
		maker.signingMethod = jwt.SigningMethodHS384
	case "HS512":
		maker.signingMethod = jwt.SigningMethodHS512
	case "RS256":
		maker.signingMethod = jwt.SigningMethodRS256
	case "RS384":
		maker.signingMethod = jwt.SigningMethodRS384
	case "RS512":
		maker.signingMethod = jwt.SigningMethodRS512
	case "PS256":
		maker.signingMethod = jwt.SigningMethodPS256
	case "PS384":
		maker.signingMethod = jwt.SigningMethodPS384
	case "PS512":
		maker.signingMethod = jwt.SigningMethodPS512
	case "ES256":
		maker.signingMethod = jwt.SigningMethodES256
	case "ES384":
		maker.signingMethod = jwt.SigningMethodES384
	case "ES512":
		maker.signingMethod = jwt.SigningMethodES512
	case "EdDSA":
		maker.signingMethod = jwt.SigningMethodEdDSA
	case "none":
		return fmt.Errorf("unsecured tokens are disabled for security reasons")
	default:
		return fmt.Errorf("unsupported algorithm: %s", maker.config.Algorithm)
	}

	return nil
}

// initializeKeys loads and validates cryptographic keys based on the signing method.
// For symmetric signing, uses the configured secret key.
// For asymmetric signing, loads keys from PEM files.
//
// Symmetric Key Handling:
//   - Uses SymmetricKey for both signing and verification
//   - Key is used as-is (ensure it's properly secured)
//
// Asymmetric Key Handling:
//   - Loads private key from PrivateKeyPath (for signing)
//   - Loads public key from PublicKeyPath (for verification)
//   - Supports multiple PEM formats (PKCS1, PKCS8, SEC1)
//   - Validates key types match the algorithm
//
// Supported Key Types:
//   - RSA: 2048-bit minimum recommended
//   - ECDSA: P-256, P-384, P-521 curves
//   - EdDSA: Ed25519 keys
//
// Returns:
//   - error: If keys cannot be loaded, are invalid, or don't match the algorithm
//
// Notes:
//   - Called internally during initialization
//   - Private key files should have 0600 permissions
//   - Public keys can be distributed for token verification
func (maker *JWTMaker) initializeKeys() error {
	switch maker.config.SigningMethod {
	case Symmetric:
		maker.privateKey = []byte(maker.config.SymmetricKey)
		maker.publicKey = []byte(maker.config.SymmetricKey)
		return nil
	case Asymmetric:
		return maker.parseKeyPair()
	default:
		return fmt.Errorf("unsupported signing method: %s", maker.config.SigningMethod)
	}
}

// parseKeyPair loads and parses asymmetric key pairs from PEM files.
// Handles RSA, ECDSA, and EdDSA key types with multiple encoding formats.
//
// Supported Private Key Formats:
//   - PKCS#1 (RSA only)
//   - PKCS#8 (all key types)
//   - SEC1 (ECDSA only)
//
// Supported Public Key Formats:
//   - PKIX (SubjectPublicKeyInfo)
//   - X.509 certificates (extracts public key)
//
// Algorithm Detection:
//   - Uses maker.signingMethod.Alg() to determine expected key type
//   - Validates loaded keys match the algorithm
//
// Returns:
//   - error: If files cannot be read, keys cannot be parsed, or key types don't match
//
// Notes:
//   - Called by initializeKeys for asymmetric signing
//   - Automatically detects key format from PEM structure
func (maker *JWTMaker) parseKeyPair() error {
	privateKeyBytes, err := os.ReadFile(maker.config.PrivateKeyPath)
	if err != nil {
		return fmt.Errorf("failed to read private key file: %w", err)
	}

	publicKeyBytes, err := os.ReadFile(maker.config.PublicKeyPath)
	if err != nil {
		return fmt.Errorf("failed to read public key file: %w", err)
	}

	switch maker.signingMethod.Alg() {
	case "RS256", "RS384", "RS512", "PS256", "PS384", "PS512":
		maker.privateKey, err = parseRSAPrivateKey(privateKeyBytes)
		if err != nil {
			return fmt.Errorf("failed to parse RSA private key: %w", err)
		}
		maker.publicKey, err = parseRSAPublicKey(publicKeyBytes)
		if err != nil {
			return fmt.Errorf("failed to parse RSA public key: %w", err)
		}
	case "ES256", "ES384", "ES512":
		maker.privateKey, err = parseECDSAPrivateKey(privateKeyBytes)
		if err != nil {
			return fmt.Errorf("failed to parse ECDSA private key: %w", err)
		}
		maker.publicKey, err = parseECDSAPublicKey(publicKeyBytes)
		if err != nil {
			return fmt.Errorf("failed to parse ECDSA public key: %w", err)
		}
	case "EdDSA":
		maker.privateKey, err = parseEdDSAPrivateKey(privateKeyBytes)
		if err != nil {
			return fmt.Errorf("failed to parse EdDSA private key: %w", err)
		}
		maker.publicKey, err = parseEdDSAPublicKey(publicKeyBytes)
		if err != nil {
			return fmt.Errorf("failed to parse EdDSA public key: %w", err)
		}
	default:
		return fmt.Errorf("unsupported algorithm for asymmetric signing: %s", maker.signingMethod.Alg())
	}

	return nil
}

// hashToken creates a SHA-256 hash of the token for secure storage.
// Used internally to avoid storing full JWTs in the repository.
//
// Benefits:
//   - Reduces storage size (256 bits vs full JWT)
//   - Protects against token leakage from storage
//   - Enables efficient lookups with fixed-size keys
//
// Parameters:
//   - token: The JWT token string to hash
//
// Returns:
//   - string: Hexadecimal representation of SHA-256 hash
//
// Example Output:
//
//	"a3c5b7f9e2d4..." (64 hexadecimal characters)
//
// Notes:
//   - Used internally by revocation and rotation operations
//   - Hash is deterministic (same token = same hash)
//   - Collision probability is negligible (2^256 space)
func hashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

// validateConfig performs comprehensive validation of the token maker configuration.
// Checks all parameters for security, consistency, and logical correctness.
//
// Validation Checks:
//   - Signing method compatibility (symmetric vs asymmetric)
//   - Algorithm matches signing method
//   - Required parameters are provided
//   - Key/file paths are correct for signing method
//   - Duration values are positive and logical
//   - File permissions are secure (0600 for private keys)
//   - Algorithms are not weak (rejects "none")
//   - Cleanup interval is reasonable (>= 1 minute)
//
// Symmetric Signing Validation:
//   - SymmetricKey must be provided and >= 32 bytes
//   - Algorithm must be HS256, HS384, or HS512
//   - Private/public key paths must be empty
//
// Asymmetric Signing Validation:
//   - PrivateKeyPath and PublicKeyPath must be provided
//   - Algorithm must be RS*, ES*, PS*, or EdDSA
//   - SymmetricKey must be empty
//   - Key files must exist with secure permissions
//
// Duration Validation:
//   - All durations must be positive
//   - AccessExpiryDuration <= AccessMaxLifetimeExpiry
//   - RefreshExpiryDuration <= RefreshMaxLifetimeExpiry
//   - CleanupInterval >= 1 minute
//
// Parameters:
//   - config: The configuration to validate
//
// Returns:
//   - error: Detailed error describing the validation failure, or nil if valid
//
// Notes:
//   - Called automatically during initialization
//   - Returns first validation error encountered
func validateConfig(config *GourdianTokenConfig) error {
	switch config.SigningMethod {
	case Symmetric:
		if config.SymmetricKey == "" {
			return fmt.Errorf("symmetric key is required for symmetric signing method")
		}
		if !strings.HasPrefix(config.Algorithm, "HS") && config.Algorithm != "none" {
			return fmt.Errorf("algorithm %s not compatible with symmetric signing", config.Algorithm)
		}
		if len(config.SymmetricKey) < 32 {
			return fmt.Errorf("symmetric key must be at least 32 bytes")
		}
		if config.PrivateKeyPath != "" || config.PublicKeyPath != "" {
			return fmt.Errorf("private and public key paths must be empty for symmetric signing")
		}
	case Asymmetric:
		if config.PrivateKeyPath == "" || config.PublicKeyPath == "" {
			return fmt.Errorf("private and public key paths are required for asymmetric signing method")
		}
		if config.SymmetricKey != "" {
			return fmt.Errorf("symmetric key must be empty for asymmetric signing")
		}
		if !strings.HasPrefix(config.Algorithm, "RS") &&
			!strings.HasPrefix(config.Algorithm, "ES") &&
			!strings.HasPrefix(config.Algorithm, "PS") &&
			config.Algorithm != "EdDSA" {
			return fmt.Errorf("algorithm %s not compatible with asymmetric signing", config.Algorithm)
		}
		if err := checkFilePermissions(config.PrivateKeyPath, 0600); err != nil {
			return fmt.Errorf("insecure private key file permissions: %w", err)
		}
		if err := checkFilePermissions(config.PublicKeyPath, 0600); err != nil {
			return fmt.Errorf("insecure public key file permissions: %w", err)
		}
	default:
		return fmt.Errorf("unsupported signing method: %s, supports %s and %s",
			config.SigningMethod, Symmetric, Asymmetric)
	}

	if config.AccessExpiryDuration <= 0 {
		return fmt.Errorf("access token duration must be positive")
	}
	if config.AccessMaxLifetimeExpiry > 0 &&
		config.AccessExpiryDuration > config.AccessMaxLifetimeExpiry {
		return fmt.Errorf("access token duration exceeds max lifetime")
	}

	if config.RefreshExpiryDuration <= 0 {
		return fmt.Errorf("refresh token duration must be positive")
	}
	if config.RefreshMaxLifetimeExpiry > 0 &&
		config.RefreshExpiryDuration > config.RefreshMaxLifetimeExpiry {
		return fmt.Errorf("refresh token duration exceeds max lifetime")
	}

	if config.RefreshReuseInterval < 0 {
		return fmt.Errorf("refresh reuse interval cannot be negative")
	}

	// Validate CleanupInterval
	if config.CleanupInterval <= 0 {
		return fmt.Errorf("cleanup interval must be positive (e.g., 1h, 30m)")
	}
	if config.CleanupInterval < 1*time.Minute {
		return fmt.Errorf("cleanup interval too short: minimum 1 minute recommended")
	}

	// Reject weak algorithms
	weakAlgorithms := map[string]bool{
		"HS256": false,
		"none":  true,
	}
	if weak, ok := weakAlgorithms[config.Algorithm]; ok && weak {
		return fmt.Errorf("algorithm %s is too weak for production use", config.Algorithm)
	}

	if len(config.AllowedAlgorithms) > 0 {
		supportedAlgs := map[string]bool{
			"HS256": true, "HS384": true, "HS512": true,
			"RS256": true, "RS384": true, "RS512": true,
			"ES256": true, "ES384": true, "ES512": true,
			"PS256": true, "PS384": true, "PS512": true,
			"EdDSA": true,
		}

		for _, alg := range config.AllowedAlgorithms {
			if !supportedAlgs[alg] {
				return fmt.Errorf("unsupported algorithm in AllowedAlgorithms: %s", alg)
			}
		}
	}

	return nil
}

// validateAlgorithmAndMethod ensures the algorithm is compatible with the signing method.
// Prevents misconfigurations like using HS256 with asymmetric mode.
//
// Valid Combinations:
//   - Symmetric: HS256, HS384, HS512
//   - Asymmetric: RS256/384/512, ES256/384/512, PS256/384/512, EdDSA
//
// Parameters:
//   - config: The configuration to validate
//
// Returns:
//   - error: If algorithm and method are incompatible
//
// Example Errors:
//   - "algorithm HS256 not compatible with asymmetric signing"
//   - "algorithm RS256 not compatible with symmetric signing"
func validateAlgorithmAndMethod(config *GourdianTokenConfig) error {
	switch config.SigningMethod {
	case Symmetric:
		if !strings.HasPrefix(config.Algorithm, "HS") {
			return fmt.Errorf("algorithm %s not compatible with symmetric signing", config.Algorithm)
		}
	case Asymmetric:
		if !strings.HasPrefix(config.Algorithm, "RS") &&
			!strings.HasPrefix(config.Algorithm, "ES") &&
			!strings.HasPrefix(config.Algorithm, "PS") &&
			config.Algorithm != "EdDSA" {
			return fmt.Errorf("algorithm %s not compatible with asymmetric signing", config.Algorithm)
		}
	}
	return nil
}

// toMapClaims converts strongly-typed claims structures to JWT MapClaims.
// Handles both AccessTokenClaims and RefreshTokenClaims.
//
// Conversions:
//   - UUIDs → strings
//   - Time → Unix timestamps (int64)
//   - TokenType → string
//   - Arrays remain as-is
//
// Optional Claims:
//   - NotBefore (nbf) only included if not zero
//   - MaxLifetimeExpiry (mle) only included if not zero
//
// Parameters:
//   - claims: Either AccessTokenClaims or RefreshTokenClaims
//
// Returns:
//   - jwt.MapClaims: Map suitable for JWT encoding
//
// Panics:
//   - If claims type is not AccessTokenClaims or RefreshTokenClaims
//   - If AccessTokenClaims has empty Roles array
//
// Notes:
//   - Used internally during token creation
//   - Should not be called directly by users
func toMapClaims(claims interface{}) jwt.MapClaims {
	switch v := claims.(type) {
	case AccessTokenClaims:
		if len(v.Roles) == 0 {
			panic("at least one role must be provided")
		}
		mapClaims := jwt.MapClaims{
			"jti": v.ID.String(),
			"sub": v.Subject.String(),
			"usr": v.Username,
			"sid": v.SessionID.String(),
			"iss": v.Issuer,
			"aud": v.Audience,
			"iat": v.IssuedAt.Unix(),
			"exp": v.ExpiresAt.Unix(),
			"typ": string(v.TokenType),
			"rls": v.Roles,
		}
		if !v.NotBefore.IsZero() {
			mapClaims["nbf"] = v.NotBefore.Unix()
		}
		if !v.MaxLifetimeExpiry.IsZero() {
			mapClaims["mle"] = v.MaxLifetimeExpiry.Unix()
		}
		return mapClaims
	case RefreshTokenClaims:
		mapClaims := jwt.MapClaims{
			"jti": v.ID.String(),
			"sub": v.Subject.String(),
			"usr": v.Username,
			"sid": v.SessionID.String(),
			"iss": v.Issuer,
			"aud": v.Audience,
			"iat": v.IssuedAt.Unix(),
			"exp": v.ExpiresAt.Unix(),
			"typ": string(v.TokenType),
		}
		if !v.NotBefore.IsZero() {
			mapClaims["nbf"] = v.NotBefore.Unix()
		}
		if !v.MaxLifetimeExpiry.IsZero() {
			mapClaims["mle"] = v.MaxLifetimeExpiry.Unix()
		}
		return mapClaims
	default:
		panic(fmt.Sprintf("unsupported claims type: %T", claims))
	}
}

// mapToAccessClaims converts JWT MapClaims to strongly-typed AccessTokenClaims.
// Performs type checking and validation of all fields.
//
// Conversions:
//   - String UUIDs → uuid.UUID
//   - Unix timestamps → time.Time
//   - String token type → TokenType
//   - Interface arrays → string arrays
//
// Validation:
//   - All UUIDs must be valid
//   - Roles must be non-empty array of strings
//   - Timestamps must be valid numbers
//   - Required fields must be present
//
// Parameters:
//   - claims: JWT MapClaims from parsed token
//
// Returns:
//   - *AccessTokenClaims: Strongly-typed claims structure
//   - error: If any field is invalid or missing
//
// Notes:
//   - Used internally during token verification
//   - Handles various JSON number types (float64, int, json.Number)
func mapToAccessClaims(claims jwt.MapClaims) (*AccessTokenClaims, error) {
	jti, ok := claims["jti"].(string)
	if !ok {
		return nil, fmt.Errorf("invalid token ID type: expected string")
	}
	tokenID, err := uuid.Parse(jti)
	if err != nil {
		return nil, fmt.Errorf("invalid token ID: %w", err)
	}

	sub, ok := claims["sub"].(string)
	if !ok {
		return nil, fmt.Errorf("invalid user ID type: expected string")
	}
	userID, err := uuid.Parse(sub)
	if err != nil {
		return nil, fmt.Errorf("invalid user ID: %w", err)
	}

	sid, ok := claims["sid"].(string)
	if !ok {
		return nil, fmt.Errorf("invalid session ID type: expected string")
	}
	sessionID, err := uuid.Parse(sid)
	if err != nil {
		return nil, fmt.Errorf("invalid session ID: %w", err)
	}

	username, ok := claims["usr"].(string)
	if !ok {
		return nil, fmt.Errorf("invalid username type: expected string")
	}

	issuer, _ := claims["iss"].(string)

	var audience []string
	if aud, ok := claims["aud"]; ok {
		switch v := aud.(type) {
		case string:
			audience = []string{v}
		case []interface{}:
			audience = make([]string, 0, len(v))
			for _, a := range v {
				if aStr, ok := a.(string); ok {
					audience = append(audience, aStr)
				}
			}
		case []string:
			audience = v
		}
	}

	rolesInterface, ok := claims["rls"]
	if !ok {
		return nil, fmt.Errorf("missing roles claim")
	}

	var roles []string
	switch v := rolesInterface.(type) {
	case []interface{}:
		roles = make([]string, 0, len(v))
		for _, r := range v {
			role, ok := r.(string)
			if !ok {
				return nil, fmt.Errorf("invalid role type: expected string")
			}
			roles = append(roles, role)
		}
	case []string:
		roles = v
	default:
		return nil, fmt.Errorf("invalid roles type: expected array of strings")
	}

	if len(roles) == 0 {
		return nil, fmt.Errorf("at least one role must be provided")
	}

	typ, ok := claims["typ"].(string)
	if !ok {
		return nil, fmt.Errorf("invalid token type: expected string")
	}

	iat := getUnixTime(claims["iat"])
	exp := getUnixTime(claims["exp"])
	nbf := getUnixTime(claims["nbf"])
	mle := getUnixTime(claims["mle"])

	if iat == 0 || exp == 0 {
		return nil, fmt.Errorf("invalid timestamp format")
	}

	accessClaims := &AccessTokenClaims{
		ID:        tokenID,
		Subject:   userID,
		Username:  username,
		SessionID: sessionID,
		Issuer:    issuer,
		Audience:  audience,
		IssuedAt:  time.Unix(iat, 0),
		ExpiresAt: time.Unix(exp, 0),
		TokenType: TokenType(typ),
		Roles:     roles,
	}

	if nbf != 0 {
		accessClaims.NotBefore = time.Unix(nbf, 0)
	}

	if mle != 0 {
		accessClaims.MaxLifetimeExpiry = time.Unix(mle, 0)
	}

	return accessClaims, nil
}

// mapToRefreshClaims converts JWT MapClaims to strongly-typed RefreshTokenClaims.
// Performs type checking and validation of all fields.
//
// Conversions:
//   - String UUIDs → uuid.UUID
//   - Unix timestamps → time.Time
//   - String token type → TokenType
//   - Interface arrays → string arrays
//
// Validation:
//   - All UUIDs must be valid
//   - Token type must be "refresh"
//   - Timestamps must be valid numbers
//   - Required fields must be present
//
// Parameters:
//   - claims: JWT MapClaims from parsed token
//
// Returns:
//   - *RefreshTokenClaims: Strongly-typed claims structure
//   - error: If any field is invalid or missing
//
// Notes:
//   - Used internally during token verification
//   - Does not include roles (refresh tokens don't have roles)
func mapToRefreshClaims(claims jwt.MapClaims) (*RefreshTokenClaims, error) {
	tokenID, err := uuid.Parse(claims["jti"].(string))
	if err != nil {
		return nil, fmt.Errorf("invalid token ID: %w", err)
	}

	userID, err := uuid.Parse(claims["sub"].(string))
	if err != nil {
		return nil, fmt.Errorf("invalid user ID: %w", err)
	}

	sessionID, err := uuid.Parse(claims["sid"].(string))
	if err != nil {
		return nil, fmt.Errorf("invalid session ID: %w", err)
	}

	username, ok := claims["usr"].(string)
	if !ok {
		return nil, fmt.Errorf("invalid username type: expected string")
	}

	issuer, _ := claims["iss"].(string)

	var audience []string
	if aud, ok := claims["aud"]; ok {
		switch v := aud.(type) {
		case string:
			audience = []string{v}
		case []interface{}:
			audience = make([]string, 0, len(v))
			for _, a := range v {
				if aStr, ok := a.(string); ok {
					audience = append(audience, aStr)
				}
			}
		case []string:
			audience = v
		}
	}

	typ, ok := claims["typ"].(string)
	if !ok {
		return nil, fmt.Errorf("invalid or missing token type")
	}

	if TokenType(typ) != RefreshToken {
		return nil, fmt.Errorf("invalid token type: expected 'refresh'")
	}

	iat := getUnixTime(claims["iat"])
	exp := getUnixTime(claims["exp"])
	nbf := getUnixTime(claims["nbf"])
	mle := getUnixTime(claims["mle"])

	if iat == 0 || exp == 0 {
		return nil, fmt.Errorf("invalid timestamp format")
	}

	refreshClaims := &RefreshTokenClaims{
		ID:        tokenID,
		Subject:   userID,
		Username:  username,
		SessionID: sessionID,
		Issuer:    issuer,
		Audience:  audience,
		IssuedAt:  time.Unix(iat, 0),
		ExpiresAt: time.Unix(exp, 0),
		TokenType: TokenType(typ),
	}

	if nbf != 0 {
		refreshClaims.NotBefore = time.Unix(nbf, 0)
	}

	if mle != 0 {
		refreshClaims.MaxLifetimeExpiry = time.Unix(mle, 0)
	}

	return refreshClaims, nil
}

// validateTokenClaims performs comprehensive validation of JWT claims.
// Checks required claims, timestamps, token type, and UUID formats.
//
// Validation Checks:
//   - All required claims are present (base + custom)
//   - UUIDs (jti, sub, sid) are valid
//   - Token type matches expected type
//   - Token has not expired (exp > now)
//   - Token is not used before valid time (iat <= now)
//   - Token has not exceeded maximum lifetime (mle > now)
//
// Base Required Claims:
//   - Access tokens: jti, sub, sid, usr, iat, exp, typ, rls
//   - Refresh tokens: jti, sub, sid, usr, iat, exp, typ
//
// Parameters:
//   - claims: JWT MapClaims to validate
//   - expectedType: Expected token type (AccessToken or RefreshToken)
//   - required: Additional required claims beyond base requirements
//
// Returns:
//   - error: Detailed validation error, or nil if all checks pass
//
// Example Errors:
//   - "missing required claim: iss"
//   - "token has expired"
//   - "invalid token type: expected access"
//   - "invalid user ID format"
func validateTokenClaims(claims jwt.MapClaims, expectedType TokenType, required []string) error {
	baseRequired := map[TokenType][]string{
		AccessToken:  {"jti", "sub", "sid", "usr", "iat", "exp", "typ", "rls"},
		RefreshToken: {"jti", "sub", "sid", "usr", "iat", "exp", "typ"},
	}

	for _, claim := range append(baseRequired[expectedType], required...) {
		if _, ok := claims[claim]; !ok {
			return fmt.Errorf("missing required claim: %s", claim)
		}
	}

	if jti, ok := claims["jti"].(string); !ok {
		return fmt.Errorf("invalid token ID type: expected string")
	} else if _, err := uuid.Parse(jti); err != nil {
		return fmt.Errorf("invalid token ID format: %w", err)
	}

	if sub, ok := claims["sub"].(string); !ok {
		return fmt.Errorf("invalid user ID type: expected string")
	} else if _, err := uuid.Parse(sub); err != nil {
		return fmt.Errorf("invalid user ID format: %w", err)
	}

	if sid, ok := claims["sid"].(string); !ok {
		return fmt.Errorf("invalid session ID type: expected string")
	} else if _, err := uuid.Parse(sid); err != nil {
		return fmt.Errorf("invalid session ID format: %w", err)
	}

	tokenType, ok := claims["typ"].(string)
	if !ok || TokenType(tokenType) != expectedType {
		return fmt.Errorf("invalid token type: expected %s", expectedType)
	}

	exp, ok := claims["exp"].(float64)
	if !ok {
		return fmt.Errorf("invalid exp claim type")
	}
	if time.Unix(int64(exp), 0).Before(time.Now()) {
		return fmt.Errorf("token has expired")
	}

	if iat, ok := claims["iat"].(float64); ok {
		if time.Unix(int64(iat), 0).After(time.Now()) {
			return fmt.Errorf("token issued in the future")
		}
	}

	if mle, ok := claims["mle"].(float64); ok {
		maxExpiry := time.Unix(int64(mle), 0)
		if time.Now().After(maxExpiry) {
			return fmt.Errorf("token exceeded maximum lifetime")
		}
	}

	return nil
}

// parseEdDSAPrivateKey parses an Ed25519 private key from PEM-encoded bytes.
// Supports PKCS#8 format.
//
// Ed25519 Keys:
//   - Modern elliptic curve algorithm
//   - Fast signing and verification
//   - Small key and signature sizes (32/64 bytes)
//   - Strong security (128-bit equivalent)
//
// Parameters:
//   - pemBytes: PEM-encoded private key data
//
// Returns:
//   - ed25519.PrivateKey: Parsed private key
//   - error: If PEM cannot be decoded or key is invalid
//
// Example PEM Format:
//
//	-----BEGIN PRIVATE KEY-----
//	MC4CAQAwBQYDK2VwBCIEIJ+DYvh6SEqVTm50DFtMDoQikTmiCqirVv9mWG9qfSnF
//	-----END PRIVATE KEY-----
func parseEdDSAPrivateKey(pemBytes []byte) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block containing the private key")
	}

	priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse EdDSA private key: %w", err)
	}

	eddsaPriv, ok := priv.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("not a valid EdDSA private key")
	}

	return eddsaPriv, nil
}

// parseEdDSAPublicKey parses an Ed25519 public key from PEM-encoded bytes.
// Supports both raw public keys and X.509 certificates.
//
// Supported Formats:
//   - PKIX public key (SubjectPublicKeyInfo)
//   - X.509 certificate (extracts public key)
//
// Parameters:
//   - pemBytes: PEM-encoded public key or certificate data
//
// Returns:
//   - ed25519.PublicKey: Parsed public key
//   - error: If PEM cannot be decoded or key is invalid
//
// Example PEM Format:
//
//	-----BEGIN PUBLIC KEY-----
//	MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=
//	-----END PUBLIC KEY-----
func parseEdDSAPublicKey(pemBytes []byte) (ed25519.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block containing the public key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse EdDSA public key: %w", err)
		}
		eddsaPub, ok := cert.PublicKey.(ed25519.PublicKey)
		if !ok {
			return nil, fmt.Errorf("not a valid EdDSA public key")
		}
		return eddsaPub, nil
	}

	eddsaPub, ok := pub.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not a valid EdDSA public key")
	}
	return eddsaPub, nil
}

// parseRSAPrivateKey parses an RSA private key from PEM-encoded bytes.
// Supports PKCS#1 and PKCS#8 formats with fallback parsing.
//
// Supported Formats:
//   - PKCS#1 (traditional RSA format)
//   - PKCS#8 (modern format, supports multiple algorithms)
//   - Legacy ASN.1 structures
//
// Key Size Recommendations:
//   - Minimum: 2048 bits
//   - Recommended: 3072 bits
//   - High security: 4096 bits
//
// Parameters:
//   - pemBytes: PEM-encoded private key data
//
// Returns:
//   - *rsa.PrivateKey: Parsed private key
//   - error: If PEM cannot be decoded or key is invalid
//
// Example PEM Format:
//
//	-----BEGIN RSA PRIVATE KEY-----
//	MIIEpAIBAAKCAQEA...
//	-----END RSA PRIVATE KEY-----
func parseRSAPrivateKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block containing the RSA private key")
	}

	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}

	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if rsaKey, ok := key.(*rsa.PrivateKey); ok {
			return rsaKey, nil
		}
		return nil, fmt.Errorf("expected RSA private key, got %T", key)
	}

	var privKey pkcs8
	if _, err := asn1.Unmarshal(block.Bytes, &privKey); err != nil {
		return nil, fmt.Errorf("failed to parse PKCS8 structure: %w", err)
	}

	var rsaPriv rsaPrivateKey
	if _, err := asn1.Unmarshal(privKey.PrivateKey, &rsaPriv); err != nil {
		return nil, fmt.Errorf("failed to parse RSA private key: %w", err)
	}

	return &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			N: rsaPriv.N,
			E: int(rsaPriv.E.Int64()),
		},
		D:      rsaPriv.D,
		Primes: []*big.Int{rsaPriv.P, rsaPriv.Q},
		Precomputed: rsa.PrecomputedValues{
			Dp:   rsaPriv.Dp,
			Dq:   rsaPriv.Dq,
			Qinv: rsaPriv.Qinv,
		},
	}, nil
}

// parseRSAPublicKey parses an RSA public key from PEM-encoded bytes.
// Supports multiple formats including certificates.
//
// Supported Formats:
//   - PKIX public key (SubjectPublicKeyInfo)
//   - PKCS#1 public key
//   - X.509 certificate (extracts public key)
//   - Legacy ASN.1 structures
//
// Parameters:
//   - pemBytes: PEM-encoded public key or certificate data
//
// Returns:
//   - *rsa.PublicKey: Parsed public key
//   - error: If PEM cannot be decoded or key is invalid
//
// Example PEM Format:
//
//	-----BEGIN PUBLIC KEY-----
//	MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
//	-----END PUBLIC KEY-----
func parseRSAPublicKey(pemBytes []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block containing the RSA public key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err == nil {
		if rsaPub, ok := pub.(*rsa.PublicKey); ok {
			return rsaPub, nil
		}
		return nil, fmt.Errorf("expected RSA public key, got %T", pub)
	}

	if pub, err := x509.ParsePKCS1PublicKey(block.Bytes); err == nil {
		return pub, nil
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err == nil {
		if rsaPub, ok := cert.PublicKey.(*rsa.PublicKey); ok {
			return rsaPub, nil
		}
		return nil, fmt.Errorf("expected RSA public key in certificate, got %T", cert.PublicKey)
	}

	var pubKey struct {
		Algo      pkix.AlgorithmIdentifier
		BitString asn1.BitString
	}
	if _, err := asn1.Unmarshal(block.Bytes, &pubKey); err != nil {
		return nil, fmt.Errorf("failed to parse public key structure: %w", err)
	}

	var rsaPub struct {
		N *big.Int
		E *big.Int
	}
	if _, err := asn1.Unmarshal(pubKey.BitString.Bytes, &rsaPub); err != nil {
		return nil, fmt.Errorf("failed to parse RSA public key: %w", err)
	}

	return &rsa.PublicKey{
		N: rsaPub.N,
		E: int(rsaPub.E.Int64()),
	}, nil
}

// parseECDSAPrivateKey parses an ECDSA private key from PEM-encoded bytes.
// Supports SEC1 and PKCS#8 formats.
//
// Supported Curves:
//   - P-256 (ES256) - 128-bit security
//   - P-384 (ES384) - 192-bit security
//   - P-521 (ES512) - 256-bit security
//
// Parameters:
//   - pemBytes: PEM-encoded private key data
//
// Returns:
//   - *ecdsa.PrivateKey: Parsed private key
//   - error: If PEM cannot be decoded or key is invalid
//
// Example PEM Format:
//
//	-----BEGIN EC PRIVATE KEY-----
//	MHcCAQEEIIGlRFzR...
//	-----END EC PRIVATE KEY-----
func parseECDSAPrivateKey(pemBytes []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block containing the ECDSA private key")
	}

	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		pkcs8Key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse ECDSA private key: %w", err)
		}
		key, ok := pkcs8Key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("not a valid ECDSA private key")
		}
		return key, nil
	}
	return key, nil
}

// parseECDSAPublicKey parses an ECDSA public key from PEM-encoded bytes.
// Supports both raw public keys and X.509 certificates.
//
// Supported Formats:
//   - PKIX public key (SubjectPublicKeyInfo)
//   - X.509 certificate (extracts public key)
//
// Parameters:
//   - pemBytes: PEM-encoded public key or certificate data
//
// Returns:
//   - *ecdsa.PublicKey: Parsed public key
//   - error: If PEM cannot be decoded or key is invalid
//
// Example PEM Format:
//
//	-----BEGIN PUBLIC KEY-----
//	MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...
//	-----END PUBLIC KEY-----
func parseECDSAPublicKey(pemBytes []byte) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block containing the ECDSA public key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse ECDSA public key: %w", err)
		}
		ecdsaPub, ok := cert.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("not a valid ECDSA public key")
		}
		return ecdsaPub, nil
	}

	ecdsaPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not a valid ECDSA public key")
	}
	return ecdsaPub, nil
}

// checkFilePermissions verifies that a file has secure permissions.
// Used to ensure private key files are not world-readable.
//
// Security Check:
//   - Verifies file doesn't have permissions beyond required
//   - Recommended: 0600 (read/write for owner only)
//   - Fails if file is readable by group or others
//
// Parameters:
//   - path: File path to check
//   - requiredPerm: Maximum allowed permissions (e.g., 0600)
//
// Returns:
//   - error: If file has excessive permissions or cannot be accessed
//
// Example:
//
//	err := checkFilePermissions("/keys/private.pem", 0600)
//	if err != nil {
//	    log.Fatal("Private key file has insecure permissions")
//	}
func checkFilePermissions(path string, requiredPerm os.FileMode) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("failed to stat file: %w", err)
	}

	actualPerm := info.Mode().Perm()
	if actualPerm&^requiredPerm != 0 {
		return fmt.Errorf("file %s has permissions %#o, expected %#o", path, actualPerm, requiredPerm)
	}

	return nil
}

// getUnixTime extracts a Unix timestamp from various claim value types.
// Handles different JSON number representations used by JWT libraries.
//
// Supported Types:
//   - float64 (standard JSON number)
//   - int64 (Go integer)
//   - int (Go integer)
//   - json.Number (string-based number)
//
// Parameters:
//   - claim: The claim value to convert
//
// Returns:
//   - int64: Unix timestamp in seconds, or 0 if conversion fails
//
// Notes:
//   - Returns 0 for unrecognized types (not an error)
//   - Used internally for timestamp claim parsing
func getUnixTime(claim interface{}) int64 {
	switch v := claim.(type) {
	case float64:
		return int64(v)
	case int64:
		return v
	case int:
		return int64(v)
	case json.Number:
		i, _ := v.Int64()
		return i
	default:
		return 0
	}
}

// pkcs8 represents a PKCS#8 encoded private key structure.
// Used for parsing PKCS#8 format keys that can't be parsed with standard library.
//
// ASN.1 Structure:
//
//	PrivateKeyInfo ::= SEQUENCE {
//	  version Version,
//	  privateKeyAlgorithm AlgorithmIdentifier,
//	  privateKey OCTET STRING
//	}
type pkcs8 struct {
	Version    int
	Algo       pkix.AlgorithmIdentifier
	PrivateKey []byte
}

// rsaPrivateKey represents the ASN.1 structure of an RSA private key.
// Used for manual parsing when standard methods fail.
//
// ASN.1 Structure (PKCS#1):
//
//	RSAPrivateKey ::= SEQUENCE {
//	  version Version,
//	  modulus INTEGER,
//	  publicExponent INTEGER,
//	  privateExponent INTEGER,
//	  prime1 INTEGER,
//	  prime2 INTEGER,
//	  exponent1 INTEGER,
//	  exponent2 INTEGER,
//	  coefficient INTEGER
//	}
type rsaPrivateKey struct {
	Version int
	N       *big.Int // modulus
	E       *big.Int // public exponent
	D       *big.Int // private exponent
	P       *big.Int // prime1
	Q       *big.Int // prime2
	Dp      *big.Int // exponent1 (d mod (p-1))
	Dq      *big.Int // exponent2 (d mod (q-1))
	Qinv    *big.Int // coefficient (q^-1 mod p)
}
