// File: gourdiantoken.claims.go

package gourdiantoken

import (
	"time"

	"github.com/google/uuid"
)

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
