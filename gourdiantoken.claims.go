// File: gourdiantoken.claims.go

package gourdiantoken

import (
	"time"
)

// AccessTokenClaims represents the claims contained in an access token JWT.
// Access tokens are short-lived and include authorization information (roles).
//
// Standard JWT Claims:
//   - jti: JWT ID (unique token identifier)
//   - sub: Subject (user identifier)
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
	// ID is the unique token identifier (a UUIDv4 string, generated internally)
	// used for tracking and revocation.
	ID string `json:"jti"`

	// Subject is the user's unique identifier (any non-empty string).
	Subject string `json:"sub"`

	// SessionID uniquely identifies the user's session (any string; may be
	// empty for sessionless tokens). Used to invalidate all tokens when a
	// session ends.
	SessionID string `json:"sid"`

	// Username is the human-readable username for logging and display purposes.
	Username string `json:"usr"`

	// TenantID identifies the tenant this token was issued for (any non-empty string).
	// Empty unless GourdianTokenConfig.MultiTenantEnabled is true, in which case it is
	// always non-empty (enforced at creation and verification). Absent from the JWT
	// payload entirely when empty — see toMapClaims.
	TenantID string `json:"tid"`

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
//   - sub: Subject (user identifier)
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
	// ID is the unique token identifier (a UUIDv4 string, generated internally)
	// used for tracking and rotation.
	ID string `json:"jti"`

	// Subject is the user's unique identifier (any non-empty string).
	Subject string `json:"sub"`

	// SessionID uniquely identifies the user's session (any string; may be
	// empty for sessionless tokens).
	SessionID string `json:"sid"`

	// Username is the human-readable username.
	Username string `json:"usr"`

	// TenantID identifies the tenant this token was issued for (any non-empty string).
	// Empty unless GourdianTokenConfig.MultiTenantEnabled is true, in which case it is
	// always non-empty (enforced at creation and verification). Absent from the JWT
	// payload entirely when empty — see toMapClaims.
	TenantID string `json:"tid"`

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
	// Subject is the user's unique identifier (any non-empty string).
	Subject string `json:"sub"`

	// SessionID uniquely identifies the user's session (any string; may be
	// empty for sessionless tokens).
	SessionID string `json:"sid"`

	// Token is the signed JWT string ready for use in Authorization headers.
	Token string `json:"tok"`

	// Issuer identifies the authentication service.
	Issuer string `json:"iss"`

	// Username is the human-readable username.
	Username string `json:"usr"`

	// TenantID identifies the tenant this token was issued for. Empty unless
	// GourdianTokenConfig.MultiTenantEnabled is true.
	TenantID string `json:"tid"`

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
	// Subject is the user's unique identifier (any non-empty string).
	Subject string `json:"sub"`

	// SessionID uniquely identifies the user's session (any string; may be
	// empty for sessionless tokens).
	SessionID string `json:"sid"`

	// Token is the signed JWT string that can be used to obtain new access tokens.
	Token string `json:"tok"`

	// Issuer identifies the authentication service.
	Issuer string `json:"iss"`

	// Username is the human-readable username.
	Username string `json:"usr"`

	// TenantID identifies the tenant this token was issued for. Empty unless
	// GourdianTokenConfig.MultiTenantEnabled is true.
	TenantID string `json:"tid"`

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

// VerificationTokenClaims represents the claims contained in a verification token JWT.
// Verification tokens are short-lived, single-use, and scoped to a specific "use case"
// (e.g. a pending 2FA verification step, a password reset link, or an email verification
// link). Unlike AccessTokenClaims/RefreshTokenClaims, there is no session, username, or
// roles concept — correlate application-specific state via Metadata instead.
//
// Standard JWT Claims:
//   - jti: JWT ID (unique token identifier)
//   - sub: Subject (the identifier the token is issued for)
//   - iss: Issuer (authentication service)
//   - aud: Audience (intended recipients)
//   - iat: Issued At (token creation time)
//   - exp: Expiration Time
//   - nbf: Not Before
//
// Custom Claims:
//   - uc: UseCase (the purpose this token is scoped to)
//   - mtd: Metadata (optional, application-defined key/value payload)
//   - typ: Token Type (always "verification")
//   - mle: Maximum Lifetime Expiry (equal to ExpiresAt; verification tokens are never renewed)
type VerificationTokenClaims struct {
	// ID is the unique token identifier (a UUIDv4 string, generated internally)
	// used for tracking and single-use enforcement.
	ID string `json:"jti"`

	// Subject is the identifier this token is issued for (any non-empty string).
	Subject string `json:"sub"`

	// UseCase scopes this token to a specific purpose (e.g. "2fa-pending",
	// "password-reset"). Must be non-empty and, if GourdianTokenConfig.VerificationAllowedUseCases
	// is set, must appear in that whitelist.
	UseCase string `json:"uc"`

	// Issuer identifies the service that created this token.
	Issuer string `json:"iss"`

	// Audience lists the services that should accept this token.
	Audience []string `json:"aud"`

	// IssuedAt is the timestamp when this token was created (UTC).
	IssuedAt time.Time `json:"iat"`

	// ExpiresAt is the timestamp when this token expires (UTC).
	ExpiresAt time.Time `json:"exp"`

	// NotBefore is the timestamp before which the token is not valid (UTC).
	NotBefore time.Time `json:"nbf"`

	// MaxLifetimeExpiry equals ExpiresAt for verification tokens (they are never renewed,
	// so there is no separate absolute ceiling to model).
	MaxLifetimeExpiry time.Time `json:"mle"`

	// Metadata is an optional, application-defined payload (e.g. a username to display
	// during a 2FA-pending step). Omitted from the JWT entirely when empty.
	Metadata map[string]interface{} `json:"mtd,omitempty"`

	// TokenType is always "verification" for verification tokens.
	TokenType TokenType `json:"typ"`
}

// VerificationTokenResponse contains the generated verification token and its associated
// metadata. This is returned after successful verification token creation.
type VerificationTokenResponse struct {
	// Subject is the identifier this token is issued for.
	Subject string `json:"sub"`

	// UseCase scopes this token to a specific purpose.
	UseCase string `json:"uc"`

	// Token is the signed JWT string.
	Token string `json:"tok"`

	// Issuer identifies the authentication service.
	Issuer string `json:"iss"`

	// Audience lists the intended recipients of this token.
	Audience []string `json:"aud"`

	// IssuedAt is when the token was created (RFC3339 format).
	IssuedAt time.Time `json:"iat"`

	// ExpiresAt is when the token expires (RFC3339 format).
	ExpiresAt time.Time `json:"exp"`

	// NotBefore is when the token becomes valid (RFC3339 format).
	NotBefore time.Time `json:"nbf"`

	// MaxLifetimeExpiry equals ExpiresAt for verification tokens.
	MaxLifetimeExpiry time.Time `json:"mle"`

	// Metadata is the optional, application-defined payload supplied at creation.
	Metadata map[string]interface{} `json:"mtd,omitempty"`

	// TokenType is always "verification".
	TokenType TokenType `json:"typ"`
}
