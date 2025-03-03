package gourdiantoken

import (
	"time"

	"github.com/google/uuid"
)

// AccessTokenClaims contains claims specific to access tokens.
//
// Fields:
//   - ID: Unique token ID (JWT ID)
//   - Subject: User ID (subject)
//   - Username: Username
//   - SessionID: Session ID
//   - IssuedAt: Token issuance time
//   - ExpiresAt: Token expiration time
//   - TokenType: Token type (access or refresh)
//   - Role: User role
//   - Permissions: List of user permissions
type AccessTokenClaims struct {
	ID          uuid.UUID `json:"jti"`
	Subject     uuid.UUID `json:"sub"`
	Username    string    `json:"usr"`
	SessionID   uuid.UUID `json:"sid"`
	IssuedAt    time.Time `json:"iat"`
	ExpiresAt   time.Time `json:"exp"`
	TokenType   TokenType `json:"typ"`
	Role        string    `json:"rol"`
	Permissions []string  `json:"per"`
}

// RefreshTokenClaims contains claims specific to refresh tokens.
//
// Fields:
//   - ID: Unique token ID (JWT ID)
//   - Subject: User ID (subject)
//   - Username: Username
//   - SessionID: Session ID
//   - IssuedAt: Token issuance time
//   - ExpiresAt: Token expiration time
//   - TokenType: Token type (access or refresh)
type RefreshTokenClaims struct {
	ID        uuid.UUID `json:"jti"`
	Subject   uuid.UUID `json:"sub"`
	Username  string    `json:"usr"`
	SessionID uuid.UUID `json:"sid"`
	IssuedAt  time.Time `json:"iat"`
	ExpiresAt time.Time `json:"exp"`
	TokenType TokenType `json:"typ"`
}

// AccessTokenResponse represents the response after creating an access token.
//
// Fields:
//   - Token: Signed access token
//   - Subject: User ID (subject)
//   - Username: Username
//   - SessionID: Session ID
//   - ExpiresAt: Token expiration time
//   - IssuedAt: Token issuance time
//   - Role: User role
//   - Permissions: List of user permissions
type AccessTokenResponse struct {
	Token       string    `json:"tok"`
	Subject     uuid.UUID `json:"sub"`
	Username    string    `json:"usr"`
	SessionID   uuid.UUID `json:"sid"`
	ExpiresAt   time.Time `json:"exp"`
	IssuedAt    time.Time `json:"iat"`
	Role        string    `json:"rol"`
	Permissions []string  `json:"per"`
}

// RefreshTokenResponse represents the response after creating a refresh token.
//
// Fields:
//   - Token: Signed refresh token
//   - Subject: User ID (subject)
//   - Username: Username
//   - SessionID: Session ID
//   - ExpiresAt: Token expiration time
//   - IssuedAt: Token issuance time
type RefreshTokenResponse struct {
	Token     string    `json:"tok"`
	Subject   uuid.UUID `json:"sub"`
	Username  string    `json:"usr"`
	SessionID uuid.UUID `json:"sid"`
	ExpiresAt time.Time `json:"exp"`
	IssuedAt  time.Time `json:"iat"`
}
