package gourdiantoken

import (
	"time"
)

// TokenType represents the type of token (access or refresh).
type TokenType string

const (
	AccessToken  TokenType = "access"  // Access token type
	RefreshToken TokenType = "refresh" // Refresh token type
)

// SigningMethod represents the key signing method (symmetric or asymmetric).
type SigningMethod string

const (
	Symmetric  SigningMethod = "symmetric"  // Symmetric key signing (HMAC)
	Asymmetric SigningMethod = "asymmetric" // Asymmetric key signing (RSA, ECDSA)
)

// GourdianTokenConfig holds the configuration for token generation and verification.
//
// Fields:
//   - Algorithm: Signing algorithm (e.g., "HS256", "RS256", "ES256")
//   - SigningMethod: Method to use for signing (symmetric or asymmetric)
//   - SymmetricKey: Symmetric key for signing tokens (used when SigningMethod is Symmetric)
//   - PrivateKeyPath: Path to the private key file (used when SigningMethod is Asymmetric)
//   - PublicKeyPath: Path to the public key file (used when SigningMethod is Asymmetric)
//   - AccessToken: Configuration for access tokens
//   - RefreshToken: Configuration for refresh tokens
type GourdianTokenConfig struct {
	Algorithm      string
	SigningMethod  SigningMethod
	SymmetricKey   string
	PrivateKeyPath string
	PublicKeyPath  string
	AccessToken    AccessTokenConfig
	RefreshToken   RefreshTokenConfig
}

// AccessTokenConfig holds configuration specific to access tokens.
//
// Fields:
//   - Duration: Token validity duration
//   - MaxLifetime: Maximum lifetime of the token
//   - Issuer: Token issuer
//   - Audience: Intended audience for the token
//   - AllowedAlgorithms: List of allowed signing algorithms
//   - RequiredClaims: List of required claims
type AccessTokenConfig struct {
	Duration          time.Duration
	MaxLifetime       time.Duration
	Issuer            string
	Audience          []string
	AllowedAlgorithms []string
	RequiredClaims    []string
}

// RefreshTokenConfig holds configuration specific to refresh tokens.
//
// Fields:
//   - Duration: Token validity duration
//   - MaxLifetime: Maximum lifetime of the token
//   - ReuseInterval: Time interval before a refresh token can be reused
//   - RotationEnabled: Whether token rotation is enabled
//   - FamilyEnabled: Whether token family tracking is enabled
//   - MaxPerUser: Maximum number of refresh tokens per user
type RefreshTokenConfig struct {
	Duration        time.Duration
	MaxLifetime     time.Duration
	ReuseInterval   time.Duration
	RotationEnabled bool
	FamilyEnabled   bool
	MaxPerUser      int
}
