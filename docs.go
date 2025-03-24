// docs.go

// Package gourdiantoken provides a secure and flexible JWT-based token management system
// for handling both access and refresh tokens in Go applications.
//
// The package is designed with security best practices in mind and offers extensive
// customization options while maintaining sensible defaults.
//
// # Overview
//
// The package provides:
// - Generation of cryptographically-signed JWT tokens
// - Verification of token signatures and claims
// - Configurable token lifetimes and rotation policies
// - Support for both symmetric (HMAC) and asymmetric (RSA/ECDSA) signing methods
// - Comprehensive claim validation
// - Built-in UUID support for token and session identifiers
//
// # Key Features
//
// ## Token Types
// - Access Tokens: Short-lived tokens for API authorization (typically minutes/hours)
// - Refresh Tokens: Long-lived tokens for obtaining new access tokens (typically days/weeks)
//
// ## Security Features
// - Automatic token expiration validation
// - Configurable signing algorithms (HS256/384/512, RS256/384/512, ES256/384/512)
// - Secure key handling with file permission checks
// - Refresh token rotation and reuse detection
// - Token family support to prevent token replay
//
// ## Configuration Options
// - Custom token lifetimes for access and refresh tokens
// - Configurable maximum token lifetimes
// - Optional token claim requirements
// - Audience and issuer validation
// - Algorithm allow-listing
//
// # Usage Example
//
//	// Initialize token maker with configuration
//	config := gourdiantoken.GourdianTokenConfig{
//	    Algorithm:      "RS256",
//	    SigningMethod:  gourdiantoken.Asymmetric,
//	    PrivateKeyPath: "keys/private.pem",
//	    PublicKeyPath:  "keys/public.pem",
//	    AccessToken: gourdiantoken.AccessTokenConfig{
//	        Duration:     time.Hour,
//	        MaxLifetime:  24 * time.Hour,
//	        Issuer:       "myapp.com",
//	        Audience:     []string{"myapp.com"},
//	    },
//	    RefreshToken: gourdiantoken.RefreshTokenConfig{
//	        Duration:        7 * 24 * time.Hour,
//	        RotationEnabled: true,
//	        ReuseInterval:   time.Minute,
//	    },
//	}
//
//	maker, err := gourdiantoken.NewGourdianTokenMaker(config)
//	if err != nil {
//	    log.Fatal("Failed to create token maker:", err)
//	}
//
//	// Create tokens
//	userID := uuid.New()
//	accessToken, err := maker.CreateAccessToken(context.Background(), userID, "username", "admin", uuid.New())
//	if err != nil {
//	    log.Fatal("Failed to create access token:", err)
//	}
//
//	refreshToken, err := maker.CreateRefreshToken(context.Background(), userID, "username", uuid.New())
//	if err != nil {
//	    log.Fatal("Failed to create refresh token:", err)
//	}
//
//	// Verify tokens
//	accessClaims, err := maker.VerifyAccessToken(accessToken.Token)
//	if err != nil {
//	    log.Fatal("Invalid access token:", err)
//	}
//
//	// Rotate refresh token
//	newRefreshToken, err := maker.RotateRefreshToken(refreshToken.Token)
//	if err != nil {
//	    log.Fatal("Failed to rotate refresh token:", err)
//	}
//
// # Security Considerations
//
// - Always use HTTPS when transmitting tokens
// - Store refresh tokens securely (httpOnly, Secure cookies)
// - Keep private keys protected with proper file permissions (0600)
// - Rotate cryptographic keys periodically
// - Set appropriate token lifetimes based on your security requirements
// - Implement proper token revocation for sensitive operations
//
// # Performance
//
// The package is optimized for performance with:
// - Efficient JWT parsing and validation
// - Minimal allocations during token processing
// - Concurrent-safe operations
//
// # Dependencies
//
// - github.com/golang-jwt/jwt/v5 - JWT implementation
// - github.com/google/uuid - UUID generation
package gourdiantoken
