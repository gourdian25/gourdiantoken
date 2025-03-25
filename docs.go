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
// - Support for both symmetric (HMAC) and asymmetric (RSA/ECDSA/EdDSA) signing methods
// - Comprehensive claim validation with required fields
// - Built-in UUID support for token and session identifiers
// - Redis-backed token rotation and invalidation
//
// # Key Features
//
// ## Token Types
// - Access Tokens: Short-lived tokens for API authorization (typically minutes/hours)
//   - Contains user ID, username, role, and session ID
//   - Configurable expiration and maximum lifetime
//
// - Refresh Tokens: Long-lived tokens for obtaining new access tokens (typically days/weeks)
//   - Contains user ID, username, and session ID
//   - Supports rotation with Redis-backed invalidation
//
// ## Security Features
// - Automatic token expiration validation
// - Configurable signing algorithms (HS256/384/512, RS256/384/512, ES256/384/512, EdDSA)
// - Secure key handling with strict file permission checks (0600 for private keys)
// - Refresh token rotation and reuse detection via Redis
// - Required claim validation for all tokens
// - Protection against algorithm substitution attacks
//
// ## Configuration Options
// - Custom token lifetimes for access and refresh tokens
// - Configurable maximum absolute token lifetimes
// - Strict claim requirements (jti, sub, usr, sid, iat, exp, typ)
// - Redis integration for token rotation
// - Support for both symmetric and asymmetric cryptography
//
// # Usage Example
//
//	// Initialize token maker with default configuration
//	config := gourdiantoken.DefaultGourdianTokenConfig("your-32-byte-secret-key-1234567890abcdef")
//	config.AccessToken.Issuer = "myapp.com"
//	config.AccessToken.Audience = []string{"api.myapp.com"}
//	config.RefreshToken.RotationEnabled = true
//
//	redisOpts := &redis.Options{
//	    Addr:     "localhost:6379",
//	    Password: "",
//	    DB:       0,
//	}
//
//	maker, err := gourdiantoken.NewGourdianTokenMaker(config, redisOpts)
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
//	// Rotate refresh token (requires Redis)
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
// - Set minimum 32-byte keys for HMAC algorithms
// - Set appropriate token lifetimes based on your security requirements
// - When using rotation, ensure Redis is properly secured
//
// # Performance
//
// The package is optimized for performance with:
// - Efficient JWT parsing and validation
// - Minimal allocations during token processing
// - Concurrent-safe operations
// - Optional Redis integration only when rotation is enabled
//
// # Dependencies
//
// - github.com/golang-jwt/jwt/v5 - JWT implementation
// - github.com/google/uuid - UUID generation
// - github.com/redis/go-redis/v9 - Redis client (optional, only for token rotation)
//
// # Implementation Details
//
// ## Token Structure
// All tokens include these mandatory claims:
// - jti (JWT ID): Unique token identifier (UUID)
// - sub (Subject): User identifier (UUID)
// - usr (Username): Human-readable user identifier
// - sid (Session ID): Unique session identifier (UUID)
// - iat (Issued At): Token creation timestamp
// - exp (Expiration): Token expiration timestamp
// - typ (Type): Token type ("access" or "refresh")
//
// Access tokens additionally include:
// - rol (Role): User role/privileges
//
// ## Key Management
// The package supports:
// - Symmetric keys (HMAC) - Minimum 32 bytes recommended
// - Asymmetric keys (RSA/ECDSA/EdDSA) - Loaded from PEM files
// - Automatic key parsing with fallback mechanisms
// - Strict file permission checks (0600 for private keys)
//
// ## Redis Integration
// When refresh token rotation is enabled:
// - Uses Redis to track recently used tokens
// - Prevents token reuse within configured interval
// - Automatically expires rotation records
package gourdiantoken
