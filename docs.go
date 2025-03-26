// Package gourdiantoken provides a secure and flexible JWT-based token management system
// for handling both access and refresh tokens in Go applications.
//
// # Overview
//
// The gourdiantoken package implements a production-ready JWT token system with:
// - Secure token generation and validation
// - Configurable access and refresh token policies
// - Support for multiple cryptographic algorithms
// - Redis-backed token rotation
//
// The system is designed around security best practices while providing flexibility
// for different application requirements.
//
// # Core Concepts
//
// ## Token Types
// - Access Tokens: Short-lived tokens (minutes/hours) for API authorization
// - Refresh Tokens: Long-lived tokens (days/weeks) for obtaining new access tokens
//
// ## Security Features
// - Algorithm flexibility (HMAC, RSA, ECDSA, EdDSA)
// - Automatic expiration validation
// - Required claim enforcement
// - Refresh token rotation
// - Secure key handling
//
// # Getting Started
//
// Basic usage involves:
// 1. Creating a configuration
// 2. Initializing a token maker
// 3. Generating tokens
// 4. Verifying tokens
//
// Example:
//
//	// 1. Create configuration
//	config := gourdiantoken.DefaultGourdianTokenConfig("your-32-byte-secret-key")
//	config.AccessToken.Issuer = "myapp.com"
//	config.AccessToken.Audience = []string{"api.myapp.com"}
//
//	// 2. Initialize maker (without Redis for simple cases)
//	maker, err := gourdiantoken.NewGourdianTokenMaker(config, nil)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// 3. Generate tokens
//	userID := uuid.New()
//	accessToken, err := maker.CreateAccessToken(context.Background(), userID, "john", "user", uuid.New())
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// 4. Verify tokens
//	claims, err := maker.VerifyAccessToken(accessToken.Token)
//	if err != nil {
//	    log.Fatal("Invalid token:", err)
//	}
//
// # Configuration
//
// The package offers two main configuration approaches:
//
// 1. DefaultGourdianTokenConfig() - Secure defaults with HMAC-SHA256
// 2. NewGourdianTokenConfig() - Full customization of all parameters
//
// ## Security Recommendations
// - Use 32+ byte keys for HMAC algorithms
// - Set appropriate token lifetimes (30m-1h for access, 7d for refresh)
// - Enable refresh token rotation when using multiple client devices
// - Set file permissions to 0600 for private keys
//
// # Token Rotation
//
// When refresh token rotation is enabled:
// - Old tokens are invalidated after use
// - Token reuse is detected and prevented
// - Requires Redis for state management
//
// Rotation example:
//
//	config.RefreshToken.RotationEnabled = true
//	redisOpts := &redis.Options{Addr: "localhost:6379"}
//	maker, _ := gourdianToken.NewGourdianTokenMaker(config, redisOpts)
//
//	// First use
//	refreshToken1, _ := maker.CreateRefreshToken(ctx, userID, "john", sessionID)
//
//	// Rotation
//	refreshToken2, err := maker.RotateRefreshToken(refreshToken1.Token)
//
// # Performance Considerations
//
// The package is optimized for:
// - Fast token generation and validation
// - Minimal allocations
// - Concurrent usage
// - Optional Redis dependency
//
// Benchmarks show:
// - ~5,000-10,000 token generations/verifications per second (varies by algorithm)
// - Sub-millisecond Redis operations for rotation
//
// # Advanced Features
//
// ## Custom Claims
// While the package enforces standard claims, you can extend tokens by:
// 1. Creating custom token types that embed AccessTokenClaims/RefreshTokenClaims
// 2. Implementing custom verification logic
//
// ## Multiple Issuers
// Support for multiple token issuers can be implemented by:
// - Maintaining multiple JWTMaker instances
// - Using different key pairs per issuer
// - Validating the 'iss' claim during verification
//
// # Error Handling
//
// The package returns detailed errors for:
// - Invalid tokens (expired, malformed, etc.)
// - Configuration errors
// - Key loading failures
// - Redis communication issues
//
// All errors should be checked and handled appropriately.
//
// # Dependencies
//
// Core:
// - github.com/golang-jwt/jwt/v5
// - github.com/google/uuid
//
// Optional (for rotation):
// - github.com/redis/go-redis/v9
//
// # Examples
//
// ## Symmetric Key Example
//
//	config := gourdiantoken.DefaultGourdianTokenConfig("secure-key-32-bytes-long")
//	maker, _ := gourdiantoken.NewGourdianTokenMaker(config, nil)
//	token, _ := maker.CreateAccessToken(ctx, userID, "user", "role", sessionID)
//
// ## Asymmetric Key Example
//
//	config := gourdiantoken.NewGourdianTokenConfig(
//	    "RS256",
//	    gourdiantoken.Asymmetric,
//	    "",
//	    "/path/to/private.pem",
//	    "/path/to/public.pem",
//	    time.Hour, 24*time.Hour, "issuer", nil, nil, nil,
//	    7*24*time.Hour, 30*24*time.Hour, time.Minute, true)
//	maker, _ := gourdiantoken.NewGourdianTokenMaker(config, nil)
//
// # Security Best Practices
//
// When using this package in production:
// 1. Always use HTTPS
// 2. Store secrets securely (not in code)
// 3. Set minimum token lifetimes for your use case
// 4. Monitor for abnormal token patterns
// 5. Rotate cryptographic keys periodically
// 6. Keep dependencies updated
//
// # Testing
//
// The package is designed for testability:
// - Interfaces allow mock implementations
// - Configurable timeouts for expiration testing
// - Clear separation of concerns
//
// Example test pattern:
//
//	func TestTokenVerification(t *testing.T) {
//	    maker := setupTestMaker()
//	    token := createTestToken(maker)
//	    claims, err := maker.VerifyAccessToken(token)
//	    // verification tests...
//	}
//
// # Limitations
//
// 1. Requires Go 1.18+
// 2. Redis is required for rotation feature
// 3. Not designed for extremely high throughput (>10k TPS) without tuning
//
// # See Also
//
// Related packages:
// - golang.org/x/oauth2 for OAuth2 integration
// - github.com/gorilla/securecookie for cookie storage
// - github.com/auth0/go-jwt-middleware for HTTP middleware
package gourdiantoken
