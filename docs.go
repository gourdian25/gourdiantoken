// File: docs.go

// Package gourdiantoken provides a secure and flexible JWT-based token management system
// for handling both access and refresh tokens in Go applications.
//
// # Overview
//
// The gourdiantoken package implements a production-ready JWT token system with:
// - Secure token generation and validation
// - Configurable access and refresh token policies
// - Support for multiple cryptographic algorithms (HMAC, RSA, ECDSA, EdDSA)
// - Redis-backed token revocation and rotation
// - Comprehensive claim validation
//
// # Core Concepts
//
// ## Token Types
// - Access Tokens: Short-lived tokens (15m-1h) containing user roles
// - Refresh Tokens: Long-lived tokens (7d-30d) for session continuity
//
// ## Security Features
// - Algorithm flexibility (10+ supported algorithms)
// - Automatic expiration validation
// - Required claim enforcement
// - Refresh token rotation
// - Secure key handling
// - Redis-based revocation
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
//	config.AccessToken.RevocationEnabled = true
//
//	// 2. Initialize maker with Redis
//	redisOpts := &redis.Options{Addr: "localhost:6379"}
//	maker, err := gourdiantoken.NewGourdianTokenMaker(context.Background(), config, redisOpts)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// 3. Generate tokens
//	userID := uuid.New()
//	accessToken, err := maker.CreateAccessToken(
//	    context.Background(),
//	    userID,
//	    "john",
//	    []string{"user", "admin"},
//	    uuid.New(),
//	)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// 4. Verify tokens
//	claims, err := maker.VerifyAccessToken(context.Background(), accessToken.Token)
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
// - Set access token lifetime to 15-30 minutes
// - Set refresh token lifetime to 7-30 days
// - Enable refresh token rotation
// - Set file permissions to 0600 for private keys
// - Use asymmetric algorithms (RS256/ES256/EdDSA) for production
//
// # Token Lifecycle
//
// ## Access Token Flow:
// 1. Generated with user identity and roles
// 2. Short-lived (configurable duration)
// 3. Verified on each API call
// 4. Optionally revocable via Redis
//
// ## Refresh Token Flow:
// 1. Generated with user identity
// 2. Long-lived (configurable duration)
// 3. Used to obtain new access tokens
// 4. Supports rotation (invalidates old tokens)
//
// # Token Rotation
//
// When refresh token rotation is enabled:
// - Old tokens are invalidated after use
// - Token reuse is detected via Redis
// - New tokens are issued with same session identity
//
// Rotation example:
//
//	config.RefreshToken.RotationEnabled = true
//	config.RefreshToken.RevocationEnabled = true
//	redisOpts := &redis.Options{Addr: "localhost:6379"}
//	maker, _ := gourdianToken.NewGourdianTokenMaker(context.Background(), config, redisOpts)
//
//	// First use
//	refreshToken1, _ := maker.CreateRefreshToken(ctx, userID, "john", sessionID)
//
//	// Rotation
//	refreshToken2, err := maker.RotateRefreshToken(ctx, refreshToken1.Token)
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
// - Invalid tokens (expired, malformed, revoked)
// - Configuration errors
// - Key loading failures
// - Redis communication issues
// - Claim validation failures
//
// # Dependencies
//
// Core:
// - github.com/golang-jwt/jwt/v5
// - github.com/google/uuid
//
// Optional (for revocation/rotation):
// - github.com/redis/go-redis/v9
//
// # Examples
//
// ## Symmetric Key Example
//
//	key := base64.RawURLEncoding.EncodeToString(generateRandomBytes(32))
//	config := gourdiantoken.DefaultGourdianTokenConfig(key)
//	maker, _ := gourdiantoken.NewGourdianTokenMaker(ctx, config, nil)
//	token, _ := maker.CreateAccessToken(ctx, userID, "user", []string{"admin"}, sessionID)
//
// ## Asymmetric Key Example
//
//	config := gourdiantoken.GourdianTokenConfig{
//	    Algorithm:      "RS256",
//	    SigningMethod:  gourdiantoken.Asymmetric,
//	    PrivateKeyPath: "/path/to/private.pem",
//	    PublicKeyPath:  "/path/to/public.pem",
//	    AccessToken: gourdiantoken.AccessTokenConfig{
//	        Duration:    30 * time.Minute,
//	        MaxLifetime: 24 * time.Hour,
//	        Issuer:      "myapp.com",
//	        RevocationEnabled: true,
//	    },
//	    RefreshToken: gourdiantoken.RefreshTokenConfig{
//	        Duration:        7 * 24 * time.Hour,
//	        RotationEnabled: true,
//	    },
//	}
//	maker, _ := gourdiantoken.NewGourdianTokenMaker(ctx, config, redisOpts)
//
// # Security Best Practices
//
// When using this package in production:
// 1. Always use HTTPS
// 2. Store secrets in secure secret management systems
// 3. Set minimum token lifetimes for your use case
// 4. Monitor for abnormal token patterns
// 5. Rotate cryptographic keys periodically
// 6. Keep dependencies updated
// 7. Enable revocation for sensitive applications
// 8. Use proper key sizes (256-bit for HMAC, 2048+ for RSA)
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
//	    claims, err := maker.VerifyAccessToken(context.Background(), token)
//	    // verification tests...
//	}
//
// # Performance
//
// The package has been extensively benchmarked with the following results:
//
// ## Test Coverage
// - 70.4% statement coverage (full coverage of critical paths)
// - Core token operations and security features fully covered
//
// ## Benchmark Results (Intel i5-9300H @ 2.40GHz)
//
// ### Token Creation
// - HMAC-SHA256: ~7,600 ns/op (160k ops/sec)
// - RSA-2048: ~1.23ms/op (921 ops/sec)
// - ECDSA-P256: ~46μs/op (27k ops/sec)
// - Parallel creation: ~5μs/op (227k ops/sec)
//
// ### Token Verification
// - HMAC-SHA256: ~8.9μs/op (129k ops/sec)
// - RSA-2048: ~45μs/op (27k ops/sec)
// - ECDSA-P256: ~86μs/op (13k ops/sec)
// - Parallel verification: ~4.2μs/op (272k ops/sec)
//
// ### Advanced Operations
// - Token rotation: ~687μs/op (1,570 ops/sec)
// - Token revocation: ~232μs/op (4,852 ops/sec)
// - Parallel rotation: ~196μs/op (5,659 ops/sec)
//
// ### Memory Characteristics
// - HMAC token creation: ~4.6KB/op, 58 allocs/op
// - RSA token creation: ~5.7KB/op, 56 allocs/op
// - Verification: ~3.4-5.1KB/op, 66-80 allocs/op
//
// ### Algorithm Comparison
// | Algorithm      | Create (ns/op) | Verify (ns/op) | Memory (B/op) |
// |----------------|----------------|----------------|---------------|
// | HMAC-256       | 7,604          | 8,916          | 4,682         |
// | HMAC-384       | 8,236          | 9,371          | 5,083         |
// | HMAC-512       | 8,864          | 9,936          | 5,163         |
// | RSA-2048       | 1,233,938      | 45,002         | 5,772         |
// | RSA-4096       | 6,916,576      | 372,440        | 44,204        |
// | ECDSA-P256     | 46,240         | 86,439         | 11,079        |
// | ECDSA-P384     | 273,140        | 759,271        | 11,624        |
// | EdDSA          | 52,110*        | 92,340*        | 10,920*       |
// (* estimated based on similar implementations)
//
// ## Performance Recommendations
// 1. Use HMAC for high-throughput applications
// 2. Use ECDSA for balanced performance/security
// 3. Avoid RSA-4096 for latency-sensitive applications
// 4. Leverage parallel verification for API endpoints
// 5. Consider Redis connection pooling for rotation/revocation
//
// # Limitations
//
// 1. Requires Go 1.18+
// 2. Redis is required for advanced features
// 3. Asymmetric algorithms require proper key management
//
// # See Also
//
// Related packages:
// - golang.org/x/oauth2 for OAuth2 integration
// - github.com/gorilla/securecookie for cookie storage
// - github.com/auth0/go-jwt-middleware for HTTP middleware
package gourdiantoken
