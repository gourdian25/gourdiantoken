// File: docs.go

// Package gourdiantoken provides a secure and flexible JWT-based token management system
// with advanced security features for Go applications.
//
// # Overview
//
// The gourdiantoken package implements a production-ready JWT token system with:
// - Secure token generation and validation using modern cryptographic standards
// - Configurable token lifetimes and security policies
// - Support for both symmetric (HMAC) and asymmetric (RSA/ECDSA/EdDSA) algorithms
// - Redis-backed token revocation and rotation
// - Comprehensive claim validation with strict security defaults
//
// # Core Features
//
// ## Token Types
// - Access Tokens: Short-lived tokens (default 30m) containing user authorization roles
// - Refresh Tokens: Long-lived tokens (default 7d) for obtaining new access tokens
//
// ## Security Features
// - Algorithm flexibility (HS256/384/512, RS256/384/512, ES256/384/512, PS256/384/512, EdDSA)
// - Automatic expiration validation with maximum lifetime enforcement
// - Required claim enforcement (issuer, audience, expiration, etc.)
// - Refresh token rotation with reuse detection
// - Secure key handling with file permission checks
// - Redis-based revocation for immediate token invalidation
//
// # Getting Started
//
// Basic usage pattern:
//
//	// 1. Create configuration (HMAC example)
//	config := gourdiantoken.DefaultGourdianTokenConfig("your-32-byte-base64-secret")
//	config.Issuer = "myapp.com"
//	config.Audience = []string{"api.myapp.com"}
//	config.RevocationEnabled = true
//
//	// 2. Initialize maker
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
//	    "john.doe",
//	    []string{"user", "admin"},
//	    uuid.New(), // session ID
//	)
//
//	// 4. Verify tokens
//	claims, err := maker.VerifyAccessToken(context.Background(), accessToken.Token)
//	if err != nil {
//	    log.Fatal("Invalid token:", err)
//	}
//
// # Configuration
//
// The package offers flexible configuration through:
//
// 1. DefaultGourdianTokenConfig() - Secure HMAC defaults with minimal setup
// 2. NewGourdianTokenConfig() - Full control over all security parameters
//
// ## Security Recommendations
// - Use 32+ byte keys for HMAC algorithms (HS256+)
// - Set access token lifetime to 15-60 minutes based on sensitivity
// - Set refresh token lifetime to 1-30 days with rotation enabled
// - Enable revocation for sensitive applications
// - Use asymmetric algorithms (RS256/ES256/EdDSA) for production systems
// - Set file permissions to 0600 for private keys
//
// # Token Lifecycle Management
//
// ## Access Token Flow:
// 1. Generated with user identity, roles, and session context
// 2. Short-lived with configurable expiration
// 3. Verified on each API request
// 4. Revocable via Redis when revocation is enabled
//
// ## Refresh Token Flow:
// 1. Generated with user identity and session context
// 2. Long-lived with separate expiration policy
// 3. Used to obtain new access tokens via rotation
// 4. Supports automatic invalidation of previous tokens
//
// # Advanced Features
//
// ## Token Rotation
//
// When enabled, refresh tokens automatically rotate:
// - Old tokens are invalidated after use
// - Reuse attempts are detected and blocked
// - New tokens maintain session continuity
//
// Example:
//
//	config := gourdiantoken.DefaultGourdianTokenConfig("secret")
//	config.RotationEnabled = true
//	config.RevocationEnabled = true
//
//	maker, _ := gourdiantoken.NewGourdianTokenMaker(ctx, config, redisOpts)
//	refreshToken, _ := maker.CreateRefreshToken(ctx, userID, "user", sessionID)
//
//	// Later, rotate the token
//	newToken, err := maker.RotateRefreshToken(ctx, refreshToken.Token)
//
// ## Revocation
//
// Tokens can be explicitly revoked:
//
//	err := maker.RevokeAccessToken(ctx, tokenString)
//	err := maker.RevokeRefreshToken(ctx, tokenString)
//
// Revoked tokens will fail verification even if otherwise valid.
//
// # Security Best Practices
//
// Production deployments should:
// 1. Always use HTTPS for token transmission
// 2. Store secrets in secure vaults (not in code)
// 3. Set minimum necessary token lifetimes
// 4. Monitor for abnormal token usage patterns
// 5. Rotate cryptographic keys periodically
// 6. Enable all available security features
// 7. Use proper key sizes:
//   - 256+ bit for HMAC
//   - 2048+ bit for RSA
//   - P-256/P-384 for ECDSA
//
// # Error Handling
//
// The package returns detailed errors for:
// - Invalid tokens (expired, malformed, revoked)
// - Configuration errors (invalid algorithms, key sizes)
// - Key loading failures
// - Redis communication issues
// - Claim validation failures
//
// # Dependencies
//
// Required:
// - github.com/golang-jwt/jwt/v5 - JWT implementation
// - github.com/google/uuid - UUID generation
//
// Optional (for revocation/rotation):
// - github.com/redis/go-redis/v9 - Redis client
//
// # Examples
//
// ## HMAC-SHA256 Example
//
//	// Generate secure random key
//	key := base64.RawURLEncoding.EncodeToString(cryptoRandBytes(32))
//
//	// Configure
//	config := gourdiantoken.DefaultGourdianTokenConfig(key)
//	config.Issuer = "myapp.com"
//	config.AccessExpiryDuration = 15 * time.Minute
//
//	// Create maker
//	maker, _ := gourdiantoken.NewGourdianTokenMaker(ctx, config, nil)
//
//	// Generate token
//	token, _ := maker.CreateAccessToken(ctx, userID, "user", []string{"admin"}, sessionID)
//
// ## RSA Example
//
//	config := gourdiantoken.GourdianTokenConfig{
//	    SigningMethod:  gourdiantoken.Asymmetric,
//	    Algorithm:      "RS256",
//	    PrivateKeyPath: "/path/to/private.pem",
//	    PublicKeyPath:  "/path/to/public.pem",
//	    Issuer:         "secure.myapp.com",
//	    Audience:       []string{"api.myapp.com"},
//	    AccessExpiryDuration:     30 * time.Minute,
//	    AccessMaxLifetimeExpiry:  24 * time.Hour,
//	    RefreshExpiryDuration:    7 * 24 * time.Hour,
//	    RefreshMaxLifetimeExpiry: 30 * 24 * time.Hour,
//	    RotationEnabled:         true,
//	    RevocationEnabled:       true,
//	}
//
//	maker, _ := gourdiantoken.NewGourdianTokenMaker(ctx, config, redisOpts)
//
// # Performance Characteristics
//
// Benchmarks on AWS t3.medium (Go 1.21):
//
// ## Token Operations
// | Operation          | Algorithm | Time (μs) | Throughput | Memory |
// |--------------------|-----------|-----------|------------|--------|
// | Create Access      | HS256     | 7.6       | 131k ops/s | 4.6KB  |
// | Verify Access      | HS256     | 8.9       | 112k ops/s | 3.4KB  |
// | Create Access      | RS256     | 1234      | 810 ops/s  | 5.7KB  |
// | Verify Access      | RS256     | 45        | 22k ops/s  | 5.1KB  |
// | Create Access      | ES256     | 46        | 21k ops/s  | 11KB   |
// | Verify Access      | ES256     | 86        | 11k ops/s  | 10KB   |
// | Rotate Refresh     | HS256     | 687       | 1.4k ops/s | 12KB   |
// | Revoke Token       | -         | 232       | 4.3k ops/s | 8KB    |
//
// ## Recommendations
// 1. Use HMAC for high-throughput services (>100k requests/sec)
// 2. Use ECDSA for balanced performance/security
// 3. Consider RSA for compatibility with existing systems
// 4. Enable connection pooling for Redis operations
//
// # Testing
//
// The package is designed for testability:
// - Interface-based design allows mock implementations
// - Configurable timeouts for expiration testing
// - Clear separation of concerns
//
// Example test:
//
//	func TestTokenRotation(t *testing.T) {
//	    maker := createTestMaker()
//	    oldToken := createTestRefreshToken(maker)
//
//	    // First rotation should succeed
//	    newToken1, err := maker.RotateRefreshToken(ctx, oldToken)
//	    require.NoError(t, err)
//
//	    // Second attempt should fail
//	    _, err = maker.RotateRefreshToken(ctx, oldToken)
//	    require.Error(t, err)
//	}
//
// # Limitations
//
// 1. Requires Go 1.18+
// 2. Redis is required for revocation/rotation features
// 3. Asymmetric algorithms require proper key management
//
// # See Also
//
// Related packages:
// - golang.org/x/oauth2 - OAuth2 integration
// - github.com/gorilla/securecookie - Secure cookie handling
// - github.com/auth0/go-jwt-middleware - HTTP middleware
//
// # Versioning
//
// This package follows semantic versioning (SemVer). Breaking changes will only
// be introduced in major version updates.
//
// # License
//
// MIT License - see LICENSE file for full text
package gourdiantoken
