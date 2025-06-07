// File: docs.go

// Package gourdiantoken provides a comprehensive JWT token management system
// with advanced security features for Go applications.
//
// # Overview
//
// The package implements a production-ready JWT token system with:
// - Secure token generation and validation
// - Configurable token lifetimes and security policies
// - Support for both symmetric (HMAC) and asymmetric (RSA/ECDSA/EdDSA) algorithms
// - Optional Redis-backed token revocation and rotation
// - Strict claim validation with configurable requirements
//
// # Core Components
//
// ## Token Types
// - AccessToken: Short-lived tokens containing user roles (default 30m)
// - RefreshToken: Long-lived tokens for session continuity (default 7d)
//
// ## Configuration
// - GourdianTokenConfig: Central configuration struct
// - Two construction methods:
//   - DefaultGourdianTokenConfig(): HMAC-SHA256 with secure defaults
//   - NewGourdianTokenConfig(): Full customization
//
// # Key Features
//
// ## Security
// - Algorithm support:
//   - HMAC: HS256, HS384, HS512
//   - RSA: RS256, RS384, RS512, PS256, PS384, PS512
//   - ECDSA: ES256, ES384, ES512
//   - EdDSA: Ed25519
//
// - Automatic expiration validation
// - Required claim enforcement
// - Secure key handling with file permission checks
//
// ## Redis Integration
// - Token revocation (access and refresh)
// - Refresh token rotation
// - Automatic cleanup of expired records
//
// # Basic Usage
//
// ## Initialization
//
//	// HMAC example
//	config := gourdiantoken.DefaultGourdianTokenConfig("your-32-byte-secret")
//	config.Issuer = "myapp.com"
//	config.Audience = []string{"api.myapp.com"}
//
//	// With Redis
//	redisClient := redis.NewClient(&redis.Options{Addr: "localhost:6379"})
//	maker, err := gourdiantoken.NewGourdianTokenMaker(
//	    context.Background(),
//	    config,
//	    redisClient,
//	)
//
// ## Token Operations
//
//	// Create tokens
//	accessToken, err := maker.CreateAccessToken(
//	    ctx,
//	    userID,
//	    "username",
//	    []string{"role1", "role2"},
//	    sessionID,
//	)
//
//	refreshToken, err := maker.CreateRefreshToken(
//	    ctx,
//	    userID,
//	    "username",
//	    sessionID,
//	)
//
//	// Verify tokens
//	accessClaims, err := maker.VerifyAccessToken(ctx, accessToken.Token)
//	refreshClaims, err := maker.VerifyRefreshToken(ctx, refreshToken.Token)
//
//	// Revocation
//	err = maker.RevokeAccessToken(ctx, tokenString)
//	err = maker.RevokeRefreshToken(ctx, tokenString)
//
//	// Rotation
//	newRefreshToken, err := maker.RotateRefreshToken(ctx, oldRefreshToken)
//
// # Configuration Details
//
// ## GourdianTokenConfig Fields
//
// Key security parameters:
// - SigningMethod: Symmetric or Asymmetric
// - Algorithm: Specific JWT algorithm
// - SymmetricKey: Base64-encoded secret (for HMAC)
// - PrivateKeyPath/PublicKeyPath: Key files (for RSA/ECDSA)
// - Issuer/Audience: Token validation claims
// - AccessExpiryDuration: Access token validity (default 30m)
// - AccessMaxLifetimeExpiry: Absolute maximum lifetime (default 24h)
// - RefreshExpiryDuration: Refresh token validity (default 7d)
// - RefreshMaxLifetimeExpiry: Absolute maximum lifetime (default 30d)
// - RotationEnabled: Refresh token rotation (default false)
// - RevocationEnabled: Token revocation (default false)
// - RefreshReuseInterval: Minimum time between reuse attempts (default 5m)
//
// # Security Recommendations
//
// 1. For production:
//   - Use asymmetric algorithms (RS256/ES256/EdDSA)
//   - Set proper key sizes:
//   - RSA: 2048+ bits
//   - ECDSA: P-256/P-384 curves
//   - HMAC: 32+ byte keys
//   - Set file permissions to 0600 for private keys
//
// 2. Token lifetimes:
//   - Access tokens: 15-60 minutes
//   - Refresh tokens: 1-30 days
//
// 3. Enable all security features:
//   - Rotation for refresh tokens
//   - Revocation for sensitive applications
//
// # Advanced Features
//
// ## Token Rotation
//
// When enabled:
// - Each refresh token use generates a new token
// - Old tokens are recorded in Redis
// - Reuse attempts are blocked during the reuse interval
//
// Example:
//
//	config := gourdiantoken.DefaultGourdianTokenConfig("secret")
//	config.RotationEnabled = true
//	config.RefreshReuseInterval = 1 * time.Minute
//
// ## Revocation
//
// Revoked tokens:
// - Are stored in Redis with TTL matching token expiration
// - Fail verification even if otherwise valid
// - Are automatically cleaned up after expiration
//
// # Error Handling
//
// Common error scenarios:
// - Invalid tokens (expired, malformed, revoked)
// - Configuration errors (invalid algorithms, key sizes)
// - Key loading failures
// - Redis communication issues
// - Claim validation failures
//
// # Performance Considerations
//
// 1. Algorithm choice impacts performance:
//   - HMAC is fastest (100k+ ops/sec)
//   - ECDSA offers good balance
//   - RSA verification is fast but signing is slow
//
// 2. Redis operations add overhead:
//   - Revocation checks add ~200μs per verification
//   - Rotation adds ~700μs per operation
//
// # Testing
//
// The package includes:
// - Core functionality tests
// - Security validation tests
// - Redis integration tests
// - Benchmark tests
//
// Test patterns:
//
//	func TestAccessToken(t *testing.T) {
//	    maker := createTestMaker()
//	    token, err := maker.CreateAccessToken(...)
//	    require.NoError(t, err)
//
//	    claims, err := maker.VerifyAccessToken(ctx, token.Token)
//	    require.NoError(t, err)
//	    assert.Equal(t, "username", claims.Username)
//	}
//
// # Dependencies
//
// Required:
// - github.com/golang-jwt/jwt/v5 - JWT implementation
// - github.com/google/uuid - UUID generation
//
// Optional for Redis features(for revocation/rotation):
// - github.com/redis/go-redis/v9
//
// # Examples
//
// ## HMAC Configuration
//
//	config := gourdiantoken.DefaultGourdianTokenConfig(
//	    base64.RawURLEncoding.EncodeToString(secureRandomBytes(32)),
//	)
//	config.AccessExpiryDuration = 15 * time.Minute
//	config.RefreshExpiryDuration = 24 * time.Hour
//
//	maker, err := gourdiantoken.NewGourdianTokenMaker(ctx, config, nil)
//
// ## RSA Configuration
//
//	config := gourdiantoken.GourdianTokenConfig{
//	    SigningMethod:    gourdiantoken.Asymmetric,
//	    Algorithm:        "RS256",
//	    PrivateKeyPath:   "private.pem",
//	    PublicKeyPath:    "public.pem",
//	    Issuer:          "auth.example.com",
//	    RotationEnabled: true,
//	    RevocationEnabled: true,
//	}
//
//	redisClient := redis.NewClient(...)
//	maker, err := gourdiantoken.NewGourdianTokenMaker(ctx, config, redisClient)
//
// # Limitations
//
// 1. Requires Go 1.18+
// 2. Redis is optional but required for advanced features
// 3. Asymmetric algorithms require proper key management
//
// # See Also
//
// Related packages:
// - golang.org/x/oauth2
// - github.com/gorilla/securecookie
//
// # Versioning
//
// This package follows semantic versioning (SemVer). Breaking changes will only
// be introduced in major version updates.
//
// # License
//
// MIT License
package gourdiantoken
