// File: docs.go

// Package gourdiantoken provides a production-ready JWT token management system
// with comprehensive security features, flexible storage backends, and support for
// multiple cryptographic algorithms.
//
// # Overview
//
// The gourdiantoken package implements a robust JWT token lifecycle management
// system designed for enterprise authentication systems. It provides:
//
//   - Access and refresh token generation with configurable lifetimes
//   - Cryptographic signing with symmetric (HMAC) and asymmetric (RSA, ECDSA, EdDSA) algorithms
//   - Token verification with comprehensive security checks
//   - Optional token revocation for logout and security incident response
//   - Refresh token rotation for preventing token replay attacks
//   - Multiple storage backends for revocation/rotation tracking
//   - Thread-safe concurrent operations with context-aware cancellation
//   - Automatic background cleanup of expired tokens
//   - Highly configurable security policies
//
// # Architecture
//
// ## Core Components
//
// ### Token Types
//
// The package supports two primary token types:
//
//   - AccessToken: Short-lived tokens (default 30 minutes) containing user identity,
//     session information, and authorization roles. Used for API authorization and
//     should be transmitted in Authorization headers. AccessTokenClaims include
//     the "rls" (roles) claim for RBAC.
//
//   - RefreshToken: Long-lived tokens (default 7 days) used solely to obtain new
//     access tokens without re-authentication. RefreshTokenClaims do not include
//     roles since they're not directly used for authorization. Should be stored
//     securely (httpOnly cookies recommended).
//
// ### Cryptographic Support
//
// Symmetric algorithms (HMAC):
//   - HS256: HMAC with SHA-256 (recommended for development)
//   - HS384: HMAC with SHA-384
//   - HS512: HMAC with SHA-512
//
// Asymmetric algorithms (RSA with PKCS#1 v1.5):
//   - RS256, RS384, RS512: RSA signatures with PKCS#1 v1.5
//
// Asymmetric algorithms (RSA-PSS, recommended for new implementations):
//   - PS256, PS384, PS512: RSA PSS signatures
//
// ECDSA algorithms:
//   - ES256: ECDSA with P-256 curve and SHA-256
//   - ES384: ECDSA with P-384 curve and SHA-384
//   - ES512: ECDSA with P-521 curve and SHA-512
//
// EdDSA algorithms:
//   - EdDSA: Ed25519 signatures (modern, recommended for new systems)
//
// ### Storage Backends
//
// The package provides multiple implementations of TokenRepository for different
// deployment scenarios:
//
//   - MemoryTokenRepository: In-memory storage with background cleanup. Suitable for
//     development, testing, and single-instance deployments. Data lost on restart.
//
//   - GormTokenRepository: SQL database support via GORM ORM. Works with PostgreSQL,
//     MySQL, SQLite, SQL Server, and CockroachDB. Recommended for production systems
//     with persistent storage requirements.
//
//   - MongoTokenRepository: MongoDB document storage with optional transaction support.
//     Provides automatic TTL index-based cleanup and horizontal scaling via sharding.
//
//   - RedisTokenRepository: High-performance in-memory store with TTL-based expiration.
//     Recommended for systems requiring sub-millisecond token validation latency.
//     Supports Redis Cluster for distributed deployments.
//
// ### Configuration
//
// All token creation, validation, and security policies are controlled through
// GourdianTokenConfig. Two factory methods provide different levels of control:
//
//   - DefaultGourdianTokenConfig(): Pre-configured with secure HMAC defaults suitable
//     for immediate use. Customizable after creation.
//
//   - NewGourdianTokenConfig(): Full explicit control for complex requirements or
//     asymmetric algorithm setup.
//
// ## Token Claims Structure
//
// ### AccessTokenClaims (JWT Payload)
//
// Standard JWT claims (RFC 7519):
//   - jti (JWT ID): Unique token identifier (UUIDv4)
//   - iss (Issuer): Authentication service identifier
//   - aud (Audience): Intended recipients list
//   - sub (Subject): User's unique identifier (UUID)
//   - iat (Issued At): Token creation timestamp
//   - exp (Expiration Time): Token expiration timestamp
//   - nbf (Not Before): Optional token validity start time
//   - typ (Type): Always "access" for access tokens
//
// Custom claims:
//   - sid (Session ID): Session identifier for tracking user sessions
//   - usr (Username): Human-readable username for logging
//   - rls (Roles): Array of authorization roles for RBAC
//   - mle (Maximum Lifetime Expiry): Absolute expiration regardless of refreshes
//
// ### RefreshTokenClaims (JWT Payload)
//
// Similar structure to AccessTokenClaims but without:
//   - rls (Roles): Not included in refresh tokens
//
// Both token types include all required JWT claims and custom tracking information.
//
// # Key Features and Behaviors
//
// ## Token Creation
//
// Access Token Flow:
//  1. Validates input parameters (user ID, roles, session ID)
//  2. Generates unique token ID (UUIDv4)
//  3. Sets timestamps: iat (now), exp (now + AccessExpiryDuration),
//     nbf (now), mle (now + AccessMaxLifetimeExpiry)
//  4. Cryptographically signs the token payload
//  5. Returns AccessTokenResponse with signed JWT and metadata
//
// Refresh Token Flow:
//  1. Similar validation and setup as access tokens
//  2. No roles included in token
//  3. Longer default lifetime for session continuity
//  4. Returns RefreshTokenResponse with signed JWT and metadata
//
// ## Token Verification
//
// Access Token Verification Process:
//  1. Check context cancellation
//  2. Check revocation status (if RevocationEnabled)
//  3. Verify cryptographic signature
//  4. Validate algorithm matches expected method
//  5. Check all timestamps: iat, exp, nbf, mle
//  6. Verify required claims presence
//  7. Validate token type is "access"
//  8. Parse and return AccessTokenClaims
//
// Refresh Token Verification Process:
//  1. Same as access token verification, plus:
//  2. Check rotation status (if RotationEnabled)
//  3. Return RefreshTokenClaims
//
// Verification failures provide detailed error information for debugging and logging.
//
// ## Token Revocation
//
// Revocation operates as follows:
//  1. User initiates logout or revocation request
//  2. RevokeAccessToken() / RevokeRefreshToken() is called
//  3. Token is parsed to extract expiration time
//  4. Token hash (SHA-256) is stored in repository with TTL
//  5. TTL is set to match token's natural expiration time
//  6. Subsequent verification checks revocation status before accepting token
//  7. Background cleanup automatically removes expired revocation records
//
// Use cases:
//   - User logout (revoke both access and refresh tokens)
//   - Security incident response (immediately revoke compromised tokens)
//   - Password change (revoke all user tokens)
//   - Session termination (revoke all session tokens)
//
// ## Token Rotation (Refresh Token Rotation)
//
// Rotation prevents refresh token reuse and provides attack detection:
//
//  1. Client calls RotateRefreshToken() with old refresh token
//  2. Old token is verified (signature, expiration, revocation status)
//  3. Old token is atomically marked as rotated using compare-and-swap
//  4. If already rotated by another request, operation fails (attack detected)
//  5. New refresh token is created with fresh expiration time
//  6. New token is returned to client; old token is now invalid
//  7. Background cleanup removes expired rotation records
//
// Security guarantees:
//   - Only one concurrent rotation succeeds (atomic operation)
//   - Multiple attempts detect possible token theft
//   - Limits blast radius of compromised tokens
//   - Enables enforcing re-authentication after detecting reuse
//
// Rotation detection enables strong security policies:
//   - Log potential security incidents
//   - Force re-authentication for suspicious patterns
//   - Invalidate entire sessions
//   - Trigger additional security checks (MFA, device verification)
//
// # Configuration Guide
//
// ## GourdianTokenConfig Fields
//
// Signing and Algorithm Configuration:
//   - SigningMethod: Must be either Symmetric or Asymmetric
//   - Algorithm: Specific JWT algorithm (HS256, RS256, ES256, EdDSA, etc.)
//   - SymmetricKey: Base64-encoded secret for HMAC algorithms (required for Symmetric)
//   - PrivateKeyPath: Path to PEM-encoded private key (required for Asymmetric)
//   - PublicKeyPath: Path to PEM-encoded public key (required for Asymmetric)
//
// JWT Claims Configuration:
//   - Issuer: Authentication service identifier (included in "iss" claim)
//   - Audience: Intended token recipients (included in "aud" claim)
//   - AllowedAlgorithms: Whitelist of acceptable algorithms during verification
//   - RequiredClaims: List of mandatory claims beyond JWT standard claims
//
// Token Lifetime Configuration:
//   - AccessExpiryDuration: Time until access token expires after issuance (default 30m)
//   - AccessMaxLifetimeExpiry: Absolute maximum validity period for access tokens (default 24h)
//   - RefreshExpiryDuration: Time until refresh token expires after issuance (default 7d)
//   - RefreshMaxLifetimeExpiry: Absolute maximum validity period for refresh tokens (default 30d)
//   - RefreshReuseInterval: Minimum time between token reuse attempts (default 5m)
//
// Feature Flags and Cleanup:
//   - RotationEnabled: Whether to enforce refresh token rotation (default false)
//   - RevocationEnabled: Whether to allow token revocation (default false)
//   - CleanupInterval: How often to remove expired tokens from storage (default 6h)
//
// ## Configuration Examples
//
// Symmetric (HMAC) Development Configuration:
//
//	config := gourdiantoken.DefaultGourdianTokenConfig(
//	    "your-secret-key-at-least-32-bytes-long",
//	)
//	config.Issuer = "auth.example.com"
//	config.Audience = []string{"api.example.com"}
//	config.AccessExpiryDuration = 15 * time.Minute
//	config.RefreshExpiryDuration = 24 * time.Hour
//
// Asymmetric (RSA) Production Configuration:
//
//	config := gourdiantoken.NewGourdianTokenConfig(
//	    gourdiantoken.Asymmetric,
//	    true, true,  // rotation, revocation enabled
//	    []string{"api.example.com"},
//	    []string{"RS256", "PS256"},
//	    []string{"iss", "aud", "nbf", "mle"},
//	    "RS256",
//	    "", // no symmetric key for asymmetric
//	    "/secure/private.pem",
//	    "/secure/public.pem",
//	    "auth.production.example.com",
//	    15*time.Minute, 24*time.Hour,
//	    7*24*time.Hour, 30*24*time.Hour,
//	    5*time.Minute, 6*time.Hour,
//	)
//
// EdDSA (Ed25519) Production Configuration:
//
//	config := gourdiantoken.NewGourdianTokenConfig(
//	    gourdiantoken.Asymmetric,
//	    true, true,
//	    []string{"api.example.com"},
//	    []string{"EdDSA"},
//	    []string{"iss", "aud", "nbf", "mle"},
//	    "EdDSA",
//	    "",
//	    "/keys/ed25519-private.pem",
//	    "/keys/ed25519-public.pem",
//	    "auth.example.com",
//	    15*time.Minute, 24*time.Hour,
//	    7*24*time.Hour, 30*24*time.Hour,
//	    5*time.Minute, 6*time.Hour,
//	)
//
// # Factory Methods and Initialization
//
// ## Stateless Token Maker (No Storage)
//
// For systems that only validate tokens without revocation/rotation:
//
//	maker, err := gourdiantoken.NewGourdianTokenMakerNoStorage(ctx, config)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
// Use cases:
//   - Microservices that only validate tokens
//   - Distributed systems with no shared state
//   - High-performance scenarios where database lookups unacceptable
//
// Limitations:
//   - RevocationEnabled must be false
//   - RotationEnabled must be false
//   - No token revocation capability
//   - No refresh token rotation
//
// ## In-Memory Token Maker
//
// For development and testing with optional revocation/rotation:
//
//	maker, err := gourdiantoken.NewGourdianTokenMakerWithMemory(ctx, config)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
// Characteristics:
//   - Automatic background cleanup goroutine
//   - Data lost on application restart
//   - Sub-microsecond token operations
//   - Suitable for single-instance deployments
//   - Perfect for testing authentication logic
//
// ## SQL Database Token Maker (GORM)
//
// For production systems with SQL databases:
//
//	gormDB, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	maker, err := gourdiantoken.NewGourdianTokenMakerWithGorm(ctx, config, gormDB)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
// Supported databases:
//   - PostgreSQL (recommended for production)
//   - MySQL/MariaDB
//   - SQLite (development only)
//   - SQL Server
//   - CockroachDB
//
// Features:
//   - ACID transaction support
//   - Complex query capabilities
//   - Connection pooling
//   - Automatic migrations
//   - Composite indexing for performance
//
// ## MongoDB Token Maker
//
// For document-oriented production systems:
//
//	client, err := mongo.Connect(ctx, options.Client().ApplyURI(mongoURI))
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	mongoDB := client.Database("auth_service")
//	maker, err := gourdiantoken.NewGourdianTokenMakerWithMongo(ctx, config, mongoDB)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
// Features:
//   - Automatic TTL-based cleanup via indexes
//   - Optional transaction support
//   - Horizontal scaling via sharding
//   - High-write throughput
//   - Flexible document schema
//
// Transaction behavior:
//   - Pass true to enable transactions (requires replica set)
//   - Pass false for standalone instances
//
// ## Redis Token Maker
//
// For high-performance systems requiring sub-millisecond validation:
//
//	redisClient := redis.NewClient(&redis.Options{
//	    Addr:     "localhost:6379",
//	    PoolSize: 100,
//	})
//
//	maker, err := gourdiantoken.NewGourdianTokenMakerWithRedis(ctx, config, redisClient)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
// Performance characteristics:
//   - Sub-microsecond token operations
//   - O(1) for all operations
//   - Built-in TTL-based expiration
//   - Distributed via Redis Cluster
//   - High availability via Sentinel
//
// # Basic Usage Patterns
//
// ## Complete Authentication Flow
//
//	// 1. Initialize token maker
//	config := gourdiantoken.DefaultGourdianTokenConfig("secret-key")
//	maker, err := gourdiantoken.NewGourdianTokenMakerWithMemory(ctx, config)
//	if err != nil {
//	    return err
//	}
//	defer maker.Close()
//
//	// 2. Login endpoint - create token pair
//	accessToken, err := maker.CreateAccessToken(
//	    ctx,
//	    userID,              // uuid.UUID
//	    email,               // string
//	    []string{"user"},    // roles
//	    sessionID,           // uuid.UUID
//	)
//	if err != nil {
//	    return err
//	}
//
//	refreshToken, err := maker.CreateRefreshToken(ctx, userID, email, sessionID)
//	if err != nil {
//	    return err
//	}
//
//	// 3. Return tokens to client
//	w.Header().Set("Content-Type", "application/json")
//	json.NewEncoder(w).Encode(map[string]string{
//	    "access_token":  accessToken.Token,
//	    "refresh_token": refreshToken.Token,
//	})
//
//	// 4. Middleware - verify access token
//	func authMiddleware(next http.Handler) http.Handler {
//	    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
//	        authHeader := r.Header.Get("Authorization")
//	        token := strings.TrimPrefix(authHeader, "Bearer ")
//
//	        claims, err := maker.VerifyAccessToken(r.Context(), token)
//	        if err != nil {
//	            http.Error(w, "invalid token", http.StatusUnauthorized)
//	            return
//	        }
//
//	        // Attach claims to context
//	        ctx := context.WithValue(r.Context(), "claims", claims)
//	        next.ServeHTTP(w, r.WithContext(ctx))
//	    })
//	}
//
//	// 5. Token refresh endpoint
//	refreshToken := r.Header.Get("X-Refresh-Token")
//	newRefresh, err := maker.RotateRefreshToken(ctx, refreshToken)
//	if err != nil {
//	    http.Error(w, "invalid refresh token", http.StatusUnauthorized)
//	    return
//	}
//
//	newAccess, err := maker.CreateAccessToken(
//	    ctx, claims.Subject, claims.Username, roles, claims.SessionID)
//	if err != nil {
//	    http.Error(w, "failed to create token", http.StatusInternalServerError)
//	    return
//	}
//
//	// 6. Logout endpoint
//	accessToken := r.Header.Get("Authorization")
//	accessToken = strings.TrimPrefix(accessToken, "Bearer ")
//	maker.RevokeAccessToken(ctx, accessToken)
//	maker.RevokeRefreshToken(ctx, refreshTokenString)
//
// ## RBAC Authorization
//
//	func requireRole(requiredRole string) func(http.Handler) http.Handler {
//	    return func(next http.Handler) http.Handler {
//	        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
//	            claims := r.Context().Value("claims").(*gourdiantoken.AccessTokenClaims)
//
//	            hasRole := false
//	            for _, role := range claims.Roles {
//	                if role == requiredRole {
//	                    hasRole = true
//	                    break
//	                }
//	            }
//
//	            if !hasRole {
//	                http.Error(w, "insufficient permissions", http.StatusForbidden)
//	                return
//	            }
//
//	            next.ServeHTTP(w, r)
//	        })
//	    }
//	}
//
// # Security Considerations
//
// ## Algorithm Selection
//
// Symmetric (HMAC):
//   - Pros: Fastest performance, simplest deployment
//   - Cons: Shared secret must be distributed securely
//   - Recommendation: Development only, not production
//   - Minimum key size: 32 bytes (256 bits)
//
// RSA/RSA-PSS:
//   - Pros: Public key can be distributed, widely supported
//   - Cons: Slower than ECDSA for signing
//   - Recommendation: Good for backward compatibility
//   - Minimum key size: 2048 bits (3072+ recommended)
//
// ECDSA:
//   - Pros: Efficient key sizes, good performance
//   - Cons: Implementation complexity
//   - Recommendation: Excellent general-purpose choice
//   - Recommended curves: P-256, P-384
//
// EdDSA:
//   - Pros: Modern, fast, resistant to side-channel attacks
//   - Cons: Less widely supported in legacy systems
//   - Recommendation: Best for new implementations
//   - Standard algorithm: Ed25519 (128-bit security)
//
// ## Key Management Best Practices
//
// For Symmetric Keys:
//   - Generate using cryptographically secure random source
//   - Store in secure configuration management (Vault, etc.)
//   - Never commit to version control
//   - Rotate periodically (every 90 days recommended)
//   - Use environment variables or secrets managers
//
// For Asymmetric Keys:
//   - Generate using proper key generation tools
//   - Store private keys with 0600 file permissions
//   - Store public keys separately for distribution
//   - Use PKCS#8 or SEC1 formats (PEM-encoded)
//   - Implement key rotation strategy
//   - Consider hardware security modules for sensitive systems
//
// ## Token Lifetime Recommendations
//
// Access Tokens:
//   - Short-lived: 15-30 minutes for high-security systems
//   - Medium-lived: 30-60 minutes for balanced security
//   - Minimum: 5 minutes (usability threshold)
//   - Maximum: 2 hours (beyond this, use refresh tokens)
//
// Refresh Tokens:
//   - Short-lived: 1-7 days for high-security systems
//   - Medium-lived: 1-4 weeks for balanced security
//   - Long-lived: 30-90 days for consumer apps
//   - Maximum lifetime should limit implicit token chains
//
// ## Security Features Configuration
//
// For Development:
//
//	config := gourdiantoken.DefaultGourdianTokenConfig("dev-secret-key")
//	config.RotationEnabled = false
//	config.RevocationEnabled = false
//	config.AccessExpiryDuration = 1 * time.Hour
//
// For Production:
//
//	config := gourdiantoken.NewGourdianTokenConfig(
//	    gourdiantoken.Asymmetric,
//	    true, true,  // Enable rotation and revocation
//	    []string{"api.example.com"},
//	    []string{"RS256", "ES256", "EdDSA"},
//	    []string{"iss", "aud", "nbf", "mle"},
//	    "ES256",
//	    "",
//	    "/secure/private.pem",
//	    "/secure/public.pem",
//	    "auth.example.com",
//	    15*time.Minute, 24*time.Hour,
//	    7*24*time.Hour, 30*24*time.Hour,
//	    5*time.Minute, 6*time.Hour,
//	)
//
// ## Attack Prevention
//
// Token Replay Attack Prevention:
//   - Enable RotationEnabled for refresh token protection
//   - Implement RefreshReuseInterval for delay-based detection
//   - Monitor for multiple rotation attempts (indicates theft)
//   - Store refresh tokens securely (httpOnly cookies)
//
// Token Theft Mitigation:
//   - Enable RevocationEnabled for logout support
//   - Implement device fingerprinting
//   - Use short access token lifetimes
//   - Implement rate limiting on token endpoints
//   - Monitor for suspicious token patterns
//
// Key Compromise Response:
//   - Revoke all existing tokens immediately
//   - Force full re-authentication
//   - Rotate compromised keys
//   - Audit token usage logs
//   - Consider additional verification (MFA)
//
// # Storage Backend Comparison
//
// ## Selection Matrix
//
// Use MemoryTokenRepository when:
//   - Developing and testing
//   - Single-instance deployment
//   - Restart-based token reset acceptable
//   - Testing authentication logic
//
// Use GormTokenRepository when:
//   - Existing SQL database in use
//   - ACID transaction requirements critical
//   - Complex query patterns needed
//   - Multi-instance deployment with shared database
//
// Use MongoTokenRepository when:
//   - Document-oriented storage preferred
//   - Horizontal scaling required
//   - Flexible schema beneficial
//   - TTL-based cleanup sufficient
//
// Use RedisTokenRepository when:
//   - Sub-millisecond latency critical
//   - High token validation throughput
//   - Can accept in-memory storage
//   - Distributed via cluster or Sentinel
//
// ## Performance Characteristics
//
// Operation Latencies (approximate):
//   - Memory: 1-10 microseconds
//   - Redis: 50-500 microseconds (network dependent)
//   - MongoDB: 500-5000 microseconds (with indexes)
//   - SQL (GORM): 1-10 milliseconds (with indexes)
//
// Token Creation Performance:
//   - Symmetric signing: 100,000+ tokens/second
//   - ECDSA signing: 50,000+ tokens/second
//   - RSA signing: 1,000-5,000 tokens/second
//   - EdDSA signing: 50,000+ tokens/second
//
// Token Verification Performance:
//   - Symmetric verification: 500,000+ tokens/second
//   - ECDSA verification: 200,000+ tokens/second
//   - RSA verification: 50,000+ tokens/second (much faster than signing)
//   - EdDSA verification: 200,000+ tokens/second
//
// # Error Handling
//
// ## Common Error Scenarios
//
// Invalid Token Errors:
//   - Malformed JWT: "invalid token" with parsing details
//   - Signature mismatch: "invalid token" with algorithm details
//   - Expired token: "token has expired"
//   - Future token: "token issued in the future"
//   - Exceeds max lifetime: "token exceeded maximum lifetime"
//
// Revocation Errors:
//   - Revocation disabled: "access token revocation is not enabled"
//   - Token revoked: "token has been revoked"
//   - Database error: detailed error with context
//
// Rotation Errors:
//   - Rotation disabled: "token rotation not enabled"
//   - Already rotated: "token has been rotated"
//   - Database error: detailed error with context
//
// Configuration Errors:
//   - Algorithm mismatch: "algorithm HS256 not compatible with asymmetric signing"
//   - Key file missing: "failed to read private key file"
//   - Invalid duration: "access token duration must be positive"
//   - Invalid key size: "symmetric key must be at least 32 bytes"
//
// ## Error Recovery Patterns
//
//	// Handle token expiration
//	claims, err := maker.VerifyAccessToken(ctx, token)
//	if err != nil {
//	    if strings.Contains(err.Error(), "expired") {
//	        // Attempt refresh
//	        newToken, err := refreshAccessToken(ctx)
//	        if err != nil {
//	            // Force re-authentication
//	            return redirectToLogin()
//	        }
//	        return newToken
//	    }
//	    return handleAuthError(err)
//	}
//
//	// Handle rotation detection
//	newToken, err := maker.RotateRefreshToken(ctx, oldToken)
//	if err != nil {
//	    if strings.Contains(err.Error(), "rotated") {
//	        // Suspicious activity detected
//	        logSecurityAlert("token reuse detected")
//	        revokeAllUserTokens(ctx, userID)
//	        return errors.New("security violation: session terminated")
//	    }
//	    return handleError(err)
//	}
//
// # Advanced Topics
//
// ## Multi-Service Token Validation
//
// For distributed systems where multiple services validate the same tokens:
//
//	// Auth service (creates tokens)
//	authMaker, _ := gourdiantoken.NewGourdianTokenMakerWithRedis(ctx, config, redisClient)
//
//	// API service (validates tokens)
//	apiMaker, _ := gourdiantoken.NewGourdianTokenMakerWithRedis(ctx, config, redisClient)
//
// Both services use same Redis backend for revocation/rotation checking.
// For stateless validation without storage, omit the repository.
//
// ## Custom Claims Validation
//
//	config.RequiredClaims = []string{"iss", "aud", "nbf", "mle", "custom_claim"}
//	config.Audience = []string{"service1", "service2"}
//
// Claims are validated during verification. Additional custom logic can
// be applied after verification:
//
//	claims, err := maker.VerifyAccessToken(ctx, token)
//	if err != nil {
//	    return err
//	}
//
//	if !slices.Contains(claims.Roles, "admin") {
//	    return errors.New("admin role required")
//	}
//
// ## Token Metadata and Auditing
//
// All token operations include comprehensive metadata:
//
//	accessResp, _ := maker.CreateAccessToken(ctx, userID, username, roles, sessionID)
//	// Contains: IssuedAt, ExpiresAt, NotBefore, MaxLifetimeExpiry
//	// Use for audit logs and client display
//
//	claims, _ := maker.VerifyAccessToken(ctx, token)
//	// Contains: ID (jti), Subject, SessionID for detailed tracking
//	// Use for request logging and security audit trails
//
// ## Background Cleanup Management
//
// Cleanup goroutines run automatically for token makers with storage:
//
//	maker, _ := gourdiantoken.NewGourdianTokenMakerWithMemory(ctx, config)
//	// Cleanup runs automatically at config.CleanupInterval
//
//	// Graceful shutdown
//	maker.Close()  // Stops cleanup goroutine
//
// Cleanup behavior:
//   - Runs at configured intervals
//   - Removes expired revocation records
//   - Removes expired rotation records
//   - Continues automatically until stopped
//   - Can be called manually for testing
//
// # Testing Patterns
//
// ## Unit Testing
//
//	func TestAccessTokenCreation(t *testing.T) {
//	    maker := createTestMaker()
//	    userID := uuid.New()
//	    sessionID := uuid.New()
//
//	    token, err := maker.CreateAccessToken(
//	        context.Background(),
//	        userID,
//	        "testuser",
//	        []string{"user"},
//	        sessionID,
//	    )
//	    require.NoError(t, err)
//	    assert.NotEmpty(t, token.Token)
//	    assert.Equal(t, userID, token.Subject)
//	}
//
// ## Integration Testing
//
//	func TestTokenRotation(t *testing.T) {
//	    redisClient := redis.NewClient(&redis.Options{Addr: "localhost:6379"})
//	    config := gourdiantoken.DefaultGourdianTokenConfig("test-secret")
//	    config.RotationEnabled = true
//	    maker, _ := gourdiantoken.NewGourdianTokenMakerWithRedis(
//	        context.Background(), config, redisClient)
//
//	    // Create refresh token
//	    refresh, _ := maker.CreateRefreshToken(context.Background(), userID, "user", sessionID)
//
//	    // Rotate token
//	    newRefresh, err := maker.RotateRefreshToken(context.Background(), refresh.Token)
//	    require.NoError(t, err)
//	    assert.NotEqual(t, refresh.Token, newRefresh.Token)
//
//	    // Old token should be invalid
//	    _, err = maker.VerifyRefreshToken(context.Background(), refresh.Token)
//	    assert.Error(t, err)
//	}
//
// ## Benchmark Testing
//
//	func BenchmarkAccessTokenCreation(b *testing.B) {
//	    maker := createBenchMaker()
//	    userID := uuid.New()
//	    sessionID := uuid.New()
//
//	    b.ResetTimer()
//	    for i := 0; i < b.N; i++ {
//	        maker.CreateAccessToken(context.Background(), userID, "user", []string{"role"}, sessionID)
//	    }
//	}
//
//	func BenchmarkAccessTokenVerification(b *testing.B) {
//	    maker := createBenchMaker()
//	    token, _ := maker.CreateAccessToken(context.Background(), userID, "user", []string{"role"}, sessionID)
//
//	    b.ResetTimer()
//	    for i := 0; i < b.N; i++ {
//	        maker.VerifyAccessToken(context.Background(), token.Token)
//	    }
//	}
//
// # Thread Safety and Concurrency
//
// All methods in GourdianTokenMaker are thread-safe for concurrent use across
// multiple goroutines. The implementation uses:
//
//   - Immutable state after initialization (no race conditions)
//   - Thread-safe underlying JWT library
//   - Concurrent-safe repository implementations
//   - Proper context handling for cancellation
//
// Safe concurrent usage:
//
//	for i := 0; i < 100; i++ {
//	    go func() {
//	        claims, err := maker.VerifyAccessToken(ctx, token)
//	        // Handle result
//	    }()
//	}
//
// MemoryTokenRepository uses RWMutex for concurrent access:
//   - Multiple concurrent readers (VerifyAccessToken)
//   - Exclusive writers (RevokeAccessToken, RotateRefreshToken)
//   - Automatic background cleanup without blocking operations
//
// Redis and database repositories provide inherent thread safety through
// their underlying implementations.
//
// # Context Handling
//
// All operations accept a context.Context for cancellation, timeout, and
// deadline management:
//
//	// With timeout
//	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
//	defer cancel()
//	claims, err := maker.VerifyAccessToken(ctx, token)
//
//	// With cancellation
//	ctx, cancel := context.WithCancel(context.Background())
//	defer cancel()
//	token, err := maker.CreateAccessToken(ctx, userID, username, roles, sessionID)
//
//	// Operations check context at multiple points
//	// Cancellation returns immediately with context error
//
// # Dependencies
//
// Required external dependencies:
//   - github.com/golang-jwt/jwt/v5: JWT implementation
//   - github.com/google/uuid: UUID generation and parsing
//
// Optional dependencies (for storage backends):
//   - gorm.io/gorm: SQL database ORM
//   - go.mongodb.org/mongo-driver: MongoDB database driver
//   - github.com/redis/go-redis/v9: Redis client
//
// All dependencies use modern versions and stable APIs.
//
// # Version Compatibility
//
// Minimum requirements:
//   - Go 1.18 or later (generics support)
//   - JWT library v5.x
//   - UUID library v1.x
//
// Database backend version requirements:
//   - GORM: v1.25+
//   - MongoDB: 4.0+ (4.2+ recommended for transactions)
//   - Redis: 6.0+ (recommended)
//
// # Migration and Upgrade Guide
//
// ## From Stateless to Revocation-Enabled
//
// Existing deployments can add revocation without recreating tokens:
//
//	// Step 1: Choose storage backend (e.g., Redis)
//	redisClient := redis.NewClient(&redis.Options{Addr: "localhost:6379"})
//
//	// Step 2: Update configuration
//	config.RevocationEnabled = true
//	config.RotationEnabled = true
//
//	// Step 3: Create new maker with storage
//	maker, err := gourdiantoken.NewGourdianTokenMakerWithRedis(ctx, config, redisClient)
//
//	// Existing tokens remain valid until natural expiration
//	// New tokens support revocation immediately
//
// ## Algorithm Migration
//
// Transitioning from HMAC to RSA:
//
//	// Phase 1: Both algorithms allowed
//	config.AllowedAlgorithms = []string{"HS256", "RS256"}
//
//	// Phase 2: Create tokens with new algorithm
//	config.Algorithm = "RS256"
//	// Old HS256 tokens still validated
//
//	// Phase 3: After expiration period, restrict to RS256
//	config.AllowedAlgorithms = []string{"RS256"}
//
// ## Storage Backend Migration
//
// From memory to Redis:
//
//	// Existing revoked/rotated tokens are lost (acceptable for transition)
//	oldMaker, _ := gourdiantoken.NewGourdianTokenMakerWithMemory(ctx, config)
//	oldMaker.Close()
//
//	// Deploy new Redis-backed maker
//	redisClient := redis.NewClient(...)
//	newMaker, _ := gourdiantoken.NewGourdianTokenMakerWithRedis(ctx, config, redisClient)
//
// # Common Pitfalls and Solutions
//
// ## Pitfall: Token Expiration Not Enforced
//
// Problem: All tokens are accepted regardless of expiration time.
// Solution: Ensure RequiredClaims includes "exp" and token verification is called.
//
//	// Correct: Always call VerifyAccessToken
//	claims, err := maker.VerifyAccessToken(ctx, token)
//	if err != nil {
//	    return errors.New("token validation failed")
//	}
//
//	// Wrong: Parsing JWT without verification
//	token, _ := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
//	    return "any-secret", nil
//	})
//	// This bypasses all security checks
//
// ## Pitfall: Symmetric Key Too Short
//
// Problem: Configuration validation passes but security is weak.
// Solution: Use cryptographically secure random 32+ byte keys.
//
//	// Correct
//	key := make([]byte, 32)
//	rand.Read(key)
//	encodedKey := base64.RawURLEncoding.EncodeToString(key)
//	config := gourdiantoken.DefaultGourdianTokenConfig(encodedKey)
//
//	// Wrong
//	config := gourdiantoken.DefaultGourdianTokenConfig("short-key")
//	// Fails validation
//
// ## Pitfall: Refresh Token Rotation Without Storage
//
// Problem: Configuration requires storage but none provided.
// Solution: Provide repository or disable rotation.
//
//	// Correct: Use with storage
//	config.RotationEnabled = true
//	maker, err := gourdiantoken.NewGourdianTokenMakerWithMemory(ctx, config)
//
//	// Correct: Disable rotation for stateless
//	config.RotationEnabled = false
//	maker, err := gourdiantoken.NewGourdianTokenMakerNoStorage(ctx, config)
//
// ## Pitfall: Revocation Checks Not Running
//
// Problem: Revoked tokens still validate successfully.
// Solution: Ensure RevocationEnabled is true and storage is provided.
//
//	config.RevocationEnabled = true
//	maker, err := gourdiantoken.NewGourdianTokenMakerWithRedis(ctx, config, redisClient)
//	// RevocationEnabled must be true AND valid repository provided
//
// ## Pitfall: Private Key File Permissions Too Permissive
//
// Problem: Security validation rejects private key during initialization.
// Solution: Set proper file permissions before creating maker.
//
//	// Correct
//	chmod 0600 /path/to/private.pem
//
//	// Then create maker
//	maker, err := gourdiantoken.NewGourdianTokenMaker(ctx, config, repo)
//
// # Performance Tuning
//
// ## Token Creation Optimization
//
//	// Batch token creation for high throughput
//	tokens := make([]*gourdiantoken.AccessTokenResponse, 1000)
//	for i := 0; i < 1000; i++ {
//	    token, _ := maker.CreateAccessToken(ctx, userID, username, roles, sessionID)
//	    tokens[i] = token
//	}
//
//	// Use context with timeout for batch operations
//	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
//	defer cancel()
//
// ## Verification Caching (Application Level)
//
// For high-frequency verification of same tokens:
//
//	var cache sync.Map // Simple in-memory cache
//
//	func verifyWithCache(token string) (*Claims, error) {
//	    if cached, ok := cache.Load(token); ok {
//	        return cached.(*Claims), nil
//	    }
//	    claims, err := maker.VerifyAccessToken(ctx, token)
//	    if err != nil {
//	        return nil, err
//	    }
//	    cache.Store(token, claims)
//	    return claims, nil
//	}
//
// ## Redis Connection Pool Tuning
//
//	client := redis.NewClient(&redis.Options{
//	    Addr:     "localhost:6379",
//	    PoolSize: 100,    // Adjust based on concurrency
//	    MinIdleConns: 10, // Keep minimum connections open
//	})
//
// # Monitoring and Observability
//
// ## Token Statistics
//
// Most repository implementations provide Stats() for monitoring:
//
//	stats, err := repo.Stats(ctx)
//	// Returns counts of revoked/rotated tokens
//	// Use for Prometheus metrics or logging
//
//	log.Printf("Active revocations: %d", stats["total_revoked_tokens"])
//	log.Printf("Rotated tokens: %d", stats["rotated_tokens"])
//
// ## Audit Logging
//
//	func auditLog(action string, userID uuid.UUID, result error) {
//	    log.Printf("[AUDIT] action=%s user=%s result=%v timestamp=%s",
//	        action, userID, result, time.Now())
//	}
//
//	// Usage
//	auditLog("token_created", userID, nil)
//	auditLog("token_verified", userID, nil)
//	auditLog("token_revoked", userID, nil)
//
// ## Health Checks
//
//	func healthCheck(maker gourdiantoken.GourdianTokenMaker) error {
//	    // Create and verify test token
//	    token, err := maker.CreateAccessToken(
//	        context.Background(),
//	        testUserID,
//	        "health-check",
//	        []string{"test"},
//	        testSessionID,
//	    )
//	    if err != nil {
//	        return err
//	    }
//
//	    _, err = maker.VerifyAccessToken(context.Background(), token.Token)
//	    return err
//	}
//
// # Related Patterns and Best Practices
//
// ## Token-Based Session Management
//
// Using tokens for session tracking:
//
//	// Create session entry with tokens
//	session := &Session{
//	    ID:        sessionID,
//	    UserID:    userID,
//	    CreatedAt: time.Now(),
//	    ExpiresAt: time.Now().Add(30 * 24 * time.Hour),
//	}
//	db.SaveSession(session)
//
//	// Verify session still active during token verification
//	claims, _ := maker.VerifyAccessToken(ctx, token)
//	session, _ := db.GetSession(claims.SessionID)
//	if session == nil || session.ExpiresAt.Before(time.Now()) {
//	    return errors.New("session expired")
//	}
//
// ## Multi-Tenant Token Isolation
//
// For multi-tenant systems, include tenant information in token:
//
//	// Custom implementation using token claims
//	type TenantAccessClaims struct {
//	    *gourdiantoken.AccessTokenClaims
//	    TenantID string `json:"tid"`
//	}
//
//	// Verify tenant matches request
//	claims, _ := maker.VerifyAccessToken(ctx, token)
//	if claims.Subject != requestUserID {
//	    return errors.New("user mismatch")
//	}
//
// ## Device Fingerprinting
//
// For enhanced security, validate device consistency:
//
//	// Create token with device fingerprint
//	deviceID := hashDeviceInfo(r.Header)
//	// Store in session/database
//
//	// Verify device matches during token validation
//	currentDevice := hashDeviceInfo(r.Header)
//	if currentDevice != storedDevice {
//	    // Suspicious activity - require re-authentication
//	}
//
// # License and Support
//
// This package is provided as-is for production use. For issues, feature requests,
// or contributions, refer to the repository's issue tracker and contribution guidelines.
//
// # Conclusion
//
// The gourdiantoken package provides a comprehensive, flexible, and secure
// JWT token management system suitable for small startups to large enterprises.
// Its modular design with multiple storage backends and cryptographic algorithms
// allows customization for virtually any authentication requirement while
// maintaining strict security standards through validation, configuration
// enforcement, and best-practice defaults.
package gourdiantoken
