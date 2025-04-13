// gourdiantoken.go

package gourdiantoken

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

type TokenType string

const (
	AccessToken  TokenType = "access"
	RefreshToken TokenType = "refresh"
)

type SigningMethod string

const (
	Symmetric  SigningMethod = "symmetric"
	Asymmetric SigningMethod = "asymmetric"
)

// GourdianTokenConfig defines the complete configuration needed to initialize the token system.
//
// This struct serves as the central configuration point for all token-related settings including:
// - Cryptographic algorithm selection
// - Key material paths or values
// - Access and refresh token lifetimes
// - Security features like rotation and revocation
//
// The configuration is designed to be explicit about security choices with safe defaults.
// All durations are in Go's time.Duration format (e.g., 30*time.Minute).
//
// Security Recommendations:
// - For production: Use asymmetric algorithms (RS256, ES256, EdDSA)
// - Set reasonable token lifetimes (short for access, longer for refresh)
// - Enable revocation for sensitive applications
//
// Example Configuration:
//
//	cfg := GourdianTokenConfig{
//	    Algorithm: "RS256",
//	    SigningMethod: Asymmetric,
//	    PrivateKeyPath: "/path/to/private.pem",
//	    PublicKeyPath: "/path/to/public.pem",
//	    AccessToken: AccessTokenConfig{
//	        Duration: 15*time.Minute,
//	        RevocationEnabled: true,
//	    },
//	    RefreshToken: RefreshTokenConfig{
//	        Duration: 7*24*time.Hour,
//	        RotationEnabled: true,
//	    },
//	}
type GourdianTokenConfig struct {
	Algorithm      string             // JWT signing algorithm (e.g., "HS256", "RS256"). Must match key type.
	SigningMethod  SigningMethod      // Cryptographic method (Symmetric/Asymmetric)
	SymmetricKey   string             // Base64-encoded secret key for HMAC (min 32 bytes for HS256)
	PrivateKeyPath string             // Path to PEM-encoded private key file (asymmetric only)
	PublicKeyPath  string             // Path to PEM-encoded public key/certificate (asymmetric only)
	AccessToken    AccessTokenConfig  // Fine-grained access token settings
	RefreshToken   RefreshTokenConfig // Fine-grained refresh token settings
}

// AccessTokenConfig contains settings specific to access token generation and validation.
//
// Access tokens are short-lived credentials that grant access to resources. These settings
// control their security characteristics and validation requirements.
//
// Important Security Settings:
// - Duration: Should be short (minutes to hours)
// - MaxLifetime: Absolute maximum validity period
// - RequiredClaims: Ensure essential claims are always validated
//
// Example:
//
//	AccessTokenConfig{
//	    Duration: 30*time.Minute,
//	    MaxLifetime: 24*time.Hour,
//	    RequiredClaims: []string{"jti", "sub", "exp"},
//	    RevocationEnabled: true,
//	}
type AccessTokenConfig struct {
	Duration          time.Duration // Time until token expires after issuance (e.g., 30m)
	MaxLifetime       time.Duration // Absolute maximum validity from creation (e.g., 24h)
	Issuer            string        // Token issuer identifier (e.g., "auth.example.com")
	Audience          []string      // Intended recipients (e.g., ["api.example.com"])
	AllowedAlgorithms []string      // Whitelist of acceptable algorithms for verification
	RequiredClaims    []string      // Mandatory claims that must be present and valid
	RevocationEnabled bool          // Whether to check Redis for revoked tokens
}

// RefreshTokenConfig contains settings specific to refresh token generation and validation.
//
// Refresh tokens are long-lived credentials used to obtain new access tokens. These settings
// control their extended lifetime and rotation behavior.
//
// Important Security Settings:
// - RotationEnabled: Recommended for all production use
// - ReuseInterval: Should be short to detect token replay
// - MaxLifetime: Should have reasonable upper bound
//
// Example:
//
//	RefreshTokenConfig{
//	    Duration: 168*time.Hour, // 7 days
//	    RotationEnabled: true,
//	    ReuseInterval: 5*time.Minute,
//	}
type RefreshTokenConfig struct {
	Duration          time.Duration // Time until token expires after issuance
	MaxLifetime       time.Duration // Absolute maximum validity from creation
	ReuseInterval     time.Duration // Minimum time between reuse attempts (rotation)
	RotationEnabled   bool          // Whether to enable refresh token rotation
	RevocationEnabled bool          // Whether to check Redis for revoked tokens
}

// NewGourdianTokenConfig constructs a complete token configuration with explicit settings.
//
// This constructor forces explicit consideration of all security parameters rather than
// relying on defaults. For most cases, DefaultGourdianTokenConfig() is recommended.
//
// Parameters:
//   - algorithm: JWT signing algorithm name (e.g., "HS256")
//   - signingMethod: Cryptographic method type (Symmetric/Asymmetric)
//   - symmetricKey: Secret key for HMAC (base64 encoded)
//   - privateKeyPath: File path to private key (asymmetric)
//   - publicKeyPath: File path to public key (asymmetric)
//   - accessDuration: Access token validity duration
//   - accessMaxLifetime: Access token absolute max lifetime
//   - [remaining parameters...]
//
// Example:
//
//	config := NewGourdianTokenConfig(
//	    "RS256",
//	    Asymmetric,
//	    "",
//	    "/path/to/private.pem",
//	    "/path/to/public.pem",
//	    30*time.Minute,
//	    24*time.Hour,
//	    "auth.example.com",
//	    []string{"api.example.com"},
//	    []string{"RS256"},
//	    []string{"jti", "sub", "exp"},
//	    true,
//	    168*time.Hour,
//	    720*time.Hour,
//	    5*time.Minute,
//	    true,
//	    true,
//	)
func NewGourdianTokenConfig(
	algorithm string,
	signingMethod SigningMethod,
	symmetricKey string,
	privateKeyPath string,
	publicKeyPath string,
	accessDuration time.Duration,
	accessMaxLifetime time.Duration,
	accessIssuer string,
	accessAudience []string,
	accessAllowedAlgorithms []string,
	accessRequiredClaims []string,
	accessRevocationEnabled bool,
	refreshDuration time.Duration,
	refreshMaxLifetime time.Duration,
	refreshReuseInterval time.Duration,
	refreshRotationEnabled bool,
	refreshRevocationEnabled bool,
) GourdianTokenConfig {
	return GourdianTokenConfig{
		Algorithm:      algorithm,
		SigningMethod:  signingMethod,
		SymmetricKey:   symmetricKey,
		PrivateKeyPath: privateKeyPath,
		PublicKeyPath:  publicKeyPath,
		AccessToken: AccessTokenConfig{
			Duration:          accessDuration,
			MaxLifetime:       accessMaxLifetime,
			Issuer:            accessIssuer,
			Audience:          accessAudience,
			AllowedAlgorithms: accessAllowedAlgorithms,
			RequiredClaims:    accessRequiredClaims,
			RevocationEnabled: accessRevocationEnabled,
		},
		RefreshToken: RefreshTokenConfig{
			Duration:          refreshDuration,
			MaxLifetime:       refreshMaxLifetime,
			ReuseInterval:     refreshReuseInterval,
			RotationEnabled:   refreshRotationEnabled,
			RevocationEnabled: refreshRevocationEnabled,
		},
	}
}

// DefaultGourdianTokenConfig returns a secure default configuration using HMAC-SHA256.
//
// This configuration:
// - Uses HS256 symmetric signing
// - Sets 30-minute access tokens
// - Sets 7-day refresh tokens
// - Disables revocation/rotation by default
//
// Important: The symmetricKey parameter must be at least 32 bytes for HS256 security.
// Consider using crypto/rand to generate a strong key.
//
// Example:
//
//	key := base64.RawURLEncoding.EncodeToString(generateRandomBytes(32))
//	config := DefaultGourdianTokenConfig(key)
func DefaultGourdianTokenConfig(symmetricKey string) GourdianTokenConfig {
	return GourdianTokenConfig{
		Algorithm:      "HS256",
		SigningMethod:  Symmetric,
		SymmetricKey:   symmetricKey,
		PrivateKeyPath: "",
		PublicKeyPath:  "",
		AccessToken: AccessTokenConfig{
			Duration:          30 * time.Minute,
			MaxLifetime:       24 * time.Hour,
			Issuer:            "",
			Audience:          nil,
			AllowedAlgorithms: []string{"HS256"},
			RequiredClaims:    []string{"jti", "sub", "exp", "iat", "typ", "rls"},
			RevocationEnabled: false,
		},
		RefreshToken: RefreshTokenConfig{
			Duration:          7 * 24 * time.Hour,
			MaxLifetime:       30 * 24 * time.Hour,
			ReuseInterval:     time.Minute,
			RotationEnabled:   false,
			RevocationEnabled: false,
		},
	}
}

// AccessTokenClaims represents the decoded payload of an access token.
//
// Contains standard JWT claims (exp, iat, etc.) plus custom claims for:
// - User identification (sub, usr)
// - Session tracking (sid)
// - Authorization (rls)
//
// The claims use abbreviated names (3 chars) to minimize token size.
//
// Example JSON Structure:
//
//	{
//	    "jti": "123e4567-e89b-12d3-a456-426614174000",
//	    "sub": "123e4567-e89b-12d3-a456-426614174000",
//	    "usr": "alice",
//	    "sid": "123e4567-e89b-12d3-a456-426614174000",
//	    "iat": 1516239022,
//	    "exp": 1516242622,
//	    "typ": "access",
//	    "rls": ["admin", "user"]
//	}
type AccessTokenClaims struct {
	ID        uuid.UUID `json:"jti"` // Unique token identifier (UUIDv4)
	Subject   uuid.UUID `json:"sub"` // Subject (user UUID)
	Username  string    `json:"usr"` // Human-readable username
	SessionID uuid.UUID `json:"sid"` // Session identifier (UUIDv4)
	IssuedAt  time.Time `json:"iat"` // Issuance timestamp (UTC)
	ExpiresAt time.Time `json:"exp"` // Expiration timestamp (UTC)
	TokenType TokenType `json:"typ"` // Fixed value "access"
	Roles     []string  `json:"rls"` // Authorization roles
}

// RefreshTokenClaims represents the decoded payload of a refresh token.
//
// Contains standard JWT claims plus session identifiers but no authorization roles.
// Refresh tokens are simpler since they're only used to obtain new access tokens.
//
// Example JSON Structure:
//
//	{
//	    "jti": "123e4567-e89b-12d3-a456-426614174000",
//	    "sub": "123e4567-e89b-12d3-a456-426614174000",
//	    "usr": "alice",
//	    "sid": "123e4567-e89b-12d3-a456-426614174000",
//	    "iat": 1516239022,
//	    "exp": 1516242622,
//	    "typ": "refresh"
//	}
type RefreshTokenClaims struct {
	ID        uuid.UUID `json:"jti"` // Unique token identifier
	Subject   uuid.UUID `json:"sub"` // Subject (user UUID)
	Username  string    `json:"usr"` // Human-readable username
	SessionID uuid.UUID `json:"sid"` // Session identifier
	IssuedAt  time.Time `json:"iat"` // Issuance timestamp
	ExpiresAt time.Time `json:"exp"` // Expiration timestamp
	TokenType TokenType `json:"typ"` // Fixed value "refresh"
}

// AccessTokenResponse contains the results of a successful access token generation.
//
// This struct serves as both the return value from CreateAccessToken and as a
// potential API response format. It includes both the raw token and metadata.
//
// Example JSON Response:
//
//	{
//	    "tok": "eyJhbGciOi...",
//	    "sub": "123e4567-e89b-12d3-a456-426614174000",
//	    "usr": "alice",
//	    "sid": "123e4567-e89b-12d3-a456-426614174000",
//	    "exp": "2023-01-01T12:00:00Z",
//	    "iat": "2023-01-01T11:30:00Z",
//	    "rls": ["admin", "user"]
//	}
type AccessTokenResponse struct {
	Token     string    `json:"tok"` // Signed JWT string
	Subject   uuid.UUID `json:"sub"` // User UUID
	Username  string    `json:"usr"` // Username
	SessionID uuid.UUID `json:"sid"` // Session UUID
	ExpiresAt time.Time `json:"exp"` // Expiration timestamp (RFC3339)
	IssuedAt  time.Time `json:"iat"` // Issuance timestamp (RFC3339)
	Roles     []string  `json:"rls"` // Authorization roles
}

// RefreshTokenResponse contains the results of refresh token generation or rotation.
//
// Similar to AccessTokenResponse but without roles since refresh tokens don't carry
// authorization claims.
//
// Example JSON Response:
//
//	{
//	    "tok": "eyJhbGciOi...",
//	    "sub": "123e4567-e89b-12d3-a456-426614174000",
//	    "usr": "alice",
//	    "sid": "123e4567-e89b-12d3-a456-426614174000",
//	    "exp": "2023-01-08T11:30:00Z",
//	    "iat": "2023-01-01T11:30:00Z"
//	}
type RefreshTokenResponse struct {
	Token     string    `json:"tok"` // Signed JWT string
	Subject   uuid.UUID `json:"sub"` // User UUID
	Username  string    `json:"usr"` // Username
	SessionID uuid.UUID `json:"sid"` // Session UUID
	ExpiresAt time.Time `json:"exp"` // Expiration timestamp
	IssuedAt  time.Time `json:"iat"` // Issuance timestamp
}

// GourdianTokenMaker defines the interface for generating and verifying secure access and refresh tokens.
//
// Any implementation (e.g., JWTMaker) must satisfy this interface to provide
// token creation, verification, revocation, and rotation capabilities.
//
// Example usage:
//
//	access, err := maker.CreateAccessToken(ctx, userID, "username", []string{"admin"}, sessionID)
//	refresh, err := maker.CreateRefreshToken(ctx, userID, "username", sessionID)
type GourdianTokenMaker interface {
	CreateAccessToken(ctx context.Context, userID uuid.UUID, username string, roles []string, sessionID uuid.UUID) (*AccessTokenResponse, error)
	CreateRefreshToken(ctx context.Context, userID uuid.UUID, username string, sessionID uuid.UUID) (*RefreshTokenResponse, error)
	VerifyAccessToken(ctx context.Context, tokenString string) (*AccessTokenClaims, error)
	VerifyRefreshToken(ctx context.Context, tokenString string) (*RefreshTokenClaims, error)
	RevokeAccessToken(ctx context.Context, token string) error
	RevokeRefreshToken(ctx context.Context, token string) error
	RotateRefreshToken(ctx context.Context, oldToken string) (*RefreshTokenResponse, error)
}

// JWTMaker is the concrete implementation of GourdianTokenMaker using JWT.
//
// This struct maintains:
// - Cryptographic configuration and keys
// - Redis connection for advanced features
// - Token generation/verification state
//
// Security Note:
// The privateKey field contains sensitive key material and should be protected
// from memory inspection in secure environments.
type JWTMaker struct {
	config        GourdianTokenConfig // Immutable configuration
	signingMethod jwt.SigningMethod   // JWT signing algorithm instance
	privateKey    interface{}         // Cryptographic key (HMAC secret or private key)
	publicKey     interface{}         // Verification key (HMAC secret or public key)
	redisClient   *redis.Client       // Redis client for revocation/rotation
}

// NewGourdianTokenMaker creates a new token maker instance with the provided configuration.
//
// This is the primary initialization function that:
// 1. Validates the configuration
// 2. Initializes cryptographic keys
// 3. Sets up Redis connection if rotation/revocation is enabled
// 4. Returns a ready-to-use token maker
//
// Parameters:
//   - config: Complete token configuration
//   - redisOpts: Redis options (required if Redis-based features like rotation/revocation are enabled)
//
// Returns:
// A fully initialized GourdianTokenMaker or error.
//
// Example:
//
//	config := DefaultGourdianTokenConfig("your-secret-key")
//	redisOpts := &redis.Options{ Addr: "localhost:6379" }
//	maker, err := NewGourdianTokenMaker(ctx, config, redisOpts)
func NewGourdianTokenMaker(ctx context.Context, config GourdianTokenConfig, redisOpts *redis.Options) (GourdianTokenMaker, error) {
	// Validate configuration
	if err := validateConfig(&config); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	// Check Redis requirements
	if (config.RefreshToken.RotationEnabled || config.RefreshToken.RevocationEnabled ||
		config.AccessToken.RevocationEnabled) && redisOpts == nil {
		return nil, fmt.Errorf("redis options required for token rotation/revocation")
	}

	maker := &JWTMaker{
		config: config,
	}

	// Initialize Redis client if any feature requiring Redis is enabled
	if config.RefreshToken.RotationEnabled || config.RefreshToken.RevocationEnabled ||
		config.AccessToken.RevocationEnabled {
		maker.redisClient = redis.NewClient(redisOpts)

		// Verify Redis connection with the provided context
		if _, err := maker.redisClient.Ping(ctx).Result(); err != nil {
			return nil, fmt.Errorf("redis connection failed: %w", err)
		}

		// Set up background cleanup if needed
		if config.RefreshToken.RotationEnabled {
			go maker.cleanupRotatedTokens(ctx)
		}
		if config.RefreshToken.RevocationEnabled || config.AccessToken.RevocationEnabled {
			go maker.cleanupRevokedTokens(ctx)
		}
	}

	// Initialize signing method
	if err := maker.initializeSigningMethod(); err != nil {
		return nil, fmt.Errorf("failed to initialize signing method: %w", err)
	}

	// Initialize cryptographic keys
	if err := maker.initializeKeys(); err != nil {
		return nil, fmt.Errorf("failed to initialize keys: %w", err)
	}

	return maker, nil
}

// CreateAccessToken generates a new JWT access token containing the user's identity and authorization claims.
// The token is signed using the maker's private key and includes standard JWT claims along with custom claims
// for roles and session management. The token expiration is determined by the maker's configuration.
//
// Parameters:
//   - ctx: Context for request-scoped values, cancellations, and deadlines
//   - userID: Unique identifier for the user (UUID)
//   - username: Human-readable user identifier
//   - roles: List of authorization roles granted to the user (cannot be empty)
//   - sessionID: Unique identifier for the user's session
//
// Returns:
//   - AccessTokenResponse containing the signed token string and metadata
//   - Error if input validation fails, cryptographic operations fail, or token generation fails
//
// Example:
//
//	maker, _ := NewGourdianTokenMaker(ctx, config, redisOpts)
//	userID := uuid.MustParse("a1b2c3d4-e5f6-7890-g1h2-i3j4k5l6m7n8")
//	sessionID := uuid.New()
//	token, err := maker.CreateAccessToken(
//	    ctx,
//	    userID,
//	    "john_doe",
//	    []string{"admin", "editor"},
//	    sessionID,
//	)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Printf("Generated access token: %s\n", token.Token)
func (maker *JWTMaker) CreateAccessToken(ctx context.Context, userID uuid.UUID, username string, roles []string, sessionID uuid.UUID) (*AccessTokenResponse, error) {
	if userID == uuid.Nil {
		return nil, fmt.Errorf("invalid user ID: cannot be empty")
	}
	if len(roles) == 0 {
		return nil, fmt.Errorf("at least one role must be provided")
	}
	if len(username) > 1024 {
		return nil, fmt.Errorf("username too long: max 1024 characters")
	}

	// Validate roles are non-empty strings
	for _, role := range roles {
		if role == "" {
			return nil, fmt.Errorf("roles cannot contain empty strings")
		}
	}

	tokenID, err := uuid.NewRandom()
	if err != nil {
		return nil, fmt.Errorf("failed to generate token ID: %w", err)
	}

	now := time.Now()
	claims := AccessTokenClaims{
		ID:        tokenID,
		Subject:   userID,
		Username:  username,
		SessionID: sessionID,
		IssuedAt:  now,
		ExpiresAt: now.Add(maker.config.AccessToken.Duration),
		TokenType: AccessToken,
		Roles:     roles,
	}

	token := jwt.NewWithClaims(maker.signingMethod, toMapClaims(claims))

	signedToken, err := token.SignedString(maker.privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign access token: %w", err)
	}

	response := &AccessTokenResponse{
		Token:     signedToken,
		Subject:   claims.Subject,
		Username:  claims.Username,
		SessionID: claims.SessionID,
		ExpiresAt: claims.ExpiresAt,
		IssuedAt:  claims.IssuedAt,
		Roles:     roles,
	}

	return response, nil
}

// CreateRefreshToken generates a long-lived refresh token used to obtain new access tokens without
// requiring re-authentication. Refresh tokens have different security characteristics than access tokens
// and are typically stored more securely. The token includes the user's identity and session information
// but no role claims.
//
// Parameters:
//   - ctx: Context for request-scoped values, cancellations, and deadlines
//   - userID: Unique identifier for the user (UUID)
//   - username: Human-readable user identifier
//   - sessionID: Unique identifier for the user's session
//
// Returns:
//   - RefreshTokenResponse containing the signed token string and metadata
//   - Error if input validation fails or token generation fails
//
// Example:
//
//	maker, _ := NewGourdianTokenMaker(ctx, config, redisOpts)
//	userID := uuid.MustParse("a1b2c3d4-e5f6-7890-g1h2-i3j4k5l6m7n8")
//	sessionID := uuid.New()
//	token, err := maker.CreateRefreshToken(
//	    ctx,
//	    userID,
//	    "john_doe",
//	    sessionID,
//	)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Printf("Generated refresh token: %s (expires %v)\n", token.Token, token.ExpiresAt)
func (maker *JWTMaker) CreateRefreshToken(ctx context.Context, userID uuid.UUID, username string, sessionID uuid.UUID) (*RefreshTokenResponse, error) {
	if userID == uuid.Nil {
		return nil, fmt.Errorf("invalid user ID: cannot be empty")
	}
	if len(username) > 1024 {
		return nil, fmt.Errorf("username too long: max 1024 characters")
	}

	tokenID, err := uuid.NewRandom()
	if err != nil {
		return nil, fmt.Errorf("failed to generate token ID: %w", err)
	}

	now := time.Now()
	claims := RefreshTokenClaims{
		ID:        tokenID,
		Subject:   userID,
		Username:  username,
		SessionID: sessionID,
		IssuedAt:  now,
		ExpiresAt: now.Add(maker.config.RefreshToken.Duration),
		TokenType: RefreshToken,
	}

	token := jwt.NewWithClaims(maker.signingMethod, toMapClaims(claims))

	signedToken, err := token.SignedString(maker.privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign refresh token: %w", err)
	}

	response := &RefreshTokenResponse{
		Token:     signedToken,
		Subject:   claims.Subject,
		Username:  claims.Username,
		SessionID: claims.SessionID,
		ExpiresAt: claims.ExpiresAt,
		IssuedAt:  claims.IssuedAt,
	}

	return response, nil
}

// VerifyAccessToken validates an access token's signature, checks for revocation (if enabled),
// and verifies all standard and custom claims. Returns the decoded claims if valid.
//
// Parameters:
//   - ctx: Context for request-scoped values, cancellations, and deadlines
//   - tokenString: The JWT access token string to verify
//
// Returns:
//   - AccessTokenClaims containing all verified claims from the token
//   - Error if token is invalid, expired, revoked, or malformed
//
// Example:
//
//	maker, _ := NewGourdianTokenMaker(ctx, config, redisOpts)
//	claims, err := maker.VerifyAccessToken(ctx, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...")
//	if err != nil {
//	    log.Fatal("Token verification failed:", err)
//	}
//	fmt.Printf("Valid token for user %s with roles %v\n", claims.Username, claims.Roles)
func (maker *JWTMaker) VerifyAccessToken(ctx context.Context, tokenString string) (*AccessTokenClaims, error) {

	if maker.config.AccessToken.RevocationEnabled && maker.redisClient != nil {

		exists, err := maker.redisClient.Exists(ctx, "revoked:access:"+tokenString).Result()
		if err != nil {
			return nil, fmt.Errorf("failed to check token revocation: %w", err)
		}
		if exists > 0 {
			return nil, fmt.Errorf("token has been revoked")
		}
	}

	// 1. Verify token signature and basic structure
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if token.Method.Alg() != maker.signingMethod.Alg() {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return maker.publicKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("invalid token: %v", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token claims")
	}

	// 2. Validate all required claims exist
	if err := validateTokenClaims(claims, AccessToken); err != nil {
		return nil, err
	}

	// 3. Convert and validate UUID formats before other validations
	accessClaims, err := mapToAccessClaims(claims)
	if err != nil {
		return nil, err
	}

	// 4. Validate roles claim exists and is non-empty
	if _, ok := claims["rls"]; !ok {
		return nil, fmt.Errorf("missing roles claim in access token")
	}

	return accessClaims, nil
}

// VerifyRefreshToken validates a refresh token's signature, checks for revocation (if enabled),
// and verifies all standard claims. Returns the decoded claims if valid.
//
// Parameters:
//   - ctx: Context for request-scoped values, cancellations, and deadlines
//   - tokenString: The JWT refresh token string to verify
//
// Returns:
//   - RefreshTokenClaims containing all verified claims from the token
//   - Error if token is invalid, expired, revoked, or malformed
//
// Example:
//
//	maker, _ := NewGourdianTokenMaker(ctx, config, redisOpts)
//	claims, err := maker.VerifyRefreshToken(ctx, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...")
//	if err != nil {
//	    log.Fatal("Token verification failed:", err)
//	}
//	fmt.Printf("Valid refresh token for user %s (session %v)\n", claims.Username, claims.SessionID)
func (maker *JWTMaker) VerifyRefreshToken(ctx context.Context, tokenString string) (*RefreshTokenClaims, error) {

	if maker.config.RefreshToken.RevocationEnabled && maker.redisClient != nil {

		exists, err := maker.redisClient.Exists(ctx, "revoked:refresh:"+tokenString).Result()
		if err != nil {
			return nil, fmt.Errorf("failed to check token revocation: %w", err)
		}
		if exists > 0 {
			return nil, fmt.Errorf("token has been revoked")
		}
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if token.Method.Alg() != maker.signingMethod.Alg() {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return maker.publicKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("invalid token: %v", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token claims")
	}

	if err := validateTokenClaims(claims, RefreshToken); err != nil {
		return nil, err
	}

	return mapToRefreshClaims(claims)
}

// RevokeAccessToken invalidates an access token before its natural expiration,
// preventing its future use. Requires Redis-based revocation to be enabled in configuration.
// The revocation is stored in Redis with a TTL matching the token's remaining lifetime.
//
// Parameters:
//   - ctx: Context for request-scoped values, cancellations, and deadlines
//   - token: The access token string to revoke
//
// Returns:
//   - Error if revocation is disabled, token is invalid, or Redis operation fails
//
// Example:
//
//	maker, _ := NewGourdianTokenMaker(ctx, config, redisOpts)
//	err := maker.RevokeAccessToken(ctx, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...")
//	if err != nil {
//	    log.Fatal("Failed to revoke token:", err)
//	}
//	fmt.Println("Access token successfully revoked")
func (maker *JWTMaker) RevokeAccessToken(ctx context.Context, token string) error {
	if !maker.config.AccessToken.RevocationEnabled || maker.redisClient == nil {
		return fmt.Errorf("access token revocation is not enabled")
	}

	// Parse the token to extract expiration time
	parsed, err := jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		return maker.publicKey, nil
	})
	if err != nil || !parsed.Valid {
		return fmt.Errorf("invalid token: %w", err)
	}

	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return fmt.Errorf("invalid token claims")
	}

	exp := getUnixTime(claims["exp"])
	if exp == 0 {
		return fmt.Errorf("token missing exp claim")
	}
	ttl := time.Until(time.Unix(exp, 0))

	// Store the token string as revoked in Redis with expiry
	return maker.redisClient.Set(ctx, "revoked:access:"+token, "1", ttl).Err()
}

// RevokeRefreshToken invalidates a refresh token before its natural expiration,
// preventing its future use for obtaining new access tokens. Requires Redis-based
// revocation to be enabled in configuration.
//
// Parameters:
//   - ctx: Context for request-scoped values, cancellations, and deadlines
//   - token: The refresh token string to revoke
//
// Returns:
//   - Error if revocation is disabled, token is invalid, or Redis operation fails
//
// Example:
//
//	maker, _ := NewGourdianTokenMaker(ctx, config, redisOpts)
//	err := maker.RevokeRefreshToken(ctx, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...")
//	if err != nil {
//	    log.Fatal("Failed to revoke token:", err)
//	}
//	fmt.Println("Refresh token successfully revoked")
func (maker *JWTMaker) RevokeRefreshToken(ctx context.Context, token string) error {
	if !maker.config.RefreshToken.RevocationEnabled || maker.redisClient == nil {
		return fmt.Errorf("refresh token revocation is not enabled")
	}

	// Parse the token to extract expiration time
	parsed, err := jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		return maker.publicKey, nil
	})
	if err != nil || !parsed.Valid {
		return fmt.Errorf("invalid token: %w", err)
	}

	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return fmt.Errorf("invalid token claims")
	}

	exp := getUnixTime(claims["exp"])
	if exp == 0 {
		return fmt.Errorf("token missing exp claim")
	}
	ttl := time.Until(time.Unix(exp, 0))

	// Store the token string as revoked in Redis with expiry
	return maker.redisClient.Set(ctx, "revoked:refresh:"+token, "1", ttl).Err()
}

// RotateRefreshToken generates a new refresh token while invalidating the previous one,
// implementing the refresh token rotation security practice. The old token is recorded
// in Redis to prevent immediate reuse (detection of token replay attacks). Requires
// rotation to be enabled in configuration.
//
// Parameters:
//   - ctx: Context for request-scoped values, cancellations, and deadlines
//   - oldToken: The refresh token to rotate out
//
// Returns:
//   - RefreshTokenResponse containing the new refresh token and metadata
//   - Error if rotation is disabled, old token is invalid, or Redis operation fails
//
// Example:
//
//	maker, _ := NewGourdianTokenMaker(ctx, config, redisOpts)
//	newToken, err := maker.RotateRefreshToken(ctx, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...")
//	if err != nil {
//	    log.Fatal("Failed to rotate token:", err)
//	}
//	fmt.Printf("Issued new refresh token: %s (expires %v)\n", newToken.Token, newToken.ExpiresAt)
func (maker *JWTMaker) RotateRefreshToken(ctx context.Context, oldToken string) (*RefreshTokenResponse, error) {
	if !maker.config.RefreshToken.RotationEnabled {
		return nil, fmt.Errorf("token rotation not enabled")
	}

	if _, err := maker.redisClient.Ping(ctx).Result(); err != nil {
		return nil, fmt.Errorf("redis connection failed: %w", err)
	}

	claims, err := maker.VerifyRefreshToken(ctx, oldToken)
	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	tokenKey := "rotated:" + oldToken

	exists, err := maker.redisClient.Exists(ctx, tokenKey).Result()
	if err != nil {
		return nil, fmt.Errorf("redis error: %w", err)
	}

	if exists == 1 {
		return nil, fmt.Errorf("token reused too soon")
	}

	newToken, err := maker.CreateRefreshToken(ctx, claims.Subject, claims.Username, claims.SessionID)
	if err != nil {
		return nil, err
	}

	err = maker.redisClient.Set(ctx, tokenKey, "1", maker.config.RefreshToken.MaxLifetime).Err()
	if err != nil {
		return nil, fmt.Errorf("failed to record rotation: %w", err)
	}

	return newToken, nil
}

// cleanupRotatedTokens runs as a background goroutine to remove expired rotated refresh tokens from Redis.
//
// This is only started if RefreshToken.RotationEnabled is true. It uses SCAN to efficiently iterate over
// all keys prefixed with "rotated:*" and checks their TTL. If any key has expired or has no remaining TTL,
// it is queued for deletion. This helps avoid cluttering Redis with stale rotation entries.
//
// Frequency: Every 1 hour.
// Safety: Stops when context is canceled.
func (maker *JWTMaker) cleanupRotatedTokens(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if maker.redisClient == nil {
				continue
			}

			var cursor uint64
			const batchSize = 100

			for {
				// Use SCAN to iterate keys matching the pattern in a memory-efficient way
				keys, newCursor, err := maker.redisClient.Scan(ctx, cursor, "rotated:*", batchSize).Result()
				if err != nil {
					fmt.Printf("Error scanning Redis keys: %v\n", err)
					break
				}

				// Filter out keys with expired TTL (or TTL = -2 meaning already expired)
				var keysToDelete []string
				for _, key := range keys {
					ttl, err := maker.redisClient.TTL(ctx, key).Result()
					if err != nil {
						fmt.Printf("Error checking TTL for key %s: %v\n", key, err)
						continue
					}
					if ttl <= 0 {
						keysToDelete = append(keysToDelete, key)
					}
				}

				// Delete expired keys in batch
				if len(keysToDelete) > 0 {
					if _, err := maker.redisClient.Del(ctx, keysToDelete...).Result(); err != nil {
						fmt.Printf("Error deleting expired rotated tokens: %v\n", err)
					}
				}

				// Exit loop if iteration is complete
				if newCursor == 0 {
					break
				}
				cursor = newCursor
			}
		}
	}
}

// cleanupRevokedTokens removes expired revoked tokens from Redis to free memory.
//
// This method is launched as a goroutine only if token revocation is enabled for access or refresh tokens.
// It scans all keys with prefixes "revoked:access:" and "revoked:refresh:", checks their TTLs,
// and deletes expired ones in batches.
//
// Frequency: Every 1 hour.
// This is a background housekeeping task to keep Redis clean from already-expired revocation entries.
func (maker *JWTMaker) cleanupRevokedTokens(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if maker.redisClient == nil {
				continue
			}

			for _, prefix := range []string{"revoked:access:", "revoked:refresh:"} {
				var cursor uint64
				const batchSize = 100

				for {
					keys, newCursor, err := maker.redisClient.Scan(ctx, cursor, prefix+"*", batchSize).Result()
					if err != nil {
						fmt.Printf("Error scanning Redis keys for %s: %v\n", prefix, err)
						break
					}

					var keysToDelete []string
					for _, key := range keys {
						ttl, err := maker.redisClient.TTL(ctx, key).Result()
						if err != nil {
							fmt.Printf("Error checking TTL for key %s: %v\n", key, err)
							continue
						}
						if ttl <= 0 {
							keysToDelete = append(keysToDelete, key)
						}
					}

					if len(keysToDelete) > 0 {
						if _, err := maker.redisClient.Del(ctx, keysToDelete...).Result(); err != nil {
							fmt.Printf("Error deleting expired revoked tokens: %v\n", err)
						}
					}

					if newCursor == 0 {
						break
					}
					cursor = newCursor
				}
			}
		}
	}
}

// initializeSigningMethod sets the JWT signing method instance based on the configured algorithm.
//
// Supports HS256, RS256, ES256, PS256, EdDSA, and more.
// Rejects "none" for security reasons. Returns error for unsupported algorithms.
func (maker *JWTMaker) initializeSigningMethod() error {
	switch maker.config.Algorithm {
	case "HS256":
		maker.signingMethod = jwt.SigningMethodHS256
	case "HS384":
		maker.signingMethod = jwt.SigningMethodHS384
	case "HS512":
		maker.signingMethod = jwt.SigningMethodHS512
	case "RS256":
		maker.signingMethod = jwt.SigningMethodRS256
	case "RS384":
		maker.signingMethod = jwt.SigningMethodRS384
	case "RS512":
		maker.signingMethod = jwt.SigningMethodRS512
	case "PS256":
		maker.signingMethod = jwt.SigningMethodPS256
	case "PS384":
		maker.signingMethod = jwt.SigningMethodPS384
	case "PS512":
		maker.signingMethod = jwt.SigningMethodPS512
	case "ES256":
		maker.signingMethod = jwt.SigningMethodES256
	case "ES384":
		maker.signingMethod = jwt.SigningMethodES384
	case "ES512":
		maker.signingMethod = jwt.SigningMethodES512
	case "EdDSA":
		maker.signingMethod = jwt.SigningMethodEdDSA
	case "none":
		return fmt.Errorf("unsecured tokens are disabled for security reasons")
	default:
		return fmt.Errorf("unsupported algorithm: %s", maker.config.Algorithm)
	}
	return nil
}

// initializeKeys loads signing and verification keys based on the signing method.
//
// For symmetric methods (HMAC), it uses the same key for both signing and verification.
// For asymmetric methods (RSA, ECDSA, EdDSA), it reads and parses the keys from the specified file paths.
func (maker *JWTMaker) initializeKeys() error {
	switch maker.config.SigningMethod {
	case Symmetric:
		maker.privateKey = []byte(maker.config.SymmetricKey)
		maker.publicKey = []byte(maker.config.SymmetricKey)
		return nil
	case Asymmetric:
		return maker.parseKeyPair()
	default:
		return fmt.Errorf("unsupported signing method: %s", maker.config.SigningMethod)
	}
}

// parseKeyPair reads and parses the private/public key files based on the chosen asymmetric algorithm.
//
// This function supports parsing RSA, ECDSA, and EdDSA keys from PEM-encoded files,
// handling multiple formats (PKCS1, PKCS8, certificates). It returns descriptive errors if parsing fails.
func (maker *JWTMaker) parseKeyPair() error {
	privateKeyBytes, err := os.ReadFile(maker.config.PrivateKeyPath)
	if err != nil {
		return fmt.Errorf("failed to read private key file: %w", err)
	}

	publicKeyBytes, err := os.ReadFile(maker.config.PublicKeyPath)
	if err != nil {
		return fmt.Errorf("failed to read public key file: %w", err)
	}

	switch maker.signingMethod.Alg() {
	case "RS256", "RS384", "RS512", "PS256", "PS384", "PS512":
		maker.privateKey, err = parseRSAPrivateKey(privateKeyBytes)
		if err != nil {
			return fmt.Errorf("failed to parse RSA private key: %w", err)
		}
		maker.publicKey, err = parseRSAPublicKey(publicKeyBytes)
		if err != nil {
			return fmt.Errorf("failed to parse RSA public key: %w", err)
		}
	case "ES256", "ES384", "ES512":
		maker.privateKey, err = parseECDSAPrivateKey(privateKeyBytes)
		if err != nil {
			return fmt.Errorf("failed to parse ECDSA private key: %w", err)
		}
		maker.publicKey, err = parseECDSAPublicKey(publicKeyBytes)
		if err != nil {
			return fmt.Errorf("failed to parse ECDSA public key: %w", err)
		}
	case "EdDSA":
		maker.privateKey, err = parseEdDSAPrivateKey(privateKeyBytes)
		if err != nil {
			return fmt.Errorf("failed to parse EdDSA private key: %w", err)
		}
		maker.publicKey, err = parseEdDSAPublicKey(publicKeyBytes)
		if err != nil {
			return fmt.Errorf("failed to parse EdDSA public key: %w", err)
		}
	default:
		return fmt.Errorf("unsupported algorithm for asymmetric signing: %s", maker.signingMethod.Alg())
	}

	return nil
}

// validateConfig performs a strict validation of the GourdianTokenConfig struct.
//
// Ensures required fields are set for symmetric/asymmetric methods.
// Checks for invalid or insecure combinations (e.g., using keys for the wrong signing method).
// Also verifies file permissions of private/public key files to prevent leaking secrets.
func validateConfig(config *GourdianTokenConfig) error {
	switch config.SigningMethod {
	case Symmetric:
		if config.SymmetricKey == "" {
			return fmt.Errorf("symmetric key is required for symmetric signing method")
		}
		if !strings.HasPrefix(config.Algorithm, "HS") && config.Algorithm != "none" {
			return fmt.Errorf("algorithm %s not compatible with symmetric signing", config.Algorithm)
		}
		if len(config.SymmetricKey) < 32 {
			return fmt.Errorf("symmetric key must be at least 32 bytes")
		}
		if config.PrivateKeyPath != "" || config.PublicKeyPath != "" {
			return fmt.Errorf("private and public key paths must be empty for symmetric signing")
		}
	case Asymmetric:
		if config.PrivateKeyPath == "" || config.PublicKeyPath == "" {
			return fmt.Errorf("private and public key paths are required for asymmetric signing method")
		}
		if config.SymmetricKey != "" {
			return fmt.Errorf("symmetric key must be empty for asymmetric signing")
		}
		if !strings.HasPrefix(config.Algorithm, "RS") &&
			!strings.HasPrefix(config.Algorithm, "ES") &&
			!strings.HasPrefix(config.Algorithm, "PS") &&
			config.Algorithm != "EdDSA" {
			return fmt.Errorf("algorithm %s not compatible with asymmetric signing", config.Algorithm)
		}
		if err := checkFilePermissions(config.PrivateKeyPath, 0644); err != nil {
			return fmt.Errorf("insecure private key file permissions: %w", err)
		}
		if err := checkFilePermissions(config.PublicKeyPath, 0644); err != nil {
			return fmt.Errorf("insecure public key file permissions: %w", err)
		}
	default:
		return fmt.Errorf("unsupported signing method: %s, supports %s and %s",
			config.SigningMethod, Symmetric, Asymmetric)
	}

	return nil
}

// toMapClaims converts strongly-typed claims (AccessTokenClaims or RefreshTokenClaims)
// into jwt.MapClaims format used by the jwt-go library.
//
// This internal helper panics if roles are empty or if the claims type is unsupported.
// It ensures consistent token encoding.
func toMapClaims(claims interface{}) jwt.MapClaims {
	switch v := claims.(type) {
	case AccessTokenClaims:
		if len(v.Roles) == 0 {
			panic("at least one role must be provided")
		}
		return jwt.MapClaims{
			"jti": v.ID.String(),
			"sub": v.Subject.String(),
			"usr": v.Username,
			"sid": v.SessionID.String(),
			"iat": v.IssuedAt.Unix(),
			"exp": v.ExpiresAt.Unix(),
			"typ": string(v.TokenType),
			"rls": v.Roles,
		}
	case RefreshTokenClaims:
		return jwt.MapClaims{
			"jti": v.ID.String(),
			"sub": v.Subject.String(),
			"usr": v.Username,
			"sid": v.SessionID.String(),
			"iat": v.IssuedAt.Unix(),
			"exp": v.ExpiresAt.Unix(),
			"typ": string(v.TokenType),
		}
	default:
		panic(fmt.Sprintf("unsupported claims type: %T", claims))
	}
}

// mapToAccessClaims decodes jwt.MapClaims into a strongly-typed AccessTokenClaims struct.
//
// It validates UUID formats, checks the existence and type of each claim,
// and handles both []string and []interface{} formats for the "rls" (roles) claim.
func mapToAccessClaims(claims jwt.MapClaims) (*AccessTokenClaims, error) {
	// Validate and convert jti claim
	jti, ok := claims["jti"].(string)
	if !ok {
		return nil, fmt.Errorf("invalid token ID type: expected string")
	}
	tokenID, err := uuid.Parse(jti)
	if err != nil {
		return nil, fmt.Errorf("invalid token ID: %w", err)
	}

	// Validate and convert sub claim
	sub, ok := claims["sub"].(string)
	if !ok {
		return nil, fmt.Errorf("invalid user ID type: expected string")
	}
	userID, err := uuid.Parse(sub)
	if err != nil {
		return nil, fmt.Errorf("invalid user ID: %w", err)
	}

	// Validate and convert sid claim
	sid, ok := claims["sid"].(string)
	if !ok {
		return nil, fmt.Errorf("invalid session ID type: expected string")
	}
	sessionID, err := uuid.Parse(sid)
	if err != nil {
		return nil, fmt.Errorf("invalid session ID: %w", err)
	}

	// Validate username claim
	username, ok := claims["usr"].(string)
	if !ok {
		return nil, fmt.Errorf("invalid username type: expected string")
	}

	// Validate roles claim
	rolesInterface, ok := claims["rls"]
	if !ok {
		return nil, fmt.Errorf("missing roles claim")
	}

	var roles []string
	switch v := rolesInterface.(type) {
	case []interface{}:
		roles = make([]string, 0, len(v))
		for _, r := range v {
			role, ok := r.(string)
			if !ok {
				return nil, fmt.Errorf("invalid role type: expected string")
			}
			roles = append(roles, role)
		}
	case []string:
		roles = v
	default:
		return nil, fmt.Errorf("invalid roles type: expected array of strings")
	}

	if len(roles) == 0 {
		return nil, fmt.Errorf("at least one role must be provided")
	}

	// Validate token type claim
	typ, ok := claims["typ"].(string)
	if !ok {
		return nil, fmt.Errorf("invalid token type: expected string")
	}

	// Get timestamps with validation
	iat := getUnixTime(claims["iat"])
	exp := getUnixTime(claims["exp"])
	if iat == 0 || exp == 0 {
		return nil, fmt.Errorf("invalid timestamp format")
	}

	return &AccessTokenClaims{
		ID:        tokenID,
		Subject:   userID,
		Username:  username,
		SessionID: sessionID,
		IssuedAt:  time.Unix(iat, 0),
		ExpiresAt: time.Unix(exp, 0),
		TokenType: TokenType(typ),
		Roles:     roles,
	}, nil
}

// mapToRefreshClaims decodes jwt.MapClaims into a strongly-typed RefreshTokenClaims struct.
//
// It ensures all fields exist and have correct types (UUIDs, timestamps, etc.),
// and that the token type is specifically "refresh".
func mapToRefreshClaims(claims jwt.MapClaims) (*RefreshTokenClaims, error) {
	tokenID, err := uuid.Parse(claims["jti"].(string))
	if err != nil {
		return nil, fmt.Errorf("invalid token ID: %w", err)
	}

	userID, err := uuid.Parse(claims["sub"].(string))
	if err != nil {
		return nil, fmt.Errorf("invalid user ID: %w", err)
	}

	sessionID, err := uuid.Parse(claims["sid"].(string))
	if err != nil {
		return nil, fmt.Errorf("invalid session ID: %w", err)
	}

	username, ok := claims["usr"].(string)
	if !ok {
		return nil, fmt.Errorf("invalid username type: expected string")
	}

	typ, ok := claims["typ"].(string)
	if !ok {
		return nil, fmt.Errorf("invalid or missing token type")
	}

	if TokenType(typ) != RefreshToken {
		return nil, fmt.Errorf("invalid token type: expected 'refresh'")
	}

	iat := getUnixTime(claims["iat"])
	exp := getUnixTime(claims["exp"])

	if iat == 0 || exp == 0 {
		return nil, fmt.Errorf("invalid timestamp format")
	}

	return &RefreshTokenClaims{
		ID:        tokenID,
		Subject:   userID,
		Username:  username,
		SessionID: sessionID,
		IssuedAt:  time.Unix(iat, 0),
		ExpiresAt: time.Unix(exp, 0),
		TokenType: TokenType(typ),
	}, nil
}

// validateTokenClaims performs runtime validation of claims for expiration, issuance, and required fields.
//
// It compares the "typ" claim to the expected type (access or refresh),
// verifies timestamps, and ensures critical fields like jti, sub, sid, etc., are present.
func validateTokenClaims(claims jwt.MapClaims, expectedType TokenType) error {

	tokenType, ok := claims["typ"].(string)
	if !ok || TokenType(tokenType) != expectedType {
		return fmt.Errorf("invalid token type: expected %s", expectedType)
	}

	requiredClaims := []string{"jti", "sub", "typ", "usr", "sid", "iat", "exp"}
	if expectedType == AccessToken {
		requiredClaims = append(requiredClaims, "rls")
	}

	for _, claim := range requiredClaims {
		if _, ok := claims[claim]; !ok {
			return fmt.Errorf("missing required claim: %s", claim)
		}
	}

	exp, ok := claims["exp"].(float64)
	if !ok {
		return fmt.Errorf("invalid exp claim type")
	}
	if time.Unix(int64(exp), 0).Before(time.Now()) {
		return fmt.Errorf("token has expired")
	}

	if iat, ok := claims["iat"].(float64); ok {
		if time.Unix(int64(iat), 0).After(time.Now()) {
			return fmt.Errorf("token issued in the future")
		}
	}

	return nil
}

func parseEdDSAPrivateKey(pemBytes []byte) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block containing the private key")
	}

	priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse EdDSA private key: %w", err)
	}

	eddsaPriv, ok := priv.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("not a valid EdDSA private key")
	}

	return eddsaPriv, nil
}

func parseEdDSAPublicKey(pemBytes []byte) (ed25519.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block containing the public key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse EdDSA public key: %w", err)
		}
		eddsaPub, ok := cert.PublicKey.(ed25519.PublicKey)
		if !ok {
			return nil, fmt.Errorf("not a valid EdDSA public key")
		}
		return eddsaPub, nil
	}

	eddsaPub, ok := pub.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not a valid EdDSA public key")
	}
	return eddsaPub, nil
}

func parseRSAPrivateKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block containing the RSA private key")
	}

	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}

	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if rsaKey, ok := key.(*rsa.PrivateKey); ok {
			return rsaKey, nil
		}
		return nil, fmt.Errorf("expected RSA private key, got %T", key)
	}

	var privKey pkcs8
	if _, err := asn1.Unmarshal(block.Bytes, &privKey); err != nil {
		return nil, fmt.Errorf("failed to parse PKCS8 structure: %w", err)
	}

	var rsaPriv rsaPrivateKey
	if _, err := asn1.Unmarshal(privKey.PrivateKey, &rsaPriv); err != nil {
		return nil, fmt.Errorf("failed to parse RSA private key: %w", err)
	}

	return &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			N: rsaPriv.N,
			E: int(rsaPriv.E.Int64()),
		},
		D:      rsaPriv.D,
		Primes: []*big.Int{rsaPriv.P, rsaPriv.Q},
		Precomputed: rsa.PrecomputedValues{
			Dp:   rsaPriv.Dp,
			Dq:   rsaPriv.Dq,
			Qinv: rsaPriv.Qinv,
		},
	}, nil
}

func parseRSAPublicKey(pemBytes []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block containing the RSA public key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err == nil {
		if rsaPub, ok := pub.(*rsa.PublicKey); ok {
			return rsaPub, nil
		}
		return nil, fmt.Errorf("expected RSA public key, got %T", pub)
	}

	if pub, err := x509.ParsePKCS1PublicKey(block.Bytes); err == nil {
		return pub, nil
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err == nil {
		if rsaPub, ok := cert.PublicKey.(*rsa.PublicKey); ok {
			return rsaPub, nil
		}
		return nil, fmt.Errorf("expected RSA public key in certificate, got %T", cert.PublicKey)
	}

	var pubKey struct {
		Algo      pkix.AlgorithmIdentifier
		BitString asn1.BitString
	}
	if _, err := asn1.Unmarshal(block.Bytes, &pubKey); err != nil {
		return nil, fmt.Errorf("failed to parse public key structure: %w", err)
	}

	var rsaPub struct {
		N *big.Int
		E *big.Int
	}
	if _, err := asn1.Unmarshal(pubKey.BitString.Bytes, &rsaPub); err != nil {
		return nil, fmt.Errorf("failed to parse RSA public key: %w", err)
	}

	return &rsa.PublicKey{
		N: rsaPub.N,
		E: int(rsaPub.E.Int64()),
	}, nil
}

func parseECDSAPrivateKey(pemBytes []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block containing the ECDSA private key")
	}

	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		pkcs8Key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse ECDSA private key: %w", err)
		}
		key, ok := pkcs8Key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("not a valid ECDSA private key")
		}
		return key, nil
	}
	return key, nil
}

func parseECDSAPublicKey(pemBytes []byte) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block containing the ECDSA public key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse ECDSA public key: %w", err)
		}
		ecdsaPub, ok := cert.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("not a valid ECDSA public key")
		}
		return ecdsaPub, nil
	}

	ecdsaPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not a valid ECDSA public key")
	}
	return ecdsaPub, nil
}

func checkFilePermissions(path string, requiredPerm os.FileMode) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("failed to stat file: %w", err)
	}

	actualPerm := info.Mode().Perm()
	if actualPerm&^requiredPerm != 0 {
		return fmt.Errorf("file %s has permissions %#o, expected %#o", path, actualPerm, requiredPerm)
	}

	return nil
}

func getUnixTime(claim interface{}) int64 {
	switch v := claim.(type) {
	case float64:
		return int64(v)
	case int64:
		return v
	case int:
		return int64(v)
	case json.Number:
		i, _ := v.Int64()
		return i
	default:
		return 0
	}
}

type pkcs8 struct {
	Version    int
	Algo       pkix.AlgorithmIdentifier
	PrivateKey []byte
}

type rsaPrivateKey struct {
	Version int
	N       *big.Int
	E       *big.Int
	D       *big.Int
	P       *big.Int
	Q       *big.Int
	Dp      *big.Int
	Dq      *big.Int
	Qinv    *big.Int
}
