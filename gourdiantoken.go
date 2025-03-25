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

// TokenType represents the type of JWT token (access or refresh).
// This is used to distinguish between short-lived access tokens and long-lived refresh tokens.
type TokenType string

const (
	AccessToken  TokenType = "access"  // AccessToken represents an access token type used for API authorization
	RefreshToken TokenType = "refresh" // RefreshToken represents a refresh token type used to obtain new access tokens
)

// SigningMethod represents the cryptographic method used for signing tokens.
// This determines whether HMAC (symmetric) or RSA/ECDSA (asymmetric) signing is used.
type SigningMethod string

const (
	Symmetric  SigningMethod = "symmetric"  // Symmetric uses HMAC with a shared secret key
	Asymmetric SigningMethod = "asymmetric" // Asymmetric uses RSA/ECDSA/EdDSA with public/private key pairs
)

// GourdianTokenConfig holds the complete configuration for JWT token generation and verification.
// This is the main configuration struct that controls all aspects of token creation and validation.
type GourdianTokenConfig struct {
	Algorithm      string             // JWT signing algorithm (e.g., "HS256", "RS256", "ES256", "EdDSA")
	SigningMethod  SigningMethod      // Cryptographic method (symmetric or asymmetric)
	SymmetricKey   string             // Secret key for symmetric signing (min 32 bytes for HS256)
	PrivateKeyPath string             // Path to private key file for asymmetric signing
	PublicKeyPath  string             // Path to public key/certificate file for asymmetric verification
	AccessToken    AccessTokenConfig  // Configuration for access token settings
	RefreshToken   RefreshTokenConfig // Configuration for refresh token settings
}

// AccessTokenConfig contains settings specific to access tokens.
// These tokens are short-lived and used for API authorization.
type AccessTokenConfig struct {
	Duration          time.Duration // Token validity duration from issuance (e.g., 30m)
	MaxLifetime       time.Duration // Absolute maximum lifetime from creation time (e.g., 24h)
	Issuer            string        // Token issuer identifier (optional)
	Audience          []string      // Intended recipients (optional)
	AllowedAlgorithms []string      // Permitted algorithms for verification (must include primary algorithm)
	RequiredClaims    []string      // Mandatory claims (e.g., ["jti", "sub", "exp", "iat", "typ"])
}

// RefreshTokenConfig contains settings specific to refresh tokens.
// These tokens are long-lived and used to obtain new access tokens.
type RefreshTokenConfig struct {
	Duration        time.Duration // Token validity duration (e.g., 7d)
	MaxLifetime     time.Duration // Absolute maximum lifetime (e.g., 30d)
	ReuseInterval   time.Duration // Minimum time between reuse attempts (e.g., 1m)
	RotationEnabled bool          // Whether refresh token rotation is enabled (requires Redis)
}

// NewGourdianTokenConfig creates a fully configured GourdianTokenConfig with explicit parameters for all settings.
//
// This constructor provides maximum flexibility by requiring all configuration values to be specified,
// avoiding hidden defaults and making the configuration completely explicit.
//
// Parameters:
//   - algorithm: JWT signing algorithm (e.g., "HS256", "RS256", "ES256", "EdDSA")
//   - signingMethod: Cryptographic method (Symmetric or Asymmetric)
//   - symmetricKey: Secret key for symmetric signing (leave empty for asymmetric)
//   - privateKeyPath: Path to private key file (leave empty for symmetric)
//   - publicKeyPath: Path to public key file (leave empty for symmetric)
//   - accessDuration: Access token validity duration (e.g., 30*time.Minute)
//   - accessMaxLifetime: Maximum absolute lifetime for access tokens (e.g., 24*time.Hour)
//   - accessIssuer: Issuer claim for access tokens (optional)
//   - accessAudience: Audience claims for access tokens (optional)
//   - accessAllowedAlgorithms: Permitted algorithms for access token verification
//   - accessRequiredClaims: Mandatory claims for access tokens (e.g., ["jti","sub","exp"])
//   - refreshDuration: Refresh token validity duration (e.g., 7*24*time.Hour)
//   - refreshMaxLifetime: Maximum absolute lifetime for refresh tokens (e.g., 30*24*time.Hour)
//   - refreshReuseInterval: Minimum time between refresh token reuse (e.g., time.Minute)
//   - refreshRotationEnabled: Whether refresh token rotation is enabled
//
// Returns:
// A fully configured GourdianTokenConfig with no implicit defaults.
//
// Example Usage:
// config := NewGourdianTokenConfig(
//
//	"HS256",
//	Symmetric,
//	"your-32-byte-secure-key-1234567890abcdef",
//	"", "", // No key paths for symmetric
//	30*time.Minute,  // accessDuration
//	24*time.Hour,    // accessMaxLifetime
//	"auth.myapp.com",
//	[]string{"api.myapp.com"},
//	[]string{"HS256"},
//	[]string{"jti", "sub", "exp", "iat", "typ", "rol"},
//	7*24*time.Hour,  // refreshDuration
//	30*24*time.Hour, // refreshMaxLifetime
//	time.Minute,     // refreshReuseInterval
//	true,            // refreshRotationEnabled
//
// )
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
	refreshDuration time.Duration,
	refreshMaxLifetime time.Duration,
	refreshReuseInterval time.Duration,
	refreshRotationEnabled bool,
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
		},
		RefreshToken: RefreshTokenConfig{
			Duration:        refreshDuration,
			MaxLifetime:     refreshMaxLifetime,
			ReuseInterval:   refreshReuseInterval,
			RotationEnabled: refreshRotationEnabled,
		},
	}
}

// DefaultGourdianTokenConfig returns a secure default configuration for common use cases.
//
// This configuration provides:
// - HMAC-SHA256 symmetric signing (recommended for single-service deployments)
// - Secure defaults for both access and refresh tokens
// - Reasonable security constraints out of the box
//
// Security Defaults:
// - Access tokens: 30 minute lifetime (24 hour maximum)
// - Refresh tokens: 7 day lifetime (30 day maximum)
// - Refresh token rotation disabled by default
// - Minimum 1 minute reuse interval
// - Strict claim requirements
//
// Parameters:
//   - symmetricKey: Must be at least 32 bytes for HS256
//
// Returns:
// A ready-to-use configuration with secure defaults.
//
// Example Usage:
// config := DefaultGourdianTokenConfig("your-32-byte-secure-key-1234567890abcdef")
// maker, err := NewGourdianTokenMaker(config, nil)
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
			RequiredClaims:    []string{"jti", "sub", "exp", "iat", "typ", "rol"},
		},
		RefreshToken: RefreshTokenConfig{
			Duration:        7 * 24 * time.Hour,
			MaxLifetime:     30 * 24 * time.Hour,
			ReuseInterval:   time.Minute,
			RotationEnabled: false,
		},
	}
}

// AccessTokenClaims represents the JWT claims for access tokens.
// These claims are embedded in the JWT and contain user identity and session information.
type AccessTokenClaims struct {
	ID        uuid.UUID `json:"jti"` // Unique token identifier (UUIDv4)
	Subject   uuid.UUID `json:"sub"` // Subject (user ID as UUID)
	Username  string    `json:"usr"` // Human-readable username
	SessionID uuid.UUID `json:"sid"` // Session identifier (UUIDv4)
	IssuedAt  time.Time `json:"iat"` // Token issuance timestamp
	ExpiresAt time.Time `json:"exp"` // Token expiration timestamp
	TokenType TokenType `json:"typ"` // Token type ("access")
	Role      string    `json:"rol"` // User role/privilege level
}

// RefreshTokenClaims represents the JWT claims for refresh tokens.
// These claims are similar to access tokens but without the role claim.
type RefreshTokenClaims struct {
	ID        uuid.UUID `json:"jti"` // Unique token identifier (UUIDv4)
	Subject   uuid.UUID `json:"sub"` // Subject (user ID as UUID)
	Username  string    `json:"usr"` // Human-readable username
	SessionID uuid.UUID `json:"sid"` // Session identifier (UUIDv4)
	IssuedAt  time.Time `json:"iat"` // Token issuance timestamp
	ExpiresAt time.Time `json:"exp"` // Token expiration timestamp
	TokenType TokenType `json:"typ"` // Token type ("refresh")
}

// AccessTokenResponse contains the response after creating an access token.
// This is returned to clients after successful token creation.
type AccessTokenResponse struct {
	Token     string    `json:"tok"` // The signed JWT string
	Subject   uuid.UUID `json:"sub"` // User ID (UUID)
	Username  string    `json:"usr"` // Username
	SessionID uuid.UUID `json:"sid"` // Session ID (UUID)
	ExpiresAt time.Time `json:"exp"` // Expiration timestamp
	IssuedAt  time.Time `json:"iat"` // Issuance timestamp
	Role      string    `json:"rol"` // User role
}

// RefreshTokenResponse contains the response after creating a refresh token.
// This is returned to clients after successful token creation.
type RefreshTokenResponse struct {
	Token     string    `json:"tok"` // The signed JWT string
	Subject   uuid.UUID `json:"sub"` // User ID (UUID)
	Username  string    `json:"usr"` // Username
	SessionID uuid.UUID `json:"sid"` // Session ID (UUID)
	ExpiresAt time.Time `json:"exp"` // Expiration timestamp
	IssuedAt  time.Time `json:"iat"` // Issuance timestamp
}

// GourdianTokenMaker defines the interface for complete JWT token lifecycle management.
//
// This interface provides all methods needed for:
// - Token generation (access and refresh)
// - Token verification
// - Refresh token rotation
// - Token validation
//
// Implementations should be thread-safe and support concurrent access.
type GourdianTokenMaker interface {
	CreateAccessToken(ctx context.Context, userID uuid.UUID, username, role string, sessionID uuid.UUID) (*AccessTokenResponse, error)
	CreateRefreshToken(ctx context.Context, userID uuid.UUID, username string, sessionID uuid.UUID) (*RefreshTokenResponse, error)
	VerifyAccessToken(tokenString string) (*AccessTokenClaims, error)
	VerifyRefreshToken(tokenString string) (*RefreshTokenClaims, error)
	RotateRefreshToken(oldToken string) (*RefreshTokenResponse, error)
}

// JWTMaker implements GourdianTokenMaker using JWT tokens with Redis support for rotation.
//
// This implementation provides:
// - Support for both symmetric (HMAC) and asymmetric (RSA/ECDSA/EdDSA) signing
// - Redis-backed refresh token rotation
// - Comprehensive claim validation
// - Secure defaults and configuration
//
// The struct fields are:
// - config: Complete token configuration
// - signingMethod: JWT signing method instance
// - privateKey: Key used for signing (HMAC secret or private key)
// - publicKey: Key used for verification (HMAC secret or public key)
// - redisClient: Redis client for token rotation (nil if rotation disabled)
type JWTMaker struct {
	config        GourdianTokenConfig // Complete token configuration
	signingMethod jwt.SigningMethod   // JWT signing method instance
	privateKey    interface{}         // Key used for signing (HMAC secret or private key)
	publicKey     interface{}         // Key used for verification (HMAC secret or public key)
	redisClient   *redis.Client       // Redis client for token rotation (nil if rotation disabled)
}

// NewGourdianTokenMaker creates a new token maker instance with the provided configuration.
//
// This is the primary initialization function that:
// 1. Validates the configuration
// 2. Initializes cryptographic keys
// 3. Sets up Redis connection if rotation enabled
// 4. Returns a ready-to-use token maker
//
// Parameters:
//   - config: Complete token configuration
//   - redisOpts: Redis options (required if rotation enabled)
//
// Returns:
// A fully initialized token maker instance or error if initialization fails.
//
// Example Usage:
// config := DefaultGourdianTokenConfig("your-secret-key")
//
//	redisOpts := &redis.Options{
//	    Addr:     "localhost:6379",
//	    Password: "",
//	    DB:       0,
//	}
//
// maker, err := NewGourdianTokenMaker(config, redisOpts)
func NewGourdianTokenMaker(config GourdianTokenConfig, redisOpts *redis.Options) (GourdianTokenMaker, error) {
	if err := validateConfig(&config); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	if config.RefreshToken.RotationEnabled && redisOpts == nil {
		return nil, fmt.Errorf("redis options required for token rotation")
	}

	maker := &JWTMaker{
		config: config,
	}

	if config.RefreshToken.RotationEnabled {
		maker.redisClient = redis.NewClient(redisOpts)
		if _, err := maker.redisClient.Ping(context.Background()).Result(); err != nil {
			return nil, fmt.Errorf("redis connection failed: %w", err)
		}
	}

	if err := maker.initializeSigningMethod(); err != nil {
		return nil, fmt.Errorf("failed to initialize signing method: %w", err)
	}

	if err := maker.initializeKeys(); err != nil {
		return nil, fmt.Errorf("failed to initialize keys: %w", err)
	}

	return maker, nil
}

// CreateAccessToken generates a new access token with the specified user details.
//
// The token includes:
// - Standard JWT claims (jti, sub, iat, exp)
// - Custom claims (usr, sid, rol)
// - Configurable expiration based on AccessToken.Duration
//
// Parameters:
//   - ctx: Context for request cancellation
//   - userID: Unique user identifier (UUID)
//   - username: Human-readable username
//   - role: User role/privilege level
//   - sessionID: Unique session identifier (UUID)
//
// Returns:
// AccessTokenResponse containing the signed token and metadata, or error if generation fails.
//
// Example Usage:
// token, err := maker.CreateAccessToken(context.Background(),
//
//	userID, "john.doe", "admin", sessionID)
func (maker *JWTMaker) CreateAccessToken(ctx context.Context, userID uuid.UUID, username, role string, sessionID uuid.UUID) (*AccessTokenResponse, error) {
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
		Role:      role,
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
		Role:      role,
	}

	return response, nil
}

// CreateRefreshToken generates a new refresh token with the specified user details.
//
// Refresh tokens:
// - Have longer lifetimes than access tokens
// - Can be rotated if configured
// - Don't include role claims
//
// Parameters:
//   - ctx: Context for request cancellation
//   - userID: Unique user identifier (UUID)
//   - username: Human-readable username
//   - sessionID: Unique session identifier (UUID)
//
// Returns:
// RefreshTokenResponse containing the signed token and metadata, or error if generation fails.
//
// Example Usage:
// token, err := maker.CreateRefreshToken(context.Background(),
//
//	userID, "john.doe", sessionID)
func (maker *JWTMaker) CreateRefreshToken(ctx context.Context, userID uuid.UUID, username string, sessionID uuid.UUID) (*RefreshTokenResponse, error) {
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

// VerifyAccessToken validates an access token string and returns its claims.
//
// Performs the following validations:
// 1. Verifies token signature
// 2. Checks token expiration
// 3. Validates required claims
// 4. Ensures token type is "access"
//
// Parameters:
//   - tokenString: The JWT token string to verify
//
// Returns:
// AccessTokenClaims if valid, error if validation fails.
//
// Example Usage:
// claims, err := maker.VerifyAccessToken(tokenString)
//
//	if err != nil {
//	    // Handle invalid token
//	}
func (maker *JWTMaker) VerifyAccessToken(tokenString string) (*AccessTokenClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if token.Method.Alg() != maker.signingMethod.Alg() {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return maker.publicKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token claims")
	}

	if err := validateTokenClaims(claims, AccessToken); err != nil {
		return nil, err
	}

	if _, ok := claims["rol"]; !ok {
		return nil, fmt.Errorf("missing role claim in access token")
	}

	return mapToAccessClaims(claims)
}

// VerifyRefreshToken validates a refresh token string and returns its claims.
//
// Performs the following validations:
// 1. Verifies token signature
// 2. Checks token expiration
// 3. Validates required claims
// 4. Ensures token type is "refresh"
//
// Parameters:
//   - tokenString: The JWT token string to verify
//
// Returns:
// RefreshTokenClaims if valid, error if validation fails.
//
// Example Usage:
// claims, err := maker.VerifyRefreshToken(tokenString)
//
//	if err != nil {
//	    // Handle invalid token
//	}
func (maker *JWTMaker) VerifyRefreshToken(tokenString string) (*RefreshTokenClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if token.Method.Alg() != maker.signingMethod.Alg() {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return maker.publicKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
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

// RotateRefreshToken generates a new refresh token while invalidating the old one.
//
// This implements the OAuth2 refresh token rotation pattern for enhanced security:
// 1. Verifies the old token is valid
// 2. Checks Redis to prevent token reuse
// 3. Creates new refresh token
// 4. Records old token in Redis to prevent reuse
//
// Parameters:
//   - oldToken: The refresh token to rotate
//
// Returns:
// New refresh token response or error if rotation fails.
//
// Example Usage:
// newToken, err := maker.RotateRefreshToken(oldRefreshToken)
//
//	if err != nil {
//	    // Handle rotation failure
//	}
func (maker *JWTMaker) RotateRefreshToken(oldToken string) (*RefreshTokenResponse, error) {
	if !maker.config.RefreshToken.RotationEnabled {
		return nil, fmt.Errorf("token rotation not enabled")
	}

	claims, err := maker.VerifyRefreshToken(oldToken)
	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	ctx := context.Background()
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

// Helper functions...

// validateConfig validates the configuration for completeness and security
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
		if err := checkFilePermissions(config.PrivateKeyPath, 0600); err != nil {
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

// initializeSigningMethod sets up the JWT signing method based on the configured algorithm
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

// initializeKeys loads and parses the cryptographic keys based on the signing method
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

// parseKeyPair loads and parses both private and public keys for asymmetric signing
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

// toMapClaims converts claims struct to jwt.MapClaims for JWT generation
func toMapClaims(claims interface{}) jwt.MapClaims {
	switch v := claims.(type) {
	case AccessTokenClaims:
		return jwt.MapClaims{
			"jti": v.ID.String(),
			"sub": v.Subject.String(),
			"usr": v.Username,
			"sid": v.SessionID.String(),
			"iat": v.IssuedAt.Unix(),
			"exp": v.ExpiresAt.Unix(),
			"typ": string(v.TokenType),
			"rol": v.Role,
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
		return nil
	}
}

// mapToAccessClaims converts JWT claims map to AccessTokenClaims struct
func mapToAccessClaims(claims jwt.MapClaims) (*AccessTokenClaims, error) {
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

	role, ok := claims["rol"].(string)
	if !ok {
		return nil, fmt.Errorf("invalid role type: expected string")
	}

	return &AccessTokenClaims{
		ID:        tokenID,
		Subject:   userID,
		Username:  username,
		SessionID: sessionID,
		IssuedAt:  time.Unix(getUnixTime(claims["iat"]), 0),
		ExpiresAt: time.Unix(getUnixTime(claims["exp"]), 0),
		TokenType: TokenType(claims["typ"].(string)),
		Role:      role,
	}, nil
}

// mapToRefreshClaims converts JWT claims map to RefreshTokenClaims struct
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

	return &RefreshTokenClaims{
		ID:        tokenID,
		Subject:   userID,
		Username:  username,
		SessionID: sessionID,
		IssuedAt:  time.Unix(getUnixTime(claims["iat"]), 0),
		ExpiresAt: time.Unix(getUnixTime(claims["exp"]), 0),
		TokenType: TokenType(claims["typ"].(string)),
	}, nil
}

// validateTokenClaims validates the standard JWT claims
func validateTokenClaims(claims jwt.MapClaims, expectedType TokenType) error {
	requiredClaims := []string{"jti", "sub", "usr", "sid", "iat", "exp", "typ"}
	for _, claim := range requiredClaims {
		if _, ok := claims[claim]; !ok {
			return fmt.Errorf("missing required claim: %s", claim)
		}
	}

	tokenType, ok := claims["typ"].(string)
	if !ok || TokenType(tokenType) != expectedType {
		return fmt.Errorf("invalid token type: expected %s", expectedType)
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

// Key parsing functions...

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

// checkFilePermissions verifies file permissions meet security requirements
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

// getUnixTime converts various numeric types to int64 timestamp
func getUnixTime(claim interface{}) int64 {
	switch v := claim.(type) {
	case float64:
		return int64(v)
	case int64:
		return v
	default:
		return 0
	}
}

// Internal key parsing structures
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
