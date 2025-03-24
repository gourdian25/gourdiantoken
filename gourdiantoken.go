// gourdiantoken.go

package gourdiantoken

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// TokenType represents the type of JWT token (access or refresh).
type TokenType string

const (
	AccessToken  TokenType = "access"  // AccessToken represents an access token type
	RefreshToken TokenType = "refresh" // RefreshToken represents a refresh token type
)

// SigningMethod represents the cryptographic method used for signing tokens.
type SigningMethod string

const (
	Symmetric  SigningMethod = "symmetric"  // Symmetric uses HMAC with a shared secret
	Asymmetric SigningMethod = "asymmetric" // Asymmetric uses RSA/ECDSA with public/private key pairs
)

// GourdianTokenConfig holds the complete configuration for JWT token generation and verification.
//
// This struct serves as the central configuration point for the token system, containing:
// - Cryptographic settings (algorithm, keys)
// - Access token specific configuration
// - Refresh token specific configuration
//
// # Required Fields
// - Algorithm: Must be one of the supported JWT algorithms (HS256/384/512, RS256/384/512, ES256/384/512)
// - SigningMethod: Must be either Symmetric or Asymmetric
//
// # Field Requirements
// For Symmetric signing:
// - SymmetricKey: Required (minimum 32 bytes)
// - PrivateKeyPath/PublicKeyPath: Must be empty
//
// For Asymmetric signing:
// - PrivateKeyPath: Required (path to PEM-encoded private key)
// - PublicKeyPath: Required (path to PEM-encoded public key or certificate)
// - SymmetricKey: Must be empty
//
// # Example
// Typical usage involves creating a config with NewGourdianTokenConfig() or manually:
//
//	config := GourdianTokenConfig{
//	    Algorithm:     "HS256",
//	    SigningMethod: Symmetric,
//	    SymmetricKey:  "your-32-byte-secure-key-1234567890abcdef",
//	    AccessToken: AccessTokenConfig{
//	        Duration: time.Hour,
//	    },
//	}
type GourdianTokenConfig struct {
	Algorithm      string             // JWT signing algorithm (e.g., "HS256", "RS256", "ES256")
	SigningMethod  SigningMethod      // Cryptographic method (symmetric or asymmetric)
	SymmetricKey   string             // Secret key for symmetric signing (min 32 bytes)
	PrivateKeyPath string             // Path to private key for asymmetric signing
	PublicKeyPath  string             // Path to public key for asymmetric verification
	AccessToken    AccessTokenConfig  // Configuration specific to access tokens
	RefreshToken   RefreshTokenConfig // Configuration specific to refresh tokens
}

// AccessTokenConfig contains settings specific to access tokens (short-lived API tokens).
//
// These tokens typically have:
// - Short lifetimes (minutes to hours)
// - Specific roles/permissions
// - Strict validation requirements
//
// # Recommended Settings
// - Duration: 15 minutes to 1 hour for most applications
// - MaxLifetime: 24 hours maximum for security
// - RequiredClaims: At minimum ["jti", "sub", "exp", "iat"]
//
// # Security Notes
// Always set:
// - Issuer for validation
// - Audience when tokens are consumed by multiple services
type AccessTokenConfig struct {
	Duration          time.Duration // Token validity duration from issuance
	MaxLifetime       time.Duration // Absolute maximum lifetime from creation time
	Issuer            string        // Token issuer (e.g., "auth.example.com")
	Audience          []string      // Intended recipients (e.g., ["api.example.com"])
	AllowedAlgorithms []string      // Permitted algorithms for verification
	RequiredClaims    []string      // Mandatory claims (e.g., ["jti", "sub", "role"])
}

// RefreshTokenConfig contains settings specific to refresh tokens (long-lived renewal tokens).
//
// These tokens typically have:
// - Longer lifetimes (days to weeks)
// - Rotation capabilities
// - Family tracking for security
//
// # Security Recommendations
// - Enable rotation (RotationEnabled: true)
// - Set ReuseInterval (e.g., 1 minute)
// - Consider enabling token families
// - Limit MaxPerUser (e.g., 5 devices)
type RefreshTokenConfig struct {
	Duration        time.Duration // Token validity duration
	MaxLifetime     time.Duration // Absolute maximum lifetime
	ReuseInterval   time.Duration // Minimum time between reuse attempts
	RotationEnabled bool          // Whether to enable automatic rotation
	FamilyEnabled   bool          // Whether to track token families
	MaxPerUser      int           // Maximum concurrent tokens per user
}

// NewGourdianTokenConfig creates a fully configured GourdianTokenConfig with explicit parameters for all settings.
//
// This constructor provides maximum flexibility by requiring all configuration values to be specified,
// avoiding hidden defaults and making the configuration completely explicit.
//
// Parameters:
//   - algorithm: JWT signing algorithm (e.g., "HS256", "RS256", "ES256")
//   - signingMethod: Cryptographic method (Symmetric or Asymmetric)
//   - symmetricKey: Secret key for symmetric signing (leave empty for asymmetric)
//   - privateKeyPath: Path to private key file (leave empty for symmetric)
//   - publicKeyPath: Path to public key file (leave empty for symmetric)
//   - accessDuration: Access token validity duration
//   - accessMaxLifetime: Maximum absolute lifetime for access tokens
//   - accessIssuer: Issuer claim for access tokens
//   - accessAudience: Audience claims for access tokens
//   - accessAllowedAlgorithms: Permitted algorithms for access token verification
//   - accessRequiredClaims: Mandatory claims for access tokens
//   - refreshDuration: Refresh token validity duration
//   - refreshMaxLifetime: Maximum absolute lifetime for refresh tokens
//   - refreshReuseInterval: Minimum time between refresh token reuse
//   - refreshRotationEnabled: Whether refresh token rotation is enabled
//   - refreshFamilyEnabled: Whether token family tracking is enabled
//   - refreshMaxPerUser: Maximum concurrent refresh tokens per user
//
// Returns:
// A fully configured GourdianTokenConfig with no implicit defaults.
//
// Examples:
//
// # Symmetric Example (HMAC):
//
//	config := NewGourdianTokenConfig(
//	    "HS256",
//	    Symmetric,
//	    "your-32-byte-secret-key-1234567890abcdef",
//	    "",                          // privateKeyPath (empty for symmetric)
//	    "",                          // publicKeyPath (empty for symmetric)
//	    30*time.Minute,              // accessDuration
//	    24*time.Hour,                // accessMaxLifetime
//	    "auth.myapp.com",            // accessIssuer
//	    []string{"api.myapp.com"},   // accessAudience
//	    []string{"HS256"},           // accessAllowedAlgorithms
//	    []string{"jti", "sub", "exp", "iat", "typ"}, // accessRequiredClaims
//	    24*time.Hour,                // refreshDuration
//	    7*24*time.Hour,              // refreshMaxLifetime
//	    2*time.Minute,               // refreshReuseInterval
//	    true,                       // refreshRotationEnabled
//	    false,                      // refreshFamilyEnabled
//	    10,                         // refreshMaxPerUser
//	)
//
// # Asymmetric Example (RSA):
//
//	config := NewGourdianTokenConfig(
//	    "RS256",
//	    Asymmetric,
//	    "",                          // symmetricKey (empty for asymmetric)
//	    "/path/to/private.pem",      // privateKeyPath
//	    "/path/to/public.pem",       // publicKeyPath
//	    1*time.Hour,                // accessDuration
//	    24*time.Hour,               // accessMaxLifetime
//	    "myapp.com",                // accessIssuer
//	    []string{"api.myapp.com"},  // accessAudience
//	    []string{"RS256"},          // accessAllowedAlgorithms
//	    []string{"jti", "sub"},     // accessRequiredClaims
//	    7*24*time.Hour,             // refreshDuration
//	    30*24*time.Hour,            // refreshMaxLifetime
//	    time.Minute,                // refreshReuseInterval
//	    true,                       // refreshRotationEnabled
//	    true,                       // refreshFamilyEnabled
//	    5,                          // refreshMaxPerUser
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
	refreshDuration time.Duration,
	refreshMaxLifetime time.Duration,
	refreshReuseInterval time.Duration,
	refreshRotationEnabled bool,
	refreshFamilyEnabled bool,
	refreshMaxPerUser int,
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
			FamilyEnabled:   refreshFamilyEnabled,
			MaxPerUser:      refreshMaxPerUser,
		},
	}
}

// AccessTokenClaims represents the JWT claims specific to access tokens.
type AccessTokenClaims struct {
	ID        uuid.UUID `json:"jti"` // Unique token identifier
	Subject   uuid.UUID `json:"sub"` // Subject (user ID)
	Username  string    `json:"usr"` // Username
	SessionID uuid.UUID `json:"sid"` // Session identifier
	IssuedAt  time.Time `json:"iat"` // Time when token was issued
	ExpiresAt time.Time `json:"exp"` // Time when token expires
	TokenType TokenType `json:"typ"` // Type of token (access)
	Role      string    `json:"rol"` // User role/privileges
}

// RefreshTokenClaims represents the JWT claims specific to refresh tokens.
type RefreshTokenClaims struct {
	ID        uuid.UUID `json:"jti"` // Unique token identifier
	Subject   uuid.UUID `json:"sub"` // Subject (user ID)
	Username  string    `json:"usr"` // Username
	SessionID uuid.UUID `json:"sid"` // Session identifier
	IssuedAt  time.Time `json:"iat"` // Time when token was issued
	ExpiresAt time.Time `json:"exp"` // Time when token expires
	TokenType TokenType `json:"typ"` // Type of token (refresh)
}

// AccessTokenResponse contains the response after creating an access token.
type AccessTokenResponse struct {
	Token     string    `json:"tok"` // The signed JWT string
	Subject   uuid.UUID `json:"sub"` // User ID
	Username  string    `json:"usr"` // Username
	SessionID uuid.UUID `json:"sid"` // Session ID
	ExpiresAt time.Time `json:"exp"` // Expiration time
	IssuedAt  time.Time `json:"iat"` // Issuance time
	Role      string    `json:"rol"` // User role
}

// RefreshTokenResponse contains the response after creating a refresh token.
type RefreshTokenResponse struct {
	Token     string    `json:"tok"` // The signed JWT string
	Subject   uuid.UUID `json:"sub"` // User ID
	Username  string    `json:"usr"` // Username
	SessionID uuid.UUID `json:"sid"` // Session ID
	ExpiresAt time.Time `json:"exp"` // Expiration time
	IssuedAt  time.Time `json:"iat"` // Issuance time
}

// validateConfig validates the configuration.
func validateConfig(config *GourdianTokenConfig) error {
	switch config.SigningMethod {
	case Symmetric:
		if config.SymmetricKey == "" {
			return fmt.Errorf("symmetric key is required for symmetric signing method")
		}
		if len(config.SymmetricKey) < 32 {
			return fmt.Errorf("symmetric key must be at least 32 bytes")
		}
	case Asymmetric:
		if config.PrivateKeyPath == "" || config.PublicKeyPath == "" {
			return fmt.Errorf("private and public key paths are required for asymmetric signing method")
		}
		// Add file permission checks
		if err := checkFilePermissions(config.PrivateKeyPath, 0600); err != nil {
			return fmt.Errorf("insecure private key file permissions: %w", err)
		}
		// Add file permission checks
		if err := checkFilePermissions(config.PublicKeyPath, 0600); err != nil {
			return fmt.Errorf("insecure public key file permissions: %w", err)
		}
	default:
		return fmt.Errorf("unsupported signing method: %s, supports %s and %s ", config.SigningMethod, Symmetric, Asymmetric)
	}
	return nil
}

// GourdianTokenMaker defines the interface for token management operations.
type GourdianTokenMaker interface {
	// CreateAccessToken generates a new access token for the specified user
	CreateAccessToken(ctx context.Context, userID uuid.UUID, username, role string, sessionID uuid.UUID) (*AccessTokenResponse, error)

	// CreateRefreshToken generates a new refresh token for the specified user
	CreateRefreshToken(ctx context.Context, userID uuid.UUID, username string, sessionID uuid.UUID) (*RefreshTokenResponse, error)

	// VerifyAccessToken validates and parses an access token string
	VerifyAccessToken(tokenString string) (*AccessTokenClaims, error)

	// VerifyRefreshToken validates and parses a refresh token string
	VerifyRefreshToken(tokenString string) (*RefreshTokenClaims, error)

	// RotateRefreshToken generates a new refresh token while invalidating the old one
	RotateRefreshToken(oldToken string) (*RefreshTokenResponse, error)
}

// JWTMaker implements GourdianTokenMaker using JWT tokens.
type JWTMaker struct {
	config        GourdianTokenConfig
	signingMethod jwt.SigningMethod
	privateKey    interface{} // Key used for signing (HMAC secret, RSA or ECDSA private key)
	publicKey     interface{} // Key used for verification (HMAC secret, RSA or ECDSA public key)
}

// NewGourdianTokenMaker creates a new token maker instance with the provided configuration.
// This is the primary initialization function for the token management system.
//
// The function performs several critical operations:
//  1. Validates the configuration for completeness and security
//  2. Initializes the appropriate JWT signing method based on configuration
//  3. Loads and verifies cryptographic keys (either symmetric or asymmetric)
//  4. Returns a ready-to-use token maker instance implementing GourdianTokenMaker
//
// # Configuration Requirements
//
// For symmetric signing (HMAC):
//   - Must provide SymmetricKey (minimum 32 bytes)
//   - Supported algorithms: HS256, HS384, HS512
//
// For asymmetric signing (RSA/ECDSA):
//   - Must provide both PrivateKeyPath and PublicKeyPath
//   - Files must have secure permissions (0600)
//   - Supported algorithms:
//   - RSA: RS256, RS384, RS512
//   - ECDSA: ES256, ES384, ES512
//
// # Example Usage
//
// ## Symmetric Key Example
//
//	config := GourdianTokenConfig{
//	    Algorithm:     "HS256",
//	    SigningMethod: Symmetric,
//	    SymmetricKey:  "your-32-byte-secret-key-here-1234567890",
//	    AccessToken: AccessTokenConfig{
//	        Duration:    30 * time.Minute,
//	        MaxLifetime: 24 * time.Hour,
//	    },
//	    RefreshToken: RefreshTokenConfig{
//	        Duration:        7 * 24 * time.Hour,
//	        RotationEnabled: true,
//	    },
//	}
//	maker, err := NewGourdianTokenMaker(config)
//
// ## Asymmetric Key Example
//
//	config := GourdianTokenConfig{
//	    Algorithm:      "RS256",
//	    SigningMethod:  Asymmetric,
//	    PrivateKeyPath: "/path/to/private.pem",
//	    PublicKeyPath:  "/path/to/public.pem",
//	    AccessToken: AccessTokenConfig{
//	        Duration:    time.Hour,
//	        Issuer:      "your-issuer",
//	        Audience:    []string{"your-audience"},
//	    },
//	}
//	maker, err := NewGourdianTokenMaker(config)
//
// # Error Handling
//
// The function may return various errors including:
//   - ErrInvalidConfig: When configuration is incomplete or invalid
//   - ErrUnsupportedAlgorithm: When specified algorithm isn't supported
//   - ErrKeyInitialization: When key loading or parsing fails
//   - ErrInsecureKeyFile: When key file permissions are too permissive
//
// The returned GourdianTokenMaker is safe for concurrent use by multiple goroutines.
func NewGourdianTokenMaker(config GourdianTokenConfig) (GourdianTokenMaker, error) {
	if err := validateConfig(&config); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	maker := &JWTMaker{
		config: config,
	}

	// Initialize signing method first
	if err := maker.initializeSigningMethod(); err != nil {
		return nil, fmt.Errorf("failed to initialize signing method: %w", err)
	}

	// Then initialize keys
	if err := maker.initializeKeys(); err != nil {
		return nil, fmt.Errorf("failed to initialize keys: %w", err)
	}

	return maker, nil
}

// CreateAccessToken generates a new access token with the specified user details.
// The token includes standard JWT claims along with custom claims for user identity and role.
// Returns an AccessTokenResponse containing the signed token and its metadata.
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
// Refresh tokens are used to obtain new access tokens without re-authentication.
// Returns a RefreshTokenResponse containing the signed token and its metadata.
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
// It checks the token signature, expiration, and required claims.
// Returns AccessTokenClaims if valid, otherwise returns an error.
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

	// Validate standard claims
	if err := validateTokenClaims(claims, AccessToken); err != nil {
		return nil, err
	}

	// Additional access token specific validation
	if _, ok := claims["rol"]; !ok {
		return nil, fmt.Errorf("missing role claim in access token")
	}

	return mapToAccessClaims(claims)
}

// VerifyRefreshToken validates a refresh token string and returns its claims.
// It checks the token signature, expiration, and required claims.
// Returns RefreshTokenClaims if valid, otherwise returns an error.
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

	// Validate standard claims
	if err := validateTokenClaims(claims, RefreshToken); err != nil {
		return nil, err
	}

	return mapToRefreshClaims(claims)
}

// RotateRefreshToken generates a new refresh token while invalidating the old one.
// This implements refresh token rotation for enhanced security.
// Returns a new RefreshTokenResponse if successful, otherwise returns an error.
func (maker *JWTMaker) RotateRefreshToken(oldToken string) (*RefreshTokenResponse, error) {
	claims, err := maker.VerifyRefreshToken(oldToken)
	if err != nil {
		return nil, err
	}

	if !maker.config.RefreshToken.RotationEnabled {
		return nil, fmt.Errorf("token rotation not enabled")
	}

	// Check against reuse interval
	if time.Since(claims.IssuedAt) < maker.config.RefreshToken.ReuseInterval {
		return nil, fmt.Errorf("token reuse too soon")
	}

	return maker.CreateRefreshToken(
		context.Background(),
		claims.Subject,
		claims.Username,
		claims.SessionID,
	)
}

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

// initializeSigningMethod initializes the JWT signing method based on the algorithm
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
	case "ES256":
		maker.signingMethod = jwt.SigningMethodES256
	case "ES384":
		maker.signingMethod = jwt.SigningMethodES384
	case "ES512":
		maker.signingMethod = jwt.SigningMethodES512
	default:
		return fmt.Errorf("unsupported algorithm: %s", maker.config.Algorithm)
	}
	return nil
}

// validateTokenClaims validates the standard JWT claims
func validateTokenClaims(claims jwt.MapClaims, expectedType TokenType) error {
	// Check required claims
	requiredClaims := []string{"jti", "sub", "usr", "sid", "iat", "exp", "typ"}
	for _, claim := range requiredClaims {
		if _, ok := claims[claim]; !ok {
			return fmt.Errorf("missing required claim: %s", claim)
		}
	}

	// Verify token type
	tokenType, ok := claims["typ"].(string)
	if !ok || TokenType(tokenType) != expectedType {
		return fmt.Errorf("invalid token type: expected %s", expectedType)
	}

	// Check expiration
	exp, ok := claims["exp"].(float64)
	if !ok {
		return fmt.Errorf("invalid exp claim type")
	}
	if time.Unix(int64(exp), 0).Before(time.Now()) {
		return fmt.Errorf("token has expired")
	}

	// Check issued at
	if iat, ok := claims["iat"].(float64); ok {
		if time.Unix(int64(iat), 0).After(time.Now()) {
			return fmt.Errorf("token issued in the future")
		}
	}

	return nil
}

// parseKeyPair parses both private and public keys for asymmetric signing
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
	case "RS256", "RS384", "RS512":
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

	default:
		return fmt.Errorf("unsupported algorithm for asymmetric signing: %s", maker.signingMethod.Alg())
	}

	return nil
}

// Helper functions to parse PEM encoded keys
func parseRSAPrivateKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block containing the RSA private key")
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		// Try parsing as PKCS8
		pkcs8Key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse RSA private key: %w", err)
		}
		key, ok := pkcs8Key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("not a valid RSA private key")
		}
		return key, nil
	}
	return key, nil
}

func parseRSAPublicKey(pemBytes []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block containing the RSA public key")
	}

	// Try parsing as PKIX
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		// Try parsing as X509 certificate
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse RSA public key: %w", err)
		}
		rsaPub, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("not a valid RSA public key")
		}
		return rsaPub, nil
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not a valid RSA public key")
	}
	return rsaPub, nil
}

func parseECDSAPrivateKey(pemBytes []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block containing the ECDSA private key")
	}

	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		// Try parsing as PKCS8
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

	// Try parsing as PKIX
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		// Try parsing as X509 certificate
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

// checkFilePermissions checks if the file has the required permissions
func checkFilePermissions(path string, requiredPerm os.FileMode) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("failed to stat file: %w", err)
	}

	// Get the actual permissions
	actualPerm := info.Mode().Perm()

	// Check if the actual permissions are more permissive than required
	if actualPerm&^requiredPerm != 0 {
		return fmt.Errorf("file %s has permissions %#o, expected %#o", path, actualPerm, requiredPerm)
	}

	return nil
}

// toMapClaims converts claims to jwt.MapClaims.
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
			"typ": v.TokenType,
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
			"typ": v.TokenType,
		}
	default:
		return nil
	}
}

// mapToAccessClaims converts JWT claims to AccessTokenClaims.
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

	// Get role as string directly
	role, ok := claims["rol"].(string)
	if !ok {
		return nil, fmt.Errorf("invalid role type: expected string")
	}

	return &AccessTokenClaims{
		ID:        tokenID,
		Subject:   userID,
		Username:  username,
		SessionID: sessionID,
		IssuedAt:  time.Unix(int64(claims["iat"].(float64)), 0),
		ExpiresAt: time.Unix(int64(claims["exp"].(float64)), 0),
		TokenType: TokenType(claims["typ"].(string)),
		Role:      role,
	}, nil
}

// mapToRefreshClaims converts JWT claims to RefreshTokenClaims.
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
		IssuedAt:  time.Unix(int64(claims["iat"].(float64)), 0),
		ExpiresAt: time.Unix(int64(claims["exp"].(float64)), 0),
		TokenType: TokenType(claims["typ"].(string)),
	}, nil
}
