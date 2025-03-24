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

// TokenType represents the type of token (access or refresh).
type TokenType string

const (
	AccessToken  TokenType = "access"  // Access token type
	RefreshToken TokenType = "refresh" // Refresh token type
)

// SigningMethod represents the key signing method (symmetric or asymmetric).
type SigningMethod string

const (
	Symmetric  SigningMethod = "symmetric"  // Symmetric key signing (HMAC)
	Asymmetric SigningMethod = "asymmetric" // Asymmetric key signing (RSA, ECDSA)
)

// GourdianTokenConfig holds the configuration for token generation and verification.
//
// Fields:
//   - Algorithm: Signing algorithm (e.g., "HS256", "RS256", "ES256")
//   - SigningMethod: Method to use for signing (symmetric or asymmetric)
//   - SymmetricKey: Symmetric key for signing tokens (used when SigningMethod is Symmetric)
//   - PrivateKeyPath: Path to the private key file (used when SigningMethod is Asymmetric)
//   - PublicKeyPath: Path to the public key file (used when SigningMethod is Asymmetric)
//   - AccessToken: Configuration for access tokens
//   - RefreshToken: Configuration for refresh tokens
type GourdianTokenConfig struct {
	Algorithm      string
	SigningMethod  SigningMethod
	SymmetricKey   string
	PrivateKeyPath string
	PublicKeyPath  string
	AccessToken    AccessTokenConfig
	RefreshToken   RefreshTokenConfig
}

// AccessTokenConfig holds configuration specific to access tokens.
//
// Fields:
//   - Duration: Token validity duration
//   - MaxLifetime: Maximum lifetime of the token
//   - Issuer: Token issuer
//   - Audience: Intended audience for the token
//   - AllowedAlgorithms: List of allowed signing algorithms
//   - RequiredClaims: List of required claims
type AccessTokenConfig struct {
	Duration          time.Duration
	MaxLifetime       time.Duration
	Issuer            string
	Audience          []string
	AllowedAlgorithms []string
	RequiredClaims    []string
}

// RefreshTokenConfig holds configuration specific to refresh tokens.
//
// Fields:
//   - Duration: Token validity duration
//   - MaxLifetime: Maximum lifetime of the token
//   - ReuseInterval: Time interval before a refresh token can be reused
//   - RotationEnabled: Whether token rotation is enabled
//   - FamilyEnabled: Whether token family tracking is enabled
//   - MaxPerUser: Maximum number of refresh tokens per user
type RefreshTokenConfig struct {
	Duration        time.Duration
	MaxLifetime     time.Duration
	ReuseInterval   time.Duration
	RotationEnabled bool
	FamilyEnabled   bool
	MaxPerUser      int
}

// AccessTokenClaims contains claims specific to access tokens.
//
// Fields:
//   - ID: Unique token ID (JWT ID)
//   - Subject: User ID (subject)
//   - Username: Username
//   - SessionID: Session ID
//   - IssuedAt: Token issuance time
//   - ExpiresAt: Token expiration time
//   - TokenType: Token type (access or refresh)
//   - Role: User role
type AccessTokenClaims struct {
	ID        uuid.UUID `json:"jti"`
	Subject   uuid.UUID `json:"sub"`
	Username  string    `json:"usr"`
	SessionID uuid.UUID `json:"sid"`
	IssuedAt  time.Time `json:"iat"`
	ExpiresAt time.Time `json:"exp"`
	TokenType TokenType `json:"typ"`
	Role      string    `json:"rol"`
}

// RefreshTokenClaims contains claims specific to refresh tokens.
//
// Fields:
//   - ID: Unique token ID (JWT ID)
//   - Subject: User ID (subject)
//   - Username: Username
//   - SessionID: Session ID
//   - IssuedAt: Token issuance time
//   - ExpiresAt: Token expiration time
//   - TokenType: Token type (access or refresh)
type RefreshTokenClaims struct {
	ID        uuid.UUID `json:"jti"`
	Subject   uuid.UUID `json:"sub"`
	Username  string    `json:"usr"`
	SessionID uuid.UUID `json:"sid"`
	IssuedAt  time.Time `json:"iat"`
	ExpiresAt time.Time `json:"exp"`
	TokenType TokenType `json:"typ"`
}

// AccessTokenResponse represents the response after creating an access token.
//
// Fields:
//   - Token: Signed access token
//   - Subject: User ID (subject)
//   - Username: Username
//   - SessionID: Session ID
//   - ExpiresAt: Token expiration time
//   - IssuedAt: Token issuance time
//   - Role: User role
type AccessTokenResponse struct {
	Token     string    `json:"tok"`
	Subject   uuid.UUID `json:"sub"`
	Username  string    `json:"usr"`
	SessionID uuid.UUID `json:"sid"`
	ExpiresAt time.Time `json:"exp"`
	IssuedAt  time.Time `json:"iat"`
	Role      string    `json:"rol"`
}

// RefreshTokenResponse represents the response after creating a refresh token.
//
// Fields:
//   - Token: Signed refresh token
//   - Subject: User ID (subject)
//   - Username: Username
//   - SessionID: Session ID
//   - ExpiresAt: Token expiration time
//   - IssuedAt: Token issuance time
type RefreshTokenResponse struct {
	Token     string    `json:"tok"`
	Subject   uuid.UUID `json:"sub"`
	Username  string    `json:"usr"`
	SessionID uuid.UUID `json:"sid"`
	ExpiresAt time.Time `json:"exp"`
	IssuedAt  time.Time `json:"iat"`
}

// GourdianTokenMaker defines the interface for token management.
//
// Methods:
//   - CreateAccessToken: Creates a new access token
//   - CreateRefreshToken: Creates a new refresh token
//   - VerifyAccessToken: Verifies and decodes an access token
//   - VerifyRefreshToken: Verifies and decodes a refresh token
type GourdianTokenMaker interface {
	CreateAccessToken(ctx context.Context, userID uuid.UUID, username, role string, sessionID uuid.UUID) (*AccessTokenResponse, error)
	CreateRefreshToken(ctx context.Context, userID uuid.UUID, username string, sessionID uuid.UUID) (*RefreshTokenResponse, error)
	VerifyAccessToken(tokenString string) (*AccessTokenClaims, error)
	VerifyRefreshToken(tokenString string) (*RefreshTokenClaims, error)
}

// JWTMaker is the concrete implementation of GourdianTokenMaker using JWT.
type JWTMaker struct {
	config        GourdianTokenConfig
	signingMethod jwt.SigningMethod
	privateKey    interface{} // Can be []byte for HMAC, *rsa.PrivateKey for RSA, or *ecdsa.PrivateKey for ECDSA
	publicKey     interface{} // Can be []byte for HMAC, *rsa.PublicKey for RSA, or *ecdsa.PublicKey for ECDSA
}

// NewGourdianTokenMaker creates a new instance of JWTMaker.
//
// Parameters:
//   - config: Token configuration
//
// Returns:
//   - GourdianTokenMaker: Token maker instance
//   - error: Any error encountered during initialization
func NewGourdianTokenMaker(config GourdianTokenConfig) (GourdianTokenMaker, error) {
	maker := &JWTMaker{
		config: config,
	}

	// Set the signing method based on the algorithm
	switch config.Algorithm {
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
		return nil, fmt.Errorf("unsupported signing algorithm: %s", config.Algorithm)
	}

	// Initialize keys based on the signing method
	if err := maker.initializeKeys(); err != nil {
		return nil, err
	}

	return maker, nil
}

// CreateAccessToken creates a new access token.
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

// CreateRefreshToken creates a new refresh token.
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

// VerifyAccessToken verifies and decodes an access token.
func (maker *JWTMaker) VerifyAccessToken(tokenString string) (*AccessTokenClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Validate the signing method
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

	// Verify token type
	tokenType, ok := claims["typ"].(string)
	if !ok || TokenType(tokenType) != AccessToken {
		return nil, fmt.Errorf("invalid token type: expected access token")
	}

	return mapToAccessClaims(claims)
}

// VerifyRefreshToken verifies and decodes a refresh token.
func (maker *JWTMaker) VerifyRefreshToken(tokenString string) (*RefreshTokenClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Validate the signing method
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

	// Verify token type
	tokenType, ok := claims["typ"].(string)
	if !ok || TokenType(tokenType) != RefreshToken {
		return nil, fmt.Errorf("invalid token type: expected refresh token")
	}

	return mapToRefreshClaims(claims)
}

// initializeKeys initializes the signing keys based on the configured signing method.
func (maker *JWTMaker) initializeKeys() error {
	switch maker.config.SigningMethod {
	case Symmetric:
		if maker.config.SymmetricKey == "" {
			return fmt.Errorf("symmetric key is required for symmetric signing method")
		}
		maker.privateKey = []byte(maker.config.SymmetricKey)
		maker.publicKey = []byte(maker.config.SymmetricKey)
		return nil

	case Asymmetric:
		if maker.config.PrivateKeyPath == "" {
			return fmt.Errorf("private key path is required for asymmetric signing method")
		}
		if maker.config.PublicKeyPath == "" {
			return fmt.Errorf("public key path is required for asymmetric signing method")
		}

		// Load private key
		privateKeyBytes, err := os.ReadFile(maker.config.PrivateKeyPath)
		if err != nil {
			return fmt.Errorf("failed to read private key file: %w", err)
		}

		// Load public key
		publicKeyBytes, err := os.ReadFile(maker.config.PublicKeyPath)
		if err != nil {
			return fmt.Errorf("failed to read public key file: %w", err)
		}

		// Parse the keys based on the algorithm
		switch {
		case maker.signingMethod.Alg() == "RS256" || maker.signingMethod.Alg() == "RS384" || maker.signingMethod.Alg() == "RS512":
			// Parse RSA private key
			privateKey, err := parseRSAPrivateKey(privateKeyBytes)
			if err != nil {
				return fmt.Errorf("failed to parse RSA private key: %w", err)
			}
			maker.privateKey = privateKey

			// Parse RSA public key
			publicKey, err := parseRSAPublicKey(publicKeyBytes)
			if err != nil {
				return fmt.Errorf("failed to parse RSA public key: %w", err)
			}
			maker.publicKey = publicKey

		case maker.signingMethod.Alg() == "ES256" || maker.signingMethod.Alg() == "ES384" || maker.signingMethod.Alg() == "ES512":
			// Parse ECDSA private key
			privateKey, err := parseECDSAPrivateKey(privateKeyBytes)
			if err != nil {
				return fmt.Errorf("failed to parse ECDSA private key: %w", err)
			}
			maker.privateKey = privateKey

			// Parse ECDSA public key
			publicKey, err := parseECDSAPublicKey(publicKeyBytes)
			if err != nil {
				return fmt.Errorf("failed to parse ECDSA public key: %w", err)
			}
			maker.publicKey = publicKey

		default:
			return fmt.Errorf("unsupported algorithm for asymmetric signing: %s", maker.signingMethod.Alg())
		}
		return nil

	default:
		return fmt.Errorf("unsupported signing method: %s", maker.config.SigningMethod)
	}
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

	// Get role as string directly
	role, ok := claims["rol"].(string)
	if !ok {
		return nil, fmt.Errorf("invalid role type: expected string")
	}

	return &AccessTokenClaims{
		ID:        tokenID,
		Subject:   userID,
		Username:  claims["usr"].(string),
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

	return &RefreshTokenClaims{
		ID:        tokenID,
		Subject:   userID,
		Username:  claims["usr"].(string),
		SessionID: sessionID,
		IssuedAt:  time.Unix(int64(claims["iat"].(float64)), 0),
		ExpiresAt: time.Unix(int64(claims["exp"].(float64)), 0),
		TokenType: TokenType(claims["typ"].(string)),
	}, nil
}
