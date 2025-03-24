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
type AccessTokenConfig struct {
	Duration          time.Duration
	MaxLifetime       time.Duration
	Issuer            string
	Audience          []string
	AllowedAlgorithms []string
	RequiredClaims    []string
}

// RefreshTokenConfig holds configuration specific to refresh tokens.
type RefreshTokenConfig struct {
	Duration        time.Duration
	MaxLifetime     time.Duration
	ReuseInterval   time.Duration
	RotationEnabled bool
	FamilyEnabled   bool
	MaxPerUser      int
}

// AccessTokenClaims contains claims specific to access tokens.
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
type RefreshTokenResponse struct {
	Token     string    `json:"tok"`
	Subject   uuid.UUID `json:"sub"`
	Username  string    `json:"usr"`
	SessionID uuid.UUID `json:"sid"`
	ExpiresAt time.Time `json:"exp"`
	IssuedAt  time.Time `json:"iat"`
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

// GourdianTokenMaker defines the interface for token management.
type GourdianTokenMaker interface {
	CreateAccessToken(ctx context.Context, userID uuid.UUID, username, role string, sessionID uuid.UUID) (*AccessTokenResponse, error)
	CreateRefreshToken(ctx context.Context, userID uuid.UUID, username string, sessionID uuid.UUID) (*RefreshTokenResponse, error)
	VerifyAccessToken(tokenString string) (*AccessTokenClaims, error)
	VerifyRefreshToken(tokenString string) (*RefreshTokenClaims, error)
	RotateRefreshToken(oldToken string) (*RefreshTokenResponse, error)
}

// JWTMaker is the concrete implementation of GourdianTokenMaker using JWT.
type JWTMaker struct {
	config        GourdianTokenConfig
	signingMethod jwt.SigningMethod
	privateKey    interface{} // Can be []byte for HMAC, *rsa.PrivateKey for RSA, or *ecdsa.PrivateKey for ECDSA
	publicKey     interface{} // Can be []byte for HMAC, *rsa.PublicKey for RSA, or *ecdsa.PublicKey for ECDSA
}

// NewGourdianTokenMaker (improved version)
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

// VerifyAccessToken (improved version)
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

// VerifyRefreshToken (improved version)
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
