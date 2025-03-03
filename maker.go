package gourdiantoken

import (
	"context"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// GourdianTokenMaker defines the interface for token management.
//
// Methods:
//   - CreateAccessToken: Creates a new access token
//   - CreateRefreshToken: Creates a new refresh token
//   - VerifyAccessToken: Verifies and decodes an access token
//   - VerifyRefreshToken: Verifies and decodes a refresh token
type GourdianTokenMaker interface {
	CreateAccessToken(ctx context.Context, userID uuid.UUID, username, role string, sessionID uuid.UUID, permissions []string) (*AccessTokenResponse, error)
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
func (maker *JWTMaker) CreateAccessToken(ctx context.Context, userID uuid.UUID, username, role string, sessionID uuid.UUID, permissions []string) (*AccessTokenResponse, error) {
	tokenID, err := uuid.NewRandom()
	if err != nil {
		return nil, fmt.Errorf("failed to generate token ID: %w", err)
	}

	now := time.Now()
	claims := AccessTokenClaims{
		ID:          tokenID,
		Subject:     userID,
		Username:    username,
		SessionID:   sessionID,
		IssuedAt:    now,
		ExpiresAt:   now.Add(maker.config.AccessToken.Duration),
		TokenType:   AccessToken,
		Role:        role,
		Permissions: permissions,
	}

	token := jwt.NewWithClaims(maker.signingMethod, toMapClaims(claims))

	signedToken, err := token.SignedString(maker.privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign access token: %w", err)
	}

	response := &AccessTokenResponse{
		Token:       signedToken,
		Subject:     claims.Subject,
		Username:    claims.Username,
		SessionID:   claims.SessionID,
		ExpiresAt:   claims.ExpiresAt,
		IssuedAt:    claims.IssuedAt,
		Role:        role,
		Permissions: permissions,
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
