package gourdiantoken

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

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
			"per": v.Permissions,
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

	permissions := make([]string, 0)
	if permsInterface, ok := claims["per"].([]interface{}); ok {
		for _, p := range permsInterface {
			if perm, ok := p.(string); ok {
				permissions = append(permissions, perm)
			}
		}
	}

	return &AccessTokenClaims{
		ID:          tokenID,
		Subject:     userID,
		Username:    claims["usr"].(string),
		SessionID:   sessionID,
		IssuedAt:    time.Unix(int64(claims["iat"].(float64)), 0),
		ExpiresAt:   time.Unix(int64(claims["exp"].(float64)), 0),
		TokenType:   TokenType(claims["typ"].(string)),
		Role:        role,
		Permissions: permissions,
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
