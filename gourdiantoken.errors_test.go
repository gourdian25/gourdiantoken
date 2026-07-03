// File: gourdiantoken.errors_test.go

package gourdiantoken

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestErrTokenRevoked_ErrorsIs(t *testing.T) {
	maker := setupTestMakerWithRepo(t)
	ctx := context.Background()

	token, err := maker.CreateAccessToken(ctx, uuid.New(), "user", []string{"admin"}, uuid.New())
	require.NoError(t, err)

	require.NoError(t, maker.RevokeAccessToken(ctx, token.Token))

	_, err = maker.VerifyAccessToken(ctx, token.Token)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTokenRevoked)
}

func TestErrTokenRotated_ErrorsIs(t *testing.T) {
	maker := setupTestMakerWithRepo(t)
	ctx := context.Background()

	token, err := maker.CreateRefreshToken(ctx, uuid.New(), "user", uuid.New())
	require.NoError(t, err)

	_, err = maker.RotateRefreshToken(ctx, token.Token)
	require.NoError(t, err)

	// Reusing the same (now-rotated) refresh token must fail with ErrTokenRotated,
	// both via RotateRefreshToken's atomic-mark check and via VerifyRefreshToken directly.
	_, err = maker.RotateRefreshToken(ctx, token.Token)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTokenRotated)

	_, err = maker.VerifyRefreshToken(ctx, token.Token)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTokenRotated)
}

func TestErrTokenExpired_ErrorsIs(t *testing.T) {
	maker := setupTestMakerWithConfig(t, DefaultTestConfig(), nil)

	pastTime := time.Now().Add(-1 * time.Hour)
	claims := AccessTokenClaims{
		ID:                uuid.New(),
		Subject:           uuid.New(),
		SessionID:         uuid.New(),
		Username:          "user",
		Issuer:            maker.config.Issuer,
		Audience:          maker.config.Audience,
		Roles:             []string{"admin"},
		IssuedAt:          pastTime,
		ExpiresAt:         pastTime.Add(30 * time.Minute), // expired 30 minutes ago
		NotBefore:         pastTime,
		MaxLifetimeExpiry: pastTime.Add(24 * time.Hour),
		TokenType:         AccessToken,
	}

	mapClaims, err := toMapClaims(claims)
	require.NoError(t, err)
	jwtToken := jwt.NewWithClaims(maker.signingMethod, mapClaims)
	expiredToken, err := jwtToken.SignedString(maker.privateKey)
	require.NoError(t, err)

	_, err = maker.VerifyAccessToken(context.Background(), expiredToken)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTokenExpired)
	assert.True(t, errors.Is(err, jwt.ErrTokenExpired))
}

func TestErrTokenMaxLifetimeExceeded_ErrorsIs(t *testing.T) {
	maker := setupTestMakerWithConfig(t, DefaultTestConfig(), nil)

	now := time.Now()
	pastMle := now.Add(-1 * time.Minute)
	claims := AccessTokenClaims{
		ID:                uuid.New(),
		Subject:           uuid.New(),
		SessionID:         uuid.New(),
		Username:          "user",
		Issuer:            maker.config.Issuer,
		Audience:          maker.config.Audience,
		Roles:             []string{"admin"},
		IssuedAt:          now,
		ExpiresAt:         now.Add(30 * time.Minute), // still valid by exp
		NotBefore:         now,
		MaxLifetimeExpiry: pastMle, // but exceeded max lifetime
		TokenType:         AccessToken,
	}

	mapClaims, err := toMapClaims(claims)
	require.NoError(t, err)
	jwtToken := jwt.NewWithClaims(maker.signingMethod, mapClaims)
	token, err := jwtToken.SignedString(maker.privateKey)
	require.NoError(t, err)

	_, err = maker.VerifyAccessToken(context.Background(), token)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTokenMaxLifetimeExceeded)
}
