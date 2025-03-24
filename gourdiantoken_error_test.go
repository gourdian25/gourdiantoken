package gourdiantoken

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestErrorCases(t *testing.T) {
	t.Run("Invalid Token String", func(t *testing.T) {
		config := DefaultGourdianTokenConfig("test-secret-32-bytes-long-1234567890")
		maker, err := NewGourdianTokenMaker(config)
		require.NoError(t, err)

		_, err = maker.VerifyAccessToken("invalid.token.string")
		require.Error(t, err)
		assert.True(t, errors.Is(err, jwt.ErrTokenMalformed))
	})

	t.Run("Expired Token", func(t *testing.T) {
		config := DefaultGourdianTokenConfig("test-secret-32-bytes-long-1234567890")
		config.AccessToken.Duration = -time.Hour // Set to expire immediately
		maker, err := NewGourdianTokenMaker(config)
		require.NoError(t, err)

		token, err := maker.CreateAccessToken(
			context.Background(),
			uuid.New(),
			"user",
			"role",
			uuid.New(),
		)
		require.NoError(t, err)

		_, err = maker.VerifyAccessToken(token.Token)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "token has expired")
	})

	t.Run("Wrong Algorithm", func(t *testing.T) {
		// Create token with HS256
		config1 := DefaultGourdianTokenConfig("test-secret-32-bytes-long-1234567890")
		maker1, err := NewGourdianTokenMaker(config1)
		require.NoError(t, err)

		token, err := maker1.CreateAccessToken(
			context.Background(),
			uuid.New(),
			"user",
			"role",
			uuid.New(),
		)
		require.NoError(t, err)

		// Try to verify with RS256
		privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
		config2 := GourdianTokenConfig{
			Algorithm:     "RS256",
			SigningMethod: Asymmetric,
		}
		maker2 := &JWTMaker{
			config:        config2,
			signingMethod: jwt.SigningMethodRS256,
			privateKey:    privateKey,
			publicKey:     &privateKey.PublicKey,
		}

		_, err = maker2.VerifyAccessToken(token.Token)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unexpected signing method")
	})

	t.Run("Invalid UUID in Claims", func(t *testing.T) {
		config := DefaultGourdianTokenConfig("test-secret-32-bytes-long-1234567890")
		maker, err := NewGourdianTokenMaker(config)
		require.NoError(t, err)

		// Create a token with invalid UUID format
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"jti": "invalid-uuid",
			"sub": uuid.New().String(),
			"usr": "user",
			"sid": uuid.New().String(),
			"iat": time.Now().Unix(),
			"exp": time.Now().Add(time.Hour).Unix(),
			"typ": AccessToken,
			"rol": "role",
		})

		tokenString, err := token.SignedString([]byte(config.SymmetricKey))
		require.NoError(t, err)

		_, err = maker.VerifyAccessToken(tokenString)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid token ID")
	})
}
