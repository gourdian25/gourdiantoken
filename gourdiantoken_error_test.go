// gourdiantoken_error_test.go

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
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestErrorCases(t *testing.T) {
	t.Run("Invalid Token String", func(t *testing.T) {
		config := DefaultGourdianTokenConfig("test-secret-32-bytes-long-1234567890")
		maker, err := NewGourdianTokenMaker(context.Background(), config, nil)
		require.NoError(t, err)

		_, err = maker.VerifyAccessToken(context.Background(), "invalid.token.string")
		require.Error(t, err)
		assert.True(t, errors.Is(err, jwt.ErrTokenMalformed))
	})

	t.Run("Expired Token", func(t *testing.T) {
		config := DefaultGourdianTokenConfig("test-secret-32-bytes-long-1234567890")
		config.AccessToken.Duration = -time.Hour // Set to expire immediately
		maker, err := NewGourdianTokenMaker(context.Background(), config, nil)
		require.NoError(t, err)

		token, err := maker.CreateAccessToken(
			context.Background(),
			uuid.New(),
			"user",
			[]string{"role"},
			uuid.New(),
		)
		require.NoError(t, err)

		_, err = maker.VerifyAccessToken(context.Background(), token.Token)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "expired")
	})

	t.Run("Wrong Algorithm", func(t *testing.T) {
		// Create token with HS256
		config1 := DefaultGourdianTokenConfig("test-secret-32-bytes-long-1234567890")
		maker1, err := NewGourdianTokenMaker(context.Background(), config1, nil)
		require.NoError(t, err)

		token, err := maker1.CreateAccessToken(
			context.Background(),
			uuid.New(),
			"user",
			[]string{"role"},
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

		_, err = maker2.VerifyAccessToken(context.Background(), token.Token)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unexpected signing method")
	})

	t.Run("Invalid UUID in Claims", func(t *testing.T) {
		config := DefaultGourdianTokenConfig("test-secret-32-bytes-long-1234567890")
		maker, err := NewGourdianTokenMaker(context.Background(), config, nil)
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
			"rls": []string{"role"},
		})

		tokenString, err := token.SignedString([]byte(config.SymmetricKey))
		require.NoError(t, err)

		_, err = maker.VerifyAccessToken(context.Background(), tokenString)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid token ID")
	})

	t.Run("Missing Required Claims", func(t *testing.T) {
		config := DefaultGourdianTokenConfig("test-secret-32-bytes-long-1234567890")
		maker, err := NewGourdianTokenMaker(context.Background(), config, nil)
		require.NoError(t, err)

		// Create token missing required claims
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"jti": uuid.New().String(),
			"sub": uuid.New().String(),
			// Missing "usr", "sid", "rls" claims
			"iat": time.Now().Unix(),
			"exp": time.Now().Add(time.Hour).Unix(),
			"typ": AccessToken,
		})

		tokenString, err := token.SignedString([]byte(config.SymmetricKey))
		require.NoError(t, err)

		_, err = maker.VerifyAccessToken(context.Background(), tokenString)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "missing required claim")
	})

	t.Run("Invalid Token Type", func(t *testing.T) {
		config := DefaultGourdianTokenConfig("test-secret-32-bytes-long-1234567890")
		maker, err := NewGourdianTokenMaker(context.Background(), config, nil)
		require.NoError(t, err)

		// Create token with wrong type
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"jti": uuid.New().String(),
			"sub": uuid.New().String(),
			"usr": "user",
			"sid": uuid.New().String(),
			"iat": time.Now().Unix(),
			"exp": time.Now().Add(time.Hour).Unix(),
			"typ": "invalid-type",
			"rls": []string{"role"},
		})

		tokenString, err := token.SignedString([]byte(config.SymmetricKey))
		require.NoError(t, err)

		_, err = maker.VerifyAccessToken(context.Background(), tokenString)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid token type")
	})

	t.Run("Empty Roles", func(t *testing.T) {
		config := DefaultGourdianTokenConfig("test-secret-32-bytes-long-1234567890")
		maker, err := NewGourdianTokenMaker(context.Background(), config, nil)
		require.NoError(t, err)

		// Create token with empty roles
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"jti": uuid.New().String(),
			"sub": uuid.New().String(),
			"usr": "user",
			"sid": uuid.New().String(),
			"iat": time.Now().Unix(),
			"exp": time.Now().Add(time.Hour).Unix(),
			"typ": AccessToken,
			"rls": []string{},
		})

		tokenString, err := token.SignedString([]byte(config.SymmetricKey))
		require.NoError(t, err)

		_, err = maker.VerifyAccessToken(context.Background(), tokenString)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "at least one role must be provided")
	})

	t.Run("Revoked Token", func(t *testing.T) {
		config := DefaultGourdianTokenConfig("test-secret-32-bytes-long-1234567890")
		config.AccessToken.RevocationEnabled = true
		maker, err := NewGourdianTokenMaker(context.Background(), config, &redis.Options{
			Addr: "localhost:6379",
		})
		if err != nil {
			t.Skip("Redis not available, skipping test")
		}

		token, err := maker.CreateAccessToken(
			context.Background(),
			uuid.New(),
			"user",
			[]string{"role"},
			uuid.New(),
		)
		require.NoError(t, err)

		// Verify token works initially
		_, err = maker.VerifyAccessToken(context.Background(), token.Token)
		require.NoError(t, err)

		// Revoke the token
		err = maker.RevokeAccessToken(context.Background(), token.Token)
		require.NoError(t, err)

		// Verify token is now revoked
		_, err = maker.VerifyAccessToken(context.Background(), token.Token)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "token has been revoked")
	})

	t.Run("Future Issued At", func(t *testing.T) {
		config := DefaultGourdianTokenConfig("test-secret-32-bytes-long-1234567890")
		maker, err := NewGourdianTokenMaker(context.Background(), config, nil)
		require.NoError(t, err)

		// Create token with iat in the future
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"jti": uuid.New().String(),
			"sub": uuid.New().String(),
			"usr": "user",
			"sid": uuid.New().String(),
			"iat": time.Now().Add(time.Hour).Unix(),
			"exp": time.Now().Add(2 * time.Hour).Unix(),
			"typ": AccessToken,
			"rls": []string{"role"},
		})

		tokenString, err := token.SignedString([]byte(config.SymmetricKey))
		require.NoError(t, err)

		_, err = maker.VerifyAccessToken(context.Background(), tokenString)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "token issued in the future")
	})
}
