// gourdiantoken_error_test.go

package gourdiantoken

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"os"
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

	t.Run("Malformed Redis URL", func(t *testing.T) {
		config := DefaultGourdianTokenConfig("test-secret-32-bytes-long-1234567890")
		config.AccessToken.RevocationEnabled = true
		_, err := NewGourdianTokenMaker(context.Background(), config, &redis.Options{
			Addr: "invalid-redis-url",
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "redis connection failed")
	})

	t.Run("Rotation Reuse Too Soon", func(t *testing.T) {
		config := DefaultGourdianTokenConfig("test-secret-32-bytes-long-1234567890")
		config.RefreshToken.RotationEnabled = true
		maker, err := NewGourdianTokenMaker(context.Background(), config, &redis.Options{
			Addr: "localhost:6379",
		})
		if err != nil {
			t.Skip("Redis not available, skipping test")
		}

		refreshToken, err := maker.CreateRefreshToken(
			context.Background(),
			uuid.New(),
			"user",
			uuid.New(),
		)
		require.NoError(t, err)

		_, err = maker.RotateRefreshToken(context.Background(), refreshToken.Token)
		require.NoError(t, err)

		_, err = maker.RotateRefreshToken(context.Background(), refreshToken.Token)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "token reused too soon")
	})

	t.Run("Invalid Signing Method Config", func(t *testing.T) {
		config := DefaultGourdianTokenConfig("test-secret-32-bytes-long-1234567890")
		config.Algorithm = "none" // Disallowed
		_, err := NewGourdianTokenMaker(context.Background(), config, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unsecured tokens are disabled")
	})

	t.Run("Missing Role Claim in Access Token", func(t *testing.T) {
		config := DefaultGourdianTokenConfig("test-secret-32-bytes-long-1234567890")
		maker, err := NewGourdianTokenMaker(context.Background(), config, nil)
		require.NoError(t, err)

		// Role claim omitted
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"jti": uuid.New().String(),
			"sub": uuid.New().String(),
			"usr": "user",
			"sid": uuid.New().String(),
			"iat": time.Now().Unix(),
			"exp": time.Now().Add(time.Hour).Unix(),
			"typ": AccessToken,
		})

		tokenString, err := token.SignedString([]byte(config.SymmetricKey))
		require.NoError(t, err)

		_, err = maker.VerifyAccessToken(context.Background(), tokenString)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "missing roles claim")
	})

	t.Run("Unsupported Signing Algorithm", func(t *testing.T) {
		config := DefaultGourdianTokenConfig("test-secret-32-bytes-long-1234567890")
		config.Algorithm = "XYZ999"
		_, err := NewGourdianTokenMaker(context.Background(), config, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported algorithm")
	})

	t.Run("Invalid Private Key File Path", func(t *testing.T) {
		config := DefaultGourdianTokenConfig("")
		config.Algorithm = "RS256"
		config.SigningMethod = Asymmetric
		config.PrivateKeyPath = "nonexistent-private.pem"
		config.PublicKeyPath = "nonexistent-public.pem"

		_, err := NewGourdianTokenMaker(context.Background(), config, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to read private key file")
	})

	t.Run("Invalid Public Key Format", func(t *testing.T) {
		// Create temp private and public key files
		privPath := "test_invalid_priv.pem"
		pubPath := "test_invalid_pub.pem"
		_ = os.WriteFile(privPath, []byte("invalid private pem"), 0644)
		_ = os.WriteFile(pubPath, []byte("invalid public pem"), 0644)
		defer os.Remove(privPath)
		defer os.Remove(pubPath)

		config := DefaultGourdianTokenConfig("")
		config.Algorithm = "RS256"
		config.SigningMethod = Asymmetric
		config.PrivateKeyPath = privPath
		config.PublicKeyPath = pubPath

		_, err := NewGourdianTokenMaker(context.Background(), config, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to parse RSA private key")
	})

	t.Run("Revoke Token Without Exp Claim", func(t *testing.T) {
		config := DefaultGourdianTokenConfig("test-secret-32-bytes-long-1234567890")
		config.AccessToken.RevocationEnabled = true
		maker, err := NewGourdianTokenMaker(context.Background(), config, &redis.Options{
			Addr: "localhost:6379",
		})
		if err != nil {
			t.Skip("Redis not available")
		}

		// Create malformed token (no exp)
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"jti": uuid.New().String(),
			"sub": uuid.New().String(),
			"usr": "user",
			"sid": uuid.New().String(),
			"iat": time.Now().Unix(),
			"typ": AccessToken,
			"rls": []string{"admin"},
		})
		tokenString, _ := token.SignedString([]byte(config.SymmetricKey))

		err = maker.RevokeAccessToken(context.Background(), tokenString)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "token missing exp claim")
	})

	t.Run("Revoke Token With Invalid Format", func(t *testing.T) {
		config := DefaultGourdianTokenConfig("test-secret-32-bytes-long-1234567890")
		config.AccessToken.RevocationEnabled = true
		maker, err := NewGourdianTokenMaker(context.Background(), config, &redis.Options{
			Addr: "localhost:6379",
		})
		if err != nil {
			t.Skip("Redis not available")
		}

		err = maker.RevokeAccessToken(context.Background(), "not.a.valid.token")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid token")
	})

	t.Run("Rotate With Invalid Refresh Token", func(t *testing.T) {
		config := DefaultGourdianTokenConfig("test-secret-32-bytes-long-1234567890")
		config.RefreshToken.RotationEnabled = true
		maker, err := NewGourdianTokenMaker(context.Background(), config, &redis.Options{
			Addr: "localhost:6379",
		})
		if err != nil {
			t.Skip("Redis not available")
		}

		_, err = maker.RotateRefreshToken(context.Background(), "invalid.token.string")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid token")
	})

	t.Run("Rotation Without Redis Client", func(t *testing.T) {
		config := DefaultGourdianTokenConfig("test-secret-32-bytes-long-1234567890")
		config.RefreshToken.RotationEnabled = true

		_, err := NewGourdianTokenMaker(context.Background(), config, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "redis options required")
	})

}
