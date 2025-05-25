package gourdiantoken

// import (
// 	"testing"
// 	"time"

// 	"github.com/golang-jwt/jwt/v5"
// 	"github.com/google/uuid"
// 	"github.com/stretchr/testify/require"
// )

// func TestClaimsValidation(t *testing.T) {
// 	now := time.Now()
// 	validAccessClaims := jwt.MapClaims{
// 		"jti": uuid.New().String(),
// 		"sub": uuid.New().String(),
// 		"usr": "testuser",
// 		"sid": uuid.New().String(),
// 		"iss": "test-issuer",
// 		"aud": []string{"aud1", "aud2"},
// 		"rls": []string{"admin", "user"},
// 		"iat": now.Unix(),
// 		"exp": now.Add(time.Hour).Unix(),
// 		"nbf": now.Unix(),
// 		"mle": now.Add(24 * time.Hour).Unix(),
// 		"typ": string(AccessToken),
// 	}

// 	validRefreshClaims := jwt.MapClaims{
// 		"jti": uuid.New().String(),
// 		"sub": uuid.New().String(),
// 		"usr": "testuser",
// 		"sid": uuid.New().String(),
// 		"iss": "test-issuer",
// 		"aud": []string{"aud1", "aud2"},
// 		"iat": now.Unix(),
// 		"exp": now.Add(24 * time.Hour).Unix(),
// 		"nbf": now.Unix(),
// 		"mle": now.Add(7 * 24 * time.Hour).Unix(),
// 		"typ": string(RefreshToken),
// 	}

// 	t.Run("Valid access token claims", func(t *testing.T) {
// 		err := validateTokenClaims(validAccessClaims, AccessToken, []string{"iss", "aud", "nbf", "mle"})
// 		require.NoError(t, err)
// 	})

// 	t.Run("Valid refresh token claims", func(t *testing.T) {
// 		err := validateTokenClaims(validRefreshClaims, RefreshToken, []string{"iss", "aud", "nbf", "mle"})
// 		require.NoError(t, err)
// 	})

// 	t.Run("Missing required claim", func(t *testing.T) {
// 		claims := jwt.MapClaims{}
// 		for k, v := range validAccessClaims {
// 			claims[k] = v
// 		}
// 		delete(claims, "sub") // Remove required claim
// 		err := validateTokenClaims(claims, AccessToken, []string{"iss", "aud", "nbf", "mle"})
// 		require.Error(t, err)
// 		require.Contains(t, err.Error(), "missing required claim")
// 	})

// 	t.Run("Invalid token type", func(t *testing.T) {
// 		claims := jwt.MapClaims{}
// 		for k, v := range validAccessClaims {
// 			claims[k] = v
// 		}
// 		claims["typ"] = "invalid-type"
// 		err := validateTokenClaims(claims, AccessToken, []string{"iss", "aud", "nbf", "mle"})
// 		require.Error(t, err)
// 		require.Contains(t, err.Error(), "invalid token type")
// 	})

// 	t.Run("Expired token", func(t *testing.T) {
// 		claims := jwt.MapClaims{}
// 		for k, v := range validAccessClaims {
// 			claims[k] = v
// 		}
// 		claims["exp"] = now.Add(-time.Hour).Unix() // Expired
// 		err := validateTokenClaims(claims, AccessToken, []string{"iss", "aud", "nbf", "mle"})
// 		require.Error(t, err)
// 		require.Contains(t, err.Error(), "expired")
// 	})

// 	t.Run("Token from future", func(t *testing.T) {
// 		claims := jwt.MapClaims{}
// 		for k, v := range validAccessClaims {
// 			claims[k] = v
// 		}
// 		claims["iat"] = now.Add(time.Hour).Unix() // Future
// 		err := validateTokenClaims(claims, AccessToken, []string{"iss", "aud", "nbf", "mle"})
// 		require.Error(t, err)
// 		require.Contains(t, err.Error(), "future")
// 	})

// 	t.Run("Max lifetime exceeded", func(t *testing.T) {
// 		claims := jwt.MapClaims{}
// 		for k, v := range validAccessClaims {
// 			claims[k] = v
// 		}
// 		claims["mle"] = now.Add(-time.Hour).Unix() // Past
// 		err := validateTokenClaims(claims, AccessToken, []string{"iss", "aud", "nbf", "mle"})
// 		require.Error(t, err)
// 		require.Contains(t, err.Error(), "exceeded maximum lifetime")
// 	})

// 	t.Run("Invalid roles claim", func(t *testing.T) {
// 		claims := jwt.MapClaims{}
// 		for k, v := range validAccessClaims {
// 			claims[k] = v
// 		}
// 		claims["rls"] = "not-an-array" // Invalid type
// 		err := validateTokenClaims(claims, AccessToken, []string{"iss", "aud", "nbf", "mle"})
// 		require.Error(t, err)
// 		require.Contains(t, err.Error(), "invalid roles type")
// 	})
// }
