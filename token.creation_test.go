// File: token.creation_test.go


package gourdiantoken

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateAccessToken_Valid(t *testing.T) {
	maker := setupTestMaker(t)
	ctx := context.Background()

	userID := uuid.New()
	sessionID := uuid.New()
	username := "testuser"
	roles := []string{"admin", "user"}

	t.Run("creates valid access token", func(t *testing.T) {
		response, err := maker.CreateAccessToken(ctx, userID, username, roles, sessionID)

		require.NoError(t, err)
		require.NotNil(t, response)
		assert.NotEmpty(t, response.Token)
		assert.Equal(t, userID, response.Subject)
		assert.Equal(t, sessionID, response.SessionID)
		assert.Equal(t, username, response.Username)
		assert.Equal(t, roles, response.Roles)
		assert.Equal(t, "test.com", response.Issuer)
		assert.Equal(t, []string{"api.test.com"}, response.Audience)
		assert.Equal(t, AccessToken, response.TokenType)
	})

	t.Run("token has correct claims", func(t *testing.T) {
		response, err := maker.CreateAccessToken(ctx, userID, username, roles, sessionID)
		require.NoError(t, err)

		// Parse the token
		token, err := jwt.Parse(response.Token, func(token *jwt.Token) (interface{}, error) {
			return []byte(maker.config.SymmetricKey), nil
		})
		require.NoError(t, err)

		claims, ok := token.Claims.(jwt.MapClaims)
		require.True(t, ok)

		assert.Equal(t, userID.String(), claims["sub"])
		assert.Equal(t, sessionID.String(), claims["sid"])
		assert.Equal(t, username, claims["usr"])
		assert.Equal(t, "test.com", claims["iss"])
		assert.Equal(t, string(AccessToken), claims["typ"])

		// Check roles
		claimsRoles, ok := claims["rls"].([]interface{})
		require.True(t, ok)
		assert.Len(t, claimsRoles, 2)
	})

	t.Run("timestamps are correct", func(t *testing.T) {
		before := time.Now()
		response, err := maker.CreateAccessToken(ctx, userID, username, roles, sessionID)
		after := time.Now()

		require.NoError(t, err)
		assert.True(t, response.IssuedAt.After(before.Add(-time.Second)))
		assert.True(t, response.IssuedAt.Before(after.Add(time.Second)))
		assert.True(t, response.NotBefore.After(before.Add(-time.Second)))
		assert.Equal(t, response.IssuedAt.Add(30*time.Minute), response.ExpiresAt)
		assert.Equal(t, response.IssuedAt.Add(24*time.Hour), response.MaxLifetimeExpiry)
	})

	t.Run("multiple tokens have unique IDs", func(t *testing.T) {
		token1, err := maker.CreateAccessToken(ctx, userID, username, roles, sessionID)
		require.NoError(t, err)

		token2, err := maker.CreateAccessToken(ctx, userID, username, roles, sessionID)
		require.NoError(t, err)

		// Parse and compare token IDs
		jwt1, _ := jwt.Parse(token1.Token, func(token *jwt.Token) (interface{}, error) {
			return []byte(maker.config.SymmetricKey), nil
		})
		jwt2, _ := jwt.Parse(token2.Token, func(token *jwt.Token) (interface{}, error) {
			return []byte(maker.config.SymmetricKey), nil
		})

		claims1 := jwt1.Claims.(jwt.MapClaims)
		claims2 := jwt2.Claims.(jwt.MapClaims)

		assert.NotEqual(t, claims1["jti"], claims2["jti"])
	})
}

func TestCreateAccessToken_InvalidInput(t *testing.T) {
	maker := setupTestMaker(t)
	ctx := context.Background()

	userID := uuid.New()
	sessionID := uuid.New()
	username := "testuser"
	roles := []string{"admin"}

	t.Run("nil user ID", func(t *testing.T) {
		response, err := maker.CreateAccessToken(ctx, uuid.Nil, username, roles, sessionID)

		assert.Error(t, err)
		assert.Nil(t, response)
		assert.Contains(t, err.Error(), "invalid user ID")
	})

	t.Run("empty roles", func(t *testing.T) {
		response, err := maker.CreateAccessToken(ctx, userID, username, []string{}, sessionID)

		assert.Error(t, err)
		assert.Nil(t, response)
		assert.Contains(t, err.Error(), "at least one role must be provided")
	})

	t.Run("nil roles", func(t *testing.T) {
		response, err := maker.CreateAccessToken(ctx, userID, username, nil, sessionID)

		assert.Error(t, err)
		assert.Nil(t, response)
		assert.Contains(t, err.Error(), "at least one role must be provided")
	})

	t.Run("empty string in roles", func(t *testing.T) {
		response, err := maker.CreateAccessToken(ctx, userID, username, []string{"admin", ""}, sessionID)

		assert.Error(t, err)
		assert.Nil(t, response)
		assert.Contains(t, err.Error(), "roles cannot contain empty strings")
	})

	t.Run("username too long", func(t *testing.T) {
		longUsername := string(make([]byte, 1025))
		response, err := maker.CreateAccessToken(ctx, userID, longUsername, roles, sessionID)

		assert.Error(t, err)
		assert.Nil(t, response)
		assert.Contains(t, err.Error(), "username too long")
	})

	t.Run("canceled context", func(t *testing.T) {
		canceledCtx, cancel := context.WithCancel(context.Background())
		cancel()

		response, err := maker.CreateAccessToken(canceledCtx, userID, username, roles, sessionID)

		assert.Error(t, err)
		assert.Nil(t, response)
		assert.Contains(t, err.Error(), "context canceled")
	})

	t.Run("empty username is allowed", func(t *testing.T) {
		response, err := maker.CreateAccessToken(ctx, userID, "", roles, sessionID)

		assert.NoError(t, err)
		assert.NotNil(t, response)
		assert.Equal(t, "", response.Username)
	})

	t.Run("nil session ID is allowed", func(t *testing.T) {
		response, err := maker.CreateAccessToken(ctx, userID, username, roles, uuid.Nil)

		assert.NoError(t, err)
		assert.NotNil(t, response)
		assert.Equal(t, uuid.Nil, response.SessionID)
	})
}

func TestCreateRefreshToken_Valid(t *testing.T) {
	maker := setupTestMaker(t)
	ctx := context.Background()

	userID := uuid.New()
	sessionID := uuid.New()
	username := "testuser"

	t.Run("creates valid refresh token", func(t *testing.T) {
		response, err := maker.CreateRefreshToken(ctx, userID, username, sessionID)

		require.NoError(t, err)
		require.NotNil(t, response)
		assert.NotEmpty(t, response.Token)
		assert.Equal(t, userID, response.Subject)
		assert.Equal(t, sessionID, response.SessionID)
		assert.Equal(t, username, response.Username)
		assert.Equal(t, "test.com", response.Issuer)
		assert.Equal(t, []string{"api.test.com"}, response.Audience)
		assert.Equal(t, RefreshToken, response.TokenType)
	})

	t.Run("token has correct claims", func(t *testing.T) {
		response, err := maker.CreateRefreshToken(ctx, userID, username, sessionID)
		require.NoError(t, err)

		// Parse the token
		token, err := jwt.Parse(response.Token, func(token *jwt.Token) (interface{}, error) {
			return []byte(maker.config.SymmetricKey), nil
		})
		require.NoError(t, err)

		claims, ok := token.Claims.(jwt.MapClaims)
		require.True(t, ok)

		assert.Equal(t, userID.String(), claims["sub"])
		assert.Equal(t, sessionID.String(), claims["sid"])
		assert.Equal(t, username, claims["usr"])
		assert.Equal(t, "test.com", claims["iss"])
		assert.Equal(t, string(RefreshToken), claims["typ"])

		// Refresh token should NOT have roles
		_, hasRoles := claims["rls"]
		assert.False(t, hasRoles)
	})

	t.Run("timestamps are correct", func(t *testing.T) {
		before := time.Now()
		response, err := maker.CreateRefreshToken(ctx, userID, username, sessionID)
		after := time.Now()

		require.NoError(t, err)
		assert.True(t, response.IssuedAt.After(before.Add(-time.Second)))
		assert.True(t, response.IssuedAt.Before(after.Add(time.Second)))
		assert.Equal(t, response.IssuedAt.Add(7*24*time.Hour), response.ExpiresAt)
		assert.Equal(t, response.IssuedAt.Add(30*24*time.Hour), response.MaxLifetimeExpiry)
	})

	t.Run("multiple tokens have unique IDs", func(t *testing.T) {
		token1, err := maker.CreateRefreshToken(ctx, userID, username, sessionID)
		require.NoError(t, err)

		token2, err := maker.CreateRefreshToken(ctx, userID, username, sessionID)
		require.NoError(t, err)

		assert.NotEqual(t, token1.Token, token2.Token)
	})
}

func TestCreateRefreshToken_InvalidInput(t *testing.T) {
	maker := setupTestMaker(t)
	ctx := context.Background()

	userID := uuid.New()
	sessionID := uuid.New()
	username := "testuser"

	t.Run("nil user ID", func(t *testing.T) {
		response, err := maker.CreateRefreshToken(ctx, uuid.Nil, username, sessionID)

		assert.Error(t, err)
		assert.Nil(t, response)
		assert.Contains(t, err.Error(), "invalid user ID")
	})

	t.Run("username too long", func(t *testing.T) {
		longUsername := string(make([]byte, 1025))
		response, err := maker.CreateRefreshToken(ctx, userID, longUsername, sessionID)

		assert.Error(t, err)
		assert.Nil(t, response)
		assert.Contains(t, err.Error(), "username too long")
	})

	t.Run("canceled context", func(t *testing.T) {
		canceledCtx, cancel := context.WithCancel(context.Background())
		cancel()

		response, err := maker.CreateRefreshToken(canceledCtx, userID, username, sessionID)

		assert.Error(t, err)
		assert.Nil(t, response)
		assert.Contains(t, err.Error(), "context canceled")
	})

	t.Run("empty username is allowed", func(t *testing.T) {
		response, err := maker.CreateRefreshToken(ctx, userID, "", sessionID)

		assert.NoError(t, err)
		assert.NotNil(t, response)
		assert.Equal(t, "", response.Username)
	})
}

func TestTokenClaims_Mapping(t *testing.T) {
	t.Run("access token claims to map claims", func(t *testing.T) {
		now := time.Now()
		userID := uuid.New()
		sessionID := uuid.New()
		tokenID := uuid.New()

		claims := AccessTokenClaims{
			ID:                tokenID,
			Subject:           userID,
			SessionID:         sessionID,
			Username:          "testuser",
			Issuer:            "test.com",
			Audience:          []string{"api.test.com"},
			Roles:             []string{"admin", "user"},
			IssuedAt:          now,
			ExpiresAt:         now.Add(30 * time.Minute),
			NotBefore:         now,
			MaxLifetimeExpiry: now.Add(24 * time.Hour),
			TokenType:         AccessToken,
		}

		mapClaims := toMapClaims(claims)

		assert.Equal(t, tokenID.String(), mapClaims["jti"])
		assert.Equal(t, userID.String(), mapClaims["sub"])
		assert.Equal(t, sessionID.String(), mapClaims["sid"])
		assert.Equal(t, "testuser", mapClaims["usr"])
		assert.Equal(t, "test.com", mapClaims["iss"])
		assert.Equal(t, []string{"api.test.com"}, mapClaims["aud"])
		assert.Equal(t, string(AccessToken), mapClaims["typ"])

		roles, ok := mapClaims["rls"].([]string)
		require.True(t, ok)
		assert.Equal(t, []string{"admin", "user"}, roles)
	})

	t.Run("refresh token claims to map claims", func(t *testing.T) {
		now := time.Now()
		userID := uuid.New()
		sessionID := uuid.New()
		tokenID := uuid.New()

		claims := RefreshTokenClaims{
			ID:                tokenID,
			Subject:           userID,
			SessionID:         sessionID,
			Username:          "testuser",
			Issuer:            "test.com",
			Audience:          []string{"api.test.com"},
			IssuedAt:          now,
			ExpiresAt:         now.Add(7 * 24 * time.Hour),
			NotBefore:         now,
			MaxLifetimeExpiry: now.Add(30 * 24 * time.Hour),
			TokenType:         RefreshToken,
		}

		mapClaims := toMapClaims(claims)

		assert.Equal(t, tokenID.String(), mapClaims["jti"])
		assert.Equal(t, userID.String(), mapClaims["sub"])
		assert.Equal(t, sessionID.String(), mapClaims["sid"])
		assert.Equal(t, "testuser", mapClaims["usr"])
		assert.Equal(t, string(RefreshToken), mapClaims["typ"])

		// Refresh token should NOT have roles
		_, hasRoles := mapClaims["rls"]
		assert.False(t, hasRoles)
	})

	t.Run("map claims to access token claims", func(t *testing.T) {
		now := time.Now()
		userID := uuid.New()
		sessionID := uuid.New()
		tokenID := uuid.New()

		mapClaims := jwt.MapClaims{
			"jti": tokenID.String(),
			"sub": userID.String(),
			"sid": sessionID.String(),
			"usr": "testuser",
			"iss": "test.com",
			"aud": []string{"api.test.com"},
			"rls": []interface{}{"admin", "user"},
			"iat": float64(now.Unix()),
			"exp": float64(now.Add(30 * time.Minute).Unix()),
			"nbf": float64(now.Unix()),
			"mle": float64(now.Add(24 * time.Hour).Unix()),
			"typ": string(AccessToken),
		}

		accessClaims, err := mapToAccessClaims(mapClaims)

		require.NoError(t, err)
		assert.Equal(t, tokenID, accessClaims.ID)
		assert.Equal(t, userID, accessClaims.Subject)
		assert.Equal(t, sessionID, accessClaims.SessionID)
		assert.Equal(t, "testuser", accessClaims.Username)
		assert.Equal(t, "test.com", accessClaims.Issuer)
		assert.Equal(t, []string{"api.test.com"}, accessClaims.Audience)
		assert.Equal(t, []string{"admin", "user"}, accessClaims.Roles)
		assert.Equal(t, AccessToken, accessClaims.TokenType)
	})

	t.Run("map claims to refresh token claims", func(t *testing.T) {
		now := time.Now()
		userID := uuid.New()
		sessionID := uuid.New()
		tokenID := uuid.New()

		mapClaims := jwt.MapClaims{
			"jti": tokenID.String(),
			"sub": userID.String(),
			"sid": sessionID.String(),
			"usr": "testuser",
			"iss": "test.com",
			"aud": []string{"api.test.com"},
			"iat": float64(now.Unix()),
			"exp": float64(now.Add(7 * 24 * time.Hour).Unix()),
			"nbf": float64(now.Unix()),
			"mle": float64(now.Add(30 * 24 * time.Hour).Unix()),
			"typ": string(RefreshToken),
		}

		refreshClaims, err := mapToRefreshClaims(mapClaims)

		require.NoError(t, err)
		assert.Equal(t, tokenID, refreshClaims.ID)
		assert.Equal(t, userID, refreshClaims.Subject)
		assert.Equal(t, sessionID, refreshClaims.SessionID)
		assert.Equal(t, "testuser", refreshClaims.Username)
		assert.Equal(t, RefreshToken, refreshClaims.TokenType)
	})

	t.Run("invalid UUID in map claims", func(t *testing.T) {
		mapClaims := jwt.MapClaims{
			"jti": "invalid-uuid",
			"sub": uuid.New().String(),
			"sid": uuid.New().String(),
			"usr": "testuser",
			"rls": []interface{}{"admin"},
			"iat": float64(time.Now().Unix()),
			"exp": float64(time.Now().Add(30 * time.Minute).Unix()),
			"typ": string(AccessToken),
		}

		_, err := mapToAccessClaims(mapClaims)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid token ID")
	})

	t.Run("missing required claim", func(t *testing.T) {
		mapClaims := jwt.MapClaims{
			"sub": uuid.New().String(),
			"sid": uuid.New().String(),
			"usr": "testuser",
			"rls": []interface{}{"admin"},
			"iat": float64(time.Now().Unix()),
			"exp": float64(time.Now().Add(30 * time.Minute).Unix()),
			"typ": string(AccessToken),
		}

		_, err := mapToAccessClaims(mapClaims)
		assert.Error(t, err)
	})

	t.Run("empty roles in access token", func(t *testing.T) {
		mapClaims := jwt.MapClaims{
			"jti": uuid.New().String(),
			"sub": uuid.New().String(),
			"sid": uuid.New().String(),
			"usr": "testuser",
			"rls": []interface{}{},
			"iat": float64(time.Now().Unix()),
			"exp": float64(time.Now().Add(30 * time.Minute).Unix()),
			"typ": string(AccessToken),
		}

		_, err := mapToAccessClaims(mapClaims)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "at least one role must be provided")
	})

	t.Run("wrong token type in refresh claims", func(t *testing.T) {
		mapClaims := jwt.MapClaims{
			"jti": uuid.New().String(),
			"sub": uuid.New().String(),
			"sid": uuid.New().String(),
			"usr": "testuser",
			"iat": float64(time.Now().Unix()),
			"exp": float64(time.Now().Add(7 * 24 * time.Hour).Unix()),
			"typ": string(AccessToken),
		}

		_, err := mapToRefreshClaims(mapClaims)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "expected 'refresh'")
	})
}

func TestCreateRefreshToken_ContextCancellation(t *testing.T) {
	maker := setupTestMaker(t)

	userID := uuid.New()
	sessionID := uuid.New()
	username := "testuser"

	t.Run("returns error when context is canceled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		response, err := maker.CreateRefreshToken(ctx, userID, username, sessionID)
		assert.Error(t, err)
		assert.Nil(t, response)
		assert.Contains(t, err.Error(), "context canceled")
	})

	t.Run("succeeds with valid context", func(t *testing.T) {
		response, err := maker.CreateRefreshToken(context.Background(), userID, username, sessionID)
		assert.NoError(t, err)
		assert.NotNil(t, response)
		assert.Equal(t, userID, response.Subject)
		assert.Equal(t, username, response.Username)
	})
}
