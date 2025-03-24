package gourdiantoken

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestClaimsSerialization(t *testing.T) {
	t.Run("AccessTokenClaims", func(t *testing.T) {
		now := time.Now()
		claims := AccessTokenClaims{
			ID:        uuid.New(),
			Subject:   uuid.New(),
			Username:  "testuser",
			SessionID: uuid.New(),
			IssuedAt:  now,
			ExpiresAt: now.Add(time.Hour),
			TokenType: AccessToken,
			Role:      "admin",
		}

		// Test JSON serialization
		jsonData, err := json.Marshal(claims)
		assert.NoError(t, err)

		var decoded AccessTokenClaims
		err = json.Unmarshal(jsonData, &decoded)
		assert.NoError(t, err)
		assert.Equal(t, claims.ID, decoded.ID)
		assert.Equal(t, claims.Subject, decoded.Subject)
		assert.Equal(t, claims.Username, decoded.Username)
		assert.Equal(t, claims.SessionID, decoded.SessionID)
		assert.Equal(t, claims.IssuedAt.Unix(), decoded.IssuedAt.Unix())
		assert.Equal(t, claims.ExpiresAt.Unix(), decoded.ExpiresAt.Unix())
		assert.Equal(t, claims.TokenType, decoded.TokenType)
		assert.Equal(t, claims.Role, decoded.Role)

		// Test MapClaims conversion
		mapClaims := toMapClaims(claims)
		assert.Equal(t, claims.ID.String(), mapClaims["jti"])
		assert.Equal(t, claims.Subject.String(), mapClaims["sub"])
		assert.Equal(t, claims.Username, mapClaims["usr"])
		assert.Equal(t, claims.SessionID.String(), mapClaims["sid"])
		assert.Equal(t, claims.IssuedAt.Unix(), int64(mapClaims["iat"].(float64)))
		assert.Equal(t, claims.ExpiresAt.Unix(), int64(mapClaims["exp"].(float64)))
		assert.Equal(t, string(claims.TokenType), mapClaims["typ"])
		assert.Equal(t, claims.Role, mapClaims["rol"])
	})

	t.Run("RefreshTokenClaims", func(t *testing.T) {
		now := time.Now()
		claims := RefreshTokenClaims{
			ID:        uuid.New(),
			Subject:   uuid.New(),
			Username:  "testuser",
			SessionID: uuid.New(),
			IssuedAt:  now,
			ExpiresAt: now.Add(24 * time.Hour),
			TokenType: RefreshToken,
		}

		// Test JSON serialization
		jsonData, err := json.Marshal(claims)
		assert.NoError(t, err)

		var decoded RefreshTokenClaims
		err = json.Unmarshal(jsonData, &decoded)
		assert.NoError(t, err)
		assert.Equal(t, claims.ID, decoded.ID)
		assert.Equal(t, claims.Subject, decoded.Subject)
		assert.Equal(t, claims.Username, decoded.Username)
		assert.Equal(t, claims.SessionID, decoded.SessionID)
		assert.Equal(t, claims.IssuedAt.Unix(), decoded.IssuedAt.Unix())
		assert.Equal(t, claims.ExpiresAt.Unix(), decoded.ExpiresAt.Unix())
		assert.Equal(t, claims.TokenType, decoded.TokenType)

		// Test MapClaims conversion
		mapClaims := toMapClaims(claims)
		assert.Equal(t, claims.ID.String(), mapClaims["jti"])
		assert.Equal(t, claims.Subject.String(), mapClaims["sub"])
		assert.Equal(t, claims.Username, mapClaims["usr"])
		assert.Equal(t, claims.SessionID.String(), mapClaims["sid"])
		assert.Equal(t, claims.IssuedAt.Unix(), int64(mapClaims["iat"].(float64)))
		assert.Equal(t, claims.ExpiresAt.Unix(), int64(mapClaims["exp"].(float64)))
		assert.Equal(t, string(claims.TokenType), mapClaims["typ"])
	})
}
