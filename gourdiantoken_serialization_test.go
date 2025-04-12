// gourdiantoken_serialization_test.go

package gourdiantoken

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

// Test Cases
func TestTokenClaimsSerialization(t *testing.T) {
	t.Run("AccessTokenClaims", func(t *testing.T) {
		now := time.Now().UTC()
		claims := AccessTokenClaims{
			ID:        uuid.New(),
			Subject:   uuid.New(),
			Username:  "testuser",
			SessionID: uuid.New(),
			IssuedAt:  now,
			ExpiresAt: now.Add(time.Hour),
			TokenType: AccessToken,
			Roles:     []string{"admin", "user"},
		}

		// Test JSON serialization
		t.Run("JSONSerialization", func(t *testing.T) {
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
			assert.Equal(t, claims.Roles, decoded.Roles)
		})

		// Test MapClaims conversion
		t.Run("MapClaimsConversion", func(t *testing.T) {
			mapClaims := toMapClaims(claims)
			assert.Equal(t, claims.ID.String(), mapClaims["jti"])
			assert.Equal(t, claims.Subject.String(), mapClaims["sub"])
			assert.Equal(t, claims.Username, mapClaims["usr"])
			assert.Equal(t, claims.SessionID.String(), mapClaims["sid"])
			assert.Equal(t, claims.IssuedAt.Unix(), mapClaims["iat"])
			assert.Equal(t, claims.ExpiresAt.Unix(), mapClaims["exp"])
			assert.Equal(t, string(claims.TokenType), mapClaims["typ"])
			assert.Equal(t, claims.Roles, mapClaims["rls"])
		})

		// Test claim mapping back from MapClaims
		t.Run("MapToAccessClaims", func(t *testing.T) {
			mapClaims := toMapClaims(claims)
			decodedClaims, err := mapToAccessClaims(mapClaims)
			assert.NoError(t, err)

			assert.Equal(t, claims.ID, decodedClaims.ID)
			assert.Equal(t, claims.Subject, decodedClaims.Subject)
			assert.Equal(t, claims.Username, decodedClaims.Username)
			assert.Equal(t, claims.SessionID, decodedClaims.SessionID)
			assert.Equal(t, claims.IssuedAt.Unix(), decodedClaims.IssuedAt.Unix())
			assert.Equal(t, claims.ExpiresAt.Unix(), decodedClaims.ExpiresAt.Unix())
			assert.Equal(t, claims.TokenType, decodedClaims.TokenType)
			assert.Equal(t, claims.Roles, decodedClaims.Roles)
		})
	})

	t.Run("RefreshTokenClaims", func(t *testing.T) {
		now := time.Now().UTC()
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
		t.Run("JSONSerialization", func(t *testing.T) {
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
		})

		// Test MapClaims conversion
		t.Run("MapClaimsConversion", func(t *testing.T) {
			mapClaims := toMapClaims(claims)
			assert.Equal(t, claims.ID.String(), mapClaims["jti"])
			assert.Equal(t, claims.Subject.String(), mapClaims["sub"])
			assert.Equal(t, claims.Username, mapClaims["usr"])
			assert.Equal(t, claims.SessionID.String(), mapClaims["sid"])
			assert.Equal(t, claims.IssuedAt.Unix(), mapClaims["iat"])
			assert.Equal(t, claims.ExpiresAt.Unix(), mapClaims["exp"])
			assert.Equal(t, string(claims.TokenType), mapClaims["typ"])
		})

		// Test claim mapping back from MapClaims
		t.Run("MapToRefreshClaims", func(t *testing.T) {
			mapClaims := toMapClaims(claims)
			decodedClaims, err := mapToRefreshClaims(mapClaims)
			assert.NoError(t, err)

			assert.Equal(t, claims.ID, decodedClaims.ID)
			assert.Equal(t, claims.Subject, decodedClaims.Subject)
			assert.Equal(t, claims.Username, decodedClaims.Username)
			assert.Equal(t, claims.SessionID, decodedClaims.SessionID)
			assert.Equal(t, claims.IssuedAt.Unix(), decodedClaims.IssuedAt.Unix())
			assert.Equal(t, claims.ExpiresAt.Unix(), decodedClaims.ExpiresAt.Unix())
			assert.Equal(t, claims.TokenType, decodedClaims.TokenType)
		})
	})
}
