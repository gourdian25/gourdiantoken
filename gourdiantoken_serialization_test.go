// gourdiantoken_serialization_test.go

package gourdiantoken

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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

		// Test JSON serialization with empty roles
		t.Run("JSONSerializationEmptyRoles", func(t *testing.T) {
			emptyRolesClaims := claims
			emptyRolesClaims.Roles = []string{}
			assert.Panics(t, func() {
				toMapClaims(emptyRolesClaims)
			}, "should panic with empty roles")
		})

		// Test JSON serialization with nil roles
		t.Run("JSONSerializationNilRoles", func(t *testing.T) {
			nilRolesClaims := claims
			nilRolesClaims.Roles = nil
			assert.Panics(t, func() {
				toMapClaims(nilRolesClaims)
			}, "should panic with nil roles")
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
			require.NoError(t, err)

			assert.Equal(t, claims.ID, decodedClaims.ID)
			assert.Equal(t, claims.Subject, decodedClaims.Subject)
			assert.Equal(t, claims.Username, decodedClaims.Username)
			assert.Equal(t, claims.SessionID, decodedClaims.SessionID)
			assert.Equal(t, claims.IssuedAt.Unix(), decodedClaims.IssuedAt.Unix())
			assert.Equal(t, claims.ExpiresAt.Unix(), decodedClaims.ExpiresAt.Unix())
			assert.Equal(t, claims.TokenType, decodedClaims.TokenType)
			assert.Equal(t, claims.Roles, decodedClaims.Roles)
		})

		// Test invalid UUID in MapClaims
		t.Run("MapToAccessClaimsInvalidUUID", func(t *testing.T) {
			mapClaims := toMapClaims(claims)
			mapClaims["jti"] = "invalid-uuid"
			_, err := mapToAccessClaims(mapClaims)
			assert.Error(t, err)
		})

		// Test missing required claim
		t.Run("MapToAccessClaimsMissingClaim", func(t *testing.T) {
			mapClaims := toMapClaims(claims)
			delete(mapClaims, "sub")
			_, err := mapToAccessClaims(mapClaims)
			assert.Error(t, err)
		})

		// Test invalid type in claim
		t.Run("MapToAccessClaimsInvalidType", func(t *testing.T) {
			mapClaims := toMapClaims(claims)
			mapClaims["usr"] = 12345 // should be string
			_, err := mapToAccessClaims(mapClaims)
			assert.Error(t, err)
		})

		// Test invalid roles type
		t.Run("MapToAccessClaimsInvalidRolesType", func(t *testing.T) {
			mapClaims := toMapClaims(claims)
			mapClaims["rls"] = "not-an-array"
			_, err := mapToAccessClaims(mapClaims)
			assert.Error(t, err)
		})

		// Test empty roles array
		t.Run("MapToAccessClaimsEmptyRoles", func(t *testing.T) {
			mapClaims := toMapClaims(claims)
			mapClaims["rls"] = []string{}
			_, err := mapToAccessClaims(mapClaims)
			assert.Error(t, err)
		})

		// Test invalid timestamp format
		t.Run("MapToAccessClaimsInvalidTimestamp", func(t *testing.T) {
			mapClaims := toMapClaims(claims)
			mapClaims["iat"] = "not-a-timestamp"
			_, err := mapToAccessClaims(mapClaims)
			assert.Error(t, err)
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

		// Test JSON serialization with empty username
		t.Run("JSONSerializationEmptyUsername", func(t *testing.T) {
			emptyUserClaims := claims
			emptyUserClaims.Username = ""
			_, err := json.Marshal(emptyUserClaims)
			assert.NoError(t, err, "empty username should be allowed")
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

		// Test invalid UUID in MapClaims
		t.Run("MapToRefreshClaimsInvalidUUID", func(t *testing.T) {
			mapClaims := toMapClaims(claims)
			mapClaims["sid"] = "invalid-uuid"
			_, err := mapToRefreshClaims(mapClaims)
			assert.Error(t, err)
		})

		// Test missing required claim
		t.Run("MapToRefreshClaimsMissingClaim", func(t *testing.T) {
			mapClaims := toMapClaims(claims)
			delete(mapClaims, "typ")
			_, err := mapToRefreshClaims(mapClaims)
			assert.Error(t, err)
		})

		// Test invalid token type
		t.Run("MapToRefreshClaimsInvalidTokenType", func(t *testing.T) {
			mapClaims := toMapClaims(claims)
			mapClaims["typ"] = "invalid-type"
			_, err := mapToRefreshClaims(mapClaims)
			assert.Error(t, err)
		})

		// Test invalid timestamp format
		t.Run("MapToRefreshClaimsInvalidTimestamp", func(t *testing.T) {
			mapClaims := toMapClaims(claims)
			mapClaims["exp"] = "not-a-timestamp"
			_, err := mapToRefreshClaims(mapClaims)
			assert.Error(t, err)
		})
	})

	t.Run("ResponseTypes", func(t *testing.T) {
		now := time.Now().UTC()
		userID := uuid.New()
		sessionID := uuid.New()

		t.Run("AccessTokenResponse", func(t *testing.T) {
			resp := AccessTokenResponse{
				Token:     "test-token",
				Subject:   userID,
				Username:  "testuser",
				SessionID: sessionID,
				ExpiresAt: now.Add(time.Hour),
				IssuedAt:  now,
				Roles:     []string{"admin", "user"},
			}

			// Test JSON serialization
			jsonData, err := json.Marshal(resp)
			require.NoError(t, err)

			var decoded AccessTokenResponse
			err = json.Unmarshal(jsonData, &decoded)
			require.NoError(t, err)

			assert.Equal(t, resp.Token, decoded.Token)
			assert.Equal(t, resp.Subject, decoded.Subject)
			assert.Equal(t, resp.Username, decoded.Username)
			assert.Equal(t, resp.SessionID, decoded.SessionID)
			assert.Equal(t, resp.ExpiresAt.Unix(), decoded.ExpiresAt.Unix())
			assert.Equal(t, resp.IssuedAt.Unix(), decoded.IssuedAt.Unix())
			assert.Equal(t, resp.Roles, decoded.Roles)
		})

		t.Run("RefreshTokenResponse", func(t *testing.T) {
			resp := RefreshTokenResponse{
				Token:     "test-token",
				Subject:   userID,
				Username:  "testuser",
				SessionID: sessionID,
				ExpiresAt: now.Add(24 * time.Hour),
				IssuedAt:  now,
			}

			// Test JSON serialization
			jsonData, err := json.Marshal(resp)
			require.NoError(t, err)

			var decoded RefreshTokenResponse
			err = json.Unmarshal(jsonData, &decoded)
			require.NoError(t, err)

			assert.Equal(t, resp.Token, decoded.Token)
			assert.Equal(t, resp.Subject, decoded.Subject)
			assert.Equal(t, resp.Username, decoded.Username)
			assert.Equal(t, resp.SessionID, decoded.SessionID)
			assert.Equal(t, resp.ExpiresAt.Unix(), decoded.ExpiresAt.Unix())
			assert.Equal(t, resp.IssuedAt.Unix(), decoded.IssuedAt.Unix())
		})
	})

	t.Run("EdgeCases", func(t *testing.T) {
		t.Run("NilUUID", func(t *testing.T) {
			claims := AccessTokenClaims{
				ID:        uuid.Nil,
				Subject:   uuid.Nil,
				SessionID: uuid.Nil,
			}

			// Should fail validation when converting to map claims
			assert.Panics(t, func() {
				toMapClaims(claims)
			})
		})

		t.Run("LongUsername", func(t *testing.T) {
			longUsername := make([]rune, 1025)
			for i := range longUsername {
				longUsername[i] = 'a'
			}

			claims := AccessTokenClaims{
				Username: string(longUsername),
			}

			// Should fail validation when converting to map claims
			assert.Panics(t, func() {
				toMapClaims(claims)
			})
		})

		t.Run("InvalidTokenType", func(t *testing.T) {
			claims := AccessTokenClaims{
				TokenType: "invalid-type",
			}

			// Should fail validation when converting to map claims
			assert.Panics(t, func() {
				toMapClaims(claims)
			})
		})
	})
}
