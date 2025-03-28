package gourdiantoken

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
)

func TestClaimsSerialization(t *testing.T) {
	// Create a test Redis options for the maker
	redisOpts := &redis.Options{
		Addr: "localhost:6379", // Use a test Redis instance
	}

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
			Role:      "admin",
		}

		// Test JSON serialization
		jsonData, err := json.Marshal(claims)
		assert.NoError(t, err)

		var decoded AccessTokenClaims
		err = json.Unmarshal(jsonData, &decoded)
		assert.NoError(t, err)

		// Compare fields individually
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
		assert.Equal(t, claims.IssuedAt.Unix(), mapClaims["iat"])
		assert.Equal(t, claims.ExpiresAt.Unix(), mapClaims["exp"])
		assert.Equal(t, claims.TokenType, TokenType(mapClaims["typ"].(string)))
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
		assert.Equal(t, claims.IssuedAt.Unix(), mapClaims["iat"])
		assert.Equal(t, claims.ExpiresAt.Unix(), mapClaims["exp"])
		assert.Equal(t, claims.TokenType, TokenType(mapClaims["typ"].(string)))
	})

	t.Run("NewGourdianTokenMakerWithRedis", func(t *testing.T) {
		config := DefaultGourdianTokenConfig("test-secret-32-bytes-long-1234567890")
		maker, err := NewGourdianTokenMaker(config, redisOpts)
		assert.NoError(t, err)
		assert.NotNil(t, maker)
	})

	t.Run("NewGourdianTokenMakerWithoutRedis", func(t *testing.T) {
		config := DefaultGourdianTokenConfig("test-secret-32-bytes-long-1234567890")
		config.RefreshToken.RotationEnabled = false
		maker, err := NewGourdianTokenMaker(config, nil)
		assert.NoError(t, err)
		assert.NotNil(t, maker)
	})
}
