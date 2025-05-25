package gourdiantoken

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestResponseTypes(t *testing.T) {
	now := time.Now()
	userID := uuid.New()
	sessionID := uuid.New()

	t.Run("AccessTokenResponse JSON", func(t *testing.T) {
		resp := AccessTokenResponse{
			Token:             "test-token",
			Subject:           userID,
			SessionID:         sessionID,
			Issuer:            "test-issuer",
			Username:          "testuser",
			Roles:             []string{"admin", "user"},
			Audience:          []string{"aud1", "aud2"},
			IssuedAt:          now,
			ExpiresAt:         now.Add(time.Hour),
			NotBefore:         now,
			MaxLifetimeExpiry: now.Add(24 * time.Hour),
			TokenType:         AccessToken,
		}

		// Test JSON marshaling
		jsonData, err := json.Marshal(resp)
		require.NoError(t, err)

		var decoded AccessTokenResponse
		err = json.Unmarshal(jsonData, &decoded)
		require.NoError(t, err)

		require.Equal(t, resp.Token, decoded.Token)
		require.Equal(t, resp.Subject, decoded.Subject)
		require.Equal(t, resp.SessionID, decoded.SessionID)
		require.Equal(t, resp.Issuer, decoded.Issuer)
		require.Equal(t, resp.Username, decoded.Username)
		require.Equal(t, resp.Roles, decoded.Roles)
		require.Equal(t, resp.Audience, decoded.Audience)
		require.Equal(t, resp.IssuedAt.Unix(), decoded.IssuedAt.Unix())
		require.Equal(t, resp.ExpiresAt.Unix(), decoded.ExpiresAt.Unix())
		require.Equal(t, resp.NotBefore.Unix(), decoded.NotBefore.Unix())
		require.Equal(t, resp.MaxLifetimeExpiry.Unix(), decoded.MaxLifetimeExpiry.Unix())
		require.Equal(t, resp.TokenType, decoded.TokenType)
	})

	t.Run("RefreshTokenResponse JSON", func(t *testing.T) {
		resp := RefreshTokenResponse{
			Token:             "test-token",
			Subject:           userID,
			SessionID:         sessionID,
			Issuer:            "test-issuer",
			Username:          "testuser",
			Audience:          []string{"aud1", "aud2"},
			IssuedAt:          now,
			ExpiresAt:         now.Add(24 * time.Hour),
			NotBefore:         now,
			MaxLifetimeExpiry: now.Add(7 * 24 * time.Hour),
			TokenType:         RefreshToken,
		}

		// Test JSON marshaling
		jsonData, err := json.Marshal(resp)
		require.NoError(t, err)

		var decoded RefreshTokenResponse
		err = json.Unmarshal(jsonData, &decoded)
		require.NoError(t, err)

		require.Equal(t, resp.Token, decoded.Token)
		require.Equal(t, resp.Subject, decoded.Subject)
		require.Equal(t, resp.SessionID, decoded.SessionID)
		require.Equal(t, resp.Issuer, decoded.Issuer)
		require.Equal(t, resp.Username, decoded.Username)
		require.Equal(t, resp.Audience, decoded.Audience)
		require.Equal(t, resp.IssuedAt.Unix(), decoded.IssuedAt.Unix())
		require.Equal(t, resp.ExpiresAt.Unix(), decoded.ExpiresAt.Unix())
		require.Equal(t, resp.NotBefore.Unix(), decoded.NotBefore.Unix())
		require.Equal(t, resp.MaxLifetimeExpiry.Unix(), decoded.MaxLifetimeExpiry.Unix())
		require.Equal(t, resp.TokenType, decoded.TokenType)
	})

	t.Run("Response validation", func(t *testing.T) {
		t.Run("AccessTokenResponse with empty roles", func(t *testing.T) {
			resp := AccessTokenResponse{
				Roles: []string{},
			}
			_, err := json.Marshal(resp)
			require.NoError(t, err) // Should not error, just empty array
		})

		t.Run("RefreshTokenResponse with empty username", func(t *testing.T) {
			resp := RefreshTokenResponse{
				Username: "",
			}
			_, err := json.Marshal(resp)
			require.NoError(t, err) // Should not error, just empty string
		})
	})
}
