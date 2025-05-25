// gourdiantoken_verification_test.go
package gourdiantoken

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestTokenVerificationEdgeCases(t *testing.T) {
	config := DefaultGourdianTokenConfig(testSymmetricKey)
	maker, err := NewGourdianTokenMaker(context.Background(), config, nil)
	require.NoError(t, err)

	t.Run("Expired Token", func(t *testing.T) {
		// Create token with immediate expiration
		config := DefaultGourdianTokenConfig(testSymmetricKey)
		config.AccessExpiryDuration = time.Nanosecond
		tempMaker, err := NewGourdianTokenMaker(context.Background(), config, nil)
		require.NoError(t, err)

		token, err := tempMaker.CreateAccessToken(context.Background(), uuid.New(), "user", []string{"admin"}, uuid.New())
		require.NoError(t, err)

		// Wait for it to expire
		time.Sleep(time.Millisecond)

		_, err = maker.VerifyAccessToken(context.Background(), token.Token)
		require.Error(t, err)
		require.Contains(t, err.Error(), "expired")
	})

	t.Run("Tampered Signature", func(t *testing.T) {
		token, err := maker.CreateAccessToken(context.Background(), uuid.New(), "user", []string{"admin"}, uuid.New())
		require.NoError(t, err)

		// Tamper with the token by changing one character in the signature
		tampered := token.Token[:len(token.Token)-4] + "abcd"

		_, err = maker.VerifyAccessToken(context.Background(), tampered)
		require.Error(t, err)
		require.Contains(t, err.Error(), "signature is invalid")
	})

	t.Run("Invalid Algorithm", func(t *testing.T) {
		// Create token with different algorithm
		privKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		claims := AccessTokenClaims{
			ID:        uuid.New(),
			Subject:   uuid.New(),
			Username:  "user",
			SessionID: uuid.New(),
			Issuer:    config.Issuer,
			Audience:  config.Audience,
			Roles:     []string{"admin"},
			IssuedAt:  time.Now(),
			ExpiresAt: time.Now().Add(time.Hour),
			TokenType: AccessToken,
		}

		token := jwt.NewWithClaims(jwt.SigningMethodRS256, toMapClaims(claims))
		tokenString, err := token.SignedString(privKey)
		require.NoError(t, err)

		_, err = maker.VerifyAccessToken(context.Background(), tokenString)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unexpected signing method")
	})

	t.Run("Empty Audience", func(t *testing.T) {
		config := DefaultGourdianTokenConfig(testSymmetricKey)
		config.Audience = nil
		tempMaker, err := NewGourdianTokenMaker(context.Background(), config, nil)
		require.NoError(t, err)

		token, err := tempMaker.CreateAccessToken(context.Background(), uuid.New(), "user", []string{"admin"}, uuid.New())
		require.NoError(t, err)

		// Should still verify successfully
		_, err = tempMaker.VerifyAccessToken(context.Background(), token.Token)
		require.NoError(t, err)
	})
}

func TestValidateAlgorithmAndMethod(t *testing.T) {
	tests := []struct {
		name      string
		algorithm string
		method    SigningMethod
		wantErr   bool
	}{
		{"Valid HS256", "HS256", Symmetric, false},
		{"Valid RS256", "RS256", Asymmetric, false},
		{"Invalid HS256 with Asymmetric", "HS256", Asymmetric, true},
		{"Invalid RS256 with Symmetric", "RS256", Symmetric, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := GourdianTokenConfig{
				Algorithm:     tt.algorithm,
				SigningMethod: tt.method,
			}
			err := validateAlgorithmAndMethod(&config)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestGetUnixTime(t *testing.T) {
	now := time.Now().Unix()
	tests := []struct {
		name  string
		input interface{}
		want  int64
	}{
		{"Float64", float64(now), now},
		{"Int64", int64(now), now},
		{"Int", int(now), now},
		{"JSON Number", json.Number(fmt.Sprintf("%d", now)), now},
		{"Invalid Type", "not a number", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getUnixTime(tt.input)
			require.Equal(t, tt.want, got)
		})
	}
}

// func TestContextCancellation(t *testing.T) {
// 	config := DefaultGourdianTokenConfig(testSymmetricKey)
// 	config.RevocationEnabled = true
// 	config.RotationEnabled = true

// 	ctx, cancel := context.WithCancel(context.Background())
// 	cancel() // Immediately cancel the context

// 	// Test NewGourdianTokenMaker with cancelled context
// 	_, err := NewGourdianTokenMaker(ctx, config, testRedisOptions())
// 	require.Error(t, err)
// 	require.Contains(t, err.Error(), "context canceled")

// 	// Test token operations with cancelled context
// 	maker, err := NewGourdianTokenMaker(context.Background(), config, testRedisOptions())
// 	require.NoError(t, err)

// 	cancelledCtx, cancel := context.WithCancel(context.Background())
// 	cancel()

// 	_, err = maker.CreateAccessToken(cancelledCtx, uuid.New(), "user", []string{"admin"}, uuid.New())
// 	require.Error(t, err)
// 	require.Contains(t, err.Error(), "context canceled")
// }
