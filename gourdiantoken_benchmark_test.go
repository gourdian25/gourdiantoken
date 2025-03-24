package gourdiantoken

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func BenchmarkCreateAccessToken(b *testing.B) {
	// Setup symmetric maker
	symmetricConfig := DefaultGourdianTokenConfig("test-secret-32-bytes-long-1234567890")
	symmetricMaker, _ := NewGourdianTokenMaker(symmetricConfig)

	// Setup asymmetric maker
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	asymmetricConfig := GourdianTokenConfig{
		Algorithm:     "RS256",
		SigningMethod: Asymmetric,
		AccessToken: AccessTokenConfig{
			Duration: time.Hour,
		},
	}
	asymmetricMaker := &JWTMaker{
		config:        asymmetricConfig,
		signingMethod: jwt.SigningMethodRS256,
		privateKey:    privateKey,
		publicKey:     &privateKey.PublicKey,
	}

	userID := uuid.New()
	username := "benchuser"
	role := "user"
	sessionID := uuid.New()

	b.Run("Symmetric", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := symmetricMaker.CreateAccessToken(context.Background(), userID, username, role, sessionID)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("Asymmetric", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := asymmetricMaker.CreateAccessToken(context.Background(), userID, username, role, sessionID)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkVerifyAccessToken(b *testing.B) {
	// Setup symmetric maker
	symmetricConfig := DefaultGourdianTokenConfig("test-secret-32-bytes-long-1234567890")
	symmetricMaker, _ := NewGourdianTokenMaker(symmetricConfig)

	// Setup asymmetric maker
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	asymmetricConfig := GourdianTokenConfig{
		Algorithm:     "RS256",
		SigningMethod: Asymmetric,
		AccessToken: AccessTokenConfig{
			Duration: time.Hour,
		},
	}
	asymmetricMaker := &JWTMaker{
		config:        asymmetricConfig,
		signingMethod: jwt.SigningMethodRS256,
		privateKey:    privateKey,
		publicKey:     &privateKey.PublicKey,
	}

	userID := uuid.New()
	username := "benchuser"
	role := "user"
	sessionID := uuid.New()

	symToken, _ := symmetricMaker.CreateAccessToken(context.Background(), userID, username, role, sessionID)
	asymToken, _ := asymmetricMaker.CreateAccessToken(context.Background(), userID, username, role, sessionID)

	b.Run("Symmetric", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := symmetricMaker.VerifyAccessToken(symToken.Token)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("Asymmetric", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := asymmetricMaker.VerifyAccessToken(asymToken.Token)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}
