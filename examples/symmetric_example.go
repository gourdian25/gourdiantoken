package main

import (
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
	"github.com/gourdian25/gourdiantoken/gourdiantoken"
)

func symmetricExample() {
	fmt.Println("=== Symmetric Key Example (HMAC) ===")

	// Create a configuration with symmetric key (HMAC)
	config := gourdiantoken.GourdianTokenConfig{
		Algorithm:     "HS256",
		SigningMethod: gourdiantoken.Symmetric,
		SymmetricKey:  "your-very-secure-secret-key-at-least-32-bytes",
		AccessToken: gourdiantoken.AccessTokenConfig{
			Duration:          15 * time.Minute,
			MaxLifetime:       24 * time.Hour,
			Issuer:            "gourdian-example-app",
			Audience:          []string{"web", "mobile"},
			AllowedAlgorithms: []string{"HS256"},
			RequiredClaims:    []string{"sub", "exp", "jti"},
		},
		RefreshToken: gourdiantoken.RefreshTokenConfig{
			Duration:        7 * 24 * time.Hour,
			MaxLifetime:     30 * 24 * time.Hour,
			ReuseInterval:   5 * time.Minute,
			RotationEnabled: true,
			FamilyEnabled:   true,
			MaxPerUser:      5,
		},
	}

	// Create a token maker
	maker, err := gourdiantoken.NewGourdianTokenMaker(config)
	if err != nil {
		log.Fatalf("Failed to create token maker: %v", err)
	}

	// User and session details
	userID := uuid.New()
	username := "john.doe"
	role := "admin"
	sessionID := uuid.New()
	permissions := []string{"read:users", "write:users", "read:reports"}

	// Create an access token
	accessToken, err := createAccessToken(maker, userID, username, role, sessionID, permissions)
	if err != nil {
		log.Fatalf("Failed to create access token: %v", err)
	}

	// Create a refresh token
	refreshToken, err := createRefreshToken(maker, userID, username, sessionID)
	if err != nil {
		log.Fatalf("Failed to create refresh token: %v", err)
	}

	// Verify the tokens
	verifyTokens(maker, accessToken.Token, refreshToken.Token)
}
