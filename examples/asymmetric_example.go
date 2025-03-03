package main

import (
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
	"github.com/gourdian25/gourdiantoken"
)

func asymmetricExample() {
	fmt.Println("=== Asymmetric Key Example (RSA) ===")

	// Create a configuration with asymmetric keys (RSA)
	config := gourdiantoken.GourdianTokenConfig{
		Algorithm:      "RS256",
		SigningMethod:  gourdiantoken.Asymmetric,
		PrivateKeyPath: "keys/rsa_private.pem", // Update with your key path
		PublicKeyPath:  "keys/rsa_public.pem",  // Update with your key path
		AccessToken: gourdiantoken.AccessTokenConfig{
			Duration:          15 * time.Minute,
			MaxLifetime:       24 * time.Hour,
			Issuer:            "gourdian-example-app",
			Audience:          []string{"web", "mobile"},
			AllowedAlgorithms: []string{"RS256"},
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
	username := "jane.doe"
	role := "manager"
	sessionID := uuid.New()
	permissions := []string{"read:users", "read:reports"}

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
