package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
	"github.com/gourdian25/gourdiantoken/gourdiantoken"
)

func refreshTokenExample() {
	fmt.Println("=== Token Refresh Example ===")

	// Use the symmetric example configuration for simplicity
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

	maker, err := gourdiantoken.NewGourdianTokenMaker(config)
	if err != nil {
		log.Fatalf("Failed to create token maker: %v", err)
	}

	// Create a refresh token
	userID := uuid.New()
	username := "john.doe"
	sessionID := uuid.New()
	refreshToken, err := createRefreshToken(maker, userID, username, sessionID)
	if err != nil {
		log.Fatalf("Failed to create refresh token: %v", err)
	}

	// Refresh the token
	refreshTokenStr := refreshToken.Token
	refreshClaims, err := maker.VerifyRefreshToken(refreshTokenStr)
	if err != nil {
		log.Fatalf("Invalid refresh token: %v", err)
	}

	// Extract user information from the refresh token
	userID = refreshClaims.Subject
	username = refreshClaims.Username
	sessionID = refreshClaims.SessionID

	// In a real application, you would look up the user's role and permissions from your database
	role := "admin"
	permissions := []string{"read:users", "write:users"}

	ctx := context.Background()

	// Generate a new access token
	newAccessToken, err := maker.CreateAccessToken(ctx, userID, username, role, sessionID, permissions)
	if err != nil {
		log.Fatalf("Failed to create new access token: %v", err)
	}

	// Generate a new refresh token if token rotation is enabled
	newRefreshToken, err := maker.CreateRefreshToken(ctx, userID, username, sessionID)
	if err != nil {
		log.Fatalf("Failed to create new refresh token: %v", err)
	}

	fmt.Println("Token Refresh Successful:")
	fmt.Printf("  New Access Token: %s...\n", newAccessToken.Token[:30])
	fmt.Printf("  New Refresh Token: %s...\n", newRefreshToken.Token[:30])
}
