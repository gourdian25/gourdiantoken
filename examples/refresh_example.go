package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
	"github.com/gourdian25/gourdiantoken"
)

func refreshTokenExample() {
	fmt.Println("=== Token Refresh Example ===")

	// Use the symmetric example configuration
	config := gourdiantoken.NewGourdianTokenConfig(
		"HS256",
		gourdiantoken.Symmetric,
		"your-very-secure-secret-key-at-least-32-bytes",
		"",             // No private key path
		"",             // No public key path
		15*time.Minute, // accessDuration
		24*time.Hour,   // accessMaxLifetime
		"gourdian-example-app",
		[]string{"web", "mobile"},
		[]string{"HS256"},
		[]string{"sub", "exp", "jti"},
		7*24*time.Hour,  // refreshDuration
		30*24*time.Hour, // refreshMaxLifetime
		5*time.Minute,   // refreshReuseInterval
		true,            // refreshRotationEnabled
		true,            // refreshFamilyEnabled
		5,               // refreshMaxPerUser
	)

	maker, err := gourdiantoken.NewGourdianTokenMaker(config)
	if err != nil {
		log.Fatalf("Failed to create token maker: %v", err)
	}

	// Create a refresh token
	userID := uuid.New()
	username := "john.doe"
	sessionID := uuid.New()
	refreshToken, err := maker.CreateRefreshToken(context.Background(), userID, username, sessionID)
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

	// In a real application, you would look up the user's role from your database
	role := "admin"

	// Generate a new access token
	newAccessToken, err := maker.CreateAccessToken(context.Background(), userID, username, role, sessionID)
	if err != nil {
		log.Fatalf("Failed to create new access token: %v", err)
	}

	// Generate a new refresh token (rotation)
	newRefreshToken, err := maker.CreateRefreshToken(context.Background(), userID, username, sessionID)
	if err != nil {
		log.Fatalf("Failed to create new refresh token: %v", err)
	}

	fmt.Println("Token Refresh Successful:")
	fmt.Printf("  New Access Token: %s...\n", newAccessToken.Token[:30])
	fmt.Printf("  New Refresh Token: %s...\n", newRefreshToken.Token[:30])
	fmt.Printf("  User: %s (%s)\n", username, userID)
}
