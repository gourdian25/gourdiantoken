package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
	"github.com/gourdian25/gourdiantoken"
)

func symmetricExample() {
	fmt.Println("=== Symmetric Key Example (HMAC) ===")

	// Create a configuration with symmetric key (HMAC)
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

	// Create an access token
	accessToken, err := maker.CreateAccessToken(context.Background(), userID, username, role, sessionID)
	if err != nil {
		log.Fatalf("Failed to create access token: %v", err)
	}

	// Create a refresh token
	refreshToken, err := maker.CreateRefreshToken(context.Background(), userID, username, sessionID)
	if err != nil {
		log.Fatalf("Failed to create refresh token: %v", err)
	}

	// Verify the tokens
	verifyTokens(maker, accessToken.Token, refreshToken.Token)
}
