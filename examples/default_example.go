package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
	"github.com/gourdian25/gourdiantoken"
)

func defaultUsageExample() {
	printHeader("Default Configuration Example")

	// Using default configuration without rotation
	printSection("Creating Default Config")
	config := gourdiantoken.DefaultGourdianTokenConfig(
		"your-32-byte-secret-key-1234567890abcdef",
	)
	config.RefreshToken.RotationEnabled = false // Disable rotation for this example
	config.AccessToken.Duration = 45 * time.Second

	// Initialize without Redis
	maker, err := gourdiantoken.NewGourdianTokenMaker(config, nil)
	if err != nil {
		log.Fatalf("Failed to create token maker: %v", err)
	}

	// Create tokens
	userID := uuid.New()
	username := "new.user@myapp.com"
	sessionID := uuid.New()

	printSection("Initial Tokens")
	refreshToken, err := maker.CreateRefreshToken(context.Background(), userID, username, sessionID)
	if err != nil {
		log.Fatalf("Failed to create refresh token: %v", err)
	}

	accessToken, err := maker.CreateAccessToken(context.Background(), userID, username, "user", sessionID)
	if err != nil {
		log.Fatalf("Failed to create access token: %v", err)
	}

	// Simulate usage
	printSection("Token Usage")
	simulateAPICall(accessToken.Token)
	fmt.Println("Waiting for access token to expire...")
	time.Sleep(50 * time.Second)

	// Create new access token (no rotation in this example)
	newAccessToken, err := maker.CreateAccessToken(context.Background(), userID, username, "user", sessionID)
	if err != nil {
		log.Fatalf("Failed to create new access token: %v", err)
	}

	printSection("Final Verification")
	verifyToken(maker, newAccessToken.Token, gourdiantoken.AccessToken)
	verifyToken(maker, refreshToken.Token, gourdiantoken.RefreshToken)
}
