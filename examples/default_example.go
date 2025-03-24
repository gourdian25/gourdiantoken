// examples/default_example.go
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

	// Using default configuration with adjusted timings for demo

	// Using default configuration
	printSection("Creating Default Config")
	config := gourdiantoken.DefaultGourdianTokenConfig(
		"your-32-byte-secret-key-1234567890abcdef",
	)
	config.AccessToken.Duration = 45 * time.Second
	config.RefreshToken.ReuseInterval = 10 * time.Second

	// Initialize
	maker, err := gourdiantoken.NewGourdianTokenMaker(config)
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

	// Rotate tokens
	printSection("Token Rotation")
	fmt.Println("Waiting for reuse interval...")
	time.Sleep(10 * time.Second)

	newRefreshToken, err := maker.RotateRefreshToken(refreshToken.Token)
	if err != nil {
		log.Fatalf("Failed to rotate refresh token: %v", err)
	}

	newAccessToken, err := maker.CreateAccessToken(context.Background(), userID, username, "user", sessionID)
	if err != nil {
		log.Fatalf("Failed to create new access token: %v", err)
	}

	printSection("Final Verification")
	verifyToken(maker, newAccessToken.Token, gourdiantoken.AccessToken)
	verifyToken(maker, newRefreshToken.Token, gourdiantoken.RefreshToken)
}
