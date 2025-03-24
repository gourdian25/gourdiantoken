// examples/refresh_example.go
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
	printHeader("Token Refresh Flow Example")

	// Configuration with demo-friendly timings
	config := gourdiantoken.NewGourdianTokenConfig(
		"HS256",
		gourdiantoken.Symmetric,
		"your-32-byte-secret-key-1234567890abcdef",
		"", "",
		30*time.Second, // Very short access token for demo
		5*time.Minute,
		"auth.example.com",
		[]string{"api.example.com"},
		[]string{"HS256"},
		[]string{"jti", "sub", "exp", "iat", "typ", "rol"},
		2*time.Minute, // Refresh token valid for 2 min
		10*time.Minute,
		15*time.Second, // Can reuse after 15 seconds (for demo)
		true,
		true,
		5,
	)

	// Initialize token maker
	maker, err := gourdiantoken.NewGourdianTokenMaker(config)
	if err != nil {
		log.Fatalf("Failed to create token maker: %v", err)
	}

	// Create initial tokens
	userID := uuid.New()
	username := "demo.user@example.com"
	sessionID := uuid.New()

	printSection("Initial Token Creation")
	refreshToken, err := maker.CreateRefreshToken(context.Background(), userID, username, sessionID)
	if err != nil {
		log.Fatalf("Failed to create refresh token: %v", err)
	}
	printTokenDetails("Initial Refresh Token", refreshToken)

	accessToken, err := maker.CreateAccessToken(context.Background(), userID, username, "user", sessionID)
	if err != nil {
		log.Fatalf("Failed to create access token: %v", err)
	}
	printTokenDetails("Initial Access Token", accessToken)

	// Simulate API usage
	printSection("API Usage Simulation")
	simulateAPICall(accessToken.Token)
	fmt.Println("Waiting for access token to expire...")
	time.Sleep(35 * time.Second) // Wait longer than access token lifetime

	// Rotate refresh token (with proper timing)
	printSection("Refresh Token Rotation")
	fmt.Println("Waiting for reuse interval...")
	time.Sleep(15 * time.Second) // Wait for reuse interval to pass

	newRefreshToken, err := maker.RotateRefreshToken(refreshToken.Token)
	if err != nil {
		log.Fatalf("Failed to rotate refresh token: %v", err)
	}
	printTokenDetails("New Refresh Token", newRefreshToken)

	// Create new access token with rotated refresh token
	newAccessToken, err := maker.CreateAccessToken(context.Background(), userID, username, "user", sessionID)
	if err != nil {
		log.Fatalf("Failed to create new access token: %v", err)
	}
	printTokenDetails("New Access Token", newAccessToken)

	// Security check
	printSection("Security Validation")
	fmt.Println("Attempting to reuse old refresh token...")
	_, err = maker.RotateRefreshToken(refreshToken.Token)
	if err != nil {
		fmt.Printf("✅ Security check passed: %v\n", err)
	} else {
		fmt.Println("❌ WARNING: Old refresh token was accepted!")
	}
}
