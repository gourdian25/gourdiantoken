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

	// Configuration with shorter intervals for demo purposes
	config := gourdiantoken.NewGourdianTokenConfig(
		"HS256",
		gourdiantoken.Symmetric,
		"your-32-byte-secret-key-1234567890abcdef",
		"", "",
		1*time.Minute, // Short access token for demo
		10*time.Minute,
		"auth.example.com",
		[]string{"api.example.com"},
		[]string{"HS256"},
		[]string{"jti", "sub", "exp", "iat", "typ", "rol"},
		5*time.Minute, // Refresh token valid for 5 min
		30*time.Minute,
		30*time.Second, // Can reuse after 30 seconds (for demo)
		true,
		true,
		5,
	)

	// Initialize
	printSection("Initializing Token Maker")
	maker, err := gourdiantoken.NewGourdianTokenMaker(config)
	if err != nil {
		log.Fatalf("Failed to create token maker: %v", err)
	}

	// Initial token creation
	printSection("Initial Token Creation")
	userID := uuid.New()
	username := "demo.user@example.com"
	sessionID := uuid.New()

	refreshToken, err := maker.CreateRefreshToken(
		context.Background(),
		userID,
		username,
		sessionID,
	)
	if err != nil {
		log.Fatalf("Failed to create initial refresh token: %v", err)
	}
	printTokenDetails("Initial Refresh", refreshToken)

	// First access token
	printSection("First Access Token")
	accessToken1, err := maker.CreateAccessToken(
		context.Background(),
		userID,
		username,
		"user",
		sessionID,
	)
	if err != nil {
		log.Fatalf("Failed to create first access token: %v", err)
	}
	printTokenDetails("Access Token 1", accessToken1)

	// Simulate token usage
	printSection("Simulating API Usage")
	simulateAPICall(accessToken1.Token)
	fmt.Println("Waiting for access token to expire...")
	time.Sleep(65 * time.Second) // Wait slightly longer than access token lifetime

	// Token rotation
	printSection("Token Rotation")
	fmt.Println("Attempting to rotate refresh token...")

	// Wait until reuse interval has passed if needed
	now := time.Now()
	issuedAt := refreshToken.IssuedAt
	minReuseTime := issuedAt.Add(config.RefreshToken.ReuseInterval)

	if now.Before(minReuseTime) {
		waitTime := minReuseTime.Sub(now)
		fmt.Printf("Waiting %.0f seconds for reuse interval...\n", waitTime.Seconds())
		time.Sleep(waitTime)
	}

	newRefreshToken, err := maker.RotateRefreshToken(refreshToken.Token)
	if err != nil {
		log.Fatalf("Failed to rotate refresh token: %v", err)
	}
	printTokenDetails("New Refresh", newRefreshToken)

	// New access token
	printSection("New Access Token")
	accessToken2, err := maker.CreateAccessToken(
		context.Background(),
		userID,
		username,
		"user",
		sessionID,
	)
	if err != nil {
		log.Fatalf("Failed to create new access token: %v", err)
	}
	printTokenDetails("Access Token 2", accessToken2)

	// Verification
	printSection("Verification")
	verifyToken(maker, accessToken2.Token, gourdiantoken.AccessToken)
	verifyToken(maker, newRefreshToken.Token, gourdiantoken.RefreshToken)

	// Security checks
	printSection("Security Checks")
	fmt.Println("Attempting to reuse old refresh token...")
	_, err = maker.RotateRefreshToken(refreshToken.Token)
	if err != nil {
		fmt.Printf("✅ Security check passed: %v\n", err)
	} else {
		fmt.Println("❌ WARNING: Old refresh token was accepted!")
	}
}
