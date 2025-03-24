// examples/default_example.go
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/google/uuid"
	"github.com/gourdian25/gourdiantoken"
)

func defaultUsageExample() {
	printHeader("Default Configuration Example")

	// Using default configuration
	printSection("Creating Default Config")
	config := gourdiantoken.DefaultGourdianTokenConfig(
		"your-32-byte-secret-key-1234567890abcdef",
	)

	// Customize minimal required settings
	config.AccessToken.Issuer = "myapp.com"
	config.AccessToken.Audience = []string{"api.myapp.com", "web.myapp.com"}

	// Initialize
	printSection("Initializing Token Maker")
	maker, err := gourdiantoken.NewGourdianTokenMaker(config)
	if err != nil {
		log.Fatalf("Failed to create token maker: %v", err)
	}
	fmt.Println("Token maker initialized with default configuration")

	// User data
	userID := uuid.New()
	username := "new.user@myapp.com"
	sessionID := uuid.New()

	// Token creation
	printSection("Creating Tokens")
	accessToken, err := maker.CreateAccessToken(
		context.Background(),
		userID,
		username,
		"user", // default role
		sessionID,
	)
	if err != nil {
		log.Fatalf("Failed to create access token: %v", err)
	}
	printTokenDetails("Access", accessToken)

	refreshToken, err := maker.CreateRefreshToken(
		context.Background(),
		userID,
		username,
		sessionID,
	)
	if err != nil {
		log.Fatalf("Failed to create refresh token: %v", err)
	}
	printTokenDetails("Refresh", refreshToken)

	// Verification
	verifyToken(maker, accessToken.Token, gourdiantoken.AccessToken)
	verifyToken(maker, refreshToken.Token, gourdiantoken.RefreshToken)

	// Full lifecycle demo
	printSection("Full Lifecycle Demo")
	fmt.Println("1. User authenticates and receives tokens")
	fmt.Println("2. User makes API requests with access token")
	simulateAPICall(accessToken.Token)
	fmt.Println("3. Access token expires")
	fmt.Println("4. Client uses refresh token to get new tokens")

	newRefreshToken, err := maker.RotateRefreshToken(refreshToken.Token)
	if err != nil {
		log.Fatalf("Failed to rotate refresh token: %v", err)
	}
	printTokenDetails("Rotated Refresh", newRefreshToken)
}
