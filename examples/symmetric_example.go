// examples/symmetric_example.go
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
	printHeader("Symmetric Key Example (HMAC-SHA256)")

	// Configuration
	config := gourdiantoken.NewGourdianTokenConfig(
		"HS256",
		gourdiantoken.Symmetric,
		"your-very-secure-secret-key-at-least-32-bytes",
		"", "", // No key paths for symmetric
		15*time.Minute, // access token valid for 15 minutes
		24*time.Hour,   // but must be refreshed within 24 hours
		"auth.example.com",
		[]string{"api.example.com"},
		[]string{"HS256"},
		[]string{"jti", "sub", "exp", "iat", "typ", "rol"},
		7*24*time.Hour,  // refresh token valid for 7 days
		30*24*time.Hour, // but must be rotated within 30 days
		5*time.Minute,   // prevent refresh token reuse for 5 minutes
		true,            // enable refresh token rotation
		true,            // enable token family tracking
		5,               // max 5 concurrent refresh tokens per user
	)

	// Initialize
	printSection("Initializing Token Maker")
	maker, err := gourdiantoken.NewGourdianTokenMaker(config)
	if err != nil {
		log.Fatalf("Failed to create token maker: %v", err)
	}
	fmt.Println("Token maker initialized successfully")

	// User data
	userID := uuid.MustParse("6bacf1a8-10b6-4756-afb7-05f331e72b6a")
	username := "john.doe@example.com"
	role := "admin"
	sessionID := uuid.New()

	// Token creation
	printSection("Creating Tokens")

	accessToken, err := maker.CreateAccessToken(
		context.Background(),
		userID,
		username,
		role,
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

	// Simulate usage
	simulateAPICall(accessToken.Token)
}
