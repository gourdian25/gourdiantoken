// examples/asymmetric_example.go
package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
	"github.com/gourdian25/gourdiantoken"
)

func asymmetricExample() {
	printHeader("Asymmetric Key Example (RSA-SHA256)")

	// Configuration
	config := gourdiantoken.NewGourdianTokenConfig(
		"RS256",
		gourdiantoken.Asymmetric,
		"", // No symmetric key
		"examples/keys/rsa_private.pem",
		"examples/keys/rsa_public.pem",
		30*time.Minute, // longer access token for demo
		24*time.Hour,
		"api.example.com",
		[]string{"web.example.com", "mobile.example.com"},
		[]string{"RS256"},
		[]string{"jti", "sub", "exp", "iat", "typ", "rol"},
		14*24*time.Hour, // longer refresh for demo
		60*24*time.Hour,
		10*time.Minute, // longer reuse interval
		true,
		true,
		10, // more concurrent tokens allowed
	)

	// Initialize
	printSection("Initializing Token Maker")
	maker, err := gourdiantoken.NewGourdianTokenMaker(config)
	if err != nil {
		log.Fatalf("Failed to create token maker: %v", err)
	}
	fmt.Println("Token maker initialized with RSA keys")

	// User data
	userID := uuid.New()
	username := "jane.doe@example.com"
	role := "manager"
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
