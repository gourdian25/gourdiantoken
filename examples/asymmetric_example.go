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
	fmt.Println("=== Asymmetric Key Example (RSA) ===")

	// Create a configuration with asymmetric keys (RSA)
	config := gourdiantoken.NewGourdianTokenConfig(
		"RS256",
		gourdiantoken.Asymmetric,
		"", // No symmetric key for asymmetric
		"keys/rsa_private.pem",
		"keys/rsa_public.pem",
		15*time.Minute, // accessDuration
		24*time.Hour,   // accessMaxLifetime
		"gourdian-example-app",
		[]string{"web", "mobile"},
		[]string{"RS256"},
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
	username := "jane.doe"
	role := "manager"
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

func verifyTokens(maker gourdiantoken.GourdianTokenMaker, accessToken, refreshToken string) {
	// Verify access token
	accessClaims, err := maker.VerifyAccessToken(accessToken)
	if err != nil {
		log.Fatalf("Invalid access token: %v", err)
	}
	fmt.Printf("Access Token Valid:\n  User: %s (%s)\n  Role: %s\n  Expires: %v\n",
		accessClaims.Username, accessClaims.Subject, accessClaims.Role, accessClaims.ExpiresAt)

	// Verify refresh token
	refreshClaims, err := maker.VerifyRefreshToken(refreshToken)
	if err != nil {
		log.Fatalf("Invalid refresh token: %v", err)
	}
	fmt.Printf("Refresh Token Valid:\n  User: %s (%s)\n  Expires: %v\n",
		refreshClaims.Username, refreshClaims.Subject, refreshClaims.ExpiresAt)
}
