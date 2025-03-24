package main

import (
	"context"
	"log"
	"time"

	"github.com/google/uuid"
	"github.com/gourdian25/gourdiantoken"
)

func defaultUsageExample() {
	// Generate a secure random key (in production, use a proper key management system)
	// This is just for demonstration - in real usage, the key should come from secure storage
	secretKey := "your-32-byte-secret-key-1234567890abcdef" // Replace with actual 32+ byte key

	// Create default configuration
	config := gourdiantoken.DefaultGourdianTokenConfig(secretKey)

	// Customize specific settings if needed
	config.AccessToken.Issuer = "myapp.com"
	config.AccessToken.Audience = []string{"api.myapp.com"}

	// Initialize token maker
	maker, err := gourdiantoken.NewGourdianTokenMaker(config)
	if err != nil {
		log.Fatalf("Failed to create token maker: %v", err)
	}

	// Create sample user data
	userID := uuid.New()
	sessionID := uuid.New()

	// Create access token
	accessToken, err := maker.CreateAccessToken(
		context.Background(),
		userID,
		"john_doe",
		"admin",
		sessionID,
	)
	if err != nil {
		log.Fatalf("Failed to create access token: %v", err)
	}

	log.Printf("Created access token:\nToken: %s\nExpires: %v",
		accessToken.Token,
		accessToken.ExpiresAt.Format(time.RFC3339),
	)

	// Create refresh token
	refreshToken, err := maker.CreateRefreshToken(
		context.Background(),
		userID,
		"john_doe",
		sessionID,
	)
	if err != nil {
		log.Fatalf("Failed to create refresh token: %v", err)
	}

	log.Printf("Created refresh token:\nToken: %s\nExpires: %v",
		refreshToken.Token,
		refreshToken.ExpiresAt.Format(time.RFC3339),
	)

	// Verify access token
	claims, err := maker.VerifyAccessToken(accessToken.Token)
	if err != nil {
		log.Fatalf("Token verification failed: %v", err)
	}

	log.Printf("Token verified for user %s (role: %s)", claims.Username, claims.Role)
}
