package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
	"github.com/gourdian25/gourdiantoken"
	"github.com/redis/go-redis/v9"
)

func asymmetricExample() {
	printHeader("Asymmetric Key Example (RSA-SHA256)")

	// Redis configuration for rotation
	redisOpts := &redis.Options{
		Addr:     "localhost:6379",      // Connect to your container
		Password: "GourdianRedisSecret", // No password
		DB:       0,                     // Default DB
	}

	// Configuration
	config := gourdiantoken.NewGourdianTokenConfig(
		"RS256",
		gourdiantoken.Asymmetric,
		"", // No symmetric key
		"examples/keys/rsa_private.pem",
		"examples/keys/rsa_public.pem",
		30*time.Minute, // Access token duration
		24*time.Hour,   // Access token max lifetime
		"api.example.com",
		[]string{"web.example.com", "mobile.example.com"},
		[]string{"RS256"},
		[]string{"jti", "sub", "exp", "iat", "typ", "rol"},
		14*24*time.Hour, // Refresh token duration
		60*24*time.Hour, // Refresh token max lifetime
		10*time.Minute,  // Reuse interval
		true,            // Enable rotation
	)

	// Initialize with Redis
	printSection("Initializing Token Maker")
	maker, err := gourdiantoken.NewGourdianTokenMaker(config, redisOpts)
	if err != nil {
		log.Fatalf("Failed to create token maker: %v", err)
	}
	fmt.Println("Token maker initialized with RSA keys and Redis")

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

	// Rotation demo
	printSection("Demonstrating Token Rotation")
	fmt.Println("Waiting 5 seconds before rotation...")
	time.Sleep(5 * time.Second)

	newRefreshToken, err := maker.RotateRefreshToken(refreshToken.Token)
	if err != nil {
		log.Fatalf("Failed to rotate refresh token: %v", err)
	}
	printTokenDetails("Rotated Refresh", newRefreshToken)

	// Verify old token is now invalid
	_, err = maker.VerifyRefreshToken(refreshToken.Token)
	if err != nil {
		fmt.Printf("✅ Old token correctly invalidated: %v\n", err)
	}
}
