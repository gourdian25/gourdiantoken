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

func symmetricExample() {
	printHeader("Symmetric Key Example (HMAC-SHA256)")

	// Redis configuration for rotation
	redisOpts := &redis.Options{
		Addr:     "localhost:6379",      // Connect to your container
		Password: "GourdianRedisSecret", // No password
		DB:       0,                     // Default DB
	}

	// Configuration
	config := gourdiantoken.NewGourdianTokenConfig(
		"HS256",
		gourdiantoken.Symmetric,
		"your-very-secure-secret-key-at-least-32-bytes",
		"", "",
		15*time.Minute,
		24*time.Hour,
		"auth.example.com",
		[]string{"api.example.com"},
		[]string{"HS256"},
		[]string{"jti", "sub", "exp", "iat", "typ", "rol"},
		7*24*time.Hour,
		30*24*time.Hour,
		5*time.Minute,
		true, // Enable rotation
	)

	// Initialize with Redis
	printSection("Initializing Token Maker")
	maker, err := gourdiantoken.NewGourdianTokenMaker(config, redisOpts)
	if err != nil {
		log.Fatalf("Failed to create token maker: %v", err)
	}
	fmt.Println("Token maker initialized with Redis support")

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

	// Rotation demo
	printSection("Demonstrating Rotation")
	fmt.Println("Waiting 5 seconds before rotation...")
	time.Sleep(5 * time.Second)

	newRefreshToken, err := maker.RotateRefreshToken(refreshToken.Token)
	if err != nil {
		log.Fatalf("Rotation failed: %v", err)
	}
	printTokenDetails("Rotated Refresh", newRefreshToken)
}
