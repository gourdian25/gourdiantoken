package scenarios

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
	"github.com/gourdian25/gourdiantoken"
	"github.com/gourdian25/gourdiantoken/examples/utils"
	"github.com/redis/go-redis/v9"
)

func RunRefreshFlowExample() {
	utils.PrintHeader("Token Refresh Flow Example")

	// Redis configuration for rotation
	redisOpts := &redis.Options{
		Addr:     "localhost:6379",      // Connect to your container
		Password: "GourdianRedisSecret", // No password
		DB:       0,                     // Default DB
	}

	// Configuration with rotation enabled
	config := gourdiantoken.NewGourdianTokenConfig(
		"HS256",
		gourdiantoken.Symmetric,
		"your-32-byte-secret-key-1234567890abcdef",
		"", "",
		30*time.Second, // Short access token
		5*time.Minute,
		"auth.example.com",
		[]string{"api.example.com"},
		[]string{"HS256"},
		[]string{"jti", "sub", "exp", "iat", "typ", "rol"},
		2*time.Minute, // Refresh token duration
		10*time.Minute,
		15*time.Second, // Reuse interval
		true,           // Enable rotation
	)

	// Initialize with Redis
	maker, err := gourdiantoken.NewGourdianTokenMaker(config, redisOpts)
	if err != nil {
		log.Fatalf("Failed to create token maker: %v", err)
	}

	// Create initial tokens
	userID := uuid.New()
	username := "demo.user@example.com"
	sessionID := uuid.New()

	utils.PrintSection("Initial Token Creation")
	refreshToken, err := maker.CreateRefreshToken(context.Background(), userID, username, sessionID)
	if err != nil {
		log.Fatalf("Failed to create refresh token: %v", err)
	}
	utils.PrintTokenDetails("Initial Refresh Token", refreshToken)

	accessToken, err := maker.CreateAccessToken(context.Background(), userID, username, "user", sessionID)
	if err != nil {
		log.Fatalf("Failed to create access token: %v", err)
	}
	utils.PrintTokenDetails("Initial Access Token", accessToken)

	// Simulate API usage
	utils.PrintSection("API Usage Simulation")
	utils.SimulateAPICall(accessToken.Token)
	fmt.Println("Waiting for access token to expire...")
	time.Sleep(35 * time.Second)

	// Rotate refresh token
	utils.PrintSection("Refresh Token Rotation")
	fmt.Println("Waiting for reuse interval...")
	time.Sleep(15 * time.Second)

	newRefreshToken, err := maker.RotateRefreshToken(refreshToken.Token)
	if err != nil {
		log.Fatalf("Failed to rotate refresh token: %v", err)
	}
	utils.PrintTokenDetails("New Refresh Token", newRefreshToken)

	// Security check
	utils.PrintSection("Security Validation")
	fmt.Println("Attempting to reuse old refresh token...")
	_, err = maker.RotateRefreshToken(refreshToken.Token)
	if err != nil {
		fmt.Printf("✅ Security check passed: %v\n", err)
	} else {
		fmt.Println("❌ WARNING: Old refresh token was accepted!")
	}
}
