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

func RunShortLivedExample() {
	utils.PrintHeader("Short-Lived Token Example")

	// Redis configuration
	redisOpts := &redis.Options{
		Addr:     "localhost:6379",
		Password: "GourdianRedisSecret",
		DB:       0,
	}

	// Configuration with very short token lifetimes
	config := gourdiantoken.DefaultGourdianTokenConfig(
		"your-32-byte-secret-key-1234567890abcdef",
	)
	// Override defaults for this example
	config.AccessToken.Duration = 1 * time.Minute
	config.AccessToken.MaxLifetime = 5 * time.Minute
	config.RefreshToken.Duration = 5 * time.Minute
	config.RefreshToken.MaxLifetime = 30 * time.Minute
	config.RefreshToken.ReuseInterval = 15 * time.Second
	config.RefreshToken.RotationEnabled = true // Enable rotation for this example

	// Initialize with Redis
	maker, err := gourdiantoken.NewGourdianTokenMaker(config, redisOpts)
	if err != nil {
		log.Fatalf("Failed to create token maker: %v", err)
	}

	// Create initial tokens
	userID := uuid.New()
	username := "shortlived.user@example.com"
	sessionID := uuid.New()

	utils.PrintSection("Initial Tokens")
	refreshToken, err := maker.CreateRefreshToken(
		context.Background(),
		userID,
		username,
		sessionID,
	)
	if err != nil {
		log.Fatalf("Failed to create refresh token: %v", err)
	}

	accessToken, err := maker.CreateAccessToken(
		context.Background(),
		userID,
		username,
		"user",
		sessionID,
	)
	if err != nil {
		log.Fatalf("Failed to create access token: %v", err)
	}

	// Demonstrate quick rotation
	utils.PrintSection("Demonstrating Quick Rotation")
	fmt.Println("Waiting for access token to expire...")
	time.Sleep(70 * time.Second) // Slightly more than 1 minute

	// Rotate refresh token to get new access token
	newRefreshToken, err := maker.RotateRefreshToken(refreshToken.Token)
	if err != nil {
		log.Fatalf("Rotation failed: %v", err)
	}

	// Create new access token
	newAccessToken, err := maker.CreateAccessToken(
		context.Background(),
		userID,
		username,
		"user",
		sessionID,
	)
	if err != nil {
		log.Fatalf("Failed to create new access token: %v", err)
	}

	utils.PrintTokenDetails("Old Access Token", accessToken)
	utils.PrintTokenDetails("New Access Token", newAccessToken)
	utils.PrintTokenDetails("New Refresh Token", newRefreshToken)
}
