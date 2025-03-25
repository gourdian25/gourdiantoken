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

func RunTokenFamilyExample() {
	utils.PrintHeader("Token Family Example")

	// Redis configuration
	redisOpts := &redis.Options{
		Addr:     "localhost:6379",
		Password: "GourdianRedisSecret",
		DB:       0,
	}

	// Configuration with token families
	config := gourdiantoken.DefaultGourdianTokenConfig(
		"your-32-byte-secret-key-1234567890abcdef",
	)
	config.RefreshToken.RotationEnabled = true
	config.RefreshToken.MaxLifetime = 30 * 24 * time.Hour
	config.AccessToken.Duration = 5 * time.Minute // Short access token for demo

	// Initialize token maker
	maker, err := gourdiantoken.NewGourdianTokenMaker(config, redisOpts)
	if err != nil {
		log.Fatalf("Failed to create token maker: %v", err)
	}

	// User data
	userID := uuid.New()
	username := "family.user@example.com"
	familyID := uuid.New().String() // In real implementation, this would be stored per user session

	// Store family ID in Redis
	redisClient := redis.NewClient(redisOpts)
	ctx := context.Background()
	err = redisClient.Set(ctx, "token_family:"+userID.String(), familyID, config.RefreshToken.MaxLifetime).Err()
	if err != nil {
		log.Fatalf("Failed to store token family: %v", err)
	}

	// Create initial tokens
	utils.PrintSection("Initial Token Generation")
	refreshToken, err := maker.CreateRefreshToken(ctx, userID, username, uuid.New())
	if err != nil {
		log.Fatalf("Failed to create refresh token: %v", err)
	}

	accessToken, err := maker.CreateAccessToken(ctx, userID, username, "user", uuid.New())
	if err != nil {
		log.Fatalf("Failed to create access token: %v", err)
	}

	// Simulate token rotation over time
	utils.PrintSection("Simulating Token Rotation Over Time")
	for i := 0; i < 3; i++ {
		fmt.Printf("\nRotation #%d\n", i+1)
		fmt.Println("Waiting for access token to expire...")
		time.Sleep(6 * time.Minute)

		newRefreshToken, err := maker.RotateRefreshToken(refreshToken.Token)
		if err != nil {
			log.Fatalf("Rotation failed: %v", err)
		}

		// Create new access token
		newAccessToken, err := maker.CreateAccessToken(ctx, userID, username, "user", uuid.New())
		if err != nil {
			log.Fatalf("Failed to create access token: %v", err)
		}

		fmt.Println("Successfully rotated tokens")
		refreshToken = newRefreshToken
		accessToken = newAccessToken
	}

	// Verify final tokens
	utils.PrintSection("Final Verification")
	utils.VerifyToken(maker, accessToken.Token, gourdiantoken.AccessToken)
	utils.VerifyToken(maker, refreshToken.Token, gourdiantoken.RefreshToken)
}
