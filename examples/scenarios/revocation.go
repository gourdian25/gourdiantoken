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

func RunRevocationExample() {
	utils.PrintHeader("Token Revocation Example")

	// Redis configuration
	redisOpts := &redis.Options{
		Addr:     "localhost:6379",
		Password: "GourdianRedisSecret",
		DB:       0,
	}

	// Configuration with short token lifetimes for demo
	config := gourdiantoken.DefaultGourdianTokenConfig(
		"your-32-byte-secret-key-1234567890abcdef",
	)
	config.AccessToken.Duration = 2 * time.Minute
	config.RefreshToken.Duration = 10 * time.Minute
	config.RefreshToken.RotationEnabled = true

	// Initialize token maker
	maker, err := gourdiantoken.NewGourdianTokenMaker(config, redisOpts)
	if err != nil {
		log.Fatalf("Failed to create token maker: %v", err)
	}

	// Create tokens
	userID := uuid.New()
	username := "security.demo@example.com"
	sessionID := uuid.New()

	utils.PrintSection("Creating Tokens")
	accessToken, err := maker.CreateAccessToken(context.Background(), userID, username, "user", sessionID)
	if err != nil {
		log.Fatalf("Failed to create access token: %v", err)
	}

	refreshToken, err := maker.CreateRefreshToken(context.Background(), userID, username, sessionID)
	if err != nil {
		log.Fatalf("Failed to create refresh token: %v", err)
	}

	// Verify tokens initially work
	utils.PrintSection("Initial Verification")
	utils.VerifyToken(maker, accessToken.Token, gourdiantoken.AccessToken)
	utils.VerifyToken(maker, refreshToken.Token, gourdiantoken.RefreshToken)

	// Simulate token compromise and revocation
	utils.PrintSection("Simulating Token Compromise")
	fmt.Println("Adding tokens to revocation list...")

	// In a real implementation, you would add methods to JWTMaker for revocation
	// For this example, we'll directly use Redis
	redisClient := redis.NewClient(redisOpts)
	ctx := context.Background()

	// Calculate remaining TTL for tokens
	accessTTL := time.Until(accessToken.ExpiresAt)
	refreshTTL := time.Until(refreshToken.ExpiresAt)

	// Add to revocation list
	err = redisClient.Set(ctx, "revoked:access:"+accessToken.Token, "revoked", accessTTL).Err()
	if err != nil {
		log.Fatalf("Failed to revoke access token: %v", err)
	}

	err = redisClient.Set(ctx, "revoked:refresh:"+refreshToken.Token, "revoked", refreshTTL).Err()
	if err != nil {
		log.Fatalf("Failed to revoke refresh token: %v", err)
	}

	fmt.Println("Tokens successfully revoked")

	// Verify tokens are now invalid
	utils.PrintSection("Post-Revocation Verification")
	_, err = maker.VerifyAccessToken(accessToken.Token)
	if err != nil {
		fmt.Printf("✅ Access token correctly invalidated: %v\n", err)
	}

	_, err = maker.VerifyRefreshToken(refreshToken.Token)
	if err != nil {
		fmt.Printf("✅ Refresh token correctly invalidated: %v\n", err)
	}
}
