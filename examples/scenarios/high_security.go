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

func RunHighSecurityExample() {
	utils.PrintHeader("High Security Configuration Example")

	// Redis configuration
	redisOpts := &redis.Options{
		Addr:     "localhost:6379",
		Password: "GourdianRedisSecret",
		DB:       0,
	}

	// High security configuration
	config := gourdiantoken.GourdianTokenConfig{
		Algorithm:      "ES256", // ECDSA for stronger security
		SigningMethod:  gourdiantoken.Asymmetric,
		PrivateKeyPath: "examples/keys/ecdsa_private.pem",
		PublicKeyPath:  "examples/keys/ecdsa_public.pem",
		AccessToken: gourdiantoken.AccessTokenConfig{
			Duration:          5 * time.Minute,  // Very short-lived access tokens
			MaxLifetime:       30 * time.Minute, // Absolute maximum
			Issuer:            "highsecurity.example.com",
			Audience:          []string{"api.highsecurity.example.com"},
			AllowedAlgorithms: []string{"ES256"},
			RequiredClaims:    []string{"jti", "sub", "exp", "iat", "typ", "rol", "aud", "iss"},
		},
		RefreshToken: gourdiantoken.RefreshTokenConfig{
			Duration:        30 * time.Minute, // Short-lived refresh tokens
			MaxLifetime:     2 * time.Hour,
			ReuseInterval:   1 * time.Minute,
			RotationEnabled: true,
		},
	}

	// Initialize with Redis
	maker, err := gourdiantoken.NewGourdianTokenMaker(config, redisOpts)
	if err != nil {
		log.Fatalf("Failed to create token maker: %v", err)
	}

	// Create tokens
	userID := uuid.New()
	username := "secure.user@example.com"
	sessionID := uuid.New()

	utils.PrintSection("Creating High Security Tokens")
	accessToken, err := maker.CreateAccessToken(
		context.Background(),
		userID,
		username,
		"admin",
		sessionID,
	)
	if err != nil {
		log.Fatalf("Failed to create access token: %v", err)
	}

	refreshToken, err := maker.CreateRefreshToken(
		context.Background(),
		userID,
		username,
		sessionID,
	)
	if err != nil {
		log.Fatalf("Failed to create refresh token: %v", err)
	}

	// Verify with strict requirements
	utils.PrintSection("Strict Verification")
	_, err = maker.VerifyAccessToken(accessToken.Token)
	if err != nil {
		log.Fatalf("Access token verification failed: %v", err)
	}
	fmt.Println("Access token meets all high security requirements")

	_, err = maker.VerifyRefreshToken(refreshToken.Token)
	if err != nil {
		log.Fatalf("Refresh token verification failed: %v", err)
	}
	fmt.Println("Refresh token meets all high security requirements")
}
