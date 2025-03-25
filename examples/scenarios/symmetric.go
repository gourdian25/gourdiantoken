// examples/scenarios/symmetric.go
package scenarios

import (
	"context"
	"log"
	"time"

	"github.com/google/uuid"
	"github.com/gourdian25/gourdiantoken"
	"github.com/gourdian25/gourdiantoken/examples/utils"
	"github.com/redis/go-redis/v9"
)

func RunSymmetricExample() {
	utils.PrintHeader("Symmetric Key Example (HMAC-SHA256)")

	// Redis configuration
	redisOpts := &redis.Options{
		Addr:     "localhost:6379",
		Password: "GourdianRedisSecret",
		DB:       0,
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
		true,
	)

	// Initialize with Redis
	maker, err := gourdiantoken.NewGourdianTokenMaker(config, redisOpts)
	if err != nil {
		log.Fatalf("Failed to create token maker: %v", err)
	}

	// User data
	userID := uuid.MustParse("6bacf1a8-10b6-4756-afb7-05f331e72b6a")
	username := "john.doe@example.com"
	role := "admin"
	sessionID := uuid.New()

	// Token creation
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

	refreshToken, err := maker.CreateRefreshToken(
		context.Background(),
		userID,
		username,
		sessionID,
	)
	if err != nil {
		log.Fatalf("Failed to create refresh token: %v", err)
	}

	// Verification
	utils.VerifyToken(maker, accessToken.Token, gourdiantoken.AccessToken)
	utils.VerifyToken(maker, refreshToken.Token, gourdiantoken.RefreshToken)

	// Rotation demo
	time.Sleep(5 * time.Second)
	newRefreshToken, err := maker.RotateRefreshToken(refreshToken.Token)
	if err != nil {
		log.Fatalf("Rotation failed: %v", err)
	}

	utils.PrintTokenDetails("Rotated Refresh", newRefreshToken)
}
