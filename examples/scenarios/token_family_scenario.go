package scenarios

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/gourdian25/gourdiantoken"
	"github.com/gourdian25/gourdiantoken/examples/utils"
	"github.com/redis/go-redis/v9"
)

func DemonstrateTokenFamilies() {
	utils.PrintHeader("Token Family Demonstration")

	config := gourdiantoken.DefaultGourdianTokenConfig(
		"your-32-byte-secret-key-1234567890abcdef",
	)
	config.RefreshToken.RotationEnabled = true
	config.RefreshToken.MaxLifetime = 30 * 24 * time.Hour
	config.AccessToken.Duration = 5 * time.Minute

	maker, err := utils.CreateTokenMaker(config, true)
	if err != nil {
		utils.PrintError("Initialization failed", err)
		return
	}

	userID, username, _ := utils.CreateTestUser()
	familyID := uuid.New().String()

	utils.PrintSection("Initial Token Generation")
	refreshToken, err := maker.CreateRefreshToken(context.Background(), userID, username, uuid.New())
	if err != nil {
		utils.PrintError("Refresh token creation failed", err)
		return
	}

	accessToken, err := maker.CreateAccessToken(context.Background(), userID, username, "user", uuid.New())
	if err != nil {
		utils.PrintError("Access token creation failed", err)
		return
	}

	// Store family ID in Redis
	redisClient := redis.NewClient(utils.GetRedisOptions())
	ctx := context.Background()
	err = redisClient.Set(ctx, "token_family:"+userID.String(), familyID, config.RefreshToken.MaxLifetime).Err()
	if err != nil {
		utils.PrintError("Failed to store token family", err)
		return
	}

	utils.PrintSection("Simulating Token Rotation Over Time")
	for i := 0; i < 3; i++ {
		utils.PrintSection(fmt.Sprintf("Rotation #%d", i+1))
		utils.SimulateTokenExpiration(6 * time.Minute)

		newRefreshToken, err := maker.RotateRefreshToken(refreshToken.Token)
		if err != nil {
			utils.PrintError("Rotation failed", err)
			return
		}

		newAccessToken, err := maker.CreateAccessToken(ctx, userID, username, "user", uuid.New())
		if err != nil {
			utils.PrintError("Access token creation failed", err)
			return
		}

		refreshToken = newRefreshToken
		accessToken = newAccessToken
	}

	utils.PrintSection("Final Verification")
	utils.VerifyToken(maker, accessToken.Token, gourdiantoken.AccessToken)
	utils.VerifyToken(maker, refreshToken.Token, gourdiantoken.RefreshToken)
}
