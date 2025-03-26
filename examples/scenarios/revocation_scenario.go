package scenarios

import (
	"context"
	"time"

	"github.com/gourdian25/gourdiantoken"
	"github.com/gourdian25/gourdiantoken/examples/utils"
	"github.com/redis/go-redis/v9"
)

func DemonstrateTokenRevocation() {
	utils.PrintHeader("Token Revocation Demonstration")

	config := gourdiantoken.DefaultGourdianTokenConfig(
		"your-32-byte-secret-key-1234567890abcdef",
	)
	config.AccessToken.Duration = 2 * time.Minute
	config.RefreshToken.Duration = 10 * time.Minute
	config.RefreshToken.RotationEnabled = true

	maker, err := utils.CreateTokenMaker(config, true)
	if err != nil {
		utils.PrintError("Initialization failed", err)
		return
	}

	userID, username, sessionID := utils.CreateTestUser()

	utils.PrintSection("Creating Tokens")
	accessToken, err := maker.CreateAccessToken(context.Background(), userID, username, "user", sessionID)
	if err != nil {
		utils.PrintError("Access token creation failed", err)
		return
	}

	refreshToken, err := maker.CreateRefreshToken(context.Background(), userID, username, sessionID)
	if err != nil {
		utils.PrintError("Refresh token creation failed", err)
		return
	}

	utils.VerifyToken(maker, accessToken.Token, gourdiantoken.AccessToken)
	utils.VerifyToken(maker, refreshToken.Token, gourdiantoken.RefreshToken)

	utils.PrintSection("Simulating Token Compromise")
	redisClient := redis.NewClient(utils.GetRedisOptions())
	ctx := context.Background()

	accessTTL := time.Until(accessToken.ExpiresAt)
	refreshTTL := time.Until(refreshToken.ExpiresAt)

	err = redisClient.Set(ctx, "revoked:access:"+accessToken.Token, "revoked", accessTTL).Err()
	if err != nil {
		utils.PrintError("Access token revocation failed", err)
		return
	}

	err = redisClient.Set(ctx, "revoked:refresh:"+refreshToken.Token, "revoked", refreshTTL).Err()
	if err != nil {
		utils.PrintError("Refresh token revocation failed", err)
		return
	}

	utils.PrintSection("Post-Revocation Verification")
	_, err = maker.VerifyAccessToken(accessToken.Token)
	utils.VerifyError("Access token verification", err, "should fail")

	_, err = maker.VerifyRefreshToken(refreshToken.Token)
	utils.VerifyError("Refresh token verification", err, "should fail")
}
