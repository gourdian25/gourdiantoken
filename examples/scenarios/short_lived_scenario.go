package scenarios

import (
	"context"
	"time"

	"github.com/gourdian25/gourdiantoken"
	"github.com/gourdian25/gourdiantoken/examples/utils"
)

func DemonstrateShortLivedTokens() {
	utils.PrintHeader("Short-Lived Token Demonstration")

	config := gourdiantoken.DefaultGourdianTokenConfig(
		"your-32-byte-secret-key-1234567890abcdef",
	)
	config.AccessToken.Duration = 1 * time.Minute
	config.AccessToken.MaxLifetime = 5 * time.Minute
	config.RefreshToken.Duration = 5 * time.Minute
	config.RefreshToken.MaxLifetime = 30 * time.Minute
	config.RefreshToken.ReuseInterval = 15 * time.Second
	config.RefreshToken.RotationEnabled = true

	maker, err := utils.CreateTokenMaker(config, true)
	if err != nil {
		utils.PrintError("Initialization failed", err)
		return
	}

	userID, username, sessionID := utils.CreateTestUser()

	utils.PrintSection("Initial Tokens")
	refreshToken, err := maker.CreateRefreshToken(context.Background(), userID, username, sessionID)
	if err != nil {
		utils.PrintError("Refresh token creation failed", err)
		return
	}

	_, err = maker.CreateAccessToken(context.Background(), userID, username, "user", sessionID)
	if err != nil {
		utils.PrintError("Access token creation failed", err)
		return
	}

	utils.PrintSection("Demonstrating Quick Rotation")
	utils.SimulateTokenExpiration(70 * time.Second)

	newRefreshToken, err := maker.RotateRefreshToken(refreshToken.Token)
	if err != nil {
		utils.PrintError("Rotation failed", err)
		return
	}

	newAccessToken, err := maker.CreateAccessToken(context.Background(), userID, username, "user", sessionID)
	if err != nil {
		utils.PrintError("New access token creation failed", err)
		return
	}

	utils.PrintTokenDetails("New Access Token", newAccessToken)
	utils.PrintTokenDetails("New Refresh Token", newRefreshToken)
}
