package scenarios

import (
	"context"
	"time"

	"github.com/gourdian25/gourdiantoken"
	"github.com/gourdian25/gourdiantoken/examples/utils"
)

func DemonstrateBasicUsage() {
	utils.PrintHeader("Basic Usage Demonstration")

	config := gourdiantoken.DefaultGourdianTokenConfig(
		"your-32-byte-secret-key-1234567890abcdef",
	)
	config.RefreshToken.RotationEnabled = false
	config.AccessToken.Duration = 45 * time.Second

	maker, err := utils.CreateTokenMaker(config, false)
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

	accessToken, err := maker.CreateAccessToken(context.Background(), userID, username, "user", sessionID)
	if err != nil {
		utils.PrintError("Access token creation failed", err)
		return
	}

	utils.PrintSection("Token Usage")
	utils.SimulateAPICall(accessToken.Token)
	utils.SimulateTokenExpiration(50 * time.Second)

	utils.PrintSection("New Access Token")
	newAccessToken, err := maker.CreateAccessToken(context.Background(), userID, username, "user", sessionID)
	if err != nil {
		utils.PrintError("New access token creation failed", err)
		return
	}

	utils.PrintSection("Final Verification")
	utils.VerifyToken(maker, newAccessToken.Token, gourdiantoken.AccessToken)
	utils.VerifyToken(maker, refreshToken.Token, gourdiantoken.RefreshToken)
}
