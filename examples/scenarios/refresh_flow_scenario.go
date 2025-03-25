package scenarios

import (
	"context"
	"time"

	"github.com/gourdian25/gourdiantoken"
	"github.com/gourdian25/gourdiantoken/examples/utils"
)

func DemonstrateRefreshFlow() {
	utils.PrintHeader("Refresh Token Flow Demonstration")

	config := gourdiantoken.NewGourdianTokenConfig(
		"HS256",
		gourdiantoken.Symmetric,
		"your-32-byte-secret-key-1234567890abcdef",
		"", "",
		30*time.Second, // Short access token for demo
		5*time.Minute,
		"auth.example.com",
		nil,
		[]string{"HS256"},
		nil,
		2*time.Minute,
		10*time.Minute,
		15*time.Second,
		true,
	)

	maker, err := utils.CreateTokenMaker(config, true)
	if err != nil {
		utils.PrintError("Initialization failed", err)
		return
	}

	userID, username, sessionID := utils.CreateTestUser()

	utils.PrintSection("Initial Token Creation")
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

	utils.PrintTokenDetails("Initial Access Token", accessToken)
	utils.PrintTokenDetails("Initial Refresh Token", refreshToken)

	utils.SimulateAPICall(accessToken.Token)
	utils.SimulateTokenExpiration(35 * time.Second)

	utils.PrintSection("Token Rotation")
	newRefreshToken, err := maker.RotateRefreshToken(refreshToken.Token)
	if err != nil {
		utils.PrintError("Rotation failed", err)
		return
	}

	utils.PrintTokenDetails("New Refresh Token", newRefreshToken)

	utils.PrintSection("Security Validation")
	_, err = maker.RotateRefreshToken(refreshToken.Token)
	utils.VerifyError("Old token rejection", err, "should reject old token")
}
