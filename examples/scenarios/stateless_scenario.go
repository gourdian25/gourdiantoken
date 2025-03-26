package scenarios

import (
	"context"
	"fmt"
	"time"

	"github.com/gourdian25/gourdiantoken"
	"github.com/gourdian25/gourdiantoken/examples/utils"
)

func DemonstrateStatelessTokens() {
	utils.PrintHeader("Stateless Token Demonstration")

	config := gourdiantoken.DefaultGourdianTokenConfig(
		"your-32-byte-secret-key-1234567890abcdef",
	)
	config.RefreshToken.RotationEnabled = false
	config.AccessToken.Duration = 1 * time.Hour
	config.RefreshToken.Duration = 24 * time.Hour

	maker, err := utils.CreateTokenMaker(config, false)
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

	utils.PrintSection("Token Verification")
	utils.VerifyToken(maker, accessToken.Token, gourdiantoken.AccessToken)
	utils.VerifyToken(maker, refreshToken.Token, gourdiantoken.RefreshToken)

	utils.PrintSection("Note")
	fmt.Println("Token rotation is disabled in stateless mode")
}
