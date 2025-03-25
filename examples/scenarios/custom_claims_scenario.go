package scenarios

import (
	"context"

	"github.com/gourdian25/gourdiantoken"
	"github.com/gourdian25/gourdiantoken/examples/utils"
)

func DemonstrateCustomClaims() {
	utils.PrintHeader("Custom Claims Demonstration")

	config := gourdiantoken.DefaultGourdianTokenConfig(
		"your-32-byte-secret-key-1234567890abcdef",
	)
	config.AccessToken.RequiredClaims = append(config.AccessToken.RequiredClaims, "custom_data")

	maker, err := utils.CreateTokenMaker(config, false)
	if err != nil {
		utils.PrintError("Initialization failed", err)
		return
	}

	userID, username, sessionID := utils.CreateTestUser()

	utils.PrintSection("Creating Token with Custom Claims")
	accessToken, err := maker.CreateAccessToken(
		context.Background(),
		userID,
		username,
		"premium_user",
		sessionID,
	)
	if err != nil {
		utils.PrintError("Token creation failed", err)
		return
	}

	utils.PrintSection("Extracting Claims")
	claims, err := maker.VerifyAccessToken(accessToken.Token)
	if err != nil {
		utils.PrintError("Token verification failed", err)
		return
	}

	utils.PrintTokenDetails("Custom Claims Token", accessToken)
	utils.PrintClaims(claims)
}
