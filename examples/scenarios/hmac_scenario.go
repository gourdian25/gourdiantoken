package scenarios

import (
	"context"

	"github.com/gourdian25/gourdiantoken"
	"github.com/gourdian25/gourdiantoken/examples/utils"
)

func DemonstrateHMACTokens() {
	utils.PrintHeader("HMAC Token Demonstration")

	config := gourdiantoken.DefaultGourdianTokenConfig(
		"your-32-byte-secret-key-1234567890abcdef",
	)
	config.AccessToken.Issuer = "hmac.example.com"

	maker, err := utils.CreateTokenMaker(config, false)
	if err != nil {
		utils.PrintError("Initialization failed", err)
		return
	}

	userID, username, sessionID := utils.CreateTestUser()

	utils.PrintSection("Creating HMAC Token")
	tokenResp, err := maker.CreateAccessToken(context.Background(), userID, username, []string{"user"}, sessionID)
	if err != nil {
		utils.PrintError("Token creation failed", err)
		return
	}

	utils.PrintSection("Verifying HMAC Token")
	claims, err := maker.VerifyAccessToken(tokenResp.Token)
	if err != nil {
		utils.PrintError("Token verification failed", err)
		return
	}

	utils.PrintTokenDetails("HMAC Token", tokenResp)
	utils.PrintClaims(claims)
}
