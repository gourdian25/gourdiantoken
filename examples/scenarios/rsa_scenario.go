package scenarios

import (
	"context"
	"time"

	"github.com/gourdian25/gourdiantoken"
	"github.com/gourdian25/gourdiantoken/examples/utils"
)

func DemonstrateRSATokens() {
	utils.PrintHeader("RSA Token Demonstration")

	config := gourdiantoken.GourdianTokenConfig{
		Algorithm:      "RS256",
		SigningMethod:  gourdiantoken.Asymmetric,
		PrivateKeyPath: "examples/keys/rsa_private.pem",
		PublicKeyPath:  "examples/keys/rsa_public.pem",
		AccessToken: gourdiantoken.AccessTokenConfig{
			Duration:    30 * time.Minute,
			MaxLifetime: 24 * time.Hour,
			Issuer:      "rsa.example.com",
		},
	}

	maker, err := utils.CreateTokenMaker(config, false)
	if err != nil {
		utils.PrintError("Failed to create token maker", err)
		return
	}

	userID, username, sessionID := utils.CreateTestUser()

	// Create and verify token
	utils.PrintSection("Creating RSA Token")
	tokenResp, err := maker.CreateAccessToken(
		context.Background(),
		userID,
		username,
		"user",
		sessionID,
	)
	if err != nil {
		utils.PrintError("Token creation failed", err)
		return
	}

	utils.VerifyToken(maker, tokenResp.Token, gourdiantoken.AccessToken)
}
