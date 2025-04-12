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
		utils.PrintError("Token maker creation failed", err)
		return
	}

	userID, username, sessionID := utils.CreateTestUser()

	utils.PrintSection("Creating RSA Token")
	tokenResp, err := maker.CreateAccessToken(context.Background(),
		userID,
		username,
		[]string{"user"},
		sessionID,
	)
	if err != nil {
		utils.PrintError("Token creation failed", err)
		return
	}

	utils.PrintSection("Verifying RSA Token")
	claims, err := maker.VerifyAccessToken(context.Background(), tokenResp.Token)
	if err != nil {
		utils.PrintError("Token verification failed", err)
		return
	}

	utils.PrintTokenDetails("RSA Token", tokenResp)
	utils.PrintClaims(claims)
}
