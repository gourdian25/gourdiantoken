package scenarios

import (
	"context"
	"time"

	"github.com/gourdian25/gourdiantoken"
	"github.com/gourdian25/gourdiantoken/examples/utils"
)

func DemonstrateRSAPSSTokens() {
	utils.PrintHeader("RSA-PSS Token Demonstration")

	config := gourdiantoken.GourdianTokenConfig{
		Algorithm:      "PS256",
		SigningMethod:  gourdiantoken.Asymmetric,
		PrivateKeyPath: "examples/keys/rsa_pss_private.pem",
		PublicKeyPath:  "examples/keys/rsa_pss_public.pem",
		AccessToken: gourdiantoken.AccessTokenConfig{
			Duration:          30 * time.Minute,
			MaxLifetime:       24 * time.Hour,
			Issuer:            "rsapss.example.com",
			AllowedAlgorithms: []string{"PS256"},
		},
	}

	maker, err := utils.CreateTokenMaker(config, false)
	if err != nil {
		utils.PrintError("Initialization failed", err)
		return
	}

	userID, username, sessionID := utils.CreateTestUser()

	utils.PrintSection("Creating RSA-PSS Token")
	tokenResp, err := maker.CreateAccessToken(context.Background(), userID, username, "admin", sessionID)
	if err != nil {
		utils.PrintError("Token creation failed", err)
		return
	}

	utils.PrintSection("Verifying RSA-PSS Token")
	claims, err := maker.VerifyAccessToken(tokenResp.Token)
	if err != nil {
		utils.PrintError("Token verification failed", err)
		return
	}

	utils.PrintTokenDetails("RSA-PSS Token", tokenResp)
	utils.PrintClaims(claims)
}
