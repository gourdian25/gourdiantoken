package scenarios

import (
	"context"
	"os"
	"time"

	"github.com/gourdian25/gourdiantoken"
	"github.com/gourdian25/gourdiantoken/examples/utils"
)

func DemonstrateEdDSATokens() {
	utils.PrintHeader("EdDSA Token Demonstration")

	if _, err := os.Stat("examples/keys/ed25519_private.pem"); os.IsNotExist(err) {
		utils.PrintError("Key file missing", err)
		return
	}

	config := gourdiantoken.GourdianTokenConfig{
		Algorithm:      "EdDSA",
		SigningMethod:  gourdiantoken.Asymmetric,
		PrivateKeyPath: "examples/keys/ed25519_private.pem",
		PublicKeyPath:  "examples/keys/ed25519_public.pem",
		AccessToken: gourdiantoken.AccessTokenConfig{
			Duration:    30 * time.Minute,
			MaxLifetime: 24 * time.Hour,
			Issuer:      "eddsa.example.com",
		},
	}

	maker, err := utils.CreateTokenMaker(config, false)
	if err != nil {
		utils.PrintError("Initialization failed", err)
		return
	}

	userID, username, sessionID := utils.CreateTestUser()

	utils.PrintSection("Creating EdDSA Token")
	tokenResp, err := maker.CreateAccessToken(context.Background(), userID, username, "user", sessionID)
	if err != nil {
		utils.PrintError("Token creation failed", err)
		return
	}

	utils.PrintSection("Verifying EdDSA Token")
	claims, err := maker.VerifyAccessToken(tokenResp.Token)
	if err != nil {
		utils.PrintError("Token verification failed", err)
		return
	}

	utils.PrintTokenDetails("EdDSA Token", tokenResp)
	utils.PrintClaims(claims)
}
