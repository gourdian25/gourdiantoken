package scenarios

import (
	"context"
	"time"

	"github.com/gourdian25/gourdiantoken"
	"github.com/gourdian25/gourdiantoken/examples/utils"
)

func DemonstrateHighSecurity() {
	utils.PrintHeader("High Security Token Demonstration")

	config := gourdiantoken.GourdianTokenConfig{
		Algorithm:      "ES256",
		SigningMethod:  gourdiantoken.Asymmetric,
		PrivateKeyPath: "examples/keys/ec256_private.pem",
		PublicKeyPath:  "examples/keys/ec256_public.pem",
		AccessToken: gourdiantoken.AccessTokenConfig{
			Duration:          5 * time.Minute,
			MaxLifetime:       30 * time.Minute,
			Issuer:            "highsecurity.example.com",
			Audience:          []string{"api.highsecurity.example.com"},
			AllowedAlgorithms: []string{"ES256"},
			RequiredClaims:    []string{"jti", "sub", "exp", "iat", "typ", "rol", "aud", "iss"},
		},
		RefreshToken: gourdiantoken.RefreshTokenConfig{
			Duration:        30 * time.Minute,
			MaxLifetime:     2 * time.Hour,
			ReuseInterval:   1 * time.Minute,
			RotationEnabled: true,
		},
	}

	maker, err := utils.CreateTokenMaker(config, true)
	if err != nil {
		utils.PrintError("Initialization failed", err)
		return
	}

	userID, username, sessionID := utils.CreateTestUser()

	utils.PrintSection("Token Creation")
	tokenResp, err := maker.CreateAccessToken(context.Background(), userID, username, []string{"user"}, sessionID)
	if err != nil {
		utils.PrintError("Token creation failed", err)
		return
	}

	utils.PrintSection("Strict Verification")
	claims, err := maker.VerifyAccessToken(context.Background(), tokenResp.Token)
	if err != nil {
		utils.PrintError("Verification failed", err)
		return
	}

	utils.PrintTokenDetails("High Security Token", tokenResp)
	utils.PrintClaims(claims)
}
