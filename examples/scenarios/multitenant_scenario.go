package scenarios

import (
	"context"

	"github.com/google/uuid"
	"github.com/gourdian25/gourdiantoken"
	"github.com/gourdian25/gourdiantoken/examples/utils"
)

func DemonstrateMultiTenant() {
	utils.PrintHeader("Multi-Tenant Token Demonstration")

	config := gourdiantoken.DefaultGourdianTokenConfig(
		"your-32-byte-secret-key-1234567890abcdef",
	)
	config.AccessToken.Issuer = "auth.multitenant.example.com"
	config.AccessToken.Audience = []string{"api.tenant1.example.com", "api.tenant2.example.com"}
	config.AccessToken.RequiredClaims = append(config.AccessToken.RequiredClaims, "tenant_id")

	maker, err := utils.CreateTokenMaker(config, false)
	if err != nil {
		utils.PrintError("Initialization failed", err)
		return
	}

	utils.PrintSection("Creating Tenant Token")
	tenant1User := uuid.New()
	tenant1Token, err := maker.CreateAccessToken(
		context.Background(),
		tenant1User,
		"user1@tenant1.example.com",
		"tenant_user",
		uuid.New(),
	)
	if err != nil {
		utils.PrintError("Token creation failed", err)
		return
	}

	utils.PrintSection("Verifying Tenant Context")
	claims, err := maker.VerifyAccessToken(tenant1Token.Token)
	if err != nil {
		utils.PrintError("Token verification failed", err)
		return
	}

	utils.PrintTokenDetails("Tenant Token", tenant1Token)
	utils.PrintClaims(claims)
}
