package scenarios

import (
	"context"
	"fmt"
	"log"

	"github.com/google/uuid"
	"github.com/gourdian25/gourdiantoken"
	"github.com/gourdian25/gourdiantoken/examples/utils"
)

func RunMultiTenantExample() {
	utils.PrintHeader("Multi-Tenant Token Example")

	// Configuration for multi-tenant system
	config := gourdiantoken.DefaultGourdianTokenConfig(
		"your-32-byte-secret-key-1234567890abcdef",
	)
	config.AccessToken.Issuer = "auth.multitenant.example.com"
	config.AccessToken.Audience = []string{"api.tenant1.example.com", "api.tenant2.example.com"}
	config.AccessToken.RequiredClaims = append(config.AccessToken.RequiredClaims, "tenant_id")

	// Initialize token maker
	maker, err := gourdiantoken.NewGourdianTokenMaker(config, nil)
	if err != nil {
		log.Fatalf("Failed to create token maker: %v", err)
	}

	// Create token for tenant 1
	utils.PrintSection("Creating Tenant 1 Token")
	tenant1User := uuid.New()
	tenant1Token, err := maker.CreateAccessToken(
		context.Background(),
		tenant1User,
		"user1@tenant1.example.com",
		"tenant_user",
		uuid.New(),
	)
	if err != nil {
		log.Fatalf("Failed to create tenant 1 token: %v", err)
	}

	// In a real implementation, you would modify the claims before signing
	// For demo purposes, we'll just verify with tenant context
	utils.PrintSection("Verifying Tenant Context")
	claims, err := maker.VerifyAccessToken(tenant1Token.Token)
	if err != nil {
		log.Fatalf("Token verification failed: %v", err)
	}

	// Simulate tenant-specific processing
	fmt.Println("Processing request for tenant:", claims.Username)
	fmt.Println("User role:", claims.Role)
	fmt.Println("Token valid for audiences:", config.AccessToken.Audience)

	// Output token details
	utils.PrintTokenDetails("Tenant 1", tenant1Token)
}
