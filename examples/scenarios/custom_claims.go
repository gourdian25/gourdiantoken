package scenarios

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
	"github.com/gourdian25/gourdiantoken"
	"github.com/gourdian25/gourdiantoken/examples/utils"
)

func RunCustomClaimsExample() {
	utils.PrintHeader("Custom Claims Example")

	// Configuration
	config := gourdiantoken.DefaultGourdianTokenConfig(
		"your-32-byte-secret-key-1234567890abcdef",
	)
	config.AccessToken.RequiredClaims = append(config.AccessToken.RequiredClaims, "custom_data")

	// Initialize token maker
	maker, err := gourdiantoken.NewGourdianTokenMaker(config, nil)
	if err != nil {
		log.Fatalf("Failed to create token maker: %v", err)
	}

	// Create token with custom claims
	utils.PrintSection("Creating Token with Custom Claims")
	userID := uuid.New()
	sessionID := uuid.New()

	// In a real implementation, you would extend the AccessTokenClaims struct
	// For this example, we'll use the standard claims and add custom data
	accessToken, err := maker.CreateAccessToken(
		context.Background(),
		userID,
		"custom.user@example.com",
		"premium_user",
		sessionID,
	)
	if err != nil {
		log.Fatalf("Failed to create access token: %v", err)
	}

	// Verify and extract custom claims
	utils.PrintSection("Extracting Custom Claims")
	claims, err := maker.VerifyAccessToken(accessToken.Token)
	if err != nil {
		log.Fatalf("Token verification failed: %v", err)
	}

	// In a real implementation, you would have methods to get custom claims
	fmt.Printf("User %s has role: %s\n", claims.Username, claims.Role)
	fmt.Printf("Session ID: %s\n", claims.SessionID)
	fmt.Printf("Token expires at: %s\n", claims.ExpiresAt.Format(time.RFC3339))

	utils.PrintTokenDetails("Custom Claims Token", accessToken)
}
