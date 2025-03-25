// scenarios/hmac_example.go
package scenarios

import (
	"context"
	"fmt"
	"log"

	"github.com/google/uuid"
	"github.com/gourdian25/gourdiantoken"
	"github.com/gourdian25/gourdiantoken/examples/utils"
)

func RunHMACExample() {
	utils.PrintHeader("HMAC (HS256) Configuration Example")

	// In production, use a secure random key of at least 32 bytes
	secretKey := "your-32-byte-secret-key-1234567890abcdef"

	config := gourdiantoken.DefaultGourdianTokenConfig(secretKey)
	config.AccessToken.Issuer = "hmac.example.com"

	maker, err := gourdiantoken.NewGourdianTokenMaker(config, nil)
	if err != nil {
		log.Fatalf("Failed to create token maker: %v", err)
	}

	userID := uuid.New()
	username := "hmac.user@example.com"
	sessionID := uuid.New()

	utils.PrintSection("Creating HMAC Signed Tokens")
	accessToken, err := maker.CreateAccessToken(
		context.Background(),
		userID,
		username,
		"user",
		sessionID,
	)
	if err != nil {
		log.Fatalf("Failed to create access token: %v", err)
	}

	utils.PrintSection("Verifying HMAC Signed Token")
	claims, err := maker.VerifyAccessToken(accessToken.Token)
	if err != nil {
		log.Fatalf("Token verification failed: %v", err)
	}

	fmt.Printf("Successfully verified HMAC-signed token for user: %s\n", claims.Username)
	fmt.Printf("Token uses algorithm: %s\n", config.Algorithm)
}
