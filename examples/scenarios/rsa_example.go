// scenarios/rsa_example.go
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

func RunRSAExample() {
	utils.PrintHeader("RSA (RS256) Configuration Example")

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
		RefreshToken: gourdiantoken.RefreshTokenConfig{
			Duration: 24 * time.Hour,
		},
	}

	maker, err := gourdiantoken.NewGourdianTokenMaker(config, nil)
	if err != nil {
		log.Fatalf("Failed to create token maker: %v", err)
	}

	userID := uuid.New()
	username := "rsa.user@example.com"
	sessionID := uuid.New()

	utils.PrintSection("Creating RSA Signed Tokens")
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

	utils.PrintSection("Verifying RSA Signed Token")
	claims, err := maker.VerifyAccessToken(accessToken.Token)
	if err != nil {
		log.Fatalf("Token verification failed: %v", err)
	}

	fmt.Printf("Successfully verified RSA-signed token for user: %s\n", claims.Username)
	fmt.Printf("Token ID: %s\n", claims.ID)
	fmt.Printf("Role: %s\n", claims.Role)
}
