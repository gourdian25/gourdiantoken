// scenarios/eddsa_example.go
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

func RunEdDSAExample() {
	utils.PrintHeader("EdDSA (Ed25519) Configuration Example")

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
		RefreshToken: gourdiantoken.RefreshTokenConfig{
			Duration: 24 * time.Hour,
		},
	}

	maker, err := gourdiantoken.NewGourdianTokenMaker(config, nil)
	if err != nil {
		log.Fatalf("Failed to create token maker: %v", err)
	}

	userID := uuid.New()
	username := "eddsa.user@example.com"
	sessionID := uuid.New()

	utils.PrintSection("Creating EdDSA Signed Tokens")
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

	utils.PrintSection("Verifying EdDSA Signed Token")
	claims, err := maker.VerifyAccessToken(accessToken.Token)
	if err != nil {
		log.Fatalf("Token verification failed: %v", err)
	}

	fmt.Printf("Successfully verified EdDSA signed token for user: %s\n", claims.Username)
	fmt.Printf("Token uses algorithm: %s\n", config.Algorithm)
}
