// scenarios/rsa_pss_example.go
package scenarios

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/gourdian25/gourdiantoken"
	"github.com/gourdian25/gourdiantoken/examples/utils"
)

func RunRSAPSSExample() {
	utils.PrintHeader("RSA-PSS (PS256) Configuration Example")

	// Verify key files exist
	if _, err := os.Stat("examples/keys/rsa_pss_private.pem"); os.IsNotExist(err) {
		log.Fatal("RSA-PSS private key not found at examples/keys/rsa_pss_private.pem")
	}
	if _, err := os.Stat("examples/keys/rsa_pss_public.pem"); os.IsNotExist(err) {
		log.Fatal("RSA-PSS public key not found at examples/keys/rsa_pss_public.pem")
	}

	config := gourdiantoken.GourdianTokenConfig{
		Algorithm:      "PS256",
		SigningMethod:  gourdiantoken.Asymmetric,
		PrivateKeyPath: "examples/keys/rsa_pss_private.pem",
		PublicKeyPath:  "examples/keys/rsa_pss_public.pem",
		AccessToken: gourdiantoken.AccessTokenConfig{
			Duration:          30 * time.Minute,
			MaxLifetime:       24 * time.Hour,
			Issuer:            "rsapss.example.com",
			AllowedAlgorithms: []string{"PS256"}, // Only allow PS256
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
	username := "rsapss.user@example.com"
	sessionID := uuid.New()

	utils.PrintSection("Creating RSA-PSS Signed Tokens")
	accessToken, err := maker.CreateAccessToken(
		context.Background(),
		userID,
		username,
		"admin",
		sessionID,
	)
	if err != nil {
		log.Fatalf("Failed to create access token: %v", err)
	}

	utils.PrintSection("Verifying RSA-PSS Signed Token")
	claims, err := maker.VerifyAccessToken(accessToken.Token)
	if err != nil {
		log.Fatalf("Token verification failed: %v", err)
	}

	fmt.Printf("Successfully verified RSA-PSS signed token for user: %s\n", claims.Username)
	fmt.Printf("Token uses algorithm: %s\n", config.Algorithm)
	fmt.Printf("Token ID: %s\n", claims.ID)
	fmt.Printf("Session ID: %s\n", claims.SessionID)
}
