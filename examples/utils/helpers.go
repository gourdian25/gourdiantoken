// examples/utils/helpers.go
package utils

import (
	"fmt"
	"time"

	"github.com/gourdian25/gourdiantoken"
)

func PrintSection(title string) {
	fmt.Printf("\n» %s\n", title)
}

func PrintHeader(title string) {
	fmt.Printf("\n=== %s ===\n", title)
	fmt.Println("----------------------------------------")
}

func PrintTokenDetails(tokenType string, token interface{}) {
	switch t := token.(type) {
	case *gourdiantoken.AccessTokenResponse:
		fmt.Printf("\n%s Token Details:\n", tokenType)
		fmt.Printf("  Token: %s...\n", t.Token[:20])
		fmt.Printf("  User: %s (%s)\n", t.Username, t.Subject)
		fmt.Printf("  Session: %s\n", t.SessionID)
		fmt.Printf("  Role: %s\n", t.Role)
		fmt.Printf("  Issued: %s\n", t.IssuedAt.Format(time.RFC3339))
		fmt.Printf("  Expires: %s\n", t.ExpiresAt.Format(time.RFC3339))
	case *gourdiantoken.RefreshTokenResponse:
		fmt.Printf("\n%s Token Details:\n", tokenType)
		fmt.Printf("  Token: %s...\n", t.Token[:20])
		fmt.Printf("  User: %s (%s)\n", t.Username, t.Subject)
		fmt.Printf("  Session: %s\n", t.SessionID)
		fmt.Printf("  Issued: %s\n", t.IssuedAt.Format(time.RFC3339))
		fmt.Printf("  Expires: %s\n", t.ExpiresAt.Format(time.RFC3339))
	}
}

func VerifyToken(maker gourdiantoken.GourdianTokenMaker, token string, tokenType gourdiantoken.TokenType) {
	PrintSection("Token Verification")

	var err error
	var claims interface{}
	switch tokenType {
	case gourdiantoken.AccessToken:
		claims, err = maker.VerifyAccessToken(token)
	case gourdiantoken.RefreshToken:
		claims, err = maker.VerifyRefreshToken(token)
	}

	if err != nil {
		fmt.Printf("❌ Token verification failed: %v\n", err)
	} else {
		fmt.Printf("✅ Token verified successfully\n")

		fmt.Printf("%s Token is VALID\n", tokenType)
		PrintTokenDetails("Verified "+string(tokenType)+" Claims", claims)
	}
}

func SimulateAPICall(token string) {
	PrintSection("Simulating API Call")
	fmt.Println("Making request with token:", token[:30]+"...")
	time.Sleep(500 * time.Millisecond)
	fmt.Println("API request successful!")
}
