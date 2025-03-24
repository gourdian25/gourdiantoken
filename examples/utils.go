// examples/utils.go
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/gourdian25/gourdiantoken"
)

func printHeader(title string) {
	fmt.Printf("\n=== %s ===\n", title)
	fmt.Println("----------------------------------------")
}

func printTokenDetails(tokenType string, token interface{}) {
	fmt.Printf("\n%s Token Details:\n", tokenType)
	fmt.Println("----------------------------------------")

	jsonData, err := json.MarshalIndent(token, "", "  ")
	if err != nil {
		log.Printf("Error formatting token: %v", err)
		return
	}
	fmt.Println(string(jsonData))
}

func printSection(title string) {
	fmt.Printf("\n» %s\n", title)
}

func verifyToken(maker gourdiantoken.GourdianTokenMaker, token string, tokenType gourdiantoken.TokenType) {
	printSection("Token Verification")

	var err error
	var claims interface{}

	switch tokenType {
	case gourdiantoken.AccessToken:
		claims, err = maker.VerifyAccessToken(token)
	case gourdiantoken.RefreshToken:
		claims, err = maker.VerifyRefreshToken(token)
	}

	if err != nil {
		log.Printf("Invalid %s token: %v", tokenType, err)
		return
	}

	fmt.Printf("%s Token is VALID\n", tokenType)
	printTokenDetails("Verified "+string(tokenType)+" Claims", claims)
}

func simulateAPICall(token string) {
	printSection("Simulating API Call")
	fmt.Println("Making request with token:", token[:30]+"...")
	time.Sleep(500 * time.Millisecond)
	fmt.Println("API request successful!")
}
