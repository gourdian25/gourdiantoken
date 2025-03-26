package utils

import (
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gourdian25/gourdiantoken"
	"github.com/redis/go-redis/v9"
)

// PrintSection prints a formatted section header
func PrintSection(title string) {
	fmt.Printf("\n» %s\n", title)
}

// PrintHeader prints a formatted main header
func PrintHeader(title string) {
	fmt.Printf("\n=== %s ===\n", title)
	fmt.Println(strings.Repeat("-", len(title)+8))
}

// PrintTokenDetails displays formatted token information
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

// VerifyToken verifies a token and prints the result
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
		PrintTokenDetails("Verified "+string(tokenType), claims)
	}
}

// SimulateAPICall simulates an API call with a token
func SimulateAPICall(token string) {
	PrintSection("Simulating API Call")
	fmt.Println("Making request with token:", token[:30]+"...")
	time.Sleep(500 * time.Millisecond)
	fmt.Println("API request successful!")
}

// GetRedisOptions returns default Redis configuration
func GetRedisOptions() *redis.Options {
	return &redis.Options{
		Addr:     "localhost:6379",
		Password: "GourdianRedisSecret",
		DB:       0,
	}
}

// CreateTestUser generates test user data
func CreateTestUser() (uuid.UUID, string, uuid.UUID) {
	return uuid.New(), "test.user@example.com", uuid.New()
}

// CreateTokenMaker creates a new token maker instance
func CreateTokenMaker(config gourdiantoken.GourdianTokenConfig, useRedis bool) (gourdiantoken.GourdianTokenMaker, error) {
	var redisOpts *redis.Options
	if useRedis {
		redisOpts = GetRedisOptions()
	}
	return gourdiantoken.NewGourdianTokenMaker(config, redisOpts)
}

// PrintError displays an error message with context
func PrintError(context string, err error) {
	fmt.Printf("❌ %s: %v\n", context, err)
}

// VerifyError checks if an error matches expectations
func VerifyError(context string, err error, expected string) {
	if err != nil {
		fmt.Printf("✅ %s (expected: %s)\n", context, expected)
	} else {
		fmt.Printf("❌ %s (expected error but got none)\n", context)
	}
}

// PrintClaims displays detailed claims information
func PrintClaims(claims interface{}) {
	switch c := claims.(type) {
	case *gourdiantoken.AccessTokenClaims:
		fmt.Println("\nAccess Token Claims:")
		fmt.Printf("  ID:        %s\n", c.ID)
		fmt.Printf("  Subject:   %s\n", c.Subject)
		fmt.Printf("  Username:  %s\n", c.Username)
		fmt.Printf("  SessionID: %s\n", c.SessionID)
		fmt.Printf("  Role:      %s\n", c.Role)
		fmt.Printf("  IssuedAt:  %s\n", c.IssuedAt.Format(time.RFC3339))
		fmt.Printf("  ExpiresAt: %s\n", c.ExpiresAt.Format(time.RFC3339))
		fmt.Printf("  TokenType: %s\n", c.TokenType)
	case *gourdiantoken.RefreshTokenClaims:
		fmt.Println("\nRefresh Token Claims:")
		fmt.Printf("  ID:        %s\n", c.ID)
		fmt.Printf("  Subject:   %s\n", c.Subject)
		fmt.Printf("  Username:  %s\n", c.Username)
		fmt.Printf("  SessionID: %s\n", c.SessionID)
		fmt.Printf("  IssuedAt:  %s\n", c.IssuedAt.Format(time.RFC3339))
		fmt.Printf("  ExpiresAt: %s\n", c.ExpiresAt.Format(time.RFC3339))
		fmt.Printf("  TokenType: %s\n", c.TokenType)
	default:
		fmt.Println("Unknown claims type")
	}
}

// SimulateTokenExpiration waits for token expiration
func SimulateTokenExpiration(duration time.Duration) {
	fmt.Printf("Waiting %v for token expiration...\n", duration)
	time.Sleep(duration)
}

// GenerateKeyPair generates a key pair for testing (placeholder)
func GenerateKeyPair(algorithm string) (string, string, error) {
	// This would be implemented to actually generate keys
	// For now just return placeholder paths
	switch algorithm {
	case "RS256":
		return "examples/keys/rsa_private.pem", "examples/keys/rsa_public.pem", nil
	case "ES256":
		return "examples/keys/ec256_private.pem", "examples/keys/ec256_public.pem", nil
	case "EdDSA":
		return "examples/keys/ed25519_private.pem", "examples/keys/ed25519_public.pem", nil
	default:
		return "", "", fmt.Errorf("unsupported algorithm: %s", algorithm)
	}
}
