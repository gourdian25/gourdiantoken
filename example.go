package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
	"github.com/gourdian25/gourdiantoken/gourdiantoken"
)

func main() {
	// Example 1: Using symmetric key configuration (HMAC)
	symmetricExample()

	// Example 2: Using asymmetric key configuration (RSA)
	// Uncomment if you have RSA keys available
	asymmetricExample()
}

func symmetricExample() {
	fmt.Println("=== Symmetric Key Example (HMAC) ===")

	// Create a configuration with symmetric key (HMAC)
	config := gourdiantoken.GourdianTokenConfig{
		Algorithm:     "HS256",
		SigningMethod: gourdiantoken.Symmetric,
		SymmetricKey:  "your-very-secure-secret-key-at-least-32-bytes",
		AccessToken: gourdiantoken.AccessTokenConfig{
			Duration:          15 * time.Minute,
			MaxLifetime:       24 * time.Hour,
			Issuer:            "gourdian-example-app",
			Audience:          []string{"web", "mobile"},
			AllowedAlgorithms: []string{"HS256"},
			RequiredClaims:    []string{"sub", "exp", "jti"},
		},
		RefreshToken: gourdiantoken.RefreshTokenConfig{
			Duration:        7 * 24 * time.Hour,
			MaxLifetime:     30 * 24 * time.Hour,
			ReuseInterval:   5 * time.Minute,
			RotationEnabled: true,
			FamilyEnabled:   true,
			MaxPerUser:      5,
		},
	}

	// Create a token maker
	maker, err := gourdiantoken.NewGourdianTokenMaker(config)
	if err != nil {
		log.Fatalf("Failed to create token maker: %v", err)
	}

	// User and session details
	userID := uuid.New()
	username := "john.doe"
	role := "admin"
	sessionID := uuid.New()
	permissions := []string{"read:users", "write:users", "read:reports"}

	// Create an access token
	accessToken, err := createAccessToken(maker, userID, username, role, sessionID, permissions)
	if err != nil {
		log.Fatalf("Failed to create access token: %v", err)
	}

	// Create a refresh token
	refreshToken, err := createRefreshToken(maker, userID, username, sessionID)
	if err != nil {
		log.Fatalf("Failed to create refresh token: %v", err)
	}

	// Verify the tokens
	verifyTokens(maker, accessToken.Token, refreshToken.Token)
}

func asymmetricExample() {
	fmt.Println("=== Asymmetric Key Example (RSA) ===")

	// Create a configuration with asymmetric keys (RSA)
	config := gourdiantoken.GourdianTokenConfig{
		Algorithm:      "RS256",
		SigningMethod:  gourdiantoken.Asymmetric,
		PrivateKeyPath: "keys/rsa_private.pem", // Update with your key path
		PublicKeyPath:  "keys/rsa_public.pem",  // Update with your key path
		AccessToken: gourdiantoken.AccessTokenConfig{
			Duration:          15 * time.Minute,
			MaxLifetime:       24 * time.Hour,
			Issuer:            "gourdian-example-app",
			Audience:          []string{"web", "mobile"},
			AllowedAlgorithms: []string{"RS256"},
			RequiredClaims:    []string{"sub", "exp", "jti"},
		},
		RefreshToken: gourdiantoken.RefreshTokenConfig{
			Duration:        7 * 24 * time.Hour,
			MaxLifetime:     30 * 24 * time.Hour,
			ReuseInterval:   5 * time.Minute,
			RotationEnabled: true,
			FamilyEnabled:   true,
			MaxPerUser:      5,
		},
	}

	// Create a token maker
	maker, err := gourdiantoken.NewGourdianTokenMaker(config)
	if err != nil {
		log.Fatalf("Failed to create token maker: %v", err)
	}

	// User and session details
	userID := uuid.New()
	username := "jane.doe"
	role := "manager"
	sessionID := uuid.New()
	permissions := []string{"read:users", "read:reports"}

	// Create an access token
	accessToken, err := createAccessToken(maker, userID, username, role, sessionID, permissions)
	if err != nil {
		log.Fatalf("Failed to create access token: %v", err)
	}

	// Create a refresh token
	refreshToken, err := createRefreshToken(maker, userID, username, sessionID)
	if err != nil {
		log.Fatalf("Failed to create refresh token: %v", err)
	}

	// Verify the tokens
	verifyTokens(maker, accessToken.Token, refreshToken.Token)
}

// Helper function to create an access token
func createAccessToken(
	maker gourdiantoken.GourdianTokenMaker,
	userID uuid.UUID,
	username, role string,
	sessionID uuid.UUID,
	permissions []string,
) (*gourdiantoken.AccessTokenResponse, error) {
	ctx := context.Background()
	accessToken, err := maker.CreateAccessToken(ctx, userID, username, role, sessionID, permissions)
	if err != nil {
		return nil, fmt.Errorf("failed to create access token: %w", err)
	}

	fmt.Println("Access Token Created:")
	fmt.Printf("  Token: %s...\n", accessToken.Token[:30])
	fmt.Printf("  User ID: %s\n", accessToken.Subject)
	fmt.Printf("  Username: %s\n", accessToken.Username)
	fmt.Printf("  Role: %s\n", accessToken.Role)
	fmt.Printf("  Expires At: %v\n", accessToken.ExpiresAt)
	fmt.Printf("  Permissions: %v\n", accessToken.Permissions)

	return accessToken, nil
}

// Helper function to create a refresh token
func createRefreshToken(
	maker gourdiantoken.GourdianTokenMaker,
	userID uuid.UUID,
	username string,
	sessionID uuid.UUID,
) (*gourdiantoken.RefreshTokenResponse, error) {
	ctx := context.Background()
	refreshToken, err := maker.CreateRefreshToken(ctx, userID, username, sessionID)
	if err != nil {
		return nil, fmt.Errorf("failed to create refresh token: %w", err)
	}

	fmt.Println("Refresh Token Created:")
	fmt.Printf("  Token: %s...\n", refreshToken.Token[:30])
	fmt.Printf("  User ID: %s\n", refreshToken.Subject)
	fmt.Printf("  Username: %s\n", refreshToken.Username)
	fmt.Printf("  Expires At: %v\n", refreshToken.ExpiresAt)

	return refreshToken, nil
}

// Helper function to verify tokens
func verifyTokens(maker gourdiantoken.GourdianTokenMaker, accessTokenStr, refreshTokenStr string) {
	// Verify access token
	accessClaims, err := maker.VerifyAccessToken(accessTokenStr)
	if err != nil {
		fmt.Printf("Access token verification failed: %v\n", err)
	} else {
		fmt.Println("Access Token Verified Successfully:")
		fmt.Printf("  Token ID: %s\n", accessClaims.ID)
		fmt.Printf("  User ID: %s\n", accessClaims.Subject)
		fmt.Printf("  Username: %s\n", accessClaims.Username)
		fmt.Printf("  Role: %s\n", accessClaims.Role)
		fmt.Printf("  Session ID: %s\n", accessClaims.SessionID)
		fmt.Printf("  Issued At: %v\n", accessClaims.IssuedAt)
		fmt.Printf("  Expires At: %v\n", accessClaims.ExpiresAt)
		fmt.Printf("  Permissions: %v\n", accessClaims.Permissions)
	}

	// Verify refresh token
	refreshClaims, err := maker.VerifyRefreshToken(refreshTokenStr)
	if err != nil {
		fmt.Printf("Refresh token verification failed: %v\n", err)
	} else {
		fmt.Println("Refresh Token Verified Successfully:")
		fmt.Printf("  Token ID: %s\n", refreshClaims.ID)
		fmt.Printf("  User ID: %s\n", refreshClaims.Subject)
		fmt.Printf("  Username: %s\n", refreshClaims.Username)
		fmt.Printf("  Session ID: %s\n", refreshClaims.SessionID)
		fmt.Printf("  Issued At: %v\n", refreshClaims.IssuedAt)
		fmt.Printf("  Expires At: %v\n", refreshClaims.ExpiresAt)
	}
}

// This function demonstrates how to handle token refresh
func refreshTokenExample(maker gourdiantoken.GourdianTokenMaker, refreshTokenStr string) {
	fmt.Println("=== Token Refresh Example ===")

	// First verify the refresh token
	refreshClaims, err := maker.VerifyRefreshToken(refreshTokenStr)
	if err != nil {
		log.Fatalf("Invalid refresh token: %v", err)
	}

	// Extract user information from the refresh token
	userID := refreshClaims.Subject
	username := refreshClaims.Username
	sessionID := refreshClaims.SessionID

	// In a real application, you would look up the user's role and permissions from your database
	role := "admin"                                      // This would normally come from your database
	permissions := []string{"read:users", "write:users"} // This would normally come from your database

	ctx := context.Background()

	// Generate a new access token
	newAccessToken, err := maker.CreateAccessToken(ctx, userID, username, role, sessionID, permissions)
	if err != nil {
		log.Fatalf("Failed to create new access token: %v", err)
	}

	// Generate a new refresh token if token rotation is enabled
	// Note: In a real application, you would invalidate the old refresh token in your database
	newRefreshToken, err := maker.CreateRefreshToken(ctx, userID, username, sessionID)
	if err != nil {
		log.Fatalf("Failed to create new refresh token: %v", err)
	}

	fmt.Println("Token Refresh Successful:")
	fmt.Printf("  New Access Token: %s...\n", newAccessToken.Token[:30])
	fmt.Printf("  New Refresh Token: %s...\n", newRefreshToken.Token[:30])
}

// This function demonstrates how to implement token validation middleware for HTTP handlers
func tokenValidationMiddlewareExample() {
	fmt.Println("=== Token Validation Middleware Example ===")
	fmt.Println("// Example of how to implement a token validation middleware")
	fmt.Println(`
func AuthMiddleware(maker gourdiantoken.GourdianTokenMaker) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Extract token from Authorization header
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" || len(strings.Split(authHeader, " ")) != 2 {
				http.Error(w, "Unauthorized: Missing or invalid Authorization header", http.StatusUnauthorized)
				return
			}

			tokenString := strings.Split(authHeader, " ")[1]
			
			// Verify the access token
			claims, err := maker.VerifyAccessToken(tokenString)
			if err != nil {
				http.Error(w, "Unauthorized: Invalid token", http.StatusUnauthorized)
				return
			}
			
			// Add claims to request context for use in handlers
			ctx := context.WithValue(r.Context(), "user_id", claims.Subject)
			ctx = context.WithValue(ctx, "username", claims.Username)
			ctx = context.WithValue(ctx, "role", claims.Role)
			ctx = context.WithValue(ctx, "permissions", claims.Permissions)
			
			// Continue with the next handler
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}`)
}
