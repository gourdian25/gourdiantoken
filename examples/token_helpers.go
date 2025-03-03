package main

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/gourdian25/gourdiantoken/gourdiantoken"
)

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
