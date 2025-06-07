// File: gourdiantoken_integration_test.go

package gourdiantoken

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestFullTokenLifecycle_Symmetric(t *testing.T) {
	config := DefaultGourdianTokenConfig(testSymmetricKey)
	config.RevocationEnabled = true
	config.RotationEnabled = true

	maker, err := NewGourdianTokenMaker(context.Background(), config, testRedisClient())
	require.NoError(t, err)

	// Create test data
	userID := uuid.New()
	username := "testuser"
	roles := []string{"admin", "user"}
	sessionID := uuid.New()

	// Step 1: Create access token
	accessToken, err := maker.CreateAccessToken(context.Background(), userID, username, roles, sessionID)
	require.NoError(t, err)
	require.NotEmpty(t, accessToken.Token)

	// Step 2: Verify access token
	accessClaims, err := maker.VerifyAccessToken(context.Background(), accessToken.Token)
	require.NoError(t, err)
	require.Equal(t, userID, accessClaims.Subject)
	require.Equal(t, username, accessClaims.Username)
	require.Equal(t, sessionID, accessClaims.SessionID)
	require.Equal(t, roles, accessClaims.Roles)

	// Step 3: Create refresh token
	refreshToken, err := maker.CreateRefreshToken(context.Background(), userID, username, sessionID)
	require.NoError(t, err)
	require.NotEmpty(t, refreshToken.Token)

	// Step 4: Verify refresh token
	refreshClaims, err := maker.VerifyRefreshToken(context.Background(), refreshToken.Token)
	require.NoError(t, err)
	require.Equal(t, userID, refreshClaims.Subject)
	require.Equal(t, username, refreshClaims.Username)
	require.Equal(t, sessionID, refreshClaims.SessionID)

	// Step 5: Rotate refresh token
	newRefreshToken, err := maker.RotateRefreshToken(context.Background(), refreshToken.Token)
	require.NoError(t, err)
	require.NotEmpty(t, newRefreshToken.Token)

	// Step 6: Verify rotated refresh token can't be reused immediately
	_, err = maker.RotateRefreshToken(context.Background(), refreshToken.Token)
	require.Error(t, err)
	require.Contains(t, err.Error(), "token reused too soon")

	// Step 7: Revoke access token
	err = maker.RevokeAccessToken(context.Background(), accessToken.Token)
	require.NoError(t, err)

	// Step 8: Verify revoked access token can't be used
	_, err = maker.VerifyAccessToken(context.Background(), accessToken.Token)
	require.Error(t, err)
	require.Contains(t, err.Error(), "token has been revoked")

	// Step 9: Create new access token with rotated refresh token
	newAccessToken, err := maker.CreateAccessToken(context.Background(), userID, username, roles, sessionID)
	require.NoError(t, err)

	// Step 10: Verify new access token
	_, err = maker.VerifyAccessToken(context.Background(), newAccessToken.Token)
	require.NoError(t, err)
}

func TestFullTokenLifecycle_Asymmetric(t *testing.T) {
	// Generate RSA key pair
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	privBytes := x509.MarshalPKCS1PrivateKey(privKey)
	privBlock := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes}
	privPath := filepath.Join(t.TempDir(), "rsa.key")
	require.NoError(t, os.WriteFile(privPath, pem.EncodeToMemory(privBlock), 0600))

	pubBytes, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	require.NoError(t, err)
	pubBlock := &pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes}
	pubPath := filepath.Join(t.TempDir(), "rsa.pub")
	require.NoError(t, os.WriteFile(pubPath, pem.EncodeToMemory(pubBlock), 0644))

	config := GourdianTokenConfig{
		SigningMethod:            Asymmetric,
		Algorithm:                "RS256",
		PrivateKeyPath:           privPath,
		PublicKeyPath:            pubPath,
		Issuer:                   "test-issuer",
		Audience:                 []string{"test-audience"},
		RotationEnabled:          true,
		RevocationEnabled:        true,
		AccessExpiryDuration:     30 * time.Minute,
		AccessMaxLifetimeExpiry:  24 * time.Hour,
		RefreshExpiryDuration:    7 * 24 * time.Hour,
		RefreshMaxLifetimeExpiry: 30 * 24 * time.Hour,
		RefreshReuseInterval:     5 * time.Minute,
	}

	maker, err := NewGourdianTokenMaker(context.Background(), config, testRedisClient())
	require.NoError(t, err)

	// Create test data
	userID := uuid.New()
	username := "testuser"
	roles := []string{"admin", "user"}
	sessionID := uuid.New()

	// Step 1: Create access token
	accessToken, err := maker.CreateAccessToken(context.Background(), userID, username, roles, sessionID)
	require.NoError(t, err)
	require.NotEmpty(t, accessToken.Token)

	// Step 2: Verify access token
	accessClaims, err := maker.VerifyAccessToken(context.Background(), accessToken.Token)
	require.NoError(t, err)
	require.Equal(t, userID, accessClaims.Subject)
	require.Equal(t, username, accessClaims.Username)
	require.Equal(t, sessionID, accessClaims.SessionID)
	require.Equal(t, roles, accessClaims.Roles)

	// Step 3: Create refresh token
	refreshToken, err := maker.CreateRefreshToken(context.Background(), userID, username, sessionID)
	require.NoError(t, err)
	require.NotEmpty(t, refreshToken.Token)

	// Step 4: Verify refresh token
	refreshClaims, err := maker.VerifyRefreshToken(context.Background(), refreshToken.Token)
	require.NoError(t, err)
	require.Equal(t, userID, refreshClaims.Subject)
	require.Equal(t, username, refreshClaims.Username)
	require.Equal(t, sessionID, refreshClaims.SessionID)

	// Step 5: Rotate refresh token
	newRefreshToken, err := maker.RotateRefreshToken(context.Background(), refreshToken.Token)
	require.NoError(t, err)
	require.NotEmpty(t, newRefreshToken.Token)

	// Step 6: Verify rotated refresh token can't be reused immediately
	_, err = maker.RotateRefreshToken(context.Background(), refreshToken.Token)
	require.Error(t, err)
	require.Contains(t, err.Error(), "token reused too soon")

	// Step 7: Revoke access token
	err = maker.RevokeAccessToken(context.Background(), accessToken.Token)
	require.NoError(t, err)

	// Step 8: Verify revoked access token can't be used
	_, err = maker.VerifyAccessToken(context.Background(), accessToken.Token)
	require.Error(t, err)
	require.Contains(t, err.Error(), "token has been revoked")
}

// func TestMultipleKeyTypes(t *testing.T) {
// 	tests := []struct {
// 		name      string
// 		algorithm string
// 		keyGen    func() (privPath, pubPath string)
// 	}{
// 		{
// 			name:      "RSA",
// 			algorithm: "RS256",
// 			keyGen: func() (string, string) {
// 				privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
// 				privBytes := x509.MarshalPKCS1PrivateKey(privKey)
// 				privBlock := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes}
// 				privPath := filepath.Join(t.TempDir(), "rsa.key")
// 				require.NoError(t, os.WriteFile(privPath, pem.EncodeToMemory(privBlock), 0600))

// 				pubBytes, _ := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
// 				pubBlock := &pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes}
// 				pubPath := filepath.Join(t.TempDir(), "rsa.pub")
// 				require.NoError(t, os.WriteFile(pubPath, pem.EncodeToMemory(pubBlock), 0644))
// 				return privPath, pubPath
// 			},
// 		},
// 		{
// 			name:      "ECDSA",
// 			algorithm: "ES256",
// 			keyGen: func() (string, string) {
// 				privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
// 				privBytes, _ := x509.MarshalECPrivateKey(privKey)
// 				privBlock := &pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes}
// 				privPath := filepath.Join(t.TempDir(), "ec.key")
// 				require.NoError(t, os.WriteFile(privPath, pem.EncodeToMemory(privBlock), 0600))

// 				pubBytes, _ := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
// 				pubBlock := &pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes}
// 				pubPath := filepath.Join(t.TempDir(), "ec.pub")
// 				require.NoError(t, os.WriteFile(pubPath, pem.EncodeToMemory(pubBlock), 0644))
// 				return privPath, pubPath
// 			},
// 		},
// 		{
// 			name:      "EdDSA",
// 			algorithm: "EdDSA",
// 			keyGen: func() (string, string) {
// 				pubKey, privKey, _ := ed25519.GenerateKey(rand.Reader)
// 				privBytes, _ := x509.MarshalPKCS8PrivateKey(privKey)
// 				privBlock := &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}
// 				privPath := filepath.Join(t.TempDir(), "ed.key")
// 				require.NoError(t, os.WriteFile(privPath, pem.EncodeToMemory(privBlock), 0600))

// 				pubBytes, _ := x509.MarshalPKIXPublicKey(pubKey)
// 				pubBlock := &pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes}
// 				pubPath := filepath.Join(t.TempDir(), "ed.pub")
// 				require.NoError(t, os.WriteFile(pubPath, pem.EncodeToMemory(pubBlock), 0644))
// 				return privPath, pubPath
// 			},
// 		},
// 	}

// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			privPath, pubPath := tt.keyGen()

// 			config := GourdianTokenConfig{
// 				SigningMethod:         Asymmetric,
// 				Algorithm:             tt.algorithm,
// 				PrivateKeyPath:        privPath,
// 				PublicKeyPath:         pubPath,
// 				Issuer:                "test-issuer",
// 				Audience:              []string{"test-audience"},
// 				AccessExpiryDuration:  30 * time.Minute,
// 				RefreshExpiryDuration: 24 * time.Hour,
// 			}

// 			maker, err := NewGourdianTokenMaker(context.Background(), config, nil)
// 			require.NoError(t, err)

// 			// Test token creation and verification
// 			userID := uuid.New()
// 			accessToken, err := maker.CreateAccessToken(context.Background(), userID, "testuser", []string{"admin"}, uuid.New())
// 			require.NoError(t, err)

// 			claims, err := maker.VerifyAccessToken(context.Background(), accessToken.Token)
// 			require.NoError(t, err)
// 			require.Equal(t, userID, claims.Subject)
// 		})
// 	}
// }
