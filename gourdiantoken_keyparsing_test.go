// gourdiantoken_keyparsing_test.go
package gourdiantoken

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestKeyParsingEdgeCases(t *testing.T) {
	t.Run("Invalid PEM Block", func(t *testing.T) {
		invalidPEM := []byte("-----BEGIN INVALID-----\ninvalid data\n-----END INVALID-----")
		_, err := parseRSAPrivateKey(invalidPEM)
		require.Error(t, err)
	})

	t.Run("Corrupted RSA Private Key", func(t *testing.T) {
		// Generate a valid key first
		privKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		// Marshal to PKCS1
		privBytes := x509.MarshalPKCS1PrivateKey(privKey)

		// Corrupt the key data
		privBytes[10] ^= 0xFF // Flip some bits

		block := &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: privBytes,
		}

		_, err = parseRSAPrivateKey(pem.EncodeToMemory(block))
		require.Error(t, err)
	})

	t.Run("Ed25519 Key Parsing", func(t *testing.T) {
		pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		// Test private key parsing
		privBytes, err := x509.MarshalPKCS8PrivateKey(privKey)
		require.NoError(t, err)

		privBlock := &pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: privBytes,
		}

		parsedPriv, err := parseEdDSAPrivateKey(pem.EncodeToMemory(privBlock))
		require.NoError(t, err)
		require.Equal(t, privKey, parsedPriv)

		// Test public key parsing
		pubBytes, err := x509.MarshalPKIXPublicKey(pubKey)
		require.NoError(t, err)

		pubBlock := &pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: pubBytes,
		}

		parsedPub, err := parseEdDSAPublicKey(pem.EncodeToMemory(pubBlock))
		require.NoError(t, err)
		require.Equal(t, pubKey, parsedPub)
	})

	t.Run("Invalid EC Curve", func(t *testing.T) {
		// Generate key with unsupported curve
		privKey, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
		require.NoError(t, err)

		privBytes, err := x509.MarshalECPrivateKey(privKey)
		require.NoError(t, err)

		block := &pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: privBytes,
		}

		// Should still parse even though curve isn't typically used with JWT
		_, err = parseECDSAPrivateKey(pem.EncodeToMemory(block))
		require.NoError(t, err)
	})

	t.Run("File Permission Checks", func(t *testing.T) {
		// Create a temp file with insecure permissions
		tempFile := filepath.Join(t.TempDir(), "insecure.key")
		err := os.WriteFile(tempFile, []byte("test data"), 0666)
		require.NoError(t, err)

		err = checkFilePermissions(tempFile, 0600)
		require.Error(t, err)
		// Check for any permission-related error, not exact message
		require.Contains(t, err.Error(), "permissions")
	})
}

func TestNewGourdianTokenMaker_InvalidConfigs(t *testing.T) {
	tests := []struct {
		name    string
		config  GourdianTokenConfig
		wantErr bool
	}{
		{
			name: "Invalid Algorithm",
			config: GourdianTokenConfig{
				SigningMethod: Symmetric,
				Algorithm:     "INVALID",
				SymmetricKey:  "12345678901234567890123456789012",
			},
			wantErr: true,
		},
		{
			name: "Asymmetric with missing keys",
			config: GourdianTokenConfig{
				SigningMethod: Asymmetric,
				Algorithm:     "RS256",
			},
			wantErr: true,
		},
		// Add more invalid config cases
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewGourdianTokenMaker(context.Background(), tt.config, nil)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewGourdianTokenMaker() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestCreateAccessToken_InvalidInputs(t *testing.T) {
	maker, _ := DefaultGourdianTokenMaker(context.Background(), "test-key-123456789012345678901234", nil)

	tests := []struct {
		name      string
		userID    uuid.UUID
		username  string
		roles     []string
		sessionID uuid.UUID
		wantErr   bool
	}{
		{"Nil UserID", uuid.Nil, "user1", []string{"admin"}, uuid.New(), true},
		{"Empty Roles", uuid.New(), "user1", []string{}, uuid.New(), true},
		{"Long Username", uuid.New(), strings.Repeat("a", 1025), []string{"admin"}, uuid.New(), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := maker.CreateAccessToken(context.Background(), tt.userID, tt.username, tt.roles, tt.sessionID)
			if (err != nil) != tt.wantErr {
				t.Errorf("CreateAccessToken() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestRevocationFlow(t *testing.T) {
	config := DefaultGourdianTokenConfig("test-key-123456789012345678901234")
	config.RevocationEnabled = true

	maker, _ := NewGourdianTokenMaker(context.Background(), config, testRedisOptions())

	// Create and verify token
	token, _ := maker.CreateAccessToken(context.Background(), uuid.New(), "user1", []string{"admin"}, uuid.New())
	_, err := maker.VerifyAccessToken(context.Background(), token.Token)
	require.NoError(t, err)

	// Revoke token
	err = maker.RevokeAccessToken(context.Background(), token.Token)
	require.NoError(t, err)

	// Verify revoked token
	_, err = maker.VerifyAccessToken(context.Background(), token.Token)
	require.Error(t, err)
	require.Contains(t, err.Error(), "revoked")
}

func TestKeyParsingErrors(t *testing.T) {
	// Test invalid PEM data
	_, err := parseRSAPrivateKey([]byte("not a pem"))
	require.Error(t, err)

	// Test invalid key type
	_, err = parseECDSAPublicKey([]byte("-----BEGIN PUBLIC KEY-----\ninvalid\n-----END PUBLIC KEY-----"))
	require.Error(t, err)
}

func TestInvalidConfig(t *testing.T) {
	// Test invalid symmetric key length
	cfg := DefaultGourdianTokenConfig("shortkey")
	err := validateConfig(&cfg)
	require.Error(t, err)

	// Test asymmetric config without key paths
	cfg = GourdianTokenConfig{SigningMethod: Asymmetric}
	err = validateConfig(&cfg)
	require.Error(t, err)
}
