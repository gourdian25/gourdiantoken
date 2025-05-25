// gourdiantoken_validation_test.go
package gourdiantoken

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestInitializeSigningMethod_EdgeCases(t *testing.T) {
	tests := []struct {
		name        string
		algorithm   string
		allowedAlgs []string
		expectedErr string
	}{
		{
			name:        "Unsupported algorithm",
			algorithm:   "INVALID",
			expectedErr: "unsupported algorithm",
		},
		{
			name:        "Algorithm not in allowed list",
			algorithm:   "HS384",
			allowedAlgs: []string{"HS256", "RS256"},
			expectedErr: "configured algorithm HS384 not in allowed algorithms list",
		},
		{
			name:        "Disabled none algorithm",
			algorithm:   "none",
			expectedErr: "unsecured tokens are disabled",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			maker := &JWTMaker{
				config: GourdianTokenConfig{
					Algorithm:         tt.algorithm,
					AllowedAlgorithms: tt.allowedAlgs,
				},
			}

			err := maker.initializeSigningMethod()
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.expectedErr)
		})
	}
}

func TestValidateConfig_EdgeCases(t *testing.T) {
	t.Run("Invalid Symmetric Config with Key Paths", func(t *testing.T) {
		config := GourdianTokenConfig{
			SigningMethod:            Symmetric,
			SymmetricKey:             testSymmetricKey,
			PrivateKeyPath:           "private.key",
			PublicKeyPath:            "public.key",
			Algorithm:                "HS256",
			AccessExpiryDuration:     time.Hour,
			RefreshExpiryDuration:    time.Hour * 24,
			RefreshMaxLifetimeExpiry: time.Hour * 24 * 30,
		}

		err := validateConfig(&config)
		require.Error(t, err)
		require.Contains(t, err.Error(), "private and public key paths must be empty for symmetric signing")
	})

	t.Run("Invalid Asymmetric Config with Symmetric Key", func(t *testing.T) {
		// Create temp key files
		privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
		privBytes := x509.MarshalPKCS1PrivateKey(privKey)
		privBlock := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes}
		privPath := filepath.Join(t.TempDir(), "rsa.key")
		require.NoError(t, os.WriteFile(privPath, pem.EncodeToMemory(privBlock), 0600))

		pubBytes, _ := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
		pubBlock := &pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes}
		pubPath := filepath.Join(t.TempDir(), "rsa.pub")
		require.NoError(t, os.WriteFile(pubPath, pem.EncodeToMemory(pubBlock), 0644))

		config := GourdianTokenConfig{
			SigningMethod:            Asymmetric,
			SymmetricKey:             testSymmetricKey,
			PrivateKeyPath:           privPath,
			PublicKeyPath:            pubPath,
			Algorithm:                "RS256",
			AccessExpiryDuration:     time.Hour,
			RefreshExpiryDuration:    time.Hour * 24,
			RefreshMaxLifetimeExpiry: time.Hour * 24 * 30,
		}

		err := validateConfig(&config)
		require.Error(t, err)
		require.Contains(t, err.Error(), "symmetric key must be empty for asymmetric signing")
	})

}

func TestTokenCreationEdgeCases(t *testing.T) {
	maker, err := DefaultGourdianTokenMaker(context.Background(), testSymmetricKey, nil)
	require.NoError(t, err)

	t.Run("Create Access Token with Empty Roles", func(t *testing.T) {
		_, err := maker.CreateAccessToken(context.Background(), uuid.New(), "user", []string{}, uuid.New())
		require.Error(t, err)
		require.Contains(t, err.Error(), "at least one role must be provided")
	})

	t.Run("Create Access Token with Empty Role String", func(t *testing.T) {
		_, err := maker.CreateAccessToken(context.Background(), uuid.New(), "user", []string{""}, uuid.New())
		require.Error(t, err)
		require.Contains(t, err.Error(), "roles cannot contain empty strings")
	})

	t.Run("Create Refresh Token with Long Username", func(t *testing.T) {
		longUsername := strings.Repeat("a", 1025)
		_, err := maker.CreateRefreshToken(context.Background(), uuid.New(), longUsername, uuid.New())
		require.Error(t, err)
		require.Contains(t, err.Error(), "username too long")
	})
}

func TestValidateTokenClaims_EdgeCases(t *testing.T) {
	now := time.Now()
	validClaims := jwt.MapClaims{
		"jti": uuid.New().String(),
		"sub": uuid.New().String(),
		"usr": "testuser",
		"sid": uuid.New().String(),
		"iss": "test-issuer",
		"aud": []string{"aud1", "aud2"},
		"rls": []string{"admin"},
		"iat": now.Unix(),
		"exp": now.Add(time.Hour).Unix(),
		"nbf": now.Unix(),
		"mle": now.Add(24 * time.Hour).Unix(),
		"typ": string(AccessToken),
	}

	tests := []struct {
		name        string
		modifyFn    func(jwt.MapClaims)
		expectedErr string
	}{
		{
			name: "Missing JTI",
			modifyFn: func(c jwt.MapClaims) {
				delete(c, "jti")
			},
			expectedErr: "missing required claim: jti",
		},
		{
			name: "Invalid JTI format",
			modifyFn: func(c jwt.MapClaims) {
				c["jti"] = "not-a-uuid"
			},
			expectedErr: "invalid token ID",
		},
		// Add other test cases similarly...
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := make(jwt.MapClaims)
			for k, v := range validClaims {
				claims[k] = v
			}
			tt.modifyFn(claims)

			err := validateTokenClaims(claims, AccessToken, []string{"iss", "aud", "nbf", "mle"})
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.expectedErr)
		})
	}
}

func TestInitializeKeys_EdgeCases(t *testing.T) {
	t.Run("Invalid Symmetric Key Length", func(t *testing.T) {
		maker := &JWTMaker{
			config: GourdianTokenConfig{
				SigningMethod: Symmetric,
				SymmetricKey:  "too-short",
				Algorithm:     "HS256",
			},
			signingMethod: jwt.SigningMethodHS256,
		}

		err := maker.initializeKeys()
		require.Error(t, err)
		require.Contains(t, err.Error(), "symmetric key must be at least 32 bytes")
	})

	t.Run("Missing Private Key File", func(t *testing.T) {
		maker := &JWTMaker{
			config: GourdianTokenConfig{
				SigningMethod:  Asymmetric,
				Algorithm:      "RS256",
				PrivateKeyPath: "nonexistent.key",
				PublicKeyPath:  "nonexistent.pub",
			},
			signingMethod: jwt.SigningMethodRS256,
		}

		err := maker.initializeKeys()
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to read private key file")
	})

	t.Run("Invalid Private Key Format", func(t *testing.T) {
		tempDir := t.TempDir()
		invalidKeyPath := filepath.Join(tempDir, "invalid.key")
		require.NoError(t, os.WriteFile(invalidKeyPath, []byte("invalid key data"), 0600))

		maker := &JWTMaker{
			config: GourdianTokenConfig{
				SigningMethod:  Asymmetric,
				Algorithm:      "RS256",
				PrivateKeyPath: invalidKeyPath,
				PublicKeyPath:  "nonexistent.pub", // Still need this even though we'll fail earlier
			},
			signingMethod: jwt.SigningMethodRS256,
		}

		err := maker.initializeKeys()
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to parse RSA private key")
	})
}
