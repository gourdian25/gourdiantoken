// File: gourdiantoken_init_test.go

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

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

func TestInitializeSigningMethod(t *testing.T) {
	tests := []struct {
		name      string
		algorithm string
		wantErr   bool
	}{
		{"HS256", "HS256", false},
		{"RS256", "RS256", false},
		{"ES256", "ES256", false},
		{"PS256", "PS256", false},
		{"EdDSA", "EdDSA", false},
		{"Invalid", "INVALID", true},
		{"None", "none", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			maker := &JWTMaker{
				config: GourdianTokenConfig{
					Algorithm: tt.algorithm,
				},
			}
			err := maker.initializeSigningMethod()
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.NotNil(t, maker.signingMethod)
			}
		})
	}
}

func TestInitializeKeys(t *testing.T) {
	t.Run("Symmetric key initialization", func(t *testing.T) {
		maker := &JWTMaker{
			config: GourdianTokenConfig{
				SigningMethod: Symmetric,
				SymmetricKey:  "test-secret-32-bytes-long-1234567890",
			},
			signingMethod: jwt.SigningMethodHS256,
		}
		err := maker.initializeKeys()
		require.NoError(t, err)
		require.NotNil(t, maker.privateKey)
		require.NotNil(t, maker.publicKey)
	})

	t.Run("Asymmetric key initialization", func(t *testing.T) {
		// Generate temp RSA keys
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		privateBytes := x509.MarshalPKCS1PrivateKey(privateKey)
		privateBlock := &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: privateBytes,
		}

		privatePath := filepath.Join(t.TempDir(), "private.pem")
		err = os.WriteFile(privatePath, pem.EncodeToMemory(privateBlock), 0600)
		require.NoError(t, err)

		publicBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
		require.NoError(t, err)
		publicBlock := &pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: publicBytes,
		}

		publicPath := filepath.Join(t.TempDir(), "public.pem")
		err = os.WriteFile(publicPath, pem.EncodeToMemory(publicBlock), 0644)
		require.NoError(t, err)

		maker := &JWTMaker{
			config: GourdianTokenConfig{
				SigningMethod:  Asymmetric,
				Algorithm:      "RS256",
				PrivateKeyPath: privatePath,
				PublicKeyPath:  publicPath,
			},
			signingMethod: jwt.SigningMethodRS256,
		}
		err = maker.initializeKeys()
		require.NoError(t, err)
		require.NotNil(t, maker.privateKey)
		require.NotNil(t, maker.publicKey)
	})

	t.Run("Invalid key paths", func(t *testing.T) {
		maker := &JWTMaker{
			config: GourdianTokenConfig{
				SigningMethod:  Asymmetric,
				Algorithm:      "RS256",
				PrivateKeyPath: "nonexistent_private.pem",
				PublicKeyPath:  "nonexistent_public.pem",
			},
			signingMethod: jwt.SigningMethodRS256,
		}
		err := maker.initializeKeys()
		require.Error(t, err)
	})
}

func TestNewGourdianTokenMaker(t *testing.T) {
	t.Run("Successful creation with symmetric key", func(t *testing.T) {
		maker, err := DefaultGourdianTokenMaker(context.Background(), testSymmetricKey, nil)
		require.NoError(t, err)
		require.NotNil(t, maker)
	})

	t.Run("Failed creation with invalid config", func(t *testing.T) {
		config := GourdianTokenConfig{
			SigningMethod: Symmetric,
			SymmetricKey:  "too-short",
		}
		_, err := NewGourdianTokenMaker(context.Background(), config, nil)
		require.Error(t, err)
	})

	t.Run("Failed creation with cancelled context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := DefaultGourdianTokenMaker(ctx, testSymmetricKey, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "context canceled")
	})
}
