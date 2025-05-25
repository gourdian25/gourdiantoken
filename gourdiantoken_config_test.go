// File: gourdiantoken_config_test.go

package gourdiantoken

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestConfigValidation(t *testing.T) {
	t.Run("Valid symmetric config", func(t *testing.T) {
		config := GourdianTokenConfig{
			Algorithm:                "HS256",
			SigningMethod:            Symmetric,
			SymmetricKey:             testSymmetricKey,
			AccessExpiryDuration:     time.Hour,
			RefreshExpiryDuration:    time.Hour * 24,
			RefreshMaxLifetimeExpiry: time.Hour * 24 * 30,
		}
		err := validateConfig(&config)
		require.NoError(t, err)
	})

	t.Run("Invalid symmetric key length", func(t *testing.T) {
		config := GourdianTokenConfig{
			Algorithm:     "HS256",
			SigningMethod: Symmetric,
			SymmetricKey:  "too-short",
		}
		err := validateConfig(&config)
		require.Error(t, err)
		require.Contains(t, err.Error(), "symmetric key must be at least 32 bytes")
	})

	t.Run("Valid asymmetric config", func(t *testing.T) {
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

		config := GourdianTokenConfig{
			Algorithm:                "RS256",
			SigningMethod:            Asymmetric,
			PrivateKeyPath:           privatePath,
			PublicKeyPath:            publicPath,
			AccessExpiryDuration:     time.Hour,
			RefreshExpiryDuration:    time.Hour * 24,
			RefreshMaxLifetimeExpiry: time.Hour * 24 * 30,
		}
		err = validateConfig(&config)
		require.NoError(t, err)
	})

	t.Run("Invalid expiry durations", func(t *testing.T) {
		config := GourdianTokenConfig{
			Algorithm:                "HS256",
			SigningMethod:            Symmetric,
			SymmetricKey:             "test-secret-32-bytes-long-1234567890",
			AccessExpiryDuration:     0,              // Invalid
			RefreshExpiryDuration:    -1 * time.Hour, // Invalid
			RefreshMaxLifetimeExpiry: time.Hour,
		}
		err := validateConfig(&config)
		require.Error(t, err)
		require.Contains(t, err.Error(), "must be positive")
	})

	t.Run("Invalid max lifetime", func(t *testing.T) {
		config := GourdianTokenConfig{
			Algorithm:               "HS256",
			SigningMethod:           Symmetric,
			SymmetricKey:            "test-secret-32-bytes-long-1234567890",
			AccessExpiryDuration:    time.Hour * 2,
			AccessMaxLifetimeExpiry: time.Hour, // Less than expiry duration
		}
		err := validateConfig(&config)
		require.Error(t, err)
		require.Contains(t, err.Error(), "exceeds max lifetime")
	})
}
