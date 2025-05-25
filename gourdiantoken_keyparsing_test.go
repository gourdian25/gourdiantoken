// gourdiantoken_keyparsing_test.go
package gourdiantoken

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

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
		require.Contains(t, err.Error(), "file has permissions")
	})
}
