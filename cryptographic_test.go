// File: cryptographic_test.go

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
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Key Management Tests
// =============================================================================

func TestInitializeSigningMethod_Symmetric(t *testing.T) {
	t.Run("HS256 algorithm", func(t *testing.T) {
		config := DefaultTestConfig()
		config.Algorithm = "HS256"
		config.SigningMethod = Symmetric

		maker := setupTestMakerWithConfig(t, config, nil)
		require.NotNil(t, maker)
		assert.Equal(t, "HS256", maker.signingMethod.Alg())
	})

	t.Run("HS384 algorithm", func(t *testing.T) {
		config := DefaultTestConfig()
		config.Algorithm = "HS384"
		config.SigningMethod = Symmetric

		maker := setupTestMakerWithConfig(t, config, nil)
		require.NotNil(t, maker)
		assert.Equal(t, "HS384", maker.signingMethod.Alg())
	})

	t.Run("HS512 algorithm", func(t *testing.T) {
		config := DefaultTestConfig()
		config.Algorithm = "HS512"
		config.SigningMethod = Symmetric

		maker := setupTestMakerWithConfig(t, config, nil)
		require.NotNil(t, maker)
		assert.Equal(t, "HS512", maker.signingMethod.Alg())
	})

	t.Run("rejects algorithm not in allowed list", func(t *testing.T) {
		config := DefaultTestConfig()
		config.Algorithm = "HS384"
		config.AllowedAlgorithms = []string{"HS256", "HS512"} // HS384 not allowed

		_, err := NewGourdianTokenMaker(context.Background(), config, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not in allowed algorithms list")
	})

	t.Run("accepts algorithm in allowed list", func(t *testing.T) {
		config := DefaultTestConfig()
		config.Algorithm = "HS384"
		config.AllowedAlgorithms = []string{"HS256", "HS384", "HS512"}

		maker, err := NewGourdianTokenMaker(context.Background(), config, nil)
		assert.NoError(t, err)
		assert.NotNil(t, maker)
	})

	t.Run("rejects 'none' algorithm", func(t *testing.T) {
		config := DefaultTestConfig()
		config.Algorithm = "none"

		_, err := NewGourdianTokenMaker(context.Background(), config, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "algorithm none is too weak for production use")
	})

	t.Run("rejects unsupported algorithm", func(t *testing.T) {
		config := DefaultTestConfig()
		config.Algorithm = "UNSUPPORTED256"

		_, err := NewGourdianTokenMaker(context.Background(), config, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "algorithm UNSUPPORTED256 not compatible with symmetric signing")
	})
}

func TestInitializeSigningMethod_Asymmetric(t *testing.T) {
	tempDir := t.TempDir()

	// Helper to generate RSA key pair
	generateRSAKeyPair := func(t *testing.T, bits int) (string, string) {
		privateKey, err := rsa.GenerateKey(rand.Reader, bits)
		require.NoError(t, err)

		// Write private key
		privPath := filepath.Join(tempDir, "rsa_private.pem")
		privFile, err := os.OpenFile(privPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		require.NoError(t, err)
		defer func() {
			if err := privFile.Close(); err != nil {
				t.Logf("Warning: failed to close private key file: %v", err)
			}
		}()

		privBytes := x509.MarshalPKCS1PrivateKey(privateKey)
		err = pem.Encode(privFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes})
		require.NoError(t, err)

		// Write public key
		pubPath := filepath.Join(tempDir, "rsa_public.pem")
		pubFile, err := os.OpenFile(pubPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		require.NoError(t, err)
		defer func() {
			if err := pubFile.Close(); err != nil {
				t.Logf("Warning: failed to close public key file: %v", err)
			}
		}()

		pubBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
		require.NoError(t, err)
		err = pem.Encode(pubFile, &pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})
		require.NoError(t, err)

		return privPath, pubPath
	}

	t.Run("RS256 algorithm", func(t *testing.T) {
		privPath, pubPath := generateRSAKeyPair(t, 2048)

		config := DefaultTestConfig()
		config.SigningMethod = Asymmetric
		config.Algorithm = "RS256"
		config.SymmetricKey = ""
		config.PrivateKeyPath = privPath
		config.PublicKeyPath = pubPath

		maker, err := NewGourdianTokenMaker(context.Background(), config, nil)
		require.NoError(t, err)
		assert.NotNil(t, maker)

		jwtMaker := maker.(*JWTMaker)
		assert.Equal(t, "RS256", jwtMaker.signingMethod.Alg())
		assert.IsType(t, &rsa.PrivateKey{}, jwtMaker.privateKey)
		assert.IsType(t, &rsa.PublicKey{}, jwtMaker.publicKey)
	})

	t.Run("RS384 algorithm", func(t *testing.T) {
		privPath, pubPath := generateRSAKeyPair(t, 2048)

		config := DefaultTestConfig()
		config.SigningMethod = Asymmetric
		config.Algorithm = "RS384"
		config.SymmetricKey = ""
		config.PrivateKeyPath = privPath
		config.PublicKeyPath = pubPath

		maker, err := NewGourdianTokenMaker(context.Background(), config, nil)
		require.NoError(t, err)
		assert.Equal(t, "RS384", maker.(*JWTMaker).signingMethod.Alg())
	})

	t.Run("RS512 algorithm", func(t *testing.T) {
		privPath, pubPath := generateRSAKeyPair(t, 2048)

		config := DefaultTestConfig()
		config.SigningMethod = Asymmetric
		config.Algorithm = "RS512"
		config.SymmetricKey = ""
		config.PrivateKeyPath = privPath
		config.PublicKeyPath = pubPath

		maker, err := NewGourdianTokenMaker(context.Background(), config, nil)
		require.NoError(t, err)
		assert.Equal(t, "RS512", maker.(*JWTMaker).signingMethod.Alg())
	})

	t.Run("PS256 algorithm", func(t *testing.T) {
		privPath, pubPath := generateRSAKeyPair(t, 2048)

		config := DefaultTestConfig()
		config.SigningMethod = Asymmetric
		config.Algorithm = "PS256"
		config.SymmetricKey = ""
		config.PrivateKeyPath = privPath
		config.PublicKeyPath = pubPath

		maker, err := NewGourdianTokenMaker(context.Background(), config, nil)
		require.NoError(t, err)
		assert.Equal(t, "PS256", maker.(*JWTMaker).signingMethod.Alg())
	})

	t.Run("PS384 algorithm", func(t *testing.T) {
		privPath, pubPath := generateRSAKeyPair(t, 2048)

		config := DefaultTestConfig()
		config.SigningMethod = Asymmetric
		config.Algorithm = "PS384"
		config.SymmetricKey = ""
		config.PrivateKeyPath = privPath
		config.PublicKeyPath = pubPath

		maker, err := NewGourdianTokenMaker(context.Background(), config, nil)
		require.NoError(t, err)
		assert.Equal(t, "PS384", maker.(*JWTMaker).signingMethod.Alg())
	})

	t.Run("PS512 algorithm", func(t *testing.T) {
		privPath, pubPath := generateRSAKeyPair(t, 2048)

		config := DefaultTestConfig()
		config.SigningMethod = Asymmetric
		config.Algorithm = "PS512"
		config.SymmetricKey = ""
		config.PrivateKeyPath = privPath
		config.PublicKeyPath = pubPath

		maker, err := NewGourdianTokenMaker(context.Background(), config, nil)
		require.NoError(t, err)
		assert.Equal(t, "PS512", maker.(*JWTMaker).signingMethod.Alg())
	})
}

func TestParseKeyPair_RSA(t *testing.T) {
	tempDir := t.TempDir()

	generateAndTestRSA := func(t *testing.T, bits int, keyFormat string) {
		privateKey, err := rsa.GenerateKey(rand.Reader, bits)
		require.NoError(t, err)

		// Write private key in specified format
		privPath := filepath.Join(tempDir, "rsa_private.pem")
		privFile, err := os.OpenFile(privPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		require.NoError(t, err)
		defer func() {
			if err := privFile.Close(); err != nil {
				t.Logf("Warning: failed to close private key file: %v", err)
			}
		}()

		var privBytes []byte
		var blockType string
		if keyFormat == "PKCS1" {
			privBytes = x509.MarshalPKCS1PrivateKey(privateKey)
			blockType = "RSA PRIVATE KEY"
		} else {
			privBytes, err = x509.MarshalPKCS8PrivateKey(privateKey)
			require.NoError(t, err)
			blockType = "PRIVATE KEY"
		}

		err = pem.Encode(privFile, &pem.Block{Type: blockType, Bytes: privBytes})
		require.NoError(t, err)

		// Write public key
		pubPath := filepath.Join(tempDir, "rsa_public.pem")
		pubFile, err := os.OpenFile(pubPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		require.NoError(t, err)
		defer func() {
			if err := pubFile.Close(); err != nil {
				t.Logf("Warning: failed to close public key file: %v", err)
			}
		}()

		pubBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
		require.NoError(t, err)
		err = pem.Encode(pubFile, &pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})
		require.NoError(t, err)

		// Test key parsing
		config := DefaultTestConfig()
		config.SigningMethod = Asymmetric
		config.Algorithm = "RS256"
		config.SymmetricKey = ""
		config.PrivateKeyPath = privPath
		config.PublicKeyPath = pubPath

		maker, err := NewGourdianTokenMaker(context.Background(), config, nil)
		require.NoError(t, err)

		jwtMaker := maker.(*JWTMaker)
		assert.IsType(t, &rsa.PrivateKey{}, jwtMaker.privateKey)
		assert.IsType(t, &rsa.PublicKey{}, jwtMaker.publicKey)

		// Verify key properties
		parsedPriv := jwtMaker.privateKey.(*rsa.PrivateKey)
		assert.Equal(t, bits, parsedPriv.N.BitLen())
	}

	t.Run("PKCS1 format 2048 bits", func(t *testing.T) {
		generateAndTestRSA(t, 2048, "PKCS1")
	})

	t.Run("PKCS8 format 2048 bits", func(t *testing.T) {
		generateAndTestRSA(t, 2048, "PKCS8")
	})

	t.Run("PKCS1 format 4096 bits", func(t *testing.T) {
		generateAndTestRSA(t, 4096, "PKCS1")
	})

	t.Run("PKCS8 format 4096 bits", func(t *testing.T) {
		generateAndTestRSA(t, 4096, "PKCS8")
	})

	t.Run("invalid private key file", func(t *testing.T) {
		privPath := filepath.Join(tempDir, "invalid_private.pem")
		pubPath := filepath.Join(tempDir, "rsa_public.pem")

		// Write invalid PEM
		err := os.WriteFile(privPath, []byte("invalid pem content"), 0600)
		require.NoError(t, err)

		// Create valid public key
		privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
		pubFile, err := os.OpenFile(pubPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		require.NoError(t, err)
		defer func() {
			if err := pubFile.Close(); err != nil {
				t.Logf("Warning: failed to close public key file: %v", err)
			}
		}()

		pubBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
		require.NoError(t, err)
		err = pem.Encode(pubFile, &pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})
		require.NoError(t, err)

		config := DefaultTestConfig()
		config.SigningMethod = Asymmetric
		config.Algorithm = "RS256"
		config.SymmetricKey = ""
		config.PrivateKeyPath = privPath
		config.PublicKeyPath = pubPath

		_, err = NewGourdianTokenMaker(context.Background(), config, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to parse RSA private key")
	})

	t.Run("missing private key file", func(t *testing.T) {
		config := DefaultTestConfig()
		config.SigningMethod = Asymmetric
		config.Algorithm = "RS256"
		config.SymmetricKey = ""
		config.PrivateKeyPath = "/nonexistent/path/private.pem"
		config.PublicKeyPath = "/nonexistent/path/public.pem"

		_, err := NewGourdianTokenMaker(context.Background(), config, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to stat file")
	})
}

func TestParseKeyPair_ECDSA(t *testing.T) {
	tempDir := t.TempDir()

	generateAndTestECDSA := func(t *testing.T, curve elliptic.Curve, alg string) {
		privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
		require.NoError(t, err)

		// Write private key
		privPath := filepath.Join(tempDir, "ecdsa_private.pem")
		privFile, err := os.OpenFile(privPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		require.NoError(t, err)
		defer func() {
			if err := privFile.Close(); err != nil {
				t.Logf("Warning: failed to close private key file: %v", err)
			}
		}()

		privBytes, err := x509.MarshalECPrivateKey(privateKey)
		require.NoError(t, err)
		err = pem.Encode(privFile, &pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes})
		require.NoError(t, err)

		// Write public key
		pubPath := filepath.Join(tempDir, "ecdsa_public.pem")
		pubFile, err := os.OpenFile(pubPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		require.NoError(t, err)
		defer func() {
			if err := pubFile.Close(); err != nil {
				t.Logf("Warning: failed to close public key file: %v", err)
			}
		}()

		pubBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
		require.NoError(t, err)
		err = pem.Encode(pubFile, &pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})
		require.NoError(t, err)

		// Test key parsing
		config := DefaultTestConfig()
		config.SigningMethod = Asymmetric
		config.Algorithm = alg
		config.SymmetricKey = ""
		config.PrivateKeyPath = privPath
		config.PublicKeyPath = pubPath

		maker, err := NewGourdianTokenMaker(context.Background(), config, nil)
		require.NoError(t, err)

		jwtMaker := maker.(*JWTMaker)
		assert.IsType(t, &ecdsa.PrivateKey{}, jwtMaker.privateKey)
		assert.IsType(t, &ecdsa.PublicKey{}, jwtMaker.publicKey)
	}

	t.Run("P256 curve (ES256)", func(t *testing.T) {
		generateAndTestECDSA(t, elliptic.P256(), "ES256")
	})

	t.Run("P384 curve (ES384)", func(t *testing.T) {
		generateAndTestECDSA(t, elliptic.P384(), "ES384")
	})

	t.Run("P521 curve (ES512)", func(t *testing.T) {
		generateAndTestECDSA(t, elliptic.P521(), "ES512")
	})

	t.Run("PKCS8 format", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		privPath := filepath.Join(tempDir, "ecdsa_pkcs8_private.pem")
		privFile, err := os.OpenFile(privPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		require.NoError(t, err)
		defer func() {
			if err := privFile.Close(); err != nil {
				t.Logf("Warning: failed to close private key file: %v", err)
			}
		}()

		privBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
		require.NoError(t, err)
		err = pem.Encode(privFile, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})
		require.NoError(t, err)

		pubPath := filepath.Join(tempDir, "ecdsa_public.pem")
		pubFile, err := os.OpenFile(pubPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		require.NoError(t, err)
		defer func() {
			if err := pubFile.Close(); err != nil {
				t.Logf("Warning: failed to close public key file: %v", err)
			}
		}()

		pubBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
		require.NoError(t, err)
		err = pem.Encode(pubFile, &pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})
		require.NoError(t, err)

		config := DefaultTestConfig()
		config.SigningMethod = Asymmetric
		config.Algorithm = "ES256"
		config.SymmetricKey = ""
		config.PrivateKeyPath = privPath
		config.PublicKeyPath = pubPath

		maker, err := NewGourdianTokenMaker(context.Background(), config, nil)
		require.NoError(t, err)
		assert.NotNil(t, maker)
	})

	t.Run("invalid ECDSA private key", func(t *testing.T) {
		privPath := filepath.Join(tempDir, "invalid_ecdsa.pem")
		pubPath := filepath.Join(tempDir, "ecdsa_public.pem")

		err := os.WriteFile(privPath, []byte("-----BEGIN EC PRIVATE KEY-----\ninvalid\n-----END EC PRIVATE KEY-----"), 0600)
		require.NoError(t, err)

		privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		pubFile, err := os.OpenFile(pubPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		require.NoError(t, err)
		defer func() {
			if err := pubFile.Close(); err != nil {
				t.Logf("Warning: failed to close public key file: %v", err)
			}
		}()

		pubBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
		require.NoError(t, err)
		err = pem.Encode(pubFile, &pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})
		require.NoError(t, err)

		config := DefaultTestConfig()
		config.SigningMethod = Asymmetric
		config.Algorithm = "ES256"
		config.SymmetricKey = ""
		config.PrivateKeyPath = privPath
		config.PublicKeyPath = pubPath

		_, err = NewGourdianTokenMaker(context.Background(), config, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to parse ECDSA private key")
	})
}

func TestParseKeyPair_EdDSA(t *testing.T) {
	tempDir := t.TempDir()

	t.Run("valid EdDSA key pair", func(t *testing.T) {
		publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		// Write private key
		privPath := filepath.Join(tempDir, "eddsa_private.pem")
		privFile, err := os.OpenFile(privPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		require.NoError(t, err)
		defer func() {
			if err := privFile.Close(); err != nil {
				t.Logf("Warning: failed to close private key file: %v", err)
			}
		}()

		privBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
		require.NoError(t, err)
		err = pem.Encode(privFile, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})
		require.NoError(t, err)

		// Write public key
		pubPath := filepath.Join(tempDir, "eddsa_public.pem")
		pubFile, err := os.OpenFile(pubPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		require.NoError(t, err)
		defer func() {
			if err := pubFile.Close(); err != nil {
				t.Logf("Warning: failed to close public key file: %v", err)
			}
		}()

		pubBytes, err := x509.MarshalPKIXPublicKey(publicKey)
		require.NoError(t, err)
		err = pem.Encode(pubFile, &pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})
		require.NoError(t, err)

		// Test key parsing
		config := DefaultTestConfig()
		config.SigningMethod = Asymmetric
		config.Algorithm = "EdDSA"
		config.SymmetricKey = ""
		config.PrivateKeyPath = privPath
		config.PublicKeyPath = pubPath

		maker, err := NewGourdianTokenMaker(context.Background(), config, nil)
		require.NoError(t, err)

		jwtMaker := maker.(*JWTMaker)
		assert.IsType(t, ed25519.PrivateKey{}, jwtMaker.privateKey)
		assert.IsType(t, ed25519.PublicKey{}, jwtMaker.publicKey)
	})

	t.Run("invalid EdDSA private key", func(t *testing.T) {
		privPath := filepath.Join(tempDir, "invalid_eddsa.pem")
		pubPath := filepath.Join(tempDir, "eddsa_public.pem")

		err := os.WriteFile(privPath, []byte("-----BEGIN PRIVATE KEY-----\ninvalid\n-----END PRIVATE KEY-----"), 0600)
		require.NoError(t, err)

		publicKey, _, _ := ed25519.GenerateKey(rand.Reader)
		pubFile, err := os.OpenFile(pubPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		require.NoError(t, err)
		defer func() {
			if err := pubFile.Close(); err != nil {
				t.Logf("Warning: failed to close public key file: %v", err)
			}
		}()

		pubBytes, err := x509.MarshalPKIXPublicKey(publicKey)
		require.NoError(t, err)
		err = pem.Encode(pubFile, &pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})
		require.NoError(t, err)

		config := DefaultTestConfig()
		config.SigningMethod = Asymmetric
		config.Algorithm = "EdDSA"
		config.SymmetricKey = ""
		config.PrivateKeyPath = privPath
		config.PublicKeyPath = pubPath

		_, err = NewGourdianTokenMaker(context.Background(), config, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to parse EdDSA private key")
	})
}

func TestParseKeyPair_Invalid(t *testing.T) {
	tempDir := t.TempDir()

	t.Run("mismatched key types", func(t *testing.T) {
		// RSA private key
		rsaPrivKey, _ := rsa.GenerateKey(rand.Reader, 2048)
		privPath := filepath.Join(tempDir, "rsa_private.pem")
		privFile, err := os.OpenFile(privPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		require.NoError(t, err)
		defer func() {
			if err := privFile.Close(); err != nil {
				t.Logf("Warning: failed to close private key file: %v", err)
			}
		}()

		privBytes := x509.MarshalPKCS1PrivateKey(rsaPrivKey)
		err = pem.Encode(privFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes})
		require.NoError(t, err)

		// ECDSA public key
		ecdsaPrivKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		pubPath := filepath.Join(tempDir, "ecdsa_public.pem")
		pubFile, err := os.OpenFile(pubPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		require.NoError(t, err)
		defer func() {
			if err := pubFile.Close(); err != nil {
				t.Logf("Warning: failed to close public key file: %v", err)
			}
		}()

		pubBytes, err := x509.MarshalPKIXPublicKey(&ecdsaPrivKey.PublicKey)
		require.NoError(t, err)
		err = pem.Encode(pubFile, &pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})
		require.NoError(t, err)

		config := DefaultTestConfig()
		config.SigningMethod = Asymmetric
		config.Algorithm = "RS256"
		config.SymmetricKey = ""
		config.PrivateKeyPath = privPath
		config.PublicKeyPath = pubPath

		_, err = NewGourdianTokenMaker(context.Background(), config, nil)
		assert.Error(t, err)
	})

	t.Run("corrupted PEM block", func(t *testing.T) {
		privPath := filepath.Join(tempDir, "corrupted.pem")
		err := os.WriteFile(privPath, []byte("not a valid pem file"), 0600)
		require.NoError(t, err)

		config := DefaultTestConfig()
		config.SigningMethod = Asymmetric
		config.Algorithm = "RS256"
		config.SymmetricKey = ""
		config.PrivateKeyPath = privPath
		config.PublicKeyPath = privPath

		_, err = NewGourdianTokenMaker(context.Background(), config, nil)
		assert.Error(t, err)
	})

	t.Run("empty file", func(t *testing.T) {
		privPath := filepath.Join(tempDir, "empty.pem")
		err := os.WriteFile(privPath, []byte(""), 0600)
		require.NoError(t, err)

		config := DefaultTestConfig()
		config.SigningMethod = Asymmetric
		config.Algorithm = "RS256"
		config.SymmetricKey = ""
		config.PrivateKeyPath = privPath
		config.PublicKeyPath = privPath

		_, err = NewGourdianTokenMaker(context.Background(), config, nil)
		assert.Error(t, err)
	})
}

// =============================================================================
// Algorithm Tests
// =============================================================================

func TestAllSupportedAlgorithms(t *testing.T) {
	tempDir := t.TempDir()

	algorithms := []struct {
		name      string
		algorithm string
		method    SigningMethod
		setup     func() (string, string)
	}{
		{
			name:      "HS256",
			algorithm: "HS256",
			method:    Symmetric,
			setup: func() (string, string) {
				return "test-secret-key-that-is-at-least-32-bytes-long", ""
			},
		},
		{
			name:      "HS384",
			algorithm: "HS384",
			method:    Symmetric,
			setup: func() (string, string) {
				return "test-secret-key-that-is-at-least-32-bytes-long", ""
			},
		},
		{
			name:      "HS512",
			algorithm: "HS512",
			method:    Symmetric,
			setup: func() (string, string) {
				return "test-secret-key-that-is-at-least-32-bytes-long", ""
			},
		},
		{
			name:      "RS256",
			algorithm: "RS256",
			method:    Asymmetric,
			setup: func() (string, string) {
				privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
				privPath := filepath.Join(tempDir, "rs256_private.pem")
				pubPath := filepath.Join(tempDir, "rs256_public.pem")

				privFile, err := os.OpenFile(privPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
				require.NoError(t, err)
				defer func() {
					if err := privFile.Close(); err != nil {
						t.Logf("Warning: failed to close private key file: %v", err)
					}
				}()

				privBytes := x509.MarshalPKCS1PrivateKey(privateKey)
				err = pem.Encode(privFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes})
				require.NoError(t, err)

				pubFile, err := os.OpenFile(pubPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
				require.NoError(t, err)
				defer func() {
					if err := pubFile.Close(); err != nil {
						t.Logf("Warning: failed to close public key file: %v", err)
					}
				}()

				pubBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
				require.NoError(t, err)
				err = pem.Encode(pubFile, &pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})
				require.NoError(t, err)

				return privPath, pubPath
			},
		},
		{
			name:      "RS384",
			algorithm: "RS384",
			method:    Asymmetric,
			setup: func() (string, string) {
				privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
				privPath := filepath.Join(tempDir, "rs384_private.pem")
				pubPath := filepath.Join(tempDir, "rs384_public.pem")

				privFile, err := os.OpenFile(privPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
				require.NoError(t, err)
				defer func() {
					if err := privFile.Close(); err != nil {
						t.Logf("Warning: failed to close private key file: %v", err)
					}
				}()

				privBytes := x509.MarshalPKCS1PrivateKey(privateKey)
				err = pem.Encode(privFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes})
				require.NoError(t, err)

				pubFile, err := os.OpenFile(pubPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
				require.NoError(t, err)
				defer func() {
					if err := pubFile.Close(); err != nil {
						t.Logf("Warning: failed to close public key file: %v", err)
					}
				}()

				pubBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
				require.NoError(t, err)
				err = pem.Encode(pubFile, &pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})
				require.NoError(t, err)

				return privPath, pubPath
			},
		},
		{
			name:      "RS512",
			algorithm: "RS512",
			method:    Asymmetric,
			setup: func() (string, string) {
				privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
				privPath := filepath.Join(tempDir, "rs512_private.pem")
				pubPath := filepath.Join(tempDir, "rs512_public.pem")

				privFile, err := os.OpenFile(privPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
				require.NoError(t, err)
				defer func() {
					if err := privFile.Close(); err != nil {
						t.Logf("Warning: failed to close private key file: %v", err)
					}
				}()

				privBytes := x509.MarshalPKCS1PrivateKey(privateKey)
				err = pem.Encode(privFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes})
				require.NoError(t, err)

				pubFile, err := os.OpenFile(pubPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
				require.NoError(t, err)
				defer func() {
					if err := pubFile.Close(); err != nil {
						t.Logf("Warning: failed to close public key file: %v", err)
					}
				}()

				pubBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
				require.NoError(t, err)
				err = pem.Encode(pubFile, &pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})
				require.NoError(t, err)

				return privPath, pubPath
			},
		},
		{
			name:      "PS256",
			algorithm: "PS256",
			method:    Asymmetric,
			setup: func() (string, string) {
				privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
				privPath := filepath.Join(tempDir, "ps256_private.pem")
				pubPath := filepath.Join(tempDir, "ps256_public.pem")

				privFile, err := os.OpenFile(privPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
				require.NoError(t, err)
				defer func() {
					if err := privFile.Close(); err != nil {
						t.Logf("Warning: failed to close private key file: %v", err)
					}
				}()

				privBytes := x509.MarshalPKCS1PrivateKey(privateKey)
				err = pem.Encode(privFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes})
				require.NoError(t, err)

				pubFile, err := os.OpenFile(pubPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
				require.NoError(t, err)
				defer func() {
					if err := pubFile.Close(); err != nil {
						t.Logf("Warning: failed to close public key file: %v", err)
					}
				}()

				pubBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
				require.NoError(t, err)
				err = pem.Encode(pubFile, &pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})
				require.NoError(t, err)

				return privPath, pubPath
			},
		},
		{
			name:      "PS384",
			algorithm: "PS384",
			method:    Asymmetric,
			setup: func() (string, string) {
				privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
				privPath := filepath.Join(tempDir, "ps384_private.pem")
				pubPath := filepath.Join(tempDir, "ps384_public.pem")

				privFile, err := os.OpenFile(privPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
				require.NoError(t, err)
				defer func() {
					if err := privFile.Close(); err != nil {
						t.Logf("Warning: failed to close private key file: %v", err)
					}
				}()

				privBytes := x509.MarshalPKCS1PrivateKey(privateKey)
				err = pem.Encode(privFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes})
				require.NoError(t, err)

				pubFile, err := os.OpenFile(pubPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
				require.NoError(t, err)
				defer func() {
					if err := pubFile.Close(); err != nil {
						t.Logf("Warning: failed to close public key file: %v", err)
					}
				}()

				pubBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
				require.NoError(t, err)
				err = pem.Encode(pubFile, &pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})
				require.NoError(t, err)

				return privPath, pubPath
			},
		},
		{
			name:      "PS512",
			algorithm: "PS512",
			method:    Asymmetric,
			setup: func() (string, string) {
				privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
				privPath := filepath.Join(tempDir, "ps512_private.pem")
				pubPath := filepath.Join(tempDir, "ps512_public.pem")

				privFile, err := os.OpenFile(privPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
				require.NoError(t, err)
				defer func() {
					if err := privFile.Close(); err != nil {
						t.Logf("Warning: failed to close private key file: %v", err)
					}
				}()

				privBytes := x509.MarshalPKCS1PrivateKey(privateKey)
				err = pem.Encode(privFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes})
				require.NoError(t, err)

				pubFile, err := os.OpenFile(pubPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
				require.NoError(t, err)
				defer func() {
					if err := pubFile.Close(); err != nil {
						t.Logf("Warning: failed to close public key file: %v", err)
					}
				}()

				pubBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
				require.NoError(t, err)
				err = pem.Encode(pubFile, &pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})
				require.NoError(t, err)

				return privPath, pubPath
			},
		},
		{
			name:      "ES256",
			algorithm: "ES256",
			method:    Asymmetric,
			setup: func() (string, string) {
				privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				privPath := filepath.Join(tempDir, "es256_private.pem")
				pubPath := filepath.Join(tempDir, "es256_public.pem")

				privFile, err := os.OpenFile(privPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
				require.NoError(t, err)
				defer func() {
					if err := privFile.Close(); err != nil {
						t.Logf("Warning: failed to close private key file: %v", err)
					}
				}()

				privBytes, err := x509.MarshalECPrivateKey(privateKey)
				require.NoError(t, err)
				err = pem.Encode(privFile, &pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes})
				require.NoError(t, err)

				pubFile, err := os.OpenFile(pubPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
				require.NoError(t, err)
				defer func() {
					if err := pubFile.Close(); err != nil {
						t.Logf("Warning: failed to close public key file: %v", err)
					}
				}()

				pubBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
				require.NoError(t, err)
				err = pem.Encode(pubFile, &pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})
				require.NoError(t, err)

				return privPath, pubPath
			},
		},
		{
			name:      "ES384",
			algorithm: "ES384",
			method:    Asymmetric,
			setup: func() (string, string) {
				privateKey, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
				privPath := filepath.Join(tempDir, "es384_private.pem")
				pubPath := filepath.Join(tempDir, "es384_public.pem")

				privFile, err := os.OpenFile(privPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
				require.NoError(t, err)
				defer func() {
					if err := privFile.Close(); err != nil {
						t.Logf("Warning: failed to close private key file: %v", err)
					}
				}()

				privBytes, err := x509.MarshalECPrivateKey(privateKey)
				require.NoError(t, err)
				err = pem.Encode(privFile, &pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes})
				require.NoError(t, err)

				pubFile, err := os.OpenFile(pubPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
				require.NoError(t, err)
				defer func() {
					if err := pubFile.Close(); err != nil {
						t.Logf("Warning: failed to close public key file: %v", err)
					}
				}()

				pubBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
				require.NoError(t, err)
				err = pem.Encode(pubFile, &pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})
				require.NoError(t, err)

				return privPath, pubPath
			},
		},
		{
			name:      "ES512",
			algorithm: "ES512",
			method:    Asymmetric,
			setup: func() (string, string) {
				privateKey, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
				privPath := filepath.Join(tempDir, "es512_private.pem")
				pubPath := filepath.Join(tempDir, "es512_public.pem")

				privFile, err := os.OpenFile(privPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
				require.NoError(t, err)
				defer func() {
					if err := privFile.Close(); err != nil {
						t.Logf("Warning: failed to close private key file: %v", err)
					}
				}()

				privBytes, err := x509.MarshalECPrivateKey(privateKey)
				require.NoError(t, err)
				err = pem.Encode(privFile, &pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes})
				require.NoError(t, err)

				pubFile, err := os.OpenFile(pubPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
				require.NoError(t, err)
				defer func() {
					if err := pubFile.Close(); err != nil {
						t.Logf("Warning: failed to close public key file: %v", err)
					}
				}()

				pubBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
				require.NoError(t, err)
				err = pem.Encode(pubFile, &pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})
				require.NoError(t, err)

				return privPath, pubPath
			},
		},
		{
			name:      "EdDSA",
			algorithm: "EdDSA",
			method:    Asymmetric,
			setup: func() (string, string) {
				publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
				privPath := filepath.Join(tempDir, "eddsa_private.pem")
				pubPath := filepath.Join(tempDir, "eddsa_public.pem")

				privFile, err := os.OpenFile(privPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
				require.NoError(t, err)
				defer func() {
					if err := privFile.Close(); err != nil {
						t.Logf("Warning: failed to close private key file: %v", err)
					}
				}()

				privBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
				require.NoError(t, err)
				err = pem.Encode(privFile, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})
				require.NoError(t, err)

				pubFile, err := os.OpenFile(pubPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
				require.NoError(t, err)
				defer func() {
					if err := pubFile.Close(); err != nil {
						t.Logf("Warning: failed to close public key file: %v", err)
					}
				}()

				pubBytes, err := x509.MarshalPKIXPublicKey(publicKey)
				require.NoError(t, err)
				err = pem.Encode(pubFile, &pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})
				require.NoError(t, err)

				return privPath, pubPath
			},
		},
	}

	for _, alg := range algorithms {
		t.Run(alg.name, func(t *testing.T) {
			config := DefaultTestConfig()
			config.Algorithm = alg.algorithm
			config.SigningMethod = alg.method

			if alg.method == Symmetric {
				symmetricKey, _ := alg.setup()
				config.SymmetricKey = symmetricKey
				config.PrivateKeyPath = ""
				config.PublicKeyPath = ""
			} else {
				privPath, pubPath := alg.setup()
				config.SymmetricKey = ""
				config.PrivateKeyPath = privPath
				config.PublicKeyPath = pubPath
			}

			// Create maker
			maker, err := NewGourdianTokenMaker(context.Background(), config, nil)
			require.NoError(t, err, "failed to create maker for %s", alg.name)
			require.NotNil(t, maker)

			// Create and verify access token
			userID := uuid.New()
			sessionID := uuid.New()
			username := "testuser"
			roles := []string{"admin"}

			accessToken, err := maker.CreateAccessToken(context.Background(), userID, username, roles, sessionID)
			require.NoError(t, err, "failed to create access token for %s", alg.name)
			require.NotNil(t, accessToken)
			assert.NotEmpty(t, accessToken.Token)

			// Verify access token
			claims, err := maker.VerifyAccessToken(context.Background(), accessToken.Token)
			require.NoError(t, err, "failed to verify access token for %s", alg.name)
			assert.Equal(t, userID, claims.Subject)
			assert.Equal(t, username, claims.Username)
			assert.Equal(t, roles, claims.Roles)

			// Create and verify refresh token
			refreshToken, err := maker.CreateRefreshToken(context.Background(), userID, username, sessionID)
			require.NoError(t, err, "failed to create refresh token for %s", alg.name)
			require.NotNil(t, refreshToken)
			assert.NotEmpty(t, refreshToken.Token)

			// Verify refresh token
			refreshClaims, err := maker.VerifyRefreshToken(context.Background(), refreshToken.Token)
			require.NoError(t, err, "failed to verify refresh token for %s", alg.name)
			assert.Equal(t, userID, refreshClaims.Subject)
			assert.Equal(t, username, refreshClaims.Username)
		})
	}
}

func TestWeakAlgorithmRejection(t *testing.T) {
	t.Run("rejects 'none' algorithm", func(t *testing.T) {
		config := DefaultTestConfig()
		config.Algorithm = "none"

		_, err := NewGourdianTokenMaker(context.Background(), config, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "algorithm none is too weak for production use")
	})

	t.Run("rejects unsupported algorithm", func(t *testing.T) {
		config := DefaultTestConfig()
		config.Algorithm = "WEAK123"

		_, err := NewGourdianTokenMaker(context.Background(), config, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "algorithm WEAK123 not compatible with symmetric signing")
	})

	t.Run("rejects algorithm not in allowed list", func(t *testing.T) {
		config := DefaultTestConfig()
		config.Algorithm = "HS256"
		config.AllowedAlgorithms = []string{"HS384", "HS512"}

		_, err := NewGourdianTokenMaker(context.Background(), config, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not in allowed algorithms list")
	})

	t.Run("accepts HS256 by default", func(t *testing.T) {
		config := DefaultTestConfig()
		config.Algorithm = "HS256"
		config.AllowedAlgorithms = []string{"HS256", "HS384", "HS512"}

		maker, err := NewGourdianTokenMaker(context.Background(), config, nil)
		assert.NoError(t, err)
		assert.NotNil(t, maker)
	})

	t.Run("rejects invalid algorithm in AllowedAlgorithms", func(t *testing.T) {
		config := DefaultTestConfig()
		config.Algorithm = "HS256"
		config.AllowedAlgorithms = []string{"HS256", "INVALID_ALG"}

		_, err := NewGourdianTokenMaker(context.Background(), config, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported algorithm in AllowedAlgorithms")
	})

	t.Run("allows strong algorithms", func(t *testing.T) {
		strongAlgorithms := []string{"HS384", "HS512", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA"}

		for _, alg := range strongAlgorithms {
			config := DefaultTestConfig()
			config.Algorithm = alg
			config.AllowedAlgorithms = []string{alg}

			if alg[:2] == "HS" {
				// Symmetric
				maker, err := NewGourdianTokenMaker(context.Background(), config, nil)
				assert.NoError(t, err, "algorithm %s should be accepted", alg)
				assert.NotNil(t, maker)
			}
		}
	})
}

// =============================================================================
// Additional Security Tests
// =============================================================================

func TestKeyPermissions(t *testing.T) {
	tempDir := t.TempDir()

	t.Run("rejects private key with insecure permissions", func(t *testing.T) {
		privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)

		privPath := filepath.Join(tempDir, "insecure_private.pem")
		privFile, err := os.OpenFile(privPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644) // Too permissive
		require.NoError(t, err)
		defer func() {
			if err := privFile.Close(); err != nil {
				t.Logf("Warning: failed to close private key file: %v", err)
			}
		}()

		privBytes := x509.MarshalPKCS1PrivateKey(privateKey)
		err = pem.Encode(privFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes})
		require.NoError(t, err)

		pubPath := filepath.Join(tempDir, "public.pem")
		pubFile, err := os.OpenFile(pubPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		require.NoError(t, err)
		defer func() {
			if err := pubFile.Close(); err != nil {
				t.Logf("Warning: failed to close public key file: %v", err)
			}
		}()

		pubBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
		require.NoError(t, err)
		err = pem.Encode(pubFile, &pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})
		require.NoError(t, err)

		config := DefaultTestConfig()
		config.SigningMethod = Asymmetric
		config.Algorithm = "RS256"
		config.SymmetricKey = ""
		config.PrivateKeyPath = privPath
		config.PublicKeyPath = pubPath

		_, err = NewGourdianTokenMaker(context.Background(), config, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "insecure private key file permissions")
	})

	t.Run("accepts private key with secure permissions", func(t *testing.T) {
		privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)

		privPath := filepath.Join(tempDir, "secure_private.pem")
		privFile, err := os.OpenFile(privPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600) // Secure
		require.NoError(t, err)
		defer func() {
			if err := privFile.Close(); err != nil {
				t.Logf("Warning: failed to close private key file: %v", err)
			}
		}()

		privBytes := x509.MarshalPKCS1PrivateKey(privateKey)
		err = pem.Encode(privFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes})
		require.NoError(t, err)

		pubPath := filepath.Join(tempDir, "secure_public.pem")
		pubFile, err := os.OpenFile(pubPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		require.NoError(t, err)
		defer func() {
			if err := pubFile.Close(); err != nil {
				t.Logf("Warning: failed to close public key file: %v", err)
			}
		}()

		pubBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
		require.NoError(t, err)
		err = pem.Encode(pubFile, &pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})
		require.NoError(t, err)

		config := DefaultTestConfig()
		config.SigningMethod = Asymmetric
		config.Algorithm = "RS256"
		config.SymmetricKey = ""
		config.PrivateKeyPath = privPath
		config.PublicKeyPath = pubPath

		maker, err := NewGourdianTokenMaker(context.Background(), config, nil)
		assert.NoError(t, err)
		assert.NotNil(t, maker)
	})
}

func TestSymmetricKeyValidation(t *testing.T) {
	t.Run("rejects short symmetric key", func(t *testing.T) {
		config := DefaultTestConfig()
		config.SymmetricKey = "short" // Less than 32 bytes

		_, err := NewGourdianTokenMaker(context.Background(), config, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "symmetric key must be at least 32 bytes")
	})

	t.Run("accepts 32 byte symmetric key", func(t *testing.T) {
		config := DefaultTestConfig()
		config.SymmetricKey = "12345678901234567890123456789012" // Exactly 32 bytes

		maker, err := NewGourdianTokenMaker(context.Background(), config, nil)
		assert.NoError(t, err)
		assert.NotNil(t, maker)
	})

	t.Run("accepts longer symmetric key", func(t *testing.T) {
		config := DefaultTestConfig()
		config.SymmetricKey = "test-secret-key-that-is-at-least-32-bytes-long-and-more" // > 32 bytes

		maker, err := NewGourdianTokenMaker(context.Background(), config, nil)
		assert.NoError(t, err)
		assert.NotNil(t, maker)
	})

	t.Run("rejects empty symmetric key", func(t *testing.T) {
		config := DefaultTestConfig()
		config.SymmetricKey = ""

		_, err := NewGourdianTokenMaker(context.Background(), config, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "symmetric key is required")
	})
}

func TestCrossAlgorithmVerification(t *testing.T) {
	ctx := context.Background()

	t.Run("token signed with HS256 cannot be verified with HS512", func(t *testing.T) {
		// Create token with HS256
		config256 := DefaultTestConfig()
		config256.Algorithm = "HS256"
		maker256, _ := NewGourdianTokenMaker(ctx, config256, nil)

		userID := uuid.New()
		token, err := maker256.CreateAccessToken(ctx, userID, "user", []string{"role"}, uuid.New())
		require.NoError(t, err)

		// Try to verify with HS512
		config512 := DefaultTestConfig()
		config512.Algorithm = "HS512"
		maker512, _ := NewGourdianTokenMaker(ctx, config512, nil)

		_, err = maker512.VerifyAccessToken(ctx, token.Token)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unexpected signing method")
	})

	t.Run("token signed with one key cannot be verified with different key", func(t *testing.T) {
		// Create token with first key
		config1 := DefaultTestConfig()
		config1.SymmetricKey = "first-secret-key-that-is-at-least-32-bytes-long"
		maker1, _ := NewGourdianTokenMaker(ctx, config1, nil)

		userID := uuid.New()
		token, err := maker1.CreateAccessToken(ctx, userID, "user", []string{"role"}, uuid.New())
		require.NoError(t, err)

		// Try to verify with second key
		config2 := DefaultTestConfig()
		config2.SymmetricKey = "second-secret-key-that-is-at-least-32-bytes"
		maker2, _ := NewGourdianTokenMaker(ctx, config2, nil)

		_, err = maker2.VerifyAccessToken(ctx, token.Token)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid token")
	})
}
