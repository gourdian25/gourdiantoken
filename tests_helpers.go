// tests_helpers.go
package gourdiantoken

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

func testRedisOptions() *redis.Options {
	return &redis.Options{
		Addr:     "127.0.0.1:6379",
		Password: "GourdianRedisSecret",
		DB:       0,
	}
}

// Redis helpers
func testRedisClient(t *testing.T) *redis.Client {
	t.Helper()
	client := redis.NewClient(testRedisOptions())
	_, err := client.Ping(context.Background()).Result()
	if err != nil {
		t.Skip("Redis not available, skipping test")
	}
	return client
}

// Key generation helpers
func generateRSAKey(bits int) *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		panic(fmt.Sprintf("Failed to generate RSA key: %v", err))
	}
	return key
}

func generateECDSAKey(curve elliptic.Curve) *ecdsa.PrivateKey {
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		panic(fmt.Sprintf("Failed to generate ECDSA key: %v", err))
	}
	return key
}

func generateEdDSAKey() ed25519.PrivateKey {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(fmt.Sprintf("Failed to generate EdDSA key: %v", err))
	}
	return privateKey
}

// Unified key file writer
func writeKeyPairToTempFiles(t testing.TB, privateKey interface{}, publicKey interface{}) (privatePath, publicPath string) {
	t.Helper()
	tempDir := t.TempDir()

	// Write private key
	privateBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	require.NoError(t, err, "Failed to marshal private key")

	privateBlock := &pem.Block{Type: "PRIVATE KEY", Bytes: privateBytes}
	privatePath = filepath.Join(tempDir, "private.pem")
	require.NoError(t, os.WriteFile(privatePath, pem.EncodeToMemory(privateBlock), 0600), "Failed to write private key")

	// Write public key
	publicBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	require.NoError(t, err, "Failed to marshal public key")

	publicBlock := &pem.Block{Type: "PUBLIC KEY", Bytes: publicBytes}
	publicPath = filepath.Join(tempDir, "public.pem")
	require.NoError(t, os.WriteFile(publicPath, pem.EncodeToMemory(publicBlock), 0644), "Failed to write public key")

	return privatePath, publicPath
}

// Key pair generators
func generateTempRSAPair(t *testing.T) (privatePath, publicPath string) {
	t.Helper()
	key := generateRSAKey(2048)
	return writeKeyPairToTempFiles(t, key, &key.PublicKey)
}

func generateTempECDSAPair(t *testing.T) (privatePath, publicPath string) {
	t.Helper()
	key := generateECDSAKey(elliptic.P256())
	return writeKeyPairToTempFiles(t, key, &key.PublicKey)
}

func generateTempEdDSAPair(t *testing.T) (privatePath, publicPath string) {
	t.Helper()
	key := generateEdDSAKey()
	return writeKeyPairToTempFiles(t, key, key.Public().(ed25519.PublicKey))
}

func generateTempCertificate(t *testing.T) (privatePath, publicPath string) {
	t.Helper()
	privateKey := generateRSAKey(2048)

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour),
	}

	certBytes, err := x509.CreateCertificate(
		rand.Reader,
		&template,
		&template,
		&privateKey.PublicKey,
		privateKey,
	)
	require.NoError(t, err, "Failed to create certificate")

	// Write private key
	privateBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateBlock := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: privateBytes}
	privatePath = filepath.Join(t.TempDir(), "private.pem")
	require.NoError(t, os.WriteFile(privatePath, pem.EncodeToMemory(privateBlock), 0600))

	// Write certificate
	certBlock := &pem.Block{Type: "CERTIFICATE", Bytes: certBytes}
	publicPath = filepath.Join(t.TempDir(), "cert.pem")
	require.NoError(t, os.WriteFile(publicPath, pem.EncodeToMemory(certBlock), 0644))

	return privatePath, publicPath
}

// Maker helper
func createTestMaker(t *testing.T, config GourdianTokenConfig) *JWTMaker {
	t.Helper()
	ctx := context.Background()
	maker, err := NewGourdianTokenMaker(ctx, config, testRedisOptions())
	require.NoError(t, err, "Failed to create token maker")
	return maker.(*JWTMaker)
}
