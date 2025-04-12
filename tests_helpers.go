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
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

// Test Helper Functions

func testRedisOptions() *redis.Options {
	return &redis.Options{
		Addr:     "127.0.0.1:6379",
		Password: "",
		DB:       0,
	}
}

func testRedisClient(t *testing.T) *redis.Client {
	client := redis.NewClient(testRedisOptions())
	_, err := client.Ping(context.Background()).Result()
	if err != nil {
		t.Skip("Redis not available, skipping test")
	}
	return client
}

func generateTempRSAPair(t *testing.T) (privatePath, publicPath string) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	privateBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateBytes,
	}

	privatePath = filepath.Join(t.TempDir(), "private.pem")
	err = os.WriteFile(privatePath, pem.EncodeToMemory(privateBlock), 0600)
	require.NoError(t, err)

	publicBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	require.NoError(t, err)
	publicBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicBytes,
	}

	publicPath = filepath.Join(t.TempDir(), "public.pem")
	err = os.WriteFile(publicPath, pem.EncodeToMemory(publicBlock), 0600)
	require.NoError(t, err)

	return privatePath, publicPath
}

func generateTempECDSAPair(t *testing.T) (privatePath, publicPath string) {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	privateBytes, err := x509.MarshalECPrivateKey(privateKey)
	require.NoError(t, err)
	privateBlock := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privateBytes,
	}

	privatePath = filepath.Join(t.TempDir(), "ec_private.pem")
	err = os.WriteFile(privatePath, pem.EncodeToMemory(privateBlock), 0600)
	require.NoError(t, err)

	publicBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	require.NoError(t, err)
	publicBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicBytes,
	}

	publicPath = filepath.Join(t.TempDir(), "ec_public.pem")
	err = os.WriteFile(publicPath, pem.EncodeToMemory(publicBlock), 0600)
	require.NoError(t, err)

	return privatePath, publicPath
}

func generateTempCertificate(t *testing.T) (privatePath, publicPath string) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour),
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	privateBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateBytes,
	}

	privatePath = filepath.Join(t.TempDir(), "cert_private.pem")
	err = os.WriteFile(privatePath, pem.EncodeToMemory(privateBlock), 0600)
	require.NoError(t, err)

	certBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	}

	publicPath = filepath.Join(t.TempDir(), "cert_public.pem")
	err = os.WriteFile(publicPath, pem.EncodeToMemory(certBlock), 0600)
	require.NoError(t, err)

	return privatePath, publicPath
}

var (
	testRedisOpts = &redis.Options{
		Addr: "localhost:6379",
	}
	testSymmetricKey = "test-secret-32-bytes-long-1234567890"
)

// Test Helper Functions
func generateTestRSAKeys(t *testing.T) (privateKeyPath, publicKeyPath string) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Create temp files
	privateKeyFile, err := os.CreateTemp("", "rsa-private-*.pem")
	require.NoError(t, err)
	defer privateKeyFile.Close()

	publicKeyFile, err := os.CreateTemp("", "rsa-public-*.pem")
	require.NoError(t, err)
	defer publicKeyFile.Close()

	// Encode private key
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	}
	err = pem.Encode(privateKeyFile, privateKeyBlock)
	require.NoError(t, err)

	// Encode public key
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	require.NoError(t, err)
	publicKeyBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}
	err = pem.Encode(publicKeyFile, publicKeyBlock)
	require.NoError(t, err)

	return privateKeyFile.Name(), publicKeyFile.Name()
}

func generateTestECDSAKeys(t *testing.T) (privateKeyPath, publicKeyPath string) {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Create temp files
	privateKeyFile, err := os.CreateTemp("", "ecdsa-private-*.pem")
	require.NoError(t, err)
	defer privateKeyFile.Close()

	publicKeyFile, err := os.CreateTemp("", "ecdsa-public-*.pem")
	require.NoError(t, err)
	defer publicKeyFile.Close()

	// Encode private key
	privateKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
	require.NoError(t, err)
	privateKeyBlock := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privateKeyBytes,
	}
	err = pem.Encode(privateKeyFile, privateKeyBlock)
	require.NoError(t, err)

	// Encode public key
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	require.NoError(t, err)
	publicKeyBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}
	err = pem.Encode(publicKeyFile, publicKeyBlock)
	require.NoError(t, err)

	return privateKeyFile.Name(), publicKeyFile.Name()
}

func generateTestEdDSAKeys(t *testing.T) (privateKeyPath, publicKeyPath string) {
	t.Helper()

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	// Create temp files
	privateKeyFile, err := os.CreateTemp("", "ed25519-private-*.pem")
	require.NoError(t, err)
	defer privateKeyFile.Close()

	publicKeyFile, err := os.CreateTemp("", "ed25519-public-*.pem")
	require.NoError(t, err)
	defer publicKeyFile.Close()

	// Encode private key
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	require.NoError(t, err)
	privateKeyBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyBytes,
	}
	err = pem.Encode(privateKeyFile, privateKeyBlock)
	require.NoError(t, err)

	// Encode public key
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	require.NoError(t, err)
	publicKeyBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}
	err = pem.Encode(publicKeyFile, publicKeyBlock)
	require.NoError(t, err)

	return privateKeyFile.Name(), publicKeyFile.Name()
}

func createTestMaker(t *testing.T, config GourdianTokenConfig) *JWTMaker {
	t.Helper()

	ctx := context.Background()
	maker, err := NewGourdianTokenMaker(ctx, config, testRedisOpts)
	require.NoError(t, err)
	return maker.(*JWTMaker)
}

func generateRSAKey(bits int) *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		panic(err)
	}
	return key
}

func generateECDSAKey(curve elliptic.Curve) *ecdsa.PrivateKey {
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		panic(err)
	}
	return key
}

func writeTempKeyFiles(t testing.TB, key interface{}) (privatePath, publicPath string) {
	t.Helper()
	tempDir := t.TempDir()

	switch k := key.(type) {
	case *rsa.PrivateKey:
		privateBytes := x509.MarshalPKCS1PrivateKey(k)
		privateBlock := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: privateBytes}
		privatePath = filepath.Join(tempDir, "private.pem")
		require.NoError(t, os.WriteFile(privatePath, pem.EncodeToMemory(privateBlock), 0600))

		publicBytes, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
		require.NoError(t, err)
		publicBlock := &pem.Block{Type: "PUBLIC KEY", Bytes: publicBytes}
		publicPath = filepath.Join(tempDir, "public.pem")
		require.NoError(t, os.WriteFile(publicPath, pem.EncodeToMemory(publicBlock), 0644))

	case *ecdsa.PrivateKey:
		privateBytes, err := x509.MarshalECPrivateKey(k)
		require.NoError(t, err)
		privateBlock := &pem.Block{Type: "EC PRIVATE KEY", Bytes: privateBytes}
		privatePath = filepath.Join(tempDir, "ec_private.pem")
		require.NoError(t, os.WriteFile(privatePath, pem.EncodeToMemory(privateBlock), 0600))

		publicBytes, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
		require.NoError(t, err)
		publicBlock := &pem.Block{Type: "PUBLIC KEY", Bytes: publicBytes}
		publicPath = filepath.Join(tempDir, "ec_public.pem")
		require.NoError(t, os.WriteFile(publicPath, pem.EncodeToMemory(publicBlock), 0644))
	}

	return privatePath, publicPath
}
