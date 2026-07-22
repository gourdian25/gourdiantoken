// File: gourdiantoken.keys_test.go

package gourdiantoken

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// selfSignedCert builds a minimal self-signed certificate wrapping pub,
// signed by priv, PEM-encoded — used to exercise each key parser's
// certificate-fallback branch directly.
func selfSignedCert(t *testing.T, pub, signerPriv any) []byte {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, signerPriv)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestDecodePEMBlock_InvalidPEM(t *testing.T) {
	_, err := decodePEMBlock([]byte("not pem at all"), "test key")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse PEM block containing the test key")
}

func TestParseRSAPublicKey_AllPaths(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	t.Run("PKCS1 public key", func(t *testing.T) {
		der := x509.MarshalPKCS1PublicKey(&rsaKey.PublicKey)
		pemBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: der})
		pub, err := parseRSAPublicKey(pemBytes)
		require.NoError(t, err)
		assert.Equal(t, rsaKey.N, pub.N)
	})

	t.Run("certificate containing RSA key", func(t *testing.T) {
		certPEM := selfSignedCert(t, &rsaKey.PublicKey, rsaKey)
		pub, err := parseRSAPublicKey(certPEM)
		require.NoError(t, err)
		assert.Equal(t, rsaKey.N, pub.N)
	})

	t.Run("certificate containing non-RSA key", func(t *testing.T) {
		certPEM := selfSignedCert(t, &ecdsaKey.PublicKey, ecdsaKey)
		_, err := parseRSAPublicKey(certPEM)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "expected RSA public key in certificate")
	})

	t.Run("PKIX-encoded non-RSA key", func(t *testing.T) {
		der, err := x509.MarshalPKIXPublicKey(&ecdsaKey.PublicKey)
		require.NoError(t, err)
		pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
		_, err = parseRSAPublicKey(pemBytes)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "expected RSA public key, got")
	})

	t.Run("garbage bytes fail every parse path", func(t *testing.T) {
		pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("not asn1 at all")})
		_, err := parseRSAPublicKey(pemBytes)
		require.Error(t, err)
	})

	t.Run("invalid PEM", func(t *testing.T) {
		_, err := parseRSAPublicKey([]byte("garbage"))
		require.Error(t, err)
	})
}

func TestParseECDSAPublicKey_AllPaths(t *testing.T) {
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	t.Run("certificate containing ECDSA key", func(t *testing.T) {
		certPEM := selfSignedCert(t, &ecdsaKey.PublicKey, ecdsaKey)
		pub, err := parseECDSAPublicKey(certPEM)
		require.NoError(t, err)
		assert.Equal(t, ecdsaKey.X, pub.X)
	})

	t.Run("certificate containing non-ECDSA key", func(t *testing.T) {
		certPEM := selfSignedCert(t, &rsaKey.PublicKey, rsaKey)
		_, err := parseECDSAPublicKey(certPEM)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not a valid ECDSA public key")
	})

	t.Run("PKIX-encoded non-ECDSA key", func(t *testing.T) {
		der, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
		require.NoError(t, err)
		pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
		_, err = parseECDSAPublicKey(pemBytes)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not a valid ECDSA public key")
	})

	t.Run("neither PKIX nor certificate", func(t *testing.T) {
		pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("not asn1 at all")})
		_, err := parseECDSAPublicKey(pemBytes)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to parse ECDSA public key")
	})

	t.Run("invalid PEM", func(t *testing.T) {
		_, err := parseECDSAPublicKey([]byte("garbage"))
		require.Error(t, err)
	})
}

func TestParseEdDSAPublicKey_AllPaths(t *testing.T) {
	eddsaPub, eddsaPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	t.Run("certificate containing EdDSA key", func(t *testing.T) {
		certPEM := selfSignedCert(t, eddsaPub, eddsaPriv)
		pub, err := parseEdDSAPublicKey(certPEM)
		require.NoError(t, err)
		assert.Equal(t, eddsaPub, pub)
	})

	t.Run("certificate containing non-EdDSA key", func(t *testing.T) {
		certPEM := selfSignedCert(t, &rsaKey.PublicKey, rsaKey)
		_, err := parseEdDSAPublicKey(certPEM)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not a valid EdDSA public key")
	})

	t.Run("PKIX-encoded non-EdDSA key", func(t *testing.T) {
		der, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
		require.NoError(t, err)
		pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
		_, err = parseEdDSAPublicKey(pemBytes)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not a valid EdDSA public key")
	})

	t.Run("neither PKIX nor certificate", func(t *testing.T) {
		pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("not asn1 at all")})
		_, err := parseEdDSAPublicKey(pemBytes)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to parse EdDSA public key")
	})

	t.Run("invalid PEM", func(t *testing.T) {
		_, err := parseEdDSAPublicKey([]byte("garbage"))
		require.Error(t, err)
	})
}

func TestParseRSAPrivateKey_PKCS8NonRSA(t *testing.T) {
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(ecdsaKey)
	require.NoError(t, err)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	_, err = parseRSAPrivateKey(pemBytes)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expected RSA private key, got")
}

func TestParseRSAPrivateKey_InvalidPEM(t *testing.T) {
	_, err := parseRSAPrivateKey([]byte("garbage"))
	require.Error(t, err)
}

func TestParseECDSAPrivateKey_PKCS8NonECDSA(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	require.NoError(t, err)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	_, err = parseECDSAPrivateKey(pemBytes)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not a valid ECDSA private key")
}

func TestParseECDSAPrivateKey_InvalidPEM(t *testing.T) {
	_, err := parseECDSAPrivateKey([]byte("garbage"))
	require.Error(t, err)
}

func TestParseEdDSAPrivateKey_PKCS8NonEdDSA(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	require.NoError(t, err)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	_, err = parseEdDSAPrivateKey(pemBytes)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not a valid EdDSA private key")
}

func TestParseEdDSAPrivateKey_InvalidPEM(t *testing.T) {
	_, err := parseEdDSAPrivateKey([]byte("garbage"))
	require.Error(t, err)
}

func TestGetUnixTime_AllTypes(t *testing.T) {
	now := time.Now().Unix()

	assert.Equal(t, now, getUnixTime(float64(now)))
	assert.Equal(t, now, getUnixTime(now))
	assert.Equal(t, now, getUnixTime(int(now)))

	n := json.Number("1234567890")
	assert.Equal(t, int64(1234567890), getUnixTime(n))

	assert.Equal(t, int64(0), getUnixTime("not-a-number"))
	assert.Equal(t, int64(0), getUnixTime(nil))
}
