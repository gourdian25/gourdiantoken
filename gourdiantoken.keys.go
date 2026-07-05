// File: gourdiantoken.keys.go

package gourdiantoken

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
)

// decodePEMBlock decodes a PEM block, returning a descriptive error if decoding fails.
// Shared by all six key parser functions below.
func decodePEMBlock(pemBytes []byte, description string) (*pem.Block, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block containing the %s", description)
	}
	return block, nil
}

// parseEdDSAPrivateKey parses an Ed25519 private key from PEM-encoded bytes.
// Supports PKCS#8 format.
//
// Ed25519 Keys:
//   - Modern elliptic curve algorithm
//   - Fast signing and verification
//   - Small key and signature sizes (32/64 bytes)
//   - Strong security (128-bit equivalent)
//
// Parameters:
//   - pemBytes: PEM-encoded private key data
//
// Returns:
//   - ed25519.PrivateKey: Parsed private key
//   - error: If PEM cannot be decoded or key is invalid
//
// Example PEM Format:
//
//	-----BEGIN PRIVATE KEY-----
//	MC4CAQAwBQYDK2VwBCIEIJ+DYvh6SEqVTm50DFtMDoQikTmiCqirVv9mWG9qfSnF
//	-----END PRIVATE KEY-----
func parseEdDSAPrivateKey(pemBytes []byte) (ed25519.PrivateKey, error) {
	block, err := decodePEMBlock(pemBytes, "private key")
	if err != nil {
		return nil, err
	}

	priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse EdDSA private key: %w", err)
	}

	eddsaPriv, ok := priv.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("not a valid EdDSA private key")
	}

	return eddsaPriv, nil
}

// parseEdDSAPublicKey parses an Ed25519 public key from PEM-encoded bytes.
// Supports both raw public keys and X.509 certificates.
//
// Supported Formats:
//   - PKIX public key (SubjectPublicKeyInfo)
//   - X.509 certificate (extracts public key)
//
// Parameters:
//   - pemBytes: PEM-encoded public key or certificate data
//
// Returns:
//   - ed25519.PublicKey: Parsed public key
//   - error: If PEM cannot be decoded or key is invalid
//
// Example PEM Format:
//
//	-----BEGIN PUBLIC KEY-----
//	MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=
//	-----END PUBLIC KEY-----
func parseEdDSAPublicKey(pemBytes []byte) (ed25519.PublicKey, error) {
	block, err := decodePEMBlock(pemBytes, "public key")
	if err != nil {
		return nil, err
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse EdDSA public key: %w", err)
		}
		eddsaPub, ok := cert.PublicKey.(ed25519.PublicKey)
		if !ok {
			return nil, fmt.Errorf("not a valid EdDSA public key")
		}
		return eddsaPub, nil
	}

	eddsaPub, ok := pub.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not a valid EdDSA public key")
	}
	return eddsaPub, nil
}

// parseRSAPrivateKey parses an RSA private key from PEM-encoded bytes.
// Supports PKCS#1 and PKCS#8 formats with fallback parsing.
//
// Supported Formats:
//   - PKCS#1 (traditional RSA format)
//   - PKCS#8 (modern format, supports multiple algorithms)
//   - Legacy ASN.1 structures
//
// Key Size Recommendations:
//   - Minimum: 2048 bits
//   - Recommended: 3072 bits
//   - High security: 4096 bits
//
// Parameters:
//   - pemBytes: PEM-encoded private key data
//
// Returns:
//   - *rsa.PrivateKey: Parsed private key
//   - error: If PEM cannot be decoded or key is invalid
//
// Example PEM Format:
//
//	-----BEGIN RSA PRIVATE KEY-----
//	MIIEpAIBAAKCAQEA...
//	-----END RSA PRIVATE KEY-----
func parseRSAPrivateKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, err := decodePEMBlock(pemBytes, "RSA private key")
	if err != nil {
		return nil, err
	}

	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}

	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if rsaKey, ok := key.(*rsa.PrivateKey); ok {
			return rsaKey, nil
		}
		return nil, fmt.Errorf("expected RSA private key, got %T", key)
	}

	var privKey pkcs8
	if _, err := asn1.Unmarshal(block.Bytes, &privKey); err != nil {
		return nil, fmt.Errorf("failed to parse PKCS8 structure: %w", err)
	}

	var rsaPriv rsaPrivateKey
	if _, err := asn1.Unmarshal(privKey.PrivateKey, &rsaPriv); err != nil {
		return nil, fmt.Errorf("failed to parse RSA private key: %w", err)
	}

	return &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			N: rsaPriv.N,
			E: int(rsaPriv.E.Int64()),
		},
		D:      rsaPriv.D,
		Primes: []*big.Int{rsaPriv.P, rsaPriv.Q},
		Precomputed: rsa.PrecomputedValues{
			Dp:   rsaPriv.Dp,
			Dq:   rsaPriv.Dq,
			Qinv: rsaPriv.Qinv,
		},
	}, nil
}

// parseRSAPublicKey parses an RSA public key from PEM-encoded bytes.
// Supports multiple formats including certificates.
//
// Supported Formats:
//   - PKIX public key (SubjectPublicKeyInfo)
//   - PKCS#1 public key
//   - X.509 certificate (extracts public key)
//   - Legacy ASN.1 structures
//
// Parameters:
//   - pemBytes: PEM-encoded public key or certificate data
//
// Returns:
//   - *rsa.PublicKey: Parsed public key
//   - error: If PEM cannot be decoded or key is invalid
//
// Example PEM Format:
//
//	-----BEGIN PUBLIC KEY-----
//	MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
//	-----END PUBLIC KEY-----
func parseRSAPublicKey(pemBytes []byte) (*rsa.PublicKey, error) {
	block, err := decodePEMBlock(pemBytes, "RSA public key")
	if err != nil {
		return nil, err
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err == nil {
		if rsaPub, ok := pub.(*rsa.PublicKey); ok {
			return rsaPub, nil
		}
		return nil, fmt.Errorf("expected RSA public key, got %T", pub)
	}

	if pub, err := x509.ParsePKCS1PublicKey(block.Bytes); err == nil {
		return pub, nil
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err == nil {
		if rsaPub, ok := cert.PublicKey.(*rsa.PublicKey); ok {
			return rsaPub, nil
		}
		return nil, fmt.Errorf("expected RSA public key in certificate, got %T", cert.PublicKey)
	}

	var pubKey struct {
		Algo      pkix.AlgorithmIdentifier
		BitString asn1.BitString
	}
	if _, err := asn1.Unmarshal(block.Bytes, &pubKey); err != nil {
		return nil, fmt.Errorf("failed to parse public key structure: %w", err)
	}

	var rsaPub struct {
		N *big.Int
		E *big.Int
	}
	if _, err := asn1.Unmarshal(pubKey.BitString.Bytes, &rsaPub); err != nil {
		return nil, fmt.Errorf("failed to parse RSA public key: %w", err)
	}

	return &rsa.PublicKey{
		N: rsaPub.N,
		E: int(rsaPub.E.Int64()),
	}, nil
}

// parseECDSAPrivateKey parses an ECDSA private key from PEM-encoded bytes.
// Supports SEC1 and PKCS#8 formats.
//
// Supported Curves:
//   - P-256 (ES256) - 128-bit security
//   - P-384 (ES384) - 192-bit security
//   - P-521 (ES512) - 256-bit security
//
// Parameters:
//   - pemBytes: PEM-encoded private key data
//
// Returns:
//   - *ecdsa.PrivateKey: Parsed private key
//   - error: If PEM cannot be decoded or key is invalid
//
// Example PEM Format:
//
//	-----BEGIN EC PRIVATE KEY-----
//	MHcCAQEEIIGlRFzR...
//	-----END EC PRIVATE KEY-----
func parseECDSAPrivateKey(pemBytes []byte) (*ecdsa.PrivateKey, error) {
	block, err := decodePEMBlock(pemBytes, "ECDSA private key")
	if err != nil {
		return nil, err
	}

	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		pkcs8Key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse ECDSA private key: %w", err)
		}
		key, ok := pkcs8Key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("not a valid ECDSA private key")
		}
		return key, nil
	}
	return key, nil
}

// parseECDSAPublicKey parses an ECDSA public key from PEM-encoded bytes.
// Supports both raw public keys and X.509 certificates.
//
// Supported Formats:
//   - PKIX public key (SubjectPublicKeyInfo)
//   - X.509 certificate (extracts public key)
//
// Parameters:
//   - pemBytes: PEM-encoded public key or certificate data
//
// Returns:
//   - *ecdsa.PublicKey: Parsed public key
//   - error: If PEM cannot be decoded or key is invalid
//
// Example PEM Format:
//
//	-----BEGIN PUBLIC KEY-----
//	MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...
//	-----END PUBLIC KEY-----
func parseECDSAPublicKey(pemBytes []byte) (*ecdsa.PublicKey, error) {
	block, err := decodePEMBlock(pemBytes, "ECDSA public key")
	if err != nil {
		return nil, err
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse ECDSA public key: %w", err)
		}
		ecdsaPub, ok := cert.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("not a valid ECDSA public key")
		}
		return ecdsaPub, nil
	}

	ecdsaPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not a valid ECDSA public key")
	}
	return ecdsaPub, nil
}

// checkFilePermissions verifies that a file has secure permissions.
// Used to ensure private key files are not world-readable.
//
// Security Check:
//   - Verifies file doesn't have permissions beyond required
//   - Recommended: 0600 (read/write for owner only)
//   - Fails if file is readable by group or others
//
// Parameters:
//   - path: File path to check
//   - requiredPerm: Maximum allowed permissions (e.g., 0600)
//
// Returns:
//   - error: If file has excessive permissions or cannot be accessed
//
// Example:
//
//	err := checkFilePermissions("/keys/private.pem", 0600)
//	if err != nil {
//	    log.Fatal("Private key file has insecure permissions")
//	}
func checkFilePermissions(path string, requiredPerm os.FileMode) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("failed to stat file: %w", err)
	}

	actualPerm := info.Mode().Perm()
	if actualPerm&^requiredPerm != 0 {
		return fmt.Errorf("file %s has permissions %#o, expected %#o", path, actualPerm, requiredPerm)
	}

	return nil
}

// getUnixTime extracts a Unix timestamp from various claim value types.
// Handles different JSON number representations used by JWT libraries.
//
// Supported Types:
//   - float64 (standard JSON number)
//   - int64 (Go integer)
//   - int (Go integer)
//   - json.Number (string-based number)
//
// Parameters:
//   - claim: The claim value to convert
//
// Returns:
//   - int64: Unix timestamp in seconds, or 0 if conversion fails
//
// Notes:
//   - Returns 0 for unrecognized types (not an error)
//   - Used internally for timestamp claim parsing
func getUnixTime(claim interface{}) int64 {
	switch v := claim.(type) {
	case float64:
		return int64(v)
	case int64:
		return v
	case int:
		return int64(v)
	case json.Number:
		i, _ := v.Int64()
		return i
	default:
		return 0
	}
}

// pkcs8 represents a PKCS#8 encoded private key structure.
// Used for parsing PKCS#8 format keys that can't be parsed with standard library.
//
// ASN.1 Structure:
//
//	PrivateKeyInfo ::= SEQUENCE {
//	  version Version,
//	  privateKeyAlgorithm AlgorithmIdentifier,
//	  privateKey OCTET STRING
//	}
type pkcs8 struct {
	Version    int
	Algo       pkix.AlgorithmIdentifier
	PrivateKey []byte
}

// rsaPrivateKey represents the ASN.1 structure of an RSA private key.
// Used for manual parsing when standard methods fail.
//
// ASN.1 Structure (PKCS#1):
//
//	RSAPrivateKey ::= SEQUENCE {
//	  version Version,
//	  modulus INTEGER,
//	  publicExponent INTEGER,
//	  privateExponent INTEGER,
//	  prime1 INTEGER,
//	  prime2 INTEGER,
//	  exponent1 INTEGER,
//	  exponent2 INTEGER,
//	  coefficient INTEGER
//	}
type rsaPrivateKey struct {
	Version int
	N       *big.Int // modulus
	E       *big.Int // public exponent
	D       *big.Int // private exponent
	P       *big.Int // prime1
	Q       *big.Int // prime2
	Dp      *big.Int // exponent1 (d mod (p-1))
	Dq      *big.Int // exponent2 (d mod (q-1))
	Qinv    *big.Int // coefficient (q^-1 mod p)
}
