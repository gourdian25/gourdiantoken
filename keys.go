package gourdiantoken

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

// initializeKeys initializes the signing keys based on the configured signing method.
func (maker *JWTMaker) initializeKeys() error {
	switch maker.config.SigningMethod {
	case Symmetric:
		if maker.config.SymmetricKey == "" {
			return fmt.Errorf("symmetric key is required for symmetric signing method")
		}
		maker.privateKey = []byte(maker.config.SymmetricKey)
		maker.publicKey = []byte(maker.config.SymmetricKey)
		return nil

	case Asymmetric:
		if maker.config.PrivateKeyPath == "" {
			return fmt.Errorf("private key path is required for asymmetric signing method")
		}
		if maker.config.PublicKeyPath == "" {
			return fmt.Errorf("public key path is required for asymmetric signing method")
		}

		// Load private key
		privateKeyBytes, err := os.ReadFile(maker.config.PrivateKeyPath)
		if err != nil {
			return fmt.Errorf("failed to read private key file: %w", err)
		}

		// Load public key
		publicKeyBytes, err := os.ReadFile(maker.config.PublicKeyPath)
		if err != nil {
			return fmt.Errorf("failed to read public key file: %w", err)
		}

		// Parse the keys based on the algorithm
		switch {
		case maker.signingMethod.Alg() == "RS256" || maker.signingMethod.Alg() == "RS384" || maker.signingMethod.Alg() == "RS512":
			// Parse RSA private key
			privateKey, err := parseRSAPrivateKey(privateKeyBytes)
			if err != nil {
				return fmt.Errorf("failed to parse RSA private key: %w", err)
			}
			maker.privateKey = privateKey

			// Parse RSA public key
			publicKey, err := parseRSAPublicKey(publicKeyBytes)
			if err != nil {
				return fmt.Errorf("failed to parse RSA public key: %w", err)
			}
			maker.publicKey = publicKey

		case maker.signingMethod.Alg() == "ES256" || maker.signingMethod.Alg() == "ES384" || maker.signingMethod.Alg() == "ES512":
			// Parse ECDSA private key
			privateKey, err := parseECDSAPrivateKey(privateKeyBytes)
			if err != nil {
				return fmt.Errorf("failed to parse ECDSA private key: %w", err)
			}
			maker.privateKey = privateKey

			// Parse ECDSA public key
			publicKey, err := parseECDSAPublicKey(publicKeyBytes)
			if err != nil {
				return fmt.Errorf("failed to parse ECDSA public key: %w", err)
			}
			maker.publicKey = publicKey

		default:
			return fmt.Errorf("unsupported algorithm for asymmetric signing: %s", maker.signingMethod.Alg())
		}
		return nil

	default:
		return fmt.Errorf("unsupported signing method: %s", maker.config.SigningMethod)
	}
}

// Helper functions to parse PEM encoded keys
func parseRSAPrivateKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block containing the RSA private key")
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		// Try parsing as PKCS8
		pkcs8Key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse RSA private key: %w", err)
		}
		key, ok := pkcs8Key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("not a valid RSA private key")
		}
		return key, nil
	}
	return key, nil
}

func parseRSAPublicKey(pemBytes []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block containing the RSA public key")
	}

	// Try parsing as PKIX
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		// Try parsing as X509 certificate
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse RSA public key: %w", err)
		}
		rsaPub, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("not a valid RSA public key")
		}
		return rsaPub, nil
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not a valid RSA public key")
	}
	return rsaPub, nil
}

func parseECDSAPrivateKey(pemBytes []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block containing the ECDSA private key")
	}

	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		// Try parsing as PKCS8
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

func parseECDSAPublicKey(pemBytes []byte) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block containing the ECDSA public key")
	}

	// Try parsing as PKIX
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		// Try parsing as X509 certificate
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
