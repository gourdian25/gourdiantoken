// File: config.validation_test.go

package gourdiantoken

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// config validation tests

func TestDefaultGourdianTokenConfig(t *testing.T) {
	t.Run("creates valid default config", func(t *testing.T) {
		symmetricKey := "test-secret-key-that-is-at-least-32-bytes-long"
		config := DefaultGourdianTokenConfig(symmetricKey)

		assert.Equal(t, Symmetric, config.SigningMethod)
		assert.Equal(t, "HS256", config.Algorithm)
		assert.Equal(t, symmetricKey, config.SymmetricKey)
		assert.Equal(t, "gourdian.com", config.Issuer)
		assert.False(t, config.RevocationEnabled)
		assert.False(t, config.RotationEnabled)
		assert.Equal(t, 30*time.Minute, config.AccessExpiryDuration)
		assert.Equal(t, 24*time.Hour, config.AccessMaxLifetimeExpiry)
		assert.Equal(t, 7*24*time.Hour, config.RefreshExpiryDuration)
		assert.Equal(t, 30*24*time.Hour, config.RefreshMaxLifetimeExpiry)
		assert.Equal(t, 5*time.Minute, config.RefreshReuseInterval)
		assert.Equal(t, 6*time.Hour, config.CleanupInterval)
	})

	t.Run("has required claims", func(t *testing.T) {
		config := DefaultGourdianTokenConfig("test-secret-key-that-is-at-least-32-bytes-long")

		expectedClaims := []string{"iss", "aud", "nbf", "mle"}
		assert.ElementsMatch(t, expectedClaims, config.RequiredClaims)
	})

	t.Run("has allowed algorithms", func(t *testing.T) {
		config := DefaultGourdianTokenConfig("test-secret-key-that-is-at-least-32-bytes-long")

		assert.Contains(t, config.AllowedAlgorithms, "HS256")
		assert.Contains(t, config.AllowedAlgorithms, "RS256")
		assert.Contains(t, config.AllowedAlgorithms, "ES256")
		assert.Contains(t, config.AllowedAlgorithms, "PS256")
	})
}

func TestValidateConfig_Symmetric(t *testing.T) {
	t.Run("valid symmetric config", func(t *testing.T) {
		config := &GourdianTokenConfig{
			SigningMethod:            Symmetric,
			Algorithm:                "HS256",
			SymmetricKey:             "test-secret-key-that-is-at-least-32-bytes-long",
			Issuer:                   "test.com",
			AccessExpiryDuration:     30 * time.Minute,
			AccessMaxLifetimeExpiry:  24 * time.Hour,
			RefreshExpiryDuration:    7 * 24 * time.Hour,
			RefreshMaxLifetimeExpiry: 30 * 24 * time.Hour,
			RefreshReuseInterval:     5 * time.Minute,
			CleanupInterval:          1 * time.Hour,
		}

		err := validateConfig(config)
		assert.NoError(t, err)
	})

	t.Run("missing symmetric key", func(t *testing.T) {
		config := &GourdianTokenConfig{
			SigningMethod:            Symmetric,
			Algorithm:                "HS256",
			SymmetricKey:             "",
			AccessExpiryDuration:     30 * time.Minute,
			AccessMaxLifetimeExpiry:  24 * time.Hour,
			RefreshExpiryDuration:    7 * 24 * time.Hour,
			RefreshMaxLifetimeExpiry: 30 * 24 * time.Hour,
			CleanupInterval:          1 * time.Hour,
		}

		err := validateConfig(config)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "symmetric key is required")
	})

	t.Run("symmetric key too short", func(t *testing.T) {
		config := &GourdianTokenConfig{
			SigningMethod:            Symmetric,
			Algorithm:                "HS256",
			SymmetricKey:             "short",
			AccessExpiryDuration:     30 * time.Minute,
			AccessMaxLifetimeExpiry:  24 * time.Hour,
			RefreshExpiryDuration:    7 * 24 * time.Hour,
			RefreshMaxLifetimeExpiry: 30 * 24 * time.Hour,
			CleanupInterval:          1 * time.Hour,
		}

		err := validateConfig(config)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "symmetric key must be at least 32 bytes")
	})

	t.Run("incompatible algorithm with symmetric", func(t *testing.T) {
		config := &GourdianTokenConfig{
			SigningMethod:            Symmetric,
			Algorithm:                "RS256",
			SymmetricKey:             "test-secret-key-that-is-at-least-32-bytes-long",
			AccessExpiryDuration:     30 * time.Minute,
			AccessMaxLifetimeExpiry:  24 * time.Hour,
			RefreshExpiryDuration:    7 * 24 * time.Hour,
			RefreshMaxLifetimeExpiry: 30 * 24 * time.Hour,
			CleanupInterval:          1 * time.Hour,
		}

		err := validateConfig(config)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not compatible with symmetric signing")
	})

	t.Run("key paths provided with symmetric", func(t *testing.T) {
		config := &GourdianTokenConfig{
			SigningMethod:            Symmetric,
			Algorithm:                "HS256",
			SymmetricKey:             "test-secret-key-that-is-at-least-32-bytes-long",
			PrivateKeyPath:           "/path/to/key",
			AccessExpiryDuration:     30 * time.Minute,
			AccessMaxLifetimeExpiry:  24 * time.Hour,
			RefreshExpiryDuration:    7 * 24 * time.Hour,
			RefreshMaxLifetimeExpiry: 30 * 24 * time.Hour,
			CleanupInterval:          1 * time.Hour,
		}

		err := validateConfig(config)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "must be empty for symmetric signing")
	})
}

func TestValidateConfig_Asymmetric(t *testing.T) {
	t.Run("missing private key path", func(t *testing.T) {
		config := &GourdianTokenConfig{
			SigningMethod:            Asymmetric,
			Algorithm:                "RS256",
			PublicKeyPath:            "/path/to/public.pem",
			AccessExpiryDuration:     30 * time.Minute,
			AccessMaxLifetimeExpiry:  24 * time.Hour,
			RefreshExpiryDuration:    7 * 24 * time.Hour,
			RefreshMaxLifetimeExpiry: 30 * 24 * time.Hour,
			CleanupInterval:          1 * time.Hour,
		}

		err := validateConfig(config)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "private and public key paths are required")
	})

	t.Run("missing public key path", func(t *testing.T) {
		config := &GourdianTokenConfig{
			SigningMethod:            Asymmetric,
			Algorithm:                "RS256",
			PrivateKeyPath:           "/path/to/private.pem",
			AccessExpiryDuration:     30 * time.Minute,
			AccessMaxLifetimeExpiry:  24 * time.Hour,
			RefreshExpiryDuration:    7 * 24 * time.Hour,
			RefreshMaxLifetimeExpiry: 30 * 24 * time.Hour,
			CleanupInterval:          1 * time.Hour,
		}

		err := validateConfig(config)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "private and public key paths are required")
	})

	t.Run("symmetric key provided with asymmetric", func(t *testing.T) {
		config := &GourdianTokenConfig{
			SigningMethod:            Asymmetric,
			Algorithm:                "RS256",
			SymmetricKey:             "key",
			PrivateKeyPath:           "/path/to/private.pem",
			PublicKeyPath:            "/path/to/public.pem",
			AccessExpiryDuration:     30 * time.Minute,
			AccessMaxLifetimeExpiry:  24 * time.Hour,
			RefreshExpiryDuration:    7 * 24 * time.Hour,
			RefreshMaxLifetimeExpiry: 30 * 24 * time.Hour,
			CleanupInterval:          1 * time.Hour,
		}

		err := validateConfig(config)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "symmetric key must be empty for asymmetric signing")
	})

	t.Run("incompatible algorithm with asymmetric", func(t *testing.T) {
		config := &GourdianTokenConfig{
			SigningMethod:            Asymmetric,
			Algorithm:                "HS256",
			PrivateKeyPath:           "/path/to/private.pem",
			PublicKeyPath:            "/path/to/public.pem",
			AccessExpiryDuration:     30 * time.Minute,
			AccessMaxLifetimeExpiry:  24 * time.Hour,
			RefreshExpiryDuration:    7 * 24 * time.Hour,
			RefreshMaxLifetimeExpiry: 30 * 24 * time.Hour,
			CleanupInterval:          1 * time.Hour,
		}

		err := validateConfig(config)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not compatible with asymmetric signing")
	})
}

func TestValidateConfig_InvalidScenarios(t *testing.T) {
	t.Run("zero access expiry duration", func(t *testing.T) {
		config := &GourdianTokenConfig{
			SigningMethod:            Symmetric,
			Algorithm:                "HS256",
			SymmetricKey:             "test-secret-key-that-is-at-least-32-bytes-long",
			AccessExpiryDuration:     0,
			AccessMaxLifetimeExpiry:  24 * time.Hour,
			RefreshExpiryDuration:    7 * 24 * time.Hour,
			RefreshMaxLifetimeExpiry: 30 * 24 * time.Hour,
			CleanupInterval:          1 * time.Hour,
		}

		err := validateConfig(config)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "access token duration must be positive")
	})

	t.Run("negative access expiry duration", func(t *testing.T) {
		config := &GourdianTokenConfig{
			SigningMethod:            Symmetric,
			Algorithm:                "HS256",
			SymmetricKey:             "test-secret-key-that-is-at-least-32-bytes-long",
			AccessExpiryDuration:     -1 * time.Minute,
			AccessMaxLifetimeExpiry:  24 * time.Hour,
			RefreshExpiryDuration:    7 * 24 * time.Hour,
			RefreshMaxLifetimeExpiry: 30 * 24 * time.Hour,
			CleanupInterval:          1 * time.Hour,
		}

		err := validateConfig(config)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "access token duration must be positive")
	})

	t.Run("access expiry exceeds max lifetime", func(t *testing.T) {
		config := &GourdianTokenConfig{
			SigningMethod:            Symmetric,
			Algorithm:                "HS256",
			SymmetricKey:             "test-secret-key-that-is-at-least-32-bytes-long",
			AccessExpiryDuration:     48 * time.Hour,
			AccessMaxLifetimeExpiry:  24 * time.Hour,
			RefreshExpiryDuration:    7 * 24 * time.Hour,
			RefreshMaxLifetimeExpiry: 30 * 24 * time.Hour,
			CleanupInterval:          1 * time.Hour,
		}

		err := validateConfig(config)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "access token duration exceeds max lifetime")
	})

	t.Run("zero refresh expiry duration", func(t *testing.T) {
		config := &GourdianTokenConfig{
			SigningMethod:            Symmetric,
			Algorithm:                "HS256",
			SymmetricKey:             "test-secret-key-that-is-at-least-32-bytes-long",
			AccessExpiryDuration:     30 * time.Minute,
			AccessMaxLifetimeExpiry:  24 * time.Hour,
			RefreshExpiryDuration:    0,
			RefreshMaxLifetimeExpiry: 30 * 24 * time.Hour,
			CleanupInterval:          1 * time.Hour,
		}

		err := validateConfig(config)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "refresh token duration must be positive")
	})

	t.Run("refresh expiry exceeds max lifetime", func(t *testing.T) {
		config := &GourdianTokenConfig{
			SigningMethod:            Symmetric,
			Algorithm:                "HS256",
			SymmetricKey:             "test-secret-key-that-is-at-least-32-bytes-long",
			AccessExpiryDuration:     30 * time.Minute,
			AccessMaxLifetimeExpiry:  24 * time.Hour,
			RefreshExpiryDuration:    60 * 24 * time.Hour,
			RefreshMaxLifetimeExpiry: 30 * 24 * time.Hour,
			CleanupInterval:          1 * time.Hour,
		}

		err := validateConfig(config)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "refresh token duration exceeds max lifetime")
	})

	t.Run("negative refresh reuse interval", func(t *testing.T) {
		config := &GourdianTokenConfig{
			SigningMethod:            Symmetric,
			Algorithm:                "HS256",
			SymmetricKey:             "test-secret-key-that-is-at-least-32-bytes-long",
			AccessExpiryDuration:     30 * time.Minute,
			AccessMaxLifetimeExpiry:  24 * time.Hour,
			RefreshExpiryDuration:    7 * 24 * time.Hour,
			RefreshMaxLifetimeExpiry: 30 * 24 * time.Hour,
			RefreshReuseInterval:     -1 * time.Minute,
			CleanupInterval:          1 * time.Hour,
		}

		err := validateConfig(config)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "refresh reuse interval cannot be negative")
	})

	t.Run("zero cleanup interval", func(t *testing.T) {
		config := &GourdianTokenConfig{
			SigningMethod:            Symmetric,
			Algorithm:                "HS256",
			SymmetricKey:             "test-secret-key-that-is-at-least-32-bytes-long",
			AccessExpiryDuration:     30 * time.Minute,
			AccessMaxLifetimeExpiry:  24 * time.Hour,
			RefreshExpiryDuration:    7 * 24 * time.Hour,
			RefreshMaxLifetimeExpiry: 30 * 24 * time.Hour,
			RefreshReuseInterval:     5 * time.Minute,
			CleanupInterval:          0,
		}

		err := validateConfig(config)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "cleanup interval must be positive")
	})

	t.Run("negative cleanup interval", func(t *testing.T) {
		config := &GourdianTokenConfig{
			SigningMethod:            Symmetric,
			Algorithm:                "HS256",
			SymmetricKey:             "test-secret-key-that-is-at-least-32-bytes-long",
			AccessExpiryDuration:     30 * time.Minute,
			AccessMaxLifetimeExpiry:  24 * time.Hour,
			RefreshExpiryDuration:    7 * 24 * time.Hour,
			RefreshMaxLifetimeExpiry: 30 * 24 * time.Hour,
			RefreshReuseInterval:     5 * time.Minute,
			CleanupInterval:          -1 * time.Hour,
		}

		err := validateConfig(config)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "cleanup interval must be positive")
	})

	t.Run("cleanup interval too short", func(t *testing.T) {
		config := &GourdianTokenConfig{
			SigningMethod:            Symmetric,
			Algorithm:                "HS256",
			SymmetricKey:             "test-secret-key-that-is-at-least-32-bytes-long",
			AccessExpiryDuration:     30 * time.Minute,
			AccessMaxLifetimeExpiry:  24 * time.Hour,
			RefreshExpiryDuration:    7 * 24 * time.Hour,
			RefreshMaxLifetimeExpiry: 30 * 24 * time.Hour,
			RefreshReuseInterval:     5 * time.Minute,
			CleanupInterval:          30 * time.Second,
		}

		err := validateConfig(config)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "cleanup interval too short")
	})

	t.Run("unsupported signing method", func(t *testing.T) {
		config := &GourdianTokenConfig{
			SigningMethod:            SigningMethod("invalid"),
			Algorithm:                "HS256",
			SymmetricKey:             "test-secret-key-that-is-at-least-32-bytes-long",
			AccessExpiryDuration:     30 * time.Minute,
			AccessMaxLifetimeExpiry:  24 * time.Hour,
			RefreshExpiryDuration:    7 * 24 * time.Hour,
			RefreshMaxLifetimeExpiry: 30 * 24 * time.Hour,
			CleanupInterval:          1 * time.Hour,
		}

		err := validateConfig(config)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported signing method")
	})

	t.Run("weak algorithm none", func(t *testing.T) {
		config := &GourdianTokenConfig{
			SigningMethod:            Symmetric,
			Algorithm:                "none",
			SymmetricKey:             "test-secret-key-that-is-at-least-32-bytes-long",
			AccessExpiryDuration:     30 * time.Minute,
			AccessMaxLifetimeExpiry:  24 * time.Hour,
			RefreshExpiryDuration:    7 * 24 * time.Hour,
			RefreshMaxLifetimeExpiry: 30 * 24 * time.Hour,
			CleanupInterval:          1 * time.Hour,
		}

		err := validateConfig(config)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "too weak for production use")
	})

	t.Run("unsupported algorithm in allowed list", func(t *testing.T) {
		config := &GourdianTokenConfig{
			SigningMethod:            Symmetric,
			Algorithm:                "HS256",
			SymmetricKey:             "test-secret-key-that-is-at-least-32-bytes-long",
			AllowedAlgorithms:        []string{"HS256", "INVALID_ALG"},
			AccessExpiryDuration:     30 * time.Minute,
			AccessMaxLifetimeExpiry:  24 * time.Hour,
			RefreshExpiryDuration:    7 * 24 * time.Hour,
			RefreshMaxLifetimeExpiry: 30 * 24 * time.Hour,
			CleanupInterval:          1 * time.Hour,
		}

		err := validateConfig(config)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported algorithm in AllowedAlgorithms")
	})
}

func TestValidateAlgorithmAndMethod(t *testing.T) {
	testCases := []struct {
		name          string
		signingMethod SigningMethod
		algorithm     string
		shouldError   bool
	}{
		{"HS256 with Symmetric", Symmetric, "HS256", false},
		{"HS384 with Symmetric", Symmetric, "HS384", false},
		{"HS512 with Symmetric", Symmetric, "HS512", false},
		{"RS256 with Asymmetric", Asymmetric, "RS256", false},
		{"RS384 with Asymmetric", Asymmetric, "RS384", false},
		{"RS512 with Asymmetric", Asymmetric, "RS512", false},
		{"ES256 with Asymmetric", Asymmetric, "ES256", false},
		{"ES384 with Asymmetric", Asymmetric, "ES384", false},
		{"ES512 with Asymmetric", Asymmetric, "ES512", false},
		{"PS256 with Asymmetric", Asymmetric, "PS256", false},
		{"PS384 with Asymmetric", Asymmetric, "PS384", false},
		{"PS512 with Asymmetric", Asymmetric, "PS512", false},
		{"EdDSA with Asymmetric", Asymmetric, "EdDSA", false},
		{"RS256 with Symmetric", Symmetric, "RS256", true},
		{"HS256 with Asymmetric", Asymmetric, "HS256", true},
		{"ES256 with Symmetric", Symmetric, "ES256", true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := &GourdianTokenConfig{
				SigningMethod: tc.signingMethod,
				Algorithm:     tc.algorithm,
			}

			err := validateAlgorithmAndMethod(config)
			if tc.shouldError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "not compatible")
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestNewGourdianTokenConfig(t *testing.T) {
	t.Run("creates config with all parameters", func(t *testing.T) {
		config := NewGourdianTokenConfig(
			Symmetric,
			true,
			true,
			[]string{"api.example.com"},
			[]string{"HS256", "RS256"},
			[]string{"iss", "aud"},
			"HS256",
			"test-secret-key-that-is-at-least-32-bytes-long",
			"",
			"",
			"test.com",
			30*time.Minute,
			24*time.Hour,
			7*24*time.Hour,
			30*24*time.Hour,
			5*time.Minute,
			1*time.Hour,
		)

		assert.Equal(t, Symmetric, config.SigningMethod)
		assert.True(t, config.RotationEnabled)
		assert.True(t, config.RevocationEnabled)
		assert.Equal(t, []string{"api.example.com"}, config.Audience)
		assert.Equal(t, []string{"HS256", "RS256"}, config.AllowedAlgorithms)
		assert.Equal(t, []string{"iss", "aud"}, config.RequiredClaims)
		assert.Equal(t, "HS256", config.Algorithm)
		assert.Equal(t, "test.com", config.Issuer)
		assert.Equal(t, 1*time.Hour, config.CleanupInterval)
	})
}
