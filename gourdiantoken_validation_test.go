// gourdiantoken_validation_test.go
package gourdiantoken

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestInitializeSigningMethod_EdgeCases(t *testing.T) {
	tests := []struct {
		name        string
		algorithm   string
		allowedAlgs []string
		expectedErr string
	}{
		{
			name:        "Unsupported algorithm",
			algorithm:   "INVALID",
			expectedErr: "unsupported algorithm",
		},
		{
			name:        "Algorithm not in allowed list",
			algorithm:   "HS384",
			allowedAlgs: []string{"HS256", "RS256"},
			expectedErr: "configured algorithm HS384 not in allowed algorithms list",
		},
		{
			name:        "Disabled none algorithm",
			algorithm:   "none",
			expectedErr: "unsecured tokens are disabled",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			maker := &JWTMaker{
				config: GourdianTokenConfig{
					Algorithm:         tt.algorithm,
					AllowedAlgorithms: tt.allowedAlgs,
				},
			}

			err := maker.initializeSigningMethod()
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.expectedErr)
		})
	}
}

// func TestValidateTokenClaims_EdgeCases(t *testing.T) {
// 	config := DefaultGourdianTokenConfig(testSymmetricKey)
// 	maker, err := NewGourdianTokenMaker(context.Background(), config, nil)
// 	require.NoError(t, err)

// 	now := time.Now()
// 	baseClaims := jwt.MapClaims{
// 		"jti": "invalid-uuid", // Will be replaced in each test
// 		"sub": "invalid-uuid",
// 		"usr": "testuser",
// 		"sid": "invalid-uuid",
// 		"iss": config.Issuer,
// 		"aud": config.Audience,
// 		"iat": now.Unix(),
// 		"exp": now.Add(time.Hour).Unix(),
// 		"typ": string(AccessToken),
// 		"rls": []string{"admin"},
// 	}

// 	tests := []struct {
// 		name        string
// 		modifyFn    func(jwt.MapClaims)
// 		expectedErr string
// 	}{
// 		{
// 			name: "Invalid JTI format",
// 			modifyFn: func(c jwt.MapClaims) {
// 				c["jti"] = "not-a-uuid"
// 			},
// 			expectedErr: "invalid token ID",
// 		},
// 		{
// 			name: "Invalid SUB format",
// 			modifyFn: func(c jwt.MapClaims) {
// 				c["sub"] = "not-a-uuid"
// 			},
// 			expectedErr: "invalid user ID",
// 		},
// 		{
// 			name: "Invalid SID format",
// 			modifyFn: func(c jwt.MapClaims) {
// 				c["sid"] = "not-a-uuid"
// 			},
// 			expectedErr: "invalid session ID",
// 		},
// 		{
// 			name: "Missing username",
// 			modifyFn: func(c jwt.MapClaims) {
// 				delete(c, "usr")
// 			},
// 			expectedErr: "missing required claim: usr",
// 		},
// 		{
// 			name: "Invalid username type",
// 			modifyFn: func(c jwt.MapClaims) {
// 				c["usr"] = 12345
// 			},
// 			expectedErr: "invalid username type",
// 		},
// 		{
// 			name: "Invalid issuer",
// 			modifyFn: func(c jwt.MapClaims) {
// 				c["iss"] = "wrong-issuer"
// 			},
// 			expectedErr: "invalid issuer",
// 		},
// 		{
// 			name: "Invalid audience",
// 			modifyFn: func(c jwt.MapClaims) {
// 				c["aud"] = "wrong-audience"
// 			},
// 			expectedErr: "invalid audience",
// 		},
// 		{
// 			name: "Invalid issued at time",
// 			modifyFn: func(c jwt.MapClaims) {
// 				c["iat"] = "not-a-number"
// 			},
// 			expectedErr: "invalid iat claim type",
// 		},
// 		{
// 			name: "Token from future",
// 			modifyFn: func(c jwt.MapClaims) {
// 				c["iat"] = time.Now().Add(time.Hour).Unix()
// 			},
// 			expectedErr: "token issued in the future",
// 		},
// 		{
// 			name: "Invalid expiration time",
// 			modifyFn: func(c jwt.MapClaims) {
// 				c["exp"] = "not-a-number"
// 			},
// 			expectedErr: "invalid exp claim type",
// 		},
// 		{
// 			name: "Expired token",
// 			modifyFn: func(c jwt.MapClaims) {
// 				c["exp"] = time.Now().Add(-time.Hour).Unix()
// 			},
// 			expectedErr: "token has expired",
// 		},
// 		{
// 			name: "Invalid token type",
// 			modifyFn: func(c jwt.MapClaims) {
// 				c["typ"] = "invalid-type"
// 			},
// 			expectedErr: "invalid token type",
// 		},
// 		{
// 			name: "Missing roles",
// 			modifyFn: func(c jwt.MapClaims) {
// 				delete(c, "rls")
// 			},
// 			expectedErr: "missing roles claim",
// 		},
// 		{
// 			name: "Invalid roles type",
// 			modifyFn: func(c jwt.MapClaims) {
// 				c["rls"] = "not-an-array"
// 			},
// 			expectedErr: "invalid roles type",
// 		},
// 		{
// 			name: "Empty roles array",
// 			modifyFn: func(c jwt.MapClaims) {
// 				c["rls"] = []string{}
// 			},
// 			expectedErr: "at least one role must be provided",
// 		},
// 		{
// 			name: "Invalid role type",
// 			modifyFn: func(c jwt.MapClaims) {
// 				c["rls"] = []interface{}{123}
// 			},
// 			expectedErr: "invalid role type",
// 		},
// 	}

// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			claims := make(jwt.MapClaims)
// 			for k, v := range baseClaims {
// 				claims[k] = v
// 			}

// 			// Set valid UUIDs by default
// 			claims["jti"] = uuid.New().String()
// 			claims["sub"] = uuid.New().String()
// 			claims["sid"] = uuid.New().String()

// 			tt.modifyFn(claims)

// 			token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
// 			tokenString, err := token.SignedString([]byte(config.SymmetricKey))
// 			require.NoError(t, err)

// 			_, err = maker.VerifyAccessToken(context.Background(), tokenString)
// 			require.Error(t, err)
// 			require.Contains(t, err.Error(), tt.expectedErr)
// 		})
// 	}
// }

// func TestInitializeKeys_EdgeCases(t *testing.T) {
// 	t.Run("Invalid Symmetric Key Length", func(t *testing.T) {
// 		maker := &JWTMaker{
// 			config: GourdianTokenConfig{
// 				SigningMethod: Symmetric,
// 				SymmetricKey:  "too-short",
// 			},
// 		}

// 		err := maker.initializeKeys()
// 		require.Error(t, err)
// 		require.Contains(t, err.Error(), "symmetric key must be at least 32 bytes")
// 	})

// 	t.Run("Missing Private Key File", func(t *testing.T) {
// 		maker := &JWTMaker{
// 			config: GourdianTokenConfig{
// 				SigningMethod:  Asymmetric,
// 				Algorithm:      "RS256",
// 				PrivateKeyPath: "nonexistent.key",
// 				PublicKeyPath:  "nonexistent.pub",
// 			},
// 		}

// 		err := maker.initializeKeys()
// 		require.Error(t, err)
// 		require.Contains(t, err.Error(), "failed to read private key file")
// 	})

// 	t.Run("Invalid Private Key Format", func(t *testing.T) {
// 		tempDir := t.TempDir()
// 		invalidKeyPath := filepath.Join(tempDir, "invalid.key")
// 		require.NoError(t, os.WriteFile(invalidKeyPath, []byte("invalid key data"), 0600))

// 		maker := &JWTMaker{
// 			config: GourdianTokenConfig{
// 				SigningMethod:  Asymmetric,
// 				Algorithm:      "RS256",
// 				PrivateKeyPath: invalidKeyPath,
// 				PublicKeyPath:  "nonexistent.pub",
// 			},
// 		}

// 		err := maker.initializeKeys()
// 		require.Error(t, err)
// 		require.Contains(t, err.Error(), "failed to parse RSA private key")
// 	})

// 	t.Run("Key Algorithm Mismatch", func(t *testing.T) {
// 		// Generate RSA key but try to use with EdDSA algorithm
// 		privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
// 		privBytes := x509.MarshalPKCS1PrivateKey(privKey)
// 		privBlock := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes}
// 		privPath := filepath.Join(t.TempDir(), "rsa.key")
// 		require.NoError(t, os.WriteFile(privPath, pem.EncodeToMemory(privBlock), 0600))

// 		// Generate Ed25519 public key
// 		pubKey, _, _ := ed25519.GenerateKey(rand.Reader)
// 		pubBytes, _ := x509.MarshalPKIXPublicKey(pubKey)
// 		pubBlock := &pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes}
// 		pubPath := filepath.Join(t.TempDir(), "ed25519.pub")
// 		require.NoError(t, os.WriteFile(pubPath, pem.EncodeToMemory(pubBlock), 0644))

// 		maker := &JWTMaker{
// 			config: GourdianTokenConfig{
// 				SigningMethod:  Asymmetric,
// 				Algorithm:      "EdDSA",
// 				PrivateKeyPath: privPath,
// 				PublicKeyPath:  pubPath,
// 			},
// 			signingMethod: jwt.SigningMethodEdDSA,
// 		}

// 		err := maker.initializeKeys()
// 		require.Error(t, err)
// 		require.Contains(t, err.Error(), "failed to parse EdDSA private key")
// 	})
// }

// func TestValidateConfig_EdgeCases(t *testing.T) {
// 	t.Run("Invalid Symmetric Config with Key Paths", func(t *testing.T) {
// 		config := GourdianTokenConfig{
// 			SigningMethod:     Symmetric,
// 			SymmetricKey:      testSymmetricKey,
// 			PrivateKeyPath:    "private.key",
// 			PublicKeyPath:     "public.key",
// 			Algorithm:         "HS256",
// 			AllowedAlgorithms: []string{"HS256"},
// 		}

// 		err := validateConfig(&config)
// 		require.Error(t, err)
// 		require.Contains(t, err.Error(), "private and public key paths must be empty for symmetric signing")
// 	})

// 	t.Run("Invalid Asymmetric Config with Symmetric Key", func(t *testing.T) {
// 		config := GourdianTokenConfig{
// 			SigningMethod:     Asymmetric,
// 			SymmetricKey:      testSymmetricKey,
// 			Algorithm:         "RS256",
// 			AllowedAlgorithms: []string{"RS256"},
// 		}

// 		err := validateConfig(&config)
// 		require.Error(t, err)
// 		require.Contains(t, err.Error(), "symmetric key must be empty for asymmetric signing")
// 	})

// 	t.Run("Invalid Expiry Durations", func(t *testing.T) {
// 		tests := []struct {
// 			name          string
// 			accessExpiry  time.Duration
// 			refreshExpiry time.Duration
// 			expectedErr   string
// 		}{
// 			{
// 				name:          "Negative access expiry",
// 				accessExpiry:  -time.Hour,
// 				refreshExpiry: time.Hour,
// 				expectedErr:   "access token duration must be positive",
// 			},
// 			{
// 				name:          "Negative refresh expiry",
// 				accessExpiry:  time.Hour,
// 				refreshExpiry: -time.Hour,
// 				expectedErr:   "refresh token duration must be positive",
// 			},
// 			{
// 				name:          "Access expiry exceeds max lifetime",
// 				accessExpiry:  48 * time.Hour,
// 				refreshExpiry: time.Hour,
// 				expectedErr:   "access token duration exceeds max lifetime",
// 			},
// 		}

// 		for _, tt := range tests {
// 			t.Run(tt.name, func(t *testing.T) {
// 				config := GourdianTokenConfig{
// 					SigningMethod:           Symmetric,
// 					SymmetricKey:            testSymmetricKey,
// 					Algorithm:               "HS256",
// 					AccessExpiryDuration:    tt.accessExpiry,
// 					AccessMaxLifetimeExpiry: 24 * time.Hour,
// 					RefreshExpiryDuration:   tt.refreshExpiry,
// 				}

// 				err := validateConfig(&config)
// 				require.Error(t, err)
// 				require.Contains(t, err.Error(), tt.expectedErr)
// 			})
// 		}
// 	})

// 	t.Run("Invalid Algorithm for Method", func(t *testing.T) {
// 		config := GourdianTokenConfig{
// 			SigningMethod: Symmetric,
// 			SymmetricKey:  testSymmetricKey,
// 			Algorithm:     "RS256", // RSA algorithm with symmetric method
// 		}

// 		err := validateConfig(&config)
// 		require.Error(t, err)
// 		require.Contains(t, err.Error(), "algorithm RS256 not compatible with symmetric signing")
// 	})

// 	t.Run("Unsupported Algorithm in AllowedAlgorithms", func(t *testing.T) {
// 		config := GourdianTokenConfig{
// 			SigningMethod:     Symmetric,
// 			SymmetricKey:      testSymmetricKey,
// 			Algorithm:         "HS256",
// 			AllowedAlgorithms: []string{"HS256", "INVALID"},
// 		}

// 		err := validateConfig(&config)
// 		require.Error(t, err)
// 		require.Contains(t, err.Error(), "unsupported algorithm in AllowedAlgorithms")
// 	})
// }
