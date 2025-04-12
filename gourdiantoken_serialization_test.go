// gourdiantoken_serialization_test.go

package gourdiantoken

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

// Test Cases
func TestTokenClaimsSerialization(t *testing.T) {
	t.Run("AccessTokenClaims", func(t *testing.T) {
		now := time.Now().UTC()
		claims := AccessTokenClaims{
			ID:        uuid.New(),
			Subject:   uuid.New(),
			Username:  "testuser",
			SessionID: uuid.New(),
			IssuedAt:  now,
			ExpiresAt: now.Add(time.Hour),
			TokenType: AccessToken,
			Roles:     []string{"admin", "user"},
		}

		// Test JSON serialization
		t.Run("JSONSerialization", func(t *testing.T) {
			jsonData, err := json.Marshal(claims)
			assert.NoError(t, err)

			var decoded AccessTokenClaims
			err = json.Unmarshal(jsonData, &decoded)
			assert.NoError(t, err)

			assert.Equal(t, claims.ID, decoded.ID)
			assert.Equal(t, claims.Subject, decoded.Subject)
			assert.Equal(t, claims.Username, decoded.Username)
			assert.Equal(t, claims.SessionID, decoded.SessionID)
			assert.Equal(t, claims.IssuedAt.Unix(), decoded.IssuedAt.Unix())
			assert.Equal(t, claims.ExpiresAt.Unix(), decoded.ExpiresAt.Unix())
			assert.Equal(t, claims.TokenType, decoded.TokenType)
			assert.Equal(t, claims.Roles, decoded.Roles)
		})

		// Test MapClaims conversion
		t.Run("MapClaimsConversion", func(t *testing.T) {
			mapClaims := toMapClaims(claims)
			assert.Equal(t, claims.ID.String(), mapClaims["jti"])
			assert.Equal(t, claims.Subject.String(), mapClaims["sub"])
			assert.Equal(t, claims.Username, mapClaims["usr"])
			assert.Equal(t, claims.SessionID.String(), mapClaims["sid"])
			assert.Equal(t, claims.IssuedAt.Unix(), mapClaims["iat"])
			assert.Equal(t, claims.ExpiresAt.Unix(), mapClaims["exp"])
			assert.Equal(t, string(claims.TokenType), mapClaims["typ"])
			assert.Equal(t, claims.Roles, mapClaims["rls"])
		})

		// Test claim mapping back from MapClaims
		t.Run("MapToAccessClaims", func(t *testing.T) {
			mapClaims := toMapClaims(claims)
			decodedClaims, err := mapToAccessClaims(mapClaims)
			assert.NoError(t, err)

			assert.Equal(t, claims.ID, decodedClaims.ID)
			assert.Equal(t, claims.Subject, decodedClaims.Subject)
			assert.Equal(t, claims.Username, decodedClaims.Username)
			assert.Equal(t, claims.SessionID, decodedClaims.SessionID)
			assert.Equal(t, claims.IssuedAt.Unix(), decodedClaims.IssuedAt.Unix())
			assert.Equal(t, claims.ExpiresAt.Unix(), decodedClaims.ExpiresAt.Unix())
			assert.Equal(t, claims.TokenType, decodedClaims.TokenType)
			assert.Equal(t, claims.Roles, decodedClaims.Roles)
		})
	})

	t.Run("RefreshTokenClaims", func(t *testing.T) {
		now := time.Now().UTC()
		claims := RefreshTokenClaims{
			ID:        uuid.New(),
			Subject:   uuid.New(),
			Username:  "testuser",
			SessionID: uuid.New(),
			IssuedAt:  now,
			ExpiresAt: now.Add(24 * time.Hour),
			TokenType: RefreshToken,
		}

		// Test JSON serialization
		t.Run("JSONSerialization", func(t *testing.T) {
			jsonData, err := json.Marshal(claims)
			assert.NoError(t, err)

			var decoded RefreshTokenClaims
			err = json.Unmarshal(jsonData, &decoded)
			assert.NoError(t, err)

			assert.Equal(t, claims.ID, decoded.ID)
			assert.Equal(t, claims.Subject, decoded.Subject)
			assert.Equal(t, claims.Username, decoded.Username)
			assert.Equal(t, claims.SessionID, decoded.SessionID)
			assert.Equal(t, claims.IssuedAt.Unix(), decoded.IssuedAt.Unix())
			assert.Equal(t, claims.ExpiresAt.Unix(), decoded.ExpiresAt.Unix())
			assert.Equal(t, claims.TokenType, decoded.TokenType)
		})

		// Test MapClaims conversion
		t.Run("MapClaimsConversion", func(t *testing.T) {
			mapClaims := toMapClaims(claims)
			assert.Equal(t, claims.ID.String(), mapClaims["jti"])
			assert.Equal(t, claims.Subject.String(), mapClaims["sub"])
			assert.Equal(t, claims.Username, mapClaims["usr"])
			assert.Equal(t, claims.SessionID.String(), mapClaims["sid"])
			assert.Equal(t, claims.IssuedAt.Unix(), mapClaims["iat"])
			assert.Equal(t, claims.ExpiresAt.Unix(), mapClaims["exp"])
			assert.Equal(t, string(claims.TokenType), mapClaims["typ"])
		})

		// Test claim mapping back from MapClaims
		t.Run("MapToRefreshClaims", func(t *testing.T) {
			mapClaims := toMapClaims(claims)
			decodedClaims, err := mapToRefreshClaims(mapClaims)
			assert.NoError(t, err)

			assert.Equal(t, claims.ID, decodedClaims.ID)
			assert.Equal(t, claims.Subject, decodedClaims.Subject)
			assert.Equal(t, claims.Username, decodedClaims.Username)
			assert.Equal(t, claims.SessionID, decodedClaims.SessionID)
			assert.Equal(t, claims.IssuedAt.Unix(), decodedClaims.IssuedAt.Unix())
			assert.Equal(t, claims.ExpiresAt.Unix(), decodedClaims.ExpiresAt.Unix())
			assert.Equal(t, claims.TokenType, decodedClaims.TokenType)
		})
	})
}

func TestTokenMakerInitialization(t *testing.T) {
	t.Run("DefaultSymmetricConfig", func(t *testing.T) {
		config := DefaultGourdianTokenConfig(testSymmetricKey)
		maker := createTestMaker(t, config)
		assert.NotNil(t, maker)
		assert.Equal(t, jwt.SigningMethodHS256, maker.signingMethod)
	})

	t.Run("SymmetricWithDifferentAlgorithms", func(t *testing.T) {
		testCases := []struct {
			algorithm string
			method    jwt.SigningMethod
		}{
			{"HS256", jwt.SigningMethodHS256},
			{"HS384", jwt.SigningMethodHS384},
			{"HS512", jwt.SigningMethodHS512},
		}

		for _, tc := range testCases {
			t.Run(tc.algorithm, func(t *testing.T) {
				config := DefaultGourdianTokenConfig(testSymmetricKey)
				config.Algorithm = tc.algorithm
				maker := createTestMaker(t, config)
				assert.Equal(t, tc.method, maker.signingMethod)
			})
		}
	})

	t.Run("AsymmetricRSA", func(t *testing.T) {
		privatePath, publicPath := generateTestRSAKeys(t)
		defer os.Remove(privatePath)
		defer os.Remove(publicPath)

		testCases := []struct {
			algorithm string
			method    jwt.SigningMethod
		}{
			{"RS256", jwt.SigningMethodRS256},
			{"RS384", jwt.SigningMethodRS384},
			{"RS512", jwt.SigningMethodRS512},
			{"PS256", jwt.SigningMethodPS256},
			{"PS384", jwt.SigningMethodPS384},
			{"PS512", jwt.SigningMethodPS512},
		}

		for _, tc := range testCases {
			t.Run(tc.algorithm, func(t *testing.T) {
				config := DefaultGourdianTokenConfig("")
				config.SigningMethod = Asymmetric
				config.Algorithm = tc.algorithm
				config.PrivateKeyPath = privatePath
				config.PublicKeyPath = publicPath
				maker := createTestMaker(t, config)
				assert.Equal(t, tc.method, maker.signingMethod)
				assert.IsType(t, &rsa.PrivateKey{}, maker.privateKey)
				assert.IsType(t, &rsa.PublicKey{}, maker.publicKey)
			})
		}
	})

	t.Run("AsymmetricECDSA", func(t *testing.T) {
		privatePath, publicPath := generateTestECDSAKeys(t)
		defer os.Remove(privatePath)
		defer os.Remove(publicPath)

		testCases := []struct {
			algorithm string
			method    jwt.SigningMethod
		}{
			{"ES256", jwt.SigningMethodES256},
			{"ES384", jwt.SigningMethodES384},
			{"ES512", jwt.SigningMethodES512},
		}

		for _, tc := range testCases {
			t.Run(tc.algorithm, func(t *testing.T) {
				config := DefaultGourdianTokenConfig("")
				config.SigningMethod = Asymmetric
				config.Algorithm = tc.algorithm
				config.PrivateKeyPath = privatePath
				config.PublicKeyPath = publicPath
				maker := createTestMaker(t, config)
				assert.Equal(t, tc.method, maker.signingMethod)
				assert.IsType(t, &ecdsa.PrivateKey{}, maker.privateKey)
				assert.IsType(t, &ecdsa.PublicKey{}, maker.publicKey)
			})
		}
	})

	t.Run("AsymmetricEdDSA", func(t *testing.T) {
		privatePath, publicPath := generateTestEdDSAKeys(t)
		defer os.Remove(privatePath)
		defer os.Remove(publicPath)

		config := DefaultGourdianTokenConfig("")
		config.SigningMethod = Asymmetric
		config.Algorithm = "EdDSA"
		config.PrivateKeyPath = privatePath
		config.PublicKeyPath = publicPath
		maker := createTestMaker(t, config)
		assert.Equal(t, jwt.SigningMethodEdDSA, maker.signingMethod)
		assert.IsType(t, ed25519.PrivateKey{}, maker.privateKey)
		assert.IsType(t, ed25519.PublicKey{}, maker.publicKey)
	})

	t.Run("InvalidConfigurations", func(t *testing.T) {
		testCases := []struct {
			name        string
			config      GourdianTokenConfig
			expectedErr string
		}{
			{
				name: "EmptySymmetricKey",
				config: GourdianTokenConfig{
					SigningMethod: Symmetric,
					Algorithm:     "HS256",
					SymmetricKey:  "",
				},
				expectedErr: "symmetric key is required",
			},
			{
				name: "ShortSymmetricKey",
				config: GourdianTokenConfig{
					SigningMethod: Symmetric,
					Algorithm:     "HS256",
					SymmetricKey:  "too-short",
				},
				expectedErr: "symmetric key must be at least 32 bytes",
			},
			{
				name: "AsymmetricMissingPrivateKey",
				config: GourdianTokenConfig{
					SigningMethod:  Asymmetric,
					Algorithm:      "RS256",
					PublicKeyPath:  "public.pem",
					PrivateKeyPath: "",
				},
				expectedErr: "private and public key paths are required",
			},
			{
				name: "UnsupportedAlgorithm",
				config: GourdianTokenConfig{
					SigningMethod: Symmetric,
					Algorithm:     "UNSUPPORTED",
					SymmetricKey:  testSymmetricKey,
				},
				expectedErr: "unsupported algorithm",
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				ctx := context.Background()
				_, err := NewGourdianTokenMaker(ctx, tc.config, testRedisOpts)
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectedErr)
			})
		}
	})
}

func TestTokenCreationAndVerification(t *testing.T) {
	ctx := context.Background()

	t.Run("SymmetricHS256", func(t *testing.T) {
		config := DefaultGourdianTokenConfig(testSymmetricKey)
		maker := createTestMaker(t, config)

		userID := uuid.New()
		sessionID := uuid.New()
		roles := []string{"admin", "user"}

		t.Run("CreateAndVerifyAccessToken", func(t *testing.T) {
			accessToken, err := maker.CreateAccessToken(ctx, userID, "testuser", roles, sessionID)
			assert.NoError(t, err)
			assert.NotEmpty(t, accessToken.Token)

			claims, err := maker.VerifyAccessToken(ctx, accessToken.Token)
			assert.NoError(t, err)
			assert.Equal(t, userID, claims.Subject)
			assert.Equal(t, "testuser", claims.Username)
			assert.Equal(t, sessionID, claims.SessionID)
			assert.Equal(t, roles, claims.Roles)
			assert.Equal(t, AccessToken, claims.TokenType)
		})

		t.Run("CreateAndVerifyRefreshToken", func(t *testing.T) {
			refreshToken, err := maker.CreateRefreshToken(ctx, userID, "testuser", sessionID)
			assert.NoError(t, err)
			assert.NotEmpty(t, refreshToken.Token)

			claims, err := maker.VerifyRefreshToken(ctx, refreshToken.Token)
			assert.NoError(t, err)
			assert.Equal(t, userID, claims.Subject)
			assert.Equal(t, "testuser", claims.Username)
			assert.Equal(t, sessionID, claims.SessionID)
			assert.Equal(t, RefreshToken, claims.TokenType)
		})
	})

	t.Run("AsymmetricRS256", func(t *testing.T) {
		privatePath, publicPath := generateTestRSAKeys(t)
		defer os.Remove(privatePath)
		defer os.Remove(publicPath)

		config := DefaultGourdianTokenConfig("")
		config.SigningMethod = Asymmetric
		config.Algorithm = "RS256"
		config.PrivateKeyPath = privatePath
		config.PublicKeyPath = publicPath
		maker := createTestMaker(t, config)

		userID := uuid.New()
		sessionID := uuid.New()
		roles := []string{"admin"}

		t.Run("CreateAndVerifyAccessToken", func(t *testing.T) {
			accessToken, err := maker.CreateAccessToken(ctx, userID, "rsa-user", roles, sessionID)
			assert.NoError(t, err)
			assert.NotEmpty(t, accessToken.Token)

			claims, err := maker.VerifyAccessToken(ctx, accessToken.Token)
			assert.NoError(t, err)
			assert.Equal(t, userID, claims.Subject)
			assert.Equal(t, "rsa-user", claims.Username)
			assert.Equal(t, sessionID, claims.SessionID)
			assert.Equal(t, roles, claims.Roles)
		})
	})

	t.Run("InvalidTokens", func(t *testing.T) {
		config := DefaultGourdianTokenConfig(testSymmetricKey)
		maker := createTestMaker(t, config)

		t.Run("ExpiredToken", func(t *testing.T) {
			// Create a token that expired 1 hour ago
			claims := AccessTokenClaims{
				ID:        uuid.New(),
				Subject:   uuid.New(),
				Username:  "expired",
				SessionID: uuid.New(),
				IssuedAt:  time.Now().Add(-2 * time.Hour),
				ExpiresAt: time.Now().Add(-1 * time.Hour),
				TokenType: AccessToken,
				Roles:     []string{"user"},
			}

			token := jwt.NewWithClaims(maker.signingMethod, toMapClaims(claims))
			tokenString, err := token.SignedString(maker.privateKey)
			assert.NoError(t, err)

			_, err = maker.VerifyAccessToken(ctx, tokenString)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "token has expired")
		})

		t.Run("InvalidSignature", func(t *testing.T) {
			// Create a valid token
			accessToken, err := maker.CreateAccessToken(ctx, uuid.New(), "testuser", []string{"user"}, uuid.New())
			assert.NoError(t, err)

			// Tamper with the token by changing a character in the signature
			tamperedToken := accessToken.Token[:len(accessToken.Token)-2] + "XX"

			_, err = maker.VerifyAccessToken(ctx, tamperedToken)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "signature is invalid")
		})

		t.Run("MissingRequiredClaims", func(t *testing.T) {
			// Create a token missing the 'exp' claim
			claims := jwt.MapClaims{
				"jti": uuid.New().String(),
				"sub": uuid.New().String(),
				"usr": "testuser",
				"sid": uuid.New().String(),
				"iat": time.Now().Unix(),
				"typ": string(AccessToken),
				"rls": []string{"user"},
			}

			token := jwt.NewWithClaims(maker.signingMethod, claims)
			tokenString, err := token.SignedString(maker.privateKey)
			assert.NoError(t, err)

			_, err = maker.VerifyAccessToken(ctx, tokenString)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "missing required claim: exp")
		})
	})
}

func TestTokenRevocation(t *testing.T) {
	ctx := context.Background()

	t.Run("AccessTokenRevocation", func(t *testing.T) {
		config := DefaultGourdianTokenConfig(testSymmetricKey)
		config.AccessToken.RevocationEnabled = true
		maker := createTestMaker(t, config)

		accessToken, err := maker.CreateAccessToken(ctx, uuid.New(), "revoke-test", []string{"user"}, uuid.New())
		assert.NoError(t, err)

		// Verify token works before revocation
		_, err = maker.VerifyAccessToken(ctx, accessToken.Token)
		assert.NoError(t, err)

		// Revoke the token
		err = maker.RevokeAccessToken(ctx, accessToken.Token)
		assert.NoError(t, err)

		// Verify token is now rejected
		_, err = maker.VerifyAccessToken(ctx, accessToken.Token)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "token has been revoked")
	})

	t.Run("RefreshTokenRevocation", func(t *testing.T) {
		config := DefaultGourdianTokenConfig(testSymmetricKey)
		config.RefreshToken.RevocationEnabled = true
		maker := createTestMaker(t, config)

		refreshToken, err := maker.CreateRefreshToken(ctx, uuid.New(), "revoke-test", uuid.New())
		assert.NoError(t, err)

		// Verify token works before revocation
		_, err = maker.VerifyRefreshToken(ctx, refreshToken.Token)
		assert.NoError(t, err)

		// Revoke the token
		err = maker.RevokeRefreshToken(ctx, refreshToken.Token)
		assert.NoError(t, err)

		// Verify token is now rejected
		_, err = maker.VerifyRefreshToken(ctx, refreshToken.Token)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "token has been revoked")
	})

	t.Run("RevocationDisabled", func(t *testing.T) {
		config := DefaultGourdianTokenConfig(testSymmetricKey)
		config.AccessToken.RevocationEnabled = false
		maker := createTestMaker(t, config)

		accessToken, err := maker.CreateAccessToken(ctx, uuid.New(), "revoke-test", []string{"user"}, uuid.New())
		assert.NoError(t, err)

		err = maker.RevokeAccessToken(ctx, accessToken.Token)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "access token revocation is not enabled")
	})
}

func TestRefreshTokenRotation(t *testing.T) {
	ctx := context.Background()

	t.Run("SuccessfulRotation", func(t *testing.T) {
		config := DefaultGourdianTokenConfig(testSymmetricKey)
		config.RefreshToken.RotationEnabled = true
		maker := createTestMaker(t, config)

		userID := uuid.New()
		sessionID := uuid.New()

		// Create initial refresh token
		oldToken, err := maker.CreateRefreshToken(ctx, userID, "rotation-test", sessionID)
		assert.NoError(t, err)

		// Rotate the token
		newToken, err := maker.RotateRefreshToken(ctx, oldToken.Token)
		assert.NoError(t, err)
		assert.NotEqual(t, oldToken.Token, newToken.Token)
		assert.Equal(t, userID, newToken.Subject)
		assert.Equal(t, sessionID, newToken.SessionID)

		// Verify the new token works
		_, err = maker.VerifyRefreshToken(ctx, newToken.Token)
		assert.NoError(t, err)

		// Old token should be marked as rotated and rejected if used again
		_, err = maker.RotateRefreshToken(ctx, oldToken.Token)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "token reused too soon")
	})

	t.Run("RotationDisabled", func(t *testing.T) {
		config := DefaultGourdianTokenConfig(testSymmetricKey)
		config.RefreshToken.RotationEnabled = false
		maker := createTestMaker(t, config)

		refreshToken, err := maker.CreateRefreshToken(ctx, uuid.New(), "rotation-test", uuid.New())
		assert.NoError(t, err)

		_, err = maker.RotateRefreshToken(ctx, refreshToken.Token)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "token rotation not enabled")
	})

	t.Run("ReuseProtection", func(t *testing.T) {
		config := DefaultGourdianTokenConfig(testSymmetricKey)
		config.RefreshToken.RotationEnabled = true
		config.RefreshToken.ReuseInterval = time.Minute
		maker := createTestMaker(t, config)

		userID := uuid.New()
		sessionID := uuid.New()

		// Create and rotate token
		oldToken, err := maker.CreateRefreshToken(ctx, userID, "reuse-test", sessionID)
		assert.NoError(t, err)

		_, err = maker.RotateRefreshToken(ctx, oldToken.Token)
		assert.NoError(t, err)

		// Immediate reuse attempt should fail
		_, err = maker.RotateRefreshToken(ctx, oldToken.Token)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "token reused too soon")
	})
}

func TestTokenValidation(t *testing.T) {
	ctx := context.Background()
	config := DefaultGourdianTokenConfig(testSymmetricKey)
	maker := createTestMaker(t, config)

	t.Run("InvalidTokenType", func(t *testing.T) {
		// Create an access token but claim it's a refresh token
		claims := AccessTokenClaims{
			ID:        uuid.New(),
			Subject:   uuid.New(),
			Username:  "invalid-type",
			SessionID: uuid.New(),
			IssuedAt:  time.Now(),
			ExpiresAt: time.Now().Add(time.Hour),
			TokenType: RefreshToken, // Wrong type
			Roles:     []string{"user"},
		}

		token := jwt.NewWithClaims(maker.signingMethod, toMapClaims(claims))
		tokenString, err := token.SignedString(maker.privateKey)
		assert.NoError(t, err)

		_, err = maker.VerifyAccessToken(ctx, tokenString)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid token type: expected access")
	})

	t.Run("FutureIssuedAt", func(t *testing.T) {
		// Create a token with iat in the future
		claims := AccessTokenClaims{
			ID:        uuid.New(),
			Subject:   uuid.New(),
			Username:  "future-iat",
			SessionID: uuid.New(),
			IssuedAt:  time.Now().Add(time.Hour),
			ExpiresAt: time.Now().Add(2 * time.Hour),
			TokenType: AccessToken,
			Roles:     []string{"user"},
		}

		token := jwt.NewWithClaims(maker.signingMethod, toMapClaims(claims))
		tokenString, err := token.SignedString(maker.privateKey)
		assert.NoError(t, err)

		_, err = maker.VerifyAccessToken(ctx, tokenString)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "token issued in the future")
	})

	t.Run("InvalidUUIDs", func(t *testing.T) {
		// Create a token with invalid UUID strings
		claims := jwt.MapClaims{
			"jti": "not-a-uuid",
			"sub": uuid.New().String(),
			"usr": "invalid-uuid",
			"sid": uuid.New().String(),
			"iat": time.Now().Unix(),
			"exp": time.Now().Add(time.Hour).Unix(),
			"typ": string(AccessToken),
			"rls": []string{"user"},
		}

		token := jwt.NewWithClaims(maker.signingMethod, claims)
		tokenString, err := token.SignedString(maker.privateKey)
		assert.NoError(t, err)

		_, err = maker.VerifyAccessToken(ctx, tokenString)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid token ID")
	})
}
