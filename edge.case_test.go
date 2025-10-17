// File: edge.case_test.go


package gourdiantoken

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestContextCancellation tests various context cancellation scenarios
func TestContextCancellation(t *testing.T) {
	t.Run("canceled context during maker creation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		config := DefaultTestConfig()
		maker, err := NewGourdianTokenMaker(ctx, config, nil)

		assert.Error(t, err)
		assert.Nil(t, maker)
		assert.Contains(t, err.Error(), "context canceled")
	})

	t.Run("canceled context during token creation", func(t *testing.T) {
		maker := setupTestMaker(t)

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		userID := uuid.New()
		token, err := maker.CreateAccessToken(ctx, userID, "user", []string{"admin"}, uuid.New())

		assert.Error(t, err)
		assert.Nil(t, token)
		assert.Contains(t, err.Error(), "context canceled")
	})

	t.Run("canceled context during token verification", func(t *testing.T) {
		maker := setupTestMaker(t)

		// Create token with valid context
		token, err := maker.CreateAccessToken(context.Background(), uuid.New(), "user", []string{"admin"}, uuid.New())
		require.NoError(t, err)

		// Verify with canceled context
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		claims, err := maker.VerifyAccessToken(ctx, token.Token)
		assert.Error(t, err)
		assert.Nil(t, claims)
		assert.Contains(t, err.Error(), "context canceled")
	})

	t.Run("timeout context during token operations", func(t *testing.T) {
		maker := setupTestMaker(t)

		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
		defer cancel()

		time.Sleep(10 * time.Millisecond) // Ensure timeout

		userID := uuid.New()
		token, err := maker.CreateAccessToken(ctx, userID, "user", []string{"admin"}, uuid.New())

		assert.Error(t, err)
		assert.Nil(t, token)
	})

	t.Run("canceled context during revocation", func(t *testing.T) {
		maker := setupTestMakerWithRepo(t)

		// Create token
		token, err := maker.CreateAccessToken(context.Background(), uuid.New(), "user", []string{"admin"}, uuid.New())
		require.NoError(t, err)

		// Revoke with canceled context
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		err = maker.RevokeAccessToken(ctx, token.Token)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "context canceled")
	})

	t.Run("canceled context during rotation", func(t *testing.T) {
		maker := setupTestMakerWithRepo(t)

		// Create refresh token
		token, err := maker.CreateRefreshToken(context.Background(), uuid.New(), "user", uuid.New())
		require.NoError(t, err)

		// Rotate with canceled context
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		newToken, err := maker.RotateRefreshToken(ctx, token.Token)
		assert.Error(t, err)
		assert.Nil(t, newToken)
		assert.Contains(t, err.Error(), "context canceled")
	})
}

// TestInvalidUUIDs tests handling of invalid UUID formats
func TestInvalidUUIDs(t *testing.T) {
	maker := setupTestMaker(t)

	t.Run("invalid UUID in token claims - jti", func(t *testing.T) {
		now := time.Now()
		claims := jwt.MapClaims{
			"jti": "not-a-valid-uuid",
			"sub": uuid.New().String(),
			"sid": uuid.New().String(),
			"usr": "testuser",
			"iss": maker.config.Issuer,
			"aud": maker.config.Audience,
			"rls": []string{"admin"},
			"iat": now.Unix(),
			"exp": now.Add(30 * time.Minute).Unix(),
			"nbf": now.Unix(),
			"mle": now.Add(24 * time.Hour).Unix(),
			"typ": string(AccessToken),
		}

		token := jwt.NewWithClaims(maker.signingMethod, claims)
		signedToken, err := token.SignedString(maker.privateKey)
		require.NoError(t, err)

		accessClaims, err := maker.VerifyAccessToken(context.Background(), signedToken)
		assert.Error(t, err)
		assert.Nil(t, accessClaims)
		assert.Contains(t, err.Error(), "invalid token ID")
	})

	t.Run("invalid UUID in token claims - sub", func(t *testing.T) {
		now := time.Now()
		claims := jwt.MapClaims{
			"jti": uuid.New().String(),
			"sub": "invalid-user-uuid",
			"sid": uuid.New().String(),
			"usr": "testuser",
			"iss": maker.config.Issuer,
			"aud": maker.config.Audience,
			"rls": []string{"admin"},
			"iat": now.Unix(),
			"exp": now.Add(30 * time.Minute).Unix(),
			"nbf": now.Unix(),
			"mle": now.Add(24 * time.Hour).Unix(),
			"typ": string(AccessToken),
		}

		token := jwt.NewWithClaims(maker.signingMethod, claims)
		signedToken, err := token.SignedString(maker.privateKey)
		require.NoError(t, err)

		accessClaims, err := maker.VerifyAccessToken(context.Background(), signedToken)
		assert.Error(t, err)
		assert.Nil(t, accessClaims)
		assert.Contains(t, err.Error(), "invalid user ID")
	})

	t.Run("invalid UUID in token claims - sid", func(t *testing.T) {
		now := time.Now()
		claims := jwt.MapClaims{
			"jti": uuid.New().String(),
			"sub": uuid.New().String(),
			"sid": "bad-session-id",
			"usr": "testuser",
			"iss": maker.config.Issuer,
			"aud": maker.config.Audience,
			"rls": []string{"admin"},
			"iat": now.Unix(),
			"exp": now.Add(30 * time.Minute).Unix(),
			"nbf": now.Unix(),
			"mle": now.Add(24 * time.Hour).Unix(),
			"typ": string(AccessToken),
		}

		token := jwt.NewWithClaims(maker.signingMethod, claims)
		signedToken, err := token.SignedString(maker.privateKey)
		require.NoError(t, err)

		accessClaims, err := maker.VerifyAccessToken(context.Background(), signedToken)
		assert.Error(t, err)
		assert.Nil(t, accessClaims)
		assert.Contains(t, err.Error(), "invalid session ID")
	})

	t.Run("non-string UUID types", func(t *testing.T) {
		now := time.Now()
		claims := jwt.MapClaims{
			"jti": 12345, // Wrong type
			"sub": uuid.New().String(),
			"sid": uuid.New().String(),
			"usr": "testuser",
			"iss": maker.config.Issuer,
			"aud": maker.config.Audience,
			"rls": []string{"admin"},
			"iat": now.Unix(),
			"exp": now.Add(30 * time.Minute).Unix(),
			"nbf": now.Unix(),
			"mle": now.Add(24 * time.Hour).Unix(),
			"typ": string(AccessToken),
		}

		token := jwt.NewWithClaims(maker.signingMethod, claims)
		signedToken, err := token.SignedString(maker.privateKey)
		require.NoError(t, err)

		accessClaims, err := maker.VerifyAccessToken(context.Background(), signedToken)
		assert.Error(t, err)
		assert.Nil(t, accessClaims)
	})
}

// TestMalformedTokens tests handling of various malformed token formats
func TestMalformedTokens(t *testing.T) {
	maker := setupTestMaker(t)
	ctx := context.Background()

	testCases := []struct {
		name  string
		token string
	}{
		{"empty token", ""},
		{"single part", "onlyonepart"},
		{"two parts", "two.parts"},
		{"invalid base64", "invalid!!!.base64###.encoding$$$"},
		{"corrupted header", "corrupted.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature"},
		{"corrupted payload", "eyJhbGciOiJIUzI1NiJ9.corrupted!!!.signature"},
		{"missing signature", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0."},
		{"extra dots", "part1.part2.part3.part4"},
		{"non-JWT string", "this-is-not-a-jwt-token-at-all"},
		{"null bytes", "header\x00.payload\x00.signature\x00"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			claims, err := maker.VerifyAccessToken(ctx, tc.token)
			assert.Error(t, err)
			assert.Nil(t, claims)
		})
	}

	t.Run("token with invalid JSON in payload", func(t *testing.T) {
		// Manually construct a token with invalid JSON
		invalidToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.aW52YWxpZC1qc29u.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

		claims, err := maker.VerifyAccessToken(ctx, invalidToken)
		assert.Error(t, err)
		assert.Nil(t, claims)
	})

	t.Run("extremely long token", func(t *testing.T) {
		longString := make([]byte, 100000)
		for i := range longString {
			longString[i] = 'a'
		}

		claims, err := maker.VerifyAccessToken(ctx, string(longString))
		assert.Error(t, err)
		assert.Nil(t, claims)
	})
}

// TestEmptyClaims tests handling of missing or empty claim values
func TestEmptyClaims(t *testing.T) {
	maker := setupTestMaker(t)
	now := time.Now()

	testCases := []struct {
		name          string
		claims        jwt.MapClaims
		expectedError string
	}{
		{
			name: "missing jti",
			claims: jwt.MapClaims{
				"sub": uuid.New().String(),
				"sid": uuid.New().String(),
				"usr": "user",
				"iss": maker.config.Issuer,   // ADD THIS
				"aud": maker.config.Audience, // ADD THIS
				"rls": []string{"admin"},
				"iat": now.Unix(),
				"exp": now.Add(30 * time.Minute).Unix(),
				"nbf": now.Unix(),                     // ADD THIS
				"mle": now.Add(24 * time.Hour).Unix(), // ADD THIS
				"typ": string(AccessToken),
			},
			expectedError: "missing required claim",
		},
		{
			name: "missing sub",
			claims: jwt.MapClaims{
				"jti": uuid.New().String(),
				"sid": uuid.New().String(),
				"usr": "user",
				"iss": maker.config.Issuer,   // ADD THIS
				"aud": maker.config.Audience, // ADD THIS
				"rls": []string{"admin"},
				"iat": now.Unix(),
				"exp": now.Add(30 * time.Minute).Unix(),
				"nbf": now.Unix(),                     // ADD THIS
				"mle": now.Add(24 * time.Hour).Unix(), // ADD THIS
				"typ": string(AccessToken),
			},
			expectedError: "missing required claim",
		},
		{
			name: "missing iat",
			claims: jwt.MapClaims{
				"jti": uuid.New().String(),
				"sub": uuid.New().String(),
				"sid": uuid.New().String(),
				"usr": "user",
				"iss": maker.config.Issuer,   // ADD THIS
				"aud": maker.config.Audience, // ADD THIS
				"rls": []string{"admin"},
				"exp": now.Add(30 * time.Minute).Unix(),
				"nbf": now.Unix(),                     // ADD THIS
				"mle": now.Add(24 * time.Hour).Unix(), // ADD THIS
				"typ": string(AccessToken),
			},
			expectedError: "missing required claim",
		},
		{
			name: "missing exp",
			claims: jwt.MapClaims{
				"jti": uuid.New().String(),
				"sub": uuid.New().String(),
				"sid": uuid.New().String(),
				"usr": "user",
				"iss": maker.config.Issuer,   // ADD THIS
				"aud": maker.config.Audience, // ADD THIS
				"rls": []string{"admin"},
				"iat": now.Unix(),
				"nbf": now.Unix(),                     // ADD THIS
				"mle": now.Add(24 * time.Hour).Unix(), // ADD THIS
				"typ": string(AccessToken),
			},
			expectedError: "missing required claim",
		},
		{
			name: "missing typ",
			claims: jwt.MapClaims{
				"jti": uuid.New().String(),
				"sub": uuid.New().String(),
				"sid": uuid.New().String(),
				"usr": "user",
				"iss": maker.config.Issuer,   // ADD THIS
				"aud": maker.config.Audience, // ADD THIS
				"rls": []string{"admin"},
				"iat": now.Unix(),
				"exp": now.Add(30 * time.Minute).Unix(),
				"nbf": now.Unix(),                     // ADD THIS
				"mle": now.Add(24 * time.Hour).Unix(), // ADD THIS
			},
			expectedError: "missing required claim",
		},
		{
			name: "empty string jti",
			claims: jwt.MapClaims{
				"jti": "",
				"sub": uuid.New().String(),
				"sid": uuid.New().String(),
				"usr": "user",
				"iss": maker.config.Issuer,   // ADD THIS
				"aud": maker.config.Audience, // ADD THIS
				"rls": []string{"admin"},
				"iat": now.Unix(),
				"exp": now.Add(30 * time.Minute).Unix(),
				"nbf": now.Unix(),                     // ADD THIS
				"mle": now.Add(24 * time.Hour).Unix(), // ADD THIS
				"typ": string(AccessToken),
			},
			expectedError: "invalid token ID",
		},
		{
			name: "null jti",
			claims: jwt.MapClaims{
				"jti": nil,
				"sub": uuid.New().String(),
				"sid": uuid.New().String(),
				"usr": "user",
				"iss": maker.config.Issuer,   // ADD THIS
				"aud": maker.config.Audience, // ADD THIS
				"rls": []string{"admin"},
				"iat": now.Unix(),
				"exp": now.Add(30 * time.Minute).Unix(),
				"nbf": now.Unix(),                     // ADD THIS
				"mle": now.Add(24 * time.Hour).Unix(), // ADD THIS
				"typ": string(AccessToken),
			},
			expectedError: "invalid token ID",
		},
		{
			name: "wrong type for exp",
			claims: jwt.MapClaims{
				"jti": uuid.New().String(),
				"sub": uuid.New().String(),
				"sid": uuid.New().String(),
				"usr": "user",
				"iss": maker.config.Issuer,
				"aud": maker.config.Audience,
				"rls": []string{"admin"},
				"iat": now.Unix(),
				"exp": "not-a-number",
				"nbf": now.Unix(),
				"mle": now.Add(24 * time.Hour).Unix(),
				"typ": string(AccessToken),
			},
			expectedError: "invalid type for claim: exp is invalid",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			token := jwt.NewWithClaims(maker.signingMethod, tc.claims)
			signedToken, err := token.SignedString(maker.privateKey)
			require.NoError(t, err)

			claims, err := maker.VerifyAccessToken(context.Background(), signedToken)
			assert.Error(t, err)
			assert.Nil(t, claims)
			if tc.expectedError != "" {
				assert.Contains(t, err.Error(), tc.expectedError)
			}
		})
	}

	t.Run("empty username is valid", func(t *testing.T) {
		claims := jwt.MapClaims{
			"jti": uuid.New().String(),
			"sub": uuid.New().String(),
			"sid": uuid.New().String(),
			"usr": "", // Empty username should be allowed
			"iss": maker.config.Issuer,
			"aud": maker.config.Audience,
			"rls": []string{"admin"},
			"iat": now.Unix(),
			"exp": now.Add(30 * time.Minute).Unix(),
			"nbf": now.Unix(),
			"mle": now.Add(24 * time.Hour).Unix(),
			"typ": string(AccessToken),
		}

		token := jwt.NewWithClaims(maker.signingMethod, claims)
		signedToken, err := token.SignedString(maker.privateKey)
		require.NoError(t, err)

		accessClaims, err := maker.VerifyAccessToken(context.Background(), signedToken)
		assert.NoError(t, err)
		assert.NotNil(t, accessClaims)
		assert.Equal(t, "", accessClaims.Username)
	})
}

// TestBoundaryConditions tests edge cases at boundaries
func TestBoundaryConditions(t *testing.T) {
	t.Run("username at max length", func(t *testing.T) {
		maker := setupTestMaker(t)
		username := string(make([]byte, 1024))
		for i := range username {
			username = username[:i] + "a" + username[i+1:]
		}

		token, err := maker.CreateAccessToken(context.Background(), uuid.New(), username, []string{"admin"}, uuid.New())
		assert.NoError(t, err)
		assert.NotNil(t, token)
		assert.Equal(t, 1024, len(token.Username))
	})

	t.Run("username exceeds max length by one", func(t *testing.T) {
		maker := setupTestMaker(t)
		username := string(make([]byte, 1025))

		token, err := maker.CreateAccessToken(context.Background(), uuid.New(), username, []string{"admin"}, uuid.New())
		assert.Error(t, err)
		assert.Nil(t, token)
		assert.Contains(t, err.Error(), "username too long")
	})

	t.Run("single role", func(t *testing.T) {
		maker := setupTestMaker(t)
		token, err := maker.CreateAccessToken(context.Background(), uuid.New(), "user", []string{"user"}, uuid.New())
		assert.NoError(t, err)
		assert.NotNil(t, token)
		assert.Len(t, token.Roles, 1)
	})

	t.Run("many roles", func(t *testing.T) {
		maker := setupTestMaker(t)
		roles := make([]string, 100)
		for i := range roles {
			roles[i] = "role" + string(rune(i))
		}

		token, err := maker.CreateAccessToken(context.Background(), uuid.New(), "user", roles, uuid.New())
		assert.NoError(t, err)
		assert.NotNil(t, token)
		assert.Len(t, token.Roles, 100)
	})

	t.Run("token expiry validation", func(t *testing.T) {
		config := DefaultTestConfig()
		maker := setupTestMakerWithConfig(t, config, nil)

		// Test with an explicitly expired token
		pastTime := time.Now().Add(-1 * time.Hour)
		expiredClaims := jwt.MapClaims{
			"jti": uuid.New().String(),
			"sub": uuid.New().String(),
			"sid": uuid.New().String(),
			"usr": "user",
			"iss": maker.config.Issuer,
			"aud": maker.config.Audience,
			"rls": []string{"admin"},
			"iat": pastTime.Unix(),
			"exp": pastTime.Add(30 * time.Minute).Unix(), // Expired 30 minutes ago
			"nbf": pastTime.Unix(),
			"mle": pastTime.Add(24 * time.Hour).Unix(),
			"typ": string(AccessToken),
		}

		jwtToken := jwt.NewWithClaims(maker.signingMethod, expiredClaims)
		expiredToken, err := jwtToken.SignedString(maker.privateKey)
		require.NoError(t, err)

		// This should fail because the token is expired
		claims, err := maker.VerifyAccessToken(context.Background(), expiredToken)
		assert.Error(t, err)
		assert.Nil(t, claims)
		assert.Contains(t, err.Error(), "expired")

		// Test with a valid token
		validToken, err := maker.CreateAccessToken(context.Background(), uuid.New(), "user", []string{"admin"}, uuid.New())
		require.NoError(t, err)

		claims, err = maker.VerifyAccessToken(context.Background(), validToken.Token)
		assert.NoError(t, err)
		assert.NotNil(t, claims)
	})

	t.Run("token expiry validation(1)", func(t *testing.T) {
		config := DefaultTestConfig()
		maker := setupTestMakerWithConfig(t, config, nil)

		// Test 1: Create a token that's already expired
		pastTime := time.Now().Add(-1 * time.Hour)
		tokenID := uuid.New()
		userID := uuid.New()
		sessionID := uuid.New()

		expiredClaims := AccessTokenClaims{
			ID:                tokenID,
			Subject:           userID,
			SessionID:         sessionID,
			Username:          "user",
			Issuer:            maker.config.Issuer,
			Audience:          maker.config.Audience,
			Roles:             []string{"admin"},
			IssuedAt:          pastTime,
			ExpiresAt:         pastTime.Add(30 * time.Minute), // Expired 30 minutes ago
			NotBefore:         pastTime,
			MaxLifetimeExpiry: pastTime.Add(24 * time.Hour),
			TokenType:         AccessToken,
		}

		jwtToken := jwt.NewWithClaims(maker.signingMethod, toMapClaims(expiredClaims))
		expiredToken, err := jwtToken.SignedString(maker.privateKey)
		require.NoError(t, err)

		// This should fail because the token is expired
		claims, err := maker.VerifyAccessToken(context.Background(), expiredToken)
		assert.Error(t, err)
		assert.Nil(t, claims)
		assert.Contains(t, err.Error(), "expired")

		// Test 2: Create a valid token and verify it works
		validToken, err := maker.CreateAccessToken(context.Background(), uuid.New(), "user", []string{"admin"}, uuid.New())
		require.NoError(t, err)

		claims, err = maker.VerifyAccessToken(context.Background(), validToken.Token)
		assert.NoError(t, err)
		assert.NotNil(t, claims)
	})

	t.Run("token at exact expiry moment", func(t *testing.T) {
		config := DefaultTestConfig()
		// Use a longer duration for more reliable testing
		config.AccessExpiryDuration = 1 * time.Second
		maker := setupTestMakerWithConfig(t, config, nil)

		// Create token and immediately verify it's valid
		token, err := maker.CreateAccessToken(context.Background(), uuid.New(), "user", []string{"admin"}, uuid.New())
		require.NoError(t, err)

		// Verify token is initially valid
		claims, err := maker.VerifyAccessToken(context.Background(), token.Token)
		assert.NoError(t, err)
		assert.NotNil(t, claims)

		// Wait until well past expiry to ensure reliable test
		time.Sleep(2 * time.Second)

		// Now verify it's expired
		claims, err = maker.VerifyAccessToken(context.Background(), token.Token)
		assert.Error(t, err)
		assert.Nil(t, claims)
		assert.Contains(t, err.Error(), "expired")
	})

	t.Run("zero duration config", func(t *testing.T) {
		config := DefaultTestConfig()
		config.AccessExpiryDuration = 0

		_, err := NewGourdianTokenMaker(context.Background(), config, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "access token duration must be positive")
	})

	t.Run("negative duration config", func(t *testing.T) {
		config := DefaultTestConfig()
		config.AccessExpiryDuration = -1 * time.Hour

		_, err := NewGourdianTokenMaker(context.Background(), config, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "access token duration must be positive")
	})
}
