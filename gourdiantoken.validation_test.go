// File: gourdiantoken.validation_test.go

package gourdiantoken

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// validAccessClaims returns a baseline set of claims shaped exactly like what
// jwt.Parse hands back from a real signed token — numeric fields as float64,
// since encoding/json always decodes JSON numbers that way. Tests mutate a
// copy of this map to exercise one broken field at a time.
func validAccessClaims() jwt.MapClaims {
	now := time.Now()
	return jwt.MapClaims{
		"jti": "token-id-1",
		"sub": "user-1",
		"sid": "session-1",
		"usr": "alice",
		"iss": "issuer",
		"aud": "audience",
		"iat": float64(now.Unix()),
		"exp": float64(now.Add(time.Hour).Unix()),
		"nbf": float64(now.Unix()),
		"mle": float64(now.Add(2 * time.Hour).Unix()),
		"typ": string(AccessToken),
		"rls": []interface{}{"admin"},
	}
}

func TestToMapClaims_UnsupportedType(t *testing.T) {
	_, err := toMapClaims("not a claims struct")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported claims type")
}

func TestExtractCommonClaims_Valid(t *testing.T) {
	common, err := extractCommonClaims(validAccessClaims())
	require.NoError(t, err)
	assert.Equal(t, "token-id-1", common.ID)
	assert.Equal(t, "user-1", common.Subject)
	assert.Equal(t, "session-1", common.SessionID)
	assert.Equal(t, "alice", common.Username)
	assert.Equal(t, "issuer", common.Issuer)
	assert.Equal(t, []string{"audience"}, common.Audience)
}

func TestExtractCommonClaims_ErrorBranches(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(jwt.MapClaims)
		wantErr string
	}{
		{"missing jti", func(c jwt.MapClaims) { delete(c, "jti") }, "invalid token ID type"},
		{"non-string jti", func(c jwt.MapClaims) { c["jti"] = 123 }, "invalid token ID type"},
		{"empty jti", func(c jwt.MapClaims) { c["jti"] = "" }, "invalid token ID: cannot be empty"},
		{"non-string sub", func(c jwt.MapClaims) { c["sub"] = 123 }, "invalid user ID type"},
		{"empty sub", func(c jwt.MapClaims) { c["sub"] = "" }, "invalid user ID: cannot be empty"},
		{"non-string sid", func(c jwt.MapClaims) { c["sid"] = 123 }, "invalid session ID type"},
		{"non-string usr", func(c jwt.MapClaims) { c["usr"] = 123 }, "invalid username type"},
		{"non-string iss", func(c jwt.MapClaims) { c["iss"] = 123 }, "invalid issuer type"},
		{"missing iat", func(c jwt.MapClaims) { delete(c, "iat") }, "invalid timestamp format"},
		{"missing exp", func(c jwt.MapClaims) { delete(c, "exp") }, "invalid timestamp format"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			claims := validAccessClaims()
			tc.mutate(claims)
			_, err := extractCommonClaims(claims)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}
}

func TestExtractCommonClaims_AudienceVariants(t *testing.T) {
	t.Run("string slice", func(t *testing.T) {
		claims := validAccessClaims()
		claims["aud"] = []string{"a", "b"}
		common, err := extractCommonClaims(claims)
		require.NoError(t, err)
		assert.Equal(t, []string{"a", "b"}, common.Audience)
	})

	t.Run("interface slice", func(t *testing.T) {
		claims := validAccessClaims()
		claims["aud"] = []interface{}{"a", "b"}
		common, err := extractCommonClaims(claims)
		require.NoError(t, err)
		assert.Equal(t, []string{"a", "b"}, common.Audience)
	})

	t.Run("absent audience", func(t *testing.T) {
		claims := validAccessClaims()
		delete(claims, "aud")
		common, err := extractCommonClaims(claims)
		require.NoError(t, err)
		assert.Nil(t, common.Audience)
	})

	t.Run("nbf and mle absent", func(t *testing.T) {
		claims := validAccessClaims()
		delete(claims, "nbf")
		delete(claims, "mle")
		common, err := extractCommonClaims(claims)
		require.NoError(t, err)
		assert.True(t, common.NotBefore.IsZero())
		assert.True(t, common.MaxLifetimeExpiry.IsZero())
	})
}

func TestMapToAccessClaims_ErrorBranches(t *testing.T) {
	t.Run("propagates extractCommonClaims error", func(t *testing.T) {
		claims := validAccessClaims()
		delete(claims, "jti")
		_, err := mapToAccessClaims(claims)
		require.Error(t, err)
	})

	t.Run("missing roles", func(t *testing.T) {
		claims := validAccessClaims()
		delete(claims, "rls")
		_, err := mapToAccessClaims(claims)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "missing roles claim")
	})

	t.Run("roles as string slice", func(t *testing.T) {
		claims := validAccessClaims()
		claims["rls"] = []string{"admin", "user"}
		got, err := mapToAccessClaims(claims)
		require.NoError(t, err)
		assert.Equal(t, []string{"admin", "user"}, got.Roles)
	})

	t.Run("role with non-string element", func(t *testing.T) {
		claims := validAccessClaims()
		claims["rls"] = []interface{}{"admin", 123}
		_, err := mapToAccessClaims(claims)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid role type")
	})

	t.Run("empty roles", func(t *testing.T) {
		claims := validAccessClaims()
		claims["rls"] = []interface{}{}
		_, err := mapToAccessClaims(claims)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "at least one role must be provided")
	})

	t.Run("invalid roles type", func(t *testing.T) {
		claims := validAccessClaims()
		claims["rls"] = 123
		_, err := mapToAccessClaims(claims)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid roles type")
	})

	t.Run("missing typ", func(t *testing.T) {
		claims := validAccessClaims()
		delete(claims, "typ")
		_, err := mapToAccessClaims(claims)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid token type")
	})
}

func validRefreshClaims() jwt.MapClaims {
	claims := validAccessClaims()
	delete(claims, "rls")
	claims["typ"] = string(RefreshToken)
	return claims
}

func TestMapToRefreshClaims(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		got, err := mapToRefreshClaims(validRefreshClaims())
		require.NoError(t, err)
		assert.Equal(t, RefreshToken, got.TokenType)
	})

	t.Run("propagates extractCommonClaims error", func(t *testing.T) {
		claims := validRefreshClaims()
		delete(claims, "sub")
		_, err := mapToRefreshClaims(claims)
		require.Error(t, err)
	})

	t.Run("missing typ", func(t *testing.T) {
		claims := validRefreshClaims()
		delete(claims, "typ")
		_, err := mapToRefreshClaims(claims)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid or missing token type")
	})

	t.Run("wrong typ", func(t *testing.T) {
		claims := validRefreshClaims()
		claims["typ"] = string(AccessToken)
		_, err := mapToRefreshClaims(claims)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "expected 'refresh'")
	})
}

func validVerificationClaims() jwt.MapClaims {
	claims := validAccessClaims()
	delete(claims, "rls")
	claims["typ"] = string(VerificationToken)
	claims["uc"] = "email-verification"
	return claims
}

func TestMapToVerificationClaims(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		got, err := mapToVerificationClaims(validVerificationClaims())
		require.NoError(t, err)
		assert.Equal(t, "email-verification", got.UseCase)
	})

	t.Run("propagates extractCommonClaims error", func(t *testing.T) {
		claims := validVerificationClaims()
		delete(claims, "sub")
		_, err := mapToVerificationClaims(claims)
		require.Error(t, err)
	})

	t.Run("missing typ", func(t *testing.T) {
		claims := validVerificationClaims()
		delete(claims, "typ")
		_, err := mapToVerificationClaims(claims)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid or missing token type")
	})

	t.Run("wrong typ", func(t *testing.T) {
		claims := validVerificationClaims()
		claims["typ"] = string(AccessToken)
		_, err := mapToVerificationClaims(claims)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "expected 'verification'")
	})

	t.Run("missing use case", func(t *testing.T) {
		claims := validVerificationClaims()
		delete(claims, "uc")
		_, err := mapToVerificationClaims(claims)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid use case type")
	})

	t.Run("empty use case", func(t *testing.T) {
		claims := validVerificationClaims()
		claims["uc"] = ""
		_, err := mapToVerificationClaims(claims)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "cannot be empty")
	})

	t.Run("metadata wrong type", func(t *testing.T) {
		claims := validVerificationClaims()
		claims["mtd"] = "not-an-object"
		_, err := mapToVerificationClaims(claims)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid metadata type")
	})

	t.Run("metadata present and valid", func(t *testing.T) {
		claims := validVerificationClaims()
		claims["mtd"] = map[string]interface{}{"ip": "127.0.0.1"}
		got, err := mapToVerificationClaims(claims)
		require.NoError(t, err)
		assert.Equal(t, "127.0.0.1", got.Metadata["ip"])
	})
}

// TestTenantIDClaim_MapConversions covers the "tid" claim's optional-extraction branches in
// mapToAccessClaims/mapToRefreshClaims (tid is only mandatory when the maker's config has
// MultiTenantEnabled true, enforced upstream in parseAndValidateToken - not here), plus
// confirms toMapClaims's VerificationTokenClaims branch never emits a "tid" key, since tenant
// scoping for verification tokens is a Metadata convention, not a struct field.
func TestTenantIDClaim_MapConversions(t *testing.T) {
	t.Run("mapToAccessClaims tid absent", func(t *testing.T) {
		got, err := mapToAccessClaims(validAccessClaims())
		require.NoError(t, err)
		assert.Empty(t, got.TenantID)
	})

	t.Run("mapToAccessClaims tid present", func(t *testing.T) {
		claims := validAccessClaims()
		claims["tid"] = "acme-corp"
		got, err := mapToAccessClaims(claims)
		require.NoError(t, err)
		assert.Equal(t, "acme-corp", got.TenantID)
	})

	t.Run("mapToAccessClaims tid wrong type", func(t *testing.T) {
		claims := validAccessClaims()
		claims["tid"] = 123
		_, err := mapToAccessClaims(claims)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid tenant ID type")
	})

	t.Run("mapToRefreshClaims tid absent", func(t *testing.T) {
		got, err := mapToRefreshClaims(validRefreshClaims())
		require.NoError(t, err)
		assert.Empty(t, got.TenantID)
	})

	t.Run("mapToRefreshClaims tid present", func(t *testing.T) {
		claims := validRefreshClaims()
		claims["tid"] = "acme-corp"
		got, err := mapToRefreshClaims(claims)
		require.NoError(t, err)
		assert.Equal(t, "acme-corp", got.TenantID)
	})

	t.Run("mapToRefreshClaims tid wrong type", func(t *testing.T) {
		claims := validRefreshClaims()
		claims["tid"] = 123
		_, err := mapToRefreshClaims(claims)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid tenant ID type")
	})

	t.Run("toMapClaims never emits tid for access/refresh when TenantID is empty", func(t *testing.T) {
		accessMap, err := toMapClaims(AccessTokenClaims{
			ID: "id", Subject: "sub", Username: "usr", Roles: []string{"admin"}, TokenType: AccessToken,
		})
		require.NoError(t, err)
		assert.NotContains(t, accessMap, "tid")

		refreshMap, err := toMapClaims(RefreshTokenClaims{
			ID: "id", Subject: "sub", Username: "usr", TokenType: RefreshToken,
		})
		require.NoError(t, err)
		assert.NotContains(t, refreshMap, "tid")
	})

	t.Run("toMapClaims never emits tid for verification tokens", func(t *testing.T) {
		verMap, err := toMapClaims(VerificationTokenClaims{
			ID: "id", Subject: "sub", UseCase: "2fa-pending", TokenType: VerificationToken,
			Metadata: map[string]interface{}{"tenant_id": "acme-corp"},
		})
		require.NoError(t, err)
		assert.NotContains(t, verMap, "tid", "tenant scoping for verification tokens is a Metadata convention, not a tid claim")
	})
}

func TestValidateTokenClaims(t *testing.T) {
	t.Run("valid access claims", func(t *testing.T) {
		err := validateTokenClaims(validAccessClaims(), AccessToken, nil)
		require.NoError(t, err)
	})

	t.Run("missing required custom claim", func(t *testing.T) {
		err := validateTokenClaims(validAccessClaims(), AccessToken, []string{"custom"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "missing required claim: custom")
	})

	t.Run("non-string jti", func(t *testing.T) {
		claims := validAccessClaims()
		claims["jti"] = 1
		err := validateTokenClaims(claims, AccessToken, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid token ID type")
	})

	t.Run("empty jti", func(t *testing.T) {
		claims := validAccessClaims()
		claims["jti"] = ""
		err := validateTokenClaims(claims, AccessToken, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid token ID: cannot be empty")
	})

	t.Run("non-string sub", func(t *testing.T) {
		claims := validAccessClaims()
		claims["sub"] = 1
		err := validateTokenClaims(claims, AccessToken, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid user ID type")
	})

	t.Run("empty sub", func(t *testing.T) {
		claims := validAccessClaims()
		claims["sub"] = ""
		err := validateTokenClaims(claims, AccessToken, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid user ID: cannot be empty")
	})

	t.Run("non-string sid", func(t *testing.T) {
		claims := validAccessClaims()
		claims["sid"] = 1
		err := validateTokenClaims(claims, AccessToken, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid session ID type")
	})

	t.Run("wrong token type", func(t *testing.T) {
		err := validateTokenClaims(validAccessClaims(), RefreshToken, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid token type: expected refresh")
	})

	t.Run("non-float exp", func(t *testing.T) {
		claims := validAccessClaims()
		claims["exp"] = "not-a-number"
		err := validateTokenClaims(claims, AccessToken, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid exp claim type")
	})

	t.Run("expired token", func(t *testing.T) {
		claims := validAccessClaims()
		claims["exp"] = float64(time.Now().Add(-time.Hour).Unix())
		err := validateTokenClaims(claims, AccessToken, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "token has expired")
	})

	t.Run("issued in the future", func(t *testing.T) {
		claims := validAccessClaims()
		claims["iat"] = float64(time.Now().Add(time.Hour).Unix())
		err := validateTokenClaims(claims, AccessToken, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "issued in the future")
	})

	t.Run("max lifetime exceeded", func(t *testing.T) {
		claims := validAccessClaims()
		claims["mle"] = float64(time.Now().Add(-time.Minute).Unix())
		err := validateTokenClaims(claims, AccessToken, nil)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrTokenMaxLifetimeExceeded)
	})

	t.Run("non-float iat is ignored, not an error", func(t *testing.T) {
		claims := validAccessClaims()
		claims["iat"] = "not-a-number"
		err := validateTokenClaims(claims, AccessToken, nil)
		require.NoError(t, err)
	})

	t.Run("non-float mle is ignored, not an error", func(t *testing.T) {
		claims := validAccessClaims()
		claims["mle"] = "not-a-number"
		err := validateTokenClaims(claims, AccessToken, nil)
		require.NoError(t, err)
	})
}
