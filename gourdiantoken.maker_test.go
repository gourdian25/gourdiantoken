// File: gourdiantoken.maker_test.go

package gourdiantoken

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// erroringRepo is a TokenRepository test double whose methods return a
// configured error on demand, used to exercise the repository-error
// branches of parseAndValidateToken/revokeToken/RotateRefreshToken that
// MemoryTokenRepository never fails.
type erroringRepo struct {
	isTokenRevokedErr       error
	isTokenRotatedErr       error
	markTokenRotatedAtomic  bool
	markTokenRotatedAtomErr error
}

func (r *erroringRepo) MarkTokenRevoke(ctx context.Context, tokenType TokenType, token string, ttl time.Duration) error {
	return nil
}
func (r *erroringRepo) IsTokenRevoked(ctx context.Context, tokenType TokenType, token string) (bool, error) {
	if r.isTokenRevokedErr != nil {
		return false, r.isTokenRevokedErr
	}
	return false, nil
}
func (r *erroringRepo) MarkTokenRotated(ctx context.Context, token string, ttl time.Duration) error {
	return nil
}
func (r *erroringRepo) MarkTokenRotatedAtomic(ctx context.Context, token string, ttl time.Duration) (bool, error) {
	if r.markTokenRotatedAtomErr != nil {
		return false, r.markTokenRotatedAtomErr
	}
	return r.markTokenRotatedAtomic, nil
}
func (r *erroringRepo) IsTokenRotated(ctx context.Context, token string) (bool, error) {
	if r.isTokenRotatedErr != nil {
		return false, r.isTokenRotatedErr
	}
	return false, nil
}
func (r *erroringRepo) GetRotationTTL(ctx context.Context, token string) (time.Duration, error) {
	return 0, nil
}
func (r *erroringRepo) CleanupExpiredRevokedTokens(ctx context.Context, tokenType TokenType) error {
	return nil
}
func (r *erroringRepo) CleanupExpiredRotatedTokens(ctx context.Context) error { return nil }

func makerWithRepo(t *testing.T, repo TokenRepository) *JWTMaker {
	t.Helper()
	config := DefaultTestConfig()
	config.RevocationEnabled = true
	config.RotationEnabled = true
	maker, err := NewGourdianTokenMaker(context.Background(), config, repo)
	require.NoError(t, err)
	return maker.(*JWTMaker)
}

// TestSignClaims_ContextCancelledBeforeSigning calls signClaims directly
// with a pre-cancelled context: CreateAccessToken's own ctx.Err() check at
// the very top would already reject a cancelled context before ever
// reaching signClaims, so signClaims' own internal check is otherwise
// never exercised.
func TestSignClaims_ContextCancelledBeforeSigning(t *testing.T) {
	maker := setupTestMaker(t)
	now := time.Now()
	claims := AccessTokenClaims{
		ID:        "token-id",
		Subject:   "user-1",
		Username:  "user",
		IssuedAt:  now,
		ExpiresAt: now.Add(time.Hour),
		TokenType: AccessToken,
		Roles:     []string{"admin"},
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := maker.signClaims(ctx, claims, AccessToken)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "context canceled before signing")
}

func TestCreateAccessToken_ContextCancelled(t *testing.T) {
	maker := setupTestMaker(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := maker.CreateAccessToken(ctx, "user-1", "user", []string{"admin"}, "session-1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "context canceled")
}

func TestCreateAccessToken_EmptyRoleString(t *testing.T) {
	maker := setupTestMaker(t)
	_, err := maker.CreateAccessToken(context.Background(), "user-1", "user", []string{"admin", ""}, "session-1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "roles cannot contain empty strings")
}

func TestCreateRefreshToken_ContextCancelled(t *testing.T) {
	maker := setupTestMaker(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := maker.CreateRefreshToken(ctx, "user-1", "user", "session-1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "context canceled")
}

func TestCreateVerificationToken_ContextCancelled(t *testing.T) {
	maker := setupTestMaker(t)
	maker.config.VerificationTokensEnabled = true
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := maker.CreateVerificationToken(ctx, "user-1", "signup", time.Minute, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "context canceled")
}

func TestCreateVerificationToken_NotEnabled(t *testing.T) {
	maker := setupTestMaker(t)
	maker.config.VerificationTokensEnabled = false

	_, err := maker.CreateVerificationToken(context.Background(), "user-1", "signup", time.Minute, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not enabled")
}

func TestCreateVerificationToken_EmptyUserID(t *testing.T) {
	maker := setupTestMaker(t)
	maker.config.VerificationTokensEnabled = true

	_, err := maker.CreateVerificationToken(context.Background(), "", "signup", time.Minute, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "user ID cannot be empty")
}

func TestParseAndValidateToken_RevocationCheckError(t *testing.T) {
	repo := &erroringRepo{isTokenRevokedErr: fmt.Errorf("boom")}
	maker := makerWithRepo(t, repo)

	token, err := maker.CreateAccessToken(context.Background(), "user-1", "user", []string{"admin"}, "session-1")
	require.NoError(t, err)

	_, err = maker.VerifyAccessToken(context.Background(), token.Token)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to check token revocation")
}

func TestParseAndValidateToken_RotationCheckError(t *testing.T) {
	repo := &erroringRepo{isTokenRotatedErr: fmt.Errorf("boom")}
	maker := makerWithRepo(t, repo)

	token, err := maker.CreateRefreshToken(context.Background(), "user-1", "user", "session-1")
	require.NoError(t, err)

	_, err = maker.VerifyRefreshToken(context.Background(), token.Token)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to check token rotation")
}

func TestParseAndValidateToken_UnexpectedSigningMethod(t *testing.T) {
	maker := setupTestMaker(t)

	now := time.Now()
	claims := jwt.MapClaims{
		"jti": "token-id",
		"sub": "user-1",
		"sid": "session-1",
		"usr": "user",
		"iss": maker.config.Issuer,
		"aud": maker.config.Audience,
		"rls": []string{"admin"},
		"iat": float64(now.Unix()),
		"exp": float64(now.Add(time.Hour).Unix()),
		"nbf": float64(now.Unix()),
		"mle": float64(now.Add(2 * time.Hour).Unix()),
		"typ": string(AccessToken),
	}
	// Sign with a different HMAC variant than the maker expects (HS256), so
	// parseAndValidateToken's alg-mismatch check inside jwt.Parse's keyFunc
	// rejects it before ever reaching claims validation.
	token := jwt.NewWithClaims(jwt.SigningMethodHS384, claims)
	signed, err := token.SignedString(maker.privateKey)
	require.NoError(t, err)

	_, err = maker.VerifyAccessToken(context.Background(), signed)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected signing method")
}

func TestVerifyVerificationToken_NotEnabled(t *testing.T) {
	maker := setupTestMaker(t)
	maker.config.VerificationTokensEnabled = false

	_, err := maker.VerifyVerificationToken(context.Background(), "irrelevant")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not enabled")
}

func TestVerifyVerificationToken_UseCaseNoLongerAllowed(t *testing.T) {
	maker := setupTestMaker(t)
	maker.config.VerificationTokensEnabled = true

	token, err := maker.CreateVerificationToken(context.Background(), "user-1", "signup", time.Minute, nil)
	require.NoError(t, err)

	// Simulate the use case being removed from the allow-list after this
	// token was already issued — defense-in-depth check inside
	// VerifyVerificationToken, re-validating what CreateVerificationToken
	// already checked at issuance time.
	maker.config.VerificationAllowedUseCases = []string{"password-reset"}

	_, err = maker.VerifyVerificationToken(context.Background(), token.Token)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not in the allowed list")
}

func TestRevokeToken_NotEnabled(t *testing.T) {
	maker := setupTestMaker(t)
	err := maker.revokeToken(context.Background(), AccessToken, "some-token")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "revocation is not enabled")
}

func TestRevokeToken_ContextCancelled(t *testing.T) {
	maker := setupTestMakerWithRepo(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := maker.revokeToken(ctx, AccessToken, "some-token")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "context canceled")
}

func TestRevokeToken_InvalidToken(t *testing.T) {
	maker := setupTestMakerWithRepo(t)
	err := maker.revokeToken(context.Background(), AccessToken, "not-a-jwt")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid token")
}

func TestRevokeToken_MissingExpClaim(t *testing.T) {
	maker := setupTestMakerWithRepo(t)

	// CreateAccessToken always sets exp, so a token missing it can only be
	// constructed by hand rather than through the maker's own factory.
	claims := jwt.MapClaims{
		"jti": "token-id",
		"sub": "user-1",
	}
	token := jwt.NewWithClaims(maker.signingMethod, claims)
	signed, err := token.SignedString(maker.privateKey)
	require.NoError(t, err)

	err = maker.revokeToken(context.Background(), AccessToken, signed)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrMissingExpClaim)
}

func TestRotateRefreshToken_NotEnabled(t *testing.T) {
	maker := setupTestMaker(t)
	_, err := maker.RotateRefreshToken(context.Background(), "some-token")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "rotation not enabled")
}

// TestRotateRefreshToken_MarkAtomicReturnsFalse exercises RotateRefreshToken's
// own `if !marked` branch directly — distinct from
// TestRotateRefreshToken_AlreadyRotated in token.rotate_test.go, where a real
// second rotation attempt is rejected earlier by VerifyRefreshToken's own
// rotation check and never reaches this branch at all. Here IsTokenRotated
// reports false (so verification passes) while MarkTokenRotatedAtomic itself
// reports it lost the race.
func TestRotateRefreshToken_MarkAtomicReturnsFalse(t *testing.T) {
	repo := &erroringRepo{markTokenRotatedAtomic: false}
	maker := makerWithRepo(t, repo)

	refresh, err := maker.CreateRefreshToken(context.Background(), "user-1", "user", "session-1")
	require.NoError(t, err)

	_, err = maker.RotateRefreshToken(context.Background(), refresh.Token)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTokenRotated)
}

func TestRotateRefreshToken_RepositoryError(t *testing.T) {
	repo := &erroringRepo{markTokenRotatedAtomErr: fmt.Errorf("boom")}
	maker := makerWithRepo(t, repo)

	refresh, err := maker.CreateRefreshToken(context.Background(), "user-1", "user", "session-1")
	require.NoError(t, err)

	_, err = maker.RotateRefreshToken(context.Background(), refresh.Token)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "repository error")
}

func TestInitializeKeys_UnsupportedSigningMethod(t *testing.T) {
	maker := &JWTMaker{config: GourdianTokenConfig{SigningMethod: "bogus"}}
	err := maker.initializeKeys()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported signing method")
}

// TestParseKeyPair_MissingPublicKeyFile calls parseKeyPair directly rather
// than going through NewGourdianTokenMaker: the full constructor's
// validateConfig runs its own os.Stat-based permission check on both key
// paths first, which already fails fast on a missing file — never reaching
// parseKeyPair's own os.ReadFile call at all.
func TestParseKeyPair_MissingPublicKeyFile(t *testing.T) {
	tempDir := t.TempDir()
	privPath := filepath.Join(tempDir, "priv.pem")
	require.NoError(t, os.WriteFile(privPath, []byte("placeholder"), 0600))

	maker := &JWTMaker{
		config: GourdianTokenConfig{
			PrivateKeyPath: privPath,
			PublicKeyPath:  filepath.Join(tempDir, "does-not-exist.pem"),
		},
		signingMethod: jwt.SigningMethodRS256,
	}

	err := maker.parseKeyPair()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read public key file")
}

// TestNewGourdianTokenMaker_InitializeKeysFailureCancelsCleanup uses
// existing, correctly-permissioned but garbage-content key files: a
// genuinely missing/insecurely-permissioned path would be rejected earlier
// by validateConfig's own file-permission check (see
// TestParseKeyPair_MissingPublicKeyFile above) before ever reaching
// initializeKeys, so reaching *this* failure path — after the cleanup
// goroutines have already been started because RevocationEnabled/
// RotationEnabled are true — needs files that pass the permission check
// but fail to parse as PEM.
func TestNewGourdianTokenMaker_InitializeKeysFailureCancelsCleanup(t *testing.T) {
	tempDir := t.TempDir()
	privPath := filepath.Join(tempDir, "priv.pem")
	pubPath := filepath.Join(tempDir, "pub.pem")
	require.NoError(t, os.WriteFile(privPath, []byte("not a real key"), 0600))
	require.NoError(t, os.WriteFile(pubPath, []byte("not a real key"), 0600))

	config := DefaultTestConfig()
	config.RevocationEnabled = true
	config.RotationEnabled = true
	config.SigningMethod = Asymmetric
	config.Algorithm = "RS256"
	config.SymmetricKey = ""
	config.PrivateKeyPath = privPath
	config.PublicKeyPath = pubPath

	repo := NewMemoryTokenRepository(time.Minute)
	_, err := NewGourdianTokenMaker(context.Background(), config, repo)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to initialize keys")
}
