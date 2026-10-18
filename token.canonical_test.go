// File: token.canonical_test.go

package gourdiantoken

import (
	"bytes"
	"context"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// base64URLAlphabet is RFC 4648 section 5's alphabet, in value order.
const base64URLAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

// respellings returns the other strings a lenient base64url decoder reads as token's own
// signature -- the strings a verifier keyed on the token *string* would take for a new token:
//
//   - spareBit: every other last character that decodes to the same bytes (the spare bits
//     at the end of the last character are ignored); none when the signature is a whole
//     number of three-byte groups.
//   - lineBreak: a CR, an LF and a CRLF spliced into the middle, which Go's decoder skips
//     even in strict mode, so jwt.WithStrictDecoding alone would not refuse them.
//
// Each is checked to decode to the real signature, so the test is about genuine
// respellings, not about tampering.
func respellings(t *testing.T, token string) (spareBit, lineBreak []string) {
	t.Helper()

	dot := strings.LastIndexByte(token, '.')
	require.Positive(t, dot)
	head, sig := token[:dot+1], token[dot+1:]
	want, err := base64.RawURLEncoding.DecodeString(sig)
	require.NoError(t, err)

	for i := 0; i < len(base64URLAlphabet); i++ {
		if base64URLAlphabet[i] == sig[len(sig)-1] {
			continue
		}
		candidate := sig[:len(sig)-1] + string(base64URLAlphabet[i])
		if got, err := base64.RawURLEncoding.DecodeString(candidate); err == nil && bytes.Equal(got, want) {
			spareBit = append(spareBit, head+candidate)
		}
	}

	for _, br := range []string{"\n", "\r", "\r\n"} {
		candidate := sig[:len(sig)/2] + br + sig[len(sig)/2:]
		got, err := base64.RawURLEncoding.DecodeString(candidate)
		require.NoError(t, err)
		require.Equal(t, want, got)
		lineBreak = append(lineBreak, head+candidate)
	}
	return spareBit, lineBreak
}

// TestCanonicalToken_RespelledTokensAreRefused is the regression test for token-string
// malleability: revocation, rotation and single-use state is keyed on a hash of the token
// string, so a token accepted in a second spelling would escape every one of them. A token
// is accepted only in the spelling this package issued it in.
func TestCanonicalToken_RespelledTokensAreRefused(t *testing.T) {
	ctx := context.Background()

	algorithms := []struct {
		alg      string
		spareBit bool
	}{
		{"HS256", true},  // a 32-byte signature is 43 characters: 2 spare bits
		{"HS384", false}, // 48 bytes is exactly 64 characters: nothing spare, only the line breaks
		{"HS512", true},  // 64 bytes is 86 characters: 4 spare bits
	}

	for _, a := range algorithms {
		t.Run(a.alg, func(t *testing.T) {
			config := DefaultTestConfig()
			config.Algorithm = a.alg
			config.AllowedAlgorithms = []string{a.alg}
			config.VerificationTokensEnabled = true
			config.VerificationDefaultExpiryDuration = 5 * time.Minute
			config.VerificationMaxExpiryDuration = time.Hour
			config.VerificationAllowedUseCases = []string{"2fa-pending"}

			maker := setupTestMakerWithConfig(t, config, NewMemoryTokenRepository(time.Minute))
			t.Cleanup(func() { _ = maker.Close() })

			userID, sessionID := uuid.NewString(), uuid.NewString()

			kinds := []struct {
				name   string
				create func(t *testing.T) string
				verify func(token string) error
				// retire makes the real token unusable the way its type allows.
				retire func(token string) error
			}{
				{
					name: "access token, revoked",
					create: func(t *testing.T) string {
						resp, err := maker.CreateAccessToken(ctx, userID, "alice", []string{"admin"}, sessionID, "")
						require.NoError(t, err)
						return resp.Token
					},
					verify: func(token string) error { _, err := maker.VerifyAccessToken(ctx, token); return err },
					retire: func(token string) error { return maker.RevokeAccessToken(ctx, token) },
				},
				{
					name: "refresh token, revoked",
					create: func(t *testing.T) string {
						resp, err := maker.CreateRefreshToken(ctx, userID, "alice", sessionID, "")
						require.NoError(t, err)
						return resp.Token
					},
					verify: func(token string) error { _, err := maker.VerifyRefreshToken(ctx, token); return err },
					retire: func(token string) error { return maker.RevokeRefreshToken(ctx, token) },
				},
				{
					name: "refresh token, rotated",
					create: func(t *testing.T) string {
						resp, err := maker.CreateRefreshToken(ctx, userID, "alice", sessionID, "")
						require.NoError(t, err)
						return resp.Token
					},
					verify: func(token string) error { _, err := maker.VerifyRefreshToken(ctx, token); return err },
					retire: func(token string) error { _, err := maker.RotateRefreshToken(ctx, token); return err },
				},
				{
					name: "verification token, used",
					create: func(t *testing.T) string {
						resp, err := maker.CreateVerificationToken(ctx, userID, "2fa-pending", 0, nil)
						require.NoError(t, err)
						return resp.Token
					},
					verify: func(token string) error { _, err := maker.VerifyVerificationToken(ctx, token); return err },
					retire: func(token string) error { return maker.MarkVerificationTokenUsed(ctx, token) },
				},
			}

			for _, k := range kinds {
				t.Run(k.name, func(t *testing.T) {
					issued := k.create(t)
					spareBit, lineBreak := respellings(t, issued)
					if a.spareBit {
						require.NotEmpty(t, spareBit, "the algorithm leaves spare bits, so there are spellings to try")
					} else {
						require.Empty(t, spareBit, "the algorithm leaves no spare bits")
					}
					respelt := append(append([]string{}, spareBit...), lineBreak...)

					require.NoError(t, k.verify(issued), "the token as issued verifies")

					// A respelling is refused as an invalid token although its signature
					// checks out: nothing keyed on the token string would recognise it.
					for i, v := range respelt {
						assert.ErrorIs(t, k.verify(v), ErrInvalidToken, "respelling %d is refused", i)
					}

					// Retiring a respelling fails and leaves the issued token's state alone,
					// rather than recording a hash that will never match it.
					for i, v := range respelt {
						assert.Error(t, k.retire(v), "retiring respelling %d fails", i)
					}
					require.NoError(t, k.verify(issued), "retiring respellings left the issued token alone")

					// Once the issued token is retired, no respelling gets past what it can't.
					require.NoError(t, k.retire(issued))
					require.Error(t, k.verify(issued), "the retired token is refused")
					for i, v := range respelt {
						assert.ErrorIs(t, k.verify(v), ErrInvalidToken, "respelling %d of the retired token is refused", i)
					}
				})
			}
		})
	}
}
