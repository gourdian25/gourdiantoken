# gourdiantoken Improvement Plan

Scope: the gourdiantoken Go library at repo root (package `gourdiantoken`). Excludes bark.txt/.bark.toml tooling entirely.

All findings below were re-verified against the actual source on 2026-07-02 (line numbers may drift by a few lines as the file changes, but the pattern/location is confirmed correct as of this check). Actual filenames in repo use dotted convention, e.g. `gourdiantoken.repository.gorm.imp.go`, `gourdiantoken.factories.go` (not `gorm.imp.go`/`factories.go` shorthand used in the research notes) — the plan below uses the real filenames.

---

## Phase 0 — Baseline safety net (prerequisite, do first)

Before any refactor, confirm test coverage is adequate to catch regressions during the mechanical file split and dedup work.

- Run `go test ./...` and `go vet ./...` to capture a clean baseline.
- No code changes in this phase.

---

## Phase 1 — Safe, isolated fixes (no public API changes)

These are bug fixes and internal-only additions. Safe to ship in a patch release.

1. **Fix the dead-`err` bug in VerifyAccessToken / VerifyRefreshToken.**
   - `gourdiantoken.go` ~L1418-1420 (`VerifyAccessToken`) and ~L1561-1564 (`VerifyRefreshToken`):
     ```go
     if !token.Valid {
         return nil, fmt.Errorf("invalid token: %v", err)  // err is always nil here
     }
     ```
     Since `err != nil` was already handled just above, this branch always prints `"invalid token: <nil>"`. Replace with a real message, e.g. `fmt.Errorf("token failed validation")` (or once sentinels exist in Phase 3, wrap `ErrTokenInvalid`).

2. **Replace panics in `toMapClaims` with returned errors.**
   - `gourdiantoken.go` ~L2461-2508: unsupported claim type (~L2465) and empty `Roles` (~L2506) currently `panic(...)`, reachable from the public `CreateAccessToken`/`CreateRefreshToken` path. Change `toMapClaims` signature to return `(jwt.MapClaims, error)` and propagate the error to callers (`CreateAccessToken` ~L1098, `CreateRefreshToken` ~L1248). This is an internal function so the signature change itself has no external impact, but callers must be updated in the same commit.

3. **Add a logger hook for background cleanup goroutines.**
   - `cleanupRotatedTokens` (~L1992) and `cleanupRevokedTokens` (~L2037) currently `fmt.Printf` errors to stdout. Add an unexported field, e.g. `logf func(format string, args ...any)`, defaulting to a no-op or `log.Printf`, settable via a new functional option (see Phase 3, since exposing a way to set it does touch public API — but the internal plumbing/default no-op swap can land now with the field defaulting to today's `fmt.Printf` behavior, deferring only the public setter to Phase 3).

4. **Improve the ambiguous validation message.**
   - `gourdiantoken.go` ~L879: `"token repository required for token rotation/revocation"` doesn't say which flag triggered it. Change to report the specific cause, e.g. `"token repository required: RotationEnabled=%v, RevocationEnabled=%v"` or two distinct messages depending on which flag(s) are set.

5. **Add exported constants for magic `RequiredClaims` strings.**
   - `gourdiantoken.go` ~L116-118 documents `"iss"`, `"aud"`, `"nbf"`, `"mle"` as magic strings with no exported constants. Add e.g. `const ClaimIssuer = "iss"`, `ClaimAudience = "aud"`, `ClaimNotBefore = "nbf"`, `ClaimMaxLifetimeExceeded = "mle"` (or the internal name actually used) to `config.go` (or the constants section). Purely additive — no existing behavior changes; consumers can adopt at their own pace.

6. **Test gap fill.**
   - Add a test that calls `NewGourdianTokenMaker` (generic, not `NewGourdianTokenMakerNoStorage`) directly with `tokenRepo == nil` and `RotationEnabled`/`RevocationEnabled` true, asserting the specific error path from item 4 above.
   - Extend `TestAllFactories_InvalidConfigurationsFail` (`gourdiantoken.factories_test.go` ~L574-613) to cover Gorm/Mongo/Redis/Memory factories with equivalent invalid-config rejection cases, matching the 2 scenarios already covered for NoStorage.

**Files touched in Phase 1:** `gourdiantoken.go`, `gourdiantoken.factories_test.go` (new/extended tests), possibly a new `config.go` if Phase 2's split lands first (see ordering note below).

**Ordering note:** Phase 1 items 1-2 are pure bug fixes and can land independent of Phase 2. Items 4-5 touch code that will move during the Phase 2 file split — sequence Phase 1 *before* Phase 2 to keep diffs small and reviewable, or fold trivial ones into the Phase 2 PR if that's more convenient. Either order is safe since Phase 2 is mechanical.

---

## Phase 2 — Internal refactors (behavior-preserving, no public API changes)

### 2a. File split (purely mechanical move, no logic changes)

Split `gourdiantoken.go` (3262 lines) into cohesive files, all remaining in `package gourdiantoken`. Since Go packages are flat namespaces, **no consumer import changes are required** — this is confirmed safe. This matches the existing convention already used for the repository backends (`gourdiantoken.repository.*.go`).

| New file | Contents | Source lines (approx, gourdiantoken.go) |
|---|---|---|
| `gourdiantoken.config.go` | Config struct, constants, `NewGourdianTokenConfig`, `DefaultGourdianTokenConfig` | ~L37-273 |
| `gourdiantoken.claims.go` | Claims/response types (`AccessTokenClaims`, `RefreshTokenClaims`, `AccessTokenResponse`, `RefreshTokenResponse`, etc.) | ~L275-463 |
| `gourdiantoken.interfaces.go` | `TokenRepository`, `GourdianTokenMaker` interfaces | ~L478-758 |
| `gourdiantoken.maker.go` | `JWTMaker` struct, constructors, Create/Verify/Revoke/Rotate methods, cleanup goroutines | ~L771-2260 |
| `gourdiantoken.validation.go` | `validateConfig`, `validateAlgorithmAndMethod`, `toMapClaims`, `mapToAccessClaims`, `mapToRefreshClaims`, `validateTokenClaims` | ~L2268-2842 |
| `gourdiantoken.keys.go` | `parseEdDSA*`/`parseRSA*`/`parseECDSA*`, `checkFilePermissions`, `getUnixTime`, PEM/ASN.1 structs | ~L2844-3262 |

Process for this step:
- Move code verbatim (cut/paste), do not touch logic.
- Keep `package gourdiantoken` declaration and existing imports at the top of each new file, letting `goimports`/`gofmt` trim unused imports per file.
- Run `go build ./...` and `go test ./...` after the split to confirm zero behavior change (should be a no-op diff at the AST level; consider `git diff` inspection to make sure no lines were altered beyond the move).
- Naming: follow the existing dotted convention seen in the repo (`gourdiantoken.repository.gorm.imp.go` etc.) rather than the shorthand names used in the initial research pass, i.e. `gourdiantoken.config.go` not bare `config.go`.

### 2b. Deduplication (behavior-preserving)

Do this *after* the file split so the diffs land in the right final files.

1. **CreateAccessToken / CreateRefreshToken** (`gourdiantoken.maker.go`, orig ~L1098-1169 / ~L1248-1307): factor common skeleton (context check, claims construction, signing, response building) into a shared unexported helper, e.g. `createToken(ctx, tokenType, ...)`, with type-specific bits passed in or handled via a small closure/struct.

2. **VerifyAccessToken / VerifyRefreshToken** (orig ~L1387-1447 / ~L1521-1581): the revocation check, the `jwt.Parse` callback with the alg-mismatch check (byte-for-byte identical, orig ~L1403-1413 / ~L1546-1556), and the `token.Valid` checks are duplicated. Factor into a shared helper, e.g. `parseAndValidateToken(ctx, tokenString, tokenType) (jwt.MapClaims, error)`, leaving only the rotation check (refresh-only) and the final `mapToAccessClaims`/`mapToRefreshClaims` call distinct in each public method.

3. **RevokeAccessToken / RevokeRefreshToken** (orig ~L1656-1694 / ~L1762-1798): identical parse-then-extract-exp-then-`MarkTokenRevoke` logic except the `TokenType` constant. Factor into `revokeToken(ctx, tokenType, token) error`.

4. **RSA/ECDSA/EdDSA key parsers** (`gourdiantoken.keys.go`, orig ~L2865-3149): 6 functions repeat `pem.Decode` + nil-check boilerplate. Factor a shared `decodePEMBlock(pemBytes []byte, expectedType string) (*pem.Block, error)` helper used by all 6.

5. **mapToAccessClaims / mapToRefreshClaims** (`gourdiantoken.validation.go`, orig ~L2535-2649 / ~L2676-2755): duplicate jti/sub/sid/username/issuer/audience extraction. Factor a shared `extractCommonClaims(claims jwt.MapClaims) (commonClaims, error)` struct/helper, with each function extracting only its type-specific fields afterward.

Each dedup step should be validated with `go test ./...` (100% behavior-preserving — no assertions should need to change). Do dedup as separate, reviewable commits per item (not one giant commit) so any regression is easy to bisect.

**Files touched in Phase 2:** all six new files listed above (via `git mv`-equivalent content moves — note plain filesystem moves aren't literal `git mv` since content is being split, not moved 1:1, but frame commits that way for review clarity).

---

## Phase 3 — Public API changes (semver-relevant; needs documentation + version bump)

These change or extend the public surface. Bundle into a single minor-version release (per semver, since additive interface/API surface without breaking existing signatures is a MINOR bump; if `NewGourdianTokenConfig` is deprecated rather than removed, and `Close()` is *added* to the interface — see the breaking-change callout below — this is only non-breaking if handled carefully).

### 3a. Sentinel errors

Add a new file `gourdiantoken.errors.go`:

```go
package gourdiantoken

import "errors"

var (
    ErrTokenRevoked        = errors.New("token has been revoked")
    ErrTokenRotated         = errors.New("token has been rotated and is no longer valid")
    ErrTokenExpired         = errors.New("token has expired")
    ErrInvalidSignature     = errors.New("invalid token signature")
    ErrInvalidToken         = errors.New("invalid token")
    ErrInvalidClaims        = errors.New("invalid token claims")
    ErrTokenRepositoryRequired = errors.New("token repository required")
    ErrMissingExpClaim      = errors.New("token missing exp claim")
)
```

(Exact set/names to be finalized with the user, but these cover every distinguishable failure mode called out in the findings.)

Raise-site changes (wrap via `%w`, preserving existing message text where useful for humans, e.g. `fmt.Errorf("%w", ErrTokenRevoked)` or `fmt.Errorf("verify access token: %w", ErrTokenRevoked)`):

- `gourdiantoken.go` ~L1398 `VerifyAccessToken`: `return nil, fmt.Errorf("token has been revoked")` -> `return nil, fmt.Errorf("%w", ErrTokenRevoked)`
- `gourdiantoken.go` ~L1532 `VerifyRefreshToken`: same revoked-token site -> wrap `ErrTokenRevoked`
- `gourdiantoken.go` ~L1542 `VerifyRefreshToken`: `"token has been rotated and is no longer valid"` -> wrap `ErrTokenRotated`
- `gourdiantoken.go` ~L1955 `RotateRefreshToken` (if it independently raises a rotated-token error) -> wrap `ErrTokenRotated`
- `gourdiantoken.go` ~L2825 (`validateTokenClaims`, expired-token branch) -> wrap `ErrTokenExpired`
- `gourdiantoken.go` ~L1416 / ~L1559 (jwt.Parse error wrapping in Verify*) -> wrap `ErrInvalidSignature` when the underlying `jwt.Parse` error indicates a signature/alg mismatch, or `ErrInvalidToken` for general parse failure — needs a type-switch on the underlying `jwt.ValidationError` to pick the right sentinel; document this mapping precisely during implementation since `jwt.Parse` bundles several failure kinds into one error.
- `gourdiantoken.go` ~L879 (validateConfig-adjacent, "token repository required...") -> wrap `ErrTokenRepositoryRequired`, combined with the clearer message from Phase 1 item 4.

Doc examples to update from `strings.Contains` to `errors.Is`:

- `docs.go` ~L674: `strings.Contains(err.Error(), "expired")` -> `errors.Is(err, gourdiantoken.ErrTokenExpired)`
- `docs.go` ~L689: `strings.Contains(err.Error(), "rotated")` -> `errors.Is(err, gourdiantoken.ErrTokenRotated)`
- `gourdiantoken.go` ~L1856: same rotated-token doc comment example -> `errors.Is`
- `gourdiantoken.go` ~L1887: same -> `errors.Is`

Test-file usages of `strings.Contains` on error messages (`revocation.rotation_test.go` ~L560, `token.verification_test.go` ~L749-751) are not doc examples but should be migrated to `errors.Is` in the same PR for consistency and to serve as regression tests that the sentinel wrapping actually works.

**Compatibility note:** Adding sentinel errors and wrapping existing error strings with `%w` is additive and backward compatible — `err.Error()` text can be preserved by keeping the original message inside the `fmt.Errorf` format string ahead of `%w`, so any caller doing string matching continues to work unchanged. Recommend preserving original message text (e.g. `fmt.Errorf("token has been revoked: %w", ErrTokenRevoked)`) rather than replacing it, purely for compatibility with any existing consumer doing string matching, even though the library's own docs are what we're fixing.

### 3b. Close()/Shutdown() on the maker

- Add `Close() error` (or `Shutdown(ctx context.Context) error` — recommend `Close() error` for symmetry with `TokenRepository.Close()` signatures already used by 3 of 4 backends) to the `GourdianTokenMaker` interface (`gourdiantoken.go` ~L585-758, to become `gourdiantoken.interfaces.go` after Phase 2).
- Implement on `*JWTMaker`: cancel the context/close the stop-channel that the two background goroutines (`cleanupRotatedTokens` ~L1992, `cleanupRevokedTokens` ~L2037) select on. Follow the `sync.Once` + channel pattern already used in `MemoryTokenRepository.Close()` (`gourdiantoken.repository.inmemory.imp.go` ~L623-628) for consistency.
- **This is a breaking change** for any existing external implementer of the `GourdianTokenMaker` interface (adding a method to a public interface breaks all external implementations that don't embed it). Since the library's own `JWTMaker` is presumably the only intended implementer, and Go interfaces are structurally typed, this is a judgment call to flag explicitly to the user before implementing: either (a) accept the break and bump to a new major/minor version with a CHANGELOG note, or (b) add `Close()` as a new interface `GourdianTokenMakerCloser` (or similar) that `*JWTMaker` also satisfies, avoiding the break, at the cost of a slightly less discoverable API. Recommend surfacing this choice to the user rather than deciding unilaterally.
- Wire the Phase 1 item 3 logger field's public setter here too (e.g. a functional option `WithLogger(logf func(string, ...any))` passed to the constructors), since exposing configuration for the goroutines' error handling is itself a public API surface change.

### 3c. Config constructor

- Findings confirm `NewGourdianTokenConfig` (`gourdiantoken.go` ~L190-216) is a thin 17-positional-arg wrapper that's strictly more error-prone than the struct-literal + `DefaultGourdianTokenConfig` pattern the README (~L339-343, ~L379-384) and the package's own godoc example (~L174-189) already recommend as preferred.
- **Do NOT remove or break it in this pass.** Recommended action: add a `// Deprecated: use DefaultGourdianTokenConfig + struct-literal field assignment instead. NewGourdianTokenConfig will be removed in a future major version.` godoc comment (Go tooling / IDEs surface `// Deprecated:` comments automatically), but keep the function fully functional. This is the standard safe deprecation path for a public library with external consumers, and matches semver expectations (deprecate in a minor, remove only in a major with a clear migration window).
- Separately, note the shape inconsistency: `NewGourdianTokenMakerWithMongo` (`gourdiantoken.factories.go` ~L380) takes an extra `transactionsEnabled bool` positional param vs. the other four factories' `(ctx, config, client)` 2-arg-after-ctx shape. Do not change this signature in this pass either (also a breaking change) — just flag it in the deprecation comment or a follow-up issue, since fixing it would require either an options struct or a new factory variant, which is a larger design decision better suited to a follow-up, separately-scoped change.

**Files touched in Phase 3:** `gourdiantoken.errors.go` (new), `gourdiantoken.go`/`gourdiantoken.maker.go`, `gourdiantoken.interfaces.go`, `gourdiantoken.config.go`, `gourdiantoken.factories.go`, `docs.go`, `revocation.rotation_test.go`, `token.verification_test.go`.

---

## Phase 4 — Repository backend fixes (mix of bug fix and behavior change; sequence after Phase 3 sentinel errors land since the fix references error-boundary conventions)

1. **Mongo transaction/duplicate-key issue (concrete fix, not "investigate").**
   - File: `gourdiantoken.repository.mongo.imp.go`, `MarkTokenRotatedAtomic` (~L528-565) and its use of `withTransaction` (~L253-269).
   - Problem: inside the transaction callback, catching `mongo.IsDuplicateKeyError(err)` and returning `nil` (~L550-553) to signal "already rotated" is risky because a write error inside a MongoDB transaction can abort the transaction server-side regardless of what the callback returns, making the subsequent `session.WithTransaction` commit behavior driver-version-dependent.
   - **Concrete fix:** restructure so the duplicate-key detection happens at the *boundary*, not inside the txn callback:
     - Have the transaction callback simply attempt the `InsertOne` and return the raw error (including duplicate-key errors) without swallowing it — do not call `mongo.IsDuplicateKeyError` inside `fn`.
     - After `r.withTransaction(...)` returns, check `if mongo.IsDuplicateKeyError(err) { return false, nil }` at the `MarkTokenRotatedAtomic` call site (outside/after the transaction has already been aborted/rolled back by the driver, which is the correct outcome for "someone else already rotated this token concurrently").
     - This makes the atomic contract identical to Redis's `SetNX` (~L394) and GORM's `ON CONFLICT DO NOTHING` + `RowsAffected` (~L472-483): "false, nil" means "not newly marked, no real error", decided at the outer boundary rather than by the callback pretending nothing happened.
     - Apply the equivalent fix to `MarkTokenRevoke`'s analogous duplicate-key path if present (verify at implementation time whether `MarkTokenRevoke` has the same catch-inside-callback pattern; the findings only explicitly call out `MarkTokenRotatedAtomic`, but the same "revoke an already-revoked token" case may exist).
   - Add a regression test exercising concurrent/duplicate `MarkTokenRotatedAtomic` calls against Mongo with `useTransactions=true` to lock in the corrected boundary behavior (existing tests may only cover `useTransactions=false` or non-conflicting cases — verify at implementation time).

2. **RotateRefreshToken unrecoverable-lockout bug** (`gourdiantoken.go` ~L1928-1969, to become `gourdiantoken.maker.go`): if `CreateRefreshToken` fails *after* `MarkTokenRotatedAtomic` already succeeded (~L1948), the old token is permanently burned with no new token issued. Recommend: at minimum, document this failure mode clearly in the `RotateRefreshToken` godoc (a compensating "un-rotate" is not generally safe/possible against most backends, so full recovery may not be achievable without a two-phase design). If the user wants an actual fix rather than just documentation, that's a larger design change (e.g. delay marking rotated until after the new token is successfully created, trading off a small race window) — flag as a separate decision point rather than bundling into this phase's scope.

3. **Redis TTL floor vs. other backends (behavioral divergence, flag only — no fix mandated here).**
   - `gourdiantoken.repository.redis.imp.go` ~L178-180, ~L316-319, ~L385-387: `minRedisTTL = 100 * time.Millisecond` silently clamps TTLs below it, while in-memory/GORM/Mongo use the exact TTL. This is a genuine cross-backend inconsistency worth documenting (e.g. in `TokenRepository` interface godoc: "implementations may enforce a minimum TTL floor") rather than silently changing Redis behavior, since removing the floor could have been an intentional Redis-specific safeguard against near-zero TTL races. Recommend: document the divergence explicitly; only change behavior if the user confirms it's unintentional.

4. **Mongo `Close(ctx context.Context) error` signature inconsistency vs. the other three backends' `Close() error`** (`gourdiantoken.repository.mongo.imp.go` ~L888-892 vs. `gourdiantoken.repository.{inmemory,redis,gorm}.imp.go`). This is a `TokenRepository` interface-level inconsistency — fixing it means either changing the `TokenRepository` interface (breaking, same category as 3b's `Close()` discussion) or leaving Mongo's `Close` as an extra method beyond the interface (if the interface itself doesn't declare `Close` at all, verify this at implementation time — the interface's actual `Close` requirement, if any, determines whether this is fixable without a breaking change). Flag as a decision point; do not silently change the interface.

**Files touched in Phase 4:** `gourdiantoken.repository.mongo.imp.go`, `gourdiantoken.go`/`gourdiantoken.maker.go` (doc comment), `gourdiantoken.repository.redis.imp.go` (doc comment only), `gourdiantoken.repository_test.go` or a Mongo-specific test file (new regression test).

---

## Explicitly deferred / low priority (do NOT do in a first pass)

Per the requirements, these are noted but not scheduled as urgent work in this plan:

- Removing/simplifying Redis's `cleanupExpiredKeys` SCAN+PTTL pass (`gourdiantoken.repository.redis.imp.go` ~L627-687) — redundant with Redis's native TTL expiry, but low-risk-of-harm as-is; efficiency-only.
- Adding a composite `(token_type, expires_at)` index in GORM (`gourdiantoken.repository.gorm.imp.go` ~L37-39 currently has separate indexes only) — efficiency-only, no correctness impact.
- Consolidating GORM/Mongo `Stats()` from 4 sequential count queries into one aggregate — efficiency-only.
- Bounding in-memory map growth between cleanup ticks — flagged as a burst-growth risk, not an active bug; revisit only if it manifests in practice.

## Explicitly NOT recommended for a first pass

- **Do not remove `NewGourdianTokenConfig` outright.** It's a public constructor in an already-published library; removal without a deprecation window breaks every existing caller at compile time. Deprecate via godoc comment only (Phase 3c).
- **Do not change `NewGourdianTokenMakerWithMongo`'s positional-arg shape** to match the other four factories in this pass — it's a breaking signature change; only flag the inconsistency.
- **Do not add `Close()` to `GourdianTokenMaker` without first flagging the interface-breaking implication to the user** — this needs an explicit go/no-go decision (accept the break vs. use a separate closer interface), not a unilateral implementation choice.
- **Do not change Redis's TTL-floor behavior** to match the other three backends without confirming with the user whether the floor was an intentional safeguard.

---

## Suggested sequencing summary

1. Phase 0 (baseline) -> 2. Phase 1 (safe fixes) -> 3. Phase 2 (file split, then dedup) -> 4. Phase 3 (sentinel errors, Close(), config deprecation — bundle as one semver-relevant release, after explicit user sign-off on the Close()-breaking-interface question) -> 5. Phase 4 (repository fixes, sequenced after Phase 3 so error-boundary conventions are consistent).

Each phase is independently shippable; Phases 1-2 could go out as a single patch release, Phase 3 as a minor release with a CHANGELOG entry and doc updates, Phase 4 as a follow-on patch/minor depending on whether the Close()-signature question in item 4 requires an interface change.
