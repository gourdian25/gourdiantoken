# gourdiantoken Improvement Plan (Consolidated)

Scope: the `gourdiantoken` Go library at repo root (package `gourdiantoken`). Excludes bark.txt/.bark.toml tooling entirely.

This is a single merged plan built from two prior passes: an initial research pass, and a follow-up session that re-verified every claim line-by-line against the actual source and found several things the first pass missed (a larger dead-error-handling bug, a false doc comment about goroutine cleanup, a file-naming bug that forces every consumer to pull in `testify` as a hard dependency, a simplification available via golang-jwt v5's built-in sentinels, and a corrected file-split line mapping). Where the two passes disagreed, this document uses the verified/corrected version and notes what changed.

**Design decisions already made (do not re-litigate these):**
- UUID scope for Phase 5: `ID` (jti), `Subject` (sub), and `SessionID` (sid) all become `string`, not just caller-supplied fields.
- Post-migration, `userID`/`sessionID` become fully opaque — any non-empty string is accepted, no UUID-shape requirement.
- Phase 5 (UUID removal) ships as a separate v2.0.0 major release, strictly after Phases 0-4 ship as v1.x.
- `Close()` ships via a new, separate `GourdianTokenMakerCloser` interface — not added to the existing `GourdianTokenMaker` interface — so it stays non-breaking.
- Phase 5 lands on the `dev#manish#remove_uuid` branch; Phases 1-4 land on `dev`/`master` as normal v1.x patch/minor releases.

---

## Before you start: re-verify against current source, and expand this plan if needed

Line numbers in this document were accurate as of the last verification pass, but they **will drift** as the file changes — code review, other PRs, or your own earlier edits in this session can all shift them. Treat every `~L####` reference here as a *pointer to go look*, not a guarantee.

For every phase, before writing any code:

1. **Re-locate every referenced site** with `grep -n` or your editor's search, rather than trusting the line number directly. If a pattern has moved, drifted, or no longer matches the description, note the actual current location before proceeding.
2. **Confirm the pattern still matches the description.** Code may have changed since the last check. If what you find doesn't match what's described (different logic, already fixed, different error message), stop and flag it rather than applying the fix blindly.
3. **Actively look for siblings of each bug class.** Several items in this plan were found precisely because someone searched for "does this exact anti-pattern appear elsewhere" (e.g. the dead-`err` bug turned out to have 4 sites, not 2; the mis-suffixed test-helper files were found by checking `go list -f '{{.GoFiles}}'` rather than assuming naming implies test-only status). Do the equivalent check for each fix in this plan — e.g. when fixing one duplicate-key-swallowing pattern in Mongo, check whether the same pattern appears in a sibling method; when fixing one panic-instead-of-error, grep for other `panic(` calls reachable from public methods.
4. **If you find additional issues, missed sites, or a correction to something in this plan, expand this document** rather than fixing silently and moving on. Add the new finding to the relevant phase using the same format used throughout (file, approximate line, current behavior, proposed fix, why it's safe/what it breaks). Note explicitly whether it changes the phase's risk profile (e.g. a "safe fix" phase should stay behavior-preserving — if a newly found issue isn't, it belongs in a later phase instead).
5. **Re-run the verification commands for the phase you just finished** (see "Verification" section near the end) before moving to the next phase. Don't batch verification across phases — each phase should leave the tree in a known-good, fully tested state before the next one starts.

This applies with extra force to Phase 2 (the file split) and Phase 5 (the UUID migration): both are large mechanical changes where a stale line reference is likely to cause you to move or edit the wrong code. Re-view the actual current file immediately before editing it, every time — not just once at the start of the phase.

---

## Phase 0 — Baseline safety net (prerequisite, do first)

Before any refactor, confirm test coverage is adequate to catch regressions during the mechanical file split and dedup work.

- Run `go build ./...` and `go vet ./...` — confirm a clean baseline (0 errors/issues).
- `go test ./...` exercises repository-backed tests across **Memory, Redis, MongoDB, GORM** subtests (via `token.test.helper.go`'s `getTestRepositoryFactories()`); the latter three need real local services (hardcoded creds, no docker-compose in repo). To get a meaningful green baseline without standing up infra, scope to:
  ```
  go test -run '.*/Memory' ./...
  ```
  plus the non-repository-backed test files. If you *do* have Redis/MongoDB/PostgreSQL available locally, run the full `make test` / `make race` instead for a stronger baseline — check for a `CLAUDE.md` or similar contributor doc for connection details.
- No code changes in this phase.

---

## Phase 1 — Safe, isolated fixes (patch release, v1.0.8)

All behavior-preserving-or-additive, zero public API surface change. Land as one PR.

1. **Dead-`err` bug — confirm all 4 sites, not just the obvious 2.**
   - `VerifyAccessToken` (~L1420) and `VerifyRefreshToken` (~L1563):
     ```go
     if !token.Valid {
         return nil, fmt.Errorf("invalid token: %v", err)  // err is always nil here
     }
     ```
     `err != nil` was already handled above, so this always prints `"invalid token: <nil>"`.
   - Also check `RevokeAccessToken` (~L1673-1674) and `RevokeRefreshToken` (~L1778-1779), which have the same defect in a combined-OR form:
     ```go
     if err != nil || !parsed.Valid {
         return fmt.Errorf("invalid token: %w", err)
     }
     ```
     When `!parsed.Valid` is the true disjunct, `%w` on a nil `err` renders a malformed `%!w(<nil>)` — worse than the `%v` case.
   - Fix: split each combined check apart and give the `!Valid` branch its own real message, e.g. `"token failed validation"` (or, once Phase 3 sentinels exist, wrap `ErrTokenInvalid`/`ErrInvalidToken`).
   - **Explore further:** grep for other `%v`/`%w` uses of `err` inside branches where `err` was already checked and known-nil above — this pattern may recur elsewhere in the file.

2. **Replace panics in `toMapClaims` with returned errors.**
   - `toMapClaims` (~L2461-2508): unsupported claim type (~L2465) and empty `Roles` (~L2506) currently `panic(...)`, reachable from the public `CreateAccessToken`/`CreateRefreshToken` path.
   - Change signature to `func toMapClaims(claims interface{}) (jwt.MapClaims, error)`; both panic sites become `return nil, fmt.Errorf(...)`.
   - Update both call sites (`CreateAccessToken` ~L1141, `CreateRefreshToken` ~L1280). Both already have `err` in scope from the preceding `uuid.NewRandom()` call — reuse it via `mapClaims, err := toMapClaims(claims)` (valid Go, since at least one new variable is on the LHS); no shadowing needed.
   - This is an internal-only signature change — no external impact — but every caller must be updated in the same commit.
   - **Explore further:** grep for any other `panic(` calls reachable from a public method; this is a good time to eliminate the whole class if any exist.

3. **Add a logger hook for background cleanup goroutines (internal plumbing only this phase).**
   - `cleanupRotatedTokens` (~L1992-2013) and `cleanupRevokedTokens` (~L2037-2060) currently `fmt.Printf` errors to stdout.
   - Add an unexported field to `JWTMaker`, e.g. `logf func(format string, args ...any)`, defaulting to today's `fmt.Printf` behavior.
   - No public setter yet — exposing a way to configure it is a public API change and belongs in Phase 3b, bundled with `Close()`.

4. **Improve the ambiguous validation message.**
   - ~L879: `"token repository required for token rotation/revocation"` doesn't say which flag triggered it.
   - Change to something specific, e.g.:
     ```go
     fmt.Errorf("token repository required: RotationEnabled=%v, RevocationEnabled=%v", config.RotationEnabled, config.RevocationEnabled)
     ```

5. **Add exported constants for magic `RequiredClaims` strings.**
   - ~L65-147 / ~L116-118 documents `"iss"`, `"aud"`, `"nbf"`, `"mle"` as magic strings with no exported constants.
   - Add e.g. `ClaimIssuer = "iss"`, `ClaimAudience = "aud"`, `ClaimNotBefore = "nbf"`, `ClaimMaxLifetimeExpiry = "mle"` near `GourdianTokenConfig`.
   - Purely additive — no existing behavior changes; consumers adopt at their own pace.

6. **Fix a false doc comment about goroutine cleanup.**
   - `JWTMaker`'s doc comment (~L770, "Cleanup goroutines stop when the maker is garbage collected") and the matching lines in `cleanupRotatedTokens`/`cleanupRevokedTokens`'s doc comments (~L1986, ~L2031) are false — there are zero `runtime.SetFinalizer` calls anywhere in the repo.
   - Once rotation/revocation is enabled, those goroutines currently run until process exit with no way to stop them. Reword the comments now to stop making a false claim; Phase 3b's `Close()` is the actual fix for the underlying leak — don't promise it here, just stop lying about the current behavior.

7. **Rename the two mis-suffixed test helper files.**
   - `token.test.helper.go` → `token.test.helper_test.go`
   - `token.bench.helper.go` → `token.bench.helper_test.go`
   - Verify with `go list -f '{{.GoFiles}}' .` that both currently compile as **ordinary package files**, not test-only. `token.test.helper.go` is the only non-`_test.go` file importing `stretchr/testify`, meaning every consumer of this library today transitively pulls in `testify` (plus its indirect deps `go-spew`, `go-difflib`, `yaml.v3`) purely because of this naming bug.
   - Before renaming, confirm zero non-test references to the helpers these files define (e.g. `setupTestMaker`, `generateTestUUID`) — grep across the whole repo, not just `*_test.go` files, to be sure. This should be a safe, pure rename with a real dependency-footprint benefit for consumers.

8. **Test gap fill.**
   - Add a direct test of `NewGourdianTokenMaker(ctx, config, nil)` (generic constructor, not `NewGourdianTokenMakerNoStorage`) with `RotationEnabled`/`RevocationEnabled` true, asserting the specific error from item 4.
   - `TestAllFactories_InvalidConfigurationsFail` (`gourdiantoken.factories_test.go` ~L574-613) is misnamed today — it only exercises `NewGourdianTokenMakerNoStorage`, never `WithMemory`/`WithGorm`/`WithMongo`/`WithRedis`. Extend it with nil-handle cases for Gorm/Mongo/Redis (each already has a real guard clause — e.g. `"gorm database instance cannot be nil"` in `gourdiantoken.factories.go` ~L278-280 — just currently untested), plus one shared invalid-config case (e.g. negative `AccessExpiryDuration`) run as a table test across all 5 factories.

9. **Flag only — do NOT fix in this phase.**
   - `RevokeAccessToken`/`RevokeRefreshToken`'s `jwt.Parse` keyfunc callbacks (~L1666-1672, ~L1771-1777) don't check `token.Method.Alg() != maker.signingMethod.Alg()` the way `VerifyAccessToken`/`VerifyRefreshToken` do. Real, but low-severity (Go's static typing of `maker.publicKey` bounds classic alg-confusion attacks here). Adding the check would reject inputs accepted today — a real behavior change, so it doesn't belong in a "safe fixes" phase. Open a follow-up issue instead.

**Files touched in Phase 1:** the main source file (pre-split), `gourdiantoken.factories_test.go` (new/extended tests), two renamed test-helper files.

---

## Phase 2 — Internal refactors (patch release, v1.0.9), behavior-preserving

Land 2a and 2b as **separate commits** so a regression is easy to bisect between "changed behavior" and "moved code."

### 2a. File split (purely mechanical move, no logic changes)

Split the ~3262-line main source file into 6 cohesive files, all remaining in `package gourdiantoken`. Go packages are flat namespaces, so **no consumer import changes are required**. This matches the existing convention already used for the repository backends (`*.repository.*.imp.go`), so use the same dotted naming style rather than bare shorthand names.

Use this corrected mapping (a first pass left a ~200-line gap unassigned — this version accounts for every line):

| New file | Approx. lines | Contents |
|---|---|---|
| `gourdiantoken.config.go` | 1-273 | `TokenType`/`SigningMethod` types+consts, `GourdianTokenConfig`, `NewGourdianTokenConfig`, `DefaultGourdianTokenConfig` |
| `gourdiantoken.claims.go` | 275-463 | `AccessTokenClaims`, `RefreshTokenClaims`, `AccessTokenResponse`, `RefreshTokenResponse` |
| `gourdiantoken.interfaces.go` | 465-758 | `TokenRepository`, `GourdianTokenMaker` |
| `gourdiantoken.maker.go` | 760-2266 | `JWTMaker` struct, constructors, Create/Verify/Revoke/Rotate methods, cleanup goroutines, **plus `initializeSigningMethod` (~2062-2132), `initializeKeys` (~2134-2171), `parseKeyPair` (~2173-2239), and `hashToken` (~2241-2266)** — these four are maker-specific (three are `*JWTMaker` methods, `hashToken` is used only by Revoke*) and are easy to miss if you only skim for the "obvious" method groups |
| `gourdiantoken.validation.go` | 2268-2842 | `validateConfig`, `validateAlgorithmAndMethod`, `toMapClaims`, `mapToAccessClaims`, `mapToRefreshClaims`, `validateTokenClaims` |
| `gourdiantoken.keys.go` | 2844-3262 | 6 key parsers (`parseEdDSA*`/`parseRSA*`/`parseECDSA*`), `checkFilePermissions`, `getUnixTime`, PEM/ASN.1 structs |

Process:
- Move code verbatim (cut/paste), do not touch logic.
- Keep the `package gourdiantoken` declaration and existing imports at the top of each new file; let `goimports`/`gofmt` trim unused imports per file.
- Before moving each block, re-view the *current* file at that location — line numbers above are approximate and may have drifted since the last check (see "Before you start" section).
- Run `go build ./...` and `go test ./...` after the split. This should be a no-op at the AST level — inspect `git diff` to confirm no lines were altered beyond the move.

### 2b. Deduplication (behavior-preserving, do after the split)

1. **Create\* helpers.** Don't force `CreateAccessToken`/`CreateRefreshToken` into one mega-function — the two claims structs genuinely differ, and Phase 5 will touch these literals directly, so keep them inline. Instead extract 3 small shared pieces:
   - `validateUserAndUsername(userID uuid.UUID, username string) error`
   - `newTokenID() (uuid.UUID, error)` — centralizes the `uuid.NewRandom()` error path
   - `func (maker *JWTMaker) signClaims(ctx context.Context, claims interface{}, tokenType TokenType) (string, error)` — builds map claims via `toMapClaims`, signs, wraps errors with `"failed to sign %s token"`

2. **Verify\* helpers.** One shared:
   ```go
   func (maker *JWTMaker) parseAndValidateToken(ctx context.Context, tokenString string, tokenType TokenType) (jwt.MapClaims, error)
   ```
   covering the revocation check, the rotation check (gated on `tokenType == RefreshToken`, folded in rather than kept external — keeping it external would require reordering checks, which this phase can't do since it must stay behavior-preserving), the `jwt.Parse` call (its keyfunc callback is byte-identical between the two today), and `validateTokenClaims`. `VerifyAccessToken`/`VerifyRefreshToken` become thin wrappers calling this then `mapToAccessClaims`/`mapToRefreshClaims`.
   While here: drop `VerifyAccessToken`'s trailing `claims["rls"]` recheck (~L1442-1444) — it's provably dead, since `mapToAccessClaims` and `validateTokenClaims` both already require `"rls"` to be present before this line is ever reached.

3. **Revoke\* helpers.** One shared `func (maker *JWTMaker) revokeToken(ctx context.Context, tokenType TokenType, token string) error`, parametrizing the "not enabled" message and the `TokenType` passed to `MarkTokenRevoke` via `%s`/`string(tokenType)`. `RevokeAccessToken`/`RevokeRefreshToken` become 1-line wrappers.

4. **6 key parsers.** Shared `func decodePEMBlock(pemBytes []byte, description string) (*pem.Block, error)`, called with each function's existing description string (`"private key"`, `"RSA public key"`, etc.) to keep error messages byte-exact.

5. **`mapToAccessClaims`/`mapToRefreshClaims`.** Shared `extractCommonClaims(claims jwt.MapClaims) (*commonClaims, error)` for the jti/sub/sid/username/issuer/audience/timestamps extraction common to both.
   **This also fixes a latent bug:** today `mapToRefreshClaims` does unchecked inline assertions (`uuid.Parse(claims["jti"].(string))` and similarly for sub/sid) that panic on a missing or non-string claim, unlike `mapToAccessClaims`'s checked pattern. The shared helper should use the safe checked pattern for both. Each caller then handles only its own type-specific bits (`Roles` for access; the now-redundant-but-harmless `typ == "refresh"` recheck for refresh).

Validate every dedup step with `go test ./...` — this is 100% behavior-preserving, so no assertions should need to change. Do each item as a separate, reviewable commit, not one giant commit.

**Files touched in Phase 2:** all six new files listed above.

---

## Phase 3 — Public API additions (minor release, v1.1.0)

### 3a. Sentinel errors

Add a new file `gourdiantoken.errors.go`. Key point: golang-jwt v5's `jwt.Parse` already runs its own default validator (nothing in this codebase disables it via `ParserOption`), and it already returns `jwt.ErrTokenExpired`/`jwt.ErrTokenSignatureInvalid` on the relevant failures — already reachable via `errors.Is` today through the existing `%w` chains with zero code changes. So **alias** rather than reinvent for those two:

```go
package gourdiantoken

import (
    "errors"

    "github.com/golang-jwt/jwt/v5"
)

var (
    ErrTokenRevoked             = errors.New("token has been revoked")
    ErrTokenRotated             = errors.New("token has been rotated")
    ErrTokenExpired             = jwt.ErrTokenExpired          // alias — golang-jwt already produces this
    ErrInvalidSignature         = jwt.ErrTokenSignatureInvalid // alias
    ErrInvalidToken             = errors.New("invalid token")
    ErrInvalidClaims            = errors.New("invalid token claims")
    ErrTokenRepositoryRequired  = errors.New("token repository required")
    ErrMissingExpClaim          = errors.New("token missing exp claim")
    ErrTokenMaxLifetimeExceeded = errors.New("token exceeded maximum lifetime") // the "mle" branch is gourdiantoken-only; golang-jwt has no equivalent
)
```

Wrap sites (adjust to actual current line numbers — re-verify first):
- Revoked-token checks in `VerifyAccessToken`/`VerifyRefreshToken` (~L1398, ~L1532) → wrap `ErrTokenRevoked`
- Max-lifetime branch in `validateTokenClaims` (~L2837) → wrap `ErrTokenMaxLifetimeExceeded`
- Missing-exp sites in Revoke* (~L1684, ~L1789) → wrap `ErrMissingExpClaim`
- Repo-required site (~L879, post-Phase-1-item-4 wording) → wrap `ErrTokenRepositoryRequired`
- **Rotated-token wording:** `VerifyRefreshToken` currently says "token has been rotated and is no longer valid" (~L1542) while `RotateRefreshToken` says just "token has been rotated" (~L1955) for the same logical condition. Check all existing test assertions on this message (there are roughly 17) — confirm none depends on the longer suffix — then unify both to `fmt.Errorf("%w", ErrTokenRotated)`.
- **Generic invalid-token wrap** (in `VerifyAccessToken`/`VerifyRefreshToken`'s `jwt.Parse` error handling, and in the post-2b `parseAndValidateToken`/`revokeToken` helpers): use a double-`%w` so both a coarse and fine-grained `errors.Is` check work through the same chain:
  ```go
  fmt.Errorf("%w: %w", ErrInvalidToken, err)
  ```

Doc comment updates — replace `strings.Contains(err.Error(), "expired")`-style examples with `errors.Is(err, gourdiantoken.ErrTokenExpired)` (and the rotated-token equivalent) wherever such examples appear in package docs or godoc comments.

Test changes: convert only the **real, non-doc-comment** `strings.Contains(err.Error(), ...)` sites to `assert.ErrorIs` — these are `revocation.rotation_test.go` (~L559-561) and `token.verification_test.go` (~L749-751). Do **not** touch other `assert.Contains(t, err.Error(), ...)` calls elsewhere in the test suite (there are roughly 164 of these across the repo) — they aren't wrong, just not using the new sentinels yet, and migrating all of them is out of proportion to this pass.

**Compatibility note:** Adding sentinel errors and wrapping existing error strings with `%w` is additive and backward compatible. Preserve original message text ahead of `%w` (e.g. `fmt.Errorf("token has been revoked: %w", ErrTokenRevoked)`) so any existing caller doing string matching continues to work unchanged.

### 3b. `Close()` via a new, separate interface

Non-breaking design (do **not** add `Close()` to the existing `GourdianTokenMaker` interface — that would break any external implementer):

```go
type GourdianTokenMakerCloser interface {
    Close() error
}

func (maker *JWTMaker) Close() error {
    maker.closeOnce.Do(func() {
        if maker.cleanupCancel != nil {
            maker.cleanupCancel()
        }
    })
    return nil
}
```

- Add `closeOnce sync.Once` to `JWTMaker`, alongside the existing `cleanupCancel context.CancelFunc` field (~L787).
- Mirror `MemoryTokenRepository.Close()`'s existing `sync.Once` + channel pattern (`gourdiantoken.repository.inmemory.imp.go` ~L623-628) for consistency with the rest of the codebase.
- Wire in the Phase 1 item 3 logger field's public setter here too — a functional option, e.g. `WithLogger(logf func(string, ...any))`, passed to the constructors — since exposing configuration for the goroutines' error handling is itself a public API surface change and belongs in the same minor release as `Close()`.
- Add tests for: idempotent double-`Close()`, and the cleanup goroutines actually stopping after `Close()` (e.g. assert the cleanup goroutine's context is `Done()` afterward). Today only `MemoryTokenRepository.Close()` has any such test.

### 3c. Config constructor deprecation

- Add a `// Deprecated: use DefaultGourdianTokenConfig + struct-literal field assignment instead. NewGourdianTokenConfig will be removed in a future major version.` godoc comment to `NewGourdianTokenConfig` (~L190). Go tooling/IDEs surface `// Deprecated:` comments automatically.
- **Do not remove or break it.** Confirm it has exactly one real call site in the repo today (its own test) before proceeding — this is a safe, low-stakes deprecation.
- Separately, flag (comment or issue only — **no signature change** in this pass) that `NewGourdianTokenMakerWithMongo`'s extra `transactionsEnabled bool` positional param breaks the `(ctx, config, handle)` shape its true peers `NewGourdianTokenMakerWithGorm`/`WithRedis` share. Fixing this would require an options struct or a new factory variant — a larger design decision for a separately-scoped follow-up.

**Files touched in Phase 3:** `gourdiantoken.errors.go` (new), `gourdiantoken.maker.go`, `gourdiantoken.interfaces.go`, `gourdiantoken.config.go`, `gourdiantoken.factories.go`, package doc file, `revocation.rotation_test.go`, `token.verification_test.go`.

---

## Phase 4 — Repository backend fixes (ship with Phase 3, or as v1.1.1 immediately after)

Sequenced after Phase 3 since item 1 references error-boundary conventions consistent with the sentinel-error work.

1. **Mongo `MarkTokenRotatedAtomic` duplicate-key fix (concrete fix, not "investigate").**
   - `gourdiantoken.repository.mongo.imp.go`, `MarkTokenRotatedAtomic` (~L528-566) and its use of `withTransaction` (~L253-269).
   - Problem: today, `mongo.IsDuplicateKeyError(err)` is checked *inside* the transaction callback and swallowed (`return nil`). This is risky because a write error inside a MongoDB transaction can abort the transaction server-side regardless of what the callback returns, making the subsequent commit behavior driver-version-dependent.
   - **Fix:** move the duplicate-key detection to the *boundary*, not inside the txn callback:
     - Have the transaction callback attempt the `InsertOne` and return the raw error (including duplicate-key errors) unchanged — do not call `mongo.IsDuplicateKeyError` inside the callback.
     - After `r.withTransaction(...)` returns, check `if mongo.IsDuplicateKeyError(err) { return false, nil }` at the `MarkTokenRotatedAtomic` call site — this is the correct outcome for "someone else already rotated this token concurrently," decided outside the already-aborted/rolled-back transaction.
     - This makes the atomic contract identical to Redis's `SetNX` (~L394) and GORM's `OnConflict{DoNothing:true}` + `RowsAffected` (~L472-483): "false, nil" means "not newly marked, no real error," decided at the outer boundary.
   - Confirmed at verification time: `MarkTokenRevoke` and non-atomic `MarkTokenRotated` both use upsert-`ReplaceOne` and structurally can't hit this bug, so the fix is scoped to `MarkTokenRotatedAtomic` only — but re-check this assumption against current source before skipping the other two, since behavior may have changed.
   - Add a regression test exercising concurrent/duplicate `MarkTokenRotatedAtomic` calls against Mongo with `useTransactions=true` to lock in the corrected boundary behavior.

2. **`RotateRefreshToken` unrecoverable-lockout bug.**
   - ~L1928-1969: if `CreateRefreshToken` (~L1963) fails *after* `MarkTokenRotatedAtomic` (~L1948) already succeeded, the old token is permanently burned with no new token issued.
   - **Document only this pass** — add a clear godoc warning on `RotateRefreshToken` describing this failure mode. A real fix is a two-phase-commit-style redesign (delay marking rotated until after the new token is successfully created, trading off a small race window) — that's a larger design change, flag as a separate follow-up decision rather than bundling into this phase.

3. **Redis's `minRedisTTL` (100ms) floor — document divergence, do not change behavior.**
   - `gourdiantoken.repository.redis.imp.go` (~L178-180, ~L316-319, ~L385-387): silently clamps TTLs below 100ms, while in-memory/GORM/Mongo use the exact TTL requested.
   - Document the divergence explicitly in `TokenRepository`'s interface godoc, e.g. "implementations may enforce a minimum TTL floor." Do not remove or change the floor — it may have been an intentional Redis-specific safeguard against near-zero-TTL races. Only change behavior if you separately confirm with the maintainer that it's unintentional.

4. **Mongo's `Close(ctx context.Context) error` vs. the other three backends' bare `Close() error`.**
   - Verify first whether `TokenRepository` itself declares `Close()` at all. If it doesn't, this signature difference only affects direct callers of the concrete `*MongoTokenRepository` type, not an interface-breaking concern — confirm this before treating it as urgent.
   - Flag only, no change this pass either way.
   - Worth doing regardless of the signature question: today only `MemoryTokenRepository.Close()` has test coverage — Gorm/Redis/Mongo's `Close()` implementations are all untested. Add coverage for all three.

**Files touched in Phase 4:** `gourdiantoken.repository.mongo.imp.go`, `gourdiantoken.maker.go` (doc comment), `gourdiantoken.repository.redis.imp.go` (doc comment only), a Mongo-specific regression test file.

---

## Phase 5 — UUID → string migration (major release, v2.0.0, separate from v1.x)

Ships on the `dev#manish#remove_uuid` branch, strictly after Phases 0-4 land as v1.x. Breaking by definition (exported struct field types plus 2 interface method signatures change), so it needs its own major version and, per Go modules convention, a new module path (`/v2`).

**Scope** (per the design decisions at the top of this document): `ID`/`Subject`/`SessionID` on all 4 claim/response structs (`AccessTokenClaims`, `RefreshTokenClaims`, `AccessTokenResponse`, `RefreshTokenResponse`) and `userID`/`sessionID` params on `CreateAccessToken`/`CreateRefreshToken` (both the `GourdianTokenMaker` interface and `*JWTMaker` implementation) all become `string`. Validation becomes fully opaque — any non-empty string is accepted.

**This phase is all-or-nothing** — partial type changes won't compile. Do the steps below in order, then verify with a full build, not incrementally.

1. **Type changes.** Flip `uuid.UUID` → `string` on the 4 struct types (post-2a, in `gourdiantoken.claims.go`) and on the interface + implementation signatures for `CreateAccessToken`/`CreateRefreshToken`.

2. **Validation changes.**
   - `validateUserAndUsername`'s `userID == uuid.Nil` → `userID == ""`. SessionID has no such check today and shouldn't gain one — the existing doc comment already treats an empty/nil sessionID as valid for sessionless tokens.
   - In `validateTokenClaims`, **replace, don't bare-delete**, the 3 `uuid.Parse(...)` format-validation blocks (for jti/sub/sid) with explicit non-empty checks:
     ```go
     if jti, ok := claims["jti"].(string); !ok || jti == "" {
         return fmt.Errorf(...)
     }
     ```
     This is the one place where a literal "just drop the UUID validation" reading would create a silent regression: `uuid.Parse("")` today incidentally rejects empty claim values, and that guarantee must be preserved explicitly via the non-empty check, not dropped along with the UUID-shape check.

3. **Internal generation.** Keep `tokenID, err := uuid.NewRandom()` as the internal ID generator — do **not** switch to `uuid.NewString()`, which panics on entropy-read failure instead of returning an error. Only the assignment changes: `ID: tokenID` → `ID: tokenID.String()`. In the post-2b `toMapClaims`/`extractCommonClaims` helpers, drop the `.String()` call on the way in and the `uuid.Parse()` call on the way out, replaced by the same non-empty check as step 2.

4. **Mechanical call-site updates.** This is one repeated pattern across roughly 430 call sites spread over the test files and the example file — describe and apply the pattern rather than tracking each site individually:
   - `userID := uuid.New()` → `userID := uuid.NewString()` (keep `google/uuid` as a *test-only* import for convenient unique test values — the exported Go type changed, not the need for a UUID generator in tests)
   - drop trailing `.String()` calls at comparison sites
   - `uuid.UUID` local variable declarations → `string`
   - `uuid.Nil` → `""`

5. **Non-Go touch points** (easy to miss since they aren't caught by `go build`):
   - `go.mod`: module path gains `/v2`. `github.com/google/uuid` stays a real dependency, but confirm it's internal-only — check for zero references anywhere in the 4 repository backend implementations or the `TokenRepository` interface before assuming that whole layer needs no changes.
   - The example file: if it self-imports the module by path, that import needs `/v2` appended.
   - `README.md`: import-block code samples need `/v2`; any pkg.go.dev/GoDoc badge URL also needs `/v2` (issue/discussion links do not).
   - `Makefile` (or equivalent build tooling): any `MODULE`/`MAIN_PACKAGE`-style variables used in release `-ldflags` or doc-generation targets need `/v2` too — easy to overlook since it isn't a `.go` file.

6. **Worth stating in the v2 migration notes:** once `google/uuid` usage is purely internal, v2 consumers calling only the string-based API no longer need to import `github.com/google/uuid` themselves at all — a real dependency-footprint win worth advertising in the changelog.

---

## Explicitly deferred / low priority (do NOT do in a first pass)

- Removing/simplifying Redis's `cleanupExpiredKeys` SCAN+PTTL pass — redundant with Redis's native TTL expiry, but low risk as-is; efficiency-only.
- Adding a composite `(token_type, expires_at)` index in GORM (currently separate indexes only) — efficiency-only, no correctness impact.
- Consolidating GORM/Mongo `Stats()` from 4 sequential count queries into one aggregate — efficiency-only.
- Bounding in-memory map growth between cleanup ticks — flagged as a burst-growth risk, not an active bug; revisit only if it manifests in practice.

## Explicitly NOT recommended for a first pass

- **Do not remove `NewGourdianTokenConfig` outright.** It's a published public constructor; removing it without a deprecation window breaks every existing caller at compile time. Deprecate via godoc comment only (Phase 3c).
- **Do not change `NewGourdianTokenMakerWithMongo`'s positional-arg shape** to match the other four factories in this pass — it's a breaking signature change; flag the inconsistency only.
- **Do not add `Close()` to `GourdianTokenMaker`** — use the separate `GourdianTokenMakerCloser` interface (already decided, see Phase 3b).
- **Do not change Redis's TTL-floor behavior** to match the other three backends without separately confirming the floor was unintentional.

---

## Release sequencing

| Release | Contents |
|---|---|
| v1.0.8 (patch) | Phase 1 |
| v1.0.9 (patch) | Phase 2 (2a then 2b as separate commits) |
| v1.1.0 (minor) | Phase 3 (3a + 3b + 3c) |
| v1.1.1 (patch) or bundled with v1.1.0 | Phase 4 |
| v2.0.0 (major) | Phase 5, on `dev#manish#remove_uuid`, strictly after v1.x above stabilizes |

Each phase is independently shippable. Phases 1-2 could go out as a single patch release if preferred; Phase 3 as a minor release with a CHANGELOG entry and doc updates; Phase 4 as a follow-on patch/minor depending on whether anything in item 4 ends up needing an interface change (it shouldn't, per the current-source check above — re-verify before assuming).

---

## Verification (run after every phase, not just at the end)

- `go build ./...` and `go vet ./...` after every change.
- `go test -run '.*/Memory' ./...` for logic that doesn't touch storage backends; full `make test`/`make race` needs local Redis/MongoDB/PostgreSQL.
- **Phase 1:** new item-8 tests pass; confirm `go list -f '{{.GoFiles}}'` / `{{.TestGoFiles}}` after the rename shows the two helper files moved into `TestGoFiles`; confirm a fresh `go mod graph` (or `go list -deps` from a throwaway consumer module) no longer pulls in `testify`.
- **Phase 2:** `git diff` after 2a should be a pure move (no logic lines changed); `go test ./...` after each 2b commit should need zero assertion changes.
- **Phase 3:** new `errors.Is`/`ErrorIs` assertions pass for `ErrTokenRevoked`, `ErrTokenRotated`, `ErrTokenExpired`, `ErrTokenMaxLifetimeExceeded`; new `Close()` idempotency + goroutine-stop test passes.
- **Phase 4:** new Mongo concurrent-rotation regression test (`useTransactions=true`) passes and would have failed pre-fix (verify this by temporarily reverting the fix and confirming the test fails).
- **Phase 5:** verify via full `go build ./...` success, then the full mechanical test suite, then a manual read-through of `README.md`'s code blocks (not auto-tested) for consistency with the new API.

Remember: if any of the above turns up something not covered in this document, add it here — in the relevant phase, using the same format — rather than fixing it silently.