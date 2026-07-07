# Add VerificationToken support to gourdiantoken

## Context

Two internal consumers — `rbac.authentication.golang.backend` (`pkg/gourdiantemptoken`) and `skipp.app.dashboard.golang.backend` (via a second, independent fork vendored into `skipp.app.shared.golang.library/gourdiantemptoken`) — each carry their own ~930-line copy of a stripped-down JWT library whose only job is short-lived, single-use, "use-case"-scoped tokens (e.g. the gap between password-check and full session issuance when 2FA is pending, or password-reset/email-verify links). A diff already shows the forks have drifted from gourdiantoken's own key-parsing refactor, so neither fork benefits from crypto fixes made here.

This plan ports that capability directly into `gourdiantoken` (currently v2.0.0) as a new, purely additive `VerificationToken` type, so it rides the same signing keys, config, repository backend, and background cleanup that Access/Refresh tokens already use — eliminating the need for a separate package per consuming repo. **Hard constraint: zero impact on existing AccessToken/RefreshToken behavior or any existing public signature.** Migrating the two consuming repos onto this is explicitly out of scope for this plan (separate repos, separate follow-up).

Two decisions were confirmed with the user up front:
- **Naming**: `VerificationToken` (not `TempToken`/`EphemeralToken`).
- **Single-use mechanism**: reuse the existing revocation infrastructure (`MarkTokenRevoke`/`IsTokenRevoked`, already generic over `TokenType`) rather than adding new `TokenRepository` interface methods. "Mark used" = revoke; "already used" = revoked. This is the DRY-maximizing choice and adds zero new repository interface surface.

A third requirement from the user: **raise the project's coverage bar to 80%** (Makefile's `COVERAGE_MIN` is currently `70`, per `Makefile:10`; the last fully-verified run per `plan.md` was 78.6%, so 80% is realistic once the new, thoroughly-tested code is added).

All file:line references below were independently re-verified by direct grep/read against the current source, not just taken from exploration — see the "verified" note per section.

## Design summary

- New `TokenType` constant `VerificationToken = "verification"` (`gourdiantoken.config.go`).
- New `VerificationTokenClaims`/`VerificationTokenResponse` structs (`gourdiantoken.claims.go`) — include `Audience`/`NotBefore`/`MaxLifetimeExpiry` (unlike the leaner reference design) specifically so the existing shared `parseAndValidateToken` → `validateTokenClaims` path (which checks the *global* `config.RequiredClaims`, default `["iss","aud","nbf","mle"]`) works completely unchanged for the new type. `MaxLifetimeExpiry` is simply set equal to `ExpiresAt` (verification tokens are never renewed, so there's no separate "absolute ceiling beyond a renewed exp" concept to model).
- New config fields on `GourdianTokenConfig`: `VerificationTokensEnabled bool` (master switch, defaults to `false` so every pre-existing config is unaffected), `VerificationAllowedUseCases []string` (empty = allow any), `VerificationDefaultExpiryDuration`, `VerificationMaxExpiryDuration time.Duration`.
- `CreateVerificationToken` deliberately takes a **per-call `ttl time.Duration`** parameter (0 = use the configured default), unlike `CreateAccessToken`/`CreateRefreshToken` which have no such parameter — this is intentional, since variable per-use-case TTL (5 min for a 2FA-pending window vs. 24h for a password-reset link) is the entire point of the source feature. Because it's a brand-new method, this has no effect on the existing fixed-duration Access/Refresh signatures.
- Three new methods on `*JWTMaker`: `CreateVerificationToken`, `VerifyVerificationToken`, `MarkVerificationTokenUsed` — exposed via a **new optional interface** `GourdianTokenMakerVerification` in `gourdiantoken.interfaces.go`, following the exact precedent already set by `GourdianTokenMakerCloser` (added separately so it doesn't break existing external implementers of `GourdianTokenMaker`, which stays untouched).
- `MarkVerificationTokenUsed` is a one-line call to the existing unexported `revokeToken(ctx, VerificationToken, token)` helper (`gourdiantoken.maker.go:868-909`). `VerifyVerificationToken` calls the existing `parseAndValidateToken` unchanged — its already-generic `IsTokenRevoked` check is what makes a second verify-after-mark-used fail, for free. No new revocation logic anywhere.
- New sentinel `ErrTokenAlreadyUsed = ErrTokenRevoked` (`gourdiantoken.errors.go`) — a plain alias, matching the existing `ErrTokenExpired = jwt.ErrTokenExpired` precedent, zero new logic.
- Single-use enforcement requires **both** `VerificationTokensEnabled: true` **and** `RevocationEnabled: true` (plus a repo) — `MarkVerificationTokenUsed` delegates to `revokeToken`, which already gates on `RevocationEnabled`. Misconfiguration surfaces as an explicit error on the mark-used call, never a silent bypass. Document this coupling.

## File-by-file changes

**`gourdiantoken.config.go`** — add `VerificationToken` const; add `ClaimUseCase = "uc"` claim-key const; add the four new `GourdianTokenConfig` fields (doc-commented like the existing Access/Refresh fields). Do not touch `NewGourdianTokenConfig` (deprecated, frozen) or `DefaultGourdianTokenConfig`'s literal (new fields stay at zero value = feature off).

**`gourdiantoken.claims.go`** — add `VerificationTokenClaims`/`VerificationTokenResponse` (fields: `ID/jti`, `Subject/sub`, `UseCase/uc`, `Issuer/iss`, `Audience/aud`, `IssuedAt/iat`, `ExpiresAt/exp`, `NotBefore/nbf`, `MaxLifetimeExpiry/mle`, `Metadata/mtd`, `TokenType/typ`). No `SessionID`/`Username`/`Roles` — no session or RBAC concept applies here; correlate via `Metadata` if needed.

**`gourdiantoken.validation.go`** (verified: `toMapClaims` type-switch, `extractCommonClaims` at line 276, `baseRequired` map at line 528, `mapToRefreshClaims` at line 467):
- `toMapClaims`: add a `case VerificationTokenClaims:` branch. Must also emit placeholder `"sid": ""` / `"usr": ""` keys — confirmed at `gourdiantoken.validation.go:553` that `extractCommonClaims` does `claims["sid"].(string)` with a bare `!ok` check, which fails on a genuinely-missing key, not just a wrong-typed one, so these keys must be physically present for `extractCommonClaims` to stay reusable as-is. Emit `"mtd"` only when `len(Metadata) > 0`.
- Add `mapToVerificationClaims`, following `mapToRefreshClaims`'s exact template: call `extractCommonClaims`, validate `"typ" == VerificationToken`, extract/validate non-empty `"uc"`, extract optional `"mtd"`, build the struct (dropping `SessionID`/`Username` from the common result).
- `baseRequired` map: add `VerificationToken: {"jti", "sub", "iat", "exp", "typ", "uc"}`.
- `validateConfig`: new block, gated entirely by `if config.VerificationTokensEnabled { ... }`, checking `VerificationDefaultExpiryDuration > 0`, `VerificationMaxExpiryDuration >= VerificationDefaultExpiryDuration` (when max is set), and no empty strings in `VerificationAllowedUseCases`. This gate is what keeps every pre-existing config (which never sets these fields) passing validation unchanged.
- New shared helper `validateUseCase(allowed []string, useCase string) error` (empty-list-means-unrestricted, mirroring the `AllowedAlgorithms` convention) — called from both `CreateVerificationToken` and `VerifyVerificationToken`, avoiding a duplicated whitelist-loop.
- New shared helper `resolveVerificationTTL(config, requested) (time.Duration, error)` — `requested <= 0` → default; `requested > max` (if max set) → **reject with an error** (matches this codebase's existing fail-loud style; no precedent here for silently clamping a caller-supplied value).

**`gourdiantoken.maker.go`**:
- `CreateVerificationToken(ctx, userID, useCase string, ttl time.Duration, metadata map[string]interface{}) (*VerificationTokenResponse, error)` — placed after `CreateRefreshToken`. Flow: ctx check → `VerificationTokensEnabled` gate → non-empty `userID` check (plain inline check, not `validateUserAndUsername`, since there's no username param here) → `validateUseCase` → `resolveVerificationTTL` → `newTokenID()` (reused) → build claims (`NotBefore = now`, `MaxLifetimeExpiry = ExpiresAt`) → `signClaims` (reused, already generic over `interface{}`) → build response.
- `VerifyVerificationToken(ctx, tokenString string) (*VerificationTokenClaims, error)` — placed after `VerifyRefreshToken`. Flow: `VerificationTokensEnabled` gate → `parseAndValidateToken(ctx, tokenString, VerificationToken)` (fully reused, unchanged) → `mapToVerificationClaims` → `validateUseCase` again (defense-in-depth against whitelist drift after issuance) → return.
- `MarkVerificationTokenUsed(ctx, token string) error` — gate, then `return maker.revokeToken(ctx, VerificationToken, token)`.
- One-line fix in `cleanupRevokedTokens` (confirmed at `gourdiantoken.maker.go:1332`): widen `[]TokenType{AccessToken, RefreshToken}` to include `VerificationToken`.

**`gourdiantoken.interfaces.go`** — add `GourdianTokenMakerVerification` optional interface (3 methods above), doc-commented with the same "why separate" rationale as `GourdianTokenMakerCloser` (lines 309-329). `GourdianTokenMaker` itself untouched.

**`gourdiantoken.errors.go`** — add `ErrTokenAlreadyUsed = ErrTokenRevoked`.

**`gourdiantoken.factories.go`** — **no changes**. All 5 factories build a generic `TokenRepository` and delegate to `NewGourdianTokenMaker`; the new capability is purely config-driven (`VerificationTokensEnabled`) on the same config struct they already accept.

**Repository implementations — verified directly, all four need the closed 2-value allow-list widened to 3:**
- `gourdiantoken.repository.inmemory.imp.go`: separate maps per type (confirmed `revokedAccess`/`revokedRefresh` fields at lines 57-58) — add a third `revokedVerification map[string]tokenEntry` field, initialize it in the constructor, add a `case VerificationToken:` to each of the three switches (lines 182, 242, 505), add it to `periodicCleanup`, add `"revoked_verification_tokens"` to `Stats()` (line 659).
- `gourdiantoken.repository.redis.imp.go`: add `revokedVerificationPrefix = "revoked:verification:"` const (alongside lines 15-16), add a `case VerificationToken:` to each of the three switches (lines 192, 260, 569), extend `Stats()` (line 739) with a third `countKeys` call.
- `gourdiantoken.repository.gorm.imp.go`: single table, `token_type varchar(20)` with **no CHECK constraint** (confirmed) — widen the `if tokenType != AccessToken && tokenType != RefreshToken` guard (confirmed at lines 258, 333, 641) to also allow `VerificationToken`; extend `Stats()` (line 747) and `CleanupAll` with a third count/call.
- `gourdiantoken.repository.mongo.imp.go`: same shape as GORM — widen the identical guard (confirmed at lines 327, 399, 718); extend `Stats()` (line 833) with a third `CountDocuments` call. No `CleanupAll` exists here (confirmed) — nothing to add.
- All four changes are pure additions to existing switch/if constructs — no existing `AccessToken`/`RefreshToken` branch is altered.

## Test plan (targeting ≥80% overall coverage)

- Bump `Makefile`'s `COVERAGE_MIN` from `70` to `80` (`Makefile:10`).
- New `token.verification_token_test.go` (named to avoid colliding with the existing `token.verification_test.go`, which covers Access/Refresh): full create→verify→mark-used→re-verify-fails lifecycle (asserting `errors.Is(err, ErrTokenAlreadyUsed)` and `ErrTokenRevoked`); TTL defaulting and max-TTL rejection; use-case whitelist enforcement at both Create and Verify (including the empty-whitelist-allows-any case, and a case where a use case valid at issuance is later removed from the whitelist); metadata roundtrip (including nil/empty); config validation errors for the new block; the feature-disabled path (`VerificationTokensEnabled: false` → all three methods error); the "single-use requires `RevocationEnabled` too" coupling.
- New `setupTestMakerWithVerification(t)` helper alongside the existing ones in `token.test.helper_test.go`.
- Extend `gourdiantoken.repository_test.go`'s existing table-driven tests (reusing `getTestRepositoryFactories()`, confirmed reusable across Memory/Redis/MongoDB/GORM) with `VerificationToken` cases: mark/is-revoked/cleanup parity per backend, plus confirming `TestMarkTokenRevoke_InvalidTokenType`-style tests still reject a genuinely bogus `TokenType` after the 2→3 widening.
- `gourdiantoken.errors_test.go`: add `TestErrTokenAlreadyUsed_ErrorsIs` alongside the existing sentinel tests.
- `config.validation_test.go`: new cases for the new `validateConfig` block.
- Optional (nice-to-have, not required for the coverage target): `BenchmarkCreateVerificationToken`/`BenchmarkVerifyVerificationToken` in `gourdiantoken.benchmark_test.go`.

## Docs/example updates (describe pattern, not exhaustive)

- `docs.go`: new "VerificationToken" subsection under "Token Types", a claims-structure entry, config-fields mention, and a short create→verify→mark-used lifecycle callout.
- `README.md`: new "Verification Tokens" subsection parallel to the existing "Access Tokens"/"Refresh Tokens" sections; new API reference entries for the three methods; optional 2FA-pending example under "Advanced Usage".
- `CHANGELOG.md`: new `## v2.1.0 (Unreleased)` section above the current `## v2.0.0` (confirmed as the current top section) — do **not** touch `plan.md`, which tracks the already-completed, unrelated v2.0.0 migration effort.
- `example/example.go`: new `runVerificationTokenTests` function following the existing `run*Tests(ctx, tokenMaker) []TestResult` pattern, type-asserting the optional interface the way a real caller would.

## Zero-impact verification (hard requirement)

- `TokenRepository` and `GourdianTokenMaker` interfaces: unchanged.
- Every existing public function/method signature (`CreateAccessToken`, `CreateRefreshToken`, `VerifyAccessToken`, `VerifyRefreshToken`, `RevokeAccessToken`, `RevokeRefreshToken`, `RotateRefreshToken`, all 5 factories, both config constructors): unchanged.
- `validateConfig`, `toMapClaims`, `validateTokenClaims`, `parseAndValidateToken`, `revokeToken`, `signClaims`: additively widened (new case/map-entry) only — every existing `AccessToken`/`RefreshToken` branch is left byte-for-byte identical.
- `DefaultGourdianTokenConfig()`'s literal is untouched; new fields default to zero values, so `VerificationTokensEnabled` is `false` for every config that predates this change.

## How to verify end-to-end after implementation

1. `make fmt && make vet && make staticcheck` — no regressions in existing files.
2. `go test -run '.*/Memory' ./...` for fast iteration (no live services needed, per this repo's existing convention).
3. Full backend pass once Redis/MongoDB/PostgreSQL are up: `make test` (includes `-bench=. -benchmem`) and `make race`.
4. `make coverage-check` — must pass at the new 80% gate.
5. Manually exercise the new optional interface via `example/example.go`'s new `runVerificationTokenTests`, confirming: token created → verified (correct claims) → marked used → re-verify fails with `ErrTokenAlreadyUsed`.
6. Confirm zero diff in behavior for existing Access/Refresh flows by re-running the full existing test suite unmodified (aside from the additive cases above) and confirming no existing test needed to change.

## Post-approval follow-up (not part of the coding work, noted so it isn't lost)

- The user asked for this plan to be saved at `/Users/varun/Dev/github/gourdiantoken/docs/plan` (an existing empty directory). Plan-mode restricts file writes to this designated plan file during planning; immediately after approval, copy this finalized plan into `docs/plan/verification-token-upgrade-plan.md`.
- Migrating `rbac.authentication.golang.backend` and the shared dashboard library off their forked `gourdiantemptoken` packages onto this new capability is a deliberate follow-up, out of scope here.
