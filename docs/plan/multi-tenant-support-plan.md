# gourdiantoken: Multi-tenant claim support + interface consolidation + repository standardization

> Source of truth for this initiative. Mirrored from
> `/Users/varun/.claude/plans/generic-twirling-waterfall.md`, kept here so it
> travels with the repo, matching the sibling repos' `docs/plan/<repo>-plan.md`
> convention (see `ECOSYSTEM_PLAN.md` in this repo for the tracker/stage-by-stage
> format this plan mirrors). **Pause after each stage for review before
> starting the next.**

## Context

The ERP backend (a sibling project) is adopting true multi-tenant SaaS with
schema-per-tenant Postgres isolation. Every authenticated request needs
`tenant_id` resolved immediately after JWT verification, before any handler
logic runs — a client-supplied tenant ID (header/query param/body) must never
be trusted, since a malicious or buggy client could simply claim a different
tenant. The only safe source is the verified JWT itself.

`gourdiantoken` — the JWT library already used by dashboard backend and slated
for ERP — has no concept of a tenant claim today, and its `AccessTokenClaims`/
`RefreshTokenClaims` structs are fixed, hand-mapped (no reflection/generics),
so this isn't a config change, it's a real code change to the library.

While making that change, two other things surfaced during codebase research
that are worth fixing in the same pass, now that the repo owner has confirmed
**zero consumers exist anywhere** (confirmed via grep across every sibling
gourdian25 repo — none actually import gourdiantoken, only mention it in
prose) and breaking changes are explicitly authorized:

1. `GourdianTokenMaker` is artificially split into three interfaces
   (`GourdianTokenMaker`/`GourdianTokenMakerCloser`/`GourdianTokenMakerVerification`)
   purely to avoid breaking hypothetical external implementers — a constraint
   that no longer applies. `*JWTMaker` already implements all three
   unconditionally.
2. The four `TokenRepository` backends (Memory/Redis/Postgres/MongoDB) have
   accumulated real inconsistencies: divergent `Close()`/`Stats()` signatures,
   a Postgres-only `CleanupAll`, and a genuine bug — `MarkTokenRotatedAtomic`
   rejects re-marking an already-*expired* rotation entry on Postgres/MongoDB
   only (Memory/Redis handle it correctly), previously documented as a known
   issue rather than fixed.

Decisions already confirmed with the repo owner (do not re-litigate):
tenant claim is **opt-in** via a config flag (not always-mandatory, so the
library stays usable by any future single-tenant consumer); tenant-scoped
**bulk revocation** (for tenant offboarding/suspension) ships **in this same
pass**, not deferred; the **repository inconsistencies get fixed now**, as
their own stage; module stays on **`/v2`**, version bumps to **`v2.3.0`**
(matching the exact precedent this repo's own `v2.2.0` CHANGELOG entry set
for its prior breaking release).

This plan was produced via: two parallel Explore-agent research passes over
the full `gourdiantoken` source (claims/maker/validation/interfaces, and
separately the four repository backends/factories), a Plan-agent design pass
that re-verified every finding against source and resolved the open design
questions into concrete decisions, and a final manual spot-check of the two
riskiest claims (the `RotateRefreshToken` tenant-propagation call site and
the `parseAndValidateToken` claims-map flow) — both confirmed exactly as
described below.

## Tracker

| Stage | Scope | Status |
|---|---|---|
| Stage 1 | Tenant claim foundation | ✅ Done |
| Stage 2 | Interface consolidation | ✅ Done |
| Stage 3 | Tenant-scoped bulk revocation | ✅ Done |
| Stage 4 | Repository backend standardization | ✅ Done |
| Stage 5 | Docs / CHANGELOG / version bump / example.go | ✅ Done |
| Stage 6 | Full validation pass | Not started |

**Note:** after Stage 3, `docs/plan/key-material-config-plan.md` (in-memory
`PrivateKeyPEM`/`PublicKeyPEM` config, replacing `PrivateKeyPath`/
`PublicKeyPath`) was inserted and executed **before** Stage 4 below, per
explicit instruction — an unrelated-to-multi-tenancy breaking change that
surfaced mid-flight but targets the same `v2.3.0` release. Both of that
plan's stages are now done (core change + docs/README/CHANGELOG/example.go
pass), including a `## v2.3.0` section it created in both `README.md`
("Upgrading to v2.3.0") and `CHANGELOG.md` — Stage 5 below should extend
those same sections with its own entries rather than creating new ones.
Stage 4 is unblocked; resume it next.

## Design decisions locked in for the executor

1. **`GourdianTokenConfig.MultiTenantEnabled bool`** — new opt-in flag.
2. **`CreateAccessToken`/`CreateRefreshToken` gain `tenantID string` as a new
   *trailing* parameter** (after `sessionID`), not inserted mid-list —
   appending is strictly additive and avoids risk of transposing adjacent
   string args across ~245 existing call sites in tests + `example/example.go`.
3. **Fail loud both directions**: `MultiTenantEnabled=true` + empty
   `tenantID` → error; `MultiTenantEnabled=false` + non-empty `tenantID` →
   error. Silently dropping a caller-supplied tenant ID is exactly the kind
   of footgun this whole change exists to prevent.
4. **Verification tokens get zero structural changes.** `VerificationTokenClaims`
   already has a free-form `Metadata map[string]interface{}` field — tenant
   scoping for verification tokens (e.g. a tenant-scoped password-reset
   token) is a documented *convention* (put `"tenant_id"` in `Metadata`), not
   a new struct field. This deliberately avoids repeating an existing wart in
   `toMapClaims`'s verification branch, which today fakes empty `usr`/`sid`
   placeholders purely so shared claim-extraction code keeps working —
   forcing a field onto a token type that doesn't structurally have it.
5. **Bulk tenant revocation uses a per-tenant revocation epoch**, not
   enumeration. Rejected alternative: "revoke every token belonging to
   tenant X" by scanning/marking individual token rows — this would require
   building and maintaining a new "tokens by tenant" index on all 4 backends,
   and fundamentally can't work for access tokens, which this library never
   persists a record of unless individually revoked. An epoch
   ("any token issued for tenant X at-or-before time T is dead") needs no
   enumeration and correctly covers tokens the repository has never seen —
   one indexed lookup per `Verify*` call.
6. **Epoch TTL = `max(AccessExpiryDuration, RefreshExpiryDuration)`**, not
   `MaxLifetimeExpiry`. Past that window every pre-epoch token has already
   failed its own native `exp` check regardless of the epoch record, making
   the record redundant — so that's the correct, minimal TTL. Verified this
   holds even across `RotateRefreshToken` chains: rotation always calls
   `VerifyRefreshToken` on the *old* token first, which the epoch check
   already gates — there's no path to "refresh past" a tenant revocation.
7. **`Stats`/`CleanupAll` join the `TokenRepository` interface; `Close` does
   not.** Postgres's `Close()` has real pool-ownership caveats (its own doc
   comment already warns the caller may share that pool elsewhere) that make
   it a poor fit for a uniform interface method — `Stats`/`CleanupAll` have
   no such subtlety.
8. **`NewGourdianTokenMakerWithMongo` drops its oddball `transactionsEnabled bool`**
   parameter (the only factory with this shape inconsistency), hardcoding
   `true` per its own doc comment ("enabled by default for consistency").
   Callers needing `false` (standalone dev Mongo) already have
   `NewMongoTokenRepository(db, false)` + `NewGourdianTokenMaker(...)` directly.
9. **New JWT claim key: `"tid"`** — free to use, matches the existing 3-letter
   claim-key convention (`jti`/`sub`/`sid`/`usr`/`iss`/`aud`/`rls`/`iat`/
   `exp`/`nbf`/`mle`/`typ`/`uc`).
10. **Version bump: stay on `/v2`, bump to `v2.3.0`** — exact precedent set by
    this repo's own `v2.2.0` CHANGELOG entry for its prior breaking release.

## Stage 1 — Tenant claim foundation

No other stage can start before this lands. `CreateAccessToken`/
`CreateRefreshToken` are called **245 times** across 13 test files plus
`example/example.go` — the largest mechanical diff in the whole plan; budget
for a scripted rewrite that still needs a human skim per hunk (two adjacent
string args are easy to transpose blindly).

**Files touched:**

- **`gourdiantoken.config.go`** — add `MultiTenantEnabled bool` to
  `GourdianTokenConfig` (doc-comment style matching `VerificationTokensEnabled`).
  No `validateConfig` change needed (no dependent sub-fields). No
  `NewGourdianTokenConfig` change (already frozen/deprecated, already
  doesn't express `VerificationTokensEnabled` either — same precedent applies).
- **`gourdiantoken.claims.go`** — add `TenantID string \`json:"tid"\`` to
  `AccessTokenClaims`, `RefreshTokenClaims`, `AccessTokenResponse`,
  `RefreshTokenResponse`. `VerificationTokenClaims`/`VerificationTokenResponse`
  untouched.
- **`gourdiantoken.errors.go`** — add `ErrTenantIDRequired`,
  `ErrTenantIDNotAllowed`.
- **`gourdiantoken.validation.go`** — new `validateTenantID(multiTenantEnabled bool, tenantID string) error`
  helper (mirrors `validateUseCase`'s shape). `toMapClaims`: Access/Refresh
  branches gain `if v.TenantID != "" { mapClaims["tid"] = v.TenantID }`
  (same omitempty pattern as `nbf`/`mle`); **verification branch untouched**.
  `mapToAccessClaims`/`mapToRefreshClaims`: each independently extracts an
  optional `"tid"` (mirrors `extractCommonClaims`'s existing optional-`iss`
  handling). `extractCommonClaims`/`commonClaims`/`validateTokenClaims`'s
  `baseRequired` map **untouched** — `tid` must stay opt-in per-config, not
  unconditionally required, or every existing single-tenant config breaks.
- **`gourdiantoken.maker.go`** —
  `CreateAccessToken(ctx, userID, username string, roles []string, sessionID, tenantID string)`,
  `CreateRefreshToken(ctx, userID, username, sessionID, tenantID string)`:
  call `validateTenantID` right after the existing `validateUserAndUsername`
  check; set `claims.TenantID`/`response.TenantID`.
  `parseAndValidateToken` (confirmed at line 718, returns raw `jwt.MapClaims`
  — the right insertion point since it runs before token-type-specific
  mapping): after the existing `validateTokenClaims` call succeeds, add a
  guarded `tid`-required check for `AccessToken`/`RefreshToken` only
  (never `VerificationToken`) when `MultiTenantEnabled`.
  **`RotateRefreshToken` (confirmed at line 1334, the internal
  `CreateRefreshToken` call is at line 1359)**: `maker.CreateRefreshToken(ctx, claims.Subject, claims.Username, claims.SessionID)`
  **must** become `...claims.SessionID, claims.TenantID)` — verified this is
  the exact call site; missing this silently drops the tenant claim on every
  refresh-token rotation. Flag prominently to whoever implements this stage.
- **`gourdiantoken.interfaces.go`** — update `GourdianTokenMaker.CreateAccessToken`/
  `CreateRefreshToken` signatures to match.
- **`CLAUDE.md`** — update the claims.go/config.go bullets.

**New/changed public API:**
```go
type GourdianTokenConfig struct { /* ... */ MultiTenantEnabled bool }
type AccessTokenClaims struct { /* ... */ TenantID string `json:"tid"` }   // + RefreshTokenClaims, both *Response structs
var ErrTenantIDRequired = errors.New("tenant ID is required when MultiTenantEnabled is true")
var ErrTenantIDNotAllowed = errors.New("tenant ID must be empty when MultiTenantEnabled is false")
CreateAccessToken(ctx, userID, username string, roles []string, sessionID, tenantID string) (*AccessTokenResponse, error)
CreateRefreshToken(ctx, userID, username, sessionID, tenantID string) (*RefreshTokenResponse, error)
```

**Test-file impact:** mechanical `tenantID` argument added at every
`CreateAccessToken`/`CreateRefreshToken` call site across `concurrency_test.go`,
`cryptographic_test.go`, `edge.case_test.go`, `gourdiantoken.benchmark_test.go`,
`gourdiantoken.errors_test.go`, `gourdiantoken.factories_test.go`,
`gourdiantoken.maker_test.go`, `integration_test.go`,
`revocation.rotation_test.go`, `token.creation_test.go`,
`token.revocation_test.go`, `token.rotate_test.go`, `token.verification_test.go`,
`example/example.go`. New cases: sentinel `errors.Is` tests in
`gourdiantoken.errors_test.go`; enabled/disabled × empty/non-empty matrix and
a full create→verify round-trip in `token.creation_test.go`; a rotation
propagates `TenantID` regression test in `token.rotate_test.go` (directly
covering the bug above); `tid`-present/absent/wrong-type branches in
`gourdiantoken.validation_test.go`, including confirming `VerificationTokenClaims`
never emits `tid`; a `MultiTenantEnabled=true` passes `validateConfig` case in
`config.validation_test.go`.

**Dependencies:** none — foundation stage.

**Verification:** `go build ./...`, `go vet ./...`, `make race`,
`make coverage-check`; run `go test -run TestCreate ./...` and
`go test -run TestRotate ./...` in isolation first to catch argument-order
mistakes before the full suite.

### Stage 1 completion notes

Landed on `dev#manish#feat_support_for_tenant_id`. The struct/config/error/
interface/claim-mapping changes described above (commit `7994564`) were
already in place when this stage was picked back up; what was missing and
got finished in this pass:

- **The verify-side `tid`-required check was never actually added** —
  `validateTenantID` only guards `CreateAccessToken`/`CreateRefreshToken`
  (create side). `mapToAccessClaims`/`mapToRefreshClaims`'s own doc comments
  already claimed "enforced upstream in `parseAndValidateToken`", but that
  check didn't exist, so a pre-existing or hand-crafted token missing `tid`
  verified successfully even with `MultiTenantEnabled=true`. Added a guarded
  check in `parseAndValidateToken` (after the existing `validateTokenClaims`
  call, `AccessToken`/`RefreshToken` only, never `VerificationToken`) that
  returns `ErrTenantIDRequired` when `tid` is absent/empty. Covered by
  `TestMultiTenant_TenantIDValidation/MultiTenantEnabled=true/token_missing_tid_claim_fails_verification`.
- **`example/example.go` and all ~294 existing `CreateAccessToken`/
  `CreateRefreshToken` call sites** (across every test file listed above)
  needed the new trailing `tenantID` argument — this was the "largest
  mechanical diff" the stage description warned about. Done via a small
  one-off `go/ast`-based codemod (parse each file, find `CallExpr`s with the
  old 5-arg/4-arg arity, insert `, ""` right after the last argument's `End()`
  position rather than before `Rparen`, to stay correct across both
  single-line and multi-line/trailing-comma call styles) rather than by hand
  or via a blind regex — verified gofmt-clean and diff-minimal on a sample
  file before running it across the rest. `go build ./...`/`go vet ./...`
  went from failing (on `example`) to clean.
- Fixed 8 stale doc-comment example snippets in `gourdiantoken.maker.go`
  still showing the pre-tenantID call signatures (`CreateAccessToken`'s and
  `CreateRefreshToken`'s own doc comments, plus the examples inside
  `VerifyRefreshToken`'s and `RotateRefreshToken`'s doc comments).
  `gourdiantoken.interfaces.go`'s doc-comment examples were already correct
  from the original commit.
- Added the "New cases" tests the stage called for: sentinel `errors.Is`
  tests (`TestErrTenantIDRequired_ErrorsIs`/`TestErrTenantIDNotAllowed_ErrorsIs`
  in `gourdiantoken.errors_test.go`), the enabled/disabled × empty/non-empty
  matrix plus a full create→verify round trip
  (`TestMultiTenant_TenantIDValidation` in `token.creation_test.go`), the
  rotation tenant-propagation regression test
  (`TestRotateRefreshToken_PropagatesTenantID` in `token.rotate_test.go` —
  confirmed `RotateRefreshToken`'s `claims.TenantID` forwarding, already
  correct in the original commit, actually holds end-to-end), the `tid`
  present/absent/wrong-type branch tests plus the "verification tokens never
  emit tid" check (`TestTenantIDClaim_MapConversions` in
  `gourdiantoken.validation_test.go`), and the `MultiTenantEnabled=true`
  `validateConfig` case (in `TestValidateConfig_Symmetric`,
  `config.validation_test.go`).
- Full verification suite green against all 4 live backends (started via
  `make docker-up`, none were running beforehand): `go build ./...`,
  `go vet ./...`, `gofmt -l .` (clean), `go test -count=1 -timeout=5m -cover .`
  (95.4% coverage), `make race`, `make coverage-check` (95.4%, meets the 95%
  gate), and `go run ./example` end-to-end (46/46 scenarios × all 4 backends
  + stateless mode, 230/230 passed).
- Note for whoever runs the full suite unfiltered in an environment with no
  live services: the MongoDB repository factory's `client.Ping` call in
  `token.test.helper_test.go` has no context timeout, so with no Mongo
  reachable it burns the driver's default 30s server-selection timeout
  *per repository-backed test function* rather than skipping fast — enough
  of those add up to blow past a 5-minute suite timeout even though Redis/
  Postgres skip quickly. Not a regression from this stage; pre-existing.
  Easiest fix if it comes up again: `make docker-up` first (as done here),
  or scope runs to `-run '.../Memory'`-style subtests per CLAUDE.md's
  existing guidance.

## Stage 2 — Interface consolidation

Smaller than it looks: `*JWTMaker` already implements everything, so merging
the interface *definition* requires no factory-function body changes — only
callers holding a `GourdianTokenMaker`-typed variable stop needing a type
assertion. Confirmed via grep that this type-assertion pattern appears in
exactly one test file (`gourdiantoken.close_test.go`) plus `example/example.go`
plus `README.md` — every other test obtains a concrete `*JWTMaker` directly
and is unaffected.

**Files touched:**

- **`gourdiantoken.interfaces.go`** — merge `GourdianTokenMakerCloser` and
  `GourdianTokenMakerVerification`'s method sets directly into
  `GourdianTokenMaker`; delete both as separate declarations (no back-compat
  alias). Resulting interface: `CreateAccessToken`, `CreateRefreshToken`,
  `VerifyAccessToken`, `VerifyRefreshToken`, `RevokeAccessToken`,
  `RevokeRefreshToken`, `RotateRefreshToken`, `Close() error`,
  `CreateVerificationToken`, `VerifyVerificationToken`,
  `MarkVerificationTokenUsed`.
- **`gourdiantoken.close_test.go`** — replace the
  `closer, ok := maker.(GourdianTokenMakerCloser)` type-assertion dance with
  a direct `maker.Close()` call in both `TestClose_Idempotent` and
  `TestClose_NoOpWhenRotationAndRevocationDisabled`.
- **`example/example.go`** — `runVerificationTokenTests` (~line 216-226):
  drop the `tokenMaker.(gourdiantoken.GourdianTokenMakerVerification)`
  assertion and its "not implemented (skipped)" fallback; call the methods
  directly.
- **`docs.go`** — rewrite the three references to the split interfaces
  (~lines 38, 147, 218) to describe the single merged interface.
- **`CLAUDE.md`** — same fix for the interfaces.go and maker.go bullets.
- **`README.md`** — deferred to Stage 5 with the rest of the prose-heavy doc
  pass, since it's better updated once the full API surface is final.

**New/changed public API:** `GourdianTokenMakerCloser` and
`GourdianTokenMakerVerification` removed; their methods now live directly on
`GourdianTokenMaker`.

**Test-file impact:** the two sites in `gourdiantoken.close_test.go` above;
no other test file requires changes.

**Dependencies:** none structurally on Stage 1, but sequenced after it to
avoid two rounds of churn in the same interface file.

**Verification:** `go build ./...`, `go vet ./...`, `make race`,
`make coverage-check`; grep the repo post-change for
`GourdianTokenMakerCloser`/`GourdianTokenMakerVerification` to confirm zero
references remain outside `CHANGELOG.md`'s historical entries.

### Stage 2 completion notes

- `GourdianTokenMakerCloser` and `GourdianTokenMakerVerification` deleted as
  separate declarations; their methods (`Close`, `CreateVerificationToken`,
  `VerifyVerificationToken`, `MarkVerificationTokenUsed`) now live directly
  on `GourdianTokenMaker`, inserted right after `RotateRefreshToken` to match
  the method order specified above. No back-compat alias, per the plan.
- `gourdiantoken.close_test.go`'s two type-assertion sites
  (`TestClose_Idempotent`, `TestClose_NoOpWhenRotationAndRevocationDisabled`)
  replaced with direct `maker.Close()` calls.
- `example/example.go`'s `runVerificationTokenTests` no longer type-asserts
  for `GourdianTokenMakerVerification` (the "not implemented (skipped)"
  fallback path is gone — it's always implemented now); calls
  `tokenMaker.CreateVerificationToken`/`VerifyVerificationToken`/
  `MarkVerificationTokenUsed` directly. The plan's premise that no
  `GourdianTokenMakerCloser` assertion existed in `example/example.go` was
  confirmed by grep — only the Verification one needed fixing there.
- `docs.go`'s three references (package doc's token-types section, the
  thread-safety section's "concrete implementation" phrasing, and the
  common-mistakes list's Close() bullet) rewritten to describe the single
  merged interface.
- Also fixed one stale reference the plan didn't call out explicitly:
  `gourdiantoken.config.go`'s `VerificationTokensEnabled` doc comment named
  "the GourdianTokenMakerVerification optional interface" — updated since it
  no longer exists as a separate type.
- Post-change repo-wide grep for `GourdianTokenMakerCloser`/
  `GourdianTokenMakerVerification`: zero hits in any `.go` file. Remaining
  hits are `CLAUDE.md` (updated in this pass), `README.md` (left as-is,
  deferred to Stage 5 per the plan), and this plan file's own prose
  describing the change.
- Full verification green: `go build ./...`, `go vet ./...`, `gofmt -l .`
  clean, full suite against all 4 live backends (95.4% coverage), `make
  race`, `make coverage-check` (95.4%), `go run ./example` end-to-end
  (230/230 passed, verification-token scenarios included).

## Stage 3 — Tenant-scoped bulk revocation

Depends on Stage 1 (the `tid` claim must exist) and Stage 2 (so the new
`RevokeTenant` maker method lands directly in the final merged interface).

**Files touched:**

- **`gourdiantoken.interfaces.go`** — `TokenRepository` gains
  `RevokeTenant(ctx, tenantID string, ttl time.Duration) error`,
  `GetTenantRevocationEpoch(ctx, tenantID string) (time.Time, error)`
  (zero time = none/expired), `CleanupExpiredTenantRevocations(ctx) error`.
  `GourdianTokenMaker` gains `RevokeTenant(ctx, tenantID string) error`.
- **`gourdiantoken.errors.go`** — add `ErrMultiTenantDisabled`, `ErrTenantRevoked`.
- **`gourdiantoken.maker.go`** — new `JWTMaker.RevokeTenant`: validates
  `MultiTenantEnabled`/non-empty tenant/`RevocationEnabled`+repo present,
  computes `ttl := max(AccessExpiryDuration, RefreshExpiryDuration)`, calls
  `tokenRepo.RevokeTenant`. `parseAndValidateToken`: after the Stage 1
  tid-required block, add the epoch check (Access/Refresh only, only if a
  repo is configured) — fetch the epoch, compare against the token's `iat`,
  reject if `iat` is at-or-before the epoch. `cleanupRotatedTokens`/
  `cleanupRevokedTokens`: add a guarded call to
  `CleanupExpiredTenantRevocations` on the existing cleanup tick.
- **`gourdiantoken.repository.inmemory.imp.go`** — new
  `tenantRevocations map[string]tenantRevocation` (unhashed — tenant IDs
  aren't secrets the way tokens are); 3 new methods mirroring the existing
  rotated-token methods' shape; `Stats()` gains a `tenant_revocations` count.
- **`gourdiantoken.repository.redis.imp.go`** — new
  `tenantRevokedPrefix = "gourdiantoken:tenant_revoked:"`; `RevokeTenant` via
  `SET ... EX ttl` (existing `minRedisTTL` floor applies);
  `GetTenantRevocationEpoch` via `GET`+parse (`redis.Nil` → zero time);
  `CleanupExpiredTenantRevocations` reuses the existing generic
  `cleanupExpiredKeys` helper; `Stats()` gains a count via the existing
  `countKeys` helper.
- **`internal/postgresdb/schema.sql`** — new table
  `gourdiantoken_tenant_revocations (tenant_id VARCHAR(255) PRIMARY KEY, revoked_at TIMESTAMPTZ NOT NULL, expires_at TIMESTAMPTZ NOT NULL)`
  + index on `expires_at`.
- **`internal/postgresdb/queries/tokens.sql`** — new `UpsertTenantRevocation`,
  `GetTenantRevocationEpoch`, `DeleteExpiredTenantRevocations` queries; run
  `sqlc generate` afterward (never hand-edit the generated output).
- **`gourdiantoken.repository.postgres.imp.go`** — 3 new methods wired to the
  above (`pgx.ErrNoRows` → zero time); `Stats()` gains a count; `CleanupAll`
  extended to also call the new cleanup (this is the concrete reason
  Stage 4 depends on this stage, not the other way around).
- **`gourdiantoken.repository.mongo.imp.go`** — new collection
  `gourdiantoken_tenant_revocations` (unique index on `tenant_id` + TTL index
  on `expires_at`, matching the existing dual-index pattern); 3 new methods
  (`RevokeTenant` via `ReplaceOne` upsert, matching `MarkTokenRevoke`'s
  pattern); `Stats()` gains a count.
- **`CLAUDE.md`** — update the `TokenRepository` method-count bullet.

**New/changed public API:**
```go
type TokenRepository interface { /* + */
    RevokeTenant(ctx context.Context, tenantID string, ttl time.Duration) error
    GetTenantRevocationEpoch(ctx context.Context, tenantID string) (time.Time, error)
    CleanupExpiredTenantRevocations(ctx context.Context) error
}
type GourdianTokenMaker interface { /* + */ RevokeTenant(ctx context.Context, tenantID string) error }
var ErrMultiTenantDisabled = errors.New("multi-tenant support is not enabled")
var ErrTenantRevoked = errors.New("tenant has been revoked")
```

**Test-file impact:** `gourdiantoken.repository_test.go` gains cross-backend
table-driven tests (all 4 backends via `getTestRepositoryFactories()`) for
revoke/epoch/cleanup, matching the density of the existing
`TestMarkTokenRevoke_*` group. `gourdiantoken.maker_test.go`/
`token.revocation_test.go` gain `JWTMaker.RevokeTenant` precondition-failure
tests plus the end-to-end story (pre-epoch token fails verify, post-epoch
token succeeds, pre-epoch refresh token can't be rotated).
`gourdiantoken.errors_test.go` gains the two new sentinel tests.
`integration_test.go` gains a realistic tenant-offboarding scenario.
`gourdiantoken.repository.coverage_test.go` likely needs new fault-injection
cases for the 95% coverage gate.

**Dependencies:** hard dependency on Stage 1; sequenced after Stage 2.

**Verification:** `make race`, `make coverage-check`, plus a manual run
against all 4 live backends (`make docker-up` first) since this touches
schema/index/collection creation on 3 of them.

### Stage 3 completion notes

Implemented exactly as designed above — `RevokeTenant`/`GetTenantRevocationEpoch`/
`CleanupExpiredTenantRevocations` on `TokenRepository` and `RevokeTenant` on
`GourdianTokenMaker`, `ErrMultiTenantDisabled`/`ErrTenantRevoked`, the epoch check
in `parseAndValidateToken` right after the Stage 1 tid-required block, the
`max(AccessExpiryDuration, RefreshExpiryDuration)` TTL, and per-backend storage
(unhashed tenant-ID key, revocation timestamp as the value — not a bare marker,
since the epoch itself is the payload). A few things worth flagging for whoever
touches this next:

- **A design detail not spelled out above turned out to matter**: since a JWT's
  `iat` is second-granular (`toMapClaims` calls `.Unix()`) but the stored epoch
  can carry sub-second precision on Memory/Postgres/MongoDB (Redis stores it as a
  plain Unix-second string, so it's the one backend that's naturally
  second-granular too), a token minted within the same wall-clock second as the
  `RevokeTenant` call can land on either side of the `iat <= epoch` boundary
  somewhat arbitrarily. This isn't a bug — the whole system is already
  second-granular via `iat` — but every test that needed to demonstrate "a token
  issued after the epoch succeeds" had to sleep past the next whole second
  first (`TestRevokeTenant_EndToEndEpoch`, `TestRevokeTenant_OverwritesPreviousEpoch`).
  Document this ~1-second fuzziness if it ever reaches user-facing docs
  (Stage 5's docs.go/README pass).
- **Test-infra gap, not a code bug**: `token.test.helper_test.go`'s Postgres/
  MongoDB factories truncate/drop `gourdiantoken_revoked_tokens`/
  `gourdiantoken_rotated_tokens` between tests but, before this stage, had no
  equivalent for the new `gourdiantoken_tenant_revocations`
  table/collection — caught immediately by `TestRepositoryStats_AllBackends`
  failing with leftover counts from earlier tests once live services were
  actually exercised (`make docker-up` first, since Docker wasn't running when
  this stage started — MongoDB's `client.Ping` in that same helper has no
  context timeout, so running the suite unfiltered with no live services
  burns the driver's ~30s default server-selection timeout per repository-backed
  test rather than skipping fast; harmless once services are up, worth knowing
  if it happens again). Fixed by adding the truncate/drop to both factories.
- **Coverage**: initially dropped to 94.0% after this stage's first pass
  (new repository/maker branches, mostly error-wrapping paths on all three
  live backends, uncovered). Brought back up to 95.8% — actually above the
  pre-Stage-3 baseline of 95.4% — via fault-injection tests following each
  backend's existing convention exactly: Redis's closed-client pattern
  (`TestRedisRepository_OperationsAfterClientClosed`) plus a raw-client-poke
  test for the malformed-epoch-value branch; Postgres's closed-pool pattern
  (`TestPostgresRepository_OperationsAfterPoolClosed`) plus two new
  drop-only-the-tenant-revocations-table tests mirroring the existing
  rotated-tokens ones, since `CountTenantRevocations`/
  `CleanupExpiredTenantRevocations` are last in `Stats`/`CleanupAll`'s call
  sequence and a blanket pool-close only ever reaches the *first* failing call;
  Mongo's disconnected-client pattern for the three standalone tenant methods
  (Mongo's `Stats` has the same last-in-sequence problem as Postgres's, but
  unlike Postgres, MongoDB doesn't error on an empty/missing collection for
  `CountDocuments`, so there's no equivalent "drop just one collection" trick —
  that one specific branch was left as an accepted, pre-existing-pattern gap,
  consistent with the other four count calls in that same function already
  being equally unreachable this way before this stage). Also added
  `erroringRepo.getTenantRevocationEpochErr` for `parseAndValidateToken`'s new
  branch, and extended `cleanupCountingRepo` plus two new
  `gourdiantoken.close_test.go` tests for the tenant-cleanup branches in both
  background goroutines — one of which (the `structuredLogger` path) turned out
  to also cover a **pre-existing** gap in the non-tenant rotated/revoked
  `structuredLogger` branches that had no test at all before this stage,
  since `recordingLogger` (`logger_test.go`) wasn't previously exercised
  against the cleanup goroutines. Picked up a small drive-by fix while at it:
  `recordingLogger` gained a mutex, since the two cleanup goroutines can call
  its `Error` method concurrently and `go test -race` would otherwise flag it.
- Full verification green against all 4 live backends: `go build ./...`,
  `go vet ./...`, `gofmt -l .` clean, `golangci-lint run` (0 issues),
  `go test -count=1 -timeout=5m -cover .` (95.8%), `make race`,
  `make coverage-check` (95.8%), `go run ./example` end-to-end (230/230
  passed).

## Stage 4 — Repository backend standardization

**Files touched:**

- **`gourdiantoken.interfaces.go`** — `TokenRepository` gains
  `Stats(ctx context.Context) (map[string]interface{}, error)` and
  `CleanupAll(ctx context.Context) error`. `Close` deliberately **not**
  added (Postgres pool-ownership caveat, see decision #7).
- **`gourdiantoken.repository.inmemory.imp.go`** — `Stats() map[string]int`
  → `Stats(ctx) (map[string]interface{}, error)`, normalizing values to
  `int64` to match the other three backends' count types. New
  `CleanupAll(ctx) error` (same shape as Postgres's existing one).
- **`gourdiantoken.repository.redis.imp.go`** — new `CleanupAll(ctx) error`.
- **`gourdiantoken.repository.mongo.imp.go`** —
  `Close(ctx context.Context) error` → `Close() error` (confirmed a literal
  no-op internally — dropping the unused parameter is free). New
  `CleanupAll(ctx) error`.
- **`gourdiantoken.repository.postgres.imp.go`** — extend `CleanupAll` to
  also call `CleanupExpiredTenantRevocations`. **Fix the
  `MarkTokenRotatedAtomic` bug**: change `InsertRotatedTokenIfNotExists`
  (in `internal/postgresdb/queries/tokens.sql`) from unconditional
  `ON CONFLICT DO NOTHING` to a conditional
  `ON CONFLICT (token_hash) DO UPDATE ... WHERE gourdiantoken_rotated_tokens.expires_at <= EXCLUDED.created_at`
  — Postgres reports 0 affected rows when the `WHERE` is false, giving
  exactly the "conflict and not expired" semantics the existing Go-side
  `rowsAffected > 0` check already expects, with no Go code change needed.
  Regenerate via `sqlc generate`.
- **`gourdiantoken.repository.mongo.imp.go`** (second fix) — same bug: replace
  `MarkTokenRotatedAtomic`'s blind `InsertOne` with a conditional upsert
  (`UpdateOne` with `upsert=true`, filtered on `expires_at <= now`) so a
  not-yet-expired existing document collides on the unique index
  (`E11000`, caught via the existing `mongo.IsDuplicateKeyError` check →
  `false, nil`) while an expired one gets updated in place.
- **`gourdiantoken.factories.go`** —
  `NewGourdianTokenMakerWithMongo` drops `transactionsEnabled bool`,
  internally calling `NewMongoTokenRepository(mongoDB, true)`.
- **`CLAUDE.md`** — update the `Close()`/repository-methods bullets.

**New/changed public API:**
```go
type TokenRepository interface { /* + */
    Stats(ctx context.Context) (map[string]interface{}, error)
    CleanupAll(ctx context.Context) error
}
func (m *MemoryTokenRepository) Stats(ctx context.Context) (map[string]interface{}, error) // was: Stats() map[string]int
func (r *MongoTokenRepository) Close() error                                                // was: Close(ctx context.Context) error
func NewGourdianTokenMakerWithMongo(ctx context.Context, config GourdianTokenConfig, mongoDB *mongo.Database, opts ...Option) (GourdianTokenMaker, error) // dropped transactionsEnabled
```

**Test-file impact:** `concurrency_test.go` (`memRepo.Stats()` call sites,
~lines 888/894) gain error handling. `gourdiantoken.repository_test.go`:
collapse the Memory-special-cased `Stats` tests now that all 4 backends
share one signature; generalize `TestPostgresRepository_CleanupAll` into a
table-driven test across all 4 backends. `gourdiantoken.repository.coverage_test.go`'s
`TestMarkTokenRotatedAtomic_ReMarksAfterExpiry` — currently hardcoded to
`["Memory", "Redis"]` with a comment documenting the known bug — changes to
run against all 4 backends, and the doc comment flips from "documents a
known inconsistency" to "confirms all 4 backends now agree."
`gourdiantoken.factories_test.go` and `example/example.go` drop the Mongo
factory's bool arg.

**Dependencies:** hard dependency on Stage 3 (`CleanupAll` must call
`CleanupExpiredTenantRevocations`, which only exists once Stage 3 lands).
The `Close()`/Mongo-factory/`MarkTokenRotatedAtomic` fixes are otherwise
independent and could in principle run earlier — this ordering is a judgment
call, not a hard requirement beyond the `CleanupAll` coupling.

**Verification:** `make race`, `make coverage-check`, full run against all 4
live backends; specifically re-run `TestMarkTokenRotatedAtomic_ReMarksAfterExpiry`
and confirm it now passes for Postgres/MongoDB too, not just Memory/Redis.

### Stage 4 completion notes

Implemented as scoped, with one pre-existing item found already done and one
scope narrowing on the coverage side:

- **Postgres's `CleanupAll` already called `CleanupExpiredTenantRevocations`**
  — this specific item was already satisfied, apparently picked up as a
  natural side effect of Stage 3's own work on tenant revocation, not
  something separately implemented here. `Stats` similarly already included
  `tenant_revocations`. Confirmed via direct inspection before making any
  changes, so no duplicate work landed.
- `gourdiantoken.interfaces.go`: `TokenRepository` gained
  `Stats(ctx) (map[string]interface{}, error)` and `CleanupAll(ctx) error`,
  exactly as scoped; `Close` deliberately not added (decision #7).
- `gourdiantoken.repository.inmemory.imp.go`: `Stats() map[string]int` →
  `Stats(ctx) (map[string]interface{}, error)`, normalized to `int64` and
  matching the other three backends' exact key names
  (`total_revoked_tokens`/`revoked_access_tokens`/etc., not just the subset
  the old signature had). New `CleanupAll`, with a doc comment explaining
  why its own error-wrap branches are structurally unreachable (each
  `CleanupExpired*` call it makes uses a fixed, valid literal argument;
  `MemoryTokenRepository`'s own implementations only ever fail on an
  invalid `TokenType`) — same "documented inline, not chased with a
  synthetic test" precedent as `newTokenID`'s crypto/rand failure path.
- `gourdiantoken.repository.redis.imp.go`: new `CleanupAll`, same shape as
  Postgres's existing one.
- `gourdiantoken.repository.mongo.imp.go`: `Close(ctx context.Context) error`
  → `Close() error` (confirmed a literal no-op internally, so dropping the
  parameter was free — no call site outside the repository's own doc
  comments passed a context here, since tests clean up Mongo via the driver
  client's own `Disconnect(ctx)`, not this method). New `CleanupAll`.
  **`MarkTokenRotatedAtomic` bug fixed**: replaced the blind `InsertOne`
  with a conditional upsert (`UpdateOne` with `upsert=true`, filtered on
  `token_hash` equal *and* `expires_at <= now`) — an existing not-yet-expired
  document doesn't match the filter, so the upsert's implicit insert
  collides with the unique index on `token_hash` (caught via the existing
  `mongo.IsDuplicateKeyError` check), while an expired document matches and
  gets updated in place. No change to the duplicate-key-detection-at-the-
  transaction-boundary pattern the existing concurrency regression test
  (`TestMongoRepository_MarkTokenRotatedAtomic_ConcurrentDuplicate_WithTransactions`)
  depends on — re-ran it directly against the new implementation, still
  green.
- `gourdiantoken.repository.postgres.imp.go` / `internal/postgresdb/queries/tokens.sql`:
  **`MarkTokenRotatedAtomic` bug fixed** exactly as scoped —
  `InsertRotatedTokenIfNotExists` changed from unconditional
  `ON CONFLICT (token_hash) DO NOTHING` to
  `ON CONFLICT (token_hash) DO UPDATE SET expires_at = EXCLUDED.expires_at, created_at = EXCLUDED.created_at WHERE gourdiantoken_rotated_tokens.expires_at <= EXCLUDED.created_at`,
  regenerated via `sqlc generate`. Postgres reports 0 affected rows when the
  `WHERE` is false (existing row still live), giving the same "conflict, not
  expired → false" outcome as before for that case; the existing Go-side
  `rowsAffected > 0` check needed no change, confirming the plan's own
  prediction.
- `gourdiantoken.factories.go`: `NewGourdianTokenMakerWithMongo` dropped
  `transactionsEnabled bool`, now hardcoding `true` internally (decision #8)
  — matches the `(ctx, config, handle, opts...)` shape shared by the other
  three backend factories.
- **Test-file impact, broader than originally scoped** (the plan anticipated
  `concurrency_test.go` and a Mongo-arg drop in `factories_test.go`/
  `example/example.go` — `example/example.go` turned out to need no change,
  since its Mongo repository construction goes through
  `NewMongoTokenRepository(db, false)` directly, not the factory):
  - `concurrency_test.go`: `memRepo.Stats()` → `memRepo.Stats(ctx)` with
    error handling at both call sites (~lines 888/894 as predicted).
  - `gourdiantoken.repository_test.go`: `TestMemoryRepository_Stats`
    updated for the new signature.
    `TestRepositoryStats_AllBackends`'s per-backend `switch`/type-assertion
    collapsed into one shared assertion block calling `repo.Stats(ctx)`
    directly on the `TokenRepository` interface value — no longer needs a
    type assertion now that `Stats` is part of the interface. New
    `TestCleanupAll_AllBackends` (not explicitly called for in the plan, but
    a natural companion test now that `CleanupAll` is also on the
    interface): seeds one short-TTL entry of each kind, sleeps past
    expiry, calls `CleanupAll` once, and asserts both `Stats` and
    `GetTenantRevocationEpoch` reflect the sweep, across all 4 backends.
    `TestPostgresRepository_CleanupAll`/`_RotatedCleanupFails`/
    `_TenantRevocationCleanupFails` (pre-existing, Postgres-specific) were
    left as-is rather than merged into the new generalized test, since they
    exercise fault-injection paths (`DROP TABLE`) specific to Postgres.
    The `Close()` idempotency test's Mongo case simplified from
    `func() error { return r.Close(context.Background()) }` to plain
    `r.Close` now that all four backends share the same no-argument shape.
  - `gourdiantoken.factories_test.go`: all 5 `NewGourdianTokenMakerWithMongo`
    call sites dropped their trailing bool argument.
    `TestNewGourdianTokenMakerWithMongo_CreatesTransactionEnabledRepository`
    repurposed from "confirms passing `true` enables transactions" to
    "confirms the factory always produces a transactions-enabled repository"
    (the assertion is unchanged; only the doc comment and the removed
    argument reflect that it's no longer caller-controlled).
  - `gourdiantoken.repository.mongo_test.go`: 1 call site fixed; added a
    `CleanupAll` assertion to the existing
    `TestMongoRepository_OperationsAfterDisconnected` fault-injection test.
  - `gourdiantoken.repository.redis_test.go`: added a `CleanupAll` assertion
    to the existing `TestRedisRepository_OperationsAfterClientClosed`
    fault-injection test.
  - `gourdiantoken.repository.coverage_test.go`:
    `TestMarkTokenRotatedAtomic_ReMarksAfterExpiry` generalized from
    `["Memory", "Redis"]` to all 4 backends, doc comment flipped from
    "documents a known inconsistency" to "confirms all 4 backends now
    agree", per the plan.
  - `gourdiantoken.maker_test.go`/`gourdiantoken.close_test.go`: the two
    hand-written `TokenRepository` test-double stubs (`erroringRepo`,
    `cleanupCountingRepo`) needed trivial `Stats`/`CleanupAll` stub methods
    to keep satisfying the interface — not called out explicitly in the
    plan's test-file-impact list, but a mechanical consequence of adding
    two new interface methods.
- **Coverage note**: overall repo coverage moved from the 95.8-95.9% range
  carried over from key-material-config Stage 1 down to **95.1%** — still
  well above the 95% gate, but worth recording why it isn't higher. The new
  `CleanupAll` methods on Memory/Redis/Mongo each wrap 5 sequential
  `CleanupExpired*` calls in `if err != nil` branches; Memory's are
  genuinely unreachable (documented inline, see above). Redis's and Mongo's
  *are* reachable in principle (a real network/database error), and one
  fault-injection assertion was added to each backend's existing
  closed-client/disconnected-client test to cover the first (access-token)
  branch — but reaching the *later* branches (refresh/verification/rotated/
  tenant) in isolation would require making only that one specific
  downstream call fail while every earlier call in the same sequence
  succeeds, which isn't achievable via "close the client" (fails
  everything uniformly) the way Postgres's "drop one specific table" trick
  works, since Redis/Mongo's revoked-token storage is one shared
  keyspace/collection across all three token types rather than one table
  per type. Postgres's own `CleanupAll` was already well-covered via its
  pre-existing `TestPostgresRepository_CleanupAll_RotatedCleanupFails`/
  `_TenantRevocationCleanupFails` tests plus the pool-closed test's first
  branch, and needed no new tests.
- Full verification green: `go build ./...`, `go vet ./...`, `gofmt -l .`
  (clean), `golangci-lint run` (0 issues), `staticcheck ./...` (clean),
  `TestMarkTokenRotatedAtomic_ReMarksAfterExpiry` re-run directly and
  confirmed passing for all 4 backends including Postgres/MongoDB (was
  Memory/Redis-only before this stage), full suite against all 4 live
  backends, `make race`, `make coverage-check` (95.1%, meets the 95% gate),
  and `go run ./example` end-to-end (46/46 scenarios × 6 suites — the 4
  backends, stateless mode, and the asymmetric-signing (RS256) demo suite
  added earlier in this session — 276/276 passed).

## Stage 5 — Docs, CHANGELOG, version bump, example.go

Last, once the API surface from Stages 1-4 is final.

**Files touched:**

- **`example/example.go`** — wire `tenantID` through the demo's create calls;
  add a demo group exercising `MultiTenantEnabled` + `RevokeTenant`.
- **`docs.go`** — new "Multi-Tenancy" section covering the flag, the `tid`
  claim, `RevokeTenant`'s epoch design and rationale, and the
  Metadata-for-verification-tokens convention.
- **`README.md`** — new "Upgrading to v2.3.0" section (same format as the
  existing v2.2.0 one: breaking-changes-despite-minor-version framing,
  before/after code blocks, migration table) covering: the new trailing
  `tenantID` parameter (breaks *every* caller — lead with "pass `\"\"` if you
  don't need this"), the removed split interfaces, the Mongo factory
  signature change, the `Stats`/`Close` signature changes. Update the
  `GourdianTokenMaker Interface` code block to the full merged method list.
  Remove every "optional interface, use a type assertion" reference. New
  "Multi-Tenancy" section near "Security Features".
- **`CHANGELOG.md`** — new `## v2.3.0` entry following the exact structure of
  the existing `v2.2.0` entry (breaking-changes callout,
  `Added`/`Breaking`/`Changed`/`Fixed`/`Testing`/`Documentation` subsections
  as applicable, a "Why the module path is still /v2" note reusing v2.2.0's
  reasoning). Every breaking item gets a concrete before/after, not just a
  label — matching this repo's established changelog convention of
  explaining rationale, not just diffing.
- **`version.go`** — `Version` bump to `"v2.3.0"`.
- **`Makefile`** — `VERSION` bump to match.
- **`CLAUDE.md`** — final consistency pass across all bullets touched
  incrementally in Stages 1-4.

**Test-file impact:** none expected — documentation/metadata-only stage.

**Dependencies:** Stages 1-4 fully landed.

**Verification:** `go build ./example/...` and run it end-to-end against at
least Memory (all 4 backends if `make docker-up` is available); `gofmt`/
`goimports` clean; `bark check` reports no header debris on touched files.

### Stage 5 completion notes

Landed with a substantially wider documentation-accuracy pass than the plan
originally scoped, per explicit instruction to audit `docs.go` and
`README.md` against the real current code rather than just append new
sections:

- **`example/example.go`**: added a standalone "Multi-Tenant Demo
  (RevokeTenant)" suite (`runMultiTenantDemo`, 7 scenarios: create with
  tenantID → reject empty tenantID → verify carries `tid` → revoke tenant →
  pre-revocation token rejected → post-revocation token for the same tenant
  still valid → `RotateRefreshToken` preserves `tid`), run against its own
  dedicated maker rather than folded into `RunComprehensiveTests`' shared
  pipeline — every other test group there passes an empty `tenantID` and
  would fail outright against a `MultiTenantEnabled=true` maker. (The
  equivalent asymmetric-signing suite was added earlier in this session,
  ahead of Stage 4, per separate explicit instruction — noted here since
  Stage 5's own file-touched list originally called for it.)
- **`docs.go`**: new "Multi-Tenancy" `#`-section (flag, `tid` claim,
  `RevokeTenant`'s epoch design and rationale, the `Metadata` convention for
  verification tokens), plus fixes found during the audit that predated
  this stage: the "Storage Backends" section still claimed Mongo's `Close()`
  took a `context.Context` (fixed in Stage 4, not reflected in docs.go
  until now) and didn't mention `Stats`/`CleanupAll` joining the interface;
  "Error Handling" was missing all four tenant sentinels; "Common Pitfalls"
  gained a tenant-related entry; the package-level "Overview" paragraph
  gained a one-line mention of multi-tenancy for discoverability.
- **`README.md`**: extensive drift found and fixed, most of it predating
  Stage 5 entirely (accumulated across Stages 1-4 without a doc pass):
  - The `GourdianTokenMaker Interface` code block was still the pre-Stage-1
    7-method version with no `tenantID` parameters, no `RevokeTenant`, no
    `Close`, no verification-token methods — replaced with the full current
    12-method merged interface.
  - **Every** `CreateAccessToken`/`CreateRefreshToken` call site in the
    README (11 locations: both Quick Start examples, the API Reference
    signatures/examples, `setupAsymmetric`, all three numbered Examples, and
    all three Testing-section snippets) was still missing the `tenantID`
    argument entirely — none of this example code would have compiled
    against the actual `v2.3.0` API. All given a trailing `""` (or
    `claims.TenantID` in the one rotation-flow example where propagating it
    was the more correct choice).
  - Five references to the removed `GourdianTokenMakerVerification`/
    `GourdianTokenMakerCloser` split interfaces — including a `maker.(...)`
    type assertion pattern in the runnable verification-token example and
    in the `CreateVerificationToken`/`VerifyVerificationToken`/
    `MarkVerificationTokenUsed` API Reference entries — removed; those
    interfaces were merged away in Stage 2 but README never caught up.
  - Both `NewGourdianTokenMakerWithMongo` call sites still passed the
    `transactionsEnabled` bool Stage 4 removed; fixed, with the MongoDB
    Storage section's feature bullet reworded to explain transactions are
    now always-on and how to opt out (construct the repository directly).
  - `GourdianTokenConfig`'s struct block and field-reference table were
    missing `MultiTenantEnabled` entirely (field count corrected `~21` →
    `~22`); `AccessTokenClaims`'s Go struct block and `RefreshTokenClaims`'s
    note were missing `TenantID`.
  - "Secure Defaults" and "Best Practices → Key Management" both still
    claimed gourdiantoken checks private-key file permissions (0600) —
    removed in the key-material-config plan, before Stage 4 even started;
    reworded to note this is now the caller's own responsibility if a key
    ever touches disk upstream of this library.
  - New top-level "🏢 Multi-Tenancy" section added near "Security Features"
    (with a Table of Contents entry) covering enabling the flag, the
    required/forbidden `tenantID` contract, the `Metadata` convention for
    verification tokens, and `RevokeTenant`'s epoch design — condensed from
    the same explanation now in `docs.go` and `CLAUDE.md`, kept consistent
    across all three.
  - "Upgrading to v2.3.0" (created by key-material-config Stage 2) extended
    with four more numbered breaking-change entries covering the
    `tenantID` parameter, the interface merge, the Mongo factory signature
    change, and `TokenRepository`'s `Stats`/`CleanupAll`/`Close` changes —
    each with a concrete before/after, matching the section's existing
    style and this repo's changelog convention generally.
- **`CHANGELOG.md`**: extended the existing `## v2.3.0` section (also
  created by key-material-config Stage 2) with `### Added` (multi-tenancy,
  `RevokeTenant`, the four new sentinels, `Stats`/`CleanupAll`, the two new
  example suites), further `### Breaking` entries (the four items listed
  above), a new `### Fixed` entry for the two `MarkTokenRotatedAtomic`
  bugs, and a `### Testing` entry explaining the 95.1% coverage number —
  rather than creating a second `## v2.3.0` section, per the note left in
  this plan's own tracker after key-material-config Stage 2.
- **`version.go`**/**`Makefile`**: `Version`/`VERSION` bumped `v2.2.0` →
  `v2.3.0`. No test asserts the literal version string, so no test-file
  impact.
- **`CLAUDE.md`**: consistency pass across every bullet touched
  incrementally in Stages 1-4 — the coverage-percentage callout (now
  references `v2.3.0`'s Testing section and 95.1%), the `example/example.go`
  file-layout bullet (now describes the two standalone demo suites and the
  per-entry config-override mechanism they use), the "Multi-tenancy"
  section's stale "Stage 1+3" self-reference (now "Stages 1-4"), and the
  "In-progress work" section (both plan docs' actual current stage status).
- Full verification green: `go build ./...`, `go vet ./...`, `gofmt -l .`
  (clean), `golangci-lint run` (0 issues), `staticcheck ./...` (clean), full
  test suite against all 4 live backends, `make race` (cache cleared and
  re-run fresh to confirm, since `version.go` changed), `make coverage-check`
  (95.1%, unchanged from Stage 4 — this stage was docs/example-only for the
  root package's own test surface), and `go run ./example` end-to-end — all
  7 suites (4 backends + stateless + asymmetric + multi-tenant demo) passed
  100%, 0 failures across 237 total scenarios.

## Stage 6 — Full validation pass

`make clean` → `make fmt` → `make vet` → `make lint` → `make staticcheck` →
`make docker-up` → `make coverage-check` (must stay ≥95%; cover any new
hard-to-reach branch via the established "close the connection out from
under it" fault-injection technique, or document a permanent justified gap
inline — never let the number silently slip) → `make race` → `make bench`
(optional, confirms the new trailing parameter and epoch-check branch didn't
regress the hot path; update README's benchmark table if numbers moved) →
`go build ./example/...` run end-to-end against all 4 live backends →
`make precommit` → `make prerelease` → `make release` only once everything
above is green and you're ready to tag `v2.3.0`.

**Specific design-goal verification:**
- Confirm a token issued with `MultiTenantEnabled=false` produces a
  byte-identical JWT payload to today (no `tid` key at all).
- One dedicated integration test phrased close to how ERP's auth middleware
  will actually use this: create an access token with `tenantID` → verify →
  read `claims.TenantID` → nothing else touched before that point.

## New sentinel errors introduced across this plan

| Sentinel | Stage | Triggered by |
|---|---|---|
| `ErrTenantIDRequired` | 1 | Create* with `MultiTenantEnabled=true` + empty `tenantID`; Verify* with `tid` missing/empty when enabled |
| `ErrTenantIDNotAllowed` | 1 | Create* with `MultiTenantEnabled=false` + non-empty `tenantID` |
| `ErrMultiTenantDisabled` | 3 | `RevokeTenant` called with `MultiTenantEnabled=false` |
| `ErrTenantRevoked` | 3 | Verify* on a token issued at-or-before its tenant's revocation epoch |

## Critical files

- `gourdiantoken.maker.go` — `CreateAccessToken`/`CreateRefreshToken`
  (claim construction), `parseAndValidateToken` (line 718, verified —
  insertion point for tid-required + epoch checks), `RotateRefreshToken`
  (line 1334, verified — the tenant-propagation bug site is line 1359)
- `gourdiantoken.validation.go` — `toMapClaims`, `mapToAccessClaims`,
  `mapToRefreshClaims`, `validateTokenClaims`
- `gourdiantoken.interfaces.go` — `GourdianTokenMaker`, `TokenRepository`
- `gourdiantoken.repository.postgres.imp.go` + `internal/postgresdb/` —
  schema/query source of truth for the Postgres backend changes
- `token.test.helper_test.go` — `getTestRepositoryFactories()`, the shared
  test-factory entry point every cross-backend test drives through
