# Changelog

All notable changes to `gourdiantoken` are documented in this file.

## v2.4.0

**Breaking**, for the Postgres backend only. Closes a gap found while
wiring `NewGourdianTokenMakerWithPostgres` into `grauth`: its schema
auto-apply on every connect required `CREATE` on the target schema, which
a deliberately least-privilege application role (a common production
setup — a separate role owns migrations, the app connects with a
DML-only role) doesn't have, failing construction with `permission
denied for schema ...` — and this can't be worked around by
pre-creating the tables some other way, since `CREATE TABLE IF NOT
EXISTS` still checks `CREATE` privilege before checking whether the
table exists, so the attempt fails every time regardless.

Rather than add a flag to opt out of auto-apply on a per-call basis,
`NewPostgresTokenRepository`/`NewGourdianTokenMakerWithPostgres` now
**never** apply schema at all — see
[docs/postgres.md](../gourdiantoken/docs/postgres.md) (new file; the
Postgres factory doc comments have referenced it since `v2.0` but it was
never actually written until now).

### Changed

- **`NewPostgresTokenRepository(ctx, pool)` no longer applies schema.**
  Signature is unchanged (still 2 args — an earlier draft of this release
  added a `WithSkipSchemaEnsure()` opt-out instead of removing auto-apply
  outright; that approach was dropped before release in favor of the
  simpler "always the caller's job" rule below), but its behavior is:
  construction now only pings the pool. Call `PostgresSchemaSQL()` and
  apply the result through your own project's migration tool before
  constructing — see docs/postgres.md. Existing deployments that relied
  on the implicit auto-apply need to add that migration step; the schema
  itself is unchanged (still `CREATE TABLE/INDEX IF NOT EXISTS`, still the
  same 3 `gourdiantoken_`-prefixed tables).
- **`NewGourdianTokenMakerWithPostgres`** is unchanged in signature and is
  still exactly `NewPostgresTokenRepository` + `NewGourdianTokenMaker`
  composed for convenience — it inherits the same "schema must already
  exist" requirement.

### Added

- **`PostgresSchemaSQL() string`**, returning gourdiantoken's Postgres
  schema as text, for applying through your own migration tool (see
  docs/postgres.md).

## v2.3.0

**Breaking changes** — see
[README.md's "Upgrading to v2.3.0"](./README.md#️-upgrading-to-v230)
for the full migration guide. Two independent initiatives landed in this
release: in-memory key material configuration, and multi-tenancy support
(including a repository-backend standardization pass).

### Added

- **Multi-tenancy support.** `GourdianTokenConfig.MultiTenantEnabled` (opt-in,
  default `false`) gates a new `tid` claim on access/refresh tokens, backing
  a new `TenantID string` field on `AccessTokenClaims`, `RefreshTokenClaims`,
  `AccessTokenResponse`, and `RefreshTokenResponse`. `CreateAccessToken`/
  `CreateRefreshToken` gain a required trailing `tenantID string` parameter
  — see "Breaking" below. Fails loud in both directions: a non-empty
  `tenantID` when the flag is `false` is rejected (`ErrTenantIDNotAllowed`),
  as is an empty one when it's `true` (`ErrTenantIDRequired`), both on
  create and on verify. `VerificationTokenClaims` gets no `TenantID` field —
  tenant-scoping a verification token is a documented convention of putting
  `"tenant_id"` in its existing free-form `Metadata` map instead.
  `RotateRefreshToken` forwards the old token's `TenantID` to the new one.
- **`GourdianTokenMaker.RevokeTenant(ctx, tenantID) error`** bulk-revokes
  every access/refresh token for a tenant via a revocation epoch rather than
  enumeration: it records "this tenant was revoked at time T," and
  verification rejects any `AccessToken`/`RefreshToken` whose `iat` is
  at-or-before that epoch — including tokens never individually seen by the
  repository, which enumeration-based revocation fundamentally cannot reach
  for access tokens. Requires `MultiTenantEnabled`, `RevocationEnabled`, and
  a `TokenRepository`. New `TokenRepository` methods backing it:
  `RevokeTenant(ctx, tenantID, ttl) error`,
  `GetTenantRevocationEpoch(ctx, tenantID) (time.Time, error)`,
  `CleanupExpiredTenantRevocations(ctx) error` — implemented identically
  across all four backends.
- Four new sentinel errors for use with `errors.Is`: `ErrTenantIDRequired`,
  `ErrTenantIDNotAllowed`, `ErrMultiTenantDisabled`, `ErrTenantRevoked`.
- **`TokenRepository` gains `Stats(ctx) (map[string]interface{}, error)` and
  `CleanupAll(ctx) error`**, now part of the interface and implemented
  identically across all four backends (previously Postgres-only extensions
  reached via a type assertion; Redis/Memory/Mongo had no equivalents).
- `example/example.go`: a new "Asymmetric (RS256) - In-Memory Repository"
  suite demonstrating `PrivateKeyPEM`/`PublicKeyPEM` end to end, and a new
  "Multi-Tenant Demo (RevokeTenant)" suite demonstrating
  `MultiTenantEnabled` + `RevokeTenant` end to end (create with tenantID →
  verify → revoke tenant → pre-revocation token rejected → post-revocation
  token for the same tenant still valid → rotation preserves `tid`).

### Breaking

- **`PrivateKeyPath`/`PublicKeyPath` (file paths) replaced by
  `PrivateKeyPEM`/`PublicKeyPEM` (`[]byte`).** `GourdianTokenConfig` no
  longer reads a key file off disk itself — `parseKeyPair` now parses the
  PEM bytes handed to it directly. Motivated by deployment environments
  (Kubernetes in particular) where the key material already arrives as
  bytes in memory via the consumer's own config-loading path (an env var, a
  mounted `Secret` volume, the External Secrets Operator, Vault Agent
  Injector, the CSI Secret Store driver, or a direct secret-manager SDK
  call) rather than as a well-known file path gourdiantoken would need to
  read itself. `checkFilePermissions` (the 0600-permission check that only
  made sense for a file on disk) is removed along with it.
  `NewGourdianTokenConfig`'s deprecated positional constructor changed to
  match: `privateKeyPath, publicKeyPath string` → `privateKeyPEM,
  publicKeyPEM []byte`, same argument positions.
- **`CreateAccessToken`/`CreateRefreshToken` gain a required trailing
  `tenantID string` parameter.** Breaks every existing call site regardless
  of whether multi-tenancy is used — pass `""` to keep prior single-tenant
  behavior. Appended rather than inserted mid-list to avoid transposing
  adjacent string arguments across the ~294 existing call sites this touched
  (tests plus `example/example.go`).
- **`GourdianTokenMakerCloser`/`GourdianTokenMakerVerification` (the two
  optional interfaces split out of `GourdianTokenMaker` in earlier releases)
  are removed, merged back into a single flat `GourdianTokenMaker`** — which
  now also carries `RevokeTenant`. Any type assertion reaching `Close`/
  `CreateVerificationToken`/`VerifyVerificationToken`/
  `MarkVerificationTokenUsed` should be dropped; every constructor's return
  value already satisfies the merged interface. No back-compat alias kept
  for either removed interface name — confirmed zero real external
  implementers before removing them.
- **`NewGourdianTokenMakerWithMongo` drops its `transactionsEnabled bool`
  parameter**, now matching the `(ctx, config, handle, opts...)` shape
  shared by the other three backend factories. Transactions are hardcoded
  `true` internally. Construct `NewMongoTokenRepository(mongoDB, false)`
  plus `NewGourdianTokenMaker` directly if you need them disabled (e.g. a
  standalone dev MongoDB without a replica set).
- **`MongoTokenRepository.Close(ctx context.Context) error` →
  `Close() error`**, dropping its context parameter (confirmed a literal
  no-op internally), matching the other three backends' bare `Close() error`.

### Fixed

- **Cross-backend `MarkTokenRotatedAtomic` inconsistency** (flagged, not
  fixed, in v2.2.0's changelog entry): Postgres and MongoDB previously
  treated *any* existing rotation record as a conflict, even one whose own
  TTL had already logically expired, so re-marking the same token after its
  prior rotation record expired incorrectly reported `false` (Memory/Redis
  always allowed this correctly). Postgres's `InsertRotatedTokenIfNotExists`
  query changed from unconditional `ON CONFLICT (token_hash) DO NOTHING` to
  a conditional `ON CONFLICT ... DO UPDATE ... WHERE expires_at <=
  EXCLUDED.created_at`. MongoDB's `MarkTokenRotatedAtomic` changed from a
  blind `InsertOne` to a conditional upsert (`UpdateOne` with
  `upsert=true`, filtered on the existing document already being expired).
  All four backends now agree; see `TestMarkTokenRotatedAtomic_ReMarksAfterExpiry`.

### Testing

- Root-package coverage: 95.1% (down slightly from the 95.8-95.9% range
  carried by the prior release, still above the 95% gate) — the new
  `CleanupAll` methods on Memory/Redis/Mongo each wrap five sequential
  `CleanupExpired*` calls in error-handling branches; Memory's are
  genuinely unreachable (documented inline), and reaching Redis's/Mongo's
  *later* branches in isolation (refresh/verification/rotated/tenant, as
  opposed to the first, access-token branch) isn't achievable via the
  established "close the client" fault-injection technique, since — unlike
  Postgres, which has one table per token type — their revoked-token
  storage is one shared keyspace/collection across all three types.
- `TestMarkTokenRotatedAtomic_ReMarksAfterExpiry` generalized from
  `["Memory", "Redis"]` to all four backends now that the underlying bug is
  fixed everywhere.
- New `TestCleanupAll_AllBackends`, `TestRepositoryStats_AllBackends`
  simplified to call `Stats`/`CleanupAll` directly on the `TokenRepository`
  interface value (no more per-backend type assertion).

## v2.2.0

**Breaking changes, despite the minor-looking version number** — see
[README.md's "Upgrading to v2.2.0"](./README.md#️-upgrading-to-v220-gorm-removed-storage-names-changed)
for the full migration guide. Part of the gourdian25 ecosystem-wide
GORM→pgx+sqlc migration.

### Added

- `WithStructuredLogger(logger Logger) Option` — a new, additive logging
  hook alongside the existing `WithLogger`. `Logger`
  (`Debug`/`Info`/`Warn`/`Error(msg string, args ...any)`) matches
  `*slog.Logger`'s own signatures, the same shape now used by
  grcache/grevents/graudit/grpolicy/grnoti's own `Logger` interfaces, so
  `*slog.Logger` — including one backed by grlog via
  `slog.New(grlog.NewSlogHandler(...))` — satisfies it with no adapter.
  When set, it's used instead of `WithLogger`'s `logf` callback for the two
  background-cleanup error reports; when unset, `logf`'s existing behavior
  is completely unchanged. No breaking changes of its own — `WithLogger`/
  `Option`/`logf` are untouched.

### Breaking

- **Removed GORM.** `GormTokenRepository` and `NewGourdianTokenMakerWithGorm`
  are gone, replaced by `PostgresTokenRepository` and
  `NewGourdianTokenMakerWithPostgres`, built on `pgx/v5` and sqlc-generated
  queries — no ORM. The new constructor takes a caller-built
  `*pgxpool.Pool` (which this package never dials itself and never closes
  except via the repository's own `Close()`) instead of a `*gorm.DB`,
  matching the shared-pool pattern already used by `grnoti`. Schema
  (`gourdiantoken_revoked_tokens`, `gourdiantoken_rotated_tokens`) is
  applied automatically via `CREATE TABLE/INDEX IF NOT EXISTS`, serialized
  by a Postgres advisory lock so concurrent callers building a repository
  against the same fresh database don't race on the DDL.
- **Storage names now carry a `gourdiantoken_`/`gourdiantoken:` prefix**:
  Postgres tables `revoked_tokens`/`rotated_tokens` →
  `gourdiantoken_revoked_tokens`/`gourdiantoken_rotated_tokens`; Mongo
  collections, same rename; Redis key prefixes `revoked:access:` /
  `revoked:refresh:` / `revoked:verification:` / `rotated:` →
  `gourdiantoken:revoked:access:` / `gourdiantoken:revoked:refresh:` /
  `gourdiantoken:revoked:verification:` / `gourdiantoken:rotated:`. **This
  is a new storage location, not an in-place rename** — upgrading
  deployments will not see previously-revoked/rotated tokens under the old
  names unless they migrate the data themselves first. See the README
  migration guide before deploying this to a system with real users.
- Removed `gorm.io/gorm` and `gorm.io/driver/postgres` from `go.mod`;
  `github.com/jackc/pgx/v5` is now a direct dependency (previously
  indirect, pulled in only by GORM's Postgres driver).

### Changed

- `token.test.helper_test.go`'s repository test factories now skip
  (`t.Skipf`) rather than hard-fail when a backend service (Redis, Mongo,
  Postgres) is unreachable, matching the rest of the gourdian25 ecosystem's
  convention (see `grnoti`).
- Test/example Mongo database name aligned to `gourdiantoken_test`
  (previously the inconsistent `gourdian_test`).

### Why the module path is still `/v2`

A real `v3.0.0` release would require Go's tooling-mandated `/v3` import
path bump, forcing every consumer to update their imports. This library
has few external consumers today, so that churn isn't justified yet —
this release ships breaking changes under a `v2.x.y` tag rather than
following strict semver. A future breaking release will move to `/v3`
properly if broad compatibility guarantees become necessary.

### Testing

- Root-package coverage raised from an unmeasured baseline (previous
  full-backend numbers were never actually collected against live
  services) to 95%+, via direct unit tests for the PEM key parsers'
  previously-untested branches (certificate fallback paths, type-mismatch
  errors), the claims-mapping functions in `gourdiantoken.validation.go`
  (every error branch of `extractCommonClaims`/`mapToAccessClaims`/
  `mapToRefreshClaims`/`mapToVerificationClaims`/`validateTokenClaims`),
  repository-layer database-error branches across all four backends
  (closing the connection/pool/client out from under an otherwise-valid
  repository to reach error-wrapping code paths that a healthy backend
  never exercises), and a set of narrow race-window `ctx.Err()` checks in
  `gourdiantoken.maker.go` (guarding against a context cancelling *between*
  two checks a few lines apart) reached via a small test-only `context.Context`
  wrapper that succeeds a controlled number of times before reporting
  cancelled.
- Found and documented (not fixed, as it changes atomic-rotation semantics
  for two backends) a cross-backend inconsistency in
  `MarkTokenRotatedAtomic`: Postgres and MongoDB's `INSERT ... ON CONFLICT
  DO NOTHING`/upsert-based implementation treats any existing rotation
  record as a conflict regardless of whether it has logically expired,
  while Memory and Redis correctly allow re-marking an expired entry. See
  `TestMarkTokenRotatedAtomic_ReMarksAfterExpiry`.

### Documentation

- README: fixed the "Flexible Storage" bullet, which falsely advertised
  MySQL and SQLite backends that don't exist in this codebase — corrected
  to list only the four real ones (in-memory, Redis, PostgreSQL, MongoDB).
- README: both `NewGourdianTokenMakerWithMongo` example call sites (the
  "High Security (EdDSA with MongoDB)" config example and the "MongoDB
  Storage" section) were missing the required `transactionsEnabled bool`
  argument added when that factory's signature changed — the example code
  didn't actually compile as shown. Both now pass `true`, with a note on
  what the flag controls.
- README: replaced the stale Benchmark Results table (Intel i5-9300H, Go
  1.21) with numbers freshly measured on this release's own hardware/
  toolchain (Apple M4, Go 1.26.4), including a new "Repository Backend
  Operations" table covering Redis/Postgres/MongoDB revocation and
  rotation, not just Redis as before.
- CLAUDE.md: corrected the documented MongoDB test URI, which included an
  unnecessary `replicaSet=rs0&authSource=admin` — the actual test code only
  needs `directConnection=true`.
- `Makefile`'s `VERSION` bumped to `v2.2.0` to match this changelog entry,
  so `make build`/`make install` without an explicit `VERSION=` override
  stay honest.

## v2.1.1

Ecosystem-alignment and security pass; no breaking changes.

### Fixed

- **Security:** bumped `github.com/golang-jwt/jwt/v5` (`v5.2.1` → `v5.3.1`,
  closes GO-2025-3553, a reachable excessive-memory-allocation DoS in header
  parsing), `github.com/jackc/pgx/v5` (`v5.6.0` → `v5.10.0`, closes
  GO-2026-5004/4772/4771), and `golang.org/x/crypto` (`v0.31.0` → `v0.53.0`,
  clears 18 stale SSH/openpgp advisories). None were exploitable through
  this library's own code paths in isolation, but all are now patched.
- **`GormTokenRepository.Close()` was not idempotent** — unlike every other
  repository implementation in this package (Redis, Memory, `JWTMaker`),
  it had no `sync.Once` guard. A double-`Close()` call now returns the
  cached result instead of re-closing the underlying `*sql.DB`.

### Changed

- `go.mod`'s `go` directive raised from `1.24.0` to `1.26.4`, aligning
  with the rest of the gourdian25 ecosystem.
- Dependency versions aligned with `grcache` (the freshest repo in the
  ecosystem): `go.mongodb.org/mongo-driver`, `gorm.io/gorm`,
  `github.com/redis/go-redis/v9`, `github.com/stretchr/testify`,
  `github.com/klauspost/compress`, `github.com/montanaflynn/stats`,
  `github.com/xdg-go/scram`, `github.com/cespare/xxhash/v2`.
- `.bark.toml` corrected to match the rest of the ecosystem (was pointing
  at a stale `tree.txt`/`.bark_backups` template).
- `goreleaser-check` now installs `goreleaser/v2`, matching sibling repos.
- README: added a "part of the gourdian25 ecosystem" section (previously
  had none) and corrected the Go version badge/requirement to `1.26.4+`.

### Added

- `SECURITY.md` (previously missing).

## v2.1.0

### Added

- **`VerificationToken`**, a new token type for short-lived, single-use, use-case-scoped tokens (e.g. a 2FA-pending verification step between password check and full session issuance, or password-reset/email-verify links). Fully additive and disabled by default — existing configs and code are unaffected.
  - New `VerificationTokenClaims`/`VerificationTokenResponse` structs (`gourdiantoken.claims.go`).
  - New `GourdianTokenConfig` fields: `VerificationTokensEnabled` (master switch, default `false`), `VerificationAllowedUseCases`, `VerificationDefaultExpiryDuration`, `VerificationMaxExpiryDuration`.
  - New optional interface `GourdianTokenMakerVerification` (`CreateVerificationToken`, `VerifyVerificationToken`, `MarkVerificationTokenUsed`), following the same precedent as `GourdianTokenMakerCloser` — deliberately kept separate from `GourdianTokenMaker` so implementing it does not break existing implementers. `*JWTMaker` implements it.
  - `CreateVerificationToken` takes a per-call `ttl` parameter (0 = use the configured default), unlike the fixed-duration `CreateAccessToken`/`CreateRefreshToken` — variable per-use-case TTL is the reason this token type exists.
  - Single-use enforcement (`MarkVerificationTokenUsed`) reuses the existing access/refresh revocation machinery (`MarkTokenRevoke`/`IsTokenRevoked`) rather than adding new `TokenRepository` methods — "mark used" is "revoke"; requires `RevocationEnabled` plus a `TokenRepository`.
  - New sentinel `ErrTokenAlreadyUsed`, a plain alias of `ErrTokenRevoked` (matching the existing `ErrTokenExpired = jwt.ErrTokenExpired` precedent).
  - All four `TokenRepository` implementations (Memory, Redis, GORM, MongoDB) updated to recognize `VerificationToken` alongside `AccessToken`/`RefreshToken` in revocation tracking and `Stats()`.

### Changed

- `Makefile`'s coverage gate (`COVERAGE_MIN`) raised from `70` to `80`.

## v2.0.0

### ⚠️ Breaking changes

- **Module path changed to `github.com/gourdian25/gourdiantoken/v2`**, per Go's semantic import versioning rules for major version 2+. Update your import statements and `go get github.com/gourdian25/gourdiantoken/v2@latest`.
- **`ID`, `Subject`, and `SessionID` changed from `uuid.UUID` to `string`** on `AccessTokenClaims` and `RefreshTokenClaims`. `Subject` and `SessionID` likewise changed on `AccessTokenResponse` and `RefreshTokenResponse` (neither response type has an `ID`/`jti` field).
- **`userID` and `sessionID` parameters changed from `uuid.UUID` to `string`** on `CreateAccessToken` and `CreateRefreshToken` (both the `GourdianTokenMaker` interface and the `*JWTMaker` implementation).
- **Validation is now fully opaque for user-supplied identifiers**: `userID` must be a non-empty string; `sessionID` may be empty (for sessionless tokens) but is no longer required to be UUID-shaped. Any previously-valid UUID string is still accepted — this is a widening of accepted input, not a narrowing.
- If you were calling `.String()` on `claims.Subject`, `claims.SessionID`, or a response's `Subject`/`SessionID` to get a string, remove that call — they're already `string`.
- `github.com/google/uuid` is now purely an internal dependency (used only for generating the token ID / `jti`). If your code only ever passed your own string identifiers into this library and never imported `google/uuid` for anything else, you no longer need that import at all.

### Added

- Sentinel errors for use with `errors.Is`: `ErrTokenRevoked`, `ErrTokenRotated`, `ErrTokenExpired`, `ErrInvalidSignature`, `ErrInvalidToken`, `ErrInvalidClaims`, `ErrTokenRepositoryRequired`, `ErrMissingExpClaim`, `ErrTokenMaxLifetimeExceeded`. Existing error message text is preserved ahead of the wrapped sentinel, so string-matching callers are unaffected.
- `GourdianTokenMakerCloser`, a new optional interface with a `Close() error` method for makers that support stopping their background cleanup goroutines. Implemented by `*JWTMaker`; not added to the existing `GourdianTokenMaker` interface, so this is non-breaking for external implementers. Idempotent — safe to call more than once.
- `WithLogger` functional option, for overriding how background cleanup goroutines report errors (defaults to `fmt.Printf`-based logging, matching prior behavior).
- `TestRepositoryClose_Idempotent` test covering `Close()` idempotency on the Redis, GORM, and MongoDB repository backends (previously only `MemoryTokenRepository.Close()` had coverage).
- `TestMongoRepository_MarkTokenRotatedAtomic_ConcurrentDuplicate_WithTransactions` regression test locking in the Mongo duplicate-key fix below.

### Fixed

- **Mongo `MarkTokenRotatedAtomic` duplicate-key handling**: duplicate-key detection moved from inside the transaction callback to the transaction boundary. Previously, a write error surfaced to the driver mid-transaction could cause the server to abort the transaction regardless of the callback's return value, making commit behavior driver-version-dependent. Now matches the same "false, nil means not-newly-marked, no real error" contract as the Redis and GORM backends.
- **`RotateRefreshToken` unrecoverable lockout**: the new refresh token is now created *before* the old one is marked rotated (previously the reverse). If token creation fails, the old token is no longer left permanently unusable with no new token issued — the caller can safely retry.
- **`RedisTokenRepository.Close()` was not idempotent**: a second call previously returned `redis: client is closed` (an upstream `go-redis` behavior). Now guarded with `sync.Once`, matching the idempotent-`Close()` convention used elsewhere in this codebase.
- Dead-`err` bug in `VerifyAccessToken`/`VerifyRefreshToken`/`RevokeAccessToken`/`RevokeRefreshToken`: an already-nil-checked `err` was being reused in a later error message, producing misleading `"invalid token: <nil>"` output.
- `toMapClaims` panics (on unsupported claim types and empty `Roles`) converted to returned errors. These paths were not reachable through the public API as shipped, but were fragile defense-in-depth.
- Redundant `"invalid token: "` prefix stutter removed from `RotateRefreshToken`'s error wrapping around `VerifyRefreshToken`'s own already-descriptive errors.
- Ambiguous validation message when a token repository is required but missing now states which flag (`RotationEnabled`/`RevocationEnabled`) triggered it.
- False doc comment claiming cleanup goroutines stop via garbage-collection finalization (they don't — see `Close()` above, which is the real fix for this).
- Flaky race in the (pre-existing, test-only) `TestClose_StopsCleanupGoroutines` test: `Close()`'s context cancellation could race against an already-ready ticker tick, causing one legitimate in-flight cleanup cycle to be mistaken for the goroutines failing to stop. Production behavior was always correct; only the test's assertion was too strict.

### Changed

- Internal source file `gourdiantoken.go` split into topic-focused files (`gourdiantoken.config.go`, `gourdiantoken.claims.go`, `gourdiantoken.interfaces.go`, `gourdiantoken.maker.go`, `gourdiantoken.validation.go`, `gourdiantoken.keys.go`) — no behavior change, no consumer-visible impact.
- `NewGourdianTokenConfig` is now marked `// Deprecated:` in favor of `DefaultGourdianTokenConfig` plus direct struct-literal field assignment. Not removed; still fully functional.
- `TokenRepository`'s interface doc now documents that implementations may enforce a minimum TTL floor (Redis does, at 100ms); the other three backends don't. No behavior change.
- Exported claim-key constants (`ClaimIssuer`, `ClaimAudience`, `ClaimNotBefore`, `ClaimMaxLifetimeExpiry`) added alongside `GourdianTokenConfig`, replacing bare string literals used internally.

### Dependencies

- `github.com/stretchr/testify` is no longer pulled in by consumers of this library — it was previously a direct dependency only because two test-helper files were missing the `_test.go` suffix (now renamed: `token.test.helper_test.go`, `token.bench.helper_test.go`).

### Known issues (flagged, not changed in this release)

- `RevokeAccessToken`/`RevokeRefreshToken`'s internal `jwt.Parse` keyfunc callbacks don't check the token's signing algorithm the way `VerifyAccessToken`/`VerifyRefreshToken` do. Low-severity (Go's static typing of the verification key already bounds classic algorithm-confusion attacks here); left alone in this release to avoid an unreviewed behavior change to revoke/rotate paths.
- `NewGourdianTokenMakerWithMongo`'s extra `transactionsEnabled bool` positional parameter breaks the `(ctx, config, handle)` shape shared by `NewGourdianTokenMakerWithGorm`/`WithRedis`. Fixing this needs an options struct or a new factory variant — a separate, larger design decision.
- `MongoTokenRepository.Close(ctx context.Context) error` has a different signature than the other three backends' bare `Close() error`. Not an interface-satisfaction issue (`TokenRepository` doesn't declare `Close()` at all), just an inconsistency between the four concrete types' own conventions.
