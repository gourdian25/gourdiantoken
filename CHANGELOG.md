# Changelog

All notable changes to `gourdiantoken` are documented in this file.

## v2.2.0

**Breaking changes, despite the minor-looking version number** — see
[README.md's "Upgrading to v2.2.0"](./README.md#️-upgrading-to-v220-gorm-removed-storage-names-changed)
for the full migration guide. Part of the gourdian25 ecosystem-wide
GORM→pgx+sqlc migration.

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
