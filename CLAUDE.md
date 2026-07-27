# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

`gourdiantoken` is a single-package Go library (`package gourdiantoken`, module `github.com/gourdian25/gourdiantoken/v2`) providing JWT access/refresh token creation, verification, revocation, and rotation, plus short-lived single-use verification tokens, with pluggable storage backends. There is no `main` package other than the demo in `example/`.

## Commands

Build/test tooling is centralized in the `Makefile`; use it rather than raw `go` invocations where a target exists.

- `make test` — run all tests + benchmarks (`go test -count=1 -timeout=5m -cover ./... -bench=. -benchmem`)
- `make race` — run tests with `-race`
- `go test -run TestName ./...` — run a single test
- `go test -run TestName/SubtestName ./...` — run a specific subtest (many tests are table-driven over repository backends, see below)
- `make bench` / `make bench-<Name>` — run all/one benchmark
- `make coverage` / `make coverage-summary` / `make coverage-check` — coverage report / summary / 95% threshold gate (root package, real backends live — see "Backend-dependent tests" below). Measured coverage as of the pgx+sqlc migration is ~95.5% (varies slightly run-to-run since Go randomizes the `getTestRepositoryFactories()` map's iteration order) — see CHANGELOG.md's v2.2.0 "Testing" section for what's covered, including a handful of genuinely unreachable branches deliberately left uncovered (documented inline at each one, e.g. `newTokenID`'s crypto/rand failure path).
- `make vet` / `make lint` (golangci-lint) / `make staticcheck` / `make fmt` (goimports + gofmt) / `make quality` (all of the above)
- `make precommit` — clean, fmt, vet, lint, coverage-check
- `make prerelease` — precommit checks plus race detector, run before tagging a release

### Backend-dependent tests require live services

`token.test.helper_test.go`'s `getTestRepositoryFactories()` drives every repository-backed test (in `gourdiantoken.repository_test.go`, `gourdiantoken.factories_test.go`, etc.) across all four backends via `t.Run(name, ...)` subtests: `Memory`, `Redis`, `MongoDB`, `Postgres`. The non-Memory factories connect to **real local services** with hardcoded connection info and `t.Skipf` (rather than hard-failing) if unavailable, matching the rest of the gourdian25 ecosystem's convention (see grnoti).

These services are **shared across the whole gourdian25 workspace** (grnoti,
graudit, grcache, gourdiantoken all test against the same running Postgres/
Redis/Mongo instances, each using its own database/keyspace/DB-index):

- Redis: `localhost:6379`, password `redis_password`, DB `15`
- MongoDB: `mongodb://root:mongo_password@localhost:27018/?directConnection=true`, database `gourdiantoken_test` — must run as a replica set (even single-node); a standalone MongoDB doesn't support the transactions used when `NewMongoTokenRepository` is constructed with `useTransactions=true`. Port `27018`, not Mongo's default `27017`: on this project's dev machine, Docker Desktop's own port-forwarding for `27017` got stuck pointing at an orphaned mongod and didn't clear even after container recreation, `wsl --shutdown`, and a full Docker Desktop restart — `27018` sidesteps it. `directConnection=true` is required because the single-node replica set member is registered under its own container-internal hostname, which only resolves inside Docker's network; without it, the driver's topology discovery gets stuck in `ReplicaSetNoPrimary` trying to reach that unresolvable hostname. `replicaSet=rs0`/`authSource=admin` aren't needed on the connection string itself — `directConnection=true` alone is sufficient (confirmed against `token.test.helper_test.go`, matching graudit's/grcache's/grnoti's own test URIs). The container requires a `--keyFile` alongside `--replSet` (MongoDB enforces this whenever auth and a replica set are combined, even single-node) — see graudit's CLAUDE.md for the keyfile-generation steps.
- PostgreSQL (pgx/v5 + sqlc, no ORM): `host=localhost user=postgres_user password=postgres_password dbname=gourdiantoken_test port=5432 sslmode=disable`. Schema is auto-created by `NewPostgresTokenRepository` (`CREATE TABLE/INDEX IF NOT EXISTS`, serialized by a Postgres advisory lock — see `gourdiantoken.repository.postgres.imp.go`), no manual migration needed.

There is no docker-compose file in this repo — these services must be started/provided externally before running the full suite (see `make docker-up`/`make docker-down`). To iterate on logic that doesn't touch storage, scope test runs to the `Memory` subtest (e.g. `go test -run TestMarkTokenRevoke_SuccessAccessToken/Memory ./...`) to avoid needing all three services up.

## Architecture

### File layout (single package, split by concern)

The core was originally one `gourdiantoken.go` file and has since been split; there is no file by that name anymore.

- `gourdiantoken.config.go` — `TokenType`/`SigningMethod`/claim-key constants and `GourdianTokenConfig`, including the `VerificationTokensEnabled`/`VerificationAllowedUseCases`/`Verification{Default,Max}ExpiryDuration` fields that gate verification tokens (see below) and the opt-in `MultiTenantEnabled bool` flag (see "Multi-tenancy" below).
- `gourdiantoken.claims.go` — `AccessTokenClaims`, `RefreshTokenClaims`, `AccessTokenResponse`, `RefreshTokenResponse` (each carrying a `TenantID string` field, empty unless multi-tenancy is enabled), plus `VerificationTokenClaims`/`VerificationTokenResponse` for the verification-token type (no `TenantID` field — see "Multi-tenancy" below).
- `gourdiantoken.interfaces.go` — the `TokenRepository` and `GourdianTokenMaker` interfaces, plus two optional interfaces kept separate so adding them doesn't break external `GourdianTokenMaker` implementers: `GourdianTokenMakerCloser` (stopping background goroutines) and `GourdianTokenMakerVerification` (`CreateVerificationToken`/`VerifyVerificationToken`/`MarkVerificationTokenUsed`).
- `gourdiantoken.maker.go` — `JWTMaker` (the concrete implementation of `GourdianTokenMaker` and both optional interfaces above): constructors (`NewGourdianTokenMaker`, `DefaultGourdianTokenMaker`), the `Option`/`WithLogger`/`WithStructuredLogger` functional-options, `Close()`, create/verify/revoke/rotate methods, and the cleanup goroutines.
- `gourdiantoken.validation.go` — `validateConfig`, `validateAlgorithmAndMethod`, claims map conversion (`toMapClaims`, `mapToAccessClaims`, `mapToRefreshClaims`) and `validateTokenClaims`.
- `gourdiantoken.keys.go` — the six PEM key parsers (one per asymmetric algorithm family) sharing `decodePEMBlock`, plus `checkFilePermissions`.
- `gourdiantoken.errors.go` — sentinel errors for `errors.Is` (`ErrTokenRevoked`, `ErrTokenRotated`, `ErrTokenExpired`, `ErrInvalidSignature`, `ErrInvalidToken`, `ErrInvalidClaims`, `ErrTokenRepositoryRequired`, `ErrMissingExpClaim`, `ErrTokenMaxLifetimeExceeded`, `ErrTokenAlreadyUsed`). Wrapped error messages keep their original text ahead of the sentinel (e.g. `"token has been revoked: %w"`), so existing string-matching callers still work. `ErrTokenAlreadyUsed` is a plain alias for `ErrTokenRevoked` (zero new logic) — verification-token single-use enforcement reuses the access/refresh revocation machinery, so `errors.Is(err, ErrTokenAlreadyUsed)` and `errors.Is(err, ErrTokenRevoked)` behave identically.
- `logger.go` — the optional structured `Logger` interface (`Debug`/`Info`/`Warn`/`Error`, satisfied directly by `*slog.Logger`) for background cleanup goroutine diagnostics, `NopLogger`/`OrNop`, and the `WithStructuredLogger` option. Additive to the older printf-style `WithLogger`/`logf` hook — when both are configured, `WithStructuredLogger` wins for the two background-cleanup error reports.
- `gourdiantoken.factories.go` — convenience constructors (`NewGourdianTokenMakerNoStorage`, `...WithMemory`, `...WithPostgres`, `...WithMongo`, `...WithRedis`) that wire a `JWTMaker` to a specific `TokenRepository` implementation.
- `gourdiantoken.repository.{inmemory,redis,postgres,mongo}.imp.go` — one `TokenRepository` implementation per backend. All four implement the same interface (`MarkTokenRevoke`, `IsTokenRevoked`, `MarkTokenRotated`, `MarkTokenRotatedAtomic`, `IsTokenRotated`, `GetRotationTTL`, `CleanupExpiredRevokedTokens`, `CleanupExpiredRotatedTokens`) — when changing behavior here, changes typically need to be mirrored across all four for parity (the shared test suite in `gourdiantoken.repository_test.go` exercises all of them identically). Each implementation also has a concrete `Close()` method (idempotent; Mongo's takes a `context.Context`) that is not part of the `TokenRepository` interface — nor are Postgres's own `Stats()`/`CleanupAll()` (currently Postgres-only extensions, a known parity gap; Redis/Memory/Mongo have no equivalents). `gourdiantoken.repository.postgres.imp.go` is pgx/v5 + sqlc (no ORM); its generated query code lives in `internal/postgresdb` (see `sqlc.yaml`, `internal/postgresdb/schema.sql`/`queries/`) — regenerate with `sqlc generate` after editing the schema or queries, never hand-edit the generated files.
- `docs.go` — package-level documentation only (godoc), no executable logic.
- `version.go` — single `Version` var, bumped alongside the `VERSION` variable in `Makefile` and tagged via `make release`.
- `example/example.go` — standalone runnable demo (`package main`) exercising all four backends and signing methods; not part of the library's test surface.

### Verification tokens (third token type)

Beyond access/refresh, `JWTMaker` supports short-lived, single-use, use-case-scoped **verification tokens** (2FA-pending, password-reset, email-verify, etc.) via the optional `GourdianTokenMakerVerification` interface — check for it with a type assertion the same way as `GourdianTokenMakerCloser`. Gated by `GourdianTokenConfig.VerificationTokensEnabled`; single-use enforcement (`MarkVerificationTokenUsed`) additionally requires `RevocationEnabled` plus a `TokenRepository`, since it's implemented by revoking the token through the same `MarkTokenRevoke`/`IsTokenRevoked` path used for access/refresh tokens — no new repository methods were needed. See `token.verification_token_test.go` for the exercised lifecycle.

### Token lifecycle

`JWTMaker` (via `NewGourdianTokenMaker`/`DefaultGourdianTokenMaker` or the `NewGourdianTokenMakerWith*` factories) is the single entry point. Key invariants:

- `TokenRepository` is required only if `RotationEnabled` or `RevocationEnabled` is set in `GourdianTokenConfig`; construction fails otherwise if one of those flags is true and `tokenRepo` is `nil`.
- Enabling rotation/revocation spins up background goroutines (`cleanupRotatedTokens`, `cleanupRevokedTokens`) tied to an internal `context.WithCancel`, running on `config.CleanupInterval`. `JWTMaker.Close()` (part of `GourdianTokenMakerCloser`) cancels that context and is idempotent (`sync.Once`) — since `GourdianTokenMaker` callers may hold the interface rather than the concrete type, check for the optional interface before calling it: `if closer, ok := maker.(gourdiantoken.GourdianTokenMakerCloser); ok { closer.Close() }`.
- `SigningMethod` (`Symmetric`/`Asymmetric`) must match `Algorithm` (HS* vs RS*/ES*/PS*/EdDSA) — validated in `validateAlgorithmAndMethod`; asymmetric methods load PEM keys from `PrivateKeyPath`/`PublicKeyPath` via `initializeKeys`/`parseKeyPair`.
- Refresh rotation uses atomic compare-and-swap (`MarkTokenRotatedAtomic`) to prevent reuse races — always prefer this over the non-atomic `MarkTokenRotated` when adding new call sites.
- Claims carry both a sliding expiry (`AccessExpiryDuration`/`RefreshExpiryDuration`) and an absolute `mle` (max lifetime expiry) claim; both are validated on verify.
- Errors returned by verify/revoke/rotate wrap the sentinels in `gourdiantoken.errors.go` — match with `errors.Is`, not string comparison.

### Test file organization

Tests are split by concern rather than mirroring source files 1:1: `token.creation_test.go`, `token.verification_test.go`, `token.verification_token_test.go` (the verification-token type specifically, despite the similar name to the previous file), `token.revocation_test.go`, `token.rotate_test.go`, `revocation.rotation_test.go`, `concurrency_test.go`, `cryptographic_test.go` (algorithm/key handling), `config.validation_test.go`, `edge.case_test.go`, `integration_test.go`, `gourdiantoken.repository_test.go` (cross-backend repository contract tests), `gourdiantoken.factories_test.go` (factory constructors), `gourdiantoken.errors_test.go` (sentinel-error `errors.Is` checks), `gourdiantoken.close_test.go` (`Close()` idempotency and goroutine-stop behavior), `gourdiantoken.repository.mongo_test.go` (Mongo-only regression test for the transactional `MarkTokenRotatedAtomic` duplicate-key race), `logger_test.go`, `gourdiantoken.benchmark_test.go`.

A second group targets specific coverage gaps and is named after the source file it covers rather than a concern: `gourdiantoken.keys_test.go`, `gourdiantoken.maker_test.go`, `gourdiantoken.validation_test.go`, `gourdiantoken.repository.coverage_test.go` (cross-backend coverage gaps, e.g. re-marking an expired rotation entry, Redis TTL/cleanup edge cases), `gourdiantoken.repository.postgres_test.go` and `gourdiantoken.repository.redis_test.go` (construction-failure and post-close-operation paths for those two backends specifically). Prefer this pattern — a `<sourcefile>_test.go` targeting one uncovered branch — over stretching an existing concern-based file when closing a coverage gap that doesn't fit its themes.

Shared setup helpers live in `token.test.helper_test.go` (test-time maker/repo factories) and `token.bench.helper_test.go` (benchmark equivalents) — extend these rather than duplicating setup in individual test files.

### In-progress work

Initiatives that touch multiple stages are tracked as standalone plan documents in `docs/plan/<topic>-plan.md`, checked into the repo so they survive across sessions (mirrors `ECOSYSTEM_PLAN.md` at the repo root, which used the same format for the now-complete pgx+sqlc/coverage initiative across the whole gourdian25 workspace). Check `docs/plan/` before assuming a half-finished-looking feature is abandoned rather than mid-stage — e.g. as of this writing, `docs/plan/multi-tenant-support-plan.md` tracks adding an opt-in `MultiTenantEnabled` config flag and `tid` claim; Stage 1 has landed in `gourdiantoken.config.go`/`.claims.go`/`.errors.go`/`.interfaces.go`/`.maker.go`/`.validation.go` but not yet in `example/example.go` or the ~245 existing `CreateAccessToken`/`CreateRefreshToken` call sites across the test suite, so `go build ./...` currently fails on the `example` package specifically (the root package alone builds clean) until that mechanical rewrite lands.
