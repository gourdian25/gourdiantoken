# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

`gourdiantoken` is a single-package Go library (`package gourdiantoken`, module `github.com/gourdian25/gourdiantoken`) providing JWT access/refresh token creation, verification, revocation, and rotation, with pluggable storage backends. There is no `main` package other than the demo in `example/`.

## Commands

Build/test tooling is centralized in the `Makefile`; use it rather than raw `go` invocations where a target exists.

- `make test` — run all tests + benchmarks (`go test -count=1 -timeout=5m -cover ./... -bench=. -benchmem`)
- `make race` — run tests with `-race`
- `go test -run TestName ./...` — run a single test
- `go test -run TestName/SubtestName ./...` — run a specific subtest (many tests are table-driven over repository backends, see below)
- `make bench` / `make bench-<Name>` — run all/one benchmark
- `make coverage` / `make coverage-summary` / `make coverage-check` — coverage report / summary / 70% threshold gate
- `make vet` / `make lint` (golangci-lint) / `make staticcheck` / `make fmt` (goimports + gofmt) / `make quality` (all of the above)
- `make precommit` — clean, fmt, vet, lint, coverage-check
- `make prerelease` — precommit checks plus race detector, run before tagging a release

### Backend-dependent tests require live services

`token.test.helper_test.go`'s `getTestRepositoryFactories()` drives every repository-backed test (in `gourdiantoken.repository_test.go`, `gourdiantoken.factories_test.go`, etc.) across all four backends via `t.Run(name, ...)` subtests: `Memory`, `Redis`, `MongoDB`, `GORM`. The non-Memory factories connect to **real local services** with hardcoded connection info and will fail (not skip) if unavailable:

- Redis: `localhost:6379`, password `redis_password`, DB `15`
- MongoDB: `mongodb://root:mongo_password@localhost:27018/?directConnection=true`, database `gourdian_test` — must run as a replica set (even single-node); a standalone MongoDB doesn't support the transactions used when `NewMongoTokenRepository` is constructed with `useTransactions=true`. Port `27018`, not Mongo's default `27017`: on this project's dev machine, Docker Desktop's own port-forwarding for `27017` got stuck pointing at an orphaned mongod and didn't clear even after container recreation, `wsl --shutdown`, and a full Docker Desktop restart — `27018` sidesteps it. `directConnection=true` is required because the single-node replica set member is registered under its own container-internal hostname, which only resolves inside Docker's network; without it, the driver's topology discovery gets stuck in `ReplicaSetNoPrimary` trying to reach that unresolvable hostname. See `plan.md`'s "Mongo verification gap" note for the full diagnosis.
- PostgreSQL (via GORM): `host=localhost user=postgres_user password=postgres_password dbname=postgres_db port=5432 sslmode=disable` — schema is auto-created; `NewGormTokenRepository` calls `db.AutoMigrate` itself, no manual migration needed

There is no docker-compose file in this repo — these services must be started/provided externally before running the full suite. To iterate on logic that doesn't touch storage, scope test runs to the `Memory` subtest (e.g. `go test -run TestMarkTokenRevoke_SuccessAccessToken/Memory ./...`) to avoid needing all three services up.

## Architecture

### File layout (single package, split by concern)

The core was originally one `gourdiantoken.go` file and has since been split; there is no file by that name anymore.

- `gourdiantoken.config.go` — `TokenType`/`SigningMethod`/claim-key constants and `GourdianTokenConfig`.
- `gourdiantoken.claims.go` — `AccessTokenClaims`, `RefreshTokenClaims`, `AccessTokenResponse`, `RefreshTokenResponse`.
- `gourdiantoken.interfaces.go` — the `TokenRepository` and `GourdianTokenMaker` interfaces, plus `GourdianTokenMakerCloser` (an optional interface for makers that support stopping background goroutines, kept separate so adding it doesn't break external `GourdianTokenMaker` implementers).
- `gourdiantoken.maker.go` — `JWTMaker` (the concrete `GourdianTokenMaker`/`GourdianTokenMakerCloser` implementation): constructors (`NewGourdianTokenMaker`, `DefaultGourdianTokenMaker`), the `Option`/`WithLogger` functional-option, `Close()`, create/verify/revoke/rotate methods, and the cleanup goroutines.
- `gourdiantoken.validation.go` — `validateConfig`, `validateAlgorithmAndMethod`, claims map conversion (`toMapClaims`, `mapToAccessClaims`, `mapToRefreshClaims`) and `validateTokenClaims`.
- `gourdiantoken.keys.go` — the six PEM key parsers (one per asymmetric algorithm family) sharing `decodePEMBlock`, plus `checkFilePermissions`.
- `gourdiantoken.errors.go` — sentinel errors for `errors.Is` (`ErrTokenRevoked`, `ErrTokenRotated`, `ErrTokenExpired`, `ErrInvalidSignature`, `ErrInvalidToken`, `ErrInvalidClaims`, `ErrTokenRepositoryRequired`, `ErrMissingExpClaim`, `ErrTokenMaxLifetimeExceeded`). Wrapped error messages keep their original text ahead of the sentinel (e.g. `"token has been revoked: %w"`), so existing string-matching callers still work.
- `gourdiantoken.factories.go` — convenience constructors (`NewGourdianTokenMakerNoStorage`, `...WithMemory`, `...WithGorm`, `...WithMongo`, `...WithRedis`) that wire a `JWTMaker` to a specific `TokenRepository` implementation.
- `gourdiantoken.repository.{inmemory,redis,gorm,mongo}.imp.go` — one `TokenRepository` implementation per backend. All four implement the same interface (`MarkTokenRevoke`, `IsTokenRevoked`, `MarkTokenRotated`, `MarkTokenRotatedAtomic`, `IsTokenRotated`, `GetRotationTTL`, `CleanupExpiredRevokedTokens`, `CleanupExpiredRotatedTokens`) — when changing behavior here, changes typically need to be mirrored across all four for parity (the shared test suite in `gourdiantoken.repository_test.go` exercises all of them identically).
- `docs.go` — package-level documentation only (godoc), no executable logic.
- `version.go` — single `Version` var, bumped alongside the `VERSION` variable in `Makefile` and tagged via `make release`.
- `example/example.go` — standalone runnable demo (`package main`) exercising all four backends and signing methods; not part of the library's test surface.

### Token lifecycle

`JWTMaker` (via `NewGourdianTokenMaker`/`DefaultGourdianTokenMaker` or the `NewGourdianTokenMakerWith*` factories) is the single entry point. Key invariants:

- `TokenRepository` is required only if `RotationEnabled` or `RevocationEnabled` is set in `GourdianTokenConfig`; construction fails otherwise if one of those flags is true and `tokenRepo` is `nil`.
- Enabling rotation/revocation spins up background goroutines (`cleanupRotatedTokens`, `cleanupRevokedTokens`) tied to an internal `context.WithCancel`, running on `config.CleanupInterval`. `JWTMaker.Close()` (part of `GourdianTokenMakerCloser`) cancels that context and is idempotent (`sync.Once`) — since `GourdianTokenMaker` callers may hold the interface rather than the concrete type, check for the optional interface before calling it: `if closer, ok := maker.(gourdiantoken.GourdianTokenMakerCloser); ok { closer.Close() }`.
- `SigningMethod` (`Symmetric`/`Asymmetric`) must match `Algorithm` (HS* vs RS*/ES*/PS*/EdDSA) — validated in `validateAlgorithmAndMethod`; asymmetric methods load PEM keys from `PrivateKeyPath`/`PublicKeyPath` via `initializeKeys`/`parseKeyPair`.
- Refresh rotation uses atomic compare-and-swap (`MarkTokenRotatedAtomic`) to prevent reuse races — always prefer this over the non-atomic `MarkTokenRotated` when adding new call sites.
- Claims carry both a sliding expiry (`AccessExpiryDuration`/`RefreshExpiryDuration`) and an absolute `mle` (max lifetime expiry) claim; both are validated on verify.
- Errors returned by verify/revoke/rotate wrap the sentinels in `gourdiantoken.errors.go` — match with `errors.Is`, not string comparison.

### Test file organization

Tests are split by concern rather than mirroring source files 1:1: `token.creation_test.go`, `token.verification_test.go`, `token.revocation_test.go`, `token.rotate_test.go`, `revocation.rotation_test.go`, `concurrency_test.go`, `cryptographic_test.go` (algorithm/key handling), `config.validation_test.go`, `edge.case_test.go`, `integration_test.go`, `gourdiantoken.repository_test.go` (cross-backend repository contract tests), `gourdiantoken.factories_test.go` (factory constructors), `gourdiantoken.errors_test.go` (sentinel-error `errors.Is` checks), `gourdiantoken.close_test.go` (`Close()` idempotency and goroutine-stop behavior), `gourdiantoken.benchmark_test.go`. Shared setup helpers live in `token.test.helper_test.go` (test-time maker/repo factories) and `token.bench.helper_test.go` (benchmark equivalents) — extend these rather than duplicating setup in individual test files.
