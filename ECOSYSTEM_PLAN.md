# File: ECOSYSTEM_PLAN.md

# Gourdian ecosystem plan: flatten packages, replace GORM with pgx+sqlc, standardize Docker test infra, reach 95% coverage

> Source of truth for this initiative. Mirrored from
> `/Users/varun/.claude/plans/how-can-we-fix-lively-squirrel.md`, kept here so
> it travels with the repo. Update the tracker below as stages complete —
> **pause after each stage for review before starting the next.**

## Tracker

| Stage | Repos | Status |
|---|---|---|
| Stage 0 | Docker test infra (all repos) | ✅ Done |
| Stage 1 | grlog, gourdiantoken | ✅ Done |
| Stage 2 | grevents, grpolicy, grcache | ⬜ Not started |
| Stage 3 | graudit | ⬜ Not started |
| Stage 4 | grnoti (touch-ups) | ⬜ Not started |

## Context

Seven sibling Go modules under `/Users/varun/Dev/gourdian25/` (grlog, grnoti, graudit,
grcache, grpolicy, grevents, gourdiantoken) have grown independently and now
disagree on shape: some are flat single packages (grlog, grnoti, gourdiantoken),
others split each storage backend into its own subpackage (graudit, grcache) — a
pattern originally chosen deliberately (keep unused driver deps out of a
consumer's build) but which the user now wants abandoned everywhere in favor of
grnoti's flat, `<concern>.<backend>.go`-per-file shape. Two repos (graudit,
grcache) still use GORM for their Postgres backend; grnoti already proved the
pgx/v5+sqlc pattern (advisory-lock-guarded schema apply,
`PostgresConfig{DSN|Pool}` injection, ownership-aware `Close()`). Every repo also
documents its own Docker containers for local test services, and these
collide when run together (four repos want Postgres on 5432; three want
Mongo on 27018 with incompatible auth/replica-set combinations). The goal:
one consistent shape, one consistent Postgres approach, one standardized
Docker test-infrastructure story, and ≥95% real test coverage, across all
seven repos — fixing any real bugs found along the way — executed stage by
stage so a dependency is always updated before its dependents.

## Confirmed facts from research (don't re-derive these)

**Dependency graph** (from each repo's own go.mod, no cycles):
```
Tier 0 (no gourdian25 deps):     grlog, gourdiantoken
Tier 1 (-> grlog only):          grevents, grcache, grpolicy (grpolicy's core lib
                                  doesn't even import grlog — only its example/ does)
Tier 2 (-> grevents, grlog):     graudit
Tier 3 (-> grcache, grevents):   grnoti
```

**Per-repo state at plan creation:**

| Repo | Shape then | GORM? | Coverage then | Docker then |
|---|---|---|---|---|
| grlog | flat, 0 deps | no | 88.3% | none (pure lib) |
| gourdiantoken | flat root pkg, contract tests already inline | yes, isolated to one file, took caller-built `*gorm.DB` | Memory-subtest only 26.5% seen | pg 5432/`postgres_db`, redis 6379 (pw `redis_password`, DB 15), mongo 27018 replica-set+auth |
| grevents | flat + `conformance/` + `example/`, no DB at all | no | 95.2% (already at target) | none |
| grpolicy | flat + `conformance/` + `example/`, no DB | no | 88.7% on `.` | none |
| grcache | root + 5 backend subpkgs (`postgres/`, `mongostore/`, `redis/`, `memcached/`, `memory/`) + `conformance/` + `example/` | yes, isolated to `postgres/postgres.go`, 100% query-builder (no raw SQL) | root 100%, memory 96.7%, redis 86.1% (fragile) | pg 5432/`grcache_test`, redis 6379 (pw `redis_password`, DB 14), mongo 27018 auth+no-replset, memcached 11211 |
| graudit | root + 3 backend subpkgs (`postgres/`, `mongostore/`, `memory/`) + `conformance/` + `example/` | yes, isolated to `postgres/postgres.go`, one raw `Exec` (`pg_advisory_xact_lock`) | root 89.9%, memory 91.7% | pg 5432/`graudit_test`, mongo 27018 replica-set **no auth**, plus mongo 27019 standalone **no auth** |
| grnoti | flat, already pgx+sqlc | no | 94.9% | pg/redis/mongo/kafka on 5432/6379/27017/9092, mongo currently **no-auth standalone** |

Both GORM usages were cleanly isolated (one file each, public interface untouched,
`pgx/v5 v5.10.0` already resolved as an indirect dep via GORM's driver in every
GORM-using go.mod) — a low-risk swap in both repos, not a rewrite.

**User decisions locked in (apply throughout, don't re-ask):**
- Docker: **one shared container per backend type** for the whole workspace,
  each repo gets its own database/keyspace/DB-index inside it.
- Mongo: **authenticated single-node replica-set is the standard** (matches
  grcache/gourdiantoken already). A **second, separate no-auth standalone**
  Mongo container is kept solely for graudit's "must reject standalone"
  regression test. grnoti and graudit's primary Mongo usage both need
  updating to add auth.
- `conformance/` packages (grcache, graudit, grpolicy, grevents) **get folded
  into root-package test files** too — full parity with grnoti's shape.
- Module versioning: bump major version only when justified and cheap to do;
  if a repo is private/low-consumer, prefer keeping the existing module major
  version even across breaking changes rather than forcing a bump (confirmed
  for gourdiantoken: stayed on `/v2`, see Stage 1 notes).
- Execution: **pause after each stage below for review** before starting the
  next one.

## Addendum: table/collection/key naming audit (informs Stages 1-2)

| Repo | Postgres tables | Mongo default collection | Redis key prefix | Memcached key prefix |
|---|---|---|---|---|
| grnoti | `grnoti_tokens`, `grnoti_preferences`, `grnoti_experiments`, `grnoti_dlq` | `grnoti_tokens`, `grnoti_dlq` | n/a | n/a |
| graudit | `graudit_entries` | `graudit_entries` (+ `_chain_state` suffix) | n/a | n/a |
| grcache | `grcache_entries`, `grcache_entry_tags` | `grcache_entries` | `grcache:val:`, `grcache:tag:` | `grcache:tag:` on tag-list keys only — **cache value key has no prefix**, the one real gap |
| gourdiantoken (before Stage 1) | `revoked_tokens`, `rotated_tokens` — **not prefixed** | `revoked_tokens`, `rotated_tokens` — **not prefixed** | `revoked:access:`, `revoked:refresh:`, `revoked:verification:`, `rotated:` — **not prefixed** | n/a |

grnoti, graudit, and grcache already converged on prefixing every
table/collection with their own repo name — valuable for readability and as a
second layer of protection. gourdiantoken was the outlier; fixed in Stage 1.
grcache's memcached value-key prefix gap remains for Stage 2.

## Addendum: README.md + Makefile updates (every repo with a backend)

**README.md**: mirror the CLAUDE.md docker-section rewrites into each repo's
README (grcache's and graudit's have stale pre-standardization `docker run`
blocks; grnoti's and gourdiantoken's gain a short section pointing at
`make docker-up`).

**Makefile**: `docker-up`/`docker-down` targets, idempotent
(`docker inspect ... || docker run ...`, then `docker start` to cover
already-exists-but-stopped), starting only the containers that specific repo
needs. `docker-down` stops (not removes) containers. Update each repo's
`help` target in its own existing style.

---

## Stage 0 — Standardize Docker test infrastructure ✅ Done

One documented set of containers, re-stated identically in every repo's own
CLAUDE.md "Starting the backends" section:

- **Postgres**: one container, `5432`, `postgres_user`/`postgres_password`.
  One database per repo: `grnoti_test`, `graudit_test`, `grcache_test`,
  `gourdiantoken_test`.
- **Redis**: one container, `6379`, `requirepass redis_password`. One DB
  index per repo (grcache=14, gourdiantoken=15; grnoti updated to use the
  password).
- **MongoDB**: one **authenticated single-node replica-set** container,
  `27018`, `root`/`mongo_password`, `directConnection=true`. One database per
  repo. PLUS a second, minimal **no-auth standalone** Mongo container, `27019`,
  used only by graudit's replica-set-requirement regression test.
- **Kafka**: unchanged, `9092`, grnoti only.
- **Memcached**: unchanged, `11211`, grcache only.

Includes: grnoti's Mongo connection config updated to support auth; every
repo's CLAUDE.md connection-info table and `*_test.go` connection constants
updated; `docker-up`/`docker-down` Makefile targets added; READMEs updated.
Verified by starting all containers and running every repo's full test suite
once with real (not skipped/failed) numbers.

## Stage 1 (Tier 0) — grlog, gourdiantoken ✅ Done

**grlog**: no structural change needed (already flat, no GORM). Full
bug/best-practices read-through of `grlog.go`/`slog.go` — no bugs found.
Coverage raised 88.3% → **95.0-95.1%**. All tests/race/lint clean.

**gourdiantoken**:
- Replaced `gourdiantoken.repository.gorm.imp.go` with
  `gourdiantoken.repository.postgres.imp.go` (pgx/v5 + sqlc), pool-injection
  only (`NewPostgresTokenRepository(ctx, pool *pgxpool.Pool)`), schema applied
  via advisory-lock pattern (`gourdiantokenSchemaLockKey`).
- New sqlc scaffolding: `sqlc.yaml`, `internal/postgresdb/schema.sql` +
  `queries/tokens.sql`, generated `internal/postgresdb/{db,models,querier,tokens.sql}.go`.
  Never hand-edit generated files — `sqlc generate` after editing schema/queries.
- Renamed `NewGourdianTokenMakerWithGorm` → `NewGourdianTokenMakerWithPostgres`.
- Storage renamed to the `gourdiantoken_`/`gourdiantoken:` convention:
  Postgres tables `gourdiantoken_revoked_tokens`/`gourdiantoken_rotated_tokens`;
  Mongo collections to match; Redis prefixes
  `gourdiantoken:revoked:{access,refresh,verification}:`, `gourdiantoken:rotated:`.
  **Breaking, non-in-place rename** — migration warning documented in
  CHANGELOG.md and README.md.
- `token.test.helper_test.go` factories switched to skip-gracefully
  (`t.Skipf`) on unreachable backend, matching grnoti's convention.
- **Module path decision**: kept `github.com/gourdian25/gourdiantoken/v2`
  (NOT bumped to `/v3`) despite the breaking storage-rename change, per
  explicit user instruction — repo is private with few consumers. `Version`
  bumped to `v2.2.0` instead. Rationale documented in CHANGELOG.md.
- Coverage raised from an unmeasured/~84% baseline to **95.4-95.8%** on `.`,
  confirmed via a full `make ci` run (clean → deps → vet → lint → test+bench
  → coverage-check → race), all green.
- **Found, documented (not silently fixed)**: `MarkTokenRotatedAtomic` is
  inconsistent across backends — Postgres/MongoDB's `INSERT ... ON CONFLICT
  DO NOTHING` / upsert treats *any* existing rotation record as a conflict
  regardless of whether it's logically expired, while Memory/Redis correctly
  allow re-marking an expired entry. Inherited unchanged from the original
  GORM code; narrow in practice; flagged as a known issue in CHANGELOG.md
  rather than folded silently into this coverage pass (fixing it changes
  atomic-rotation semantics for two backends).
- Observed (not fixed): a handful of intermittent, pre-existing test flakes
  under heavy full-suite load on shared Docker containers (never
  reproducible in isolation) — attributed to environmental timing, not a
  regression from this stage's changes.

## Stage 2 (Tier 1) — grevents, grcache, grpolicy ⬜ Not started

**grevents**: already flat, no DB, already 95.2% coverage. Work: read
`conformance/conformance.go` and fold it into root-package test files
(mirroring grnoti's `contract_*_test.go` pattern); general bug-fix pass.

**grpolicy**: fold `conformance/` into root-package test files the same
way; raise coverage 88.7% → 95%+; general bug-fix pass. No DB, no GORM —
smallest repo in this stage.

**grcache** (biggest lift in this tier): flatten `postgres/`, `mongostore/`,
`redis/`, `memcached/`, `memory/`, and `conformance/` into the root package.
Single concern ("cache"), so files become `postgres.go`, `mongo.go`,
`redis.go`, `memcached.go`, `memory.go` directly (flattening incidentally
resolves the `mongo`→`mongostore` rename-for-collision issue). Replace GORM
with pgx+sqlc (new schema.sql for `cache_entry`/`cache_entry_tag`, same
advisory-lock schema-apply pattern). Fix the latent bug in Makefile's
`coverage-check` (`./mongo` doesn't exist, silently mis-measuring coverage)
— moot once flattened. Standardize Docker info; fix redis test's fragile
pass (currently working by accident against a differently-configured Redis);
adopt skip-gracefully convention; add memcached value-key prefix (mirroring
`redis.go`'s `valuePrefix`/`tagPrefix` pattern — the one internal naming gap
found); raise coverage to 95%+ with all 5 backends genuinely live; general
bug-fix pass.

## Stage 3 (Tier 2) — graudit ⬜ Not started

Flatten `postgres/`, `mongostore/`, `memory/`, `conformance/` into root
package (`postgres.go`, `mongo.go`, `memory.go`). Replace GORM with
pgx+sqlc (schema.sql for the audit-entry table; the one existing raw
`pg_advisory_xact_lock` Exec carries over naturally since everything is
raw SQL via pgx now anyway). Update graudit's Mongo backend to the
authenticated-replica-set standard for its primary usage, while preserving
its **separate, deliberate** standalone-required regression test pointed
at Stage 0's no-auth standalone container — this test's hard-fail-if-
skipped nature is a documented, intentional exception to the
skip-gracefully convention adopted everywhere else. Fix stale
`CLAUDE.md`/`docs/architecture.md` `mongo`→`mongostore` references (moot
post-flattening — rewrite to describe the new flat shape + pgx backend).
Raise coverage 89.9%/91.7% → 95%+ merged, with real postgres/mongo numbers
against live standardized containers. General bug-fix pass.

## Stage 4 (Tier 3) — grnoti touch-ups ⬜ Not started

Already flat, already pgx+sqlc, already 94.9% coverage — only remaining
work is adopting Stage 0's standardized authenticated Mongo (currently
assumes no-auth standalone): update the Mongo connection config in
`tokenstore.mongo.go`/`dlq.mongo.go`-equivalent, its `CLAUDE.md` docker
commands, and test constants. Nudge coverage past 95% if any easy gaps
remain. Confirm `docs/postgres.md` still reads correctly — no changes
expected there.

## Cross-cutting, every stage

- `go build ./...`, `go vet ./...`, `golangci-lint run` (0 issues) per repo.
- Full test suite + `-race` suite against Stage 0's live standardized
  containers — real numbers, not skips, for every backend.
- Coverage measured on real library code only (`.`, not `./...` — matches
  grnoti's own documented convention of excluding generated/example
  packages from the headline number). **95% is the enforced gate** (see
  each repo's `Makefile` `COVERAGE_MIN`/`coverage-check` target).
- Each repo's own `example/` program still builds and runs after its
  constructor-signature changes (GORM removal, package flattening).
- `bark` header integrity preserved on every touched/new file; each repo's
  own `CHANGELOG.md` gets an entry in its existing style.
- Stop and report back after each stage; do not start the next stage
  without confirmation.
