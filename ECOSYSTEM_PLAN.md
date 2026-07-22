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
| Stage 2 | grevents, grpolicy, grcache | ✅ Done |
| Stage 3 | graudit | ✅ Done |
| Stage 4 | grnoti (touch-ups) | ✅ Done |

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

## Stage 2 (Tier 1) — grevents, grcache, grpolicy ✅ Done

**grevents**: folded `conformance/conformance.go` into root-package
`contract_bus_test.go` (`runBusContract`/`TestBus_Contract`), dropping the
vestigial unused `RunOption` extension point in the process. Found and
fixed a real bug: `Bus.Close()` never closed a caller-supplied
`DeadLetterSink` for a sync-only bus (sync mode never delivers through it,
but a caller who wired one up via `WithDeadLetterSink` still expects
`Close` to release it). Coverage raised 94.9% → **100%**. Stale
"pre-implementation" `CLAUDE.md` (the repo was already fully built)
rewritten to describe the actual shipped architecture. `make ci`/race
clean.

**grpolicy**: folded `conformance/conformance.go` into root-package
`contract_engine_test.go` (`runEngineContract`/`TestEngine_Contract`),
same vestigial-option cleanup. Found and fixed two real bugs: (1)
`evalArray`/`evalArgs` didn't stub not-yet-reached elements/arguments in
`Decision.Trace` when an earlier one failed, unlike every binary operator's
own eval* function, which already did this for its unevaluated sibling —
inconsistent partial-trace shape; (2) `Compile`'s non-identifier-call-target
rejection (e.g. `a.b()`) wrapped no sentinel at all, so
`errors.Is(err, ErrCompileFailed)` returned false for it. Coverage raised
88.7% → **99.8%** (two branches accepted as permanent gaps: a structurally
unreachable defensive check in `policyCache.put`, and `noopLogger`'s
empty-bodied methods — a Go tooling artifact for zero-statement functions).
`make ci`/race clean.

**grcache** (biggest lift in this tier): flattened `postgres/`,
`mongostore/`, `redis/`, `memcached/`, `memory/`, and `conformance/` into
the root package (`postgres.go`, `mongo.go`, `redis.go`, `memcached.go`,
`memory.go`, `contract_cache_test.go`) — each backend's former exported
`Cache` struct renamed to an unexported `<backend>Cache` to avoid colliding
with the shared `Cache` interface now in the same package; the
`mongostore`→`mongo` rename-for-collision issue resolved incidentally,
since a file isn't a separate importable package. Replaced GORM with
pgx/v5 + sqlc (`internal/postgresdb`, schema for `grcache_entries`/
`grcache_entry_tags`, advisory-lock schema-apply pattern matching
gourdiantoken/grnoti; `expires_at` changed from GORM's zero-time convention
to a genuine nullable `TIMESTAMPTZ`). Fixed the latent Makefile
`coverage-check` bug (iterated over a stale `./mongo` entry that never
matched the actual `mongostore` directory, silently under-measuring
coverage every run) — moot now that there's one package. Fixed the real
memcached value-key prefix gap (cache values were stored bare; only
tag-list keys were namespaced) by adding `memcachedValuePrefix =
"grcache:val:"`, applied consistently to Get/Set/Delete/Exists/
InvalidateTag. Re-verified the "redis test fragility" flagged during
research predates Stage 0's Docker standardization — confirmed genuinely
passing against the now-standardized shared container, not by accident.
Adopted the skip-gracefully convention across every networked backend's
test factory. Coverage raised 84.7-96.7% (per-subpackage) →
**95.6%** (root package, aggregate) with all 5 backends genuinely live
against real Docker containers. `make ci`/race clean; `example/` runs
successfully against all 5 live backends.

## Stage 3 (Tier 2) — graudit ✅ Done

Flattened `postgres/`, `mongostore/`, `memory/`, `conformance/` into the
root package (`postgres.go`, `mongo.go`, `memory.go`,
`contract_audit_test.go`), the same shape every other flattened repo in
the ecosystem now uses. Each backend's concrete `AuditLog` implementation
had to be renamed (`memoryAuditLog`/`postgresAuditLog`/`mongoAuditLog`,
unexported) since all three previously named their own struct plain
`AuditLog` in separate packages — a collision once merged into one
package alongside the shared, exported `AuditLog` interface.

Replaced GORM with pgx/v5 + sqlc (`internal/postgresdb`, generated from a
new `schema.sql`/`queries/audit.sql`), matching gourdiantoken's, grnoti's,
and grcache's own Postgres backend pattern. `EntryID` is still explicitly
assigned inside the same `pg_advisory_xact_lock`-held transaction as
before (never `BIGSERIAL`); a *second*, distinct advisory lock
(`grauditSchemaLockKey`, `5_198_204_733`) now serializes schema
application at connect time, separate from the existing per-Record
`chainLockKey`. `QueryFilter`'s dynamic multi-condition filtering (any
combination of ActorID/EntityType/EntityID/From/To/Limit) was implemented
as one sqlc query using `sqlc.narg()` nullable parameters — no prior repo
in the ecosystem had needed this pattern before.

Updated graudit's Mongo backend test suite to the workspace's standardized
**authenticated** single-node replica set (`root`/`mongo_password` on
27018), matching grcache's/gourdiantoken's own connection string exactly,
while preserving the separate, deliberately no-auth standalone container
(27019) required by `TestNewMongoAuditLog_RequiresReplicaSet` — that
test's hard-fail-if-skipped nature remains a documented, intentional
exception to the skip-gracefully convention adopted everywhere else.

**A real test-coverage gap found and fixed** (not a behavioral bug — the
implementation was already correct): `Verify()`'s "Check B" (chain-linkage
integrity — each entry's stored `PrevHash` must equal the immediately
preceding entry's stored `Hash`) had no dedicated regression test on any
of the three backends. The shared contract suite's `VerifyDetectsTamper`
scenario only ever corrupts a stored entry's `Payload` (exercising "Check
A", per-entry hash integrity) — never `PrevHash` directly. Added
`Test<Backend>AuditLog_VerifyDetectsChainLinkageBreak` for all three
backends, directly corrupting `PrevHash` via each backend's own
tamper mechanism (raw SQL, raw driver call, direct struct mutation) and
confirming `Verify` correctly localizes the break.

Also removed two lines of genuinely dead code found during the coverage
pass: `encodeCanonical`'s two `json.Marshal`-of-a-plain-Go-string error
checks can never fail (marshaling a Go string never errors) — deleted
per the "don't add error handling for scenarios that can't happen"
convention, rather than defended with a permanent-gap comment.

Coverage raised 89.9%/91.7% (previous per-subpackage numbers) → **95.2%**
merged, via a new white-box `internal_coverage_test.go` using the
established close-the-connection-out-from-under-it technique plus three
deliberate-fault-injection tests unique to this repo: a Postgres `CHECK
(false)` constraint added directly to reject an insert mid-Record, a
MongoDB collection validator added directly to reject the chain-state
upsert, and a table dropped out from under an already-open connection
pool (each restoring the schema/removing the constraint/validator
afterward so later tests aren't affected). A handful of branches remain
documented as permanently unreachable (e.g. `DecodeStoredPayload`'s error
branch on the Postgres backend — a `jsonb` column guarantees valid JSON
at the type level, so SQL-level corruption can never produce an
undecodable payload there) rather than force-covered.

`go build`/`go vet`/`golangci-lint run` (0 issues, including one new
class of finding — gosec G115 flagging the `EntryID`(uint64)⟷Postgres-
`bigint`(int64) conversions introduced by the pgx rewrite, fixed via two
small, well-documented `pgEntryID`/`toPgEntryID` helpers rather than
scattering `//nolint` comments) and `-race` all clean. `example/` runs
correctly end-to-end. `bark tag` run from the repo root correctly
prepended `// File:` headers to all four sqlc-generated files with no
debris.

## Stage 4 (Tier 3) — grnoti touch-ups ✅ Done

Already flat, already pgx+sqlc — the only structural work was adopting
Stage 0's standardized authenticated containers. `MongoTokenStoreConfig`/
`MongoDLQHandlerConfig`/`RedisRateLimiterConfig`/`grcache.RedisConfig`
already accepted arbitrary URIs/passwords, so no production code needed
changing for auth — only test constants: `testMongoURI`
(`tokenstore.mongo_test.go`) moved from the old no-auth
`mongodb://localhost:27017` to the workspace-standard
`mongodb://root:mongo_password@localhost:27018/?directConnection=true`
(confirmed, like graudit/grcache/gourdiantoken, that `directConnection=
true` alone suffices — no `replicaSet=rs0`/`authSource=admin` needed on
the connection string itself, even though the container is a real
authenticated replica set); a new `testRedisPassword` constant
(`ratelimiter.redis_test.go`) wired into every Redis-backed test
(rate-limiter and the `grcache`-backed cache adapter tests). `CLAUDE.md`'s
connection-info table updated to drop the "not yet wired in" caveats it
had carried since Stage 0.

Also found and fixed along the way: `cache_test.go`/`cache.redis_test.go`/
`service_test.go`/`example/main.go` were still importing grcache's
pre-flattening `grcache/memory`/`grcache/redis` subpackages — stale since
Stage 2 flattened grcache into a single package and tagged it as v0.2.0
(the version grnoti's `go.mod` already pinned). These were realigned to
`grcache.NewMemoryCache`/`grcache.NewRedisCache`.

Coverage was 94.9% before this stage; two genuine small gaps were closed
(`fcmPayloadValidator.EstimateSize`'s `ImageURL`-set branch untested;
`applyPostgresSchema`'s `pool.Acquire` failure branch untested, closed via
a closed-pool fault-injection test) bringing it to 95.1% — `COVERAGE_MIN`
in the `Makefile` raised from 90 to 95 to match every other repo's own
gate. Two remaining error branches in `applyPostgresSchema` (the
advisory-lock and schema-apply `Exec` calls) are left as a documented,
accepted gap — reachable only via a connection breaking mid-function,
which isn't deterministically triggerable against a live Postgres without
a flaky timing race (confirmed empirically: a canceled/deadline context
sometimes fails at `Acquire` and sometimes at the first `Exec`,
non-deterministically, depending on timing).

`docs/postgres.md` doesn't reference Mongo/Redis at all, so it needed no
changes. Full validation: `go build`/`vet`/`golangci-lint` (0 issues),
`go test -race .` clean, `make coverage-check` → "OK: 95.1%", every
Mongo- and Redis-backed test passing against the real authenticated
containers (not skipped), `example/` builds and runs end-to-end, `bark
check` reports all headers current.

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
