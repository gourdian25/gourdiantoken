# gourdiantoken Improvement Plan (Consolidated, Verification Pass 3)

## ⚠️ IMPLEMENTATION STATUS — READ THIS FIRST BEFORE DOING ANYTHING ELSE

**Phases 0, 1, 2, 3, 4, and 5 are all implemented and fully verified.** Release readiness (go.mod `/v2` path, README/CHANGELOG, `.goreleaser.yml`) is also done as of the third 2026-07-04 update below. Do not re-do the file split or re-apply any of the fixes described below — they're already in the tree. **What's left is purely the release mechanics** (merge to `dev`, tag + goreleaser, merge to `master`) — see "Release plan" near the bottom of this document. This section is the handoff note for continuing in a new environment/session.

**2026-07-04 update #3 (release readiness):** Decided against a separate interim v1.1.0 release — Phases 1-5 ship as one combined v2.0.0, since Phase 5 already landed on `dev#manish#major_fixes` per update #2's instruction. Workflow agreed: merge to `dev` → tag + `goreleaser` release → merge to `master`, with a documentation review first. Completed as part of that review: `go.mod`'s module path fixed to `github.com/gourdian25/gourdiantoken/v2` (closing the gap update #2 flagged), cascaded to `example/example.go`'s import and every import/badge/doc-link in `README.md`; four real bugs fixed in README's Gin middleware code samples (`claims.Subject.String()`/`claims.SessionID.String()` — `.String()` doesn't exist on `string`, these were stale from the pre-migration API and would have been compile errors if copy-pasted); stale "UUIDs for users/sessions" / "UUID format validation" wording updated to reflect opaque strings; Go version badge/requirement corrected from 1.18 to 1.24 (matching `go.mod`'s actual `go 1.24.0`, unrelated to Phase 5 but caught during the same review pass); a new "Migrating from v1.x" section added to the README; `.goreleaser.yml`'s archive file list fixed (`examples/*.go` → `example/*.go` — the plural form matched nothing, so the demo file was never actually being included in release source archives); new `CHANGELOG.md` written covering the full combined v2.0.0 release (breaking changes, all bundled fixes from Phases 1-4, and known-issues-not-fixed carried over from this plan's own flagged items). Full `go build`/`go vet`/`gofmt`/test suite/race detector re-verified clean after all of the above — see the verification block further down.

**2026-07-04 update #2 (Phase 5 implemented):** Phase 5 (UUID → string migration) was implemented this session, **on `dev#manish#major_fixes` directly, not on `dev#manish#remove_uuid`** — explicit user instruction ("we will proceed with the same branch"), overriding this plan's separate-branch design. The stale `dev#manish#remove_uuid` branch was left untouched. Scope executed as specified: `ID`/`Subject`/`SessionID` on both claims structs and `Subject`/`SessionID` on both response structs are now `string`; `CreateAccessToken`/`CreateRefreshToken` take `string` params (interface + `JWTMaker`); `validateUserAndUsername` checks `userID == ""`; `toMapClaims`/`extractCommonClaims` drop `.String()`/`uuid.Parse`; internal jti generation still uses `uuid.NewRandom()` (via `newTokenID`, which now returns `string` — the `.String()` call happens inside the helper rather than at each call site, an equivalent-but-tidier variant of the plan's step 3). `Version`/Makefile `VERSION` bumped to v2.0.0. **Deviations and findings, per this doc's record-don't-silently-fix policy:**

1. **`sid` is NOT non-empty-checked at verification (deviation from step 2's literal text).** Step 2 said to replace all three `uuid.Parse` blocks with non-empty checks, but doing that for `sid` would have made v2 sessionless tokens (created with `sessionID == ""`, which creation explicitly allows) fail verification — in v1 the sessionless roundtrip worked because `uuid.Nil` serialized to a parseable UUID string. So: `jti`/`sub` get non-empty checks (in both `extractCommonClaims` and `validateTokenClaims`); `sid` gets a string type check only, empty allowed. This preserves the create→verify roundtrip for sessionless tokens, which is the behavior-level equivalent of v1's guarantee.
2. **[RESOLVED 2026-07-04, update #3]** The module path now correctly has `/v2`: `go.mod` is `module github.com/gourdian25/gourdiantoken/v2`, cascaded to `example/example.go`'s import, every import/badge/doc link in `README.md`, and the Makefile's `MAIN_PACKAGE`/`MODULE` vars (verified: `make coverage-check`'s test output now correctly shows `github.com/gourdian25/gourdiantoken/v2` as the module path, and the `-ldflags -X` version-stamp target in `make build`/`make install` resolves correctly against it).
3. **Three tests asserted the old UUID-shape validation and were rewritten to v2 semantics** (not just mechanically migrated): `TestInvalidUUIDs` (edge.case_test.go) is now `TestIdentifierClaimValidation` — covers non-UUID strings accepted, empty `jti`/`sub` rejected, empty `sid` accepted, non-string `jti`/`sid` rejected; `TestTokenClaims_Mapping`'s "invalid UUID in map claims" subtest (token.creation_test.go) became two subtests (opaque jti accepted / empty jti rejected); two subtests in token.verification_test.go ("rejects token with invalid UUID", "rejects refresh token with invalid UUID formats") now use empty-string claims as the rejection trigger.
4. **[RESOLVED 2026-07-04, update #3] Verification status — fully green, nothing owed:** `go build ./...`, `go vet ./...`, `gofmt -l`/`goimports -l` all clean. Full suite (`go test -count=1 -timeout=5m -cover ./...`): `ok`, `78.6%` coverage, `77.664s`, all four backends including live Redis/MongoDB/PostgreSQL. Race detector (`go test -race -count=1 -timeout=5m ./...`): `ok`, `85.389s`, zero data races. `make coverage-check`: passes (`78.6` ≥ `70`). `make fmt`/`make vet` (Makefile targets): pass. `make lint` (`golangci-lint`) crashes in this environment with an internal panic (`file requires newer Go version go1.26 (application built with go1.25)`) — a pre-existing tooling-version mismatch in `golangci-lint`'s own binary, unrelated to any change made here; `goreleaser` doesn't invoke this target, so it isn't release-blocking, but worth fixing the local `golangci-lint` install separately. **Also found and fixed while verifying:** the Makefile's `MAIN_PACKAGE`/`MODULE` variables still had the pre-`/v2` path, which would have made `make build`/`make install`'s `-ldflags -X ....Version=...` version-stamp silently target the wrong package path — updated to `github.com/gourdian25/gourdiantoken/v2`. Separately noted, not fixed: the `build` Makefile target itself (`go build ... -o $(BUILD_DIR)/gourdiantoken ./...`) has been broken for at least 20 commits prior to this session — `./...` matches both the root library package (not `package main`) and `example/` (`package main`), and `go build` refuses to write multiple packages to one non-directory `-o` target. Pre-existing, not part of the release-critical path (`precommit`/`prerelease`/`test`/`race` don't use it), left alone.

**2026-07-04 update:** Phase 4 (all 4 items) was completed and fully verified this session, on the same `dev#manish#major_fixes` branch. Two new findings surfaced beyond what Phase 4 originally scoped: a real, pre-existing Redis `Close()` non-idempotency bug (fixed, documented in Phase 4's own section below) and a real race in the `TestClose_StopsCleanupGoroutines` test itself (fixed, see Phase 3b-adjacent test coverage notes / `gourdiantoken.close_test.go`). The full suite (`go test -count=1 -timeout=5m -cover ./...`) and race detector (`go test -race -count=1 -timeout=5m ./...`) both pass cleanly across all four backends (Memory/Redis/GORM/MongoDB) on the user's own machine, with real Redis/MongoDB/PostgreSQL — see "Mongo verification gap" below for the two non-code environment issues (a stuck Docker Desktop port mapping, and a replica-set `directConnection=true` requirement) that had to be resolved to get there. **This session's changes are already committed** (this repo has an external auto-commit hook — see "Where things stand" below for exact commit hashes) and pushed to `origin/dev#manish#major_fixes`.

### Mongo verification gap — RESOLVED 2026-07-04, root cause was a stuck Docker Desktop port mapping, not the code

This took two separate, stacked problems to fully untangle:

1. **This session's own sandbox** (the assistant's Bash tool) turned out to have pre-existing, already-running Redis and PostgreSQL fixtures reachable at the hardcoded `localhost` addresses, but its MongoDB was a bare **standalone, no-auth** mongod unrelated to the user's `gourdian-mongo` container (confirmed via an unauthenticated `hello` returning no `setName`/`hosts`/`me`, and a successful unauthenticated `ListDatabaseNames`). The sandbox has no `docker` group membership, so it could never reach the user's real container directly.
2. **Separately, and this is the one that actually mattered**, the user's *own* `go test` runs — from their own terminal, against their own correctly-configured `gourdian-mongo` container — hit the exact same phantom no-auth standalone mongod on `localhost:27017`. Proven decisively: `docker run --rm --network container:gourdian-mongo mongo:7 mongosh ...` (sharing the container's own network namespace, bypassing the host port-publish entirely) authenticated cleanly and returned a real signed replica-set response — so the container's own config was correct the whole time. But `sudo ss -tlnp | grep 27017` showed a listener on `127.0.0.1:27017` with no attributable owning process, and this phantom regenerated with a fresh `processId` across a container recreation, `wsl --shutdown`, *and* a full Docker Desktop quit/restart — ruling out simple staleness, a native `mongod` service (`systemctl`/`ps aux` both came up empty), and a competing container in another WSL distro (`wsl -l -v` showed 6 running distros, but `docker ps` from every one of them showed the identical single shared container — Docker Desktop's WSL integration shares one engine). The conclusion: Docker Desktop's own internal port-forwarding state for host port `27017` specifically was stuck at a level a normal restart doesn't clear, on this dev machine.

**Resolution the user chose:** stop fighting port 27017 and permanently publish `gourdian-mongo` on **host port 27018** instead (confirmed working immediately, no Docker Desktop factory-reset needed). All hardcoded references across the repo were updated to match: `token.test.helper_test.go`, `token.bench.helper_test.go`, `example/example.go`, `CLAUDE.md`, and this file.

**Second, separate problem, also resolved:** the single-node replica set member registers itself under its own container-internal hostname (e.g. `9698c87b448c:27017`), which only resolves inside Docker's network — the host running the tests can't resolve it. Without any further change, the Go driver does full replica-set topology discovery/monitoring using that unresolvable hostname (from the `hosts` list in the server's `hello` reply) and gets stuck in `ReplicaSetNoPrimary`, timing out after 30s on every single Mongo operation. **The instinct to fix this by reconfiguring the member's hostname to the host-facing port does not work**: both `rs.initiate({members:[{host:"localhost:27018"}]})` *and* `rs.reconfig()` with the same host change fail with `MongoServerError: No host described in new configuration ... maps to this node` — `rs.reconfig` performs the exact same "does this host map to this node" self-connectivity check as `rs.initiate`, and the node internally only ever listens on its container-internal port (`27017`), regardless of what Docker publishes it as externally. (The oddly large `version` numbers seen in these errors, e.g. `23121`, `32101`, are not stale state — that's MongoDB's documented behavior for `rs.reconfig(cfg, {force: true})`, which jumps the version by a large arbitrary number on purpose.)

**The actual fix is entirely on the client side**: add `directConnection=true` to the connection string (`mongodb://root:mongo_password@localhost:27018/?directConnection=true`). This tells the driver to use only the one connection dialed here for every operation, skipping topology discovery entirely — exactly right for a single-node dev/test replica set with no failover to discover anyway. Sessions/transactions still work fine over a direct connection since the server itself is genuinely part of an initialized replica set. **No `rs.reconfig()` step is needed at all** — a bare `rs.initiate()` is sufficient; leave the member registered under its own container hostname.

**Anyone else hitting `SCRAM-SHA-1: AuthenticationFailed` against a `gourdian-mongo`-style container they've verified is correctly configured** should suspect this same class of bug rather than re-checking the container's auth/replica-set setup: test with `docker run --rm --network container:<name> mongo:7 mongosh ...` first to confirm the container itself is fine, then check `sudo ss -tlnp | grep <port>` for a listener with no attributable process, and if a full Docker Desktop restart doesn't clear it, moving to a different host port is the fast, low-risk fix.

**Verified 2026-07-04 — all green, nothing left pending on Phase 4:**

```
go test -run TestMongoRepository_MarkTokenRotatedAtomic_ConcurrentDuplicate_WithTransactions -v ./...   # PASS
go test -run TestRepositoryClose_Idempotent/MongoDB -v ./...                                            # PASS
go test -run TestNewGourdianTokenMakerWithMongo -v ./...                                                # PASS
go test -count=1 -timeout=5m -cover ./...                # PASS, coverage: 78.5% of statements, 77.769s
go test -race -count=1 -timeout=5m ./...                 # ok, 81.179s, zero data races
```

The first is the Phase 4 item 1 regression test (`gourdiantoken.repository.mongo_test.go`) for the Mongo duplicate-key fix. **Not yet done, optional but recommended before fully trusting it**: temporarily revert the boundary-move in `MarkTokenRotatedAtomic` (move `mongo.IsDuplicateKeyError` back inside the transaction callback) and confirm this specific test fails, then re-apply the fix and confirm it passes again — this closes the loop on "would this test actually have caught the original bug."

### Where things stand

- **Branch:** `dev#manish#major_fixes`, working tree clean, up to date with `origin/dev#manish#major_fixes` (this repo has an external auto-commit hook that commits after each edit round — commits were not made explicitly via `git commit` by the assistant in either this session or the prior one, per this session's operating instructions to only commit when asked).
- **Latest commit as of 2026-07-04 (this session, Phase 4 work):** `841b436` ("fix: update implementation status in the improvement plan; clarify Phase 4 completion and verification details"), preceded by `17dcb5f` (Mongo port 27018 / `directConnection=true` fix) and `0f25db5` (Redis `Close()` idempotency fix + Mongo regression test — the actual Phase 4 code changes). Before those, `43dbbe3`/`35ea31c`/`74aad25`/`8a873c4` cover Phases 1-3 (handoff point of the prior session).
- **⚠️ `dev#manish#remove_uuid` exists but is STALE — do not start Phase 5 work on it as-is.** Checked 2026-07-04: it branched off at `132cb60` ("Add CLAUDE.md for project guidance and update file count in bark.txt"), *before* any of Phases 1-4 landed, and has exactly one commit of its own since (`6c746fd`, "Remove backup repository factories file and update directory structure in bark.txt" — unrelated repo-hygiene, not Phase 5 substance). It is missing all 11 commits of Phase 1-4 work that are on `dev#manish#major_fixes`. **Before starting Phase 5, either:** (a) rebase `dev#manish#remove_uuid` onto the current tip of `dev#manish#major_fixes` (cherry-picking `6c746fd` back on top if its bark.txt/backup-file cleanup is still wanted), or (b) just delete and recreate the branch fresh from `dev#manish#major_fixes`'s tip, re-applying `6c746fd`'s change manually if needed. Confirm with `git log --oneline -5` on the branch that Phase 4's commits (`0f25db5`, `17dcb5f`, `841b436`) are present before writing any Phase 5 code.

### Starting Phase 5 in a new environment (quick checklist)

1. Fix the stale-branch situation above first — do not build Phase 5 on top of a `dev#manish#remove_uuid` that's missing Phases 1-4.
2. **No live Redis/MongoDB/PostgreSQL needed for Phase 5 development.** Confirmed: none of the four repository backends ever touch `uuid.UUID` — they only store a hash of the raw JWT string for revocation/rotation tracking, never the parsed claims struct. Phase 5 only changes claims/config/validation types, which the repository layer never sees. Scope test runs to `go test -run '.*/Memory' ./...` (plus the non-repository-backed test files, which is most of the suite) for full confidence while iterating — this matches the pattern `CLAUDE.md` already documents for iterating without live services.
3. Only come back to a Docker-capable machine once, for a final `make test`/`make race` full-backend sanity pass before tagging the v2.0.0 release — not needed throughout Phase 5 development.
4. Re-verify every line reference in the Phase 5 section below against current source before touching it — per the "Before you start" section's own instructions, and doubly true here since Phase 5 hasn't been touched since the original plan draft and the file layout has changed (Phase 2a's split) since those line numbers were recorded.
- **The 6-way file split (Phase 2a) already happened.** `gourdiantoken.go` no longer exists. The single 3262-line file is now:
  - `gourdiantoken.config.go` — TokenType/SigningMethod/claim-key consts, GourdianTokenConfig, NewGourdianTokenConfig (now deprecated), DefaultGourdianTokenConfig
  - `gourdiantoken.claims.go` — AccessTokenClaims, RefreshTokenClaims, AccessTokenResponse, RefreshTokenResponse
  - `gourdiantoken.interfaces.go` — TokenRepository, GourdianTokenMaker, **GourdianTokenMakerCloser (new)**
  - `gourdiantoken.maker.go` — JWTMaker struct (now has `logf`/`closeOnce` fields), constructors, Create/Verify/Revoke/Rotate methods and their extracted shared helpers, cleanup goroutines, key init, hashToken, **Option/WithLogger/Close() (new)**
  - `gourdiantoken.validation.go` — validateConfig, validateAlgorithmAndMethod, toMapClaims, mapToAccessClaims, mapToRefreshClaims, validateTokenClaims, **commonClaims/extractCommonClaims (new)**
  - `gourdiantoken.keys.go` — 6 key parsers (now sharing `decodePEMBlock`), checkFilePermissions, getUnixTime, PEM/ASN.1 structs
  - `gourdiantoken.errors.go` — **new file**, sentinel errors (Phase 3a)
  - New test files: `gourdiantoken.errors_test.go` (sentinel-error `errors.Is` tests), `gourdiantoken.close_test.go` (Close() idempotency + goroutine-stop tests)
  - `token.test.helper.go`/`token.bench.helper.go` were renamed to `_test.go`-suffixed (Phase 1) — testify is confirmed no longer a direct dependency for consumers.
- Re-run `wc -l gourdiantoken.*.go` and `grep -n '^func\|^type' gourdiantoken.maker.go` etc. to get fresh line numbers before touching Phase 4 — don't trust any line number in the Phase 1-3 sections below, they're historical and some are already stale relative to current HEAD.

### Verification baseline in this environment (may differ in the new one)

- `go build ./...`, `go vet ./...`, `gofmt -l .` / `goimports -l .` all clean.
- Full non-live-service test sweep passes with **zero unexpected failures**. The only failures observed, consistently, across every verification run in this environment, are these 6 — all because this sandbox has no local Redis/MongoDB/PostgreSQL (see `CLAUDE.md` for the exact connection strings they expect):
  - `TestNewGourdianTokenMakerWithGorm_FailsWithCancelledContext`
  - `TestNewGourdianTokenMakerWithGorm_SupportsRevocationAndRotation`
  - `TestNewGourdianTokenMakerWithMongo_CreatesTransactionEnabledRepository`
  - `TestNewGourdianTokenMakerWithMongo_FailsWithCancelledContext`
  - `TestNewGourdianTokenMakerWithRedis_FailsWithCancelledContext`
  - `TestNewGourdianTokenMakerWithRedis_SupportsHighPerformanceOperations`
  - **If a new environment has live Redis/MongoDB/PostgreSQL available, run the full suite there** — Phase 4 item 1 (the Mongo duplicate-key fix) genuinely needs a live MongoDB with `useTransactions=true` to verify the regression test actually exercises the fix; it could not be verified in this environment and is one of the two reasons Phase 4 wasn't started.
- Race detector (`go test -race`) clean on all Memory/Concurrency/Close/sentinel-error tests.

### Setting up Redis/PostgreSQL/MongoDB in the new environment

Three local services are needed, all with **hardcoded, non-configurable** connection details baked into `token.test.helper_test.go` (not env vars — no docker-compose file exists in this repo, per `CLAUDE.md`):

| Service | Connection details | Notes |
|---|---|---|
| **Redis** | `localhost:6379`, password `redis_password`, DB index `15` | Any recent Redis image works |
| **PostgreSQL** | `host=localhost user=postgres_user password=postgres_password dbname=postgres_db port=5432 sslmode=disable` | User/db must already exist; GORM auto-migrates the `revoked_tokens`/`rotated_tokens` tables itself (`db.AutoMigrate` in `NewGormTokenRepository`) — no manual schema needed |
| **MongoDB** | `mongodb://root:mongo_password@localhost:27018/?directConnection=true`, database `gourdian_test` | **Must run as a replica set**, even a single-node one — plain standalone MongoDB doesn't support transactions, and Phase 4 item 1 (the fix that's up next) specifically needs `useTransactions=true` to work. **Port `27018`, not Mongo's default `27017`, and `directConnection=true` is required** — see "Mongo verification gap" note above for why. |

Quickest way to stand these up with Docker:

```bash
# Redis
docker run -d --name gourdian-redis -p 6379:6379 redis:7 redis-server --requirepass redis_password

# PostgreSQL
docker run -d --name gourdian-postgres -p 5432:5432 \
  -e POSTGRES_USER=postgres_user -e POSTGRES_PASSWORD=postgres_password -e POSTGRES_DB=postgres_db \
  postgres:16

# MongoDB — single-node replica set (required for transactions)
# NOTE: --replSet + auth (root user) requires a keyfile for internal cluster auth, even for a
# single-node set — MongoDB 7 refuses to start with "security.keyFile is required when
# authorization is enabled with replica sets" otherwise. Generate one into a named volume first:
docker volume create gourdian-mongo-keyfile
docker run --rm -v gourdian-mongo-keyfile:/keyfile-dir mongo:7 bash -c \
  "openssl rand -base64 756 > /keyfile-dir/mongo-keyfile && chmod 400 /keyfile-dir/mongo-keyfile && chown 999:999 /keyfile-dir/mongo-keyfile"
# Published on host port 27018, not Mongo's default 27017 — see "Mongo verification gap" note
# at the top of this document: Docker Desktop's own port-forwarding for 27017 got stuck
# pointing at an orphaned mongod on at least one dev machine, and didn't clear even after
# container recreation, `wsl --shutdown`, and a full Docker Desktop restart.
docker run -d --name gourdian-mongo -p 27018:27017 \
  -e MONGO_INITDB_ROOT_USERNAME=root -e MONGO_INITDB_ROOT_PASSWORD=mongo_password \
  -v gourdian-mongo-keyfile:/keyfile-dir \
  mongo:7 --replSet rs0 --keyFile /keyfile-dir/mongo-keyfile
# then initialize the replica set — bare, do NOT try to set the member's host to the
# host-facing port here. Both rs.initiate({members:[{host:"localhost:27018"}]}) and a
# later rs.reconfig() attempting the same change fail with "No host described in new
# configuration ... maps to this node": the node only ever listens on its container-internal
# port (27017) and can't validate itself against the externally-published one. Leave the
# member registered under its own container hostname and instead connect with
# directConnection=true client-side (see CLAUDE.md) — that's the actual, working fix:
docker exec -it gourdian-mongo mongosh -u root -p mongo_password --authenticationDatabase admin \
  --eval 'rs.initiate()'
```

Once all three are reachable, confirm with `make test` (or `go test -count=1 -timeout=5m -cover ./... -bench=. -benchmem`) and `make race`. Expect **zero failures** — the 6 tests listed in the "Verification baseline" section above should all pass with these services up, confirming Phase 1-3's changes didn't regress anything backend-specific, before starting Phase 4.

### Deviations from the plan text below, discovered during implementation (already applied — don't redo, just be aware)

1. **`extractCommonClaims`'s `iss` handling is narrower than first drafted.** The plan (2b item 5) says to apply a "checked pattern" to `iss` like jti/sub/sid. A first attempt made `iss` unconditionally required (erroring if the key is absent), which broke 2 existing tests (`TestTokenClaims_Mapping/empty_roles_in_access_token` and `.../wrong_token_type_in_refresh_claims`) that construct claims maps without an `iss` key to isolate testing other checks. **Fixed to:** only error when `iss` is *present but not a string*; an absent `iss` claim still silently becomes `""`, matching that `iss` is not part of `baseRequired` and is only mandatory when a caller's `RequiredClaims` config lists it (enforced upstream in `validateTokenClaims`, unaffected). See the comment left in `extractCommonClaims` in `gourdiantoken.validation.go`.
2. **Doc-comment placement bug, self-inflicted and fixed.** Several `Edit` calls that inserted new shared helpers (`validateUserAndUsername`/`newTokenID`/`signClaims` before `CreateAccessToken`; `parseAndValidateToken` before `VerifyAccessToken`; `revokeToken` before `RevokeAccessToken`; `decodePEMBlock` before `parseEdDSAPrivateKey`; `commonClaims`/`extractCommonClaims` before `mapToAccessClaims`) initially landed the new function **inside** the existing doc comment block of the function below it (no blank-line separator), which silently reattached that doc comment to the new helper and left the original exported function undocumented. All were caught via `gofmt -l`/`goimports -l` flagging the files plus `go doc` spot-checks, and fixed by moving each new block to sit after the *previous* function's closing brace instead. **If you add more shared helpers in Phase 4/5, verify placement the same way** (`go doc . JWTMaker.<Method>` should show the real doc text, not a generic one-liner) — this class of bug is easy to reintroduce with the same edit pattern.
3. **`Option`/`WithLogger` (Phase 3b) was threaded through all 6 constructors, not just `NewGourdianTokenMaker`.** The plan only explicitly names `NewGourdianTokenMaker`, but says "passed to the constructors" (plural), so `opts ...Option` was added to `NewGourdianTokenMakerNoStorage`, `WithMemory`, `WithGorm`, `WithMongo`, `WithRedis`, and `DefaultGourdianTokenMaker` too, all forwarding to `NewGourdianTokenMaker(ctx, config, tokenRepo, opts...)`. This is additive/backward-compatible (trailing variadic param).
4. **Rotated-token wording unification (3a) done via `fmt.Errorf("%w", ErrTokenRotated)`** at both `parseAndValidateToken` (was "token has been rotated and is no longer valid") and `RotateRefreshToken` (was already "token has been rotated"). Both now read exactly "token has been rotated". Confirmed all 18 pre-existing test assertions (substring-matching "token has been rotated") still pass.
5. **The `token.verification_test.go` 3-way `strings.Contains` conversion (3a) resolved to `context.Canceled`, not a new gourdiantoken sentinel.** Traced the actual code path: `MemoryTokenRepository.IsTokenRevoked` never checks `ctx` at all, so the "revocation" substring in the original fuzzy OR-check was speculative/unreachable with the Memory backend under test — the real and only failure path is the top-level `ctx.Err()` check in `parseAndValidateToken`, which wraps the stdlib `context.Canceled` sentinel. Converted to `assert.ErrorIs(t, err, context.Canceled)`.

### What's left: Phase 4 and Phase 5 (see full details further below, unchanged from the verified plan)

**Phase 4 — repository backend fixes.** Not started. Four items, in order of priority:
1. Mongo `MarkTokenRotatedAtomic` duplicate-key fix — **needs live MongoDB with transactions to verify**, could not be done in this environment. The fix itself (move `mongo.IsDuplicateKeyError` detection out of the transaction callback to the outer boundary) is fully specified below and doesn't require guessing — just needs a real MongoDB to run the regression test against (`useTransactions=true`), per `CLAUDE.md`'s connection string (`mongodb://root:mongo_password@localhost:27018/?directConnection=true`, db `gourdian_test`).
2. `RotateRefreshToken` unrecoverable-lockout bug — doc-comment-only fix, no live service needed, safe to do in any environment.
3. Redis TTL floor — doc-comment-only fix on the `TokenRepository` interface, no live service needed.
4. Mongo `Close(ctx)` vs. others' bare `Close()` — flag only (already confirmed non-interface-breaking, see Phase 4 item 4 below), plus add test coverage for Gorm/Redis/Mongo `Close()` — **the Gorm/Redis tests need live services**; only Mongo... actually all three need live services. None of item 4's test-coverage work could be done in this environment either.

Given items 1 and 4 need live infra this sandbox doesn't have, **the most a no-live-service environment can do for Phase 4 is items 2 and 3 (pure doc-comment changes) plus writing (but not running/verifying) the Mongo regression test and the three Close() tests for later execution.** A new environment with `docker compose` access for Redis/MongoDB/PostgreSQL should do all of Phase 4 properly, including running the regression tests.

**Phase 5 — UUID → string migration.** Not started, and per the plan's own design decision, must not start until Phase 4 ships — lands on a new `dev#manish#remove_uuid` branch (doesn't exist yet), separate v2.0.0 module path. Fully specified below; no blockers, but it's a large mechanical change — re-verify every line reference against current source before touching it, per the "Before you start" section's own instructions.

---

Scope: the `gourdiantoken` Go library at repo root (package `gourdiantoken`). Excludes bark.txt/.bark.toml tooling entirely.

This is a merged plan built from three passes: an initial research pass, a follow-up that re-verified every claim line-by-line, and a third pass (this one) that re-verified **every remaining claim against current source** using three parallel read-only explorations covering Phase 1, Phase 2/3, and Phase 4/5 respectively, plus one manual spot-check. Nearly everything held up exactly. Where this pass found a factual error, a missing item, or a new finding, it's called out explicitly below with a **[Verified 2026-07-03]** or **[Correction]** tag rather than silently rewritten — per this document's own stated policy of expanding rather than silently fixing.

**Headline outcome of this pass:** the plan was already accurate on all major structural claims (file split boundaries, line-1-to-3262 completeness, the Mongo duplicate-key bug, the RotateRefreshToken lockout bug, the Redis TTL floor, all Phase 5 UUID scope). Three concrete corrections were needed (below), and five new findings surfaced that are folded into the relevant phases.

**Design decisions already made (do not re-litigate these):**
- UUID scope for Phase 5: `ID` (jti), `Subject` (sub), and `SessionID` (sid) all become `string`, not just caller-supplied fields. **[Correction]** This applies fully to `AccessTokenClaims`/`RefreshTokenClaims` (both have all 3 fields as `uuid.UUID`). `AccessTokenResponse`/`RefreshTokenResponse` only carry `Subject` and `SessionID` as `uuid.UUID` — neither response struct has an `ID`/`jti` field. Scope text in Phase 5 updated accordingly.
- Post-migration, `userID`/`sessionID` become fully opaque — any non-empty string is accepted, no UUID-shape requirement.
- Phase 5 (UUID removal) ships as a separate v2.0.0 major release, strictly after Phases 0-4 ship as v1.x.
- `Close()` ships via a new, separate `GourdianTokenMakerCloser` interface — not added to the existing `GourdianTokenMaker` interface — so it stays non-breaking.
- Phase 5 lands on the `dev#manish#remove_uuid` branch; Phases 1-4 land on `dev`/`master` as normal v1.x patch/minor releases.

---

## Before you start: re-verify against current source, and expand this plan if needed

Line numbers in this document were re-confirmed accurate as of 2026-07-03 against a 3262-line `gourdiantoken.go`, but they **will drift** as the file changes — code review, other PRs, or your own earlier edits in this session can all shift them. Treat every `L####` reference here as a *pointer to go look*, not a guarantee.

For every phase, before writing any code:

1. **Re-locate every referenced site** with `grep -n` or your editor's search, rather than trusting the line number directly. If a pattern has moved, drifted, or no longer matches the description, note the actual current location before proceeding.
2. **Confirm the pattern still matches the description.** Code may have changed since the last check. If what you find doesn't match what's described (different logic, already fixed, different error message), stop and flag it rather than applying the fix blindly.
3. **Actively look for siblings of each bug class.** Several items in this plan were found precisely because someone searched for "does this exact anti-pattern appear elsewhere" (e.g. the dead-`err` bug turned out to have 4 sites, not 2; the mis-suffixed test-helper files were found by checking `go list -f '{{.GoFiles}}'` rather than assuming naming implies test-only status; this pass found the `Revoke*` keyfuncs are identical *to each other* but not to `Verify*`'s keyfunc). Do the equivalent check for each fix in this plan.
4. **If you find additional issues, missed sites, or a correction to something in this plan, expand this document** rather than fixing silently and moving on. Add the new finding to the relevant phase using the same format used throughout (file, approximate line, current behavior, proposed fix, why it's safe/what it breaks). Note explicitly whether it changes the phase's risk profile.
5. **Re-run the verification commands for the phase you just finished** before moving to the next phase. Don't batch verification across phases — each phase should leave the tree in a known-good, fully tested state before the next one starts.

This applies with extra force to Phase 2 (the file split) and Phase 5 (the UUID migration): both are large mechanical changes where a stale line reference is likely to cause you to move or edit the wrong code. Re-view the actual current file immediately before editing it, every time — not just once at the start of the phase.

---

## Phase 0 — Baseline safety net (prerequisite, do first) ✅ DONE

Before any refactor, confirm test coverage is adequate to catch regressions during the mechanical file split and dedup work.

- Run `go build ./...` and `go vet ./...` — confirm a clean baseline (0 errors/issues).
- `go test ./...` exercises repository-backed tests across **Memory, Redis, MongoDB, GORM** subtests (via `token.test.helper.go`'s `getTestRepositoryFactories()`); the latter three need real local services (hardcoded creds, no docker-compose in repo). To get a meaningful green baseline without standing up infra, scope to:
  ```
  go test -run '.*/Memory' ./...
  ```
  plus the non-repository-backed test files. If you *do* have Redis/MongoDB/PostgreSQL available locally, run the full `make test` / `make race` instead for a stronger baseline — see `CLAUDE.md` for connection details (Redis `localhost:6379`/`redis_password`/DB 15; MongoDB `mongodb://root:mongo_password@localhost:27018/gourdian_test?directConnection=true`; Postgres `host=localhost user=postgres_user password=postgres_password dbname=postgres_db port=5432`).
- No code changes in this phase.

---

## Phase 1 — Safe, isolated fixes (patch release, v1.0.8) ✅ DONE (all 10 items, committed)

All behavior-preserving-or-additive, zero public API surface change. Land as one PR.

1. **Dead-`err` bug — confirmed all 4 sites. [Verified 2026-07-03: exact lines]**
   - `VerifyAccessToken` (L1420) and `VerifyRefreshToken` (L1563):
     ```go
     if !token.Valid {
         return nil, fmt.Errorf("invalid token: %v", err)  // err is always nil here
     }
     ```
     `err != nil` was already handled at L1415-1417 / L1558-1560, so this always prints `"invalid token: <nil>"`.
   - `RevokeAccessToken` (L1673-1674) and `RevokeRefreshToken` (L1778-1779), same defect in a combined-OR form:
     ```go
     if err != nil || !parsed.Valid {
         return fmt.Errorf("invalid token: %w", err)
     }
     ```
     When `!parsed.Valid` is the true disjunct, `%w` on a nil `err` renders a malformed `%!w(<nil>)`.
   - Fix: split each combined check apart and give the `!Valid` branch its own real message, e.g. `"token failed validation"` (or, once Phase 3 sentinels exist, wrap `ErrTokenInvalid`/`ErrInvalidToken`).
   - Full-repo sweep confirmed: no other site reuses an already-nil-checked `err` in a later error message. These 4 are exhaustive.

2. **Replace panics in `toMapClaims` with returned errors.**
   - `toMapClaims` (L2461-2508): unsupported claim type (L2506, `default:` branch) and empty `Roles` (L2465) currently `panic(...)`, on the call path from the public `CreateAccessToken`/`CreateRefreshToken`.
   - **[Verified 2026-07-03 — severity nuance, not a plan error]:** neither panic is currently *triggerable* through the public API as written today. `CreateAccessToken` already validates `len(roles) == 0` at ~L1108 before ever calling `toMapClaims`, and the function's `default:` case can only be hit if a third claims type were ever passed (today, only `AccessTokenClaims`/`RefreshTokenClaims` are). Still worth fixing — it's fragile defense-in-depth that a future refactor could silently make reachable again (e.g. if the upstream guard is ever reordered or removed) — but don't describe it in the PR as "an active bug users can trigger today"; it's a latent-risk cleanup.
   - Change signature to `func toMapClaims(claims interface{}) (jwt.MapClaims, error)`; both panic sites become `return nil, fmt.Errorf(...)`.
   - Update both call sites (`CreateAccessToken` ~L1141, `CreateRefreshToken` ~L1280). Both already have `err` in scope from the preceding `uuid.NewRandom()` call — reuse it via `mapClaims, err := toMapClaims(claims)`.
   - Full-repo `panic(` sweep confirmed: these are the **only two** `panic(` calls anywhere in the entire repo (including all `_test.go` files). No other public-API-reachable panic exists to clean up in the same pass.

3. **Add a logger hook for background cleanup goroutines (internal plumbing only this phase).**
   - `cleanupRotatedTokens` (L1992-2013, `fmt.Printf` at L2008) and `cleanupRevokedTokens` (L2037-2060, `fmt.Printf` at L2054) currently print errors to stdout.
   - Add an unexported field to `JWTMaker`, e.g. `logf func(format string, args ...any)`, defaulting to today's `fmt.Printf` behavior.
   - No public setter yet — exposing a way to configure it is a public API change and belongs in Phase 3b, bundled with `Close()`.

4. **Improve the ambiguous validation message.**
   - L879: `"token repository required for token rotation/revocation"` doesn't say which flag triggered it.
   - Change to something specific, e.g.:
     ```go
     fmt.Errorf("token repository required: RotationEnabled=%v, RevocationEnabled=%v", config.RotationEnabled, config.RevocationEnabled)
     ```

5. **Add exported constants for magic `RequiredClaims` strings.**
   - `GourdianTokenConfig`'s `RequiredClaims` field doc (L116-118) documents `"iss"`, `"aud"`, `"nbf"`, `"mle"` as magic strings with no exported constants — **[Verified]** confirmed zero existing claim-key constants anywhere in the file (only two `const` blocks exist today: `TokenType`/`SigningMethod`, L42-63). The same literals recur as bare strings in struct tags (L308, 311, 324, 327), `toMapClaims` (L2472-2502), and `validateTokenClaims` (L2786-2836).
   - Add e.g. `ClaimIssuer = "iss"`, `ClaimAudience = "aud"`, `ClaimNotBefore = "nbf"`, `ClaimMaxLifetimeExpiry = "mle"` near `GourdianTokenConfig`.
   - Purely additive — no existing behavior changes; consumers adopt at their own pace.

6. **Fix a false doc comment about goroutine cleanup — and be honest that it's really a leak, not just stale prose.**
   - `JWTMaker`'s doc comment (L770, "Cleanup goroutines stop when the maker is garbage collected") and the matching lines in `cleanupRotatedTokens`/`cleanupRevokedTokens`'s doc comments (L1986, L2031) are false — `runtime.SetFinalizer` does not appear anywhere in the repo (confirmed via full-repo grep).
   - **[Verified 2026-07-03 — upgrade this item's framing]:** this traced further than "just a stale comment." `cleanupCancel` (the `context.CancelFunc` field, L788) is *only* ever invoked on two construction-time error paths inside `NewGourdianTokenMaker` (L912, L920 — when `initializeSigningMethod`/`initializeKeys` fail). Once a maker is constructed *successfully* with rotation/revocation enabled, nothing ever calls `cleanupCancel()` again — no finalizer, no GC hook, nothing. The two background goroutines run until process exit with no caller-accessible way to stop them today.
   - Reword the comments now to stop making a false claim about GC-based cleanup. Phase 3b's `Close()` is the actual fix for the underlying leak — don't promise it here, just stop lying about current behavior. Suggested wording: "Cleanup goroutines run for the lifetime of the process; there is currently no way to stop them once started (see `Close()`, added in a later release)" — adjust once Phase 3b ships.

7. **Rename the two mis-suffixed test helper files.**
   - `token.test.helper.go` → `token.test.helper_test.go`
   - `token.bench.helper.go` → `token.bench.helper_test.go`
   - **[Verified 2026-07-03]:** `token.test.helper.go` imports `github.com/stretchr/testify/require` (its only non-test-suffixed file to do so). `token.bench.helper.go` does *not* import testify — only this one file is the offender. `go.mod` lists `github.com/stretchr/testify v1.10.0` as a **direct** dependency (no `// indirect` comment) purely because of this naming bug — since Go only excludes `_test.go` files from normal builds, every consumer of this library today transitively compiles in testify (plus its indirect deps `go-spew`, `go-difflib`, `yaml.v3`).
   - All other 12 files importing testify already correctly end in `_test.go`. Confirm zero non-test references to the helpers these files define (e.g. `setupTestMaker`, `generateTestUUID`) before renaming — grep across the whole repo, not just `*_test.go` files. This should be a safe, pure rename with a real dependency-footprint benefit for consumers.

8. **Test gap fill.**
   - Add a direct test of `NewGourdianTokenMaker(ctx, config, nil)` (generic constructor, not `NewGourdianTokenMakerNoStorage`) with `RotationEnabled`/`RevocationEnabled` true, asserting the specific error from item 4.
   - `TestAllFactories_InvalidConfigurationsFail` (`gourdiantoken.factories_test.go` ~L574-613) is misnamed today — it only exercises `NewGourdianTokenMakerNoStorage`, never `WithMemory`/`WithGorm`/`WithMongo`/`WithRedis`. Extend it with nil-handle cases for Gorm/Mongo/Redis (each already has a real guard clause — e.g. `"gorm database instance cannot be nil"` in `gourdiantoken.factories.go` ~L278-280 — just currently untested), plus one shared invalid-config case (e.g. negative `AccessExpiryDuration`) run as a table test across all 5 factories.

9. **Flag only — do NOT fix in this phase.**
   - `RevokeAccessToken`/`RevokeRefreshToken`'s `jwt.Parse` keyfunc callbacks (L1666-1672, L1771-1777) don't check `token.Method.Alg() != maker.signingMethod.Alg()` the way `VerifyAccessToken`/`VerifyRefreshToken` do. **[Verified 2026-07-03]:** confirmed the two `Revoke*` keyfuncs are byte-identical *to each other*, but both genuinely lack the alg check present in `Verify*`'s keyfunc — this is real, not a false positive. Real, but low-severity (Go's static typing of `maker.publicKey` bounds classic alg-confusion attacks here). Adding the check would reject inputs accepted today — a real behavior change, so it doesn't belong in a "safe fixes" phase. Open a follow-up issue instead. **Note for Phase 2:** when building shared helpers, do not silently "fix" this by unifying all 4 keyfuncs into one — that would smuggle a behavior change into a phase that must stay behavior-preserving (see Phase 2b item 2's note).

10. **New: fix the error-message stutter in `RotateRefreshToken`.**
    - L1937-1940:
      ```go
      claims, err := maker.VerifyRefreshToken(ctx, oldToken)
      if err != nil {
          return nil, fmt.Errorf("invalid token: %w", err)
      }
      ```
      Since `VerifyRefreshToken` itself already returns errors prefixed `"invalid token: ..."` (or other specific messages) in most of its failure paths, callers can see doubled prefixes like `"invalid token: invalid token: <root cause>"`. Low-risk, isolated, single-line fix — drop the redundant wrapper prefix and propagate `err` as-is (or use `%w` without the extra text) since `VerifyRefreshToken`'s own error already carries sufficient context.

**Files touched in Phase 1:** the main source file (pre-split), `gourdiantoken.factories_test.go` (new/extended tests), two renamed test-helper files.

---

## Phase 2 — Internal refactors (patch release, v1.0.9), behavior-preserving ✅ DONE (2a file split + 2b dedup, committed; see deviation notes #1-2 at top of doc)

Land 2a and 2b as **separate commits** so a regression is easy to bisect between "changed behavior" and "moved code."

### 2a. File split (purely mechanical move, no logic changes)

Split the 3262-line main source file (**[Verified 2026-07-03]** exact `wc -l` count confirmed) into 6 cohesive files, all remaining in `package gourdiantoken`. Go packages are flat namespaces, so **no consumer import changes are required**. The dotted `gourdiantoken.<topic>.go` naming below deliberately mirrors the existing repository-backend files (`gourdiantoken.repository.<backend>.imp.go`) — **[Verified/nuance]** that dotted-prefix convention is specific to the repository-backend implementation files today (other existing files like `gourdiantoken.factories.go`, `docs.go`, `version.go` use a looser pattern), so this split establishes a slightly broader version of an existing convention rather than strictly matching a repo-wide standard — worth a one-line note in the PR description.

Verified line-range mapping (all 6 boundaries confirmed exact against current source, no gaps, no overlaps, union is 1-3262):

| New file | Lines | Contents |
|---|---|---|
| `gourdiantoken.config.go` | 1-273 | `TokenType`/`SigningMethod` types+consts, `GourdianTokenConfig`, `NewGourdianTokenConfig`, `DefaultGourdianTokenConfig` |
| `gourdiantoken.claims.go` | 275-463 | `AccessTokenClaims`, `RefreshTokenClaims`, `AccessTokenResponse`, `RefreshTokenResponse` |
| `gourdiantoken.interfaces.go` | 465-758 | `TokenRepository`, `GourdianTokenMaker` |
| `gourdiantoken.maker.go` | 760-2266 | `JWTMaker` struct (L771), `NewGourdianTokenMaker` (L862), **`DefaultGourdianTokenMaker` (L995 — [Correction: omitted from the prior mapping, confirmed present in this range, add it explicitly)**, Create/Verify/Revoke/Rotate methods (L1098, 1248, 1387, 1521, 1656, 1762, 1928), cleanup goroutines (L1992, 2037), plus `initializeSigningMethod` (L2083), `initializeKeys` (L2160), `parseKeyPair` (L2195), and `hashToken` (L2263) — these four are maker-specific and easy to miss if you only skim for the "obvious" method groups |
| `gourdiantoken.validation.go` | 2268-2842 | `validateConfig` (L2307), `validateAlgorithmAndMethod` (L2418), `toMapClaims` (L2461), `mapToAccessClaims` (L2535), `mapToRefreshClaims` (L2676), `validateTokenClaims` (L2785) |
| `gourdiantoken.keys.go` | 2844-3262 | 6 key parsers (`parseEdDSA*`/`parseRSA*`/`parseECDSA*`, L2865-3171), `checkFilePermissions` (L3172), `getUnixTime` (L3204), PEM/ASN.1 structs (L3230, 3252) |

Process:
- Move code verbatim (cut/paste), do not touch logic.
- Keep the `package gourdiantoken` declaration and existing imports at the top of each new file; let `goimports`/`gofmt` trim unused imports per file.
- Before moving each block, re-view the *current* file at that location — line numbers above are accurate as of 2026-07-03 but may have drifted since (see "Before you start" section).
- Run `go build ./...` and `go test ./...` after the split. This should be a no-op at the AST level — inspect `git diff` to confirm no lines were altered beyond the move.

### 2b. Deduplication (behavior-preserving, do after the split)

1. **Create\* helpers.** Don't force `CreateAccessToken`/`CreateRefreshToken` into one mega-function — the two claims structs genuinely differ, and Phase 5 will touch these literals directly, so keep them inline. Instead extract 3 small shared pieces:
   - `validateUserAndUsername(userID uuid.UUID, username string) error` — **[Correction: this function does not exist yet.]** Today the `userID == uuid.Nil` check is duplicated inline at `CreateAccessToken` L1103 and `CreateRefreshToken` L1253 (verified byte-for-byte identical: `if userID == uuid.Nil { return nil, fmt.Errorf("invalid user ID: cannot be empty") }`). This item *creates* the shared helper by extracting that duplication — Phase 5 item 2 below depends on this helper existing, so Phase 2b must land first.
   - `newTokenID() (uuid.UUID, error)` — centralizes the `uuid.NewRandom()` error path
   - `func (maker *JWTMaker) signClaims(ctx context.Context, claims interface{}, tokenType TokenType) (string, error)` — builds map claims via `toMapClaims`, signs, wraps errors with `"failed to sign %s token"`

2. **Verify\* helpers.** One shared:
   ```go
   func (maker *JWTMaker) parseAndValidateToken(ctx context.Context, tokenString string, tokenType TokenType) (jwt.MapClaims, error)
   ```
   covering the revocation check, the rotation check (gated on `tokenType == RefreshToken`, folded in rather than kept external — keeping it external would require reordering checks, which this phase can't do since it must stay behavior-preserving), the `jwt.Parse` call (**[Verified 2026-07-03]** its keyfunc callback is byte-identical between `VerifyAccessToken` L1403-1413 and `VerifyRefreshToken` L1546-1556, both checking `ctx.Err()` and `token.Method.Alg() != maker.signingMethod.Alg()`), and `validateTokenClaims`. `VerifyAccessToken`/`VerifyRefreshToken` become thin wrappers calling this then `mapToAccessClaims`/`mapToRefreshClaims`.
   While here: drop `VerifyAccessToken`'s trailing `claims["rls"]` recheck (L1441-1444) — **[Verified 2026-07-03]** confirmed provably dead at 3 layers: `validateTokenClaims` already requires `"rls"` in `baseRequired[AccessToken]` (erroring if absent), and `mapToAccessClaims` (L2587-2590, 2609-2611) already re-checks presence and non-emptiness — both run before this line is ever reached.
   Also drop the redundant `!token.Valid` half of the `if !ok || !token.Valid` guard just after the `jwt.Parse` call in both Verify methods (~L1429, ~L1572) — `token.Valid` is already guaranteed true by the earlier `if !token.Valid { return ... }` check a few lines above (the Phase 1 item 1 fix site), so re-checking it here is dead, confusing code in the same spirit as that bug. Fold this cleanup into the same commit since it touches the same lines the `parseAndValidateToken` extraction is already rewriting.
   **Do not extend this shared helper to `Revoke*`.** [New note, 2026-07-03] `RevokeAccessToken`/`RevokeRefreshToken` also call `jwt.Parse` (L1666, L1771) with keyfuncs that are byte-identical *to each other* but deliberately different from `Verify*`'s (they omit the alg check — this is Phase 1 item 9's flagged, not-yet-fixed issue). A well-intentioned "let's just make it one shared keyfunc for all 4 call sites" during this refactor would silently add the alg check to `Revoke*`, which is a real behavior change and does not belong in this behavior-preserving phase. Keep `Revoke*`'s `jwt.Parse` calls separate (they get their own, smaller consolidation in item 3 below, without touching the keyfunc).

3. **Revoke\* helpers.** One shared `func (maker *JWTMaker) revokeToken(ctx context.Context, tokenType TokenType, token string) error`, parametrizing the "not enabled" message and the `TokenType` passed to `MarkTokenRevoke` via `%s`/`string(tokenType)`. `RevokeAccessToken`/`RevokeRefreshToken` become 1-line wrappers. The two `jwt.Parse` calls inside can still be deduped into this one shared function (their keyfuncs are identical to each other) — just don't merge them with `Verify*`'s keyfunc, per the note above.

4. **6 key parsers.** Shared `func decodePEMBlock(pemBytes []byte, description string) (*pem.Block, error)`, called with each function's existing description string (`"private key"`, `"RSA public key"`, etc.) to keep error messages byte-exact.

5. **`mapToAccessClaims`/`mapToRefreshClaims`.** Shared `extractCommonClaims(claims jwt.MapClaims) (*commonClaims, error)` for the jti/sub/sid/username/issuer/audience/timestamps extraction common to both.
   **This also fixes a latent bug:** **[Verified 2026-07-03]** confirmed today `mapToRefreshClaims` (L2677-2689) does unchecked inline assertions (`uuid.Parse(claims["jti"].(string))` and similarly for sub/sid) that panic on a missing or non-string claim, while `mapToAccessClaims` (L2536-2561) uses a checked pattern (`jti, ok := claims["jti"].(string); if !ok { ... }` before parsing). The shared helper should use the safe checked pattern for both.
   **New finding, fold into this item:** [2026-07-03] Both functions also extract `issuer` via an unchecked, silently-swallowing pattern — `issuer, _ := claims["iss"].(string)` — which differs from how jti/sub/sid are handled just above it (those `ok`-check and error). If `iss` is present but not a string, this currently silently becomes `""` instead of erroring. Since `"iss"` is required by default (`RequiredClaims` defaults include it), make `extractCommonClaims` apply the same checked pattern to `issuer` as it does to jti/sub/sid — consistent tightening, same risk class as the jti/sub/sid panic-to-error fix already planned in this item.
   Each caller then handles only its own type-specific bits (`Roles` for access; the now-redundant-but-harmless `typ == "refresh"` recheck for refresh).

Validate every dedup step with `go test ./...` — this is 100% behavior-preserving (aside from the two explicitly-noted safety tightenings above, which convert panics/silent-swallows into errors rather than changing any success-path behavior), so no assertions should need to change. Do each item as a separate, reviewable commit, not one giant commit.

**Files touched in Phase 2:** all six new files listed above.

---

## Phase 3 — Public API additions (minor release, v1.1.0) ✅ DONE (3a+3b+3c, committed; see deviation notes #3-5 at top of doc)

### 3a. Sentinel errors

Add a new file `gourdiantoken.errors.go`. **[Verified 2026-07-03]** `go.mod` pins `github.com/golang-jwt/jwt/v5 v5.2.1`; confirmed directly against the module cache (`errors.go` in that exact version) that `jwt.ErrTokenExpired` and `jwt.ErrTokenSignatureInvalid` are real exported sentinels. Also confirmed: none of the 4 `jwt.Parse` call sites (L1403, 1546, 1666, 1771) use any `ParserOption` that disables default validation (no `WithoutClaimsValidation`/`WithValidMethods` anywhere in the file) — so golang-jwt's own default validator is active and these sentinels are already reachable via `errors.Is` today through the existing `%w` chains with zero code changes. So **alias** rather than reinvent for those two:

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

Wrap sites (re-verify exact current line numbers before editing):
- Revoked-token checks in `VerifyAccessToken`/`VerifyRefreshToken` (~L1398, ~L1532) → wrap `ErrTokenRevoked`
- Max-lifetime branch in `validateTokenClaims` (~L2837) → wrap `ErrTokenMaxLifetimeExceeded`
- Missing-exp sites in Revoke* (~L1684, ~L1789) → wrap `ErrMissingExpClaim`
- Repo-required site (L879, post-Phase-1-item-4 wording) → wrap `ErrTokenRepositoryRequired`
- **Rotated-token wording:** **[Verified 2026-07-03]** `VerifyRefreshToken` says "token has been rotated and is no longer valid" (L1542) while `RotateRefreshToken` says just "token has been rotated" (L1955) for the same logical condition — confirmed genuinely different text. Confirmed all 18 existing test assertions referencing this (`revocation.rotation_test.go` x4, `integration_test.go` x3, `token.rotate_test.go` x11) use `assert.Contains(t, err.Error(), "token has been rotated")` — a substring check that matches both variants, so unifying to one wording via `fmt.Errorf("%w", ErrTokenRotated)` is safe and breaks none of them.
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

- Add `closeOnce sync.Once` to `JWTMaker`, alongside the existing `cleanupCancel context.CancelFunc` field (**[Verified]** L788, confirmed only invoked today at two construction-error paths, L912/L920 — see Phase 1 item 6's expanded leak finding).
- Mirror `MemoryTokenRepository.Close()`'s existing `sync.Once` + channel pattern for consistency with the rest of the codebase — **[Verified 2026-07-03]** exact code confirmed at `gourdiantoken.repository.inmemory.imp.go` L623-628:
  ```go
  func (m *MemoryTokenRepository) Close() error {
      m.cleanupOnce.Do(func() {
          close(m.stopCleanup)
      })
      return nil
  }
  ```
- Wire in the Phase 1 item 3 logger field's public setter here too — a functional option, e.g. `WithLogger(logf func(string, ...any))`, passed to the constructors — since exposing configuration for the goroutines' error handling is itself a public API surface change and belongs in the same minor release as `Close()`.
- Add tests for: idempotent double-`Close()`, and the cleanup goroutines actually stopping after `Close()` (e.g. assert the cleanup goroutine's context is `Done()` afterward). **[Verified 2026-07-03]** confirmed today only `MemoryTokenRepository.Close()` has any test coverage (`gourdiantoken.benchmark_test.go:536`, `gourdiantoken.repository_test.go:1873,1877`) — zero `.Close()` test calls exist for Redis/Gorm/Mongo repositories.

### 3c. Config constructor deprecation

- Add a `// Deprecated: use DefaultGourdianTokenConfig + struct-literal field assignment instead. NewGourdianTokenConfig will be removed in a future major version.` godoc comment to `NewGourdianTokenConfig` (L190). Go tooling/IDEs surface `// Deprecated:` comments automatically.
- **Do not remove or break it.** **[Verified 2026-07-03]** confirmed exactly one real (compiled, non-doc-comment) call site in the repo today: `config.validation_test.go:468`, inside `TestNewGourdianTokenConfig` — every production factory takes a pre-built `GourdianTokenConfig` instead. Safe, low-stakes deprecation.
- Separately, flag (comment or issue only — **no signature change** in this pass) that `NewGourdianTokenMakerWithMongo`'s extra `transactionsEnabled bool` positional param (**[Verified]** `gourdiantoken.factories.go` L380) breaks the `(ctx, config, handle)` shape its true peers `NewGourdianTokenMakerWithGorm` (L273) / `WithRedis` (L490) share. Fixing this would require an options struct or a new factory variant — a larger design decision for a separately-scoped follow-up.

**Files touched in Phase 3:** `gourdiantoken.errors.go` (new), `gourdiantoken.maker.go`, `gourdiantoken.interfaces.go`, `gourdiantoken.config.go`, `gourdiantoken.factories.go`, package doc file, `revocation.rotation_test.go`, `token.verification_test.go`.

---

## Phase 4 — Repository backend fixes (ship with Phase 3, or as v1.1.1 immediately after) ✅ DONE AND FULLY VERIFIED (2026-07-04, not yet committed)

Sequenced after Phase 3 since item 1 references error-boundary conventions consistent with the sentinel-error work.

1. **Mongo `MarkTokenRotatedAtomic` duplicate-key fix (concrete fix, not "investigate"). [Verified 2026-07-03 — matches exactly]**
   - `gourdiantoken.repository.mongo.imp.go`, `MarkTokenRotatedAtomic` (L528-566) and its use of `withTransaction` (L254-271).
   - Confirmed: `mongo.IsDuplicateKeyError(err)` is checked at L550, *inside* the transaction callback passed to `withTransaction`, and swallowed via `return nil` at L552. This is risky because a write error surfaced to the driver mid-transaction can cause the server to abort the transaction regardless of the callback's return value, making subsequent commit behavior driver-version-dependent.
   - **Fix:** move the duplicate-key detection to the *boundary*, not inside the txn callback:
     - Have the transaction callback attempt the `InsertOne` and return the raw error (including duplicate-key errors) unchanged — do not call `mongo.IsDuplicateKeyError` inside the callback.
     - After `r.withTransaction(...)` returns, check `if mongo.IsDuplicateKeyError(err) { return false, nil }` at the `MarkTokenRotatedAtomic` call site — this is the correct outcome for "someone else already rotated this token concurrently," decided outside the already-aborted/rolled-back transaction.
     - This makes the atomic contract identical to Redis's `SetNX` (**[Verified]** L394) and GORM's `OnConflict{DoNothing:true}` (L472-475) + `RowsAffected` (L482): "false, nil" means "not newly marked, no real error," decided at the outer boundary. Both confirmed to match this pattern exactly.
   - **[Verified 2026-07-03]** `MarkTokenRevoke` (L317-350) and non-atomic `MarkTokenRotated` (L458-484) both use `ReplaceOne(..., options.Replace().SetUpsert(true))`, which matches-then-replaces rather than blind-inserting and structurally cannot hit a duplicate-key error — confirmed the fix is correctly scoped to `MarkTokenRotatedAtomic` only.
   - Add a regression test exercising concurrent/duplicate `MarkTokenRotatedAtomic` calls against Mongo with `useTransactions=true` to lock in the corrected boundary behavior.
   - **[Implemented 2026-07-04]** Fix applied exactly as specified: the transaction callback now just does `_, err := r.rotatedCollection.InsertOne(sessionCtx, doc); return err`, and `mongo.IsDuplicateKeyError(err)` is checked after `withTransaction` returns, outside the (by then already aborted/rolled-back) transaction. Regression test added as `TestMongoRepository_MarkTokenRotatedAtomic_ConcurrentDuplicate_WithTransactions` in the new file `gourdiantoken.repository.mongo_test.go`: spins up 10 concurrent goroutines calling `MarkTokenRotatedAtomic` on the same token against a repo constructed with `useTransactions=true` (via `NewMongoTokenRepository(baseRepo.revokedCollection.Database(), true)`, reusing the shared test factory's connection), asserts exactly one reports `(true, nil)` and the rest report `(false, nil)` with zero raw errors leaking through. **Verified 2026-07-04**: passes cleanly against the real replica-set MongoDB container once the "Mongo verification gap" fixes (port 27018, `directConnection=true`) were applied.

2. **`RotateRefreshToken` unrecoverable-lockout bug. [Verified 2026-07-03 — matches exactly]**
   - L1928-1969: confirmed the sequence — `MarkTokenRotatedAtomic` succeeds at L1948, then `CreateRefreshToken` is called at L1963; if it fails, the function returns the raw error at L1965 with **no compensating call** to un-mark the rotation record. The old refresh token becomes permanently unusable with no new token issued — an unrecoverable lockout for that session.
   - **Document only this pass** — add a clear godoc warning on `RotateRefreshToken` describing this failure mode. A real fix is a two-phase-commit-style redesign (delay marking rotated until after the new token is successfully created, trading off a small race window) — flag as a separate follow-up decision rather than bundling into this phase.
   - **[Implemented 2026-07-04]** Added a "Known Failure Mode — Unrecoverable Lockout" doc-comment section to `RotateRefreshToken` in `gourdiantoken.maker.go`, between the existing "Atomicity Guarantee" and "Security Benefits" sections. Doc-only change, verified via `go build`.

3. **Redis's `minRedisTTL` (100ms) floor — document divergence, do not change behavior. [Verified 2026-07-03 — exact]**
   - `gourdiantoken.repository.redis.imp.go`: constant defined L20 (`minRedisTTL = 100 * time.Millisecond`), exactly 3 usage sites confirmed (L178-179, L317-318, L385-387), each clamping TTLs below the floor. Confirmed zero equivalent floor in in-memory/GORM/Mongo backends (`grep -n "minTTL\|MinTTL\|floor"` across all three returns nothing).
   - Document the divergence explicitly in `TokenRepository`'s interface godoc, e.g. "implementations may enforce a minimum TTL floor." Do not remove or change the floor — it may have been an intentional Redis-specific safeguard against near-zero-TTL races. Only change behavior if you separately confirm with the maintainer that it's unintentional.
   - **[Implemented 2026-07-04]** Added the divergence note to `TokenRepository`'s doc comment in `gourdiantoken.interfaces.go`, in the existing "Implementation Considerations" bullet list. No behavior change, `minRedisTTL` untouched. Doc-only change, verified via `go build`.

4. **Mongo's `Close(ctx context.Context) error` vs. the other three backends' bare `Close() error`. [Correction: interface question now resolved, not just "verify first"]**
   - **[Verified 2026-07-03]:** `TokenRepository` (defined L478, closing ~L570) does **not** declare a `Close()` method at all — confirmed via full-file grep, zero matches for "Close" anywhere in the interface definition. This means the signature mismatch across the four concrete repository types (`MemoryTokenRepository.Close() error` at `gourdiantoken.repository.inmemory.imp.go:623`, `RedisTokenRepository.Close() error` at `gourdiantoken.repository.redis.imp.go:807`, `GormTokenRepository.Close() error` at `gourdiantoken.repository.gorm.imp.go:853`, `MongoTokenRepository.Close(ctx context.Context) error` at `gourdiantoken.repository.mongo.imp.go:888`) is **not an interface-satisfaction bug** — it's an inconsistency between the four concrete types' ad hoc conventions, since callers only ever invoke `Close` on the concrete type directly. Confirmed low-urgency, not interface-breaking.
   - Flag only, no change this pass either way (adding `Close()` to the interface itself would be new API surface, a separate design decision from harmonizing an existing method).
   - Worth doing regardless of the signature question: **[Verified 2026-07-03]** confirmed only `MemoryTokenRepository.Close()` has test coverage today (3 call sites total, all in `gourdiantoken.benchmark_test.go`/`gourdiantoken.repository_test.go`) — Gorm/Redis/Mongo's `Close()` implementations have zero test coverage. Add coverage for all three.
   - **[Implemented 2026-07-04]** Added `TestRepositoryClose_Idempotent` to `gourdiantoken.repository_test.go`, table-driven over `getTestRepositoryFactories()` (skipping `Memory`, already covered by `TestMemoryRepository_Close`), type-switching per backend to call the right `Close()` signature (`Mongo`'s takes a `context.Context`; the other two don't), asserting two consecutive `Close()` calls both return no error. Verified passing for `Redis` and `GORM` in this session (real live services, see below); `MongoDB` subtest written but blocked on the same environment gap described above.
   - **[New finding, 2026-07-04 — not anticipated by the plan text above]:** writing this test immediately surfaced a real, previously-undetected bug: **`RedisTokenRepository.Close()` was not idempotent.** `go-redis`'s own `(*Client).Close()` returns `ErrClosed` ("redis: client is closed") if called a second time (confirmed directly in the `go-redis v9.7.3` source, `internal/pool/pool.go:481-483`) — unlike `GormTokenRepository.Close()` (backed by `database/sql`'s `(*DB).Close()`, which the stdlib documents as idempotent) and unlike the `sync.Once`-guarded pattern already used by `MemoryTokenRepository.Close()` and `JWTMaker.Close()` elsewhere in this codebase. **Fixed:** added a `closeOnce sync.Once` field to `RedisTokenRepository` (`gourdiantoken.repository.redis.imp.go`) and wrapped the existing `r.client.Close()` call in it, matching the established idempotent-Close convention. This is a genuine bug fix, not just test coverage — flagging it explicitly per this document's own policy of expanding rather than silently fixing. Verified: `TestRepositoryClose_Idempotent/Redis` failed before this fix (second `Close()` call returned the `ErrClosed` error) and passes after it, with zero `go test -race` data races introduced.
   - **[Second new finding, 2026-07-04, unrelated to Redis/Mongo]:** running the full suite surfaced a genuine, reproducible race in the *pre-existing* `TestClose_StopsCleanupGoroutines` test (`gourdiantoken.close_test.go`, added in Phase 3b) — intermittent failure `expected: 2, actual: 3`. Root cause: `cleanupRotatedTokens`/`cleanupRevokedTokens`'s loop is `select { case <-ctx.Done(): return; case <-ticker.C: ... }`; Go's `select` doesn't prioritize `ctx.Done()` over an already-ready `ticker.C`, so one in-flight tick can legitimately complete after `Close()` returns, before the goroutine observes cancellation on its next loop iteration. The test's artificially fast 20ms `CleanupInterval` (used to observe ticks quickly, versus production's enforced ≥1-minute minimum) makes this race practically inevitable rather than rare. **Fixed:** added a one-`CleanupInterval` grace-period sleep before capturing the baseline count in the test, so a legitimate in-flight tick isn't mistaken for the goroutines failing to stop. Verified stable across 20 consecutive runs (`go test -run TestClose_StopsCleanupGoroutines -count=20`) after the fix. This is a test-only fix — the production code's actual behavior (cleanup goroutines eventually stop after `Close()`, possibly completing one in-flight tick first) was always correct; only the test's assertion was too strict.

**Files touched in Phase 4:** `gourdiantoken.repository.mongo.imp.go` (fix + doc), `gourdiantoken.maker.go` (doc comment), `gourdiantoken.repository.redis.imp.go` (doc comment + the new `closeOnce` idempotency fix), `gourdiantoken.interfaces.go` (doc comment), `gourdiantoken.repository_test.go` (new `TestRepositoryClose_Idempotent`), `gourdiantoken.repository.mongo_test.go` (new file, the Mongo regression test).

**Verification performed 2026-07-04:** `go build ./...`, `go vet ./...`, `gofmt -l .` all clean. This session's own sandbox had working Redis/PostgreSQL fixtures but no usable MongoDB (see "Mongo verification gap" note at the top of this document for the two separate bugs that took considerable effort to track down: a stuck Docker Desktop port-forwarding mapping on 27017 unrelated to any code here, and a `directConnection=true` requirement for the driver to work with a single-node replica set whose member is registered under an externally-unresolvable container hostname) — Memory/Redis/GORM were fully verified there with zero failures and zero data races. **Once those two fixes were applied on the user's own machine (real Redis/MongoDB/PostgreSQL, not the sandbox), the full suite was re-run there and is now fully green across all four backends**: `go test -count=1 -timeout=5m -cover ./...` → `PASS`, `coverage: 78.5% of statements` (comfortably above the 70% `make coverage-check` threshold), `77.769s`; `go test -race -count=1 -timeout=5m ./...` → `ok ... 81.179s`, zero data races. Phase 4 is fully closed out — nothing left pending.

---

## Phase 5 — UUID → string migration (major release, v2.0.0) ✅ IMPLEMENTED AND FULLY VERIFIED 2026-07-04 on `dev#manish#major_fixes` (per user instruction; see updates #2 and #3 at top for deviations and release-readiness work) — only release mechanics remain, see "Release plan" below

Ships on the `dev#manish#remove_uuid` branch, strictly after Phases 0-4 land as v1.x. Breaking by definition (exported struct field types plus 2 interface method signatures change), so it needs its own major version and, per Go modules convention, a new module path (`/v2`).

**Scope** (per the design decisions at the top of this document): **[Correction: exact field scope verified]** — `ID`/`Subject`/`SessionID` on `AccessTokenClaims`/`RefreshTokenClaims` (all 3 fields confirmed `uuid.UUID` on both, L295/298/302 and L354/357/360), and `Subject`/`SessionID` only on `AccessTokenResponse`/`RefreshTokenResponse` (L392/395 and L432/435 — neither response struct has an `ID`/`jti` field at all, so there's nothing to migrate there beyond Subject/SessionID). Also: `userID`/`sessionID` params on `CreateAccessToken`/`CreateRefreshToken` (both the `GourdianTokenMaker` interface, L608/630, and `*JWTMaker` implementation, L1098/1248) all become `string`. Validation becomes fully opaque — any non-empty string is accepted.

**This phase is all-or-nothing** — partial type changes won't compile. Do the steps below in order, then verify with a full build, not incrementally.

1. **Type changes.** Flip `uuid.UUID` → `string` on the struct fields listed above (post-2a, in `gourdiantoken.claims.go`) and on the interface + implementation signatures for `CreateAccessToken`/`CreateRefreshToken`.

2. **Validation changes.**
   - `validateUserAndUsername`'s `userID == uuid.Nil` → `userID == ""`. **[Correction/cross-reference]:** this function does not exist in the codebase today — it is *created* by Phase 2b item 1, which extracts the currently-duplicated inline check at `CreateAccessToken` L1103 and `CreateRefreshToken` L1253. This step assumes Phase 2b has already landed; if for some reason it hasn't, apply the same `== ""` change to both inline sites instead. SessionID has no such check today and shouldn't gain one — the existing doc comment already treats an empty/nil sessionID as valid for sessionless tokens.
   - In `validateTokenClaims`, **replace, don't bare-delete**, the 3 `uuid.Parse(...)` format-validation blocks (**[Verified 2026-07-03]** confirmed present at ~L2797-2813 for jti/sub/sid, each first type-asserting to `string` then calling `uuid.Parse`) with explicit non-empty checks:
     ```go
     if jti, ok := claims["jti"].(string); !ok || jti == "" {
         return fmt.Errorf(...)
     }
     ```
     This is the one place where a literal "just drop the UUID validation" reading would create a silent regression: `uuid.Parse("")` today incidentally rejects empty claim values, and that guarantee must be preserved explicitly via the non-empty check, not dropped along with the UUID-shape check.

3. **Internal generation.** Keep `tokenID, err := uuid.NewRandom()` as the internal ID generator — do **not** switch to `uuid.NewString()`, which panics on entropy-read failure instead of returning an error. Only the assignment changes: `ID: tokenID` → `ID: tokenID.String()`. In the post-2b `toMapClaims`/`extractCommonClaims` helpers, drop the `.String()` call on the way in and the `uuid.Parse()` call on the way out, replaced by the same non-empty check as step 2.

4. **Mechanical call-site updates.** **[Verified 2026-07-03]** grep across the whole repo for UUID-related patterns (`uuid.UUID`, `uuid.New()`, `uuid.Nil`, `.String()`) totals ~477 lines (upper-bound estimate, since it includes some non-UUID `.String()` calls) — in the same ballpark as this section's original ~430 estimate, concentrated in test files (`token.verification_test.go` 77, `integration_test.go` 55, `token.creation_test.go` 52, `edge.case_test.go` 51, `gourdiantoken.benchmark_test.go` 45) and `example/example.go` (57); `gourdiantoken.go` itself only accounts for 29. This is one repeated pattern spread over the test files and the example file — describe and apply the pattern rather than tracking each site individually:
   - `userID := uuid.New()` → `userID := uuid.NewString()` (keep `google/uuid` as a *test-only* import for convenient unique test values — the exported Go type changed, not the need for a UUID generator in tests)
   - drop trailing `.String()` calls at comparison sites
   - `uuid.UUID` local variable declarations → `string`
   - `uuid.Nil` → `""`

5. **Non-Go touch points** (easy to miss since they aren't caught by `go build`):
   - `go.mod`: module path gains `/v2` (**[Verified]** current `module github.com/gourdian25/gourdiantoken` has no existing `/v2` suffix). `github.com/google/uuid v1.6.0` stays a real *direct* dependency (**[Verified]**), but confirmed internal-only: **[Verified 2026-07-03]** zero references to `uuid.UUID` anywhere in the 4 repository backend implementation files or the `TokenRepository` interface — that whole layer needs no Phase 5 changes.
   - The example file: **[Verified]** `example/example.go:14` imports `"github.com/gourdian25/gourdiantoken"` by path — needs `/v2` appended.
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
- **Do not merge the `Revoke*` and `Verify*` `jwt.Parse` keyfunc callbacks in Phase 2** — they differ in a real, currently-flagged-but-not-fixed way (the missing alg check, Phase 1 item 9); unifying them would smuggle a behavior change into a behavior-preserving phase.

---

## Release sequencing (superseded by "Release plan" below — kept for history)

| Release | Contents | Status |
|---|---|---|
| v1.0.8 (patch) | Phase 1 | ✅ done, on `dev#manish#major_fixes` |
| v1.0.9 (patch) | Phase 2 (2a then 2b as separate commits) | ✅ done, on `dev#manish#major_fixes` |
| v1.1.0 (minor) | Phase 3 (3a + 3b + 3c) | ✅ done, on `dev#manish#major_fixes` |
| v1.1.1 (patch) or bundled with v1.1.0 | Phase 4 | ✅ done and fully verified, on `dev#manish#major_fixes` |
| v2.0.0 (major) | Phase 5 | ✅ done and fully verified, on `dev#manish#major_fixes` |

This table's original per-phase version numbers (v1.0.8, v1.0.9, v1.1.0, v1.1.1) were never actually tagged, and per the 2026-07-04 update #3 decision, never will be — **all of Phases 1-5 ship together as one combined v2.0.0**, not as a sequence of separate v1.x releases followed by v2.0.0. See "Release plan" immediately below for the actual, current plan.

---

## Release plan (current, as of 2026-07-04 update #3 — this is the plan to follow)

**Decision:** ship Phases 1-5 together as a single combined **v2.0.0** release. No separate v1.1.0/v1.1.1 release for Phases 1-4 — reasoning: Phase 5 already landed on top of Phases 1-4 on the same branch (per the user's own explicit instruction in update #2), so splitting them back out now would need non-trivial git surgery (a retroactive release branch at the pre-Phase-5 commit, a separate version bump there, a separate tag) for a project without evidence of external v1.x consumers who'd need the split. Simpler to ship once.

**Workflow (agreed with the user):**
1. Merge `dev#manish#major_fixes` into `dev`.
2. Tag the release and publish via `goreleaser` (`make goreleaser-release`, or the equivalent CI trigger) — this reads `VERSION := v2.0.0` from the Makefile and `.goreleaser.yml`'s config (archives source files including `LICENSE`/`README.md`/`go.mod`/`go.sum`/`*.go`/`example/*.go`, publishes a GitHub release with an auto-generated changelog from commit messages).
3. Merge `dev` into `master`.

**Release-readiness checklist (all done as of update #3):**
- [x] `go.mod` module path is `github.com/gourdian25/gourdiantoken/v2`
- [x] `example/example.go`, `README.md` (imports, badges, doc links), Makefile `MAIN_PACKAGE`/`MODULE` all updated to match
- [x] `.goreleaser.yml`'s archive file list fixed (`examples/*.go` → `example/*.go`)
- [x] `CHANGELOG.md` written, covering the full combined v2.0.0 scope
- [x] README reviewed for accuracy against the new string-based API (found and fixed 4 real `.String()`-on-`string` bugs in the Gin middleware examples, plus stale UUID-centric wording and an outdated Go version requirement)
- [x] Full `go build`/`go vet`/`gofmt`/`goimports` clean
- [x] Full test suite + race detector clean across all four backends with live Redis/MongoDB/PostgreSQL
- [x] `make coverage-check` passes (78.6% ≥ 70%)
- [x] **`.goreleaser.yml` fixed — was genuinely broken, not just cosmetic.** `goreleaser check` (v2.13.1 installed) failed outright: missing the required `version: 2` schema line, and `archives.format` is deprecated (should be `formats:`, plural) — both fixed. **More importantly, a `goreleaser release --snapshot --clean` dry-run revealed the archive was never actually being produced at all**: with the only `builds` entry set to `skip: true` (correct, since this is a pure library with no binary), goreleaser's default `archives` pipe has no build artifacts to attach files to and silently emits nothing — confirmed via `dist/artifacts.json` containing only `metadata.json`, no `.tar.gz`. Fixed by adding `meta: true` to the archive config, which is goreleaser's documented way to produce a build-independent archive. Re-verified after the fix: the dry-run now genuinely produces `gourdiantoken_<version>_src.tar.gz` containing all expected files (`LICENSE`, `README.md`, `go.mod`, `go.sum`, all root `.go` files including tests, `example/example.go`) plus a checksums file.
- [x] **Makefile `goreleaser-release` target now depends on `release`.** Previously the two were disconnected: `release` tags+pushes using the Makefile's `VERSION` var, while `goreleaser-release` runs `goreleaser release --clean` independently — but goreleaser determines its own release version from the actual git tag at HEAD (confirmed via the dry-run: it picked up `v1.0.7`, the real latest tag, completely ignoring `VERSION := v2.0.0` in the Makefile), not from the Makefile at all. Running `goreleaser-release` without tagging first would have built/published under the wrong (previous) version. Now `goreleaser-release: release` ensures correct ordering automatically. Also added `goreleaser-check` (runs `goreleaser check` + a `--snapshot` dry-run, no real tag or publish needed) for safely validating the config before the real thing.
- [ ] `make goreleaser-release` (now tags v2.0.0 via its `release` dependency, then builds/publishes via goreleaser) — **not yet run, this is the next actual step**
- [ ] Merge `dev#manish#major_fixes` → `dev` → (tag/release) → `master` — **not yet done, needs the user to execute or approve, since merging into shared branches is outside what should happen without explicit sign-off**

**Known pre-existing, non-blocking issues surfaced during this review (not fixed, not release-blocking):**
- `make build`/`make install` Makefile targets: `go build ... -o $(BUILD_DIR)/gourdiantoken ./...` fails ("cannot write multiple packages to non-directory") because `./...` matches both the root library package and `example/`'s `package main`. Pre-existing for 20+ commits; not part of `precommit`/`prerelease`/`test`/`race`.
- `make lint` (`golangci-lint`) crashes with an internal panic in this environment (`file requires newer Go version go1.26 (application built with go1.25)`) — a local tooling-version mismatch, not a real lint finding. `goreleaser` doesn't invoke this target.
- No CI/CD automation exists (`.github/workflows/` doesn't exist) — releases are entirely manual, run locally by whoever has a `GITHUB_TOKEN` set. Worth considering a `release.yml` workflow triggered on `v*` tag push for consistency, but that's a separate, larger decision (needs GitHub repo secrets configured) — flagged, not implemented.

---

## Verification (run after every phase, not just at the end)

- `go build ./...` and `go vet ./...` after every change.
- `go test -run '.*/Memory' ./...` for logic that doesn't touch storage backends; full `make test`/`make race` needs local Redis/MongoDB/PostgreSQL.
- **Phase 1:** new item-8 tests pass; confirm `go list -f '{{.GoFiles}}'` / `{{.TestGoFiles}}` after the rename shows the two helper files moved into `TestGoFiles`; confirm a fresh `go mod graph` (or `go list -deps` from a throwaway consumer module) no longer pulls in `testify`.
- **Phase 2:** `git diff` after 2a should be a pure move (no logic lines changed); `go test ./...` after each 2b commit should need zero assertion changes (aside from the two explicitly-noted safety tightenings — iss-claim type check and mapToRefreshClaims panic→error — which only affect malformed-input paths, not the success path any existing test exercises).
- **Phase 3:** new `errors.Is`/`ErrorIs` assertions pass for `ErrTokenRevoked`, `ErrTokenRotated`, `ErrTokenExpired`, `ErrTokenMaxLifetimeExceeded`; new `Close()` idempotency + goroutine-stop test passes.
- **Phase 4:** new Mongo concurrent-rotation regression test (`useTransactions=true`) passes and would have failed pre-fix (verify this by temporarily reverting the fix and confirming the test fails).
- **Phase 5:** verify via full `go build ./...` success, then the full mechanical test suite, then a manual read-through of `README.md`'s code blocks (not auto-tested) for consistency with the new API.

Remember: if any of the above turns up something not covered in this document, add it here — in the relevant phase, using the same format — rather than fixing it silently.
