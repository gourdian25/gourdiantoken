# gourdiantoken: In-memory key material config (PrivateKeyPEM/PublicKeyPEM)

> Source of truth for this initiative, added mid-flight during the
> `docs/plan/multi-tenant-support-plan.md` work and executed **before** that
> plan's Stage 4, per explicit instruction. Same `docs/plan/<repo>-plan.md`
> convention as that file and `ECOSYSTEM_PLAN.md`. **Pause after each stage
> for review before starting the next.**

## Context

gourdiantoken's asymmetric signing modes (`RS*`/`ES*`/`PS*`/`EdDSA`) currently
require `GourdianTokenConfig.PrivateKeyPath`/`PublicKeyPath` — filesystem
paths that `parseKeyPair` (`gourdiantoken.maker.go`) reads itself via
`os.ReadFile`.

The repo owner is deploying a consumer of this library to Kubernetes and
wants to configure the key pair from their backend's own config-loading
system (env var, a secret already read into memory, a Vault/AWS Secrets
Manager/GCP Secret Manager SDK call, etc.) rather than writing the key to a
well-known path and pointing gourdiantoken at it. Today that's not possible —
gourdiantoken always does its own file read, so every consumer is forced onto
the same "key lives at a path on disk" distribution model regardless of how
their own secret actually arrives in the pod.

One framing correction surfaced during discussion, worth keeping in mind:
a single Kubernetes `Secret` referenced via `volumeMounts` in a Deployment
spec is already automatically mounted into every replica — this was never
fundamentally a "copy the key to N pods by hand" problem. The real
motivation is decoupling *where the backend's own config system stores the
key* from *how gourdiantoken loads it*, which matters regardless of whether
the backend gets there via a mounted volume, an injected env var, or a
secret-manager SDK call — all of those end with the backend holding PEM
bytes in memory and wanting to hand them directly to gourdiantoken.

Considered and explicitly **out of scope** for this initiative: KMS-backed
signing (AWS KMS / GCP Cloud KMS / Vault Transit), where the private key
material never leaves the KMS and gourdiantoken would need a pluggable
`crypto.Signer`-style interface instead of raw key bytes at all. That's a
different shape of change (an interface, not a field type) and a
meaningfully bigger lift than what's needed here — noted as a possible
future initiative, not part of this plan.

## Decisions confirmed with the repo owner (do not re-litigate)

1. **Replace, don't add.** `PrivateKeyPath`/`PublicKeyPath` are removed from
   `GourdianTokenConfig` entirely, not kept alongside a new in-memory option.
   Consistent with the multi-tenant plan's own precedent: zero confirmed
   consumers of this library exist anywhere, and several other breaking
   changes are already accumulating for the same upcoming release, so this
   avoids carrying two parallel ways to configure the same thing.
2. **New fields: `PrivateKeyPEM []byte` / `PublicKeyPEM []byte`.** Matches
   `os.ReadFile`'s own return type and golang-jwt's `ParseXxxPrivateKeyFromPEM`-style
   helpers exactly, so there's no `string`↔`[]byte` conversion at any call
   site in either direction, and avoids an extra `string` copy of key
   material sitting around that Go's GC can't reliably zero.
3. **Ships in the same `v2.3.0` release as `docs/plan/multi-tenant-support-plan.md`**
   (assumed, since both are breaking changes accumulating for the same
   upcoming version bump — flag during Stage 2 if that assumption is wrong).
4. Sequenced **before** `docs/plan/multi-tenant-support-plan.md`'s Stage 4.

## Tracker

| Stage | Scope | Status |
|---|---|---|
| Stage 1 | Core config/validation/key-loading change | Not started |
| Stage 2 | Docs / CHANGELOG / example.go pass | Not started |

## Stage 1 — Core config/validation/key-loading change

**Files touched:**

- **`gourdiantoken.config.go`** — remove `PrivateKeyPath string` /
  `PublicKeyPath string` fields; add `PrivateKeyPEM []byte` /
  `PublicKeyPEM []byte` in their place (same doc-comment position/style).
  Update `NewGourdianTokenConfig`'s deprecated signature: swap its
  `privateKeyPath, publicKeyPath string` params for
  `privateKeyPEM, publicKeyPEM []byte`, and its own doc-comment example
  (still `Deprecated`, not un-deprecated — same removal notice as today).
  `DefaultGourdianTokenConfig` drops its `PrivateKeyPath: "", PublicKeyPath: ""`
  lines entirely (fields no longer exist; the zero value of `[]byte` is
  already `nil`, nothing to initialize).
- **`gourdiantoken.validation.go`** — `validateConfig`'s `Symmetric` case:
  `if config.PrivateKeyPEM != nil || config.PublicKeyPEM != nil` (replacing
  the Path-emptiness check). `Asymmetric` case:
  `if len(config.PrivateKeyPEM) == 0 || len(config.PublicKeyPEM) == 0`
  (replacing the Path-emptiness check); **delete** the two
  `checkFilePermissions` calls — meaningless once the key never touches disk
  via this library.
- **`gourdiantoken.keys.go`** — delete `checkFilePermissions` entirely:
  after the above change it has zero remaining call sites anywhere in the
  package (confirm via grep before deleting — as of this writing it's only
  ever called from those two now-removed `validateConfig` lines).
- **`gourdiantoken.maker.go`** — `parseKeyPair`: delete both `os.ReadFile`
  calls and their `"failed to read private/public key file"` error wraps;
  use `maker.config.PrivateKeyPEM`/`PublicKeyPEM` directly as the bytes
  passed to `parseRSAPrivateKey`/`parseRSAPublicKey`/`parseECDSAPrivateKey`/etc.
  — those parser functions already take raw `[]byte`, so nothing changes
  there. Drop the `os` import if nothing else in the file still needs it
  (confirm via build). Update `initializeKeys`/`parseKeyPair`'s doc comments,
  which currently say "Loads private key from PrivateKeyPath".
- **`gourdiantoken.factories.go`** — 4 doc-comment examples reference
  `PrivateKeyPath: "/keys/private.pem"`-style config literals; update to the
  `[]byte` equivalent (e.g. `PrivateKeyPEM: privateKeyPEM,` with a one-line
  comment on where that value came from — an env var, a mounted secret file
  read once at startup, etc.).
- **`docs.go`** — 1 reference, update.

**New/changed public API:**

```go
type GourdianTokenConfig struct { /* PrivateKeyPath/PublicKeyPath removed */
    PrivateKeyPEM []byte
    PublicKeyPEM  []byte
}

func NewGourdianTokenConfig(
    signingMethod SigningMethod,
    rotationEnabled, revocationEnabled bool,
    audience, allowedAlgorithms, requiredClaims []string,
    algorithm, symmetricKey string,
    privateKeyPEM, publicKeyPEM []byte, // was: privateKeyPath, publicKeyPath string
    issuer string,
    accessExpiryDuration, accessMaxLifetimeExpiry, refreshExpiryDuration, refreshMaxLifetimeExpiry, refreshReuseInterval, cleanupInterval time.Duration,
) GourdianTokenConfig // Deprecated, same as today — signature updated, not un-deprecated
```

**Test-file impact:**

- **`cryptographic_test.go`** — the largest single file (~19 subtests
  currently doing `config.PrivateKeyPath = privPath; config.PublicKeyPath =
  pubPath` after a `generateRSAKeyPair`/`generateECDSAKeyPair`/
  `generateEdDSAKeyPair`-style helper writes PEM to a temp file and returns
  its path). Change those helpers to return the PEM `[]byte` pair directly
  instead of writing to a temp file and returning paths — a net
  simplification, since the happy-path cases no longer need
  `t.TempDir()`/`filepath.Join`/cleanup at all. The "malformed content"
  cases (`invalid_private.pem`, `corrupted.pem`, `empty.pem`-style tests)
  get simpler too — construct the bad `[]byte` inline, no file needed. One
  exception: the `/nonexistent/path/private.pem` case tests a
  **file-not-found** error that no longer exists as a concept once there's
  no path — replace it with an **empty-PEM-bytes** validation-error case
  instead (`config.PrivateKeyPEM = nil`), the new equivalent failure mode,
  already enforced by `validateConfig`.
- **`config.validation_test.go`** — update the existing Path-based
  Asymmetric-config validation cases to the PEM equivalents. Drop (or
  repurpose) whatever case exercised `checkFilePermissions`-style
  enforcement, since no file-permission concept survives this change.
- **`gourdiantoken.maker_test.go`** — same mechanical swap at its
  construction-time test call sites.
- **`gourdiantoken.keys_test.go`** — already tests
  `parseXxxPrivateKey`/`parseXxxPublicKey` directly on raw `[]byte` (the
  shape this change moves the rest of the codebase toward), so likely
  unaffected — except removing whatever test directly covers
  `checkFilePermissions`, if any, since that function is being deleted.
- **`example/example.go`** — deferred to Stage 2 with the rest of the
  prose-heavy pass.

**Dependencies:** none — foundation change, self-contained.

**Verification:** `go build ./...`, `go vet ./...`, `gofmt -l .`,
`golangci-lint run`, the full asymmetric-signing test subset (RSA/ECDSA/EdDSA
cases in `cryptographic_test.go`, `config.validation_test.go`,
`gourdiantoken.maker_test.go`) run in isolation first, then the full suite
against at least the Memory backend, `make race`, `make coverage-check`.

## Stage 2 — Docs / CHANGELOG / example.go pass

**Files touched:**

- **`example/example.go`** — wire `PrivateKeyPEM`/`PublicKeyPEM` through the
  demo's asymmetric-signing exercises (confirm during implementation whether
  it currently writes key files to disk or already holds bytes in memory
  before writing).
- **`README.md`** — every `PrivateKeyPath`/`PublicKeyPath` reference (config
  examples, and the "Upgrading to v2.3.0" section — extend the same section
  `docs/plan/multi-tenant-support-plan.md`'s Stage 5 creates, rather than
  adding a second "Upgrading" section for the same release).
- **`docs.go`** — confirm the Stage 1 doc-comment fix is sufficient, or
  expand with a short "loading keys in Kubernetes" note covering the options
  discussed in Context above (mounted-secret file read at startup, env var,
  secret-manager SDK — all converging on "pass the bytes directly").
- **`CHANGELOG.md`** — new entry (in the same `## v2.3.0` section the
  multi-tenant plan's Stage 5 creates) covering the
  `PrivateKeyPath`/`PublicKeyPath` → `PrivateKeyPEM`/`PublicKeyPEM` breaking
  change with a concrete before/after, matching this repo's established
  changelog convention of explaining rationale, not just diffing.
- **`CLAUDE.md`** — final consistency pass across anything touched in Stage 1.

**Test-file impact:** none expected — documentation/example-only stage.

**Dependencies:** Stage 1 fully landed.

**Verification:** `go run ./example` end-to-end against at least Memory (all
4 backends if `make docker-up` is available); `gofmt`/`goimports` clean.

## Critical files

- `gourdiantoken.maker.go` — `parseKeyPair` (the actual load-and-parse logic)
- `gourdiantoken.validation.go` — `validateConfig`'s Symmetric/Asymmetric
  branches
- `gourdiantoken.config.go` — `GourdianTokenConfig` struct +
  `NewGourdianTokenConfig`
- `cryptographic_test.go` — the bulk of the test-file impact
