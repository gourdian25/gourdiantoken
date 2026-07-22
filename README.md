# Gourdiantoken – Enterprise-Grade JWT Management for Go

![Go Version](https://img.shields.io/badge/Go-1.26.4%2B-blue)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![GoDoc](https://pkg.go.dev/badge/github.com/gourdian25/gourdiantoken/v2)](https://pkg.go.dev/github.com/gourdian25/gourdiantoken/v2)

**gourdiantoken** is a production-ready, comprehensive JWT token management system designed for modern Go applications. Built with security-first principles and performance optimization, it provides everything needed for enterprise authentication systems — from basic token generation to advanced features like automatic rotation, Redis-backed revocation, and multi-algorithm cryptographic support.

## 🌐 Part of the gourdian25 ecosystem

gourdiantoken is one of several small, independent Go libraries meant to be
used together:

- [grlog](https://github.com/gourdian25/grlog) — zero-dependency structured
  logging.
- [grcache](https://github.com/gourdian25/grcache) — backend-agnostic
  caching abstraction, the same architectural pattern (interface + pluggable
  backends) gourdiantoken uses for its `TokenRepository`.
- [grevents](https://github.com/gourdian25/grevents) — an in-process event
  bus for decoupling producers of state changes from consumers that react
  to them.
- [graudit](https://github.com/gourdian25/graudit) — an append-only,
  tamper-evident audit log with pluggable storage backends.
- [grpolicy](https://github.com/gourdian25/grpolicy) — attribute-based
  policy evaluation (RBAC/ABAC), independent of any notion of "user" or
  "role".
- [grnoti](https://github.com/gourdian25/grnoti) — a push-notification
  service handling FCM dispatch, idempotent event processing, device-token
  management, DLQ retry, circuit breaking, distributed rate limiting,
  deterministic A/B experiment assignment, localization, and topic-based
  routing.

## 🎯 Why Gourdiantoken?

- 🔐 **Complete Security**: Token rotation, revocation, replay attack prevention, and strict claim validation
- ⚡ **High Performance**: Up to 200k operations/second with optimized algorithms
- 🔧 **Flexible Storage**: In-memory, Redis, PostgreSQL, MongoDB — choose what fits your architecture
- 🧩 **Algorithm Support**: HMAC (HS256/384/512), RSA (RS256/384/512, PS256/384/512), ECDSA (ES256/384/512), EdDSA
- 🛡️ **Production Ready**: Thread-safe, context-aware, automatic cleanup, comprehensive error handling
- 📊 **Battle Tested**: Extensive test coverage with real-world scenarios and edge cases

---

## 📚 Table of Contents

- [Features](#-features)
- [Installation](#-installation)
- [Migrating from v1.x](#-migrating-from-v1x)
- [Quick Start](#-quick-start)
- [Architecture Overview](#-architecture-overview)
- [Configuration](#-configuration)
- [Storage Backends](#-storage-backends)
- [Token Types & Claims](#-token-types--claims)
- [Security Features](#-security-features)
- [Thread Safety](#-thread-safety)
- [API Reference](#-api-reference)
- [Advanced Usage](#-advanced-usage)
- [Performance](#-performance)
- [Best Practices](#-best-practices)
- [Examples](#-examples)
- [Testing](#-testing)
- [Contributing](#-contributing)
- [License](#-license)

---

## 🚀 Features

### Core Token Management

- **Dual Token System**: Short-lived access tokens (15-60 min) with long-lived refresh tokens (7-90 days)
- **Comprehensive Claims**: Opaque string identifiers for users/sessions, username, roles (RBAC), issuer, audience, timestamps
- **Flexible Expiration**: Configure both sliding expiration and absolute maximum lifetime
- **Context-Aware**: All operations support Go context for cancellation and timeouts

### Advanced Security

- **Token Rotation**: Automatic refresh token rotation with replay attack detection
- **Token Revocation**: Immediately invalidate tokens before natural expiration
- **Algorithm Flexibility**: Support for 11 different JWT signing algorithms
- **Strict Validation**: Comprehensive signature, expiration, claim, and type checking
- **Secure Defaults**: Pre-configured with industry best practices

### Storage & Scalability

- **Multiple Backends**: In-memory, Redis, PostgreSQL (pgx/v5, no ORM), MongoDB
- **Automatic Cleanup**: Background goroutines remove expired entries
- **Atomic Operations**: Race-condition-free rotation with compare-and-swap semantics
- **Production Scale**: Designed for distributed systems and high-throughput APIs

### Developer Experience

- **Clean API**: Intuitive interface with clear method signatures
- **Factory Methods**: Quick setup with defaults or full customization
- **Rich Documentation**: Comprehensive inline documentation and examples
- **Type Safety**: Strong typing with time.Time throughout; user/session identifiers are plain strings (any non-empty value, not restricted to UUID format)

---

## 📦 Installation

```bash
go get github.com/gourdian25/gourdiantoken/v2@latest
```

**Requirements**: Go 1.26.4 or higher (ecosystem-aligned minimum)

**Optional Dependencies** (based on storage backend):

```bash
# For Redis support
go get github.com/redis/go-redis/v9

# For PostgreSQL
go get github.com/jackc/pgx/v5

# For MongoDB
go get go.mongodb.org/mongo-driver
```

---

## ⬆️ Migrating from v1.x

**v2.0.0 is a breaking release**: `ID`/`Subject`/`SessionID` on `AccessTokenClaims`/`RefreshTokenClaims`, and `Subject`/`SessionID` on `AccessTokenResponse`/`RefreshTokenResponse`, changed from `uuid.UUID` to plain `string`. Likewise, the `userID`/`sessionID` parameters on `CreateAccessToken`/`CreateRefreshToken` are now `string` instead of `uuid.UUID`. Any non-empty string is now accepted — values no longer need to be UUID-shaped. If you were calling `.String()` on these fields, drop that call; they're already strings. See [CHANGELOG.md](./CHANGELOG.md) for the full list of changes, including several non-breaking fixes bundled into this release. Since `google/uuid` is now only used internally (for the token ID / `jti`), v2 consumers who only pass their own string identifiers no longer need to import it themselves at all — it remains a direct dependency of this module only for that internal use.

## ⚠️ Upgrading to v2.2.0 (GORM removed, storage names changed)

**v2.2.0 contains breaking changes despite the minor-looking version bump** — the module path stays `/v2` by choice (see below), but the changes are not backward compatible:

1. **GORM is gone.** `GormTokenRepository` and `NewGourdianTokenMakerWithGorm` no longer exist. Replace them with `PostgresTokenRepository` / `NewGourdianTokenMakerWithPostgres`, which take a `*pgxpool.Pool` you build and own yourself instead of a `*gorm.DB`:

   ```go
   // Before (v2.1.x)
   db, _ := gorm.Open(postgres.Open(dsn), &gorm.Config{})
   maker, err := gourdiantoken.NewGourdianTokenMakerWithGorm(ctx, config, db)

   // After (v2.2.0+)
   pool, _ := pgxpool.New(ctx, dsn)
   defer pool.Close()
   maker, err := gourdiantoken.NewGourdianTokenMakerWithPostgres(ctx, config, pool)
   ```

2. **Storage names changed to a `gourdiantoken`-prefixed convention**, matching the rest of the gourdian25 ecosystem:

   | Storage | Old name | New name |
   |---|---|---|
   | Postgres tables | `revoked_tokens`, `rotated_tokens` | `gourdiantoken_revoked_tokens`, `gourdiantoken_rotated_tokens` |
   | Mongo collections | `revoked_tokens`, `rotated_tokens` | `gourdiantoken_revoked_tokens`, `gourdiantoken_rotated_tokens` |
   | Redis key prefixes | `revoked:access:`, `revoked:refresh:`, `revoked:verification:`, `rotated:` | `gourdiantoken:revoked:access:`, `gourdiantoken:revoked:refresh:`, `gourdiantoken:revoked:verification:`, `gourdiantoken:rotated:` |

   **This is a new location, not an in-place rename.** Any revoked or rotated tokens recorded under the old names will not be visible after upgrading — previously-revoked tokens could appear valid again until they're revoked a second time or naturally expire. Before deploying this upgrade to a system with real users:
   - Either migrate existing rows/documents/keys to the new names yourself (a straightforward `INSERT INTO gourdiantoken_revoked_tokens SELECT * FROM revoked_tokens` for Postgres, an equivalent copy for Mongo/Redis), **or**
   - Accept a one-time revocation-state reset (safe only if you can tolerate previously-revoked tokens being accepted again for the remainder of their natural expiry).

3. **Why the module path didn't change to `/v3`**: Go's own tooling requires a `/v3` import path for a real `v3.0.0` tag, which would force every consumer to update their import statements. Since this library has few external consumers today, that churn wasn't worth it — this release intentionally does not follow strict semver (a breaking change shipped as a `v2.x.y` bump). If that changes and broad compatibility guarantees become necessary, a future breaking release will move to `/v3` properly.

---

## 🚀 Quick Start

### Basic HMAC Setup (No Storage)

Perfect for getting started, development, or stateless microservices:

```go
package main

import (
    "context"
    "fmt"
    "log"
    "time"

    "github.com/gourdian25/gourdiantoken/v2"
    "github.com/google/uuid"
)

func main() {
    ctx := context.Background()

    // 1. Create configuration with secure key (min 32 bytes)
    config := gourdiantoken.DefaultGourdianTokenConfig(
        "your-secret-key-at-least-32-bytes-long",
    )

    // 2. Create token maker (nil = no storage backend)
    maker, err := gourdiantoken.NewGourdianTokenMakerNoStorage(ctx, config)
    if err != nil {
        log.Fatal(err)
    }

    // 3. Create access token
    userID := uuid.NewString()
    sessionID := uuid.NewString()
    
    accessToken, err := maker.CreateAccessToken(
        ctx,
        userID,
        "john.doe@example.com",
        []string{"user", "admin"},
        sessionID,
    )
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Access Token: %s\n", accessToken.Token)
    fmt.Printf("Expires: %s\n", accessToken.ExpiresAt.Format(time.RFC3339))

    // 4. Verify token
    claims, err := maker.VerifyAccessToken(ctx, accessToken.Token)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("User: %s (ID: %s)\n", claims.Username, claims.Subject)
    fmt.Printf("Roles: %v\n", claims.Roles)
    fmt.Printf("Session: %s\n", claims.SessionID)
}
```

### Production Setup with Redis

For production systems with token rotation and revocation:

```go
package main

import (
    "context"
    "log"
    "time"

    "github.com/gourdian25/gourdiantoken/v2"
    "github.com/google/uuid"
    "github.com/redis/go-redis/v9"
)

func main() {
    ctx := context.Background()

    // 1. Configure Redis
    redisClient := redis.NewClient(&redis.Options{
        Addr:     "localhost:6379",
        Password: "",
        DB:       0,
        PoolSize: 100,
    })

    // 2. Create configuration
    config := gourdiantoken.GourdianTokenConfig{
        SigningMethod:            gourdiantoken.Symmetric,
        Algorithm:                "HS256",
        SymmetricKey:             "your-production-secret-key-32-bytes",
        Issuer:                   "auth.myapp.com",
        Audience:                 []string{"api.myapp.com", "admin.myapp.com"},
        AllowedAlgorithms:        []string{"HS256", "HS384", "HS512"},
        RequiredClaims:           []string{"iss", "aud", "nbf", "mle"},
        RevocationEnabled:        true,
        RotationEnabled:          true,
        AccessExpiryDuration:     15 * time.Minute,
        AccessMaxLifetimeExpiry:  24 * time.Hour,
        RefreshExpiryDuration:    7 * 24 * time.Hour,
        RefreshMaxLifetimeExpiry: 30 * 24 * time.Hour,
        RefreshReuseInterval:     5 * time.Minute,
        CleanupInterval:          6 * time.Hour,
    }

    // 3. Create token maker with Redis
    maker, err := gourdiantoken.NewGourdianTokenMakerWithRedis(ctx, config, redisClient)
    if err != nil {
        log.Fatal(err)
    }

    userID := uuid.NewString()
    sessionID := uuid.NewString()

    // 4. Create token pair
    accessToken, _ := maker.CreateAccessToken(ctx, userID, "alice", []string{"user"}, sessionID)
    refreshToken, _ := maker.CreateRefreshToken(ctx, userID, "alice", sessionID)

    // 5. Rotate refresh token (old token becomes invalid)
    newRefreshToken, err := maker.RotateRefreshToken(ctx, refreshToken.Token)
    if err != nil {
        log.Printf("Rotation failed: %v", err)
    }

    // 6. Revoke on logout
    maker.RevokeAccessToken(ctx, accessToken.Token)
    maker.RevokeRefreshToken(ctx, newRefreshToken.Token)
}
```

---

## 🏗️ Architecture Overview

### Core Components

``` txt
┌─────────────────────────────────────────────────────────────┐
│                    GourdianTokenMaker                       │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │   Create     │  │    Verify    │  │   Revoke/    │     │
│  │   Tokens     │  │   Tokens     │  │   Rotate     │     │
│  └──────────────┘  └──────────────┘  └──────────────┘     │
└───────────────────────┬─────────────────────────────────────┘
                        │
        ┌───────────────┴───────────────┐
        │                               │
┌───────▼──────┐               ┌───────▼──────┐
│  Cryptographic│               │   Token      │
│   Signing     │               │  Repository  │
│  (JWT Library)│               │  (Storage)   │
└───────────────┘               └───────┬──────┘
                                        │
                    ┌───────────────────┼───────────────────┐
                    │                   │                   │
            ┌───────▼─────┐   ┌────────▼────────┐  ┌──────▼──────┐
            │  In-Memory  │   │     Redis       │  │  SQL/MongoDB│
            │  (Testing)  │   │  (Production)   │  │(Enterprise) │
            └─────────────┘   └─────────────────┘  └─────────────┘
```

### Token Lifecycle

``` txt
┌──────────┐
│  Login   │
└────┬─────┘
     │
     ▼
┌──────────────────────┐
│ CreateAccessToken    │◄──────────────┐
│ CreateRefreshToken   │               │
└────┬─────────────────┘               │
     │                                 │
     ▼                                 │
┌──────────────────────┐         ┌────┴─────────────┐
│   API Request with   │         │ RotateRefreshToken│
│   Access Token       │         │ (Get New Access)  │
└────┬─────────────────┘         └──────────────────┘
     │                                 ▲
     ▼                                 │
┌──────────────────────┐               │
│ VerifyAccessToken    │───────────────┘
└────┬─────────────────┘      Token Expired
     │
     ▼
┌──────────────────────┐
│   Grant Access /     │
│  Check Revocation    │
└────┬─────────────────┘
     │
     ▼
┌──────────────────────┐
│  Logout / Revoke     │
└──────────────────────┘
```

---

## ⚙️ Configuration

### Configuration Structure

```go
type GourdianTokenConfig struct {
    // Security Features
    RotationEnabled          bool          // Enable refresh token rotation
    RevocationEnabled        bool          // Enable token revocation
    
    // Cryptography
    SigningMethod            SigningMethod // Symmetric or Asymmetric
    Algorithm                string        // HS256, RS256, ES256, EdDSA, etc.
    SymmetricKey             string        // For HMAC (min 32 bytes)
    PrivateKeyPath           string        // For RSA/ECDSA/EdDSA
    PublicKeyPath            string        // For RSA/ECDSA/EdDSA
    
    // JWT Claims
    Issuer                   string        // Token issuer (iss)
    Audience                 []string      // Intended recipients (aud)
    AllowedAlgorithms        []string      // Algorithm whitelist
    RequiredClaims           []string      // Mandatory claims
    
    // Token Lifetimes
    AccessExpiryDuration     time.Duration // Access token lifetime
    AccessMaxLifetimeExpiry  time.Duration // Absolute max for access
    RefreshExpiryDuration    time.Duration // Refresh token lifetime
    RefreshMaxLifetimeExpiry time.Duration // Absolute max for refresh
    RefreshReuseInterval     time.Duration // Min time between reuse
    
    // Maintenance
    CleanupInterval          time.Duration // Cleanup frequency
    
    // Verification Tokens (optional; see "Verification Tokens" below)
    VerificationTokensEnabled         bool          // Master switch
    VerificationAllowedUseCases       []string      // Use-case whitelist
    VerificationDefaultExpiryDuration time.Duration // Used when ttl <= 0
    VerificationMaxExpiryDuration     time.Duration // Ceiling on caller-supplied ttl
}
```

### Configuration Field Reference

All ~21 fields of `GourdianTokenConfig`, what they control, their default under
`DefaultGourdianTokenConfig`, and — since `NewGourdianTokenConfig`'s fixed
positional-argument list is a common source of mistakes — exactly which
argument position each one maps to.

| Field | Type | Purpose | Default (`DefaultGourdianTokenConfig`) | `NewGourdianTokenConfig` arg # |
|---|---|---|---|---|
| `SigningMethod` | `SigningMethod` | `Symmetric` (HMAC) or `Asymmetric` (RSA/ECDSA/EdDSA) | `Symmetric` | 1 |
| `RotationEnabled` | `bool` | Enforce single-use refresh token rotation | `false` | 2 |
| `RevocationEnabled` | `bool` | Allow explicit revocation before expiry | `false` | 3 |
| `Audience` | `[]string` | Values written to / checked against the `aud` claim | `nil` | 4 |
| `AllowedAlgorithms` | `[]string` | Verification-time algorithm whitelist | `["HS256","HS384","HS512","RS256","ES256","PS256"]` | 5 |
| `RequiredClaims` | `[]string` | Claims that must be present on every token | `["iss","aud","nbf","mle"]` | 6 |
| `Algorithm` | `string` | JWT signing algorithm (must match `SigningMethod`) | `"HS256"` | 7 |
| `SymmetricKey` | `string` | HMAC secret; must be ≥ 32 bytes | caller-supplied | 8 |
| `PrivateKeyPath` | `string` | PEM private key path (asymmetric only) | `""` | 9 |
| `PublicKeyPath` | `string` | PEM public key path (asymmetric only) | `""` | 10 |
| `Issuer` | `string` | Value written to / checked against the `iss` claim | `"gourdian.com"` | 11 |
| `AccessExpiryDuration` | `time.Duration` | Access token sliding lifetime | `30m` | 12 |
| `AccessMaxLifetimeExpiry` | `time.Duration` | Absolute ceiling for access tokens (`mle` claim) | `24h` | 13 |
| `RefreshExpiryDuration` | `time.Duration` | Refresh token sliding lifetime | `7d` | 14 |
| `RefreshMaxLifetimeExpiry` | `time.Duration` | Absolute ceiling for refresh tokens (`mle` claim) | `30d` | 15 |
| `RefreshReuseInterval` | `time.Duration` | Minimum gap between reuse attempts (`0` disables) | `5m` | 16 |
| `CleanupInterval` | `time.Duration` | How often background goroutines purge expired entries | `6h` | 17 |
| `VerificationTokensEnabled` | `bool` | Master switch for `CreateVerificationToken`/`VerifyVerificationToken`/`MarkVerificationTokenUsed` | `false` | not settable — assign the field directly |
| `VerificationAllowedUseCases` | `[]string` | Whitelist of acceptable `useCase` strings; empty = any non-empty value | `nil` | not settable — assign the field directly |
| `VerificationDefaultExpiryDuration` | `time.Duration` | Lifetime used when `CreateVerificationToken`'s `ttl` is `<= 0` | `0` (must set if enabling) | not settable — assign the field directly |
| `VerificationMaxExpiryDuration` | `time.Duration` | Ceiling a caller-supplied `ttl` may not exceed; `0` = no ceiling | `0` | not settable — assign the field directly |

The four `Verification*` fields postdate `NewGourdianTokenConfig` and are not
among its parameters at all — set them via struct-field assignment after
construction regardless of which constructor you used, e.g.
`config.VerificationTokensEnabled = true`.

### Factory Methods

#### 1. DefaultGourdianTokenConfig (Quick Start)

```go
config := gourdiantoken.DefaultGourdianTokenConfig("your-secret-key")
```

**Defaults:**

- Algorithm: HS256
- Access Token: 30 minutes (max 24 hours)
- Refresh Token: 7 days (max 30 days)
- Rotation/Revocation: Disabled
- Issuer: "gourdian.com"

#### 2. NewGourdianTokenConfig (Full Control)

> **Deprecated.** `NewGourdianTokenConfig` will be removed in a future major
> version. Its fixed 17-argument positional list predates the `Verification*`
> fields (which it cannot set at all — see the table above) and is easy to
> get wrong by position. Prefer `DefaultGourdianTokenConfig` plus
> struct-field assignment, or a bare `gourdiantoken.GourdianTokenConfig{...}`
> literal. It's documented here only because a lot of existing call sites
> use it and the positional table above is the fastest way to read them.

```go
config := gourdiantoken.NewGourdianTokenConfig(
    gourdiantoken.Asymmetric,           // Signing method
    true,                                // Rotation enabled
    true,                                // Revocation enabled
    []string{"api.example.com"},         // Audience
    []string{"RS256", "ES256"},          // Allowed algorithms
    []string{"iss", "aud", "nbf", "mle"},// Required claims
    "RS256",                             // Algorithm
    "",                                  // Symmetric key (empty for asymmetric)
    "/path/to/private.pem",              // Private key
    "/path/to/public.pem",               // Public key
    "auth.example.com",                  // Issuer
    15*time.Minute,                      // Access expiry
    24*time.Hour,                        // Access max lifetime
    7*24*time.Hour,                      // Refresh expiry
    30*24*time.Hour,                     // Refresh max lifetime
    5*time.Minute,                       // Reuse interval
    6*time.Hour,                         // Cleanup interval
)
```

### Configuration Examples

#### Development (HMAC, No Storage)

```go
config := gourdiantoken.DefaultGourdianTokenConfig("dev-secret-key-32-bytes-long")
maker, _ := gourdiantoken.NewGourdianTokenMakerNoStorage(ctx, config)
```

#### Production (RSA with Redis)

```go
config := gourdiantoken.NewGourdianTokenConfig(
    gourdiantoken.Asymmetric, true, true,
    []string{"api.prod.com"}, []string{"RS256"},
    []string{"iss", "aud", "exp", "nbf", "mle"},
    "RS256", "", "/keys/private.pem", "/keys/public.pem",
    "auth.prod.com",
    15*time.Minute, 24*time.Hour,
    7*24*time.Hour, 30*24*time.Hour,
    5*time.Minute, 6*time.Hour,
)
redisClient := redis.NewClient(&redis.Options{Addr: "redis:6379"})
maker, _ := gourdiantoken.NewGourdianTokenMakerWithRedis(ctx, config, redisClient)
```

#### High Security (EdDSA with MongoDB)

```go
client, _ := mongo.Connect(ctx, options.Client().ApplyURI("mongodb://localhost:27017"))
mongoDB := client.Database("auth")

config := gourdiantoken.NewGourdianTokenConfig(
    gourdiantoken.Asymmetric, true, true,
    []string{"secure-api.com"}, []string{"EdDSA"},
    []string{"iss", "aud", "exp", "nbf", "mle"},
    "EdDSA", "", "/keys/ed25519-private.pem", "/keys/ed25519-public.pem",
    "auth.secure.com",
    15*time.Minute, 12*time.Hour,
    24*time.Hour, 7*24*time.Hour,
    10*time.Minute, 1*time.Hour,
)
maker, _ := gourdiantoken.NewGourdianTokenMakerWithMongo(ctx, config, mongoDB, true) // transactionsEnabled: requires mongoDB's replica set
```

### Functional Options: `WithLogger`

Every constructor (`NewGourdianTokenMaker` and all `NewGourdianTokenMakerWith*`
factories) accepts variadic `...Option`. `WithLogger` is the original
logging hook, predating the rest of the ecosystem's convention:

```go
maker, err := gourdiantoken.NewGourdianTokenMakerWithRedis(
    ctx, config, redisClient,
    gourdiantoken.WithLogger(func(format string, args ...any) {
        log.Printf(format, args...)
    }),
)
```

`WithLogger` redirects error reports from the background cleanup goroutines
away from the default `fmt.Printf`-based logger. Its signature is a bare
`func(format string, args ...any)` printf-style callback. It is unchanged
and continues to work exactly as before — see `WithStructuredLogger` below
for a second, additive option that plugs directly into the rest of the
ecosystem's logging convention.

### Functional Options: `WithStructuredLogger`

grcache, grevents, graudit, grpolicy, and grnoti all accept a shared
`Logger` interface (`Debug`/`Info`/`Warn`/`Error(msg string, args ...any)`)
matching `*slog.Logger`'s own signatures. `gourdiantoken.WithStructuredLogger`
accepts the same shape:

```go
import (
    "log/slog"

    "github.com/gourdian25/grlog"
)

logger := slog.New(grlog.NewSlogHandler(grlog.NewDefaultLogger()))

maker, err := gourdiantoken.NewGourdianTokenMakerWithRedis(
    ctx, config, redisClient,
    gourdiantoken.WithStructuredLogger(logger), // *slog.Logger satisfies Logger directly
)
```

When set, it's used instead of `WithLogger`'s `logf` callback for the same
two background-cleanup error reports; when unset, `logf`'s behavior is
completely unaffected. The two options are independent — set one, the
other, both, or neither.

---

## 💾 Storage Backends

### Overview

| Backend | Use Case | Performance | Persistence | Distributed |
|---------|----------|-------------|-------------|-------------|
| **In-Memory** | Development, Testing | ⚡⚡⚡ | ❌ | ❌ |
| **Redis** | Production, High-Performance | ⚡⚡⚡ | ✅ (optional) | ✅ |
| **PostgreSQL** | Enterprise, Complex Queries | ⚡⚡ | ✅ | ✅ |
| **MongoDB** | Document-Oriented, Scaling | ⚡⚡ | ✅ | ✅ |

### 1. No Storage (Stateless)

```go
maker, err := gourdiantoken.NewGourdianTokenMakerNoStorage(ctx, config)
```

**Features:**

- No dependencies
- No revocation/rotation support
- Perfect for microservices that only verify tokens
- Highest performance

**Limitations:**

- Cannot revoke tokens
- Cannot rotate tokens
- Config must have `RevocationEnabled` and `RotationEnabled` set to `false`

### 2. In-Memory Storage

```go
maker, err := gourdiantoken.NewGourdianTokenMakerWithMemory(ctx, config)
```

**Features:**

- Built-in storage
- Automatic cleanup
- Thread-safe
- Zero external dependencies

**Best For:**

- Development and testing
- Single-instance applications
- Prototyping

**Limitations:**

- Data lost on restart
- Not suitable for distributed systems

### 3. Redis Storage

```go
redisClient := redis.NewClient(&redis.Options{
    Addr:     "localhost:6379",
    Password: "",
    DB:       0,
    PoolSize: 100,
})
maker, err := gourdiantoken.NewGourdianTokenMakerWithRedis(ctx, config, redisClient)
```

**Features:**

- Sub-millisecond operations
- Automatic TTL-based expiration
- Distributed support via Redis Cluster
- Built-in persistence options

**Best For:**

- Production systems
- High-throughput APIs
- Microservices architectures
- Real-time applications

### 4. PostgreSQL Storage

```go
import "github.com/jackc/pgx/v5/pgxpool"

pool, _ := pgxpool.New(ctx, dsn)
defer pool.Close()
maker, err := gourdiantoken.NewGourdianTokenMakerWithPostgres(ctx, config, pool)
```

**Features:**

- pgx/v5 + sqlc-generated queries — no ORM overhead
- ACID transactions
- Schema applied automatically (`CREATE TABLE/INDEX IF NOT EXISTS`, advisory-lock-guarded so concurrent callers don't race)
- Connection pooling via the caller-provided `*pgxpool.Pool` — share one pool across your whole backend instead of opening a separate one per store

**Best For:**

- Existing PostgreSQL infrastructure
- Complex audit requirements
- Enterprise applications

### 5. MongoDB Storage

```go
client, _ := mongo.Connect(ctx, options.Client().ApplyURI(mongoURI))
mongoDB := client.Database("auth_service")
maker, err := gourdiantoken.NewGourdianTokenMakerWithMongo(ctx, config, mongoDB, true)
```

**Features:**

- Document-oriented storage
- Automatic TTL indexes
- Optional transactions, controlled by the `transactionsEnabled` argument above (requires a replica set — pass `false` against a standalone instance)
- Horizontal scaling via sharding

**Best For:**

- Document-based architectures
- High write throughput
- Flexible schemas

---

## 🔑 Token Types & Claims

### Access Tokens

**Purpose**: Short-lived credentials for API authorization

**Standard Claims:**

```json
{
  "jti": "123e4567-e89b-12d3-a456-426614174000",
  "sub": "123e4567-e89b-12d3-a456-426614174000",
  "usr": "john.doe@example.com",
  "sid": "123e4567-e89b-12d3-a456-426614174000",
  "iss": "auth.example.com",
  "aud": ["api.example.com"],
  "iat": 1609459200,
  "exp": 1609460000,
  "nbf": 1609459200,
  "mle": 1609545600,
  "typ": "access",
  "rls": ["user", "admin"]
}
```

**Go Structure:**

```go
type AccessTokenClaims struct {
    ID                string      `json:"jti"`
    Subject           string      `json:"sub"`
    SessionID         string      `json:"sid"`
    Username          string      `json:"usr"`
    Issuer            string      `json:"iss"`
    Audience          []string    `json:"aud"`
    Roles             []string    `json:"rls"`
    IssuedAt          time.Time   `json:"iat"`
    ExpiresAt         time.Time   `json:"exp"`
    NotBefore         time.Time   `json:"nbf"`
    MaxLifetimeExpiry time.Time   `json:"mle"`
    TokenType         TokenType   `json:"typ"`
}
```

### Refresh Tokens

**Purpose**: Long-lived credentials for obtaining new access tokens

**Standard Claims:**

```json
{
  "jti": "789e4567-e89b-12d3-a456-426614174999",
  "sub": "123e4567-e89b-12d3-a456-426614174000",
  "usr": "john.doe@example.com",
  "sid": "123e4567-e89b-12d3-a456-426614174000",
  "iss": "auth.example.com",
  "aud": ["api.example.com"],
  "iat": 1609459200,
  "exp": 1610064000,
  "nbf": 1609459200,
  "mle": 1612137600,
  "typ": "refresh"
}
```

**Note**: Refresh tokens do NOT include the `rls` (roles) claim.

### Verification Tokens

**Purpose**: Short-lived, single-use, use-case-scoped tokens for gaps between two authentication steps — e.g. a 2FA-pending verification step between password check and full session issuance, or password-reset/email-verify links.

**Standard Claims:**

```json
{
  "jti": "abc12345-e89b-12d3-a456-426614174000",
  "sub": "123e4567-e89b-12d3-a456-426614174000",
  "uc": "2fa-pending",
  "iss": "auth.example.com",
  "aud": ["api.example.com"],
  "iat": 1609459200,
  "exp": 1609459500,
  "nbf": 1609459200,
  "mle": 1609459500,
  "typ": "verification",
  "mtd": { "username": "john.doe@example.com" }
}
```

**Go Structure:**

```go
type VerificationTokenClaims struct {
    ID                string                 `json:"jti"`
    Subject           string                 `json:"sub"`
    UseCase           string                 `json:"uc"`
    Issuer            string                 `json:"iss"`
    Audience          []string               `json:"aud"`
    IssuedAt          time.Time              `json:"iat"`
    ExpiresAt         time.Time              `json:"exp"`
    NotBefore         time.Time              `json:"nbf"`
    MaxLifetimeExpiry time.Time              `json:"mle"`
    Metadata          map[string]interface{} `json:"mtd,omitempty"`
    TokenType         TokenType              `json:"typ"`
}
```

**Note**: No `sid`/`usr`/`rls` claims — no session, username, or roles concept. Requires `VerificationTokensEnabled`; accessed via the optional `GourdianTokenMakerVerification` interface. `mle` always equals `exp` (verification tokens are never renewed). Unlike `CreateAccessToken`/`CreateRefreshToken`, `CreateVerificationToken` takes a per-call `ttl` (0 = use `VerificationDefaultExpiryDuration`).

```go
maker, err := gourdiantoken.NewGourdianTokenMakerWithMemory(ctx, config)
verifier, ok := maker.(gourdiantoken.GourdianTokenMakerVerification)

// 1. Mint a 5-minute, single-use token scoped to "2fa-pending"
token, err := verifier.CreateVerificationToken(ctx, userID, "2fa-pending", 5*time.Minute, nil)

// 2. Verify it (does not consume it — safe to call more than once)
claims, err := verifier.VerifyVerificationToken(ctx, token.Token)

// 3. Once the gated action actually completes (e.g. TOTP check passed), consume it
err = verifier.MarkVerificationTokenUsed(ctx, token.Token)

// 4. A second verify now fails with ErrTokenAlreadyUsed
_, err = verifier.VerifyVerificationToken(ctx, token.Token) // errors.Is(err, gourdiantoken.ErrTokenAlreadyUsed)
```

### Token Comparison

| Feature | Access Token | Refresh Token | Verification Token |
|---------|-------------|---------------|---------------------|
| **Lifetime** | 15-60 minutes | 7-90 days | Per-call (default 5-15 min) |
| **Contains Roles** | ✅ Yes | ❌ No | ❌ No |
| **Used for API Calls** | ✅ Yes | ❌ No | ❌ No |
| **Can be Rotated** | ❌ No | ✅ Yes | ❌ No |
| **Revocable / Single-use** | ✅ Revocable | ✅ Revocable | ✅ Single-use (via revocation) |
| **Typical Storage** | Authorization header | HttpOnly cookie | Query param / form field |

---

## 🔐 Security Features

### 1. Token Revocation

Immediately invalidate tokens before natural expiration.

```go
// Revoke access token (e.g., on logout)
err := maker.RevokeAccessToken(ctx, accessTokenString)

// Revoke refresh token
err := maker.RevokeRefreshToken(ctx, refreshTokenString)
```

**How It Works:**

- Token hash stored in storage backend with TTL matching remaining lifetime
- Verification checks revocation status before accepting token
- Automatic cleanup removes expired revocations

**Use Cases:**

- User logout
- Security breach response
- Account suspension
- Password changes

### 2. Token Rotation

Refresh tokens are single-use when rotation is enabled.

```go
// Rotate refresh token (old token becomes invalid)
newRefreshToken, err := maker.RotateRefreshToken(ctx, oldRefreshTokenString)
if err != nil {
    // Token already rotated or invalid
    // Possible attack detected!
}
```

**Security Benefits:**

- Prevents token replay attacks
- Detects stolen tokens (multiple rotation attempts fail)
- Limits blast radius of compromised tokens

**How It Works:**

1. Verify old token is valid
2. Atomically mark old token as rotated (compare-and-swap)
3. Create new token with fresh expiration
4. Return new token; old token now invalid

### 3. Algorithm Support

```go
// Symmetric (HMAC) - Fastest
config.Algorithm = "HS256"  // or HS384, HS512

// Asymmetric (RSA) - Most Compatible
config.Algorithm = "RS256"  // or RS384, RS512
config.Algorithm = "PS256"  // RSA-PSS (recommended)

// Asymmetric (ECDSA) - Balanced
config.Algorithm = "ES256"  // or ES384, ES512

// Asymmetric (EdDSA) - Modern
config.Algorithm = "EdDSA"  // Ed25519
```

**Algorithm Recommendations:**

| Environment | Algorithm | Reason |
|-------------|-----------|--------|
| Development | HS256 | Fast, simple |
| Production API | ES256 | Balanced speed/security |
| High Security | EdDSA | Modern, resistant to side-channel attacks |
| Legacy Systems | RS256 | Widest compatibility |

### 4. Claim Validation

Automatic validation of all critical claims:

- ✅ Token signature verification
- ✅ Expiration time (`exp > now`)
- ✅ Not-before time (`nbf <= now`)
- ✅ Maximum lifetime (`mle > now`)
- ✅ Token type (access vs refresh)
- ✅ Required claims presence
- ✅ Non-empty identifier validation (`jti`/`sub`; `sid` may be empty for sessionless tokens)
- ✅ Revocation status (if enabled)
- ✅ Rotation status (if enabled)

### 5. Secure Defaults

- ✅ "none" algorithm explicitly blocked
- ✅ Minimum key sizes enforced (32 bytes for HMAC)
- ✅ Private key file permissions checked (0600)
- ✅ Algorithm must match signing method
- ✅ Logical duration validation
- ✅ Required claims enforced

---

## 🔒 Thread Safety

**`JWTMaker`** (the concrete `GourdianTokenMaker`/`GourdianTokenMakerCloser`
implementation returned by every constructor) is safe for concurrent use by
multiple goroutines without any extra locking on the caller's part. Its
config, cryptographic keys, and signing method are set once at construction
and never mutated afterward; the only mutable field is an internal
`sync.Once` that makes `Close()` idempotent. This means a single `maker` can
be shared freely across request-handling goroutines, cron jobs, and cleanup
tasks.

**Repository implementations** are independently safe for concurrent use:

| Backend | Safety mechanism |
|---|---|
| `MemoryTokenRepository` | `sync.RWMutex` around its in-process map — concurrent readers (`IsTokenRevoked`/`IsTokenRotated`), exclusive writers (`MarkTokenRevoke`/`MarkTokenRotatedAtomic`) |
| `RedisTokenRepository` | Delegates to `*redis.Client`, which is safe for concurrent use across goroutines |
| `PostgresTokenRepository` | Delegates to `*pgxpool.Pool`, which is safe for concurrent use across goroutines |
| `MongoTokenRepository` | Delegates to `*mongo.Database`, which is safe for concurrent use across goroutines |

Background cleanup goroutines (`cleanupRotatedTokens`/`cleanupRevokedTokens`,
started automatically when `RotationEnabled`/`RevocationEnabled` is set) run
independently of request-handling goroutines and use the same repository
methods, so no additional synchronization is needed on the caller's side.

**What is *not* automatically safe:** mutating a `GourdianTokenConfig` value
(or a struct you derived one from) concurrently with using it — build the
config once, before constructing the maker, and treat it as read-only
afterward. The maker itself never mutates the config it was given.

Every method on `GourdianTokenMaker`, `GourdianTokenMakerVerification`, and
`TokenRepository` takes a `context.Context` and checks it for cancellation at
multiple points, so long-running operations (e.g. a slow database call
inside a repository implementation) can be bounded with the usual
`context.WithTimeout`/`WithCancel`.

---

## 📖 API Reference

### GourdianTokenMaker Interface

```go
type GourdianTokenMaker interface {
    CreateAccessToken(ctx context.Context, userID string, username string, roles []string, sessionID string) (*AccessTokenResponse, error)
    CreateRefreshToken(ctx context.Context, userID string, username string, sessionID string) (*RefreshTokenResponse, error)
    VerifyAccessToken(ctx context.Context, tokenString string) (*AccessTokenClaims, error)
    VerifyRefreshToken(ctx context.Context, tokenString string) (*RefreshTokenClaims, error)
    RevokeAccessToken(ctx context.Context, token string) error
    RevokeRefreshToken(ctx context.Context, token string) error
    RotateRefreshToken(ctx context.Context, oldToken string) (*RefreshTokenResponse, error)
}
```

### CreateAccessToken

```go
token, err := maker.CreateAccessToken(
    ctx,
    userID,          // string - User's unique identifier (must not be empty)
    username,        // string - Human-readable name
    roles,           // []string - Authorization roles (min 1)
    sessionID,       // string - Session identifier (may be empty)
)
```

**Returns:** `*AccessTokenResponse` containing signed JWT and metadata

**Validation:**

- `userID` must not be empty
- `username` max 1024 characters
- `roles` must contain at least one non-empty string
- Checks context cancellation before signing

### CreateRefreshToken

```go
token, err := maker.CreateRefreshToken(
    ctx,
    userID,          // string
    username,        // string
    sessionID,       // string
)
```

**Returns:** `*RefreshTokenResponse` containing signed JWT and metadata

**Note:** Refresh tokens do NOT include roles

### VerifyAccessToken

```go
claims, err := maker.VerifyAccessToken(ctx, tokenString)
```

**Validation Steps:**

1. Check context cancellation
2. Check revocation status (if enabled)
3. Verify cryptographic signature
4. Validate algorithm
5. Check timestamps (iat, exp, nbf, mle)
6. Verify required claims
7. Validate token type is "access"

**Returns:** `*AccessTokenClaims` with all decoded fields

### VerifyRefreshToken

```go
claims, err := maker.VerifyRefreshToken(ctx, tokenString)
```

**Additional Checks:**

- Token rotation status (if enabled)
- Token type is "refresh"

**Returns:** `*RefreshTokenClaims`

### RevokeAccessToken

```go
err := maker.RevokeAccessToken(ctx, tokenString)
```

**Requirements:**

- `RevocationEnabled` must be `true`
- Valid token repository configured

**Effect:** Token immediately becomes invalid

### RevokeRefreshToken

```go
err := maker.RevokeRefreshToken(ctx, tokenString)
```

**Requirements:** Same as `RevokeAccessToken`

### RotateRefreshToken

```go
newToken, err := maker.RotateRefreshToken(ctx, oldTokenString)
```

**Requirements:**

- `RotationEnabled` must be `true`
- Valid token repository configured

**Process:**

1. Verify old token
2. Atomically mark as rotated (only first caller succeeds)
3. Create new token
4. Return new token

**Security:** If token already rotated, returns error (possible attack)

### CreateVerificationToken

```go
verifier := maker.(gourdiantoken.GourdianTokenMakerVerification)
token, err := verifier.CreateVerificationToken(ctx, userID, useCase, ttl, metadata)
```

**Requirements:** `VerificationTokensEnabled` must be `true`

**Parameters:** `ttl <= 0` falls back to `VerificationDefaultExpiryDuration`; a `ttl` exceeding `VerificationMaxExpiryDuration` (if configured) is rejected. `useCase` must be non-empty and, if `VerificationAllowedUseCases` is set, must appear in that whitelist.

### VerifyVerificationToken

```go
claims, err := verifier.VerifyVerificationToken(ctx, tokenString)
```

**Requirements:** `VerificationTokensEnabled` must be `true`

**Effect:** Does not consume the token — safe to call more than once before deliberately marking it used.

### MarkVerificationTokenUsed

```go
err := verifier.MarkVerificationTokenUsed(ctx, tokenString)
```

**Requirements:**

- `VerificationTokensEnabled` must be `true`
- `RevocationEnabled` must be `true`
- Valid token repository configured

**Effect:** Token immediately becomes invalid for future `VerifyVerificationToken` calls, which then fail with `ErrTokenAlreadyUsed`

---

## 🎓 Advanced Usage

### Complete Authentication Flow

See [Quick Start → Production Setup with Redis](#production-setup-with-redis) above for a
full create → rotate → revoke walkthrough with a real `TokenRepository`
backend. Wiring that up behind HTTP handlers (login issues a token pair;
an auth middleware calls `VerifyAccessToken` and attaches claims to the
request context; a refresh endpoint calls `RotateRefreshToken`; logout calls
`RevokeAccessToken`/`RevokeRefreshToken`) is a direct application of the
methods documented in [API Reference](#-api-reference) — see
`authMiddleware` in [Example 1](#example-1-standard-library-http-server)
below for the middleware half of that pattern.

### Role-Based Access Control (RBAC)

```go
func requireRole(requiredRole string) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            claims := r.Context().Value("claims").(*gourdiantoken.AccessTokenClaims)
            
            hasRole := false
            for _, role := range claims.Roles {
                if role == requiredRole {
                    hasRole = true
                    break
                }
            }
            
            if !hasRole {
                http.Error(w, "Insufficient permissions", http.StatusForbidden)
                return
            }
            
            next.ServeHTTP(w, r)
        })
    }
}

// Usage
http.Handle("/admin", 
    authMiddleware(
        requireRole("admin")(
            http.HandlerFunc(adminHandler),
        ),
    ),
)
```

### Gin Framework Middleware

For projects using [Gin](https://github.com/gin-gonic/gin), the pattern is the
same as the standard-library middleware above: pull the bearer token, call
`VerifyAccessToken`, and attach the claims to the request context.

```go
package middleware

import (
    "errors"
    "net/http"
    "strings"

    "github.com/gin-gonic/gin"
    "github.com/gourdian25/gourdiantoken/v2"
)

// AccessTokenMiddleware verifies the bearer access token and attaches its
// claims to the Gin context for downstream handlers.
func AccessTokenMiddleware(maker gourdiantoken.GourdianTokenMaker) gin.HandlerFunc {
    return func(c *gin.Context) {
        tokenString := strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer ")
        if tokenString == "" {
            c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing token"})
            return
        }

        claims, err := maker.VerifyAccessToken(c.Request.Context(), tokenString)
        if err != nil {
            status := http.StatusUnauthorized
            if errors.Is(err, gourdiantoken.ErrTokenRevoked) {
                status = http.StatusForbidden
            }
            c.AbortWithStatusJSON(status, gin.H{"error": err.Error()})
            return
        }

        c.Set("claims", claims) // *gourdiantoken.AccessTokenClaims
        c.Next()
    }
}

// Usage: protected := r.Group("/api"); protected.Use(AccessTokenMiddleware(maker))
```

A refresh-token middleware and a `RequireRoles(...)` role-check middleware
follow the same shape, calling `VerifyRefreshToken`/`RotateRefreshToken` and
inspecting `claims.Roles` respectively — see
[Role-Based Access Control (RBAC)](#role-based-access-control-rbac) above and
the [API Reference](#-api-reference) for the calls each would wrap.

### Asymmetric Key Setup

```go
func setupAsymmetric() (gourdiantoken.GourdianTokenMaker, error) {
    // NewGourdianTokenMakerNoStorage requires RotationEnabled and
    // RevocationEnabled to both be false (no repository = nowhere to track
    // revoked/rotated tokens) — pass false, false here rather than true, true.
    config := gourdiantoken.NewGourdianTokenConfig(
        gourdiantoken.Asymmetric,
        false, false,
        []string{"api.example.com"},
        []string{"RS256", "ES256"},
        []string{"iss", "aud", "nbf", "mle"},
        "RS256",
        "",
        "/secure/keys/private.pem",
        "/secure/keys/public.pem",
        "auth.example.com",
        15*time.Minute, 24*time.Hour,
        7*24*time.Hour, 30*24*time.Hour,
        5*time.Minute, 6*time.Hour,
    )
    
    ctx := context.Background()
    return gourdiantoken.NewGourdianTokenMakerNoStorage(ctx, config)
}
```

---

## ⚡ Performance

### Benchmark Results

Benchmarks run on Apple M4, Go 1.26.4, 2026-07-22 (`make bench` / targeted
`go test -bench=...`). Operations/sec is derived as `1e9 / ns_op` from the
raw `go test -bench` output.

#### Token Creation

| Benchmark | Operations/sec | Time/op | Memory/op | Allocs/op |
|-----------|----------------|---------|-----------|-----------|
| **CreateAccessToken** | 318,370 | 3.14µs | 5.89 KB | 71 |
| **HS256** | 312,012 | 3.21µs | 5.89 KB | 71 |
| **HS384** | 265,111 | 3.77µs | 6.28 KB | 71 |
| **HS512** | 284,738 | 3.51µs | 6.36 KB | 71 |

#### Token Verification

| Benchmark | Operations/sec | Time/op | Memory/op | Allocs/op |
|-----------|----------------|---------|-----------|-----------|
| **VerifyAccessToken** | 217,391 | 4.60µs | 5.66 KB | 102 |

#### Repository Backend Operations

Comparative revocation/rotation benchmarks across all four `TokenRepository`
backends (`BenchmarkRepositoryRevocation_Comparative`/
`BenchmarkRepositoryRotation_Comparative`) — Memory is in-process and has no
network round trip, so it's included as a baseline, not a fair comparison
to the three networked backends:

| Backend | Operation | Operations/sec | Time/op | Memory/op | Allocs/op |
|---------|-----------|----------------|---------|-----------|-----------|
| **Memory** | MarkRevoke | 2,388,915 | 418.6ns | 412 B | 6 |
| **Memory** | IsRevoked | 5,934,718 | 168.5ns | 192 B | 3 |
| **Memory** | MarkRotated | 2,428,363 | 411.8ns | 379 B | 6 |
| **Memory** | IsRotated | 6,172,840 | 162.0ns | 192 B | 3 |
| **Redis** | MarkRevoke | 6,411 | 155.99µs | 784 B | 21 |
| **Redis** | IsRevoked | 6,851 | 145.97µs | 491 B | 11 |
| **Redis** | MarkRotated | 10,379 | 96.35µs | 784 B | 21 |
| **Redis** | IsRotated | 10,593 | 94.40µs | 491 B | 11 |
| **Postgres** | MarkRevoke | 6,477 | 154.40µs | 554 B | 12 |
| **Postgres** | IsRevoked | 9,763 | 102.43µs | 715 B | 13 |
| **Postgres** | MarkRotated | 6,572 | 152.17µs | 522 B | 11 |
| **Postgres** | IsRotated | 9,644 | 103.70µs | 683 B | 12 |
| **MongoDB** | MarkRevoke | 2,939 | 340.27µs | 8.03 KB | 107 |
| **MongoDB** | IsRevoked | 7,374 | 135.62µs | 9.26 KB | 108 |
| **MongoDB** | MarkRotated | 3,065 | 326.29µs | 9.20 KB | 111 |
| **MongoDB** | IsRotated | 7,122 | 140.41µs | 9.05 KB | 102 |

### Performance Tips

1. **Algorithm Selection**
   - Use **HS256** for development
   - Use **ES256** for production balance
   - Use **RS256** for legacy compatibility
   - Avoid **RS4096** unless required

2. **Redis Optimization**

   ```go
   redisClient := redis.NewClient(&redis.Options{
       Addr:         "localhost:6379",
       PoolSize:     100,
       MinIdleConns: 10,
       MaxRetries:   3,
   })
   ```

3. **Connection Pooling (SQL)**

   ```go
   sqlDB, _ := db.DB()
   sqlDB.SetMaxOpenConns(100)
   sqlDB.SetMaxIdleConns(10)
   sqlDB.SetConnMaxLifetime(time.Hour)
   ```

---

## ✅ Best Practices

### Key Management

#### ✅ DO

- Store keys in secret managers (AWS Secrets Manager, Vault)
- Use environment variables, never hardcode
- Rotate keys every 90 days
- Use minimum 32 bytes for HMAC
- Set file permissions to 0600 for private keys

#### ❌ DON'T

- Commit keys to version control
- Use weak keys (< 32 bytes)
- Share keys across environments
- Store keys in plaintext

### Token Lifetime Configuration

| Environment | Access Token | Refresh Token |
|-------------|--------------|---------------|
| **Development** | 1 hour | 30 days |
| **Staging** | 30 minutes | 7 days |
| **Production** | 15 minutes | 7 days |
| **High Security** | 5 minutes | 24 hours |

### Runtime Security

```go
// HTTPS Enforcement
server := &http.Server{
    Addr:      ":443",
    TLSConfig: tlsConfig,
}
server.ListenAndServeTLS("cert.pem", "key.pem")

// Secure Cookies
http.SetCookie(w, &http.Cookie{
    Name:     "refresh_token",
    Value:    token,
    HttpOnly: true,
    Secure:   true,
    SameSite: http.SameSiteStrictMode,
})
```

---

## 📚 Examples

### Example 1: Standard Library HTTP Server

```go
package main

import (
    "context"
    "encoding/json"
    "log"
    "net/http"
    "strings"

    "github.com/gourdian25/gourdiantoken/v2"
    "github.com/google/uuid"
)

var maker gourdiantoken.GourdianTokenMaker

func init() {
    ctx := context.Background()
    config := gourdiantoken.DefaultGourdianTokenConfig("my-secret-key-32-bytes-minimum")
    var err error
    maker, err = gourdiantoken.NewGourdianTokenMakerNoStorage(ctx, config)
    if err != nil {
        log.Fatal(err)
    }
}

func main() {
    http.HandleFunc("/login", login)
    http.HandleFunc("/protected", authMiddleware(protected))
    log.Fatal(http.ListenAndServe(":8080", nil))
}

func login(w http.ResponseWriter, r *http.Request) {
    token, _ := maker.CreateAccessToken(
        r.Context(), uuid.NewString(), "user@example.com", []string{"user"}, uuid.NewString(),
    )
    json.NewEncoder(w).Encode(token)
}

func protected(w http.ResponseWriter, r *http.Request) {
    claims := r.Context().Value("claims").(*gourdiantoken.AccessTokenClaims)
    json.NewEncoder(w).Encode(map[string]interface{}{
        "message": "Protected resource",
        "user":    claims.Username,
        "roles":   claims.Roles,
    })
}

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
        claims, err := maker.VerifyAccessToken(r.Context(), token)
        if err != nil {
            http.Error(w, "Unauthorized", http.StatusUnauthorized)
            return
        }
        ctx := context.WithValue(r.Context(), "claims", claims)
        next.ServeHTTP(w, r.WithContext(ctx))
    }
}
```

### Example 2: Microservices Architecture

```go
// Service A: Authentication Service (Creates tokens)
package main

import (
    "context"
    "github.com/gourdian25/gourdiantoken/v2"
    "github.com/redis/go-redis/v9"
)

func setupAuthService() gourdiantoken.GourdianTokenMaker {
    ctx := context.Background()
    redisClient := redis.NewClient(&redis.Options{Addr: "redis:6379"})
    
    config := gourdiantoken.DefaultGourdianTokenConfig("shared-secret-key")
    config.Issuer = "auth.myapp.com"
    config.Audience = []string{"api.myapp.com", "admin.myapp.com"}
    config.RevocationEnabled = true
    config.RotationEnabled = true
    
    maker, _ := gourdiantoken.NewGourdianTokenMakerWithRedis(ctx, config, redisClient)
    return maker
}

// Service B: API Service (Only validates tokens)
package main

import (
    "context"
    "github.com/gourdian25/gourdiantoken/v2"
    "github.com/redis/go-redis/v9"
)

func setupAPIService() gourdiantoken.GourdianTokenMaker {
    ctx := context.Background()
    redisClient := redis.NewClient(&redis.Options{Addr: "redis:6379"})
    
    config := gourdiantoken.DefaultGourdianTokenConfig("shared-secret-key")
    config.Issuer = "auth.myapp.com"
    config.Audience = []string{"api.myapp.com"}
    config.RevocationEnabled = true
    
    maker, _ := gourdiantoken.NewGourdianTokenMakerWithRedis(ctx, config, redisClient)
    return maker
}
```

### Example 3: Session Management System

```go
package main

import (
    "context"
    "time"

    "github.com/gourdian25/gourdiantoken/v2"
    "github.com/google/uuid"
)

type SessionManager struct {
    maker gourdiantoken.GourdianTokenMaker
}

func (sm *SessionManager) CreateSession(ctx context.Context, userID string, username string, roles []string) (*Session, error) {
    sessionID := uuid.NewString()
    
    accessToken, err := sm.maker.CreateAccessToken(ctx, userID, username, roles, sessionID)
    if err != nil {
        return nil, err
    }
    
    refreshToken, err := sm.maker.CreateRefreshToken(ctx, userID, username, sessionID)
    if err != nil {
        return nil, err
    }
    
    return &Session{
        SessionID:    sessionID,
        UserID:       userID,
        AccessToken:  accessToken.Token,
        RefreshToken: refreshToken.Token,
        ExpiresAt:    refreshToken.ExpiresAt,
        CreatedAt:    time.Now(),
    }, nil
}

func (sm *SessionManager) RefreshSession(ctx context.Context, refreshTokenString string) (*Session, error) {
    newRefreshToken, err := sm.maker.RotateRefreshToken(ctx, refreshTokenString)
    if err != nil {
        return nil, err
    }
    
    claims, err := sm.maker.VerifyRefreshToken(ctx, newRefreshToken.Token)
    if err != nil {
        return nil, err
    }
    
    roles := []string{"user"} // Load from database
    
    accessToken, err := sm.maker.CreateAccessToken(
        ctx, claims.Subject, claims.Username, roles, claims.SessionID,
    )
    if err != nil {
        return nil, err
    }
    
    return &Session{
        SessionID:    claims.SessionID,
        UserID:       claims.Subject,
        AccessToken:  accessToken.Token,
        RefreshToken: newRefreshToken.Token,
        ExpiresAt:    newRefreshToken.ExpiresAt,
        CreatedAt:    time.Now(),
    }, nil
}

func (sm *SessionManager) EndSession(ctx context.Context, accessToken, refreshToken string) error {
    sm.maker.RevokeAccessToken(ctx, accessToken)
    sm.maker.RevokeRefreshToken(ctx, refreshToken)
    return nil
}

type Session struct {
    SessionID    string
    UserID       string
    AccessToken  string
    RefreshToken string
    ExpiresAt    time.Time
    CreatedAt    time.Time
}
```

---

## 🧪 Testing

### Running Tests

```bash
# Run all tests
go test ./...

# Run with coverage
go test -cover ./...

# Generate HTML coverage report
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out -o coverage.html
```

### Backend-dependent tests

The `Redis`, `MongoDB`, and `Postgres` repository subtests need real
local services — see [CLAUDE.md](CLAUDE.md) for exact connection details.
Start them with:

```bash
make docker-up   # starts the shared Postgres/Redis/Mongo test containers
make docker-down # stops them when you're done
```

These containers are shared with grnoti, grcache, and graudit (each gets its
own database/keyspace/DB-index). To iterate without any of them running,
scope test runs to the `Memory` subtest, e.g.
`go test -run TestMarkTokenRevoke_SuccessAccessToken/Memory ./...`.

### Unit Test Example

```go
func TestTokenCreation(t *testing.T) {
    ctx := context.Background()
    config := gourdiantoken.DefaultGourdianTokenConfig("test-secret-key-32-bytes-long")
    maker, _ := gourdiantoken.NewGourdianTokenMakerNoStorage(ctx, config)
    
    userID := uuid.NewString()
    token, err := maker.CreateAccessToken(ctx, userID, "test", []string{"user"}, uuid.NewString())
    
    require.NoError(t, err)
    assert.NotEmpty(t, token.Token)
    assert.Equal(t, userID, token.Subject)
}

func TestTokenExpiration(t *testing.T) {
    ctx := context.Background()
    config := gourdiantoken.DefaultGourdianTokenConfig("test-key")
    config.AccessExpiryDuration = 1 * time.Second
    maker, _ := gourdiantoken.NewGourdianTokenMakerNoStorage(ctx, config)
    
    token, _ := maker.CreateAccessToken(ctx, uuid.NewString(), "user", []string{"user"}, uuid.NewString())
    time.Sleep(2 * time.Second)
    
    _, err := maker.VerifyAccessToken(ctx, token.Token)
    assert.Error(t, err)
    assert.Contains(t, err.Error(), "expired")
}

func TestTokenRotation(t *testing.T) {
    ctx := context.Background()
    config := gourdiantoken.DefaultGourdianTokenConfig("test-key-32-bytes")
    config.RotationEnabled = true
    maker, _ := gourdiantoken.NewGourdianTokenMakerWithMemory(ctx, config)
    
    refresh, _ := maker.CreateRefreshToken(ctx, uuid.NewString(), "user", uuid.NewString())
    newToken, err := maker.RotateRefreshToken(ctx, refresh.Token)
    
    require.NoError(t, err)
    assert.NotEqual(t, refresh.Token, newToken.Token)
    
    _, err = maker.VerifyRefreshToken(ctx, refresh.Token)
    assert.Error(t, err)
}
```

---

## 🤝 Contributing

We welcome contributions! Here's how:

1. Fork the repository
2. Create feature branch: `git checkout -b feature/amazing-feature`
3. Make changes and write tests
4. Run tests: `go test ./...`
5. Format code: `go fmt ./...`
6. Commit: `git commit -m "feat: add amazing feature"`
7. Push and open Pull Request

### Guidelines

- Follow Go conventions
- Maintain test coverage
- Update documentation
- Use conventional commits

---

## 📄 License

MIT License - see [LICENSE](./LICENSE) file

---

## 🙏 Acknowledgments

- [golang-jwt/jwt](https://github.com/golang-jwt/jwt) - JWT implementation
- [google/uuid](https://github.com/google/uuid) - UUID support
- [redis/go-redis](https://github.com/redis/go-redis) - Redis client
- [jackc/pgx](https://github.com/jackc/pgx) - PostgreSQL driver
- [sqlc-dev/sqlc](https://github.com/sqlc-dev/sqlc) - typed query code generation
- [mongodb/mongo-go-driver](https://github.com/mongodb/mongo-go-driver) - MongoDB driver

---

## 👥 Maintainers

- [@gourdian25](https://github.com/gourdian25) - Creator & Lead
- [@lordofthemind](https://github.com/lordofthemind) - Performance & Security

---

## 🔒 Security

Report vulnerabilities privately via email. DO NOT open public issues for security concerns.

### Security Features

- ✅ Cryptographically secure generation
- ✅ Algorithm confusion prevention
- ✅ Replay attack detection
- ✅ Automatic cleanup
- ✅ Secure defaults

---

## 📚 Resources

- [GoDoc](https://pkg.go.dev/github.com/gourdian25/gourdiantoken/v2) - Full API docs
- [RFC 7519](https://tools.ietf.org/html/rfc7519) - JWT Standard
- [RFC 7515](https://tools.ietf.org/html/rfc7515) - JWS Standard
- [RFC 7518](https://tools.ietf.org/html/rfc7518) - JWA Standard

---

<div align="center">

**Made with ❤️ by the gourdiantoken team**

[Documentation](https://pkg.go.dev/github.com/gourdian25/gourdiantoken/v2) •
[Issues](https://github.com/gourdian25/gourdiantoken/issues) •
[Discussions](https://github.com/gourdian25/gourdiantoken/discussions)

⭐ Star us on GitHub if you find this useful!

</div>
