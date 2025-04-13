# Gourdiantoken – Secure & Scalable JWT Management for Golang Backend

![Go Version](https://img.shields.io/badge/Go-1.24%2B-blue)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![Coverage](https://img.shields.io/badge/Coverage-69.5%25-yellow)](coverage.html)

**gourdiantoken** is a robust, battle-tested JWT token management system for modern Go applications. Designed with performance, flexibility, and enterprise-grade security in mind, it provides an all-in-one solution for managing access and refresh tokens across both monolithic and microservice architectures.

Whether you're building a high-throughput API gateway, securing a distributed system, or managing session integrity across devices, **gourdiantoken** ensures:

- 🔐 **Secure Token Issuance** with strict claim validation and cryptographic guarantees  
- 🔄 **Token Rotation & Revocation** powered by Redis  
- ⚡ **Blazing-Fast Performance** (up to 200k ops/sec with symmetric algorithms)  
- 🔧 **Pluggable Configuration** supporting both symmetric (HMAC) and asymmetric (RSA, ECDSA, EdDSA) signing  
- 🧩 **Developer-Oriented APIs** with clean abstractions and customizable behavior  
- 📊 **Benchmark-Driven** with transparent performance metrics and memory profiling  
- 🔎 **69.5%+ Test Coverage**, covering critical logic paths and edge cases  

From rapid prototyping to production-grade authorization pipelines, **gourdiantoken** adapts to your security requirements while maintaining best-in-class performance.

---

## 📚 Table of Contents

- [🚀 Features](#-features)
- [📦 Installation](#-installation)
- [🚀 Quick Start](#-quick-start)
- [⚙️ Configuration](#️-configuration)
- [🔑 Token Types](#-token-types)
- [🔐 Security Features](#-security-features)
- [⚡ Performance](#-performance)
- [✨ Examples](#-examples)
- [✅ Best Practices](#-best-practices)
- [🧩 API Reference](#-api-reference)
- [🤝 Contributing](#-contributing)
- [🧪 Testing](#-testing)
- [🚀 Benchmarks](#-benchmarks)
- [📑 License](#-license)
- [🙌 Acknowledgments](#-acknowledgments)
- [👨‍💼 Maintainers](#-maintainers)
- [🔒 Security Policy](#-security-policy)
- [📚 Documentation](#-documentation)

---

## 🚀 Features

gourdiantoken provides a complete JWT-based authentication system with a focus on security, flexibility, and performance. Here's a comprehensive look at its core features:

### 🔐 Advanced Token Types

- **Access Tokens**
  - Short-lived tokens for API authorization
  - Embed user identity, roles, session ID, and token metadata
  - Fine-grained configuration for duration, issuer, audience, required claims, and revocation

- **Refresh Tokens**
  - Long-lived tokens used to obtain new access tokens
  - Track session continuity securely
  - Support for reuse protection and automatic rotation

---

### 🔄 Refresh Token Rotation

- Rotates tokens on each use to prevent replay attacks
- Supports rotation detection and blacklisting using Redis
- Configurable reuse interval and maximum lifetime
- Enforces single-use semantics to improve session integrity

---

### 🚫 Token Revocation (Access + Refresh)

- Revoke issued tokens on demand using Redis
- Tokens are stored with expiration TTL for automatic cleanup
- Automatic background cleanup of revoked entries to prevent Redis bloat
- Detects and blocks usage of revoked tokens during verification

---

### 📌 Redis-Backed Security

- **Rotation**: Tracks reused/rotated tokens (`rotated:*` keys)
- **Revocation**: Blacklists tokens (`revoked:access:*`, `revoked:refresh:*`)
- **Cleanup**: Background goroutines remove expired tokens every hour
- Seamless fallback for environments without Redis (disables advanced features)

---

### 🔒 Algorithm Flexibility

- **Symmetric Signing (HMAC)**: HS256, HS384, HS512
- **Asymmetric Signing**:
  - RSA: RS256, RS384, RS512
  - ECDSA: ES256, ES384, ES512
  - EdDSA: Ed25519
- Security enforcement for each method (e.g., minimum key lengths, secure file permissions)
- Automatic validation of algorithm vs. signing method during configuration

---

### 🧪 Strict Claim Validation

- Verifies all critical claims:
  - `jti`, `sub`, `usr`, `sid`, `iat`, `exp`, `typ`, `rls` (for access)
- Validates:
  - Token type (access vs refresh)
  - Expiration and issuance time
  - Required claims (customizable)
- Strong typing using UUIDs and `time.Time`
- UUID parsing with error handling for safe decoding

---

### ⚡ High-Performance Token Lifecycle

- Optimized creation & verification:
  - Up to **200k ops/sec** with HMAC
  - Efficient memory usage with minimal allocations
- **Parallel-safe** design for concurrent API loads
- Benchmark-driven optimization with detailed profiling
- Custom benchmarks included in `make bench`

---

### 🧠 Developer-Focused API

- Clean interface: `gourdiantokenMaker`
- Explicit configuration with safe defaults
- Modular & composable design
- Easy to integrate into REST or gRPC services
- Supports full override/customization of claims

---

### 🛡️ Secure Defaults Out of the Box

- 30 min access token lifetime
- 7-day refresh tokens
- 5 min reuse interval
- Secure algorithm (HS256 or RS256)
- Strict role validation on access tokens
- Disables insecure "none" algorithm
- Key length enforcement and file permission checks

---

### 🧪 Test Coverage & Benchmarks

- **~69.5% test coverage**
  - All core paths, edge cases, and error flows
- **Dozens of benchmarks**
  - Cover creation, verification, rotation, revocation
  - Memory usage and allocs/op included
- CLI tools:
  - `make test`
  - `make coverage`
  - `make bench`

---

### 🧰 Extensibility

- Easily extend token claims with custom fields
- Plug-and-play architecture with your own storage/backends
- Support for:
  - Multiple issuers
  - Token size testing
  - Multi-role verification scenarios

---

### 📚 Examples & Documentation

- In-code documentation and examples
- Sample configurations for:
  - HMAC setup (no Redis)
  - Asymmetric setup (RSA/ECDSA + Redis)
- Embedded comments for claim formats and token usage
- Visual layout of claim structure in README

---

## 📦 Installation

To get started, install the package using `go get`:

```bash
go get github.com/gourdian25/gourdiantoken@latest
```

Make sure your Go version is **1.18+** to ensure full compatibility with generics and the latest standard libraries.

---

## 🚀 Quick Start

gourdiantoken supports both **HMAC (symmetric)** and **RSA/ECDSA/EdDSA (asymmetric)** token signing methods. Here's how to get started with each setup:

---

### 🧱 Basic HMAC Example (No Redis)

This example demonstrates how to use gourdiantoken with a **secure 32-byte symmetric key**. No Redis setup is required. Ideal for fast local development or lightweight services.

```go
package main

import (
	"context"
	"fmt"
	"time"

	"github.com/gourdian25/gourdiantoken"
	"github.com/google/uuid"
)

func main() {
	// Use a securely generated 32-byte secret key (base64 recommended in production)
	key := "your-32-byte-secret-key-must-be-secure"

	// 1. Load default HMAC-based configuration
	config := gourdiantoken.DefaultgourdiantokenConfig(key)

	// 2. Create the token manager (Redis is nil here, so revocation/rotation are disabled)
	maker, err := gourdiantoken.NewgourdiantokenMaker(context.Background(), config, nil)
	if err != nil {
		panic(fmt.Errorf("token maker initialization failed: %w", err))
	}

	// 3. Generate a unique user and session ID
	userID := uuid.New()
	sessionID := uuid.New()

	// 4. Create an access token with user identity and roles
	accessToken, err := maker.CreateAccessToken(
		context.Background(),
		userID,
		"john_doe",                  // Username
		[]string{"user", "admin"},   // Roles
		sessionID,                   // Session ID
	)
	if err != nil {
		panic(fmt.Errorf("failed to create access token: %w", err))
	}

	// 5. Verify the token and extract claims
	claims, err := maker.VerifyAccessToken(context.Background(), accessToken.Token)
	if err != nil {
		panic(fmt.Errorf("token verification failed: %w", err))
	}

	fmt.Printf("✅ Verified token for user %s with roles %v\n", claims.Username, claims.Roles)
}
```

---

### 🛡️ Advanced Setup with Asymmetric RSA + Redis

This example enables **asymmetric signing (RS256)** with a private/public key pair, along with **Redis integration** for revocation and rotation support — recommended for production environments.

```go
package main

import (
	"context"
	"fmt"
	"time"

	"github.com/gourdian25/gourdiantoken"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

func main() {
	// 1. Configure Redis (used for revocation and rotation)
	redisOpts := &redis.Options{
		Addr:     "localhost:6379", // Update if using Docker, cloud, etc.
		Password: "",
		DB:       0,
	}

	// 2. Define a complete asymmetric token configuration
	config := gourdiantoken.gourdiantokenConfig{
		Algorithm:      "RS256",
		SigningMethod:  gourdiantoken.Asymmetric,
		PrivateKeyPath: "/path/to/private.pem",  // Replace with real path
		PublicKeyPath:  "/path/to/public.pem",   // Replace with real path

		AccessToken: gourdiantoken.AccessTokenConfig{
			Duration:           30 * time.Minute,
			MaxLifetime:        24 * time.Hour,
			Issuer:             "myapp.com",
			Audience:           []string{"api.myapp.com"},
			AllowedAlgorithms:  []string{"RS256"},
			RequiredClaims:     []string{"jti", "sub", "exp", "iat", "typ", "rls"},
			RevocationEnabled:  true, // Enables Redis-based access token revocation
		},

		RefreshToken: gourdiantoken.RefreshTokenConfig{
			Duration:           7 * 24 * time.Hour,
			MaxLifetime:        30 * 24 * time.Hour,
			ReuseInterval:      5 * time.Minute,  // Prevents replay attacks
			RotationEnabled:    true,             // Enables refresh token rotation
			RevocationEnabled:  true,             // Enables refresh token revocation
		},
	}

	// 3. Initialize the token maker with Redis-enabled features
	maker, err := gourdiantoken.NewgourdiantokenMaker(context.Background(), config, redisOpts)
	if err != nil {
		panic(fmt.Errorf("failed to initialize token maker: %w", err))
	}

	// 4. Generate user/session info
	userID := uuid.New()
	sessionID := uuid.New()

	// 5. Create both tokens
	accessToken, _ := maker.CreateAccessToken(context.Background(), userID, "alice", []string{"user"}, sessionID)
	refreshToken, _ := maker.CreateRefreshToken(context.Background(), userID, "alice", sessionID)

	// 6. Verify access token
	claims, err := maker.VerifyAccessToken(context.Background(), accessToken.Token)
	if err != nil {
		panic(fmt.Errorf("access token validation failed: %w", err))
	}

	fmt.Printf("✅ Access token verified for user: %s\n", claims.Username)
	fmt.Printf("🔁 Refresh token: %s\n", refreshToken.Token)
}
```

---

### 🔍 Summary

| Feature            | HMAC Example       | RSA + Redis Example     |
|--------------------|--------------------|--------------------------|
| Setup Complexity   | Low                | Medium–High              |
| Signing Method     | Symmetric (HS256)  | Asymmetric (RS256)       |
| Revocation Support | ❌ No              | ✅ Yes (via Redis)       |
| Rotation Support   | ❌ No              | ✅ Yes (via Redis)       |
| Recommended For    | Development, local | Production, distributed  |

---

## ⚙️ Configuration

gourdiantoken offers a **flexible, explicit, and secure configuration system** that allows you to tailor token behavior for different environments — from local development to enterprise-grade production.

### 🧩 Core Configuration Struct

```go
type gourdiantokenConfig struct {
	Algorithm      string
	SigningMethod  SigningMethod
	SymmetricKey   string
	PrivateKeyPath string
	PublicKeyPath  string
	AccessToken    AccessTokenConfig
	RefreshToken   RefreshTokenConfig
}
```

This struct acts as the **central configuration hub** for all signing strategies, token policies, and lifecycle behaviors. It supports both **symmetric** and **asymmetric** cryptographic modes and gives you full control over access/refresh token behavior.

---

### 🔐 AccessTokenConfig

```go
type AccessTokenConfig struct {
	Duration          time.Duration
	MaxLifetime       time.Duration
	Issuer            string
	Audience          []string
	AllowedAlgorithms []string
	RequiredClaims    []string
	RevocationEnabled bool
}
```

Defines rules for short-lived access tokens. Common use cases:

- Set `Duration` to `15–30m` for best security
- Use `RevocationEnabled = true` with Redis for mid-session invalidation
- Specify `RequiredClaims` to enforce token integrity

---

### 🔁 RefreshTokenConfig

```go
type RefreshTokenConfig struct {
	Duration          time.Duration
	MaxLifetime       time.Duration
	ReuseInterval     time.Duration
	RotationEnabled   bool
	RevocationEnabled bool
}
```

Manages the long-lived refresh token lifecycle. Typical recommendations:

- Enable `RotationEnabled` to block replay attacks
- Set `ReuseInterval` to `5m` to detect abnormal reuse
- Enable `RevocationEnabled` for full control over sessions

---

## 🧪 Configuration Options

gourdiantoken offers multiple entry-points to configure your system depending on your needs.

---

### ✅ 1. `DefaultgourdiantokenConfig(key string)`

A plug-and-play method to get started quickly with **HMAC (HS256)**.

```go
key := "your-32-byte-secure-hmac-key"
config := gourdiantoken.DefaultgourdiantokenConfig(key)
```

#### 🛡️ Defaults:

| Setting               | Value                |
|-----------------------|----------------------|
| Algorithm             | HS256 (HMAC-SHA256)  |
| Access Token Duration | 30 minutes           |
| Access Max Lifetime   | 24 hours             |
| Required Claims       | jti, sub, exp, iat, typ, rls |
| Refresh Token Duration| 7 days               |
| Refresh Max Lifetime  | 30 days              |
| Reuse Interval        | 1 minute             |
| Revocation / Rotation | Disabled by default  |

---

### 🧰 2. `NewgourdiantokenConfig(...)`

For full control — use this when building **custom configurations** with asymmetric keys or complex claims.

```go
config := gourdiantoken.NewgourdiantokenConfig(
	"RS256",                          // Algorithm
	gourdiantoken.Asymmetric,         // Signing method
	"",                               // Symmetric key (ignored for asymmetric)
	"/path/to/private.pem",           // Private key
	"/path/to/public.pem",            // Public key
	30*time.Minute,                   // Access token duration
	24*time.Hour,                     // Access token max lifetime
	"myapp.com",                      // Issuer
	[]string{"api.myapp.com"},        // Audience
	[]string{"RS256"},                // Allowed algorithms
	[]string{"jti", "sub", "exp"},    // Required claims
	true,                             // Enable access token revocation
	7*24*time.Hour,                   // Refresh token duration
	30*24*time.Hour,                  // Refresh token max lifetime
	5*time.Minute,                    // Reuse interval
	true,                             // Enable rotation
	true,                             // Enable refresh token revocation
)
```

Use this method when you want to:

- Run in **production environments**
- Leverage **RSA/ECDSA/EdDSA**
- Enforce **audience and issuer**
- Customize every lifecycle parameter

---

### ⚙️ 3. Creating the Token Maker

You can create the token manager instance (implementing `gourdiantokenMaker`) using two factory methods:

---

#### 🔹 `NewgourdiantokenMaker(ctx, config, redisOpts)`

```go
maker, err := gourdiantoken.NewgourdiantokenMaker(context.Background(), config, redisOpts)
```

- Uses a custom config
- Enables Redis-based features (if `redisOpts != nil`)
- Initializes rotation/revocation cleanup goroutines
- Validates all cryptographic requirements

Use this if:

- You need precise control
- You're loading config from file/env
- You're rotating between environments

---

#### 🔹 `NewgourdiantokenMakerWithDefaults(ctx, key, redisOpts)`

```go
key := "your-32-byte-key"
redisOpts := &redis.Options{Addr: "localhost:6379"}

maker, err := gourdiantoken.NewgourdiantokenMakerWithDefaults(context.Background(), key, redisOpts)
```

- Uses `DefaultgourdiantokenConfig`
- Automatically enables rotation/revocation if Redis is provided
- Ideal for dev/staging with Redis support

---

### 📦 Example Use Cases

#### 🟢 Local Dev (HMAC, No Redis)

```go
key := "this-is-a-32-byte-secure-hmac-key"
config := gourdiantoken.DefaultgourdiantokenConfig(key)
maker, _ := gourdiantoken.NewgourdiantokenMaker(context.Background(), config, nil)
```

#### 🔒 Production (RSA + Redis)

```go
config := gourdiantoken.NewgourdiantokenConfig(
	"RS256", gourdiantoken.Asymmetric, "", "private.pem", "public.pem",
	30*time.Minute, 24*time.Hour, "auth.app", []string{"api.app"},
	[]string{"RS256"}, []string{"jti", "sub", "exp", "rls"},
	true, 7*24*time.Hour, 30*24*time.Hour, 5*time.Minute, true, true,
)
redisOpts := &redis.Options{Addr: "localhost:6379"}
maker, _ := gourdiantoken.NewgourdiantokenMaker(context.Background(), config, redisOpts)
```

---

### ✅ Validation & Safety

All configuration methods automatically:

- Reject missing or insecure keys
- Enforce required claims and durations
- Check algorithm compatibility with signing method
- Validate file permissions (`0600`) for private keys
- Panic if token roles or critical claims are missing

---

## 🔑 Token Types

gourdiantoken supports two primary types of JSON Web Tokens (JWTs), each serving a distinct purpose in modern authentication flows:

---

### 🔓 Access Tokens

Access tokens are **short-lived credentials** that clients use to access protected APIs. They are designed to be ephemeral and carry the minimum information required for authorization.

#### 🧭 Purpose

- Authenticate requests to secured endpoints
- Embed user identity, session info, and roles
- Expire quickly to reduce exposure window

#### ⏱️ Lifetime

- Typical Duration: **15 minutes to 1 hour**
- Enforced using both `exp` (expires at) and `iat` (issued at) claims

#### 📦 Standard Claim Payload

```json
{
  "jti": "123e4567-e89b-12d3-a456-426614174000", // Token ID (UUIDv4)
  "sub": "123e4567-e89b-12d3-a456-426614174000", // Subject (user ID)
  "usr": "john_doe",                              // Human-readable username
  "sid": "123e4567-e89b-12d3-a456-426614174000", // Session ID (UUIDv4)
  "iat": 1516239022,                              // Issued At (Unix time)
  "exp": 1516242622,                              // Expiration Time (Unix time)
  "typ": "access",                                // Token type
  "rls": ["admin", "user"]                        // Roles (required for authz)
}
```

#### 🧪 Validation

- **Required Claims** (enforced by config): `jti`, `sub`, `usr`, `sid`, `iat`, `exp`, `typ`, `rls`
- **Roles** are mandatory for authorization
- Automatically checked for:
  - Expired tokens (`exp`)
  - Malformed or empty roles (`rls`)
  - Revocation status (if enabled)

#### ✅ Use Cases

- Authorization headers: `Authorization: Bearer <access_token>`
- User-facing services (mobile/web clients)
- API gateway/middleware access control

---

### 🔁 Refresh Tokens

Refresh tokens are **long-lived credentials** designed to help obtain new access tokens **without requiring the user to log in again**. They contain session and identity information but **do not include roles**.

#### 🧭 Purpose

- Maintain persistent login sessions
- Enable seamless access token rotation
- Reduce repeated login prompts for users

#### ⏱️ Lifetime

- Typical Duration: **7–30 days**
- Controlled by both `Duration` and `MaxLifetime` in config
- May be rotated on each use to prevent reuse

#### 📦 Standard Claim Payload

```json
{
  "jti": "123e4567-e89b-12d3-a456-426614174000", // Token ID (UUIDv4)
  "sub": "123e4567-e89b-12d3-a456-426614174000", // Subject (user ID)
  "usr": "john_doe",                              // Username
  "sid": "123e4567-e89b-12d3-a456-426614174000", // Session ID (UUIDv4)
  "iat": 1516239022,                              // Issued At (Unix time)
  "exp": 1516242622,                              // Expiration Time (Unix time)
  "typ": "refresh"                                // Token type
}
```

#### 🧪 Validation

- **Required Claims**: `jti`, `sub`, `usr`, `sid`, `iat`, `exp`, `typ`
- Must have `typ = "refresh"`
- Token reuse tracked via Redis (if rotation enabled)
- Expired or reused tokens are automatically rejected

#### 🔒 Rotation & Revocation

- Supports **rotation** to invalidate old refresh tokens after use
- **Reuse detection** via `rotated:*` Redis keys
- **Revocation** via `revoked:refresh:*` keys (if enabled)

#### ✅ Use Cases

- OAuth2-style flows (`/token/refresh` endpoints)
- Mobile and desktop app session management
- Background token renewal in web apps

---

### 🧩 Summary Comparison

| Feature               | Access Token              | Refresh Token            |
|-----------------------|---------------------------|---------------------------|
| Duration              | 15m–1h                    | 7–30 days                 |
| Carries Roles         | ✅ Yes                    | ❌ No                     |
| Use in API Calls      | ✅ Yes                    | ❌ No                     |
| Use in Rotation       | ❌ No                     | ✅ Yes                    |
| Revocable via Redis   | ✅ Yes (if enabled)       | ✅ Yes (if enabled)       |
| Claim: `typ`          | `"access"`               | `"refresh"`              |
| Claim: `rls` (roles)  | Required                  | Omitted                  |
| Typical Storage       | Authorization header      | HttpOnly secure cookie   |

---

## 🔐 Security Features

gourdiantoken is designed with **security-first principles**, enabling you to protect user sessions, enforce access boundaries, and mitigate common JWT threats in distributed systems. Below is a breakdown of its security capabilities and cryptographic options.

---

### 🚫 Token Revocation

Token revocation enables you to **invalidate a token before its natural expiration** — useful for immediate logout, account compromise, or policy enforcement.

#### ✅ Features

- Works with **both access and refresh tokens**
- Powered by **Redis-based blacklist** (`revoked:*`)
- TTL is set to match the remaining validity of the token
- Cleanup goroutines automatically delete expired revocations hourly

#### 🧪 Example

```go
// Revoke an access token (prevents reuse)
err := maker.RevokeAccessToken(ctx, accessToken)

// Revoke a refresh token (prevents future rotations)
err := maker.RevokeRefreshToken(ctx, refreshToken)
```

#### 🔒 Security Notes

- Prevents token reuse across logout or session hijack
- Redis is required for revocation to work
- Recommended for all production deployments

---

### 🔁 Refresh Token Rotation

Refresh token rotation enhances security by **ensuring every refresh token is single-use**. If a stolen refresh token is reused, it will be detected and denied.

#### ✅ Features

- Old token is invalidated immediately after being used
- New token inherits session/user context
- Replay attempts using old token are rejected
- Rotation state stored in Redis as `rotated:<token>`

#### ⏱️ Configurable Settings

- `RotationEnabled`: Enable/disable rotation
- `ReuseInterval`: Enforce a minimum reuse gap
- `MaxLifetime`: Limit total token lifespan across rotations

#### 🧪 Example

```go
// Rotate and invalidate the old refresh token
newToken, err := maker.RotateRefreshToken(ctx, oldRefreshToken)
if err != nil {
	log.Println("Replay attack or expired token!")
}
```

#### 🔒 Security Notes

- Detects stolen refresh tokens reused after session rotation
- One of the most effective JWT security mechanisms
- Cleanup goroutine purges rotated tokens from Redis hourly

---

### 🧬 Algorithm Support & Best Practices

gourdiantoken supports a wide variety of industry-standard cryptographic algorithms. Each has different performance and security characteristics, making the system flexible for both dev and production use.

| Algorithm | Type       | Use Case      | Key/Curve        | Recommended |
|-----------|------------|---------------|------------------|-------------|
| **HS256** | Symmetric  | Dev / API keys | 32+ byte secret  | ✅ Simple and fast for dev environments |
| **HS384** | Symmetric  | Dev           | 48+ byte secret  | ✅ Stronger hash for critical data |
| **HS512** | Symmetric  | Dev           | 64+ byte secret  | ✅ High security, higher size |
| **RS256** | Asymmetric | Production    | 2048-bit RSA     | ✅ Default for most systems |
| **RS384** | Asymmetric | Production    | 2048-bit RSA     | ✅ Enhanced hashing |
| **RS512** | Asymmetric | Production    | 2048-bit RSA     | ✅ Highest hashing in RSA family |
| **ES256** | Asymmetric | Production    | P-256 Curve      | ✅ Balanced speed & security |
| **ES384** | Asymmetric | Production    | P-384 Curve      | ✅ Stronger ECC curve |
| **ES512** | Asymmetric | Production    | P-521 Curve      | ✅ Maximum ECC strength |
| **EdDSA** | Asymmetric | Production    | Ed25519/Ed448    | ✅ Modern cryptography with low overhead |

#### 🧠 Recommendations

- Use **HS256** only for local dev/testing
- In production:
  - Use **RS256** or **ES256** for signing
  - Prefer **EdDSA** for cutting-edge security and smaller keys
- Always set `RequiredClaims` to avoid partial or tampered tokens
- Secure key files with `0600` permissions if using asymmetric keys

---

### ✅ Claim Enforcement

gourdiantoken verifies that **all essential claims** are present and valid before considering a token trustworthy.

#### Required claims per token type:

| Claim  | Access Token | Refresh Token |
|--------|--------------|---------------|
| `jti`  | ✅           | ✅            |
| `sub`  | ✅           | ✅            |
| `usr`  | ✅           | ✅            |
| `sid`  | ✅           | ✅            |
| `iat`  | ✅           | ✅            |
| `exp`  | ✅           | ✅            |
| `typ`  | `"access"`   | `"refresh"`   |
| `rls`  | ✅ (roles)   | ❌            |

> Missing or malformed claims trigger immediate rejection of the token.

---

### 🛡️ Built-in Protections

- 🔒 **Algorithm mismatch detection**
- ⛔ **"none" algorithm is explicitly disabled**
- 🧯 **Auto-cleanup** for revoked and rotated tokens in Redis
- 📆 **Expiration enforcement** with time drift protection
- 📏 **Strict type checking** for UUIDs, arrays, and timestamps
- 🧪 **Custom validation hooks** for issuer/audience allowed

---

## ⚡ Performance

gourdiantoken is engineered for high throughput and minimal latency across a wide range of cryptographic algorithms. Its design is optimized for both **API-heavy workloads** and **secure session management**, making it ideal for production-grade systems with demanding auth needs.

---

### 📊 Benchmark Highlights

These benchmarks were conducted on an **Intel i5-9300H @ 2.40GHz** system using Go 1.20+, with both sequential and parallel operations measured across multiple algorithms.

| Operation                      | Algorithm   | Avg Duration     | Memory Usage | Allocations |
|-------------------------------|-------------|------------------|--------------|-------------|
| 🛠 Create Access Token         | HMAC-256    | **24.3 µs**      | 4,682 B/op   | 58          |
| 🛠 Create Access Token         | RSA-2048    | **2.86 ms**      | 5,772 B/op   | 56          |
| 🔍 Verify Access Token         | HMAC-256    | **26.4 µs**      | 3,944 B/op   | 75          |
| 🔍 Verify Access Token         | RSA-2048    | **127 µs**       | 5,192 B/op   | 80          |
| 🔁 Refresh Token Rotation      | Redis       | **2.98 ms**      | 8,881 B/op   | 142         |
| 🧵 Parallel Verify (HMAC)      | HMAC-256    | **6.78 µs**      | 4,024 B/op   | 78          |
| 🧵 Parallel Create (HMAC)      | HMAC-256    | **7.8 µs**       | 4,701 B/op   | 59          |
| 🧵 Parallel Refresh Create     | HMAC-256    | **6.0 µs**       | 4,356 B/op   | 55          |
| 📛 Token Revocation (Redis)    | -           | **0.93 ms**      | 4,865 B/op   | 90          |
| 🔄 Rotate Refresh Token (high) | Redis       | **2.20 ms**      | 13,230 B/op  | 197         |

> All results include both single-threaded and `-cpu=8` parallel runs using `go test -bench`.

---

### 🔍 Interpretation

#### 🧪 HMAC (HS256/384/512)

- Extremely fast and memory-efficient.
- Ideal for stateless systems or API gateways.
- Low CPU usage, excellent parallel performance.

#### 🔐 RSA (2048-bit)

- Secure and widely supported but relatively slow.
- Token creation time is **>100×** slower than HMAC.
- Still usable for verification due to efficient key caching.

#### 🔁 Redis-based Operations

- Rotation and revocation are fast enough for production.
- Most Redis operations complete in **~1–3ms** even under load.
- Parallel Redis ops scale well with connection pooling.

---

### ✅ Performance Recommendations

1. **High Throughput APIs**
   - Use `HS256` or `HS512` for microservices handling thousands of RPS.
   - Avoid storing tokens — validate statelessly with in-memory caches or fast Redis setups.

2. **Balanced Security & Speed**
   - Use `ES256` for fast asymmetric auth with modern ECC cryptography.
   - ~135 µs creation + 205 µs verification is acceptable for real-time APIs.

3. **Enterprise-Grade Security**
   - Use `RS256` or `EdDSA` in environments where public/private key separation and cryptographic standards are required.
   - Avoid RSA-4096 unless you're doing signature verification only.

4. **Session Security**
   - Enable **refresh token rotation** with `5m` reuse interval and **revocation**.
   - Use Redis with eviction policy `volatile-lru` to auto-manage key memory.

5. **Parallel Environments**
   - Batch JWT creation/validation using goroutines.
   - Use `NewgourdiantokenMakerWithDefaults()` with Redis pooling for scalability.

---

### 🧠 Extra Tips

| Situation                        | Suggested Strategy                                |
|----------------------------------|---------------------------------------------------|
| 🔧 Internal microservice calls   | HMAC + stateless validation                       |
| 📱 Mobile app token storage      | Access: short TTL, Refresh: long TTL + rotation  |
| 🌐 Frontend SPAs                 | Store tokens in `HttpOnly` cookies, rotate on load|
| 🔁 OAuth flows                   | Use refresh rotation + Redis-backed revocation   |
| 🔒 Critical systems (e.g., banking) | EdDSA + rotation + multi-issuer setup          |

---

### 📌 TL;DR

| Use Case             | Recommendation                        |
|----------------------|----------------------------------------|
| Dev/Testing          | HMAC + `DefaultgourdiantokenConfig()` |
| Production APIs      | ECDSA (ES256) or RSA (RS256)          |
| Federated Auth       | EdDSA with `NewgourdiantokenConfig()` |
| Session Protection   | Redis + Rotation + Revocation         |
| High-Concurrency     | HMAC + Parallel Maker/Verifier        |

---

## ✨ Examples

gourdiantoken is highly extensible and production-ready out of the box. Below are advanced examples that demonstrate how to extend token functionality, handle multi-tenant systems, and enforce dynamic security logic.

---

### 🧬 Custom Claims Extension

Want to include more fields in your tokens (e.g., organization ID, locale, tier)? gourdiantoken supports easy extension of JWT payloads by embedding the built-in claim structs.

#### ✅ Why Extend?

- Add custom metadata to access tokens
- Reduce DB calls by embedding user context
- Support multi-tenant or scoped access policies

#### 🧱 Example

```go
type CustomClaims struct {
	gourdiantoken.AccessTokenClaims
	OrgID     string `json:"org_id"`   // Organization ID
	Tier      string `json:"tier"`     // User subscription level
	Locale    string `json:"locale"`   // User locale for i18n
	IsPremium bool   `json:"premium"`  // Flag for premium access
}
```

#### 🛠 Token Generation with Custom Claims

```go
claims := CustomClaims{
	AccessTokenClaims: gourdiantoken.AccessTokenClaims{
		ID:        uuid.New(),
		Subject:   uuid.New(),
		Username:  "john_doe",
		SessionID: uuid.New(),
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(15 * time.Minute),
		TokenType: gourdiantoken.AccessToken,
		Roles:     []string{"user"},
	},
	OrgID:     "org_abc123",
	Tier:      "gold",
	Locale:    "en-US",
	IsPremium: true,
}

token := jwt.NewWithClaims(maker.SigningMethod(), claims)
signedToken, err := token.SignedString(maker.PrivateKey())
```

> 🔐 Note: You must expose `SigningMethod()` and `PrivateKey()` via a custom wrapper if working outside the library.

---

### 🌍 Multi-Issuer & Multi-Tenant Token Verification

Running a **multi-tenant SaaS** or federated identity system? You might need to:

- Issue tokens for different domains or auth servers
- Validate tokens only from specific trusted issuers
- Route tokens dynamically based on the issuer field

#### ✅ Use Case

- Multiple frontend apps with separate auth backends
- Decentralized JWT signing using different key pairs per issuer
- Shared APIs verifying tokens across multiple sources

#### 🛠 Token Maker Initialization

```go
// Config for issuer 1
configForIssuer1 := gourdiantoken.DefaultgourdiantokenConfig("secret-key-issuer1")
issuer1Maker, _ := gourdiantoken.NewgourdiantokenMaker(ctx, configForIssuer1, nil)

// Config for issuer 2 (different signing key)
configForIssuer2 := gourdiantoken.NewgourdiantokenConfig(
	"RS256",
	gourdiantoken.Asymmetric,
	"", "issuer2-private.pem", "issuer2-public.pem",
	30*time.Minute, 24*time.Hour,
	"auth.issuer2.com",
	[]string{"api.issuer2.com"},
	[]string{"RS256"},
	[]string{"jti", "sub", "exp", "typ"},
	true,
	7*24*time.Hour, 30*24*time.Hour,
	5*time.Minute, true, true,
)
issuer2Maker, _ := gourdiantoken.NewgourdiantokenMaker(ctx, configForIssuer2, redisOpts)
```

#### 🔍 Verify Token with Issuer Filtering

```go
claims, err := issuer1Maker.VerifyAccessToken(ctx, tokenString)
if err != nil {
	return fmt.Errorf("token validation failed: %w", err)
}

// Optional manual issuer enforcement
expectedIssuer := "auth.issuer1.com"
if claims.Issuer != expectedIssuer {
	return fmt.Errorf("invalid token issuer: %s", claims.Issuer)
}
```

> 🧠 You can also implement a **router** that dynamically chooses the `JWTMaker` instance based on the `iss` claim.

---

### 🔄 Token Replay Detection

Already using **refresh token rotation**? Here’s how to handle potential **replay attacks** or reuse:

```go
refreshToken := "eyJ..."

// Try rotating token
newToken, err := maker.RotateRefreshToken(ctx, refreshToken)
if err != nil {
	if strings.Contains(err.Error(), "reused") {
		log.Warn("Potential replay attack detected")
	}
}
```

---

### 🧩 Use with Custom Middleware (Gin Example)

```go
func TokenMiddleware(maker gourdiantoken.gourdiantokenMaker) gin.HandlerFunc {
	return func(c *gin.Context) {
		token := extractBearerToken(c.Request)
		claims, err := maker.VerifyAccessToken(c, token)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			return
		}
		// Attach claims to context
		c.Set("user_id", claims.Subject)
		c.Set("roles", claims.Roles)
		c.Next()
	}
}
```

---

## 🧪 Bonus Use Cases (Quick Ideas)

| Use Case                     | What to Do                                                                 |
|-----------------------------|-----------------------------------------------------------------------------|
| ⏰ Expire all tokens after logout | Call `RevokeAccessToken` + `RevokeRefreshToken` on session destroy         |
| 🔄 OAuth Grant Flow         | Use `CreateAccessToken` + `CreateRefreshToken` at login                     |
| 🎯 Role-based Middleware    | Extract `claims.Roles` and validate before handler execution                |
| 🧯 API Rate-Limiting        | Include custom claim `ratelimit_group` to segregate tiers                   |
| 🔐 B2B SaaS Tenants         | Extend `AccessTokenClaims` with `TenantID`, verify against subdomain        |

---

## ✅ Best Practices

To get the most out of **gourdiantoken** in production environments, follow these best practices in key management, token lifecycle configuration, and runtime security hardening.

---

### 🔐 Key Management

Secure key handling is **non-negotiable** in any JWT-based system. Mismanagement can lead to total token forgery.

#### ✅ Do This

1. **Use Secret Managers**
   - Store HMAC secrets and private keys in services like:
     - AWS Secrets Manager
     - HashiCorp Vault
     - GCP Secret Manager
     - Docker secrets (for smaller deployments)
2. **Restrict File Permissions**
   - Ensure private key files are readable only by the service:

     ```bash
     chmod 0600 /path/to/private.pem
     ```

3. **Rotate Keys Regularly**
   - Suggested rotation schedule: **every 3 months**
   - Implement key versioning and allow overlapping for zero-downtime rollout

---

### 🧭 Token Configuration Strategy

Tune your configuration for the **balance between usability and security** based on token type, expiration, and expected behavior.

#### ⏳ Access Token Best Practices

- Duration: **15–30 minutes**
- MaxLifetime: **≤24 hours**
- Claims: Include `sub`, `sid`, `jti`, `iat`, `exp`, `typ`, and `rls`
- Avoid storing access tokens in localStorage (use memory or HttpOnly cookie)

#### 🔁 Refresh Token Best Practices

- Duration: **7–30 days**
- MaxLifetime: **30–90 days**
- Enable:
  - **Rotation** (`RotationEnabled = true`)
  - **Revocation** (`RevocationEnabled = true`)
- Reuse Interval: **≥5 minutes** to block fast replay attempts

> ✅ Use Redis for enforcing rotation and revocation at scale.

---

### 🛡️ Runtime Security Recommendations

Protect your system from token abuse, data leaks, and unintended access through layered controls.

#### ✅ HTTPS & Secure Transmission

- Always enforce HTTPS for all environments (even staging)
- Never send tokens over plaintext (HTTP, ws://)

#### ✅ Secure Token Storage (Frontend)

- Use **HttpOnly** and **Secure** cookie flags:

  ```http
  Set-Cookie: refresh_token=abc...; HttpOnly; Secure; SameSite=Strict
  ```

- Avoid storing tokens in localStorage or exposing them to `window` scope

#### ✅ Session Monitoring & Cleanup

- Revoke tokens immediately on:
  - Logout
  - Password change
  - Suspicious activity detection
- Use gourdiantoken’s `RevokeAccessToken` and `RevokeRefreshToken`

#### ✅ Rate-Limiting & Abuse Detection

- Monitor claims like `sub`, `sid`, `jti` for:
  - Rapid reuse
  - Unexpected issuer or audience
  - Abuse patterns (e.g., brute-force refresh attempts)

#### ✅ Multi-Audience & Environment Scoping

- Set `aud` claim to restrict token validity to specific APIs/services
- Use `iss` claim to enforce the identity of the token issuer
- Example:

  ```json
  "iss": "auth.myapp.com",
  "aud": ["api.myapp.com"]
  ```

---

### 🧩 Bonus Checklist for Production Deployment

| Category         | Checklist Item                               | Status |
|------------------|----------------------------------------------|--------|
| 🔐 Key Mgmt       | Keys stored securely (Vault, AWS)            | ✅      |
| 🔄 Rotation       | Refresh token rotation enabled                | ✅      |
| 🔥 Revocation     | Redis-based revocation system active          | ✅      |
| 📆 Expiry         | Sensible durations for access/refresh         | ✅      |
| 🧪 Testing         | Tokens validated via unit & integration tests | ✅      |
| 🌍 HTTPS           | TLS/SSL enforced everywhere                   | ✅      |
| 🍪 Cookies         | HttpOnly + Secure flags on refresh cookie     | ✅      |
| 🔎 Monitoring      | JWT usage patterns logged and analyzed        | ✅      |

---

Absolutely! Here's a **detailed and developer-friendly** expansion of the `## API Reference` section, including parameter descriptions, return values, use cases, and implementation notes for each method of the `gourdiantokenMaker` interface:

---

## 🧩 API Reference

### 🔧 `gourdiantokenMaker` Interface

The `gourdiantokenMaker` interface defines a complete contract for secure, extensible JWT management in Go applications. It is designed to be easily mocked, tested, and swapped in larger systems.

```go
type gourdiantokenMaker interface {
	CreateAccessToken(ctx context.Context, userID uuid.UUID, username string, roles []string, sessionID uuid.UUID) (*AccessTokenResponse, error)
	CreateRefreshToken(ctx context.Context, userID uuid.UUID, username string, sessionID uuid.UUID) (*RefreshTokenResponse, error)
	VerifyAccessToken(ctx context.Context, tokenString string) (*AccessTokenClaims, error)
	VerifyRefreshToken(ctx context.Context, tokenString string) (*RefreshTokenClaims, error)
	RevokeAccessToken(ctx context.Context, token string) error
	RevokeRefreshToken(ctx context.Context, token string) error
	RotateRefreshToken(ctx context.Context, oldToken string) (*RefreshTokenResponse, error)
}
```

---

### 📦 `CreateAccessToken`

```go
CreateAccessToken(ctx, userID, username, roles, sessionID) (*AccessTokenResponse, error)
```

#### Description

Generates a new **signed access token** with user identity, session metadata, and assigned roles.

#### Parameters

- `ctx`: Go context (for tracing, deadlines, etc.)
- `userID`: UUID of the authenticated user
- `username`: Human-readable name (for claim `usr`)
- `roles`: Slice of roles (e.g., `["admin", "editor"]`)
- `sessionID`: UUID representing the current session

#### Returns

- `AccessTokenResponse`: includes signed token, metadata, and expiration
- `error`: if validation or signing fails

---

### 🔁 `CreateRefreshToken`

```go
CreateRefreshToken(ctx, userID, username, sessionID) (*RefreshTokenResponse, error)
```

#### Description

Generates a long-lived **refresh token** for session continuity and token rotation. This token **does not include roles**.

#### Returns

- `RefreshTokenResponse`: includes signed JWT string and timestamps
- `error`: on failure to create or sign the token

---

### 🧾 `VerifyAccessToken`

```go
VerifyAccessToken(ctx, tokenString) (*AccessTokenClaims, error)
```

#### Description

Verifies the access token's signature, required claims, expiration, and revocation status (if enabled).

#### Behavior

- Rejects expired or tampered tokens
- Decodes into a structured `AccessTokenClaims` object

---

### 🧾 `VerifyRefreshToken`

```go
VerifyRefreshToken(ctx, tokenString) (*RefreshTokenClaims, error)
```

#### Description

Same as `VerifyAccessToken`, but for **refresh tokens**. Includes additional checks for revocation and structure but skips role verification.

#### Returns

- `RefreshTokenClaims` struct with decoded fields

---

### ❌ `RevokeAccessToken`

```go
RevokeAccessToken(ctx, tokenString) error
```

#### Description

Revokes the specified **access token** by storing it in Redis until its natural expiration. Prevents future usage.

> **Note**: Requires `RevocationEnabled` to be `true` and Redis to be configured.

---

### ❌ `RevokeRefreshToken`

```go
RevokeRefreshToken(ctx, tokenString) error
```

#### Description

Same as `RevokeAccessToken`, but for **refresh tokens**. Ensures a stolen or misused refresh token cannot be reused.

---

### 🔄 `RotateRefreshToken`

```go
RotateRefreshToken(ctx, oldToken) (*RefreshTokenResponse, error)
```

#### Description

Implements **refresh token rotation**. Generates a new refresh token and invalidates the old one via Redis.

#### Workflow

1. Validates the existing refresh token
2. Ensures it hasn't already been rotated (Replay protection)
3. Issues a new refresh token
4. Stores the old token as rotated (Redis key: `rotated:<oldToken>`)

---

### 🧪 Interface Usage Example

```go
func AuthFlowExample(maker gourdiantoken.gourdiantokenMaker) {
	userID := uuid.New()
	sessionID := uuid.New()

	// 1. Create access + refresh tokens
	access, _ := maker.CreateAccessToken(ctx, userID, "john", []string{"user"}, sessionID)
	refresh, _ := maker.CreateRefreshToken(ctx, userID, "john", sessionID)

	// 2. Verify access token
	claims, err := maker.VerifyAccessToken(ctx, access.Token)
	if err != nil {
		log.Fatal("Access denied:", err)
	}
	fmt.Println("User roles:", claims.Roles)

	// 3. Rotate refresh token
	newRefresh, err := maker.RotateRefreshToken(ctx, refresh.Token)
	if err != nil {
		log.Fatal("Rotation failed:", err)
	}

	// 4. Revoke access on logout
	_ = maker.RevokeAccessToken(ctx, access.Token)
}
```

---

## 🤝 Contributing

We welcome contributions from the community! Whether it's fixing bugs, improving documentation, or suggesting new features — every bit helps.

### 🧭 Contribution Steps

1. **Fork** this repository
2. **Clone** your fork:

   ```bash
   git clone https://github.com/gourdian25/gourdiantoken.git
   cd gourdiantoken
   ```

3. **Create a feature branch**:

   ```bash
   git checkout -b feature/my-awesome-feature
   ```

4. **Make your changes** and **write tests**
5. **Commit** and **push** your branch:

   ```bash
   git push origin feature/my-awesome-feature
   ```

6. **Submit a pull request** and describe your changes

> 📬 Please ensure your code is well-documented, formatted (`go fmt`), and tested.

---

## 🧪 Testing

We strive for production-level correctness and test coverage. Run the following to execute unit tests and generate coverage reports:

```bash
# Run the full test suite
make test

# Generate a coverage profile and HTML report
make coverage
```

You can then open the `coverage.html` file in your browser for visual analysis:

```bash
open coverage.html
```

> ✅ Current test coverage: **69.5%**  
> All critical logic paths are fully covered and continuously tested.

---

## 🚀 Benchmarks

This project includes comprehensive benchmark suites for access/refresh token creation, verification, Redis operations, and concurrency.

Run benchmarks with:

```bash
make bench
```

Benchmark results include:

- Token ops across HMAC, RSA, ECDSA, EdDSA
- Redis-backed token rotation and revocation
- Parallelized performance

Sample output:

```text
go test -bench=. -benchmem .
goos: linux
goarch: amd64
pkg: github.com/gourdian25/gourdiantoken
cpu: Intel(R) Core(TM) i5-9300H CPU @ 2.40GHz
BenchmarkCreateAccessToken/Symmetric-8                    159226              7370 ns/op            4682 B/op         58 allocs/op
BenchmarkCreateAccessToken/Asymmetric-8                      987           1262067 ns/op            5771 B/op         56 allocs/op
BenchmarkVerifyAccessToken/Symmetric-8                    136762              8861 ns/op            3944 B/op         75 allocs/op
BenchmarkVerifyAccessToken/Asymmetric-8                    28353             46053 ns/op            5192 B/op         80 allocs/op
BenchmarkTokenOperations/HMAC-256/Create-8                147465              7514 ns/op            4682 B/op         58 allocs/op
BenchmarkTokenOperations/HMAC-256/Verify-8                135084              8982 ns/op            3944 B/op         75 allocs/op
BenchmarkTokenOperations/HMAC-384/Create-8                138393              7758 ns/op            5083 B/op         58 allocs/op
BenchmarkTokenOperations/HMAC-384/Verify-8                135860             10505 ns/op            4296 B/op         75 allocs/op
BenchmarkTokenOperations/HMAC-512/Create-8                147939              7744 ns/op            5163 B/op         58 allocs/op
BenchmarkTokenOperations/HMAC-512/Verify-8                132926             10265 ns/op            4328 B/op         75 allocs/op
BenchmarkTokenOperations/RSA-2048/Create-8                   970           1318594 ns/op            5773 B/op         56 allocs/op
BenchmarkTokenOperations/RSA-2048/Verify-8                 24148             43825 ns/op            5192 B/op         80 allocs/op
BenchmarkTokenOperations/RSA-4096/Create-8                   175           6996740 ns/op           44196 B/op        107 allocs/op
BenchmarkTokenOperations/RSA-4096/Verify-8                  3459            381105 ns/op           66633 B/op        172 allocs/op
BenchmarkTokenOperations/ECDSA-P256/Create-8               28281             47819 ns/op           11079 B/op        126 allocs/op
BenchmarkTokenOperations/ECDSA-P256/Verify-8               13358             80034 ns/op            4840 B/op         95 allocs/op
BenchmarkTokenOperations/ECDSA-P384/Create-8                4261            256259 ns/op           11623 B/op        130 allocs/op
BenchmarkTokenOperations/ECDSA-P384/Verify-8                1712            705207 ns/op            5328 B/op        102 allocs/op
BenchmarkRedisTokenRotation/LocalRedis-8                    1724            683310 ns/op            8880 B/op        142 allocs/op
BenchmarkTokenRevocation-8                                  4998            248625 ns/op            4224 B/op         81 allocs/op
BenchmarkConcurrentTokenCreation-8                        206032              5595 ns/op            4687 B/op         58 allocs/op
BenchmarkTokenSizeImpact/Small-8                          140714              8620 ns/op            4619 B/op         58 allocs/op
BenchmarkTokenSizeImpact/Medium-8                         156982              7608 ns/op            4731 B/op         58 allocs/op
BenchmarkTokenSizeImpact/Large-8                          152390              7825 ns/op            5068 B/op         58 allocs/op
BenchmarkVerificationWithKeySizes/RSA-1024-8               57046             20771 ns/op            4680 B/op         80 allocs/op
BenchmarkVerificationWithKeySizes/RSA-2048-8               28603             42473 ns/op            5192 B/op         80 allocs/op
BenchmarkVerificationWithKeySizes/RSA-4096-8                3384            342528 ns/op           66633 B/op        172 allocs/op
BenchmarkVerificationWithKeySizes/ECDSA-P256-8             15271             79583 ns/op            4840 B/op         95 allocs/op
BenchmarkVerificationWithKeySizes/ECDSA-P384-8              1744            709966 ns/op            5328 B/op        102 allocs/op
BenchmarkVerificationWithKeySizes/ECDSA-P521-8               558           2239444 ns/op            5984 B/op        103 allocs/op
BenchmarkCreateRefreshToken/Symmetric-8                   127687              8028 ns/op            4387 B/op         55 allocs/op
BenchmarkCreateRefreshToken/Asymmetric-8                     964           1220863 ns/op            5477 B/op         53 allocs/op
BenchmarkVerifyRefreshToken-8                             139417              8236 ns/op            3488 B/op         66 allocs/op
BenchmarkRotateRefreshToken_RedisReuseInterval-8               1        2002112529 ns/op            8968 B/op        143 allocs/op
BenchmarkRevokeAndVerifyToken_Redis-8                       2446            476761 ns/op            4867 B/op         90 allocs/op
BenchmarkWithMultipleRoles-8                               25526             44118 ns/op           38668 B/op         58 allocs/op
BenchmarkVerifyAccessTokenParallel-8                      229293              4735 ns/op            4024 B/op         78 allocs/op
BenchmarkCreateAccessTokenParallel-8                      225867              4919 ns/op            4703 B/op         59 allocs/op
BenchmarkCreateRefreshTokenParallel-8                     253236              4345 ns/op            4358 B/op         55 allocs/op
BenchmarkVerifyRefreshTokenParallel-8                     302210              4009 ns/op            3488 B/op         66 allocs/op
BenchmarkRotateRefreshTokenParallel-8                       7461            167292 ns/op           13223 B/op        197 allocs/op
BenchmarkTokenRevocationParallel-8                         11308            110240 ns/op            9447 B/op        149 allocs/op
PASS
ok      github.com/gourdian25/gourdiantoken     82.284s
```

> 🧠 See the [Performance] (#-performance) section for detailed metrics and recommendations.

---

## 📑 License

gourdiantoken is licensed under the **MIT License**.  
You are free to use, modify, distribute, and adapt the code for both personal and commercial use.

See the full license [here](./LICENSE).

---

## 🙌 Acknowledgments

Special thanks to the following open-source projects that power the internals of this package:

- [golang-jwt/jwt](https://github.com/golang-jwt/jwt) — Standard JWT implementation in Go
- [google/uuid](https://github.com/google/uuid) — Fast and reliable UUID support
- [redis/go-redis](https://github.com/redis/go-redis) — Redis client library for Go
- [Sigil](https://github.com/gourdian25/sigil) — CLI-based RSA/ECDSA key generator

---

## 👨‍💼 Maintainers

Maintained and actively developed by:

- [@gourdian25](https://github.com/gourdian25) — Creator & Core Maintainer
- [@lordofthemind](https://github.com/lordofthemind) — Performance & Benchmarking

Want to join the team? Start contributing and open a discussion!

---

## 🔒 Security Policy

We take security seriously.

- If you discover a vulnerability, please **open a private GitHub issue** or contact the maintainers directly.
- Do **not** disclose vulnerabilities in public pull requests or issues.

For all disclosures, follow responsible vulnerability reporting best practices.

---

## 📚 Documentation

Full API documentation is available on [GoDoc](https://pkg.go.dev/github.com/gourdian25/gourdiantoken).  
Includes:

- Public types and interfaces
- Usage patterns
- Token claim structures

---

Made with ❤️ by Go developers — for Go developers.  
Secure authentication shouldn't be hard. gourdiantoken makes it elegant, efficient, and production-ready.
