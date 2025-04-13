# GourdianToken — Enterprise-Grade JWT Management for Go

**GourdianToken** is a high-performance, security-focused JWT token system for modern Go applications. It provides an enterprise-ready solution for access and refresh token generation, validation, revocation, and rotation using industry standards and best practices.

> **Version:** v1.0.0  
> **License:** MIT  
> **Go Version:** 1.18+

---

## ✨ Why GourdianToken?

- ✅ **Military-Grade Security** — Best practices for JWT signing, verification, and key management
- ⚡ **Blazing Fast** — Handles millions of tokens per second using HMAC
- 🧢 **Highly Configurable** — Token durations, required claims, rotation, revocation, and more
- 📈 **Battle-Tested** — Extensive test coverage and benchmarked under load
- 🤝 **Developer-Friendly** — Simple API, clean abstractions, and composable configuration

---

## 🔧 Installation

```bash
go get github.com/gourdian25/gourdiantoken@latest
```

---

Absolutely! Here's a **detailed and refined version** of the `## Key Features Deep Dive` section for your `README.md`:

---

## 🔍 Key Features Deep Dive

GourdianToken is built to provide a complete, secure, and scalable JWT management system for modern backend applications. This section dives deeper into its capabilities across token lifecycle management, cryptographic flexibility, security enforcement, and performance tuning.

---

### 🔑 1. Advanced Token Management

GourdianToken supports a robust dual-token architecture to handle different stages of user authentication and authorization.

#### ✅ Dual-Token Architecture

- **Access Tokens**  
  Short-lived, bearer tokens used for API authentication.  
  Carries user identity (`sub`), session (`sid`), and role (`rls`) claims.  
  Ideal for validating frontend or API requests.
  
- **Refresh Tokens**  
  Long-lived tokens used to renew access tokens without re-authentication.  
  Contain session and user identifiers but no roles.  
  Designed for secure storage and use during silent authentication flows.

#### 🕓 Configurable Lifetimes

- Fine-grained control over:
  - **`Duration`** – how long a token is valid (e.g., 15m for access, 7d for refresh).
  - **`MaxLifetime`** – hard expiry, even if `iat + duration` is extended.
  - **`ReuseInterval`** – helps prevent token reuse attacks during rotation.

#### 🔁 Refresh Token Rotation

- Automatically invalidates used refresh tokens.
- Ensures a zero-trust token lifecycle where reused tokens are detected and blocked.
- All rotation operations are **tracked and TTL-bound in Redis** for safe reuse detection.

---

### 🔐 2. Cryptographic Flexibility

Support for both symmetric and asymmetric cryptographic methods to fit a wide range of application security needs.

#### 🔄 Algorithm Support

| Type       | Algorithms                              |
|------------|------------------------------------------|
| Symmetric  | `HS256`, `HS384`, `HS512`                |
| Asymmetric | `RS256`, `RS384`, `RS512` (RSA-PKCS1)    |
|            | `PS256`, `PS384`, `PS512` (RSA-PSS)      |
|            | `ES256`, `ES384`, `ES512` (ECDSA)        |
|            | `EdDSA` (Ed25519)                        |

#### 🗝️ Key Management Options

- Symmetric: Pass a secure 32+ byte HMAC secret string.
- Asymmetric:
  - Load from `PEM` encoded RSA, ECDSA, or EdDSA key files.
  - File permission checks ensure private keys are not world-readable.
  - Built-in parsing for `PKCS1`, `PKCS8`, and certificate-based public keys.

#### 🔁 Key Rotation Ready

- Replace keys without downtime by instantiating a new `GourdianTokenMaker` with updated keys.
- Consider using the [`sigil`](https://github.com/gourdian25/sigil) tool for quick key generation.

---

### 🛡️ 3. Security Protections

Security is baked into every aspect of GourdianToken.

#### 🚫 Algorithm Confusion Prevention

- Explicit algorithm whitelisting ensures only expected signing methods are allowed.
- Rejects use of `"none"` algorithm under all configurations.

#### 🔒 Token Binding

- Access tokens are tightly bound to a session ID (`sid` claim) and optionally user/device context.
- Enables granular session tracking and revocation.

#### 🗑️ Token Revocation & Rotation

- **Access Token Revocation**:
  - Immediately invalidate a token using `RevokeAccessToken()`.
  - Stored in Redis with TTL = remaining token validity.

- **Refresh Token Rotation**:
  - Invalidate old token and issue a new one on use.
  - Rejects reused tokens after rotation (`Replay Detection`).

#### 🔒 Secure Defaults

- HMAC key: minimum 32 bytes enforced.
- Token types are strictly checked via `typ` claim.
- Strong input validation during token generation and verification.

---

### ⚡ 4. Performance Optimizations

Designed for high-throughput, low-latency systems.

#### 🧠 Efficient Memory Management

- Minimal allocations per token (~4.6 KB for HMAC).
- Custom claims and reuse of structs to reduce GC pressure.

#### 🔁 Concurrent Safe

- Stateless design for token creation and verification.
- Fully compatible with Go's concurrent runtime.

#### ⚙️ Redis Optimization

- Uses `SCAN` instead of `KEYS` for background cleanup.
- All token states (rotation/revocation) TTL-managed automatically.
- Background goroutines clean up expired entries every hour.

#### 💥 Benchmark Results

| Operation                         | Time/op       | Ops/sec        |
|----------------------------------|---------------|----------------|
| Access Token (HMAC Create)       | ~25 µs        | ~40,000 ops/s  |
| Access Token (RSA Verify)        | ~130 µs       | ~7,700 ops/s   |
| Refresh Token Rotation (Redis)   | ~1.7 ms       | ~600 ops/s     |
| Concurrent Verification (HMAC)   | ~6.7 µs       | ~150,000 ops/s |

> See the full benchmark section for detailed memory usage and algorithm comparison.

Absolutely — here's a **fully detailed and professional rendering** of the `## Enhanced Usage Examples` section for your README.md:

---

## 🚀 Enhanced Usage Examples

This section walks you through practical usage scenarios of **GourdianToken**, ranging from basic setups to advanced token flows with Redis, rotation, and asymmetric key support.

All examples assume:

```go
import (
	"context"
	"log"
	"time"

	"github.com/gourdian25/gourdiantoken"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)
```

---

### ✅ 1. Minimal Setup – Symmetric Tokens without Redis

The simplest way to get started with GourdianToken is by using the default configuration with a secure HMAC key.

```go
func basicExample() {
	ctx := context.Background()
	key := "your-very-secure-32-byte-key!!!!"

	maker, err := gourdiantoken.NewGourdianTokenMaker(ctx, gourdiantoken.DefaultGourdianTokenConfig(key), nil)
	if err != nil {
		log.Fatal("Initialization error:", err)
	}

	userID := uuid.New()
	sessionID := uuid.New()

	access, _ := maker.CreateAccessToken(ctx, userID, "alice", []string{"user"}, sessionID)
	refresh, _ := maker.CreateRefreshToken(ctx, userID, "alice", sessionID)

	log.Println("Access Token:", access.Token)
	log.Println("Refresh Token:", refresh.Token)
}
```

---

### 🔁 2. Full Lifecycle – Issue, Verify, Rotate

This example walks through issuing both tokens, verifying them, and rotating the refresh token.

```go

func fullLifecycle() {
	ctx := context.Background()
	key := "secure-hmac-key-of-32+bytes-long"
	maker, _ := gourdiantoken.NewGourdianTokenMakerWithDefaults(ctx, key, nil)

	userID := uuid.New()
	sessionID := uuid.New()

	// Create tokens
	access, _ := maker.CreateAccessToken(ctx, userID, "john", []string{"admin", "editor"}, sessionID)
	refresh, _ := maker.CreateRefreshToken(ctx, userID, "john", sessionID)

	// Verify access token
	claims, err := maker.VerifyAccessToken(ctx, access.Token)
	if err != nil {
		log.Fatal("Access verification failed:", err)
	}
	log.Println("User:", claims.Username, "Roles:", claims.Roles)

	// Rotate refresh token (recommended)
	newRefresh, err := maker.RotateRefreshToken(ctx, refresh.Token)
	if err != nil {
		log.Fatal("Refresh rotation failed:", err)
	}
	log.Println("New Refresh Token:", newRefresh.Token)
}
```

---

### 🔒 3. Enabling Redis for Rotation + Revocation

Add Redis support to track revoked or rotated tokens, essential for session management and compliance.

```go
func withRedisSupport() {
	ctx := context.Background()

	redisOpts := &redis.Options{Addr: "localhost:6379"}
	key := "redis-secure-key-that-is-32-bytes!!"

	maker, _ := gourdiantoken.NewGourdianTokenMakerWithDefaults(ctx, key, redisOpts)

	userID := uuid.New()
	sessionID := uuid.New()

	access, _ := maker.CreateAccessToken(ctx, userID, "adminUser", []string{"admin"}, sessionID)

	// Revoke the access token immediately
	_ = maker.RevokeAccessToken(ctx, access.Token)

	// This should now fail
	_, err := maker.VerifyAccessToken(ctx, access.Token)
	if err != nil {
		log.Println("Revoked token verification failed (as expected):", err)
	}
}
```

---

### 🔐 4. Asymmetric JWT (RSA) with File-based Keys

To use RS256 or any asymmetric method, provide file paths for private/public keys.

```go
func withAsymmetricKeys() {
	ctx := context.Background()

	config := gourdiantoken.NewGourdianTokenConfig(
		"RS256",
		gourdiantoken.Asymmetric,
		"",
		"./keys/private.pem",
		"./keys/public.pem",
		15*time.Minute,
		24*time.Hour,
		"api.myapp.com",
		[]string{"web.myapp.com"},
		[]string{"RS256"},
		[]string{"jti", "sub", "exp", "iat", "sid", "usr", "rls"},
		true,
		7*24*time.Hour,
		30*24*time.Hour,
		1*time.Minute,
		true,
		true,
	)

	redisOpts := &redis.Options{Addr: "localhost:6379"}
	maker, err := gourdiantoken.NewGourdianTokenMaker(ctx, config, redisOpts)
	if err != nil {
		log.Fatal("Failed to init asymmetric maker:", err)
	}

	userID := uuid.New()
	sessionID := uuid.New()

	access, _ := maker.CreateAccessToken(ctx, userID, "jwtuser", []string{"reader"}, sessionID)
	log.Println("RS256 Access Token:", access.Token)
}
```

> 🔧 Tip: Use [Sigil](https://github.com/gourdian25/sigil) CLI to generate JWT-ready RSA/ECDSA/EdDSA keys.

---

## 🚧 Configuration

```go
config := gourdiantoken.NewGourdianTokenConfig(
    "RS256",
    gourdiantoken.Asymmetric,
    "",
    "./keys/private.pem",
    "./keys/public.pem",
    15*time.Minute,
    24*time.Hour,
    "api.example.com",
    []string{"example.com"},
    []string{"RS256"},
    []string{"jti", "sub", "exp", "iat", "sid", "usr", "rls"},
    true,
    7*24*time.Hour,
    30*24*time.Hour,
    1*time.Minute,
    true,
    true,
)
```

---

## 🤖 Usage Examples

### Example 1: Simple Symmetric Token

```go
maker, _ := gourdiantoken.NewGourdianTokenMaker(ctx, gourdiantoken.DefaultGourdianTokenConfig("your-key"), nil)
access, _ := maker.CreateAccessToken(ctx, userID, "user", []string{"admin"}, sessionID)
```

### Example 2: Verify Access Token

```go
claims, err := maker.VerifyAccessToken(access.Token)
fmt.Println("Roles:", claims.Roles)
```

### Example 3: Redis-Backed Revocation

```go
redisOpts := &redis.Options{Addr: "localhost:6379"}
maker, _ := gourdiantoken.NewGourdianTokenMakerWithDefaults(ctx, key, redisOpts)
maker.RevokeAccessToken(ctx, access.Token)
```

### Example 4: Token Rotation

```go
newRefresh, err := maker.RotateRefreshToken(ctx, oldRefresh.Token)
```

---

## 📊 Performance

| Algorithm     | Create Time | Verify Time | Throughput   |
|---------------|-------------|-------------|--------------|
| HMAC-SHA256   | 25μs       | 30μs       | 1M+ ops/sec  |
| RSA-2048      | 2.9ms       | 130μs      | 121K ops/sec |
| ECDSA-P256    | 135μs      | 205μs      | 70K ops/sec  |

### Parallel Performance

- Token creation: 5.7μs/token
- Token verification: 6.7μs/token

---

## ⛨ Security Best Practices

- Use Redis for revocation and reuse detection
- Prefer ES256 or RS256 for public-facing APIs
- Rotate refresh tokens and secrets periodically
- Enforce `iat`, `exp`, `typ`, and `rls` claims
- Avoid use of "none" algorithm

---

## 📘 Full Feature List

### • Supported Algorithms

- HS256/384/512
- RS256/384/512
- ES256/384/512
- PS256/384/512
- EdDSA

### • Features

- Token generation/validation
- Rotation & revocation
- Required claim validation
- Redis cleanup goroutines
- Middleware support
- Key loading + validation

### • Developer APIs

- `CreateAccessToken`
- `CreateRefreshToken`
- `VerifyAccessToken`
- `VerifyRefreshToken`
- `RevokeAccessToken`
- `RotateRefreshToken`

---

## Acknowledgments

- [golang-jwt/jwt](https://github.com/golang-jwt/jwt) for the JWT library.
- [google/uuid](https://github.com/google/uuid) for UUID generation.
- [Sigil](https://github.com/gourdian25/sigil) for simplifying RSA key generation.

---

For more detailed documentation, please refer to the [GoDoc](https://pkg.go.dev/github.com/gourdian25/gourdiantoken).

---

## 📁 License

MIT License — see [LICENSE](./LICENSE)

## 👨‍💼 Maintainers

- [@gourdian25](https://github.com/gourdian25)
- [@lordofthemind](https://github.com/lordofthemind)

## 🚫 Security Policy

Please report vulnerabilities via GitHub Issues or contact us directly.

---

Made with ❤️ by Go developers for Go developers.
