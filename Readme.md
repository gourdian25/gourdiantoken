# Gourdiantoken – Enterprise-Grade JWT Management for Go

![Go Version](https://img.shields.io/badge/Go-1.18%2B-blue)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![GoDoc](https://pkg.go.dev/badge/github.com/gourdian25/gourdiantoken)](https://pkg.go.dev/github.com/gourdian25/gourdiantoken)

**gourdiantoken** is a production-ready, comprehensive JWT token management system designed for modern Go applications. Built with security-first principles and performance optimization, it provides everything needed for enterprise authentication systems — from basic token generation to advanced features like automatic rotation, Redis-backed revocation, and multi-algorithm cryptographic support.

## 🎯 Why Gourdiantoken?

- 🔐 **Complete Security**: Token rotation, revocation, replay attack prevention, and strict claim validation
- ⚡ **High Performance**: Up to 200k operations/second with optimized algorithms
- 🔧 **Flexible Storage**: In-memory, Redis, PostgreSQL, MySQL, SQLite, MongoDB — choose what fits your architecture
- 🧩 **Algorithm Support**: HMAC (HS256/384/512), RSA (RS256/384/512, PS256/384/512), ECDSA (ES256/384/512), EdDSA
- 🛡️ **Production Ready**: Thread-safe, context-aware, automatic cleanup, comprehensive error handling
- 📊 **Battle Tested**: Extensive test coverage with real-world scenarios and edge cases

---

## 📚 Table of Contents

- [Features](#-features)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Architecture Overview](#-architecture-overview)
- [Configuration](#-configuration)
- [Storage Backends](#-storage-backends)
- [Token Types & Claims](#-token-types--claims)
- [Security Features](#-security-features)
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
- **Comprehensive Claims**: UUIDs for users/sessions, username, roles (RBAC), issuer, audience, timestamps
- **Flexible Expiration**: Configure both sliding expiration and absolute maximum lifetime
- **Context-Aware**: All operations support Go context for cancellation and timeouts

### Advanced Security

- **Token Rotation**: Automatic refresh token rotation with replay attack detection
- **Token Revocation**: Immediately invalidate tokens before natural expiration
- **Algorithm Flexibility**: Support for 11 different JWT signing algorithms
- **Strict Validation**: Comprehensive signature, expiration, claim, and type checking
- **Secure Defaults**: Pre-configured with industry best practices

### Storage & Scalability

- **Multiple Backends**: In-memory, Redis, GORM (PostgreSQL/MySQL/SQLite), MongoDB
- **Automatic Cleanup**: Background goroutines remove expired entries
- **Atomic Operations**: Race-condition-free rotation with compare-and-swap semantics
- **Production Scale**: Designed for distributed systems and high-throughput APIs

### Developer Experience

- **Clean API**: Intuitive interface with clear method signatures
- **Factory Methods**: Quick setup with defaults or full customization
- **Rich Documentation**: Comprehensive inline documentation and examples
- **Type Safety**: Strong typing with UUIDs and time.Time throughout

---

## 📦 Installation

```bash
go get github.com/gourdian25/gourdiantoken@latest
```

**Requirements**: Go 1.18 or higher

**Optional Dependencies** (based on storage backend):
```bash
# For Redis support
go get github.com/redis/go-redis/v9

# For SQL databases (PostgreSQL, MySQL, SQLite)
go get gorm.io/gorm
go get gorm.io/driver/postgres  # or mysql, sqlite

# For MongoDB
go get go.mongodb.org/mongo-driver
```

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

    "github.com/gourdian25/gourdiantoken"
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
    userID := uuid.New()
    sessionID := uuid.New()
    
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

    "github.com/gourdian25/gourdiantoken"
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

    userID := uuid.New()
    sessionID := uuid.New()

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

```
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

```
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
}
```

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
maker, _ := gourdiantoken.NewGourdianTokenMakerWithMongo(ctx, config, mongoDB)
```

---

## 💾 Storage Backends

### Overview

| Backend | Use Case | Performance | Persistence | Distributed |
|---------|----------|-------------|-------------|-------------|
| **In-Memory** | Development, Testing | ⚡⚡⚡ | ❌ | ❌ |
| **Redis** | Production, High-Performance | ⚡⚡⚡ | ✅ (optional) | ✅ |
| **GORM (SQL)** | Enterprise, Complex Queries | ⚡⚡ | ✅ | ✅ |
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

### 4. SQL Storage (GORM)

```go
import "gorm.io/driver/postgres"

db, _ := gorm.Open(postgres.Open(dsn), &gorm.Config{})
maker, err := gourdiantoken.NewGourdianTokenMakerWithGorm(ctx, config, db)
```

**Supported Databases:**
- PostgreSQL (recommended)
- MySQL/MariaDB
- SQLite (development only)
- SQL Server
- CockroachDB

**Features:**
- ACID transactions
- Complex queries
- Automatic migrations
- Connection pooling

**Best For:**
- Existing SQL infrastructure
- Complex audit requirements
- Enterprise applications

### 5. MongoDB Storage

```go
client, _ := mongo.Connect(ctx, options.Client().ApplyURI(mongoURI))
mongoDB := client.Database("auth_service")
maker, err := gourdiantoken.NewGourdianTokenMakerWithMongo(ctx, config, mongoDB)
```

**Features:**
- Document-oriented storage
- Automatic TTL indexes
- Optional transactions (requires replica set)
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
    ID                uuid.UUID   `json:"jti"`
    Subject           uuid.UUID   `json:"sub"`
    SessionID         uuid.UUID   `json:"sid"`
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

### Token Comparison

| Feature | Access Token | Refresh Token |
|---------|-------------|---------------|
| **Lifetime** | 15-60 minutes | 7-90 days |
| **Contains Roles** | ✅ Yes | ❌ No |
| **Used for API Calls** | ✅ Yes | ❌ No |
| **Can be Rotated** | ❌ No | ✅ Yes |
| **Revocable** | ✅ Yes | ✅ Yes |
| **Typical Storage** | Authorization header | HttpOnly cookie |

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
- ✅ UUID format validation
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

## 📖 API Reference

### GourdianTokenMaker Interface

```go
type GourdianTokenMaker interface {
    CreateAccessToken(ctx context.Context, userID uuid.UUID, username string, roles []string, sessionID uuid.UUID) (*AccessTokenResponse, error)
    CreateRefreshToken(ctx context.Context, userID uuid.UUID, username string, sessionID uuid.UUID) (*RefreshTokenResponse, error)
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
    userID,          // uuid.UUID - User's unique identifier
    username,        // string - Human-readable name
    roles,           // []string - Authorization roles (min 1)
    sessionID,       // uuid.UUID - Session identifier
)
```

**Returns:** `*AccessTokenResponse` containing signed JWT and metadata

**Validation:**
- `userID` must not be `uuid.Nil`
- `username` max 1024 characters
- `roles` must contain at least one non-empty string
- Checks context cancellation before signing

### CreateRefreshToken

```go
token, err := maker.CreateRefreshToken(
    ctx,
    userID,          // uuid.UUID
    username,        // string
    sessionID,       // uuid.UUID
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

---

## 🎓 Advanced Usage

### Complete Authentication Flow

```go
package main

import (
    "context"
    "encoding/json"
    "log"
    "net/http"
    "strings"
    "time"

    "github.com/gourdian25/gourdiantoken"
    "github.com/google/uuid"
    "github.com/redis/go-redis/v9"
)

var maker gourdiantoken.GourdianTokenMaker

func init() {
    ctx := context.Background()
    
    // Setup
    redisClient := redis.NewClient(&redis.Options{Addr: "localhost:6379"})
    config := gourdiantoken.DefaultGourdianTokenConfig("production-secret-key-32-bytes")
    config.RevocationEnabled = true
    config.RotationEnabled = true
    
    var err error
    maker, err = gourdiantoken.NewGourdianTokenMakerWithRedis(ctx, config, redisClient)
    if err != nil {
        log.Fatal(err)
    }
}

// Login handler
func loginHandler(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()
    
    // Authenticate user (your logic here)
    userID := uuid.New()
    username := "john.doe@example.com"
    roles := []string{"user", "admin"}
    sessionID := uuid.New()
    
    // Create token pair
    accessToken, err := maker.CreateAccessToken(ctx, userID, username, roles, sessionID)
    if err != nil {
        http.Error(w, "Failed to create access token", http.StatusInternalServerError)
        return
    }
    
    refreshToken, err := maker.CreateRefreshToken(ctx, userID, username, sessionID)
    if err != nil {
        http.Error(w, "Failed to create refresh token", http.StatusInternalServerError)
        return
    }
    
    // Set refresh token as HttpOnly cookie
    http.SetCookie(w, &http.Cookie{
        Name:     "refresh_token",
        Value:    refreshToken.Token,
        Path:     "/",
        HttpOnly: true,
        Secure:   true,
        SameSite: http.SameSiteStrictMode,
        Expires:  refreshToken.ExpiresAt,
    })
    
    // Return access token in response
    json.NewEncoder(w).Encode(map[string]interface{}{
        "access_token": accessToken.Token,
        "expires_at":   accessToken.ExpiresAt,
        "token_type":   "Bearer",
    })
}

// Auth middleware
func authMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        authHeader := r.Header.Get("Authorization")
        if authHeader == "" {
            http.Error(w, "Missing authorization header", http.StatusUnauthorized)
            return
        }
        
        tokenString := strings.TrimPrefix(authHeader, "Bearer ")
        if tokenString == authHeader {
            http.Error(w, "Invalid authorization format", http.StatusUnauthorized)
            return
        }
        
        claims, err := maker.VerifyAccessToken(r.Context(), tokenString)
        if err != nil {
            http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
            return
        }
        
        ctx := context.WithValue(r.Context(), "claims", claims)
        next.ServeHTTP(w, r.WithContext(ctx))
    })
}

// Refresh token handler
func refreshHandler(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()
    
    cookie, err := r.Cookie("refresh_token")
    if err != nil {
        http.Error(w, "Missing refresh token", http.StatusUnauthorized)
        return
    }
    
    newRefreshToken, err := maker.RotateRefreshToken(ctx, cookie.Value)
    if err != nil {
        if strings.Contains(err.Error(), "rotated") {
            log.Printf("Token reuse detected from IP: %s", r.RemoteAddr)
            http.Error(w, "Security violation detected", http.StatusForbidden)
            return
        }
        http.Error(w, "Invalid refresh token", http.StatusUnauthorized)
        return
    }
    
    claims, err := maker.VerifyRefreshToken(ctx, newRefreshToken.Token)
    if err != nil {
        http.Error(w, "Failed to verify new token", http.StatusInternalServerError)
        return
    }
    
    roles := []string{"user"} // Load from database
    
    newAccessToken, err := maker.CreateAccessToken(
        ctx, claims.Subject, claims.Username, roles, claims.SessionID,
    )
    if err != nil {
        http.Error(w, "Failed to create access token", http.StatusInternalServerError)
        return
    }
    
    http.SetCookie(w, &http.Cookie{
        Name:     "refresh_token",
        Value:    newRefreshToken.Token,
        Path:     "/",
        HttpOnly: true,
        Secure:   true,
        SameSite: http.SameSiteStrictMode,
        Expires:  newRefreshToken.ExpiresAt,
    })
    
    json.NewEncoder(w).Encode(map[string]interface{}{
        "access_token": newAccessToken.Token,
        "expires_at":   newAccessToken.ExpiresAt,
        "token_type":   "Bearer",
    })
}

// Logout handler
func logoutHandler(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()
    
    authHeader := r.Header.Get("Authorization")
    accessToken := strings.TrimPrefix(authHeader, "Bearer ")
    
    cookie, err := r.Cookie("refresh_token")
    if err == nil {
        maker.RevokeRefreshToken(ctx, cookie.Value)
    }
    
    if accessToken != "" {
        maker.RevokeAccessToken(ctx, accessToken)
    }
    
    http.SetCookie(w, &http.Cookie{
        Name:     "refresh_token",
        Value:    "",
        Path:     "/",
        HttpOnly: true,
        Secure:   true,
        MaxAge:   -1,
    })
    
    w.WriteHeader(http.StatusOK)
}

func main() {
    http.HandleFunc("/login", loginHandler)
    http.HandleFunc("/refresh", refreshHandler)
    http.HandleFunc("/logout", logoutHandler)
    
    http.Handle("/api/protected", authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        claims := r.Context().Value("claims").(*gourdiantoken.AccessTokenClaims)
        json.NewEncoder(w).Encode(map[string]interface{}{
            "message": "Access granted",
            "user":    claims.Username,
            "roles":   claims.Roles,
        })
    })))
    
    log.Fatal(http.ListenAndServe(":8080", nil))
}
```

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

### Asymmetric Key Setup

```go
func setupAsymmetric() (gourdiantoken.GourdianTokenMaker, error) {
    config := gourdiantoken.NewGourdianTokenConfig(
        gourdiantoken.Asymmetric,
        true, true,
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

Benchmarks run on Intel i5-9300H @ 2.40GHz, Go 1.21:

#### Token Creation

| Algorithm | Operations/sec | Time/op | Memory/op | Allocs/op |
|-----------|----------------|---------|-----------|-----------|
| **HS256** | 159,226 | 7.4µs | 4.7 KB | 58 |
| **HS384** | 138,393 | 7.8µs | 5.1 KB | 58 |
| **HS512** | 147,939 | 7.7µs | 5.2 KB | 58 |
| **RS256** | 987 | 1.26ms | 5.8 KB | 56 |
| **RS512** | 970 | 1.32ms | 5.8 KB | 56 |
| **ES256** | 28,281 | 47.8µs | 11.1 KB | 126 |
| **ES384** | 4,261 | 256µs | 11.6 KB | 130 |

#### Token Verification

| Algorithm | Operations/sec | Time/op | Memory/op | Allocs/op |
|-----------|----------------|---------|-----------|-----------|
| **HS256** | 136,762 | 8.9µs | 3.9 KB | 75 |
| **RS256** | 28,353 | 46.1µs | 5.2 KB | 80 |
| **RS4096** | 3,459 | 381µs | 66.6 KB | 172 |
| **ES256** | 13,358 | 80.0µs | 4.8 KB | 95 |
| **ES384** | 1,712 | 705µs | 5.3 KB | 102 |

#### Redis Operations

| Operation | Operations/sec | Time/op | Memory/op |
|-----------|----------------|---------|-----------|
| **Token Rotation** | 1,724 | 683µs | 8.9 KB |
| **Token Revocation** | 4,998 | 249µs | 4.2 KB |

#### Concurrent Performance

| Operation | Goroutines | Ops/sec | Time/op |
|-----------|------------|---------|---------|
| **Create Access (Parallel)** | 8 | 206,032 | 5.6µs |
| **Verify Access (Parallel)** | 8 | 229,293 | 4.7µs |

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

### Simple REST API

```go
package main

import (
    "context"
    "encoding/json"
    "log"
    "net/http"
    "strings"

    "github.com/gourdian25/gourdiantoken"
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
        r.Context(), uuid.New(), "user@example.com", []string{"user"}, uuid.New(),
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

### Unit Test Example

```go
func TestTokenCreation(t *testing.T) {
    ctx := context.Background()
    config := gourdiantoken.DefaultGourdianTokenConfig("test-secret-key-32-bytes-long")
    maker, _ := gourdiantoken.NewGourdianTokenMakerNoStorage(ctx, config)
    
    userID := uuid.New()
    token, err := maker.CreateAccessToken(ctx, userID, "test", []string{"user"}, uuid.New())
    
    require.NoError(t, err)
    assert.NotEmpty(t, token.Token)
    assert.Equal(t, userID, token.Subject)
}

func TestTokenExpiration(t *testing.T) {
    ctx := context.Background()
    config := gourdiantoken.DefaultGourdianTokenConfig("test-key")
    config.AccessExpiryDuration = 1 * time.Second
    maker, _ := gourdiantoken.NewGourdianTokenMakerNoStorage(ctx, config)
    
    token, _ := maker.CreateAccessToken(ctx, uuid.New(), "user", []string{"user"}, uuid.New())
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
    
    refresh, _ := maker.CreateRefreshToken(ctx, uuid.New(), "user", uuid.New())
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
- [gorm.io/gorm](https://github.com/go-gorm/gorm) - ORM framework
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

- [GoDoc](https://pkg.go.dev/github.com/gourdian25/gourdiantoken) - Full API docs
- [RFC 7519](https://tools.ietf.org/html/rfc7519) - JWT Standard
- [RFC 7515](https://tools.ietf.org/html/rfc7515) - JWS Standard
- [RFC 7518](https://tools.ietf.org/html/rfc7518) - JWA Standard

---

<div align="center">

**Made with ❤️ by the gourdiantoken team**

[Documentation](https://pkg.go.dev/github.com/gourdian25/gourdiantoken) • 
[Issues](https://github.com/gourdian25/gourdiantoken/issues) • 
[Discussions](https://github.com/gourdian25/gourdiantoken/discussions)

⭐ Star us on GitHub if you find this useful!

</div>