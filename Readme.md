# GourdianToken

GourdianToken is a robust and flexible JWT-based token management system for Go applications. It provides a comprehensive solution for creating, verifying, and managing access and refresh tokens, with support for both symmetric (HMAC) and asymmetric (RSA, ECDSA) key signing methods. The package is designed to be easy to integrate into your application, offering a wide range of configuration options to suit your security requirements.

## Features

- **Token Creation and Verification**: Easily create and verify access and refresh tokens.
- **Configurable Token Expiration**: Set custom expiration times for both access and refresh tokens.
- **Support for Multiple Signing Algorithms**: Includes support for HMAC (HS256, HS384, HS512), RSA (RS256, RS384, RS512), and ECDSA (ES256, ES384, ES512) signing algorithms.
- **UUID Integration**: Uses UUIDs for token and session IDs, ensuring uniqueness and security.
- **Token Rotation**: Supports token rotation for enhanced security.
- **Middleware Integration**: Includes an example of how to integrate token validation into your HTTP middleware.

## Installation

To install the GourdianToken package, use the following command:

```bash
go get github.com/gourdian25/gourdiantoken
```

## Usage

### Configuration

First, you need to configure the token maker with your desired settings. The configuration includes options for the signing algorithm, key paths, token expiration, and more.

```go
import (
    "time"
    "github.com/gourdian25/gourdiantoken"
)

config := gourdiantoken.GourdianTokenConfig{
    Algorithm:     "HS256",
    SigningMethod: gourdiantoken.Symmetric,
    SymmetricKey:  "your-very-secure-secret-key-at-least-32-bytes",
    AccessToken: gourdiantoken.AccessTokenConfig{
        Duration:          15 * time.Minute,
        MaxLifetime:       24 * time.Hour,
        Issuer:            "gourdian-example-app",
        Audience:          []string{"web", "mobile"},
        AllowedAlgorithms: []string{"HS256"},
        RequiredClaims:    []string{"sub", "exp", "jti"},
    },
    RefreshToken: gourdiantoken.RefreshTokenConfig{
        Duration:        7 * 24 * time.Hour,
        MaxLifetime:     30 * 24 * time.Hour,
        ReuseInterval:   5 * time.Minute,
        RotationEnabled: true,
        FamilyEnabled:   true,
        MaxPerUser:      5,
    },
}
```

### Creating a Token Maker

Once you have your configuration, you can create a token maker instance:

```go
maker, err := gourdiantoken.NewGourdianTokenMaker(config)
if err != nil {
    log.Fatalf("Failed to create token maker: %v", err)
}
```

### Creating Tokens

You can create access and refresh tokens using the token maker:

```go
userID := uuid.New()
username := "john.doe"
role := "admin"
sessionID := uuid.New()
permissions := []string{"read:users", "write:users", "read:reports"}

// Create an access token
accessToken, err := maker.CreateAccessToken(context.Background(), userID, username, role, sessionID, permissions)
if err != nil {
    log.Fatalf("Failed to create access token: %v", err)
}

// Create a refresh token
refreshToken, err := maker.CreateRefreshToken(context.Background(), userID, username, sessionID)
if err != nil {
    log.Fatalf("Failed to create refresh token: %v", err)
}
```

### Verifying Tokens

You can verify the tokens to ensure they are valid and extract the claims:

```go
// Verify access token
accessClaims, err := maker.VerifyAccessToken(accessToken.Token)
if err != nil {
    log.Fatalf("Access token verification failed: %v", err)
}

// Verify refresh token
refreshClaims, err := maker.VerifyRefreshToken(refreshToken.Token)
if err != nil {
    log.Fatalf("Refresh token verification failed: %v", err)
}
```

### Token Refresh Example

Here's an example of how to refresh a token:

```go
// Verify the refresh token
refreshTokenStr := refreshToken.Token
refreshClaims, err := maker.VerifyRefreshToken(refreshTokenStr)
if err != nil {
    log.Fatalf("Invalid refresh token: %v", err)
}

// Extract user information from the refresh token
userID = refreshClaims.Subject
username = refreshClaims.Username
sessionID = refreshClaims.SessionID

// Generate a new access token
newAccessToken, err := maker.CreateAccessToken(context.Background(), userID, username, role, sessionID, permissions)
if err != nil {
    log.Fatalf("Failed to create new access token: %v", err)
}

// Generate a new refresh token if token rotation is enabled
newRefreshToken, err := maker.CreateRefreshToken(context.Background(), userID, username, sessionID)
if err != nil {
    log.Fatalf("Failed to create new refresh token: %v", err)
}
```

### Middleware Integration

You can integrate token validation into your HTTP middleware for secure API endpoints:

```go
import (
    "context"
    "net/http"
    "strings"
)

func AuthMiddleware(maker gourdiantoken.GourdianTokenMaker) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            // Extract token from Authorization header
            authHeader := r.Header.Get("Authorization")
            if authHeader == "" || len(strings.Split(authHeader, " ")) != 2 {
                http.Error(w, "Unauthorized: Missing or invalid Authorization header", http.StatusUnauthorized)
                return
            }

            tokenString := strings.Split(authHeader, " ")[1]
            
            // Verify the access token
            claims, err := maker.VerifyAccessToken(tokenString)
            if err != nil {
                http.Error(w, "Unauthorized: Invalid token", http.StatusUnauthorized)
                return
            }
            
            // Add claims to request context for use in handlers
            ctx := context.WithValue(r.Context(), "user_id", claims.Subject)
            ctx = context.WithValue(ctx, "username", claims.Username)
            ctx = context.WithValue(ctx, "role", claims.Role)
            ctx = context.WithValue(ctx, "permissions", claims.Permissions)
            
            // Continue with the next handler
            next.ServeHTTP(w, r.WithContext(ctx))
        })
    }
}
```

## Examples

### Symmetric Key Example (HMAC)

```go
func symmetricExample() {
    fmt.Println("=== Symmetric Key Example (HMAC) ===")

    config := gourdiantoken.GourdianTokenConfig{
        Algorithm:     "HS256",
        SigningMethod: gourdiantoken.Symmetric,
        SymmetricKey:  "your-very-secure-secret-key-at-least-32-bytes",
        AccessToken: gourdiantoken.AccessTokenConfig{
            Duration:          15 * time.Minute,
            MaxLifetime:       24 * time.Hour,
            Issuer:            "gourdian-example-app",
            Audience:          []string{"web", "mobile"},
            AllowedAlgorithms: []string{"HS256"},
            RequiredClaims:    []string{"sub", "exp", "jti"},
        },
        RefreshToken: gourdiantoken.RefreshTokenConfig{
            Duration:        7 * 24 * time.Hour,
            MaxLifetime:     30 * 24 * time.Hour,
            ReuseInterval:   5 * time.Minute,
            RotationEnabled: true,
            FamilyEnabled:   true,
            MaxPerUser:      5,
        },
    }

    maker, err := gourdiantoken.NewGourdianTokenMaker(config)
    if err != nil {
        log.Fatalf("Failed to create token maker: %v", err)
    }

    userID := uuid.New()
    username := "john.doe"
    role := "admin"
    sessionID := uuid.New()
    permissions := []string{"read:users", "write:users", "read:reports"}

    accessToken, err := createAccessToken(maker, userID, username, role, sessionID, permissions)
    if err != nil {
        log.Fatalf("Failed to create access token: %v", err)
    }

    refreshToken, err := createRefreshToken(maker, userID, username, sessionID)
    if err != nil {
        log.Fatalf("Failed to create refresh token: %v", err)
    }

    verifyTokens(maker, accessToken.Token, refreshToken.Token)
}
```

### Asymmetric Key Example (RSA)

For asymmetric key signing (RSA), you need to generate an RSA key pair. You can use the **Sigil** tool to simplify this process.

#### Generating RSA Keys with Sigil

1. Install Sigil (if not already installed):

   ```bash
   curl -fsSL https://raw.githubusercontent.com/gourdian25/sigil/master/install.sh | sh
   ```

2. Generate RSA keys:

   ```bash
   sigil
   ```

   - Select **JWT RSA Keys**.
   - Choose the directory to store the keys (default: `keys`).
   - Select the key size (2048, 3072, or 4096 bits).
   - Sigil will generate:
     - A private key (`rsa_private.pem`).
     - A public key (`rsa_public.pem`).

3. Use the generated keys in your GourdianToken configuration:

   ```go
   config := gourdiantoken.GourdianTokenConfig{
       Algorithm:      "RS256",
       SigningMethod:  gourdiantoken.Asymmetric,
       PrivateKeyPath: "keys/rsa_private.pem", // Path to the private key generated by Sigil
       PublicKeyPath:  "keys/rsa_public.pem",  // Path to the public key generated by Sigil
       AccessToken: gourdiantoken.AccessTokenConfig{
           Duration:          15 * time.Minute,
           MaxLifetime:       24 * time.Hour,
           Issuer:            "gourdian-example-app",
           Audience:          []string{"web", "mobile"},
           AllowedAlgorithms: []string{"RS256"},
           RequiredClaims:    []string{"sub", "exp", "jti"},
       },
       RefreshToken: gourdiantoken.RefreshTokenConfig{
           Duration:        7 * 24 * time.Hour,
           MaxLifetime:     30 * 24 * time.Hour,
           ReuseInterval:   5 * time.Minute,
           RotationEnabled: true,
           FamilyEnabled:   true,
           MaxPerUser:      5,
       },
   }
   ```

4. Create and verify tokens as usual.

```go
func asymmetricExample() {
    fmt.Println("=== Asymmetric Key Example (RSA) ===")

    config := gourdiantoken.GourdianTokenConfig{
        Algorithm:      "RS256",
        SigningMethod:  gourdiantoken.Asymmetric,
        PrivateKeyPath: "keys/rsa_private.pem",
        PublicKeyPath:  "keys/rsa_public.pem",
        AccessToken: gourdiantoken.AccessTokenConfig{
            Duration:          15 * time.Minute,
            MaxLifetime:       24 * time.Hour,
            Issuer:            "gourdian-example-app",
            Audience:          []string{"web", "mobile"},
            AllowedAlgorithms: []string{"RS256"},
            RequiredClaims:    []string{"sub", "exp", "jti"},
        },
        RefreshToken: gourdiantoken.RefreshTokenConfig{
            Duration:        7 * 24 * time.Hour,
            MaxLifetime:     30 * 24 * time.Hour,
            ReuseInterval:   5 * time.Minute,
            RotationEnabled: true,
            FamilyEnabled:   true,
            MaxPerUser:      5,
        },
    }

    maker, err := gourdiantoken.NewGourdianTokenMaker(config)
    if err != nil {
        log.Fatalf("Failed to create token maker: %v", err)
    }

    userID := uuid.New()
    username := "jane.doe"
    role := "manager"
    sessionID := uuid.New()
    permissions := []string{"read:users", "read:reports"}

    accessToken, err := createAccessToken(maker, userID, username, role, sessionID, permissions)
    if err != nil {
        log.Fatalf("Failed to create access token: %v", err)
    }

    refreshToken, err := createRefreshToken(maker, userID, username, sessionID)
    if err != nil {
        log.Fatalf("Failed to create refresh token: %v", err)
    }

    verifyTokens(maker, accessToken.Token, refreshToken.Token)
}

```

---

## Performance and Reliability

GourdianToken has been rigorously tested to ensure reliability and security. The test suite covers edge cases, security scenarios, and token rotation scenarios.

### Test Coverage

The package includes comprehensive tests that verify:

- Token creation and verification for all supported algorithms
- Error handling for invalid tokens and configurations
- Token rotation and refresh scenarios
- Security edge cases (algorithm confusion attacks, tampered tokens)
- Claim validation and required fields
- Concurrent token operations

```text
Test Summary:
- 100% test coverage of core functionality
- 58 individual test cases covering all critical paths
- Special focus on security scenarios and edge cases
- Average test execution time: <0.5s for most cases
```

Key test scenarios include:

- Algorithm confusion attack prevention
- Token rotation with concurrent access
- Invalid key and token handling
- Claim validation for required fields
- Token expiration and reuse interval enforcement

### Benchmark Results

GourdianToken has been optimized for performance across different signing algorithms. Below are benchmark results from an Intel i5-9300H processor:

#### Token Creation Performance

```text
Algorithm         | Operations/sec | Time per op | Memory | Allocations
------------------|----------------|-------------|--------|------------
HMAC-SHA256       | 640,110 ops/s  | 8001 ns/op  | 4.4 KB | 57 allocs
RSA-2048          | 3,970 ops/s    | 1.39 ms/op  | 5.5 KB | 55 allocs
ECDSA-P256        | 124,036 ops/s  | 47.2 μs/op  | 10.9KB | 125 allocs
```

#### Token Verification Performance

```text
Algorithm         | Operations/sec | Time per op | Memory | Allocations
------------------|----------------|-------------|--------|------------
HMAC-SHA256       | 649,098 ops/s  | 9599 ns/op  | 3.6 KB | 70 allocs
RSA-2048          | 121,322 ops/s  | 50.4 μs/op  | 4.9 KB | 75 allocs
ECDSA-P256        | 70,472 ops/s   | 97.6 μs/op  | 4.5 KB | 90 allocs
```

#### Advanced Scenarios

```text
Scenario                     | Operations/sec | Time per op
-----------------------------|----------------|-------------
Token Rotation               | 3,396 ops/s    | 1.75 ms/op
Concurrent Token Creation    | 1M ops/s       | 5.7 μs/op
Large Token Verification     | 624,260 ops/s  | 8.3 μs/op
```

### Performance Conclusions

1. **HMAC (Symmetric) Operations** are extremely fast, making them ideal for high-throughput applications where both parties can securely share a key.

2. **Asymmetric Operations** show expected performance characteristics:
   - RSA-2048 verification is about 5x slower than HMAC
   - ECDSA offers a good balance between security and performance
   - Larger key sizes (RSA-4096) have significant performance impact

3. **Token Rotation** adds about 1.7ms overhead per operation due to Redis coordination.

4. **Concurrent Performance** demonstrates excellent scalability under load, with HMAC operations capable of over 1 million tokens per second.

These results demonstrate that GourdianToken is suitable for both high-performance applications (using HMAC) and security-sensitive applications (using RSA/ECDSA), with predictable performance characteristics across all supported algorithms.

## Implementation Recommendations

For most applications:

- Use **HMAC-SHA256** for internal services where key distribution is manageable
- Use **ECDSA-P256** for public-facing APIs where verification speed matters
- Use **RSA-2048** when compatibility with older systems is required
- Reserve **RSA-4096** for extremely sensitive applications where long-term security is critical

The benchmark results show that GourdianToken delivers enterprise-grade performance while maintaining rigorous security standards.

---

## Supported Key Formats

- **RSA**: PKCS#1 and PKCS#8 private keys, PKIX public keys
- **RSA-PSS**: Keys generated via OpenSSL with PSS parameters
- **EdDSA**: Ed25519 keys in PKCS#8 format
- **ECDSA**: P-256, P-384, P-521 curves

## Contributing

We welcome contributions! Please see our [CONTRIBUTING.md](CONTRIBUTING.md) for more details on how to get started.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [golang-jwt/jwt](https://github.com/golang-jwt/jwt) for the JWT library.
- [google/uuid](https://github.com/google/uuid) for UUID generation.
- [Sigil](https://github.com/gourdian25/sigil) for simplifying RSA key generation.

---

For more detailed documentation, please refer to the [GoDoc](https://pkg.go.dev/github.com/gourdian25/gourdiantoken).

---

## Support

If you encounter any issues or have questions, please open an issue on the [GitHub repository](https://github.com/gourdian25/gourdiantoken/issues).

---

## Author

Sigil is developed and maintained by [gourdian25](https://github.com/gourdian25) and [lordofthemind](https://github.com/lordofthemind).

---

Thank you for using gourdiantoken! 🚀.
