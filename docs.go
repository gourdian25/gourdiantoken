// File: docs.go

// Package gourdiantoken provides a production-ready JWT token management system
// with comprehensive security features, flexible storage backends, and support for
// multiple cryptographic algorithms.
//
// # Overview
//
// gourdiantoken implements the lifecycle of three JWT token types (access,
// refresh, and verification): creation, verification, revocation, and (for
// refresh tokens) rotation. It supports symmetric (HMAC) and asymmetric (RSA,
// RSA-PSS, ECDSA, EdDSA) signing, four pluggable storage backends for
// revocation/rotation tracking, and automatic background cleanup of expired
// entries.
//
// This documentation covers API-level behavior, invariants, and pitfalls. For
// installation instructions, a runnable quick-start, a full field-by-field
// GourdianTokenConfig reference (including how each field maps onto
// NewGourdianTokenConfig's positional arguments), framework integration
// examples, and current benchmark numbers, see the module's README:
// https://github.com/gourdian25/gourdiantoken#readme.
//
// # Token Types
//
// AccessToken: short-lived (default 30m), carries the "rls" (roles) claim,
// used for API authorization and sent in the Authorization header.
//
// RefreshToken: long-lived (default 7d), used only to obtain new access
// tokens. Carries no roles claim. Should be stored securely (httpOnly cookie
// recommended) and, in production, rotated on every use.
//
// VerificationToken: short-lived, single-use, use-case-scoped tokens for a
// gap between two authentication steps (e.g. a 2FA-pending step between
// password check and full session issuance, or a password-reset/email-verify
// link). Unlike the other two types, its lifetime is a per-call parameter
// (CreateVerificationToken's ttl argument), not fixed solely by
// configuration. Requires GourdianTokenConfig.VerificationTokensEnabled and is
// exposed via the optional GourdianTokenMakerVerification interface (see
// below), not the base GourdianTokenMaker interface. Single-use enforcement
// piggybacks on the same revocation machinery used for access/refresh tokens:
// MarkVerificationTokenUsed revokes the token, and VerifyVerificationToken's
// existing revocation check is what then rejects a second verification
// attempt, wrapping ErrTokenAlreadyUsed (a plain alias of ErrTokenRevoked).
// This additionally requires RevocationEnabled plus a TokenRepository.
//
// All three claim types carry the standard JWT claims (jti, iss, aud, sub,
// iat, exp, nbf) plus a gourdiantoken-specific "mle" (max lifetime expiry)
// claim: an absolute ceiling that access/refresh rotation cannot push past.
// For verification tokens mle always equals exp, since they are never
// renewed.
//
// # Cryptographic Algorithms
//
// Symmetric (HMAC, via SymmetricKey): HS256, HS384, HS512.
//
// Asymmetric (via PrivateKeyPath/PublicKeyPath PEM files): RS256/RS384/RS512
// (RSA PKCS#1 v1.5), PS256/PS384/PS512 (RSA-PSS, preferred over RS* for new
// systems), ES256/ES384/ES512 (ECDSA P-256/P-384/P-521), EdDSA (Ed25519).
//
// SigningMethod (Symmetric or Asymmetric) must be consistent with Algorithm;
// mismatches are rejected during construction, as is the JWT "none"
// algorithm.
//
// # Storage Backends
//
// TokenRepository is the interface implemented by every storage backend; all
// four live as files in the root package (there are no storage subpackages):
//
//   - MemoryTokenRepository: in-process, sync.RWMutex-guarded map with a
//     background cleanup goroutine. No persistence; single-instance only.
//   - RedisTokenRepository: TTL-based keys, gourdiantoken:-prefixed, safe for
//     Redis Cluster/Sentinel deployments.
//   - PostgresTokenRepository: pgx/v5 driver with sqlc-generated queries (no
//     ORM); schema DDL is idempotent (CREATE TABLE/INDEX IF NOT EXISTS) and
//     serialized by a Postgres advisory lock. The caller builds and owns the
//     *pgxpool.Pool.
//   - MongoTokenRepository: document storage with TTL indexes for cleanup and
//     optional multi-document transactions (requires a replica set).
//
// Each has a concrete Close() (idempotent; Mongo's takes a context.Context)
// that is not part of the TokenRepository interface itself.
//
// # Configuration
//
// GourdianTokenConfig holds every signing, claims, lifetime, and
// feature-flag setting; nearly all behavior is driven by it, validated
// once at maker construction time by validateConfig.
//
// Two constructors build a GourdianTokenConfig:
//
//   - DefaultGourdianTokenConfig(symmetricKey): secure HS256 defaults,
//     customizable afterward via field assignment. The recommended starting
//     point.
//   - NewGourdianTokenConfig(...17 positional arguments...): full explicit
//     control. Deprecated: the fixed positional-argument list cannot express
//     the newer Verification* fields (they're left at their zero values), and
//     the argument order is easy to get wrong. Prefer
//     DefaultGourdianTokenConfig plus struct-literal field assignment, or a
//     bare GourdianTokenConfig{...} literal, instead. See the README's
//     Configuration table for the full field list and, for existing callers
//     of NewGourdianTokenConfig, exactly which positional slot each field
//     occupies.
//
// # Factory Methods
//
// NewGourdianTokenMaker(ctx, config, tokenRepo, opts...) is the underlying
// constructor; tokenRepo may be nil only if both RotationEnabled and
// RevocationEnabled are false (construction fails otherwise, wrapping
// ErrTokenRepositoryRequired). The following convenience constructors wire a
// JWTMaker to a specific TokenRepository so callers don't need to construct
// one by hand:
//
//   - NewGourdianTokenMakerNoStorage(ctx, config, opts...): stateless: no
//     repository at all; RotationEnabled/RevocationEnabled must both be
//     false.
//   - NewGourdianTokenMakerWithMemory(ctx, config, opts...)
//   - NewGourdianTokenMakerWithRedis(ctx, config, *redis.Client, opts...)
//   - NewGourdianTokenMakerWithPostgres(ctx, config, *pgxpool.Pool, opts...)
//   - NewGourdianTokenMakerWithMongo(ctx, config, *mongo.Database,
//     transactionsEnabled bool, opts...)
//
// DefaultGourdianTokenMaker is a further shorthand over
// NewGourdianTokenMakerWithMemory for the simplest possible setup.
//
// # Functional Options
//
// Option (type Option func(*JWTMaker)) configures optional JWTMaker behavior
// at construction time. There are two logging-related options:
//
// WithLogger(logf func(format string, args ...any)) Option is the
// original hook, predating the rest of the ecosystem's logging convention.
// It redirects error reports from the background cleanup goroutines away
// from the default fmt.Printf-based logger. logf is a bare printf-style
// callback.
//
// WithStructuredLogger(logger Logger) Option is additive: Logger
// (Debug/Info/Warn/Error(msg string, args ...any)) matches *slog.Logger's
// own signatures exactly — the same shape grcache/grevents/graudit/grpolicy/
// grnoti's own Logger interfaces use — so *slog.Logger, including one
// backed by grlog via slog.New(grlog.NewSlogHandler(...)), satisfies it
// with no adapter. When set, it is used instead of logf for the same two
// background-cleanup error reports; when unset, logf's existing behavior
// is completely unchanged.
//
// # Thread Safety and Context Handling
//
// JWTMaker (the concrete GourdianTokenMaker/GourdianTokenMakerCloser
// implementation) is immutable after construction — config, keys, and the
// signing method are never mutated post-init — so every method is safe for
// concurrent use by multiple goroutines without any additional locking on
// the caller's part. The only mutable internal state is closeOnce
// (sync.Once), making Close idempotent.
//
// Repository implementations are independently safe for concurrent use:
// MemoryTokenRepository guards its map with a sync.RWMutex (concurrent
// readers, exclusive writers); the Redis/Postgres/Mongo implementations
// delegate to their respective client libraries (*redis.Client,
// *pgxpool.Pool, *mongo.Database), which are themselves safe for concurrent
// use across goroutines.
//
// All GourdianTokenMaker and TokenRepository methods accept a
// context.Context and check for cancellation, so callers can bound any
// operation with context.WithTimeout/WithCancel in the usual way.
//
// # Error Handling
//
// gourdiantoken.errors.go exports sentinel errors for use with errors.Is;
// wrapped messages keep their original text ahead of the sentinel (e.g.
// "token has been revoked: %w"), so pre-existing string-matching callers
// keep working:
//
//   - ErrTokenRevoked, ErrTokenRotated: explicit revocation / reuse-after-
//     rotation.
//   - ErrTokenAlreadyUsed: alias of ErrTokenRevoked, returned by
//     VerifyVerificationToken after MarkVerificationTokenUsed.
//   - ErrTokenExpired, ErrInvalidSignature: aliases of the corresponding
//     golang-jwt/jwt/v5 sentinels, re-exported so callers only need to import
//     gourdiantoken.
//   - ErrInvalidToken, ErrInvalidClaims: structural/parsing failures.
//   - ErrTokenRepositoryRequired: RotationEnabled or RevocationEnabled set
//     without a TokenRepository.
//   - ErrMissingExpClaim: a token being revoked has no "exp" claim, so its
//     repository TTL cannot be computed.
//   - ErrTokenMaxLifetimeExceeded: the "mle" claim has passed.
//
// These sentinels are intentionally not prefixed with a package name (unlike
// the "pkgname: message" convention elsewhere in the gourdian25 ecosystem) —
// a grandfathered exception kept for backward compatibility.
//
// # Security Considerations
//
// Symmetric keys must be at least 32 bytes; generate them with a
// cryptographically secure random source and never commit them to version
// control. Private key files are checked for permissive file-mode bits
// (0600 recommended) during initialization. AllowedAlgorithms lets callers
// pin verification to a whitelist, preventing algorithm-confusion attacks
// independent of what Algorithm a given token claims to use.
//
// For new systems, prefer EdDSA (fastest, side-channel resistant) or ES256
// (efficient, broadly supported) over RS*/PS*; use PS* over RS* if RSA is
// required for compatibility. Enable both RotationEnabled and
// RevocationEnabled in production: rotation limits the blast radius of a
// stolen refresh token and surfaces reuse as a signal, while revocation
// makes logout and incident response effective before natural expiry.
//
// # Common Pitfalls
//
//   - Calling jwt.Parse directly instead of VerifyAccessToken/
//     VerifyRefreshToken/VerifyVerificationToken bypasses every check this
//     package performs (revocation, rotation, mle, required claims, type).
//     Always go through the Verify* methods.
//   - RotationEnabled or RevocationEnabled set to true with no
//     TokenRepository (or with NewGourdianTokenMakerNoStorage) fails
//     construction with ErrTokenRepositoryRequired — either disable the flag
//     or supply a repository.
//   - A symmetric key under 32 bytes fails validateConfig; generate a proper
//     random key rather than shortening the requirement.
//   - Forgetting to call Close() (via the GourdianTokenMakerCloser optional
//     interface) on process shutdown leaks the background cleanup
//     goroutine(s) for the remaining process lifetime — harmless for
//     short-lived test binaries but worth doing in long-running services.
//   - MarkVerificationTokenUsed requires RevocationEnabled plus a
//     TokenRepository even when VerificationTokensEnabled is true; without
//     them it returns an explicit error rather than silently no-op'ing.
//
// # Testing
//
// The package's own test suite runs the same table-driven tests against all
// four TokenRepository backends; the Redis/Postgres/Mongo variants Skipf
// when their backing service isn't reachable rather than failing the run.
// Application code depending on gourdiantoken typically only needs
// NewGourdianTokenMakerWithMemory (or NoStorage) in tests — see the README's
// Testing section for command-line invocations and a worked example.
//
// # Version Compatibility
//
// Go 1.26.4+ (matches this module's go.mod). Direct dependencies:
// github.com/golang-jwt/jwt/v5 (JWT implementation), github.com/google/uuid
// (internal token ID / "jti" generation only — callers passing their own
// string identifiers do not need to import it). Optional, only required by
// the storage backend actually used: github.com/jackc/pgx/v5 (Postgres),
// go.mongodb.org/mongo-driver (MongoDB), github.com/redis/go-redis/v9
// (Redis).
package gourdiantoken
