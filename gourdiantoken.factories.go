// File: gourdiantoken.factories.go

package gourdiantoken

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"go.mongodb.org/mongo-driver/mongo"
)

// NewGourdianTokenMakerNoStorage creates a GourdianTokenMaker without any token storage backend.
// This is suitable for stateless token validation where token revocation and rotation are not needed.
// The token repository will be nil, so RevocationEnabled and RotationEnabled must be false.
//
// Use Cases:
//   - Stateless microservices that only validate tokens
//   - Read-only API services
//   - Systems where all state is in the JWT itself
//   - High-performance scenarios where database lookups are not acceptable
//   - Distributed systems with no shared storage
//
// Limitations:
//   - Cannot revoke tokens before expiration
//   - Cannot rotate refresh tokens
//   - Compromised tokens remain valid until natural expiration
//   - No logout functionality (unless expiry is very short)
//
// Security Implications:
//
//	Without revocation/rotation:
//	- Use shorter token lifetimes (e.g., 15 minutes for access tokens)
//	- Implement complementary security measures (rate limiting, monitoring)
//	- Consider using asymmetric signing for better key distribution
//	- Monitor for suspicious patterns and failed validation attempts
//
// Parameters:
//   - ctx: Context for initialization (cancellation support)
//   - config: Configuration for the token maker. Must have RevocationEnabled and
//     RotationEnabled set to false, otherwise this function returns an error.
//
// Returns:
//   - GourdianTokenMaker: A configured token maker instance without storage backend
//   - error: If configuration is invalid, revocation/rotation is enabled, or context is cancelled
//
// Configuration Requirements:
//   - RevocationEnabled must be false
//   - RotationEnabled must be false
//   - All other configuration options are validated normally
//
// Example (Symmetric signing):
//
//	config := gourdiantoken.GourdianTokenConfig{
//	    SigningMethod: gourdiantoken.Symmetric,
//	    Algorithm: "HS256",
//	    SymmetricKey: "your-secret-key-at-least-32-bytes-long",
//	    Issuer: "auth.example.com",
//	    Audience: []string{"api.example.com"},
//	    RevocationEnabled: false,  // Required for no-storage mode
//	    RotationEnabled: false,    // Required for no-storage mode
//	    AccessExpiryDuration: 15 * time.Minute,  // Shorter for security
//	    RefreshExpiryDuration: 7 * 24 * time.Hour,
//	    CleanupInterval: 6 * time.Hour,
//	}
//
//	maker, err := gourdiantoken.NewGourdianTokenMakerNoStorage(ctx, config)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
// Example (Asymmetric signing for microservices):
//
//	config := gourdiantoken.GourdianTokenConfig{
//	    SigningMethod: gourdiantoken.Asymmetric,
//	    Algorithm: "RS256",
//	    PrivateKeyPEM: privateKeyPEM, // e.g. read from a mounted Secret at startup
//	    PublicKeyPEM: publicKeyPEM,
//	    Issuer: "auth.example.com",
//	    Audience: []string{"api.example.com", "service.example.com"},
//	    RevocationEnabled: false,
//	    RotationEnabled: false,
//	    AccessExpiryDuration: 15 * time.Minute,
//	    AccessMaxLifetimeExpiry: 24 * time.Hour,
//	    RefreshExpiryDuration: 24 * time.Hour,
//	    RefreshMaxLifetimeExpiry: 30 * 24 * time.Hour,
//	}
//
//	maker, err := gourdiantoken.NewGourdianTokenMakerNoStorage(ctx, config)
func NewGourdianTokenMakerNoStorage(ctx context.Context, config GourdianTokenConfig, opts ...Option) (GourdianTokenMaker, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context canceled: %w", err)
	}

	// Ensure revocation and rotation are disabled for stateless operation
	if config.RevocationEnabled || config.RotationEnabled {
		return nil, fmt.Errorf("revocation and rotation must be disabled for stateless token maker")
	}

	return NewGourdianTokenMaker(ctx, config, nil, opts...)
}

// NewGourdianTokenMakerWithMemory creates a GourdianTokenMaker with an in-memory token repository.
// This is suitable for development, testing, or single-instance deployments.
// Token revocation and rotation data are stored in memory and will be lost on restart.
//
// Use Cases:
//   - Development and testing environments
//   - Single-instance applications
//   - Prototyping and proof-of-concept implementations
//   - Applications where token persistence across restarts is not required
//   - Low-security internal applications
//
// Performance Characteristics:
//   - Fastest storage backend (in-memory operations)
//   - No network latency
//   - Memory usage grows with active tokens
//   - Automatic cleanup via config.CleanupInterval
//
// Limitations:
//   - Data lost on application restart
//   - Not suitable for distributed systems
//   - Memory consumption proportional to active tokens
//   - No persistence for audit or compliance requirements
//
// Parameters:
//   - ctx: Context for initialization (cancellation, timeout support)
//   - config: Configuration for the token maker. CleanupInterval determines how often
//     expired tokens are purged from memory.
//
// Returns:
//   - GourdianTokenMaker: A configured token maker instance with in-memory storage
//   - error: If configuration is invalid, context is cancelled, or initialization fails
//
// Example (Development setup):
//
//	config := gourdiantoken.GourdianTokenConfig{
//	    SigningMethod: gourdiantoken.Symmetric,
//	    Algorithm: "HS256",
//	    SymmetricKey: "dev-secret-key-for-testing-only",
//	    Issuer: "dev-auth.local",
//	    Audience: []string{"api.dev.local"},
//	    RevocationEnabled: true,
//	    RotationEnabled: true,
//	    AccessExpiryDuration: 1 * time.Hour,
//	    RefreshExpiryDuration: 24 * time.Hour,
//	    CleanupInterval: 1 * time.Hour, // Clean up every hour
//	}
//
//	maker, err := gourdiantoken.NewGourdianTokenMakerWithMemory(ctx, config)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
// Example (Testing with short cleanup):
//
//	config := gourdiantoken.GourdianTokenConfig{
//	    SigningMethod: gourdiantoken.Symmetric,
//	    Algorithm: "HS256",
//	    SymmetricKey: "test-key",
//	    Issuer: "test",
//	    Audience: []string{"test-api"},
//	    RevocationEnabled: true,
//	    RotationEnabled: false,
//	    AccessExpiryDuration: 15 * time.Minute,
//	    RefreshExpiryDuration: 1 * time.Hour,
//	    CleanupInterval: 5 * time.Minute, // Frequent cleanup for tests
//	}
//
//	maker, err := gourdiantoken.NewGourdianTokenMakerWithMemory(ctx, config)
func NewGourdianTokenMakerWithMemory(ctx context.Context, config GourdianTokenConfig, opts ...Option) (GourdianTokenMaker, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context canceled: %w", err)
	}

	// Create in-memory repository with default cleanup interval from config
	tokenRepo := NewMemoryTokenRepository(config.CleanupInterval)

	return NewGourdianTokenMaker(ctx, config, tokenRepo, opts...)
}

// NewGourdianTokenMakerWithPostgres creates a GourdianTokenMaker with a
// PostgreSQL-based token repository (pgx/v5, sqlc-generated queries).
// Suitable for production deployments with persistent token revocation and
// rotation tracking.
//
// Use Cases:
//   - Production applications with an existing PostgreSQL database
//   - Applications requiring ACID compliance for token operations
//   - Environments where SQL expertise exists
//
// Performance Characteristics:
//   - Good read/write performance with proper indexing (schema ships with
//     composite/expiry indexes out of the box)
//   - Connection pooling via the caller-provided *pgxpool.Pool
//   - No ORM overhead — hand-written queries via sqlc
//
// Setup Requirements:
//   - Schema is applied automatically (CREATE TABLE/INDEX IF NOT EXISTS),
//     serialized by a Postgres advisory lock so concurrent callers building
//     a repository against the same fresh database don't race on the DDL
//   - The caller builds and owns the *pgxpool.Pool — share one pool across
//     your backend instead of each store opening its own; see
//     docs/postgres.md for the recommended pattern
//
// Parameters:
//   - ctx: Context for initialization (cancellation, timeout support)
//   - config: Configuration for the token maker
//   - pool: An already-constructed *pgxpool.Pool connected to PostgreSQL
//
// Returns:
//   - GourdianTokenMaker: A configured token maker instance with Postgres storage
//   - error: If the connectivity check fails, schema application fails,
//     configuration is invalid, or context is cancelled
//
// Example:
//
//	pool, err := pgxpool.New(ctx, dsn)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer pool.Close()
//
//	config := gourdiantoken.GourdianTokenConfig{
//	    SigningMethod: gourdiantoken.Asymmetric,
//	    Algorithm: "RS256",
//	    PrivateKeyPEM: privateKeyPEM, // e.g. read from a mounted Secret at startup
//	    PublicKeyPEM: publicKeyPEM,
//	    Issuer: "auth.production.com",
//	    Audience: []string{"api.production.com", "admin.production.com"},
//	    RevocationEnabled: true,
//	    RotationEnabled: true,
//	    AccessExpiryDuration: 15 * time.Minute,
//	    AccessMaxLifetimeExpiry: 24 * time.Hour,
//	    RefreshExpiryDuration: 7 * 24 * time.Hour,
//	    RefreshMaxLifetimeExpiry: 30 * 24 * time.Hour,
//	    CleanupInterval: 24 * time.Hour,
//	}
//
//	maker, err := gourdiantoken.NewGourdianTokenMakerWithPostgres(ctx, config, pool)
//	if err != nil {
//	    log.Fatal(err)
//	}
func NewGourdianTokenMakerWithPostgres(ctx context.Context, config GourdianTokenConfig, pool *pgxpool.Pool, opts ...Option) (GourdianTokenMaker, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context canceled: %w", err)
	}

	if pool == nil {
		return nil, fmt.Errorf("pgx pool cannot be nil")
	}

	tokenRepo, err := NewPostgresTokenRepository(ctx, pool)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize Postgres token repository: %w", err)
	}

	return NewGourdianTokenMaker(ctx, config, tokenRepo, opts...)
}

// NewGourdianTokenMakerWithMongo creates a GourdianTokenMaker with a MongoDB-based token repository.
// Suitable for production deployments using MongoDB for persistent token tracking.
// Transactions are enabled by default for consistency.
//
// Use Cases:
//   - Production applications using MongoDB as primary database
//   - Document-oriented architectures
//   - High-write throughput scenarios
//   - Systems requiring horizontal scaling
//   - Applications with flexible schema requirements
//
// Performance Characteristics:
//   - Excellent write performance
//   - Automatic sharding support
//   - TTL index for automatic token expiration
//   - Document-level atomic operations
//   - Built-in replication for high availability
//
// Setup Requirements:
//   - MongoDB 4.0+ for transaction support (recommended 4.2+)
//   - TTL indexes created automatically
//   - Proper replica set configuration for production
//   - Connection string with appropriate read/write concerns
//
// Parameters:
//   - ctx: Context for initialization (cancellation, timeout support)
//   - config: Configuration for the token maker
//   - mongoDB: Initialized MongoDB database instance from the official Mongo driver
//
// Returns:
//   - GourdianTokenMaker: A configured token maker instance with MongoDB storage
//   - error: If MongoDB connection fails, index creation fails, configuration is invalid,
//     or context is cancelled
//
// Example (Production with transactions):
//
//	// Initialize MongoDB client first
//	client, err := mongo.Connect(ctx, options.Client().ApplyURI(mongoURI))
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	mongoDB := client.Database("auth_service")
//
//	config := gourdiantoken.GourdianTokenConfig{
//	    SigningMethod: gourdiantoken.Asymmetric,
//	    Algorithm: "RS256",
//	    PrivateKeyPEM: privateKeyPEM, // e.g. read from a mounted Secret at startup
//	    PublicKeyPEM: publicKeyPEM,
//	    Issuer: "auth.mongodb.example.com",
//	    Audience: []string{"api.mongodb.example.com"},
//	    RevocationEnabled: true,
//	    RotationEnabled: true,
//	    AccessExpiryDuration: 15 * time.Minute,
//	    AccessMaxLifetimeExpiry: 24 * time.Hour,
//	    RefreshExpiryDuration: 7 * 24 * time.Hour,
//	    RefreshMaxLifetimeExpiry: 30 * 24 * time.Hour,
//	    CleanupInterval: 24 * time.Hour,
//	}
//
//	maker, err := gourdiantoken.NewGourdianTokenMakerWithMongo(ctx, config, mongoDB)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
// Example (Development without replica set):
//
//	// For development without replica set, transactions may be limited
//	client, err := mongo.Connect(ctx, options.Client().ApplyURI("mongodb://localhost:27017"))
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	mongoDB := client.Database("dev_auth")
//
//	config := gourdiantoken.GourdianTokenConfig{
//	    SigningMethod: gourdiantoken.Symmetric,
//	    Algorithm: "HS256",
//	    SymmetricKey: "mongo-dev-key-32-bytes-long-here",
//	    Issuer: "dev-mongo-auth",
//	    Audience: []string{"dev-api"},
//	    RevocationEnabled: true,
//	    RotationEnabled: true,
//	    AccessExpiryDuration: 1 * time.Hour,
//	    RefreshExpiryDuration: 24 * time.Hour,
//	    CleanupInterval: 12 * time.Hour,
//	}
//
//	maker, err := gourdiantoken.NewGourdianTokenMakerWithMongo(ctx, config, mongoDB)
//
// Matches the (ctx, config, handle) shape shared by the other backend factories:
// transactions are always enabled (hardcoded true, per this factory's own long-standing
// "enabled by default for consistency" doc-comment claim above) rather than being a caller
// -supplied bool. Callers who need transactions disabled (e.g. a standalone dev MongoDB
// without a replica set) should call NewMongoTokenRepository(db, false) directly and pass
// the result to NewGourdianTokenMaker themselves.
func NewGourdianTokenMakerWithMongo(ctx context.Context, config GourdianTokenConfig, mongoDB *mongo.Database, opts ...Option) (GourdianTokenMaker, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context canceled: %w", err)
	}

	if mongoDB == nil {
		return nil, fmt.Errorf("mongo database instance cannot be nil")
	}

	tokenRepo, err := NewMongoTokenRepository(mongoDB, true)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize MongoDB token repository: %w", err)
	}

	return NewGourdianTokenMaker(ctx, config, tokenRepo, opts...)
}

// NewGourdianTokenMakerWithRedis creates a GourdianTokenMaker with a Redis-based token repository.
// Suitable for high-performance production deployments with Redis as the token store.
// Redis automatically handles TTL-based key expiration.
//
// Use Cases:
//   - High-performance authentication systems
//   - Microservices architectures
//   - Distributed systems with shared token state
//   - Applications requiring sub-millisecond token validation
//   - Systems with high token revocation rates
//
// Performance Characteristics:
//   - Sub-millisecond read/write operations
//   - Built-in TTL expiration
//   - In-memory performance with optional persistence
//   - Horizontal scaling via Redis Cluster
//   - Lua scripting for complex atomic operations
//
// Redis Features Utilized:
//   - TTL (Time To Live) for automatic token expiration
//   - SETNX for atomic token creation
//   - Pipeline for batch operations
//   - Lua scripts for complex atomic operations
//   - Optional persistence (AOF/RDB) for durability
//
// Setup Requirements:
//   - Redis 6.0+ recommended (for ACLs and improved Lua scripting)
//   - Proper memory configuration (maxmemory policy)
//   - Persistence configuration if token durability required
//   - Redis Sentinel or Cluster for high availability
//
// Parameters:
//   - ctx: Context for initialization (cancellation, timeout support)
//   - config: Configuration for the token maker
//   - redisClient: Initialized Redis client from go-redis library
//
// Returns:
//   - GourdianTokenMaker: A configured token maker instance with Redis storage
//   - error: If Redis connection fails, configuration is invalid, or context is cancelled
//
// Example (Production with Redis Cluster):
//
//	// Initialize Redis client
//	redisClient := redis.NewClusterClient(&redis.ClusterOptions{
//	    Addrs: []string{"redis-node1:6379", "redis-node2:6379", "redis-node3:6379"},
//	    Password: "your-redis-password",
//	    PoolSize: 100,
//	})
//
//	config := gourdiantoken.GourdianTokenConfig{
//	    SigningMethod: gourdiantoken.Asymmetric,
//	    Algorithm: "RS256",
//	    PrivateKeyPEM: privateKeyPEM, // e.g. read from a mounted Secret at startup
//	    PublicKeyPEM: publicKeyPEM,
//	    Issuer: "auth.redis.example.com",
//	    Audience: []string{"api.redis.example.com", "gateway.redis.example.com"},
//	    RevocationEnabled: true,
//	    RotationEnabled: true,
//	    AccessExpiryDuration: 15 * time.Minute,
//	    AccessMaxLifetimeExpiry: 24 * time.Hour,
//	    RefreshExpiryDuration: 7 * 24 * time.Hour,
//	    RefreshMaxLifetimeExpiry: 30 * 24 * time.Hour,
//	    CleanupInterval: 24 * time.Hour, // Less critical with Redis TTL
//	}
//
//	maker, err := gourdiantoken.NewGourdianTokenMakerWithRedis(ctx, config, redisClient)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
// Example (Single Redis instance for development):
//
//	redisClient := redis.NewClient(&redis.Options{
//	    Addr: "localhost:6379",
//	    Password: "", // no password set
//	    DB: 0,        // use default DB
//	})
//
//	config := gourdiantoken.GourdianTokenConfig{
//	    SigningMethod: gourdiantoken.Symmetric,
//	    Algorithm: "HS256",
//	    SymmetricKey: "redis-dev-key-32-bytes-minimum",
//	    Issuer: "dev-redis-auth",
//	    Audience: []string{"dev-api"},
//	    RevocationEnabled: true,
//	    RotationEnabled: true,
//	    AccessExpiryDuration: 30 * time.Minute,
//	    RefreshExpiryDuration: 24 * time.Hour,
//	    CleanupInterval: 6 * time.Hour,
//	}
//
//	maker, err := gourdiantoken.NewGourdianTokenMakerWithRedis(ctx, config, redisClient)
func NewGourdianTokenMakerWithRedis(ctx context.Context, config GourdianTokenConfig, redisClient *redis.Client, opts ...Option) (GourdianTokenMaker, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context canceled: %w", err)
	}

	if redisClient == nil {
		return nil, fmt.Errorf("redis client cannot be nil")
	}

	// Create Redis-based repository
	tokenRepo, err := NewRedisTokenRepository(redisClient)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize Redis token repository: %w", err)
	}

	return NewGourdianTokenMaker(ctx, config, tokenRepo, opts...)
}
