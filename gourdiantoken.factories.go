// File: gourdiantoken.factories.go


package gourdiantoken

import (
	"context"
	"fmt"

	"github.com/redis/go-redis/v9"
	"go.mongodb.org/mongo-driver/mongo"
	"gorm.io/gorm"
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
//	    PrivateKeyPath: "/keys/private.pem",
//	    PublicKeyPath: "/keys/public.pem",
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
func NewGourdianTokenMakerNoStorage(ctx context.Context, config GourdianTokenConfig) (GourdianTokenMaker, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context canceled: %w", err)
	}

	// Ensure revocation and rotation are disabled for stateless operation
	if config.RevocationEnabled || config.RotationEnabled {
		return nil, fmt.Errorf("revocation and rotation must be disabled for stateless token maker")
	}

	return NewGourdianTokenMaker(ctx, config, nil)
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
func NewGourdianTokenMakerWithMemory(ctx context.Context, config GourdianTokenConfig) (GourdianTokenMaker, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context canceled: %w", err)
	}

	// Create in-memory repository with default cleanup interval from config
	tokenRepo := NewMemoryTokenRepository(config.CleanupInterval)

	return NewGourdianTokenMaker(ctx, config, tokenRepo)
}

// NewGourdianTokenMakerWithGorm creates a GourdianTokenMaker with a GORM-based token repository.
// This supports any database that GORM supports (PostgreSQL, MySQL, SQLite, etc.).
// Suitable for production deployments with persistent token revocation and rotation tracking.
//
// Use Cases:
//   - Production applications with existing SQL databases
//   - Applications requiring ACID compliance for token operations
//   - Systems with complex relational data models
//   - Environments where SQL expertise exists
//   - Applications requiring complex queries for token analytics
//
// Supported Databases:
//   - PostgreSQL (recommended for production)
//   - MySQL/MariaDB
//   - SQLite (development only)
//   - SQL Server
//   - CockroachDB
//
// Performance Characteristics:
//   - Good read/write performance with proper indexing
//   - Network latency to database
//   - Supports connection pooling
//   - Transaction support for data consistency
//
// Setup Requirements:
//   - Database migrations run automatically
//   - Proper indexes created for performance
//   - Database connection pooling configured
//   - Regular maintenance (vacuum/optimize) for SQL databases
//
// Parameters:
//   - ctx: Context for initialization (cancellation, timeout support)
//   - config: Configuration for the token maker
//   - db: Initialized GORM database instance with connection to target database
//
// Returns:
//   - GourdianTokenMaker: A configured token maker instance with GORM storage
//   - error: If database connection fails, migration fails, configuration is invalid,
//     or context is cancelled
//
// Example (PostgreSQL production):
//
//	// Initialize GORM first
//	gormDB, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	config := gourdiantoken.GourdianTokenConfig{
//	    SigningMethod: gourdiantoken.Asymmetric,
//	    Algorithm: "RS256",
//	    PrivateKeyPath: "/app/keys/private.pem",
//	    PublicKeyPath: "/app/keys/public.pem",
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
//	maker, err := gourdiantoken.NewGourdianTokenMakerWithGorm(ctx, config, gormDB)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
// Example (SQLite development):
//
//	gormDB, err := gorm.Open(sqlite.Open("test.db"), &gorm.Config{})
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	config := gourdiantoken.GourdianTokenConfig{
//	    SigningMethod: gourdiantoken.Symmetric,
//	    Algorithm: "HS256",
//	    SymmetricKey: "dev-key-for-sqlite-testing",
//	    Issuer: "dev-auth",
//	    Audience: []string{"dev-api"},
//	    RevocationEnabled: true,
//	    RotationEnabled: true,
//	    AccessExpiryDuration: 1 * time.Hour,
//	    RefreshExpiryDuration: 24 * time.Hour,
//	    CleanupInterval: 6 * time.Hour,
//	}
//
//	maker, err := gourdiantoken.NewGourdianTokenMakerWithGorm(ctx, config, gormDB)
func NewGourdianTokenMakerWithGorm(ctx context.Context, config GourdianTokenConfig, db *gorm.DB) (GourdianTokenMaker, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context canceled: %w", err)
	}

	if db == nil {
		return nil, fmt.Errorf("gorm database instance cannot be nil")
	}

	// Create GORM-based repository
	tokenRepo, err := NewGormTokenRepository(db)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize GORM token repository: %w", err)
	}

	return NewGourdianTokenMaker(ctx, config, tokenRepo)
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
//	    PrivateKeyPath: "/app/keys/private.pem",
//	    PublicKeyPath: "/app/keys/public.pem",
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
func NewGourdianTokenMakerWithMongo(ctx context.Context, config GourdianTokenConfig, mongoDB *mongo.Database) (GourdianTokenMaker, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context canceled: %w", err)
	}

	if mongoDB == nil {
		return nil, fmt.Errorf("mongo database instance cannot be nil")
	}

	// Create MongoDB-based repository with transactions enabled
	tokenRepo, err := NewMongoTokenRepository(mongoDB, true)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize MongoDB token repository: %w", err)
	}

	return NewGourdianTokenMaker(ctx, config, tokenRepo)
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
//	    PrivateKeyPath: "/app/keys/private.pem",
//	    PublicKeyPath: "/app/keys/public.pem",
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
func NewGourdianTokenMakerWithRedis(ctx context.Context, config GourdianTokenConfig, redisClient *redis.Client) (GourdianTokenMaker, error) {
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

	return NewGourdianTokenMaker(ctx, config, tokenRepo)
}
