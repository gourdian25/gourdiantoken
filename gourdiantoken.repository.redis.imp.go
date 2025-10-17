// File: gourdiantoken.repository.redis.imp.go


package gourdiantoken

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	revokedAccessPrefix  = "revoked:access:"
	revokedRefreshPrefix = "revoked:refresh:"
	rotatedPrefix        = "rotated:"

	// Minimum TTL to avoid Redis timing issues
	// Redis has millisecond precision but very short TTLs can cause race conditions
	minRedisTTL = 100 * time.Millisecond
)

// RedisTokenRepository implements TokenRepository using Redis.
// This repository provides high-performance in-memory storage for token revocation and rotation data.
//
// Architecture Features:
//   - Key-value storage with TTL-based expiration
//   - Atomic operations using Redis commands
//   - Pipeline support for batch operations
//   - Automatic key expiration via Redis TTL
//   - Connection pooling via Redis client
//
// Performance Characteristics:
//   - Sub-millisecond read/write operations
//   - O(1) average case for all operations
//   - In-memory performance with optional persistence
//   - Horizontal scaling via Redis Cluster
//
// Redis Features Utilized:
//   - SET with EX/PX for TTL-based expiration
//   - SETNX for atomic insert-if-not-exists
//   - GET for fast lookups
//   - PTTL for precise TTL checking
//   - SCAN for efficient key enumeration
//   - Pipeline for batch operations
//
// Memory Usage Considerations:
//   - Each key consumes memory based on prefix + hash (typically ~100 bytes)
//   - TTL ensures automatic memory reclamation
//   - Redis compression can reduce memory usage
//   - Consider maxmemory policy for production
type RedisTokenRepository struct {
	client *redis.Client
}

// NewRedisTokenRepository creates a new Redis-based token repository.
// Performs connection testing and client validation.
//
// Prerequisites:
//   - Redis client must be properly initialized and configured
//   - Network connectivity to Redis server/cluster
//   - Sufficient memory allocation in Redis
//   - Proper maxmemory policy configuration
//
// Initialization Steps:
//  1. Validate Redis client is not nil
//  2. Test Redis connectivity with 5-second timeout
//  3. Return initialized repository instance
//
// Parameters:
//   - client: Initialized Redis client from go-redis library
//
// Returns:
//   - TokenRepository: Initialized Redis repository instance
//   - error: If connection fails or client is nil
//
// Example (Redis standalone):
//
//	client := redis.NewClient(&redis.Options{
//	    Addr:     "localhost:6379",
//	    Password: "", // no password
//	    DB:       0,  // default DB
//	    PoolSize: 100,
//	})
//
//	repo, err := NewRedisTokenRepository(client)
//	if err != nil {
//	    return fmt.Errorf("failed to create Redis token repository: %w", err)
//	}
//
// Example (Redis Cluster):
//
//	client := redis.NewClusterClient(&redis.ClusterOptions{
//	    Addrs:    []string{"redis-node1:6379", "redis-node2:6379", "redis-node3:6379"},
//	    Password: "your-redis-password",
//	    PoolSize: 100,
//	})
//
//	repo, err := NewRedisTokenRepository(client)
//	if err != nil {
//	    return fmt.Errorf("failed to create Redis token repository: %w", err)
//	}
//
// Production Considerations:
//   - Configure connection pooling appropriately
//   - Set up Redis persistence if data durability required
//   - Implement Redis monitoring and alerting
//   - Consider Redis Sentinel for high availability
//   - Use Redis Cluster for horizontal scaling
func NewRedisTokenRepository(client *redis.Client) (TokenRepository, error) {
	if client == nil {
		return nil, fmt.Errorf("redis client cannot be nil")
	}

	// Test the connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if _, err := client.Ping(ctx).Result(); err != nil {
		return nil, fmt.Errorf("redis connection failed: %w", err)
	}

	return &RedisTokenRepository{
		client: client,
	}, nil
}

// MarkTokenRevoke marks a token as revoked by storing its hash in Redis.
// Uses key with TTL for automatic expiration and pipeline for atomic operation.
//
// Redis Operation:
//   - SET key value EX seconds
//   - Key format: "revoked:access:{hash}" or "revoked:refresh:{hash}"
//   - Value: "1" (simple marker)
//   - TTL: Automatic expiration after specified duration
//
// Performance Characteristics:
//   - Single SET operation with TTL
//   - O(1) time complexity
//   - Pipeline ensures atomic execution
//   - In-memory operation for maximum speed
//
// Security Implementation:
//   - Only token hash stored, never actual token
//   - Automatic expiration via TTL
//   - Separate namespaces for access vs refresh tokens
//
// Parameters:
//   - ctx: Context for cancellation and timeout
//   - tokenType: Type of token (AccessToken or RefreshToken)
//   - token: The actual token string to revoke
//   - ttl: Time-to-live duration for the revocation record
//
// Returns:
//   - error: If token is empty, TTL is invalid, token type is invalid,
//     or Redis operation fails
//
// Example (Revoke access token):
//
//	err := repo.MarkTokenRevoke(ctx, AccessToken, "jwt-token-here", 15*time.Minute)
//	if err != nil {
//	    return fmt.Errorf("failed to revoke token: %w", err)
//	}
//
// Redis Command:
//
//	SET revoked:access:token_hash "1" EX 900
func (r *RedisTokenRepository) MarkTokenRevoke(ctx context.Context, tokenType TokenType, token string, ttl time.Duration) error {
	if token == "" {
		return fmt.Errorf("token cannot be empty")
	}

	if ttl <= 0 {
		return fmt.Errorf("ttl must be positive")
	}

	// Ensure minimum TTL for Redis reliability
	if ttl < minRedisTTL {
		ttl = minRedisTTL
	}

	// Hash the token for secure storage
	tokenHash := hashToken(token)

	var key string
	switch tokenType {
	case AccessToken:
		key = revokedAccessPrefix + tokenHash
	case RefreshToken:
		key = revokedRefreshPrefix + tokenHash
	default:
		return fmt.Errorf("invalid token type: %s", tokenType)
	}

	// Use pipeline for atomic operation
	pipe := r.client.Pipeline()
	pipe.Set(ctx, key, "1", ttl)
	_, err := pipe.Exec(ctx)

	return err
}

// IsTokenRevoked checks if a token has been revoked by checking its hash in Redis.
// Uses GET operation for reliable existence checking with TTL validation.
//
// Redis Operation:
//   - GET key
//   - Returns value if key exists and TTL hasn't expired
//   - Returns nil if key doesn't exist or TTL has expired
//
// Performance Characteristics:
//   - O(1) time complexity
//   - Single GET operation
//   - In-memory lookup for maximum speed
//   - Automatic TTL handling by Redis
//
// Key Advantages over EXISTS:
//   - GET is atomic and reliable
//   - Works correctly with expiring keys
//   - Returns actual value for verification
//   - Consistent behavior in cluster environments
//
// Parameters:
//   - ctx: Context for cancellation and timeout
//   - tokenType: Type of token to check (AccessToken or RefreshToken)
//   - token: The token string to check for revocation
//
// Returns:
//   - bool: True if token is revoked and not expired, false otherwise
//   - error: If token is empty, token type is invalid, or Redis operation fails
//
// Example (Check access token):
//
//	revoked, err := repo.IsTokenRevoked(ctx, AccessToken, "jwt-token-here")
//	if err != nil {
//	    return fmt.Errorf("failed to check revocation: %w", err)
//	}
//	if revoked {
//	    return errors.New("token has been revoked")
//	}
//
// Redis Command:
//
//	GET revoked:access:token_hash
func (r *RedisTokenRepository) IsTokenRevoked(ctx context.Context, tokenType TokenType, token string) (bool, error) {
	if token == "" {
		return false, fmt.Errorf("token cannot be empty")
	}

	// Hash the token for lookup
	tokenHash := hashToken(token)

	var key string
	switch tokenType {
	case AccessToken:
		key = revokedAccessPrefix + tokenHash
	case RefreshToken:
		key = revokedRefreshPrefix + tokenHash
	default:
		return false, fmt.Errorf("invalid token type: %s", tokenType)
	}

	// Use GET instead of EXISTS for better atomicity
	val, err := r.client.Get(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			return false, nil
		}
		return false, fmt.Errorf("redis error: %w", err)
	}

	return val == "1", nil
}

// MarkTokenRotated marks a token as rotated by storing its hash in Redis.
// Uses key with TTL for automatic expiration and pipeline for atomic operation.
//
// Security Purpose:
//   - Prevents replay of rotated refresh tokens
//   - Enables one-time use during token rotation flow
//   - Protects against token replay attacks
//
// Redis Operation:
//   - SET key value EX seconds
//   - Key format: "rotated:{hash}"
//   - Value: "1" (simple marker)
//   - TTL: Automatic expiration after specified duration
//
// Parameters:
//   - ctx: Context for cancellation and timeout
//   - token: The refresh token being rotated
//   - ttl: Time-to-live duration for rotation record
//
// Returns:
//   - error: If token is empty, TTL is invalid, or Redis operation fails
//
// Example (Mark token as rotated):
//
//	err := repo.MarkTokenRotated(ctx, "old-refresh-token", 7*24*time.Hour)
//	if err != nil {
//	    return fmt.Errorf("failed to mark token as rotated: %w", err)
//	}
//
// Redis Command:
//
//	SET rotated:token_hash "1" EX 604800
func (r *RedisTokenRepository) MarkTokenRotated(ctx context.Context, token string, ttl time.Duration) error {
	if token == "" {
		return fmt.Errorf("token cannot be empty")
	}

	if ttl <= 0 {
		return fmt.Errorf("ttl must be positive")
	}

	// Ensure minimum TTL for Redis reliability
	if ttl < minRedisTTL {
		ttl = minRedisTTL
	}

	// Hash the token for secure storage
	tokenHash := hashToken(token)
	key := rotatedPrefix + tokenHash

	// Use pipeline for atomic operation
	pipe := r.client.Pipeline()
	pipe.Set(ctx, key, "1", ttl)
	_, err := pipe.Exec(ctx)

	return err
}

// MarkTokenRotatedAtomic marks a token as rotated atomically, returning whether it was newly rotated.
// Uses SETNX (SET if Not eXists) for true atomic rotation detection.
//
// Key Difference from MarkTokenRotated:
//   - Returns boolean indicating if rotation was actually performed
//   - Uses SETNX which only sets if key doesn't exist
//   - Essential for preventing double-spending in rotation flows
//   - Provides true atomicity for rotation detection
//
// Redis Operation:
//   - SETNX key value
//   - EXPIRE key seconds (if SETNX succeeds)
//   - Atomic check-and-set operation
//
// Use Cases:
//   - Preventing race conditions during concurrent token rotation
//   - Ensuring exactly-once rotation semantics
//   - Distributed system environments with multiple validators
//
// Parameters:
//   - ctx: Context for cancellation and timeout
//   - token: The refresh token being rotated
//   - ttl: Time-to-live duration for rotation record
//
// Returns:
//   - bool: True if token was newly rotated, false if already rotated
//   - error: If token is empty, TTL is invalid, or Redis operation fails
//
// Example (Atomic rotation check):
//
//	rotated, err := repo.MarkTokenRotatedAtomic(ctx, "refresh-token", 24*time.Hour)
//	if err != nil {
//	    return fmt.Errorf("rotation failed: %w", err)
//	}
//	if !rotated {
//	    return errors.New("token was already rotated - potential replay attack")
//	}
//	// Safe to proceed with new token issuance
//
// Redis Commands:
//
//	SETNX rotated:token_hash "1"
//	EXPIRE rotated:token_hash 86400
func (r *RedisTokenRepository) MarkTokenRotatedAtomic(ctx context.Context, token string, ttl time.Duration) (bool, error) {
	if token == "" {
		return false, fmt.Errorf("token cannot be empty")
	}

	if ttl <= 0 {
		return false, fmt.Errorf("ttl must be positive")
	}

	if ttl < minRedisTTL {
		ttl = minRedisTTL
	}

	tokenHash := hashToken(token)
	key := rotatedPrefix + tokenHash

	// Use SET with NX (Only set if Not eXists) for true atomic operation
	// This ensures only ONE goroutine can set the key
	result, err := r.client.SetNX(ctx, key, "1", ttl).Result()
	if err != nil {
		return false, fmt.Errorf("redis error: %w", err)
	}

	// SETNX returns true if the key was set, false if it already existed
	return result, nil
}

// IsTokenRotated checks if a token has been rotated by checking its hash in Redis.
// Uses GET operation for reliable existence checking with TTL validation.
//
// Security Purpose:
//   - Detects if a refresh token has been previously rotated
//   - Prevents reuse of rotated tokens in replay attacks
//   - Essential for rotation-based security schemes
//
// Performance Characteristics:
//   - O(1) time complexity
//   - Single GET operation
//   - In-memory lookup for maximum speed
//   - Automatic TTL handling by Redis
//
// Parameters:
//   - ctx: Context for cancellation and timeout
//   - token: The token to check for rotation status
//
// Returns:
//   - bool: True if token has been rotated and not expired, false otherwise
//   - error: If token is empty or Redis operation fails
//
// Example (Check rotation status):
//
//	rotated, err := repo.IsTokenRotated(ctx, "suspect-refresh-token")
//	if err != nil {
//	    return fmt.Errorf("failed to check rotation: %w", err)
//	}
//	if rotated {
//	    return errors.New("token has been rotated - do not accept")
//	}
//
// Redis Command:
//
//	GET rotated:token_hash
func (r *RedisTokenRepository) IsTokenRotated(ctx context.Context, token string) (bool, error) {
	if token == "" {
		return false, fmt.Errorf("token cannot be empty")
	}

	// Hash the token for lookup
	tokenHash := hashToken(token)
	key := rotatedPrefix + tokenHash

	// Use GET instead of EXISTS for better atomicity
	val, err := r.client.Get(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			return false, nil
		}
		return false, fmt.Errorf("redis error: %w", err)
	}

	return val == "1", nil
}

// GetRotationTTL returns the remaining TTL for a rotated token.
// Uses PTTL for millisecond precision TTL checking.
//
// Use Cases:
//   - Debugging rotation-related issues
//   - Monitoring token rotation patterns
//   - Optimizing cleanup scheduling
//   - Understanding token lifecycle
//
// Redis PTTL Behavior:
//   - Returns -2 if key doesn't exist
//   - Returns -1 if key exists but has no expiry
//   - Returns positive value for remaining TTL in milliseconds
//   - Millisecond precision for accurate timing
//
// Parameters:
//   - ctx: Context for cancellation and timeout
//   - token: The token to check for remaining TTL
//
// Returns:
//   - time.Duration: Remaining TTL if token is rotated and not expired, 0 otherwise
//   - error: If token is empty or Redis operation fails
//
// Example (Monitor rotation TTL):
//
//	ttl, err := repo.GetRotationTTL(ctx, "rotated-token")
//	if err != nil {
//	    return fmt.Errorf("failed to get rotation TTL: %w", err)
//	}
//	if ttl > 0 {
//	    log.Printf("Token will be automatically cleaned up in %v", ttl)
//	}
//
// Redis Command:
//
//	PTTL rotated:token_hash
func (r *RedisTokenRepository) GetRotationTTL(ctx context.Context, token string) (time.Duration, error) {
	if token == "" {
		return 0, fmt.Errorf("token cannot be empty")
	}

	// Hash the token for lookup
	tokenHash := hashToken(token)
	key := rotatedPrefix + tokenHash

	// Use PTTL for millisecond precision
	ttl, err := r.client.PTTL(ctx, key).Result()
	if err != nil {
		return 0, fmt.Errorf("redis error: %w", err)
	}

	// Redis PTTL returns:
	// -2 if key doesn't exist
	// -1 if key exists but has no expiry
	// positive value for remaining TTL in milliseconds
	if ttl == -2 || ttl == -1 {
		return 0, nil
	}

	// Convert to Duration and handle near-zero values
	duration := ttl
	if duration < 0 {
		return 0, nil
	}

	return duration, nil
}

// CleanupExpiredRevokedTokens removes expired revoked tokens from Redis.
// Note: Redis automatically removes expired keys, but this provides manual control.
//
// Use Cases:
//   - Force immediate cleanup of expired keys
//   - Handle memory fragmentation issues
//   - Bulk cleanup during maintenance windows
//   - Testing and development environments
//
// Cleanup Strategy:
//   - SCAN iterates through keys with specified prefix
//   - PTTL checks remaining TTL for each key
//   - DEL removes keys that are expired or have no TTL
//   - Batch processing for memory efficiency
//
// Performance Characteristics:
//   - O(N) where N is number of keys with prefix
//   - SCAN is non-blocking and production-safe
//   - Pipeline reduces round trips
//   - Batch deletion improves efficiency
//
// Parameters:
//   - ctx: Context for cancellation and timeout
//   - tokenType: Type of tokens to cleanup (AccessToken or RefreshToken)
//
// Returns:
//   - error: If token type is invalid or Redis operation fails
//
// Example (Manual cleanup):
//
//	err := repo.CleanupExpiredRevokedTokens(ctx, AccessToken)
//	if err != nil {
//	    log.Printf("Failed to cleanup access tokens: %v", err)
//	}
func (r *RedisTokenRepository) CleanupExpiredRevokedTokens(ctx context.Context, tokenType TokenType) error {
	var prefix string
	switch tokenType {
	case AccessToken:
		prefix = revokedAccessPrefix
	case RefreshToken:
		prefix = revokedRefreshPrefix
	default:
		return fmt.Errorf("invalid token type: %s", tokenType)
	}

	return r.cleanupExpiredKeys(ctx, prefix)
}

// CleanupExpiredRotatedTokens removes expired rotated tokens from Redis.
// Provides manual control over Redis's automatic key expiration.
//
// Cleanup Strategy:
//   - SCAN iterates through rotated token keys
//   - PTTL checks remaining TTL for each key
//   - DEL removes expired keys in batches
//   - Context cancellation support for long-running operations
//
// Parameters:
//   - ctx: Context for cancellation and timeout
//
// Returns:
//   - error: If Redis operation fails
//
// Example (Scheduled manual cleanup):
//
//	// Run additional cleanup weekly (Redis TTL handles most cases)
//	ticker := time.NewTicker(7 * 24 * time.Hour)
//	defer ticker.Stop()
//
//	for range ticker.C {
//	    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
//	    err := repo.CleanupExpiredRotatedTokens(ctx)
//	    cancel()
//	    if err != nil {
//	        log.Printf("Manual rotated token cleanup failed: %v", err)
//	    }
//	}
func (r *RedisTokenRepository) CleanupExpiredRotatedTokens(ctx context.Context) error {
	return r.cleanupExpiredKeys(ctx, rotatedPrefix)
}

// cleanupExpiredKeys is a helper function that removes expired keys with a given prefix.
// Implements production-safe key scanning and deletion.
//
// SCAN Strategy:
//   - Uses SCAN instead of KEYS for non-blocking operation
//   - Batch processing with configurable batch size
//   - Context cancellation checking between batches
//   - Pipeline for efficient TTL checking
//
// Error Handling:
//   - Continues processing on individual key errors
//   - Returns error only on fatal operations
//   - Logs batch errors but continues processing
//
// Performance Optimizations:
//   - SCAN cursor-based iteration
//   - Pipeline for batch TTL checking
//   - Batch deletion with DEL multiple keys
//   - Configurable batch size for memory control
func (r *RedisTokenRepository) cleanupExpiredKeys(ctx context.Context, prefix string) error {
	var cursor uint64
	const batchSize = 100
	deletedCount := 0

	for {
		// Check if context is cancelled
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("context canceled: %w", err)
		}

		keys, newCursor, err := r.client.Scan(ctx, cursor, prefix+"*", batchSize).Result()
		if err != nil {
			return fmt.Errorf("redis scan error: %w", err)
		}

		if len(keys) > 0 {
			// Check TTL for each key in batch using pipeline
			pipe := r.client.Pipeline()
			ttlCmds := make([]*redis.DurationCmd, len(keys))

			for i, key := range keys {
				ttlCmds[i] = pipe.PTTL(ctx, key)
			}

			_, err = pipe.Exec(ctx)
			if err != nil && err != redis.Nil {
				// Log error but continue
				fmt.Printf("Error checking TTL batch: %v\n", err)
			}

			// Collect expired keys
			var keysToDelete []string
			for i, ttlCmd := range ttlCmds {
				ttl, err := ttlCmd.Result()
				if err != nil {
					continue
				}

				// Delete if expired (-2) or no expiry set (-1 shouldn't happen in our case)
				if ttl == -2 || ttl <= 0 {
					keysToDelete = append(keysToDelete, keys[i])
				}
			}

			// Delete expired keys in batch
			if len(keysToDelete) > 0 {
				deleted, err := r.client.Del(ctx, keysToDelete...).Result()
				if err != nil {
					return fmt.Errorf("redis delete error: %w", err)
				}
				deletedCount += int(deleted)
			}
		}

		// Move to next batch
		if newCursor == 0 {
			break
		}
		cursor = newCursor
	}

	if deletedCount > 0 {
		fmt.Printf("Cleaned up %d expired keys with prefix %s\n", deletedCount, prefix)
	}

	return nil
}

// Stats returns statistics about the repository for monitoring and debugging.
// Provides insights into token revocation and rotation patterns using SCAN operations.
//
// Metrics Collected:
//   - Total revoked tokens (all types)
//   - Revoked access tokens count
//   - Revoked refresh tokens count
//   - Rotated tokens count
//
// Performance Characteristics:
//   - Uses SCAN for production-safe key counting
//   - O(N) where N is total number of keys
//   - Batch processing for memory efficiency
//   - Non-blocking operations
//
// Use Cases:
//   - Monitoring system health and usage patterns
//   - Capacity planning and performance tuning
//   - Security auditing and anomaly detection
//   - Debugging token-related issues
//
// Parameters:
//   - ctx: Context for cancellation and timeout
//
// Returns:
//   - map[string]interface{}: Dictionary of statistics metrics
//   - error: If any Redis count operation fails
//
// Example (Monitoring dashboard):
//
//	stats, err := repo.Stats(ctx)
//	if err != nil {
//	    log.Printf("Failed to get Redis stats: %v", err)
//	    return
//	}
//
//	fmt.Printf("Redis token statistics: %+v\n", stats)
func (r *RedisTokenRepository) Stats(ctx context.Context) (map[string]interface{}, error) {
	var accessCount, refreshCount, rotatedCount int64

	// Count each type using SCAN
	countKeys := func(pattern string) (int64, error) {
		var count int64
		var cursor uint64

		for {
			keys, newCursor, err := r.client.Scan(ctx, cursor, pattern, 100).Result()
			if err != nil {
				return 0, err
			}
			count += int64(len(keys))

			if newCursor == 0 {
				break
			}
			cursor = newCursor
		}
		return count, nil
	}

	var err error
	accessCount, err = countKeys(revokedAccessPrefix + "*")
	if err != nil {
		return nil, fmt.Errorf("failed to count access tokens: %w", err)
	}

	refreshCount, err = countKeys(revokedRefreshPrefix + "*")
	if err != nil {
		return nil, fmt.Errorf("failed to count refresh tokens: %w", err)
	}

	rotatedCount, err = countKeys(rotatedPrefix + "*")
	if err != nil {
		return nil, fmt.Errorf("failed to count rotated tokens: %w", err)
	}

	return map[string]interface{}{
		"total_revoked_tokens":   accessCount + refreshCount,
		"revoked_access_tokens":  accessCount,
		"revoked_refresh_tokens": refreshCount,
		"rotated_tokens":         rotatedCount,
	}, nil
}

// Close performs cleanup operations and closes the Redis connection.
// Implements graceful shutdown pattern for resource cleanup.
//
// Cleanup Actions:
//   - Closes Redis client connection pool
//   - Releases all Redis connections
//   - Prevents connection leaks during application shutdown
//
// Important: This should be called during application shutdown to prevent
// Redis connection leaks and ensure graceful termination.
//
// Returns:
//   - error: If closing the Redis client fails
//
// Example (Graceful shutdown):
//
//	// Setup signal handling
//	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
//	defer stop()
//
//	// Wait for shutdown signal
//	<-ctx.Done()
//
//	// Close repository during shutdown
//	if err := repo.Close(); err != nil {
//	    log.Printf("Failed to close Redis token repository: %v", err)
//	}
func (r *RedisTokenRepository) Close() error {
	return r.client.Close()
}
