// File: pkg/gourdiantoken/gourdiantoken.repository.redis.imp.go

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
)

type RedisTokenRepository struct {
	client *redis.Client
}

// NewRedisTokenRepository creates a new Redis-based token repository
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

// MarkTokenRevoke marks a token as revoked by storing its hash
func (r *RedisTokenRepository) MarkTokenRevoke(ctx context.Context, tokenType TokenType, token string, ttl time.Duration) error {
	if token == "" {
		return fmt.Errorf("token cannot be empty")
	}

	if ttl <= 0 {
		return fmt.Errorf("ttl must be positive")
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

	return r.client.Set(ctx, key, "1", ttl).Err()
}

// IsTokenRevoked checks if a token has been revoked by checking its hash
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

	exists, err := r.client.Exists(ctx, key).Result()
	if err != nil {
		return false, fmt.Errorf("redis error: %w", err)
	}

	return exists > 0, nil
}

// MarkTokenRotated marks a token as rotated by storing its hash
func (r *RedisTokenRepository) MarkTokenRotated(ctx context.Context, token string, ttl time.Duration) error {
	if token == "" {
		return fmt.Errorf("token cannot be empty")
	}

	if ttl <= 0 {
		return fmt.Errorf("ttl must be positive")
	}

	// Hash the token for secure storage
	tokenHash := hashToken(token)
	key := rotatedPrefix + tokenHash

	return r.client.Set(ctx, key, "1", ttl).Err()
}

// IsTokenRotated checks if a token has been rotated by checking its hash
func (r *RedisTokenRepository) IsTokenRotated(ctx context.Context, token string) (bool, error) {
	if token == "" {
		return false, fmt.Errorf("token cannot be empty")
	}

	// Hash the token for lookup
	tokenHash := hashToken(token)
	key := rotatedPrefix + tokenHash

	exists, err := r.client.Exists(ctx, key).Result()
	if err != nil {
		return false, fmt.Errorf("redis error: %w", err)
	}

	return exists > 0, nil
}

// GetRotationTTL returns the remaining TTL for a rotated token
func (r *RedisTokenRepository) GetRotationTTL(ctx context.Context, token string) (time.Duration, error) {
	if token == "" {
		return 0, fmt.Errorf("token cannot be empty")
	}

	// Hash the token for lookup
	tokenHash := hashToken(token)
	key := rotatedPrefix + tokenHash

	ttl, err := r.client.TTL(ctx, key).Result()
	if err != nil {
		return 0, fmt.Errorf("redis error: %w", err)
	}

	// Redis returns negative values for keys that don't exist or have no expiry
	if ttl < 0 {
		return 0, nil
	}

	return ttl, nil
}

// CleanupExpiredRevokedTokens removes expired revoked tokens from Redis
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

// CleanupExpiredRotatedTokens removes expired rotated tokens from Redis
func (r *RedisTokenRepository) CleanupExpiredRotatedTokens(ctx context.Context) error {
	return r.cleanupExpiredKeys(ctx, rotatedPrefix)
}

// cleanupExpiredKeys is a helper function that removes expired keys with a given prefix
func (r *RedisTokenRepository) cleanupExpiredKeys(ctx context.Context, prefix string) error {
	var cursor uint64
	const batchSize = 100

	for {
		// Check if context is cancelled
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("context canceled: %w", err)
		}

		keys, newCursor, err := r.client.Scan(ctx, cursor, prefix+"*", batchSize).Result()
		if err != nil {
			return fmt.Errorf("redis scan error: %w", err)
		}

		// Check TTL for each key and collect expired ones
		var keysToDelete []string
		for _, key := range keys {
			ttl, err := r.client.TTL(ctx, key).Result()
			if err != nil {
				// Log error but continue with other keys
				fmt.Printf("Error checking TTL for key %s: %v\n", key, err)
				continue
			}

			// If TTL is negative, the key has expired or doesn't exist
			if ttl <= 0 {
				keysToDelete = append(keysToDelete, key)
			}
		}

		// Delete expired keys in batch
		if len(keysToDelete) > 0 {
			if _, err := r.client.Del(ctx, keysToDelete...).Result(); err != nil {
				return fmt.Errorf("redis delete error: %w", err)
			}
		}

		// Move to next batch
		if newCursor == 0 {
			break
		}
		cursor = newCursor
	}

	return nil
}
