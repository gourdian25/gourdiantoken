// File: gourdiantoken.repository.inmemory.imp.go

package gourdiantoken

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// tokenEntry represents a stored token with its expiration time
type tokenEntry struct {
	hash      string
	expiresAt time.Time
}

// MemoryTokenRepository is an in-memory implementation of TokenRepository
// Suitable for development, testing, or single-instance deployments
type MemoryTokenRepository struct {
	mu              sync.RWMutex
	revokedAccess   map[string]tokenEntry
	revokedRefresh  map[string]tokenEntry
	rotatedTokens   map[string]tokenEntry
	cleanupInterval time.Duration
	stopCleanup     chan struct{}
	cleanupOnce     sync.Once
}

// NewMemoryTokenRepository creates a new in-memory token repository
// cleanupInterval determines how often expired entries are removed (default: 5 minutes)
func NewMemoryTokenRepository(cleanupInterval time.Duration) TokenRepository {
	if cleanupInterval <= 0 {
		cleanupInterval = 5 * time.Minute
	}

	repo := &MemoryTokenRepository{
		revokedAccess:   make(map[string]tokenEntry),
		revokedRefresh:  make(map[string]tokenEntry),
		rotatedTokens:   make(map[string]tokenEntry),
		cleanupInterval: cleanupInterval,
		stopCleanup:     make(chan struct{}),
	}

	// Start background cleanup
	go repo.periodicCleanup()

	return repo
}

// MarkTokenRevoke marks a token as revoked by storing its hash
func (m *MemoryTokenRepository) MarkTokenRevoke(ctx context.Context, tokenType TokenType, token string, ttl time.Duration) error {
	if token == "" {
		return fmt.Errorf("token cannot be empty")
	}

	if ttl <= 0 {
		return fmt.Errorf("ttl must be positive")
	}

	// Hash the token for secure storage
	tokenHash := hashToken(token)
	entry := tokenEntry{
		hash:      tokenHash,
		expiresAt: time.Now().Add(ttl),
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	switch tokenType {
	case AccessToken:
		m.revokedAccess[tokenHash] = entry
	case RefreshToken:
		m.revokedRefresh[tokenHash] = entry
	default:
		return fmt.Errorf("invalid token type: %s", tokenType)
	}

	return nil
}

// IsTokenRevoked checks if a token has been revoked by checking its hash
func (m *MemoryTokenRepository) IsTokenRevoked(ctx context.Context, tokenType TokenType, token string) (bool, error) {
	if token == "" {
		return false, fmt.Errorf("token cannot be empty")
	}

	// Hash the token for lookup
	tokenHash := hashToken(token)

	m.mu.RLock()
	defer m.mu.RUnlock()

	var entry tokenEntry
	var exists bool

	switch tokenType {
	case AccessToken:
		entry, exists = m.revokedAccess[tokenHash]
	case RefreshToken:
		entry, exists = m.revokedRefresh[tokenHash]
	default:
		return false, fmt.Errorf("invalid token type: %s", tokenType)
	}

	if !exists {
		return false, nil
	}

	// Check if entry has expired
	if time.Now().After(entry.expiresAt) {
		return false, nil
	}

	return true, nil
}

// MarkTokenRotated marks a token as rotated by storing its hash
func (m *MemoryTokenRepository) MarkTokenRotated(ctx context.Context, token string, ttl time.Duration) error {
	if token == "" {
		return fmt.Errorf("token cannot be empty")
	}

	if ttl <= 0 {
		return fmt.Errorf("ttl must be positive")
	}

	// Hash the token for secure storage
	tokenHash := hashToken(token)
	entry := tokenEntry{
		hash:      tokenHash,
		expiresAt: time.Now().Add(ttl),
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.rotatedTokens[tokenHash] = entry

	return nil
}

// IsTokenRotated checks if a token has been rotated by checking its hash
func (m *MemoryTokenRepository) IsTokenRotated(ctx context.Context, token string) (bool, error) {
	if token == "" {
		return false, fmt.Errorf("token cannot be empty")
	}

	// Hash the token for lookup
	tokenHash := hashToken(token)

	m.mu.RLock()
	defer m.mu.RUnlock()

	entry, exists := m.rotatedTokens[tokenHash]
	if !exists {
		return false, nil
	}

	// Check if entry has expired
	if time.Now().After(entry.expiresAt) {
		return false, nil
	}

	return true, nil
}

// GetRotationTTL returns the remaining TTL for a rotated token
func (m *MemoryTokenRepository) GetRotationTTL(ctx context.Context, token string) (time.Duration, error) {
	if token == "" {
		return 0, fmt.Errorf("token cannot be empty")
	}

	// Hash the token for lookup
	tokenHash := hashToken(token)

	m.mu.RLock()
	defer m.mu.RUnlock()

	entry, exists := m.rotatedTokens[tokenHash]
	if !exists {
		return 0, nil
	}

	// Calculate remaining TTL
	remaining := time.Until(entry.expiresAt)
	if remaining < 0 {
		return 0, nil
	}

	return remaining, nil
}

// CleanupExpiredRevokedTokens removes expired revoked tokens from memory
func (m *MemoryTokenRepository) CleanupExpiredRevokedTokens(ctx context.Context, tokenType TokenType) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()

	switch tokenType {
	case AccessToken:
		for hash, entry := range m.revokedAccess {
			if now.After(entry.expiresAt) {
				delete(m.revokedAccess, hash)
			}
		}
	case RefreshToken:
		for hash, entry := range m.revokedRefresh {
			if now.After(entry.expiresAt) {
				delete(m.revokedRefresh, hash)
			}
		}
	default:
		return fmt.Errorf("invalid token type: %s", tokenType)
	}

	return nil
}

// CleanupExpiredRotatedTokens removes expired rotated tokens from memory
func (m *MemoryTokenRepository) CleanupExpiredRotatedTokens(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	for hash, entry := range m.rotatedTokens {
		if now.After(entry.expiresAt) {
			delete(m.rotatedTokens, hash)
		}
	}

	return nil
}

// periodicCleanup runs background cleanup of expired entries
func (m *MemoryTokenRepository) periodicCleanup() {
	ticker := time.NewTicker(m.cleanupInterval)
	defer ticker.Stop()

	ctx := context.Background()

	for {
		select {
		case <-m.stopCleanup:
			return
		case <-ticker.C:
			// Cleanup all expired entries
			_ = m.CleanupExpiredRevokedTokens(ctx, AccessToken)
			_ = m.CleanupExpiredRevokedTokens(ctx, RefreshToken)
			_ = m.CleanupExpiredRotatedTokens(ctx)
		}
	}
}

// Close stops the background cleanup goroutine
// Call this when shutting down the application
func (m *MemoryTokenRepository) Close() error {
	m.cleanupOnce.Do(func() {
		close(m.stopCleanup)
	})
	return nil
}

// Stats returns statistics about the repository
// Useful for monitoring and debugging
func (m *MemoryTokenRepository) Stats() map[string]int {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return map[string]int{
		"revoked_access_tokens":  len(m.revokedAccess),
		"revoked_refresh_tokens": len(m.revokedRefresh),
		"rotated_tokens":         len(m.rotatedTokens),
	}
}
