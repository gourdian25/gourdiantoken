// File: gourdiantoken.repository.inmemory.imp.go

package gourdiantoken

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// tokenEntry represents a stored token with its expiration time.
// Used for both revoked and rotated token tracking in memory.
//
// Memory Efficiency:
//   - Stores only token hash (64 bytes) instead of full token
//   - Time.Time is efficiently stored as 24 bytes
//   - Total memory per entry: ~88 bytes + map overhead
//
// Security Considerations:
//   - Only token hashes are stored in memory
//   - Automatic expiration prevents memory leaks
//   - No sensitive token data retained in memory
type tokenEntry struct {
	hash      string
	expiresAt time.Time
}

// MemoryTokenRepository is an in-memory implementation of TokenRepository.
// Suitable for development, testing, or single-instance deployments.
//
// Architecture Characteristics:
//   - Fully concurrent-safe with sync.RWMutex
//   - Automatic background cleanup of expired entries
//   - Three separate maps for different token types
//   - Memory-efficient storage using token hashes
//
// Performance Characteristics:
//   - O(1) average case for lookups and inserts
//   - Read-preferring RWLock for high concurrency
//   - Background cleanup minimizes main operation impact
//   - No network latency (pure in-memory operations)
//
// Memory Usage Considerations:
//   - Memory grows with number of active tokens
//   - Automatic cleanup prevents unbounded growth
//   - Each token entry consumes ~88 bytes + map overhead
//   - Typical usage: thousands to tens of thousands of tokens
//
// Limitations:
//   - Data lost on application restart
//   - Not suitable for distributed systems
//   - Memory consumption proportional to active tokens
//   - No persistence for audit requirements
type MemoryTokenRepository struct {
	mu              sync.RWMutex
	revokedAccess   map[string]tokenEntry
	revokedRefresh  map[string]tokenEntry
	rotatedTokens   map[string]tokenEntry
	cleanupInterval time.Duration
	stopCleanup     chan struct{}
	cleanupOnce     sync.Once
}

// NewMemoryTokenRepository creates a new in-memory token repository.
// Starts background cleanup goroutine for automatic expiration management.
//
// Use Cases:
//   - Development and testing environments
//   - Single-instance applications without persistence requirements
//   - Prototyping and proof-of-concept implementations
//   - Low-security internal applications
//   - Applications where restart-based token reset is acceptable
//
// Performance Optimizations:
//   - Separate maps for different token types reduce lock contention
//   - Read-preferring lock enables high concurrent read throughput
//   - Background cleanup avoids blocking main operations
//   - Hash-based storage enables O(1) operations
//
// Parameters:
//   - cleanupInterval: How often to run background cleanup. Defaults to 5 minutes if <= 0.
//     Shorter intervals reduce memory usage but increase CPU. Longer intervals increase
//     memory usage but reduce cleanup overhead.
//
// Returns:
//   - TokenRepository: Initialized in-memory repository with running cleanup goroutine
//
// Example (Development with frequent cleanup):
//
//	// Clean up every minute for memory efficiency
//	repo := NewMemoryTokenRepository(time.Minute)
//
// Example (Testing with default cleanup):
//
//	// Use default 5-minute cleanup
//	repo := NewMemoryTokenRepository(0)
//
// Example (Production-like with hourly cleanup):
//
//	// Clean up hourly for reduced overhead
//	repo := NewMemoryTokenRepository(time.Hour)
//
// Goroutine Management:
//   - Cleanup goroutine started automatically
//   - Use Close() to stop goroutine during shutdown
//   - Automatic cleanup prevents memory leaks
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

// MarkTokenRevoke marks a token as revoked by storing its hash in memory.
// Thread-safe operation with write lock protection.
//
// Memory Storage:
//   - Token hash stored in type-specific map
//   - Expiration time stored for automatic cleanup
//   - Separate maps for access vs refresh tokens
//   - O(1) insertion time with map store
//
// Security Implementation:
//   - Only SHA-256 hash of token stored
//   - No sensitive token data retained
//   - Automatic expiration via TTL
//
// Parameters:
//   - ctx: Context for cancellation (not used in memory implementation)
//   - tokenType: Type of token (AccessToken or RefreshToken)
//   - token: The actual token string to revoke
//   - ttl: Time-to-live duration for the revocation record
//
// Returns:
//   - error: If token is empty, TTL is invalid, or token type is invalid
//
// Example (Revoke access token):
//
//	err := repo.MarkTokenRevoke(ctx, AccessToken, "jwt-token-here", 15*time.Minute)
//	if err != nil {
//	    return fmt.Errorf("failed to revoke token: %w", err)
//	}
//
// Example (Revoke refresh token):
//
//	err := repo.MarkTokenRevoke(ctx, RefreshToken, "refresh-token-here", 7*24*time.Hour)
//	if err != nil {
//	    return fmt.Errorf("failed to revoke refresh token: %w", err)
//	}
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

// IsTokenRevoked checks if a token has been revoked by checking its hash in memory.
// Thread-safe operation with read lock for high concurrency.
//
// Performance Characteristics:
//   - O(1) average case lookup
//   - Read lock enables concurrent reads
//   - Automatic expiration check during lookup
//   - No network or disk I/O
//
// Operation Sequence:
//  1. Hash the provided token
//  2. Acquire read lock
//  3. Lookup in appropriate token map
//  4. Check expiration time
//  5. Return revocation status
//
// Parameters:
//   - ctx: Context for cancellation (not used in memory implementation)
//   - tokenType: Type of token to check (AccessToken or RefreshToken)
//   - token: The token string to check for revocation
//
// Returns:
//   - bool: True if token is revoked and not expired, false otherwise
//   - error: If token is empty or token type is invalid
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

// MarkTokenRotated marks a token as rotated by storing its hash in memory.
// Thread-safe operation with write lock protection.
//
// Security Purpose:
//   - Prevents replay of rotated refresh tokens
//   - Essential for rotation-based security
//   - Protects against token reuse attacks
//
// Memory Storage:
//   - Single map for all rotated tokens
//   - O(1) insertion time
//   - Automatic expiration via TTL
//
// Parameters:
//   - ctx: Context for cancellation (not used in memory implementation)
//   - token: The refresh token being rotated
//   - ttl: Time-to-live duration for rotation record
//
// Returns:
//   - error: If token is empty or TTL is invalid
//
// Example (Mark token as rotated):
//
//	err := repo.MarkTokenRotated(ctx, "old-refresh-token", 24*time.Hour)
//	if err != nil {
//	    return fmt.Errorf("failed to mark token as rotated: %w", err)
//	}
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

// MarkTokenRotatedAtomic marks a token as rotated atomically, returning whether it was newly rotated.
// Provides true atomicity for rotation detection in concurrent scenarios.
//
// Key Features:
//   - Atomic check-and-set operation
//   - Returns whether rotation was actually performed
//   - Essential for preventing double-spending in rotation flows
//   - Thread-safe with proper locking
//
// Difference from MarkTokenRotated:
//   - Returns boolean indicating if rotation was new
//   - Performs existence check within critical section
//   - Prevents race conditions in concurrent environments
//
// Parameters:
//   - ctx: Context for cancellation (not used in memory implementation)
//   - token: The refresh token being rotated
//   - ttl: Time-to-live duration for rotation record
//
// Returns:
//   - bool: True if token was newly rotated, false if already rotated
//   - error: If token is empty or TTL is invalid
//
// Example (Atomic rotation check):
//
//	rotated, err := repo.MarkTokenRotatedAtomic(ctx, "refresh-token", time.Hour)
//	if err != nil {
//	    return fmt.Errorf("rotation failed: %w", err)
//	}
//	if !rotated {
//	    return errors.New("token was already rotated - potential security issue")
//	}
//	// Safe to proceed with new token issuance
func (m *MemoryTokenRepository) MarkTokenRotatedAtomic(ctx context.Context, token string, ttl time.Duration) (bool, error) {
	if token == "" {
		return false, fmt.Errorf("token cannot be empty")
	}

	if ttl <= 0 {
		return false, fmt.Errorf("ttl must be positive")
	}

	tokenHash := hashToken(token)
	entry := tokenEntry{
		hash:      tokenHash,
		expiresAt: time.Now().Add(ttl),
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if already rotated (within critical section)
	if existing, exists := m.rotatedTokens[tokenHash]; exists && time.Now().Before(existing.expiresAt) {
		return false, nil // Already rotated
	}

	// Mark as rotated atomically
	m.rotatedTokens[tokenHash] = entry
	return true, nil
}

// IsTokenRotated checks if a token has been rotated by checking its hash in memory.
// Thread-safe operation with read lock for high concurrency.
//
// Security Purpose:
//   - Detects if a refresh token has been previously rotated
//   - Prevents reuse of rotated tokens
//   - Essential for rotation-based security
//
// Performance:
//   - O(1) average case lookup
//   - Read lock enables concurrent access
//   - Automatic expiration check
//
// Parameters:
//   - ctx: Context for cancellation (not used in memory implementation)
//   - token: The token to check for rotation status
//
// Returns:
//   - bool: True if token has been rotated and not expired, false otherwise
//   - error: If token is empty
//
// Example (Check rotation status):
//
//	rotated, err := repo.IsTokenRotated(ctx, "suspect-token")
//	if err != nil {
//	    return fmt.Errorf("failed to check rotation: %w", err)
//	}
//	if rotated {
//	    return errors.New("token has been rotated - do not accept")
//	}
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

// GetRotationTTL returns the remaining TTL for a rotated token.
// Useful for debugging and monitoring rotation patterns.
//
// Use Cases:
//   - Debugging rotation-related issues
//   - Monitoring token lifecycle
//   - Understanding cleanup timing
//
// Parameters:
//   - ctx: Context for cancellation (not used in memory implementation)
//   - token: The token to check for remaining TTL
//
// Returns:
//   - time.Duration: Remaining TTL if token is rotated and not expired, 0 otherwise
//   - error: If token is empty
//
// Example (Monitor rotation TTL):
//
//	ttl, err := repo.GetRotationTTL(ctx, "rotated-token")
//	if err != nil {
//	    return fmt.Errorf("failed to get TTL: %w", err)
//	}
//	log.Printf("Token will be automatically cleaned up in %v", ttl)
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

// CleanupExpiredRevokedTokens removes expired revoked tokens from memory.
// Thread-safe operation with write lock protection.
//
// Cleanup Strategy:
//   - Iterates through specified token type map
//   - Removes entries where expiration time has passed
//   - O(n) operation where n is number of entries for that type
//   - Run periodically to prevent memory leaks
//
// Parameters:
//   - ctx: Context for cancellation (not used in memory implementation)
//   - tokenType: Type of tokens to cleanup (AccessToken or RefreshToken)
//
// Returns:
//   - error: If token type is invalid
//
// Example (Manual cleanup):
//
//	err := repo.CleanupExpiredRevokedTokens(ctx, AccessToken)
//	if err != nil {
//	    log.Printf("Failed to cleanup access tokens: %v", err)
//	}
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

// CleanupExpiredRotatedTokens removes expired rotated tokens from memory.
// Thread-safe operation with write lock protection.
//
// Cleanup Efficiency:
//   - Single pass through rotated tokens map
//   - O(n) operation where n is number of rotated tokens
//   - Typically fewer rotated tokens than revoked tokens
//   - Helps prevent memory bloat
//
// Parameters:
//   - ctx: Context for cancellation (not used in memory implementation)
//
// Returns:
//   - error: Always nil (error included for interface compatibility)
//
// Example (Manual cleanup):
//
//	err := repo.CleanupExpiredRotatedTokens(ctx)
//	if err != nil {
//	    log.Printf("Failed to cleanup rotated tokens: %v", err)
//	}
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

// periodicCleanup runs background cleanup of expired entries.
// Started automatically by NewMemoryTokenRepository and runs until Close() is called.
//
// Cleanup Strategy:
//   - Runs at configured cleanupInterval
//   - Cleans all three token maps (access, refresh, rotated)
//   - Continues until stopCleanup channel is closed
//   - Uses background context for cleanup operations
//
// Performance Impact:
//   - Minimal impact due to separate goroutine
//   - Write locks acquired during cleanup may briefly block writes
//   - Reads can continue during cleanup (read-preferring lock)
//   - Cleanup frequency balances memory vs CPU usage
//
// Goroutine Management:
//   - Started automatically during repository creation
//   - Stopped via Close() method during shutdown
//   - Uses sync.Once to ensure clean shutdown
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

// Close stops the background cleanup goroutine.
// Implements graceful shutdown pattern to prevent goroutine leaks.
//
// Important: Call this method when shutting down the application to ensure
// proper cleanup of resources and prevent goroutine leaks.
//
// Implementation Details:
//   - Uses sync.Once to ensure idempotent operation
//   - Closes stopCleanup channel to signal goroutine termination
//   - Goroutine will complete current cleanup cycle before exiting
//   - Safe to call multiple times
//
// Returns:
//   - error: Always nil (error included for interface compatibility)
//
// Example (Application shutdown):
//
//	// Handle graceful shutdown
//	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
//	defer cancel()
//
//	// Close repository
//	if err := repo.Close(); err != nil {
//	    log.Printf("Warning: failed to close token repository: %v", err)
//	}
func (m *MemoryTokenRepository) Close() error {
	m.cleanupOnce.Do(func() {
		close(m.stopCleanup)
	})
	return nil
}

// Stats returns statistics about the repository for monitoring and debugging.
// Provides snapshot of current memory usage and token counts.
//
// Metrics Provided:
//   - revoked_access_tokens: Count of currently revoked access tokens
//   - revoked_refresh_tokens: Count of currently revoked refresh tokens
//   - rotated_tokens: Count of currently rotated tokens
//
// Use Cases:
//   - Monitoring memory usage patterns
//   - Debugging token-related issues
//   - Capacity planning and performance analysis
//   - Health checking and alerting
//
// Returns:
//   - map[string]int: Dictionary of current repository statistics
//
// Example (Monitoring endpoint):
//
//	// Expose stats via HTTP endpoint
//	http.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
//	    stats := repo.Stats()
//	    json.NewEncoder(w).Encode(stats)
//	})
//
// Example (Logging statistics):
//
//	stats := repo.Stats()
//	log.Printf("Token repository stats: %+v", stats)
func (m *MemoryTokenRepository) Stats() map[string]int {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return map[string]int{
		"revoked_access_tokens":  len(m.revokedAccess),
		"revoked_refresh_tokens": len(m.revokedRefresh),
		"rotated_tokens":         len(m.rotatedTokens),
	}
}
