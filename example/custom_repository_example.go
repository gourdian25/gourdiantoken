// File: example/custom_repository_example.go

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/gourdian25/gourdiantoken/v2"
)

// CustomTokenRepository is a reference implementation of gourdiantoken.TokenRepository,
// meant as a template for extending gourdiantoken to a storage backend that isn't one of
// the four built in (in-memory, Redis, PostgreSQL, MongoDB) — e.g. SQLite, DynamoDB, etcd,
// BoltDB, Cassandra, or any other key-value or SQL store. gourdiantoken only ever depends
// on the TokenRepository interface, never on a concrete type, so any implementation of it
// works with every constructor: NewGourdianTokenMaker directly, and by extension every
// NewGourdianTokenMakerWith* factory (those are just NewGourdianTokenMaker plus a specific
// TokenRepository already wired in).
//
// This particular implementation stores everything in plain Go maps guarded by a
// sync.RWMutex — deliberately similar in shape to gourdiantoken's own
// MemoryTokenRepository (gourdiantoken.repository.inmemory.imp.go), which is the most
// useful thing to compare this against — but is written fresh, with the explanatory
// comments a real integration would need. To adapt this to a real datastore, swap the map
// operations below for calls into it; the method signatures and their contracts (what each
// parameter/return value means, when to return which error) don't change.
//
// Implementation contract, mirrored from TokenRepository's own doc comment
// (gourdiantoken.interfaces.go):
//   - Every method must be safe for concurrent use by multiple goroutines.
//   - MarkTokenRotatedAtomic must provide true atomic compare-and-swap semantics — the
//     check ("is this already rotated?") and the write ("mark it rotated") must happen as
//     one indivisible operation, or two concurrent callers can both observe "not yet
//     rotated" and both proceed, defeating the entire point of rotation-based reuse
//     detection. For a SQL backend this usually means a conditional upsert
//     (INSERT ... ON CONFLICT ... DO UPDATE ... WHERE <existing row is already expired>) —
//     see gourdiantoken.repository.postgres.imp.go's InsertRotatedTokenIfNotExists query
//     for a real example of exactly that pattern, and
//     gourdiantoken.repository.mongo.imp.go's MarkTokenRotatedAtomic for the same idea
//     against a document store (a filtered UpdateOne with upsert=true).
//   - Store token hashes, never raw tokens — a leaked datastore then leaks nothing
//     replayable. gourdiantoken's own repositories all do this internally (SHA-256); this
//     example does too, via hashCustomToken below.
//   - Implementations may enforce a minimum TTL floor if their backend needs one (Redis's
//     does, at 100ms, as a safeguard against near-zero-TTL races) — that's
//     implementation-specific, not part of the interface contract.
//   - Stats' returned map keys are implementation-defined; callers shouldn't depend on any
//     specific key being present across different TokenRepository implementations.
type CustomTokenRepository struct {
	mu sync.RWMutex

	revoked           map[string]customEntry       // key: tokenType + ":" + sha256(token)
	rotated           map[string]customEntry       // key: sha256(token)
	tenantRevocations map[string]customTenantEntry // key: tenantID (not hashed, see below)
}

type customEntry struct {
	expiresAt time.Time
}

type customTenantEntry struct {
	revokedAt time.Time
	expiresAt time.Time
}

// NewCustomTokenRepository constructs an empty CustomTokenRepository. A real
// datastore-backed implementation would instead take a client/connection-pool/handle here
// — compare gourdiantoken.NewRedisTokenRepository(*redis.Client) or
// gourdiantoken.NewPostgresTokenRepository(ctx, *pgxpool.Pool) — and would typically also
// apply its own schema/index setup during construction (see
// gourdiantoken.repository.postgres.imp.go's applyPostgresSchema for a real example of
// that, guarded by a Postgres advisory lock so concurrent callers building a repository
// against the same fresh database don't race on the DDL).
func NewCustomTokenRepository() gourdiantoken.TokenRepository {
	return &CustomTokenRepository{
		revoked:           make(map[string]customEntry),
		rotated:           make(map[string]customEntry),
		tenantRevocations: make(map[string]customTenantEntry),
	}
}

// hashCustomToken mirrors gourdiantoken's own internal token-hashing convention: never
// store or index on the raw token string itself.
func hashCustomToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func customRevokedKey(tokenType gourdiantoken.TokenType, token string) string {
	return string(tokenType) + ":" + hashCustomToken(token)
}

func (r *CustomTokenRepository) MarkTokenRevoke(ctx context.Context, tokenType gourdiantoken.TokenType, token string, ttl time.Duration) error {
	if token == "" {
		return fmt.Errorf("token cannot be empty")
	}
	if ttl <= 0 {
		return fmt.Errorf("ttl must be positive")
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	r.revoked[customRevokedKey(tokenType, token)] = customEntry{expiresAt: time.Now().Add(ttl)}
	return nil
}

func (r *CustomTokenRepository) IsTokenRevoked(ctx context.Context, tokenType gourdiantoken.TokenType, token string) (bool, error) {
	if token == "" {
		return false, fmt.Errorf("token cannot be empty")
	}

	r.mu.RLock()
	defer r.mu.RUnlock()
	entry, ok := r.revoked[customRevokedKey(tokenType, token)]
	if !ok || time.Now().After(entry.expiresAt) {
		return false, nil
	}
	return true, nil
}

func (r *CustomTokenRepository) MarkTokenRotated(ctx context.Context, token string, ttl time.Duration) error {
	if token == "" {
		return fmt.Errorf("token cannot be empty")
	}
	if ttl <= 0 {
		return fmt.Errorf("ttl must be positive")
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	r.rotated[hashCustomToken(token)] = customEntry{expiresAt: time.Now().Add(ttl)}
	return nil
}

// MarkTokenRotatedAtomic is the one method where correctness genuinely depends on the
// backend, not just on copying this shape. The check-then-write below is atomic here only
// because the whole operation holds a single Go mutex for its entire duration within one
// process. A real database-backed implementation cannot rely on an in-process mutex (other
// processes/replicas share the same data) and needs the database's own atomicity guarantee
// instead — see the type doc comment above for pointers to how this codebase's Postgres/
// MongoDB implementations do that.
func (r *CustomTokenRepository) MarkTokenRotatedAtomic(ctx context.Context, token string, ttl time.Duration) (bool, error) {
	if token == "" {
		return false, fmt.Errorf("token cannot be empty")
	}
	if ttl <= 0 {
		return false, fmt.Errorf("ttl must be positive")
	}

	key := hashCustomToken(token)

	r.mu.Lock()
	defer r.mu.Unlock()

	if existing, ok := r.rotated[key]; ok && time.Now().Before(existing.expiresAt) {
		return false, nil // already rotated, and that rotation record hasn't expired yet
	}
	r.rotated[key] = customEntry{expiresAt: time.Now().Add(ttl)}
	return true, nil
}

func (r *CustomTokenRepository) IsTokenRotated(ctx context.Context, token string) (bool, error) {
	if token == "" {
		return false, fmt.Errorf("token cannot be empty")
	}

	r.mu.RLock()
	defer r.mu.RUnlock()
	entry, ok := r.rotated[hashCustomToken(token)]
	if !ok || time.Now().After(entry.expiresAt) {
		return false, nil
	}
	return true, nil
}

func (r *CustomTokenRepository) GetRotationTTL(ctx context.Context, token string) (time.Duration, error) {
	if token == "" {
		return 0, fmt.Errorf("token cannot be empty")
	}

	r.mu.RLock()
	defer r.mu.RUnlock()
	entry, ok := r.rotated[hashCustomToken(token)]
	if !ok {
		return 0, nil
	}
	remaining := time.Until(entry.expiresAt)
	if remaining < 0 {
		return 0, nil
	}
	return remaining, nil
}

func (r *CustomTokenRepository) CleanupExpiredRevokedTokens(ctx context.Context, tokenType gourdiantoken.TokenType) error {
	prefix := string(tokenType) + ":"

	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	for key, entry := range r.revoked {
		if len(key) >= len(prefix) && key[:len(prefix)] == prefix && now.After(entry.expiresAt) {
			delete(r.revoked, key)
		}
	}
	return nil
}

func (r *CustomTokenRepository) CleanupExpiredRotatedTokens(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	for key, entry := range r.rotated {
		if now.After(entry.expiresAt) {
			delete(r.rotated, key)
		}
	}
	return nil
}

// RevokeTenant, GetTenantRevocationEpoch, and CleanupExpiredTenantRevocations back
// GourdianTokenMaker.RevokeTenant's bulk tenant-revocation feature (see the README's
// "Multi-Tenancy" section). tenantID is stored as-is, not hashed — tenant IDs aren't
// secrets the way tokens are.
func (r *CustomTokenRepository) RevokeTenant(ctx context.Context, tenantID string, ttl time.Duration) error {
	if tenantID == "" {
		return fmt.Errorf("tenant ID cannot be empty")
	}
	if ttl <= 0 {
		return fmt.Errorf("ttl must be positive")
	}

	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tenantRevocations[tenantID] = customTenantEntry{revokedAt: now, expiresAt: now.Add(ttl)}
	return nil
}

func (r *CustomTokenRepository) GetTenantRevocationEpoch(ctx context.Context, tenantID string) (time.Time, error) {
	if tenantID == "" {
		return time.Time{}, fmt.Errorf("tenant ID cannot be empty")
	}

	r.mu.RLock()
	defer r.mu.RUnlock()
	entry, ok := r.tenantRevocations[tenantID]
	if !ok || time.Now().After(entry.expiresAt) {
		return time.Time{}, nil
	}
	return entry.revokedAt, nil
}

func (r *CustomTokenRepository) CleanupExpiredTenantRevocations(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	for tenantID, entry := range r.tenantRevocations {
		if now.After(entry.expiresAt) {
			delete(r.tenantRevocations, tenantID)
		}
	}
	return nil
}

func (r *CustomTokenRepository) Stats(ctx context.Context) (map[string]interface{}, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return map[string]interface{}{
		"revoked_tokens":     int64(len(r.revoked)),
		"rotated_tokens":     int64(len(r.rotated)),
		"tenant_revocations": int64(len(r.tenantRevocations)),
	}, nil
}

// CleanupAll just needs to run every CleanupExpired* method this repository has — unlike
// MarkTokenRotatedAtomic, there's nothing backend-specific about it.
func (r *CustomTokenRepository) CleanupAll(ctx context.Context) error {
	if err := r.CleanupExpiredRevokedTokens(ctx, gourdiantoken.AccessToken); err != nil {
		return err
	}
	if err := r.CleanupExpiredRevokedTokens(ctx, gourdiantoken.RefreshToken); err != nil {
		return err
	}
	if err := r.CleanupExpiredRevokedTokens(ctx, gourdiantoken.VerificationToken); err != nil {
		return err
	}
	if err := r.CleanupExpiredRotatedTokens(ctx); err != nil {
		return err
	}
	return r.CleanupExpiredTenantRevocations(ctx)
}

// Close is not part of the TokenRepository interface (see the README's "Multi-Tenancy"/
// "Storage Backends" sections for why — Postgres's Close() has pool-ownership caveats that
// make it a poor fit for a uniform interface method), but every built-in implementation
// has its own concrete one, idempotent and safe to call more than once. A real
// datastore-backed implementation should follow the same convention.
func (r *CustomTokenRepository) Close() error {
	return nil
}

// Compile-time proof that CustomTokenRepository satisfies gourdiantoken.TokenRepository —
// if this line stops compiling after a gourdiantoken upgrade, the interface changed and
// this reference implementation (and yours) needs updating to match.
var _ gourdiantoken.TokenRepository = (*CustomTokenRepository)(nil)
