// File: gourdiantoken.repository.mongo.imp.go

package gourdiantoken

import (
	"context"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const (
	mongoRevokedCollectionName           = "gourdiantoken_revoked_tokens"
	mongoRotatedCollectionName           = "gourdiantoken_rotated_tokens"
	mongoTenantRevocationsCollectionName = "gourdiantoken_tenant_revocations"
)

// tokenDocument represents a token entry in MongoDB.
// Uses BSON tags for MongoDB field mapping and efficient storage.
//
// Document Structure:
//   - token_hash: SHA-256 hash of the token (64 chars) - indexed field
//   - token_type: "access", "refresh", or "verification" - used for composite indexing
//   - expires_at: Expiration timestamp - TTL index for automatic cleanup
//   - created_at: Creation timestamp for auditing and monitoring
//
// Storage Efficiency:
//   - BSON encoding is space-efficient for time.Time fields
//   - Fixed-size hash storage (64 bytes vs variable token size)
//   - Automatic TTL cleanup prevents collection bloat
//   - Indexed fields enable fast queries
//
// MongoDB Features Utilized:
//   - TTL indexes for automatic document expiration
//   - Composite indexes for unique constraint enforcement
//   - ReplaceOne with upsert for atomic operations
//   - Transactions for multi-document consistency
type tokenDocument struct {
	TokenHash string    `bson:"token_hash"`
	TokenType string    `bson:"token_type,omitempty"`
	ExpiresAt time.Time `bson:"expires_at"`
	CreatedAt time.Time `bson:"created_at"`
}

// tenantRevocationDocument represents a bulk tenant-revocation epoch in MongoDB.
// tenant_id is the document's natural key (not hashed, unlike token_hash above), since
// tenant IDs aren't secrets the way tokens are.
type tenantRevocationDocument struct {
	TenantID  string    `bson:"tenant_id"`
	RevokedAt time.Time `bson:"revoked_at"`
	ExpiresAt time.Time `bson:"expires_at"`
}

// MongoTokenRepository implements TokenRepository using MongoDB.
// This repository provides document-based storage for token revocation and rotation data.
//
// Architecture Features:
//   - Document-oriented storage with flexible schema
//   - Automatic TTL-based expiration via MongoDB indexes
//   - Transaction support for multi-operation consistency
//   - Composite indexes for optimal query performance
//   - Connection pooling via MongoDB driver
//
// Performance Characteristics:
//   - Sub-millisecond reads with proper indexing
//   - Efficient bulk operations for cleanup
//   - Horizontal scaling via MongoDB sharding
//   - Built-in replication for high availability
//
// MongoDB Version Requirements:
//   - MongoDB 4.0+ for transaction support (recommended 4.2+)
//   - TTL index support (available since MongoDB 2.2)
//   - Composite index support for unique constraints
//
// Production Considerations:
//   - Configure proper replica sets for production
//   - Set appropriate read/write concerns
//   - Monitor collection sizes and index usage
//   - Consider sharding for very high throughput
//   - Implement connection string with retry logic
type MongoTokenRepository struct {
	revokedCollection           *mongo.Collection
	rotatedCollection           *mongo.Collection
	tenantRevocationsCollection *mongo.Collection
	useTransactions             bool
}

// NewMongoTokenRepository creates a new MongoDB-based token repository.
// Performs connection testing, index creation, and collection validation.
//
// Prerequisites:
//   - MongoDB database instance must be properly initialized
//   - Database user must have index creation privileges
//   - Network connectivity to MongoDB server/cluster
//   - Sufficient connection pool size in MongoDB driver
//
// Initialization Steps:
//  1. Validate database connection is not nil
//  2. Test MongoDB connectivity with 5-second timeout
//  3. Create TTL and composite indexes for optimal performance
//  4. Configure transaction usage based on parameter
//  5. Return initialized repository instance
//
// Parameters:
//   - db: Initialized MongoDB database instance from official driver
//   - useTransactions: Whether to use MongoDB transactions for multi-document operations.
//     Recommended for production with replica sets. Disable for standalone instances.
//
// Returns:
//   - TokenRepository: Initialized MongoDB repository instance
//   - error: If connection fails, index creation fails, or context times out
//
// Example (Production with transactions):
//
//	// Initialize MongoDB client with connection pooling
//	client, err := mongo.Connect(ctx, options.Client().
//	    ApplyURI(mongoURI).
//	    SetMaxPoolSize(100).
//	    SetMinPoolSize(10))
//	if err != nil {
//	    return err
//	}
//
//	db := client.Database("auth_service")
//	repo, err := NewMongoTokenRepository(db, true) // Enable transactions
//	if err != nil {
//	    return fmt.Errorf("failed to create MongoDB token repository: %w", err)
//	}
//
// Example (Development without transactions):
//
//	client, err := mongo.Connect(ctx, options.Client().ApplyURI("mongodb://localhost:27017"))
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	db := client.Database("dev_auth")
//	repo, err := NewMongoTokenRepository(db, false) // Disable transactions for standalone
//	if err != nil {
//	    log.Fatal(err)
//	}
//
// Index Creation Details:
//   - Creates composite unique index on (token_hash, token_type) for revoked tokens
//   - Creates TTL index on expires_at for automatic document expiration
//   - Creates individual index on token_type for efficient filtering
//   - Creates unique index on token_hash for rotated tokens
func NewMongoTokenRepository(db *mongo.Database, useTransactions bool) (TokenRepository, error) {
	if db == nil {
		return nil, fmt.Errorf("database cannot be nil")
	}

	// Test the connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := db.Client().Ping(ctx, nil); err != nil {
		return nil, fmt.Errorf("mongodb connection failed: %w", err)
	}

	revokedCollection := db.Collection(mongoRevokedCollectionName)
	rotatedCollection := db.Collection(mongoRotatedCollectionName)
	tenantRevocationsCollection := db.Collection(mongoTenantRevocationsCollectionName)

	// Create indexes
	if err := createMongoIndexes(ctx, revokedCollection, rotatedCollection, tenantRevocationsCollection); err != nil {
		return nil, fmt.Errorf("failed to create indexes: %w", err)
	}

	return &MongoTokenRepository{
		revokedCollection:           revokedCollection,
		rotatedCollection:           rotatedCollection,
		tenantRevocationsCollection: tenantRevocationsCollection,
		useTransactions:             useTransactions,
	}, nil
}

// createMongoIndexes creates necessary indexes for optimal performance.
// This function is called during repository initialization.
//
// Index Strategy:
//   - Composite unique index for revoked tokens: (token_hash, token_type)
//     Prevents duplicate revocations and enables fast lookups
//   - TTL index on expires_at: Automatically removes expired documents
//   - Individual index on token_type: Enables efficient filtering by token type
//   - Unique index on rotated tokens token_hash: Prevents duplicate rotations
//
// TTL Index Behavior:
//   - MongoDB automatically deletes documents when expires_at is reached
//   - TTL monitor runs every 60 seconds
//   - SetExpireAfterSeconds(0) means use the expires_at value directly
//   - Documents are removed during normal database operations
//
// Performance Impact:
//   - Index creation is a one-time operation
//   - Indexes significantly improve query performance
//   - TTL indexes prevent collection bloat
//   - Write operations include index maintenance overhead
func createMongoIndexes(ctx context.Context, revokedCol, rotatedCol, tenantRevocationsCol *mongo.Collection) error {
	// Index for revoked tokens with TTL and composite unique key
	revokedIndexes := []mongo.IndexModel{
		{
			// Composite unique index on token_hash AND token_type
			Keys:    bson.D{{Key: "token_hash", Value: 1}, {Key: "token_type", Value: 1}},
			Options: options.Index().SetUnique(true),
		},
		{
			Keys:    bson.D{{Key: "expires_at", Value: 1}},
			Options: options.Index().SetExpireAfterSeconds(0),
		},
		{
			Keys: bson.D{{Key: "token_type", Value: 1}},
		},
	}

	if _, err := revokedCol.Indexes().CreateMany(ctx, revokedIndexes); err != nil {
		return fmt.Errorf("failed to create revoked token indexes: %w", err)
	}

	// Index for rotated tokens with TTL
	rotatedIndexes := []mongo.IndexModel{
		{
			Keys:    bson.D{{Key: "token_hash", Value: 1}},
			Options: options.Index().SetUnique(true),
		},
		{
			Keys:    bson.D{{Key: "expires_at", Value: 1}},
			Options: options.Index().SetExpireAfterSeconds(0),
		},
	}

	if _, err := rotatedCol.Indexes().CreateMany(ctx, rotatedIndexes); err != nil {
		return fmt.Errorf("failed to create rotated token indexes: %w", err)
	}

	// Index for tenant revocations: unique on tenant_id (one active epoch per tenant) plus
	// TTL on expires_at, matching the dual-index pattern above.
	tenantRevocationsIndexes := []mongo.IndexModel{
		{
			Keys:    bson.D{{Key: "tenant_id", Value: 1}},
			Options: options.Index().SetUnique(true),
		},
		{
			Keys:    bson.D{{Key: "expires_at", Value: 1}},
			Options: options.Index().SetExpireAfterSeconds(0),
		},
	}

	if _, err := tenantRevocationsCol.Indexes().CreateMany(ctx, tenantRevocationsIndexes); err != nil {
		return fmt.Errorf("failed to create tenant revocation indexes: %w", err)
	}

	return nil
}

// withTransaction executes a function within a database transaction if transactions are enabled.
// Provides transaction abstraction for MongoDB operations.
//
// Transaction Behavior:
//   - If useTransactions is false, executes function without transaction
//   - If useTransactions is true, wraps function in MongoDB transaction
//   - Transactions require replica set configuration
//   - Automatic session management and cleanup
//
// Use Cases for Transactions:
//   - Multi-document atomic operations
//   - Ensuring consistency across related operations
//   - Production environments with replica sets
//
// Limitations:
//   - Transactions not supported on standalone MongoDB instances
//   - Additional performance overhead
//   - Requires proper replica set configuration
//
// Parameters:
//   - ctx: Context for cancellation and timeout
//   - fn: Function to execute within transaction context
//
// Returns:
//   - error: If transaction fails or wrapped function returns error
func (r *MongoTokenRepository) withTransaction(ctx context.Context, fn func(sessionCtx mongo.SessionContext) error) error {
	if !r.useTransactions {
		return fn(nil)
	}

	session, err := r.revokedCollection.Database().Client().StartSession()
	if err != nil {
		return fmt.Errorf("failed to start session: %w", err)
	}
	defer session.EndSession(ctx)

	transactionFn := func(sessionCtx mongo.SessionContext) (interface{}, error) {
		return nil, fn(sessionCtx)
	}

	_, err = session.WithTransaction(ctx, transactionFn)
	return err
}

// MarkTokenRevoke marks a token as revoked by storing its hash in MongoDB.
// Uses composite unique key (token_hash, token_type) for proper upsert behavior.
//
// MongoDB Operation:
//   - Uses ReplaceOne with upsert for atomic create-or-update
//   - Composite unique index prevents duplicate entries
//   - Transaction wrapper ensures operation consistency
//   - Automatic TTL via index handles expiration
//
// Performance Characteristics:
//   - Single document write operation
//   - Indexed fields enable fast conflict detection
//   - Upsert operation is atomic at document level
//   - Transaction overhead if enabled
//
// Security Implementation:
//   - Only token hash stored, never actual token
//   - Composite key ensures type-specific revocation
//   - Automatic expiration prevents permanent storage
//
// Parameters:
//   - ctx: Context for cancellation and timeout
//   - tokenType: Type of token (AccessToken or RefreshToken)
//   - token: The actual token string to revoke
//   - ttl: Time-to-live duration for the revocation record
//
// Returns:
//   - error: If token is empty, TTL is invalid, token type is invalid,
//     or database operation fails
//
// Example (Revoke access token):
//
//	err := repo.MarkTokenRevoke(ctx, AccessToken, "jwt-token-here", 15*time.Minute)
//	if err != nil {
//	    return fmt.Errorf("failed to revoke token: %w", err)
//	}
//
// MongoDB Query:
//
//	db.revoked_tokens.replaceOne(
//	  { token_hash: "hash", token_type: "access" },
//	  { token_hash: "hash", token_type: "access", expires_at: ISODate(), created_at: ISODate() },
//	  { upsert: true }
//	)
func (r *MongoTokenRepository) MarkTokenRevoke(ctx context.Context, tokenType TokenType, token string, ttl time.Duration) error {
	if token == "" {
		return fmt.Errorf("token cannot be empty")
	}

	if ttl <= 0 {
		return fmt.Errorf("ttl must be positive")
	}

	// Validate token type
	if tokenType != AccessToken && tokenType != RefreshToken && tokenType != VerificationToken {
		return fmt.Errorf("invalid token type: %s", tokenType)
	}

	tokenHash := hashToken(token)
	doc := tokenDocument{
		TokenHash: tokenHash,
		TokenType: string(tokenType),
		ExpiresAt: time.Now().Add(ttl),
		CreatedAt: time.Now(),
	}

	return r.withTransaction(ctx, func(sessionCtx mongo.SessionContext) error {
		opts := options.Replace().SetUpsert(true)
		// Filter by BOTH token_hash AND token_type for proper composite key behavior
		filter := bson.M{"token_hash": tokenHash, "token_type": string(tokenType)}

		_, err := r.revokedCollection.ReplaceOne(sessionCtx, filter, doc, opts)
		if err != nil {
			return fmt.Errorf("failed to mark token as revoked: %w", err)
		}
		return nil
	})
}

// IsTokenRevoked checks if a token has been revoked by checking its hash in MongoDB.
// Performs efficient document lookup using composite index and expiration filter.
//
// Query Optimization:
//   - Uses composite index (token_hash, token_type) for fast lookups
//   - Additional filter on expires_at leverages TTL index
//   - Single document read operation
//   - FindOne returns at most one document
//
// Performance Characteristics:
//   - O(1) average case with proper indexing
//   - Index-only query possible with covered indexes
//   - Read operation with minimal locking
//   - No transaction overhead for reads
//
// Parameters:
//   - ctx: Context for cancellation and timeout
//   - tokenType: Type of token to check (AccessToken or RefreshToken)
//   - token: The token string to check for revocation
//
// Returns:
//   - bool: True if token is revoked and not expired, false otherwise
//   - error: If token is empty, token type is invalid, or database operation fails
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
// MongoDB Query:
//
//	db.revoked_tokens.findOne({
//	  token_hash: "hash",
//	  token_type: "access",
//	  expires_at: { $gt: ISODate() }
//	})
func (r *MongoTokenRepository) IsTokenRevoked(ctx context.Context, tokenType TokenType, token string) (bool, error) {
	if token == "" {
		return false, fmt.Errorf("token cannot be empty")
	}

	// Validate token type
	if tokenType != AccessToken && tokenType != RefreshToken && tokenType != VerificationToken {
		return false, fmt.Errorf("invalid token type: %s", tokenType)
	}

	tokenHash := hashToken(token)
	filter := bson.M{
		"token_hash": tokenHash,
		"token_type": string(tokenType),
		"expires_at": bson.M{"$gt": time.Now()},
	}

	var doc tokenDocument
	err := r.revokedCollection.FindOne(ctx, filter).Decode(&doc)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return false, nil
		}
		return false, fmt.Errorf("mongodb error: %w", err)
	}

	return true, nil
}

// MarkTokenRotated marks a token as rotated by storing its hash in MongoDB.
// Uses upsert operation for idempotent rotation tracking.
//
// Security Purpose:
//   - Prevents replay of rotated refresh tokens
//   - Enables one-time use during token rotation flow
//   - Protects against token replay attacks
//
// MongoDB Operation:
//   - ReplaceOne with upsert on token_hash field
//   - Unique index prevents duplicate rotations
//   - Transaction wrapper ensures operation consistency
//   - Automatic TTL via index handles expiration
//
// Parameters:
//   - ctx: Context for cancellation and timeout
//   - token: The refresh token being rotated
//   - ttl: Time-to-live duration for rotation record
//
// Returns:
//   - error: If token is empty, TTL is invalid, or database operation fails
//
// Example (Mark token as rotated):
//
//	err := repo.MarkTokenRotated(ctx, "old-refresh-token", 7*24*time.Hour)
//	if err != nil {
//	    return fmt.Errorf("failed to mark token as rotated: %w", err)
//	}
//
// MongoDB Query:
//
//	db.rotated_tokens.replaceOne(
//	  { token_hash: "hash" },
//	  { token_hash: "hash", expires_at: ISODate(), created_at: ISODate() },
//	  { upsert: true }
//	)
func (r *MongoTokenRepository) MarkTokenRotated(ctx context.Context, token string, ttl time.Duration) error {
	if token == "" {
		return fmt.Errorf("token cannot be empty")
	}

	if ttl <= 0 {
		return fmt.Errorf("ttl must be positive")
	}

	tokenHash := hashToken(token)
	doc := tokenDocument{
		TokenHash: tokenHash,
		ExpiresAt: time.Now().Add(ttl),
		CreatedAt: time.Now(),
	}

	return r.withTransaction(ctx, func(sessionCtx mongo.SessionContext) error {
		opts := options.Replace().SetUpsert(true)
		filter := bson.M{"token_hash": tokenHash}

		_, err := r.rotatedCollection.ReplaceOne(sessionCtx, filter, doc, opts)
		if err != nil {
			return fmt.Errorf("failed to mark token as rotated: %w", err)
		}
		return nil
	})
}

// MarkTokenRotatedAtomic marks a token as rotated atomically, returning whether it was newly
// rotated. Uses a conditional upsert (UpdateOne with upsert=true, filtered on the existing
// document — if any — already being expired) rather than a blind InsertOne, so re-marking a
// token whose *previous* rotation entry already expired succeeds instead of being rejected as
// a duplicate.
//
// Key Difference from MarkTokenRotated:
//   - Returns boolean indicating if rotation was actually performed
//   - The upsert filter requires expires_at <= now, so a not-yet-expired existing document
//     doesn't match; MongoDB's upsert then attempts an insert, which collides with the
//     unique index on token_hash (duplicate-key error) exactly when the token is still
//     actively rotated — an expired document, by contrast, matches the filter and gets
//     updated in place
//   - Essential for preventing double-spending in rotation flows
//   - Provides true atomicity for rotation detection
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
//   - bool: True if token was newly rotated, false if already rotated (and not yet expired)
//   - error: If token is empty, TTL is invalid, or database operation fails
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
//	// Proceed with issuing new tokens
//
// MongoDB Operation:
//
//	db.rotated_tokens.updateOne(
//	  { token_hash: "hash", expires_at: { $lte: ISODate() } },
//	  { $set: { token_hash: "hash", expires_at: ISODate(), created_at: ISODate() } },
//	  { upsert: true }
//	)
//	// The upsert's implicit insert fails with a duplicate-key error if a
//	// not-yet-expired document with the same token_hash already exists.
func (r *MongoTokenRepository) MarkTokenRotatedAtomic(ctx context.Context, token string, ttl time.Duration) (bool, error) {
	if token == "" {
		return false, fmt.Errorf("token cannot be empty")
	}

	if ttl <= 0 {
		return false, fmt.Errorf("ttl must be positive")
	}

	tokenHash := hashToken(token)
	now := time.Now()
	doc := tokenDocument{
		TokenHash: tokenHash,
		ExpiresAt: now.Add(ttl),
		CreatedAt: now,
	}

	err := r.withTransaction(ctx, func(sessionCtx mongo.SessionContext) error {
		filter := bson.M{
			"token_hash": tokenHash,
			"expires_at": bson.M{"$lte": now},
		}
		opts := options.Update().SetUpsert(true)
		_, err := r.rotatedCollection.UpdateOne(sessionCtx, filter, bson.M{"$set": doc}, opts)
		return err
	})

	if err != nil {
		// Duplicate-key detection happens here, at the transaction boundary, rather than
		// inside the callback above: a write error surfaced to the driver mid-transaction
		// can cause the server to abort the transaction regardless of the callback's return
		// value, making commit behavior driver-version-dependent if handled internally.
		// Checking after withTransaction returns means the transaction has already been
		// aborted/rolled back, and "already rotated by someone else" is decided cleanly at
		// the outer boundary — the same pattern Redis's SetNX and Postgres's ON CONFLICT use.
		if mongo.IsDuplicateKeyError(err) {
			return false, nil
		}
		return false, fmt.Errorf("failed to mark token as rotated: %w", err)
	}

	return true, nil
}

// IsTokenRotated checks if a token has been rotated by checking its hash in MongoDB.
// Performs efficient document lookup with automatic expiration filtering.
//
// Security Purpose:
//   - Detects if a refresh token has been previously rotated
//   - Prevents reuse of rotated tokens in replay attacks
//   - Essential for rotation-based security schemes
//
// Query Optimization:
//   - Uses unique index on token_hash for fast lookups
//   - Additional filter on expires_at leverages TTL index
//   - Single document read operation
//
// Parameters:
//   - ctx: Context for cancellation and timeout
//   - token: The token to check for rotation status
//
// Returns:
//   - bool: True if token has been rotated and not expired, false otherwise
//   - error: If token is empty or database operation fails
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
// MongoDB Query:
//
//	db.rotated_tokens.findOne({
//	  token_hash: "hash",
//	  expires_at: { $gt: ISODate() }
//	})
func (r *MongoTokenRepository) IsTokenRotated(ctx context.Context, token string) (bool, error) {
	if token == "" {
		return false, fmt.Errorf("token cannot be empty")
	}

	tokenHash := hashToken(token)
	filter := bson.M{
		"token_hash": tokenHash,
		"expires_at": bson.M{"$gt": time.Now()},
	}

	var doc tokenDocument
	err := r.rotatedCollection.FindOne(ctx, filter).Decode(&doc)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return false, nil
		}
		return false, fmt.Errorf("mongodb error: %w", err)
	}

	return true, nil
}

// GetRotationTTL returns the remaining TTL for a rotated token.
// Useful for debugging, monitoring, and cache optimization.
//
// Use Cases:
//   - Debugging rotation-related issues
//   - Monitoring token rotation patterns
//   - Optimizing cleanup scheduling
//   - Understanding token lifecycle
//
// Parameters:
//   - ctx: Context for cancellation and timeout
//   - token: The token to check for remaining TTL
//
// Returns:
//   - time.Duration: Remaining TTL if token is rotated and not expired, 0 otherwise
//   - error: If token is empty or database operation fails
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
// MongoDB Query:
//
//	db.rotated_tokens.findOne({ token_hash: "hash" })
func (r *MongoTokenRepository) GetRotationTTL(ctx context.Context, token string) (time.Duration, error) {
	if token == "" {
		return 0, fmt.Errorf("token cannot be empty")
	}

	tokenHash := hashToken(token)
	filter := bson.M{"token_hash": tokenHash}

	var doc tokenDocument
	err := r.rotatedCollection.FindOne(ctx, filter).Decode(&doc)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return 0, nil
		}
		return 0, fmt.Errorf("mongodb error: %w", err)
	}

	remaining := time.Until(doc.ExpiresAt)
	if remaining < 0 {
		return 0, nil
	}

	return remaining, nil
}

// CleanupExpiredRevokedTokens removes expired revoked tokens from MongoDB.
// Note: MongoDB TTL indexes handle automatic cleanup, but this provides manual control.
//
// Use Cases:
//   - Force immediate cleanup of expired documents
//   - Handle cases where TTL monitor is delayed
//   - Bulk cleanup during maintenance windows
//   - Testing and development environments
//
// Performance Characteristics:
//   - DeleteMany operation for batch processing
//   - Index on expires_at enables efficient range query
//   - Transaction wrapper ensures operation consistency
//   - Batch operation minimizes database round trips
//
// Parameters:
//   - ctx: Context for cancellation and timeout
//   - tokenType: Type of tokens to cleanup (AccessToken or RefreshToken)
//
// Returns:
//   - error: If token type is invalid or database operation fails
//
// Example (Manual cleanup):
//
//	err := repo.CleanupExpiredRevokedTokens(ctx, AccessToken)
//	if err != nil {
//	    log.Printf("Failed to cleanup access tokens: %v", err)
//	}
//
// MongoDB Operation:
//
//	db.revoked_tokens.deleteMany({
//	  token_type: "access",
//	  expires_at: { $lte: ISODate() }
//	})
func (r *MongoTokenRepository) CleanupExpiredRevokedTokens(ctx context.Context, tokenType TokenType) error {
	// Validate token type
	if tokenType != AccessToken && tokenType != RefreshToken && tokenType != VerificationToken {
		return fmt.Errorf("invalid token type: %s", tokenType)
	}

	return r.withTransaction(ctx, func(sessionCtx mongo.SessionContext) error {
		filter := bson.M{
			"token_type": string(tokenType),
			"expires_at": bson.M{"$lte": time.Now()},
		}

		result, err := r.revokedCollection.DeleteMany(sessionCtx, filter)
		if err != nil {
			return fmt.Errorf("failed to cleanup expired revoked tokens: %w", err)
		}

		if result.DeletedCount > 0 {
			fmt.Printf("Cleaned up %d expired revoked %s tokens\n", result.DeletedCount, tokenType)
		}

		return nil
	})
}

// CleanupExpiredRotatedTokens removes expired rotated tokens from MongoDB.
// Provides manual control over TTL-based automatic cleanup.
//
// Cleanup Strategy:
//   - DeleteMany operation with expires_at filter
//   - Leverages TTL index for efficient query
//   - Transaction wrapper for consistency
//   - Batch operation for efficiency
//
// Parameters:
//   - ctx: Context for cancellation and timeout
//
// Returns:
//   - error: If database operation fails
//
// Example (Scheduled manual cleanup):
//
//	// Run additional cleanup daily (TTL indexes handle most cases)
//	ticker := time.NewTicker(24 * time.Hour)
//	defer ticker.Stop()
//
//	for range ticker.C {
//	    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
//	    err := repo.CleanupExpiredRotatedTokens(ctx)
//	    cancel()
//	    if err != nil {
//	        log.Printf("Manual rotated token cleanup failed: %v", err)
//	    }
//	}
//
// MongoDB Operation:
//
//	db.rotated_tokens.deleteMany({
//	  expires_at: { $lte: ISODate() }
//	})
func (r *MongoTokenRepository) CleanupExpiredRotatedTokens(ctx context.Context) error {
	return r.withTransaction(ctx, func(sessionCtx mongo.SessionContext) error {
		filter := bson.M{
			"expires_at": bson.M{"$lte": time.Now()},
		}

		result, err := r.rotatedCollection.DeleteMany(sessionCtx, filter)
		if err != nil {
			return fmt.Errorf("failed to cleanup expired rotated tokens: %w", err)
		}

		if result.DeletedCount > 0 {
			fmt.Printf("Cleaned up %d expired rotated tokens\n", result.DeletedCount)
		}

		return nil
	})
}

// RevokeTenant records a bulk revocation epoch for tenantID in MongoDB.
// Uses ReplaceOne with upsert on tenant_id, matching MarkTokenRevoke's pattern — a newer
// RevokeTenant call for the same tenant overwrites the previous epoch rather than adding
// another document.
//
// MongoDB Query:
//
//	db.tenant_revocations.replaceOne(
//	  { tenant_id: "acme-corp" },
//	  { tenant_id: "acme-corp", revoked_at: ISODate(), expires_at: ISODate() },
//	  { upsert: true }
//	)
func (r *MongoTokenRepository) RevokeTenant(ctx context.Context, tenantID string, ttl time.Duration) error {
	if tenantID == "" {
		return fmt.Errorf("tenant ID cannot be empty")
	}

	if ttl <= 0 {
		return fmt.Errorf("ttl must be positive")
	}

	now := time.Now()
	doc := tenantRevocationDocument{
		TenantID:  tenantID,
		RevokedAt: now,
		ExpiresAt: now.Add(ttl),
	}

	return r.withTransaction(ctx, func(sessionCtx mongo.SessionContext) error {
		opts := options.Replace().SetUpsert(true)
		filter := bson.M{"tenant_id": tenantID}

		_, err := r.tenantRevocationsCollection.ReplaceOne(sessionCtx, filter, doc, opts)
		if err != nil {
			return fmt.Errorf("failed to revoke tenant: %w", err)
		}
		return nil
	})
}

// GetTenantRevocationEpoch returns the moment tenantID was last revoked, or the zero
// time.Time if the tenant has no active revocation record.
//
// MongoDB Query:
//
//	db.tenant_revocations.findOne({
//	  tenant_id: "acme-corp",
//	  expires_at: { $gt: ISODate() }
//	})
func (r *MongoTokenRepository) GetTenantRevocationEpoch(ctx context.Context, tenantID string) (time.Time, error) {
	if tenantID == "" {
		return time.Time{}, fmt.Errorf("tenant ID cannot be empty")
	}

	filter := bson.M{
		"tenant_id":  tenantID,
		"expires_at": bson.M{"$gt": time.Now()},
	}

	var doc tenantRevocationDocument
	err := r.tenantRevocationsCollection.FindOne(ctx, filter).Decode(&doc)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return time.Time{}, nil
		}
		return time.Time{}, fmt.Errorf("mongodb error: %w", err)
	}

	return doc.RevokedAt, nil
}

// CleanupExpiredTenantRevocations removes expired tenant revocation records from MongoDB.
// Note: MongoDB TTL indexes handle automatic cleanup, but this provides manual control,
// matching CleanupExpiredRevokedTokens/CleanupExpiredRotatedTokens.
func (r *MongoTokenRepository) CleanupExpiredTenantRevocations(ctx context.Context) error {
	return r.withTransaction(ctx, func(sessionCtx mongo.SessionContext) error {
		filter := bson.M{
			"expires_at": bson.M{"$lte": time.Now()},
		}

		result, err := r.tenantRevocationsCollection.DeleteMany(sessionCtx, filter)
		if err != nil {
			return fmt.Errorf("failed to cleanup expired tenant revocations: %w", err)
		}

		if result.DeletedCount > 0 {
			fmt.Printf("Cleaned up %d expired tenant revocations\n", result.DeletedCount)
		}

		return nil
	})
}

// Stats returns statistics about the repository for monitoring and debugging.
// Provides insights into token revocation and rotation patterns.
//
// Metrics Collected:
//   - Total revoked tokens (all types)
//   - Revoked access tokens count
//   - Revoked refresh tokens count
//   - Rotated tokens count
//
// Performance Characteristics:
//   - CountDocuments operations use collection statistics
//   - Efficient counting with MongoDB's metadata
//   - Separate queries for different token types
//   - No document scanning for count operations
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
//   - error: If any database count operation fails
//
// Example (Prometheus metrics export):
//
//	stats, err := repo.Stats(ctx)
//	if err != nil {
//	    log.Printf("Failed to get stats: %v", err)
//	    return
//	}
//
//	revokedTotal.Set(float64(stats["total_revoked_tokens"].(int64)))
//	rotatedCount.Set(float64(stats["rotated_tokens"].(int64)))
func (r *MongoTokenRepository) Stats(ctx context.Context) (map[string]interface{}, error) {
	revokedCount, err := r.revokedCollection.CountDocuments(ctx, bson.M{})
	if err != nil {
		return nil, fmt.Errorf("failed to count revoked tokens: %w", err)
	}

	rotatedCount, err := r.rotatedCollection.CountDocuments(ctx, bson.M{})
	if err != nil {
		return nil, fmt.Errorf("failed to count rotated tokens: %w", err)
	}

	// Count by token type
	accessCount, err := r.revokedCollection.CountDocuments(ctx, bson.M{"token_type": string(AccessToken)})
	if err != nil {
		return nil, fmt.Errorf("failed to count access tokens: %w", err)
	}

	refreshCount, err := r.revokedCollection.CountDocuments(ctx, bson.M{"token_type": string(RefreshToken)})
	if err != nil {
		return nil, fmt.Errorf("failed to count refresh tokens: %w", err)
	}

	verificationCount, err := r.revokedCollection.CountDocuments(ctx, bson.M{"token_type": string(VerificationToken)})
	if err != nil {
		return nil, fmt.Errorf("failed to count verification tokens: %w", err)
	}

	tenantRevocationCount, err := r.tenantRevocationsCollection.CountDocuments(ctx, bson.M{})
	if err != nil {
		return nil, fmt.Errorf("failed to count tenant revocations: %w", err)
	}

	return map[string]interface{}{
		"total_revoked_tokens":        revokedCount,
		"revoked_access_tokens":       accessCount,
		"revoked_refresh_tokens":      refreshCount,
		"revoked_verification_tokens": verificationCount,
		"rotated_tokens":              rotatedCount,
		"tenant_revocations":          tenantRevocationCount,
	}, nil
}

// CleanupAll runs every CleanupExpired* operation (revoked access/refresh/verification
// tokens, rotated tokens, tenant revocations) in one call. Largely redundant with this
// repository's own TTL indexes (MongoDB expires documents automatically in the background),
// but useful for callers that want cleanup to happen synchronously and immediately rather
// than waiting on MongoDB's own TTL monitor, which runs on its own ~60s cycle.
//
// Parameters:
//   - ctx: Context for cancellation and timeout
//
// Returns:
//   - error: If any underlying cleanup operation fails, with detailed context
func (r *MongoTokenRepository) CleanupAll(ctx context.Context) error {
	if err := r.CleanupExpiredRevokedTokens(ctx, AccessToken); err != nil {
		return fmt.Errorf("failed to cleanup access tokens: %w", err)
	}
	if err := r.CleanupExpiredRevokedTokens(ctx, RefreshToken); err != nil {
		return fmt.Errorf("failed to cleanup refresh tokens: %w", err)
	}
	if err := r.CleanupExpiredRevokedTokens(ctx, VerificationToken); err != nil {
		return fmt.Errorf("failed to cleanup verification tokens: %w", err)
	}
	if err := r.CleanupExpiredRotatedTokens(ctx); err != nil {
		return fmt.Errorf("failed to cleanup rotated tokens: %w", err)
	}
	if err := r.CleanupExpiredTenantRevocations(ctx); err != nil {
		return fmt.Errorf("failed to cleanup tenant revocations: %w", err)
	}
	return nil
}

// Close performs cleanup operations for the MongoDB repository.
// Note: MongoDB driver manages connection pooling automatically.
//
// Cleanup Behavior:
//   - MongoDB connections are managed by the driver
//   - No explicit connection closing needed for collections
//   - Client should be closed at application level
//   - This method exists for interface compatibility with the other three backends'
//     concrete Close() methods (not part of the TokenRepository interface itself — see
//     decision #7 in docs/plan/multi-tenant-support-plan.md)
//
// Returns:
//   - error: Always nil (included for interface compatibility)
//
// Important: While this repository doesn't require explicit closing,
// the MongoDB client should be closed during application shutdown:
//
//	defer func() {
//	    if err := client.Disconnect(ctx); err != nil {
//	        log.Printf("Failed to disconnect MongoDB: %v", err)
//	    }
//	}()
func (r *MongoTokenRepository) Close() error {
	// MongoDB doesn't require explicit connection closing for collections
	// The client manages connections
	return nil
}
