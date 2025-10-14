// File: pkg/gourdiantoken/gourdiantoken.repository.mongo.imp.go

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
	mongoRevokedCollectionName = "revoked_tokens"
	mongoRotatedCollectionName = "rotated_tokens"
)

// tokenDocument represents a token entry in MongoDB
type tokenDocument struct {
	TokenHash string    `bson:"token_hash"`
	TokenType string    `bson:"token_type,omitempty"`
	ExpiresAt time.Time `bson:"expires_at"`
	CreatedAt time.Time `bson:"created_at"`
}

type MongoTokenRepository struct {
	revokedCollection *mongo.Collection
	rotatedCollection *mongo.Collection
	useTransactions   bool
}

// NewMongoTokenRepository creates a new MongoDB-based token repository
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

	// Create indexes
	if err := createMongoIndexes(ctx, revokedCollection, rotatedCollection); err != nil {
		return nil, fmt.Errorf("failed to create indexes: %w", err)
	}

	return &MongoTokenRepository{
		revokedCollection: revokedCollection,
		rotatedCollection: rotatedCollection,
		useTransactions:   useTransactions,
	}, nil
}

// createMongoIndexes creates necessary indexes for optimal performance
func createMongoIndexes(ctx context.Context, revokedCol, rotatedCol *mongo.Collection) error {
	// Index for revoked tokens with TTL
	revokedIndexes := []mongo.IndexModel{
		{
			Keys:    bson.D{{Key: "token_hash", Value: 1}},
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

	return nil
}

// withTransaction executes a function within a database transaction if transactions are enabled
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

// MarkTokenRevoke marks a token as revoked by storing its hash
func (r *MongoTokenRepository) MarkTokenRevoke(ctx context.Context, tokenType TokenType, token string, ttl time.Duration) error {
	if token == "" {
		return fmt.Errorf("token cannot be empty")
	}

	if ttl <= 0 {
		return fmt.Errorf("ttl must be positive")
	}

	tokenHash := hashToken(token)
	doc := tokenDocument{
		TokenHash: tokenHash,
		TokenType: string(tokenType),
		ExpiresAt: time.Now().Add(ttl),
		CreatedAt: time.Now(),
	}

	return r.withTransaction(ctx, func(sessionCtx mongo.SessionContext) error {
		_, err := r.revokedCollection.InsertOne(sessionCtx, doc)
		if err != nil {
			if mongo.IsDuplicateKeyError(err) {
				// Token already revoked, update expiry
				filter := bson.M{"token_hash": tokenHash}
				update := bson.M{
					"$set": bson.M{
						"expires_at": doc.ExpiresAt,
						"token_type": string(tokenType),
					},
				}
				_, err = r.revokedCollection.UpdateOne(sessionCtx, filter, update)
				if err != nil {
					return fmt.Errorf("failed to update revoked token: %w", err)
				}
				return nil
			}
			return fmt.Errorf("failed to insert revoked token: %w", err)
		}
		return nil
	})
}

// IsTokenRevoked checks if a token has been revoked by checking its hash
func (r *MongoTokenRepository) IsTokenRevoked(ctx context.Context, tokenType TokenType, token string) (bool, error) {
	if token == "" {
		return false, fmt.Errorf("token cannot be empty")
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

// MarkTokenRotated marks a token as rotated by storing its hash
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
		_, err := r.rotatedCollection.InsertOne(sessionCtx, doc)
		if err != nil {
			if mongo.IsDuplicateKeyError(err) {
				// Token already rotated, update expiry
				filter := bson.M{"token_hash": tokenHash}
				update := bson.M{
					"$set": bson.M{
						"expires_at": doc.ExpiresAt,
					},
				}
				_, err = r.rotatedCollection.UpdateOne(sessionCtx, filter, update)
				if err != nil {
					return fmt.Errorf("failed to update rotated token: %w", err)
				}
				return nil
			}
			return fmt.Errorf("failed to insert rotated token: %w", err)
		}
		return nil
	})
}

// IsTokenRotated checks if a token has been rotated by checking its hash
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

// GetRotationTTL returns the remaining TTL for a rotated token
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

// CleanupExpiredRevokedTokens removes expired revoked tokens from MongoDB
// Note: MongoDB TTL indexes handle this automatically, but this method
// provides manual cleanup if needed
func (r *MongoTokenRepository) CleanupExpiredRevokedTokens(ctx context.Context, tokenType TokenType) error {
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

// CleanupExpiredRotatedTokens removes expired rotated tokens from MongoDB
// Note: MongoDB TTL indexes handle this automatically, but this method
// provides manual cleanup if needed
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

// Stats returns statistics about the repository
// Useful for monitoring and debugging
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

	return map[string]interface{}{
		"total_revoked_tokens":   revokedCount,
		"revoked_access_tokens":  accessCount,
		"revoked_refresh_tokens": refreshCount,
		"rotated_tokens":         rotatedCount,
	}, nil
}

// Close performs cleanup operations
func (r *MongoTokenRepository) Close(ctx context.Context) error {
	// MongoDB doesn't require explicit connection closing for collections
	// The client manages connections
	return nil
}
