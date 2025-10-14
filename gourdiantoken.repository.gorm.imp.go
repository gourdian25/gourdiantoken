// File: gourdiantoken.repository.gorm.imp.go

package gourdiantoken

import (
	"context"
	"errors"
	"fmt"
	"time"

	"gorm.io/gorm"
)

// RevokedTokenType represents a revoked token in the database
type RevokedTokenType struct {
	ID        uint      `gorm:"primaryKey;autoIncrement"`
	TokenHash string    `gorm:"uniqueIndex:idx_token_hash;type:varchar(64);not null"`
	TokenType string    `gorm:"index:idx_token_type;type:varchar(20);not null"`
	ExpiresAt time.Time `gorm:"index:idx_expires_at;not null"`
	CreatedAt time.Time `gorm:"not null"`
}

// TableName specifies the table name for RevokedTokenType
func (RevokedTokenType) TableName() string {
	return "revoked_tokens"
}

// RotatedTokenType represents a rotated token in the database
type RotatedTokenType struct {
	ID        uint      `gorm:"primaryKey;autoIncrement"`
	TokenHash string    `gorm:"uniqueIndex:idx_rotated_token_hash;type:varchar(64);not null"`
	ExpiresAt time.Time `gorm:"index:idx_rotated_expires_at;not null"`
	CreatedAt time.Time `gorm:"not null"`
}

// TableName specifies the table name for RotatedTokenType
func (RotatedTokenType) TableName() string {
	return "rotated_tokens"
}

type GormTokenRepository struct {
	db *gorm.DB
}

// NewGormTokenRepository creates a new GORM-based token repository
func NewGormTokenRepository(db *gorm.DB) (TokenRepository, error) {
	if db == nil {
		return nil, fmt.Errorf("database cannot be nil")
	}

	// Test the connection
	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("failed to get underlying sql.DB: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := sqlDB.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("database connection failed: %w", err)
	}

	// Auto-migrate tables
	if err := db.AutoMigrate(&RevokedTokenType{}, &RotatedTokenType{}); err != nil {
		return nil, fmt.Errorf("failed to migrate tables: %w", err)
	}

	return &GormTokenRepository{
		db: db,
	}, nil
}

// withTransaction executes a function within a database transaction
func (r *GormTokenRepository) withTransaction(ctx context.Context, fn func(tx *gorm.DB) error) error {
	tx := r.db.WithContext(ctx).Begin()
	if tx.Error != nil {
		return fmt.Errorf("failed to begin transaction: %w", tx.Error)
	}

	if err := fn(tx); err != nil {
		tx.Rollback()
		return err
	}

	if err := tx.Commit().Error; err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// MarkTokenRevoke marks a token as revoked by storing its hash
func (r *GormTokenRepository) MarkTokenRevoke(ctx context.Context, tokenType TokenType, token string, ttl time.Duration) error {
	if token == "" {
		return fmt.Errorf("token cannot be empty")
	}

	if ttl <= 0 {
		return fmt.Errorf("ttl must be positive")
	}

	tokenHash := hashToken(token)
	model := RevokedTokenType{
		TokenHash: tokenHash,
		TokenType: string(tokenType),
		ExpiresAt: time.Now().Add(ttl),
		CreatedAt: time.Now(),
	}

	return r.withTransaction(ctx, func(tx *gorm.DB) error {
		// Try to create the record
		result := tx.Create(&model)
		if result.Error != nil {
			// Check if it's a duplicate key error
			if errors.Is(result.Error, gorm.ErrDuplicatedKey) {
				// Update the existing record
				updateResult := tx.Model(&RevokedTokenType{}).
					Where("token_hash = ?", tokenHash).
					Updates(map[string]interface{}{
						"expires_at": model.ExpiresAt,
						"token_type": string(tokenType),
					})

				if updateResult.Error != nil {
					return fmt.Errorf("failed to update revoked token: %w", updateResult.Error)
				}

				return nil
			}
			return fmt.Errorf("failed to create revoked token: %w", result.Error)
		}

		return nil
	})
}

// IsTokenRevoked checks if a token has been revoked by checking its hash
func (r *GormTokenRepository) IsTokenRevoked(ctx context.Context, tokenType TokenType, token string) (bool, error) {
	if token == "" {
		return false, fmt.Errorf("token cannot be empty")
	}

	tokenHash := hashToken(token)

	var count int64
	err := r.db.WithContext(ctx).
		Model(&RevokedTokenType{}).
		Where("token_hash = ? AND token_type = ? AND expires_at > ?", tokenHash, string(tokenType), time.Now()).
		Count(&count).Error

	if err != nil {
		return false, fmt.Errorf("database error: %w", err)
	}

	return count > 0, nil
}

// MarkTokenRotated marks a token as rotated by storing its hash
func (r *GormTokenRepository) MarkTokenRotated(ctx context.Context, token string, ttl time.Duration) error {
	if token == "" {
		return fmt.Errorf("token cannot be empty")
	}

	if ttl <= 0 {
		return fmt.Errorf("ttl must be positive")
	}

	tokenHash := hashToken(token)
	model := RotatedTokenType{
		TokenHash: tokenHash,
		ExpiresAt: time.Now().Add(ttl),
		CreatedAt: time.Now(),
	}

	return r.withTransaction(ctx, func(tx *gorm.DB) error {
		// Try to create the record
		result := tx.Create(&model)
		if result.Error != nil {
			// Check if it's a duplicate key error
			if errors.Is(result.Error, gorm.ErrDuplicatedKey) {
				// Update the existing record
				updateResult := tx.Model(&RotatedTokenType{}).
					Where("token_hash = ?", tokenHash).
					Update("expires_at", model.ExpiresAt)

				if updateResult.Error != nil {
					return fmt.Errorf("failed to update rotated token: %w", updateResult.Error)
				}

				return nil
			}
			return fmt.Errorf("failed to create rotated token: %w", result.Error)
		}

		return nil
	})
}

// IsTokenRotated checks if a token has been rotated by checking its hash
func (r *GormTokenRepository) IsTokenRotated(ctx context.Context, token string) (bool, error) {
	if token == "" {
		return false, fmt.Errorf("token cannot be empty")
	}

	tokenHash := hashToken(token)

	var count int64
	err := r.db.WithContext(ctx).
		Model(&RotatedTokenType{}).
		Where("token_hash = ? AND expires_at > ?", tokenHash, time.Now()).
		Count(&count).Error

	if err != nil {
		return false, fmt.Errorf("database error: %w", err)
	}

	return count > 0, nil
}

// GetRotationTTL returns the remaining TTL for a rotated token
func (r *GormTokenRepository) GetRotationTTL(ctx context.Context, token string) (time.Duration, error) {
	if token == "" {
		return 0, fmt.Errorf("token cannot be empty")
	}

	tokenHash := hashToken(token)

	var model RotatedTokenType
	err := r.db.WithContext(ctx).
		Where("token_hash = ?", tokenHash).
		First(&model).Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return 0, nil
		}
		return 0, fmt.Errorf("database error: %w", err)
	}

	remaining := time.Until(model.ExpiresAt)
	if remaining < 0 {
		return 0, nil
	}

	return remaining, nil
}

// CleanupExpiredRevokedTokens removes expired revoked tokens from the database
func (r *GormTokenRepository) CleanupExpiredRevokedTokens(ctx context.Context, tokenType TokenType) error {
	return r.withTransaction(ctx, func(tx *gorm.DB) error {
		result := tx.Where("token_type = ? AND expires_at <= ?", string(tokenType), time.Now()).
			Delete(&RevokedTokenType{})

		if result.Error != nil {
			return fmt.Errorf("failed to cleanup expired revoked tokens: %w", result.Error)
		}

		if result.RowsAffected > 0 {
			fmt.Printf("Cleaned up %d expired revoked %s tokens\n", result.RowsAffected, tokenType)
		}

		return nil
	})
}

// CleanupExpiredRotatedTokens removes expired rotated tokens from the database
func (r *GormTokenRepository) CleanupExpiredRotatedTokens(ctx context.Context) error {
	return r.withTransaction(ctx, func(tx *gorm.DB) error {
		result := tx.Where("expires_at <= ?", time.Now()).
			Delete(&RotatedTokenType{})

		if result.Error != nil {
			return fmt.Errorf("failed to cleanup expired rotated tokens: %w", result.Error)
		}

		if result.RowsAffected > 0 {
			fmt.Printf("Cleaned up %d expired rotated tokens\n", result.RowsAffected)
		}

		return nil
	})
}

// Stats returns statistics about the repository
// Useful for monitoring and debugging
func (r *GormTokenRepository) Stats(ctx context.Context) (map[string]interface{}, error) {
	var totalRevoked int64
	if err := r.db.WithContext(ctx).Model(&RevokedTokenType{}).Count(&totalRevoked).Error; err != nil {
		return nil, fmt.Errorf("failed to count revoked tokens: %w", err)
	}

	var accessCount int64
	if err := r.db.WithContext(ctx).
		Model(&RevokedTokenType{}).
		Where("token_type = ?", string(AccessToken)).
		Count(&accessCount).Error; err != nil {
		return nil, fmt.Errorf("failed to count access tokens: %w", err)
	}

	var refreshCount int64
	if err := r.db.WithContext(ctx).
		Model(&RevokedTokenType{}).
		Where("token_type = ?", string(RefreshToken)).
		Count(&refreshCount).Error; err != nil {
		return nil, fmt.Errorf("failed to count refresh tokens: %w", err)
	}

	var rotatedCount int64
	if err := r.db.WithContext(ctx).Model(&RotatedTokenType{}).Count(&rotatedCount).Error; err != nil {
		return nil, fmt.Errorf("failed to count rotated tokens: %w", err)
	}

	return map[string]interface{}{
		"total_revoked_tokens":   totalRevoked,
		"revoked_access_tokens":  accessCount,
		"revoked_refresh_tokens": refreshCount,
		"rotated_tokens":         rotatedCount,
	}, nil
}

// CleanupAll removes all expired tokens (both revoked and rotated)
func (r *GormTokenRepository) CleanupAll(ctx context.Context) error {
	if err := r.CleanupExpiredRevokedTokens(ctx, AccessToken); err != nil {
		return fmt.Errorf("failed to cleanup access tokens: %w", err)
	}

	if err := r.CleanupExpiredRevokedTokens(ctx, RefreshToken); err != nil {
		return fmt.Errorf("failed to cleanup refresh tokens: %w", err)
	}

	if err := r.CleanupExpiredRotatedTokens(ctx); err != nil {
		return fmt.Errorf("failed to cleanup rotated tokens: %w", err)
	}

	return nil
}

// Close performs cleanup operations
func (r *GormTokenRepository) Close() error {
	sqlDB, err := r.db.DB()
	if err != nil {
		return fmt.Errorf("failed to get underlying sql.DB: %w", err)
	}

	return sqlDB.Close()
}
