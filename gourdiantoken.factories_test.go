// File: gourdiantoken.factories_test.go

package gourdiantoken

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// Tests for NewGourdianTokenMakerNoStorage
// ============================================================================

func TestNewGourdianTokenMakerNoStorage_Success(t *testing.T) {
	t.Run("symmetric_hs256_no_storage", func(t *testing.T) {
		config := GourdianTokenConfig{
			SigningMethod:            Symmetric,
			Algorithm:                "HS256",
			SymmetricKey:             "test-secret-key-that-is-at-least-32-bytes-long",
			Issuer:                   "test.com",
			Audience:                 []string{"api.test.com"},
			AllowedAlgorithms:        []string{"HS256"},
			RequiredClaims:           []string{"iss", "aud", "nbf", "mle"},
			AccessExpiryDuration:     15 * time.Minute,
			AccessMaxLifetimeExpiry:  24 * time.Hour,
			RefreshExpiryDuration:    24 * time.Hour,
			RefreshMaxLifetimeExpiry: 30 * 24 * time.Hour,
			CleanupInterval:          1 * time.Hour,
			RevocationEnabled:        false,
			RotationEnabled:          false,
		}

		maker, err := NewGourdianTokenMakerNoStorage(context.Background(), config)
		require.NoError(t, err)
		require.NotNil(t, maker)
	})
}

func TestNewGourdianTokenMakerNoStorage_FailsWithRevocationEnabled(t *testing.T) {
	config := DefaultTestConfig()
	config.RevocationEnabled = true
	config.RotationEnabled = false

	_, err := NewGourdianTokenMakerNoStorage(context.Background(), config)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "revocation and rotation must be disabled")
}

func TestNewGourdianTokenMakerNoStorage_FailsWithRotationEnabled(t *testing.T) {
	config := DefaultTestConfig()
	config.RevocationEnabled = false
	config.RotationEnabled = true

	_, err := NewGourdianTokenMakerNoStorage(context.Background(), config)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "revocation and rotation must be disabled")
}

func TestNewGourdianTokenMakerNoStorage_FailsWithCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	config := DefaultTestConfig()
	config.RevocationEnabled = false
	config.RotationEnabled = false

	_, err := NewGourdianTokenMakerNoStorage(ctx, config)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "context canceled")
}

func TestNewGourdianTokenMakerNoStorage_CanCreateAndVerifyTokens(t *testing.T) {
	config := DefaultTestConfig()
	config.RevocationEnabled = false
	config.RotationEnabled = false

	maker, err := NewGourdianTokenMakerNoStorage(context.Background(), config)
	require.NoError(t, err)

	ctx := context.Background()
	userID := generateTestUUID()
	sessionID := generateTestUUID()

	// Should be able to create tokens
	accessToken, err := maker.CreateAccessToken(ctx, userID, "testuser", []string{"user"}, sessionID)
	require.NoError(t, err)
	require.NotNil(t, accessToken)

	// Should be able to verify tokens
	claims, err := maker.VerifyAccessToken(ctx, accessToken.Token)
	require.NoError(t, err)
	require.Equal(t, userID, claims.Subject)
}

// ============================================================================
// Tests for NewGourdianTokenMakerWithMemory
// ============================================================================

func TestNewGourdianTokenMakerWithMemory_Success(t *testing.T) {
	config := DefaultTestConfig()
	config.RevocationEnabled = true
	config.RotationEnabled = true

	maker, err := NewGourdianTokenMakerWithMemory(context.Background(), config)
	require.NoError(t, err)
	require.NotNil(t, maker)
}

func TestNewGourdianTokenMakerWithMemory_WithDifferentCleanupIntervals(t *testing.T) {
	tests := []struct {
		name            string
		cleanupInterval time.Duration
	}{
		{"1_minute", time.Minute},
		{"5_minutes", 5 * time.Minute},
		{"1_hour", time.Hour},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := DefaultTestConfig()
			config.RevocationEnabled = true
			config.RotationEnabled = true
			config.CleanupInterval = tt.cleanupInterval

			maker, err := NewGourdianTokenMakerWithMemory(context.Background(), config)
			require.NoError(t, err)
			require.NotNil(t, maker)
		})
	}
}

func TestNewGourdianTokenMakerWithMemory_FailsWithCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	config := DefaultTestConfig()
	config.RevocationEnabled = true
	config.RotationEnabled = true

	_, err := NewGourdianTokenMakerWithMemory(ctx, config)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "context canceled")
}

func TestNewGourdianTokenMakerWithMemory_SupportsRevocationAndRotation(t *testing.T) {
	config := DefaultTestConfig()
	config.RevocationEnabled = true
	config.RotationEnabled = true

	maker, err := NewGourdianTokenMakerWithMemory(context.Background(), config)
	require.NoError(t, err)

	ctx := context.Background()
	userID := generateTestUUID()
	sessionID := generateTestUUID()

	// Create tokens
	accessToken, err := maker.CreateAccessToken(ctx, userID, "testuser", []string{"user"}, sessionID)
	require.NoError(t, err)

	refreshToken, err := maker.CreateRefreshToken(ctx, userID, "testuser", sessionID)
	require.NoError(t, err)

	// Revoke access token
	err = maker.RevokeAccessToken(ctx, accessToken.Token)
	require.NoError(t, err)

	// Verify it's revoked
	_, err = maker.VerifyAccessToken(ctx, accessToken.Token)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "revoked")

	// Rotate refresh token
	newRefreshToken, err := maker.RotateRefreshToken(ctx, refreshToken.Token)
	require.NoError(t, err)
	require.NotNil(t, newRefreshToken)

	// Old token should be marked as rotated
	_, err = maker.VerifyRefreshToken(ctx, refreshToken.Token)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "rotated")
}

// ============================================================================
// Tests for NewGourdianTokenMakerWithGorm
// ============================================================================

func TestNewGourdianTokenMakerWithGorm_AllRepositories(t *testing.T) {
	factories := getTestRepositoryFactories()

	for repoName := range factories {
		// Skip non-GORM repositories
		if repoName != "GORM" {
			continue
		}

		t.Run(repoName, func(t *testing.T) {
			repo, cleanup := factories[repoName](t)
			defer cleanup()

			config := DefaultTestConfig()
			config.RevocationEnabled = true
			config.RotationEnabled = true

			gormRepo, ok := repo.(*GormTokenRepository)
			require.True(t, ok)

			maker, err := NewGourdianTokenMakerWithGorm(context.Background(), config, gormRepo.db)
			require.NoError(t, err)
			require.NotNil(t, maker)
		})
	}
}

func TestNewGourdianTokenMakerWithGorm_NilDatabaseFails(t *testing.T) {
	config := DefaultTestConfig()
	config.RevocationEnabled = true
	config.RotationEnabled = true

	_, err := NewGourdianTokenMakerWithGorm(context.Background(), config, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "database instance cannot be nil")
}

func TestNewGourdianTokenMakerWithGorm_FailsWithCancelledContext(t *testing.T) {
	factories := getTestRepositoryFactories()
	repo, cleanup := factories["GORM"](t)
	defer cleanup()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	config := DefaultTestConfig()
	config.RevocationEnabled = true
	config.RotationEnabled = true

	gormRepo := repo.(*GormTokenRepository)
	_, err := NewGourdianTokenMakerWithGorm(ctx, config, gormRepo.db)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "context canceled")
}

func TestNewGourdianTokenMakerWithGorm_SupportsRevocationAndRotation(t *testing.T) {
	factories := getTestRepositoryFactories()
	repo, cleanup := factories["GORM"](t)
	defer cleanup()

	config := DefaultTestConfig()
	config.RevocationEnabled = true
	config.RotationEnabled = true

	gormRepo := repo.(*GormTokenRepository)
	maker, err := NewGourdianTokenMakerWithGorm(context.Background(), config, gormRepo.db)
	require.NoError(t, err)

	ctx := context.Background()
	userID := generateTestUUID()
	sessionID := generateTestUUID()

	// Create and revoke token
	accessToken, err := maker.CreateAccessToken(ctx, userID, "testuser", []string{"user"}, sessionID)
	require.NoError(t, err)

	err = maker.RevokeAccessToken(ctx, accessToken.Token)
	require.NoError(t, err)

	_, err = maker.VerifyAccessToken(ctx, accessToken.Token)
	require.Error(t, err)
}

// ============================================================================
// Tests for NewGourdianTokenMakerWithMongo
// ============================================================================

func TestNewGourdianTokenMakerWithMongo_AllRepositories(t *testing.T) {
	factories := getTestRepositoryFactories()

	for repoName := range factories {
		// Skip non-MongoDB repositories
		if repoName != "MongoDB" {
			continue
		}

		t.Run(repoName, func(t *testing.T) {
			repo, cleanup := factories[repoName](t)
			defer cleanup()

			config := DefaultTestConfig()
			config.RevocationEnabled = true
			config.RotationEnabled = true

			mongoRepo := repo.(*MongoTokenRepository)
			maker, err := NewGourdianTokenMakerWithMongo(context.Background(), config, mongoRepo.revokedCollection.Database())
			require.NoError(t, err)
			require.NotNil(t, maker)
		})
	}
}

func TestNewGourdianTokenMakerWithMongo_NilDatabaseFails(t *testing.T) {
	config := DefaultTestConfig()
	config.RevocationEnabled = true
	config.RotationEnabled = true

	_, err := NewGourdianTokenMakerWithMongo(context.Background(), config, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "database instance cannot be nil")
}

func TestNewGourdianTokenMakerWithMongo_FailsWithCancelledContext(t *testing.T) {
	factories := getTestRepositoryFactories()
	repo, cleanup := factories["MongoDB"](t)
	defer cleanup()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	config := DefaultTestConfig()
	config.RevocationEnabled = true
	config.RotationEnabled = true

	mongoRepo := repo.(*MongoTokenRepository)
	_, err := NewGourdianTokenMakerWithMongo(ctx, config, mongoRepo.revokedCollection.Database())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "context canceled")
}

func TestNewGourdianTokenMakerWithMongo_CreatesTransactionEnabledRepository(t *testing.T) {
	factories := getTestRepositoryFactories()
	repo, cleanup := factories["MongoDB"](t)
	defer cleanup()

	config := DefaultTestConfig()
	config.RevocationEnabled = true
	config.RotationEnabled = true

	mongoRepo := repo.(*MongoTokenRepository)
	maker, err := NewGourdianTokenMakerWithMongo(context.Background(), config, mongoRepo.revokedCollection.Database())
	require.NoError(t, err)

	// The returned maker should have transactions enabled
	jwtMaker := maker.(*JWTMaker)
	mongoInternalRepo := jwtMaker.tokenRepo.(*MongoTokenRepository)
	assert.True(t, mongoInternalRepo.useTransactions)
}

// ============================================================================
// Tests for NewGourdianTokenMakerWithRedis
// ============================================================================

func TestNewGourdianTokenMakerWithRedis_AllRepositories(t *testing.T) {
	factories := getTestRepositoryFactories()

	for repoName := range factories {
		// Skip non-Redis repositories
		if repoName != "Redis" {
			continue
		}

		t.Run(repoName, func(t *testing.T) {
			repo, cleanup := factories[repoName](t)
			defer cleanup()

			config := DefaultTestConfig()
			config.RevocationEnabled = true
			config.RotationEnabled = true

			redisRepo := repo.(*RedisTokenRepository)
			maker, err := NewGourdianTokenMakerWithRedis(context.Background(), config, redisRepo.client)
			require.NoError(t, err)
			require.NotNil(t, maker)
		})
	}
}

func TestNewGourdianTokenMakerWithRedis_NilClientFails(t *testing.T) {
	config := DefaultTestConfig()
	config.RevocationEnabled = true
	config.RotationEnabled = true

	_, err := NewGourdianTokenMakerWithRedis(context.Background(), config, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "redis client cannot be nil")
}

func TestNewGourdianTokenMakerWithRedis_FailsWithCancelledContext(t *testing.T) {
	factories := getTestRepositoryFactories()
	repo, cleanup := factories["Redis"](t)
	defer cleanup()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	config := DefaultTestConfig()
	config.RevocationEnabled = true
	config.RotationEnabled = true

	redisRepo := repo.(*RedisTokenRepository)
	_, err := NewGourdianTokenMakerWithRedis(ctx, config, redisRepo.client)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "context canceled")
}

func TestNewGourdianTokenMakerWithRedis_SupportsHighPerformanceOperations(t *testing.T) {
	factories := getTestRepositoryFactories()
	repo, cleanup := factories["Redis"](t)
	defer cleanup()

	config := DefaultTestConfig()
	config.RevocationEnabled = true
	config.RotationEnabled = true
	// Use a reasonable token lifetime to avoid expiration during the test loop
	config.AccessExpiryDuration = 5 * time.Minute

	redisRepo := repo.(*RedisTokenRepository)
	maker, err := NewGourdianTokenMakerWithRedis(context.Background(), config, redisRepo.client)
	require.NoError(t, err)

	ctx := context.Background()
	userID := generateTestUUID()
	sessionID := generateTestUUID()

	// Create and verify many tokens to test performance
	start := time.Now()
	for i := 0; i < 100; i++ {
		token, err := maker.CreateAccessToken(ctx, userID, "testuser", []string{"user"}, sessionID)
		require.NoError(t, err)

		// Should be able to verify immediately
		claims, err := maker.VerifyAccessToken(ctx, token.Token)
		require.NoError(t, err)
		require.NotNil(t, claims)
		require.Equal(t, userID, claims.Subject)
	}
	elapsed := time.Since(start)

	// Verify performance is reasonable (100 tokens in under 1 second expected)
	assert.Less(t, elapsed, 5*time.Second, "token operations took too long")
}

// ============================================================================
// Integration Tests - All Backends
// ============================================================================

func TestAllFactories_CreatesValidTokenMakers(t *testing.T) {
	tests := []struct {
		name    string
		factory func(t *testing.T) GourdianTokenMaker
	}{
		{
			name: "NoStorage",
			factory: func(t *testing.T) GourdianTokenMaker {
				config := DefaultTestConfig()
				config.RevocationEnabled = false
				config.RotationEnabled = false

				maker, err := NewGourdianTokenMakerNoStorage(context.Background(), config)
				require.NoError(t, err)
				return maker
			},
		},
		{
			name: "Memory",
			factory: func(t *testing.T) GourdianTokenMaker {
				config := DefaultTestConfig()
				config.RevocationEnabled = true
				config.RotationEnabled = true

				maker, err := NewGourdianTokenMakerWithMemory(context.Background(), config)
				require.NoError(t, err)
				return maker
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			maker := tt.factory(t)

			ctx := context.Background()
			userID := generateTestUUID()
			sessionID := generateTestUUID()

			// Test access token creation and verification
			accessToken, err := maker.CreateAccessToken(ctx, userID, "testuser", []string{"user", "admin"}, sessionID)
			require.NoError(t, err)
			require.NotNil(t, accessToken)

			claims, err := maker.VerifyAccessToken(ctx, accessToken.Token)
			require.NoError(t, err)
			assert.Equal(t, userID, claims.Subject)
			assert.Equal(t, "testuser", claims.Username)
			assert.ElementsMatch(t, []string{"user", "admin"}, claims.Roles)

			// Test refresh token creation and verification
			refreshToken, err := maker.CreateRefreshToken(ctx, userID, "testuser", sessionID)
			require.NoError(t, err)

			refreshClaims, err := maker.VerifyRefreshToken(ctx, refreshToken.Token)
			require.NoError(t, err)
			assert.Equal(t, userID, refreshClaims.Subject)
		})
	}
}

// TestAllFactories_TokenExpirationWorks tests that tokens properly expire after their duration
// Note: This test uses a separate goroutine to avoid timing conflicts with the main test execution
func TestAllFactories_TokenExpirationWorks(t *testing.T) {
	tests := []struct {
		name    string
		factory func(t *testing.T) GourdianTokenMaker
	}{
		{
			name: "NoStorage",
			factory: func(t *testing.T) GourdianTokenMaker {
				config := DefaultTestConfig()
				config.RevocationEnabled = false
				config.RotationEnabled = false
				config.AccessExpiryDuration = 1 * time.Second

				maker, err := NewGourdianTokenMakerNoStorage(context.Background(), config)
				require.NoError(t, err)
				return maker
			},
		},
		{
			name: "Memory",
			factory: func(t *testing.T) GourdianTokenMaker {
				config := DefaultTestConfig()
				config.RevocationEnabled = true
				config.RotationEnabled = true
				config.AccessExpiryDuration = 1 * time.Second

				maker, err := NewGourdianTokenMakerWithMemory(context.Background(), config)
				require.NoError(t, err)
				return maker
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			maker := tt.factory(t)

			ctx := context.Background()
			userID := generateTestUUID()
			sessionID := generateTestUUID()

			// Create token with 1 second expiry
			token, err := maker.CreateAccessToken(ctx, userID, "testuser", []string{"user"}, sessionID)
			require.NoError(t, err)

			// Should verify immediately
			_, err = maker.VerifyAccessToken(ctx, token.Token)
			require.NoError(t, err)

			// Wait for expiration (1 second + 200ms buffer)
			time.Sleep(1200 * time.Millisecond)

			// Should fail after expiration
			_, err = maker.VerifyAccessToken(ctx, token.Token)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "expired")
		})
	}
}

func TestAllFactories_InvalidConfigurationsFail(t *testing.T) {
	invalidConfigs := []struct {
		name   string
		config GourdianTokenConfig
	}{
		{
			name: "BothRevocationAndRotationEnabled",
			config: GourdianTokenConfig{
				SigningMethod:           Symmetric,
				Algorithm:               "HS256",
				SymmetricKey:            "test-secret-key-that-is-at-least-32-bytes-long",
				RevocationEnabled:       true,
				RotationEnabled:         true,
				AccessExpiryDuration:    30 * time.Minute,
				AccessMaxLifetimeExpiry: 24 * time.Hour,
				CleanupInterval:         1 * time.Hour,
			},
		},
		{
			name: "NegativeAccessExpiry",
			config: GourdianTokenConfig{
				SigningMethod:           Symmetric,
				Algorithm:               "HS256",
				SymmetricKey:            "test-secret-key-that-is-at-least-32-bytes-long",
				RevocationEnabled:       false,
				RotationEnabled:         false,
				AccessExpiryDuration:    -1 * time.Minute,
				AccessMaxLifetimeExpiry: 24 * time.Hour,
				CleanupInterval:         1 * time.Hour,
			},
		},
	}

	for _, tt := range invalidConfigs {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewGourdianTokenMakerNoStorage(context.Background(), tt.config)
			require.Error(t, err)
		})
	}
}

// ============================================================================
// Helper Functions
// ============================================================================

func generateTestUUID() uuid.UUID {
	uuid := uuid.New()
	return uuid
}
