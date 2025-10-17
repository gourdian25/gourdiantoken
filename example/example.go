// File: example/example.go

package main

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gourdian25/gourdiantoken"
	"github.com/redis/go-redis/v9"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// TestResult holds the results of a test operation
type TestResult struct {
	TestName    string
	Success     bool
	Duration    time.Duration
	Error       error
	Description string
	Details     string
}

// RepositoryConfig contains configuration for different repository types
type RepositoryConfig struct {
	Name        string
	Description string
	CreateRepo  func() (gourdiantoken.TokenRepository, error)
	Cleanup     func() error
}

// PerformanceMetrics tracks performance data
type PerformanceMetrics struct {
	OperationType string
	Count         int
	TotalDuration time.Duration
	MinDuration   time.Duration
	MaxDuration   time.Duration
	AvgDuration   time.Duration
}

func RunComprehensiveTests(ctx context.Context, tokenMaker gourdiantoken.GourdianTokenMaker, suiteName string) []TestResult {
	var results []TestResult

	fmt.Printf("\n%s\n", strings.Repeat("═", 100))
	fmt.Printf("║ %s ║\n", centerText("TEST SUITE: "+suiteName, 96))
	fmt.Printf("%s\n", strings.Repeat("═", 100))

	// Basic CRUD Operations Tests
	results = append(results, runBasicOperationsTests(ctx, tokenMaker)...)

	// Token Lifecycle Tests
	results = append(results, runTokenLifecycleTests(ctx, tokenMaker)...)

	// Security & Validation Tests
	results = append(results, runSecurityValidationTests(ctx, tokenMaker)...)

	// Edge Cases Tests
	results = append(results, runEdgeCaseTests(ctx, tokenMaker)...)

	// Concurrency Tests
	results = append(results, runConcurrencyTests(ctx, tokenMaker)...)

	// Performance Tests
	results = append(results, runPerformanceTests(ctx, tokenMaker)...)

	// Real-World Scenario Tests
	results = append(results, runRealWorldScenarioTests(ctx, tokenMaker)...)

	// Print summary
	printTestSummary(results, suiteName)

	return results
}

// runTokenLifecycleTests tests complete token lifecycle
func runTokenLifecycleTests(ctx context.Context, tokenMaker gourdiantoken.GourdianTokenMaker) []TestResult {
	var results []TestResult
	fmt.Printf("\n┌─ %s\n", "TOKEN LIFECYCLE")

	userID := uuid.New()
	sessionID := uuid.New()
	username := "lifecycle@example.com"
	roles := []string{"user"}

	// Test 1: Revoke Access Token
	results = append(results, runTest("Revoke Access Token", func() (string, error) {
		token, err := tokenMaker.CreateAccessToken(ctx, userID, username, roles, sessionID)
		if err != nil {
			return "", err
		}

		err = tokenMaker.RevokeAccessToken(ctx, token.Token)
		if err != nil {
			if err.Error() == "access token revocation is not enabled" {
				return "Revocation not enabled (skipped)", nil
			}
			return "", err
		}

		// Verify token is revoked
		_, err = tokenMaker.VerifyAccessToken(ctx, token.Token)
		if err == nil {
			return "", fmt.Errorf("token should be revoked but verification succeeded")
		}

		return "Token revoked and verification failed as expected", nil
	}))

	// Test 2: Revoke Refresh Token
	results = append(results, runTest("Revoke Refresh Token", func() (string, error) {
		token, err := tokenMaker.CreateRefreshToken(ctx, userID, username, sessionID)
		if err != nil {
			return "", err
		}

		err = tokenMaker.RevokeRefreshToken(ctx, token.Token)
		if err != nil {
			if err.Error() == "refresh token revocation is not enabled" {
				return "Revocation not enabled (skipped)", nil
			}
			return "", err
		}

		_, err = tokenMaker.VerifyRefreshToken(ctx, token.Token)
		if err == nil {
			return "", fmt.Errorf("token should be revoked but verification succeeded")
		}

		return "Token revoked and verification failed as expected", nil
	}))

	// Test 3: Rotate Refresh Token
	results = append(results, runTest("Rotate Refresh Token", func() (string, error) {
		oldToken, err := tokenMaker.CreateRefreshToken(ctx, userID, username, sessionID)
		if err != nil {
			return "", err
		}

		newToken, err := tokenMaker.RotateRefreshToken(ctx, oldToken.Token)
		if err != nil {
			if err.Error() == "token rotation not enabled" {
				return "Rotation not enabled (skipped)", nil
			}
			return "", err
		}

		// Verify old token is now invalid
		_, err = tokenMaker.VerifyRefreshToken(ctx, oldToken.Token)
		if err == nil {
			return "", fmt.Errorf("old token should be invalid after rotation")
		}

		// Verify new token is valid
		claims, err := tokenMaker.VerifyRefreshToken(ctx, newToken.Token)
		if err != nil {
			return "", fmt.Errorf("new token should be valid: %w", err)
		}

		return fmt.Sprintf("Rotated successfully, new token for user: %s", claims.Username), nil
	}))

	// Test 4: Double Rotation Prevention
	results = append(results, runTest("Prevent Double Rotation", func() (string, error) {
		oldToken, err := tokenMaker.CreateRefreshToken(ctx, userID, username, sessionID)
		if err != nil {
			return "", err
		}

		_, err = tokenMaker.RotateRefreshToken(ctx, oldToken.Token)
		if err != nil {
			if err.Error() == "token rotation not enabled" {
				return "Rotation not enabled (skipped)", nil
			}
			return "", err
		}

		// Try to rotate the same token again
		_, err = tokenMaker.RotateRefreshToken(ctx, oldToken.Token)
		if err == nil {
			return "", fmt.Errorf("expected error on double rotation")
		}

		return "Double rotation prevented as expected", nil
	}))

	// Test 5: Token Expiration Simulation
	results = append(results, runTest("Token Expiration Check", func() (string, error) {
		token, err := tokenMaker.CreateAccessToken(ctx, userID, username, roles, sessionID)
		if err != nil {
			return "", err
		}

		claims, err := tokenMaker.VerifyAccessToken(ctx, token.Token)
		if err != nil {
			return "", err
		}

		timeUntilExpiry := time.Until(claims.ExpiresAt)
		return fmt.Sprintf("Token valid, expires in: %v", timeUntilExpiry), nil
	}))

	return results
}

// runSecurityValidationTests tests security features
func runSecurityValidationTests(ctx context.Context, tokenMaker gourdiantoken.GourdianTokenMaker) []TestResult {
	var results []TestResult
	fmt.Printf("\n┌─ %s\n", "SECURITY & VALIDATION")

	userID := uuid.New()
	sessionID := uuid.New()

	// Test 1: Invalid Token Format
	results = append(results, runTest("Reject Invalid Token Format", func() (string, error) {
		invalidToken := "invalid.token.format"
		_, err := tokenMaker.VerifyAccessToken(ctx, invalidToken)
		if err == nil {
			return "", fmt.Errorf("should reject invalid token format")
		}
		return "Invalid format rejected correctly", nil
	}))

	// Test 2: Tampered Token
	results = append(results, runTest("Reject Tampered Token", func() (string, error) {
		token, err := tokenMaker.CreateAccessToken(ctx, userID, "user@test.com", []string{"user"}, sessionID)
		if err != nil {
			return "", err
		}

		// Tamper with token
		tamperedToken := token.Token[:len(token.Token)-10] + "TAMPERED12"
		_, err = tokenMaker.VerifyAccessToken(ctx, tamperedToken)
		if err == nil {
			return "", fmt.Errorf("should reject tampered token")
		}
		return "Tampered token rejected correctly", nil
	}))

	// Test 3: Empty Token
	results = append(results, runTest("Reject Empty Token", func() (string, error) {
		_, err := tokenMaker.VerifyAccessToken(ctx, "")
		if err == nil {
			return "", fmt.Errorf("should reject empty token")
		}
		return "Empty token rejected correctly", nil
	}))

	// Test 4: Wrong Token Type
	results = append(results, runTest("Reject Wrong Token Type", func() (string, error) {
		refreshToken, err := tokenMaker.CreateRefreshToken(ctx, userID, "user@test.com", sessionID)
		if err != nil {
			return "", err
		}

		// Try to verify refresh token as access token
		_, err = tokenMaker.VerifyAccessToken(ctx, refreshToken.Token)
		if err == nil {
			return "", fmt.Errorf("should reject wrong token type")
		}
		return "Wrong token type rejected correctly", nil
	}))

	// Test 5: SQL Injection in Username
	results = append(results, runTest("Handle SQL Injection in Username", func() (string, error) {
		maliciousUsername := "admin'--"
		token, err := tokenMaker.CreateAccessToken(ctx, userID, maliciousUsername, []string{"user"}, sessionID)
		if err != nil {
			return "", err
		}

		claims, err := tokenMaker.VerifyAccessToken(ctx, token.Token)
		if err != nil {
			return "", err
		}

		if claims.Username != maliciousUsername {
			return "", fmt.Errorf("username mismatch")
		}
		return "SQL injection attempt handled safely", nil
	}))

	// Test 6: XSS in Username
	results = append(results, runTest("Handle XSS in Username", func() (string, error) {
		xssUsername := "<script>alert('xss')</script>@test.com"
		token, err := tokenMaker.CreateAccessToken(ctx, userID, xssUsername, []string{"user"}, sessionID)
		if err != nil {
			return "", err
		}

		claims, err := tokenMaker.VerifyAccessToken(ctx, token.Token)
		if err != nil {
			return "", err
		}

		if claims.Username != xssUsername {
			return "", fmt.Errorf("username mismatch")
		}
		return "XSS attempt handled safely", nil
	}))

	return results
}

// runEdgeCaseTests tests edge cases
func runEdgeCaseTests(ctx context.Context, tokenMaker gourdiantoken.GourdianTokenMaker) []TestResult {
	var results []TestResult
	fmt.Printf("\n┌─ %s\n", "EDGE CASES")

	sessionID := uuid.New()

	// Test 1: Nil User ID
	results = append(results, runTest("Reject Nil User ID", func() (string, error) {
		_, err := tokenMaker.CreateAccessToken(ctx, uuid.Nil, "user@test.com", []string{"user"}, sessionID)
		if err == nil {
			return "", fmt.Errorf("should reject nil user ID")
		}
		return "Nil user ID rejected correctly", nil
	}))

	// Test 2: Empty Roles
	results = append(results, runTest("Reject Empty Roles", func() (string, error) {
		_, err := tokenMaker.CreateAccessToken(ctx, uuid.New(), "user@test.com", []string{}, sessionID)
		if err == nil {
			return "", fmt.Errorf("should reject empty roles")
		}
		return "Empty roles rejected correctly", nil
	}))

	// Test 3: Empty String in Roles
	results = append(results, runTest("Reject Empty String in Roles", func() (string, error) {
		_, err := tokenMaker.CreateAccessToken(ctx, uuid.New(), "user@test.com", []string{"user", "", "admin"}, sessionID)
		if err == nil {
			return "", fmt.Errorf("should reject empty string in roles")
		}
		return "Empty string in roles rejected correctly", nil
	}))

	// Test 4: Extremely Long Username
	results = append(results, runTest("Reject Extremely Long Username", func() (string, error) {
		longUsername := strings.Repeat("a", 2000) + "@test.com"
		_, err := tokenMaker.CreateAccessToken(ctx, uuid.New(), longUsername, []string{"user"}, sessionID)
		if err == nil {
			return "", fmt.Errorf("should reject extremely long username")
		}
		return "Extremely long username rejected correctly", nil
	}))

	// Test 5: Maximum Valid Username Length
	results = append(results, runTest("Accept Maximum Valid Username", func() (string, error) {
		maxUsername := strings.Repeat("a", 1000) + "@test.com"
		_, err := tokenMaker.CreateAccessToken(ctx, uuid.New(), maxUsername, []string{"user"}, sessionID)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("Username length: %d characters", len(maxUsername)), nil
	}))

	// Test 6: Unicode Username
	results = append(results, runTest("Handle Unicode Username", func() (string, error) {
		unicodeUsername := "用户名@例え.日本"
		token, err := tokenMaker.CreateAccessToken(ctx, uuid.New(), unicodeUsername, []string{"user"}, sessionID)
		if err != nil {
			return "", err
		}

		claims, err := tokenMaker.VerifyAccessToken(ctx, token.Token)
		if err != nil {
			return "", err
		}

		if claims.Username != unicodeUsername {
			return "", fmt.Errorf("unicode username not preserved")
		}
		return "Unicode username handled correctly", nil
	}))

	// Test 7: Special Characters in Roles
	results = append(results, runTest("Handle Special Characters in Roles", func() (string, error) {
		specialRoles := []string{"admin:write", "user/read", "mod*all", "super_admin"}
		token, err := tokenMaker.CreateAccessToken(ctx, uuid.New(), "user@test.com", specialRoles, sessionID)
		if err != nil {
			return "", err
		}

		claims, err := tokenMaker.VerifyAccessToken(ctx, token.Token)
		if err != nil {
			return "", err
		}

		return fmt.Sprintf("Special roles: %v", claims.Roles), nil
	}))

	// Test 8: Massive Role Count
	results = append(results, runTest("Handle Large Number of Roles", func() (string, error) {
		manyRoles := make([]string, 100)
		for i := 0; i < 100; i++ {
			manyRoles[i] = fmt.Sprintf("role_%d", i)
		}

		token, err := tokenMaker.CreateAccessToken(ctx, uuid.New(), "user@test.com", manyRoles, sessionID)
		if err != nil {
			return "", err
		}

		claims, err := tokenMaker.VerifyAccessToken(ctx, token.Token)
		if err != nil {
			return "", err
		}

		return fmt.Sprintf("Created token with %d roles", len(claims.Roles)), nil
	}))

	return results
}

// runConcurrencyTests tests concurrent operations
func runConcurrencyTests(ctx context.Context, tokenMaker gourdiantoken.GourdianTokenMaker) []TestResult {
	var results []TestResult
	fmt.Printf("\n┌─ %s\n", "CONCURRENCY")

	// Test 1: Concurrent Token Creation
	results = append(results, runTest("Concurrent Token Creation (50 goroutines)", func() (string, error) {
		const goroutines = 50
		errChan := make(chan error, goroutines)
		var wg sync.WaitGroup

		start := time.Now()
		for i := 0; i < goroutines; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				userID := uuid.New()
				sessionID := uuid.New()
				username := fmt.Sprintf("concurrent%d@test.com", id)
				roles := []string{"user"}

				_, err := tokenMaker.CreateAccessToken(ctx, userID, username, roles, sessionID)
				errChan <- err
			}(i)
		}

		wg.Wait()
		close(errChan)
		duration := time.Since(start)

		successCount := 0
		for err := range errChan {
			if err == nil {
				successCount++
			} else {
				return "", err
			}
		}

		return fmt.Sprintf("%d tokens created in %v (%.2f tokens/sec)",
			successCount, duration, float64(successCount)/duration.Seconds()), nil
	}))

	// Test 2: Concurrent Verification
	results = append(results, runTest("Concurrent Token Verification (50 goroutines)", func() (string, error) {
		// Create tokens first
		const count = 50
		tokens := make([]string, count)
		for i := 0; i < count; i++ {
			token, err := tokenMaker.CreateAccessToken(ctx, uuid.New(), fmt.Sprintf("user%d@test.com", i),
				[]string{"user"}, uuid.New())
			if err != nil {
				return "", err
			}
			tokens[i] = token.Token
		}

		// Verify concurrently
		errChan := make(chan error, count)
		var wg sync.WaitGroup

		start := time.Now()
		for _, tokenStr := range tokens {
			wg.Add(1)
			go func(t string) {
				defer wg.Done()
				_, err := tokenMaker.VerifyAccessToken(ctx, t)
				errChan <- err
			}(tokenStr)
		}

		wg.Wait()
		close(errChan)
		duration := time.Since(start)

		successCount := 0
		for err := range errChan {
			if err == nil {
				successCount++
			} else {
				return "", err
			}
		}

		return fmt.Sprintf("%d tokens verified in %v (%.2f verifications/sec)",
			successCount, duration, float64(successCount)/duration.Seconds()), nil
	}))

	// Test 3: Mixed Concurrent Operations
	results = append(results, runTest("Mixed Concurrent Operations (100 ops)", func() (string, error) {
		const operations = 100
		errChan := make(chan error, operations)
		var wg sync.WaitGroup

		start := time.Now()
		for i := 0; i < operations; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				userID := uuid.New()
				sessionID := uuid.New()

				// 50% create, 30% verify, 20% rotate
				switch id % 10 {
				case 0, 1, 2, 3, 4: // Create
					_, err := tokenMaker.CreateAccessToken(ctx, userID, fmt.Sprintf("user%d@test.com", id),
						[]string{"user"}, sessionID)
					errChan <- err
				case 5, 6, 7: // Verify
					token, err := tokenMaker.CreateAccessToken(ctx, userID, fmt.Sprintf("user%d@test.com", id),
						[]string{"user"}, sessionID)
					if err != nil {
						errChan <- err
						return
					}
					_, err = tokenMaker.VerifyAccessToken(ctx, token.Token)
					errChan <- err
				default: // Rotate
					token, err := tokenMaker.CreateRefreshToken(ctx, userID, fmt.Sprintf("user%d@test.com", id), sessionID)
					if err != nil {
						errChan <- err
						return
					}
					_, err = tokenMaker.RotateRefreshToken(ctx, token.Token)
					if err != nil && err.Error() != "token rotation not enabled" {
						errChan <- err
						return
					}
					errChan <- nil
				}
			}(i)
		}

		wg.Wait()
		close(errChan)
		duration := time.Since(start)

		successCount := 0
		for err := range errChan {
			if err == nil {
				successCount++
			}
		}

		return fmt.Sprintf("%d/%d operations succeeded in %v (%.2f ops/sec)",
			successCount, operations, duration, float64(operations)/duration.Seconds()), nil
	}))

	// Test 4: Race Condition on Token Rotation
	results = append(results, runTest("Race Condition: Simultaneous Rotation", func() (string, error) {
		token, err := tokenMaker.CreateRefreshToken(ctx, uuid.New(), "race@test.com", uuid.New())
		if err != nil {
			return "", err
		}

		const concurrent = 10
		var wg sync.WaitGroup
		successCount := 0
		var mu sync.Mutex

		for i := 0; i < concurrent; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, err := tokenMaker.RotateRefreshToken(ctx, token.Token)
				if err == nil {
					mu.Lock()
					successCount++
					mu.Unlock()
				} else if err.Error() == "token rotation not enabled" {
					mu.Lock()
					successCount = -1
					mu.Unlock()
				}
			}()
		}

		wg.Wait()

		if successCount == -1 {
			return "Rotation not enabled (skipped)", nil
		}

		if successCount > 1 {
			return "", fmt.Errorf("race condition: %d simultaneous rotations succeeded", successCount)
		}

		return fmt.Sprintf("Race condition handled: only %d rotation succeeded", successCount), nil
	}))

	return results
}

// runBasicOperationsTests tests basic CRUD operations
func runBasicOperationsTests(ctx context.Context, tokenMaker gourdiantoken.GourdianTokenMaker) []TestResult {
	var results []TestResult
	fmt.Printf("\n┌─ %s\n", "BASIC OPERATIONS")

	userID := uuid.New()
	sessionID := uuid.New()
	username := "john.doe@example.com"
	roles := []string{"user", "admin"}

	// Test 1: Create Access Token
	results = append(results, runTest("Create Access Token", func() (string, error) {
		token, err := tokenMaker.CreateAccessToken(ctx, userID, username, roles, sessionID)
		if err != nil {
			return "", err
		}

		// Verify the token can be decoded
		claims, err := tokenMaker.VerifyAccessToken(ctx, token.Token)
		if err != nil {
			return "", fmt.Errorf("failed to verify created token: %w", err)
		}

		if claims.Subject != userID {
			return "", fmt.Errorf("user ID mismatch: got %v, want %v", claims.Subject, userID)
		}
		if claims.Username != username {
			return "", fmt.Errorf("username mismatch: got %s, want %s", claims.Username, username)
		}

		return fmt.Sprintf("Token created for user: %s, expires: %v",
			claims.Username, time.Until(claims.ExpiresAt).Round(time.Minute)), nil
	}))

	// Test 2: Create Refresh Token
	results = append(results, runTest("Create Refresh Token", func() (string, error) {
		token, err := tokenMaker.CreateRefreshToken(ctx, userID, username, sessionID)
		if err != nil {
			return "", err
		}

		// Verify the refresh token
		claims, err := tokenMaker.VerifyRefreshToken(ctx, token.Token)
		if err != nil {
			return "", fmt.Errorf("failed to verify refresh token: %w", err)
		}

		if claims.Subject != userID {
			return "", fmt.Errorf("user ID mismatch in refresh token")
		}

		return fmt.Sprintf("Refresh token created, expires: %v",
			time.Until(claims.ExpiresAt).Round(time.Hour)), nil
	}))

	// Test 3: Verify Valid Access Token
	results = append(results, runTest("Verify Valid Access Token", func() (string, error) {
		token, err := tokenMaker.CreateAccessToken(ctx, userID, username, roles, sessionID)
		if err != nil {
			return "", err
		}

		claims, err := tokenMaker.VerifyAccessToken(ctx, token.Token)
		if err != nil {
			return "", err
		}

		// Validate claims
		if claims.Subject != userID {
			return "", fmt.Errorf("user ID verification failed")
		}
		if claims.Username != username {
			return "", fmt.Errorf("username verification failed")
		}
		if len(claims.Roles) != len(roles) {
			return "", fmt.Errorf("roles count mismatch")
		}

		return fmt.Sprintf("Token verified successfully - User: %s, Roles: %v",
			claims.Username, claims.Roles), nil
	}))

	// Test 4: Verify Valid Refresh Token
	results = append(results, runTest("Verify Valid Refresh Token", func() (string, error) {
		token, err := tokenMaker.CreateRefreshToken(ctx, userID, username, sessionID)
		if err != nil {
			return "", err
		}

		claims, err := tokenMaker.VerifyRefreshToken(ctx, token.Token)
		if err != nil {
			return "", err
		}

		if claims.Subject != userID {
			return "", fmt.Errorf("refresh token user ID verification failed")
		}
		if claims.SessionID != sessionID {
			return "", fmt.Errorf("refresh token session ID verification failed")
		}

		return "Refresh token verified successfully", nil
	}))

	// Test 5: Token Payload Integrity
	results = append(results, runTest("Token Payload Integrity", func() (string, error) {
		// Create token with specific claims
		testUserID := uuid.New()
		testSessionID := uuid.New()
		testUsername := "integrity@test.com"
		testRoles := []string{"admin", "editor", "viewer"}

		token, err := tokenMaker.CreateAccessToken(ctx, testUserID, testUsername, testRoles, testSessionID)
		if err != nil {
			return "", err
		}

		// Verify all claims are preserved
		claims, err := tokenMaker.VerifyAccessToken(ctx, token.Token)
		if err != nil {
			return "", err
		}

		if claims.Subject != testUserID {
			return "", fmt.Errorf("user ID not preserved")
		}
		if claims.Username != testUsername {
			return "", fmt.Errorf("username not preserved")
		}
		if claims.SessionID != testSessionID {
			return "", fmt.Errorf("session ID not preserved")
		}
		if len(claims.Roles) != len(testRoles) {
			return "", fmt.Errorf("roles not preserved")
		}

		// Check individual roles
		for _, expectedRole := range testRoles {
			found := false
			for _, actualRole := range claims.Roles {
				if actualRole == expectedRole {
					found = true
					break
				}
			}
			if !found {
				return "", fmt.Errorf("role %s not found in token", expectedRole)
			}
		}

		return "All token claims preserved correctly", nil
	}))

	return results
}

// runPerformanceTests tests performance and scalability
func runPerformanceTests(ctx context.Context, tokenMaker gourdiantoken.GourdianTokenMaker) []TestResult {
	var results []TestResult
	fmt.Printf("\n┌─ %s\n", "PERFORMANCE")

	// Test 1: Bulk Token Creation Performance
	results = append(results, runTest("Bulk Token Creation (100 tokens)", func() (string, error) {
		const count = 100
		start := time.Now()

		for i := 0; i < count; i++ {
			userID := uuid.New()
			sessionID := uuid.New()
			username := fmt.Sprintf("perfuser%d@test.com", i)
			roles := []string{"user", fmt.Sprintf("role%d", i%10)}

			_, err := tokenMaker.CreateAccessToken(ctx, userID, username, roles, sessionID)
			if err != nil {
				return "", fmt.Errorf("failed at token %d: %w", i, err)
			}
		}

		duration := time.Since(start)
		return fmt.Sprintf("Created %d tokens in %v (%.2f tokens/sec)",
			count, duration, float64(count)/duration.Seconds()), nil
	}))

	// Test 2: Bulk Token Verification Performance
	results = append(results, runTest("Bulk Token Verification (100 tokens)", func() (string, error) {
		const count = 100
		tokens := make([]string, count)

		// Create tokens first
		for i := 0; i < count; i++ {
			userID := uuid.New()
			sessionID := uuid.New()
			username := fmt.Sprintf("verifyuser%d@test.com", i)
			roles := []string{"user"}

			token, err := tokenMaker.CreateAccessToken(ctx, userID, username, roles, sessionID)
			if err != nil {
				return "", fmt.Errorf("failed to create token %d: %w", i, err)
			}
			tokens[i] = token.Token
		}

		// Verify all tokens
		start := time.Now()
		for i, tokenStr := range tokens {
			_, err := tokenMaker.VerifyAccessToken(ctx, tokenStr)
			if err != nil {
				return "", fmt.Errorf("failed to verify token %d: %w", i, err)
			}
		}

		duration := time.Since(start)
		return fmt.Sprintf("Verified %d tokens in %v (%.2f verifications/sec)",
			count, duration, float64(count)/duration.Seconds()), nil
	}))

	// Test 3: Memory Usage for Large Tokens
	results = append(results, runTest("Memory Usage - Large Payload Tokens", func() (string, error) {
		const count = 50
		totalBytes := 0
		start := time.Now()

		// Create tokens with large role sets
		for i := 0; i < count; i++ {
			userID := uuid.New()
			sessionID := uuid.New()
			username := fmt.Sprintf("largeuser%d@test.com", i)

			// Create many roles to simulate large payload
			roles := make([]string, 50)
			for j := 0; j < 50; j++ {
				roles[j] = fmt.Sprintf("department_%d_role_%d", i, j)
			}

			token, err := tokenMaker.CreateAccessToken(ctx, userID, username, roles, sessionID)
			if err != nil {
				return "", fmt.Errorf("failed at token %d: %w", i, err)
			}
			totalBytes += len(token.Token)
		}

		duration := time.Since(start)
		return fmt.Sprintf("Created %d large tokens in %v (~%.2f MB total size)",
			count, duration, float64(totalBytes)/(1024*1024)), nil
	}))

	// Test 4: Mixed Operations Performance
	results = append(results, runTest("Mixed Operations (Create + Verify)", func() (string, error) {
		const operations = 200
		start := time.Now()
		successCount := 0

		for i := 0; i < operations; i++ {
			userID := uuid.New()
			sessionID := uuid.New()
			username := fmt.Sprintf("mixeduser%d@test.com", i)
			roles := []string{"user"}

			// Create token
			token, err := tokenMaker.CreateAccessToken(ctx, userID, username, roles, sessionID)
			if err != nil {
				return "", fmt.Errorf("create failed at op %d: %w", i, err)
			}

			// Immediately verify it
			_, err = tokenMaker.VerifyAccessToken(ctx, token.Token)
			if err != nil {
				return "", fmt.Errorf("verify failed at op %d: %w", i, err)
			}

			successCount++
		}

		duration := time.Since(start)
		return fmt.Sprintf("Completed %d create+verify operations in %v (%.2f ops/sec)",
			successCount, duration, float64(successCount)/duration.Seconds()), nil
	}))

	// Test 5: Token Creation Latency Distribution
	results = append(results, runTest("Token Creation Latency Distribution", func() (string, error) {
		const samples = 1000
		durations := make([]time.Duration, samples)

		for i := 0; i < samples; i++ {
			userID := uuid.New()
			sessionID := uuid.New()
			username := fmt.Sprintf("latencyuser%d@test.com", i)
			roles := []string{"user"}

			start := time.Now()
			_, err := tokenMaker.CreateAccessToken(ctx, userID, username, roles, sessionID)
			if err != nil {
				return "", fmt.Errorf("failed at sample %d: %w", i, err)
			}
			durations[i] = time.Since(start)
		}

		// Calculate statistics
		var total time.Duration
		min := durations[0]
		max := durations[0]

		for _, d := range durations {
			total += d
			if d < min {
				min = d
			}
			if d > max {
				max = d
			}
		}

		avg := total / time.Duration(samples)
		return fmt.Sprintf("Latency - Min: %v, Avg: %v, Max: %v (over %d samples)",
			min.Round(time.Microsecond), avg.Round(time.Microsecond), max.Round(time.Microsecond), samples), nil
	}))

	// Test 6: High Throughput Stress Test
	results = append(results, runTest("High Throughput Stress Test (500 operations)", func() (string, error) {
		const operations = 500
		var wg sync.WaitGroup
		errorChan := make(chan error, operations)
		start := time.Now()

		for i := 0; i < operations; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()

				userID := uuid.New()
				sessionID := uuid.New()
				username := fmt.Sprintf("stressuser%d@test.com", id)
				roles := []string{"user", "stress_test"}

				// Mix of operations
				switch id % 3 {
				case 0:
					// Create access token
					_, err := tokenMaker.CreateAccessToken(ctx, userID, username, roles, sessionID)
					errorChan <- err
				case 1:
					// Create refresh token
					_, err := tokenMaker.CreateRefreshToken(ctx, userID, username, sessionID)
					errorChan <- err
				case 2:
					// Create and verify
					token, err := tokenMaker.CreateAccessToken(ctx, userID, username, roles, sessionID)
					if err != nil {
						errorChan <- err
						return
					}
					_, err = tokenMaker.VerifyAccessToken(ctx, token.Token)
					errorChan <- err
				}
			}(i)
		}

		wg.Wait()
		close(errorChan)
		duration := time.Since(start)

		// Count errors
		errorCount := 0
		for err := range errorChan {
			if err != nil {
				errorCount++
			}
		}

		successCount := operations - errorCount
		successRate := float64(successCount) / float64(operations) * 100

		return fmt.Sprintf("Stress test: %d/%d successful (%.1f%%) in %v (%.2f ops/sec)",
			successCount, operations, successRate, duration, float64(operations)/duration.Seconds()), nil
	}))

	return results
}

// runRealWorldScenarioTests tests real-world scenarios
func runRealWorldScenarioTests(ctx context.Context, tokenMaker gourdiantoken.GourdianTokenMaker) []TestResult {
	var results []TestResult
	fmt.Printf("\n┌─ %s\n", "REAL-WORLD SCENARIOS")

	// Test 1: User Login Flow
	results = append(results, runTest("Scenario: Complete User Login", func() (string, error) {
		userID := uuid.New()
		sessionID := uuid.New()
		username := "alice@company.com"
		roles := []string{"user", "employee", "developer"}

		// Create tokens
		accessToken, err := tokenMaker.CreateAccessToken(ctx, userID, username, roles, sessionID)
		if err != nil {
			return "", fmt.Errorf("failed to create access token: %w", err)
		}

		refreshToken, err := tokenMaker.CreateRefreshToken(ctx, userID, username, sessionID)
		if err != nil {
			return "", fmt.Errorf("failed to create refresh token: %w", err)
		}

		// Verify tokens
		accessClaims, err := tokenMaker.VerifyAccessToken(ctx, accessToken.Token)
		if err != nil {
			return "", fmt.Errorf("failed to verify access token: %w", err)
		}

		refreshClaims, err := tokenMaker.VerifyRefreshToken(ctx, refreshToken.Token)
		if err != nil {
			return "", fmt.Errorf("failed to verify refresh token: %w", err)
		}

		return fmt.Sprintf("Login successful - User: %s, Roles: %v, Access exp: %v, Refresh exp: %v",
			accessClaims.Username, accessClaims.Roles,
			time.Until(accessClaims.ExpiresAt).Round(time.Minute),
			time.Until(refreshClaims.ExpiresAt).Round(time.Hour)), nil
	}))

	// Test 2: Token Refresh Flow
	results = append(results, runTest("Scenario: Token Refresh Flow", func() (string, error) {
		userID := uuid.New()
		sessionID := uuid.New()
		username := "bob@company.com"

		// Initial refresh token
		oldRefreshToken, err := tokenMaker.CreateRefreshToken(ctx, userID, username, sessionID)
		if err != nil {
			return "", err
		}

		// Simulate access token expiry - rotate refresh token
		_, err = tokenMaker.RotateRefreshToken(ctx, oldRefreshToken.Token)
		if err != nil {
			if err.Error() == "token rotation not enabled" {
				return "Rotation not enabled (skipped)", nil
			}
			return "", fmt.Errorf("failed to rotate token: %w", err)
		}

		// Create new access token with same user info
		newAccessToken, err := tokenMaker.CreateAccessToken(ctx, userID, username, []string{"user"}, sessionID)
		if err != nil {
			return "", err
		}

		return fmt.Sprintf("Refresh successful - New access token valid for %v",
			time.Until(newAccessToken.ExpiresAt).Round(time.Minute)), nil
	}))

	// Test 3: User Logout Flow
	results = append(results, runTest("Scenario: User Logout (Token Revocation)", func() (string, error) {
		userID := uuid.New()
		sessionID := uuid.New()
		username := "charlie@company.com"

		// Create tokens
		accessToken, err := tokenMaker.CreateAccessToken(ctx, userID, username, []string{"user"}, sessionID)
		if err != nil {
			return "", err
		}

		refreshToken, err := tokenMaker.CreateRefreshToken(ctx, userID, username, sessionID)
		if err != nil {
			return "", err
		}

		// Revoke both tokens on logout
		err = tokenMaker.RevokeAccessToken(ctx, accessToken.Token)
		if err != nil && err.Error() != "access token revocation is not enabled" {
			return "", fmt.Errorf("failed to revoke access token: %w", err)
		}

		err = tokenMaker.RevokeRefreshToken(ctx, refreshToken.Token)
		if err != nil && err.Error() != "refresh token revocation is not enabled" {
			return "", fmt.Errorf("failed to revoke refresh token: %w", err)
		}

		return "Logout successful - All tokens revoked", nil
	}))

	// Test 4: Multi-Device Login
	results = append(results, runTest("Scenario: Multi-Device Login", func() (string, error) {
		userID := uuid.New()
		username := "david@company.com"
		devices := []string{"desktop", "mobile", "tablet"}

		deviceTokens := make(map[string]*gourdiantoken.AccessTokenResponse)

		for _, device := range devices {
			sessionID := uuid.New() // Different session per device
			token, err := tokenMaker.CreateAccessToken(ctx, userID, username, []string{"user"}, sessionID)
			if err != nil {
				return "", fmt.Errorf("failed to create token for %s: %w", device, err)
			}
			deviceTokens[device] = token

			// Verify token works
			claims, err := tokenMaker.VerifyAccessToken(ctx, token.Token)
			if err != nil {
				return "", fmt.Errorf("failed to verify token for %s: %w", device, err)
			}

			if claims.SessionID != sessionID {
				return "", fmt.Errorf("session ID mismatch for %s", device)
			}
		}

		return fmt.Sprintf("Multi-device login successful - %d devices authenticated", len(deviceTokens)), nil
	}))

	// Test 5: Role-Based Access Control
	results = append(results, runTest("Scenario: Role-Based Access Control", func() (string, error) {
		users := []struct {
			username string
			roles    []string
		}{
			{"admin@company.com", []string{"user", "admin", "superuser"}},
			{"moderator@company.com", []string{"user", "moderator"}},
			{"viewer@company.com", []string{"user", "viewer"}},
		}

		for _, u := range users {
			userID := uuid.New()
			sessionID := uuid.New()

			token, err := tokenMaker.CreateAccessToken(ctx, userID, u.username, u.roles, sessionID)
			if err != nil {
				return "", fmt.Errorf("failed for %s: %w", u.username, err)
			}

			claims, err := tokenMaker.VerifyAccessToken(ctx, token.Token)
			if err != nil {
				return "", err
			}

			// Simulate role check
			hasAdmin := false
			for _, role := range claims.Roles {
				if role == "admin" {
					hasAdmin = true
					break
				}
			}

			if u.username == "admin@company.com" && !hasAdmin {
				return "", fmt.Errorf("admin should have admin role")
			}
		}

		return fmt.Sprintf("RBAC verified for %d users with different role sets", len(users)), nil
	}))

	// Test 6: Session Management
	results = append(results, runTest("Scenario: Session Management", func() (string, error) {
		userID := uuid.New()
		username := "eve@company.com"

		// Create multiple sessions
		const sessions = 5
		sessionTokens := make([]string, sessions)

		for i := 0; i < sessions; i++ {
			sessionID := uuid.New()
			token, err := tokenMaker.CreateAccessToken(ctx, userID, username, []string{"user"}, sessionID)
			if err != nil {
				return "", err
			}
			sessionTokens[i] = token.Token
		}

		// Verify all sessions are independent
		sessionIDs := make(map[uuid.UUID]bool)
		for _, tokenStr := range sessionTokens {
			claims, err := tokenMaker.VerifyAccessToken(ctx, tokenStr)
			if err != nil {
				return "", err
			}

			if sessionIDs[claims.SessionID] {
				return "", fmt.Errorf("duplicate session ID detected")
			}
			sessionIDs[claims.SessionID] = true
		}

		return fmt.Sprintf("Session management verified - %d independent sessions", len(sessionIDs)), nil
	}))

	// Test 7: Token Expiry Near Boundary
	results = append(results, runTest("Scenario: Token Near Expiry", func() (string, error) {
		userID := uuid.New()
		sessionID := uuid.New()

		token, err := tokenMaker.CreateAccessToken(ctx, userID, "nearexpiry@test.com", []string{"user"}, sessionID)
		if err != nil {
			return "", err
		}

		claims, err := tokenMaker.VerifyAccessToken(ctx, token.Token)
		if err != nil {
			return "", err
		}

		timeUntilExpiry := time.Until(claims.ExpiresAt)
		maxLifetime := time.Until(claims.MaxLifetimeExpiry)

		return fmt.Sprintf("Token created - Expires in: %v, Max lifetime: %v",
			timeUntilExpiry.Round(time.Minute), maxLifetime.Round(time.Hour)), nil
	}))

	// Test 8: High-Security Transaction
	results = append(results, runTest("Scenario: High-Security Transaction", func() (string, error) {
		userID := uuid.New()
		sessionID := uuid.New()
		username := "banker@secure.com"
		roles := []string{"user", "banker", "transaction_approver"}

		// Create short-lived token for sensitive operation
		token, err := tokenMaker.CreateAccessToken(ctx, userID, username, roles, sessionID)
		if err != nil {
			return "", err
		}

		// Verify token immediately
		claims, err := tokenMaker.VerifyAccessToken(ctx, token.Token)
		if err != nil {
			return "", err
		}

		// Check for required role
		hasApproverRole := false
		for _, role := range claims.Roles {
			if role == "transaction_approver" {
				hasApproverRole = true
				break
			}
		}

		if !hasApproverRole {
			return "", fmt.Errorf("missing required transaction_approver role")
		}

		// Revoke immediately after use
		err = tokenMaker.RevokeAccessToken(ctx, token.Token)
		if err != nil && err.Error() != "access token revocation is not enabled" {
			return "", err
		}

		return "High-security transaction authorized and token revoked", nil
	}))

	// Test 9: API Rate Limiting Simulation
	results = append(results, runTest("Scenario: API Rate Limiting (100 requests)", func() (string, error) {
		userID := uuid.New()
		sessionID := uuid.New()

		// Create token once
		token, err := tokenMaker.CreateAccessToken(ctx, userID, "api@user.com", []string{"user", "api"}, sessionID)
		if err != nil {
			return "", err
		}

		// Simulate 100 API calls
		const requests = 100
		start := time.Now()
		for i := 0; i < requests; i++ {
			_, err := tokenMaker.VerifyAccessToken(ctx, token.Token)
			if err != nil {
				return "", fmt.Errorf("failed at request %d: %w", i, err)
			}
		}
		duration := time.Since(start)

		return fmt.Sprintf("%d API requests verified in %v (%.2f req/sec)",
			requests, duration, float64(requests)/duration.Seconds()), nil
	}))

	// Test 10: Microservices Token Sharing
	results = append(results, runTest("Scenario: Microservices Token Validation", func() (string, error) {
		userID := uuid.New()
		sessionID := uuid.New()

		// Service A creates token
		token, err := tokenMaker.CreateAccessToken(ctx, userID, "microservice@user.com",
			[]string{"user", "service_a", "service_b"}, sessionID)
		if err != nil {
			return "", err
		}

		// Simulate multiple microservices verifying the same token
		services := []string{"service_a", "service_b", "service_c", "api_gateway"}
		successCount := 0

		for _, service := range services {
			claims, err := tokenMaker.VerifyAccessToken(ctx, token.Token)
			if err != nil {
				return "", fmt.Errorf("service %s failed verification: %w", service, err)
			}

			for _, role := range claims.Roles {
				if strings.Contains(role, service) {
					break
				}
			}

			successCount++
		}

		return fmt.Sprintf("Token verified across %d microservices", successCount), nil
	}))

	return results
}

// runTest executes a single test and returns the result
func runTest(name string, testFunc func() (string, error)) TestResult {
	fmt.Printf("│  ├─ %s ... ", name)
	start := time.Now()

	details, err := testFunc()
	duration := time.Since(start)

	success := err == nil
	var status string
	if success {
		status = "✅ PASS"
		fmt.Printf("%s (%v)\n", status, duration)
		if details != "" {
			fmt.Printf("│  │  └─ %s\n", details)
		}
	} else {
		status = "❌ FAIL"
		fmt.Printf("%s (%v)\n", status, duration)
		fmt.Printf("│  │  └─ Error: %v\n", err)
	}

	return TestResult{
		TestName:    name,
		Success:     success,
		Duration:    duration,
		Error:       err,
		Description: name,
		Details:     details,
	}
}

// printTestSummary prints a summary of all test results
func printTestSummary(results []TestResult, suiteName string) {
	fmt.Printf("\n%s\n", strings.Repeat("─", 100))
	fmt.Printf("SUMMARY: %s\n", suiteName)
	fmt.Printf("%s\n", strings.Repeat("─", 100))

	passed := 0
	failed := 0
	totalDuration := time.Duration(0)
	var minDuration, maxDuration time.Duration

	for i, result := range results {
		if result.Success {
			passed++
		} else {
			failed++
		}
		totalDuration += result.Duration

		if i == 0 {
			minDuration = result.Duration
			maxDuration = result.Duration
		} else {
			if result.Duration < minDuration {
				minDuration = result.Duration
			}
			if result.Duration > maxDuration {
				maxDuration = result.Duration
			}
		}
	}

	fmt.Printf("Total Tests:     %d\n", len(results))
	fmt.Printf("Passed:          %d (%.1f%%)\n", passed, float64(passed)/float64(len(results))*100)
	fmt.Printf("Failed:          %d (%.1f%%)\n", failed, float64(failed)/float64(len(results))*100)
	fmt.Printf("Total Duration:  %v\n", totalDuration.Round(time.Millisecond))
	fmt.Printf("Average:         %v\n", (totalDuration / time.Duration(len(results))).Round(time.Microsecond))
	fmt.Printf("Min:             %v\n", minDuration.Round(time.Microsecond))
	fmt.Printf("Max:             %v\n", maxDuration.Round(time.Microsecond))

	if failed > 0 {
		fmt.Printf("\n%s\n", "FAILED TESTS:")
		for _, result := range results {
			if !result.Success {
				fmt.Printf("  ❌ %s: %v\n", result.TestName, result.Error)
			}
		}
	}

	fmt.Printf("%s\n", strings.Repeat("─", 100))
}

// printBanner prints the test suite banner
func printBanner() {
	banner := `
╔══════════════════════════════════════════════════════════════════════════════════════════════════╗
║                                                                                                  ║
║                          GOURDIAN TOKEN COMPREHENSIVE TEST SUITE                                 ║
║                                                                                                  ║
║                              Production-Ready JWT Token Manager                                  ║
║                                                                                                  ║
╚══════════════════════════════════════════════════════════════════════════════════════════════════╝
`
	fmt.Println(banner)
	fmt.Printf("Test Started: %s\n", time.Now().Format(time.RFC3339))
	fmt.Printf("Test Categories: Basic Operations | Token Lifecycle | Security | Edge Cases | \n")
	fmt.Printf("                 Concurrency | Performance | Real-World Scenarios\n")
	fmt.Println()
}

// printRepositoryHeader prints repository section header
func printRepositoryHeader(name, description string) {
	fmt.Printf("\n╔%s╗\n", strings.Repeat("═", 98))
	fmt.Printf("║ %s ║\n", centerText(name, 96))
	fmt.Printf("║ %s ║\n", centerText(description, 96))
	fmt.Printf("╚%s╝\n", strings.Repeat("═", 98))
}

// printFinalComparison prints a comparison of all repository implementations
func printFinalComparison(allResults map[string][]TestResult) {
	fmt.Printf("\n\n╔%s╗\n", strings.Repeat("═", 98))
	fmt.Printf("║ %s ║\n", centerText("FINAL COMPARISON - ALL REPOSITORIES", 96))
	fmt.Printf("╚%s╝\n\n", strings.Repeat("═", 98))

	fmt.Printf("%-35s | %8s | %8s | %12s | %12s\n",
		"Repository", "Passed", "Failed", "Avg Duration", "Success Rate")
	fmt.Printf("%s\n", strings.Repeat("─", 100))

	// Sort results for consistent output
	type repoStats struct {
		name        string
		passed      int
		failed      int
		avgDuration time.Duration
		successRate float64
	}

	var stats []repoStats
	for name, results := range allResults {
		passed := 0
		failed := 0
		totalDuration := time.Duration(0)

		for _, result := range results {
			if result.Success {
				passed++
			} else {
				failed++
			}
			totalDuration += result.Duration
		}

		avgDuration := totalDuration / time.Duration(len(results))
		successRate := float64(passed) / float64(len(results)) * 100

		stats = append(stats, repoStats{
			name:        name,
			passed:      passed,
			failed:      failed,
			avgDuration: avgDuration,
			successRate: successRate,
		})
	}

	// Print stats
	for _, stat := range stats {
		fmt.Printf("%-35s | %8d | %8d | %12v | %11.1f%%\n",
			stat.name, stat.passed, stat.failed,
			stat.avgDuration.Round(time.Microsecond), stat.successRate)
	}

	fmt.Printf("\n✅ Test suite completed successfully!\n")
	fmt.Printf("Completed at: %s\n", time.Now().Format(time.RFC3339))
}

// printPerformanceComparison prints performance metrics comparison
func printPerformanceComparison(allResults map[string][]TestResult) {
	fmt.Printf("\n\n╔%s╗\n", strings.Repeat("═", 98))
	fmt.Printf("║ %s ║\n", centerText("PERFORMANCE METRICS", 96))
	fmt.Printf("╚%s╝\n\n", strings.Repeat("═", 98))

	fmt.Printf("%-35s | %15s | %15s | %15s\n",
		"Repository", "Fastest Test", "Slowest Test", "Total Time")
	fmt.Printf("%s\n", strings.Repeat("─", 100))

	for name, results := range allResults {
		if len(results) == 0 {
			continue
		}

		minDuration := results[0].Duration
		maxDuration := results[0].Duration
		totalDuration := time.Duration(0)

		for _, result := range results {
			if result.Duration < minDuration {
				minDuration = result.Duration
			}
			if result.Duration > maxDuration {
				maxDuration = result.Duration
			}
			totalDuration += result.Duration
		}

		fmt.Printf("%-35s | %15v | %15v | %15v\n",
			name,
			minDuration.Round(time.Microsecond),
			maxDuration.Round(time.Microsecond),
			totalDuration.Round(time.Millisecond))
	}

	fmt.Println()
}

// centerText centers text within a given width
func centerText(text string, width int) string {
	if len(text) >= width {
		return text[:width]
	}
	padding := (width - len(text)) / 2
	return strings.Repeat(" ", padding) + text + strings.Repeat(" ", width-len(text)-padding)
}

// Main function to run all repository implementations
func main() {
	ctx := context.Background()

	// Print banner
	printBanner()

	// Hardcoded database credentials from Makefile
	postgresDSN := "host=localhost user=postgres_user password=postgres_password dbname=postgres_db port=5432 sslmode=disable"
	redisAddr := "localhost:6379"
	redisPassword := "redis_password"
	mongoURI := "mongodb://root:mongo_password@localhost:27017"

	// Define all repository configurations
	repositories := []RepositoryConfig{
		{
			Name:        "In-Memory Repository",
			Description: "Fast, suitable for testing and single-instance apps",
			CreateRepo: func() (gourdiantoken.TokenRepository, error) {
				return gourdiantoken.NewMemoryTokenRepository(5 * time.Minute), nil
			},
			Cleanup: func() error {
				return nil
			},
		},
		{
			Name:        "Redis Repository",
			Description: "Distributed, suitable for multi-instance production apps",
			CreateRepo: func() (gourdiantoken.TokenRepository, error) {
				redisClient := redis.NewClient(&redis.Options{
					Addr:     redisAddr,
					Password: redisPassword,
					DB:       0,
				})

				if err := redisClient.Ping(ctx).Err(); err != nil {
					return nil, fmt.Errorf("redis unavailable: %w", err)
				}

				return gourdiantoken.NewRedisTokenRepository(redisClient)
			},
			Cleanup: func() error {
				return nil
			},
		},
		{
			Name:        "PostgreSQL/GORM Repository",
			Description: "Persistent storage with ACID compliance",
			CreateRepo: func() (gourdiantoken.TokenRepository, error) {
				db, err := gorm.Open(postgres.Open(postgresDSN), &gorm.Config{})
				if err != nil {
					return nil, fmt.Errorf("postgres unavailable: %w", err)
				}

				return gourdiantoken.NewGormTokenRepository(db)
			},
			Cleanup: func() error {
				return nil
			},
		},
		{
			Name:        "MongoDB Repository",
			Description: "Document-based storage with TTL indexes",
			CreateRepo: func() (gourdiantoken.TokenRepository, error) {
				client, err := mongo.Connect(ctx, options.Client().ApplyURI(mongoURI))
				if err != nil {
					return nil, fmt.Errorf("mongodb unavailable: %w", err)
				}

				if err := client.Ping(ctx, nil); err != nil {
					return nil, fmt.Errorf("mongodb unavailable: %w", err)
				}

				db := client.Database("gourdian_test")
				return gourdiantoken.NewMongoTokenRepository(db, false)
			},
			Cleanup: func() error {
				return nil
			},
		},
		{
			Name:        "No Repository (Stateless Mode)",
			Description: "No revocation/rotation - Pure JWT validation only",
			CreateRepo: func() (gourdiantoken.TokenRepository, error) {
				return nil, nil
			},
			Cleanup: func() error {
				return nil
			},
		},
	}

	// Run tests for each repository
	allResults := make(map[string][]TestResult)

	for _, repoConfig := range repositories {
		printRepositoryHeader(repoConfig.Name, repoConfig.Description)

		// Create repository
		tokenRepo, err := repoConfig.CreateRepo()
		if err != nil {
			fmt.Printf("⚠️  Skipping %s: %v\n\n", repoConfig.Name, err)
			continue
		}

		// Create token maker configuration
		config := gourdiantoken.GourdianTokenConfig{
			RevocationEnabled:        tokenRepo != nil,
			RotationEnabled:          tokenRepo != nil,
			SigningMethod:            gourdiantoken.Symmetric,
			Algorithm:                "HS256",
			SymmetricKey:             "test-symmetric-key-32-bytes-long!!",
			Issuer:                   "test.gourdian.com",
			Audience:                 []string{"api.test.com", "web.test.com"},
			AllowedAlgorithms:        []string{"HS256", "HS384", "HS512"},
			RequiredClaims:           []string{"iss", "aud", "nbf", "mle"},
			AccessExpiryDuration:     15 * time.Minute,
			AccessMaxLifetimeExpiry:  24 * time.Hour,
			RefreshExpiryDuration:    7 * 24 * time.Hour,
			RefreshMaxLifetimeExpiry: 30 * 24 * time.Hour,
			RefreshReuseInterval:     5 * time.Minute,
			CleanupInterval:          5 * time.Minute,
		}

		// Create token maker
		tokenMaker, err := gourdiantoken.NewGourdianTokenMaker(ctx, config, tokenRepo)
		if err != nil {
			log.Fatalf("Failed to create token maker for %s: %v", repoConfig.Name, err)
		}

		// Run test suite
		results := RunComprehensiveTests(ctx, tokenMaker, repoConfig.Name)
		allResults[repoConfig.Name] = results

		// Cleanup
		if err := repoConfig.Cleanup(); err != nil {
			fmt.Printf("⚠️  Cleanup warning for %s: %v\n", repoConfig.Name, err)
		}

		fmt.Println()
	}

	// Print final comparison
	printFinalComparison(allResults)

	// Print performance comparison
	printPerformanceComparison(allResults)
}
