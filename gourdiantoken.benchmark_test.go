// File: gourdiantoken.benchmark_test.go

package gourdiantoken

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
)

// ============================================================================
// TOKEN OPERATION BENCHMARKS
// ============================================================================

func BenchmarkCreateAccessToken(b *testing.B) {
	maker := setupBenchMaker(b)
	userID := uuid.New()
	sessionID := uuid.New()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = maker.CreateAccessToken(context.Background(), userID, "testuser", []string{"user"}, sessionID)
	}
}

func BenchmarkCreateRefreshToken(b *testing.B) {
	maker := setupBenchMaker(b)
	userID := uuid.New()
	sessionID := uuid.New()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = maker.CreateRefreshToken(context.Background(), userID, "testuser", sessionID)
	}
}

func BenchmarkVerifyAccessToken(b *testing.B) {
	maker := setupBenchMaker(b)
	userID := uuid.New()
	sessionID := uuid.New()

	token, _ := maker.CreateAccessToken(context.Background(), userID, "testuser", []string{"user"}, sessionID)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = maker.VerifyAccessToken(context.Background(), token.Token)
	}
}

func BenchmarkVerifyRefreshToken(b *testing.B) {
	maker := setupBenchMaker(b)
	userID := uuid.New()
	sessionID := uuid.New()

	token, _ := maker.CreateRefreshToken(context.Background(), userID, "testuser", sessionID)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = maker.VerifyRefreshToken(context.Background(), token.Token)
	}
}

func BenchmarkRotateRefreshToken(b *testing.B) {
	maker := setupBenchMakerWithRepo(b)
	userID := uuid.New()
	sessionID := uuid.New()

	token, _ := maker.CreateRefreshToken(context.Background(), userID, "testuser", sessionID)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		newToken, _ := maker.RotateRefreshToken(context.Background(), token.Token)
		if newToken != nil {
			token = newToken
		}
	}
}

// ============================================================================
// CRYPTOGRAPHIC BENCHMARKS
// ============================================================================

func BenchmarkSigningMethods(b *testing.B) {
	algorithms := []string{"HS256", "HS384", "HS512"}

	for _, algo := range algorithms {
		b.Run(algo, func(b *testing.B) {
			config := DefaultTestConfig()
			config.Algorithm = algo

			maker, _ := NewGourdianTokenMaker(context.Background(), config, nil)
			jwtMaker := maker.(*JWTMaker)

			userID := uuid.New()
			sessionID := uuid.New()

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, _ = jwtMaker.CreateAccessToken(context.Background(), userID, "testuser", []string{"user"}, sessionID)
			}
		})
	}
}

func BenchmarkTokenHashing(b *testing.B) {
	testTokens := make([]string, 1000)
	for i := 0; i < 1000; i++ {
		testTokens[i] = fmt.Sprintf("token-%d-%s", i, uuid.New().String())
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = hashToken(testTokens[i%1000])
	}
}

func BenchmarkClaimsConversion(b *testing.B) {
	claims := AccessTokenClaims{
		ID:                uuid.New(),
		Subject:           uuid.New(),
		SessionID:         uuid.New(),
		Username:          "testuser",
		Issuer:            "test.com",
		Audience:          []string{"api.test.com"},
		Roles:             []string{"user", "admin"},
		IssuedAt:          time.Now(),
		ExpiresAt:         time.Now().Add(30 * time.Minute),
		NotBefore:         time.Now(),
		MaxLifetimeExpiry: time.Now().Add(24 * time.Hour),
		TokenType:         AccessToken,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = toMapClaims(claims)
	}
}

// ============================================================================
// REPOSITORY BENCHMARKS - COMPARATIVE
// ============================================================================

func BenchmarkRepositoryRevocation_Comparative(b *testing.B) {
	factories := getBenchRepositoryFactories()

	for repoName, factory := range factories {
		b.Run(repoName, func(b *testing.B) {
			repo, cleanup := factory(b)
			defer cleanup()

			ctx := context.Background()
			testToken := "test-revocation-token-" + uuid.New().String()

			b.Run("MarkRevoke", func(b *testing.B) {
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					token := fmt.Sprintf("%s-%d", testToken, i)
					_ = repo.MarkTokenRevoke(ctx, AccessToken, token, 1*time.Hour)
				}
			})

			b.Run("IsRevoked", func(b *testing.B) {
				_ = repo.MarkTokenRevoke(ctx, AccessToken, testToken, 1*time.Hour)

				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					_, _ = repo.IsTokenRevoked(ctx, AccessToken, testToken)
				}
			})

			b.Run("RevokeAndCheckMultiple", func(b *testing.B) {
				tokens := make([]string, 100)
				for i := 0; i < 100; i++ {
					tokens[i] = fmt.Sprintf("%s-multi-%d", testToken, i)
					_ = repo.MarkTokenRevoke(ctx, AccessToken, tokens[i], 1*time.Hour)
				}

				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					for _, token := range tokens {
						_, _ = repo.IsTokenRevoked(ctx, AccessToken, token)
					}
				}
			})
		})
	}
}

func BenchmarkRepositoryRotation_Comparative(b *testing.B) {
	factories := getBenchRepositoryFactories()

	for repoName, factory := range factories {
		b.Run(repoName, func(b *testing.B) {
			repo, cleanup := factory(b)
			defer cleanup()

			ctx := context.Background()
			testToken := "test-rotation-token-" + uuid.New().String()

			b.Run("MarkRotated", func(b *testing.B) {
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					token := fmt.Sprintf("%s-%d", testToken, i)
					_ = repo.MarkTokenRotated(ctx, token, 30*24*time.Hour)
				}
			})

			b.Run("IsRotated", func(b *testing.B) {
				_ = repo.MarkTokenRotated(ctx, testToken, 30*24*time.Hour)

				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					_, _ = repo.IsTokenRotated(ctx, testToken)
				}
			})

			b.Run("GetRotationTTL", func(b *testing.B) {
				_ = repo.MarkTokenRotated(ctx, testToken, 30*24*time.Hour)

				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					_, _ = repo.GetRotationTTL(ctx, testToken)
				}
			})
		})
	}
}

func BenchmarkRepositoryCleanup_Comparative(b *testing.B) {
	factories := getBenchRepositoryFactories()

	for repoName, factory := range factories {
		b.Run(repoName, func(b *testing.B) {
			repo, cleanup := factory(b)
			defer cleanup()

			ctx := context.Background()

			b.Run("CleanupExpiredRevoked_Access", func(b *testing.B) {
				for i := 0; i < 1000; i++ {
					token := fmt.Sprintf("expired-access-%d", i)
					_ = repo.MarkTokenRevoke(ctx, AccessToken, token, 1*time.Nanosecond)
				}

				time.Sleep(10 * time.Millisecond)

				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					_ = repo.CleanupExpiredRevokedTokens(ctx, AccessToken)
				}
			})

			b.Run("CleanupExpiredRevoked_Refresh", func(b *testing.B) {
				for i := 0; i < 1000; i++ {
					token := fmt.Sprintf("expired-refresh-%d", i)
					_ = repo.MarkTokenRevoke(ctx, RefreshToken, token, 1*time.Nanosecond)
				}

				time.Sleep(10 * time.Millisecond)

				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					_ = repo.CleanupExpiredRevokedTokens(ctx, RefreshToken)
				}
			})

			b.Run("CleanupExpiredRotated", func(b *testing.B) {
				for i := 0; i < 1000; i++ {
					token := fmt.Sprintf("expired-rotated-%d", i)
					_ = repo.MarkTokenRotated(ctx, token, 1*time.Nanosecond)
				}

				time.Sleep(10 * time.Millisecond)

				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					_ = repo.CleanupExpiredRotatedTokens(ctx)
				}
			})
		})
	}
}

// ============================================================================
// CONCURRENT OPERATION BENCHMARKS
// ============================================================================

func BenchmarkConcurrentTokenCreation(b *testing.B) {
	maker := setupBenchMaker(b)
	numGoroutines := []int{1, 10, 50, 100}

	for _, numG := range numGoroutines {
		b.Run(fmt.Sprintf("Goroutines_%d", numG), func(b *testing.B) {
			b.ResetTimer()

			var wg sync.WaitGroup
			operationsPerGoroutine := b.N / numG
			if b.N%numG != 0 {
				operationsPerGoroutine++
			}

			for g := 0; g < numG; g++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					userID := uuid.New()
					sessionID := uuid.New()

					for i := 0; i < operationsPerGoroutine; i++ {
						_, _ = maker.CreateAccessToken(
							context.Background(),
							userID,
							"testuser",
							[]string{"user"},
							sessionID,
						)
					}
				}()
			}

			wg.Wait()
		})
	}
}

func BenchmarkConcurrentTokenVerification(b *testing.B) {
	maker := setupBenchMaker(b)
	userID := uuid.New()
	sessionID := uuid.New()

	// Pre-create tokens
	tokens := make([]string, 100)
	for i := 0; i < 100; i++ {
		resp, _ := maker.CreateAccessToken(context.Background(), userID, "testuser", []string{"user"}, sessionID)
		tokens[i] = resp.Token
	}

	numGoroutines := []int{1, 10, 50, 100}

	for _, numG := range numGoroutines {
		b.Run(fmt.Sprintf("Goroutines_%d", numG), func(b *testing.B) {
			b.ResetTimer()

			var wg sync.WaitGroup
			operationsPerGoroutine := b.N / numG
			if b.N%numG != 0 {
				operationsPerGoroutine++
			}

			for g := 0; g < numG; g++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for i := 0; i < operationsPerGoroutine; i++ {
						tokenIdx := i % len(tokens)
						_, _ = maker.VerifyAccessToken(context.Background(), tokens[tokenIdx])
					}
				}()
			}

			wg.Wait()
		})
	}
}

func BenchmarkConcurrentRevocation_Comparative(b *testing.B) {
	factories := getBenchRepositoryFactories()

	for repoName, factory := range factories {
		b.Run(repoName, func(b *testing.B) {
			repo, cleanup := factory(b)
			defer cleanup()

			numGoroutines := []int{1, 10, 50}

			for _, numG := range numGoroutines {
				b.Run(fmt.Sprintf("Goroutines_%d", numG), func(b *testing.B) {
					ctx := context.Background()
					operationsPerGoroutine := b.N / numG
					if b.N%numG != 0 {
						operationsPerGoroutine++
					}

					b.ResetTimer()

					var wg sync.WaitGroup
					for g := 0; g < numG; g++ {
						wg.Add(1)
						go func(goroutineID int) {
							defer wg.Done()
							for i := 0; i < operationsPerGoroutine; i++ {
								token := fmt.Sprintf("token-g%d-i%d-%s", goroutineID, i, uuid.New().String())
								_ = repo.MarkTokenRevoke(ctx, AccessToken, token, 1*time.Hour)

								_, _ = repo.IsTokenRevoked(ctx, AccessToken, token)
							}
						}(g)
					}

					wg.Wait()
				})
			}
		})
	}
}

func BenchmarkConcurrentRotationAndRevocation(b *testing.B) {
	factories := getBenchRepositoryFactories()

	for repoName, factory := range factories {
		b.Run(repoName, func(b *testing.B) {
			repo, cleanup := factory(b)
			defer cleanup()

			ctx := context.Background()
			numGoroutines := 20

			b.ResetTimer()

			var wg sync.WaitGroup
			operationsPerGoroutine := b.N / numGoroutines

			for g := 0; g < numGoroutines; g++ {
				wg.Add(1)
				go func(goroutineID int) {
					defer wg.Done()

					for i := 0; i < operationsPerGoroutine; i++ {
						token := fmt.Sprintf("token-g%d-i%d-%s", goroutineID, i, uuid.New().String())

						if i%2 == 0 {
							_ = repo.MarkTokenRevoke(ctx, AccessToken, token, 1*time.Hour)
							_, _ = repo.IsTokenRevoked(ctx, AccessToken, token)
						} else {
							_ = repo.MarkTokenRotated(ctx, token, 30*24*time.Hour)
							_, _ = repo.IsTokenRotated(ctx, token)
						}
					}
				}(g)
			}

			wg.Wait()
		})
	}
}

// ============================================================================
// MEMORY BENCHMARKS
// ============================================================================

func BenchmarkTokenClaimsMemory(b *testing.B) {
	b.Run("AccessToken", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			_ = AccessTokenClaims{
				ID:                uuid.New(),
				Subject:           uuid.New(),
				SessionID:         uuid.New(),
				Username:          "testuser@example.com",
				Issuer:            "auth.example.com",
				Audience:          []string{"api.example.com", "web.example.com"},
				Roles:             []string{"user", "admin", "moderator"},
				IssuedAt:          time.Now(),
				ExpiresAt:         time.Now().Add(30 * time.Minute),
				NotBefore:         time.Now(),
				MaxLifetimeExpiry: time.Now().Add(24 * time.Hour),
				TokenType:         AccessToken,
			}
		}
	})

	b.Run("RefreshToken", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			_ = RefreshTokenClaims{
				ID:                uuid.New(),
				Subject:           uuid.New(),
				SessionID:         uuid.New(),
				Username:          "testuser@example.com",
				Issuer:            "auth.example.com",
				Audience:          []string{"api.example.com"},
				IssuedAt:          time.Now(),
				ExpiresAt:         time.Now().Add(7 * 24 * time.Hour),
				NotBefore:         time.Now(),
				MaxLifetimeExpiry: time.Now().Add(30 * 24 * time.Hour),
				TokenType:         RefreshToken,
			}
		}
	})
}

func BenchmarkMemoryRepositoryMemoryUsage(b *testing.B) {
	repo := NewMemoryTokenRepository(1 * time.Hour)
	ctx := context.Background()

	b.Run("TokenStorage_1000", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			b.StopTimer()
			token := fmt.Sprintf("token-%d-%s", i, uuid.New().String())
			b.StartTimer()

			_ = repo.MarkTokenRevoke(ctx, AccessToken, token, 1*time.Hour)
		}
	})

	b.Run("TokenLookup_1000", func(b *testing.B) {
		tokens := make([]string, 1000)
		for i := 0; i < 1000; i++ {
			token := fmt.Sprintf("lookup-token-%d", i)
			tokens[i] = token
			_ = repo.MarkTokenRevoke(ctx, AccessToken, token, 1*time.Hour)
		}

		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			tokenIdx := i % len(tokens)
			_, _ = repo.IsTokenRevoked(ctx, AccessToken, tokens[tokenIdx])
		}
	})

	if memRepo, ok := repo.(*MemoryTokenRepository); ok {
		_ = memRepo.Close()
	}
}

// ============================================================================
// THROUGHPUT BENCHMARKS
// ============================================================================

func BenchmarkThroughput_TokenCreation(b *testing.B) {
	maker := setupBenchMaker(b)
	userID := uuid.New()
	sessionID := uuid.New()

	b.ResetTimer()
	startTime := time.Now()
	count := int64(0)

	for i := 0; i < b.N; i++ {
		_, _ = maker.CreateAccessToken(context.Background(), userID, "testuser", []string{"user"}, sessionID)
		atomic.AddInt64(&count, 1)
	}

	elapsed := time.Since(startTime)
	throughput := float64(count) / elapsed.Seconds()
	b.ReportMetric(throughput, "tokens/sec")
}

func BenchmarkThroughput_Repository(b *testing.B) {
	factories := getBenchRepositoryFactories()

	for repoName, factory := range factories {
		b.Run(repoName, func(b *testing.B) {
			repo, cleanup := factory(b)
			defer cleanup()

			ctx := context.Background()

			b.Run("Revocation", func(b *testing.B) {
				b.ResetTimer()
				startTime := time.Now()
				count := int64(0)

				for i := 0; i < b.N; i++ {
					token := fmt.Sprintf("token-%d-%s", i, uuid.New().String())
					_ = repo.MarkTokenRevoke(ctx, AccessToken, token, 1*time.Hour)
					atomic.AddInt64(&count, 1)
				}

				elapsed := time.Since(startTime)
				throughput := float64(count) / elapsed.Seconds()
				b.ReportMetric(throughput, "ops/sec")
			})

			b.Run("Lookup", func(b *testing.B) {
				token := "bench-lookup-token"
				_ = repo.MarkTokenRevoke(ctx, AccessToken, token, 1*time.Hour)

				b.ResetTimer()
				startTime := time.Now()
				count := int64(0)

				for i := 0; i < b.N; i++ {
					_, _ = repo.IsTokenRevoked(ctx, AccessToken, token)
					atomic.AddInt64(&count, 1)
				}

				elapsed := time.Since(startTime)
				throughput := float64(count) / elapsed.Seconds()
				b.ReportMetric(throughput, "ops/sec")
			})
		})
	}
}

// ============================================================================
// END-TO-END WORKFLOW BENCHMARKS
// ============================================================================

func BenchmarkEndToEnd_TokenLifecycle(b *testing.B) {
	maker := setupBenchMakerWithRepo(b)
	userID := uuid.New()
	sessionID := uuid.New()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Create token
		accessResp, _ := maker.CreateAccessToken(
			context.Background(),
			userID,
			"testuser",
			[]string{"user"},
			sessionID,
		)

		// Verify token
		_, _ = maker.VerifyAccessToken(context.Background(), accessResp.Token)

		// Revoke token
		_ = maker.RevokeAccessToken(context.Background(), accessResp.Token)
	}
}

func BenchmarkEndToEnd_RefreshFlow(b *testing.B) {
	maker := setupBenchMakerWithRepo(b)
	userID := uuid.New()
	sessionID := uuid.New()

	refreshResp, _ := maker.CreateRefreshToken(
		context.Background(),
		userID,
		"testuser",
		sessionID,
	)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = maker.VerifyRefreshToken(context.Background(), refreshResp.Token)

		newRefresh, _ := maker.RotateRefreshToken(context.Background(), refreshResp.Token)
		if newRefresh != nil {
			refreshResp = newRefresh
		}
	}
}

// ============================================================================
// STRESS TEST BENCHMARKS
// ============================================================================

func BenchmarkStress_HighConcurrencyTokenOperations(b *testing.B) {
	maker := setupBenchMaker(b)
	numGoroutines := 100
	numTokens := 50

	tokens := make([]string, numTokens)
	userID := uuid.New()
	sessionID := uuid.New()

	// Pre-create tokens
	for i := 0; i < numTokens; i++ {
		resp, _ := maker.CreateAccessToken(context.Background(), userID, "testuser", []string{"user"}, sessionID)
		tokens[i] = resp.Token
	}

	b.ResetTimer()

	var wg sync.WaitGroup
	operationsPerGoroutine := b.N / numGoroutines

	for g := 0; g < numGoroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < operationsPerGoroutine; i++ {
				tokenIdx := i % len(tokens)
				_, _ = maker.VerifyAccessToken(context.Background(), tokens[tokenIdx])
			}
		}()
	}

	wg.Wait()
}

func BenchmarkStress_RepositoryLoad(b *testing.B) {
	factories := getBenchRepositoryFactories()

	for repoName, factory := range factories {
		b.Run(repoName, func(b *testing.B) {
			repo, cleanup := factory(b)
			defer cleanup()

			ctx := context.Background()
			numGoroutines := 50

			b.ResetTimer()

			var wg sync.WaitGroup
			operationsPerGoroutine := b.N / numGoroutines

			var successCount, errorCount int64

			for g := 0; g < numGoroutines; g++ {
				wg.Add(1)
				go func(goroutineID int) {
					defer wg.Done()
					for i := 0; i < operationsPerGoroutine; i++ {
						token := fmt.Sprintf("stress-g%d-i%d-%s", goroutineID, i, uuid.New().String())

						if err := repo.MarkTokenRevoke(ctx, AccessToken, token, 1*time.Hour); err == nil {
							atomic.AddInt64(&successCount, 1)
						} else {
							atomic.AddInt64(&errorCount, 1)
						}

						if _, err := repo.IsTokenRevoked(ctx, AccessToken, token); err == nil {
							atomic.AddInt64(&successCount, 1)
						} else {
							atomic.AddInt64(&errorCount, 1)
						}
					}
				}(g)
			}

			wg.Wait()

			b.ReportMetric(float64(successCount), "successful_ops")
			b.ReportMetric(float64(errorCount), "failed_ops")
		})
	}
}

// ============================================================================
// REPOSITORY OPERATIONS BENCHMARK - COMPARATIVE
// ============================================================================

func BenchmarkRepositoryOperations(b *testing.B) {
	factories := getBenchRepositoryFactories()

	for repoName, factory := range factories {
		b.Run(repoName, func(b *testing.B) {
			repo, cleanup := factory(b)
			defer cleanup()

			ctx := context.Background()

			b.Run("MarkTokenRevoke", func(b *testing.B) {
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					token := fmt.Sprintf("bench-token-%d-%s", i, uuid.New().String())
					_ = repo.MarkTokenRevoke(ctx, AccessToken, token, 1*time.Hour)
				}
			})

			b.Run("IsTokenRevoked", func(b *testing.B) {
				// Setup - create a token to check
				token := "bench-check-token-" + uuid.New().String()
				_ = repo.MarkTokenRevoke(ctx, AccessToken, token, 1*time.Hour)

				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					_, _ = repo.IsTokenRevoked(ctx, AccessToken, token)
				}
			})

			b.Run("MarkTokenRotated", func(b *testing.B) {
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					token := fmt.Sprintf("bench-rotate-%d-%s", i, uuid.New().String())
					_ = repo.MarkTokenRotated(ctx, token, 1*time.Hour)
				}
			})

			b.Run("GetRotationTTL", func(b *testing.B) {
				// Setup - create a rotated token to check TTL
				token := "bench-ttl-token-" + uuid.New().String()
				_ = repo.MarkTokenRotated(ctx, token, 1*time.Hour)

				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					_, _ = repo.GetRotationTTL(ctx, token)
				}
			})
		})
	}
}
