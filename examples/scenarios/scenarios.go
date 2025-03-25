package scenarios

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/gourdian25/gourdiantoken"
	"github.com/gourdian25/gourdiantoken/examples/utils"
	"github.com/redis/go-redis/v9"
)

func RunAsymmetricExample() {
	utils.PrintHeader("Asymmetric Key Example (RSA-SHA256)")

	// Redis configuration for rotation
	redisOpts := &redis.Options{
		Addr:     "localhost:6379",      // Connect to your container
		Password: "GourdianRedisSecret", // No password
		DB:       0,                     // Default DB
	}

	// Configuration
	config := gourdiantoken.NewGourdianTokenConfig(
		"RS256",
		gourdiantoken.Asymmetric,
		"", // No symmetric key
		"examples/keys/rsa_private.pem",
		"examples/keys/rsa_public.pem",
		30*time.Minute, // Access token duration
		24*time.Hour,   // Access token max lifetime
		"api.example.com",
		[]string{"web.example.com", "mobile.example.com"},
		[]string{"RS256"},
		[]string{"jti", "sub", "exp", "iat", "typ", "rol"},
		14*24*time.Hour, // Refresh token duration
		60*24*time.Hour, // Refresh token max lifetime
		10*time.Minute,  // Reuse interval
		true,            // Enable rotation
	)

	// Initialize with Redis
	utils.PrintSection("Initializing Token Maker")
	maker, err := gourdiantoken.NewGourdianTokenMaker(config, redisOpts)
	if err != nil {
		log.Fatalf("Failed to create token maker: %v", err)
	}
	fmt.Println("Token maker initialized with RSA keys and Redis")

	// User data
	userID := uuid.New()
	username := "jane.doe@example.com"
	role := "manager"
	sessionID := uuid.New()

	// Token creation
	utils.PrintSection("Creating Tokens")
	accessToken, err := maker.CreateAccessToken(
		context.Background(),
		userID,
		username,
		role,
		sessionID,
	)
	if err != nil {
		log.Fatalf("Failed to create access token: %v", err)
	}
	utils.PrintTokenDetails("Access", accessToken)

	refreshToken, err := maker.CreateRefreshToken(
		context.Background(),
		userID,
		username,
		sessionID,
	)
	if err != nil {
		log.Fatalf("Failed to create refresh token: %v", err)
	}
	utils.PrintTokenDetails("Refresh", refreshToken)

	// Verification
	utils.VerifyToken(maker, accessToken.Token, gourdiantoken.AccessToken)
	utils.VerifyToken(maker, refreshToken.Token, gourdiantoken.RefreshToken)

	// Rotation demo
	utils.PrintSection("Demonstrating Token Rotation")
	fmt.Println("Waiting 5 seconds before rotation...")
	time.Sleep(5 * time.Second)

	newRefreshToken, err := maker.RotateRefreshToken(refreshToken.Token)
	if err != nil {
		log.Fatalf("Failed to rotate refresh token: %v", err)
	}
	utils.PrintTokenDetails("Rotated Refresh", newRefreshToken)

	// Verify old token is now invalid
	_, err = maker.VerifyRefreshToken(refreshToken.Token)
	if err != nil {
		fmt.Printf("✅ Old token correctly invalidated: %v\n", err)
	}
}

func RunCustomClaimsExample() {
	utils.PrintHeader("Custom Claims Example")

	// Configuration
	config := gourdiantoken.DefaultGourdianTokenConfig(
		"your-32-byte-secret-key-1234567890abcdef",
	)
	config.AccessToken.RequiredClaims = append(config.AccessToken.RequiredClaims, "custom_data")

	// Initialize token maker
	maker, err := gourdiantoken.NewGourdianTokenMaker(config, nil)
	if err != nil {
		log.Fatalf("Failed to create token maker: %v", err)
	}

	// Create token with custom claims
	utils.PrintSection("Creating Token with Custom Claims")
	userID := uuid.New()
	sessionID := uuid.New()

	// In a real implementation, you would extend the AccessTokenClaims struct
	// For this example, we'll use the standard claims and add custom data
	accessToken, err := maker.CreateAccessToken(
		context.Background(),
		userID,
		"custom.user@example.com",
		"premium_user",
		sessionID,
	)
	if err != nil {
		log.Fatalf("Failed to create access token: %v", err)
	}

	// Verify and extract custom claims
	utils.PrintSection("Extracting Custom Claims")
	claims, err := maker.VerifyAccessToken(accessToken.Token)
	if err != nil {
		log.Fatalf("Token verification failed: %v", err)
	}

	// In a real implementation, you would have methods to get custom claims
	fmt.Printf("User %s has role: %s\n", claims.Username, claims.Role)
	fmt.Printf("Session ID: %s\n", claims.SessionID)
	fmt.Printf("Token expires at: %s\n", claims.ExpiresAt.Format(time.RFC3339))

	utils.PrintTokenDetails("Custom Claims Token", accessToken)
}

func RunDefaultConfigExample() {
	utils.PrintHeader("Default Configuration Example")

	// Using default configuration without rotation
	utils.PrintSection("Creating Default Config")
	config := gourdiantoken.DefaultGourdianTokenConfig(
		"your-32-byte-secret-key-1234567890abcdef",
	)
	config.RefreshToken.RotationEnabled = false // Disable rotation for this example
	config.AccessToken.Duration = 45 * time.Second

	// Initialize without Redis
	maker, err := gourdiantoken.NewGourdianTokenMaker(config, nil)
	if err != nil {
		log.Fatalf("Failed to create token maker: %v", err)
	}

	// Create tokens
	userID := uuid.New()
	username := "new.user@myapp.com"
	sessionID := uuid.New()

	utils.PrintSection("Initial Tokens")
	refreshToken, err := maker.CreateRefreshToken(context.Background(), userID, username, sessionID)
	if err != nil {
		log.Fatalf("Failed to create refresh token: %v", err)
	}

	accessToken, err := maker.CreateAccessToken(context.Background(), userID, username, "user", sessionID)
	if err != nil {
		log.Fatalf("Failed to create access token: %v", err)
	}

	// Simulate usage
	utils.PrintSection("Token Usage")
	utils.SimulateAPICall(accessToken.Token)
	fmt.Println("Waiting for access token to expire...")
	time.Sleep(50 * time.Second)

	// Create new access token (no rotation in this example)
	newAccessToken, err := maker.CreateAccessToken(context.Background(), userID, username, "user", sessionID)
	if err != nil {
		log.Fatalf("Failed to create new access token: %v", err)
	}

	utils.PrintSection("Final Verification")
	utils.VerifyToken(maker, newAccessToken.Token, gourdiantoken.AccessToken)
	utils.VerifyToken(maker, refreshToken.Token, gourdiantoken.RefreshToken)
}

func RunEdDSAExample() {
	utils.PrintHeader("EdDSA (Ed25519) Configuration Example")

	config := gourdiantoken.GourdianTokenConfig{
		Algorithm:      "EdDSA",
		SigningMethod:  gourdiantoken.Asymmetric,
		PrivateKeyPath: "examples/keys/ed25519_private.pem",
		PublicKeyPath:  "examples/keys/ed25519_public.pem",
		AccessToken: gourdiantoken.AccessTokenConfig{
			Duration:    30 * time.Minute,
			MaxLifetime: 24 * time.Hour,
			Issuer:      "eddsa.example.com",
		},
		RefreshToken: gourdiantoken.RefreshTokenConfig{
			Duration: 24 * time.Hour,
		},
	}

	maker, err := gourdiantoken.NewGourdianTokenMaker(config, nil)
	if err != nil {
		log.Fatalf("Failed to create token maker: %v", err)
	}

	userID := uuid.New()
	username := "eddsa.user@example.com"
	sessionID := uuid.New()

	utils.PrintSection("Creating EdDSA Signed Tokens")
	accessToken, err := maker.CreateAccessToken(
		context.Background(),
		userID,
		username,
		"user",
		sessionID,
	)
	if err != nil {
		log.Fatalf("Failed to create access token: %v", err)
	}

	utils.PrintSection("Verifying EdDSA Signed Token")
	claims, err := maker.VerifyAccessToken(accessToken.Token)
	if err != nil {
		log.Fatalf("Token verification failed: %v", err)
	}

	fmt.Printf("Successfully verified EdDSA signed token for user: %s\n", claims.Username)
	fmt.Printf("Token uses algorithm: %s\n", config.Algorithm)
}

func RunHighSecurityExample() {
	utils.PrintHeader("High Security Configuration Example")

	// Redis configuration
	redisOpts := &redis.Options{
		Addr:     "localhost:6379",
		Password: "GourdianRedisSecret",
		DB:       0,
	}

	// High security configuration
	config := gourdiantoken.GourdianTokenConfig{
		Algorithm:      "ES256", // ECDSA for stronger security
		SigningMethod:  gourdiantoken.Asymmetric,
		PrivateKeyPath: "examples/keys/ec256_private.pem",
		PublicKeyPath:  "examples/keys/ec256_public.pem",
		AccessToken: gourdiantoken.AccessTokenConfig{
			Duration:          5 * time.Minute,  // Very short-lived access tokens
			MaxLifetime:       30 * time.Minute, // Absolute maximum
			Issuer:            "highsecurity.example.com",
			Audience:          []string{"api.highsecurity.example.com"},
			AllowedAlgorithms: []string{"ES256"},
			RequiredClaims:    []string{"jti", "sub", "exp", "iat", "typ", "rol", "aud", "iss"},
		},
		RefreshToken: gourdiantoken.RefreshTokenConfig{
			Duration:        30 * time.Minute, // Short-lived refresh tokens
			MaxLifetime:     2 * time.Hour,
			ReuseInterval:   1 * time.Minute,
			RotationEnabled: true,
		},
	}

	// Initialize with Redis
	maker, err := gourdiantoken.NewGourdianTokenMaker(config, redisOpts)
	if err != nil {
		log.Fatalf("Failed to create token maker: %v", err)
	}

	// Create tokens
	userID := uuid.New()
	username := "secure.user@example.com"
	sessionID := uuid.New()

	utils.PrintSection("Creating High Security Tokens")
	accessToken, err := maker.CreateAccessToken(
		context.Background(),
		userID,
		username,
		"admin",
		sessionID,
	)
	if err != nil {
		log.Fatalf("Failed to create access token: %v", err)
	}

	refreshToken, err := maker.CreateRefreshToken(
		context.Background(),
		userID,
		username,
		sessionID,
	)
	if err != nil {
		log.Fatalf("Failed to create refresh token: %v", err)
	}

	// Verify with strict requirements
	utils.PrintSection("Strict Verification")
	_, err = maker.VerifyAccessToken(accessToken.Token)
	if err != nil {
		log.Fatalf("Access token verification failed: %v", err)
	}
	fmt.Println("Access token meets all high security requirements")

	_, err = maker.VerifyRefreshToken(refreshToken.Token)
	if err != nil {
		log.Fatalf("Refresh token verification failed: %v", err)
	}
	fmt.Println("Refresh token meets all high security requirements")
}
func RunHMACExample() {
	utils.PrintHeader("HMAC (HS256) Configuration Example")

	// In production, use a secure random key of at least 32 bytes
	secretKey := "your-32-byte-secret-key-1234567890abcdef"

	config := gourdiantoken.DefaultGourdianTokenConfig(secretKey)
	config.AccessToken.Issuer = "hmac.example.com"

	maker, err := gourdiantoken.NewGourdianTokenMaker(config, nil)
	if err != nil {
		log.Fatalf("Failed to create token maker: %v", err)
	}

	userID := uuid.New()
	username := "hmac.user@example.com"
	sessionID := uuid.New()

	utils.PrintSection("Creating HMAC Signed Tokens")
	accessToken, err := maker.CreateAccessToken(
		context.Background(),
		userID,
		username,
		"user",
		sessionID,
	)
	if err != nil {
		log.Fatalf("Failed to create access token: %v", err)
	}

	utils.PrintSection("Verifying HMAC Signed Token")
	claims, err := maker.VerifyAccessToken(accessToken.Token)
	if err != nil {
		log.Fatalf("Token verification failed: %v", err)
	}

	fmt.Printf("Successfully verified HMAC-signed token for user: %s\n", claims.Username)
	fmt.Printf("Token uses algorithm: %s\n", config.Algorithm)
}
func RunMultiTenantExample() {
	utils.PrintHeader("Multi-Tenant Token Example")

	// Configuration for multi-tenant system
	config := gourdiantoken.DefaultGourdianTokenConfig(
		"your-32-byte-secret-key-1234567890abcdef",
	)
	config.AccessToken.Issuer = "auth.multitenant.example.com"
	config.AccessToken.Audience = []string{"api.tenant1.example.com", "api.tenant2.example.com"}
	config.AccessToken.RequiredClaims = append(config.AccessToken.RequiredClaims, "tenant_id")

	// Initialize token maker
	maker, err := gourdiantoken.NewGourdianTokenMaker(config, nil)
	if err != nil {
		log.Fatalf("Failed to create token maker: %v", err)
	}

	// Create token for tenant 1
	utils.PrintSection("Creating Tenant 1 Token")
	tenant1User := uuid.New()
	tenant1Token, err := maker.CreateAccessToken(
		context.Background(),
		tenant1User,
		"user1@tenant1.example.com",
		"tenant_user",
		uuid.New(),
	)
	if err != nil {
		log.Fatalf("Failed to create tenant 1 token: %v", err)
	}

	// In a real implementation, you would modify the claims before signing
	// For demo purposes, we'll just verify with tenant context
	utils.PrintSection("Verifying Tenant Context")
	claims, err := maker.VerifyAccessToken(tenant1Token.Token)
	if err != nil {
		log.Fatalf("Token verification failed: %v", err)
	}

	// Simulate tenant-specific processing
	fmt.Println("Processing request for tenant:", claims.Username)
	fmt.Println("User role:", claims.Role)
	fmt.Println("Token valid for audiences:", config.AccessToken.Audience)

	// Output token details
	utils.PrintTokenDetails("Tenant 1", tenant1Token)
}
func RunRefreshFlowExample() {
	utils.PrintHeader("Token Refresh Flow Example")

	// Redis configuration for rotation
	redisOpts := &redis.Options{
		Addr:     "localhost:6379",      // Connect to your container
		Password: "GourdianRedisSecret", // No password
		DB:       0,                     // Default DB
	}

	// Configuration with rotation enabled
	config := gourdiantoken.NewGourdianTokenConfig(
		"HS256",
		gourdiantoken.Symmetric,
		"your-32-byte-secret-key-1234567890abcdef",
		"", "",
		30*time.Second, // Short access token
		5*time.Minute,
		"auth.example.com",
		[]string{"api.example.com"},
		[]string{"HS256"},
		[]string{"jti", "sub", "exp", "iat", "typ", "rol"},
		2*time.Minute, // Refresh token duration
		10*time.Minute,
		15*time.Second, // Reuse interval
		true,           // Enable rotation
	)

	// Initialize with Redis
	maker, err := gourdiantoken.NewGourdianTokenMaker(config, redisOpts)
	if err != nil {
		log.Fatalf("Failed to create token maker: %v", err)
	}

	// Create initial tokens
	userID := uuid.New()
	username := "demo.user@example.com"
	sessionID := uuid.New()

	utils.PrintSection("Initial Token Creation")
	refreshToken, err := maker.CreateRefreshToken(context.Background(), userID, username, sessionID)
	if err != nil {
		log.Fatalf("Failed to create refresh token: %v", err)
	}
	utils.PrintTokenDetails("Initial Refresh Token", refreshToken)

	accessToken, err := maker.CreateAccessToken(context.Background(), userID, username, "user", sessionID)
	if err != nil {
		log.Fatalf("Failed to create access token: %v", err)
	}
	utils.PrintTokenDetails("Initial Access Token", accessToken)

	// Simulate API usage
	utils.PrintSection("API Usage Simulation")
	utils.SimulateAPICall(accessToken.Token)
	fmt.Println("Waiting for access token to expire...")
	time.Sleep(35 * time.Second)

	// Rotate refresh token
	utils.PrintSection("Refresh Token Rotation")
	fmt.Println("Waiting for reuse interval...")
	time.Sleep(15 * time.Second)

	newRefreshToken, err := maker.RotateRefreshToken(refreshToken.Token)
	if err != nil {
		log.Fatalf("Failed to rotate refresh token: %v", err)
	}
	utils.PrintTokenDetails("New Refresh Token", newRefreshToken)

	// Security check
	utils.PrintSection("Security Validation")
	fmt.Println("Attempting to reuse old refresh token...")
	_, err = maker.RotateRefreshToken(refreshToken.Token)
	if err != nil {
		fmt.Printf("✅ Security check passed: %v\n", err)
	} else {
		fmt.Println("❌ WARNING: Old refresh token was accepted!")
	}
}
func RunRevocationExample() {
	utils.PrintHeader("Token Revocation Example")

	// Redis configuration
	redisOpts := &redis.Options{
		Addr:     "localhost:6379",
		Password: "GourdianRedisSecret",
		DB:       0,
	}

	// Configuration with short token lifetimes for demo
	config := gourdiantoken.DefaultGourdianTokenConfig(
		"your-32-byte-secret-key-1234567890abcdef",
	)
	config.AccessToken.Duration = 2 * time.Minute
	config.RefreshToken.Duration = 10 * time.Minute
	config.RefreshToken.RotationEnabled = true

	// Initialize token maker
	maker, err := gourdiantoken.NewGourdianTokenMaker(config, redisOpts)
	if err != nil {
		log.Fatalf("Failed to create token maker: %v", err)
	}

	// Create tokens
	userID := uuid.New()
	username := "security.demo@example.com"
	sessionID := uuid.New()

	utils.PrintSection("Creating Tokens")
	accessToken, err := maker.CreateAccessToken(context.Background(), userID, username, "user", sessionID)
	if err != nil {
		log.Fatalf("Failed to create access token: %v", err)
	}

	refreshToken, err := maker.CreateRefreshToken(context.Background(), userID, username, sessionID)
	if err != nil {
		log.Fatalf("Failed to create refresh token: %v", err)
	}

	// Verify tokens initially work
	utils.PrintSection("Initial Verification")
	utils.VerifyToken(maker, accessToken.Token, gourdiantoken.AccessToken)
	utils.VerifyToken(maker, refreshToken.Token, gourdiantoken.RefreshToken)

	// Simulate token compromise and revocation
	utils.PrintSection("Simulating Token Compromise")
	fmt.Println("Adding tokens to revocation list...")

	// In a real implementation, you would add methods to JWTMaker for revocation
	// For this example, we'll directly use Redis
	redisClient := redis.NewClient(redisOpts)
	ctx := context.Background()

	// Calculate remaining TTL for tokens
	accessTTL := time.Until(accessToken.ExpiresAt)
	refreshTTL := time.Until(refreshToken.ExpiresAt)

	// Add to revocation list
	err = redisClient.Set(ctx, "revoked:access:"+accessToken.Token, "revoked", accessTTL).Err()
	if err != nil {
		log.Fatalf("Failed to revoke access token: %v", err)
	}

	err = redisClient.Set(ctx, "revoked:refresh:"+refreshToken.Token, "revoked", refreshTTL).Err()
	if err != nil {
		log.Fatalf("Failed to revoke refresh token: %v", err)
	}

	fmt.Println("Tokens successfully revoked")

	// Verify tokens are now invalid
	utils.PrintSection("Post-Revocation Verification")
	_, err = maker.VerifyAccessToken(accessToken.Token)
	if err != nil {
		fmt.Printf("✅ Access token correctly invalidated: %v\n", err)
	}

	_, err = maker.VerifyRefreshToken(refreshToken.Token)
	if err != nil {
		fmt.Printf("✅ Refresh token correctly invalidated: %v\n", err)
	}
}

func RunRSAExample() {
	utils.PrintHeader("RSA (RS256) Configuration Example")

	config := gourdiantoken.GourdianTokenConfig{
		Algorithm:      "RS256",
		SigningMethod:  gourdiantoken.Asymmetric,
		PrivateKeyPath: "examples/keys/rsa_private.pem",
		PublicKeyPath:  "examples/keys/rsa_public.pem",
		AccessToken: gourdiantoken.AccessTokenConfig{
			Duration:    30 * time.Minute,
			MaxLifetime: 24 * time.Hour,
			Issuer:      "rsa.example.com",
		},
		RefreshToken: gourdiantoken.RefreshTokenConfig{
			Duration: 24 * time.Hour,
		},
	}

	maker, err := gourdiantoken.NewGourdianTokenMaker(config, nil)
	if err != nil {
		log.Fatalf("Failed to create token maker: %v", err)
	}

	userID := uuid.New()
	username := "rsa.user@example.com"
	sessionID := uuid.New()

	utils.PrintSection("Creating RSA Signed Tokens")
	accessToken, err := maker.CreateAccessToken(
		context.Background(),
		userID,
		username,
		"user",
		sessionID,
	)
	if err != nil {
		log.Fatalf("Failed to create access token: %v", err)
	}

	utils.PrintSection("Verifying RSA Signed Token")
	claims, err := maker.VerifyAccessToken(accessToken.Token)
	if err != nil {
		log.Fatalf("Token verification failed: %v", err)
	}

	fmt.Printf("Successfully verified RSA-signed token for user: %s\n", claims.Username)
	fmt.Printf("Token ID: %s\n", claims.ID)
	fmt.Printf("Role: %s\n", claims.Role)
}

func RunRSAPSSExample() {
	utils.PrintHeader("RSA-PSS (PS256) Configuration Example")

	// Verify key files exist
	if _, err := os.Stat("examples/keys/rsa_pss_private.pem"); os.IsNotExist(err) {
		log.Fatal("RSA-PSS private key not found at examples/keys/rsa_pss_private.pem")
	}
	if _, err := os.Stat("examples/keys/rsa_pss_public.pem"); os.IsNotExist(err) {
		log.Fatal("RSA-PSS public key not found at examples/keys/rsa_pss_public.pem")
	}

	config := gourdiantoken.GourdianTokenConfig{
		Algorithm:      "PS256",
		SigningMethod:  gourdiantoken.Asymmetric,
		PrivateKeyPath: "examples/keys/rsa_pss_private.pem",
		PublicKeyPath:  "examples/keys/rsa_pss_public.pem",
		AccessToken: gourdiantoken.AccessTokenConfig{
			Duration:          30 * time.Minute,
			MaxLifetime:       24 * time.Hour,
			Issuer:            "rsapss.example.com",
			AllowedAlgorithms: []string{"PS256"}, // Only allow PS256
		},
		RefreshToken: gourdiantoken.RefreshTokenConfig{
			Duration: 24 * time.Hour,
		},
	}

	maker, err := gourdiantoken.NewGourdianTokenMaker(config, nil)
	if err != nil {
		log.Fatalf("Failed to create token maker: %v", err)
	}

	userID := uuid.New()
	username := "rsapss.user@example.com"
	sessionID := uuid.New()

	utils.PrintSection("Creating RSA-PSS Signed Tokens")
	accessToken, err := maker.CreateAccessToken(
		context.Background(),
		userID,
		username,
		"admin",
		sessionID,
	)
	if err != nil {
		log.Fatalf("Failed to create access token: %v", err)
	}

	utils.PrintSection("Verifying RSA-PSS Signed Token")
	claims, err := maker.VerifyAccessToken(accessToken.Token)
	if err != nil {
		log.Fatalf("Token verification failed: %v", err)
	}

	fmt.Printf("Successfully verified RSA-PSS signed token for user: %s\n", claims.Username)
	fmt.Printf("Token uses algorithm: %s\n", config.Algorithm)
	fmt.Printf("Token ID: %s\n", claims.ID)
	fmt.Printf("Session ID: %s\n", claims.SessionID)
}

func RunShortLivedExample() {
	utils.PrintHeader("Short-Lived Token Example")

	// Redis configuration
	redisOpts := &redis.Options{
		Addr:     "localhost:6379",
		Password: "GourdianRedisSecret",
		DB:       0,
	}

	// Configuration with very short token lifetimes
	config := gourdiantoken.DefaultGourdianTokenConfig(
		"your-32-byte-secret-key-1234567890abcdef",
	)
	// Override defaults for this example
	config.AccessToken.Duration = 1 * time.Minute
	config.AccessToken.MaxLifetime = 5 * time.Minute
	config.RefreshToken.Duration = 5 * time.Minute
	config.RefreshToken.MaxLifetime = 30 * time.Minute
	config.RefreshToken.ReuseInterval = 15 * time.Second
	config.RefreshToken.RotationEnabled = true // Enable rotation for this example

	// Initialize with Redis
	maker, err := gourdiantoken.NewGourdianTokenMaker(config, redisOpts)
	if err != nil {
		log.Fatalf("Failed to create token maker: %v", err)
	}

	// Create initial tokens
	userID := uuid.New()
	username := "shortlived.user@example.com"
	sessionID := uuid.New()

	utils.PrintSection("Initial Tokens")
	refreshToken, err := maker.CreateRefreshToken(
		context.Background(),
		userID,
		username,
		sessionID,
	)
	if err != nil {
		log.Fatalf("Failed to create refresh token: %v", err)
	}

	accessToken, err := maker.CreateAccessToken(
		context.Background(),
		userID,
		username,
		"user",
		sessionID,
	)
	if err != nil {
		log.Fatalf("Failed to create access token: %v", err)
	}

	// Demonstrate quick rotation
	utils.PrintSection("Demonstrating Quick Rotation")
	fmt.Println("Waiting for access token to expire...")
	time.Sleep(70 * time.Second) // Slightly more than 1 minute

	// Rotate refresh token to get new access token
	newRefreshToken, err := maker.RotateRefreshToken(refreshToken.Token)
	if err != nil {
		log.Fatalf("Rotation failed: %v", err)
	}

	// Create new access token
	newAccessToken, err := maker.CreateAccessToken(
		context.Background(),
		userID,
		username,
		"user",
		sessionID,
	)
	if err != nil {
		log.Fatalf("Failed to create new access token: %v", err)
	}

	utils.PrintTokenDetails("Old Access Token", accessToken)
	utils.PrintTokenDetails("New Access Token", newAccessToken)
	utils.PrintTokenDetails("New Refresh Token", newRefreshToken)
}

func RunStatelessExample() {
	utils.PrintHeader("Stateless Token Example (No Redis)")

	// Configuration with rotation disabled
	config := gourdiantoken.DefaultGourdianTokenConfig(
		"your-32-byte-secret-key-1234567890abcdef",
	)
	config.RefreshToken.RotationEnabled = false
	config.AccessToken.Duration = 1 * time.Hour
	config.RefreshToken.Duration = 24 * time.Hour

	// Initialize without Redis
	maker, err := gourdiantoken.NewGourdianTokenMaker(config, nil)
	if err != nil {
		log.Fatalf("Failed to create token maker: %v", err)
	}

	// Create tokens
	userID := uuid.New()
	username := "stateless.user@example.com"
	sessionID := uuid.New()

	utils.PrintSection("Creating Tokens")
	accessToken, err := maker.CreateAccessToken(
		context.Background(),
		userID,
		username,
		"user",
		sessionID,
	)
	if err != nil {
		log.Fatalf("Failed to create access token: %v", err)
	}

	refreshToken, err := maker.CreateRefreshToken(
		context.Background(),
		userID,
		username,
		sessionID,
	)
	if err != nil {
		log.Fatalf("Failed to create refresh token: %v", err)
	}

	// Verify tokens
	utils.PrintSection("Token Verification")
	utils.VerifyToken(maker, accessToken.Token, gourdiantoken.AccessToken)
	utils.VerifyToken(maker, refreshToken.Token, gourdiantoken.RefreshToken)

	// Note: Without Redis, rotation is not possible
	fmt.Println("\nNote: Token rotation is disabled in stateless mode")
}
func RunSymmetricExample() {
	utils.PrintHeader("Symmetric Key Example (HMAC-SHA256)")

	// Redis configuration
	redisOpts := &redis.Options{
		Addr:     "localhost:6379",
		Password: "GourdianRedisSecret",
		DB:       0,
	}

	// Configuration
	config := gourdiantoken.NewGourdianTokenConfig(
		"HS256",
		gourdiantoken.Symmetric,
		"your-very-secure-secret-key-at-least-32-bytes",
		"", "",
		15*time.Minute,
		24*time.Hour,
		"auth.example.com",
		[]string{"api.example.com"},
		[]string{"HS256"},
		[]string{"jti", "sub", "exp", "iat", "typ", "rol"},
		7*24*time.Hour,
		30*24*time.Hour,
		5*time.Minute,
		true,
	)

	// Initialize with Redis
	maker, err := gourdiantoken.NewGourdianTokenMaker(config, redisOpts)
	if err != nil {
		log.Fatalf("Failed to create token maker: %v", err)
	}

	// User data
	userID := uuid.MustParse("6bacf1a8-10b6-4756-afb7-05f331e72b6a")
	username := "john.doe@example.com"
	role := "admin"
	sessionID := uuid.New()

	// Token creation
	accessToken, err := maker.CreateAccessToken(
		context.Background(),
		userID,
		username,
		role,
		sessionID,
	)
	if err != nil {
		log.Fatalf("Failed to create access token: %v", err)
	}

	refreshToken, err := maker.CreateRefreshToken(
		context.Background(),
		userID,
		username,
		sessionID,
	)
	if err != nil {
		log.Fatalf("Failed to create refresh token: %v", err)
	}

	// Verification
	utils.VerifyToken(maker, accessToken.Token, gourdiantoken.AccessToken)
	utils.VerifyToken(maker, refreshToken.Token, gourdiantoken.RefreshToken)

	// Rotation demo
	time.Sleep(5 * time.Second)
	newRefreshToken, err := maker.RotateRefreshToken(refreshToken.Token)
	if err != nil {
		log.Fatalf("Rotation failed: %v", err)
	}

	utils.PrintTokenDetails("Rotated Refresh", newRefreshToken)
}
func RunTokenFamilyExample() {
	utils.PrintHeader("Token Family Example")

	// Redis configuration
	redisOpts := &redis.Options{
		Addr:     "localhost:6379",
		Password: "GourdianRedisSecret",
		DB:       0,
	}

	// Configuration with token families
	config := gourdiantoken.DefaultGourdianTokenConfig(
		"your-32-byte-secret-key-1234567890abcdef",
	)
	config.RefreshToken.RotationEnabled = true
	config.RefreshToken.MaxLifetime = 30 * 24 * time.Hour
	config.AccessToken.Duration = 5 * time.Minute // Short access token for demo

	// Initialize token maker
	maker, err := gourdiantoken.NewGourdianTokenMaker(config, redisOpts)
	if err != nil {
		log.Fatalf("Failed to create token maker: %v", err)
	}

	// User data
	userID := uuid.New()
	username := "family.user@example.com"
	familyID := uuid.New().String() // In real implementation, this would be stored per user session

	// Store family ID in Redis
	redisClient := redis.NewClient(redisOpts)
	ctx := context.Background()
	err = redisClient.Set(ctx, "token_family:"+userID.String(), familyID, config.RefreshToken.MaxLifetime).Err()
	if err != nil {
		log.Fatalf("Failed to store token family: %v", err)
	}

	// Create initial tokens
	utils.PrintSection("Initial Token Generation")
	refreshToken, err := maker.CreateRefreshToken(ctx, userID, username, uuid.New())
	if err != nil {
		log.Fatalf("Failed to create refresh token: %v", err)
	}

	accessToken, err := maker.CreateAccessToken(ctx, userID, username, "user", uuid.New())
	if err != nil {
		log.Fatalf("Failed to create access token: %v", err)
	}

	// Simulate token rotation over time
	utils.PrintSection("Simulating Token Rotation Over Time")
	for i := 0; i < 3; i++ {
		fmt.Printf("\nRotation #%d\n", i+1)
		fmt.Println("Waiting for access token to expire...")
		time.Sleep(6 * time.Minute)

		newRefreshToken, err := maker.RotateRefreshToken(refreshToken.Token)
		if err != nil {
			log.Fatalf("Rotation failed: %v", err)
		}

		// Create new access token
		newAccessToken, err := maker.CreateAccessToken(ctx, userID, username, "user", uuid.New())
		if err != nil {
			log.Fatalf("Failed to create access token: %v", err)
		}

		fmt.Println("Successfully rotated tokens")
		refreshToken = newRefreshToken
		accessToken = newAccessToken
	}

	// Verify final tokens
	utils.PrintSection("Final Verification")
	utils.VerifyToken(maker, accessToken.Token, gourdiantoken.AccessToken)
	utils.VerifyToken(maker, refreshToken.Token, gourdiantoken.RefreshToken)
}
