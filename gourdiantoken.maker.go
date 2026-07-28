// File: gourdiantoken.maker.go

package gourdiantoken

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// JWTMaker is the concrete implementation of GourdianTokenMaker.
// Handles JWT token lifecycle with configurable security features and multiple signing algorithms.
//
// Thread Safety:
//
//	Safe for concurrent use. Internal state is immutable after initialization.
//
// Lifecycle:
//   - Create with NewGourdianTokenMaker or DefaultGourdianTokenMaker
//   - Automatically starts background cleanup goroutines if rotation/revocation enabled
//   - Cleanup goroutines run for the lifetime of the process; there is currently no
//     way to stop them once started (see Close(), added in a later release)
type JWTMaker struct {
	// config holds the immutable configuration for token operations.
	config GourdianTokenConfig

	// signingMethod is the JWT signing algorithm instance (e.g., HS256, RS256).
	signingMethod jwt.SigningMethod

	// privateKey holds the cryptographic key for signing (HMAC secret or private key).
	privateKey interface{}

	// publicKey holds the verification key (HMAC secret or public key).
	publicKey interface{}

	// tokenRepo provides persistent storage for revocation and rotation tracking.
	tokenRepo TokenRepository

	// cleanupCancel cancels background cleanup goroutines.
	cleanupCancel context.CancelFunc

	// logf receives error reports from background cleanup goroutines.
	// Defaults to a fmt.Printf-based logger; override via WithLogger.
	logf func(format string, args ...any)

	// structuredLogger, when set via WithStructuredLogger, is used instead
	// of logf for the same two background-cleanup error reports. nil means
	// logf remains the reporting path (the original, unaffected behavior).
	structuredLogger Logger

	// closeOnce ensures Close is idempotent.
	closeOnce sync.Once
}

// Option configures optional behavior for a JWTMaker, passed to NewGourdianTokenMaker.
type Option func(*JWTMaker)

// WithLogger sets the function used to report errors from background cleanup
// goroutines. Defaults to a fmt.Printf-based logger. Passing nil is a no-op.
func WithLogger(logf func(format string, args ...any)) Option {
	return func(maker *JWTMaker) {
		if logf != nil {
			maker.logf = logf
		}
	}
}

// Close stops the maker's background cleanup goroutines. Safe to call multiple
// times and safe to call even if rotation/revocation were never enabled (in which
// case there are no goroutines to stop). After Close, the maker itself remains
// usable for Create/Verify/Revoke/Rotate — only the background cleanup stops.
func (maker *JWTMaker) Close() error {
	maker.closeOnce.Do(func() {
		if maker.cleanupCancel != nil {
			maker.cleanupCancel()
		}
	})
	return nil
}

// NewGourdianTokenMaker creates a new GourdianTokenMaker with the specified configuration and token repository.
// This is the main constructor that provides full control over token maker initialization.
//
// Initialization Process:
//  1. Validates the configuration for security and consistency
//  2. Checks algorithm and signing method compatibility
//  3. Initializes cryptographic keys (loads from files for asymmetric)
//  4. Sets up background cleanup goroutines if rotation/revocation enabled
//  5. Returns a fully configured token maker ready for use
//
// Background Operations:
//
//	If rotation or revocation is enabled, background goroutines are started to:
//	- Clean up expired revoked tokens (prevents memory leaks)
//	- Clean up expired rotation markers (prevents memory leaks)
//	These goroutines run at intervals specified by config.CleanupInterval
//
// Parameters:
//   - ctx: Context for initialization. If cancelled, initialization fails immediately.
//   - config: Token maker configuration (see GourdianTokenConfig for details)
//   - tokenRepo: Repository for token storage. Required if RevocationEnabled or RotationEnabled is true.
//     Can be nil for stateless operation (revocation and rotation must be disabled).
//
// Returns:
//   - GourdianTokenMaker: Configured token maker instance ready for production use
//   - error: If configuration is invalid, keys cannot be loaded, context is cancelled,
//     or repository is required but nil
//
// Configuration Validation:
//   - Checks signing method matches algorithm (e.g., HS256 requires Symmetric)
//   - Validates key files exist and have secure permissions (0600 for private keys)
//   - Ensures durations are positive and logical (expiry < max lifetime)
//   - Verifies required parameters are provided for the chosen signing method
//
// Example (Symmetric with rotation and revocation):
//
//	config := gourdiantoken.GourdianTokenConfig{
//	    SigningMethod: gourdiantoken.Symmetric,
//	    Algorithm: "HS256",
//	    SymmetricKey: "your-secret-key-at-least-32-bytes-long",
//	    Issuer: "auth.example.com",
//	    Audience: []string{"api.example.com"},
//	    RevocationEnabled: true,
//	    RotationEnabled: true,
//	    AccessExpiryDuration: 30 * time.Minute,
//	    AccessMaxLifetimeExpiry: 24 * time.Hour,
//	    RefreshExpiryDuration: 7 * 24 * time.Hour,
//	    RefreshMaxLifetimeExpiry: 30 * 24 * time.Hour,
//	    CleanupInterval: 6 * time.Hour,
//	}
//
//	maker, err := gourdiantoken.NewGourdianTokenMaker(ctx, config, tokenRepo)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
// Example (Asymmetric with RSA):
//
//	config := gourdiantoken.GourdianTokenConfig{
//	    SigningMethod: gourdiantoken.Asymmetric,
//	    Algorithm: "RS256",
//	    PrivateKeyPath: "/path/to/private.pem",
//	    PublicKeyPath: "/path/to/public.pem",
//	    Issuer: "auth.example.com",
//	    RevocationEnabled: false,
//	    RotationEnabled: false,
//	    AccessExpiryDuration: 15 * time.Minute,
//	    RefreshExpiryDuration: 7 * 24 * time.Hour,
//	}
//
//	maker, err := gourdiantoken.NewGourdianTokenMaker(ctx, config, nil)
func NewGourdianTokenMaker(ctx context.Context, config GourdianTokenConfig, tokenRepo TokenRepository, opts ...Option) (GourdianTokenMaker, error) {
	// Check context cancellation first
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context canceled: %w", err)
	}

	// Validate configuration
	if err := validateConfig(&config); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	if err := validateAlgorithmAndMethod(&config); err != nil {
		return nil, fmt.Errorf("invalid algorithm/method combination: %w", err)
	}

	// Check repository requirements
	if (config.RotationEnabled || config.RevocationEnabled) && tokenRepo == nil {
		return nil, fmt.Errorf("%w: RotationEnabled=%v, RevocationEnabled=%v", ErrTokenRepositoryRequired, config.RotationEnabled, config.RevocationEnabled)
	}

	maker := &JWTMaker{
		config: config,
		logf:   func(format string, args ...any) { fmt.Printf(format, args...) },
	}

	for _, opt := range opts {
		opt(maker)
	}

	// Set repository if any feature requiring it is enabled
	if config.RotationEnabled || config.RevocationEnabled {
		maker.tokenRepo = tokenRepo

		// Create a cleanup context
		cleanupCtx, cancel := context.WithCancel(context.Background())
		maker.cleanupCancel = cancel

		// Check context again before starting goroutines
		if err := ctx.Err(); err != nil {
			cancel()
			return nil, fmt.Errorf("context canceled: %w", err)
		}

		// Set up background cleanup if needed
		if config.RotationEnabled {
			go maker.cleanupRotatedTokens(cleanupCtx)
		}
		if config.RevocationEnabled {
			go maker.cleanupRevokedTokens(cleanupCtx)
		}
	}

	// Initialize signing method
	if err := maker.initializeSigningMethod(); err != nil {
		if maker.cleanupCancel != nil {
			maker.cleanupCancel()
		}
		return nil, fmt.Errorf("failed to initialize signing method: %w", err)
	}

	// Initialize cryptographic keys
	if err := maker.initializeKeys(); err != nil {
		if maker.cleanupCancel != nil {
			maker.cleanupCancel()
		}
		return nil, fmt.Errorf("failed to initialize keys: %w", err)
	}

	return maker, nil
}

// DefaultGourdianTokenMaker creates a token maker with sensible defaults for quick setup.
// Uses symmetric HMAC-SHA256 signing with minimal configuration required.
//
// Default Configuration:
//   - Algorithm: HS256 (HMAC-SHA256)
//   - Issuer: "gourdian.com"
//   - AllowedAlgorithms: ["HS256", "RS256", "ES256", "PS256"]
//   - RequiredClaims: ["iss", "aud", "nbf", "mle"]
//   - AccessExpiryDuration: 30 minutes
//   - AccessMaxLifetimeExpiry: 24 hours
//   - RefreshExpiryDuration: 7 days
//   - RefreshMaxLifetimeExpiry: 30 days
//   - RefreshReuseInterval: 5 minutes
//   - CleanupInterval: 6 hours
//
// Automatic Feature Detection:
//   - If tokenRepo is provided: RevocationEnabled and RotationEnabled are set to true
//   - If tokenRepo is nil: RevocationEnabled and RotationEnabled are set to false
//
// Parameters:
//   - ctx: Context for initialization (cancellation support)
//   - symmetricKey: Secret key for HMAC signing (must be at least 32 bytes)
//   - tokenRepo: Optional token repository. If provided, enables revocation and rotation.
//     Pass nil for stateless operation without these features.
//
// Returns:
//   - GourdianTokenMaker: Configured token maker with default settings
//   - error: If initialization fails or context is cancelled
//
// Use Cases:
//   - Rapid prototyping and development
//   - Simple authentication systems
//   - Microservices with symmetric signing
//   - Getting started with JWT tokens
//
// Security Considerations:
//
//	For production systems, consider using NewGourdianTokenMaker with:
//	- Asymmetric signing for distributed systems
//	- Shorter access token durations (15 minutes)
//	- Custom audience and issuer values
//	- Stricter allowed algorithms list
//
// Example (Stateless - no repository):
//
//	maker, err := gourdiantoken.DefaultGourdianTokenMaker(
//	    ctx,
//	    "your-secret-key-at-least-32-bytes-long",
//	    nil, // No token repository, stateless operation
//	)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	// Revocation and rotation are disabled
//
// Example (With repository - rotation and revocation enabled):
//
//	redisRepo := NewRedisTokenRepository(redisClient)
//	maker, err := gourdiantoken.DefaultGourdianTokenMaker(
//	    ctx,
//	    "your-secret-key-at-least-32-bytes-long",
//	    redisRepo, // Token repository provided
//	)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	// Revocation and rotation are automatically enabled
func DefaultGourdianTokenMaker(
	ctx context.Context,
	symmetricKey string,
	tokenRepo TokenRepository,
	opts ...Option,
) (GourdianTokenMaker, error) {
	config := GourdianTokenConfig{
		RevocationEnabled:        false,
		RotationEnabled:          false,
		Algorithm:                "HS256",
		SymmetricKey:             symmetricKey,
		PrivateKeyPath:           "",
		PublicKeyPath:            "",
		Issuer:                   "gourdian.com",
		Audience:                 nil,
		AllowedAlgorithms:        []string{"HS256", "RS256", "ES256", "PS256"},
		RequiredClaims:           []string{"iss", "aud", "nbf", "mle"},
		SigningMethod:            Symmetric,
		AccessExpiryDuration:     30 * time.Minute,
		AccessMaxLifetimeExpiry:  24 * time.Hour,
		RefreshExpiryDuration:    7 * 24 * time.Hour,
		RefreshMaxLifetimeExpiry: 30 * 24 * time.Hour,
		RefreshReuseInterval:     5 * time.Minute,
		CleanupInterval:          6 * time.Hour,
	}

	if tokenRepo != nil {
		config.RevocationEnabled = true
		config.RotationEnabled = true
	}
	return NewGourdianTokenMaker(ctx, config, tokenRepo, opts...)
}

// validateUserAndUsername validates the userID/username preconditions shared by
// CreateAccessToken and CreateRefreshToken.
func validateUserAndUsername(userID string, username string) error {
	if userID == "" {
		return fmt.Errorf("invalid user ID: cannot be empty")
	}
	if len(username) > 1024 {
		return fmt.Errorf("username too long: max 1024 characters")
	}
	return nil
}

// newTokenID generates a new random token ID (a UUIDv4 string), centralizing the
// uuid.NewRandom error path. uuid.NewRandom is used rather than uuid.NewString
// because the latter panics on entropy-read failure instead of returning an error.
func newTokenID() (string, error) {
	tokenID, err := uuid.NewRandom()
	if err != nil {
		return "", fmt.Errorf("failed to generate token ID: %w", err)
	}
	return tokenID.String(), nil
}

// signClaims builds map claims via toMapClaims and signs the resulting JWT, checking
// for context cancellation before the CPU-intensive signing operation.
func (maker *JWTMaker) signClaims(ctx context.Context, claims interface{}, tokenType TokenType) (string, error) {
	mapClaims, err := toMapClaims(claims)
	if err != nil {
		return "", fmt.Errorf("failed to build claims: %w", err)
	}
	token := jwt.NewWithClaims(maker.signingMethod, mapClaims)

	// Check context before CPU-intensive signing operation
	if err := ctx.Err(); err != nil {
		return "", fmt.Errorf("context canceled before signing: %w", err)
	}

	signedToken, err := token.SignedString(maker.privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign %s token: %w", tokenType, err)
	}

	return signedToken, nil
}

// CreateAccessToken generates a new signed access token with the specified claims.
// Access tokens are short-lived and include user identity, session, and authorization roles.
//
// Token Structure:
//   - Header: Algorithm and token type
//   - Payload: User claims (ID, username, roles, timestamps)
//   - Signature: Cryptographic signature for verification
//
// Automatic Claims:
//   - jti: Unique token identifier (auto-generated UUIDv4)
//   - iat: Issued at timestamp (current time)
//   - exp: Expiration time (iat + AccessExpiryDuration)
//   - nbf: Not before time (current time)
//   - mle: Maximum lifetime expiry (iat + AccessMaxLifetimeExpiry)
//   - iss: Issuer from configuration
//   - aud: Audience from configuration
//   - typ: Token type ("access")
//
// Validation:
//   - userID must not be empty
//   - username must not exceed 1024 characters
//   - roles must contain at least one non-empty string
//   - sessionID can be any string (including empty for sessionless tokens)
//
// Parameters:
//   - ctx: Context for cancellation. Checks are performed before signing and during I/O.
//   - userID: The user's unique identifier (must not be empty)
//   - username: Human-readable username (max 1024 characters, can be empty)
//   - roles: List of authorization roles (must contain at least one non-empty role)
//   - sessionID: Session identifier (can be empty for sessionless operation)
//
// Returns:
//   - *AccessTokenResponse: Complete token response with signed JWT and metadata
//   - error: If parameters are invalid, signing fails, or context is cancelled
//
// Example (Basic usage):
//
//	userID := "123e4567-e89b-12d3-a456-426614174000"
//	sessionID := uuid.NewString()
//
//	token, err := maker.CreateAccessToken(
//	    ctx,
//	    userID,
//	    "john.doe",
//	    []string{"user", "admin"},
//	    sessionID,
//	    "",
//	)
//	if err != nil {
//	    return fmt.Errorf("failed to create token: %w", err)
//	}
//
//	// Use token.Token in Authorization header
//	fmt.Printf("Token: %s\n", token.Token)
//	fmt.Printf("Expires: %s\n", token.ExpiresAt)
//
// Example (Multiple roles):
//
//	token, err := maker.CreateAccessToken(
//	    ctx,
//	    userID,
//	    "admin@example.com",
//	    []string{"user", "admin", "moderator"},
//	    sessionID,
//	    "",
//	)
//
// Example (With context timeout):
//
//	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
//	defer cancel()
//
//	token, err := maker.CreateAccessToken(ctx, userID, username, roles, sessionID, "")
func (maker *JWTMaker) CreateAccessToken(ctx context.Context, userID string, username string, roles []string, sessionID string, tenantID string) (*AccessTokenResponse, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context canceled: %w", err)
	}

	if err := validateUserAndUsername(userID, username); err != nil {
		return nil, err
	}
	if len(roles) == 0 {
		return nil, fmt.Errorf("at least one role must be provided")
	}

	// Validate roles are non-empty strings
	for _, role := range roles {
		if role == "" {
			return nil, fmt.Errorf("roles cannot contain empty strings")
		}
	}

	if err := validateTenantID(maker.config.MultiTenantEnabled, tenantID); err != nil {
		return nil, err
	}

	tokenID, err := newTokenID()
	if err != nil {
		return nil, err
	}

	now := time.Now()
	claims := AccessTokenClaims{
		ID:                tokenID,
		Subject:           userID,
		SessionID:         sessionID,
		Username:          username,
		TenantID:          tenantID,
		Issuer:            maker.config.Issuer,
		Audience:          maker.config.Audience,
		Roles:             roles,
		IssuedAt:          now,
		ExpiresAt:         now.Add(maker.config.AccessExpiryDuration),
		NotBefore:         now,
		MaxLifetimeExpiry: now.Add(maker.config.AccessMaxLifetimeExpiry),
		TokenType:         AccessToken,
	}

	signedToken, err := maker.signClaims(ctx, claims, AccessToken)
	if err != nil {
		return nil, err
	}

	response := &AccessTokenResponse{
		Subject:           claims.Subject,
		SessionID:         claims.SessionID,
		Token:             signedToken,
		Issuer:            claims.Issuer,
		Username:          claims.Username,
		TenantID:          claims.TenantID,
		Roles:             roles,
		Audience:          claims.Audience,
		IssuedAt:          claims.IssuedAt,
		ExpiresAt:         claims.ExpiresAt,
		NotBefore:         claims.NotBefore,
		MaxLifetimeExpiry: claims.MaxLifetimeExpiry,
		TokenType:         claims.TokenType,
	}

	return response, nil
}

// CreateRefreshToken generates a new signed refresh token for obtaining new access tokens.
// Refresh tokens are long-lived and do not include authorization roles.
//
// Token Structure:
//   - Header: Algorithm and token type
//   - Payload: User identity and session (no roles)
//   - Signature: Cryptographic signature for verification
//
// Automatic Claims:
//   - jti: Unique token identifier (auto-generated UUIDv4)
//   - iat: Issued at timestamp (current time)
//   - exp: Expiration time (iat + RefreshExpiryDuration)
//   - nbf: Not before time (current time)
//   - mle: Maximum lifetime expiry (iat + RefreshMaxLifetimeExpiry)
//   - iss: Issuer from configuration
//   - aud: Audience from configuration
//   - typ: Token type ("refresh")
//
// Validation:
//   - userID must not be empty
//   - username must not exceed 1024 characters
//   - sessionID can be any string (including empty for sessionless tokens)
//
// Parameters:
//   - ctx: Context for cancellation
//   - userID: The user's unique identifier (must not be empty)
//   - username: Human-readable username (max 1024 characters)
//   - sessionID: Session identifier (can be empty for sessionless operation)
//
// Returns:
//   - *RefreshTokenResponse: Complete token response with signed JWT and metadata
//   - error: If parameters are invalid, signing fails, or context is cancelled
//
// Security Best Practices:
//   - Store refresh tokens securely (httpOnly cookies, secure storage)
//   - Use token rotation to prevent reuse
//   - Implement refresh token revocation for logout
//   - Monitor for suspicious refresh patterns
//
// Example (Create refresh token):
//
//	refreshToken, err := maker.CreateRefreshToken(
//	    ctx,
//	    userID,
//	    "john.doe",
//	    sessionID,
//	    "",
//	)
//	if err != nil {
//	    return fmt.Errorf("failed to create refresh token: %w", err)
//	}
//
//	// Store securely (e.g., httpOnly cookie)
//	http.SetCookie(w, &http.Cookie{
//	    Name:     "refresh_token",
//	    Value:    refreshToken.Token,
//	    Expires:  refreshToken.ExpiresAt,
//	    HttpOnly: true,
//	    Secure:   true,
//	    SameSite: http.SameSiteStrictMode,
//	})
//
// Example (Create token pair):
//
//	accessToken, err := maker.CreateAccessToken(ctx, userID, username, roles, sessionID, "")
//	if err != nil {
//	    return err
//	}
//
//	refreshToken, err := maker.CreateRefreshToken(ctx, userID, username, sessionID, "")
//	if err != nil {
//	    return err
//	}
//
//	return &TokenPair{
//	    AccessToken:  accessToken.Token,
//	    RefreshToken: refreshToken.Token,
//	}
func (maker *JWTMaker) CreateRefreshToken(ctx context.Context, userID string, username string, sessionID string, tenantID string) (*RefreshTokenResponse, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context canceled: %w", err)
	}

	if err := validateUserAndUsername(userID, username); err != nil {
		return nil, err
	}

	if err := validateTenantID(maker.config.MultiTenantEnabled, tenantID); err != nil {
		return nil, err
	}

	tokenID, err := newTokenID()
	if err != nil {
		return nil, err
	}

	now := time.Now()
	claims := RefreshTokenClaims{
		ID:                tokenID,
		Subject:           userID,
		SessionID:         sessionID,
		Username:          username,
		TenantID:          tenantID,
		Issuer:            maker.config.Issuer,
		Audience:          maker.config.Audience,
		IssuedAt:          now,
		ExpiresAt:         now.Add(maker.config.RefreshExpiryDuration),
		NotBefore:         now,
		MaxLifetimeExpiry: now.Add(maker.config.RefreshMaxLifetimeExpiry),
		TokenType:         RefreshToken,
	}

	signedToken, err := maker.signClaims(ctx, claims, RefreshToken)
	if err != nil {
		return nil, err
	}

	response := &RefreshTokenResponse{
		Subject:           claims.Subject,
		SessionID:         claims.SessionID,
		Token:             signedToken,
		Issuer:            claims.Issuer,
		Username:          claims.Username,
		TenantID:          claims.TenantID,
		Audience:          claims.Audience,
		IssuedAt:          claims.IssuedAt,
		ExpiresAt:         claims.ExpiresAt,
		NotBefore:         claims.NotBefore,
		MaxLifetimeExpiry: claims.MaxLifetimeExpiry,
		TokenType:         claims.TokenType,
	}

	return response, nil
}

// CreateVerificationToken generates a new signed, short-lived, single-use-capable token
// scoped to useCase (e.g. "2fa-pending", "password-reset"). Unlike CreateAccessToken/
// CreateRefreshToken, its lifetime is a per-call parameter rather than fixed solely by
// configuration: ttl <= 0 falls back to config.VerificationDefaultExpiryDuration; ttl
// exceeding config.VerificationMaxExpiryDuration (when configured) is rejected. This
// variable-TTL-per-use-case support is the entire reason this token type exists alongside
// Access/Refresh tokens.
//
// Requires GourdianTokenConfig.VerificationTokensEnabled.
//
// Example:
//
//	token, err := maker.CreateVerificationToken(ctx, userID, "2fa-pending", 5*time.Minute, nil)
func (maker *JWTMaker) CreateVerificationToken(ctx context.Context, userID string, useCase string, ttl time.Duration, metadata map[string]interface{}) (*VerificationTokenResponse, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context canceled: %w", err)
	}

	if !maker.config.VerificationTokensEnabled {
		return nil, fmt.Errorf("verification tokens are not enabled")
	}

	if userID == "" {
		return nil, fmt.Errorf("user ID cannot be empty")
	}

	if err := validateUseCase(maker.config.VerificationAllowedUseCases, useCase); err != nil {
		return nil, err
	}

	effectiveTTL, err := resolveVerificationTTL(&maker.config, ttl)
	if err != nil {
		return nil, err
	}

	tokenID, err := newTokenID()
	if err != nil {
		return nil, err
	}

	now := time.Now()
	expiresAt := now.Add(effectiveTTL)
	claims := VerificationTokenClaims{
		ID:                tokenID,
		Subject:           userID,
		UseCase:           useCase,
		Issuer:            maker.config.Issuer,
		Audience:          maker.config.Audience,
		IssuedAt:          now,
		ExpiresAt:         expiresAt,
		NotBefore:         now,
		MaxLifetimeExpiry: expiresAt,
		Metadata:          metadata,
		TokenType:         VerificationToken,
	}

	signedToken, err := maker.signClaims(ctx, claims, VerificationToken)
	if err != nil {
		return nil, err
	}

	response := &VerificationTokenResponse{
		Subject:           claims.Subject,
		UseCase:           claims.UseCase,
		Token:             signedToken,
		Issuer:            claims.Issuer,
		Audience:          claims.Audience,
		IssuedAt:          claims.IssuedAt,
		ExpiresAt:         claims.ExpiresAt,
		NotBefore:         claims.NotBefore,
		MaxLifetimeExpiry: claims.MaxLifetimeExpiry,
		Metadata:          claims.Metadata,
		TokenType:         claims.TokenType,
	}

	return response, nil
}

// parseAndValidateToken performs the revocation check, the rotation check (for refresh
// tokens only), signature/structure verification, and required-claims validation shared
// by VerifyAccessToken and VerifyRefreshToken.
func (maker *JWTMaker) parseAndValidateToken(ctx context.Context, tokenString string, tokenType TokenType) (jwt.MapClaims, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context canceled: %w", err)
	}

	if maker.config.RevocationEnabled && maker.tokenRepo != nil {
		revoked, err := maker.tokenRepo.IsTokenRevoked(ctx, tokenType, tokenString)
		if err != nil {
			return nil, fmt.Errorf("failed to check token revocation: %w", err)
		}
		if revoked {
			return nil, fmt.Errorf("%w", ErrTokenRevoked)
		}
	}

	if tokenType == RefreshToken && maker.config.RotationEnabled && maker.tokenRepo != nil {
		rotated, err := maker.tokenRepo.IsTokenRotated(ctx, tokenString)
		if err != nil {
			return nil, fmt.Errorf("failed to check token rotation: %w", err)
		}
		if rotated {
			return nil, fmt.Errorf("%w", ErrTokenRotated)
		}
	}

	// Verify token signature and basic structure
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Check context during parsing
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("context canceled during parsing: %w", err)
		}

		if token.Method.Alg() != maker.signingMethod.Alg() {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return maker.publicKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidToken, err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("token failed validation")
	}

	// Check context before claims processing
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context canceled during claims processing: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("%w", ErrInvalidClaims)
	}

	if err := validateTokenClaims(claims, tokenType, maker.config.RequiredClaims); err != nil {
		return nil, err
	}

	// tid is required on access/refresh tokens (never verification tokens, which use
	// Metadata for any tenant scoping instead — see VerificationTokenClaims) once
	// MultiTenantEnabled is true. This is the verify-side counterpart to validateTenantID,
	// which only guards the create side; without this check a pre-existing or
	// maliciously-crafted token missing "tid" would otherwise verify successfully.
	if maker.config.MultiTenantEnabled && (tokenType == AccessToken || tokenType == RefreshToken) {
		tid, _ := claims["tid"].(string)
		if tid == "" {
			return nil, fmt.Errorf("%w", ErrTenantIDRequired)
		}

		// Bulk tenant revocation (see RevokeTenant): reject any token issued at-or-before
		// its tenant's revocation epoch, even one never individually revoked or rotated.
		// Only meaningful once a RevokeTenant call could actually have happened, so this is
		// gated the same way the revocation/rotation checks above are.
		if maker.config.RevocationEnabled && maker.tokenRepo != nil {
			epoch, err := maker.tokenRepo.GetTenantRevocationEpoch(ctx, tid)
			if err != nil {
				return nil, fmt.Errorf("failed to check tenant revocation: %w", err)
			}
			if !epoch.IsZero() {
				iat := getUnixTime(claims["iat"])
				if !time.Unix(iat, 0).After(epoch) {
					return nil, fmt.Errorf("%w", ErrTenantRevoked)
				}
			}
		}
	}

	return claims, nil
}

// VerifyAccessToken validates an access token and returns its claims if valid.
// Performs comprehensive security checks including signature, expiration, and revocation.
//
// Validation Steps:
//  1. Check context cancellation
//  2. Check revocation status (if RevocationEnabled)
//  3. Verify cryptographic signature
//  4. Validate token structure and algorithm
//  5. Check all timestamps (iat, exp, nbf, mle)
//  6. Verify required claims are present
//  7. Validate token type is "access"
//  8. Parse and return claims
//
// Checks Performed:
//   - Signature matches expected algorithm
//   - Token has not expired (exp > now)
//   - Token is not used before valid time (nbf <= now)
//   - Token has not exceeded maximum lifetime (mle > now)
//   - Token has not been revoked (if revocation enabled)
//   - All required claims are present
//   - Token type is "access" (not "refresh")
//
// Parameters:
//   - ctx: Context for cancellation. Checked multiple times during verification.
//   - tokenString: The JWT token string to verify (from Authorization header)
//
// Returns:
//   - *AccessTokenClaims: Parsed and validated token claims with all user information
//   - error: If token is invalid, expired, revoked, or any validation check fails
//
// Error Scenarios:
//   - Invalid signature: Token has been tampered with
//   - Expired: Token lifetime has ended
//   - Revoked: Token was explicitly invalidated
//   - Wrong type: Refresh token used where access token expected
//   - Missing claims: Token structure is incomplete
//   - Future issued: Token claims to be issued in the future
//   - Context cancelled: Operation was cancelled by caller
//
// Example (Verify and use claims):
//
//	claims, err := maker.VerifyAccessToken(ctx, tokenString)
//	if err != nil {
//	    return nil, fmt.Errorf("invalid token: %w", err)
//	}
//
//	// Use claims for authorization
//	if !hasRole(claims.Roles, "admin") {
//	    return fmt.Errorf("insufficient permissions")
//	}
//
//	// Access user information
//	fmt.Printf("User: %s (%s)\n", claims.Username, claims.Subject)
//	fmt.Printf("Session: %s\n", claims.SessionID)
//	fmt.Printf("Roles: %v\n", claims.Roles)
//
// Example (HTTP middleware):
//
//	func authMiddleware(next http.Handler) http.Handler {
//	    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
//	        authHeader := r.Header.Get("Authorization")
//	        if authHeader == "" {
//	            http.Error(w, "missing authorization", http.StatusUnauthorized)
//	            return
//	        }
//
//	        token := strings.TrimPrefix(authHeader, "Bearer ")
//	        claims, err := maker.VerifyAccessToken(r.Context(), token)
//	        if err != nil {
//	            http.Error(w, "invalid token", http.StatusUnauthorized)
//	            return
//	        }
//
//	        // Add claims to context
//	        ctx := context.WithValue(r.Context(), "user_claims", claims)
//	        next.ServeHTTP(w, r.WithContext(ctx))
//	    })
//	}
func (maker *JWTMaker) VerifyAccessToken(ctx context.Context, tokenString string) (*AccessTokenClaims, error) {
	claims, err := maker.parseAndValidateToken(ctx, tokenString, AccessToken)
	if err != nil {
		return nil, err
	}

	return mapToAccessClaims(claims)
}

// VerifyRefreshToken validates a refresh token and returns its claims if valid.
// Performs comprehensive security checks including signature, expiration, revocation, and rotation.
//
// Validation Steps:
//  1. Check context cancellation
//  2. Check revocation status (if RevocationEnabled)
//  3. Check rotation status (if RotationEnabled)
//  4. Verify cryptographic signature
//  5. Validate token structure and algorithm
//  6. Check all timestamps (iat, exp, nbf, mle)
//  7. Verify required claims are present
//  8. Validate token type is "refresh"
//  9. Parse and return claims
//
// Checks Performed:
//   - Signature matches expected algorithm
//   - Token has not expired (exp > now)
//   - Token is not used before valid time (nbf <= now)
//   - Token has not exceeded maximum lifetime (mle > now)
//   - Token has not been revoked (if revocation enabled)
//   - Token has not been rotated (if rotation enabled)
//   - All required claims are present
//   - Token type is "refresh" (not "access")
//
// Parameters:
//   - ctx: Context for cancellation
//   - tokenString: The JWT refresh token string to verify
//
// Returns:
//   - *RefreshTokenClaims: Parsed and validated token claims
//   - error: If token is invalid, expired, revoked, rotated, or any validation check fails
//
// Error Scenarios:
//   - Invalid signature: Token has been tampered with
//   - Expired: Token lifetime has ended
//   - Revoked: Token was explicitly invalidated
//   - Rotated: Token has been used to obtain a new token (rotation enabled)
//   - Wrong type: Access token used where refresh token expected
//   - Missing claims: Token structure is incomplete
//   - Context cancelled: Operation was cancelled
//
// Use Cases:
//   - Validating refresh token before rotation
//   - Checking refresh token validity before issuing new access token
//   - Verifying refresh token in logout operations
//
// Example (Refresh access token):
//
//	// Verify the refresh token
//	refreshClaims, err := maker.VerifyRefreshToken(ctx, refreshTokenString)
//	if err != nil {
//	    return nil, fmt.Errorf("invalid refresh token: %w", err)
//	}
//
//	// Create new access token with same user/session
//	newAccessToken, err := maker.CreateAccessToken(
//	    ctx,
//	    refreshClaims.Subject,
//	    refreshClaims.Username,
//	    []string{"user"}, // Load roles from database
//	    refreshClaims.SessionID,
//	    refreshClaims.TenantID,
//	)
//
// Example (With rotation):
//
//	// Automatically rotates the token if rotation is enabled
//	newRefreshToken, err := maker.RotateRefreshToken(ctx, oldRefreshTokenString)
//	if err != nil {
//	    return fmt.Errorf("rotation failed: %w", err)
//	}
//
//	// Old token is now invalid, use new token
func (maker *JWTMaker) VerifyRefreshToken(ctx context.Context, tokenString string) (*RefreshTokenClaims, error) {
	claims, err := maker.parseAndValidateToken(ctx, tokenString, RefreshToken)
	if err != nil {
		return nil, err
	}

	return mapToRefreshClaims(claims)
}

// VerifyVerificationToken validates a verification token and returns its claims.
// Checks signature, expiration, single-use status (if RevocationEnabled and a
// TokenRepository are configured — see MarkVerificationTokenUsed), and the use-case
// whitelist (checked again here as defense-in-depth against a use case being removed
// from GourdianTokenConfig.VerificationAllowedUseCases after tokens bearing it were
// already issued).
//
// Requires GourdianTokenConfig.VerificationTokensEnabled.
func (maker *JWTMaker) VerifyVerificationToken(ctx context.Context, tokenString string) (*VerificationTokenClaims, error) {
	if !maker.config.VerificationTokensEnabled {
		return nil, fmt.Errorf("verification tokens are not enabled")
	}

	claims, err := maker.parseAndValidateToken(ctx, tokenString, VerificationToken)
	if err != nil {
		return nil, err
	}

	verificationClaims, err := mapToVerificationClaims(claims)
	if err != nil {
		return nil, err
	}

	if err := validateUseCase(maker.config.VerificationAllowedUseCases, verificationClaims.UseCase); err != nil {
		return nil, err
	}

	return verificationClaims, nil
}

// revokeToken parses token to extract its expiration, then marks it revoked in the
// repository. Shared by RevokeAccessToken, RevokeRefreshToken, and
// MarkVerificationTokenUsed.
func (maker *JWTMaker) revokeToken(ctx context.Context, tokenType TokenType, token string) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("context canceled: %w", err)
	}

	if !maker.config.RevocationEnabled || maker.tokenRepo == nil {
		return fmt.Errorf("%s token revocation is not enabled", tokenType)
	}

	// Parse the token to extract expiration time
	parsed, err := jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		// Check context during parsing
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("context canceled during parsing: %w", err)
		}
		return maker.publicKey, nil
	})
	if err != nil {
		return fmt.Errorf("invalid token: %w", err)
	}
	if !parsed.Valid {
		return fmt.Errorf("token failed validation")
	}

	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return fmt.Errorf("invalid token claims")
	}

	exp := getUnixTime(claims["exp"])
	if exp == 0 {
		return fmt.Errorf("%w", ErrMissingExpClaim)
	}
	ttl := time.Until(time.Unix(exp, 0))

	// Check context before database operation
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("context canceled before revocation: %w", err)
	}

	return maker.tokenRepo.MarkTokenRevoke(ctx, tokenType, token, ttl)
}

// RevokeAccessToken marks an access token as revoked, preventing its further use.
// The token will fail verification even if it hasn't expired yet.
// Requires RevocationEnabled to be true in the configuration.
//
// Revocation Process:
//  1. Parses the token to extract expiration time
//  2. Calculates time-to-live (TTL) until natural expiration
//  3. Stores token hash in repository with TTL
//  4. Token verification will now fail for this token
//  5. Token is automatically removed from storage after TTL expires
//
// Storage Considerations:
//   - Tokens are stored with TTL matching their remaining lifetime
//   - After natural expiration, revoked tokens are cleaned up
//   - Only the token hash is stored (not the full token)
//   - Cleanup runs automatically at CleanupInterval
//
// Parameters:
//   - ctx: Context for cancellation and timeout
//   - token: The JWT token string to revoke
//
// Returns:
//   - error: If revocation is disabled, token is invalid, repository operation fails,
//     or context is cancelled
//
// Use Cases:
//   - User logout (revoke current access token)
//   - Security breach (revoke compromised token)
//   - Administrative action (revoke specific user's tokens)
//   - Password change (revoke all existing tokens)
//
// Limitations:
//   - Requires RevocationEnabled = true
//   - Requires TokenRepository
//   - Adds latency to token verification (repository lookup)
//   - Requires distributed storage for multi-instance systems
//
// Example (Logout - revoke access token):
//
//	err := maker.RevokeAccessToken(ctx, accessTokenString)
//	if err != nil {
//	    return fmt.Errorf("failed to revoke token: %w", err)
//	}
//
//	// Token is now invalid and will fail verification
//	fmt.Println("User logged out successfully")
//
// Example (Revoke all session tokens):
//
//	// Get all tokens for a session from your database
//	tokens, err := db.GetSessionTokens(ctx, sessionID)
//	if err != nil {
//	    return err
//	}
//
//	// Revoke each token
//	for _, token := range tokens {
//	    if err := maker.RevokeAccessToken(ctx, token); err != nil {
//	        log.Printf("Failed to revoke token: %v", err)
//	    }
//	}
//
// Example (Security breach response):
//
//	// Revoke access token immediately
//	if err := maker.RevokeAccessToken(ctx, compromisedToken); err != nil {
//	    log.Printf("Failed to revoke compromised token: %v", err)
//	}
//
//	// Also revoke refresh token to prevent new access tokens
//	if err := maker.RevokeRefreshToken(ctx, refreshToken); err != nil {
//	    log.Printf("Failed to revoke refresh token: %v", err)
//	}
func (maker *JWTMaker) RevokeAccessToken(ctx context.Context, token string) error {
	return maker.revokeToken(ctx, AccessToken, token)
}

// RevokeRefreshToken marks a refresh token as revoked, preventing its further use.
// The token cannot be used to obtain new access tokens after revocation.
// Requires RevocationEnabled to be true in the configuration.
//
// Revocation Process:
//  1. Parses the token to extract expiration time
//  2. Calculates time-to-live (TTL) until natural expiration
//  3. Stores token hash in repository with TTL
//  4. Token verification will now fail for this token
//  5. Token is automatically removed from storage after TTL expires
//
// Impact:
//   - Prevents token from being used in RotateRefreshToken
//   - Prevents token from being verified successfully
//   - Existing access tokens remain valid until they expire
//   - User must re-authenticate to get new refresh token
//
// Parameters:
//   - ctx: Context for cancellation and timeout
//   - token: The JWT refresh token string to revoke
//
// Returns:
//   - error: If revocation is disabled, token is invalid, repository operation fails,
//     or context is cancelled
//
// Use Cases:
//   - User logout (revoke refresh token to prevent new access tokens)
//   - Forced re-authentication (after password change)
//   - Security incident response
//   - Session termination
//
// Best Practices:
//   - Always revoke both access and refresh tokens during logout
//   - Revoke refresh tokens after password changes
//   - Monitor failed verification attempts (may indicate stolen tokens)
//   - Use short-lived refresh tokens if revocation is disabled
//
// Example (Complete logout):
//
//	// Revoke both access and refresh tokens
//	if err := maker.RevokeAccessToken(ctx, accessToken); err != nil {
//	    log.Printf("Failed to revoke access token: %v", err)
//	}
//
//	if err := maker.RevokeRefreshToken(ctx, refreshToken); err != nil {
//	    return fmt.Errorf("failed to revoke refresh token: %w", err)
//	}
//
//	fmt.Println("Logged out successfully")
//
// Example (Password change - revoke all user tokens):
//
//	// Get all refresh tokens for user
//	tokens, err := db.GetUserRefreshTokens(ctx, userID)
//	if err != nil {
//	    return err
//	}
//
//	// Revoke each refresh token
//	for _, token := range tokens {
//	    if err := maker.RevokeRefreshToken(ctx, token); err != nil {
//	        log.Printf("Failed to revoke token: %v", err)
//	    }
//	}
//
//	// User must re-authenticate on all devices
func (maker *JWTMaker) RevokeRefreshToken(ctx context.Context, token string) error {
	return maker.revokeToken(ctx, RefreshToken, token)
}

// MarkVerificationTokenUsed marks a verification token as used, implemented by revoking it
// via the same revokeToken helper used by RevokeAccessToken/RevokeRefreshToken — "mark
// used" for a verification token and "revoke" for an access/refresh token are the same
// underlying repository operation. A subsequent VerifyVerificationToken call on the same
// token then fails with ErrTokenAlreadyUsed (a plain alias of ErrTokenRevoked), since
// parseAndValidateToken's existing revocation check applies to VerificationToken the same
// as it does to AccessToken/RefreshToken.
//
// Requires GourdianTokenConfig.VerificationTokensEnabled AND RevocationEnabled, plus a
// TokenRepository — returns an error otherwise (see revokeToken).
//
// VerifyVerificationToken does not call this automatically: callers decide when a
// verification token is actually consumed (e.g. only after a 2FA code check succeeds AND
// the resulting session is issued), so a token can be verified more than once before being
// deliberately marked used.
func (maker *JWTMaker) MarkVerificationTokenUsed(ctx context.Context, token string) error {
	if !maker.config.VerificationTokensEnabled {
		return fmt.Errorf("verification tokens are not enabled")
	}
	return maker.revokeToken(ctx, VerificationToken, token)
}

// RotateRefreshToken exchanges an old refresh token for a new one with extended expiration.
// The old token is atomically marked as rotated and cannot be reused, preventing token theft.
// Requires RotationEnabled to be true in the configuration.
//
// Rotation Process:
//  1. Verifies the old token is valid (signature, expiration, not revoked/rotated)
//  2. Creates a new refresh token with the same user and session
//  3. Atomically marks the old token as rotated using compare-and-swap
//  4. If already rotated (by another concurrent request), discards the new token and
//     returns an error
//  5. Returns the new token with fresh expiration time
//
// Atomicity Guarantee:
//
//	Uses MarkTokenRotatedAtomic to ensure only ONE concurrent request's new token is ever
//	returned to a caller. If multiple requests attempt to rotate the same token
//	simultaneously, only the first to win the atomic mark succeeds and others receive an
//	error. This detects token theft attempts.
//
// Avoiding Unrecoverable Lockout:
//
//	The new token is created *before* the old one is marked rotated (the reverse of a naive
//	implementation). This means that if CreateRefreshToken fails (repository outage, signing
//	error, context cancellation, etc.), nothing has been persisted yet — the old token is
//	never marked rotated, so it remains valid and the caller can safely retry rotation
//	instead of being permanently locked out. The trade-off: a losing concurrent request (see
//	Atomicity Guarantee above) does the signing work for a new token that is then discarded —
//	cheap, since it's pure cryptographic signing with no repository call, and the discarded
//	token is never returned to any caller or persisted anywhere, so it poses no risk.
//
// Security Benefits:
//   - Prevents token reuse attacks
//   - Detects concurrent rotation attempts (possible token theft)
//   - Limits blast radius of compromised tokens
//   - Enforces one-time use of refresh tokens
//
// Parameters:
//   - ctx: Context for cancellation and timeout
//   - oldToken: The current refresh token to rotate (will be invalidated)
//
// Returns:
//   - *RefreshTokenResponse: New refresh token with extended expiration
//   - error: If rotation is disabled, old token is invalid/already rotated,
//     atomic operation fails, or context is cancelled
//
// Error Scenarios:
//   - Token already rotated: Possible replay attack, invalidate session
//   - Token invalid/expired: Require re-authentication
//   - Rotation disabled: Feature not configured
//   - Repository error: Storage system unavailable
//
// Security Implications:
//
//	If rotation fails due to "already rotated":
//	- Indicates possible token theft
//	- Consider invalidating the entire session
//	- Alert security monitoring systems
//	- Require full re-authentication
//
// Example (Token refresh endpoint):
//
//	func refreshTokenHandler(w http.ResponseWriter, r *http.Request) {
//	    // Get refresh token from cookie or body
//	    oldToken := r.Header.Get("X-Refresh-Token")
//
//	    // Rotate the token
//	    newRefresh, err := maker.RotateRefreshToken(r.Context(), oldToken)
//	    if err != nil {
//	        if errors.Is(err, gourdiantoken.ErrTokenRotated) {
//	            // Possible token theft detected
//	            log.Printf("Token reuse detected for token: %v", err)
//	            http.Error(w, "security violation", http.StatusForbidden)
//	            return
//	        }
//	        http.Error(w, "invalid token", http.StatusUnauthorized)
//	        return
//	    }
//
//	    // Create new access token
//	    claims, _ := maker.VerifyRefreshToken(r.Context(), newRefresh.Token)
//	    accessToken, err := maker.CreateAccessToken(
//	        r.Context(),
//	        claims.Subject,
//	        claims.Username,
//	        getUserRoles(claims.Subject), // Load from DB
//	        claims.SessionID,
//	        claims.TenantID,
//	    )
//
//	    // Return new token pair
//	    json.NewEncoder(w).Encode(map[string]string{
//	        "access_token":  accessToken.Token,
//	        "refresh_token": newRefresh.Token,
//	    })
//	}
//
// Example (With security monitoring):
//
//	newToken, err := maker.RotateRefreshToken(ctx, oldToken)
//	if err != nil {
//	    if errors.Is(err, gourdiantoken.ErrTokenRotated) {
//	        // Token theft detected
//	        securityLog.Alert("Token reuse attempt detected", map[string]interface{}{
//	            "token_prefix": oldToken[:10],
//	            "ip_address":   clientIP,
//	            "timestamp":    time.Now(),
//	        })
//
//	        // Revoke all user tokens
//	        revokeAllUserTokens(ctx, userID)
//	        return nil, fmt.Errorf("security violation: session terminated")
//	    }
//	    return nil, err
//	}
//
// Example (Race condition handling):
//
//	// Multiple concurrent requests with same token
//	var wg sync.WaitGroup
//	results := make(chan error, 3)
//
//	for i := 0; i < 3; i++ {
//	    wg.Add(1)
//	    go func() {
//	        defer wg.Done()
//	        _, err := maker.RotateRefreshToken(ctx, sameToken)
//	        results <- err
//	    }()
//	}
//
//	wg.Wait()
//	close(results)
//
//	// Only one should succeed, others should get "already rotated" error
//	successCount := 0
//	for err := range results {
//	    if err == nil {
//	        successCount++
//	    }
//	}
//	// successCount should be exactly 1
func (maker *JWTMaker) RotateRefreshToken(ctx context.Context, oldToken string) (*RefreshTokenResponse, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context canceled: %w", err)
	}

	if !maker.config.RotationEnabled {
		return nil, fmt.Errorf("token rotation not enabled")
	}

	claims, err := maker.VerifyRefreshToken(ctx, oldToken)
	if err != nil {
		return nil, err
	}

	// Check context before creating the new token
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context canceled before creating new token: %w", err)
	}

	// Create the new token BEFORE marking the old one as rotated. If CreateRefreshToken
	// fails, nothing has been persisted yet, so the old token remains valid and the caller
	// can safely retry rotation instead of being permanently locked out (see the "Known
	// Failure Mode" note above this function, which described the lockout this reordering
	// fixes). The trade-off: a losing concurrent request (see below) does this signing work
	// for nothing — cheap, since it's pure cryptographic signing with no repository call.
	newToken, err := maker.CreateRefreshToken(ctx, claims.Subject, claims.Username, claims.SessionID, claims.TenantID)
	if err != nil {
		return nil, err
	}

	// Check context before the atomic rotation claim
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context canceled before rotation check: %w", err)
	}

	// ATOMIC OPERATION: Only one goroutine will succeed here
	marked, err := maker.tokenRepo.MarkTokenRotatedAtomic(ctx, oldToken, maker.config.RefreshMaxLifetimeExpiry)
	if err != nil {
		return nil, fmt.Errorf("repository error: %w", err)
	}

	if !marked {
		// Token was already rotated by another goroutine. The new token created above is
		// simply discarded here — it was never returned to any caller and was never
		// persisted anywhere, so it poses no risk and needs no explicit revocation.
		return nil, fmt.Errorf("%w", ErrTokenRotated)
	}

	return newToken, nil
}

// RevokeTenant bulk-revokes every access/refresh token for tenantID by recording a
// revocation epoch (see TokenRepository.RevokeTenant), rather than enumerating and marking
// individual tokens — the only approach that also covers access tokens, which this package
// never persists a record of unless individually revoked, and which needs no "tokens by
// tenant" index on any backend.
//
// Requires GourdianTokenConfig.MultiTenantEnabled and RevocationEnabled plus a
// TokenRepository — the same preconditions RevokeAccessToken/RevokeRefreshToken already
// enforce, since this is built on the same repository.
//
// The revocation record's TTL is max(AccessExpiryDuration, RefreshExpiryDuration): past
// that window, every token issued before the epoch has already failed its own native "exp"
// check regardless of the epoch record, making the record redundant beyond that point.
//
// Parameters:
//   - ctx: Context for cancellation and timeout
//   - tenantID: The tenant to revoke (must not be empty)
//
// Returns:
//   - error: If multi-tenancy or revocation is disabled, tenantID is empty, or the
//     repository operation fails
func (maker *JWTMaker) RevokeTenant(ctx context.Context, tenantID string) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("context canceled: %w", err)
	}

	if !maker.config.MultiTenantEnabled {
		return fmt.Errorf("%w", ErrMultiTenantDisabled)
	}

	if tenantID == "" {
		return fmt.Errorf("%w", ErrTenantIDRequired)
	}

	if !maker.config.RevocationEnabled || maker.tokenRepo == nil {
		return fmt.Errorf("tenant revocation is not enabled")
	}

	ttl := maker.config.AccessExpiryDuration
	if maker.config.RefreshExpiryDuration > ttl {
		ttl = maker.config.RefreshExpiryDuration
	}

	return maker.tokenRepo.RevokeTenant(ctx, tenantID, ttl)
}

// cleanupRotatedTokens is a background goroutine that periodically removes expired rotation markers.
// Runs automatically when RotationEnabled is true and stops when the context is cancelled.
//
// Purpose:
//   - Prevents memory/storage leaks from accumulated rotation markers
//   - Removes entries for tokens that have naturally expired
//   - Maintains repository performance over time
//
// Behavior:
//   - Runs at intervals specified by config.CleanupInterval
//   - Each cleanup has a 30-second timeout
//   - Continues running until context cancellation
//   - Logs errors but continues operation
//
// Parameters:
//   - ctx: Context for cancellation. Currently only cancelled on a construction-time
//     error path inside NewGourdianTokenMaker; once construction succeeds there is no
//     caller-accessible way to stop this goroutine (see Close(), added in a later release).
//
// Notes:
//   - Started automatically by NewGourdianTokenMaker
//   - Should not be called directly
//   - Errors are reported via the maker's logf hook (defaults to stdout)
func (maker *JWTMaker) cleanupRotatedTokens(ctx context.Context) {
	ticker := time.NewTicker(maker.config.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if maker.tokenRepo == nil {
				continue
			}

			// Create a timeout context for cleanup operation
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			if err := maker.tokenRepo.CleanupExpiredRotatedTokens(cleanupCtx); err != nil {
				if maker.structuredLogger != nil {
					maker.structuredLogger.Error("gourdiantoken: cleanup rotated tokens failed", "error", err)
				} else {
					maker.logf("Error cleaning up rotated tokens: %v\n", err)
				}
			}
			cancel()

			if maker.config.MultiTenantEnabled {
				tenantCleanupCtx, tenantCancel := context.WithTimeout(context.Background(), 30*time.Second)
				if err := maker.tokenRepo.CleanupExpiredTenantRevocations(tenantCleanupCtx); err != nil {
					if maker.structuredLogger != nil {
						maker.structuredLogger.Error("gourdiantoken: cleanup tenant revocations failed", "error", err)
					} else {
						maker.logf("Error cleaning up tenant revocations: %v\n", err)
					}
				}
				tenantCancel()
			}
		}
	}
}

// cleanupRevokedTokens is a background goroutine that periodically removes expired revoked tokens.
// Runs automatically when RevocationEnabled is true and stops when the context is cancelled.
//
// Purpose:
//   - Prevents memory/storage leaks from accumulated revoked tokens
//   - Removes entries for tokens that have naturally expired
//   - Maintains repository performance over time
//
// Behavior:
//   - Runs at intervals specified by config.CleanupInterval
//   - Cleans up access, refresh, and verification tokens
//   - Each cleanup has a 30-second timeout
//   - Continues running until context cancellation
//   - Logs errors but continues operation
//
// Parameters:
//   - ctx: Context for cancellation. Currently only cancelled on a construction-time
//     error path inside NewGourdianTokenMaker; once construction succeeds there is no
//     caller-accessible way to stop this goroutine (see Close(), added in a later release).
//
// Notes:
//   - Started automatically by NewGourdianTokenMaker
//   - Should not be called directly
//   - Errors are reported via the maker's logf hook (defaults to stdout)
func (maker *JWTMaker) cleanupRevokedTokens(ctx context.Context) {
	ticker := time.NewTicker(maker.config.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if maker.tokenRepo == nil {
				continue
			}

			for _, tokenType := range []TokenType{AccessToken, RefreshToken, VerificationToken} {
				// Create a timeout context for cleanup operation
				cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				if err := maker.tokenRepo.CleanupExpiredRevokedTokens(cleanupCtx, tokenType); err != nil {
					if maker.structuredLogger != nil {
						maker.structuredLogger.Error("gourdiantoken: cleanup revoked tokens failed", "token_type", tokenType, "error", err)
					} else {
						maker.logf("Error cleaning up revoked %s tokens: %v\n", tokenType, err)
					}
				}
				cancel()
			}

			if maker.config.MultiTenantEnabled {
				tenantCleanupCtx, tenantCancel := context.WithTimeout(context.Background(), 30*time.Second)
				if err := maker.tokenRepo.CleanupExpiredTenantRevocations(tenantCleanupCtx); err != nil {
					if maker.structuredLogger != nil {
						maker.structuredLogger.Error("gourdiantoken: cleanup tenant revocations failed", "error", err)
					} else {
						maker.logf("Error cleaning up tenant revocations: %v\n", err)
					}
				}
				tenantCancel()
			}
		}
	}
}

// initializeSigningMethod sets up the JWT signing algorithm based on configuration.
// Validates that the algorithm is in the allowed list and creates the signing method instance.
//
// Supported Algorithms:
//   - HMAC: HS256, HS384, HS512 (symmetric)
//   - RSA: RS256, RS384, RS512 (asymmetric)
//   - RSA-PSS: PS256, PS384, PS512 (asymmetric, recommended)
//   - ECDSA: ES256, ES384, ES512 (asymmetric)
//   - EdDSA: EdDSA (asymmetric, modern)
//
// Security:
//   - "none" algorithm is explicitly rejected for security
//   - Validates algorithm is in AllowedAlgorithms list
//   - Ensures algorithm matches the signing method type
//
// Returns:
//   - error: If algorithm is unsupported, not allowed, or insecure
//
// Notes:
//   - Called internally during initialization
//   - Should not be called directly by users
func (maker *JWTMaker) initializeSigningMethod() error {
	if len(maker.config.AllowedAlgorithms) > 0 {
		allowed := false
		for _, alg := range maker.config.AllowedAlgorithms {
			if alg == maker.config.Algorithm {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("configured algorithm %s not in allowed algorithms list",
				maker.config.Algorithm)
		}
	}

	switch maker.config.Algorithm {
	case "HS256":
		maker.signingMethod = jwt.SigningMethodHS256
	case "HS384":
		maker.signingMethod = jwt.SigningMethodHS384
	case "HS512":
		maker.signingMethod = jwt.SigningMethodHS512
	case "RS256":
		maker.signingMethod = jwt.SigningMethodRS256
	case "RS384":
		maker.signingMethod = jwt.SigningMethodRS384
	case "RS512":
		maker.signingMethod = jwt.SigningMethodRS512
	case "PS256":
		maker.signingMethod = jwt.SigningMethodPS256
	case "PS384":
		maker.signingMethod = jwt.SigningMethodPS384
	case "PS512":
		maker.signingMethod = jwt.SigningMethodPS512
	case "ES256":
		maker.signingMethod = jwt.SigningMethodES256
	case "ES384":
		maker.signingMethod = jwt.SigningMethodES384
	case "ES512":
		maker.signingMethod = jwt.SigningMethodES512
	case "EdDSA":
		maker.signingMethod = jwt.SigningMethodEdDSA
	case "none":
		return fmt.Errorf("unsecured tokens are disabled for security reasons")
	default:
		return fmt.Errorf("unsupported algorithm: %s", maker.config.Algorithm)
	}

	return nil
}

// initializeKeys loads and validates cryptographic keys based on the signing method.
// For symmetric signing, uses the configured secret key.
// For asymmetric signing, loads keys from PEM files.
//
// Symmetric Key Handling:
//   - Uses SymmetricKey for both signing and verification
//   - Key is used as-is (ensure it's properly secured)
//
// Asymmetric Key Handling:
//   - Loads private key from PrivateKeyPath (for signing)
//   - Loads public key from PublicKeyPath (for verification)
//   - Supports multiple PEM formats (PKCS1, PKCS8, SEC1)
//   - Validates key types match the algorithm
//
// Supported Key Types:
//   - RSA: 2048-bit minimum recommended
//   - ECDSA: P-256, P-384, P-521 curves
//   - EdDSA: Ed25519 keys
//
// Returns:
//   - error: If keys cannot be loaded, are invalid, or don't match the algorithm
//
// Notes:
//   - Called internally during initialization
//   - Private key files should have 0600 permissions
//   - Public keys can be distributed for token verification
func (maker *JWTMaker) initializeKeys() error {
	switch maker.config.SigningMethod {
	case Symmetric:
		maker.privateKey = []byte(maker.config.SymmetricKey)
		maker.publicKey = []byte(maker.config.SymmetricKey)
		return nil
	case Asymmetric:
		return maker.parseKeyPair()
	default:
		return fmt.Errorf("unsupported signing method: %s", maker.config.SigningMethod)
	}
}

// parseKeyPair loads and parses asymmetric key pairs from PEM files.
// Handles RSA, ECDSA, and EdDSA key types with multiple encoding formats.
//
// Supported Private Key Formats:
//   - PKCS#1 (RSA only)
//   - PKCS#8 (all key types)
//   - SEC1 (ECDSA only)
//
// Supported Public Key Formats:
//   - PKIX (SubjectPublicKeyInfo)
//   - X.509 certificates (extracts public key)
//
// Algorithm Detection:
//   - Uses maker.signingMethod.Alg() to determine expected key type
//   - Validates loaded keys match the algorithm
//
// Returns:
//   - error: If files cannot be read, keys cannot be parsed, or key types don't match
//
// Notes:
//   - Called by initializeKeys for asymmetric signing
//   - Automatically detects key format from PEM structure
func (maker *JWTMaker) parseKeyPair() error {
	privateKeyBytes, err := os.ReadFile(maker.config.PrivateKeyPath)
	if err != nil {
		return fmt.Errorf("failed to read private key file: %w", err)
	}

	publicKeyBytes, err := os.ReadFile(maker.config.PublicKeyPath)
	if err != nil {
		return fmt.Errorf("failed to read public key file: %w", err)
	}

	switch maker.signingMethod.Alg() {
	case "RS256", "RS384", "RS512", "PS256", "PS384", "PS512":
		maker.privateKey, err = parseRSAPrivateKey(privateKeyBytes)
		if err != nil {
			return fmt.Errorf("failed to parse RSA private key: %w", err)
		}
		maker.publicKey, err = parseRSAPublicKey(publicKeyBytes)
		if err != nil {
			return fmt.Errorf("failed to parse RSA public key: %w", err)
		}
	case "ES256", "ES384", "ES512":
		maker.privateKey, err = parseECDSAPrivateKey(privateKeyBytes)
		if err != nil {
			return fmt.Errorf("failed to parse ECDSA private key: %w", err)
		}
		maker.publicKey, err = parseECDSAPublicKey(publicKeyBytes)
		if err != nil {
			return fmt.Errorf("failed to parse ECDSA public key: %w", err)
		}
	case "EdDSA":
		maker.privateKey, err = parseEdDSAPrivateKey(privateKeyBytes)
		if err != nil {
			return fmt.Errorf("failed to parse EdDSA private key: %w", err)
		}
		maker.publicKey, err = parseEdDSAPublicKey(publicKeyBytes)
		if err != nil {
			return fmt.Errorf("failed to parse EdDSA public key: %w", err)
		}
	default:
		return fmt.Errorf("unsupported algorithm for asymmetric signing: %s", maker.signingMethod.Alg())
	}

	return nil
}

// hashToken creates a SHA-256 hash of the token for secure storage.
// Used internally to avoid storing full JWTs in the repository.
//
// Benefits:
//   - Reduces storage size (256 bits vs full JWT)
//   - Protects against token leakage from storage
//   - Enables efficient lookups with fixed-size keys
//
// Parameters:
//   - token: The JWT token string to hash
//
// Returns:
//   - string: Hexadecimal representation of SHA-256 hash
//
// Example Output:
//
//	"a3c5b7f9e2d4..." (64 hexadecimal characters)
//
// Notes:
//   - Used internally by revocation and rotation operations
//   - Hash is deterministic (same token = same hash)
//   - Collision probability is negligible (2^256 space)
func hashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}
