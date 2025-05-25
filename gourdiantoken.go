// gourdiantoken.go

package gourdiantoken

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

const (
	revokedAccessPrefix  = "revoked:access:"
	revokedRefreshPrefix = "revoked:refresh:"
	rotatedPrefix        = "rotated:"
)

type TokenType string

const (
	AccessToken  TokenType = "access"
	RefreshToken TokenType = "refresh"
)

type SigningMethod string

const (
	Symmetric  SigningMethod = "symmetric"
	Asymmetric SigningMethod = "asymmetric"
)

type GourdianTokenConfig struct {
	RotationEnabled          bool          // Whether to enable refresh token rotation
	RevocationEnabled        bool          // Whether to check Redis for revoked tokens
	Algorithm                string        // JWT signing algorithm (e.g., "HS256", "RS256"). Must match key type.
	SymmetricKey             string        // Base64-encoded secret key for HMAC (min 32 bytes for HS256)
	PrivateKeyPath           string        // Path to PEM-encoded private key file (asymmetric only)
	PublicKeyPath            string        // Path to PEM-encoded public key/certificate (asymmetric only)
	Issuer                   string        // Token issuer identifier (e.g., "auth.example.com")
	Audience                 []string      // Intended recipients (e.g., ["api.example.com"])
	AllowedAlgorithms        []string      // Whitelist of acceptable algorithms for verification
	RequiredClaims           []string      // Mandatory claims that must be present and valid
	SigningMethod            SigningMethod // Cryptographic method (Symmetric/Asymmetric)
	AccessExpiryDuration     time.Duration // Time until token expires after issuance (e.g., 30m)
	AccessMaxLifetimeExpiry  time.Duration // Absolute maximum validity from creation (e.g., 24h)
	RefreshExpiryDuration    time.Duration // Time until token expires after issuance
	RefreshMaxLifetimeExpiry time.Duration // Absolute maximum validity from creation
	RefreshReuseInterval     time.Duration // Minimum time between reuse attempts (rotation)
}

func NewGourdianTokenConfig(
	signingMethod SigningMethod,
	rotationEnabled, revocationEnabled bool,
	audience, allowedAlgorithms, requiredClaims []string,
	algorithm, symmetricKey, privateKeyPath, publicKeyPath, issuer string,
	accessExpiryDuration, accessMaxLifetimeExpiry, refreshExpiryDuration, refreshMaxLifetimeExpiry, refreshReuseInterval time.Duration,
) GourdianTokenConfig {
	return GourdianTokenConfig{
		RevocationEnabled:        revocationEnabled,
		RotationEnabled:          rotationEnabled,
		SigningMethod:            signingMethod,
		Audience:                 audience,
		AllowedAlgorithms:        allowedAlgorithms,
		RequiredClaims:           requiredClaims,
		Algorithm:                algorithm,
		SymmetricKey:             symmetricKey,
		PrivateKeyPath:           privateKeyPath,
		PublicKeyPath:            publicKeyPath,
		Issuer:                   issuer,
		AccessExpiryDuration:     accessExpiryDuration,
		AccessMaxLifetimeExpiry:  accessMaxLifetimeExpiry,
		RefreshExpiryDuration:    refreshExpiryDuration,
		RefreshMaxLifetimeExpiry: refreshMaxLifetimeExpiry,
		RefreshReuseInterval:     refreshReuseInterval,
	}
}

func DefaultGourdianTokenConfig(symmetricKey string) GourdianTokenConfig {
	return GourdianTokenConfig{
		RevocationEnabled:        false,
		RotationEnabled:          false,
		SigningMethod:            Symmetric,
		Algorithm:                "HS256",
		SymmetricKey:             symmetricKey,
		PrivateKeyPath:           "",
		PublicKeyPath:            "",
		Issuer:                   "gourdian.com",
		Audience:                 nil,
		AllowedAlgorithms:        []string{"HS256", "HS384", "HS512", "RS256", "ES256", "PS256"},
		RequiredClaims:           []string{"iss", "aud", "nbf", "mle"},
		AccessExpiryDuration:     30 * time.Minute,
		AccessMaxLifetimeExpiry:  24 * time.Hour,
		RefreshExpiryDuration:    7 * 24 * time.Hour,
		RefreshMaxLifetimeExpiry: 30 * 24 * time.Hour,
		RefreshReuseInterval:     5 * time.Minute,
	}
}

type AccessTokenClaims struct {
	ID                uuid.UUID `json:"jti"` // Unique token identifier (UUIDv4)
	Subject           uuid.UUID `json:"sub"` // Subject (user UUID)
	SessionID         uuid.UUID `json:"sid"` // Session identifier (UUIDv4)
	Username          string    `json:"usr"` // Human-readable username
	Issuer            string    `json:"iss"` // Issuer identifier (e.g., "auth.example.com")
	Audience          []string  `json:"aud"` // Intended audience (e.g., ["api.example.com"])
	Roles             []string  `json:"rls"` // Authorization roles
	IssuedAt          time.Time `json:"iat"` // Issuance timestamp (UTC)
	ExpiresAt         time.Time `json:"exp"` // Expiration timestamp (UTC)
	NotBefore         time.Time `json:"nbf"` // Not before timestamp (optional)
	MaxLifetimeExpiry time.Time `json:"mle"` // Maximum lifetime expiry timestamp (RFC3339)
	TokenType         TokenType `json:"typ"` // Fixed value "access"
}

type RefreshTokenClaims struct {
	ID                uuid.UUID `json:"jti"` // Unique token identifier
	Subject           uuid.UUID `json:"sub"` // Subject (user UUID)
	SessionID         uuid.UUID `json:"sid"` // Session identifier
	Username          string    `json:"usr"` // Human-readable username
	Issuer            string    `json:"iss"` // Issuer identifier (e.g., "auth.example.com")
	Audience          []string  `json:"aud"` // Intended audience (e.g., ["api.example.com"])
	IssuedAt          time.Time `json:"iat"` // Issuance timestamp
	ExpiresAt         time.Time `json:"exp"` // Expiration timestamp
	NotBefore         time.Time `json:"nbf"` // Not before timestamp (optional)
	MaxLifetimeExpiry time.Time `json:"mle"` // Maximum lifetime expiry timestamp (RFC3339)
	TokenType         TokenType `json:"typ"` // Fixed value "refresh"
}

type AccessTokenResponse struct {
	Subject           uuid.UUID `json:"sub"` // User UUID
	SessionID         uuid.UUID `json:"sid"` // Session UUID
	Token             string    `json:"tok"` // Signed JWT string
	Issuer            string    `json:"iss"` // Issuer identifier
	Username          string    `json:"usr"` // Username
	Roles             []string  `json:"rls"` // Authorization roles
	Audience          []string  `json:"aud"` // Intended audience
	IssuedAt          time.Time `json:"iat"` // Issuance timestamp (RFC3339)
	ExpiresAt         time.Time `json:"exp"` // Expiration timestamp (RFC3339)
	NotBefore         time.Time `json:"nbf"` // Not before timestamp (optional)
	MaxLifetimeExpiry time.Time `json:"mle"` // Maximum lifetime expiry timestamp (RFC3339)
	TokenType         TokenType `json:"typ"` // Fixed value "access"
}

type RefreshTokenResponse struct {
	Subject           uuid.UUID `json:"sub"` // User UUID
	SessionID         uuid.UUID `json:"sid"` // Session UUID
	Token             string    `json:"tok"` // Signed JWT string
	Issuer            string    `json:"iss"` // Issuer identifier
	Username          string    `json:"usr"` // Username
	Audience          []string  `json:"aud"` // Intended audience
	IssuedAt          time.Time `json:"iat"` // Issuance timestamp
	ExpiresAt         time.Time `json:"exp"` // Expiration timestamp
	NotBefore         time.Time `json:"nbf"` // Not before timestamp
	MaxLifetimeExpiry time.Time `json:"mle"` // Maximum lifetime expiry timestamp (RFC3339)
	TokenType         TokenType `json:"typ"` // Fixed value "access"
}

type GourdianTokenMaker interface {
	CreateAccessToken(ctx context.Context, userID uuid.UUID, username string, roles []string, sessionID uuid.UUID) (*AccessTokenResponse, error)
	CreateRefreshToken(ctx context.Context, userID uuid.UUID, username string, sessionID uuid.UUID) (*RefreshTokenResponse, error)
	VerifyAccessToken(ctx context.Context, tokenString string) (*AccessTokenClaims, error)
	VerifyRefreshToken(ctx context.Context, tokenString string) (*RefreshTokenClaims, error)
	RevokeAccessToken(ctx context.Context, token string) error
	RevokeRefreshToken(ctx context.Context, token string) error
	RotateRefreshToken(ctx context.Context, oldToken string) (*RefreshTokenResponse, error)
}

type JWTMaker struct {
	config        GourdianTokenConfig // Immutable configuration
	signingMethod jwt.SigningMethod   // JWT signing algorithm instance
	privateKey    interface{}         // Cryptographic key (HMAC secret or private key)
	publicKey     interface{}         // Verification key (HMAC secret or public key)
	redisClient   *redis.Client       // Redis client for revocation/rotation
}

func NewGourdianTokenMaker(ctx context.Context, config GourdianTokenConfig, redisOpts *redis.Options) (GourdianTokenMaker, error) {
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

	// Check Redis requirements
	if (config.RotationEnabled || config.RevocationEnabled) && redisOpts == nil {
		return nil, fmt.Errorf("redis options required for token rotation/revocation")
	}

	maker := &JWTMaker{
		config: config,
	}

	// Initialize Redis client if any feature requiring Redis is enabled
	if config.RotationEnabled || config.RevocationEnabled {
		maker.redisClient = redis.NewClient(redisOpts)

		// Verify Redis connection with the provided context
		if _, err := maker.redisClient.Ping(ctx).Result(); err != nil {
			return nil, fmt.Errorf("redis connection failed: %w", err)
		}

		// Check context again before starting goroutines
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("context canceled: %w", err)
		}

		// Set up background cleanup if needed
		if config.RotationEnabled {
			go maker.cleanupRotatedTokens(ctx)
		}
		if config.RevocationEnabled {
			go maker.cleanupRevokedTokens(ctx)
		}
	}

	// Initialize signing method
	if err := maker.initializeSigningMethod(); err != nil {
		return nil, fmt.Errorf("failed to initialize signing method: %w", err)
	}

	// Initialize cryptographic keys
	if err := maker.initializeKeys(); err != nil {
		return nil, fmt.Errorf("failed to initialize keys: %w", err)
	}

	return maker, nil
}

func DefaultGourdianTokenMaker(
	ctx context.Context,
	symmetricKey string,
	redisOpts *redis.Options,
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
	}

	if redisOpts != nil {
		config.RevocationEnabled = true
		config.RotationEnabled = true
	}
	return NewGourdianTokenMaker(ctx, config, redisOpts)
}

func (maker *JWTMaker) CreateAccessToken(ctx context.Context, userID uuid.UUID, username string, roles []string, sessionID uuid.UUID) (*AccessTokenResponse, error) {

	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context canceled: %w", err)
	}

	if userID == uuid.Nil {
		return nil, fmt.Errorf("invalid user ID: cannot be empty")
	}
	if len(roles) == 0 {
		return nil, fmt.Errorf("at least one role must be provided")
	}
	if len(username) > 1024 {
		return nil, fmt.Errorf("username too long: max 1024 characters")
	}

	// Validate roles are non-empty strings
	for _, role := range roles {
		if role == "" {
			return nil, fmt.Errorf("roles cannot contain empty strings")
		}
	}

	tokenID, err := uuid.NewRandom()
	if err != nil {
		return nil, fmt.Errorf("failed to generate token ID: %w", err)
	}

	now := time.Now()
	claims := AccessTokenClaims{
		ID:                tokenID,
		Subject:           userID,
		SessionID:         sessionID,
		Username:          username,
		Issuer:            maker.config.Issuer,
		Audience:          maker.config.Audience,
		Roles:             roles,
		IssuedAt:          now,
		ExpiresAt:         now.Add(maker.config.AccessExpiryDuration),
		NotBefore:         now,
		MaxLifetimeExpiry: now.Add(maker.config.AccessMaxLifetimeExpiry),
		TokenType:         AccessToken,
	}

	token := jwt.NewWithClaims(maker.signingMethod, toMapClaims(claims))

	signedToken, err := token.SignedString(maker.privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign access token: %w", err)
	}

	response := &AccessTokenResponse{
		Subject:           claims.Subject,
		SessionID:         claims.SessionID,
		Token:             signedToken,
		Issuer:            claims.Issuer,
		Username:          claims.Username,
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

func (maker *JWTMaker) CreateRefreshToken(ctx context.Context, userID uuid.UUID, username string, sessionID uuid.UUID) (*RefreshTokenResponse, error) {

	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context canceled: %w", err)
	}

	if userID == uuid.Nil {
		return nil, fmt.Errorf("invalid user ID: cannot be empty")
	}
	if len(username) > 1024 {
		return nil, fmt.Errorf("username too long: max 1024 characters")
	}

	tokenID, err := uuid.NewRandom()
	if err != nil {
		return nil, fmt.Errorf("failed to generate token ID: %w", err)
	}

	now := time.Now()
	claims := RefreshTokenClaims{
		ID:                tokenID,
		Subject:           userID,
		SessionID:         sessionID,
		Username:          username,
		Issuer:            maker.config.Issuer,
		Audience:          maker.config.Audience,
		IssuedAt:          now,
		ExpiresAt:         now.Add(maker.config.RefreshExpiryDuration),
		NotBefore:         now,
		MaxLifetimeExpiry: now.Add(maker.config.RefreshMaxLifetimeExpiry),
		TokenType:         RefreshToken,
	}

	token := jwt.NewWithClaims(maker.signingMethod, toMapClaims(claims))

	signedToken, err := token.SignedString(maker.privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign refresh token: %w", err)
	}

	response := &RefreshTokenResponse{
		Subject:           claims.Subject,
		SessionID:         claims.SessionID,
		Token:             signedToken,
		Issuer:            claims.Issuer,
		Username:          claims.Username,
		Audience:          claims.Audience,
		IssuedAt:          claims.IssuedAt,
		ExpiresAt:         claims.ExpiresAt,
		NotBefore:         claims.NotBefore,
		MaxLifetimeExpiry: claims.MaxLifetimeExpiry,
		TokenType:         claims.TokenType,
	}

	return response, nil
}

func (maker *JWTMaker) VerifyAccessToken(ctx context.Context, tokenString string) (*AccessTokenClaims, error) {

	if maker.config.RevocationEnabled && maker.redisClient != nil {

		exists, err := maker.redisClient.Exists(ctx, revokedAccessPrefix+tokenString).Result()
		if err != nil {
			return nil, fmt.Errorf("failed to check token revocation: %w", err)
		}
		if exists > 0 {
			return nil, fmt.Errorf("token has been revoked")
		}
	}

	// 1. Verify token signature and basic structure
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if token.Method.Alg() != maker.signingMethod.Alg() {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return maker.publicKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("invalid token: %v", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token claims")
	}

	// 2. Validate all required claims exist
	if err := validateTokenClaims(claims, AccessToken, maker.config.RequiredClaims); err != nil {
		return nil, err
	}

	// 3. Convert and validate UUID formats before other validations
	accessClaims, err := mapToAccessClaims(claims)
	if err != nil {
		return nil, err
	}

	// 4. Validate roles claim exists and is non-empty
	if _, ok := claims["rls"]; !ok {
		return nil, fmt.Errorf("missing roles claim in access token")
	}

	return accessClaims, nil
}

func (maker *JWTMaker) VerifyRefreshToken(ctx context.Context, tokenString string) (*RefreshTokenClaims, error) {

	if maker.config.RevocationEnabled && maker.redisClient != nil {

		exists, err := maker.redisClient.Exists(ctx, revokedRefreshPrefix+tokenString).Result()
		if err != nil {
			return nil, fmt.Errorf("failed to check token revocation: %w", err)
		}
		if exists > 0 {
			return nil, fmt.Errorf("token has been revoked")
		}
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if token.Method.Alg() != maker.signingMethod.Alg() {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return maker.publicKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("invalid token: %v", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token claims")
	}

	if err := validateTokenClaims(claims, RefreshToken, maker.config.RequiredClaims); err != nil {
		return nil, err
	}

	return mapToRefreshClaims(claims)
}

func (maker *JWTMaker) RevokeAccessToken(ctx context.Context, token string) error {
	if !maker.config.RevocationEnabled || maker.redisClient == nil {
		return fmt.Errorf("access token revocation is not enabled")
	}

	// Parse the token to extract expiration time
	parsed, err := jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		return maker.publicKey, nil
	})
	if err != nil || !parsed.Valid {
		return fmt.Errorf("invalid token: %w", err)
	}

	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return fmt.Errorf("invalid token claims")
	}

	exp := getUnixTime(claims["exp"])
	if exp == 0 {
		return fmt.Errorf("token missing exp claim")
	}
	ttl := time.Until(time.Unix(exp, 0))

	// Store the token string as revoked in Redis with expiry
	return maker.redisClient.Set(ctx, revokedAccessPrefix+token, "1", ttl).Err()
}

func (maker *JWTMaker) RevokeRefreshToken(ctx context.Context, token string) error {
	if !maker.config.RevocationEnabled || maker.redisClient == nil {
		return fmt.Errorf("refresh token revocation is not enabled")
	}

	// Parse the token to extract expiration time
	parsed, err := jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		return maker.publicKey, nil
	})
	if err != nil || !parsed.Valid {
		return fmt.Errorf("invalid token: %w", err)
	}

	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return fmt.Errorf("invalid token claims")
	}

	exp := getUnixTime(claims["exp"])
	if exp == 0 {
		return fmt.Errorf("token missing exp claim")
	}
	ttl := time.Until(time.Unix(exp, 0))

	// Store the token string as revoked in Redis with expiry
	return maker.redisClient.Set(ctx, revokedRefreshPrefix+token, "1", ttl).Err()
}

func (maker *JWTMaker) RotateRefreshToken(ctx context.Context, oldToken string) (*RefreshTokenResponse, error) {

	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context canceled: %w", err)
	}

	if !maker.config.RotationEnabled {
		return nil, fmt.Errorf("token rotation not enabled")
	}

	if _, err := maker.redisClient.Ping(ctx).Result(); err != nil {
		return nil, fmt.Errorf("redis connection failed: %w", err)
	}

	claims, err := maker.VerifyRefreshToken(ctx, oldToken)
	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	tokenKey := rotatedPrefix + oldToken

	exists, err := maker.redisClient.Exists(ctx, tokenKey).Result()
	if err != nil {
		return nil, fmt.Errorf("redis error: %w", err)
	}

	if exists == 1 {
		return nil, fmt.Errorf("token reused too soon")
	}

	// Enforce reuse interval
	if maker.config.RefreshReuseInterval > 0 {
		ttl, err := maker.redisClient.TTL(ctx, rotatedPrefix+oldToken).Result()
		if err == nil && ttl > 0 {
			remaining := time.Duration(ttl) * time.Second
			if remaining > maker.config.RefreshReuseInterval {
				return nil, fmt.Errorf("token reused too soon, wait %v", remaining)
			}
		}
	}

	newToken, err := maker.CreateRefreshToken(ctx, claims.Subject, claims.Username, claims.SessionID)
	if err != nil {
		return nil, err
	}

	err = maker.redisClient.Set(ctx, tokenKey, "1", maker.config.RefreshMaxLifetimeExpiry).Err()
	if err != nil {
		return nil, fmt.Errorf("failed to record rotation: %w", err)
	}

	return newToken, nil
}

func (maker *JWTMaker) cleanupRotatedTokens(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if maker.redisClient == nil {
				continue
			}

			var cursor uint64
			const batchSize = 100

			for {
				// Use SCAN to iterate keys matching the pattern in a memory-efficient way
				keys, newCursor, err := maker.redisClient.Scan(ctx, cursor, "rotated:*", batchSize).Result()
				if err != nil {
					fmt.Printf("Error scanning Redis keys: %v\n", err)
					break
				}

				// Filter out keys with expired TTL (or TTL = -2 meaning already expired)
				var keysToDelete []string
				for _, key := range keys {
					ttl, err := maker.redisClient.TTL(ctx, key).Result()
					if err != nil {
						fmt.Printf("Error checking TTL for key %s: %v\n", key, err)
						continue
					}
					if ttl <= 0 {
						keysToDelete = append(keysToDelete, key)
					}
				}

				// Delete expired keys in batch
				if len(keysToDelete) > 0 {
					if _, err := maker.redisClient.Del(ctx, keysToDelete...).Result(); err != nil {
						fmt.Printf("Error deleting expired rotated tokens: %v\n", err)
					}
				}

				// Exit loop if iteration is complete
				if newCursor == 0 {
					break
				}
				cursor = newCursor
			}
		}
	}
}

func (maker *JWTMaker) cleanupRevokedTokens(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if maker.redisClient == nil {
				continue
			}

			for _, prefix := range []string{revokedAccessPrefix, revokedRefreshPrefix} {
				var cursor uint64
				const batchSize = 100

				for {
					keys, newCursor, err := maker.redisClient.Scan(ctx, cursor, prefix+"*", batchSize).Result()
					if err != nil {
						fmt.Printf("Error scanning Redis keys for %s: %v\n", prefix, err)
						break
					}

					var keysToDelete []string
					for _, key := range keys {
						ttl, err := maker.redisClient.TTL(ctx, key).Result()
						if err != nil {
							fmt.Printf("Error checking TTL for key %s: %v\n", key, err)
							continue
						}
						if ttl <= 0 {
							keysToDelete = append(keysToDelete, key)
						}
					}

					if len(keysToDelete) > 0 {
						if _, err := maker.redisClient.Del(ctx, keysToDelete...).Result(); err != nil {
							fmt.Printf("Error deleting expired revoked tokens: %v\n", err)
						}
					}

					if newCursor == 0 {
						break
					}
					cursor = newCursor
				}
			}
		}
	}
}

func (maker *JWTMaker) initializeSigningMethod() error {

	// Check if configured algorithm is in allowed list if specified
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

func validateConfig(config *GourdianTokenConfig) error {
	switch config.SigningMethod {
	case Symmetric:
		if config.SymmetricKey == "" {
			return fmt.Errorf("symmetric key is required for symmetric signing method")
		}
		if !strings.HasPrefix(config.Algorithm, "HS") && config.Algorithm != "none" {
			return fmt.Errorf("algorithm %s not compatible with symmetric signing", config.Algorithm)
		}
		if len(config.SymmetricKey) < 32 {
			return fmt.Errorf("symmetric key must be at least 32 bytes")
		}
		if config.PrivateKeyPath != "" || config.PublicKeyPath != "" {
			return fmt.Errorf("private and public key paths must be empty for symmetric signing")
		}
	case Asymmetric:
		if config.PrivateKeyPath == "" || config.PublicKeyPath == "" {
			return fmt.Errorf("private and public key paths are required for asymmetric signing method")
		}
		if config.SymmetricKey != "" {
			return fmt.Errorf("symmetric key must be empty for asymmetric signing")
		}
		if !strings.HasPrefix(config.Algorithm, "RS") &&
			!strings.HasPrefix(config.Algorithm, "ES") &&
			!strings.HasPrefix(config.Algorithm, "PS") &&
			config.Algorithm != "EdDSA" {
			return fmt.Errorf("algorithm %s not compatible with asymmetric signing", config.Algorithm)
		}
		if err := checkFilePermissions(config.PrivateKeyPath, 0644); err != nil {
			return fmt.Errorf("insecure private key file permissions: %w", err)
		}
		if err := checkFilePermissions(config.PublicKeyPath, 0644); err != nil {
			return fmt.Errorf("insecure public key file permissions: %w", err)
		}
	default:
		return fmt.Errorf("unsupported signing method: %s, supports %s and %s",
			config.SigningMethod, Symmetric, Asymmetric)
	}

	// Validate token durations make sense
	if config.AccessExpiryDuration <= 0 {
		return fmt.Errorf("access token duration must be positive")
	}
	if config.AccessMaxLifetimeExpiry > 0 &&
		config.AccessExpiryDuration > config.AccessMaxLifetimeExpiry {
		return fmt.Errorf("access token duration exceeds max lifetime")
	}

	if config.RefreshExpiryDuration <= 0 {
		return fmt.Errorf("refresh token duration must be positive")
	}
	if config.RefreshMaxLifetimeExpiry > 0 &&
		config.RefreshExpiryDuration > config.RefreshMaxLifetimeExpiry {
		return fmt.Errorf("refresh token duration exceeds max lifetime")
	}

	if config.RefreshReuseInterval < 0 {
		return fmt.Errorf("refresh reuse interval cannot be negative")
	}

	// Reject weak algorithms
	weakAlgorithms := map[string]bool{
		"HS256": false, // Considered strong enough with proper key size
		"none":  true,
	}
	if weak, ok := weakAlgorithms[config.Algorithm]; ok && weak {
		return fmt.Errorf("algorithm %s is too weak for production use", config.Algorithm)
	}

	if len(config.AllowedAlgorithms) > 0 {
		supportedAlgs := map[string]bool{
			"HS256": true, "HS384": true, "HS512": true,
			"RS256": true, "RS384": true, "RS512": true,
			"ES256": true, "ES384": true, "ES512": true,
			"PS256": true, "PS384": true, "PS512": true,
			"EdDSA": true,
		}

		for _, alg := range config.AllowedAlgorithms {
			if !supportedAlgs[alg] {
				return fmt.Errorf("unsupported algorithm in AllowedAlgorithms: %s", alg)
			}
		}
	}

	return nil
}

func validateAlgorithmAndMethod(config *GourdianTokenConfig) error {
	switch config.SigningMethod {
	case Symmetric:
		if !strings.HasPrefix(config.Algorithm, "HS") {
			return fmt.Errorf("algorithm %s not compatible with symmetric signing", config.Algorithm)
		}
	case Asymmetric:
		if !strings.HasPrefix(config.Algorithm, "RS") &&
			!strings.HasPrefix(config.Algorithm, "ES") &&
			!strings.HasPrefix(config.Algorithm, "PS") &&
			config.Algorithm != "EdDSA" {
			return fmt.Errorf("algorithm %s not compatible with asymmetric signing", config.Algorithm)
		}
	}
	return nil
}

func toMapClaims(claims interface{}) jwt.MapClaims {
	switch v := claims.(type) {
	case AccessTokenClaims:
		if len(v.Roles) == 0 {
			panic("at least one role must be provided")
		}
		mapClaims := jwt.MapClaims{
			"jti": v.ID.String(),
			"sub": v.Subject.String(),
			"usr": v.Username,
			"sid": v.SessionID.String(),
			"iss": v.Issuer,
			"aud": v.Audience,
			"iat": v.IssuedAt.Unix(),
			"exp": v.ExpiresAt.Unix(),
			"typ": string(v.TokenType),
			"rls": v.Roles,
		}
		if !v.NotBefore.IsZero() {
			mapClaims["nbf"] = v.NotBefore.Unix()
		}
		if !v.MaxLifetimeExpiry.IsZero() {
			mapClaims["mle"] = v.MaxLifetimeExpiry.Unix()
		}
		return mapClaims
	case RefreshTokenClaims:
		mapClaims := jwt.MapClaims{
			"jti": v.ID.String(),
			"sub": v.Subject.String(),
			"usr": v.Username,
			"sid": v.SessionID.String(),
			"iss": v.Issuer,
			"aud": v.Audience,
			"iat": v.IssuedAt.Unix(),
			"exp": v.ExpiresAt.Unix(),
			"typ": string(v.TokenType),
		}
		if !v.NotBefore.IsZero() {
			mapClaims["nbf"] = v.NotBefore.Unix()
		}
		if !v.MaxLifetimeExpiry.IsZero() {
			mapClaims["mle"] = v.MaxLifetimeExpiry.Unix()
		}
		return mapClaims
	default:
		panic(fmt.Sprintf("unsupported claims type: %T", claims))
	}
}

func mapToAccessClaims(claims jwt.MapClaims) (*AccessTokenClaims, error) {
	// Validate and convert jti claim
	jti, ok := claims["jti"].(string)
	if !ok {
		return nil, fmt.Errorf("invalid token ID type: expected string")
	}
	tokenID, err := uuid.Parse(jti)
	if err != nil {
		return nil, fmt.Errorf("invalid token ID: %w", err)
	}

	// Validate and convert sub claim
	sub, ok := claims["sub"].(string)
	if !ok {
		return nil, fmt.Errorf("invalid user ID type: expected string")
	}
	userID, err := uuid.Parse(sub)
	if err != nil {
		return nil, fmt.Errorf("invalid user ID: %w", err)
	}

	// Validate and convert sid claim
	sid, ok := claims["sid"].(string)
	if !ok {
		return nil, fmt.Errorf("invalid session ID type: expected string")
	}
	sessionID, err := uuid.Parse(sid)
	if err != nil {
		return nil, fmt.Errorf("invalid session ID: %w", err)
	}

	// Validate username claim
	username, ok := claims["usr"].(string)
	if !ok {
		return nil, fmt.Errorf("invalid username type: expected string")
	}

	// Validate issuer claim
	issuer, _ := claims["iss"].(string) // Optional

	// Validate audience claim
	var audience []string
	if aud, ok := claims["aud"]; ok {
		switch v := aud.(type) {
		case string:
			audience = []string{v}
		case []interface{}:
			audience = make([]string, 0, len(v))
			for _, a := range v {
				if aStr, ok := a.(string); ok {
					audience = append(audience, aStr)
				}
			}
		case []string:
			audience = v
		}
	}

	// Validate roles claim
	rolesInterface, ok := claims["rls"]
	if !ok {
		return nil, fmt.Errorf("missing roles claim")
	}

	var roles []string
	switch v := rolesInterface.(type) {
	case []interface{}:
		roles = make([]string, 0, len(v))
		for _, r := range v {
			role, ok := r.(string)
			if !ok {
				return nil, fmt.Errorf("invalid role type: expected string")
			}
			roles = append(roles, role)
		}
	case []string:
		roles = v
	default:
		return nil, fmt.Errorf("invalid roles type: expected array of strings")
	}

	if len(roles) == 0 {
		return nil, fmt.Errorf("at least one role must be provided")
	}

	// Validate token type claim
	typ, ok := claims["typ"].(string)
	if !ok {
		return nil, fmt.Errorf("invalid token type: expected string")
	}

	// Get timestamps with validation
	iat := getUnixTime(claims["iat"])
	exp := getUnixTime(claims["exp"])
	nbf := getUnixTime(claims["nbf"])
	mle := getUnixTime(claims["mle"])

	if iat == 0 || exp == 0 {
		return nil, fmt.Errorf("invalid timestamp format")
	}

	accessClaims := &AccessTokenClaims{
		ID:        tokenID,
		Subject:   userID,
		Username:  username,
		SessionID: sessionID,
		Issuer:    issuer,
		Audience:  audience,
		IssuedAt:  time.Unix(iat, 0),
		ExpiresAt: time.Unix(exp, 0),
		TokenType: TokenType(typ),
		Roles:     roles,
	}

	if nbf != 0 {
		accessClaims.NotBefore = time.Unix(nbf, 0)
	}

	// Only set MaxLifetimeExpiry if mle exists and is valid
	if mle != 0 {
		accessClaims.MaxLifetimeExpiry = time.Unix(mle, 0)
	}

	return accessClaims, nil
}

func mapToRefreshClaims(claims jwt.MapClaims) (*RefreshTokenClaims, error) {
	tokenID, err := uuid.Parse(claims["jti"].(string))
	if err != nil {
		return nil, fmt.Errorf("invalid token ID: %w", err)
	}

	userID, err := uuid.Parse(claims["sub"].(string))
	if err != nil {
		return nil, fmt.Errorf("invalid user ID: %w", err)
	}

	sessionID, err := uuid.Parse(claims["sid"].(string))
	if err != nil {
		return nil, fmt.Errorf("invalid session ID: %w", err)
	}

	username, ok := claims["usr"].(string)
	if !ok {
		return nil, fmt.Errorf("invalid username type: expected string")
	}

	issuer, _ := claims["iss"].(string) // Optional

	var audience []string
	if aud, ok := claims["aud"]; ok {
		switch v := aud.(type) {
		case string:
			audience = []string{v}
		case []interface{}:
			audience = make([]string, 0, len(v))
			for _, a := range v {
				if aStr, ok := a.(string); ok {
					audience = append(audience, aStr)
				}
			}
		case []string:
			audience = v
		}
	}

	typ, ok := claims["typ"].(string)
	if !ok {
		return nil, fmt.Errorf("invalid or missing token type")
	}

	if TokenType(typ) != RefreshToken {
		return nil, fmt.Errorf("invalid token type: expected 'refresh'")
	}

	iat := getUnixTime(claims["iat"])
	exp := getUnixTime(claims["exp"])
	nbf := getUnixTime(claims["nbf"])
	mle := getUnixTime(claims["mle"])

	if iat == 0 || exp == 0 {
		return nil, fmt.Errorf("invalid timestamp format")
	}

	refreshClaims := &RefreshTokenClaims{
		ID:        tokenID,
		Subject:   userID,
		Username:  username,
		SessionID: sessionID,
		Issuer:    issuer,
		Audience:  audience,
		IssuedAt:  time.Unix(iat, 0),
		ExpiresAt: time.Unix(exp, 0),
		TokenType: TokenType(typ),
	}

	if nbf != 0 {
		refreshClaims.NotBefore = time.Unix(nbf, 0)
	}

	// Only set MaxLifetimeExpiry if mle exists and is valid
	if mle != 0 {
		refreshClaims.MaxLifetimeExpiry = time.Unix(mle, 0)
	}

	return refreshClaims, nil
}

func validateTokenClaims(claims jwt.MapClaims, expectedType TokenType, required []string) error {
	// Base required claims
	baseRequired := map[TokenType][]string{
		AccessToken:  {"jti", "sub", "sid", "usr", "iat", "exp", "typ", "rls"},
		RefreshToken: {"jti", "sub", "sid", "usr", "iat", "exp", "typ"},
	}

	// Check all required claims
	for _, claim := range append(baseRequired[expectedType], required...) {
		if _, ok := claims[claim]; !ok {
			return fmt.Errorf("missing required claim: %s", claim)
		}
	}

	// Validate token type
	tokenType, ok := claims["typ"].(string)
	if !ok || TokenType(tokenType) != expectedType {
		return fmt.Errorf("invalid token type: expected %s", expectedType)
	}

	// Validate expiration
	exp, ok := claims["exp"].(float64)
	if !ok {
		return fmt.Errorf("invalid exp claim type")
	}
	if time.Unix(int64(exp), 0).Before(time.Now()) {
		return fmt.Errorf("token has expired")
	}

	// Validate issuance time
	if iat, ok := claims["iat"].(float64); ok {
		if time.Unix(int64(iat), 0).After(time.Now()) {
			return fmt.Errorf("token issued in the future")
		}
	}

	// Check max lifetime if present in claims
	if mle, ok := claims["mle"].(float64); ok {
		maxExpiry := time.Unix(int64(mle), 0)
		if time.Now().After(maxExpiry) {
			return fmt.Errorf("token exceeded maximum lifetime")
		}
	}

	return nil
}

func parseEdDSAPrivateKey(pemBytes []byte) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block containing the private key")
	}

	priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse EdDSA private key: %w", err)
	}

	eddsaPriv, ok := priv.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("not a valid EdDSA private key")
	}

	return eddsaPriv, nil
}

func parseEdDSAPublicKey(pemBytes []byte) (ed25519.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block containing the public key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse EdDSA public key: %w", err)
		}
		eddsaPub, ok := cert.PublicKey.(ed25519.PublicKey)
		if !ok {
			return nil, fmt.Errorf("not a valid EdDSA public key")
		}
		return eddsaPub, nil
	}

	eddsaPub, ok := pub.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not a valid EdDSA public key")
	}
	return eddsaPub, nil
}

func parseRSAPrivateKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block containing the RSA private key")
	}

	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}

	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if rsaKey, ok := key.(*rsa.PrivateKey); ok {
			return rsaKey, nil
		}
		return nil, fmt.Errorf("expected RSA private key, got %T", key)
	}

	var privKey pkcs8
	if _, err := asn1.Unmarshal(block.Bytes, &privKey); err != nil {
		return nil, fmt.Errorf("failed to parse PKCS8 structure: %w", err)
	}

	var rsaPriv rsaPrivateKey
	if _, err := asn1.Unmarshal(privKey.PrivateKey, &rsaPriv); err != nil {
		return nil, fmt.Errorf("failed to parse RSA private key: %w", err)
	}

	return &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			N: rsaPriv.N,
			E: int(rsaPriv.E.Int64()),
		},
		D:      rsaPriv.D,
		Primes: []*big.Int{rsaPriv.P, rsaPriv.Q},
		Precomputed: rsa.PrecomputedValues{
			Dp:   rsaPriv.Dp,
			Dq:   rsaPriv.Dq,
			Qinv: rsaPriv.Qinv,
		},
	}, nil
}

func parseRSAPublicKey(pemBytes []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block containing the RSA public key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err == nil {
		if rsaPub, ok := pub.(*rsa.PublicKey); ok {
			return rsaPub, nil
		}
		return nil, fmt.Errorf("expected RSA public key, got %T", pub)
	}

	if pub, err := x509.ParsePKCS1PublicKey(block.Bytes); err == nil {
		return pub, nil
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err == nil {
		if rsaPub, ok := cert.PublicKey.(*rsa.PublicKey); ok {
			return rsaPub, nil
		}
		return nil, fmt.Errorf("expected RSA public key in certificate, got %T", cert.PublicKey)
	}

	var pubKey struct {
		Algo      pkix.AlgorithmIdentifier
		BitString asn1.BitString
	}
	if _, err := asn1.Unmarshal(block.Bytes, &pubKey); err != nil {
		return nil, fmt.Errorf("failed to parse public key structure: %w", err)
	}

	var rsaPub struct {
		N *big.Int
		E *big.Int
	}
	if _, err := asn1.Unmarshal(pubKey.BitString.Bytes, &rsaPub); err != nil {
		return nil, fmt.Errorf("failed to parse RSA public key: %w", err)
	}

	return &rsa.PublicKey{
		N: rsaPub.N,
		E: int(rsaPub.E.Int64()),
	}, nil
}

func parseECDSAPrivateKey(pemBytes []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block containing the ECDSA private key")
	}

	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		pkcs8Key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse ECDSA private key: %w", err)
		}
		key, ok := pkcs8Key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("not a valid ECDSA private key")
		}
		return key, nil
	}
	return key, nil
}

func parseECDSAPublicKey(pemBytes []byte) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block containing the ECDSA public key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse ECDSA public key: %w", err)
		}
		ecdsaPub, ok := cert.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("not a valid ECDSA public key")
		}
		return ecdsaPub, nil
	}

	ecdsaPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not a valid ECDSA public key")
	}
	return ecdsaPub, nil
}

func checkFilePermissions(path string, requiredPerm os.FileMode) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("failed to stat file: %w", err)
	}

	actualPerm := info.Mode().Perm()
	if actualPerm&^requiredPerm != 0 {
		return fmt.Errorf("file %s has permissions %#o, expected %#o", path, actualPerm, requiredPerm)
	}

	return nil
}

func getUnixTime(claim interface{}) int64 {
	switch v := claim.(type) {
	case float64:
		return int64(v)
	case int64:
		return v
	case int:
		return int64(v)
	case json.Number:
		i, _ := v.Int64()
		return i
	default:
		return 0
	}
}

type pkcs8 struct {
	Version    int
	Algo       pkix.AlgorithmIdentifier
	PrivateKey []byte
}

type rsaPrivateKey struct {
	Version int
	N       *big.Int
	E       *big.Int
	D       *big.Int
	P       *big.Int
	Q       *big.Int
	Dp      *big.Int
	Dq      *big.Int
	Qinv    *big.Int
}
