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
	Algorithm      string             // JWT signing algorithm (e.g., "HS256", "RS256", "ES256", "EdDSA")
	SigningMethod  SigningMethod      // Cryptographic method (symmetric or asymmetric)
	SymmetricKey   string             // Secret key for symmetric signing (min 32 bytes for HS256)
	PrivateKeyPath string             // Path to private key file for asymmetric signing
	PublicKeyPath  string             // Path to public key/certificate file for asymmetric verification
	AccessToken    AccessTokenConfig  // Configuration for access token settings
	RefreshToken   RefreshTokenConfig // Configuration for refresh token settings
}

type AccessTokenConfig struct {
	Duration          time.Duration // Token validity duration from issuance (e.g., 30m)
	MaxLifetime       time.Duration // Absolute maximum lifetime from creation time (e.g., 24h)
	Issuer            string        // Token issuer identifier (optional)
	Audience          []string      // Intended recipients (optional)
	AllowedAlgorithms []string      // Permitted algorithms for verification (must include primary algorithm)
	RequiredClaims    []string      // Mandatory claims (e.g., ["jti", "sub", "exp", "iat", "typ"])
	RevocationEnabled bool
}

type RefreshTokenConfig struct {
	Duration          time.Duration // Token validity duration (e.g., 7d)
	MaxLifetime       time.Duration // Absolute maximum lifetime (e.g., 30d)
	ReuseInterval     time.Duration // Minimum time between reuse attempts (e.g., 1m)
	RotationEnabled   bool          // Whether refresh token rotation is enabled (requires Redis)
	RevocationEnabled bool
}

func NewGourdianTokenConfig(
	algorithm string,
	signingMethod SigningMethod,
	symmetricKey string,
	privateKeyPath string,
	publicKeyPath string,
	accessDuration time.Duration,
	accessMaxLifetime time.Duration,
	accessIssuer string,
	accessAudience []string,
	accessAllowedAlgorithms []string,
	accessRequiredClaims []string,
	accessRevocationEnabled bool,
	refreshDuration time.Duration,
	refreshMaxLifetime time.Duration,
	refreshReuseInterval time.Duration,
	refreshRotationEnabled bool,
	refreshRevocationEnabled bool,
) GourdianTokenConfig {
	return GourdianTokenConfig{
		Algorithm:      algorithm,
		SigningMethod:  signingMethod,
		SymmetricKey:   symmetricKey,
		PrivateKeyPath: privateKeyPath,
		PublicKeyPath:  publicKeyPath,
		AccessToken: AccessTokenConfig{
			Duration:          accessDuration,
			MaxLifetime:       accessMaxLifetime,
			Issuer:            accessIssuer,
			Audience:          accessAudience,
			AllowedAlgorithms: accessAllowedAlgorithms,
			RequiredClaims:    accessRequiredClaims,
			RevocationEnabled: accessRevocationEnabled,
		},
		RefreshToken: RefreshTokenConfig{
			Duration:          refreshDuration,
			MaxLifetime:       refreshMaxLifetime,
			ReuseInterval:     refreshReuseInterval,
			RotationEnabled:   refreshRotationEnabled,
			RevocationEnabled: refreshRevocationEnabled,
		},
	}
}

func DefaultGourdianTokenConfig(symmetricKey string) GourdianTokenConfig {
	return GourdianTokenConfig{
		Algorithm:      "HS256",
		SigningMethod:  Symmetric,
		SymmetricKey:   symmetricKey,
		PrivateKeyPath: "",
		PublicKeyPath:  "",
		AccessToken: AccessTokenConfig{
			Duration:          30 * time.Minute,
			MaxLifetime:       24 * time.Hour,
			Issuer:            "",
			Audience:          nil,
			AllowedAlgorithms: []string{"HS256"},
			RequiredClaims:    []string{"jti", "sub", "exp", "iat", "typ", "rls"},
			RevocationEnabled: false,
		},
		RefreshToken: RefreshTokenConfig{
			Duration:          7 * 24 * time.Hour,
			MaxLifetime:       30 * 24 * time.Hour,
			ReuseInterval:     time.Minute,
			RotationEnabled:   false,
			RevocationEnabled: false,
		},
	}
}

type AccessTokenClaims struct {
	ID        uuid.UUID `json:"jti"` // Unique token identifier (UUIDv4)
	Subject   uuid.UUID `json:"sub"` // Subject (user ID as UUID)
	Username  string    `json:"usr"` // Human-readable username
	SessionID uuid.UUID `json:"sid"` // Session identifier (UUIDv4)
	IssuedAt  time.Time `json:"iat"` // Token issuance timestamp
	ExpiresAt time.Time `json:"exp"` // Token expiration timestamp
	TokenType TokenType `json:"typ"` // Token type ("access")
	Roles     []string  `json:"rls"` // User roles/privilege levels
}

type RefreshTokenClaims struct {
	ID        uuid.UUID `json:"jti"` // Unique token identifier (UUIDv4)
	Subject   uuid.UUID `json:"sub"` // Subject (user ID as UUID)
	Username  string    `json:"usr"` // Human-readable username
	SessionID uuid.UUID `json:"sid"` // Session identifier (UUIDv4)
	IssuedAt  time.Time `json:"iat"` // Token issuance timestamp
	ExpiresAt time.Time `json:"exp"` // Token expiration timestamp
	TokenType TokenType `json:"typ"` // Token type ("refresh")
}

type AccessTokenResponse struct {
	Token     string    `json:"tok"` // The signed JWT string
	Subject   uuid.UUID `json:"sub"` // User ID (UUID)
	Username  string    `json:"usr"` // Username
	SessionID uuid.UUID `json:"sid"` // Session ID (UUID)
	ExpiresAt time.Time `json:"exp"` // Expiration timestamp
	IssuedAt  time.Time `json:"iat"` // Issuance timestamp
	Roles     []string  `json:"rls"` // User roles
}

type RefreshTokenResponse struct {
	Token     string    `json:"tok"` // The signed JWT string
	Subject   uuid.UUID `json:"sub"` // User ID (UUID)
	Username  string    `json:"usr"` // Username
	SessionID uuid.UUID `json:"sid"` // Session ID (UUID)
	ExpiresAt time.Time `json:"exp"` // Expiration timestamp
	IssuedAt  time.Time `json:"iat"` // Issuance timestamp
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
	config        GourdianTokenConfig // Complete token configuration
	signingMethod jwt.SigningMethod   // JWT signing method instance
	privateKey    interface{}         // Key used for signing (HMAC secret or private key)
	publicKey     interface{}         // Key used for verification (HMAC secret or public key)
	redisClient   *redis.Client       // Redis client for token rotation (nil if rotation disabled)
}

func NewGourdianTokenMaker(ctx context.Context, config GourdianTokenConfig, redisOpts *redis.Options) (GourdianTokenMaker, error) {
	// Validate configuration
	if err := validateConfig(&config); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	// Check Redis requirements
	if (config.RefreshToken.RotationEnabled || config.RefreshToken.RevocationEnabled ||
		config.AccessToken.RevocationEnabled) && redisOpts == nil {
		return nil, fmt.Errorf("redis options required for token rotation/revocation")
	}

	maker := &JWTMaker{
		config: config,
	}

	// Initialize Redis client if any feature requiring Redis is enabled
	if config.RefreshToken.RotationEnabled || config.RefreshToken.RevocationEnabled ||
		config.AccessToken.RevocationEnabled {
		maker.redisClient = redis.NewClient(redisOpts)

		// Verify Redis connection with the provided context
		if _, err := maker.redisClient.Ping(ctx).Result(); err != nil {
			return nil, fmt.Errorf("redis connection failed: %w", err)
		}

		// Set up background cleanup if needed
		if config.RefreshToken.RotationEnabled {
			go maker.cleanupRotatedTokens(ctx)
		}
		if config.RefreshToken.RevocationEnabled || config.AccessToken.RevocationEnabled {
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

func (maker *JWTMaker) CreateAccessToken(ctx context.Context, userID uuid.UUID, username string, roles []string, sessionID uuid.UUID) (*AccessTokenResponse, error) {
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
		ID:        tokenID,
		Subject:   userID,
		Username:  username,
		SessionID: sessionID,
		IssuedAt:  now,
		ExpiresAt: now.Add(maker.config.AccessToken.Duration),
		TokenType: AccessToken,
		Roles:     roles,
	}

	token := jwt.NewWithClaims(maker.signingMethod, toMapClaims(claims))

	signedToken, err := token.SignedString(maker.privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign access token: %w", err)
	}

	response := &AccessTokenResponse{
		Token:     signedToken,
		Subject:   claims.Subject,
		Username:  claims.Username,
		SessionID: claims.SessionID,
		ExpiresAt: claims.ExpiresAt,
		IssuedAt:  claims.IssuedAt,
		Roles:     roles,
	}

	return response, nil
}

func (maker *JWTMaker) CreateRefreshToken(ctx context.Context, userID uuid.UUID, username string, sessionID uuid.UUID) (*RefreshTokenResponse, error) {
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
		ID:        tokenID,
		Subject:   userID,
		Username:  username,
		SessionID: sessionID,
		IssuedAt:  now,
		ExpiresAt: now.Add(maker.config.RefreshToken.Duration),
		TokenType: RefreshToken,
	}

	token := jwt.NewWithClaims(maker.signingMethod, toMapClaims(claims))

	signedToken, err := token.SignedString(maker.privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign refresh token: %w", err)
	}

	response := &RefreshTokenResponse{
		Token:     signedToken,
		Subject:   claims.Subject,
		Username:  claims.Username,
		SessionID: claims.SessionID,
		ExpiresAt: claims.ExpiresAt,
		IssuedAt:  claims.IssuedAt,
	}

	return response, nil
}

func (maker *JWTMaker) VerifyAccessToken(ctx context.Context, tokenString string) (*AccessTokenClaims, error) {

	if maker.config.AccessToken.RevocationEnabled && maker.redisClient != nil {

		exists, err := maker.redisClient.Exists(ctx, "revoked:access:"+tokenString).Result()
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
	if err := validateTokenClaims(claims, AccessToken); err != nil {
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

	if maker.config.RefreshToken.RevocationEnabled && maker.redisClient != nil {

		exists, err := maker.redisClient.Exists(ctx, "revoked:refresh:"+tokenString).Result()
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

	if err := validateTokenClaims(claims, RefreshToken); err != nil {
		return nil, err
	}

	return mapToRefreshClaims(claims)
}

func (maker *JWTMaker) RevokeAccessToken(ctx context.Context, token string) error {
	if !maker.config.AccessToken.RevocationEnabled || maker.redisClient == nil {
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
	return maker.redisClient.Set(ctx, "revoked:access:"+token, "1", ttl).Err()
}

func (maker *JWTMaker) RevokeRefreshToken(ctx context.Context, token string) error {
	if !maker.config.RefreshToken.RevocationEnabled || maker.redisClient == nil {
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
	return maker.redisClient.Set(ctx, "revoked:refresh:"+token, "1", ttl).Err()
}

func (maker *JWTMaker) RotateRefreshToken(ctx context.Context, oldToken string) (*RefreshTokenResponse, error) {
	if !maker.config.RefreshToken.RotationEnabled {
		return nil, fmt.Errorf("token rotation not enabled")
	}

	if _, err := maker.redisClient.Ping(ctx).Result(); err != nil {
		return nil, fmt.Errorf("redis connection failed: %w", err)
	}

	claims, err := maker.VerifyRefreshToken(ctx, oldToken)
	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	tokenKey := "rotated:" + oldToken

	exists, err := maker.redisClient.Exists(ctx, tokenKey).Result()
	if err != nil {
		return nil, fmt.Errorf("redis error: %w", err)
	}

	if exists == 1 {
		return nil, fmt.Errorf("token reused too soon")
	}

	newToken, err := maker.CreateRefreshToken(ctx, claims.Subject, claims.Username, claims.SessionID)
	if err != nil {
		return nil, err
	}

	err = maker.redisClient.Set(ctx, tokenKey, "1", maker.config.RefreshToken.MaxLifetime).Err()
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

			for _, prefix := range []string{"revoked:access:", "revoked:refresh:"} {
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

	return nil
}

func toMapClaims(claims interface{}) jwt.MapClaims {
	switch v := claims.(type) {
	case AccessTokenClaims:
		if len(v.Roles) == 0 {
			panic("at least one role must be provided")
		}
		return jwt.MapClaims{
			"jti": v.ID.String(),
			"sub": v.Subject.String(),
			"usr": v.Username,
			"sid": v.SessionID.String(),
			"iat": v.IssuedAt.Unix(),
			"exp": v.ExpiresAt.Unix(),
			"typ": string(v.TokenType),
			"rls": v.Roles,
		}
	case RefreshTokenClaims:
		return jwt.MapClaims{
			"jti": v.ID.String(),
			"sub": v.Subject.String(),
			"usr": v.Username,
			"sid": v.SessionID.String(),
			"iat": v.IssuedAt.Unix(),
			"exp": v.ExpiresAt.Unix(),
			"typ": string(v.TokenType),
		}
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
	if iat == 0 || exp == 0 {
		return nil, fmt.Errorf("invalid timestamp format")
	}

	return &AccessTokenClaims{
		ID:        tokenID,
		Subject:   userID,
		Username:  username,
		SessionID: sessionID,
		IssuedAt:  time.Unix(iat, 0),
		ExpiresAt: time.Unix(exp, 0),
		TokenType: TokenType(typ),
		Roles:     roles,
	}, nil
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

	return &RefreshTokenClaims{
		ID:        tokenID,
		Subject:   userID,
		Username:  username,
		SessionID: sessionID,
		IssuedAt:  time.Unix(getUnixTime(claims["iat"]), 0),
		ExpiresAt: time.Unix(getUnixTime(claims["exp"]), 0),
		TokenType: TokenType(claims["typ"].(string)),
	}, nil
}

func validateTokenClaims(claims jwt.MapClaims, expectedType TokenType) error {
	requiredClaims := []string{"jti", "sub", "typ", "usr", "sid", "iat", "exp"}
	if expectedType == AccessToken {
		requiredClaims = append(requiredClaims, "rls")
	}

	for _, claim := range requiredClaims {
		if _, ok := claims[claim]; !ok {
			return fmt.Errorf("missing required claim: %s", claim)
		}
	}

	tokenType, ok := claims["typ"].(string)
	if !ok || TokenType(tokenType) != expectedType {
		return fmt.Errorf("invalid token type: expected %s", expectedType)
	}

	exp, ok := claims["exp"].(float64)
	if !ok {
		return fmt.Errorf("invalid exp claim type")
	}
	if time.Unix(int64(exp), 0).Before(time.Now()) {
		return fmt.Errorf("token has expired")
	}

	if iat, ok := claims["iat"].(float64); ok {
		if time.Unix(int64(iat), 0).After(time.Now()) {
			return fmt.Errorf("token issued in the future")
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
