// File: gourdiantoken.validation.go

package gourdiantoken

import (
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// validateConfig performs comprehensive validation of the token maker configuration.
// Checks all parameters for security, consistency, and logical correctness.
//
// Validation Checks:
//   - Signing method compatibility (symmetric vs asymmetric)
//   - Algorithm matches signing method
//   - Required parameters are provided
//   - Key/file paths are correct for signing method
//   - Duration values are positive and logical
//   - File permissions are secure (0600 for private keys)
//   - Algorithms are not weak (rejects "none")
//   - Cleanup interval is reasonable (>= 1 minute)
//
// Symmetric Signing Validation:
//   - SymmetricKey must be provided and >= 32 bytes
//   - Algorithm must be HS256, HS384, or HS512
//   - Private/public key paths must be empty
//
// Asymmetric Signing Validation:
//   - PrivateKeyPath and PublicKeyPath must be provided
//   - Algorithm must be RS*, ES*, PS*, or EdDSA
//   - SymmetricKey must be empty
//   - Key files must exist with secure permissions
//
// Duration Validation:
//   - All durations must be positive
//   - AccessExpiryDuration <= AccessMaxLifetimeExpiry
//   - RefreshExpiryDuration <= RefreshMaxLifetimeExpiry
//   - CleanupInterval >= 1 minute
//
// Parameters:
//   - config: The configuration to validate
//
// Returns:
//   - error: Detailed error describing the validation failure, or nil if valid
//
// Notes:
//   - Called automatically during initialization
//   - Returns first validation error encountered
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
		if err := checkFilePermissions(config.PrivateKeyPath, 0600); err != nil {
			return fmt.Errorf("insecure private key file permissions: %w", err)
		}
		if err := checkFilePermissions(config.PublicKeyPath, 0600); err != nil {
			return fmt.Errorf("insecure public key file permissions: %w", err)
		}
	default:
		return fmt.Errorf("unsupported signing method: %s, supports %s and %s",
			config.SigningMethod, Symmetric, Asymmetric)
	}

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

	// Validate CleanupInterval
	if config.CleanupInterval <= 0 {
		return fmt.Errorf("cleanup interval must be positive (e.g., 1h, 30m)")
	}
	if config.CleanupInterval < 1*time.Minute {
		return fmt.Errorf("cleanup interval too short: minimum 1 minute recommended")
	}

	// Reject weak algorithms
	weakAlgorithms := map[string]bool{
		"HS256": false,
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

// validateAlgorithmAndMethod ensures the algorithm is compatible with the signing method.
// Prevents misconfigurations like using HS256 with asymmetric mode.
//
// Valid Combinations:
//   - Symmetric: HS256, HS384, HS512
//   - Asymmetric: RS256/384/512, ES256/384/512, PS256/384/512, EdDSA
//
// Parameters:
//   - config: The configuration to validate
//
// Returns:
//   - error: If algorithm and method are incompatible
//
// Example Errors:
//   - "algorithm HS256 not compatible with asymmetric signing"
//   - "algorithm RS256 not compatible with symmetric signing"
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

// toMapClaims converts strongly-typed claims structures to JWT MapClaims.
// Handles both AccessTokenClaims and RefreshTokenClaims.
//
// Conversions:
//   - UUIDs → strings
//   - Time → Unix timestamps (int64)
//   - TokenType → string
//   - Arrays remain as-is
//
// Optional Claims:
//   - NotBefore (nbf) only included if not zero
//   - MaxLifetimeExpiry (mle) only included if not zero
//
// Parameters:
//   - claims: Either AccessTokenClaims or RefreshTokenClaims
//
// Returns:
//   - jwt.MapClaims: Map suitable for JWT encoding
//
// Panics:
//   - If claims type is not AccessTokenClaims or RefreshTokenClaims
//   - If AccessTokenClaims has empty Roles array
//
// Notes:
//   - Used internally during token creation
//   - Should not be called directly by users
func toMapClaims(claims interface{}) (jwt.MapClaims, error) {
	switch v := claims.(type) {
	case AccessTokenClaims:
		if len(v.Roles) == 0 {
			return nil, fmt.Errorf("at least one role must be provided")
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
		return mapClaims, nil
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
		return mapClaims, nil
	default:
		return nil, fmt.Errorf("unsupported claims type: %T", claims)
	}
}

// commonClaims holds the claim fields shared by AccessTokenClaims and RefreshTokenClaims.
// TokenType is deliberately excluded: mapToAccessClaims and mapToRefreshClaims report
// different error text for a missing/invalid "typ" claim, so each caller extracts it itself.
type commonClaims struct {
	ID                uuid.UUID
	Subject           uuid.UUID
	SessionID         uuid.UUID
	Username          string
	Issuer            string
	Audience          []string
	IssuedAt          time.Time
	ExpiresAt         time.Time
	NotBefore         time.Time
	MaxLifetimeExpiry time.Time
}

// extractCommonClaims extracts and validates the jti/sub/sid/usr/iss/aud/timestamp
// fields common to both AccessTokenClaims and RefreshTokenClaims, using a safe checked
// pattern throughout. This also tightens the "iss" claim to require a string type,
// consistent with how jti/sub/sid are already handled (previously issuer silently
// became "" via an unchecked type assertion instead of erroring on a bad claim).
func extractCommonClaims(claims jwt.MapClaims) (*commonClaims, error) {
	jti, ok := claims["jti"].(string)
	if !ok {
		return nil, fmt.Errorf("invalid token ID type: expected string")
	}
	tokenID, err := uuid.Parse(jti)
	if err != nil {
		return nil, fmt.Errorf("invalid token ID: %w", err)
	}

	sub, ok := claims["sub"].(string)
	if !ok {
		return nil, fmt.Errorf("invalid user ID type: expected string")
	}
	userID, err := uuid.Parse(sub)
	if err != nil {
		return nil, fmt.Errorf("invalid user ID: %w", err)
	}

	sid, ok := claims["sid"].(string)
	if !ok {
		return nil, fmt.Errorf("invalid session ID type: expected string")
	}
	sessionID, err := uuid.Parse(sid)
	if err != nil {
		return nil, fmt.Errorf("invalid session ID: %w", err)
	}

	username, ok := claims["usr"].(string)
	if !ok {
		return nil, fmt.Errorf("invalid username type: expected string")
	}

	// iss is not part of baseRequired (it's only mandatory when the caller's config
	// lists it in RequiredClaims, enforced upstream by validateTokenClaims), so an
	// absent iss claim is not an error here — only a present-but-wrong-typed one is.
	var issuer string
	if rawIssuer, present := claims["iss"]; present {
		issuer, ok = rawIssuer.(string)
		if !ok {
			return nil, fmt.Errorf("invalid issuer type: expected string")
		}
	}

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

	iat := getUnixTime(claims["iat"])
	exp := getUnixTime(claims["exp"])
	nbf := getUnixTime(claims["nbf"])
	mle := getUnixTime(claims["mle"])

	if iat == 0 || exp == 0 {
		return nil, fmt.Errorf("invalid timestamp format")
	}

	common := &commonClaims{
		ID:        tokenID,
		Subject:   userID,
		SessionID: sessionID,
		Username:  username,
		Issuer:    issuer,
		Audience:  audience,
		IssuedAt:  time.Unix(iat, 0),
		ExpiresAt: time.Unix(exp, 0),
	}

	if nbf != 0 {
		common.NotBefore = time.Unix(nbf, 0)
	}

	if mle != 0 {
		common.MaxLifetimeExpiry = time.Unix(mle, 0)
	}

	return common, nil
}

// mapToAccessClaims converts JWT MapClaims to strongly-typed AccessTokenClaims.
// Performs type checking and validation of all fields.
//
// Conversions:
//   - String UUIDs → uuid.UUID
//   - Unix timestamps → time.Time
//   - String token type → TokenType
//   - Interface arrays → string arrays
//
// Validation:
//   - All UUIDs must be valid
//   - Roles must be non-empty array of strings
//   - Timestamps must be valid numbers
//   - Required fields must be present
//
// Parameters:
//   - claims: JWT MapClaims from parsed token
//
// Returns:
//   - *AccessTokenClaims: Strongly-typed claims structure
//   - error: If any field is invalid or missing
//
// Notes:
//   - Used internally during token verification
//   - Handles various JSON number types (float64, int, json.Number)
func mapToAccessClaims(claims jwt.MapClaims) (*AccessTokenClaims, error) {
	common, err := extractCommonClaims(claims)
	if err != nil {
		return nil, err
	}

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

	typ, ok := claims["typ"].(string)
	if !ok {
		return nil, fmt.Errorf("invalid token type: expected string")
	}

	accessClaims := &AccessTokenClaims{
		ID:                common.ID,
		Subject:           common.Subject,
		Username:          common.Username,
		SessionID:         common.SessionID,
		Issuer:            common.Issuer,
		Audience:          common.Audience,
		IssuedAt:          common.IssuedAt,
		ExpiresAt:         common.ExpiresAt,
		NotBefore:         common.NotBefore,
		MaxLifetimeExpiry: common.MaxLifetimeExpiry,
		TokenType:         TokenType(typ),
		Roles:             roles,
	}

	return accessClaims, nil
}

// mapToRefreshClaims converts JWT MapClaims to strongly-typed RefreshTokenClaims.
// Performs type checking and validation of all fields.
//
// Conversions:
//   - String UUIDs → uuid.UUID
//   - Unix timestamps → time.Time
//   - String token type → TokenType
//   - Interface arrays → string arrays
//
// Validation:
//   - All UUIDs must be valid
//   - Token type must be "refresh"
//   - Timestamps must be valid numbers
//   - Required fields must be present
//
// Parameters:
//   - claims: JWT MapClaims from parsed token
//
// Returns:
//   - *RefreshTokenClaims: Strongly-typed claims structure
//   - error: If any field is invalid or missing
//
// Notes:
//   - Used internally during token verification
//   - Does not include roles (refresh tokens don't have roles)
func mapToRefreshClaims(claims jwt.MapClaims) (*RefreshTokenClaims, error) {
	common, err := extractCommonClaims(claims)
	if err != nil {
		return nil, err
	}

	typ, ok := claims["typ"].(string)
	if !ok {
		return nil, fmt.Errorf("invalid or missing token type")
	}

	if TokenType(typ) != RefreshToken {
		return nil, fmt.Errorf("invalid token type: expected 'refresh'")
	}

	refreshClaims := &RefreshTokenClaims{
		ID:                common.ID,
		Subject:           common.Subject,
		Username:          common.Username,
		SessionID:         common.SessionID,
		Issuer:            common.Issuer,
		Audience:          common.Audience,
		IssuedAt:          common.IssuedAt,
		ExpiresAt:         common.ExpiresAt,
		NotBefore:         common.NotBefore,
		MaxLifetimeExpiry: common.MaxLifetimeExpiry,
		TokenType:         TokenType(typ),
	}

	return refreshClaims, nil
}

// validateTokenClaims performs comprehensive validation of JWT claims.
// Checks required claims, timestamps, token type, and UUID formats.
//
// Validation Checks:
//   - All required claims are present (base + custom)
//   - UUIDs (jti, sub, sid) are valid
//   - Token type matches expected type
//   - Token has not expired (exp > now)
//   - Token is not used before valid time (iat <= now)
//   - Token has not exceeded maximum lifetime (mle > now)
//
// Base Required Claims:
//   - Access tokens: jti, sub, sid, usr, iat, exp, typ, rls
//   - Refresh tokens: jti, sub, sid, usr, iat, exp, typ
//
// Parameters:
//   - claims: JWT MapClaims to validate
//   - expectedType: Expected token type (AccessToken or RefreshToken)
//   - required: Additional required claims beyond base requirements
//
// Returns:
//   - error: Detailed validation error, or nil if all checks pass
//
// Example Errors:
//   - "missing required claim: iss"
//   - "token has expired"
//   - "invalid token type: expected access"
//   - "invalid user ID format"
func validateTokenClaims(claims jwt.MapClaims, expectedType TokenType, required []string) error {
	baseRequired := map[TokenType][]string{
		AccessToken:  {"jti", "sub", "sid", "usr", "iat", "exp", "typ", "rls"},
		RefreshToken: {"jti", "sub", "sid", "usr", "iat", "exp", "typ"},
	}

	for _, claim := range append(baseRequired[expectedType], required...) {
		if _, ok := claims[claim]; !ok {
			return fmt.Errorf("missing required claim: %s", claim)
		}
	}

	if jti, ok := claims["jti"].(string); !ok {
		return fmt.Errorf("invalid token ID type: expected string")
	} else if _, err := uuid.Parse(jti); err != nil {
		return fmt.Errorf("invalid token ID format: %w", err)
	}

	if sub, ok := claims["sub"].(string); !ok {
		return fmt.Errorf("invalid user ID type: expected string")
	} else if _, err := uuid.Parse(sub); err != nil {
		return fmt.Errorf("invalid user ID format: %w", err)
	}

	if sid, ok := claims["sid"].(string); !ok {
		return fmt.Errorf("invalid session ID type: expected string")
	} else if _, err := uuid.Parse(sid); err != nil {
		return fmt.Errorf("invalid session ID format: %w", err)
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

	if mle, ok := claims["mle"].(float64); ok {
		maxExpiry := time.Unix(int64(mle), 0)
		if time.Now().After(maxExpiry) {
			return fmt.Errorf("%w", ErrTokenMaxLifetimeExceeded)
		}
	}

	return nil
}
