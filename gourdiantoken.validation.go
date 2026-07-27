// File: gourdiantoken.validation.go

package gourdiantoken

import (
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
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

	// Gated entirely by VerificationTokensEnabled: every config that predates this field
	// (where it defaults to false) skips this block and validates exactly as before.
	if config.VerificationTokensEnabled {
		if config.VerificationDefaultExpiryDuration <= 0 {
			return fmt.Errorf("verification token default expiry duration must be positive")
		}
		if config.VerificationMaxExpiryDuration > 0 &&
			config.VerificationDefaultExpiryDuration > config.VerificationMaxExpiryDuration {
			return fmt.Errorf("verification token default expiry duration exceeds max expiry duration")
		}
		for _, uc := range config.VerificationAllowedUseCases {
			if uc == "" {
				return fmt.Errorf("verification allowed use cases cannot contain empty strings")
			}
		}
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
			"jti": v.ID,
			"sub": v.Subject,
			"usr": v.Username,
			"sid": v.SessionID,
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
		if v.TenantID != "" {
			mapClaims["tid"] = v.TenantID
		}
		return mapClaims, nil
	case RefreshTokenClaims:
		mapClaims := jwt.MapClaims{
			"jti": v.ID,
			"sub": v.Subject,
			"usr": v.Username,
			"sid": v.SessionID,
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
		if v.TenantID != "" {
			mapClaims["tid"] = v.TenantID
		}
		return mapClaims, nil
	case VerificationTokenClaims:
		// sid/usr are emitted as empty-string placeholders (VerificationTokenClaims has no
		// session or username concept) solely so extractCommonClaims/validateTokenClaims,
		// which unconditionally type-assert these two keys for every token type, keep working
		// unchanged for this new type too.
		mapClaims := jwt.MapClaims{
			"jti": v.ID,
			"sub": v.Subject,
			"usr": "",
			"sid": "",
			"uc":  v.UseCase,
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
		if len(v.Metadata) > 0 {
			mapClaims["mtd"] = v.Metadata
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
	ID                string
	Subject           string
	SessionID         string
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
// pattern throughout. jti and sub must be non-empty strings; sid must be a string but
// may be empty (sessionless tokens). This also tightens the "iss" claim to require a string type,
// consistent with how jti/sub/sid are already handled (previously issuer silently
// became "" via an unchecked type assertion instead of erroring on a bad claim).
func extractCommonClaims(claims jwt.MapClaims) (*commonClaims, error) {
	tokenID, ok := claims["jti"].(string)
	if !ok {
		return nil, fmt.Errorf("invalid token ID type: expected string")
	}
	if tokenID == "" {
		return nil, fmt.Errorf("invalid token ID: cannot be empty")
	}

	userID, ok := claims["sub"].(string)
	if !ok {
		return nil, fmt.Errorf("invalid user ID type: expected string")
	}
	if userID == "" {
		return nil, fmt.Errorf("invalid user ID: cannot be empty")
	}

	// sid may be empty: an empty session ID is valid for sessionless tokens,
	// mirroring the creation-side contract (only the type is enforced).
	sessionID, ok := claims["sid"].(string)
	if !ok {
		return nil, fmt.Errorf("invalid session ID type: expected string")
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
//   - Unix timestamps → time.Time
//   - String token type → TokenType
//   - Interface arrays → string arrays
//
// Validation:
//   - jti and sub must be non-empty strings (sid may be empty)
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

	// tid is not part of baseRequired (only mandatory when the maker's config has
	// MultiTenantEnabled true, enforced upstream in parseAndValidateToken), so an absent
	// tid claim is not an error here — only a present-but-wrong-typed one is. Mirrors how
	// extractCommonClaims already treats the optional "iss" claim.
	var tenantID string
	if raw, present := claims["tid"]; present {
		tenantID, ok = raw.(string)
		if !ok {
			return nil, fmt.Errorf("invalid tenant ID type: expected string")
		}
	}

	accessClaims := &AccessTokenClaims{
		ID:                common.ID,
		Subject:           common.Subject,
		Username:          common.Username,
		SessionID:         common.SessionID,
		TenantID:          tenantID,
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
//   - Unix timestamps → time.Time
//   - String token type → TokenType
//   - Interface arrays → string arrays
//
// Validation:
//   - jti and sub must be non-empty strings (sid may be empty)
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

	// tid is optional here for the same reason as in mapToAccessClaims — see that
	// function's comment.
	var tenantID string
	if raw, present := claims["tid"]; present {
		tenantID, ok = raw.(string)
		if !ok {
			return nil, fmt.Errorf("invalid tenant ID type: expected string")
		}
	}

	refreshClaims := &RefreshTokenClaims{
		ID:                common.ID,
		Subject:           common.Subject,
		Username:          common.Username,
		SessionID:         common.SessionID,
		TenantID:          tenantID,
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

// mapToVerificationClaims converts JWT MapClaims to strongly-typed VerificationTokenClaims.
// Performs type checking and validation of all fields.
//
// Validation:
//   - jti and sub must be non-empty strings
//   - uc (use case) must be a non-empty string
//   - Token type must be "verification"
//   - Timestamps must be valid numbers
//
// Notes:
//   - Used internally during verification token verification
//   - common.SessionID/common.Username are discarded: VerificationTokenClaims has no
//     session or username concept (those keys only exist in the map as placeholders,
//     see toMapClaims)
func mapToVerificationClaims(claims jwt.MapClaims) (*VerificationTokenClaims, error) {
	common, err := extractCommonClaims(claims)
	if err != nil {
		return nil, err
	}

	typ, ok := claims["typ"].(string)
	if !ok {
		return nil, fmt.Errorf("invalid or missing token type")
	}

	if TokenType(typ) != VerificationToken {
		return nil, fmt.Errorf("invalid token type: expected 'verification'")
	}

	useCase, ok := claims["uc"].(string)
	if !ok {
		return nil, fmt.Errorf("invalid use case type: expected string")
	}
	if useCase == "" {
		return nil, fmt.Errorf("invalid use case: cannot be empty")
	}

	var metadata map[string]interface{}
	if raw, present := claims["mtd"]; present {
		metadata, ok = raw.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("invalid metadata type: expected object")
		}
	}

	verificationClaims := &VerificationTokenClaims{
		ID:                common.ID,
		Subject:           common.Subject,
		UseCase:           useCase,
		Issuer:            common.Issuer,
		Audience:          common.Audience,
		IssuedAt:          common.IssuedAt,
		ExpiresAt:         common.ExpiresAt,
		NotBefore:         common.NotBefore,
		MaxLifetimeExpiry: common.MaxLifetimeExpiry,
		Metadata:          metadata,
		TokenType:         TokenType(typ),
	}

	return verificationClaims, nil
}

// validateUseCase checks useCase against allowed. An empty allowed list means any
// non-empty use case is accepted, mirroring the AllowedAlgorithms "empty means
// unrestricted" convention. Shared by CreateVerificationToken and VerifyVerificationToken
// so the whitelist-membership check has a single implementation.
func validateUseCase(allowed []string, useCase string) error {
	if useCase == "" {
		return fmt.Errorf("use case cannot be empty")
	}
	if len(allowed) == 0 {
		return nil
	}
	for _, a := range allowed {
		if a == useCase {
			return nil
		}
	}
	return fmt.Errorf("use case %q is not in the allowed list", useCase)
}

// validateTenantID enforces GourdianTokenConfig.MultiTenantEnabled against a tenantID
// supplied to CreateAccessToken/CreateRefreshToken: required and non-empty when true,
// forbidden (must be empty) when false. Fails loud in both directions rather than
// silently ignoring a caller-supplied tenant ID — the one thing this whole feature exists
// to prevent.
func validateTenantID(multiTenantEnabled bool, tenantID string) error {
	if multiTenantEnabled {
		if tenantID == "" {
			return fmt.Errorf("%w", ErrTenantIDRequired)
		}
		return nil
	}
	if tenantID != "" {
		return fmt.Errorf("%w", ErrTenantIDNotAllowed)
	}
	return nil
}

// resolveVerificationTTL determines the effective expiry duration for a verification
// token being created. A non-positive requested duration falls back to
// config.VerificationDefaultExpiryDuration. A requested duration exceeding
// config.VerificationMaxExpiryDuration (when a ceiling is configured) is rejected outright
// rather than silently clamped, consistent with this codebase's fail-loud validation style.
func resolveVerificationTTL(config *GourdianTokenConfig, requested time.Duration) (time.Duration, error) {
	if requested <= 0 {
		return config.VerificationDefaultExpiryDuration, nil
	}
	if config.VerificationMaxExpiryDuration > 0 && requested > config.VerificationMaxExpiryDuration {
		return 0, fmt.Errorf("requested ttl %s exceeds maximum allowed %s", requested, config.VerificationMaxExpiryDuration)
	}
	return requested, nil
}

// validateTokenClaims performs comprehensive validation of JWT claims.
// Checks required claims, timestamps, token type, and identifier claims.
//
// Validation Checks:
//   - All required claims are present (base + custom)
//   - jti and sub are non-empty strings; sid is a string (may be empty)
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
//   - "invalid user ID: cannot be empty"
func validateTokenClaims(claims jwt.MapClaims, expectedType TokenType, required []string) error {
	baseRequired := map[TokenType][]string{
		AccessToken:       {"jti", "sub", "sid", "usr", "iat", "exp", "typ", "rls"},
		RefreshToken:      {"jti", "sub", "sid", "usr", "iat", "exp", "typ"},
		VerificationToken: {"jti", "sub", "iat", "exp", "typ", "uc"},
	}

	for _, claim := range append(baseRequired[expectedType], required...) {
		if _, ok := claims[claim]; !ok {
			return fmt.Errorf("missing required claim: %s", claim)
		}
	}

	if jti, ok := claims["jti"].(string); !ok {
		return fmt.Errorf("invalid token ID type: expected string")
	} else if jti == "" {
		return fmt.Errorf("invalid token ID: cannot be empty")
	}

	if sub, ok := claims["sub"].(string); !ok {
		return fmt.Errorf("invalid user ID type: expected string")
	} else if sub == "" {
		return fmt.Errorf("invalid user ID: cannot be empty")
	}

	// sid may be empty (sessionless tokens) — only the type is enforced,
	// mirroring extractCommonClaims and the creation-side contract.
	if _, ok := claims["sid"].(string); !ok {
		return fmt.Errorf("invalid session ID type: expected string")
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
