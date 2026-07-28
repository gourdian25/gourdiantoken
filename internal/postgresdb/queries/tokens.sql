-- File: internal/postgresdb/queries/tokens.sql

-- name: UpsertRevokedToken :exec
INSERT INTO gourdiantoken_revoked_tokens (token_hash, token_type, expires_at, created_at)
VALUES ($1, $2, $3, $4)
ON CONFLICT (token_hash, token_type) DO UPDATE SET expires_at = EXCLUDED.expires_at;

-- name: CountRevokedToken :one
SELECT COUNT(*) FROM gourdiantoken_revoked_tokens
WHERE token_hash = $1 AND token_type = $2 AND expires_at > $3;

-- name: UpsertRotatedToken :exec
INSERT INTO gourdiantoken_rotated_tokens (token_hash, expires_at, created_at)
VALUES ($1, $2, $3)
ON CONFLICT (token_hash) DO UPDATE SET expires_at = EXCLUDED.expires_at;

-- name: InsertRotatedTokenIfNotExists :execrows
INSERT INTO gourdiantoken_rotated_tokens (token_hash, expires_at, created_at)
VALUES ($1, $2, $3)
ON CONFLICT (token_hash) DO NOTHING;

-- name: CountRotatedToken :one
SELECT COUNT(*) FROM gourdiantoken_rotated_tokens
WHERE token_hash = $1 AND expires_at > $2;

-- name: GetRotatedTokenExpiresAt :one
SELECT expires_at FROM gourdiantoken_rotated_tokens WHERE token_hash = $1;

-- name: DeleteExpiredRevokedTokens :execrows
DELETE FROM gourdiantoken_revoked_tokens WHERE token_type = $1 AND expires_at <= $2;

-- name: DeleteExpiredRotatedTokens :execrows
DELETE FROM gourdiantoken_rotated_tokens WHERE expires_at <= $1;

-- name: CountAllRevokedTokens :one
SELECT COUNT(*) FROM gourdiantoken_revoked_tokens;

-- name: CountRevokedTokensByType :one
SELECT COUNT(*) FROM gourdiantoken_revoked_tokens WHERE token_type = $1;

-- name: CountRotatedTokens :one
SELECT COUNT(*) FROM gourdiantoken_rotated_tokens;

-- name: UpsertTenantRevocation :exec
INSERT INTO gourdiantoken_tenant_revocations (tenant_id, revoked_at, expires_at)
VALUES ($1, $2, $3)
ON CONFLICT (tenant_id) DO UPDATE SET revoked_at = EXCLUDED.revoked_at, expires_at = EXCLUDED.expires_at;

-- name: GetTenantRevocationEpoch :one
SELECT revoked_at FROM gourdiantoken_tenant_revocations
WHERE tenant_id = $1 AND expires_at > $2;

-- name: DeleteExpiredTenantRevocations :execrows
DELETE FROM gourdiantoken_tenant_revocations WHERE expires_at <= $1;

-- name: CountTenantRevocations :one
SELECT COUNT(*) FROM gourdiantoken_tenant_revocations;
