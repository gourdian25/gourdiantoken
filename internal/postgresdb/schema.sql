-- File: internal/postgresdb/schema.sql
--
-- Schema for gourdiantoken's PostgreSQL-backed token repository. Applied by
-- connectPostgres (gourdiantoken.repository.postgres.imp.go) on every
-- connect, serialized by a Postgres advisory lock (applyPostgresSchema) so
-- concurrent connects don't race on this DDL. CREATE TABLE IF NOT EXISTS is
-- sufficient for this library's one linear schema — there is no separate
-- migration tool.
--
-- BREAKING (v3.0.0): table names are prefixed with gourdiantoken_, replacing
-- the unprefixed revoked_tokens/rotated_tokens names used by the removed
-- GORM backend. This is a new table, not a rename in place — upgrading
-- deployments will not see their existing revocation/rotation state under
-- the new names. See CHANGELOG.md for the migration note.

CREATE TABLE IF NOT EXISTS gourdiantoken_revoked_tokens (
    id         BIGSERIAL PRIMARY KEY,
    token_hash VARCHAR(64)  NOT NULL,
    token_type VARCHAR(20)  NOT NULL,
    expires_at TIMESTAMPTZ  NOT NULL,
    created_at TIMESTAMPTZ  NOT NULL,
    UNIQUE (token_hash, token_type)
);
CREATE INDEX IF NOT EXISTS idx_gourdiantoken_revoked_token_type ON gourdiantoken_revoked_tokens (token_type);
CREATE INDEX IF NOT EXISTS idx_gourdiantoken_revoked_expires_at ON gourdiantoken_revoked_tokens (expires_at);

CREATE TABLE IF NOT EXISTS gourdiantoken_rotated_tokens (
    id         BIGSERIAL PRIMARY KEY,
    token_hash VARCHAR(64)  NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ  NOT NULL,
    created_at TIMESTAMPTZ  NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_gourdiantoken_rotated_expires_at ON gourdiantoken_rotated_tokens (expires_at);
