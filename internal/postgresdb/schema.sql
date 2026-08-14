-- File: internal/postgresdb/schema.sql
--
-- Schema for gourdiantoken's PostgreSQL-backed token repository. Returned as
-- text by PostgresSchemaSQL() (gourdiantoken.repository.postgres.imp.go) for
-- the consuming application to apply through its own project's migration
-- tool (golang-migrate, Flyway, a plain SQL file in CI, ...) -- gourdiantoken
-- itself never applies this; NewPostgresTokenRepository assumes it already
-- exists. CREATE TABLE IF NOT EXISTS is used so applying it more than once
-- (e.g. re-running your own migration) is harmless, but that alone does not
-- remove the need for a CREATE-capable role to run it at least once -- see
-- docs/postgres.md for the least-privilege-runtime-role rationale and the
-- full pattern.
--
-- BREAKING (v2.2.0): table names are prefixed with gourdiantoken_, replacing
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

-- Bulk tenant revocation (see GourdianTokenMaker.RevokeTenant): one row per tenant, holding
-- the moment it was last revoked. tenant_id is the primary key directly (not hashed, unlike
-- token_hash above) since tenant IDs aren't secrets the way tokens are, and a tenant can
-- only ever have one active revocation epoch at a time — a newer RevokeTenant call
-- overwrites the row rather than adding another.
CREATE TABLE IF NOT EXISTS gourdiantoken_tenant_revocations (
    tenant_id  VARCHAR(255) PRIMARY KEY,
    revoked_at TIMESTAMPTZ  NOT NULL,
    expires_at TIMESTAMPTZ  NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_gourdiantoken_tenant_revocations_expires_at ON gourdiantoken_tenant_revocations (expires_at);
