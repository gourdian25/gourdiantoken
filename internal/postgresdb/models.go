// File: internal/postgresdb/models.go

// versions:
//   sqlc v1.31.1

package postgresdb

import (
	"github.com/jackc/pgx/v5/pgtype"
)

type GourdiantokenRevokedToken struct {
	ID        int64              `db:"id" json:"id"`
	TokenHash string             `db:"token_hash" json:"token_hash"`
	TokenType string             `db:"token_type" json:"token_type"`
	ExpiresAt pgtype.Timestamptz `db:"expires_at" json:"expires_at"`
	CreatedAt pgtype.Timestamptz `db:"created_at" json:"created_at"`
}

type GourdiantokenRotatedToken struct {
	ID        int64              `db:"id" json:"id"`
	TokenHash string             `db:"token_hash" json:"token_hash"`
	ExpiresAt pgtype.Timestamptz `db:"expires_at" json:"expires_at"`
	CreatedAt pgtype.Timestamptz `db:"created_at" json:"created_at"`
}
