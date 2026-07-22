// File: internal/postgresdb/querier.go

// versions:
//   sqlc v1.31.1

package postgresdb

import (
	"context"

	"github.com/jackc/pgx/v5/pgtype"
)

type Querier interface {
	CountAllRevokedTokens(ctx context.Context) (int64, error)
	CountRevokedToken(ctx context.Context, arg CountRevokedTokenParams) (int64, error)
	CountRevokedTokensByType(ctx context.Context, tokenType string) (int64, error)
	CountRotatedToken(ctx context.Context, arg CountRotatedTokenParams) (int64, error)
	CountRotatedTokens(ctx context.Context) (int64, error)
	DeleteExpiredRevokedTokens(ctx context.Context, arg DeleteExpiredRevokedTokensParams) (int64, error)
	DeleteExpiredRotatedTokens(ctx context.Context, expiresAt pgtype.Timestamptz) (int64, error)
	GetRotatedTokenExpiresAt(ctx context.Context, tokenHash string) (pgtype.Timestamptz, error)
	InsertRotatedTokenIfNotExists(ctx context.Context, arg InsertRotatedTokenIfNotExistsParams) (int64, error)
	// File: internal/postgresdb/queries/tokens.sql
	UpsertRevokedToken(ctx context.Context, arg UpsertRevokedTokenParams) error
	UpsertRotatedToken(ctx context.Context, arg UpsertRotatedTokenParams) error
}

var _ Querier = (*Queries)(nil)
