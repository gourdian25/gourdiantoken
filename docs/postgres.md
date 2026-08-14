# Using gourdiantoken's Postgres-backed TokenRepository in a backend

This is the pattern for wiring `NewPostgresTokenRepository`/
`NewGourdianTokenMakerWithPostgres` into a real backend service: how to
share one connection pool with the rest of your application, and how to
get the schema in place before you do — gourdiantoken never applies its
own schema at runtime. It mirrors [grnoti's own `docs/postgres.md`](../../grnoti/docs/postgres.md)
in spirit (sharing one pool, being explicit about schema ownership)
though the mechanism differs — see "Why no auto-apply" below.

## Sharing one pool

`NewPostgresTokenRepository`/`NewGourdianTokenMakerWithPostgres` both take
an already-constructed `*pgxpool.Pool` rather than dialing their own —
build it once in your own bootstrap code and hand the same pool to
gourdiantoken and the rest of your backend:

```go
pool, err := pgxpool.New(ctx, dsn)
if err != nil {
    log.Fatal(err)
}
defer pool.Close() // your backend owns this pool -- gourdiantoken never closes it

maker, err := gourdiantoken.NewGourdianTokenMakerWithPostgres(ctx, config, pool)
```

gourdiantoken never calls `pool.Close()` itself; closing it is entirely
your backend's job, typically once at shutdown after everything using it
is done.

## Applying the schema — required, and always your job

Neither `NewPostgresTokenRepository` nor `NewGourdianTokenMakerWithPostgres`
ever runs `CREATE TABLE`/`CREATE INDEX` — gourdiantoken has no migration
tool of its own and doesn't try to be one. The 3 tables it queries
(`gourdiantoken_revoked_tokens`, `gourdiantoken_rotated_tokens`,
`gourdiantoken_tenant_revocations`) must already exist before you
construct either of these, or every real repository call
(`MarkTokenRevoke`, `IsTokenRevoked`, ...) fails with a plain Postgres
"relation does not exist" error — construction itself still succeeds,
since it only pings the pool.

Call `PostgresSchemaSQL()` to get the exact schema as text, and apply it
through whatever migration tool your own project already uses:

```go
fmt.Println(gourdiantoken.PostgresSchemaSQL())
```

Paste that into a new migration file (golang-migrate, Flyway, a plain
`.sql` file run once in CI, whatever you already have) and run it with
your project's normal migration process, once, before your application
first connects.

### Why no auto-apply

An earlier iteration of this package had `NewPostgresTokenRepository`
apply its schema automatically on every connect. That works fine as long
as the pool's connection role has `CREATE` on the target schema — but a
common, deliberate production setup is the opposite: one Postgres role
owns migrations (`CREATE`/`ALTER`/`DROP`), while the application's own
runtime connection uses a separate, least-privilege role with only
`SELECT`/`INSERT`/`UPDATE`/`DELETE` on already-existing tables. Against a
role like that, auto-apply fails loudly at construction with `permission
denied for schema ...` — and pre-creating the tables through some other
path doesn't help, either, since `CREATE TABLE IF NOT EXISTS` still checks
`CREATE` privilege before checking whether the table exists, so the
attempt itself fails every time, not just the first.

Rather than add a flag to opt out of that default, gourdiantoken simply
never does it: you always apply the schema yourself, through your own
project's existing migration pipeline, with whatever role already owns
that pipeline. This keeps gourdiantoken's runtime connection requirements
identical regardless of how your application's own roles are set up, and
means there's exactly one way this works, not a default plus an
exception to remember.

### What `PostgresSchemaSQL()` does *not* do

It only ever adds (`CREATE ... IF NOT EXISTS`). There's no
down-migration, no versioning, and no support for evolving the schema
beyond that — an `ALTER TABLE`, a column type change, or a backfill is
entirely your own migration tool's responsibility. If you upgrade
gourdiantoken and its schema changes, `CHANGELOG.md` documents it; re-sync
your vendored copy by hand the same way you'd pick up any other
dependency's breaking schema change.

## Table names

`gourdiantoken_revoked_tokens`, `gourdiantoken_rotated_tokens`,
`gourdiantoken_tenant_revocations` — all `gourdiantoken_`-prefixed, so
they won't collide with your own application's tables.
