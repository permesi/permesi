# Database SQL helpers

`db/sql/` is the single source of truth for Permesi IAM database schemas and bootstrap helpers.

## Bootstrapping

- `00_init.sql` — creates databases, roles, grants, and loads service schemas.
- `01_genesis.sql` — Genesis schema (includes `partitioning.sql`).
- `02_permesi.sql` — Permesi schema (includes `cleanup_expired_tokens()`).
- `seed_test_client.sql` — optional test-only seed client for Genesis.
- `cron_jobs.sql` — **only place** where pg_cron jobs are registered (run against `postgres`).
- `check.sql` — post-bootstrap verification (run against `postgres`).
- `reset_all.sql` — destructive reset for dev/test (run against `postgres`).

## Runtime role & grant checks

Use these psql commands to verify runtime roles and grants after bootstrap:

```sql
-- roles + membership
\du+ vault_genesis
\du+ genesis_runtime
\du+ vault_permesi
\du+ permesi_runtime

-- database-level grants (run in postgres)
\l+ genesis
\l+ permesi

-- schema/table grants (genesis)
\c genesis
\dn+ public
\dp public.clients
\dp public.tokens
\dp public.tokens_default

-- schema/table grants (permesi)
\c permesi
\dn+ public
\dp public.users
\dp public.user_sessions
\dp public.email_outbox

-- default privileges (future tables)
\c genesis
SELECT * FROM pg_default_acl WHERE defaclnamespace = 'public'::regnamespace;
\c permesi
SELECT * FROM pg_default_acl WHERE defaclnamespace = 'public'::regnamespace;

-- programmatic checks (examples)
\c genesis
SELECT has_table_privilege('genesis_runtime', 'public.clients', 'SELECT') AS clients_select;
\c permesi
SELECT has_table_privilege('permesi_runtime', 'public.users', 'SELECT') AS users_select;
```
