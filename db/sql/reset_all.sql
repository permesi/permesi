-- Reset script for local/dev/test environments.
--
-- WARNING: This destroys ALL data, schemas, and roles created by the Permesi
-- bootstrap scripts. It is not reversible.
--
-- Run as a Postgres superuser against the `postgres` database:
--   psql "postgres://<admin>@<host>:5432/postgres" -v ON_ERROR_STOP=1 -f db/sql/reset_all.sql
--
-- This will:
--   - Terminate active connections to the `genesis` and `permesi` databases.
--   - Drop the `genesis` and `permesi` databases.
--   - Drop the Vault root roles and runtime roles.

\set ON_ERROR_STOP 1

\echo 'Resetting Permesi databases and roles...'

SELECT pg_terminate_backend(pid)
FROM pg_stat_activity
WHERE datname IN ('genesis', 'permesi')
  AND pid <> pg_backend_pid();

SELECT format('DROP DATABASE %I', 'genesis')
WHERE EXISTS (SELECT 1 FROM pg_database WHERE datname = 'genesis')\gexec

SELECT format('DROP DATABASE %I', 'permesi')
WHERE EXISTS (SELECT 1 FROM pg_database WHERE datname = 'permesi')\gexec

SELECT format('DROP ROLE %I', 'genesis_runtime')
WHERE EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'genesis_runtime')\gexec

SELECT format('DROP ROLE %I', 'permesi_runtime')
WHERE EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'permesi_runtime')\gexec

SELECT format('DROP ROLE %I', 'vault_genesis')
WHERE EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vault_genesis')\gexec

SELECT format('DROP ROLE %I', 'vault_permesi')
WHERE EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vault_permesi')\gexec

\echo 'Reset complete.'
