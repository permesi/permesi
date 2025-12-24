-- Postgres init for local dev.
--
-- This file is mounted into `/docker-entrypoint-initdb.d/` (so it runs on first init),
-- and also executed explicitly by the `just postgres` recipe (so it's safe to re-run).
--
-- `CREATE DATABASE` can't run inside a transaction block, so we use `psql`'s `\gexec` to
-- conditionally emit and execute the statement.

SELECT format('CREATE DATABASE %I', 'genesis')
WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'genesis')\gexec

SELECT format('CREATE DATABASE %I', 'permesi')
WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'permesi')\gexec

-- Bootstrap genesis schema (idempotent, safe to re-run).
\connect genesis
\ir /db/sql/01_genesis.sql
