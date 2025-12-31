-- Postgres init for local dev.
--
-- This file is mounted into `/docker-entrypoint-initdb.d/` (so it runs on first init),
-- and also executed explicitly by the `just postgres` recipe (so it's safe to re-run).
--
-- `CREATE DATABASE` can't run inside a transaction block, so we use `psql`'s `\gexec` to
-- conditionally emit and execute the statement.

-- Guard against concurrent init runs (entrypoint + `just postgres`).
SELECT pg_advisory_lock(hashtext('permesi-initdb'));

SELECT format('CREATE DATABASE %I', 'genesis')
WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'genesis')\gexec

SELECT format('CREATE DATABASE %I', 'permesi')
WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'permesi')\gexec

SELECT pg_advisory_unlock(hashtext('permesi-initdb'));

-- Bootstrap genesis schema (idempotent, safe to re-run).
\connect genesis
\ir /db/sql/01_genesis.sql

-- Bootstrap permesi schema.
\connect permesi
\ir /db/sql/02_permesi.sql
