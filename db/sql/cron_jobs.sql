-- Centralized pg_cron scheduler for Permesi IAM.
--
-- Run this as a superuser against the `postgres` database after schemas exist.
-- It registers jobs that execute in the target databases using pg_cron.
--
--   psql "postgres://<admin>@<host>:5432/postgres" -v ON_ERROR_STOP=1 -f db/sql/cron_jobs.sql
--
-- Requirements:
--   - cron.database_name = 'postgres'
--   - pg_cron installed and listed in shared_preload_libraries
--   - genesis/permesi databases and vault_* roles already created
--
-- Authentication for Vault-Managed Users (Critical):
--   These cron jobs run as `vault_genesis` and `vault_permesi`. Because Vault can
--   rotate passwords for these roles (either automatically in Vault Enterprise or
--   manually via API), `pg_cron` cannot safely use password authentication.
--   Instead, it must use `peer` authentication over the local socket, mapping the
--   internal system user (usually `postgres`) to the target Vault roles.
--
--   Manual Rotation Command (for reference):
--     vault write -f database/rotate-root/permesi
--     vault write -f database/rotate-root/genesis
--
--   1. Update `pg_ident.conf` (User Name Maps):
--      # MAPNAME   SYSTEM-USERNAME   PG-USERNAME
--      cronmap     postgres          vault_genesis
--      cronmap     postgres          vault_permesi
--
--   2. Update `pg_hba.conf` (Host-Based Authentication):
--      Insert these lines *before* generic local rules:
--      # TYPE  DATABASE  USER            ADDRESS  METHOD  OPTIONS
--      local   genesis   vault_genesis            peer    map=cronmap
--      local   permesi   vault_permesi            peer    map=cronmap
--
--   3. Reload configuration:
--      SELECT pg_reload_conf();

\set ON_ERROR_STOP 1

DO $$
DECLARE
    cron_ns oid;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_available_extensions WHERE name = 'pg_cron') THEN
        RAISE EXCEPTION 'pg_cron extension is not installed';
    END IF;

    IF position(
        'pg_cron' IN coalesce(current_setting('shared_preload_libraries', true), '')
    ) = 0 THEN
        RAISE EXCEPTION 'pg_cron must be preloaded via shared_preload_libraries';
    END IF;

    CREATE EXTENSION IF NOT EXISTS pg_cron;

    SELECT oid INTO cron_ns
    FROM pg_namespace
    WHERE nspname = 'cron';

    IF NOT EXISTS (
        SELECT 1
        FROM pg_proc
        WHERE proname = 'schedule_in_database'
          AND pronamespace = cron_ns
    ) THEN
        RAISE EXCEPTION 'pg_cron schedule_in_database is unavailable; upgrade pg_cron';
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'genesis') THEN
        RAISE EXCEPTION 'genesis database is missing';
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'permesi') THEN
        RAISE EXCEPTION 'permesi database is missing';
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vault_genesis') THEN
        RAISE EXCEPTION 'vault_genesis role is missing';
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vault_permesi') THEN
        RAISE EXCEPTION 'vault_permesi role is missing';
    END IF;

    IF NOT EXISTS (SELECT 1 FROM cron.job WHERE jobname = 'genesis_tokens_rollover') THEN
        PERFORM cron.schedule_in_database(
            'genesis_tokens_rollover',
            '5 0 * * *',
            $cron$SELECT genesis_tokens_rollover(7, 2);$cron$,
            'genesis',
            'vault_genesis'
        );
    END IF;

    IF NOT EXISTS (SELECT 1 FROM cron.job WHERE jobname = 'permesi_cleanup_expired_tokens') THEN
        PERFORM cron.schedule_in_database(
            'permesi_cleanup_expired_tokens',
            '15 0 * * *',
            $cron$SELECT cleanup_expired_tokens();$cron$,
            'permesi',
            'vault_permesi'
        );
    END IF;
END;
$$;
