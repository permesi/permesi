-- Genesis schema bootstrap.
-- Requires PostgreSQL 18+ for uuidv7().
-- Idempotent: safe to run multiple times.

CREATE TABLE IF NOT EXISTS clients (
    id SMALLINT PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    name text NOT NULL,
    uuid UUID DEFAULT uuidv7() UNIQUE,
    is_reserved boolean NOT NULL DEFAULT true
);

CREATE TABLE IF NOT EXISTS tokens (
    id UUID NOT NULL DEFAULT uuidv7(),
    client_id SMALLINT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    ip_address INET,
    country CHAR(2),
    user_agent text,
    metadata JSONB,
    PRIMARY KEY (id, created_at)
) PARTITION BY RANGE (created_at);

-- Bootstrap partition; remove once partition maintenance is active.
-- Keeping this long-term will accumulate rows outside retention.
CREATE TABLE IF NOT EXISTS tokens_default PARTITION OF tokens DEFAULT;

CREATE INDEX IF NOT EXISTS idx_tokens_country ON tokens(country);
CREATE INDEX IF NOT EXISTS idx_tokens_ip ON tokens(ip_address);

-- Optional: schedule partition maintenance if pg_cron is available.
\ir partitioning.sql

-- Runtime identities can read configuration and append admission receipts via the
-- partitioned parent. Future tables receive no implicit runtime write authority.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='genesis_runtime') THEN
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='genesis_runtime'
            AND (rolsuper OR rolcreaterole OR rolcreatedb OR rolreplication OR rolbypassrls OR rolcanlogin))
            OR EXISTS (SELECT 1 FROM pg_auth_members WHERE member='genesis_runtime'::regrole) THEN
            RAISE EXCEPTION 'Runtime role has unexpected attributes or role memberships';
        END IF;
        REVOKE ALL ON ALL TABLES IN SCHEMA public FROM genesis_runtime, PUBLIC;
        REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM genesis_runtime, PUBLIC;
        REVOKE CREATE ON SCHEMA public FROM genesis_runtime, PUBLIC;
        GRANT USAGE ON SCHEMA public TO genesis_runtime;
        EXECUTE format('REVOKE ALL ON DATABASE %I FROM genesis_runtime',current_database());
        EXECUTE format('GRANT CONNECT, TEMPORARY ON DATABASE %I TO genesis_runtime',current_database());
        GRANT SELECT ON clients TO genesis_runtime;
        GRANT SELECT, INSERT ON tokens,tokens_default TO genesis_runtime;
        ALTER DEFAULT PRIVILEGES REVOKE ALL ON TABLES FROM genesis_runtime, PUBLIC;
        ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON TABLES FROM genesis_runtime, PUBLIC;
        ALTER DEFAULT PRIVILEGES REVOKE ALL ON SEQUENCES FROM genesis_runtime, PUBLIC;
        ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON SEQUENCES FROM genesis_runtime, PUBLIC;
        ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
    END IF;
END $$;
