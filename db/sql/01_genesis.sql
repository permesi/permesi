-- Genesis schema bootstrap for dev containers.
-- Requires PostgreSQL 18+ for uuidv7().
-- Idempotent: safe to run multiple times.

CREATE TABLE IF NOT EXISTS clients (
    id SMALLINT PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    name text NOT NULL,
    uuid UUID DEFAULT uuidv7() UNIQUE,
    is_reserved boolean NOT NULL DEFAULT true
);

-- Test-only seed client; remove/override for non-test deployments.
INSERT INTO clients (id, name, uuid, is_reserved)
OVERRIDING SYSTEM VALUE
VALUES (0, '__test_only__', '00000000-0000-0000-0000-000000000000', false)
ON CONFLICT (id) DO NOTHING;

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

-- Bootstrap partition; replace with time-based partitions in production.
CREATE TABLE IF NOT EXISTS tokens_default PARTITION OF tokens DEFAULT;

CREATE INDEX IF NOT EXISTS idx_tokens_country ON tokens(country);
CREATE INDEX IF NOT EXISTS idx_tokens_ip ON tokens(ip_address);

-- Optional: schedule partition maintenance if pg_cron is available.
\ir /db/sql/partitioning.sql
