-- Genesis schema bootstrap.
-- Requires PostgreSQL 18+ for uuidv7().
-- Idempotent: safe to run multiple times.

CREATE TABLE IF NOT EXISTS clients (
    id SMALLINT PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    name text NOT NULL,
    uuid UUID DEFAULT uuidv7() UNIQUE,
    is_reserved boolean NOT NULL DEFAULT true
);

-- Optional test-only seed client lives in `seed_test_client.sql`.

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
