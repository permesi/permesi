-- Permesi schema bootstrap for dev containers.
-- Keep in sync with services/permesi/sql/schema.sql.

DROP TABLE IF EXISTS email_outbox;
DROP TABLE IF EXISTS email_verification_tokens;
DROP TABLE IF EXISTS user_sessions;
DROP TABLE IF EXISTS users_metadata;
DROP TABLE IF EXISTS users_password_history;
DROP TABLE IF EXISTS users;
DROP TYPE IF EXISTS email_outbox_status;
DROP TYPE IF EXISTS user_status;

CREATE TYPE user_status AS ENUM ('pending_verification', 'active', 'disabled');
CREATE TYPE email_outbox_status AS ENUM ('pending', 'sent', 'failed');

CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email TEXT NOT NULL UNIQUE CHECK (email = LOWER(TRIM(email))) CHECK (email <> '') CHECK (char_length(email) <= 255),
    opaque_registration_record BYTEA NOT NULL,
    status user_status NOT NULL DEFAULT 'pending_verification',
    email_verified_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_users_status ON users (status);

CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    IF (NEW.email, NEW.opaque_registration_record, NEW.status, NEW.email_verified_at, NEW.created_at)
        IS DISTINCT FROM
       (OLD.email, OLD.opaque_registration_record, OLD.status, OLD.email_verified_at, OLD.created_at) THEN
        NEW.updated_at := NOW();
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS update_users_updated_at ON users;
CREATE TRIGGER update_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TABLE user_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_hash BYTEA NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX user_sessions_user_id_idx ON user_sessions (user_id);
CREATE INDEX user_sessions_expires_at_idx ON user_sessions (expires_at);

CREATE TABLE email_verification_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash BYTEA NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX email_verification_tokens_token_hash_key
    ON email_verification_tokens (token_hash);
CREATE INDEX email_verification_tokens_user_id_idx
    ON email_verification_tokens (user_id);
CREATE INDEX email_verification_tokens_expires_at_idx
    ON email_verification_tokens (expires_at);

CREATE TABLE email_outbox (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    to_email TEXT NOT NULL,
    template TEXT NOT NULL,
    payload_json JSONB NOT NULL,
    status email_outbox_status NOT NULL DEFAULT 'pending',
    attempts INTEGER NOT NULL DEFAULT 0,
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    sent_at TIMESTAMPTZ
);

CREATE INDEX email_outbox_status_idx ON email_outbox (status);
CREATE INDEX email_outbox_next_attempt_idx ON email_outbox (status, next_attempt_at);
CREATE INDEX email_outbox_created_at_idx ON email_outbox (created_at);
