-- psql -U <user> -d permesi -f schema.sql

DROP TABLE IF EXISTS email_outbox;
DROP TABLE IF EXISTS email_verification_tokens;
DROP TABLE IF EXISTS users_metadata;
DROP TABLE IF EXISTS users_password_history;
DROP TABLE IF EXISTS users;
DROP TYPE IF EXISTS email_outbox_status;
DROP TYPE IF EXISTS user_status;

CREATE TYPE user_status AS ENUM ('pending_verification', 'active', 'disabled');
CREATE TYPE email_outbox_status AS ENUM ('pending', 'sent', 'failed');

CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username TEXT NOT NULL,
    username_normalized TEXT NOT NULL,
    email TEXT NOT NULL,
    email_normalized TEXT NOT NULL,
    opaque_registration_record BYTEA NOT NULL,
    status user_status NOT NULL DEFAULT 'pending_verification',
    email_verified_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX users_username_normalized_key ON users (username_normalized);
CREATE UNIQUE INDEX users_email_normalized_key ON users (email_normalized);

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
