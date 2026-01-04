-- Permesi schema bootstrap for dev containers.
-- Keep in sync with services/permesi/sql/schema.sql.

CREATE EXTENSION IF NOT EXISTS citext;

DROP TABLE IF EXISTS email_outbox;
DROP TABLE IF EXISTS email_verification_tokens;
DROP TABLE IF EXISTS user_sessions;
DROP TABLE IF EXISTS applications;
DROP TABLE IF EXISTS environments;
DROP TABLE IF EXISTS projects;
DROP TABLE IF EXISTS org_member_roles;
DROP TABLE IF EXISTS org_roles;
DROP TABLE IF EXISTS org_memberships;
DROP TABLE IF EXISTS organizations;
DROP TABLE IF EXISTS users_metadata;
DROP TABLE IF EXISTS users_password_history;
DROP TABLE IF EXISTS users;
DROP TYPE IF EXISTS email_outbox_status;
DROP TYPE IF EXISTS environment_tier;
DROP TYPE IF EXISTS org_membership_status;
DROP TYPE IF EXISTS user_status;

CREATE TYPE user_status AS ENUM ('pending_verification', 'active', 'disabled');
CREATE TYPE email_outbox_status AS ENUM ('pending', 'sent', 'failed');
CREATE TYPE environment_tier AS ENUM ('production', 'non_production');
CREATE TYPE org_membership_status AS ENUM ('active', 'invited', 'suspended');

CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email CITEXT NOT NULL UNIQUE
        CHECK (email::text = LOWER(TRIM(email::text)))
        CHECK (email <> '')
        CHECK (char_length(email) <= 255),
    opaque_registration_record BYTEA NOT NULL,
    display_name TEXT,
    locale TEXT,
    status user_status NOT NULL DEFAULT 'pending_verification',
    email_verified_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_users_status ON users (status);

CREATE TABLE organizations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    slug TEXT NOT NULL
        CHECK (slug = LOWER(slug))
        CHECK (slug ~ '^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$'),
    name TEXT NOT NULL
        CHECK (name <> ''),
    created_by UUID NOT NULL REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), -- keep updated_at for orgs
    deleted_at TIMESTAMPTZ
);

CREATE UNIQUE INDEX organizations_slug_active_idx -- unique among active orgs only
    ON organizations (slug)
    WHERE deleted_at IS NULL;

CREATE TABLE org_memberships (
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    status org_membership_status NOT NULL DEFAULT 'invited',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), -- keep updated_at for membership changes
    PRIMARY KEY (org_id, user_id)
);

CREATE INDEX org_memberships_user_id_idx ON org_memberships (user_id);

CREATE TABLE org_roles (
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name TEXT NOT NULL
        CHECK (char_length(name) BETWEEN 1 AND 64)
        CHECK (name = LOWER(name))
        CHECK (name ~ '^[a-z][a-z0-9-]{0,62}[a-z0-9]$'), -- lowercase slug role names
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (org_id, name)
);

CREATE TABLE org_member_roles (
    org_id UUID NOT NULL,
    user_id UUID NOT NULL,
    role_name TEXT NOT NULL,
    assigned_by UUID REFERENCES users(id),
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (org_id, user_id, role_name),
    FOREIGN KEY (org_id, user_id) REFERENCES org_memberships(org_id, user_id) ON DELETE CASCADE,
    FOREIGN KEY (org_id, role_name) REFERENCES org_roles(org_id, name) ON DELETE CASCADE
);

CREATE TABLE projects (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    slug TEXT NOT NULL
        CHECK (slug = LOWER(slug))
        CHECK (slug ~ '^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$'),
    name TEXT NOT NULL
        CHECK (name <> ''),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), -- keep updated_at for projects
    deleted_at TIMESTAMPTZ
);

CREATE INDEX projects_org_id_idx ON projects (org_id);
CREATE UNIQUE INDEX projects_org_slug_active_idx -- unique among active projects only
    ON projects (org_id, slug)
    WHERE deleted_at IS NULL;

CREATE TABLE environments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    slug TEXT NOT NULL
        CHECK (slug = LOWER(slug))
        CHECK (slug ~ '^[a-z0-9][a-z0-9-]{0,30}[a-z0-9]$'),
    name TEXT NOT NULL
        CHECK (name <> ''),
    tier environment_tier NOT NULL DEFAULT 'non_production',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), -- keep updated_at for environments
    deleted_at TIMESTAMPTZ
);

CREATE INDEX environments_project_id_idx ON environments (project_id);
CREATE UNIQUE INDEX environments_project_slug_active_idx -- unique among active envs only
    ON environments (project_id, slug)
    WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX environments_project_primary_production_idx -- single active production env
    ON environments (project_id)
    WHERE tier = 'production' AND deleted_at IS NULL;

CREATE TABLE applications (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    environment_id UUID NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
    name TEXT NOT NULL
        CHECK (name <> ''),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), -- keep updated_at for applications
    deleted_at TIMESTAMPTZ
);

CREATE INDEX applications_environment_id_idx ON applications (environment_id);
CREATE UNIQUE INDEX applications_environment_name_active_idx -- unique among active apps only
    ON applications (environment_id, name)
    WHERE deleted_at IS NULL;

CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    IF (
        NEW.email,
        NEW.opaque_registration_record,
        NEW.display_name,
        NEW.locale,
        NEW.status,
        NEW.email_verified_at
    )
        IS DISTINCT FROM
       (
        OLD.email,
        OLD.opaque_registration_record,
        OLD.display_name,
        OLD.locale,
        OLD.status,
        OLD.email_verified_at
       ) THEN
        NEW.updated_at := clock_timestamp();
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS update_users_updated_at ON users;
CREATE TRIGGER update_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE OR REPLACE FUNCTION touch_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at := clock_timestamp();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS update_organizations_updated_at ON organizations;
CREATE TRIGGER update_organizations_updated_at
    BEFORE UPDATE ON organizations
    FOR EACH ROW
    EXECUTE FUNCTION touch_updated_at(); -- bump updated_at on org changes

DROP TRIGGER IF EXISTS update_projects_updated_at ON projects;
CREATE TRIGGER update_projects_updated_at
    BEFORE UPDATE ON projects
    FOR EACH ROW
    EXECUTE FUNCTION touch_updated_at(); -- bump updated_at on project changes

DROP TRIGGER IF EXISTS update_environments_updated_at ON environments;
CREATE TRIGGER update_environments_updated_at
    BEFORE UPDATE ON environments
    FOR EACH ROW
    EXECUTE FUNCTION touch_updated_at(); -- bump updated_at on env changes

DROP TRIGGER IF EXISTS update_applications_updated_at ON applications;
CREATE TRIGGER update_applications_updated_at
    BEFORE UPDATE ON applications
    FOR EACH ROW
    EXECUTE FUNCTION touch_updated_at(); -- bump updated_at on app changes

DROP TRIGGER IF EXISTS update_org_memberships_updated_at ON org_memberships;
CREATE TRIGGER update_org_memberships_updated_at
    BEFORE UPDATE ON org_memberships
    FOR EACH ROW
    EXECUTE FUNCTION touch_updated_at(); -- bump updated_at on membership changes

CREATE TABLE user_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_hash BYTEA NOT NULL UNIQUE CHECK (octet_length(session_hash) = 32), -- sha-256 hash length
    expires_at TIMESTAMPTZ NOT NULL
        CHECK (expires_at > created_at),
    last_seen_at TIMESTAMPTZ
        CHECK (last_seen_at IS NULL OR last_seen_at >= created_at),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX user_sessions_user_id_idx ON user_sessions (user_id);
CREATE INDEX user_sessions_expires_at_idx ON user_sessions (expires_at);

CREATE TABLE email_verification_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash BYTEA NOT NULL CHECK (octet_length(token_hash) >= 32), -- allow future hash lengths
    expires_at TIMESTAMPTZ NOT NULL
        CHECK (expires_at > created_at),
    consumed_at TIMESTAMPTZ
        CHECK (consumed_at IS NULL OR consumed_at >= created_at),
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
    to_email CITEXT NOT NULL
        CHECK (to_email::text = LOWER(TRIM(to_email::text)))
        CHECK (to_email <> '')
        CHECK (char_length(to_email) <= 255),
    template TEXT NOT NULL,
    payload_json JSONB NOT NULL,
    status email_outbox_status NOT NULL DEFAULT 'pending',
    attempts INTEGER NOT NULL DEFAULT 0
        CHECK (attempts >= 0 AND attempts <= 100),
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    sent_at TIMESTAMPTZ
        CHECK (sent_at IS NULL OR sent_at >= created_at)
);

CREATE INDEX email_outbox_status_idx ON email_outbox (status);
CREATE INDEX email_outbox_next_attempt_idx ON email_outbox (status, next_attempt_at);
CREATE INDEX email_outbox_created_at_idx ON email_outbox (created_at);

-- Cleanup expired auth tokens (safe to call from cron/pg_cron).
CREATE OR REPLACE FUNCTION cleanup_expired_tokens()
RETURNS void AS $$
BEGIN
    DELETE FROM user_sessions WHERE expires_at < NOW() - INTERVAL '7 days';
    DELETE FROM email_verification_tokens WHERE expires_at < NOW() - INTERVAL '7 days';
END;
$$ LANGUAGE plpgsql;
