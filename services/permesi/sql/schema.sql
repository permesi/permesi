-- Permesi schema bootstrap.
-- Keep this file in sync with the matching schema under db/sql and services/permesi/sql.

CREATE EXTENSION IF NOT EXISTS citext;

-- Idempotent type creation.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'user_status') THEN
        CREATE TYPE user_status AS ENUM ('pending_verification', 'active', 'disabled');
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'email_outbox_status') THEN
        CREATE TYPE email_outbox_status AS ENUM ('pending', 'sent', 'failed');
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'environment_tier') THEN
        CREATE TYPE environment_tier AS ENUM ('production', 'non_production');
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'org_membership_status') THEN
        CREATE TYPE org_membership_status AS ENUM ('active', 'invited', 'suspended');
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT uuidv4(),
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

CREATE INDEX IF NOT EXISTS idx_users_status ON users (status);

CREATE TABLE IF NOT EXISTS roles (
    name TEXT PRIMARY KEY CHECK (name = LOWER(name))
);

INSERT INTO roles (name) VALUES ('owner'), ('admin'), ('editor'), ('member') ON CONFLICT DO NOTHING;

CREATE TABLE IF NOT EXISTS user_roles (
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    role TEXT NOT NULL REFERENCES roles(name),
    assigned_by UUID REFERENCES users(id),
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS role_audit_log (
    id UUID PRIMARY KEY DEFAULT uuidv4(),
    actor_id UUID REFERENCES users(id),
    target_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    previous_role TEXT,
    new_role TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS platform_operators (
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by UUID NULL REFERENCES users(id),
    note TEXT NULL
);

CREATE TABLE IF NOT EXISTS organizations (
    id UUID PRIMARY KEY DEFAULT uuidv4(),
    slug TEXT NOT NULL
        CHECK (slug = LOWER(slug))
        CHECK (slug ~ '^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$'),
    name TEXT NOT NULL
        CHECK (name <> ''),
    created_by UUID NOT NULL REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ
);

CREATE UNIQUE INDEX IF NOT EXISTS organizations_slug_active_idx
    ON organizations (slug)
    WHERE deleted_at IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS organizations_creator_name_active_idx
    ON organizations (created_by, name)
    WHERE deleted_at IS NULL;

CREATE TABLE IF NOT EXISTS org_memberships (
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    status org_membership_status NOT NULL DEFAULT 'invited',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (org_id, user_id)
);

CREATE INDEX IF NOT EXISTS org_memberships_user_id_idx ON org_memberships (user_id);

CREATE TABLE IF NOT EXISTS org_roles (
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name TEXT NOT NULL
        CHECK (char_length(name) BETWEEN 1 AND 64)
        CHECK (name = LOWER(name))
        CHECK (name ~ '^[a-z][a-z0-9-]{0,62}[a-z0-9]$'),
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (org_id, name)
);

CREATE TABLE IF NOT EXISTS org_member_roles (
    org_id UUID NOT NULL,
    user_id UUID NOT NULL,
    role_name TEXT NOT NULL,
    assigned_by UUID REFERENCES users(id),
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (org_id, user_id, role_name),
    FOREIGN KEY (org_id, user_id) REFERENCES org_memberships(org_id, user_id) ON DELETE CASCADE,
    FOREIGN KEY (org_id, role_name) REFERENCES org_roles(org_id, name) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS projects (
    id UUID PRIMARY KEY DEFAULT uuidv4(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    slug TEXT NOT NULL
        CHECK (slug = LOWER(slug))
        CHECK (slug ~ '^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$'),
    name TEXT NOT NULL
        CHECK (name <> ''),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS projects_org_id_idx ON projects (org_id);
CREATE UNIQUE INDEX IF NOT EXISTS projects_org_slug_active_idx
    ON projects (org_id, slug)
    WHERE deleted_at IS NULL;

CREATE TABLE IF NOT EXISTS environments (
    id UUID PRIMARY KEY DEFAULT uuidv4(),
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    slug TEXT NOT NULL
        CHECK (slug = LOWER(slug))
        CHECK (slug ~ '^[a-z0-9][a-z0-9-]{0,30}[a-z0-9]$'),
    name TEXT NOT NULL
        CHECK (name <> ''),
    tier environment_tier NOT NULL DEFAULT 'non_production',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS environments_project_id_idx ON environments (project_id);
CREATE UNIQUE INDEX IF NOT EXISTS environments_project_slug_active_idx
    ON environments (project_id, slug)
    WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS environments_project_primary_production_idx
    ON environments (project_id)
    WHERE tier = 'production' AND deleted_at IS NULL;

CREATE TABLE IF NOT EXISTS applications (
    id UUID PRIMARY KEY DEFAULT uuidv4(),
    environment_id UUID NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
    name TEXT NOT NULL
        CHECK (name <> ''),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS applications_environment_id_idx ON applications (environment_id);
CREATE UNIQUE INDEX IF NOT EXISTS applications_environment_name_active_idx
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
    EXECUTE FUNCTION touch_updated_at();

DROP TRIGGER IF EXISTS update_projects_updated_at ON projects;
CREATE TRIGGER update_projects_updated_at
    BEFORE UPDATE ON projects
    FOR EACH ROW
    EXECUTE FUNCTION touch_updated_at();

DROP TRIGGER IF EXISTS update_environments_updated_at ON environments;
CREATE TRIGGER update_environments_updated_at
    BEFORE UPDATE ON environments
    FOR EACH ROW
    EXECUTE FUNCTION touch_updated_at();

DROP TRIGGER IF EXISTS update_applications_updated_at ON applications;
CREATE TRIGGER update_applications_updated_at
    BEFORE UPDATE ON applications
    FOR EACH ROW
    EXECUTE FUNCTION touch_updated_at();

DROP TRIGGER IF EXISTS update_org_memberships_updated_at ON org_memberships;
CREATE TRIGGER update_org_memberships_updated_at
    BEFORE UPDATE ON org_memberships
    FOR EACH ROW
    EXECUTE FUNCTION touch_updated_at();

CREATE TABLE IF NOT EXISTS user_sessions (
    id UUID PRIMARY KEY DEFAULT uuidv4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_hash BYTEA NOT NULL UNIQUE CHECK (octet_length(session_hash) = 32),
    auth_time TIMESTAMPTZ NOT NULL DEFAULT NOW()
        CHECK (auth_time >= created_at),
    expires_at TIMESTAMPTZ NOT NULL
        CHECK (expires_at > created_at),
    last_seen_at TIMESTAMPTZ
        CHECK (last_seen_at IS NULL OR last_seen_at >= created_at),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS user_sessions_user_id_idx ON user_sessions (user_id);
CREATE INDEX IF NOT EXISTS user_sessions_expires_at_idx ON user_sessions (expires_at);

CREATE TABLE IF NOT EXISTS email_verification_tokens (
    id UUID PRIMARY KEY DEFAULT uuidv4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash BYTEA NOT NULL CHECK (octet_length(token_hash) >= 32),
    expires_at TIMESTAMPTZ NOT NULL
        CHECK (expires_at > created_at),
    consumed_at TIMESTAMPTZ
        CHECK (consumed_at IS NULL OR consumed_at >= created_at),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS email_verification_tokens_token_hash_key
    ON email_verification_tokens (token_hash);
CREATE INDEX IF NOT EXISTS email_verification_tokens_user_id_idx
    ON email_verification_tokens (user_id);
CREATE INDEX IF NOT EXISTS email_verification_tokens_expires_at_idx
    ON email_verification_tokens (expires_at);

CREATE TABLE IF NOT EXISTS email_outbox (
    id UUID PRIMARY KEY DEFAULT uuidv4(),
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

CREATE INDEX IF NOT EXISTS email_outbox_status_idx ON email_outbox (status);
CREATE INDEX IF NOT EXISTS email_outbox_next_attempt_idx ON email_outbox (status, next_attempt_at);
CREATE INDEX IF NOT EXISTS email_outbox_created_at_idx ON email_outbox (created_at);

CREATE TABLE IF NOT EXISTS admin_attempts (
    id UUID PRIMARY KEY DEFAULT uuidv4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    ip_address INET,
    country_code CHAR(2),
    is_failure BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_admin_attempts_user_time ON admin_attempts (user_id, created_at);
CREATE INDEX IF NOT EXISTS idx_admin_attempts_ip_time ON admin_attempts (ip_address, created_at);

CREATE OR REPLACE FUNCTION cleanup_expired_tokens()
RETURNS void AS $$
BEGIN
    DELETE FROM user_sessions WHERE expires_at < NOW() - INTERVAL '7 days';
    DELETE FROM email_verification_tokens WHERE expires_at < NOW() - INTERVAL '7 days';
    DELETE FROM admin_attempts WHERE created_at < NOW() - INTERVAL '24 hours';
END;
$$ LANGUAGE plpgsql;
