-- Permesi schema bootstrap.
-- Canonical source: db/sql/02_permesi.sql

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

-- OAuth registration foundation. Applications remain logical tenant resources.
-- Public client identifiers are independent UUIDs, unique forever (including deleted rows).
CREATE TABLE IF NOT EXISTS oauth_clients (
    id UUID PRIMARY KEY DEFAULT uuidv4(),
    application_id UUID NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    client_id UUID NOT NULL UNIQUE DEFAULT uuidv4(),
    name TEXT NOT NULL CHECK (char_length(name) BETWEEN 1 AND 255)
        CHECK (name = TRIM(name) AND name !~ '[[:cntrl:]]'),
    client_type TEXT NOT NULL CHECK (client_type IN ('public', 'confidential')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    disabled_at TIMESTAMPTZ,
    deleted_at TIMESTAMPTZ,
    UNIQUE (id, application_id),
    UNIQUE (id, client_type),
    CHECK (deleted_at IS NULL OR disabled_at IS NOT NULL)
);
CREATE UNIQUE INDEX IF NOT EXISTS oauth_clients_application_name_active_idx
    ON oauth_clients (application_id, name) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS oauth_clients_application_idx ON oauth_clients (application_id);

-- Confidential credentials contain high-entropy material; only salted Argon2id PHC
-- hashes persist. Client row locks serialize creation, overlap rotation and revocation.
CREATE TABLE IF NOT EXISTS oauth_client_secrets (
    id UUID PRIMARY KEY DEFAULT uuidv4(),
    client_id UUID NOT NULL,
    client_type TEXT NOT NULL DEFAULT 'confidential' CHECK (client_type = 'confidential'),
    secret_hash TEXT NOT NULL CHECK (secret_hash LIKE '$argon2id$%'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at TIMESTAMPTZ,
    FOREIGN KEY (client_id, client_type) REFERENCES oauth_clients(id, client_type) ON DELETE CASCADE
);
ALTER TABLE oauth_client_secrets ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ;
CREATE UNIQUE INDEX IF NOT EXISTS oauth_client_secrets_current_idx
    ON oauth_client_secrets(client_id) WHERE revoked_at IS NULL AND expires_at IS NULL;

-- Identity/hash creation is immutable; revocation is irreversible and retirement can only shorten.
CREATE OR REPLACE FUNCTION protect_oauth_client_secret() RETURNS TRIGGER
LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.id IS DISTINCT FROM OLD.id OR NEW.client_id IS DISTINCT FROM OLD.client_id
       OR NEW.client_type IS DISTINCT FROM OLD.client_type OR NEW.secret_hash IS DISTINCT FROM OLD.secret_hash
       OR NEW.created_at IS DISTINCT FROM OLD.created_at
       OR (OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS DISTINCT FROM OLD.revoked_at)
       OR (OLD.expires_at IS NOT NULL AND (NEW.expires_at IS NULL OR NEW.expires_at > OLD.expires_at))
       OR (OLD.expires_at IS NULL AND NEW.expires_at > clock_timestamp() + INTERVAL '3600 seconds') THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Invalid credential transition';
    END IF;
    RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS protect_oauth_client_secret ON oauth_client_secrets;
CREATE TRIGGER protect_oauth_client_secret BEFORE UPDATE ON oauth_client_secrets
    FOR EACH ROW EXECUTE FUNCTION protect_oauth_client_secret();

-- Credentials start live; callers cannot pre-retire them or forge creation times.
CREATE OR REPLACE FUNCTION initialize_oauth_client_secret() RETURNS TRIGGER
LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.revoked_at IS NOT NULL OR NEW.expires_at IS NOT NULL THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Invalid initial credential state';
    END IF;
    NEW.created_at := clock_timestamp();
    RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS initialize_oauth_client_secret ON oauth_client_secrets;
CREATE TRIGGER initialize_oauth_client_secret BEFORE INSERT ON oauth_client_secrets
    FOR EACH ROW EXECUTE FUNCTION initialize_oauth_client_secret();

CREATE INDEX IF NOT EXISTS oauth_client_secrets_active_idx
    ON oauth_client_secrets (client_id) WHERE revoked_at IS NULL;

-- A client may have only one live retiring credential. Serialize direct writes too;
-- the partial unique index separately enforces one non-revoked current credential.
CREATE OR REPLACE FUNCTION limit_oauth_client_secret_overlap() RETURNS TRIGGER
LANGUAGE plpgsql AS $$
BEGIN
    PERFORM 1 FROM oauth_clients WHERE id=NEW.client_id FOR UPDATE;
    IF (SELECT count(*) FROM oauth_client_secrets WHERE client_id=NEW.client_id
        AND revoked_at IS NULL AND expires_at>clock_timestamp()) > 1 THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Credential overlap already active';
    END IF;
    RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS limit_oauth_client_secret_overlap ON oauth_client_secrets;
CREATE TRIGGER limit_oauth_client_secret_overlap AFTER INSERT OR UPDATE ON oauth_client_secrets
    FOR EACH ROW EXECUTE FUNCTION limit_oauth_client_secret_overlap();

CREATE TABLE IF NOT EXISTS oauth_client_redirect_uris (
    client_id UUID NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    redirect_uri TEXT COLLATE "C" NOT NULL
        CHECK (char_length(redirect_uri) BETWEEN 1 AND 2048)
        CHECK (redirect_uri ~ '^https?://[^/]+')
        CHECK (redirect_uri !~ '[[:space:][:cntrl:]*#]')
        CHECK (position(chr(92) in redirect_uri) = 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (client_id, redirect_uri)
);

CREATE TABLE IF NOT EXISTS oauth_scopes (
    id UUID PRIMARY KEY DEFAULT uuidv4(),
    application_id UUID NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    name TEXT COLLATE "C" NOT NULL CHECK (char_length(name) BETWEEN 1 AND 128)
        CHECK (name ~ '^[!-~]+$' AND position('"' in name) = 0 AND position(chr(92) in name) = 0),
    description TEXT NOT NULL DEFAULT '' CHECK (char_length(description) <= 2048),
    kind TEXT NOT NULL CHECK (kind IN ('application', 'protocol')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (application_id, name),
    UNIQUE (id, application_id),
    CHECK (
        (kind = 'protocol' AND name IN ('openid', 'profile', 'email', 'address', 'phone', 'offline_access'))
        OR
        (kind = 'application'
            AND LOWER(name) NOT IN ('openid', 'profile', 'email', 'address', 'phone', 'offline_access')
            AND LOWER(name) !~ '^(platform|users):')
    )
);

CREATE TABLE IF NOT EXISTS oauth_client_scopes (
    client_id UUID NOT NULL,
    application_id UUID NOT NULL,
    scope_id UUID NOT NULL,
    PRIMARY KEY (client_id, scope_id),
    UNIQUE (client_id, application_id, scope_id),
    FOREIGN KEY (client_id, application_id) REFERENCES oauth_clients(id, application_id) ON DELETE CASCADE,
    FOREIGN KEY (scope_id, application_id) REFERENCES oauth_scopes(id, application_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS oauth_client_scopes_scope_idx ON oauth_client_scopes (scope_id);

-- Fixed protocol entries are per-application so the same composite FKs protect
-- every allow-list and grant, while kind keeps protocol semantics distinct.
CREATE OR REPLACE FUNCTION seed_oauth_protocol_scopes()
RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO oauth_scopes (application_id, name, kind)
    SELECT NEW.id, name, 'protocol'
    FROM unnest(ARRAY['openid', 'profile', 'email', 'address', 'phone', 'offline_access']) AS name
    ON CONFLICT (application_id, name) DO NOTHING;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS seed_application_oauth_scopes ON applications;
CREATE TRIGGER seed_application_oauth_scopes AFTER INSERT ON applications
    FOR EACH ROW EXECUTE FUNCTION seed_oauth_protocol_scopes();
INSERT INTO oauth_scopes (application_id, name, kind)
SELECT a.id, s.name, 'protocol' FROM applications a
CROSS JOIN unnest(ARRAY['openid', 'profile', 'email', 'address', 'phone', 'offline_access']) AS s(name)
ON CONFLICT (application_id, name) DO NOTHING;

-- Authorization consent writes grants. Explicit organization/application context prevent
-- one user's consent from implicitly spanning all their organization memberships.
CREATE TABLE IF NOT EXISTS oauth_grants (
    id UUID PRIMARY KEY DEFAULT uuidv4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id UUID NOT NULL,
    application_id UUID NOT NULL,
    organization_id UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at TIMESTAMPTZ,
    UNIQUE (id, client_id, application_id),
    FOREIGN KEY (client_id, application_id) REFERENCES oauth_clients(id, application_id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, user_id) REFERENCES org_memberships(org_id, user_id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX IF NOT EXISTS oauth_grants_active_idx
    ON oauth_grants (user_id, client_id, organization_id) WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS oauth_grants_client_idx ON oauth_grants (client_id);

CREATE OR REPLACE FUNCTION validate_oauth_grant_context()
RETURNS TRIGGER AS $$
BEGIN
    -- Share locks conflict with lifecycle/membership UPDATEs and the service's
    -- client FOR UPDATE, while allowing independent consent writers. PostgreSQL
    -- rechecks current row versions after waiting; stale context cannot pass.
    PERFORM 1 FROM applications a
        JOIN environments e ON e.id = a.environment_id
        JOIN projects p ON p.id = e.project_id
        JOIN organizations o ON o.id = p.org_id
        JOIN oauth_clients c ON c.application_id = a.id AND c.id = NEW.client_id
        JOIN org_memberships m ON m.org_id = o.id AND m.user_id = NEW.user_id
        WHERE a.id = NEW.application_id AND o.id = NEW.organization_id
            AND a.deleted_at IS NULL AND e.deleted_at IS NULL
            AND p.deleted_at IS NULL AND o.deleted_at IS NULL
            AND c.disabled_at IS NULL AND c.deleted_at IS NULL AND m.status = 'active'
        FOR SHARE OF a, e, p, o, c, m;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Invalid OAuth grant context' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS validate_oauth_grant_context ON oauth_grants;
CREATE TRIGGER validate_oauth_grant_context
    BEFORE INSERT OR UPDATE OF user_id, client_id, application_id, organization_id ON oauth_grants
    FOR EACH ROW EXECUTE FUNCTION validate_oauth_grant_context();

-- Reauthorization creates a new grant; revoked records cannot be reactivated.
-- Keep this separate from context validation so revocation always works even
-- after membership suspension or ancestor/client deletion.
CREATE OR REPLACE FUNCTION forbid_oauth_grant_reactivation()
RETURNS TRIGGER AS $$
BEGIN
    IF OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS DISTINCT FROM OLD.revoked_at THEN
        RAISE EXCEPTION 'Revoked OAuth grants are immutable' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS forbid_oauth_grant_reactivation ON oauth_grants;
CREATE TRIGGER forbid_oauth_grant_reactivation BEFORE UPDATE OF revoked_at ON oauth_grants
    FOR EACH ROW EXECUTE FUNCTION forbid_oauth_grant_reactivation();

CREATE TABLE IF NOT EXISTS oauth_grant_scopes (
    grant_id UUID NOT NULL,
    client_id UUID NOT NULL,
    application_id UUID NOT NULL,
    scope_id UUID NOT NULL,
    PRIMARY KEY (grant_id, scope_id),
    FOREIGN KEY (grant_id, client_id, application_id)
        REFERENCES oauth_grants(id, client_id, application_id) ON DELETE CASCADE,
    FOREIGN KEY (client_id, application_id, scope_id)
        REFERENCES oauth_client_scopes(client_id, application_id, scope_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS oauth_grant_scopes_client_scope_idx ON oauth_grant_scopes (client_id, scope_id);

-- Snapshot arrays reject NULLs and duplicates even for direct SQL writes.
CREATE OR REPLACE FUNCTION oauth_scope_ids_valid(ids UUID[]) RETURNS BOOLEAN
    LANGUAGE SQL IMMUTABLE AS $$
    SELECT cardinality(ids) BETWEEN 1 AND 64
        AND cardinality(ids) = (SELECT count(DISTINCT id) FROM unnest(ids) id);
$$;
CREATE OR REPLACE FUNCTION oauth_scope_names_valid(names TEXT[]) RETURNS BOOLEAN
    LANGUAGE SQL IMMUTABLE AS $$
    SELECT cardinality(names) BETWEEN 1 AND 64
        AND cardinality(names) = (SELECT count(DISTINCT name) FROM unnest(names) name)
        AND NOT EXISTS (SELECT 1 FROM unnest(names) name WHERE name IS NULL
            OR char_length(name) NOT BETWEEN 1 AND 128
            OR name !~ '^[!-~]+$' OR position('"' in name) > 0 OR position(chr(92) in name) > 0);
$$;

-- Authorization requests survive login/MFA and replica changes. Browser and CSRF
-- capabilities are hashes, while all authority-bearing values are server snapshots.
CREATE TABLE IF NOT EXISTS oauth_authorization_requests (
    id UUID PRIMARY KEY DEFAULT uuidv4(),
    client_id UUID NOT NULL,
    application_id UUID NOT NULL,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    redirect_uri TEXT COLLATE "C" NOT NULL,
    scope_ids UUID[] NOT NULL CHECK (oauth_scope_ids_valid(scope_ids)),
    scope_names TEXT[] NOT NULL CHECK (oauth_scope_names_valid(scope_names) AND cardinality(scope_names) = cardinality(scope_ids)),
    code_challenge TEXT COLLATE "C" NOT NULL CHECK (code_challenge ~ '^[A-Za-z0-9_-]{43}$'),
    code_challenge_method TEXT NOT NULL DEFAULT 'S256' CHECK (code_challenge_method = 'S256'),
    state TEXT CHECK (octet_length(state) <= 2048),
    nonce TEXT CHECK (octet_length(nonce) BETWEEN 1 AND 2048),
    prompt TEXT NOT NULL CHECK (prompt IN ('default', 'consent', 'none')),
    issuer TEXT NOT NULL,
    audience TEXT NOT NULL,
    browser_hash BYTEA NOT NULL CHECK (octet_length(browser_hash) = 32),
    csrf_hash BYTEA CHECK (octet_length(csrf_hash) = 32),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    session_hash BYTEA CHECK (octet_length(session_hash) = 32),
    created_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    expires_at TIMESTAMPTZ NOT NULL CHECK (expires_at > created_at AND expires_at <= created_at + INTERVAL '30 minutes'),
    completed_at TIMESTAMPTZ CHECK (completed_at >= created_at),
    CHECK ((user_id IS NULL) = (session_hash IS NULL)),
    CHECK (csrf_hash IS NULL OR user_id IS NOT NULL),
    CHECK (('openid' = ANY(scope_names)) = (nonce IS NOT NULL)),
    FOREIGN KEY (client_id, application_id) REFERENCES oauth_clients(id, application_id) ON DELETE CASCADE,
    FOREIGN KEY (client_id, redirect_uri) REFERENCES oauth_client_redirect_uris(client_id, redirect_uri) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS oauth_authorization_requests_expiry_idx ON oauth_authorization_requests(expires_at);

-- Bind the complete code context to its saved consent with a composite foreign key.
CREATE UNIQUE INDEX IF NOT EXISTS oauth_grants_code_context_key
    ON oauth_grants(id, client_id, application_id, organization_id, user_id);
CREATE TABLE IF NOT EXISTS oauth_authorization_codes (
    code_hash BYTEA PRIMARY KEY CHECK (octet_length(code_hash) = 32),
    request_id UUID NOT NULL UNIQUE REFERENCES oauth_authorization_requests(id) ON DELETE CASCADE,
    grant_id UUID NOT NULL,
    client_id UUID NOT NULL,
    application_id UUID NOT NULL,
    organization_id UUID NOT NULL,
    user_id UUID NOT NULL,
    redirect_uri TEXT COLLATE "C" NOT NULL,
    scope_ids UUID[] NOT NULL CHECK (oauth_scope_ids_valid(scope_ids)),
    scope_names TEXT[] NOT NULL CHECK (oauth_scope_names_valid(scope_names) AND cardinality(scope_names) = cardinality(scope_ids)),
    code_challenge TEXT COLLATE "C" NOT NULL CHECK (code_challenge ~ '^[A-Za-z0-9_-]{43}$'),
    code_challenge_method TEXT NOT NULL DEFAULT 'S256' CHECK (code_challenge_method = 'S256'),
    nonce TEXT CHECK (octet_length(nonce) BETWEEN 1 AND 2048),
    issuer TEXT NOT NULL,
    audience TEXT NOT NULL,
    auth_time TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    expires_at TIMESTAMPTZ NOT NULL CHECK (expires_at > created_at AND expires_at <= created_at + INTERVAL '5 minutes'),
    consumed_at TIMESTAMPTZ CHECK (consumed_at >= created_at AND consumed_at < expires_at),
    CHECK (('openid' = ANY(scope_names)) = (nonce IS NOT NULL)),
    FOREIGN KEY (grant_id, client_id, application_id, organization_id, user_id)
        REFERENCES oauth_grants(id, client_id, application_id, organization_id, user_id) ON DELETE CASCADE,
    FOREIGN KEY (client_id, redirect_uri) REFERENCES oauth_client_redirect_uris(client_id, redirect_uri) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS oauth_authorization_codes_expiry_idx ON oauth_authorization_codes(expires_at);

-- Browser handles cannot rewrite validated authority or switch the bound full session.
CREATE OR REPLACE FUNCTION protect_oauth_authorization_request()
RETURNS TRIGGER AS $$
BEGIN
    IF (to_jsonb(NEW) - ARRAY['csrf_hash','user_id','session_hash','completed_at'])
        IS DISTINCT FROM (to_jsonb(OLD) - ARRAY['csrf_hash','user_id','session_hash','completed_at'])
        OR (OLD.user_id IS NOT NULL AND (NEW.user_id, NEW.session_hash) IS DISTINCT FROM (OLD.user_id, OLD.session_hash))
        OR (OLD.completed_at IS NOT NULL AND NEW IS DISTINCT FROM OLD) THEN
        RAISE EXCEPTION 'Authorization request binding is immutable' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS protect_oauth_authorization_request ON oauth_authorization_requests;
CREATE TRIGGER protect_oauth_authorization_request BEFORE UPDATE ON oauth_authorization_requests
    FOR EACH ROW EXECUTE FUNCTION protect_oauth_authorization_request();

-- Codes must preserve the exact validated request and its bound user.
CREATE OR REPLACE FUNCTION validate_oauth_authorization_code()
RETURNS TRIGGER AS $$
BEGIN
    PERFORM 1 FROM oauth_authorization_requests r
        WHERE r.id = NEW.request_id AND r.completed_at IS NULL AND r.expires_at > clock_timestamp()
        AND (r.client_id,r.application_id,r.organization_id,r.user_id,r.redirect_uri,
             r.scope_ids,r.scope_names,r.code_challenge,r.code_challenge_method,r.nonce,r.issuer,r.audience)
        IS NOT DISTINCT FROM (NEW.client_id,NEW.application_id,NEW.organization_id,NEW.user_id,NEW.redirect_uri,
             NEW.scope_ids,NEW.scope_names,NEW.code_challenge,NEW.code_challenge_method,NEW.nonce,NEW.issuer,NEW.audience)
        FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Invalid authorization code binding' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS validate_oauth_authorization_code ON oauth_authorization_codes;
CREATE TRIGGER validate_oauth_authorization_code BEFORE INSERT ON oauth_authorization_codes
    FOR EACH ROW EXECUTE FUNCTION validate_oauth_authorization_code();

-- Codes are immutable snapshots; consumption is an irreversible one-way transition.
CREATE OR REPLACE FUNCTION protect_oauth_authorization_code()
RETURNS TRIGGER AS $$
BEGIN
    IF (to_jsonb(NEW) - 'consumed_at') IS DISTINCT FROM (to_jsonb(OLD) - 'consumed_at')
        OR (OLD.consumed_at IS NOT NULL AND NEW.consumed_at IS DISTINCT FROM OLD.consumed_at) THEN
        RAISE EXCEPTION 'Authorization code is immutable' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS protect_oauth_authorization_code ON oauth_authorization_codes;
CREATE TRIGGER protect_oauth_authorization_code BEFORE UPDATE ON oauth_authorization_codes
    FOR EACH ROW EXECUTE FUNCTION protect_oauth_authorization_code();

-- Hash-only issuance receipts commit atomically with code consumption. Redirect retirement
-- may remove a code, but must not silently erase its issuance history.
CREATE TABLE IF NOT EXISTS oauth_token_issuances (
    access_jti UUID PRIMARY KEY,
    code_hash BYTEA NOT NULL UNIQUE CHECK (octet_length(code_hash)=32),
    access_token_hash BYTEA NOT NULL UNIQUE CHECK (octet_length(access_token_hash)=32),
    id_token_hash BYTEA UNIQUE CHECK (octet_length(id_token_hash)=32),
    grant_id UUID NOT NULL,
    client_id UUID NOT NULL,
    application_id UUID NOT NULL,
    organization_id UUID NOT NULL,
    user_id UUID NOT NULL,
    issuer TEXT NOT NULL,
    audience TEXT NOT NULL,
    issued_at TIMESTAMPTZ NOT NULL,
    access_expires_at TIMESTAMPTZ NOT NULL CHECK
        (access_expires_at>issued_at AND access_expires_at<=issued_at+INTERVAL '1 hour'),
    id_expires_at TIMESTAMPTZ CHECK
        (id_expires_at>issued_at AND id_expires_at<=issued_at+INTERVAL '1 hour'),
    CHECK ((id_token_hash IS NULL)=(id_expires_at IS NULL)),
    FOREIGN KEY (grant_id,client_id,application_id,organization_id,user_id)
        REFERENCES oauth_grants(id,client_id,application_id,organization_id,user_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS oauth_token_issuances_expiry_idx ON oauth_token_issuances(access_expires_at);

CREATE OR REPLACE FUNCTION validate_oauth_token_issuance()
RETURNS TRIGGER AS $$
BEGIN
    PERFORM 1 FROM oauth_authorization_codes c
        WHERE c.code_hash=NEW.code_hash AND c.consumed_at IS NOT NULL
        AND (c.grant_id,c.client_id,c.application_id,c.organization_id,c.user_id,c.issuer,c.audience)
        IS NOT DISTINCT FROM (NEW.grant_id,NEW.client_id,NEW.application_id,NEW.organization_id,NEW.user_id,NEW.issuer,NEW.audience)
        AND (c.nonce IS NOT NULL)=(NEW.id_token_hash IS NOT NULL) FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Invalid token issuance binding' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS validate_oauth_token_issuance ON oauth_token_issuances;
CREATE TRIGGER validate_oauth_token_issuance BEFORE INSERT ON oauth_token_issuances
    FOR EACH ROW EXECUTE FUNCTION validate_oauth_token_issuance();

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

DROP TRIGGER IF EXISTS update_oauth_clients_updated_at ON oauth_clients;
CREATE TRIGGER update_oauth_clients_updated_at BEFORE UPDATE ON oauth_clients
    FOR EACH ROW EXECUTE FUNCTION touch_updated_at();
DROP TRIGGER IF EXISTS update_oauth_scopes_updated_at ON oauth_scopes;
CREATE TRIGGER update_oauth_scopes_updated_at BEFORE UPDATE ON oauth_scopes
    FOR EACH ROW EXECUTE FUNCTION touch_updated_at();

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

-- Authentication rate limits are shared by every Permesi replica. Subjects are
-- HMAC-SHA256 tags of normalized IP/account/request identifiers, never raw identifiers.
CREATE TABLE IF NOT EXISTS auth_rate_limits (
    dimension TEXT NOT NULL CHECK (dimension IN ('ip', 'account')),
    subject_hash BYTEA NOT NULL CHECK (octet_length(subject_hash) = 32),
    action TEXT NOT NULL CHECK (action IN (
        'signup', 'login', 'verify_email', 'resend_verification', 'mfa_recovery', 'authorize', 'token_exchange','jwks_refresh', 'client_credentials_management','client_credentials_revocation'
    )),
    attempts BIGINT NOT NULL CHECK (attempts > 0),
    expires_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (dimension, subject_hash, action)
);

-- Add the independent OAuth authorization counter without changing existing actions.
ALTER TABLE auth_rate_limits DROP CONSTRAINT IF EXISTS auth_rate_limits_action_check;
ALTER TABLE auth_rate_limits ADD CONSTRAINT auth_rate_limits_action_check
    CHECK (action IN ('signup','login','verify_email','resend_verification','mfa_recovery','authorize','token_exchange','jwks_refresh','client_credentials_management','client_credentials_revocation'));

CREATE INDEX IF NOT EXISTS auth_rate_limits_expires_at_idx ON auth_rate_limits (expires_at);

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
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    DELETE FROM user_sessions WHERE expires_at < NOW() - INTERVAL '7 days';
    DELETE FROM email_verification_tokens WHERE expires_at < NOW() - INTERVAL '7 days';
    DELETE FROM admin_attempts WHERE created_at < NOW() - INTERVAL '24 hours';
    DELETE FROM auth_rate_limits WHERE expires_at < NOW();
    DELETE FROM oauth_token_issuances WHERE GREATEST(access_expires_at,id_expires_at) < NOW() - INTERVAL '7 days';
    DELETE FROM oauth_authorization_codes WHERE expires_at < NOW() - INTERVAL '7 days';
    DELETE FROM oauth_authorization_requests WHERE expires_at < NOW() - INTERVAL '7 days';
END;
$$;

-- -----------------------------------------------------------------------------
-- MFA (Multi-Factor Authentication)
-- -----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS user_mfa_state (
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    state TEXT NOT NULL CHECK (state IN ('disabled', 'required_unenrolled', 'enabled')),
    totp_secret BYTEA,
    recovery_batch_id UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS user_mfa_recovery_codes (
    id UUID PRIMARY KEY DEFAULT uuidv4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    batch_id UUID NOT NULL,
    code_hash TEXT NOT NULL,
    used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS user_mfa_recovery_codes_user_batch_idx ON user_mfa_recovery_codes (user_id, batch_id);

CREATE TABLE IF NOT EXISTS user_mfa_bootstrap_sessions (
    id UUID PRIMARY KEY DEFAULT uuidv4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_hash BYTEA NOT NULL UNIQUE CHECK (octet_length(session_hash) = 32),
    expires_at TIMESTAMPTZ NOT NULL CHECK (expires_at > created_at),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS user_mfa_bootstrap_sessions_expires_at_idx ON user_mfa_bootstrap_sessions (expires_at);

CREATE TABLE IF NOT EXISTS user_mfa_challenge_sessions (
    id UUID PRIMARY KEY DEFAULT uuidv4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_hash BYTEA NOT NULL UNIQUE CHECK (octet_length(session_hash) = 32),
    expires_at TIMESTAMPTZ NOT NULL CHECK (expires_at > created_at),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS user_mfa_challenge_sessions_expires_at_idx ON user_mfa_challenge_sessions (expires_at);

-- -----------------------------------------------------------------------------
-- TOTP MFA
-- -----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS totp_deks (
    dek_id UUID PRIMARY KEY,
    status TEXT NOT NULL CHECK (status IN ('active', 'decrypt_only', 'retired')),
    wrapped_dek TEXT NOT NULL, -- Vault transit ciphertext
    kek_mount TEXT NOT NULL DEFAULT 'transit/permesi',
    kek_key TEXT NOT NULL DEFAULT 'totp',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    rotated_at TIMESTAMPTZ
);

-- Ensure only one active DEK
CREATE UNIQUE INDEX IF NOT EXISTS totp_deks_active_idx ON totp_deks (status) WHERE status = 'active';

CREATE TABLE IF NOT EXISTS totp_credentials (
    credential_id UUID PRIMARY KEY DEFAULT uuidv4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    label TEXT,
    digits SMALLINT NOT NULL DEFAULT 6,
    period SMALLINT NOT NULL DEFAULT 30,
    algo TEXT NOT NULL DEFAULT 'SHA1',
    dek_id UUID NOT NULL REFERENCES totp_deks(dek_id),
    seed_ciphertext BYTEA NOT NULL, -- nonce (12 bytes) + ciphertext
    confirmed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_totp_credentials_user ON totp_credentials (user_id);

-- One active confirmed credential per user
CREATE UNIQUE INDEX IF NOT EXISTS idx_totp_credentials_active_confirmed
ON totp_credentials (user_id)
WHERE confirmed_at IS NOT NULL;

-- One active pending enrollment per user (prevents flooding)
CREATE UNIQUE INDEX IF NOT EXISTS idx_totp_credentials_active_pending
ON totp_credentials (user_id)
WHERE confirmed_at IS NULL;

CREATE TABLE IF NOT EXISTS totp_audit_log (
    id UUID PRIMARY KEY DEFAULT uuidv4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id UUID REFERENCES totp_credentials(credential_id) ON DELETE SET NULL,
    action TEXT NOT NULL, -- enroll, confirm, verify_success, verify_failure, lockout
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_totp_audit_user_time ON totp_audit_log (user_id, created_at);

-- -----------------------------------------------------------------------------
-- Security Keys (WebAuthn)
-- -----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS security_keys (
    credential_id BYTEA PRIMARY KEY, -- WebAuthn Credential ID
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    label TEXT NOT NULL,
    public_key BYTEA NOT NULL,
    sign_count BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_security_keys_user ON security_keys (user_id);

CREATE TABLE IF NOT EXISTS security_key_audit_log (
    id UUID PRIMARY KEY DEFAULT uuidv4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id BYTEA REFERENCES security_keys(credential_id) ON DELETE SET NULL,
    action TEXT NOT NULL, -- register, verify_success, verify_failure, delete
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_security_key_audit_user_time ON security_key_audit_log (user_id, created_at);

-- -----------------------------------------------------------------------------
-- Passkeys (WebAuthn)
-- -----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS passkeys (
    credential_id BYTEA PRIMARY KEY, -- WebAuthn Credential ID
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    label TEXT,
    passkey_data BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_passkeys_user ON passkeys (user_id);

CREATE TABLE IF NOT EXISTS passkey_audit_log (
    id UUID PRIMARY KEY DEFAULT uuidv4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id BYTEA REFERENCES passkeys(credential_id) ON DELETE SET NULL,
    action TEXT NOT NULL, -- register, verify_success, verify_failure, delete
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_passkey_audit_user_time ON passkey_audit_log (user_id, created_at);

-- Grant permissions to permesi_runtime
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'permesi_runtime') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE
            oauth_clients, oauth_client_redirect_uris, oauth_scopes,
            oauth_client_scopes, oauth_grants, oauth_grant_scopes,
            oauth_authorization_requests, oauth_authorization_codes TO permesi_runtime;
        GRANT SELECT, INSERT, UPDATE ON TABLE oauth_client_secrets TO permesi_runtime;
        GRANT SELECT, INSERT ON TABLE oauth_token_issuances TO permesi_runtime;
        REVOKE UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER ON TABLE oauth_token_issuances FROM permesi_runtime;
        REVOKE DELETE, TRUNCATE ON TABLE oauth_client_secrets FROM permesi_runtime;
        GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE auth_rate_limits TO permesi_runtime;
        GRANT ALL PRIVILEGES ON TABLE totp_deks TO permesi_runtime;
        GRANT ALL PRIVILEGES ON TABLE totp_credentials TO permesi_runtime;
        GRANT ALL PRIVILEGES ON TABLE totp_audit_log TO permesi_runtime;
        GRANT ALL PRIVILEGES ON TABLE security_keys TO permesi_runtime;
        GRANT ALL PRIVILEGES ON TABLE security_key_audit_log TO permesi_runtime;
        GRANT ALL PRIVILEGES ON TABLE passkeys TO permesi_runtime;
        GRANT ALL PRIVILEGES ON TABLE passkey_audit_log TO permesi_runtime;
    END IF;
END $$;
