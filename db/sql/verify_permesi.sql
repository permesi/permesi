-- Permesi schema verification (transactional smoke test).
-- Rolls back all changes so it is safe to run against dev DBs.

BEGIN;

-- Refresh history and only the irreversible transition columns survive bootstrap grants.
DO $$
BEGIN
    IF to_regclass('oauth_refresh_tokens_active_idx') IS NULL OR to_regclass('oauth_refresh_tokens_root_idx') IS NULL THEN
        RAISE EXCEPTION 'missing refresh lineage uniqueness';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='permesi_runtime') THEN
        IF has_table_privilege('permesi_runtime','oauth_refresh_families','UPDATE')
            OR has_table_privilege('permesi_runtime','oauth_refresh_families','DELETE')
            OR has_table_privilege('permesi_runtime','oauth_refresh_families','TRUNCATE')
            OR has_table_privilege('permesi_runtime','oauth_refresh_families','REFERENCES')
            OR has_table_privilege('permesi_runtime','oauth_refresh_families','TRIGGER')
            OR has_table_privilege('permesi_runtime','oauth_refresh_families','MAINTAIN')
            OR has_table_privilege('permesi_runtime','oauth_refresh_tokens','UPDATE')
            OR has_table_privilege('permesi_runtime','oauth_refresh_tokens','DELETE')
            OR has_table_privilege('permesi_runtime','oauth_refresh_tokens','TRUNCATE')
            OR has_table_privilege('permesi_runtime','oauth_refresh_tokens','REFERENCES')
            OR has_table_privilege('permesi_runtime','oauth_refresh_tokens','TRIGGER')
            OR has_table_privilege('permesi_runtime','oauth_refresh_tokens','MAINTAIN')
            OR NOT has_table_privilege('permesi_runtime','oauth_refresh_families','SELECT')
            OR NOT has_table_privilege('permesi_runtime','oauth_refresh_families','INSERT')
            OR NOT has_table_privilege('permesi_runtime','oauth_refresh_tokens','SELECT')
            OR NOT has_table_privilege('permesi_runtime','oauth_refresh_tokens','INSERT')
            OR NOT has_column_privilege('permesi_runtime','oauth_refresh_families','revoked_at','UPDATE')
            OR NOT has_column_privilege('permesi_runtime','oauth_refresh_families','revocation_reason','UPDATE')
            OR NOT has_column_privilege('permesi_runtime','oauth_refresh_tokens','consumed_at','UPDATE') THEN
            RAISE EXCEPTION 'invalid runtime refresh privileges';
        END IF;
    END IF;
END $$;

-- Shared pending admission metadata must remain hash-only and indexed after upgrades.
DO $$
BEGIN
    IF to_regclass('opaque_exchanges_subject_idx') IS NULL OR to_regclass('webauthn_exchanges_subject_idx') IS NULL
        OR NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='opaque_exchanges' AND column_name='subject_tag' AND data_type='bytea')
        OR NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='webauthn_exchanges' AND column_name='subject_tag' AND data_type='bytea') THEN
        RAISE EXCEPTION 'missing authentication subject admission metadata';
    END IF;
END $$;

-- Credential lifecycle backstops must survive schema reapplication and bootstrap grants.
DO $$
DECLARE
    protection text;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_index WHERE indexrelid=to_regclass('oauth_client_secrets_current_idx')
        AND indisunique AND indisvalid AND indpred IS NOT NULL) THEN
        RAISE EXCEPTION 'missing unique current credential index';
    END IF;
    FOREACH protection IN ARRAY ARRAY['protect_oauth_client_secret','initialize_oauth_client_secret','limit_oauth_client_secret_overlap'] LOOP
        IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgrelid='oauth_client_secrets'::regclass
            AND tgname=protection AND tgenabled='O' AND NOT tgisinternal) THEN
            RAISE EXCEPTION 'missing credential protection: %',protection;
        END IF;
    END LOOP;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='permesi_runtime') THEN
        IF NOT has_table_privilege('permesi_runtime','opaque_exchanges','SELECT')
            OR NOT has_table_privilege('permesi_runtime','opaque_exchanges','INSERT')
            OR NOT has_table_privilege('permesi_runtime','opaque_exchanges','DELETE')
            OR has_table_privilege('permesi_runtime','opaque_exchanges','UPDATE')
            OR has_table_privilege('permesi_runtime','opaque_exchanges','TRUNCATE')
            OR has_table_privilege('permesi_runtime','opaque_exchanges','REFERENCES')
            OR has_table_privilege('permesi_runtime','opaque_exchanges','TRIGGER')
            OR has_table_privilege('permesi_runtime','opaque_exchanges','MAINTAIN') THEN
            RAISE EXCEPTION 'invalid runtime OPAQUE exchange privileges';
        END IF;
        IF has_table_privilege('permesi_runtime','oauth_token_issuances','UPDATE')
            OR has_table_privilege('permesi_runtime','oauth_token_issuances','DELETE')
            OR has_table_privilege('permesi_runtime','oauth_token_issuances','TRUNCATE')
            OR has_table_privilege('permesi_runtime','oauth_token_issuances','REFERENCES')
            OR has_table_privilege('permesi_runtime','oauth_token_issuances','TRIGGER')
            OR NOT has_table_privilege('permesi_runtime','oauth_token_issuances','SELECT')
            OR NOT has_table_privilege('permesi_runtime','oauth_token_issuances','INSERT') THEN
            RAISE EXCEPTION 'invalid runtime token receipt privileges';
        END IF;
        IF has_table_privilege('permesi_runtime','oauth_client_secrets','DELETE')
            OR has_table_privilege('permesi_runtime','oauth_client_secrets','TRUNCATE') THEN
            RAISE EXCEPTION 'runtime role may erase credential revocation history';
        END IF;
    END IF;
END $$;

-- Durable WebAuthn state cannot be rewritten by the runtime role.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='permesi_runtime') THEN
        IF NOT has_table_privilege('permesi_runtime','webauthn_exchanges','SELECT')
            OR NOT has_table_privilege('permesi_runtime','webauthn_exchanges','INSERT')
            OR NOT has_table_privilege('permesi_runtime','webauthn_exchanges','DELETE')
            OR has_table_privilege('permesi_runtime','webauthn_exchanges','UPDATE')
            OR has_table_privilege('permesi_runtime','webauthn_exchanges','TRUNCATE')
            OR has_table_privilege('permesi_runtime','webauthn_exchanges','REFERENCES')
            OR has_table_privilege('permesi_runtime','webauthn_exchanges','TRIGGER')
            OR has_table_privilege('permesi_runtime','webauthn_exchanges','MAINTAIN') THEN
            RAISE EXCEPTION 'invalid runtime WebAuthn exchange privileges';
        END IF;
    END IF;
    INSERT INTO webauthn_exchanges (id_hash,purpose,origin,rp_id,sealed_state,created_at,expires_at)
    VALUES (decode(repeat('b1',32),'hex'),'passkey_login','https://example.com','example.com',decode(repeat('00',40),'hex'),NOW(),NOW()+INTERVAL '5 minutes');
    BEGIN
        UPDATE webauthn_exchanges SET purpose='security_key_authentication' WHERE id_hash=decode(repeat('b1',32),'hex');
        RAISE EXCEPTION 'expected WebAuthn ceremony authority constraint';
    EXCEPTION WHEN check_violation THEN NULL; END;
    BEGIN
        UPDATE webauthn_exchanges SET expires_at=created_at+INTERVAL '2 hours' WHERE id_hash=decode(repeat('b1',32),'hex');
        RAISE EXCEPTION 'expected bounded WebAuthn TTL';
    EXCEPTION WHEN check_violation THEN NULL; END;
END $$;

-- Exchange rows are transient and bounded; application crypto authenticates their contents.
DO $$
DECLARE
    identifier bytea := decode(repeat('a1',32),'hex');
BEGIN
    INSERT INTO opaque_exchanges (id_hash,purpose,sealed_state,created_at,expires_at)
    VALUES (identifier,'login',decode(repeat('00',41),'hex'),NOW(),NOW()+INTERVAL '5 minutes');
    BEGIN
        UPDATE opaque_exchanges SET expires_at=created_at WHERE id_hash=identifier;
        RAISE EXCEPTION 'expected positive exchange TTL constraint';
    EXCEPTION WHEN check_violation THEN NULL; END;
    BEGIN
        UPDATE opaque_exchanges SET expires_at=created_at+INTERVAL '2 hours' WHERE id_hash=identifier;
        RAISE EXCEPTION 'expected bounded exchange TTL constraint';
    EXCEPTION WHEN check_violation THEN NULL; END;
    BEGIN
        UPDATE opaque_exchanges SET purpose='reauth' WHERE id_hash=identifier;
        RAISE EXCEPTION 'expected verified reauthentication binding constraint';
    EXCEPTION WHEN check_violation THEN NULL; END;
    BEGIN
        UPDATE opaque_exchanges SET credential_hash=identifier WHERE id_hash=identifier;
        RAISE EXCEPTION 'expected paired user and credential binding constraint';
    EXCEPTION WHEN check_violation THEN NULL; END;
    BEGIN
        UPDATE opaque_exchanges SET sealed_state=decode('00','hex') WHERE id_hash=identifier;
        RAISE EXCEPTION 'expected sealed state length constraint';
    EXCEPTION WHEN check_violation THEN NULL; END;
    BEGIN
        UPDATE opaque_exchanges SET sealed_state=decode(repeat('00',40),'hex') WHERE id_hash=identifier;
        RAISE EXCEPTION 'expected v2 nonce/tag/nonempty ciphertext constraint';
    EXCEPTION WHEN check_violation THEN NULL; END;
    BEGIN
        INSERT INTO opaque_exchanges (id_hash,purpose,sealed_state,created_at,expires_at)
        VALUES (decode('00','hex'),'login',decode(repeat('00',41),'hex'),NOW(),NOW()+INTERVAL '5 minutes');
        RAISE EXCEPTION 'expected reference hash length constraint';
    EXCEPTION WHEN check_violation THEN NULL; END;
    DELETE FROM opaque_exchanges WHERE id_hash=identifier;
END $$;

-- Constraint checks live inside a DO block so we can assert failures explicitly.
DO $$
DECLARE
    v_user_id uuid := uuidv4();
    v_op_id uuid := uuidv4();
    suffix text := substr(replace(uuidv4()::text, '-', ''), 1, 8);
    bad_email text := 'owner-' || substr(replace(uuidv4()::text, '-', ''), 1, 8) || '@example.com';
    org_id uuid := uuidv4();
    org_id_reuse uuid := uuidv4();
    org_slug text := 'org-' || substr(replace(uuidv4()::text, '-', ''), 1, 12);
    project_id uuid := uuidv4();
    project_id_reuse uuid := uuidv4();
    sibling_project_id uuid := uuidv4();
    other_org_id uuid := uuidv4();
    other_project_id uuid := uuidv4();
    project_slug text := 'proj-' || substr(replace(uuidv4()::text, '-', ''), 1, 12);
    env_id uuid := uuidv4();
    env_id_reuse uuid := uuidv4();
    env_slug text := 'prod-' || substr(replace(uuidv4()::text, '-', ''), 1, 12);
    app_id uuid := uuidv4();
    app_id_reuse uuid := uuidv4();
    app_name text := 'app-' || substr(replace(uuidv4()::text, '-', ''), 1, 12);
BEGIN
    -- Users: lowercase enforcement + basic insert.
    INSERT INTO users (id, email, opaque_registration_record, status)
    VALUES (v_user_id, 'owner-' || suffix || '@example.com', decode('00', 'hex'), 'active');

    -- Ensure users.updated_at advances only when tracked fields change.
    PERFORM pg_sleep(0.001);
    UPDATE users
    SET display_name = 'Owner ' || suffix
    WHERE id = v_user_id;

    PERFORM 1
    FROM users
    WHERE id = v_user_id
      AND updated_at > created_at;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'expected users.updated_at to advance on tracked field updates';
    END IF;

    -- Reject uppercase email normalization (users.email).
    BEGIN
        INSERT INTO users (id, email, opaque_registration_record)
        VALUES (uuidv4(), upper(bad_email), decode('00', 'hex'));
        RAISE EXCEPTION 'expected lowercase email check to fail';
    EXCEPTION WHEN check_violation THEN
        -- expected
    END;

    -- Platform Operators: basic insert + enabled default + cascade delete.
    INSERT INTO users (id, email, opaque_registration_record, status)
    VALUES (v_op_id, 'operator-' || suffix || '@example.com', decode('00', 'hex'), 'active');

    INSERT INTO platform_operators (user_id, note)
    VALUES (v_op_id, 'Initial operator');

    PERFORM 1 FROM platform_operators WHERE user_id = v_op_id AND enabled = TRUE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'expected platform_operator to be enabled by default';
    END IF;

    -- Orgs: active slug uniqueness + soft-delete reuse.
    INSERT INTO organizations (id, slug, name, created_by)
    VALUES (org_id, org_slug, 'Acme', v_user_id);

    -- Reject blank organization name.
    BEGIN
        INSERT INTO organizations (id, slug, name, created_by)
        VALUES (uuidv4(), org_slug || '-blank', '', v_user_id);
        RAISE EXCEPTION 'expected organization name non-empty check to fail';
    EXCEPTION WHEN check_violation THEN
        -- expected
    END;

    -- Reject duplicate active org slug.
    BEGIN
        INSERT INTO organizations (id, slug, name, created_by)
        VALUES (uuidv4(), org_slug, 'Acme Duplicate', v_user_id);
        RAISE EXCEPTION 'expected active org slug uniqueness to fail';
    EXCEPTION WHEN unique_violation THEN
        -- expected
    END;

    -- Reject duplicate org name for the same creator.
    BEGIN
        INSERT INTO organizations (id, slug, name, created_by)
        VALUES (uuidv4(), org_slug || '-dup', 'Acme', v_user_id);
        RAISE EXCEPTION 'expected creator+name uniqueness to fail';
    EXCEPTION WHEN unique_violation THEN
        -- expected
    END;

    UPDATE organizations SET deleted_at = NOW() WHERE id = org_id;
    INSERT INTO organizations (id, slug, name, created_by)
    VALUES (org_id_reuse, org_slug, 'Acme Reuse', v_user_id);

    -- Different creator CAN have the same org name.
    INSERT INTO organizations (id, slug, name, created_by)
    VALUES (uuidv4(), org_slug || '-other', 'Acme Reuse', v_op_id);

    -- Memberships: enum enforcement + updated_at bump + FK behavior.
    INSERT INTO org_memberships (org_id, user_id, status)
    VALUES (org_id_reuse, v_user_id, 'invited'::org_membership_status);

    -- Ensure updated_at advances on status change.
    PERFORM pg_sleep(0.001);
    UPDATE org_memberships
    SET status = 'active'::org_membership_status
    WHERE org_memberships.org_id = org_id_reuse
      AND org_memberships.user_id = v_user_id;

    PERFORM 1
    FROM org_memberships
    WHERE org_memberships.org_id = org_id_reuse
      AND org_memberships.user_id = v_user_id
      AND updated_at > created_at;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'expected org_memberships.updated_at to advance on status change';
    END IF;

    -- Reject invalid membership status enum value.
    BEGIN
        INSERT INTO org_memberships (org_id, user_id, status)
        VALUES (org_id_reuse, uuidv4(), 'actve'::org_membership_status);
        RAISE EXCEPTION 'expected invalid enum value to fail';
    EXCEPTION WHEN invalid_text_representation THEN
        -- expected
    END;

    -- Org roles: slug format constraint + member-role FK.
    INSERT INTO org_roles (org_id, name) VALUES (org_id_reuse, 'owner');

    -- Reject role names that are not lowercase slugs.
    BEGIN
        INSERT INTO org_roles (org_id, name) VALUES (org_id_reuse, 'Admin');
        RAISE EXCEPTION 'expected invalid role name to fail';
    EXCEPTION WHEN check_violation THEN
        -- expected
    END;

    -- Reject member-role assignment when role does not exist.
    BEGIN
        INSERT INTO org_member_roles (org_id, user_id, role_name)
        VALUES (org_id_reuse, v_user_id, 'missing');
        RAISE EXCEPTION 'expected org_member_roles FK to fail';
    EXCEPTION WHEN foreign_key_violation THEN
        -- expected
    END;

    -- Projects: active slug uniqueness + soft-delete reuse.
    INSERT INTO projects (id, org_id, slug, name)
    VALUES (project_id, org_id_reuse, project_slug, 'Payments');

    -- Reject blank project name.
    BEGIN
        INSERT INTO projects (id, org_id, slug, name)
        VALUES (uuidv4(), org_id_reuse, project_slug || '-blank', '');
        RAISE EXCEPTION 'expected project name non-empty check to fail';
    EXCEPTION WHEN check_violation THEN
        -- expected
    END;

    -- Reject duplicate active project slug within org.
    BEGIN
        INSERT INTO projects (id, org_id, slug, name)
        VALUES (uuidv4(), org_id_reuse, project_slug, 'Payments Duplicate');
        RAISE EXCEPTION 'expected active project slug uniqueness to fail';
    EXCEPTION WHEN unique_violation THEN
        -- expected
    END;

    UPDATE projects SET deleted_at = NOW() WHERE id = project_id;
    INSERT INTO projects (id, org_id, slug, name)
    VALUES (project_id_reuse, org_id_reuse, project_slug, 'Payments Reuse');

    -- Independent sibling environments: non-production can exist without production.
    INSERT INTO environments (project_id, slug, name, tier)
    VALUES (project_id_reuse, 'dev', 'Development', 'non_production'),
           (project_id_reuse, 'staging', 'Staging', 'non_production');

    PERFORM 1 FROM environments e
    WHERE e.project_id = project_id_reuse AND e.tier = 'production' AND e.deleted_at IS NULL;
    IF FOUND THEN
        RAISE EXCEPTION 'expected non-production siblings without production';
    END IF;

    -- Production may be added later; the partial unique index limits active rows.
    INSERT INTO environments (id, project_id, slug, name, tier)
    VALUES (env_id, project_id_reuse, env_slug, 'Production', 'production');

    INSERT INTO environments (project_id, slug, name, tier)
    VALUES (project_id_reuse, 'qa', 'QA', 'non_production');

    -- The production slot belongs to a project, not its organization or another tenant.
    INSERT INTO projects (id, org_id, slug, name)
    VALUES (sibling_project_id, org_id_reuse, project_slug || '-other', 'Other Project');
    INSERT INTO environments (project_id, slug, name, tier)
    VALUES (sibling_project_id, 'production', 'Production', 'production');

    INSERT INTO organizations (id, slug, name, created_by)
    VALUES (other_org_id, org_slug || '-env-other', 'Other Organization', v_user_id);
    INSERT INTO projects (id, org_id, slug, name)
    VALUES (other_project_id, other_org_id, project_slug, 'Other Tenant Project');
    INSERT INTO environments (project_id, slug, name, tier)
    VALUES (other_project_id, 'production', 'Production', 'production');

    -- Reject blank environment name.
    BEGIN
        INSERT INTO environments (id, project_id, slug, name, tier)
        VALUES (uuidv4(), project_id_reuse, env_slug || '-blank', '', 'non_production');
        RAISE EXCEPTION 'expected environment name non-empty check to fail';
    EXCEPTION WHEN check_violation THEN
        -- expected
    END;

    -- Reject second production-tier environment for a project.
    BEGIN
        INSERT INTO environments (id, project_id, slug, name, tier)
        VALUES (uuidv4(), project_id_reuse, 'live', 'Live', 'production');
        RAISE EXCEPTION 'expected single production env to fail';
    EXCEPTION WHEN unique_violation THEN
        -- expected
    END;

    -- Reject duplicate active environment slug within project.
    BEGIN
        INSERT INTO environments (id, project_id, slug, name, tier)
        VALUES (uuidv4(), project_id_reuse, env_slug, 'Dup', 'non_production');
        RAISE EXCEPTION 'expected active env slug uniqueness to fail';
    EXCEPTION WHEN unique_violation THEN
        -- expected
    END;

    UPDATE environments SET deleted_at = NOW() WHERE id = env_id;
    INSERT INTO environments (id, project_id, slug, name, tier)
    VALUES (env_id_reuse, project_id_reuse, env_slug, 'Production Reuse', 'production');

    -- Applications: active name uniqueness + soft-delete reuse.
    INSERT INTO applications (id, environment_id, name)
    VALUES (app_id, env_id_reuse, app_name);

    -- Reject blank application name.
    BEGIN
        INSERT INTO applications (id, environment_id, name)
        VALUES (uuidv4(), env_id_reuse, '');
        RAISE EXCEPTION 'expected application name non-empty check to fail';
    EXCEPTION WHEN check_violation THEN
        -- expected
    END;

    -- Reject duplicate active application name within environment.
    BEGIN
        INSERT INTO applications (id, environment_id, name)
        VALUES (uuidv4(), env_id_reuse, app_name);
        RAISE EXCEPTION 'expected active app name uniqueness to fail';
    EXCEPTION WHEN unique_violation THEN
        -- expected
    END;

    UPDATE applications SET deleted_at = NOW() WHERE id = app_id;
    INSERT INTO applications (id, environment_id, name)
    VALUES (app_id_reuse, env_id_reuse, app_name);

    -- Hash length checks + timestamp ordering constraints.
    -- Reject session hashes with incorrect length.
    BEGIN
        INSERT INTO user_sessions (id, user_id, session_hash, expires_at)
        VALUES (uuidv4(), v_user_id, decode('00', 'hex'), NOW() + INTERVAL '1 hour');
        RAISE EXCEPTION 'expected session hash length check to fail';
    EXCEPTION WHEN check_violation THEN
        -- expected
    END;

    INSERT INTO user_sessions (id, user_id, session_hash, expires_at)
    VALUES (
        uuidv4(),
        v_user_id,
        decode(repeat('00', 32), 'hex'),
        NOW() + INTERVAL '1 hour'
    );

    -- Reject sessions that expire at or before creation time.
    BEGIN
        INSERT INTO user_sessions (id, user_id, session_hash, created_at, expires_at)
        VALUES (
            uuidv4(),
            v_user_id,
            decode(repeat('00', 32), 'hex'),
            NOW(),
            NOW()
        );
        RAISE EXCEPTION 'expected expires_at > created_at check to fail';
    EXCEPTION WHEN check_violation THEN
        -- expected
    END;

    -- Reject last_seen_at earlier than created_at.
    BEGIN
        INSERT INTO user_sessions (id, user_id, session_hash, created_at, expires_at, last_seen_at)
        VALUES (
            uuidv4(),
            v_user_id,
            decode(repeat('00', 32), 'hex'),
            NOW(),
            NOW() + INTERVAL '1 hour',
            NOW() - INTERVAL '1 minute'
        );
        RAISE EXCEPTION 'expected last_seen_at >= created_at check to fail';
    EXCEPTION WHEN check_violation THEN
        -- expected
    END;

    -- Reject auth_time earlier than created_at.
    BEGIN
        INSERT INTO user_sessions (id, user_id, session_hash, created_at, auth_time, expires_at)
        VALUES (
            uuidv4(),
            v_user_id,
            decode(repeat('01', 32), 'hex'),
            NOW(),
            NOW() - INTERVAL '1 minute',
            NOW() + INTERVAL '1 hour'
        );
        RAISE EXCEPTION 'expected auth_time >= created_at check to fail';
    EXCEPTION WHEN check_violation THEN
        -- expected
    END;

    -- Reject verification token hashes that are too short.
    BEGIN
        INSERT INTO email_verification_tokens (id, user_id, token_hash, expires_at)
        VALUES (uuidv4(), v_user_id, decode('00', 'hex'), NOW() + INTERVAL '1 hour');
        RAISE EXCEPTION 'expected token hash length check to fail';
    EXCEPTION WHEN check_violation THEN
        -- expected
    END;

    INSERT INTO email_verification_tokens (id, user_id, token_hash, expires_at)
    VALUES (
        uuidv4(),
        v_user_id,
        decode(repeat('00', 32), 'hex'),
        NOW() + INTERVAL '1 hour'
    );

    -- Reject verification tokens that expire at or before creation time.
    BEGIN
        INSERT INTO email_verification_tokens (id, user_id, token_hash, created_at, expires_at)
        VALUES (
            uuidv4(),
            v_user_id,
            decode(repeat('00', 32), 'hex'),
            NOW(),
            NOW()
        );
        RAISE EXCEPTION 'expected token expires_at > created_at check to fail';
    EXCEPTION WHEN check_violation THEN
        -- expected
    END;

    -- Reject consumed_at earlier than created_at.
    BEGIN
        INSERT INTO email_verification_tokens (id, user_id, token_hash, created_at, expires_at, consumed_at)
        VALUES (
            uuidv4(),
            v_user_id,
            decode(repeat('00', 32), 'hex'),
            NOW(),
            NOW() + INTERVAL '1 hour',
            NOW() - INTERVAL '1 minute'
        );
        RAISE EXCEPTION 'expected consumed_at >= created_at check to fail';
    EXCEPTION WHEN check_violation THEN
        -- expected
    END;

    -- Email outbox: lowercase enforcement + timestamps + attempts bound.
    INSERT INTO email_outbox (id, to_email, template, payload_json)
    VALUES (uuidv4(), 'notify-' || suffix || '@example.com', 'verify', '{}'::jsonb);

    -- Reject uppercase to_email in outbox entries.
    BEGIN
        INSERT INTO email_outbox (id, to_email, template, payload_json)
        VALUES (uuidv4(), upper('notify-' || suffix || '@example.com'), 'verify', '{}'::jsonb);
        RAISE EXCEPTION 'expected email_outbox to_email lowercase check to fail';
    EXCEPTION WHEN check_violation THEN
        -- expected
    END;

    -- Reject sent_at earlier than created_at.
    BEGIN
        INSERT INTO email_outbox (id, to_email, template, payload_json, created_at, sent_at)
        VALUES (
            uuidv4(),
            'notify-' || suffix || '@example.com',
            'verify',
            '{}'::jsonb,
            NOW(),
            NOW() - INTERVAL '1 minute'
        );
        RAISE EXCEPTION 'expected email_outbox sent_at >= created_at check to fail';
    EXCEPTION WHEN check_violation THEN
        -- expected
    END;

    -- Reject attempts above the allowed max.
    BEGIN
        INSERT INTO email_outbox (id, to_email, template, payload_json, attempts)
        VALUES (
            uuidv4(),
            'notify-' || suffix || '@example.com',
            'verify',
            '{}'::jsonb,
            101
        );
        RAISE EXCEPTION 'expected email_outbox attempts max check to fail';
    EXCEPTION WHEN check_violation THEN
        -- expected
    END;

    -- Cleanup function should delete expired rows and retain active rows.
    INSERT INTO user_sessions (id, user_id, session_hash, created_at, expires_at)
    VALUES (
        uuidv4(),
        v_user_id,
        decode(repeat('02', 32), 'hex'),
        NOW() - INTERVAL '9 days',
        NOW() - INTERVAL '8 days'
    );

    INSERT INTO user_sessions (id, user_id, session_hash, created_at, expires_at)
    VALUES (
        uuidv4(),
        v_user_id,
        decode(repeat('03', 32), 'hex'),
        NOW() - INTERVAL '1 hour',
        NOW() + INTERVAL '1 hour'
    );

    INSERT INTO email_verification_tokens (id, user_id, token_hash, created_at, expires_at)
    VALUES (
        uuidv4(),
        v_user_id,
        decode(repeat('04', 32), 'hex'),
        NOW() - INTERVAL '9 days',
        NOW() - INTERVAL '8 days'
    );

    INSERT INTO email_verification_tokens (id, user_id, token_hash, created_at, expires_at)
    VALUES (
        uuidv4(),
        v_user_id,
        decode(repeat('05', 32), 'hex'),
        NOW() - INTERVAL '1 hour',
        NOW() + INTERVAL '1 hour'
    );

    INSERT INTO admin_attempts (id, user_id, ip_address, created_at)
    VALUES (uuidv4(), v_user_id, '203.0.113.10', NOW() - INTERVAL '2 days');

    INSERT INTO admin_attempts (id, user_id, ip_address, created_at)
    VALUES (uuidv4(), v_user_id, '203.0.113.11', NOW() - INTERVAL '1 hour');

    INSERT INTO auth_rate_limits (dimension, subject_hash, action, attempts, expires_at)
    VALUES ('ip', decode(repeat('06', 32), 'hex'), 'login', 3, NOW() - INTERVAL '1 hour');

    INSERT INTO auth_rate_limits (dimension, subject_hash, action, attempts, expires_at)
    VALUES ('ip', decode(repeat('07', 32), 'hex'), 'login', 2, NOW() + INTERVAL '1 hour');

    PERFORM cleanup_expired_tokens();

    PERFORM 1
    FROM user_sessions
    WHERE session_hash = decode(repeat('02', 32), 'hex');
    IF FOUND THEN
        RAISE EXCEPTION 'expected expired user_session to be deleted by cleanup_expired_tokens';
    END IF;

    PERFORM 1
    FROM user_sessions
    WHERE session_hash = decode(repeat('03', 32), 'hex');
    IF NOT FOUND THEN
        RAISE EXCEPTION 'expected active user_session to remain after cleanup_expired_tokens';
    END IF;

    PERFORM 1
    FROM email_verification_tokens
    WHERE token_hash = decode(repeat('04', 32), 'hex');
    IF FOUND THEN
        RAISE EXCEPTION 'expected expired email_verification_token to be deleted by cleanup_expired_tokens';
    END IF;

    PERFORM 1
    FROM email_verification_tokens
    WHERE token_hash = decode(repeat('05', 32), 'hex');
    IF NOT FOUND THEN
        RAISE EXCEPTION 'expected active email_verification_token to remain after cleanup_expired_tokens';
    END IF;

    PERFORM 1
    FROM admin_attempts
    WHERE ip_address = '203.0.113.10';
    IF FOUND THEN
        RAISE EXCEPTION 'expected old admin_attempt to be deleted by cleanup_expired_tokens';
    END IF;

    PERFORM 1
    FROM admin_attempts
    WHERE ip_address = '203.0.113.11';
    IF NOT FOUND THEN
        RAISE EXCEPTION 'expected recent admin_attempt to remain after cleanup_expired_tokens';
    END IF;

    PERFORM 1
    FROM auth_rate_limits
    WHERE subject_hash = decode(repeat('06', 32), 'hex');
    IF FOUND THEN
        RAISE EXCEPTION 'expected expired auth rate limit to be deleted by cleanup_expired_tokens';
    END IF;

    PERFORM 1
    FROM auth_rate_limits
    WHERE subject_hash = decode(repeat('07', 32), 'hex');
    IF NOT FOUND THEN
        RAISE EXCEPTION 'expected active auth rate limit to remain after cleanup_expired_tokens';
    END IF;

    -- Cascade deletions: ensure deleting a user removes their operator record.
    DELETE FROM organizations WHERE created_by = v_op_id;
    DELETE FROM users WHERE id = v_op_id;
    PERFORM 1 FROM platform_operators WHERE user_id = v_op_id;
    IF FOUND THEN
        RAISE EXCEPTION 'expected platform_operator to be deleted via user cascade';
    END IF;
END $$;

ROLLBACK;
