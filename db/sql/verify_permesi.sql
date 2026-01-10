-- Permesi schema verification (transactional smoke test).
-- Rolls back all changes so it is safe to run against dev DBs.

BEGIN;

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
    EXCEPTION WHEN others THEN
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

    -- Environments: single production tier + slug uniqueness + soft-delete reuse.
    INSERT INTO environments (id, project_id, slug, name, tier)
    VALUES (env_id, project_id_reuse, env_slug, 'Production', 'production');

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

    -- Cascade deletions: ensure deleting a user removes their operator record.
    DELETE FROM organizations WHERE created_by = v_op_id;
    DELETE FROM users WHERE id = v_op_id;
    PERFORM 1 FROM platform_operators WHERE user_id = v_op_id;
    IF FOUND THEN
        RAISE EXCEPTION 'expected platform_operator to be deleted via user cascade';
    END IF;
END $$;

ROLLBACK;
