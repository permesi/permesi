-- Validate roles in postgres; transfer only application objects in this dedicated service database's public schema.
-- Run as the bootstrap administrator, inside the bootstrap transaction. Extension
-- members retain extension-managed ownership; system/shared objects are never reassigned.
-- Unexpected owners or privileged runtime roles abort rather than silently retaining authority.
DO $$
DECLARE
    service_owner name;
    runtime_role name;
    owner_id oid;
    runtime_id oid;
    config record;
    item record;
BEGIN
    -- Never invoke application overloads or use owner-controlled database defaults as administrator.
    PERFORM pg_catalog.set_config('search_path','pg_catalog, pg_temp',true);
    IF pg_catalog.current_database() NOT IN ('postgres','genesis','permesi') THEN
        RAISE EXCEPTION 'Ownership bootstrap requires a dedicated service or maintenance database';
    END IF;
    FOR config IN SELECT * FROM (VALUES
        ('genesis','vault_genesis','genesis_runtime'),
        ('permesi','vault_permesi','permesi_runtime')) AS services(database_name,owner_name,runtime_name)
        WHERE pg_catalog.current_database() IN ('postgres',database_name)
    LOOP
        service_owner := config.owner_name;
        runtime_role := config.runtime_name;
        SELECT oid INTO STRICT owner_id FROM pg_catalog.pg_roles WHERE rolname=service_owner;
        SELECT oid INTO STRICT runtime_id FROM pg_catalog.pg_roles WHERE rolname=runtime_role;
        IF pg_catalog.current_database()='postgres' AND EXISTS (
            SELECT 1 FROM pg_catalog.pg_database d JOIN pg_catalog.pg_roles r ON r.oid=d.datdba
            WHERE d.datname=config.database_name AND r.rolname NOT IN (service_owner,current_user,'postgres')) THEN
            RAISE EXCEPTION 'Service database has an unexpected owner';
        END IF;
        IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE oid=owner_id
            AND (rolsuper OR rolbypassrls OR rolreplication OR rolcreatedb OR NOT rolcanlogin OR NOT rolcreaterole)) THEN
            RAISE EXCEPTION 'Vault database roles require non-superuser login and CREATEROLE attributes';
        END IF;
        IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE oid=runtime_id
            AND (rolcanlogin OR rolsuper OR rolcreaterole OR rolcreatedb OR rolreplication OR rolbypassrls))
            OR EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members WHERE member=runtime_id) THEN
            RAISE EXCEPTION 'Runtime role has unexpected attributes or role memberships';
        END IF;
        IF EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members m
            JOIN pg_catalog.pg_roles granted ON granted.oid=m.roleid
            WHERE m.member=owner_id AND m.roleid NOT IN (runtime_id,'pg_signal_backend'::regrole)
            -- CREATEROLE gives Vault ADMIN-only membership in the safe runtime logins it creates.
            AND NOT (m.admin_option AND NOT m.inherit_option AND NOT m.set_option
                AND EXISTS (SELECT 1 FROM pg_catalog.pg_roles grantor
                    WHERE grantor.oid=m.grantor AND grantor.rolsuper)
                AND granted.rolcanlogin AND NOT granted.rolsuper AND NOT granted.rolcreaterole
                AND NOT granted.rolcreatedb AND NOT granted.rolreplication AND NOT granted.rolbypassrls
                AND EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members child
                    WHERE child.member=m.roleid AND child.roleid=runtime_id)
                AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members child
                    WHERE child.member=m.roleid AND child.roleid<>runtime_id))) THEN
            RAISE EXCEPTION 'Vault database owner has unexpected role memberships';
        END IF;
    END LOOP;
    -- The maintenance database pass validates roles before granting any authority.
    IF pg_catalog.current_database()='postgres' THEN RETURN; END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_database
        WHERE datname=pg_catalog.current_database() AND datdba=owner_id) THEN
        RAISE EXCEPTION 'Service database has an unexpected owner';
    END IF;
    EXECUTE pg_catalog.format('ALTER SCHEMA public OWNER TO %I', service_owner);
    REVOKE ALL ON SCHEMA public FROM PUBLIC;
    EXECUTE pg_catalog.format('REVOKE CREATE ON SCHEMA public FROM %I',runtime_role);

    FOR item IN
        SELECT c.oid,c.relname,c.relkind,c.relowner,pg_catalog.pg_get_userbyid(c.relowner) AS old_owner
        FROM pg_catalog.pg_class c WHERE c.relnamespace='public'::regnamespace
        AND c.relkind IN ('r','p','S','v','m')
        AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_depend d
            WHERE d.classid='pg_catalog.pg_class'::regclass AND d.objid=c.oid AND d.deptype='e')
        ORDER BY c.relkind='S',c.oid
    LOOP
        IF item.old_owner NOT IN (service_owner,current_user,'postgres') THEN
            RAISE EXCEPTION 'Application relation has an unexpected owner';
        END IF;
        IF item.relowner<>owner_id THEN
            EXECUTE pg_catalog.format('ALTER %s public.%I OWNER TO %I',
                CASE item.relkind WHEN 'S' THEN 'SEQUENCE' WHEN 'v' THEN 'VIEW'
                    WHEN 'm' THEN 'MATERIALIZED VIEW' ELSE 'TABLE' END,item.relname,service_owner);
        END IF;
    END LOOP;
    FOR item IN
        SELECT p.oid,p.proname,p.proowner,pg_catalog.pg_get_userbyid(p.proowner) AS old_owner,
            pg_catalog.pg_get_function_identity_arguments(p.oid) AS arguments
        FROM pg_catalog.pg_proc p WHERE p.pronamespace='public'::regnamespace
        AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_depend d
            WHERE d.classid='pg_catalog.pg_proc'::regclass AND d.objid=p.oid AND d.deptype='e')
    LOOP
        IF item.old_owner NOT IN (service_owner,current_user,'postgres') THEN
            RAISE EXCEPTION 'Application routine has an unexpected owner';
        END IF;
        IF item.proowner<>owner_id THEN
            EXECUTE pg_catalog.format('ALTER ROUTINE public.%I(%s) OWNER TO %I',item.proname,item.arguments,service_owner);
        END IF;
    END LOOP;
    FOR item IN
        SELECT t.oid,t.typname,t.typowner,pg_catalog.pg_get_userbyid(t.typowner) AS old_owner
        FROM pg_catalog.pg_type t WHERE t.typnamespace='public'::regnamespace AND t.typtype IN ('e','d')
        AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_depend d
            WHERE d.classid='pg_catalog.pg_type'::regclass AND d.objid=t.oid AND d.deptype='e')
    LOOP
        IF item.old_owner NOT IN (service_owner,current_user,'postgres') THEN
            RAISE EXCEPTION 'Application type has an unexpected owner';
        END IF;
        IF item.typowner<>owner_id THEN
            EXECUTE pg_catalog.format('ALTER TYPE public.%I OWNER TO %I',item.typname,service_owner);
        END IF;
    END LOOP;
END $$;
