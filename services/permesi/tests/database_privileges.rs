//! Real PostgreSQL ownership, runtime privilege and retained-history regressions.
//!
//! Flow Overview: run the actual psql bootstrap, repair deliberately broad legacy
//! grants, mint independent runtime identities, and exercise allowed operations and
//! destructive negatives. Dependencies are required: setup errors never count as passes.

use anyhow::{Context, Result, ensure};
use sqlx::{Connection, PgConnection, postgres::PgConnectOptions};
use test_support::{
    postgres::{BootstrapPolicyViolation, PostgresContainer},
    runtime,
};
use uuid::Uuid;

const OWNERSHIP: &str = include_str!("../../../db/sql/bootstrap_ownership.sql");

/// Transport, setup and unrelated SQL failures cannot stand in for the expected policy rejection.
fn policy_rejected(result: Result<()>, expected: BootstrapPolicyViolation) -> Result<()> {
    let error = result
        .err()
        .context("Unsafe policy unexpectedly accepted")?;
    ensure!(
        error.downcast_ref::<BootstrapPolicyViolation>() == Some(&expected),
        "Bootstrap did not reach the expected role-policy rejection"
    );
    Ok(())
}

/// Rejected bootstrap must not add direct authority grants, even when the owner is temporarily a superuser.
async fn owner_lacks_role(admin: &mut PgConnection, role: &str) -> Result<()> {
    let member: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members m
         JOIN pg_catalog.pg_roles r ON r.oid=m.roleid
         WHERE m.member='vault_permesi'::regrole AND r.rolname=$1)",
    )
    .bind(role)
    .fetch_one(admin)
    .await?;
    ensure!(!member, "Rejected bootstrap expanded owner membership");
    Ok(())
}

/// Independent Genesis logins append receipts through owner-created partitions without maintenance access.
#[tokio::test]
async fn genesis_runtime_appends_partitioned_receipts_without_maintenance_authority() -> Result<()>
{
    let (postgres, _) = database().await?;
    let mut admin = PgConnection::connect(&postgres.admin_dsn_for_db("genesis")).await?;
    sqlx::raw_sql("SET ROLE vault_genesis; SELECT public.genesis_tokens_rollover(7,2)")
        .execute(&mut admin)
        .await?;
    sqlx::query("RESET ROLE").execute(&mut admin).await?;
    for _ in 0..3 {
        let name = format!("genesis_runtime_{}", Uuid::new_v4().simple());
        let password = Uuid::new_v4().simple().to_string();
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
            "CREATE ROLE {name} LOGIN PASSWORD '{password}'; GRANT genesis_runtime TO {name};"
        )))
        .execute(&mut admin)
        .await?;
        let options = PgConnectOptions::new()
            .host("127.0.0.1")
            .port(postgres.host_port())
            .database("genesis")
            .username(&name)
            .password(&password);
        let mut connection = PgConnection::connect_with(&options).await?;
        let stored: bool = sqlx::query_scalar(
            "WITH inserted AS (INSERT INTO public.tokens(client_id) VALUES(0) RETURNING tableoid) SELECT tableoid<> 'public.tokens_default'::regclass FROM inserted",
        )
        .fetch_one(&mut connection)
        .await?;
        ensure!(stored, "Receipts must reach owner-created dated partitions");
        for statement in [
            "SELECT public.genesis_tokens_rollover(-100,100)",
            "DELETE FROM public.tokens",
            "TRUNCATE public.tokens CASCADE",
            "SET ROLE vault_genesis",
        ] {
            rejected(
                sqlx::query(statement).execute(&mut connection).await,
                "42501",
            )?;
        }
    }
    Ok(())
}

/// Boots the canonical schema on an owned container and requires the dependency to run.
async fn database() -> Result<(PostgresContainer, PgConnection)> {
    runtime::ensure_container_runtime()
        .context("Database hardening tests require local PostgreSQL containers")?;
    let postgres = PostgresContainer::start("bridge").await?;
    postgres.wait_until_ready().await?;
    postgres.bootstrap().await?;
    let connection = PgConnection::connect(&postgres.admin_dsn_for_db("permesi")).await?;
    Ok((postgres, connection))
}

/// Assert the actual PostgreSQL failure class, excluding unrelated setup and SQL errors.
fn rejected<T>(result: std::result::Result<T, sqlx::Error>, code: &str) -> Result<()> {
    match result {
        Err(sqlx::Error::Database(error)) => ensure!(
            error.code().as_deref() == Some(code),
            "Expected PostgreSQL {code}, received {}",
            error.code().as_deref().unwrap_or("missing")
        ),
        Err(error) => return Err(error.into()),
        Ok(_) => anyhow::bail!("Protected database operation unexpectedly succeeded"),
    }
    Ok(())
}

/// Requires the immutable-binding guard itself, excluding unrelated check and FK failures.
fn consent_rewrite_rejected<T>(result: std::result::Result<T, sqlx::Error>) -> Result<()> {
    match result {
        Err(sqlx::Error::Database(error)) => ensure!(
            error.code().as_deref() == Some("23514")
                && error.message() == "OAuth grant scope bindings are immutable",
            "Expected the immutable consent binding guard"
        ),
        Err(error) => return Err(error.into()),
        Ok(_) => anyhow::bail!("Consent binding rewrite unexpectedly succeeded"),
    }
    Ok(())
}

/// Creates a real login identity; session-user superuser rights cannot mask SET ROLE rejection.
async fn runtime_options(
    postgres: &PostgresContainer,
    admin: &mut PgConnection,
) -> Result<PgConnectOptions> {
    let name = format!("runtime_{}", Uuid::new_v4().simple());
    let password = Uuid::new_v4().simple().to_string();
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
        "CREATE ROLE {name} LOGIN PASSWORD '{password}'; GRANT permesi_runtime TO {name};"
    )))
    .execute(admin)
    .await?;
    Ok(PgConnectOptions::new()
        .host("127.0.0.1")
        .port(postgres.host_port())
        .database("permesi")
        .username(&name)
        .password(&password))
}

/// Reapplication must repair legacy superuser ownership and grants, without touching system catalogs.
#[tokio::test]
async fn bootstrap_repairs_ownership_and_removes_legacy_privileges() -> Result<()> {
    let (postgres, mut admin) = database().await?;
    sqlx::raw_sql("ALTER TABLE public.users OWNER TO postgres;
        ALTER FUNCTION public.cleanup_expired_tokens() OWNER TO postgres;
        GRANT ALL ON ALL TABLES IN SCHEMA public TO permesi_runtime;
        ALTER DEFAULT PRIVILEGES FOR ROLE vault_permesi IN SCHEMA public GRANT ALL ON TABLES TO permesi_runtime;
        ALTER DEFAULT PRIVILEGES FOR ROLE vault_permesi GRANT ALL ON TABLES TO PUBLIC;
        ALTER DEFAULT PRIVILEGES FOR ROLE vault_permesi IN SCHEMA public GRANT ALL ON TABLES TO PUBLIC;
        ALTER DEFAULT PRIVILEGES FOR ROLE vault_permesi GRANT ALL ON SEQUENCES TO PUBLIC;
        ALTER DEFAULT PRIVILEGES FOR ROLE vault_permesi IN SCHEMA public GRANT ALL ON SEQUENCES TO PUBLIC;")
        .execute(&mut admin).await?;
    postgres.bootstrap().await?;
    let safe: bool=sqlx::query_scalar("SELECT
        (SELECT relowner='vault_permesi'::regrole FROM pg_catalog.pg_class WHERE oid='public.users'::regclass)
        AND (SELECT proowner='vault_permesi'::regrole FROM pg_catalog.pg_proc WHERE oid='public.cleanup_expired_tokens()'::regprocedure)
        AND (SELECT NOT rolsuper FROM pg_catalog.pg_roles WHERE rolname='vault_permesi')
        AND (SELECT relowner='postgres'::regrole FROM pg_catalog.pg_class WHERE oid='pg_catalog.pg_class'::regclass)
        AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class c,unnest(ARRAY['TRUNCATE','REFERENCES','TRIGGER','MAINTAIN']) p
            WHERE c.relnamespace='public'::regnamespace AND c.relkind IN ('r','p') AND has_table_privilege('permesi_runtime',c.oid,p))")
        .fetch_one(&mut admin).await?;
    ensure!(
        safe,
        "Bootstrap retained unsafe ownership or runtime maintenance authority"
    );
    sqlx::raw_sql("SET ROLE vault_permesi; CREATE TABLE public.future_privilege_probe(id INTEGER); CREATE SEQUENCE public.future_sequence_probe; RESET ROLE;")
        .execute(&mut admin).await?;
    let implicit: bool=sqlx::query_scalar("SELECT has_table_privilege('permesi_runtime','public.future_privilege_probe','SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER,MAINTAIN') OR has_sequence_privilege('permesi_runtime','public.future_sequence_probe','USAGE,SELECT,UPDATE')")
        .fetch_one(&mut admin).await?;
    ensure!(
        !implicit,
        "Future tables must require an explicit runtime privilege migration"
    );
    for database in ["genesis", "permesi"] {
        let mut connection = PgConnection::connect(&postgres.admin_dsn_for_db(database)).await?;
        let wrong:i64=sqlx::query_scalar("SELECT count(*) FROM pg_catalog.pg_class c JOIN pg_catalog.pg_roles r ON r.oid=c.relowner WHERE c.relnamespace='public'::regnamespace AND c.relkind IN ('r','p','S') AND (r.rolsuper OR r.rolname<>('vault_'||current_database()))")
            .fetch_one(&mut connection).await?;
        ensure!(
            wrong == 0,
            "Service relations must have verified non-superuser ownership"
        );
    }
    Ok(())
}

/// Dangerous role attributes and owner memberships fail the ownership check before granting authority.
#[tokio::test]
async fn bootstrap_rejects_privileged_runtime_roles_and_foreign_objects() -> Result<()> {
    let (postgres, mut admin) = database().await?;
    for mutation in [
        "ALTER ROLE permesi_runtime CREATEROLE",
        "GRANT pg_read_all_data TO permesi_runtime",
        "ALTER ROLE vault_permesi SUPERUSER",
        "GRANT pg_write_server_files TO vault_permesi",
        "GRANT genesis_runtime TO vault_permesi",
    ] {
        let mut transaction = admin.begin().await?;
        sqlx::query(mutation).execute(&mut *transaction).await?;
        rejected(
            sqlx::raw_sql(OWNERSHIP).execute(&mut *transaction).await,
            "P0001",
        )?;
        transaction.rollback().await?;
    }
    sqlx::raw_sql("CREATE ROLE foreign_schema_owner NOLOGIN; CREATE TABLE public.foreign_probe(id INTEGER); ALTER TABLE public.foreign_probe OWNER TO foreign_schema_owner;")
        .execute(&mut admin).await?;
    rejected(sqlx::raw_sql(OWNERSHIP).execute(&mut admin).await, "P0001")?;
    sqlx::query("DROP TABLE public.foreign_probe")
        .execute(&mut admin)
        .await?;
    for (mutation, restore, expected) in [
        (
            "ALTER ROLE vault_permesi SUPERUSER",
            "ALTER ROLE vault_permesi NOSUPERUSER",
            BootstrapPolicyViolation::OwnerAttributes,
        ),
        (
            "GRANT pg_write_server_files TO vault_permesi",
            "REVOKE pg_write_server_files FROM vault_permesi",
            BootstrapPolicyViolation::OwnerMemberships,
        ),
        (
            "GRANT genesis_runtime TO vault_permesi",
            "REVOKE genesis_runtime FROM vault_permesi",
            BootstrapPolicyViolation::OwnerMemberships,
        ),
    ] {
        sqlx::query("REVOKE pg_signal_backend FROM vault_permesi")
            .execute(&mut admin)
            .await?;
        sqlx::query(mutation).execute(&mut admin).await?;
        policy_rejected(postgres.bootstrap().await, expected)?;
        owner_lacks_role(&mut admin, "pg_signal_backend").await?;
        sqlx::query(restore).execute(&mut admin).await?;
        postgres.bootstrap().await?;
    }
    sqlx::raw_sql(
        "REVOKE permesi_runtime,pg_signal_backend FROM vault_permesi;
        ALTER ROLE permesi_runtime CREATEROLE;",
    )
    .execute(&mut admin)
    .await?;
    policy_rejected(
        postgres.bootstrap().await,
        BootstrapPolicyViolation::RuntimeRole,
    )?;
    owner_lacks_role(&mut admin, "permesi_runtime").await?;
    owner_lacks_role(&mut admin, "pg_signal_backend").await?;
    sqlx::query("ALTER ROLE permesi_runtime NOCREATEROLE")
        .execute(&mut admin)
        .await?;
    postgres.bootstrap().await?;
    Ok(())
}

/// Hostile owner overloads, database settings and RESET ROLE triggers never regain administrator authority.
#[tokio::test]
async fn bootstrap_reapplication_never_executes_owner_code_as_administrator() -> Result<()> {
    let (postgres, mut admin) = database().await?;
    let password = Uuid::new_v4().simple().to_string();
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "ALTER ROLE vault_permesi PASSWORD '{password}'"
    )))
    .execute(&mut admin)
    .await?;
    let options = PgConnectOptions::new()
        .host("127.0.0.1")
        .port(postgres.host_port())
        .database("permesi")
        .username("vault_permesi")
        .password(&password);
    let mut owner = PgConnection::connect_with(&options).await?;
    sqlx::raw_sql("CREATE TABLE public.bootstrap_identity_probe(actor NAME NOT NULL);
        CREATE FUNCTION public.pg_advisory_xact_lock(INTEGER) RETURNS VOID LANGUAGE plpgsql AS $$
            BEGIN RESET ROLE; INSERT INTO public.bootstrap_identity_probe VALUES(current_user); END $$;
        CREATE FUNCTION public.format(template TEXT,object_name NAME) RETURNS TEXT LANGUAGE plpgsql AS $$
            BEGIN RESET ROLE; INSERT INTO public.bootstrap_identity_probe VALUES(current_user);
                RETURN pg_catalog.format(template,object_name); END $$;
        CREATE FUNCTION public.capture_bootstrap_actor() RETURNS TRIGGER LANGUAGE plpgsql AS $$
            BEGIN RESET ROLE; INSERT INTO public.bootstrap_identity_probe VALUES(current_user); RETURN NULL; END $$;
        CREATE TRIGGER capture_bootstrap_actor BEFORE INSERT ON public.roles
            FOR EACH STATEMENT EXECUTE FUNCTION public.capture_bootstrap_actor();
        ALTER DATABASE permesi SET search_path = public, pg_catalog, pg_temp;")
        .execute(&mut owner).await?;
    postgres.bootstrap().await?;
    let safe: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM public.bootstrap_identity_probe)
        AND NOT EXISTS(SELECT 1 FROM public.bootstrap_identity_probe WHERE actor<>'vault_permesi')
        AND NOT (SELECT rolsuper FROM pg_catalog.pg_roles WHERE rolname='vault_permesi')",
    )
    .fetch_one(&mut admin)
    .await?;
    ensure!(
        safe,
        "Owner-controlled bootstrap code restored administrator authority"
    );
    Ok(())
}

/// Runtime sessions can soft-delete tenants, but cannot physically delete their parent resources.
#[tokio::test]
async fn runtime_parent_deletion_and_ddl_are_denied_for_independent_identities() -> Result<()> {
    let (postgres, mut admin) = database().await?;
    for _ in 0..3 {
        let mut runtime =
            PgConnection::connect_with(&runtime_options(&postgres, &mut admin).await?).await?;
        for relation in [
            "organizations",
            "projects",
            "environments",
            "applications",
            "oauth_clients",
            "oauth_grants",
            "oauth_refresh_families",
            "oauth_refresh_tokens",
            "oauth_token_issuances",
        ] {
            rejected(
                sqlx::query(sqlx::AssertSqlSafe(format!(
                    "DELETE FROM public.{relation}"
                )))
                .execute(&mut runtime)
                .await,
                "42501",
            )?;
        }
        for statement in [
            "TRUNCATE public.users CASCADE",
            "ALTER TABLE public.oauth_refresh_tokens DISABLE TRIGGER ALL",
            "CREATE TABLE public.runtime_probe(id INTEGER)",
            "SET ROLE vault_permesi",
        ] {
            rejected(sqlx::query(statement).execute(&mut runtime).await, "42501")?;
        }
        let user = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO public.users(id,email,opaque_registration_record) VALUES($1,$2,$3)",
        )
        .bind(user)
        .bind(format!("runtime-{user}@example.test"))
        .bind(vec![1_u8])
        .execute(&mut runtime)
        .await?;
        sqlx::query("UPDATE public.users SET display_name='Runtime positive control' WHERE id=$1")
            .bind(user)
            .execute(&mut runtime)
            .await?;
        let attempt: Uuid = sqlx::query_scalar(
            "INSERT INTO public.admin_attempts(user_id,is_failure) VALUES($1,TRUE) RETURNING id",
        )
        .bind(user)
        .fetch_one(&mut runtime)
        .await?;
        let successful: bool = sqlx::query_scalar(
            "UPDATE public.admin_attempts SET is_failure=FALSE WHERE id=$1 RETURNING NOT is_failure",
        )
        .bind(attempt)
        .fetch_one(&mut runtime)
        .await?;
        ensure!(
            successful,
            "Successful elevation must clear its failure flag"
        );
        rejected(
            sqlx::query(
                "UPDATE public.admin_attempts SET created_at=clock_timestamp() WHERE id=$1",
            )
            .bind(attempt)
            .execute(&mut runtime)
            .await,
            "42501",
        )?;
        let removed = sqlx::query("DELETE FROM public.users WHERE id=$1")
            .bind(user)
            .execute(&mut runtime)
            .await?;
        ensure!(
            removed.rows_affected() == 1,
            "Unreferenced administrative user deletion must keep working"
        );
        sqlx::query("SELECT public.cleanup_expired_tokens()")
            .execute(&mut runtime)
            .await?;
    }
    Ok(())
}

/// Creates a real consumed OIDC code and validated receipt, without disabling constraints or triggers.
async fn receipt_fixture(admin: &mut PgConnection) -> Result<(Uuid, Uuid)> {
    // The organization creator differs from the subject, so the existing creator FK cannot mask this test.
    let user = Uuid::new_v4();
    let creator = Uuid::new_v4();
    for id in [user, creator] {
        sqlx::query("INSERT INTO users(id,email,opaque_registration_record,status) VALUES($1,$2,$3,'active')")
            .bind(id).bind(format!("subject-{id}@example.test")).bind(vec![1_u8]).execute(&mut *admin).await?;
    }
    let org:Uuid=sqlx::query_scalar("INSERT INTO organizations(slug,name,created_by) VALUES('history-org','History',$1) RETURNING id")
        .bind(creator).fetch_one(&mut *admin).await?;
    sqlx::query("INSERT INTO org_memberships(org_id,user_id,status) VALUES($1,$2,'active')")
        .bind(org)
        .bind(user)
        .execute(&mut *admin)
        .await?;
    let project:Uuid=sqlx::query_scalar("INSERT INTO projects(org_id,slug,name) VALUES($1,'history-project','History') RETURNING id").bind(org).fetch_one(&mut *admin).await?;
    let environment:Uuid=sqlx::query_scalar("INSERT INTO environments(project_id,slug,name) VALUES($1,'history-env','History') RETURNING id").bind(project).fetch_one(&mut *admin).await?;
    let app: Uuid = sqlx::query_scalar(
        "INSERT INTO applications(environment_id,name) VALUES($1,'History') RETURNING id",
    )
    .bind(environment)
    .fetch_one(&mut *admin)
    .await?;
    let client:Uuid=sqlx::query_scalar("INSERT INTO oauth_clients(application_id,name,client_type) VALUES($1,'History','public') RETURNING id").bind(app).fetch_one(&mut *admin).await?;
    sqlx::query("INSERT INTO oauth_client_redirect_uris(client_id,redirect_uri) VALUES($1,'https://client.example/callback')").bind(client).execute(&mut *admin).await?;
    let grant:Uuid=sqlx::query_scalar("INSERT INTO oauth_grants(user_id,client_id,application_id,organization_id) VALUES($1,$2,$3,$4) RETURNING id").bind(user).bind(client).bind(app).bind(org).fetch_one(&mut *admin).await?;
    let scope: Uuid =
        sqlx::query_scalar("SELECT id FROM oauth_scopes WHERE application_id=$1 AND name='openid'")
            .bind(app)
            .fetch_one(&mut *admin)
            .await?;
    let offline: Uuid = sqlx::query_scalar(
        "SELECT id FROM oauth_scopes WHERE application_id=$1 AND name='offline_access'",
    )
    .bind(app)
    .fetch_one(&mut *admin)
    .await?;
    let request:Uuid=sqlx::query_scalar("INSERT INTO oauth_authorization_requests(client_id,application_id,organization_id,user_id,session_hash,redirect_uri,scope_ids,scope_names,code_challenge,prompt,nonce,issuer,audience,browser_hash,expires_at) VALUES($1,$2,$3,$4,decode(repeat('11',32),'hex'),'https://client.example/callback',ARRAY[$5,$6],ARRAY['openid','offline_access'],repeat('A',43),'consent','nonce','https://issuer.example','resource',decode(repeat('22',32),'hex'),statement_timestamp()+INTERVAL '5 minutes') RETURNING id")
        .bind(client).bind(app).bind(org).bind(user).bind(scope).bind(offline).fetch_one(&mut *admin).await?;
    sqlx::query("INSERT INTO oauth_authorization_codes(code_hash,request_id,grant_id,client_id,application_id,organization_id,user_id,redirect_uri,scope_ids,scope_names,code_challenge,nonce,issuer,audience,auth_time,expires_at) VALUES(decode(repeat('33',32),'hex'),$1,$2,$3,$4,$5,$6,'https://client.example/callback',ARRAY[$7,$8],ARRAY['openid','offline_access'],repeat('A',43),'nonce','https://issuer.example','resource',clock_timestamp(),statement_timestamp()+INTERVAL '2 minutes')")
        .bind(request).bind(grant).bind(client).bind(app).bind(org).bind(user).bind(scope).bind(offline).execute(&mut *admin).await?;
    sqlx::query("UPDATE oauth_authorization_codes SET consumed_at=clock_timestamp()")
        .execute(&mut *admin)
        .await?;
    sqlx::query("INSERT INTO oauth_token_issuances(access_jti,code_hash,access_token_hash,id_token_hash,grant_id,client_id,application_id,organization_id,user_id,issuer,audience,issued_at,access_expires_at,id_expires_at) VALUES(uuidv4(),decode(repeat('33',32),'hex'),decode(repeat('44',32),'hex'),decode(repeat('55',32),'hex'),$1,$2,$3,$4,$5,'https://issuer.example','resource',clock_timestamp(),clock_timestamp()+INTERVAL '5 minutes',clock_timestamp()+INTERVAL '5 minutes')")
        .bind(grant).bind(client).bind(app).bind(org).bind(user).execute(&mut *admin).await?;
    Ok((user, grant))
}

/// Real runtime logins can lock saved consent but cannot substitute an otherwise allowed scope.
#[tokio::test]
async fn runtime_consent_locks_preserve_immutable_scope_bindings() -> Result<()> {
    let (postgres, mut admin) = database().await?;
    let (_, grant) = receipt_fixture(&mut admin).await?;
    sqlx::query(
        "INSERT INTO oauth_client_scopes(client_id,application_id,scope_id)
        SELECT g.client_id,g.application_id,s.id FROM oauth_grants g
        JOIN oauth_scopes s ON s.application_id=g.application_id
        WHERE g.id=$1 AND s.name IN ('openid','profile') ON CONFLICT DO NOTHING",
    )
    .bind(grant)
    .execute(&mut admin)
    .await?;
    let original: Uuid = sqlx::query_scalar(
        "INSERT INTO oauth_grant_scopes(grant_id,client_id,application_id,scope_id)
        SELECT g.id,g.client_id,g.application_id,s.id FROM oauth_grants g
        JOIN oauth_scopes s ON s.application_id=g.application_id
        WHERE g.id=$1 AND s.name='openid' RETURNING scope_id",
    )
    .bind(grant)
    .fetch_one(&mut admin)
    .await?;
    let replacement: Uuid = sqlx::query_scalar(
        "SELECT cs.scope_id FROM oauth_client_scopes cs
        JOIN oauth_grants g ON g.client_id=cs.client_id
        JOIN oauth_scopes s ON s.id=cs.scope_id
        WHERE g.id=$1 AND s.name='profile'",
    )
    .bind(grant)
    .fetch_one(&mut admin)
    .await?;
    let mut runtime =
        PgConnection::connect_with(&runtime_options(&postgres, &mut admin).await?).await?;
    let locked: Uuid =
        sqlx::query_scalar("SELECT scope_id FROM oauth_grant_scopes WHERE grant_id=$1 FOR SHARE")
            .bind(grant)
            .fetch_one(&mut runtime)
            .await?;
    ensure!(locked == original, "Consent lock changed its scope binding");
    for statement in [
        "UPDATE oauth_grant_scopes SET scope_id=$2 WHERE grant_id=$1",
        "INSERT INTO oauth_grant_scopes SELECT * FROM oauth_grant_scopes WHERE grant_id=$1
         ON CONFLICT(grant_id,scope_id) DO UPDATE SET scope_id=$2",
        "MERGE INTO oauth_grant_scopes target USING (SELECT $1::uuid AS grant_id,$2::uuid AS scope_id) proposed
         ON target.grant_id=proposed.grant_id WHEN MATCHED THEN UPDATE SET scope_id=proposed.scope_id",
    ] {
        consent_rewrite_rejected(sqlx::query(statement)
            .bind(grant)
            .bind(replacement)
            .execute(&mut runtime)
            .await)?;
        let unchanged: Vec<Uuid> =
            sqlx::query_scalar("SELECT scope_id FROM oauth_grant_scopes WHERE grant_id=$1")
                .bind(grant)
                .fetch_all(&mut runtime)
                .await?;
        ensure!(unchanged == vec![original], "Rejected rewrite changed the saved consent");
    }
    for statement in [
        "UPDATE oauth_grant_scopes SET grant_id=grant_id WHERE grant_id=$1",
        "UPDATE oauth_grant_scopes SET client_id=client_id WHERE grant_id=$1",
        "UPDATE oauth_grant_scopes SET application_id=application_id WHERE grant_id=$1",
        "DELETE FROM oauth_grant_scopes WHERE grant_id=$1",
    ] {
        rejected(
            sqlx::query(statement)
                .bind(grant)
                .execute(&mut runtime)
                .await,
            "42501",
        )?;
    }
    Ok(())
}

/// A grant-bound receipt prevents a user cascade even when the caller has legitimate users DELETE.
#[tokio::test]
async fn runtime_user_deletion_preserves_retained_issuance_history() -> Result<()> {
    let (postgres, mut admin) = database().await?;
    let (user, grant) = receipt_fixture(&mut admin).await?;
    // Recreate the previous release's cascading FKs with live data, then run the actual upgrade.
    for relation in ["oauth_token_issuances", "oauth_refresh_families"] {
        let constraint:String=sqlx::query_scalar("SELECT conname FROM pg_catalog.pg_constraint WHERE conrelid=$1::regclass AND confrelid='public.oauth_grants'::regclass AND contype='f'")
            .bind(relation).fetch_one(&mut admin).await?;
        ensure!(
            constraint
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_'),
            "Unexpected fixture constraint name"
        );
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!("ALTER TABLE {relation} DROP CONSTRAINT {constraint}; ALTER TABLE {relation} ADD CONSTRAINT {constraint} FOREIGN KEY(grant_id,client_id,application_id,organization_id,user_id) REFERENCES oauth_grants(id,client_id,application_id,organization_id,user_id) ON DELETE CASCADE;")))
            .execute(&mut admin).await?;
    }
    postgres.bootstrap().await?;
    sqlx::query("SET ROLE permesi_runtime")
        .execute(&mut admin)
        .await?;
    rejected(
        sqlx::query("DELETE FROM users WHERE id=$1")
            .bind(user)
            .execute(&mut admin)
            .await,
        "23001",
    )?;
    sqlx::query("SELECT cleanup_expired_tokens()")
        .execute(&mut admin)
        .await?;
    let intact:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE id=$1) AND EXISTS(SELECT 1 FROM oauth_grants WHERE id=$2) AND EXISTS(SELECT 1 FROM oauth_token_issuances WHERE grant_id=$2)").bind(user).bind(grant).fetch_one(&mut admin).await?;
    ensure!(
        intact,
        "Rejected user deletion or cleanup erased live authorization history"
    );
    sqlx::query("RESET ROLE").execute(&mut admin).await?;
    rejected(
        sqlx::query("DELETE FROM oauth_grants WHERE id=$1")
            .bind(grant)
            .execute(&mut admin)
            .await,
        "23001",
    )?;
    sqlx::query("DELETE FROM oauth_token_issuances WHERE grant_id=$1")
        .bind(grant)
        .execute(&mut admin)
        .await?;
    let family:Uuid=sqlx::query_scalar("INSERT INTO oauth_refresh_families(source_code_hash,client_id,application_id,organization_id,user_id,grant_id,authorization_revision,scope_ids,scope_names,issuer,audience,auth_time,issued_at,expires_at,idle_ttl_seconds) SELECT code_hash,client_id,application_id,organization_id,user_id,grant_id,authorization_revision,scope_ids,scope_names,issuer,audience,auth_time,statement_timestamp(),statement_timestamp()+INTERVAL '7 days',3600 FROM oauth_authorization_codes WHERE grant_id=$1 RETURNING id")
        .bind(grant).fetch_one(&mut admin).await?;
    sqlx::query("INSERT INTO oauth_refresh_tokens(token_hash,family_id,issued_at,expires_at) VALUES(decode(repeat('66',32),'hex'),$1,statement_timestamp(),statement_timestamp()+INTERVAL '1 hour')").bind(family).execute(&mut admin).await?;
    sqlx::query("UPDATE oauth_refresh_tokens SET consumed_at=clock_timestamp() WHERE family_id=$1")
        .bind(family)
        .execute(&mut admin)
        .await?;
    sqlx::query("INSERT INTO oauth_refresh_tokens(token_hash,family_id,previous_hash,issued_at,expires_at) VALUES(decode(repeat('77',32),'hex'),$1,decode(repeat('66',32),'hex'),statement_timestamp(),statement_timestamp()+INTERVAL '1 hour')").bind(family).execute(&mut admin).await?;
    sqlx::query("SET ROLE permesi_runtime")
        .execute(&mut admin)
        .await?;
    rejected(
        sqlx::query("DELETE FROM users WHERE id=$1")
            .bind(user)
            .execute(&mut admin)
            .await,
        "23001",
    )?;
    let retained: i64 =
        sqlx::query_scalar("SELECT count(*) FROM oauth_refresh_tokens WHERE family_id=$1")
            .bind(family)
            .fetch_one(&mut admin)
            .await?;
    ensure!(
        retained == 2,
        "User deletion erased spent refresh lineage or its live successor"
    );
    sqlx::query("RESET ROLE").execute(&mut admin).await?;
    Ok(())
}
