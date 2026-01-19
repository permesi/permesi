//! Integration tests for Vault-managed database runtime roles.
//!
//! This suite verifies that the least-privilege SQL permissions defined in the
//! bootstrap scripts are correctly enforced when using dynamic Vault credentials.
//!
//! Flow Overview:
//! 1. Orchestrate Postgres and Vault containers.
//! 2. Bootstrap both `genesis` and `permesi` databases and runtime roles.
//! 3. Configure Vault's database secrets engine with revocation statements.
//! 4. Verify that dynamic users:
//!    - Can perform allowed operations (SELECT/INSERT on specific tables).
//!    - Are blocked from forbidden operations (CREATE TABLE).
//!    - Are correctly terminated and dropped by Vault upon lease revocation.
//!    - Data remains persistent across credential rotations.

use anyhow::{Context, Result, bail, ensure};
use sqlx::{Connection, PgConnection};
use test_support::{
    TestNetwork,
    postgres::PostgresContainer,
    runtime,
    vault::{DatabaseConfig, VaultContainer},
};

const GENESIS_SCHEMA_SQL: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../db/sql/01_genesis.sql"
));
const PERMESI_SCHEMA_SQL: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../db/sql/02_permesi.sql"
));
const GENESIS_SEED_SQL: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../db/sql/seed_test_client.sql"
));

#[tokio::test]
async fn vault_runtime_roles_survive_revocation() -> Result<()> {
    if let Err(err) = runtime::ensure_container_runtime() {
        eprintln!("Skipping integration test: {err}");
        return Ok(());
    }

    let network = TestNetwork::new("vault-db-runtime");
    let postgres = PostgresContainer::start(network.name()).await?;
    postgres.wait_until_ready().await?;
    bootstrap_database(&postgres).await?;

    let vault = VaultContainer::start(network.name()).await?;
    vault.enable_secrets_engine("database", "database").await?;

    let permesi_config = DatabaseConfig::new(
        postgres.vault_connection_url_for_db("permesi"),
        "vault_permesi",
        "vault_permesi",
        vec!["permesi".to_string()],
    );
    vault
        .configure_database_connection("permesi", &permesi_config)
        .await?;

    let genesis_config = DatabaseConfig::new(
        postgres.vault_connection_url_for_db("genesis"),
        "vault_genesis",
        "vault_genesis",
        vec!["genesis".to_string()],
    );
    vault
        .configure_database_connection("genesis", &genesis_config)
        .await?;

    let permesi_creation = vec![
        r#"CREATE ROLE "{{name}}" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';"#.to_string(),
        r#"GRANT permesi_runtime TO "{{name}}";"#.to_string(),
    ];
    let permesi_revocation = vec![
        r"SELECT pg_terminate_backend(pg_stat_activity.pid) FROM pg_stat_activity WHERE pg_stat_activity.usename = '{{name}}';".to_string(),
        r#"REVOKE permesi_runtime FROM "{{name}}";"#.to_string(),
        r#"DROP ROLE IF EXISTS "{{name}}";"#.to_string(),
    ];
    vault
        .create_database_role_with_revocation(
            "permesi",
            "permesi",
            &permesi_creation,
            &permesi_revocation,
            "1h",
            "4h",
        )
        .await?;

    let genesis_creation = vec![
        r#"CREATE ROLE "{{name}}" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';"#.to_string(),
        r#"GRANT genesis_runtime TO "{{name}}";"#.to_string(),
    ];
    let genesis_revocation = vec![
        r"SELECT pg_terminate_backend(pg_stat_activity.pid) FROM pg_stat_activity WHERE pg_stat_activity.usename = '{{name}}';".to_string(),
        r#"REVOKE genesis_runtime FROM "{{name}}";"#.to_string(),
        r#"DROP ROLE IF EXISTS "{{name}}";"#.to_string(),
    ];
    vault
        .create_database_role_with_revocation(
            "genesis",
            "genesis",
            &genesis_creation,
            &genesis_revocation,
            "1h",
            "4h",
        )
        .await?;

    verify_permesi_runtime(&postgres, &vault).await?;
    verify_genesis_runtime(&postgres, &vault).await?;

    Ok(())
}

async fn verify_permesi_runtime(
    postgres: &PostgresContainer,
    vault: &VaultContainer,
) -> Result<()> {
    let creds = vault.read_database_creds("permesi").await?;
    let mut connection = PgConnection::connect(&format!(
        "postgres://{}:{}@127.0.0.1:{}/permesi?sslmode=disable",
        creds.username,
        creds.password,
        postgres.host_port()
    ))
    .await
    .context("Failed to connect with permesi dynamic creds")?;

    sqlx::query("INSERT INTO roles (name) VALUES ('auditor') ON CONFLICT DO NOTHING")
        .execute(&mut connection)
        .await
        .context("Failed to insert role with permesi runtime creds")?;

    let create_result = sqlx::query("CREATE TABLE runtime_should_fail (id int)")
        .execute(&mut connection)
        .await;
    assert_permission_denied(create_result, "permesi runtime should not create tables")?;

    vault
        .revoke_lease(&creds.lease_id)
        .await
        .context("Failed to revoke permesi lease")?;

    let revoked_query = sqlx::query("SELECT 1").execute(&mut connection).await;
    if revoked_query.is_ok() {
        bail!("permesi connection should be terminated after lease revocation");
    }

    assert_role_dropped(postgres, &creds.username).await?;

    let new_creds = vault.read_database_creds("permesi").await?;
    let mut new_conn = PgConnection::connect(&format!(
        "postgres://{}:{}@127.0.0.1:{}/permesi?sslmode=disable",
        new_creds.username,
        new_creds.password,
        postgres.host_port()
    ))
    .await
    .context("Failed to connect with refreshed permesi creds")?;

    let role_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM roles WHERE name = 'auditor'")
        .fetch_one(&mut new_conn)
        .await
        .context("Failed to read roles with refreshed permesi creds")?;
    ensure!(role_count == 1, "Expected auditor role to persist");

    Ok(())
}

async fn verify_genesis_runtime(
    postgres: &PostgresContainer,
    vault: &VaultContainer,
) -> Result<()> {
    let creds = vault.read_database_creds("genesis").await?;
    let mut connection = PgConnection::connect(&format!(
        "postgres://{}:{}@127.0.0.1:{}/genesis?sslmode=disable",
        creds.username,
        creds.password,
        postgres.host_port()
    ))
    .await
    .context("Failed to connect with genesis dynamic creds")?;

    let client_id: i16 = sqlx::query_scalar("SELECT id FROM clients WHERE id = 0")
        .fetch_one(&mut connection)
        .await
        .context("Failed to read clients with genesis runtime creds")?;
    ensure!(client_id == 0, "Expected seed client to exist");

    let token_id: String =
        sqlx::query_scalar("INSERT INTO tokens (client_id) VALUES ($1) RETURNING id::text")
            .bind(client_id)
            .fetch_one(&mut connection)
            .await
            .context("Failed to insert token with genesis runtime creds")?;

    let delete_result = sqlx::query("DELETE FROM tokens WHERE id::text = $1")
        .bind(&token_id)
        .execute(&mut connection)
        .await;
    assert_permission_denied(delete_result, "genesis runtime should not delete tokens")?;

    let create_result = sqlx::query("CREATE TABLE genesis_should_fail (id int)")
        .execute(&mut connection)
        .await;
    assert_permission_denied(create_result, "genesis runtime should not create tables")?;

    vault
        .revoke_lease(&creds.lease_id)
        .await
        .context("Failed to revoke genesis lease")?;

    let revoked_query = sqlx::query("SELECT 1").execute(&mut connection).await;
    if revoked_query.is_ok() {
        bail!("genesis connection should be terminated after lease revocation");
    }

    assert_role_dropped(postgres, &creds.username).await?;

    let new_creds = vault.read_database_creds("genesis").await?;
    let mut new_conn = PgConnection::connect(&format!(
        "postgres://{}:{}@127.0.0.1:{}/genesis?sslmode=disable",
        new_creds.username,
        new_creds.password,
        postgres.host_port()
    ))
    .await
    .context("Failed to connect with refreshed genesis creds")?;

    let stored_id: Option<String> =
        sqlx::query_scalar("SELECT id::text FROM tokens WHERE id::text = $1 LIMIT 1")
            .bind(&token_id)
            .fetch_optional(&mut new_conn)
            .await
            .context("Failed to read token with refreshed genesis creds")?;
    ensure!(
        stored_id.as_deref() == Some(&token_id),
        "Token row should persist"
    );

    Ok(())
}

async fn bootstrap_database(postgres: &PostgresContainer) -> Result<()> {
    let mut admin = PgConnection::connect(&postgres.admin_dsn())
        .await
        .context("Failed to connect to Postgres admin DB")?;

    create_role_if_missing(&mut admin, "vault_permesi", "vault_permesi").await?;
    create_role_if_missing(&mut admin, "vault_genesis", "vault_genesis").await?;

    sqlx::query("GRANT pg_signal_backend TO vault_permesi")
        .execute(&mut admin)
        .await
        .context("Failed to grant pg_signal_backend to vault_permesi")?;
    sqlx::query("GRANT pg_signal_backend TO vault_genesis")
        .execute(&mut admin)
        .await
        .context("Failed to grant pg_signal_backend to vault_genesis")?;

    create_database_if_missing(&mut admin, "genesis").await?;
    create_database_if_missing(&mut admin, "permesi").await?;

    sqlx::query("ALTER DATABASE genesis OWNER TO vault_genesis")
        .execute(&mut admin)
        .await
        .context("Failed to set genesis database owner")?;
    sqlx::query("ALTER DATABASE permesi OWNER TO vault_permesi")
        .execute(&mut admin)
        .await
        .context("Failed to set permesi database owner")?;

    sqlx::query("REVOKE ALL ON DATABASE genesis FROM PUBLIC")
        .execute(&mut admin)
        .await
        .context("Failed to revoke public access to genesis database")?;
    sqlx::query("REVOKE ALL ON DATABASE permesi FROM PUBLIC")
        .execute(&mut admin)
        .await
        .context("Failed to revoke public access to permesi database")?;

    sqlx::query("GRANT CONNECT ON DATABASE genesis TO vault_genesis")
        .execute(&mut admin)
        .await
        .context("Failed to grant genesis connect")?;
    sqlx::query("GRANT CONNECT ON DATABASE permesi TO vault_permesi")
        .execute(&mut admin)
        .await
        .context("Failed to grant permesi connect")?;

    bootstrap_genesis(postgres).await?;
    bootstrap_permesi(postgres).await?;

    Ok(())
}

async fn bootstrap_genesis(postgres: &PostgresContainer) -> Result<()> {
    let mut genesis = PgConnection::connect(&postgres.admin_dsn_for_db("genesis"))
        .await
        .context("Failed to connect to genesis DB for schema setup")?;
    apply_schema(&mut genesis, GENESIS_SCHEMA_SQL).await?;
    apply_schema(&mut genesis, GENESIS_SEED_SQL).await?;
    sqlx::query("REVOKE USAGE ON SCHEMA public FROM PUBLIC")
        .execute(&mut genesis)
        .await
        .context("Failed to revoke schema usage in genesis")?;
    sqlx::query("REVOKE CREATE ON SCHEMA public FROM PUBLIC")
        .execute(&mut genesis)
        .await
        .context("Failed to revoke schema create in genesis")?;
    sqlx::query("ALTER SCHEMA public OWNER TO vault_genesis")
        .execute(&mut genesis)
        .await
        .context("Failed to set genesis schema owner")?;
    reassign_owned(&mut genesis, "postgres", "vault_genesis")
        .await
        .context("Failed to reassign genesis ownership")?;

    create_runtime_role(&mut genesis, "genesis_runtime").await?;
    sqlx::query("GRANT genesis_runtime TO vault_genesis WITH ADMIN OPTION")
        .execute(&mut genesis)
        .await
        .context("Failed to grant genesis_runtime admin option")?;
    sqlx::query("GRANT CONNECT, TEMPORARY ON DATABASE genesis TO genesis_runtime")
        .execute(&mut genesis)
        .await
        .context("Failed to grant genesis runtime connect")?;
    sqlx::query("GRANT USAGE ON SCHEMA public TO genesis_runtime")
        .execute(&mut genesis)
        .await
        .context("Failed to grant genesis runtime schema usage")?;
    sqlx::query("GRANT SELECT ON TABLE clients TO genesis_runtime")
        .execute(&mut genesis)
        .await
        .context("Failed to grant genesis runtime clients select")?;
    sqlx::query("GRANT SELECT, INSERT ON TABLE tokens TO genesis_runtime")
        .execute(&mut genesis)
        .await
        .context("Failed to grant genesis runtime tokens insert")?;
    sqlx::query("GRANT SELECT, INSERT ON TABLE tokens_default TO genesis_runtime")
        .execute(&mut genesis)
        .await
        .context("Failed to grant genesis runtime tokens_default insert")?;
    sqlx::query(
        "ALTER DEFAULT PRIVILEGES FOR ROLE vault_genesis IN SCHEMA public \
        GRANT SELECT, INSERT ON TABLES TO genesis_runtime",
    )
    .execute(&mut genesis)
    .await
    .context("Failed to set genesis default privileges")?;

    Ok(())
}

async fn bootstrap_permesi(postgres: &PostgresContainer) -> Result<()> {
    let mut permesi = PgConnection::connect(&postgres.admin_dsn_for_db("permesi"))
        .await
        .context("Failed to connect to permesi DB for schema setup")?;
    apply_schema(&mut permesi, PERMESI_SCHEMA_SQL).await?;
    sqlx::query("REVOKE USAGE ON SCHEMA public FROM PUBLIC")
        .execute(&mut permesi)
        .await
        .context("Failed to revoke schema usage in permesi")?;
    sqlx::query("REVOKE CREATE ON SCHEMA public FROM PUBLIC")
        .execute(&mut permesi)
        .await
        .context("Failed to revoke schema create in permesi")?;
    sqlx::query("ALTER SCHEMA public OWNER TO vault_permesi")
        .execute(&mut permesi)
        .await
        .context("Failed to set permesi schema owner")?;
    reassign_owned(&mut permesi, "postgres", "vault_permesi")
        .await
        .context("Failed to reassign permesi ownership")?;

    create_runtime_role(&mut permesi, "permesi_runtime").await?;
    sqlx::query("GRANT permesi_runtime TO vault_permesi WITH ADMIN OPTION")
        .execute(&mut permesi)
        .await
        .context("Failed to grant permesi_runtime admin option")?;
    sqlx::query("GRANT CONNECT, TEMPORARY ON DATABASE permesi TO permesi_runtime")
        .execute(&mut permesi)
        .await
        .context("Failed to grant permesi runtime connect")?;
    sqlx::query("GRANT USAGE ON SCHEMA public TO permesi_runtime")
        .execute(&mut permesi)
        .await
        .context("Failed to grant permesi runtime schema usage")?;
    sqlx::query("GRANT USAGE ON TYPE user_status TO permesi_runtime")
        .execute(&mut permesi)
        .await
        .context("Failed to grant permesi runtime user_status usage")?;
    sqlx::query("GRANT USAGE ON TYPE email_outbox_status TO permesi_runtime")
        .execute(&mut permesi)
        .await
        .context("Failed to grant permesi runtime email_outbox_status usage")?;
    sqlx::query("GRANT USAGE ON TYPE environment_tier TO permesi_runtime")
        .execute(&mut permesi)
        .await
        .context("Failed to grant permesi runtime environment_tier usage")?;
    sqlx::query("GRANT USAGE ON TYPE org_membership_status TO permesi_runtime")
        .execute(&mut permesi)
        .await
        .context("Failed to grant permesi runtime org_membership_status usage")?;
    sqlx::query("GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO permesi_runtime")
        .execute(&mut permesi)
        .await
        .context("Failed to grant permesi runtime tables privileges")?;
    sqlx::query("GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO permesi_runtime")
        .execute(&mut permesi)
        .await
        .context("Failed to grant permesi runtime sequences privileges")?;
    sqlx::query(
        "ALTER DEFAULT PRIVILEGES FOR ROLE vault_permesi IN SCHEMA public \
        GRANT ALL PRIVILEGES ON TABLES TO permesi_runtime",
    )
    .execute(&mut permesi)
    .await
    .context("Failed to set permesi default table privileges")?;
    sqlx::query(
        "ALTER DEFAULT PRIVILEGES FOR ROLE vault_permesi IN SCHEMA public \
        GRANT ALL PRIVILEGES ON SEQUENCES TO permesi_runtime",
    )
    .execute(&mut permesi)
    .await
    .context("Failed to set permesi default sequence privileges")?;
    sqlx::query(
        "ALTER DEFAULT PRIVILEGES FOR ROLE vault_permesi IN SCHEMA public \
        GRANT USAGE ON TYPES TO permesi_runtime",
    )
    .execute(&mut permesi)
    .await
    .context("Failed to set permesi default type privileges")?;

    Ok(())
}

async fn apply_schema(connection: &mut PgConnection, sql: &str) -> Result<()> {
    for (index, statement) in split_sql_statements(sql).iter().enumerate() {
        sqlx::query(statement)
            .execute(&mut *connection)
            .await
            .with_context(|| format!("Failed to execute schema statement {}", index + 1))?;
    }
    Ok(())
}

fn split_sql_statements(sql: &str) -> Vec<String> {
    let mut statements = Vec::new();
    let mut current = String::new();
    let mut in_dollar_quote = false;

    for line in sql.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("\\ir ") {
            continue;
        }
        current.push_str(line);
        current.push('\n');

        let dollar_markers = line.match_indices("$$").count();
        if dollar_markers % 2 == 1 {
            in_dollar_quote = !in_dollar_quote;
        }

        if !in_dollar_quote && trimmed.ends_with(';') {
            let statement = current.trim();
            if !statement.is_empty() {
                statements.push(statement.to_string());
            }
            current.clear();
        }
    }

    let leftover = current.trim();
    if !leftover.is_empty() {
        statements.push(leftover.to_string());
    }

    statements
}

async fn create_role_if_missing(
    connection: &mut PgConnection,
    role: &str,
    password: &str,
) -> Result<()> {
    let statement = format!(
        "DO $$ BEGIN \
            IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{role}') THEN \
                CREATE ROLE {role} WITH LOGIN PASSWORD '{password}' CREATEROLE; \
            END IF; \
        END $$;"
    );
    sqlx::query(&statement)
        .execute(connection)
        .await
        .with_context(|| format!("Failed to create role {role}"))?;
    Ok(())
}

async fn create_runtime_role(connection: &mut PgConnection, role: &str) -> Result<()> {
    let statement = format!(
        "DO $$ BEGIN \
            IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{role}') THEN \
                CREATE ROLE {role} NOLOGIN; \
            END IF; \
        END $$;"
    );
    sqlx::query(&statement)
        .execute(connection)
        .await
        .with_context(|| format!("Failed to create runtime role {role}"))?;
    Ok(())
}

async fn create_database_if_missing(connection: &mut PgConnection, db_name: &str) -> Result<()> {
    let result = sqlx::query(&format!("CREATE DATABASE {db_name}"))
        .execute(connection)
        .await;
    match result {
        Ok(_) => Ok(()),
        Err(sqlx::Error::Database(db_err)) if db_err.code().as_deref() == Some("42P04") => Ok(()),
        Err(err) => Err(err).with_context(|| format!("Failed to create database {db_name}")),
    }
}

async fn assert_role_dropped(postgres: &PostgresContainer, role: &str) -> Result<()> {
    let mut admin = PgConnection::connect(&postgres.admin_dsn())
        .await
        .context("Failed to connect to admin DB for role check")?;
    let exists: Option<i32> = sqlx::query_scalar("SELECT 1 FROM pg_roles WHERE rolname = $1")
        .bind(role)
        .fetch_optional(&mut admin)
        .await
        .context("Failed to query pg_roles")?;
    ensure!(exists.is_none(), "Expected role {role} to be dropped");
    Ok(())
}

async fn reassign_owned(
    connection: &mut PgConnection,
    from_role: &str,
    to_role: &str,
) -> Result<()> {
    let statement = format!("REASSIGN OWNED BY {from_role} TO {to_role}");
    let result = sqlx::query(&statement).execute(&mut *connection).await;
    match result {
        Ok(_) => Ok(()),
        Err(sqlx::Error::Database(db_err))
            if db_err.message().contains("required by the database system") =>
        {
            Ok(())
        }
        Err(err) => Err(err).with_context(|| format!("Failed to {statement}")),
    }
}

fn assert_permission_denied<T>(result: Result<T, sqlx::Error>, context: &str) -> Result<()> {
    match result {
        Err(sqlx::Error::Database(db_err)) if db_err.code().as_deref() == Some("42501") => Ok(()),
        Err(err) => Err(err).with_context(|| format!("{context}: expected permission denied")),
        Ok(_) => bail!("{context}: expected permission denied"),
    }
}
