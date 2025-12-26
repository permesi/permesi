use anyhow::{Context, Result};
use sqlx::{Connection, PgConnection};
use std::env;

use crate::postgres::PostgresContainer;
use crate::vault::{DatabaseConfig, VaultContainer};

const APPROLE_MOUNT: &str = "approle";
const ROLE_NAME: &str = "genesis";
const POLICY_NAME: &str = "genesis";
const TRANSIT_KEY_NAME: &str = "genesis-signing";
const DEFAULT_TRANSIT_MOUNT: &str = "transit/genesis";
const DATABASE_MOUNT: &str = "database";
const DATABASE_NAME: &str = "genesis";

const GENESIS_SCHEMA_SQL: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../db/sql/01_genesis.sql"
));

#[derive(Debug)]
pub struct GenesisVaultConfig {
    pub login_url: String,
    pub role_id: String,
    pub secret_id: String,
    pub wrapped_secret_id: String,
}

/// Apply the Genesis schema to the provided Postgres instance.
///
/// # Errors
/// Returns an error if the schema cannot be applied.
pub async fn apply_genesis_schema(postgres: &PostgresContainer) -> Result<()> {
    let mut connection = PgConnection::connect(&postgres.admin_dsn())
        .await
        .context("Failed to connect to Postgres for schema setup")?;

    for (index, statement) in split_sql_statements(GENESIS_SCHEMA_SQL).iter().enumerate() {
        sqlx::query(statement)
            .execute(&mut connection)
            .await
            .with_context(|| format!("Failed to execute schema statement {}", index + 1))?;
    }

    Ok(())
}

/// Configure Vault for Genesis (`AppRole`, transit, and database secrets).
///
/// # Errors
/// Returns an error if any Vault configuration step fails.
pub async fn configure_genesis_vault(
    vault: &VaultContainer,
    postgres: &PostgresContainer,
) -> Result<GenesisVaultConfig> {
    let transit_mount =
        env::var("GENESIS_TRANSIT_MOUNT").unwrap_or_else(|_| DEFAULT_TRANSIT_MOUNT.to_string());
    let transit_mount = transit_mount.trim_matches('/').to_string();

    let policy = genesis_policy(&transit_mount);

    vault
        .enable_auth(APPROLE_MOUNT, "approle")
        .await
        .context("Failed to enable AppRole auth")?;
    vault
        .write_policy(POLICY_NAME, &policy)
        .await
        .context("Failed to write Genesis policy")?;
    vault
        .create_approle(APPROLE_MOUNT, ROLE_NAME, &[POLICY_NAME])
        .await
        .context("Failed to create Genesis AppRole")?;

    let role_id = vault
        .read_role_id(APPROLE_MOUNT, ROLE_NAME)
        .await
        .context("Failed to read Genesis role_id")?;
    let secret_id = vault
        .create_secret_id(APPROLE_MOUNT, ROLE_NAME)
        .await
        .context("Failed to create Genesis secret_id")?;
    let wrapped_secret_id = vault
        .create_wrapped_secret_id(APPROLE_MOUNT, ROLE_NAME, "300s")
        .await
        .context("Failed to create wrapped Genesis secret_id")?;

    vault
        .enable_secrets_engine(&transit_mount, "transit")
        .await
        .with_context(|| format!("Failed to enable transit at {transit_mount}"))?;
    vault
        .create_transit_key(&transit_mount, TRANSIT_KEY_NAME, "ed25519")
        .await
        .context("Failed to create Genesis transit key")?;

    vault
        .enable_secrets_engine(DATABASE_MOUNT, "database")
        .await
        .context("Failed to enable database engine")?;

    let db_config = DatabaseConfig::new(
        postgres.vault_connection_url(),
        postgres.user(),
        postgres.password(),
        vec![ROLE_NAME.to_string()],
    );

    vault
        .configure_database_connection(DATABASE_NAME, &db_config)
        .await
        .context("Failed to configure database connection")?;

    let db_name = postgres.db_name();
    let creation_statements = vec![
        r#"CREATE ROLE "{{name}}" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';"#.to_string(),
        format!(r#"GRANT CONNECT ON DATABASE "{db_name}" TO "{{{{name}}}}";"#),
        r#"GRANT USAGE ON SCHEMA public TO "{{name}}";"#.to_string(),
        r#"GRANT SELECT ON TABLE clients TO "{{name}}";"#.to_string(),
        // Genesis inserts with `RETURNING`, so SELECT is required alongside INSERT.
        r#"GRANT SELECT, INSERT ON TABLE tokens TO "{{name}}";"#.to_string(),
        r#"GRANT SELECT, INSERT ON TABLE tokens_default TO "{{name}}";"#.to_string(),
    ];

    vault
        .create_database_role(ROLE_NAME, DATABASE_NAME, &creation_statements, "1h", "4h")
        .await
        .context("Failed to create database role")?;

    Ok(GenesisVaultConfig {
        login_url: vault.login_url(APPROLE_MOUNT),
        role_id,
        secret_id,
        wrapped_secret_id,
    })
}

fn genesis_policy(transit_mount: &str) -> String {
    format!(
        r#"path "{transit_mount}/keys/{TRANSIT_KEY_NAME}" {{
  capabilities = ["read"]
}}
path "{transit_mount}/sign/{TRANSIT_KEY_NAME}" {{
  capabilities = ["update"]
}}
path "database/creds/{ROLE_NAME}" {{
  capabilities = ["read"]
}}
path "auth/token/renew-self" {{
  capabilities = ["update"]
}}
path "sys/leases/renew" {{
  capabilities = ["update"]
}}
"#
    )
}

fn split_sql_statements(sql: &str) -> Vec<String> {
    let mut statements = Vec::new();
    let mut current = String::new();

    for line in sql.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("\\ir ") {
            continue;
        }
        current.push_str(line);
        current.push('\n');

        if trimmed.ends_with(';') {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn genesis_policy_includes_transit_mount() {
        let policy = genesis_policy("transit/custom");
        assert!(policy.contains("transit/custom/keys"));
        assert!(policy.contains("transit/custom/sign"));
    }

    #[test]
    fn split_sql_statements_skips_include_lines() {
        let sql = r"
CREATE TABLE users(id int);
\ir /db/sql/partitioning.sql
INSERT INTO users(id) VALUES (1);
";
        let statements = split_sql_statements(sql);
        assert_eq!(statements.len(), 2);
        assert!(
            statements
                .first()
                .is_some_and(|statement| statement.contains("CREATE TABLE users"))
        );
        assert!(
            statements
                .get(1)
                .is_some_and(|statement| statement.contains("INSERT INTO users"))
        );
    }
}
