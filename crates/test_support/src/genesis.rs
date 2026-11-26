use anyhow::{Context, Result};
use sqlx::{Connection, PgConnection};
use std::env;

use crate::openbao::{DatabaseConfig, OpenBaoContainer};
use crate::postgres::PostgresContainer;

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
const GENESIS_SEED_SQL: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../db/sql/seed_test_client.sql"
));

#[derive(Debug)]
pub struct GenesisOpenBaoConfig {
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

    crate::sql::execute_script(&mut connection, "01_genesis.sql", GENESIS_SCHEMA_SQL).await?;

    crate::sql::execute_script(&mut connection, "seed_test_client.sql", GENESIS_SEED_SQL).await?;

    Ok(())
}

/// Configure OpenBao for Genesis (`AppRole`, transit, and database secrets).
///
/// # Errors
/// Returns an error if any OpenBao configuration step fails.
pub async fn configure_genesis_openbao(
    openbao: &OpenBaoContainer,
    postgres: &PostgresContainer,
) -> Result<GenesisOpenBaoConfig> {
    let transit_mount =
        env::var("GENESIS_TRANSIT_MOUNT").unwrap_or_else(|_| DEFAULT_TRANSIT_MOUNT.to_string());
    let transit_mount = transit_mount.trim_matches('/').to_string();

    let policy = genesis_policy(&transit_mount);

    openbao
        .enable_auth(APPROLE_MOUNT, "approle")
        .await
        .context("Failed to enable AppRole auth")?;
    openbao
        .write_policy(POLICY_NAME, &policy)
        .await
        .context("Failed to write Genesis policy")?;
    openbao
        .create_approle(APPROLE_MOUNT, ROLE_NAME, &[POLICY_NAME])
        .await
        .context("Failed to create Genesis AppRole")?;

    let role_id = openbao
        .read_role_id(APPROLE_MOUNT, ROLE_NAME)
        .await
        .context("Failed to read Genesis role_id")?;
    let secret_id = openbao
        .create_secret_id(APPROLE_MOUNT, ROLE_NAME)
        .await
        .context("Failed to create Genesis secret_id")?;
    let wrapped_secret_id = openbao
        .create_wrapped_secret_id(APPROLE_MOUNT, ROLE_NAME, "300s")
        .await
        .context("Failed to create wrapped Genesis secret_id")?;

    openbao
        .enable_secrets_engine(&transit_mount, "transit")
        .await
        .with_context(|| format!("Failed to enable transit at {transit_mount}"))?;
    openbao
        .create_transit_key(&transit_mount, TRANSIT_KEY_NAME, "ed25519")
        .await
        .context("Failed to create Genesis transit key")?;

    openbao
        .enable_secrets_engine(DATABASE_MOUNT, "database")
        .await
        .context("Failed to enable database engine")?;

    let db_config = DatabaseConfig::new(
        postgres.openbao_connection_url(),
        postgres.user(),
        postgres.password(),
        vec![ROLE_NAME.to_string()],
    );

    openbao
        .configure_database_connection(DATABASE_NAME, &db_config)
        .await
        .context("Failed to configure database connection")?;

    let db_name = postgres.db_name();
    let creation_statements = vec![
        r#"CREATE ROLE "{{name}}" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';"#.to_string(),
        format!(r#"GRANT CONNECT ON DATABASE "{db_name}" TO "{{{{name}}}}";"#),
        r#"GRANT USAGE ON SCHEMA public TO "{{name}}";"#.to_string(),
        r#"GRANT SELECT (id, uuid, is_reserved) ON TABLE clients TO "{{name}}";"#.to_string(),
        // Genesis inserts with `RETURNING`, so SELECT is required alongside INSERT.
        r#"GRANT SELECT (id), INSERT (client_id, ip_address, country, user_agent) ON TABLE tokens TO "{{name}}";"#.to_string(),
    ];

    let revocation_statements = vec![
        r"SELECT pg_terminate_backend(pg_stat_activity.pid) FROM pg_stat_activity WHERE pg_stat_activity.usename = '{{name}}';".to_string(),
        format!(r#"REASSIGN OWNED BY "{{{{name}}}}" TO "{}";"#, postgres.user()),
        r#"DROP OWNED BY "{{name}}";"#.to_string(),
        r#"DROP ROLE IF EXISTS "{{name}}";"#.to_string(),
    ];
    openbao
        .create_database_role_with_revocation(
            ROLE_NAME,
            DATABASE_NAME,
            &creation_statements,
            &revocation_statements,
            "1h",
            "4h",
        )
        .await
        .context("Failed to create database role")?;

    Ok(GenesisOpenBaoConfig {
        login_url: openbao.login_url(APPROLE_MOUNT),
        role_id,
        secret_id,
        wrapped_secret_id,
    })
}

/// Mirrors `openbao/contrib/opentofu/policies/genesis-policy.hcl` for the fixture's mounts,
/// including the limit of lease renewal to this service's own database leases, so the
/// service is tested under the constraints it runs with.
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
  required_parameters = ["lease_id"]
  allowed_parameters = {{
    "lease_id"  = ["database/creds/{ROLE_NAME}/*"]
    "increment" = []
  }}
}}
"#
    )
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
}
