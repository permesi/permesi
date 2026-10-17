//! Fresh PostgreSQL schemas and Vault `AppRoles` for actual service binaries.
//!
//! Flow Overview: create labeled containers, wait for local readiness, apply the
//! repository schemas, bootstrap least-privilege dynamic database roles and fresh
//! OPAQUE/key material. No fixture user, membership, session or grant is inserted.

use crate::{
    error::{Failure, Result, Safe, check},
    files::PrivateDir,
    podman::Podman,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use sqlx::{Connection, PgConnection, PgPool};
use std::time::Duration;
use uuid::Uuid;

pub const POSTGRES_IMAGE: &str = "docker.io/library/postgres:18";
pub const VAULT_IMAGE: &str = "docker.io/hashicorp/vault:1.17.3";
const GENESIS_SQL: &str = include_str!("../../../db/sql/01_genesis.sql");
const GENESIS_CLIENT_SQL: &str = include_str!("../../../db/sql/seed_test_client.sql");
const PERMESI_SQL: &str = include_str!("../../../db/sql/02_permesi.sql");
const OWNERSHIP_SQL: &str = include_str!("../../../db/sql/bootstrap_ownership.sql");
const GENESIS_PARTITION_SQL: &str = include_str!("../../../db/sql/partitioning.sql");
const VERIFY_SQL: &str = include_str!("../../../db/sql/verify_permesi.sql");

/// Dynamic service credentials never implement Debug or Serialize.
pub struct AppRole {
    pub role: String,
    pub secret: String,
}

/// Only the owned stack's endpoint/credentials can be constructed by this bootstrap.
pub struct Infrastructure {
    vault: Vault,
    pub permesi_dsn: String,
    pub genesis_dsn: String,
    pub admin_dsn: String,
    pub pool: PgPool,
    pub vault_url: String,
    pub permesi_role: AppRole,
    pub genesis_role: AppRole,
}

impl Infrastructure {
    /// Provisions a fresh database and Vault; every asynchronous failure is scrubbed at this boundary.
    pub async fn start(
        engine: &mut Podman,
        files: &PrivateDir,
        ready_seconds: u64,
    ) -> Result<Self> {
        let password = Uuid::new_v4().simple().to_string();
        let root_token = random()?;
        let postgres_env = files.write(
            "postgres.env",
            format!("POSTGRES_PASSWORD={password}\n").as_bytes(),
        )?;
        let (postgres_name, pg_port) = engine
            .container("postgres", POSTGRES_IMAGE, &postgres_env, 5432)
            .await?;
        let vault_env = files.write(
            "vault.env",
            format!(
                "VAULT_DEV_ROOT_TOKEN_ID={root_token}\nVAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200\n"
            )
            .as_bytes(),
        )?;
        let (_, vault_port) = engine
            .container("vault", VAULT_IMAGE, &vault_env, 8200)
            .await?;
        let genesis_admin =
            format!("postgres://postgres:{password}@127.0.0.1:{pg_port}/postgres?sslmode=disable");
        let mut connection = wait_postgres(&genesis_admin, ready_seconds).await?;
        let (genesis_password, vault_password) =
            bootstrap_service_schemas(&mut connection, &password, pg_port).await?;
        let admin_dsn =
            format!("postgres://postgres:{password}@127.0.0.1:{pg_port}/permesi?sslmode=disable");
        let pool = PgPool::connect(&admin_dsn)
            .await
            .safe("Cannot open isolated assertion pool.")?;
        let verification_dsn = format!(
            "postgres://vault_permesi:{vault_password}@127.0.0.1:{pg_port}/permesi?sslmode=disable"
        );
        let mut verification = PgConnection::connect(&verification_dsn)
            .await
            .safe("Cannot connect to schema verification.")?;
        test_support::sql::execute_script(&mut verification, "verify_permesi.sql", VERIFY_SQL)
            .await
            .safe("Canonical runtime grants violate schema protections.")?;
        let vault_base = format!("http://127.0.0.1:{vault_port}");
        let vault = Vault {
            base: vault_base.clone(),
            token: root_token,
            client: reqwest::Client::builder()
                .no_proxy()
                .timeout(Duration::from_secs(10))
                .build()
                .safe("Cannot configure Vault bootstrap client.")?,
        };
        vault.ready(ready_seconds).await?;
        let (genesis_role, permesi_role) = vault
            .bootstrap(&postgres_name, &genesis_password, &vault_password)
            .await?;
        Ok(Self {
            vault,
            permesi_dsn: format!("postgres://127.0.0.1:{pg_port}/permesi?sslmode=disable"),
            genesis_dsn: format!("postgres://127.0.0.1:{pg_port}/genesis?sslmode=disable"),
            admin_dsn,
            pool,
            vault_url: format!("{vault_base}/v1/auth/approle/login"),
            permesi_role,
            genesis_role,
        })
    }

    /// Rotates only this run's newly provisioned key; production endpoints cannot be supplied.
    pub async fn rotate_oidc_key(&self) -> Result<()> {
        self.vault
            .post("transit/permesi/keys/oidc-signing/rotate", json!({}))
            .await?;
        Ok(())
    }

    /// Fault injection changes only the owned runtime policy's signing path, preserving renewals.
    pub async fn signing_allowed(&self, allowed: bool) -> Result<()> {
        let path = "sys/policies/acl/permesi";
        let existing = self.vault.request(reqwest::Method::GET, path, None).await?;
        let policy = existing
            .pointer("/data/policy")
            .and_then(Value::as_str)
            .ok_or_else(|| Failure::harness("Missing isolated policy."))?;
        let from = if allowed {
            "path \"transit/permesi/sign/oidc-signing\" { capabilities=[\"deny\"] }"
        } else {
            "path \"transit/permesi/sign/oidc-signing\" { capabilities=[\"update\"] }"
        };
        let to = if allowed {
            "path \"transit/permesi/sign/oidc-signing\" { capabilities=[\"update\"] }"
        } else {
            "path \"transit/permesi/sign/oidc-signing\" { capabilities=[\"deny\"] }"
        };
        check(
            policy.matches(from).count() == 1,
            "Unexpected isolated signing policy.",
        )?;
        self.vault
            .request(
                reqwest::Method::PUT,
                path,
                Some(json!({"policy":policy.replace(from,to)})),
            )
            .await?;
        Ok(())
    }
}

/// Applies the canonical schemas and ownership checks as the non-superuser service owners.
/// Only this run's new databases and roles are accepted; no existing stack is adopted.
async fn bootstrap_service_schemas(
    connection: &mut PgConnection,
    password: &str,
    pg_port: u16,
) -> Result<(String, String)> {
    let vault_password = Uuid::new_v4().simple().to_string();
    let genesis_password = Uuid::new_v4().simple().to_string();
    for (database, owner, runtime, owner_password) in [
        (
            "genesis",
            "vault_genesis",
            "genesis_runtime",
            &genesis_password,
        ),
        (
            "permesi",
            "vault_permesi",
            "permesi_runtime",
            &vault_password,
        ),
    ] {
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
            "CREATE ROLE {owner} WITH LOGIN PASSWORD '{owner_password}' CREATEROLE;
                 GRANT pg_signal_backend TO {owner};
                 CREATE ROLE {runtime} NOLOGIN;
                 GRANT {runtime} TO {owner} WITH ADMIN OPTION;"
        )))
        .execute(&mut *connection)
        .await
        .safe("Cannot bootstrap owned database roles.")?;
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "CREATE DATABASE {database} OWNER {owner}"
        )))
        .execute(&mut *connection)
        .await
        .safe("Cannot create owned service database.")?;
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "REVOKE ALL ON DATABASE {database} FROM PUBLIC"
        )))
        .execute(&mut *connection)
        .await
        .safe("Cannot restrict service database access.")?;
        let dsn = format!(
            "postgres://postgres:{password}@127.0.0.1:{pg_port}/{database}?sslmode=disable"
        );
        let mut schema = PgConnection::connect(&dsn)
            .await
            .safe("Cannot connect to owned service database.")?;
        ownership_pass(&mut schema).await?;
        apply_owned_schema(database, owner, owner_password, pg_port).await?;
        ownership_pass(&mut schema).await?;
    }
    Ok((genesis_password, vault_password))
}

/// Catalog-only administrator passes pin lookup before touching owner-controlled databases.
async fn ownership_pass(connection: &mut PgConnection) -> Result<()> {
    sqlx::raw_sql("BEGIN; SET LOCAL search_path = pg_catalog, pg_temp;")
        .execute(&mut *connection)
        .await
        .safe("Cannot start ownership transaction.")?;
    test_support::sql::execute_script(connection, "bootstrap ownership", OWNERSHIP_SQL)
        .await
        .safe("Cannot verify non-superuser ownership.")?;
    sqlx::query("COMMIT")
        .execute(connection)
        .await
        .safe("Cannot commit ownership transaction.")?;
    Ok(())
}

/// Application schemas run in an actual owner login; RESET ROLE cannot restore an administrator.
async fn apply_owned_schema(database: &str, owner: &str, password: &str, port: u16) -> Result<()> {
    let dsn = format!("postgres://{owner}:{password}@127.0.0.1:{port}/{database}?sslmode=disable");
    let mut schema = PgConnection::connect(&dsn)
        .await
        .safe("Cannot authenticate schema owner.")?;
    sqlx::raw_sql("BEGIN; SET LOCAL search_path = public, pg_temp;")
        .execute(&mut schema)
        .await
        .safe("Cannot start owner schema transaction.")?;
    if database == "genesis" {
        for (label, sql) in [
            ("01_genesis.sql", GENESIS_SQL),
            ("partitioning.sql", GENESIS_PARTITION_SQL),
            ("seed_test_client.sql", GENESIS_CLIENT_SQL),
        ] {
            test_support::sql::execute_script(&mut schema, label, sql)
                .await
                .safe("Cannot apply owned Genesis schema.")?;
        }
    } else {
        test_support::sql::execute_script(&mut schema, "02_permesi.sql", PERMESI_SQL)
            .await
            .safe("Cannot apply owned Permesi schema.")?;
    }
    sqlx::query("COMMIT")
        .execute(&mut schema)
        .await
        .safe("Cannot commit owner schema transaction.")?;
    Ok(())
}

/// Uses OS entropy only; fixture seed cannot influence passwords, PKCE, CA keys or Vault seeds.
pub fn random() -> Result<String> {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes).safe("Operating-system entropy is unavailable.")?;
    Ok(STANDARD.encode(bytes))
}

/// Retries only dependency readiness; authentication and scenario mutations are never retried.
async fn wait_postgres(dsn: &str, seconds: u64) -> Result<PgConnection> {
    tokio::time::timeout(Duration::from_secs(seconds), async {
        loop {
            if let Ok(connection) = PgConnection::connect(dsn).await {
                return connection;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    })
    .await
    .safe("Isolated PostgreSQL did not become ready.")
}

struct Vault {
    base: String,
    token: String,
    client: reqwest::Client,
}
impl Vault {
    /// Configures fresh signing and database authority for only the owned containers.
    async fn bootstrap(
        &self,
        postgres_name: &str,
        password: &str,
        vault_password: &str,
    ) -> Result<(AppRole, AppRole)> {
        self.request(reqwest::Method::DELETE, "sys/mounts/secret", None)
            .await?;
        self.post(
            "sys/mounts/secret/permesi",
            json!({"type":"kv","options":{"version":"2"}}),
        )
        .await?;
        self.post("sys/auth/approle", json!({"type":"approle"}))
            .await?;
        self.post("sys/mounts/database", json!({"type":"database"}))
            .await?;
        for (mount, key, kind) in [
            ("transit/genesis", "genesis-signing", "ed25519"),
            ("transit/permesi", "totp", "chacha20-poly1305"),
        ] {
            self.post(&format!("sys/mounts/{mount}"), json!({"type":"transit"}))
                .await?;
            self.post(&format!("{mount}/keys/{key}"), json!({"type":kind}))
                .await?;
        }
        self.post(
            "transit/permesi/keys/oidc-signing",
            json!({"type":"rsa-2048"}),
        )
        .await?;
        self.post(
            "secret/permesi/data/config",
            json!({"data":{"opaque_server_seed":random()?, "mfa_recovery_pepper":random()?}}),
        )
        .await?;
        self.database("genesis", postgres_name, "genesis", "vault_genesis", password, json!([
            "CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';",
            "GRANT genesis_runtime TO \"{{name}}\";"
        ])).await?;
        self.database("permesi", postgres_name, "permesi", "vault_permesi", vault_password, json!([
            "CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';", "GRANT permesi_runtime TO \"{{name}}\";"
        ])).await?;
        let genesis_role = self.role("genesis", "path \"transit/genesis/keys/genesis-signing\" { capabilities=[\"read\"] }\npath \"transit/genesis/sign/genesis-signing\" { capabilities=[\"update\"] }").await?;
        let permesi_role = self.role("permesi", "path \"secret/permesi/data/config\" { capabilities=[\"read\"] }\npath \"transit/permesi/keys/oidc-signing\" { capabilities=[\"read\"] }\npath \"transit/permesi/sign/oidc-signing\" { capabilities=[\"update\"] }\npath \"transit/permesi/datakey/plaintext/totp\" { capabilities=[\"update\"] }\npath \"transit/permesi/decrypt/totp\" { capabilities=[\"update\"] }").await?;
        Ok((genesis_role, permesi_role))
    }

    /// Waits for the owned dev Vault without printing its token or response body.
    async fn ready(&self, seconds: u64) -> Result<()> {
        tokio::time::timeout(Duration::from_secs(seconds), async {
            loop {
                if let Ok(response) = self
                    .client
                    .get(format!("{}/v1/sys/health", self.base))
                    .send()
                    .await
                    && response.status().is_success()
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        })
        .await
        .safe("Isolated Vault did not become ready.")
    }
    /// Sends a fixed bootstrap path; externally generated error values are discarded.
    async fn post(&self, path: &str, body: Value) -> Result<Value> {
        self.request(reqwest::Method::POST, path, Some(body)).await
    }
    /// Reads only the isolated Vault; response values remain private, never report inputs.
    async fn request(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<Value>,
    ) -> Result<Value> {
        let mut request = self
            .client
            .request(method, format!("{}/v1/{path}", self.base))
            .header("X-Vault-Token", &self.token);
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response = request
            .send()
            .await
            .safe("Vault bootstrap request failed.")?;
        check(
            response.status().is_success(),
            "Vault rejected isolated bootstrap configuration.",
        )?;
        if response.status() == reqwest::StatusCode::NO_CONTENT {
            Ok(Value::Null)
        } else {
            response
                .json()
                .await
                .safe("Invalid Vault bootstrap response.")
        }
    }
    /// Creates a least-privilege dynamic role against the owned database container, with explicit revocation.
    async fn database(
        &self,
        name: &str,
        host: &str,
        db: &str,
        user: &str,
        password: &str,
        statements: Value,
    ) -> Result<()> {
        self.post(&format!("database/config/{name}"), json!({"plugin_name":"postgresql-database-plugin", "allowed_roles":[name], "connection_url":format!("postgresql://{{{{username}}}}:{{{{password}}}}@{host}:5432/{db}?sslmode=disable"), "username":user,"password":password})).await?;
        self.post(&format!("database/roles/{name}"), json!({"db_name":name,"creation_statements":statements,"revocation_statements":["SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename='{{name}}';", format!("REASSIGN OWNED BY \"{{{{name}}}}\" TO \"{user}\";"),"DROP OWNED BY \"{{name}}\";","DROP ROLE IF EXISTS \"{{name}}\";"], "default_ttl":"1h","max_ttl":"4h"})).await?;
        Ok(())
    }
    /// Issues a fresh `AppRole` secret; service children receive it in their private environment.
    async fn role(&self, name: &str, extra: &str) -> Result<AppRole> {
        let policy = format!(
            "path \"database/creds/{name}\" {{ capabilities=[\"read\"] }}\npath \"auth/token/renew-self\" {{ capabilities=[\"update\"] }}\npath \"sys/leases/renew\" {{ capabilities=[\"update\"] }}\n{extra}"
        );
        self.request(
            reqwest::Method::PUT,
            &format!("sys/policies/acl/{name}"),
            Some(json!({"policy":policy})),
        )
        .await?;
        self.post(
            &format!("auth/approle/role/{name}"),
            json!({"token_policies":[name],"token_ttl":"1h","token_max_ttl":"4h"}),
        )
        .await?;
        let role = self
            .request(
                reqwest::Method::GET,
                &format!("auth/approle/role/{name}/role-id"),
                None,
            )
            .await?;
        let secret = self
            .post(&format!("auth/approle/role/{name}/secret-id"), json!({}))
            .await?;
        Ok(AppRole {
            role: field(&role, "role_id")?,
            secret: field(&secret, "secret_id")?,
        })
    }
}

/// Extracts known Vault data keys without formatting the secret-bearing response on failure.
fn field(value: &Value, name: &str) -> Result<String> {
    value
        .get("data")
        .and_then(|data| data.get(name))
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| Failure::infrastructure("Vault response omitted required credentials."))
}
