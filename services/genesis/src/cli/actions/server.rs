use crate::{api, cli::globals::GlobalArgs, openbao};
use anyhow::{Context, Result, anyhow};
use secrecy::{ExposeSecret, SecretString};
use service_utils::database::PoolConfig;
use tracing::{debug, info};
use url::Url;

pub struct Args {
    pub signing_version: u32,
    pub admission_issuer: String,
    pub admission_audience: String,
    pub metadata: api::peer::RequestMetadataPolicy,
    pub public_limits: service_utils::work_limit::Limits,

    pub port: u16,
    pub socket_path: Option<String>,
    pub dsn: String,
    pub db_pool: PoolConfig,
    pub http: service_utils::http_limits::HttpLimits,
    pub openbao_url: String,
    pub openbao_target: openbao::OpenBaoTarget,
    pub openbao_kubernetes: Option<openbao_client::kubernetes::KubernetesAuth>,
    pub openbao_role_id: Option<String>,
    pub openbao_secret_id: Option<String>,
    pub openbao_wrapped_token: Option<String>,
    pub openbao_transit_mount: String,
    pub tls_pem_bundle: Option<String>,
}

/// Formats only settings that are safe in a log. The struct holds the database DSN, the
/// `AppRole` `RoleID` and `SecretID`, a wrapped token and an OpenBao URL that may carry
/// userinfo, so nothing is derived: a field has to be listed here to appear at all.
impl std::fmt::Debug for Args {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Args")
            .field("port", &self.port)
            .field("socket_path", &self.socket_path)
            .field("openbao_mode", &self.openbao_target.mode())
            .field("tls", &self.tls_pem_bundle.is_some())
            .finish_non_exhaustive()
    }
}

/// Start with Agent, `AppRole`, or the explicitly selected Kubernetes login.
/// Kubernetes token renewal uses the existing fail-closed shutdown; a supervisor
/// restart reads the current JWT and reacquires all credentials, without hot replacement.
/// # Errors
/// Returns an error if OpenBao login fails, DB credentials cannot be fetched, or the server fails to start.
pub async fn execute(args: Args) -> Result<()> {
    if let Some(bundle_path) = &args.tls_pem_bundle {
        crate::tls::set_runtime_paths(crate::tls::TlsPaths::new(
            std::path::PathBuf::from(bundle_path),
            None,
        ));
    }
    log_startup_args(&args);
    let openbao_transport =
        openbao::OpenBaoTransport::from_target(crate::APP_USER_AGENT, args.openbao_target.clone())?;
    let mut globals = GlobalArgs::new(args.openbao_url, openbao_transport);
    globals.openbao_transit_mount = args.openbao_transit_mount;

    if let Some(config) = &args.openbao_kubernetes {
        let (token, lease) = openbao_client::kubernetes::kubernetes_login(
            crate::APP_USER_AGENT,
            &globals.openbao_url,
            config,
        )
        .await?;
        globals.set_token(token);
        globals.set_token_lease(lease);
    } else if matches!(args.openbao_target, openbao::OpenBaoTarget::Tcp { .. }) {
        let openbao_role_id = args
            .openbao_role_id
            .as_deref()
            .ok_or_else(|| anyhow!("OpenBao role-id is required"))?;
        let login_url = openbao::approle_login_url(&globals.openbao_url)?;

        // If openbao wrapped token try to unwrap, otherwise use secret-id.
        let (openbao_token, lease) = if let Some(wrapped) = &args.openbao_wrapped_token {
            let openbao_session_id = openbao::unwrap(&globals.openbao_url, wrapped).await?;
            openbao::approle_login(&login_url, &openbao_session_id, openbao_role_id).await?
        } else {
            let secret_id = args
                .openbao_secret_id
                .as_deref()
                .ok_or_else(|| anyhow!("OpenBao secret-id is required"))?;
            openbao::approle_login(&login_url, secret_id, openbao_role_id).await?
        };

        globals.set_token(SecretString::from(openbao_token));
        globals.set_token_lease(lease);
    }

    // Get database username and password from OpenBao
    openbao::database::database_creds(&mut globals)
        .await
        .context("Could not get database username and password")?;

    debug!("Global args: {:?}", globals);

    let mut dsn = Url::parse(&args.dsn)?;

    // Set username & password from GlobalArgs
    dsn.set_username(&globals.openbao_db_username)
        .map_err(|()| anyhow!("Error setting username"))?;

    dsn.set_password(Some(globals.openbao_db_password.expose_secret()))
        .map_err(|()| anyhow!("Error setting password"))?;

    api::new(
        args.port,
        args.socket_path,
        dsn.to_string(),
        args.db_pool,
        api::Settings {
            public_limits: args.public_limits,
            signing_version: args.signing_version,
            admission_issuer: args.admission_issuer,
            admission_audience: args.admission_audience,
            metadata: args.metadata,
            http: args.http,
        },
        &globals,
    )
    .await
}

/// Logs the effective configuration once at startup. Addresses are reduced to what is
/// safe to show and credentials appear only as "set" or not: this block is written at
/// `INFO` on every start and is the line operators most often paste into a ticket.
fn log_startup_args(args: &Args) {
    let mode = match args.openbao_target {
        openbao::OpenBaoTarget::Tcp { .. } => "Direct Access (TCP)",
        openbao::OpenBaoTarget::AgentProxy { .. } => "Agent (Sidecar)",
    };
    let listen_addr = if let Some(sock) = &args.socket_path {
        format!("unix:{sock}")
    } else {
        format!("tcp:{}", args.port)
    };
    let entries = [
        ("listen", listen_addr),
        ("dsn", service_utils::database::loggable_dsn(&args.dsn)),
        ("db_pool", args.db_pool.to_string()),
        ("http_limits", args.http.to_string()),
        (
            "openbao_url",
            openbao_client::loggable_url(&args.openbao_url),
        ),
        ("openbao_mode", mode.to_string()),
        (
            "openbao_auth_method",
            if args.openbao_kubernetes.is_some() {
                "kubernetes"
            } else if args.openbao_target.is_tcp() {
                "approle"
            } else {
                "agent"
            }
            .to_string(),
        ),
        (
            "openbao_role_id_set",
            args.openbao_role_id.is_some().to_string(),
        ),
        (
            "openbao_secret_id_set",
            args.openbao_secret_id.is_some().to_string(),
        ),
        (
            "openbao_wrapped_token_set",
            args.openbao_wrapped_token.is_some().to_string(),
        ),
        (
            "tls_pem_bundle",
            args.tls_pem_bundle
                .clone()
                .unwrap_or_else(|| "none".to_string()),
        ),
        ("admission_issuer", args.admission_issuer.clone()),
        ("admission_audience", args.admission_audience.clone()),
        ("client_metadata", args.metadata.summary()),
    ];
    log_entries("Startup configuration", &entries);
}

fn log_entries(title: &str, entries: &[(&str, String)]) {
    let max_key_len = entries.iter().map(|(key, _)| key.len()).max().unwrap_or(0);
    let mut message = format!("{}\n\n{title}:", genesis_banner());
    for (key, value) in entries {
        let padding = " ".repeat(max_key_len.saturating_sub(key.len()));
        let _ =
            std::fmt::Write::write_fmt(&mut message, format_args!("\n  {key}:{padding} {value}"));
    }
    info!("{message}");
}

fn genesis_banner() -> String {
    let short_hash = short_commit(crate::GIT_COMMIT_HASH);
    GENESIS_BANNER.replace(
        "{VERSION}",
        &format!(" - {} - {}", env!("CARGO_PKG_VERSION"), short_hash),
    )
}

fn short_commit(hash: &str) -> String {
    let trimmed = hash.trim();
    if trimmed.len() > 7 {
        trimmed[..7].to_string()
    } else {
        trimmed.to_string()
    }
}

const GENESIS_BANNER: &str = r"
   *     *
 *   * *   *
   *  *  *
    \ | /
     \|/
  ----+----  G E N E S I S {VERSION}
     /|\
    / | \
   *  *  *
 *   * *   *
   *     *";

#[cfg(test)]
mod tests {
    use super::{Args, log_startup_args};
    use crate::openbao::OpenBaoTarget;
    use service_utils::database::PoolConfig;
    use std::time::Duration;

    fn args_with_credentials() -> anyhow::Result<Args> {
        let openbao_url =
            "https://bao-user:bao-password@openbao.internal:8200/?bao_token=bao-query-value";
        Ok(Args {
            signing_version: 1,
            admission_issuer: "https://genesis.permesi.dev".to_string(),
            admission_audience: "permesi".to_string(),
            metadata: crate::api::peer::RequestMetadataPolicy::new(
                "CF-Connecting-IP",
                "CF-IPCountry",
                Vec::new(),
                false,
            )?,
            public_limits: service_utils::work_limit::Limits::new(20, 20, 5)?,
            port: 8080,
            socket_path: None,
            dsn: "postgres://dsn-user:dsn-password@db.internal:5432/genesis?password=dsn-query-password"
                .to_string(),
            db_pool: PoolConfig::new(
                10,
                2,
                Duration::from_secs(3),
                Duration::from_mins(10),
                Duration::from_mins(30),
            )?,
            http: service_utils::http_limits::HttpLimits::new(
                Duration::from_mins(1),
                Duration::from_secs(10),
                Duration::from_secs(20),
            )?,
            openbao_url: openbao_url.to_string(),
            openbao_target: OpenBaoTarget::parse(openbao_url)?,
            openbao_kubernetes: None,
            openbao_role_id: Some("role-id-value".to_string()),
            openbao_secret_id: Some("secret-id-value".to_string()),
            openbao_wrapped_token: Some("wrapped-token-value".to_string()),
            openbao_transit_mount: "transit/genesis".to_string(),
            tls_pem_bundle: None,
        })
    }

    const CREDENTIALS: [&str; 9] = [
        "dsn-password",
        "dsn-query-password",
        "bao-user",
        "bao-password",
        "bao-query-value",
        "bao_token",
        "role-id-value",
        "secret-id-value",
        "wrapped-token-value",
    ];

    /// Startup arguments are sometimes formatted in diagnostics and test output; none of
    /// their credentials may come out, directly or through the enclosing action.
    #[test]
    fn args_debug_output_names_no_credential() -> anyhow::Result<()> {
        let args = args_with_credentials()?;
        let direct = format!("{args:?}");
        let shown = format!("{direct} {:#?}", crate::cli::actions::Action::Server(args));
        for secret in CREDENTIALS.into_iter().chain(["dsn-user", "db.internal"]) {
            assert!(!shown.contains(secret), "{secret}");
        }
        assert!(shown.contains("port: 8080") && shown.contains(".."));
        Ok(())
    }

    /// The startup block is written at `INFO` on every start. It shows where the service
    /// connects, never a credential.
    #[tokio::test]
    async fn startup_log_names_no_credential() -> anyhow::Result<()> {
        let args = args_with_credentials()?;
        let logs = test_support::logs::capture_until("Startup configuration", || async {
            log_startup_args(&args);
        })
        .await?;
        assert!(logs.contains("https://openbao.internal:8200"));
        assert!(logs.contains("db.internal:5432/genesis"));
        assert!(logs.contains("openbao_role_id_set"));
        for secret in CREDENTIALS {
            assert!(!logs.contains(secret), "{secret}");
        }
        Ok(())
    }
}
