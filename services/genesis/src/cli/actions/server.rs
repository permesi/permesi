use crate::{api, cli::globals::GlobalArgs, openbao};
use anyhow::{Context, Result, anyhow};
use secrecy::{ExposeSecret, SecretString};
use service_utils::database::PoolConfig;
use tracing::{debug, info};
use url::Url;

#[derive(Debug)]
pub struct Args {
    pub port: u16,
    pub socket_path: Option<String>,
    pub dsn: String,
    pub db_pool: PoolConfig,
    pub openbao_url: String,
    pub openbao_target: openbao::OpenBaoTarget,
    pub openbao_kubernetes: Option<openbao_client::kubernetes::KubernetesAuth>,
    pub openbao_role_id: Option<String>,
    pub openbao_secret_id: Option<String>,
    pub openbao_wrapped_token: Option<String>,
    pub openbao_transit_mount: String,
    pub tls_pem_bundle: Option<String>,
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
        let (token, _) = openbao_client::kubernetes::kubernetes_login(
            crate::APP_USER_AGENT,
            &globals.openbao_url,
            config,
        )
        .await?;
        globals.set_token(token);
    } else if matches!(args.openbao_target, openbao::OpenBaoTarget::Tcp { .. }) {
        let openbao_role_id = args
            .openbao_role_id
            .as_deref()
            .ok_or_else(|| anyhow!("OpenBao role-id is required"))?;
        let login_url = openbao::approle_login_url(&globals.openbao_url)?;

        // If openbao wrapped token try to unwrap, otherwise use secret-id.
        let openbao_token: String = if let Some(wrapped) = &args.openbao_wrapped_token {
            let openbao_session_id = openbao::unwrap(&globals.openbao_url, wrapped).await?;
            let (token, _) =
                openbao::approle_login(&login_url, &openbao_session_id, openbao_role_id).await?;
            token
        } else {
            let secret_id = args
                .openbao_secret_id
                .as_deref()
                .ok_or_else(|| anyhow!("OpenBao secret-id is required"))?;
            let (token, _) = openbao::approle_login(&login_url, secret_id, openbao_role_id).await?;
            token
        };

        globals.set_token(SecretString::from(openbao_token));
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
        &globals,
    )
    .await
}

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
        ("dsn", redact_dsn(&args.dsn)),
        ("db_pool", args.db_pool.to_string()),
        ("openbao_url", args.openbao_url.clone()),
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
            "openbao_role_id",
            args.openbao_role_id
                .clone()
                .unwrap_or_else(|| "n/a".to_string()),
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
    ];
    log_entries("Startup configuration", &entries);
}

fn redact_dsn(dsn: &str) -> String {
    match Url::parse(dsn) {
        Ok(mut parsed) => {
            if parsed.password().is_some() {
                let _ = parsed.set_password(Some("REDACTED"));
            }
            parsed.to_string()
        }
        Err(_) => "invalid-dsn".to_string(),
    }
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
