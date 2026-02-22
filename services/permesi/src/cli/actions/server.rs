use crate::{api, cli::globals::GlobalArgs, vault};
use anyhow::{Context, Result, anyhow};
use secrecy::{ExposeSecret, SecretString};
use std::sync::Arc;
use tracing::{debug, info};
use url::Url;

#[derive(Debug)]
pub struct Args {
    pub port: u16,
    pub socket_path: Option<String>,
    pub dsn: String,
    pub vault_url: String,
    pub vault_target: vault_client::VaultTarget,
    pub vault_role_id: Option<String>,
    pub vault_secret_id: Option<String>,
    pub vault_wrapped_token: Option<String>,
    pub admission_paserk_url: String,
    pub admission_issuer: Option<String>,
    pub admission_audience: Option<String>,
    pub tls_pem_bundle: Option<String>,
    pub admission_paserk_ca_path: Option<String>,
    pub frontend_base_url: String,
    pub email_token_ttl_seconds: i64,
    pub email_resend_cooldown_seconds: i64,
    pub session_ttl_seconds: i64,
    pub email_outbox_poll_seconds: u64,
    pub email_outbox_batch_size: usize,
    pub email_outbox_max_attempts: u32,
    pub email_outbox_backoff_base_seconds: u64,
    pub email_outbox_backoff_max_seconds: u64,
    pub opaque_server_id: String,
    pub opaque_login_ttl_seconds: u64,
    pub platform_admin_ttl_seconds: i64,
    pub platform_recent_auth_seconds: i64,
    pub vault_kv_mount: String,
    pub vault_kv_path: String,
    pub vault_transit_mount: String,
}

/// Execute the server action.
/// # Errors
/// Returns an error if Vault login fails, DB credentials cannot be fetched, or the server fails to start.
pub async fn execute(args: Args) -> Result<()> {
    configure_tls_paths(&args);

    let issuer = args
        .admission_issuer
        .clone()
        .unwrap_or_else(|| "https://genesis.permesi.dev".to_string());
    let audience = args
        .admission_audience
        .clone()
        .unwrap_or_else(|| "permesi".to_string());
    let vault_addr = vault_base_url(&args.vault_url).unwrap_or_else(|_| args.vault_url.clone());
    log_startup_args(&args, &issuer, &audience, &vault_addr);

    let admission_verifier = Arc::new(if args.admission_paserk_url.trim().starts_with('{') {
        let keyset = admission_token::PaserkKeySet::from_json(&args.admission_paserk_url)
            .context("Failed to parse admission PASERK keyset from JSON string")?;
        api::handlers::AdmissionVerifier::new(keyset, issuer, audience)
    } else {
        api::handlers::AdmissionVerifier::new_remote(
            args.admission_paserk_url.clone(),
            issuer,
            audience,
        )
        .await?
    });

    let vault_transport = vault_client::VaultTransport::from_target(
        crate::APP_USER_AGENT,
        args.vault_target.clone(),
    )?;
    let mut globals = GlobalArgs::new(args.vault_url.clone(), vault_transport);
    globals.vault_transit_mount = args.vault_transit_mount.clone();

    if args.vault_target.is_tcp() {
        let vault_role_id = args
            .vault_role_id
            .as_deref()
            .ok_or_else(|| anyhow!("Vault role-id is required for TCP mode"))?;
        // If vault wrapped token try to unwrap, otherwise use secret-id.
        let vault_token: String = if let Some(wrapped) = &args.vault_wrapped_token {
            let vault_session_id = vault::unwrap(&globals.vault_url, wrapped).await?;
            let (token, _) =
                vault::approle_login(&globals.vault_url, &vault_session_id, vault_role_id).await?;
            token
        } else {
            let secret_id = args
                .vault_secret_id
                .as_deref()
                .ok_or_else(|| anyhow!("Vault secret-id is required"))?;
            let (token, _) =
                vault::approle_login(&globals.vault_url, secret_id, vault_role_id).await?;
            token
        };

        globals.set_token(SecretString::from(vault_token));
    }

    // Get database username and password from Vault
    vault::database::database_creds(&mut globals)
        .await
        .context("Could not get database username and password")?;

    debug!("Global args: {:?}", globals);

    let mut dsn = Url::parse(&args.dsn)?;

    // Set username & password from GlobalArgs
    dsn.set_username(&globals.vault_db_username)
        .map_err(|()| anyhow!("Error setting username"))?;

    dsn.set_password(Some(globals.vault_db_password.expose_secret()))
        .map_err(|()| anyhow!("Error setting password"))?;

    let app_config = build_app_config(&args, vault_addr);

    api::new(
        args.port,
        args.socket_path,
        dsn.to_string(),
        &globals,
        admission_verifier,
        app_config,
    )
    .await
}

fn build_app_config(args: &Args, vault_addr: String) -> api::AppConfig {
    let auth_config = api::handlers::auth::AuthConfig::new(args.frontend_base_url.clone())
        .with_email_token_ttl_seconds(args.email_token_ttl_seconds)
        .with_resend_cooldown_seconds(args.email_resend_cooldown_seconds)
        .with_session_ttl_seconds(args.session_ttl_seconds)
        .with_opaque_server_id(args.opaque_server_id.clone())
        .with_opaque_login_ttl_seconds(args.opaque_login_ttl_seconds);

    let admin_config = api::handlers::auth::AdminConfig::new(vault_addr)
        .with_vault_policy("permesi-operators".to_string())
        .with_admin_ttl_seconds(args.platform_admin_ttl_seconds)
        .with_recent_auth_seconds(args.platform_recent_auth_seconds);

    let email_config = api::email::EmailWorkerConfig::new()
        .with_poll_interval_seconds(args.email_outbox_poll_seconds)
        .with_batch_size(args.email_outbox_batch_size)
        .with_max_attempts(args.email_outbox_max_attempts)
        .with_backoff_base_seconds(args.email_outbox_backoff_base_seconds)
        .with_backoff_max_seconds(args.email_outbox_backoff_max_seconds);

    let kv_config = api::VaultKvConfig {
        mount: args.vault_kv_mount.clone(),
        path: args.vault_kv_path.clone(),
    };

    api::AppConfig {
        auth: auth_config,
        admin: admin_config,
        email: email_config,
        kv: kv_config,
    }
}

fn log_startup_args(args: &Args, issuer: &str, audience: &str, vault_addr: &str) {
    let mode = match args.vault_target {
        vault_client::VaultTarget::Tcp { .. } => "Direct Access (TCP)",
        vault_client::VaultTarget::AgentProxy { .. } => "Agent (Sidecar)",
    };

    let admission_paserk_ca = args
        .admission_paserk_ca_path
        .clone()
        .unwrap_or_else(|| "none (using system roots)".to_string());

    let listen_addr = if let Some(sock) = &args.socket_path {
        format!("unix:{sock}")
    } else {
        format!("tcp:{}", args.port)
    };

    let entries = [
        ("listen", listen_addr),
        ("dsn", redact_dsn(&args.dsn)),
        ("vault_url", args.vault_url.clone()),
        ("vault_addr", vault_addr.to_string()),
        ("vault_mode", mode.to_string()),
        (
            "vault_role_id",
            args.vault_role_id
                .clone()
                .unwrap_or_else(|| "n/a".to_string()),
        ),
        (
            "vault_secret_id_set",
            args.vault_secret_id.is_some().to_string(),
        ),
        (
            "vault_wrapped_token_set",
            args.vault_wrapped_token.is_some().to_string(),
        ),
        ("vault_policy", "permesi-operators".to_string()),
        (
            "tls_pem_bundle",
            args.tls_pem_bundle
                .clone()
                .unwrap_or_else(|| "none".to_string()),
        ),
        ("admission_paserk_url", args.admission_paserk_url.clone()),
        ("admission_paserk_ca_path", admission_paserk_ca),
        ("admission_issuer", issuer.to_string()),
        ("admission_audience", audience.to_string()),
        ("frontend_base_url", args.frontend_base_url.clone()),
        (
            "email_token_ttl_seconds",
            args.email_token_ttl_seconds.to_string(),
        ),
        (
            "email_resend_cooldown_seconds",
            args.email_resend_cooldown_seconds.to_string(),
        ),
        ("session_ttl_seconds", args.session_ttl_seconds.to_string()),
        (
            "email_outbox_poll_seconds",
            args.email_outbox_poll_seconds.to_string(),
        ),
        (
            "email_outbox_batch_size",
            args.email_outbox_batch_size.to_string(),
        ),
        (
            "email_outbox_max_attempts",
            args.email_outbox_max_attempts.to_string(),
        ),
        (
            "email_outbox_backoff_base_seconds",
            args.email_outbox_backoff_base_seconds.to_string(),
        ),
        (
            "email_outbox_backoff_max_seconds",
            args.email_outbox_backoff_max_seconds.to_string(),
        ),
        ("opaque_server_id", args.opaque_server_id.clone()),
        (
            "opaque_login_ttl_seconds",
            args.opaque_login_ttl_seconds.to_string(),
        ),
        (
            "platform_admin_ttl_seconds",
            args.platform_admin_ttl_seconds.to_string(),
        ),
        (
            "platform_recent_auth_seconds",
            args.platform_recent_auth_seconds.to_string(),
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
    let mut message = format!("{}\n\n{title}:", permesi_banner());
    for (key, value) in entries {
        let padding = " ".repeat(max_key_len.saturating_sub(key.len()));
        let _ =
            std::fmt::Write::write_fmt(&mut message, format_args!("\n  {key}:{padding} {value}"));
    }
    info!("{message}");
}

fn short_commit(hash: &str) -> String {
    let trimmed = hash.trim();
    if trimmed.len() > 7 {
        trimmed[..7].to_string()
    } else {
        trimmed.to_string()
    }
}

fn permesi_banner() -> String {
    let short_hash = short_commit(crate::GIT_COMMIT_HASH);
    PERMESI_BANNER.replace(
        "{VERSION}",
        &format!(" - {} - {}", env!("CARGO_PKG_VERSION"), short_hash),
    )
}

const PERMESI_BANNER: &str = r"
   *     *
 *   * *   *
   *  *  *
    \ | /
     \|/
  ----+----  P E R M E S I {VERSION}
     /|\
    / | \
   *  *  *
 *   * *   *
   *     *";

fn vault_base_url(url: &str) -> Result<String> {
    let parsed = Url::parse(url).context("Invalid Vault URL")?;
    let host = parsed
        .host_str()
        .ok_or_else(|| anyhow!("Vault URL missing host"))?;
    let port = parsed
        .port_or_known_default()
        .ok_or_else(|| anyhow!("Vault URL missing port"))?;
    Ok(format!("{}://{}:{}", parsed.scheme(), host, port))
}

fn configure_tls_paths(args: &Args) {
    if let Some(bundle_path) = &args.tls_pem_bundle {
        crate::tls::set_runtime_paths(crate::tls::TlsPaths::new(
            std::path::PathBuf::from(bundle_path),
            args.admission_paserk_ca_path
                .clone()
                .map(std::path::PathBuf::from),
        ));
    } else if let Some(ca_path) = &args.admission_paserk_ca_path {
        // Socket mode: no server TLS bundle, but we need CA for client (AdmissionVerifier).
        // Initialize TlsPaths with the CA path as a placeholder for the bundle.
        // This allows runtime_paths() to succeed.
        // load_server_config() would fail, but it's not called in socket mode.
        crate::tls::set_runtime_paths(crate::tls::TlsPaths::new(
            std::path::PathBuf::from(ca_path),
            Some(std::path::PathBuf::from(ca_path)),
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_args() -> Args {
        Args {
            port: 8080,
            socket_path: None,
            dsn: "postgres://user:pass@localhost:5432/db".to_string(),
            vault_url: "http://localhost:8200".to_string(),
            vault_target: vault_client::VaultTarget::Tcp {
                base_url: "http://localhost:8200".to_string(),
            },
            vault_role_id: None,
            vault_secret_id: None,
            vault_wrapped_token: None,
            admission_paserk_url: "https://genesis.example.com/paserk.json".to_string(),
            admission_issuer: None,
            admission_audience: None,
            tls_pem_bundle: None,
            admission_paserk_ca_path: None,
            frontend_base_url: "https://permesi.example.com".to_string(),
            email_token_ttl_seconds: 300,
            email_resend_cooldown_seconds: 60,
            session_ttl_seconds: 3600,
            email_outbox_poll_seconds: 10,
            email_outbox_batch_size: 100,
            email_outbox_max_attempts: 3,
            email_outbox_backoff_base_seconds: 2,
            email_outbox_backoff_max_seconds: 60,
            opaque_server_id: "server-id".to_string(),
            opaque_login_ttl_seconds: 60,
            platform_admin_ttl_seconds: 3600,
            platform_recent_auth_seconds: 60,
            vault_kv_mount: "kv".to_string(),
            vault_kv_path: "config".to_string(),
            vault_transit_mount: "transit/permesi".to_string(),
        }
    }

    #[test]
    fn test_socket_mode_sets_tls_paths() {
        let mut args = default_args();
        // Socket mode simulation: No bundle, but CA path present
        args.tls_pem_bundle = None;
        args.admission_paserk_ca_path = Some("/tmp/ca.pem".to_string());

        configure_tls_paths(&args);

        // Verify that runtime paths are set
        // Note: In a shared test environment (cargo test), this might fail if another test set it differently.
        // However, for unit testing permesi crate, this should be consistent if run in isolation or first.
        let paths = crate::tls::runtime_paths();
        assert!(
            paths.is_ok(),
            "TLS paths should be configured in socket mode"
        );

        if let Ok(p) = paths {
            // Check if the extra CA path matches what we set
            assert_eq!(p.extra_ca_path(), Some(std::path::Path::new("/tmp/ca.pem")));
        }
    }

    #[test]
    fn test_tls_mode_sets_tls_paths() {
        let mut args = default_args();
        args.tls_pem_bundle = Some("/tmp/bundle.pem".to_string());
        args.admission_paserk_ca_path = Some("/tmp/ca.pem".to_string());

        configure_tls_paths(&args);

        let paths = crate::tls::runtime_paths();
        assert!(paths.is_ok(), "TLS paths should be configured in TLS mode");
    }
}
