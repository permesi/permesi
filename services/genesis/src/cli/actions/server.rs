use crate::{api, cli::globals::GlobalArgs, vault};
use anyhow::{Context, Result, anyhow};
use secrecy::{ExposeSecret, SecretString};
use tracing::{debug, info};
use url::Url;

#[derive(Debug)]
pub struct Args {
    pub port: u16,
    pub dsn: String,
    pub vault_url: String,
    pub vault_role_id: String,
    pub vault_secret_id: Option<String>,
    pub vault_wrapped_token: Option<String>,
    pub tls_cert_path: String,
    pub tls_key_path: String,
    pub tls_ca_path: String,
}

/// Execute the server action.
/// # Errors
/// Returns an error if Vault login fails, DB credentials cannot be fetched, or the server fails to start.
pub async fn execute(args: Args) -> Result<()> {
    crate::tls::set_runtime_paths(crate::tls::TlsPaths::from_cli(
        args.tls_cert_path.clone(),
        args.tls_key_path.clone(),
        args.tls_ca_path.clone(),
    ));
    log_startup_args(&args);
    let mut globals = GlobalArgs::new(args.vault_url);

    // If vault wrapped token try to unwrap, otherwise use secret-id.
    let vault_token: String = if let Some(wrapped) = &args.vault_wrapped_token {
        let vault_session_id = vault::unwrap(&globals.vault_url, wrapped).await?;
        let (token, _) =
            vault::approle_login(&globals.vault_url, &vault_session_id, &args.vault_role_id)
                .await?;
        token
    } else {
        let secret_id = args
            .vault_secret_id
            .as_deref()
            .ok_or_else(|| anyhow!("Vault secret-id is required"))?;
        let (token, _) =
            vault::approle_login(&globals.vault_url, secret_id, &args.vault_role_id).await?;
        token
    };

    globals.set_token(SecretString::from(vault_token));

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

    api::new(args.port, dsn.to_string(), &globals).await
}

fn log_startup_args(args: &Args) {
    let entries = [
        ("port", args.port.to_string()),
        ("dsn", redact_dsn(&args.dsn)),
        ("vault_url", args.vault_url.clone()),
        ("vault_role_id", args.vault_role_id.clone()),
        (
            "vault_secret_id_set",
            args.vault_secret_id.is_some().to_string(),
        ),
        (
            "vault_wrapped_token_set",
            args.vault_wrapped_token.is_some().to_string(),
        ),
        ("tls_cert_path", args.tls_cert_path.clone()),
        ("tls_key_path", args.tls_key_path.clone()),
        ("tls_ca_path", args.tls_ca_path.clone()),
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
    let mut message = format!("{}\n{title}:", genesis_banner());
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
