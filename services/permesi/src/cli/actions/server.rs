use crate::{api, cli::globals::GlobalArgs, vault};
use admission_token::PaserkKeySet;
use anyhow::{Context, Result, anyhow};
use secrecy::{ExposeSecret, SecretString};
use std::{fs, sync::Arc};
use tracing::debug;
use url::Url;

#[derive(Debug)]
pub struct Args {
    pub port: u16,
    pub dsn: String,
    pub vault_url: String,
    pub vault_role_id: String,
    pub vault_secret_id: Option<String>,
    pub vault_wrapped_token: Option<String>,
    pub admission_paserk: Option<String>,
    pub admission_paserk_path: Option<String>,
    pub admission_paserk_url: Option<String>,
    pub admission_issuer: Option<String>,
    pub admission_audience: Option<String>,
    pub zero_token_validate_url: String,
    pub frontend_base_url: String,
    pub email_token_ttl_seconds: i64,
    pub email_resend_cooldown_seconds: i64,
    pub email_outbox_poll_seconds: u64,
    pub email_outbox_batch_size: usize,
    pub email_outbox_max_attempts: u32,
    pub email_outbox_backoff_base_seconds: u64,
    pub email_outbox_backoff_max_seconds: u64,
    pub opaque_kv_mount: String,
    pub opaque_kv_path: String,
    pub opaque_server_id: String,
    pub opaque_login_ttl_seconds: u64,
}

/// Execute the server action.
/// # Errors
/// Returns an error if Vault login fails, DB credentials cannot be fetched, or the server fails to start.
pub async fn execute(args: Args) -> Result<()> {
    let issuer = args
        .admission_issuer
        .unwrap_or_else(|| "https://genesis.permesi.dev".to_string());
    let audience = args
        .admission_audience
        .unwrap_or_else(|| "permesi".to_string());

    let admission_verifier = if let Some(url) = &args.admission_paserk_url {
        Arc::new(api::handlers::AdmissionVerifier::new_remote(url.clone(), issuer, audience).await?)
    } else {
        let keyset_json = if let Some(path) = &args.admission_paserk_path {
            fs::read_to_string(path)
                .with_context(|| format!("Failed to read PASERK file: {path}"))?
        } else if let Some(keyset) = &args.admission_paserk {
            keyset.clone()
        } else {
            return Err(anyhow!("Admission PASERK keyset is required"));
        };

        let keyset =
            PaserkKeySet::from_json(&keyset_json).context("Invalid admission PASERK JSON")?;
        keyset
            .validate()
            .context("Invalid admission PASERK keyset")?;
        Arc::new(api::handlers::AdmissionVerifier::new(
            keyset, issuer, audience,
        ))
    };

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

    let auth_config =
        api::handlers::auth::AuthConfig::new(args.zero_token_validate_url, args.frontend_base_url)
            .with_email_token_ttl_seconds(args.email_token_ttl_seconds)
            .with_resend_cooldown_seconds(args.email_resend_cooldown_seconds)
            .with_opaque_kv_mount(args.opaque_kv_mount)
            .with_opaque_kv_path(args.opaque_kv_path)
            .with_opaque_server_id(args.opaque_server_id)
            .with_opaque_login_ttl_seconds(args.opaque_login_ttl_seconds);

    let email_config = api::email::EmailWorkerConfig::new()
        .with_poll_interval_seconds(args.email_outbox_poll_seconds)
        .with_batch_size(args.email_outbox_batch_size)
        .with_max_attempts(args.email_outbox_max_attempts)
        .with_backoff_base_seconds(args.email_outbox_backoff_base_seconds)
        .with_backoff_max_seconds(args.email_outbox_backoff_max_seconds);

    api::new(
        args.port,
        dsn.to_string(),
        &globals,
        admission_verifier,
        auth_config,
        email_config,
    )
    .await
}
