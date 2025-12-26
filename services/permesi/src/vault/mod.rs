pub mod database;
pub mod renew;
pub mod transit;

use crate::permesi::APP_USER_AGENT;
use anyhow::Result;
use tracing::instrument;

#[instrument]
/// # Errors
/// Returns an error if `url` cannot be parsed, has no host, or uses an unsupported scheme.
pub fn endpoint_url(url: &str, path: &str) -> Result<String> {
    vault_client::endpoint_url(url, path)
}

/// Unwrap a wrapped Vault client token
/// Create wrapped token with:
/// vault write -wrap-ttl=300s -f auth/approle/role/permesi/secret-id
/// # Errors
/// Returns an error if the Vault request fails, Vault returns a non-success status, or the response is missing expected fields.
#[instrument(skip(token))]
pub async fn unwrap(url: &str, token: &str) -> Result<String> {
    vault_client::unwrap(APP_USER_AGENT, url, token).await
}

/// Login to Vault using `AppRole`
/// Create a secret ID with:
/// vault write -f auth/approle/role/permesi/secret-id
/// # Errors
/// Returns an error if the Vault request fails, Vault returns a non-success status, or the response is missing expected fields.
#[instrument(skip(sid))]
pub async fn approle_login(url: &str, sid: &str, rid: &str) -> Result<(String, u64)> {
    vault_client::approle_login(APP_USER_AGENT, url, sid, rid).await
}
