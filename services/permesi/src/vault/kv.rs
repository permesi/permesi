use crate::{cli::globals::GlobalArgs, vault};
use anyhow::{Context, Result, anyhow};
use base64::Engine;
use reqwest::Client;
use secrecy::ExposeSecret;
use serde_json::Value;
use tracing::{Instrument, info_span, instrument};

const OPAQUE_SEED_FIELD: &str = "opaque_seed_b64";
const OPAQUE_SEED_LEN: usize = 32;

#[instrument(skip(globals))]
/// # Errors
/// Returns an error if the Vault request fails, the secret is missing, or the seed is invalid.
pub async fn read_opaque_seed(
    globals: &GlobalArgs,
    kv_mount: &str,
    kv_path: &str,
) -> Result<[u8; OPAQUE_SEED_LEN]> {
    let client = Client::builder()
        .user_agent(crate::api::APP_USER_AGENT)
        .build()?;
    let path = format!("/v1/{kv_mount}/data/{kv_path}");
    let url = vault::endpoint_url(&globals.vault_url, &path)?;

    let span = info_span!(
        "vault.kv.read",
        http.method = "GET",
        url = %url
    );
    let response = client
        .get(&url)
        .header("X-Vault-Token", globals.vault_token.expose_secret())
        .send()
        .instrument(span)
        .await?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(anyhow!("vault kv read failed: {status} {body}"));
    }

    let json: Value = response.json().await?;
    let seed_b64 = json
        .get("data")
        .and_then(|data| data.get("data"))
        .and_then(|data| data.get(OPAQUE_SEED_FIELD))
        .and_then(Value::as_str)
        .context("opaque seed missing from vault response")?;

    let decoded = base64::engine::general_purpose::STANDARD
        .decode(seed_b64)
        .context("opaque seed is not valid base64")?;
    if decoded.len() != OPAQUE_SEED_LEN {
        return Err(anyhow!(
            "opaque seed length is {}, expected {}",
            decoded.len(),
            OPAQUE_SEED_LEN
        ));
    }

    let mut seed = [0u8; OPAQUE_SEED_LEN];
    seed.copy_from_slice(&decoded);
    Ok(seed)
}
