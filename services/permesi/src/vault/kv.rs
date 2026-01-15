use crate::{cli::globals::GlobalArgs, vault};
use anyhow::{Context, Result, anyhow};
use base64::Engine;
use reqwest::Client;
use secrecy::ExposeSecret;
use serde_json::Value;
use tracing::{Instrument, info_span, instrument};

const OPAQUE_SEED_FIELD: &str = "opaque_server_seed";
const MFA_PEPPER_FIELD: &str = "mfa_recovery_pepper";
const OPAQUE_SEED_LEN: usize = 32;

pub struct ConfigSecrets {
    pub opaque_server_seed: [u8; OPAQUE_SEED_LEN],
    pub mfa_recovery_pepper: Vec<u8>,
}

#[instrument(skip(globals))]
/// Reads Permesi configuration secrets from Vault KV.
///
/// # Errors
/// Returns an error if the Vault request fails, or required fields are missing or invalid.
pub async fn read_config_secrets(
    globals: &GlobalArgs,
    kv_mount: &str,
    kv_path: &str,
) -> Result<ConfigSecrets> {
    let client = Client::builder()
        .user_agent(crate::api::APP_USER_AGENT)
        .build()?;
    let path = format!("/v1/{kv_mount}/data/{kv_path}");
    let url = vault::endpoint_url(&globals.vault_url, &path)?;

    let span = info_span!(
        "vault.kv.read_config",
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
    let data = json
        .get("data")
        .and_then(|data| data.get("data"))
        .ok_or_else(|| anyhow!("secret data missing from vault response"))?;

    // 1. Read OPAQUE seed
    let seed_b64 = data
        .get(OPAQUE_SEED_FIELD)
        .and_then(Value::as_str)
        .context("opaque server seed missing from vault config")?;

    let decoded_seed = base64::engine::general_purpose::STANDARD
        .decode(seed_b64)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(seed_b64))
        .context("opaque seed is not valid base64")?;

    if decoded_seed.len() != OPAQUE_SEED_LEN {
        return Err(anyhow!(
            "opaque seed length is {}, expected {}",
            decoded_seed.len(),
            OPAQUE_SEED_LEN
        ));
    }

    let mut opaque_server_seed = [0u8; OPAQUE_SEED_LEN];
    opaque_server_seed.copy_from_slice(&decoded_seed);

    // 2. Read MFA recovery pepper
    let pepper_b64 = data
        .get(MFA_PEPPER_FIELD)
        .and_then(Value::as_str)
        .context("mfa recovery pepper missing from vault config")?;

    let mfa_recovery_pepper = base64::engine::general_purpose::STANDARD
        .decode(pepper_b64)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(pepper_b64))
        .context("mfa recovery pepper is not valid base64")?;

    Ok(ConfigSecrets {
        opaque_server_seed,
        mfa_recovery_pepper,
    })
}

#[cfg(test)]
mod tests {
    use super::read_config_secrets;
    use crate::cli::globals::GlobalArgs;
    use anyhow::{Result, anyhow};
    use base64::Engine;
    use secrecy::SecretString;
    use serde_json::json;
    use std::net::TcpListener;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn can_bind_localhost() -> bool {
        TcpListener::bind("127.0.0.1:0").is_ok()
    }

    #[tokio::test]
    async fn read_config_secrets_returns_expected_data() -> Result<()> {
        if !can_bind_localhost() {
            eprintln!("Skipping test: cannot bind localhost");
            return Ok(());
        }
        let server = MockServer::start().await;
        let seed_bytes = [7u8; 32];
        let seed_b64 = base64::engine::general_purpose::STANDARD.encode(seed_bytes);
        let pepper_bytes = b"my-pepper";
        let pepper_b64 = base64::engine::general_purpose::STANDARD.encode(pepper_bytes);

        Mock::given(method("GET"))
            .and(path("/v1/secret/permesi/data/config"))
            .and(header("X-Vault-Token", "vault-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": {
                    "data": {
                        "opaque_server_seed": seed_b64,
                        "mfa_recovery_pepper": pepper_b64
                    }
                }
            })))
            .mount(&server)
            .await;

        let mut globals = GlobalArgs::new(server.uri());
        globals.set_token(SecretString::from("vault-token".to_string()));

        let secrets = read_config_secrets(&globals, "secret/permesi", "config").await?;
        assert_eq!(secrets.opaque_server_seed, seed_bytes);
        assert_eq!(secrets.mfa_recovery_pepper, pepper_bytes);
        Ok(())
    }

    #[tokio::test]
    async fn read_config_secrets_errors_on_missing_field() -> Result<()> {
        if !can_bind_localhost() {
            eprintln!("Skipping test: cannot bind localhost");
            return Ok(());
        }
        let server = MockServer::start().await;
        let seed_bytes = [7u8; 32];
        let seed_b64 = base64::engine::general_purpose::STANDARD.encode(seed_bytes);

        Mock::given(method("GET"))
            .and(path("/v1/secret/permesi/data/config"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": {"data": {"opaque_server_seed": seed_b64}}
            })))
            .mount(&server)
            .await;

        let globals = GlobalArgs::new(server.uri());
        let result = read_config_secrets(&globals, "secret/permesi", "config").await;
        let err = result.err().ok_or_else(|| anyhow!("expected error"))?;
        assert!(err.to_string().contains("mfa recovery pepper missing"));
        Ok(())
    }
}
