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

#[cfg(test)]
mod tests {
    use super::read_opaque_seed;
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
    async fn read_opaque_seed_returns_bytes() -> Result<()> {
        if !can_bind_localhost() {
            eprintln!("Skipping test: cannot bind localhost");
            return Ok(());
        }
        let server = MockServer::start().await;
        let seed_bytes = [7u8; 32];
        let seed_b64 = base64::engine::general_purpose::STANDARD.encode(seed_bytes);

        Mock::given(method("GET"))
            .and(path("/v1/secret/permesi/data/opaque"))
            .and(header("X-Vault-Token", "vault-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": {"data": {"opaque_seed_b64": seed_b64}}
            })))
            .mount(&server)
            .await;

        let mut globals = GlobalArgs::new(server.uri());
        globals.set_token(SecretString::from("vault-token".to_string()));

        let seed = read_opaque_seed(&globals, "secret/permesi", "opaque").await?;
        assert_eq!(seed, seed_bytes);
        Ok(())
    }

    #[tokio::test]
    async fn read_opaque_seed_errors_on_missing_field() -> Result<()> {
        if !can_bind_localhost() {
            eprintln!("Skipping test: cannot bind localhost");
            return Ok(());
        }
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/v1/secret/permesi/data/opaque"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": {"data": {}}
            })))
            .mount(&server)
            .await;

        let globals = GlobalArgs::new(server.uri());
        let result = read_opaque_seed(&globals, "secret/permesi", "opaque").await;
        let err = result.err().ok_or_else(|| anyhow!("expected error"))?;
        assert!(err.to_string().contains("opaque seed missing"));
        Ok(())
    }

    #[tokio::test]
    async fn read_opaque_seed_errors_on_wrong_length() -> Result<()> {
        if !can_bind_localhost() {
            eprintln!("Skipping test: cannot bind localhost");
            return Ok(());
        }
        let server = MockServer::start().await;
        let seed_bytes = [1u8; 16];
        let seed_b64 = base64::engine::general_purpose::STANDARD.encode(seed_bytes);

        Mock::given(method("GET"))
            .and(path("/v1/secret/permesi/data/opaque"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": {"data": {"opaque_seed_b64": seed_b64}}
            })))
            .mount(&server)
            .await;

        let globals = GlobalArgs::new(server.uri());
        let result = read_opaque_seed(&globals, "secret/permesi", "opaque").await;
        let err = result.err().ok_or_else(|| anyhow!("expected error"))?;
        assert!(err.to_string().contains("opaque seed length"));
        Ok(())
    }
}
