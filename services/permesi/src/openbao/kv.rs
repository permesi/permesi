//! OpenBao KV v2 client for reading Permesi configuration secrets.
//!
//! This module provides helpers for loading application-wide secrets like the
//! OPAQUE server seed and MFA recovery pepper from OpenBao's static KV engine.

use crate::cli::globals::GlobalArgs;
use anyhow::{Context, Result, anyhow};
use base64::{Engine, engine::general_purpose};
use http::Method;
use secrecy::ExposeSecret;
use serde_json::Value;
use tracing::instrument;

const OPAQUE_SEED_FIELD: &str = "opaque_server_seed";
const MFA_PEPPER_FIELD: &str = "mfa_recovery_pepper";
const OPAQUE_SEED_LEN: usize = 32;

/// Application configuration secrets loaded from OpenBao.
pub struct ConfigSecrets {
    /// 32-byte seed for OPAQUE server setup.
    pub opaque_server_seed: [u8; OPAQUE_SEED_LEN],
    /// Server-side pepper for recovery code hashing.
    pub mfa_recovery_pepper: Vec<u8>,
}

#[instrument(skip(globals))]
/// Reads Permesi configuration secrets from OpenBao KV.
///
/// # Errors
/// Returns an error if the OpenBao request fails, or required fields are missing or invalid.
pub async fn read_config_secrets(
    globals: &GlobalArgs,
    kv_mount: &str,
    kv_path: &str,
) -> Result<ConfigSecrets> {
    let token = globals
        .openbao_transport
        .is_tcp()
        .then(|| globals.openbao_token.expose_secret());

    let path = format!("/v1/{kv_mount}/data/{kv_path}");

    let response = globals
        .openbao_transport
        .request_json(Method::GET, &path, token, None)
        .await?;

    if !response.status.is_success() {
        let status = response.status;
        // Try to get body text if possible, but OpenBaoResponse body is Value.
        // We can stringify it.
        let body = response.body.to_string();
        return Err(anyhow!("bao kv read failed: {status} {body}"));
    }

    let data = response
        .body
        .get("data")
        .and_then(|data| data.get("data"))
        .ok_or_else(|| anyhow!("secret data missing from openbao response"))?;

    // 1. Read OPAQUE seed
    let seed_b64 = data
        .get(OPAQUE_SEED_FIELD)
        .and_then(Value::as_str)
        .context("opaque server seed missing from openbao config")?;

    let decoded_seed = general_purpose::STANDARD
        .decode(seed_b64)
        .or_else(|_| general_purpose::URL_SAFE_NO_PAD.decode(seed_b64))
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
        .context("mfa recovery pepper missing from openbao config")?;

    let mfa_recovery_pepper = general_purpose::STANDARD
        .decode(pepper_b64)
        .or_else(|_| general_purpose::URL_SAFE_NO_PAD.decode(pepper_b64))
        .context("mfa recovery pepper is not valid base64")?;

    Ok(ConfigSecrets {
        opaque_server_seed,
        mfa_recovery_pepper,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::read_config_secrets;
    use crate::cli::globals::GlobalArgs;
    use anyhow::{Result, anyhow};
    use base64::{Engine, engine::general_purpose};
    use openbao_client::{OpenBaoTarget, OpenBaoTransport};
    use secrecy::SecretString;
    use serde_json::json;
    use std::net::TcpListener;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn can_bind_localhost() -> bool {
        TcpListener::bind("127.0.0.1:0").is_ok()
    }

    fn create_global_args(url: &str) -> GlobalArgs {
        let target = OpenBaoTarget::parse(url).unwrap();
        let transport = OpenBaoTransport::from_target("test", target).unwrap();
        GlobalArgs::new(url.to_string(), transport)
    }

    #[tokio::test]
    async fn read_config_secrets_returns_expected_data() -> Result<()> {
        if !can_bind_localhost() {
            eprintln!("Skipping test: cannot bind localhost");
            return Ok(());
        }
        let server = MockServer::start().await;
        let seed_bytes = [7u8; 32];
        let seed_b64 = general_purpose::STANDARD.encode(seed_bytes);
        let pepper_bytes = b"my-pepper";
        let pepper_b64 = general_purpose::STANDARD.encode(pepper_bytes);

        Mock::given(method("GET"))
            .and(path("/v1/secret/permesi/data/config"))
            .and(header("X-Vault-Token", "openbao-token"))
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

        let mut globals = create_global_args(&server.uri());
        globals.set_token(SecretString::from("openbao-token".to_string()));

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
        let seed_b64 = general_purpose::STANDARD.encode(seed_bytes);

        Mock::given(method("GET"))
            .and(path("/v1/secret/permesi/data/config"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": {"data": {"opaque_server_seed": seed_b64}}
            })))
            .mount(&server)
            .await;

        let globals = create_global_args(&server.uri());
        let result = read_config_secrets(&globals, "secret/permesi", "config").await;
        let err = result.err().ok_or_else(|| anyhow!("expected error"))?;
        assert!(err.to_string().contains("mfa recovery pepper missing"));
        Ok(())
    }
}
