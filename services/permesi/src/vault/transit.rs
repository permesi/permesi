use crate::{cli::globals::GlobalArgs, permesi, vault};
use anyhow::{Result, anyhow};
use base64ct::{Base64, Encoding};
use reqwest::Client;
use secrecy::ExposeSecret;
use serde_json::Value;
use std::collections::HashMap;
use tracing::{error, instrument};

fn vault_error_message(json_response: &Value) -> &str {
    json_response
        .get("errors")
        .and_then(|v| v.get(0))
        .and_then(Value::as_str)
        .unwrap_or_default()
}

fn get_required_str<'a>(json_response: &'a Value, path: &[&str]) -> Option<&'a str> {
    let mut current = json_response;
    for key in path {
        current = current.get(*key)?;
    }
    current.as_str()
}

/// Encrypt using Vault transit engine
/// # Errors
/// Returns an error if the Vault request fails, Vault returns a non-success status, or the response is missing expected fields.
#[instrument]
pub async fn encrypt(globals: &GlobalArgs, plaintext: &str, context: &str) -> Result<String> {
    let client = Client::builder()
        .user_agent(permesi::APP_USER_AGENT)
        .build()?;

    // Parse the URL
    let encrypt = vault::endpoint_url(&globals.vault_url, "/v1/transit/permesi/encrypt/users")?;

    // payload
    let mut map = HashMap::new();
    map.insert("plaintext", Base64::encode_string(plaintext.as_bytes()));
    map.insert("context", Base64::encode_string(context.as_bytes()));

    let response = client
        .post(encrypt.as_str())
        .header("X-Vault-Token", globals.vault_token.expose_secret())
        .json(&map)
        .send()
        .await?;

    if !response.status().is_success() {
        let status = response.status();
        let json_response: Value = response.json().await?;

        let error_message = vault_error_message(&json_response);

        error!("Failed to encrypt: {}", error_message);

        return Err(anyhow!("{status}, {error_message}"));
    }

    let json_response: Value = response.json().await?;

    get_required_str(&json_response, &["data", "ciphertext"]).map_or_else(
        || {
            error!("Failed to encrypt, no ciphertext in response");
            Err(anyhow!("Failed to encrypt"))
        },
        |ciphertext| Ok(ciphertext.to_string()),
    )
}

#[instrument]
/// # Errors
/// Returns an error if the Vault request fails, Vault returns a non-success status, the response is missing expected fields, or plaintext is not valid UTF-8.
pub async fn decrypt(globals: &GlobalArgs, ciphertext: &str, context: &str) -> Result<String> {
    let client = Client::builder()
        .user_agent(permesi::APP_USER_AGENT)
        .build()?;

    // Parse the URL
    let encrypt = vault::endpoint_url(&globals.vault_url, "/v1/transit/permesi/decrypt/users")?;

    // payload
    let mut map = HashMap::new();
    map.insert("ciphertext", ciphertext.to_string());
    map.insert("context", Base64::encode_string(context.as_bytes()));

    let response = client
        .post(encrypt.as_str())
        .header("X-Vault-Token", globals.vault_token.expose_secret())
        .json(&map)
        .send()
        .await?;

    if !response.status().is_success() {
        let status = response.status();
        let json_response: Value = response.json().await?;

        let error_message = vault_error_message(&json_response);

        error!("Failed to decrypt: {}", error_message);

        return Err(anyhow!("{status}, {error_message}"));
    }

    let json_response: Value = response.json().await?;

    let plaintext_b64 =
        get_required_str(&json_response, &["data", "plaintext"]).ok_or_else(|| {
            error!("Failed to decrypt, no plaintext in response");
            anyhow!("Failed to decrypt")
        })?;

    let decoded = Base64::decode_vec(plaintext_b64).map_err(|e| {
        error!("Failed to decode plaintext: {}", e);
        anyhow!("Failed to decode plaintext")
    })?;

    String::from_utf8(decoded).map_err(|e| {
        error!("Failed to convert plaintext to string: {}", e);
        anyhow!("Failed to convert plaintext to string")
    })
}
