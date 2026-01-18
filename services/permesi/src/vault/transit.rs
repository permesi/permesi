use crate::cli::globals::GlobalArgs;
use anyhow::{Result, anyhow};
use base64ct::{Base64, Encoding};
use http::Method;
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
#[instrument(skip(globals, plaintext, context))]
pub async fn encrypt(globals: &GlobalArgs, plaintext: &str, context: &str) -> Result<String> {
    let token = globals
        .vault_transport
        .is_tcp()
        .then(|| globals.vault_token.expose_secret());

    // payload
    let mut map = HashMap::new();
    map.insert("plaintext", Base64::encode_string(plaintext.as_bytes()));
    map.insert("context", Base64::encode_string(context.as_bytes()));

    let response = globals
        .vault_transport
        .request_json(
            Method::POST,
            "/v1/transit/permesi/encrypt/users",
            token,
            Some(&serde_json::to_value(&map)?),
        )
        .await?;

    if !response.status.is_success() {
        let error_message = vault_error_message(&response.body);
        error!("Failed to encrypt: {}", error_message);
        return Err(anyhow!("{}, {}", response.status, error_message));
    }

    get_required_str(&response.body, &["data", "ciphertext"]).map_or_else(
        || {
            error!("Failed to encrypt, no ciphertext in response");
            Err(anyhow!("Failed to encrypt"))
        },
        |ciphertext| Ok(ciphertext.to_string()),
    )
}

#[instrument(skip(globals, ciphertext, context))]
/// # Errors
/// Returns an error if the Vault request fails, Vault returns a non-success status, the response is missing expected fields, or plaintext is not valid UTF-8.
pub async fn decrypt(globals: &GlobalArgs, ciphertext: &str, context: &str) -> Result<String> {
    let token = globals
        .vault_transport
        .is_tcp()
        .then(|| globals.vault_token.expose_secret());

    // payload
    let mut map = HashMap::new();
    map.insert("ciphertext", ciphertext.to_string());
    map.insert("context", Base64::encode_string(context.as_bytes()));

    let response = globals
        .vault_transport
        .request_json(
            Method::POST,
            "/v1/transit/permesi/decrypt/users",
            token,
            Some(&serde_json::to_value(&map)?),
        )
        .await?;

    if !response.status.is_success() {
        let error_message = vault_error_message(&response.body);
        error!("Failed to decrypt: {}", error_message);
        return Err(anyhow!("{}, {}", response.status, error_message));
    }

    let plaintext_b64 =
        get_required_str(&response.body, &["data", "plaintext"]).ok_or_else(|| {
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn vault_error_message_returns_first_error() {
        let value = json!({ "errors": ["denied"] });
        assert_eq!(vault_error_message(&value), "denied");
    }

    #[test]
    fn vault_error_message_returns_empty_when_missing() {
        let value = json!({ "error": "nope" });
        assert_eq!(vault_error_message(&value), "");
    }

    #[test]
    fn get_required_str_returns_nested_value() {
        let value = json!({ "data": { "ciphertext": "vault:v1:abc" } });
        assert_eq!(
            get_required_str(&value, &["data", "ciphertext"]),
            Some("vault:v1:abc")
        );
    }

    #[test]
    fn get_required_str_returns_none_for_missing_path() {
        let value = json!({ "data": {} });
        assert!(get_required_str(&value, &["data", "ciphertext"]).is_none());
    }
}
