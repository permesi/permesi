use crate::{cli::globals::GlobalArgs, vault};
use anyhow::{anyhow, Result};
use base64ct::{Base64, Encoding};
use reqwest::Client;
use secrecy::ExposeSecret;
use serde_json::Value;
use std::collections::HashMap;
use tracing::{error, instrument};

/// encrypt using transit engine
#[instrument]
pub async fn encrypt(globals: &GlobalArgs, plaintext: &str, context: &str) -> Result<String> {
    let client = Client::builder()
        .user_agent(vault::APP_USER_AGENT)
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

        let error_message = json_response["errors"][0].as_str().unwrap_or_default();

        error!("Failed to encrypt: {}", error_message);

        return Err(anyhow!("{}, {}", status, error_message));
    }

    let json_response: Value = response.json().await?;

    json_response["data"]["ciphertext"].as_str().map_or_else(
        || {
            error!("Failed to encrypt, no ciphertext in response");

            Err(anyhow!("Failed to encrypt"))
        },
        |ciphertext| Ok(ciphertext.to_string()),
    )
}
