use anyhow::{Result, anyhow};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use reqwest::Client;
use secrecy::ExposeSecret;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use tracing::{error, instrument};

use crate::vault;

#[derive(Debug, Clone)]
pub struct TransitKeySet {
    pub latest_version: u32,
    pub keys: BTreeMap<u32, String>,
}

#[derive(Debug, Clone)]
pub struct VaultSignature {
    pub key_version: u32,
    pub signature_base64: String,
}

fn vault_error_message(json_response: &Value) -> &str {
    json_response
        .get("errors")
        .and_then(|v| v.get(0))
        .and_then(Value::as_str)
        .unwrap_or("")
}

fn get_required_str<'a>(json_response: &'a Value, path: &[&str]) -> Option<&'a str> {
    let mut current = json_response;
    for key in path {
        current = current.get(*key)?;
    }
    current.as_str()
}

fn parse_key_version(version: u64) -> Result<u32> {
    u32::try_from(version).map_err(|_| anyhow!("invalid key version: {version}"))
}

fn parse_signature(signature: &str) -> Result<VaultSignature> {
    let mut parts = signature.split(':');
    let prefix = parts
        .next()
        .ok_or_else(|| anyhow!("invalid vault signature"))?;
    let version_part = parts
        .next()
        .ok_or_else(|| anyhow!("invalid vault signature"))?;
    let sig_b64 = parts
        .next()
        .ok_or_else(|| anyhow!("invalid vault signature"))?;
    if parts.next().is_some() {
        return Err(anyhow!("invalid vault signature"));
    }
    if prefix != "vault" {
        return Err(anyhow!("invalid vault signature prefix"));
    }
    let version = version_part
        .strip_prefix('v')
        .ok_or_else(|| anyhow!("invalid vault signature version"))?;
    let key_version = version
        .parse::<u32>()
        .map_err(|_| anyhow!("invalid key version"))?;
    Ok(VaultSignature {
        key_version,
        signature_base64: sig_b64.to_string(),
    })
}

fn transit_path(mount: &str, suffix: &str) -> String {
    let mount = mount.trim_matches('/');
    format!("/v1/{mount}/{suffix}")
}

/// Fetch Ed25519 public keys from Vault transit.
///
/// # Errors
/// Returns an error if the Vault request fails or the response is missing key data.
#[instrument(skip(client, vault_token))]
pub async fn fetch_ed25519_keys(
    client: &Client,
    vault_url: &str,
    vault_token: &secrecy::SecretString,
    transit_mount: &str,
    key_name: &str,
) -> Result<TransitKeySet> {
    let keys_url = vault::endpoint_url(
        vault_url,
        &transit_path(transit_mount, &format!("keys/{key_name}")),
    )?;

    let response = client
        .get(&keys_url)
        .header("X-Vault-Token", vault_token.expose_secret())
        .send()
        .await?;

    if !response.status().is_success() {
        let status = response.status();
        let json_response: Value = response.json().await?;
        let error_message = vault_error_message(&json_response);
        error!("Failed to fetch transit keys: {error_message}");
        return Err(anyhow!("{keys_url} - {status}, {error_message}"));
    }

    let json_response: Value = response.json().await?;
    let data = json_response
        .get("data")
        .ok_or_else(|| anyhow!("missing data in transit response"))?;

    let key_type = data.get("type").and_then(Value::as_str).unwrap_or("");
    if key_type != "ed25519" {
        return Err(anyhow!("unexpected transit key type: {key_type}"));
    }

    let latest_version = data
        .get("latest_version")
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("missing latest_version in transit response"))?;
    let latest_version = parse_key_version(latest_version)?;

    let keys_obj = data
        .get("keys")
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow!("missing keys in transit response"))?;

    let mut keys = BTreeMap::new();
    for (version_str, entry) in keys_obj {
        let version = version_str
            .parse::<u32>()
            .map_err(|_| anyhow!("invalid transit key version: {version_str}"))?;
        if let Some(public_key) = entry.get("public_key").and_then(Value::as_str) {
            keys.insert(version, public_key.to_string());
        }
    }

    if keys.is_empty() {
        return Err(anyhow!("no public keys found in transit response"));
    }

    Ok(TransitKeySet {
        latest_version,
        keys,
    })
}

/// Sign a payload using Vault transit Ed25519.
///
/// # Errors
/// Returns an error if the Vault request fails or the signature is missing/invalid.
#[instrument(skip(client, vault_token, signing_input))]
pub async fn sign_ed25519(
    client: &Client,
    vault_url: &str,
    vault_token: &secrecy::SecretString,
    transit_mount: &str,
    key_name: &str,
    key_version: u32,
    signing_input: &[u8],
) -> Result<VaultSignature> {
    let sign_url = vault::endpoint_url(
        vault_url,
        &transit_path(transit_mount, &format!("sign/{key_name}")),
    )?;
    let input_b64 = BASE64_STANDARD.encode(signing_input);

    let payload = json!({
        "input": input_b64,
        "key_version": key_version,
    });

    let response = client
        .post(&sign_url)
        .header("X-Vault-Token", vault_token.expose_secret())
        .json(&payload)
        .send()
        .await?;

    if !response.status().is_success() {
        let status = response.status();
        let json_response: Value = response.json().await?;
        let error_message = vault_error_message(&json_response);
        error!("Failed to sign via transit: {error_message}");
        return Err(anyhow!("{sign_url} - {status}, {error_message}"));
    }

    let json_response: Value = response.json().await?;
    let signature = get_required_str(&json_response, &["data", "signature"]).ok_or_else(|| {
        error!("Missing signature in transit response");
        anyhow!("missing signature in transit response")
    })?;

    parse_signature(signature)
}
