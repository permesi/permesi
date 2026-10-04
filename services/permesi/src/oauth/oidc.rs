//! Pre-token discovery metadata and Vault-owned RSA signing-key lifecycle.
//!
//! Flow Overview: explicit deployment configuration enables metadata; JWKS reads the
//! shared transit key through a bounded, single-flight public-response cache and converts retained public versions to RSA
//! JWKs. Vault owns private material and rotation, so replicas never generate keys or
//! cache a process-local active version. Retirement is an operator action after token
//! lifetimes and downstream caches expire. No signing or token endpoint exists yet.
//! The discovery document deliberately omits `token_endpoint` until token issuance exists;
//! it is preparatory metadata, not a complete interoperable `OpenID` Provider declaration.

use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use http::Method;
use rsa::{RsaPublicKey, pkcs8::DecodePublicKey, traits::PublicKeyParts};
use secrecy::{ExposeSecret, SecretString};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{sync::Arc, time::Duration};
use tokio::{sync::Mutex, time::Instant};
use utoipa::ToSchema;
use vault_client::VaultTransport;

use super::config::OAuthConfig;

/// Immutable policy plus shared Vault connectivity; contains no locally generated keys.
#[derive(Clone)]
pub struct OAuthState {
    pub config: OAuthConfig,
    transport: VaultTransport,
    token: SecretString,
    transit_mount: String,
    cache: Arc<Mutex<Option<CachedJwks>>>,
}

/// Public response cache, never an authoritative signing version or authorization state.
struct CachedJwks {
    expires: Instant,
    keys: Option<Jwks>,
}

impl OAuthState {
    /// Connects to an operator-provisioned key; authentication/renewal reuse existing Vault state.
    pub(crate) fn new(config: OAuthConfig, globals: &crate::cli::globals::GlobalArgs) -> Self {
        Self {
            config,
            transport: globals.vault_transport.clone(),
            token: globals.vault_token.clone(),
            transit_mount: globals.vault_transit_mount.clone(),
            cache: Arc::new(Mutex::new(None)),
        }
    }

    /// Reads all retained verification versions, requiring a usable current RSA key.
    /// Only public key fields are returned; neither Vault errors nor bodies reach clients.
    pub(crate) async fn jwks(&self) -> Result<Jwks> {
        let mut cache = self.cache.lock().await;
        if let Some(cached) = cache
            .as_ref()
            .filter(|cached| cached.expires > Instant::now())
        {
            return cached.keys.clone().context("OIDC key unavailable");
        }
        let ttl = Duration::from_secs(u64::try_from(self.config.jwks_cache_ttl)?);
        let result = self.fetch_jwks().await;
        *cache = Some(CachedJwks {
            expires: Instant::now() + ttl,
            keys: result.as_ref().ok().cloned(),
        });
        result
    }

    /// Refreshes shared public versions. Failures are briefly cached and never serve stale keys.
    async fn fetch_jwks(&self) -> Result<Jwks> {
        let path = format!(
            "/v1/{}/keys/{}",
            self.transit_mount, self.config.signing_key
        );
        let token = self.transport.is_tcp().then(|| self.token.expose_secret());
        let response = self
            .transport
            .request_json(Method::GET, &path, token, None)
            .await?;
        ensure!(response.status.is_success(), "OIDC key unavailable");
        parse_jwks(&response.body)
    }
}

/// Public-only JSON Web Key Set; every retained Vault version is independently identifiable.
#[derive(Clone, Serialize, ToSchema)]
pub(crate) struct Jwks {
    pub keys: Vec<Jwk>,
}

/// RSA verification key encoded using unsigned big-endian base64url integers.
#[derive(Clone, Serialize, ToSchema)]
pub(crate) struct Jwk {
    kty: &'static str,
    #[serde(rename = "use")]
    usage: &'static str,
    alg: &'static str,
    kid: String,
    n: String,
    e: String,
}

/// Staging metadata advertises only implemented authorization behavior and public key location.
#[derive(Serialize, ToSchema)]
pub(crate) struct Discovery {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub jwks_uri: String,
    pub response_types_supported: Vec<&'static str>,
    pub response_modes_supported: Vec<&'static str>,
    pub subject_types_supported: Vec<&'static str>,
    pub id_token_signing_alg_values_supported: Vec<&'static str>,
    pub code_challenge_methods_supported: Vec<&'static str>,
    pub grant_types_supported: Vec<&'static str>,
    pub token_endpoint_auth_methods_supported: Vec<&'static str>,
    pub request_parameter_supported: bool,
    pub request_uri_parameter_supported: bool,
    pub claims_parameter_supported: bool,
}

/// Validates the transit key type and converts all available public versions without
/// trusting Vault's map order. RFC 7638 thumbprints make kid stable across replicas/rotation.
fn parse_jwks(body: &Value) -> Result<Jwks> {
    let data = body.get("data").context("missing key data")?;
    ensure!(
        data.get("type").and_then(Value::as_str) == Some("rsa-2048"),
        "OIDC requires an RSA-2048 transit key"
    );
    let latest = data
        .get("latest_version")
        .and_then(Value::as_u64)
        .context("missing active version")?;
    let versions = data
        .get("keys")
        .and_then(Value::as_object)
        .context("missing versions")?;
    ensure!(
        latest > 0 && versions.contains_key(&latest.to_string()),
        "active version unavailable"
    );
    let mut ordered = versions
        .iter()
        .map(|(v, k)| Ok((v.parse::<u64>()?, k)))
        .collect::<Result<Vec<_>>>()?;
    ordered.sort_by_key(|(v, _)| *v);
    let mut keys = Vec::new();
    for (_, version) in ordered {
        let pem = version
            .get("public_key")
            .and_then(Value::as_str)
            .context("missing public key")?;
        let key = RsaPublicKey::from_public_key_pem(pem)?;
        ensure!(key.n().bits() == 2048, "invalid RSA modulus");
        let n = URL_SAFE_NO_PAD.encode(key.n().to_bytes_be());
        let e = URL_SAFE_NO_PAD.encode(key.e().to_bytes_be());
        let thumbprint = format!(r#"{{"e":"{e}","kty":"RSA","n":"{n}"}}"#);
        let kid = URL_SAFE_NO_PAD.encode(Sha256::digest(thumbprint.as_bytes()));
        keys.push(Jwk {
            kty: "RSA",
            usage: "sig",
            alg: "RS256",
            kid,
            n,
            e,
        });
    }
    Ok(Jwks { keys })
}

#[cfg(test)]
mod tests;
