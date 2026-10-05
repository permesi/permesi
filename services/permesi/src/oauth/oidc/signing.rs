//! Vault-owned RS256 signing with an explicitly selected, independently verified version.
//!
//! Flow Overview: read current shared metadata, select one retained RSA version for the
//! exchange, ask Vault to sign each compact JWT, and verify the returned signature against
//! that version before exposure. Private keys and active-version authority never live here.

use anyhow::{Context as _, Result, ensure};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use http::Method;
use opaque_sha2::Sha256 as RsaSha256;
use rsa::{Pkcs1v15Sign, RsaPublicKey, pkcs8::DecodePublicKey as _};
use secrecy::{ExposeSecret as _, SecretString};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

use super::{OAuthState, parse_jwks};

/// Public verification material for one exchange; it confers no signing authority.
pub(crate) struct SigningKey {
    version: u64,
    key: RsaPublicKey,
    kid: String,
}

impl OAuthState {
    /// Resolves the current Vault version afresh so different replicas share signing authority.
    /// Never reads or writes the public cache: delayed reads cannot overwrite newer JWKS.
    pub(crate) async fn signing_key(&self) -> Result<SigningKey> {
        let path = format!(
            "/v1/{}/keys/{}",
            self.transit_mount, self.config.signing_key
        );
        let response = self
            .transport
            .request_json(
                Method::GET,
                &path,
                self.transport.is_tcp().then(|| self.token.expose_secret()),
                None,
            )
            .await?;
        ensure!(response.status.is_success(), "signing unavailable");
        let jwks = parse_jwks(&response.body)?;
        let data = response.body.get("data").context("missing key")?;
        let version = data
            .get("latest_version")
            .and_then(Value::as_u64)
            .context("missing version")?;
        let pem = data
            .get("keys")
            .and_then(|v| v.get(version.to_string()))
            .and_then(|v| v.get("public_key"))
            .and_then(Value::as_str)
            .context("missing public key")?;
        let key = RsaPublicKey::from_public_key_pem(pem)?;
        let kid = jwks.keys.last().context("missing JWK")?.kid.clone();
        // parse_jwks orders versions; Vault's declared latest must actually be the greatest.
        let greatest = data
            .get("keys")
            .and_then(Value::as_object)
            .context("missing keys")?
            .keys()
            .map(|v| v.parse::<u64>())
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .max()
            .context("missing version")?;
        ensure!(version == greatest, "inconsistent active key");
        Ok(SigningKey { version, key, kid })
    }

    /// Signs fixed-algorithm JWTs through transit, checks exact version and verifies RS256.
    /// Untrusted Vault responses cannot substitute a kid, algorithm, payload or signature.
    pub(crate) async fn sign_jwt<T: Serialize>(
        &self,
        key: &SigningKey,
        typ: &str,
        claims: &T,
    ) -> Result<SecretString> {
        let header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(
            &json!({"alg":"RS256", "typ":typ, "kid":key.kid}),
        )?);
        let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims)?);
        let input = format!("{header}.{payload}");
        let path = format!(
            "/v1/{}/sign/{}",
            self.transit_mount, self.config.signing_key
        );
        let response = self
            .transport
            .request_json(
                Method::POST,
                &path,
                self.transport.is_tcp().then(|| self.token.expose_secret()),
                Some(&json!({
                    "input":STANDARD.encode(input.as_bytes()), "key_version":key.version,
                    "hash_algorithm":"sha2-256", "signature_algorithm":"pkcs1v15", "prehashed":false
                })),
            )
            .await?;
        ensure!(response.status.is_success(), "signing unavailable");
        let signature = response
            .body
            .get("data")
            .and_then(|v| v.get("signature"))
            .and_then(Value::as_str)
            .context("missing signature")?;
        let prefix = format!("vault:v{}:", key.version);
        let signature = STANDARD.decode(
            signature
                .strip_prefix(&prefix)
                .context("wrong signing version")?,
        )?;
        key.key.verify(
            Pkcs1v15Sign::new::<RsaSha256>(),
            &Sha256::digest(input.as_bytes()),
            &signature,
        )?;
        Ok(format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature)).into())
    }
}
