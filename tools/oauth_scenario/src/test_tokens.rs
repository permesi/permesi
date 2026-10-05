//! Ephemeral, correctly signed negative controls; test keys never enter production fixtures.
//!
//! Flow Overview: generate one private unit-test key, expose its public JWKS and
//! sign controlled JSON, including duplicate-member negatives. Valid signatures
//! isolate parser/claim failures from cryptographic failures. Live scenarios use
//! real Vault issuance; these helpers compile only into unit-test binaries.

use crate::error::{Result, Safe};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rsa::{Pkcs1v15Sign, RsaPrivateKey, rand_core::OsRng, traits::PublicKeyParts as _};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::sync::OnceLock;

/// Reuses one freshly generated unit-test key, without a checked-in private signing key.
fn key() -> Result<&'static RsaPrivateKey> {
    static KEY: OnceLock<std::result::Result<RsaPrivateKey, rsa::Error>> = OnceLock::new();
    KEY.get_or_init(|| RsaPrivateKey::new(&mut OsRng, 2048))
        .as_ref()
        .safe("Cannot generate test RSA key.")
}

/// Produces a public-only JWKS matching the ephemeral test signing authority.
pub fn jwks() -> Result<Value> {
    let key = key()?;
    Ok(
        json!({"keys":[{"kty":"RSA","alg":"RS256","use":"sig","kid":"test-key","n":URL_SAFE_NO_PAD.encode(key.n().to_bytes_be()),"e":URL_SAFE_NO_PAD.encode(key.e().to_bytes_be())}]}),
    )
}

/// Signs deliberate bad claims too, so claim rejection cannot be explained by a bad signature.
pub fn sign(header: &Value, claims: &Value) -> Result<String> {
    sign_raw(
        &serde_json::to_string(header).safe("Test header encoding failed.")?,
        &serde_json::to_string(claims).safe("Test claims encoding failed.")?,
    )
}

/// Signs raw duplicate-member controls without silently normalizing JSON through a Value map.
pub fn sign_raw(header: &str, claims: &str) -> Result<String> {
    let message = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header),
        URL_SAFE_NO_PAD.encode(claims)
    );
    let signature = key()?
        .sign(
            Pkcs1v15Sign::new::<opaque_sha2::Sha256>(),
            &Sha256::digest(message.as_bytes()),
        )
        .safe("Test signing failed.")?;
    Ok(format!("{message}.{}", URL_SAFE_NO_PAD.encode(signature)))
}
