//! Verification of issued access JWTs before issuer-side claim disclosure.
//!
//! Flow Overview: after a hash-only issuance receipt matches the exact Bearer value,
//! parse only the bounded header to select a retained Vault public key, verify the
//! RS256 signature, then parse and validate fixed issuer, audience, type and lifetime.
//! Callers must also compare every authority claim to the immutable receipt; neither
//! an unverified payload nor a database-only fabricated receipt is sufficient.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use opaque_sha2::Sha256 as RsaSha256;
use rsa::{BigUint, Pkcs1v15Sign, RsaPublicKey};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use super::{Jwk, OAuthState};

/// Fixed size bound for header-carried compact access JWTs.
pub(crate) const MAX_ACCESS_JWT_BYTES: usize = 8192;
const MAX_ACCESS_TTL_SECONDS: i64 = 3600;

/// Verified fixed-format RFC 9068 claims, never trusted before signature validation.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AccessClaims {
    pub iss: String,
    pub sub: Uuid,
    pub aud: String,
    pub iat: i64,
    pub exp: i64,
    pub jti: Uuid,
    pub client_id: Uuid,
    pub scope: String,
    pub organization_id: Uuid,
    pub application_id: Uuid,
    pub grant_id: Uuid,
}

/// Separates invalid Bearer material from temporarily unavailable public keys.
pub(crate) enum AccessVerifyError {
    Invalid,
    Unavailable,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    alg: String,
    typ: String,
    kid: String,
}

impl OAuthState {
    /// Verifies a compact RS256 access JWT with a shared retained Vault public key.
    pub(crate) async fn verify_access_token(
        &self,
        token: &str,
        now: i64,
    ) -> Result<AccessClaims, AccessVerifyError> {
        if token.len() > MAX_ACCESS_JWT_BYTES {
            return Err(AccessVerifyError::Invalid);
        }
        let mut parts = token.split('.');
        let (Some(encoded_header), Some(encoded_claims), Some(encoded_signature), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(AccessVerifyError::Invalid);
        };
        if encoded_header.is_empty() || encoded_claims.is_empty() || encoded_signature.is_empty() {
            return Err(AccessVerifyError::Invalid);
        }
        let header: Header = serde_json::from_slice(&decode(encoded_header)?)
            .map_err(|_| AccessVerifyError::Invalid)?;
        if header.alg != "RS256"
            || header.typ != "at+jwt"
            || header.kid.is_empty()
            || header.kid.len() > 128
        {
            return Err(AccessVerifyError::Invalid);
        }
        let keys = self
            .jwks()
            .await
            .map_err(|_| AccessVerifyError::Unavailable)?;
        let key = if let Some(key) = keys.keys.iter().find(|key| key.kid == header.kid) {
            key.clone()
        } else {
            self.refresh_jwks()
                .await
                .map_err(|_| AccessVerifyError::Unavailable)?
                .keys
                .into_iter()
                .find(|key| key.kid == header.kid)
                .ok_or(AccessVerifyError::Invalid)?
        };
        verify_signature(&key, encoded_header, encoded_claims, encoded_signature)?;
        let claims: AccessClaims = serde_json::from_slice(&decode(encoded_claims)?)
            .map_err(|_| AccessVerifyError::Invalid)?;
        let issuer = self
            .config
            .issuer
            .as_deref()
            .ok_or(AccessVerifyError::Unavailable)?;
        let audience = self
            .config
            .audience
            .as_deref()
            .ok_or(AccessVerifyError::Unavailable)?;
        if claims.iss != issuer
            || claims.aud != audience
            || claims.iat > now
            || claims.exp <= now
            || claims.exp <= claims.iat
            || claims.exp.saturating_sub(claims.iat) > MAX_ACCESS_TTL_SECONDS
        {
            return Err(AccessVerifyError::Invalid);
        }
        Ok(claims)
    }
}

/// Accepts canonical base64url only, so alternate encodings cannot bypass exact-token rules.
fn decode(segment: &str) -> Result<Vec<u8>, AccessVerifyError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(segment)
        .map_err(|_| AccessVerifyError::Invalid)?;
    if URL_SAFE_NO_PAD.encode(&bytes) != segment {
        return Err(AccessVerifyError::Invalid);
    }
    Ok(bytes)
}

/// Verifies the JWS signing input with the selected retained RSA public version.
fn verify_signature(
    key: &Jwk,
    header: &str,
    claims: &str,
    signature: &str,
) -> Result<(), AccessVerifyError> {
    if key.kty != "RSA" || key.alg != "RS256" || key.usage != "sig" {
        return Err(AccessVerifyError::Invalid);
    }
    let modulus = decode(&key.n)?;
    let exponent = decode(&key.e)?;
    let public = RsaPublicKey::new(
        BigUint::from_bytes_be(&modulus),
        BigUint::from_bytes_be(&exponent),
    )
    .map_err(|_| AccessVerifyError::Invalid)?;
    let signing_input = format!("{header}.{claims}");
    public
        .verify(
            Pkcs1v15Sign::new::<RsaSha256>(),
            &Sha256::digest(signing_input.as_bytes()),
            &decode(signature)?,
        )
        .map_err(|_| AccessVerifyError::Invalid)
}
