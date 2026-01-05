//! PASETO v4.public admin token minting.
//!
//! Flow Overview:
//! 1) Build scoped admin claims with RFC3339 timestamps.
//! 2) Sign the PASETO pre-auth input with an Ed25519 key.
//! 3) Return a short-lived token for admin routes.

use admission_token::{
    PaserkKey, PaserkKeySet, VerificationOptions, build_token, verify_v4_public,
};
use anyhow::{Context, Result, anyhow};
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

const HEADER: &str = "v4.public.";
const ADMIN_SCOPE: &str = "platform:admin";
const ADMIN_STEP_UP: &str = "vault";

#[derive(Debug, Serialize, Deserialize)]
struct AdminTokenClaims {
    scope: Vec<String>,
    iss: String,
    aud: String,
    action: String,
    step_up: String,
    iat: String,
    exp: String,
    user_id: String,
    jti: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct AdminTokenFooter {
    kid: String,
}

#[derive(Debug, Clone)]
pub struct AdminToken {
    pub token: String,
    pub expires_at: String,
}

#[derive(Debug)]
pub struct AdminTokenSigner {
    signing_key: SigningKey,
    key_id: String,
}

impl AdminTokenSigner {
    /// Build a new signer with a randomly generated Ed25519 key.
    ///
    /// # Errors
    /// Returns an error if the key ID cannot be derived.
    pub fn new() -> Result<Self> {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        let signing_key = SigningKey::from_bytes(&bytes);
        let verifying_key = signing_key.verifying_key();
        let key = PaserkKey::from_ed25519_public_key_bytes(&verifying_key.to_bytes())
            .map_err(|err| anyhow!("{err}"))?;
        Ok(Self {
            signing_key,
            key_id: key.kid,
        })
    }

    /// Issue a short-lived admin token for the given user.
    ///
    /// # Errors
    /// Returns an error if timestamp formatting or signing fails.
    pub fn issue(&self, user_id: Uuid, ttl_seconds: i64) -> Result<AdminToken> {
        if ttl_seconds <= 0 {
            return Err(anyhow!("admin token ttl must be positive"));
        }
        let now = OffsetDateTime::now_utc();
        let exp = now + Duration::seconds(ttl_seconds);

        // Format without nanoseconds for cleaner UI and better JS compatibility
        let format = Rfc3339;
        let iat = now
            .replace_nanosecond(0)
            .context("strip iat nanoseconds")?
            .format(&format)
            .context("format iat")?;
        let exp_str = exp
            .replace_nanosecond(0)
            .context("strip exp nanoseconds")?
            .format(&format)
            .context("format exp")?;

        let claims = AdminTokenClaims {
            scope: vec![ADMIN_SCOPE.to_string()],
            iss: "permesi:admin".to_string(),
            aud: "permesi:admin".to_string(),
            action: ADMIN_SCOPE.to_string(),
            step_up: ADMIN_STEP_UP.to_string(),
            iat,
            exp: exp_str.clone(),
            user_id: user_id.to_string(),
            jti: user_id.to_string(),
        };
        let footer = AdminTokenFooter {
            kid: self.key_id.clone(),
        };

        let payload = serde_json::to_vec(&claims).context("encode admin token claims")?;
        let footer_bytes = serde_json::to_vec(&footer).context("encode admin token footer")?;
        let pre_auth = pae(&[
            HEADER.as_bytes(),
            payload.as_slice(),
            footer_bytes.as_slice(),
            b"",
        ])?;
        let signature = self.signing_key.sign(&pre_auth);
        let token = build_token(&payload, &footer_bytes, &signature.to_bytes());

        Ok(AdminToken {
            token,
            expires_at: exp_str,
        })
    }

    /// Verify an admin elevation token and return the user ID.
    ///
    /// # Errors
    /// Returns an error if verification fails or claims are invalid.
    pub fn verify(&self, token: &str) -> Result<Uuid> {
        let verifying_key = self.signing_key.verifying_key();
        let keyset = PaserkKeySet {
            version: "v4".to_string(),
            purpose: "public".to_string(),
            active_kid: self.key_id.clone(),
            keys: vec![PaserkKey {
                kid: self.key_id.clone(),
                paserk: format!(
                    "k4.public.{}",
                    base64::engine::general_purpose::URL_SAFE_NO_PAD
                        .encode(verifying_key.to_bytes())
                ),
            }],
        };

        let now = OffsetDateTime::now_utc().unix_timestamp();
        let options = VerificationOptions {
            expected_issuer: "permesi:admin",
            expected_audience: "permesi:admin",
            expected_action: ADMIN_SCOPE,
            now_unix_seconds: now,
            min_ttl_seconds: 0,
            max_ttl_seconds: 13 * 60 * 60, // 13h max
        };

        let claims = verify_v4_public(token, &keyset, &options).map_err(|e| anyhow!("{e}"))?;

        Uuid::parse_str(&claims.jti).context("invalid session jti in admin token")
    }
}

fn pae(pieces: &[&[u8]]) -> Result<Vec<u8>> {
    let count = u64::try_from(pieces.len()).context("invalid PAE count")?;
    let mut out = Vec::new();
    out.extend_from_slice(&le64(count));
    for piece in pieces {
        let len = u64::try_from(piece.len()).context("invalid PAE length")?;
        out.extend_from_slice(&le64(len));
        out.extend_from_slice(piece);
    }
    Ok(out)
}

fn le64(mut value: u64) -> [u8; 8] {
    let mut out = [0u8; 8];
    for (i, byte) in out.iter_mut().enumerate() {
        if i == 7 {
            value &= 0x7f;
        }
        *byte = (value & 0xff) as u8;
        value >>= 8;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::AdminTokenSigner;
    use anyhow::Result;
    use uuid::Uuid;

    #[test]
    fn admin_token_signer_mints_token() -> Result<()> {
        let signer = AdminTokenSigner::new()?;
        let token = signer.issue(Uuid::new_v4(), 60)?;
        assert!(token.token.starts_with("v4.public."));
        assert!(!token.expires_at.is_empty());
        Ok(())
    }
}
