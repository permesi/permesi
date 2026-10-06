//! `WebAuthn` service for managing hardware security key operations.
//!
//! This service coordinates the multi-step `WebAuthn` protocol:
//! 1. Generating challenges for the browser.
//! 2. Storing ephemeral protocol state (`PasskeyRegistration` / `PasskeyAuthentication`).
//! 3. Verifying the browser's cryptographic proof against the stored state and database.
//!
//! It specifically uses `SecurityKey` types to support hardware tokens as a
//! second factor (2FA) rather than a primary password replacement (Passkeys).
//!
//! Flow Overview:
//! 1) Match the request `Origin` against the configured `WebAuthn` origin allowlist.
//! 2) Start registration or authentication with the `WebAuthn` instance for that origin.
//! 3) Bind the in-progress state to the normalized origin so finish requests cannot
//!    replay a challenge from one trusted origin on another.

use super::exchange::{Binding, ExchangeStore, Purpose};
use crate::webauthn::repo::SecurityKeyRepo;
use anyhow::{Result, anyhow};
use sqlx::PgPool;
use std::collections::HashMap;
use std::sync::Arc;
use url::Url;
use uuid::Uuid;
use webauthn_rs::prelude::*;

pub struct SecurityKeyService {
    webauthn_by_origin: HashMap<String, Arc<Webauthn>>,
    pool: PgPool,
    exchanges: ExchangeStore,
}

impl SecurityKeyService {
    /// Create a new security key service.
    ///
    /// # Errors
    /// Returns error if any configured `WebAuthn` origin is invalid or the
    /// `WebAuthn` builder fails.
    pub fn new(
        pool: PgPool,
        rp_id: &str,
        allowed_origins: &[String],
        seed: &[u8; 32],
        ttl: i64,
        capacity: usize,
        timeout_ms: i64,
    ) -> Result<Self> {
        if allowed_origins.is_empty() {
            return Err(anyhow!("Security key origins must not be empty"));
        }

        let mut webauthn_by_origin = HashMap::new();
        for origin in allowed_origins {
            let normalized = normalize_origin(origin)?;
            let rp_origin_url = Url::parse(&normalized)?;
            let webauthn = WebauthnBuilder::new(rp_id, &rp_origin_url)?
                .rp_name("Permesi")
                .build()?;
            webauthn_by_origin.insert(normalized, Arc::new(webauthn));
        }

        Ok(Self {
            webauthn_by_origin,
            exchanges: ExchangeStore::new(
                pool.clone(),
                seed,
                rp_id.to_owned(),
                ttl,
                capacity,
                timeout_ms,
            )?,
            pool,
        })
    }

    /// Return the normalized origin when it matches the configured allowlist.
    #[must_use]
    pub fn match_origin(&self, origin: &str) -> Option<String> {
        let normalized = normalize_origin(origin).ok()?;
        if self.webauthn_by_origin.contains_key(&normalized) {
            Some(normalized)
        } else {
            None
        }
    }

    fn webauthn_for_origin(&self, origin: &str) -> Result<Arc<Webauthn>> {
        self.webauthn_by_origin
            .get(origin)
            .cloned()
            .ok_or_else(|| anyhow!("Security key origin not allowed"))
    }

    /// Starts the registration of a new security key.
    ///
    /// # Errors
    /// Returns error if the database query fails or the `WebAuthn` challenge generation fails.
    pub async fn register_begin(
        &self,
        user_id: Uuid,
        user_email: &str,
        origin: &str,
        session_hash: &[u8],
    ) -> Result<(CreationChallengeResponse, Uuid)> {
        // Fetch existing keys to prevent duplicate registration
        let existing_keys = SecurityKeyRepo::list_user_keys(&self.pool, user_id).await?;
        let exclude_credentials: Vec<CredentialID> =
            existing_keys.into_iter().map(|k| k.credential_id).collect();

        let webauthn = self.webauthn_for_origin(origin)?;
        let (challenge, registration) = webauthn.start_securitykey_registration(
            user_id,
            user_email,
            user_email,
            Some(exclude_credentials),
            None, // Attestation CA list
            None, // Authenticator Attachment
        )?;

        let reg_id = self
            .exchanges
            .put(
                Binding {
                    purpose: Purpose::SecurityKeyRegistration,
                    origin,
                    user: Some(user_id),
                    session: Some(session_hash),
                },
                &registration,
            )
            .await?;

        Ok((challenge, reg_id))
    }

    /// Finishes the registration.
    ///
    /// # Errors
    /// Returns error if the session is not found, registration fails, or database query fails.
    pub async fn register_finish(
        &self,
        reg_id: Uuid,
        origin: &str,
        reg_response: RegisterPublicKeyCredential,
        user_id: Uuid,
        label: &str,
        session_hash: &[u8],
    ) -> Result<()> {
        let registration = self
            .exchanges
            .take::<SecurityKeyRegistration>(
                reg_id,
                Binding {
                    purpose: Purpose::SecurityKeyRegistration,
                    origin,
                    user: Some(user_id),
                    session: Some(session_hash),
                },
            )
            .await?;

        let webauthn = self.webauthn_for_origin(origin)?;
        let passkey = webauthn.finish_securitykey_registration(&reg_response, &registration)?;

        SecurityKeyRepo::create_key(
            &self.pool,
            user_id,
            passkey.cred_id().as_slice(),
            &serde_json::to_vec(&passkey)?,
            label,
            0, // Initial sign count for new key
        )
        .await?;

        Ok(())
    }

    /// Starts the authentication flow.
    ///
    /// # Errors
    /// Returns error if no keys are registered, or the database query fails.
    pub async fn auth_begin(
        &self,
        user_id: Uuid,
        origin: &str,
        session_hash: &[u8],
    ) -> Result<(RequestChallengeResponse, Uuid)> {
        let keys = SecurityKeyRepo::list_user_keys(&self.pool, user_id).await?;
        if keys.is_empty() {
            return Err(anyhow!("No security keys registered for this user"));
        }

        let passkeys: Vec<SecurityKey> = keys
            .into_iter()
            .filter_map(|k| serde_json::from_slice(&k.public_key).ok())
            .collect();

        let webauthn = self.webauthn_for_origin(origin)?;
        let (challenge, authentication) = webauthn.start_securitykey_authentication(&passkeys)?;

        let auth_id = self
            .exchanges
            .put(
                Binding {
                    purpose: Purpose::SecurityKeyAuthentication,
                    origin,
                    user: Some(user_id),
                    session: Some(session_hash),
                },
                &authentication,
            )
            .await?;

        Ok((challenge, auth_id))
    }

    /// Finishes the authentication flow.
    ///
    /// # Errors
    /// Returns error if the session is not found, authentication fails, or database query fails.
    pub async fn auth_finish(
        &self,
        auth_id: Uuid,
        origin: &str,
        auth_response: PublicKeyCredential,
        user_id: Uuid,
        session_hash: &[u8],
    ) -> Result<Uuid> {
        let authentication = self
            .exchanges
            .take::<SecurityKeyAuthentication>(
                auth_id,
                Binding {
                    purpose: Purpose::SecurityKeyAuthentication,
                    origin,
                    user: Some(user_id),
                    session: Some(session_hash),
                },
            )
            .await?;

        let webauthn = self.webauthn_for_origin(origin)?;
        let auth_result =
            webauthn.finish_securitykey_authentication(&auth_response, &authentication)?;

        // Recheck the current credential owner before any session authority is issued.
        let key = SecurityKeyRepo::get_key(&self.pool, auth_result.cred_id().as_slice())
            .await?
            .ok_or_else(|| anyhow!("Security key unavailable"))?;
        if key.user_id != user_id {
            return Err(anyhow!("Security key unavailable"));
        }
        SecurityKeyRepo::update_key_usage(
            &self.pool,
            auth_result.cred_id().as_slice(),
            i64::from(auth_result.counter()),
        )
        .await?;

        Ok(key.user_id)
    }
}

fn normalize_origin(origin: &str) -> Result<String> {
    let parsed = Url::parse(origin)?;
    let host = parsed
        .host_str()
        .ok_or_else(|| anyhow!("Origin must include a host: {origin}"))?;
    let port = parsed
        .port()
        .map_or_else(String::new, |port| format!(":{port}"));
    Ok(format!("{}://{}{}", parsed.scheme(), host, port))
}

#[cfg(test)]
mod tests {
    use super::SecurityKeyService;
    use webauthn_rs::prelude::SecurityKey;

    /// `security_keys.public_key` as persisted by webauthn-rs 0.5, including a packed
    /// Basic attestation chain (real soft-token registration).
    const SECURITY_KEY_JSON_WEBAUTHN_RS_0_5: &str = r#"{"cred":{"cred_id":"TebR8Rr_qYQKk8xPX_ycjSbaC-9Mfe2S1lF8lQ7NGW4","cred":{"type_":"ES256","key":{"EC_EC2":{"curve":"SECP256R1","x":"pueHeWVe74FeBplzCUHa0Sq6iuVQBzUDElyrg4ti4So","y":"DpDkcMC-l-og4XeINO0iNK0WcaF-migzDI3T9zyti4I"}}},"counter":0,"transports":["internal"],"user_verified":false,"backup_eligible":false,"backup_state":false,"registration_policy":"preferred","extensions":{"cred_protect":"Ignored","hmac_create_secret":"NotRequested","appid":"NotRequested","cred_props":"Ignored"},"attestation":{"data":{"Basic":["MIICYDCCAgegAwIBAgIBAjAKBggqhkjOPQQDAjCBgzELMAkGA1UEBhMCQVUxDDAKBgNVBAgMA1FMRDEiMCAGA1UECgwZV2ViYXV0aG4gQXV0aGVudGljYXRvciBSUzFCMEAGA1UEAww5RHluYW1pYyBTb2Z0dG9rZW4gQ0EgNTcwOWZlNTctZTczNi00NzAwLThhMzktMDU3OTMzOTg3MzRjMB4XDTI2MDkyNjE4MzgzOFoXDTI2MDkyNzE4MzgzOFowgZAxCzAJBgNVBAYTAkFVMQwwCgYDVQQIDANRTEQxIjAgBgNVBAoMGVdlYmF1dGhuIEF1dGhlbnRpY2F0b3IgUlMxKzApBgNVBAMMIkR5bmFtaWMgU29mdHRva2VuIExlYWYgQ2VydGlmaWNhdGUxIjAgBgNVBAsMGUF1dGhlbnRpY2F0b3IgQXR0ZXN0YXRpb24wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARAjV1rEBdEmTurczMJ8oFuWWxB7O5ovCf4jO3W73xC9Nb3ZoPCHHWyS3XQAW1CMy5zsyoqkH_FyIZzVBRdqLDVo10wWzAJBgNVHRMEAjAAMA4GA1UdDwEB_wQEAwIF4DAdBgNVHQ4EFgQUkTVEX39RZwslV6K2gbSFyUT0WXYwHwYDVR0jBBgwFoAU2jmj7l5rSw0yVb_vlWAYkK_YBwkwCgYIKoZIzj0EAwIDRwAwRAIgQ8-yhsjkTcWcIAM6QNYo3HopKOs-q5CPUZsQKIs5-LcCIGpkX2trYkC7HqyBqcPXdkTP770Z7XiWjk-XRdzO2fYc"]},"metadata":{"Packed":{"aaguid":"0fb9bcbc-a0d4-4042-bbb0-559bc1631e28"}}},"attestation_format":"packed"}}"#;

    /// `auth_begin` silently skips keys that fail to deserialize, so a storage-format
    /// break would make registered keys vanish rather than error.
    #[test]
    fn security_key_json_accepts_webauthn_rs_0_5_format() -> anyhow::Result<()> {
        let key: SecurityKey = serde_json::from_str(SECURITY_KEY_JSON_WEBAUTHN_RS_0_5)?;
        assert_eq!(key.cred_id().len(), 32);

        let stored: serde_json::Value = serde_json::from_str(SECURITY_KEY_JSON_WEBAUTHN_RS_0_5)?;
        assert_eq!(serde_json::to_value(&key)?, stored);
        Ok(())
    }

    #[tokio::test]
    async fn match_origin_accepts_configured_subdomain_origin() -> anyhow::Result<()> {
        let service = SecurityKeyService::new(
            sqlx::postgres::PgPoolOptions::new().connect_lazy("postgres://localhost/permesi")?,
            "permesi.dev",
            &[
                "https://permesi.dev".to_string(),
                "https://k8s.permesi.dev".to_string(),
            ],
            &[1; 32],
            300,
            100,
            1000,
        )?;

        assert_eq!(
            service.match_origin("https://k8s.permesi.dev/"),
            Some("https://k8s.permesi.dev".to_string())
        );
        Ok(())
    }

    #[tokio::test]
    async fn match_origin_rejects_unconfigured_origin() -> anyhow::Result<()> {
        let service = SecurityKeyService::new(
            sqlx::postgres::PgPoolOptions::new().connect_lazy("postgres://localhost/permesi")?,
            "permesi.dev",
            &["https://permesi.dev".to_string()],
            &[1; 32],
            300,
            100,
            1000,
        )?;

        assert_eq!(service.match_origin("https://k8s.permesi.dev"), None);
        Ok(())
    }
}
