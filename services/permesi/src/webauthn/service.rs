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

use crate::webauthn::repo::SecurityKeyRepo;
use anyhow::{Result, anyhow};
use sqlx::PgPool;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use url::Url;
use uuid::Uuid;
use webauthn_rs::prelude::*;

struct RegistrationState {
    origin: String,
    registration: SecurityKeyRegistration,
}

struct AuthenticationState {
    origin: String,
    authentication: SecurityKeyAuthentication,
}

pub struct SecurityKeyService {
    webauthn_by_origin: HashMap<String, Arc<Webauthn>>,
    pool: PgPool,
    reg_states: Mutex<HashMap<Uuid, RegistrationState>>,
    auth_states: Mutex<HashMap<Uuid, AuthenticationState>>,
}

impl SecurityKeyService {
    /// Create a new security key service.
    ///
    /// # Errors
    /// Returns error if any configured `WebAuthn` origin is invalid or the
    /// `WebAuthn` builder fails.
    pub fn new(pool: PgPool, rp_id: &str, allowed_origins: &[String]) -> Result<Self> {
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
            pool,
            reg_states: Mutex::new(HashMap::new()),
            auth_states: Mutex::new(HashMap::new()),
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
    ) -> Result<(CreationChallengeResponse, Uuid)> {
        // Fetch existing keys to prevent duplicate registration
        let existing_keys = SecurityKeyRepo::list_user_keys(&self.pool, user_id).await?;
        let exclude_credentials: Vec<CredentialID> = existing_keys
            .into_iter()
            .map(|k| k.credential_id.into())
            .collect();

        let webauthn = self.webauthn_for_origin(origin)?;
        let (challenge, registration) = webauthn.start_securitykey_registration(
            user_id,
            user_email,
            user_email,
            Some(exclude_credentials),
            None, // Attestation CA list
            None, // Authenticator Attachment
        )?;

        let reg_id = Uuid::new_v4();
        let mut states = self.reg_states.lock().await;
        states.insert(
            reg_id,
            RegistrationState {
                origin: origin.to_string(),
                registration,
            },
        );

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
    ) -> Result<()> {
        let state = {
            let mut states = self.reg_states.lock().await;
            states
                .remove(&reg_id)
                .ok_or_else(|| anyhow!("Registration session not found or expired"))?
        };

        if state.origin != origin {
            return Err(anyhow!(
                "Registration origin does not match the challenge origin"
            ));
        }

        let webauthn = self.webauthn_for_origin(origin)?;
        let passkey =
            webauthn.finish_securitykey_registration(&reg_response, &state.registration)?;

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

        let auth_id = Uuid::new_v4();
        let mut states = self.auth_states.lock().await;
        states.insert(
            auth_id,
            AuthenticationState {
                origin: origin.to_string(),
                authentication,
            },
        );

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
    ) -> Result<Uuid> {
        let state = {
            let mut states = self.auth_states.lock().await;
            states
                .remove(&auth_id)
                .ok_or_else(|| anyhow!("Authentication session not found or expired"))?
        };

        if state.origin != origin {
            return Err(anyhow!(
                "Authentication origin does not match the challenge origin"
            ));
        }

        let webauthn = self.webauthn_for_origin(origin)?;
        let auth_result =
            webauthn.finish_securitykey_authentication(&auth_response, &state.authentication)?;

        // Update the sign count in DB to prevent clones
        SecurityKeyRepo::update_key_usage(
            &self.pool,
            auth_result.cred_id().as_slice(),
            i64::from(auth_result.counter()),
        )
        .await?;

        let key = SecurityKeyRepo::get_key(&self.pool, auth_result.cred_id().as_slice())
            .await?
            .ok_or_else(|| anyhow!("Security key not found in database after authentication"))?;

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

    #[tokio::test]
    async fn match_origin_accepts_configured_subdomain_origin() -> anyhow::Result<()> {
        let service = SecurityKeyService::new(
            sqlx::postgres::PgPoolOptions::new().connect_lazy("postgres://localhost/permesi")?,
            "permesi.dev",
            &[
                "https://permesi.dev".to_string(),
                "https://k8s.permesi.dev".to_string(),
            ],
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
        )?;

        assert_eq!(service.match_origin("https://k8s.permesi.dev"), None);
        Ok(())
    }
}
