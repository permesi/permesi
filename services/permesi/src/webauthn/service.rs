//! `WebAuthn` service for managing hardware security key operations.
//!
//! This service coordinates the multi-step `WebAuthn` protocol:
//! 1. Generating challenges for the browser.
//! 2. Storing ephemeral protocol state (`PasskeyRegistration` / `PasskeyAuthentication`).
//! 3. Verifying the browser's cryptographic proof against the stored state and database.
//!
//! It specifically uses `SecurityKey` types to support hardware tokens as a
//! second factor (2FA) rather than a primary password replacement (Passkeys).

use crate::webauthn::repo::SecurityKeyRepo;
use anyhow::{Result, anyhow};
use sqlx::PgPool;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;
use webauthn_rs::prelude::*;

pub struct SecurityKeyService {
    webauthn: Arc<Webauthn>,
    pool: PgPool,
    // In-memory store for registration/authentication states
    reg_states: Mutex<HashMap<Uuid, SecurityKeyRegistration>>,
    auth_states: Mutex<HashMap<Uuid, SecurityKeyAuthentication>>,
}

impl SecurityKeyService {
    /// Create a new security key service.
    ///
    /// # Errors
    /// Returns error if the `WebAuthn` builder fails.
    pub fn new(pool: PgPool, rp_id: &str, rp_origin: &str) -> Result<Self> {
        let rp_origin_url = Url::parse(rp_origin)?;
        let webauthn = WebauthnBuilder::new(rp_id, &rp_origin_url)?
            .rp_name("Permesi")
            .build()?;

        Ok(Self {
            webauthn: Arc::new(webauthn),
            pool,
            reg_states: Mutex::new(HashMap::new()),
            auth_states: Mutex::new(HashMap::new()),
        })
    }

    /// Starts the registration of a new security key.
    ///
    /// # Errors
    /// Returns error if the database query fails or the `WebAuthn` challenge generation fails.
    pub async fn register_begin(
        &self,
        user_id: Uuid,
        user_email: &str,
    ) -> Result<(CreationChallengeResponse, Uuid)> {
        // Fetch existing keys to prevent duplicate registration
        let existing_keys = SecurityKeyRepo::list_user_keys(&self.pool, user_id).await?;
        let exclude_credentials: Vec<CredentialID> = existing_keys
            .into_iter()
            .map(|k| k.credential_id.into())
            .collect();

        let (challenge, registration) = self.webauthn.start_securitykey_registration(
            user_id,
            user_email,
            user_email,
            Some(exclude_credentials),
            None, // Attestation CA list
            None, // Authenticator Attachment
        )?;

        let reg_id = Uuid::new_v4();
        let mut states = self.reg_states.lock().await;
        states.insert(reg_id, registration);

        Ok((challenge, reg_id))
    }

    /// Finishes the registration.
    ///
    /// # Errors
    /// Returns error if the session is not found, registration fails, or database query fails.
    pub async fn register_finish(
        &self,
        reg_id: Uuid,
        reg_response: RegisterPublicKeyCredential,
        user_id: Uuid,
        label: &str,
    ) -> Result<()> {
        let registration = {
            let mut states = self.reg_states.lock().await;
            states
                .remove(&reg_id)
                .ok_or_else(|| anyhow!("Registration session not found or expired"))?
        };

        let passkey = self
            .webauthn
            .finish_securitykey_registration(&reg_response, &registration)?;

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
    pub async fn auth_begin(&self, user_id: Uuid) -> Result<(RequestChallengeResponse, Uuid)> {
        let keys = SecurityKeyRepo::list_user_keys(&self.pool, user_id).await?;
        if keys.is_empty() {
            return Err(anyhow!("No security keys registered for this user"));
        }

        let passkeys: Vec<SecurityKey> = keys
            .into_iter()
            .filter_map(|k| serde_json::from_slice(&k.public_key).ok())
            .collect();

        let (challenge, authentication) =
            self.webauthn.start_securitykey_authentication(&passkeys)?;

        let auth_id = Uuid::new_v4();
        let mut states = self.auth_states.lock().await;
        states.insert(auth_id, authentication);

        Ok((challenge, auth_id))
    }

    /// Finishes the authentication flow.
    ///
    /// # Errors
    /// Returns error if the session is not found, authentication fails, or database query fails.
    pub async fn auth_finish(
        &self,
        auth_id: Uuid,
        auth_response: PublicKeyCredential,
    ) -> Result<Uuid> {
        let authentication = {
            let mut states = self.auth_states.lock().await;
            states
                .remove(&auth_id)
                .ok_or_else(|| anyhow!("Authentication session not found or expired"))?
        };

        let auth_result = self
            .webauthn
            .finish_securitykey_authentication(&auth_response, &authentication)?;

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
