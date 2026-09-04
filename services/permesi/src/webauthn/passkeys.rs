//! Passkey (`WebAuthn`) service for primary credential management.
//!
//! This module provides the passkey-specific `WebAuthn` flows used for account
//! security settings. Unlike `SecurityKeyService`, passkeys are treated as
//! primary credentials and may be stored separately when persistence exists.
//!
//! Flow Overview:
//! 1) Create registration options bound to the authenticated user/session.
//! 2) Persist the in-progress registration state with a short TTL.
//! 3) Finish registration by verifying the authenticator response.
//! 4) Persist the credential when preview mode is disabled.
//! 5) Issue discoverable authentication challenges and resolve the user only
//!    after the authenticator returns its opaque user handle.
//!
//! Security boundaries:
//! - Origin and RP ID validation are enforced by `webauthn-rs` and by explicit
//!   Origin header checks before options/finish are served.
//! - Registration challenges are single-use and tied to the user + session token
//!   hash to prevent replay across sessions.
//! - Passkey responses are never logged or stored in plaintext.

use anyhow::{Context, Result, anyhow};
use std::{
    collections::HashMap,
    time::{Duration, Instant},
};
use tokio::sync::Mutex;
use url::Url;
use uuid::Uuid;
use webauthn_rs::prelude::*;

const DEFAULT_CHALLENGE_TTL_SECONDS: u64 = 300;
const DEFAULT_RP_NAME: &str = "Permesi";
const ENV_PASSKEYS_RP_ID: &str = "PERMESI_PASSKEYS_RP_ID";
const ENV_PASSKEYS_RP_NAME: &str = "PERMESI_PASSKEYS_RP_NAME";
const ENV_PASSKEYS_ALLOWED_ORIGINS: &str = "PERMESI_PASSKEYS_ALLOWED_ORIGINS";
const ENV_PASSKEYS_CHALLENGE_TTL_SECONDS: &str = "PERMESI_PASSKEYS_CHALLENGE_TTL_SECONDS";
const ENV_PASSKEYS_PREVIEW_MODE: &str = "PERMESI_PASSKEYS_PREVIEW_MODE";

#[derive(Clone, Debug)]
pub struct PasskeyConfig {
    rp_id: String,
    rp_name: String,
    allowed_origins: Vec<String>,
    challenge_ttl: Duration,
    preview_mode: bool,
}

impl PasskeyConfig {
    /// Build passkey configuration from environment with safe defaults.
    ///
    /// # Errors
    /// Returns error if any configured origin cannot be parsed.
    pub fn from_env(rp_id: &str, default_allowed_origins: &[String]) -> Result<Self> {
        let rp_id = std::env::var(ENV_PASSKEYS_RP_ID)
            .ok()
            .map(|val| val.trim().to_string())
            .filter(|val| !val.is_empty())
            .unwrap_or_else(|| rp_id.to_string());

        let rp_name = std::env::var(ENV_PASSKEYS_RP_NAME)
            .ok()
            .map(|val| val.trim().to_string())
            .filter(|val| !val.is_empty())
            .unwrap_or_else(|| DEFAULT_RP_NAME.to_string());

        let allowed_origins = match std::env::var(ENV_PASSKEYS_ALLOWED_ORIGINS) {
            Ok(value) => value
                .split(',')
                .map(str::trim)
                .filter(|origin| !origin.is_empty())
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            Err(_) => default_allowed_origins.to_vec(),
        };

        let challenge_ttl = std::env::var(ENV_PASSKEYS_CHALLENGE_TTL_SECONDS)
            .ok()
            .and_then(|value| value.trim().parse::<u64>().ok())
            .filter(|value| *value > 0)
            .map_or_else(
                || Duration::from_secs(DEFAULT_CHALLENGE_TTL_SECONDS),
                Duration::from_secs,
            );

        let preview_mode = parse_bool_env(ENV_PASSKEYS_PREVIEW_MODE).unwrap_or(false);

        Self::new(rp_id, rp_name, allowed_origins, challenge_ttl, preview_mode)
    }

    /// Create a new passkey configuration.
    ///
    /// # Errors
    /// Returns error if origins are invalid or empty.
    pub fn new(
        rp_id: String,
        rp_name: String,
        allowed_origins: Vec<String>,
        challenge_ttl: Duration,
        preview_mode: bool,
    ) -> Result<Self> {
        if rp_id.trim().is_empty() {
            return Err(anyhow!("Passkey RP ID must not be empty"));
        }

        let allowed_origins = normalize_origins(allowed_origins)?;
        if allowed_origins.is_empty() {
            return Err(anyhow!("Passkey allowed origins must not be empty"));
        }

        Ok(Self {
            rp_id,
            rp_name,
            allowed_origins,
            challenge_ttl,
            preview_mode,
        })
    }

    #[must_use]
    pub fn rp_id(&self) -> &str {
        &self.rp_id
    }

    #[must_use]
    pub fn rp_name(&self) -> &str {
        &self.rp_name
    }

    #[must_use]
    pub fn allowed_origins(&self) -> &[String] {
        &self.allowed_origins
    }

    #[must_use]
    pub fn challenge_ttl(&self) -> Duration {
        self.challenge_ttl
    }

    #[must_use]
    pub fn preview_mode(&self) -> bool {
        self.preview_mode
    }
}

#[derive(Debug)]
pub enum PasskeyRegistrationError {
    NotFound,
    Expired,
    UserMismatch,
    SessionMismatch,
    OriginMismatch,
    Webauthn(WebauthnError),
}

#[derive(Debug)]
pub enum PasskeyAuthenticationError {
    NotFound,
    Expired,
    OriginMismatch,
    Webauthn(WebauthnError),
}

struct PasskeyRegistrationState {
    user_id: Uuid,
    session_token_hash: Vec<u8>,
    origin: String,
    created_at: Instant,
    registration: PasskeyRegistration,
}

struct PasskeyAuthenticationState {
    origin: String,
    created_at: Instant,
    authentication: DiscoverableAuthentication,
}

pub struct PasskeyService {
    config: PasskeyConfig,
    max_pending_states: usize,
    webauthn_by_origin: HashMap<String, Webauthn>,
    reg_states: Mutex<HashMap<Uuid, PasskeyRegistrationState>>,
    auth_states: Mutex<HashMap<Uuid, PasskeyAuthenticationState>>,
}

impl PasskeyService {
    /// Create a new passkey service.
    ///
    /// # Errors
    /// Returns error if the state capacity is zero or the `WebAuthn` builder
    /// fails for any configured origin.
    pub fn new(config: PasskeyConfig, max_pending_states: usize) -> Result<Self> {
        if max_pending_states == 0 {
            return Err(anyhow!("Passkey state capacity must be greater than zero"));
        }
        let mut webauthn_by_origin = HashMap::new();

        for origin in &config.allowed_origins {
            let rp_origin_url =
                Url::parse(origin).with_context(|| format!("Invalid passkey origin: {origin}"))?;
            let webauthn = WebauthnBuilder::new(config.rp_id(), &rp_origin_url)?
                .rp_name(config.rp_name())
                .build()?;
            webauthn_by_origin.insert(origin.clone(), webauthn);
        }

        Ok(Self {
            config,
            max_pending_states,
            webauthn_by_origin,
            reg_states: Mutex::new(HashMap::new()),
            auth_states: Mutex::new(HashMap::new()),
        })
    }

    #[must_use]
    pub fn config(&self) -> &PasskeyConfig {
        &self.config
    }

    #[must_use]
    pub fn match_origin(&self, origin: &str) -> Option<String> {
        let normalized = normalize_origin(origin).ok()?;
        if self.webauthn_by_origin.contains_key(&normalized) {
            Some(normalized)
        } else {
            None
        }
    }

    fn webauthn_for_origin(&self, origin: &str) -> Result<&Webauthn> {
        self.webauthn_by_origin
            .get(origin)
            .ok_or_else(|| anyhow!("Passkey origin not allowed"))
    }

    /// Begin passkey registration for a user/session.
    ///
    /// # Errors
    /// Returns error if origin is invalid or `WebAuthn` fails.
    pub async fn register_begin(
        &self,
        user_id: Uuid,
        user_name: &str,
        user_display_name: &str,
        session_token_hash: Vec<u8>,
        origin: &str,
    ) -> Result<(Uuid, CreationChallengeResponse)> {
        let webauthn = self.webauthn_for_origin(origin)?;
        let (challenge, registration) =
            webauthn.start_passkey_registration(user_id, user_name, user_display_name, None)?;

        let reg_id = Uuid::new_v4();
        let mut states = self.reg_states.lock().await;
        prune_registrations(&mut states, self.config.challenge_ttl());
        if states.len() >= self.max_pending_states {
            return Err(anyhow!("Too many pending passkey registrations"));
        }
        states.insert(
            reg_id,
            PasskeyRegistrationState {
                user_id,
                session_token_hash,
                origin: origin.to_string(),
                created_at: Instant::now(),
                registration,
            },
        );

        Ok((reg_id, challenge))
    }

    /// Finish passkey registration after verifying the client response.
    ///
    /// # Errors
    /// Returns error if the registration state is missing, expired, or mismatched.
    pub async fn register_finish(
        &self,
        reg_id: Uuid,
        user_id: Uuid,
        session_token_hash: &[u8],
        origin: &str,
        response: RegisterPublicKeyCredential,
    ) -> Result<Passkey, PasskeyRegistrationError> {
        let mut states = self.reg_states.lock().await;
        prune_registrations(&mut states, self.config.challenge_ttl());
        let state = states
            .remove(&reg_id)
            .ok_or(PasskeyRegistrationError::NotFound)?;

        if state.created_at.elapsed() >= self.config.challenge_ttl() {
            return Err(PasskeyRegistrationError::Expired);
        }
        if state.user_id != user_id {
            return Err(PasskeyRegistrationError::UserMismatch);
        }
        if state.session_token_hash != session_token_hash {
            return Err(PasskeyRegistrationError::SessionMismatch);
        }
        if state.origin != origin {
            return Err(PasskeyRegistrationError::OriginMismatch);
        }

        let webauthn = self
            .webauthn_for_origin(origin)
            .map_err(|_| PasskeyRegistrationError::OriginMismatch)?;
        webauthn
            .finish_passkey_registration(&response, &state.registration)
            .map_err(PasskeyRegistrationError::Webauthn)
    }

    /// Begin usernameless passkey authentication.
    ///
    /// No account lookup or credential identifiers are included in the start
    /// response, preventing the endpoint from serving as an email oracle.
    ///
    /// # Errors
    /// Returns error if origin is invalid or `WebAuthn` fails.
    pub async fn auth_begin(&self, origin: &str) -> Result<(Uuid, RequestChallengeResponse)> {
        let webauthn = self.webauthn_for_origin(origin)?;
        let (challenge, authentication) = webauthn.start_discoverable_authentication()?;

        let auth_id = Uuid::new_v4();
        let mut states = self.auth_states.lock().await;
        prune_authentications(&mut states, self.config.challenge_ttl());
        if states.len() >= self.max_pending_states {
            return Err(anyhow!("Too many pending passkey authentications"));
        }
        states.insert(
            auth_id,
            PasskeyAuthenticationState {
                origin: origin.to_string(),
                created_at: Instant::now(),
                authentication,
            },
        );

        Ok((auth_id, challenge))
    }

    /// Extract the opaque user handle and credential ID from an assertion.
    ///
    /// The returned identifiers are untrusted until the handler loads the
    /// credential belonging to that user and `auth_finish` verifies the proof.
    ///
    /// # Errors
    /// Returns an error if the origin is not configured or the assertion does
    /// not contain a valid discoverable user handle.
    pub fn identify_authentication(
        &self,
        origin: &str,
        response: &PublicKeyCredential,
    ) -> Result<(Uuid, Vec<u8>)> {
        let webauthn = self.webauthn_for_origin(origin)?;
        let (user_id, credential_id) = webauthn.identify_discoverable_authentication(response)?;
        Ok((user_id, credential_id.to_vec()))
    }

    /// Consume an authentication state after an assertion fails pre-verification checks.
    pub async fn discard_authentication(&self, auth_id: Uuid) {
        self.auth_states.lock().await.remove(&auth_id);
    }

    /// Finish passkey authentication against the server-loaded credential.
    ///
    /// # Errors
    /// Returns error if the authentication state is missing, expired, or mismatched.
    pub async fn auth_finish(
        &self,
        auth_id: Uuid,
        origin: &str,
        response: PublicKeyCredential,
        credentials: &[DiscoverableKey],
    ) -> Result<AuthenticationResult, PasskeyAuthenticationError> {
        let mut states = self.auth_states.lock().await;
        prune_authentications(&mut states, self.config.challenge_ttl());
        let state = states
            .remove(&auth_id)
            .ok_or(PasskeyAuthenticationError::NotFound)?;

        if state.created_at.elapsed() >= self.config.challenge_ttl() {
            return Err(PasskeyAuthenticationError::Expired);
        }
        if state.origin != origin {
            return Err(PasskeyAuthenticationError::OriginMismatch);
        }

        let webauthn = self
            .webauthn_for_origin(origin)
            .map_err(|_| PasskeyAuthenticationError::OriginMismatch)?;
        webauthn
            .finish_discoverable_authentication(&response, state.authentication, credentials)
            .map_err(PasskeyAuthenticationError::Webauthn)
    }
}

fn normalize_origins(origins: Vec<String>) -> Result<Vec<String>> {
    let mut normalized = Vec::new();
    for origin in origins {
        let origin = normalize_origin(&origin)?;
        if !normalized.contains(&origin) {
            normalized.push(origin);
        }
    }
    Ok(normalized)
}

fn normalize_origin(origin: &str) -> Result<String> {
    let parsed = Url::parse(origin).with_context(|| format!("Invalid origin URL: {origin}"))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| anyhow!("Origin must include a host: {origin}"))?;
    let port = parsed
        .port()
        .map_or_else(String::new, |port| format!(":{port}"));
    Ok(format!("{}://{}{}", parsed.scheme(), host, port))
}

fn parse_bool_env(key: &str) -> Option<bool> {
    std::env::var(key)
        .ok()
        .and_then(|value| match value.trim() {
            "1" | "true" | "TRUE" | "yes" | "YES" => Some(true),
            "0" | "false" | "FALSE" | "no" | "NO" => Some(false),
            _ => None,
        })
}

fn prune_registrations(states: &mut HashMap<Uuid, PasskeyRegistrationState>, ttl: Duration) {
    states.retain(|_, entry| entry.created_at.elapsed() < ttl);
}

fn prune_authentications(states: &mut HashMap<Uuid, PasskeyAuthenticationState>, ttl: Duration) {
    states.retain(|_, entry| entry.created_at.elapsed() < ttl);
}

/// Serialize a passkey for storage.
///
/// # Errors
/// Returns error if serialization fails.
pub fn serialize_passkey(passkey: &Passkey) -> Result<Vec<u8>> {
    serde_json::to_vec(passkey).context("Failed to serialize passkey")
}

/// Deserialize a stored passkey.
///
/// # Errors
/// Returns error if deserialization fails.
pub fn deserialize_passkey(data: &[u8]) -> Result<Passkey> {
    serde_json::from_slice(data).context("Failed to deserialize passkey")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> Result<PasskeyConfig> {
        PasskeyConfig::new(
            "example.com".to_string(),
            "Example".to_string(),
            vec!["https://example.com".to_string()],
            Duration::from_mins(2),
            true,
        )
    }

    fn dummy_register_credential() -> Result<RegisterPublicKeyCredential> {
        let credential = serde_json::from_value(serde_json::json!({
            "id": "dummy",
            "rawId": "AA",
            "type": "public-key",
            "response": {
                "attestationObject": "AA",
                "clientDataJSON": "AA"
            }
        }))?;
        Ok(credential)
    }

    #[test]
    fn origin_matching_is_exact() -> Result<()> {
        let service = PasskeyService::new(test_config()?, 100)?;
        assert_eq!(
            service.match_origin("https://example.com"),
            Some("https://example.com".to_string())
        );
        assert_eq!(
            service.match_origin("https://example.com/"),
            Some("https://example.com".to_string())
        );
        assert_eq!(service.match_origin("https://other.com"), None);
        Ok(())
    }

    #[test]
    fn origin_matching_requires_port_match() -> Result<()> {
        let config = PasskeyConfig::new(
            "example.com".to_string(),
            "Example".to_string(),
            vec!["https://example.com:8443".to_string()],
            Duration::from_mins(2),
            true,
        )?;
        let service = PasskeyService::new(config, 100)?;
        assert_eq!(service.match_origin("https://example.com"), None);
        assert_eq!(
            service.match_origin("https://example.com:8443"),
            Some("https://example.com:8443".to_string())
        );
        Ok(())
    }

    #[test]
    fn preview_mode_is_configurable() -> Result<()> {
        let enabled = PasskeyConfig::new(
            "example.com".to_string(),
            "Example".to_string(),
            vec!["https://example.com".to_string()],
            Duration::from_mins(2),
            true,
        )?;
        assert!(enabled.preview_mode());

        let disabled = PasskeyConfig::new(
            "example.com".to_string(),
            "Example".to_string(),
            vec!["https://example.com".to_string()],
            Duration::from_mins(2),
            false,
        )?;
        assert!(!disabled.preview_mode());
        Ok(())
    }

    #[tokio::test]
    async fn registration_state_is_single_use() -> Result<()> {
        let service = PasskeyService::new(test_config()?, 100)?;
        let user_id = Uuid::new_v4();
        let (reg_id, _challenge) = service
            .register_begin(
                user_id,
                "user@example.com",
                "Example User",
                vec![1, 2, 3],
                "https://example.com",
            )
            .await?;

        let mut states = service.reg_states.lock().await;
        let first = states.remove(&reg_id);
        let second = states.remove(&reg_id);
        assert!(first.is_some());
        assert!(second.is_none());
        Ok(())
    }

    #[tokio::test]
    async fn register_finish_rejects_origin_and_consumes_state() -> Result<()> {
        let service = PasskeyService::new(test_config()?, 100)?;
        let user_id = Uuid::new_v4();
        let session_hash = vec![1, 2, 3, 4];
        let (reg_id, _challenge) = service
            .register_begin(
                user_id,
                "user@example.com",
                "Example User",
                session_hash.clone(),
                "https://example.com",
            )
            .await?;

        let credential = dummy_register_credential()?;
        let err = service
            .register_finish(
                reg_id,
                user_id,
                &session_hash,
                "https://other.example.com",
                credential.clone(),
            )
            .await
            .err()
            .ok_or_else(|| anyhow!("Expected origin mismatch error"))?;
        assert!(matches!(err, PasskeyRegistrationError::OriginMismatch));

        let err = service
            .register_finish(
                reg_id,
                user_id,
                &session_hash,
                "https://example.com",
                credential,
            )
            .await
            .err()
            .ok_or_else(|| anyhow!("Expected not found error"))?;
        assert!(matches!(err, PasskeyRegistrationError::NotFound));
        Ok(())
    }

    #[tokio::test]
    async fn register_finish_rejects_session_mismatch() -> Result<()> {
        let service = PasskeyService::new(test_config()?, 100)?;
        let user_id = Uuid::new_v4();
        let (reg_id, _challenge) = service
            .register_begin(
                user_id,
                "user@example.com",
                "Example User",
                vec![1, 2, 3],
                "https://example.com",
            )
            .await?;

        let credential = dummy_register_credential()?;
        let err = service
            .register_finish(
                reg_id,
                user_id,
                &[9, 9, 9],
                "https://example.com",
                credential,
            )
            .await
            .err()
            .ok_or_else(|| anyhow!("Expected session mismatch error"))?;
        assert!(matches!(err, PasskeyRegistrationError::SessionMismatch));
        Ok(())
    }

    #[tokio::test]
    async fn authentication_start_does_not_disclose_account_credentials() -> Result<()> {
        let service = PasskeyService::new(test_config()?, 100)?;
        let (auth_id, challenge) = service.auth_begin("https://example.com").await?;

        assert!(challenge.public_key.allow_credentials.is_empty());
        service.discard_authentication(auth_id).await;
        Ok(())
    }

    #[tokio::test]
    async fn authentication_start_enforces_pending_state_capacity() -> Result<()> {
        let service = PasskeyService::new(test_config()?, 1)?;
        let (_auth_id, _challenge) = service.auth_begin("https://example.com").await?;

        assert!(service.auth_begin("https://example.com").await.is_err());
        Ok(())
    }

    #[test]
    fn preview_mode_round_trips() -> Result<()> {
        let config = test_config()?;
        assert!(config.preview_mode());
        Ok(())
    }
}
