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

use super::exchange::{Binding, ExchangeStore, Purpose};
use anyhow::{Context, Result, anyhow};
use std::{collections::HashMap, time::Duration};
use url::Url;
use uuid::Uuid;
use webauthn_rs::prelude::*;

#[derive(Clone, Debug)]
pub struct PasskeyConfig {
    rp_id: String,
    rp_name: String,
    allowed_origins: Vec<String>,
    challenge_ttl: Duration,
    preview_mode: bool,
}

impl PasskeyConfig {
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
        if !(1..=3600).contains(&challenge_ttl.as_secs()) {
            return Err(anyhow!(
                "Passkey challenge TTL must be between 1 and 3600 seconds"
            ));
        }
        if rp_id.trim().is_empty() || rp_name.trim().is_empty() {
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

pub struct PasskeyService {
    config: PasskeyConfig,
    webauthn_by_origin: HashMap<String, Webauthn>,
    exchanges: ExchangeStore,
}

impl PasskeyService {
    /// Create a new passkey service.
    ///
    /// # Errors
    /// Returns error if the state capacity is zero or the `WebAuthn` builder
    /// fails for any configured origin.
    pub fn new(
        config: PasskeyConfig,
        max_pending_states: usize,
        pool: sqlx::PgPool,
        seed: &[u8; 32],
        timeout_ms: i64,
    ) -> Result<Self> {
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
            webauthn_by_origin,
            exchanges: ExchangeStore::new(
                pool,
                seed,
                config.rp_id().to_owned(),
                i64::try_from(config.challenge_ttl().as_secs())?,
                max_pending_states,
                timeout_ms,
            )?,
            config,
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

        let reg_id = self
            .exchanges
            .put(
                Binding {
                    purpose: Purpose::PasskeyRegistration,
                    origin,
                    user: Some(user_id),
                    session: Some(&session_token_hash),
                },
                &registration,
            )
            .await?;

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
        let registration = self
            .exchanges
            .take::<PasskeyRegistration>(
                reg_id,
                Binding {
                    purpose: Purpose::PasskeyRegistration,
                    origin,
                    user: Some(user_id),
                    session: Some(session_token_hash),
                },
            )
            .await
            .map_err(|_| PasskeyRegistrationError::NotFound)?;

        let webauthn = self
            .webauthn_for_origin(origin)
            .map_err(|_| PasskeyRegistrationError::OriginMismatch)?;
        webauthn
            .finish_passkey_registration(&response, &registration)
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

        let auth_id = self
            .exchanges
            .put(
                Binding {
                    purpose: Purpose::PasskeyLogin,
                    origin,
                    user: None,
                    session: None,
                },
                &authentication,
            )
            .await?;

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
        if self.exchanges.discard(auth_id).await.is_err() {
            tracing::error!("failed to discard WebAuthn exchange");
        }
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
        let authentication = self
            .exchanges
            .take::<DiscoverableAuthentication>(
                auth_id,
                Binding {
                    purpose: Purpose::PasskeyLogin,
                    origin,
                    user: None,
                    session: None,
                },
            )
            .await
            .map_err(|_| PasskeyAuthenticationError::NotFound)?;

        let webauthn = self
            .webauthn_for_origin(origin)
            .map_err(|_| PasskeyAuthenticationError::OriginMismatch)?;
        webauthn
            .finish_discoverable_authentication(&response, authentication, credentials)
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

    fn test_service(config: PasskeyConfig, cap: usize) -> Result<PasskeyService> {
        PasskeyService::new(
            config,
            cap,
            sqlx::postgres::PgPoolOptions::new().connect_lazy("postgres://localhost/permesi")?,
            &[1; 32],
            1000,
        )
    }

    async fn durable_service(
        config: PasskeyConfig,
        cap: usize,
    ) -> Result<
        Option<(
            test_support::postgres::PostgresContainer,
            PasskeyService,
            Uuid,
            Vec<u8>,
        )>,
    > {
        use sqlx::Connection as _;
        if let Err(err) = test_support::runtime::ensure_container_runtime() {
            eprintln!("Skipping integration test: {err}");
            return Ok(None);
        }
        let postgres = test_support::postgres::PostgresContainer::start(
            test_support::TestNetwork::new("passkey").name(),
        )
        .await?;
        postgres.wait_until_ready().await?;
        let mut conn = sqlx::PgConnection::connect(&postgres.admin_dsn()).await?;
        test_support::sql::execute_script(
            &mut conn,
            "schema",
            include_str!("../../../../db/sql/02_permesi.sql"),
        )
        .await?;
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(5)
            .connect(&postgres.admin_dsn())
            .await?;
        let user: Uuid = sqlx::query_scalar("INSERT INTO users (email,opaque_registration_record,status) VALUES ('passkey@example.com',$1,'active') RETURNING id").bind(vec![0u8;32]).fetch_one(&pool).await?;
        Ok(Some((
            postgres,
            PasskeyService::new(config, cap, pool, &[1; 32], 1000)?,
            user,
            vec![1; 32],
        )))
    }

    /// `passkey_data` as persisted by webauthn-rs 0.5 (real soft-authenticator registration).
    const PASSKEY_JSON_WEBAUTHN_RS_0_5: &str = r#"{"cred":{"cred_id":"VXSvM5w3eRIFrbtTrvLI5VzbKFs82BW8AEv3F5rfYw0","cred":{"type_":"ES256","key":{"EC_EC2":{"curve":"SECP256R1","x":"BPiDk9FXwQQcOI4ue2xwwxv9Gw6_bv0XdSx3GoovAGc","y":"GVYpvy3R8IVlt13BeU-USvW28DRFmdSTfF9xdirBpw0"}}},"counter":0,"transports":null,"user_verified":true,"backup_eligible":false,"backup_state":false,"registration_policy":"required","extensions":{"cred_protect":"Ignored","hmac_create_secret":"NotRequested","appid":"NotRequested","cred_props":"Ignored"},"attestation":{"data":"Self_","metadata":"None"},"attestation_format":"packed"}}"#;

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
    fn deserialize_passkey_accepts_webauthn_rs_0_5_format() -> Result<()> {
        let passkey = deserialize_passkey(PASSKEY_JSON_WEBAUTHN_RS_0_5.as_bytes())?;
        assert_eq!(passkey.cred_id().len(), 32);

        // Re-serializing must reproduce the stored format so a rollback can still read new rows.
        let stored: serde_json::Value = serde_json::from_str(PASSKEY_JSON_WEBAUTHN_RS_0_5)?;
        let reencoded: serde_json::Value = serde_json::from_slice(&serialize_passkey(&passkey)?)?;
        assert_eq!(reencoded, stored);
        Ok(())
    }

    #[tokio::test]
    async fn origin_matching_is_exact() -> Result<()> {
        let service = test_service(test_config()?, 100)?;
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

    #[tokio::test]
    async fn origin_matching_requires_port_match() -> Result<()> {
        let config = PasskeyConfig::new(
            "example.com".to_string(),
            "Example".to_string(),
            vec!["https://example.com:8443".to_string()],
            Duration::from_mins(2),
            true,
        )?;
        let service = test_service(config, 100)?;
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
        let Some((_postgres, service, user_id, session_hash)) =
            durable_service(test_config()?, 100).await?
        else {
            return Ok(());
        };
        let (reg_id, _challenge) = service
            .register_begin(
                user_id,
                "user@example.com",
                "Example User",
                session_hash.clone(),
                "https://example.com",
            )
            .await?;

        assert!(
            service
                .register_finish(
                    reg_id,
                    user_id,
                    &session_hash,
                    "https://example.com",
                    dummy_register_credential()?
                )
                .await
                .is_err()
        );
        assert!(matches!(
            service
                .register_finish(
                    reg_id,
                    user_id,
                    &session_hash,
                    "https://example.com",
                    dummy_register_credential()?
                )
                .await,
            Err(PasskeyRegistrationError::NotFound)
        ));
        Ok(())
    }

    #[tokio::test]
    async fn register_finish_rejects_origin_and_consumes_state() -> Result<()> {
        let Some((_postgres, service, user_id, session_hash)) =
            durable_service(test_config()?, 100).await?
        else {
            return Ok(());
        };
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
        assert!(matches!(err, PasskeyRegistrationError::NotFound));

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
        let Some((_postgres, service, user_id, session_hash)) =
            durable_service(test_config()?, 100).await?
        else {
            return Ok(());
        };
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
                &[9, 9, 9],
                "https://example.com",
                credential,
            )
            .await
            .err()
            .ok_or_else(|| anyhow!("Expected session mismatch error"))?;
        assert!(matches!(err, PasskeyRegistrationError::NotFound));
        Ok(())
    }

    #[tokio::test]
    async fn authentication_start_does_not_disclose_account_credentials() -> Result<()> {
        let Some((_postgres, service, _user_id, _session_hash)) =
            durable_service(test_config()?, 100).await?
        else {
            return Ok(());
        };
        let (auth_id, challenge) = service.auth_begin("https://example.com").await?;

        assert!(challenge.public_key.allow_credentials.is_empty());
        service.discard_authentication(auth_id).await;
        Ok(())
    }

    #[tokio::test]
    async fn authentication_start_enforces_pending_state_capacity() -> Result<()> {
        let Some((_postgres, service, _user_id, _session_hash)) =
            durable_service(test_config()?, 1).await?
        else {
            return Ok(());
        };
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
