//! API handlers and shared utilities for Permesi.
//!
//! This module organizes the service's route handlers and provides common
//! functions for validation, admission token verification, and PASERK caching.

pub mod auth;
pub(crate) mod authorize;
pub mod health;
pub mod me;
pub mod me_webauthn;
pub mod orgs;
pub mod root;
pub(crate) mod token;
pub(crate) mod userinfo;
pub mod users;

use admission_token::{AdmissionTokenClaims, PaserkKeySet, VerificationOptions, verify_v4_public};
use anyhow::{Context, Result, ensure};
use std::{
    sync::Arc,
    time::{Duration, Instant, SystemTime},
};
use tokio::sync::RwLock;
use tracing::{debug, instrument, warn};

/// Body cap for the `WebAuthn` finish endpoints, enforced by the route layer in
/// `api::openapi::webauthn_finish_routes` before any JSON is parsed. A browser credential,
/// attestation included, is a few KiB; anything larger is refused with 413.
pub(crate) const MAX_WEBAUTHN_JSON_BYTES: usize = 32 * 1024;

/// Status for a `WebAuthn` finish body the `Json` extractor refused: 413 when it exceeded
/// [`MAX_WEBAUTHN_JSON_BYTES`], otherwise 400 (wrong content type, malformed JSON or a
/// credential that does not match the `webauthn-rs` types). The serde error stays out of
/// the response because it can quote attacker-supplied input.
pub(crate) fn webauthn_payload_status(
    rejection: &axum::extract::rejection::JsonRejection,
) -> axum::http::StatusCode {
    if rejection.status() == axum::http::StatusCode::PAYLOAD_TOO_LARGE {
        axum::http::StatusCode::PAYLOAD_TOO_LARGE
    } else {
        axum::http::StatusCode::BAD_REQUEST
    }
}

const MIN_TOKEN_TTL_SECONDS: i64 = 60;
const MAX_TOKEN_TTL_SECONDS: i64 = 180;
const ADMISSION_ACTION: &str = "admission";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DependencyStatus {
    Ok,
    Error,
    #[cfg(test)]
    Static,
}

/// The verifier starts empty on every boot. Only the background reader can install
/// keys. The validity deadline includes time spent waiting for the authority read.
#[derive(Debug)]
pub struct AdmissionVerifier {
    snapshot: RwLock<Option<Snapshot>>,
    issuer: String,
    audience: String,
}

#[derive(Debug)]
struct Snapshot {
    keyset: PaserkKeySet,
    deadline: Option<Instant>,
    floor: u32,
    revision: u64,
}

/// The operator publishes at most two approved Ed25519 versions in the core KV.
/// A higher withdrawal floor immediately excludes every lower version.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Authority {
    minimum_version: u32,
    keys: std::collections::BTreeMap<u32, String>,
}

impl Authority {
    fn into_snapshot(self, deadline: Instant, revision: u64) -> Result<Snapshot> {
        ensure!(
            revision > 0 && self.minimum_version > 0 && self.keys.len() <= 2,
            "invalid admission authority"
        );
        let mut keys = Vec::new();
        for (version, material) in self.keys.into_iter().rev() {
            ensure!(
                version > 0 && material.len() == 44,
                "invalid Ed25519 version or encoding"
            );
            if version >= self.minimum_version {
                keys.push(admission_token::PaserkKey::from_ed25519_public_key_base64(
                    &material,
                )?);
            }
        }
        let keyset = PaserkKeySet {
            version: "v4".into(),
            purpose: "public".into(),
            active_kid: keys.first().map_or_else(String::new, |key| key.kid.clone()),
            keys,
        };
        if !keyset.keys.is_empty() {
            keyset.validate()?;
        }
        Ok(Snapshot {
            keyset,
            deadline: Some(deadline),
            floor: self.minimum_version,
            revision,
        })
    }
}

impl AdmissionVerifier {
    #[cfg(test)]
    pub fn new(keyset: PaserkKeySet, issuer: String, audience: String) -> Self {
        Self {
            snapshot: RwLock::new(Some(Snapshot {
                keyset,
                deadline: None,
                floor: 1,
                revision: 1,
            })),
            issuer,
            audience,
        }
    }

    /// Poll only the core-controlled KV v2 record. Read failures age out the last
    /// successful observation. Stopping the service drops the reader's weak reference.
    pub(crate) fn start(
        globals: &crate::cli::globals::GlobalArgs,
        mount: &str,
        refresh: Duration,
        max_age: Duration,
        issuer: String,
        audience: String,
    ) -> Arc<Self> {
        let verifier = Arc::new(Self {
            snapshot: RwLock::new(None),
            issuer,
            audience,
        });
        let weak = Arc::downgrade(&verifier);
        let transport = globals.openbao_transport.clone();
        let token = transport.is_tcp().then(|| globals.openbao_token.clone());
        let path = format!("/v1/{mount}/data/admission-authority");
        tokio::spawn(async move {
            use secrecy::ExposeSecret;
            let mut timer = tokio::time::interval(refresh);
            timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                timer.tick().await;
                let Some(verifier) = weak.upgrade() else {
                    break;
                };
                let started = Instant::now();
                let observation = async {
                    let response = transport
                        .read_bounded(&path, token.as_ref().map(ExposeSecret::expose_secret), 8192)
                        .await?;
                    ensure!(
                        response.status.is_success(),
                        "admission authority read failed"
                    );
                    let revision = response
                        .body
                        .pointer("/data/metadata/version")
                        .and_then(serde_json::Value::as_u64)
                        .context("missing KV revision")?;
                    let authority: Authority = serde_json::from_value(
                        response
                            .body
                            .pointer("/data/data")
                            .context("missing admission authority")?
                            .clone(),
                    )?;
                    verifier
                        .install(authority.into_snapshot(started + max_age, revision)?)
                        .await
                };
                if !matches!(tokio::time::timeout(refresh, observation).await, Ok(Ok(()))) {
                    let snapshot = verifier.snapshot.read().await;
                    let age_ms = snapshot
                        .as_ref()
                        .and_then(|s| s.deadline)
                        .and_then(|end| end.checked_sub(max_age))
                        .map(|t| t.elapsed().as_millis());
                    warn!(?age_ms, "admission authority refresh failed");
                }
            }
        });
        verifier
    }

    /// Reject a regressing floor even if an older read arrives from a stale replica.
    async fn install(&self, next: Snapshot) -> Result<()> {
        let mut stored = self.snapshot.write().await;
        ensure!(
            stored
                .as_ref()
                .is_none_or(|old| next.floor >= old.floor && next.revision >= old.revision),
            "admission authority revision or floor regressed"
        );
        *stored = Some(next);
        Ok(())
    }

    #[must_use]
    pub fn issuer(&self) -> &str {
        &self.issuer
    }
    #[must_use]
    pub fn audience(&self) -> &str {
        &self.audience
    }

    async fn dependency_status(&self) -> DependencyStatus {
        let stored = self.snapshot.read().await;
        match stored.as_ref() {
            #[cfg(test)]
            Some(snapshot) if snapshot.deadline.is_none() => DependencyStatus::Static,
            Some(snapshot) if snapshot.is_current() => DependencyStatus::Ok,
            _ => DependencyStatus::Error,
        }
    }
}

impl Snapshot {
    fn is_current(&self) -> bool {
        !self.keyset.keys.is_empty() && self.deadline.is_none_or(|end| Instant::now() < end)
    }
}

fn now_unix_seconds() -> i64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

/// Verify issuer, audience, action, time bounds and signature against the current local snapshot.
#[instrument(skip_all)]
pub async fn verify_token(verifier: &AdmissionVerifier, token: &str) -> bool {
    verify_token_claims(verifier, token).await.is_some()
}

/// Reject unknown keys and expired observations locally. Only the reader contacts OpenBao.
pub async fn verify_token_claims(
    verifier: &AdmissionVerifier,
    token: &str,
) -> Option<AdmissionTokenClaims> {
    let stored = verifier.snapshot.read().await;
    let snapshot = stored.as_ref().filter(|s| s.is_current())?;
    let options = VerificationOptions {
        expected_issuer: &verifier.issuer,
        expected_audience: &verifier.audience,
        expected_action: ADMISSION_ACTION,
        now_unix_seconds: now_unix_seconds(),
        min_ttl_seconds: MIN_TOKEN_TTL_SECONDS,
        max_ttl_seconds: MAX_TOKEN_TTL_SECONDS,
    };
    let result = verify_v4_public(token, &snapshot.keyset, &options).ok();
    debug!(accepted = result.is_some(), "admission verification");
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use admission_token::Error as AdmissionError;
    use admission_token::{
        AdmissionTokenFooter, PaserkKey, build_token, encode_signing_input, rfc3339_from_unix,
    };
    use ed25519_dalek::{Signer, SigningKey};

    const ISSUER: &str = "https://genesis.example.test";
    const AUDIENCE: &str = "permesi";

    fn keyset_for_signing_key(signing_key: &SigningKey) -> Result<PaserkKeySet, AdmissionError> {
        let verifying_key = signing_key.verifying_key();
        let key = PaserkKey::from_ed25519_public_key_bytes(&verifying_key.to_bytes())?;
        Ok(PaserkKeySet {
            version: "v4".to_string(),
            purpose: "public".to_string(),
            active_kid: key.kid.clone(),
            keys: vec![key],
        })
    }

    fn sign_token(
        claims: &AdmissionTokenClaims,
        kid: &str,
        signing_key: &SigningKey,
    ) -> Result<String, AdmissionError> {
        let footer = AdmissionTokenFooter {
            kid: kid.to_string(),
        };
        let signing_input = encode_signing_input(claims, &footer)?;
        let signature = signing_key.sign(signing_input.pre_auth.as_slice());
        Ok(build_token(
            signing_input.payload.as_slice(),
            signing_input.footer.as_slice(),
            &signature.to_bytes(),
        ))
    }

    fn build_claims(now: i64, jti: &str) -> Result<AdmissionTokenClaims, AdmissionError> {
        let iat = rfc3339_from_unix(now.saturating_sub(1))?;
        let exp = rfc3339_from_unix(now.saturating_add(120))?;
        Ok(AdmissionTokenClaims {
            iss: ISSUER.to_string(),
            aud: AUDIENCE.to_string(),
            iat,
            exp,
            jti: jti.to_string(),
            action: ADMISSION_ACTION.to_string(),
            sub: None,
        })
    }

    #[tokio::test]
    async fn admission_verifier_accepts_valid_token() -> Result<(), AdmissionError> {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let keyset = keyset_for_signing_key(&signing_key)?;

        let now = now_unix_seconds();
        let claims = build_claims(now, "permesi-valid")?;
        let expected_jti = claims.jti.clone();
        let kid = keyset.active_kid.clone();
        let token = sign_token(&claims, &kid, &signing_key)?;
        let verifier = AdmissionVerifier::new(keyset, ISSUER.to_string(), AUDIENCE.to_string());

        let verified_claims = verify_token_claims(&verifier, &token)
            .await
            .ok_or(AdmissionError::InvalidSignature)?;
        assert_eq!(verified_claims.jti, expected_jti);
        Ok(())
    }

    #[tokio::test]
    async fn admission_verifier_rejects_unknown_kid() -> Result<(), AdmissionError> {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let keyset = keyset_for_signing_key(&signing_key)?;

        let other_signing_key = SigningKey::from_bytes(&[9u8; 32]);
        let other_keyset = keyset_for_signing_key(&other_signing_key)?;

        let now = now_unix_seconds();
        let claims = build_claims(now, "permesi-unknown")?;
        let token = sign_token(&claims, &other_keyset.active_kid, &other_signing_key)?;
        let verifier = AdmissionVerifier::new(keyset, ISSUER.to_string(), AUDIENCE.to_string());

        let claims_result = verify_token_claims(&verifier, &token).await;
        assert!(claims_result.is_none());
        Ok(())
    }

    /// A token's `kid` and claims are attacker-chosen until its signature verifies, so a
    /// rejected token must leave nothing of itself in the logs, at any level.
    #[tokio::test]
    async fn admission_rejection_logs_nothing_from_the_unverified_token()
    -> Result<(), AdmissionError> {
        use std::sync::{Arc, Mutex};
        use tracing::instrument::WithSubscriber;

        #[derive(Clone)]
        struct Sink(Arc<Mutex<Vec<u8>>>);
        impl std::io::Write for Sink {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0
                    .lock()
                    .map_err(|_| std::io::Error::other("capture poisoned"))?
                    .extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let trusted = SigningKey::from_bytes(&[7u8; 32]);
        let verifier = AdmissionVerifier::new(
            keyset_for_signing_key(&trusted)?,
            ISSUER.to_string(),
            AUDIENCE.to_string(),
        );
        let attacker = SigningKey::from_bytes(&[9u8; 32]);
        let claims = build_claims(now_unix_seconds(), "attacker-chosen-subject")?;
        let unknown_kid = "attacker-chosen-kid";
        let token = sign_token(&claims, unknown_kid, &attacker)?;

        let captured = Arc::new(Mutex::new(Vec::new()));
        let sink = Sink(captured.clone());
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_ansi(false)
            .with_writer(move || sink.clone())
            .finish();
        let accepted = async {
            let direct = verify_token(&verifier, &token).await;
            let claims = verify_token_claims(&verifier, &token).await;
            direct || claims.is_some()
        }
        .with_subscriber(subscriber)
        .await;
        assert!(!accepted);

        let logs = String::from_utf8_lossy(
            &captured
                .lock()
                .map_err(|_| AdmissionError::InvalidSignature)?,
        )
        .into_owned();
        assert!(
            logs.contains("admission verification"),
            "the rejection itself is logged"
        );
        for leaked in [unknown_kid, "attacker-chosen-subject", token.as_str()] {
            assert!(
                !logs.contains(leaked),
                "log carries unverified token material"
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn withdrawal_rejects_the_same_unexpired_token_and_a_regressing_floor() -> Result<()> {
        use base64::{Engine, engine::general_purpose::STANDARD};
        let signer = SigningKey::from_bytes(&[7; 32]);
        let keys = keyset_for_signing_key(&signer)?;
        let token = sign_token(
            &build_claims(now_unix_seconds(), "withdrawn")?,
            &keys.active_kid,
            &signer,
        )?;
        let verifier = AdmissionVerifier {
            snapshot: RwLock::new(None),
            issuer: ISSUER.into(),
            audience: AUDIENCE.into(),
        };
        let observation = |minimum_version, deadline, revision| {
            Authority {
                minimum_version,
                keys: [(1, STANDARD.encode(signer.verifying_key().as_bytes()))].into(),
            }
            .into_snapshot(deadline, revision)
        };
        let future = Instant::now() + Duration::from_secs(60);
        assert!(!verify_token(&verifier, &token).await);
        verifier.install(observation(1, future, 1)?).await?;
        assert!(verify_token(&verifier, &token).await);
        verifier.install(observation(1, Instant::now(), 2)?).await?;
        assert!(!verify_token(&verifier, &token).await);
        assert!(verifier.install(observation(1, future, 1)?).await.is_err());
        verifier.install(observation(2, future, 3)?).await?;
        assert!(verifier.install(observation(1, future, 1)?).await.is_err());
        assert!(!verify_token(&verifier, &token).await);
        Ok(())
    }
}
