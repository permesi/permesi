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
    /// Clock skew tolerated on a token's `iat`; Genesis runs on other hosts.
    iat_leeway_seconds: i64,
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
            iat_leeway_seconds: 0,
        }
    }

    /// The same verifier with a clock-skew allowance, as the server configures it.
    #[cfg(test)]
    pub fn with_iat_leeway(mut self, seconds: i64) -> Self {
        self.iat_leeway_seconds = seconds;
        self
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
        iat_leeway_seconds: i64,
    ) -> Arc<Self> {
        let verifier = Arc::new(Self {
            snapshot: RwLock::new(None),
            issuer,
            audience,
            iat_leeway_seconds,
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
        iat_leeway_seconds: verifier.iat_leeway_seconds,
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

    /// Genesis runs on other hosts: a token it dated a few seconds ahead of this
    /// replica's clock is admitted within the configured allowance and not beyond it.
    #[tokio::test]
    async fn admission_verifier_tolerates_bounded_signer_clock_skew() -> Result<(), AdmissionError>
    {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let keyset = keyset_for_signing_key(&signing_key)?;
        let now = now_unix_seconds();
        // `build_claims` dates the token one second before its argument. The verifier
        // reads the real clock, so the three tokens sit seconds away from the bounds they
        // probe (the exact boundary is tested with a fixed clock in `admission_token`):
        // one inside a ten second allowance, one outside it but inside the ceiling of
        // thirty, so a verifier that applied the ceiling instead of its own setting
        // would wrongly accept it, and one beyond every allowance.
        let inside = build_claims(now.saturating_add(7), "inside")?;
        let outside = build_claims(now.saturating_add(21), "outside")?;
        let beyond = build_claims(now.saturating_add(61), "beyond")?;
        let sign = |claims| sign_token(claims, &keyset.active_kid, &signing_key);
        let (inside, outside, beyond) = (sign(&inside)?, sign(&outside)?, sign(&beyond)?);

        let verifier = |leeway| {
            AdmissionVerifier::new(keyset.clone(), ISSUER.to_string(), AUDIENCE.to_string())
                .with_iat_leeway(leeway)
        };
        let strict = verifier(0);
        assert!(verify_token_claims(&strict, &inside).await.is_none());
        let tolerant = verifier(10);
        assert!(verify_token_claims(&tolerant, &inside).await.is_some());
        assert!(verify_token_claims(&tolerant, &outside).await.is_none());
        let widest = verifier(admission_token::MAX_IAT_LEEWAY_SECONDS);
        assert!(verify_token_claims(&widest, &outside).await.is_some());
        // A setting that escaped validation cannot exceed the ceiling.
        for unvalidated in [3_600, i64::MAX] {
            assert!(
                verify_token_claims(&verifier(unvalidated), &beyond)
                    .await
                    .is_none()
            );
        }
        Ok(())
    }

    /// The running verifier keeps the allowance it was started with.
    #[tokio::test]
    async fn admission_verifier_starts_with_the_configured_iat_leeway() -> anyhow::Result<()> {
        // Nothing listens here; the background reader only fails to refresh.
        let url = "http://127.0.0.1:1";
        let transport = openbao_client::OpenBaoTransport::from_target(
            crate::APP_USER_AGENT,
            openbao_client::OpenBaoTarget::parse(url)?,
        )?;
        let globals = crate::cli::globals::GlobalArgs::new(url.to_string(), transport);
        for leeway in [0, 7, 30] {
            let verifier = AdmissionVerifier::start(
                &globals,
                "secret/permesi",
                Duration::from_secs(60),
                Duration::from_secs(120),
                ISSUER.to_string(),
                AUDIENCE.to_string(),
                leeway,
            );
            assert_eq!(verifier.iat_leeway_seconds, leeway);
        }
        Ok(())
    }

    /// A token's `kid` and claims are attacker-chosen until its signature verifies, and a
    /// rejected token is still a credential someone presented. Whatever stage rejects it
    /// (parsing, the footer, the key lookup, the signature, or a claim of a correctly
    /// signed token), nothing of the token may reach the logs, at any level.
    #[tokio::test]
    async fn admission_rejection_logs_nothing_from_the_unverified_token() -> anyhow::Result<()> {
        let trusted = SigningKey::from_bytes(&[7u8; 32]);
        let keyset = keyset_for_signing_key(&trusted)?;
        let verifier =
            AdmissionVerifier::new(keyset.clone(), ISSUER.to_string(), AUDIENCE.to_string());
        let attacker = SigningKey::from_bytes(&[9u8; 32]);
        let now = now_unix_seconds();
        let hostile = |jti: &str| -> anyhow::Result<AdmissionTokenClaims> {
            let mut claims = build_claims(now, jti)?;
            claims.sub = Some("attacker-chosen-subject".to_string());
            Ok(claims)
        };

        // Rejected at the key lookup, before any signature check.
        let unknown_kid = sign_token(
            &hostile("jti-unknown-kid")?,
            "attacker-chosen-kid",
            &attacker,
        )?;
        // Rejected at the signature: the public `kid` of the trusted key, a foreign signature.
        let forged = sign_token(&hostile("jti-forged")?, &keyset.active_kid, &attacker)?;
        // Correctly signed, rejected on a claim.
        let mut wrong_audience = hostile("jti-wrong-audience")?;
        wrong_audience.aud = "audience-of-another-service".to_string();
        let wrong_audience = sign_token(&wrong_audience, &keyset.active_kid, &trusted)?;
        let expired = sign_token(
            &build_claims(now.saturating_sub(1_000), "jti-expired")?,
            &keyset.active_kid,
            &trusted,
        )?;
        // Rejected while parsing: no footer, and text that is not a token at all.
        let footerless = forged
            .rsplit_once('.')
            .map(|(head, _)| head.to_string())
            .context("token has a footer")?;
        let garbage = "v4.public.malformed-token-sentinel.malformed-footer-sentinel".to_string();
        let tokens = [
            unknown_kid,
            forged,
            wrong_audience,
            expired,
            footerless,
            garbage,
        ];

        let accepted = std::sync::atomic::AtomicBool::new(false);
        let logs = test_support::logs::capture_until("admission verification", || async {
            for token in &tokens {
                let admitted = verify_token(&verifier, token).await
                    || verify_token_claims(&verifier, token).await.is_some();
                accepted.fetch_or(admitted, std::sync::atomic::Ordering::Relaxed);
            }
        })
        .await?;
        assert!(!accepted.into_inner(), "a hostile token was admitted");

        let mut leaks: Vec<&str> = vec![
            "attacker-chosen-kid",
            "attacker-chosen-subject",
            "audience-of-another-service",
            "malformed-token-sentinel",
            "malformed-footer-sentinel",
            "jti-unknown-kid",
            "jti-forged",
            "jti-wrong-audience",
            "jti-expired",
        ];
        // The token itself and each of its encoded parts (payload, footer).
        for token in &tokens {
            leaks.push(token);
            leaks.extend(token.split('.').skip(2).filter(|part| part.len() >= 16));
        }
        for leaked in leaks {
            assert!(
                !logs.contains(leaked),
                "log carries unverified token material: {leaked}"
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
            iat_leeway_seconds: 0,
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
