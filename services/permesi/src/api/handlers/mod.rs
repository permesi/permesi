//! API handlers and shared utilities for Permesi.
//!
//! This module organizes the service's route handlers and provides common
//! functions for validation, admission token verification, and PASERK caching.

pub mod auth;
pub mod health;
pub mod me;
pub mod me_webauthn;
pub mod orgs;
pub mod root;
pub mod user_login;
pub mod user_register;
pub mod users;

use admission_token::{
    AdmissionTokenClaims, Error as AdmissionError, PaserkKeySet, VerificationOptions,
    verify_v4_public,
};
use anyhow::{Context, Result, anyhow};
use regex::Regex;
use reqwest::{
    Client,
    header::{ETAG, IF_NONE_MATCH},
};
use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant, SystemTime},
};
use tokio::sync::RwLock;
use tracing::{Instrument, error, info, info_span, instrument, warn};
use url::Url;

// PASERK caching: use in-memory keyset with TTL; refresh on stale cache or unknown kid.
// If refresh fails, keep the last known keyset so verification keeps working.
const KEYSET_CACHE_TTL_SECONDS: u64 = 300;
const KEYSET_REFRESH_COOLDOWN_SECONDS: u64 = 30;
const MIN_TOKEN_TTL_SECONDS: i64 = 60;
const MAX_TOKEN_TTL_SECONDS: i64 = 180;
const ADMISSION_ACTION: &str = "admission";

/// Lightweight email sanity check used by auth handlers before persisting data.
pub fn valid_email(email: &str) -> bool {
    Regex::new(r"^[^@\s]+@[^@\s]+\.[^@\s]+$").is_ok_and(|re| re.is_match(email))
}

/// Password inputs are expected to be 32-byte hex (e.g., 64 hex chars).
pub fn valid_password(password: &str) -> bool {
    // length must be between 64 hex characters
    Regex::new(r"^[0-9a-fA-F]{64}$").is_ok_and(|re| re.is_match(password))
}

#[derive(Debug)]
enum KeysetSource {
    /// Keyset loaded from a local file or CLI string and never refreshed.
    Static,
    /// Keyset fetched from genesis `/paserk.json` and refreshed as needed.
    Remote { url: String, client: Client },
}

#[derive(Debug, Clone)]
struct KeysetCache {
    /// Last known PASERK keyset for admission token verification.
    keyset: PaserkKeySet,
    /// When the keyset was last successfully fetched.
    fetched_at: Instant,
    /// `ETag` from the last successful fetch, if provided by genesis.
    etag: Option<String>,
}

impl KeysetCache {
    /// Keyset is fresh if within TTL; stale keysets trigger a refresh attempt.
    fn is_fresh(&self) -> bool {
        self.fetched_at.elapsed() < Duration::from_secs(KEYSET_CACHE_TTL_SECONDS)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DependencyStatus {
    /// Remote dependency is reachable and PASERK fetch succeeded.
    Ok,
    /// Remote dependency is unreachable or PASERK fetch failed.
    Error,
    /// Static keyset means no external dependency.
    Static,
}

impl DependencyStatus {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Error => "error",
            Self::Static => "static",
        }
    }

    const fn is_healthy(self) -> bool {
        !matches!(self, Self::Error)
    }
}

/// Verifies admission (zero) tokens using a cached PASERK keyset.
///
/// Used by auth handlers (signup/login/verify) to validate tokens offline and
/// by `/health` to report dependency status when the keyset is fetched remotely.
#[derive(Debug)]
pub struct AdmissionVerifier {
    /// Where the PASERK keyset comes from (static or remote genesis URL).
    keyset_source: KeysetSource,
    /// In-memory cached keyset and last fetch timestamp.
    keyset_cache: RwLock<KeysetCache>,
    /// Expected token issuer (genesis base URL).
    issuer: String,
    /// Expected token audience (permesi).
    audience: String,
    /// Expected token action ("admission").
    action: String,
    /// Timestamp to throttle refresh attempts on unknown kid.
    last_refresh_unix: AtomicU64,
}

impl AdmissionVerifier {
    /// Build from a static keyset (file/inline CLI), no remote refresh.
    #[must_use]
    pub fn new(keyset: PaserkKeySet, issuer: String, audience: String) -> Self {
        Self {
            keyset_source: KeysetSource::Static,
            keyset_cache: RwLock::new(KeysetCache {
                keyset,
                fetched_at: Instant::now(),
                etag: None,
            }),
            issuer,
            audience,
            action: ADMISSION_ACTION.to_string(),
            last_refresh_unix: AtomicU64::new(0),
        }
    }

    /// Build a verifier that fetches a PASERK keyset from a remote URL.
    ///
    /// # Errors
    /// Returns an error if the keyset cannot be fetched or parsed.
    pub async fn new_remote(url: String, issuer: String, audience: String) -> Result<Self> {
        let parsed = Url::parse(&url).context("Invalid admission PASERK URL")?;
        if parsed.scheme() != "https" {
            return Err(anyhow!("Admission PASERK URL must use https: {url}"));
        }

        let ca_cert = crate::tls::load_reqwest_ca()?;
        let mut builder = Client::builder()
            .use_rustls_tls()
            .user_agent(crate::APP_USER_AGENT);

        if let Some(cert) = ca_cert {
            builder = builder.tls_certs_only(std::iter::once(cert));
        }

        let client = builder
            .build()
            .context("Failed to build PASERK HTTP client")?;
        // Startup fetch is best-effort: if genesis isn't ready yet, start with an empty, stale cache
        // so /health stays red and verification fails closed until refresh succeeds.
        let (keyset, fetched_at, last_refresh_unix, etag) =
            match fetch_keyset(&client, &url, None).await {
                Ok(FetchOutcome::Updated { keyset, etag }) => {
                    keyset
                        .validate()
                        .context("Invalid admission PASERK keyset")?;
                    (keyset, Instant::now(), now_unix_seconds_u64(), etag)
                }
                Ok(FetchOutcome::NotModified) => {
                    warn!("admission PASERK fetch returned not-modified during startup");
                    (empty_keyset(), stale_instant(), 0, None)
                }
                Err(err) => {
                    warn!(
                        url = %url,
                        error = %err,
                        "admission PASERK fetch failed during startup; continuing with empty keyset"
                    );
                    (empty_keyset(), stale_instant(), 0, None)
                }
            };
        Ok(Self {
            keyset_source: KeysetSource::Remote { url, client },
            keyset_cache: RwLock::new(KeysetCache {
                keyset,
                fetched_at,
                etag,
            }),
            issuer,
            audience,
            action: ADMISSION_ACTION.to_string(),
            last_refresh_unix: AtomicU64::new(last_refresh_unix),
        })
    }

    /// Return the remote PASERK URL when configured, otherwise `None`.
    pub fn keyset_url(&self) -> Option<&str> {
        match &self.keyset_source {
            KeysetSource::Static => None,
            KeysetSource::Remote { url, .. } => Some(url.as_str()),
        }
    }

    /// Return the configured issuer string for admission token verification.
    #[must_use]
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// Return the configured audience for admission token verification.
    #[must_use]
    pub fn audience(&self) -> &str {
        &self.audience
    }

    /// Return a keyset snapshot; refresh if stale, keep cache if refresh fails.
    async fn keyset_snapshot(&self) -> Result<PaserkKeySet> {
        let (cached, fresh) = {
            let cache = self.keyset_cache.read().await;
            (cache.keyset.clone(), cache.is_fresh())
        };

        if fresh {
            return Ok(cached);
        }

        if let KeysetSource::Remote { url, .. } = &self.keyset_source
            && let Err(err) = self.refresh_keyset().await
        {
            // Refresh failure shouldn't break verification; keep using the last cached keyset.
            warn!(
                error = %err,
                url = %url,
                "failed to refresh paserk keyset cache"
            );
            return Ok(cached);
        }

        let cache = self.keyset_cache.read().await;
        Ok(cache.keyset.clone())
    }

    /// Fetch PASERK from genesis and update the in-memory cache.
    async fn refresh_keyset(&self) -> Result<()> {
        let (url, client, etag) = match &self.keyset_source {
            KeysetSource::Static => return Ok(()),
            KeysetSource::Remote { url, client } => {
                let etag = self.keyset_cache.read().await.etag.clone();
                (url.clone(), client.clone(), etag)
            }
        };

        match fetch_keyset(&client, &url, etag.as_deref()).await? {
            FetchOutcome::NotModified => {
                let mut cache = self.keyset_cache.write().await;
                cache.fetched_at = Instant::now();
            }
            FetchOutcome::Updated { keyset, etag } => {
                keyset
                    .validate()
                    .context("Invalid admission PASERK keyset")?;
                let mut cache = self.keyset_cache.write().await;
                cache.keyset = keyset;
                cache.fetched_at = Instant::now();
                cache.etag = etag;
                info!(
                    keyset_keys = cache.keyset.keys.len(),
                    "paserk keyset cache refreshed"
                );
            }
        }
        Ok(())
    }

    /// Report dependency status for `/health` by attempting a refresh.
    async fn dependency_status(&self) -> DependencyStatus {
        match &self.keyset_source {
            KeysetSource::Static => DependencyStatus::Static,
            KeysetSource::Remote { url, .. } => match self.refresh_keyset().await {
                Ok(()) => DependencyStatus::Ok,
                Err(err) => {
                    // /health reports dependency errors when refresh fails.
                    warn!(
                        error = %err,
                        url = %url,
                        "paserk keyset fetch failed during health check"
                    );
                    DependencyStatus::Error
                }
            },
        }
    }

    /// Refresh if a token `kid` is unknown, with cooldown to avoid spamming genesis.
    async fn refresh_on_unknown_kid(&self) -> Result<bool> {
        if matches!(&self.keyset_source, KeysetSource::Static) {
            return Ok(false);
        }
        let now = now_unix_seconds_u64();
        let last = self.last_refresh_unix.load(Ordering::Relaxed);
        if now.saturating_sub(last) < KEYSET_REFRESH_COOLDOWN_SECONDS {
            // Avoid spamming genesis when many unknown-kid tokens arrive.
            return Ok(false);
        }
        self.last_refresh_unix.store(now, Ordering::Relaxed);
        self.refresh_keyset().await?;
        Ok(true)
    }
}

/// Unix seconds for token TTL validation.
fn now_unix_seconds() -> i64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

/// Convenience for cooldown tracking (unsigned).
fn now_unix_seconds_u64() -> u64 {
    u64::try_from(now_unix_seconds()).unwrap_or(0)
}

/// Empty keyset used when startup fetch fails; forces verification to fail closed.
fn empty_keyset() -> PaserkKeySet {
    PaserkKeySet {
        version: "v4".to_string(),
        purpose: "public".to_string(),
        active_kid: String::new(),
        keys: Vec::new(),
    }
}

/// Produce an Instant that is already stale to trigger an early refresh.
fn stale_instant() -> Instant {
    Instant::now()
        .checked_sub(Duration::from_secs(KEYSET_CACHE_TTL_SECONDS + 1))
        .unwrap_or_else(Instant::now)
}

enum FetchOutcome {
    NotModified,
    Updated {
        keyset: PaserkKeySet,
        etag: Option<String>,
    },
}

/// Fetch the PASERK keyset from genesis and parse its JSON response.
async fn fetch_keyset(client: &Client, url: &str, etag: Option<&str>) -> Result<FetchOutcome> {
    let span = info_span!(
        "admission.keyset.fetch",
        http.method = "GET",
        url = %url
    );
    async {
        let mut request = client.get(url);
        if let Some(etag_value) = etag {
            request = request.header(IF_NONE_MATCH, etag_value);
        }
        let response = request.send().await?;
        let status = response.status();
        if status.as_u16() == 304 {
            return Ok(FetchOutcome::NotModified);
        }
        let etag = response
            .headers()
            .get(ETAG)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string);
        let body = response.text().await?;

        if !status.is_success() {
            return Err(anyhow!("paserk keyset fetch failed: {status}"));
        }

        let keyset = PaserkKeySet::from_json(&body).context("Invalid admission PASERK JSON")?;
        Ok(FetchOutcome::Updated { keyset, etag })
    }
    .instrument(span)
    .await
}

/// Convenience wrapper that returns true/false instead of claims.
#[instrument(skip(verifier, token))]
pub async fn verify_token(verifier: &AdmissionVerifier, token: &str) -> bool {
    verify_token_claims(verifier, token).await.is_some()
}

/// Verify a zero token and return its claims if valid.
///
/// Flow: use cached keyset; on unknown `kid`, refresh (with cooldown) and retry once.
pub async fn verify_token_claims(
    verifier: &AdmissionVerifier,
    token: &str,
) -> Option<AdmissionTokenClaims> {
    let keyset = match verifier.keyset_snapshot().await {
        Ok(keyset) => keyset,
        Err(e) => {
            error!("Admission PASERK snapshot failed: {e}");
            return None;
        }
    };

    let now = now_unix_seconds();
    let options = VerificationOptions {
        expected_issuer: &verifier.issuer,
        expected_audience: &verifier.audience,
        expected_action: &verifier.action,
        now_unix_seconds: now,
        min_ttl_seconds: MIN_TOKEN_TTL_SECONDS,
        max_ttl_seconds: MAX_TOKEN_TTL_SECONDS,
    };

    match verify_v4_public(token, &keyset, &options) {
        Ok(claims) => Some(claims),
        Err(AdmissionError::UnknownKid(kid)) => match verifier.refresh_on_unknown_kid().await {
            Ok(true) => {
                let keyset = match verifier.keyset_snapshot().await {
                    Ok(keyset) => keyset,
                    Err(e) => {
                        error!("Admission PASERK refresh failed: {e}");
                        return None;
                    }
                };
                let options = VerificationOptions {
                    expected_issuer: &verifier.issuer,
                    expected_audience: &verifier.audience,
                    expected_action: &verifier.action,
                    now_unix_seconds: now_unix_seconds(),
                    min_ttl_seconds: MIN_TOKEN_TTL_SECONDS,
                    max_ttl_seconds: MAX_TOKEN_TTL_SECONDS,
                };
                match verify_v4_public(token, &keyset, &options) {
                    Ok(claims) => Some(claims),
                    Err(e) => {
                        error!("Admission token verification failed after refresh: {e}");
                        None
                    }
                }
            }
            Ok(false) => {
                warn!(kid = %kid, "Admission token kid not found and refresh suppressed");
                None
            }
            Err(e) => {
                error!("Admission PASERK refresh failed: {e}");
                None
            }
        },
        Err(e) => {
            error!("Admission token verification failed: {e}");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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

    #[test]
    fn valid_email_accepts_simple() {
        assert!(valid_email("user@example.com"));
    }

    #[test]
    fn valid_email_rejects_missing_at() {
        assert!(!valid_email("user.example.com"));
    }

    #[test]
    fn valid_password_accepts_hex() {
        let password = "a".repeat(64);
        assert!(valid_password(&password));
    }

    #[test]
    fn valid_password_rejects_non_hex() {
        let password = "g".repeat(64);
        assert!(!valid_password(&password));
    }

    #[test]
    fn valid_password_rejects_short() {
        let password = "a".repeat(63);
        assert!(!valid_password(&password));
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

    #[tokio::test]
    async fn refresh_on_unknown_kid_skips_static_source() -> anyhow::Result<()> {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let keyset = keyset_for_signing_key(&signing_key)?;
        let verifier = AdmissionVerifier::new(keyset, ISSUER.to_string(), AUDIENCE.to_string());
        let refreshed = verifier.refresh_on_unknown_kid().await?;
        assert!(!refreshed);
        Ok(())
    }

    #[tokio::test]
    async fn refresh_on_unknown_kid_suppresses_within_cooldown() -> anyhow::Result<()> {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let keyset = keyset_for_signing_key(&signing_key)?;
        let cache = KeysetCache {
            keyset,
            fetched_at: Instant::now(),
            etag: None,
        };
        let verifier = AdmissionVerifier {
            keyset_source: KeysetSource::Remote {
                url: "http://example.test".to_string(),
                client: Client::builder().build()?,
            },
            keyset_cache: RwLock::new(cache),
            issuer: ISSUER.to_string(),
            audience: AUDIENCE.to_string(),
            action: ADMISSION_ACTION.to_string(),
            last_refresh_unix: AtomicU64::new(now_unix_seconds_u64()),
        };
        let refreshed = verifier.refresh_on_unknown_kid().await?;
        assert!(!refreshed);
        Ok(())
    }
}
