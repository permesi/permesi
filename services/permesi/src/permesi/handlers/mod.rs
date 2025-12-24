pub mod health;
pub use self::health::health;

pub mod user_register;
pub use self::user_register::register;

pub mod user_login;
pub use self::user_login::login;

// common functions for the handlers
use admission_token::{
    AdmissionTokenClaims, Error as AdmissionError, PaserkKeySet, VerificationOptions,
    verify_v4_public,
};
use anyhow::{Context, Result, anyhow};
use regex::Regex;
use reqwest::Client;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::RwLock;
use tracing::{error, info, instrument, warn};

const KEYSET_CACHE_TTL_SECONDS: u64 = 300;
const KEYSET_REFRESH_COOLDOWN_SECONDS: u64 = 30;
const MIN_TOKEN_TTL_SECONDS: i64 = 60;
const MAX_TOKEN_TTL_SECONDS: i64 = 180;
const ADMISSION_ACTION: &str = "admission";

pub fn valid_email(email: &str) -> bool {
    Regex::new(r"^[^@\s]+@[^@\s]+\.[^@\s]+$").is_ok_and(|re| re.is_match(email))
}

pub fn valid_password(password: &str) -> bool {
    // length must be between 64 hex characters
    Regex::new(r"^[0-9a-fA-F]{64}$").is_ok_and(|re| re.is_match(password))
}

#[derive(Debug)]
enum KeysetSource {
    Static,
    Remote { url: String, client: Client },
}

#[derive(Debug, Clone)]
struct KeysetCache {
    keyset: PaserkKeySet,
    fetched_at: Instant,
}

impl KeysetCache {
    fn is_fresh(&self) -> bool {
        self.fetched_at.elapsed() < Duration::from_secs(KEYSET_CACHE_TTL_SECONDS)
    }
}

#[derive(Debug)]
pub struct AdmissionVerifier {
    keyset_source: KeysetSource,
    keyset_cache: RwLock<KeysetCache>,
    issuer: String,
    audience: String,
    action: String,
    last_refresh_unix: AtomicU64,
}

impl AdmissionVerifier {
    #[must_use]
    pub fn new(keyset: PaserkKeySet, issuer: String, audience: String) -> Self {
        Self {
            keyset_source: KeysetSource::Static,
            keyset_cache: RwLock::new(KeysetCache {
                keyset,
                fetched_at: Instant::now(),
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
        let client = Client::builder()
            .user_agent(crate::permesi::APP_USER_AGENT)
            .build()?;
        let keyset = fetch_keyset(&client, &url).await?;
        keyset
            .validate()
            .context("Invalid admission PASERK keyset")?;
        Ok(Self {
            keyset_source: KeysetSource::Remote { url, client },
            keyset_cache: RwLock::new(KeysetCache {
                keyset,
                fetched_at: Instant::now(),
            }),
            issuer,
            audience,
            action: ADMISSION_ACTION.to_string(),
            last_refresh_unix: AtomicU64::new(now_unix_seconds_u64()),
        })
    }

    async fn keyset_snapshot(&self) -> Result<PaserkKeySet> {
        let (cached, fresh) = {
            let cache = self.keyset_cache.read().await;
            (cache.keyset.clone(), cache.is_fresh())
        };

        if fresh {
            return Ok(cached);
        }

        if let KeysetSource::Remote { .. } = &self.keyset_source
            && let Err(err) = self.refresh_keyset().await
        {
            warn!(error = %err, "failed to refresh paserk keyset cache");
            return Ok(cached);
        }

        let cache = self.keyset_cache.read().await;
        Ok(cache.keyset.clone())
    }

    async fn refresh_keyset(&self) -> Result<()> {
        let (url, client) = match &self.keyset_source {
            KeysetSource::Static => return Ok(()),
            KeysetSource::Remote { url, client } => (url.clone(), client.clone()),
        };

        let keyset = fetch_keyset(&client, &url).await?;
        keyset
            .validate()
            .context("Invalid admission PASERK keyset")?;
        let mut cache = self.keyset_cache.write().await;
        cache.keyset = keyset;
        cache.fetched_at = Instant::now();
        info!(
            keyset_keys = cache.keyset.keys.len(),
            "paserk keyset cache refreshed"
        );
        Ok(())
    }

    async fn refresh_on_unknown_kid(&self) -> Result<bool> {
        if matches!(&self.keyset_source, KeysetSource::Static) {
            return Ok(false);
        }
        let now = now_unix_seconds_u64();
        let last = self.last_refresh_unix.load(Ordering::Relaxed);
        if now.saturating_sub(last) < KEYSET_REFRESH_COOLDOWN_SECONDS {
            return Ok(false);
        }
        self.last_refresh_unix.store(now, Ordering::Relaxed);
        self.refresh_keyset().await?;
        Ok(true)
    }
}

fn now_unix_seconds() -> i64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

fn now_unix_seconds_u64() -> u64 {
    u64::try_from(now_unix_seconds()).unwrap_or(0)
}

async fn fetch_keyset(client: &Client, url: &str) -> Result<PaserkKeySet> {
    let response = client.get(url).send().await?;
    let status = response.status();
    let body = response.text().await?;

    if !status.is_success() {
        return Err(anyhow!("paserk keyset fetch failed: {status}"));
    }

    PaserkKeySet::from_json(&body).context("Invalid admission PASERK JSON")
}

#[instrument]
pub async fn verify_token(verifier: &AdmissionVerifier, token: &str) -> bool {
    verify_token_claims(verifier, token).await.is_some()
}

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
}
