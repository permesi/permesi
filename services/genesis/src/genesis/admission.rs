// Admission token signing/PASERK: Genesis mints short-lived "admission" PASETOs for Permesi.
// This module owns signing via Vault Transit (no private key in-process) and PASERK caching.
use admission_token::{
    AdmissionTokenClaims, AdmissionTokenFooter, PaserkKey, PaserkKeySet, build_token,
    encode_signing_input, rfc3339_from_unix,
};
use anyhow::{Context, Result, anyhow};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use secrecy::SecretString;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{info, warn};

use crate::cli::globals::GlobalArgs;
use crate::vault;

const PASERK_CACHE_TTL_SECONDS: u64 = 300;
const TRANSIT_KEY_NAME: &str = "genesis-signing";
const TRANSIT_MOUNT_DEFAULT: &str = "transit/genesis";
const ADMISSION_ACTION: &str = "admission";

pub const MIN_TOKEN_TTL_SECONDS: i64 = 60;
pub const MAX_TOKEN_TTL_SECONDS: i64 = 180;

/// `AdmissionSigner` encapsulates Vault-backed signing and PASERK refresh for admission tokens.
/// It keeps the vault details + PASERK cache together so handlers stay simple and stateless.
#[derive(Debug, Clone)]
pub struct AdmissionSigner {
    issuer: String,
    audience: String,
    action: String,
    key_name: String,
    transit_mount: String,
    vault_url: String,
    vault_token: SecretString,
    client: reqwest::Client,
    cache: Arc<RwLock<Option<CachedKeySet>>>,
}

#[derive(Debug, Clone)]
struct CachedKeySet {
    keyset: PaserkKeySet,
    fetched_at: Instant,
    latest_version: u32,
    previous_version: Option<u32>,
}

impl CachedKeySet {
    fn is_fresh(&self) -> bool {
        self.fetched_at.elapsed() < Duration::from_secs(PASERK_CACHE_TTL_SECONDS)
    }
}

#[derive(Debug, Clone)]
pub struct PaserkSnapshot {
    pub keyset: PaserkKeySet,
    pub latest_version: u32,
    pub previous_version: Option<u32>,
}

impl AdmissionSigner {
    /// Initialize the admission signer using Vault transit and environment defaults.
    ///
    /// # Errors
    /// Returns an error if the Vault client cannot be built or PASERK refresh fails.
    pub async fn new(globals: &GlobalArgs) -> Result<Self> {
        let issuer = std::env::var("GENESIS_ADMISSION_ISS")
            .unwrap_or_else(|_| "https://genesis.permesi.dev".to_string());
        let audience =
            std::env::var("GENESIS_ADMISSION_AUD").unwrap_or_else(|_| "permesi".to_string());

        let transit_mount = std::env::var("GENESIS_TRANSIT_MOUNT")
            .unwrap_or_else(|_| TRANSIT_MOUNT_DEFAULT.to_string());

        let client = reqwest::Client::builder()
            .user_agent(vault::APP_USER_AGENT)
            .build()?;

        let signer = Self {
            issuer,
            audience,
            action: ADMISSION_ACTION.to_string(),
            key_name: TRANSIT_KEY_NAME.to_string(),
            transit_mount,
            vault_url: globals.vault_url.clone(),
            vault_token: globals.vault_token.clone(),
            client,
            cache: Arc::new(RwLock::new(None)),
        };

        signer.refresh_paserk().await?;

        Ok(signer)
    }

    /// Build admission claims with the configured issuer/audience/action.
    ///
    /// # Errors
    /// Returns an error if the signer configuration is invalid.
    pub fn make_claims(
        &self,
        now_unix_seconds: i64,
        exp_unix_seconds: i64,
        jti: String,
        sub: Option<String>,
    ) -> Result<AdmissionTokenClaims> {
        if self.issuer.is_empty() || self.audience.is_empty() || self.action.is_empty() {
            return Err(anyhow!("admission config missing issuer/audience/action"));
        }

        let ttl = exp_unix_seconds - now_unix_seconds;

        if !(MIN_TOKEN_TTL_SECONDS..=MAX_TOKEN_TTL_SECONDS).contains(&ttl) {
            return Err(anyhow!("admission token ttl out of range: {ttl}"));
        }

        let iat = rfc3339_from_unix(now_unix_seconds).context("failed to format admission iat")?;
        let exp = rfc3339_from_unix(exp_unix_seconds).context("failed to format admission exp")?;

        Ok(AdmissionTokenClaims {
            iss: self.issuer.clone(),
            aud: self.audience.clone(),
            iat,
            exp,
            jti,
            action: self.action.clone(),
            sub,
        })
    }

    /// Sign the provided claims using Vault transit.
    /// The `kid` is the PASERK public-key ID for the active key version.
    ///
    /// # Errors
    /// Returns an error if the PASERK cache cannot be refreshed or Vault signing fails.
    pub async fn sign(&self, claims: &AdmissionTokenClaims) -> Result<String> {
        let snapshot = self.paserk_snapshot().await?;
        let key_version = snapshot.latest_version;
        let footer = AdmissionTokenFooter {
            kid: snapshot.keyset.active_kid.clone(),
        };
        let signing_input = encode_signing_input(claims, &footer)?;

        let start = Instant::now();
        let signature = vault::transit::sign_ed25519(
            &self.client,
            &self.vault_url,
            &self.vault_token,
            &self.transit_mount,
            &self.key_name,
            key_version,
            signing_input.pre_auth.as_slice(),
        )
        .await
        .context("Vault transit sign failed")?;

        let latency_ms = start.elapsed().as_millis();
        info!(
            key_version = signature.key_version,
            latency_ms, "vault transit sign completed"
        );

        if signature.key_version != key_version {
            return Err(anyhow!(
                "vault returned key version {} but expected {key_version}",
                signature.key_version
            ));
        }

        let signature_bytes = BASE64_STANDARD
            .decode(signature.signature_base64.as_bytes())
            .context("failed to decode vault signature")?;
        let signature_bytes: [u8; 64] = signature_bytes
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("invalid vault signature length"))?;
        Ok(build_token(
            signing_input.payload.as_slice(),
            signing_input.footer.as_slice(),
            &signature_bytes,
        ))
    }

    /// Return the cached PASERK keyset (refreshing if stale) for offline verification.
    /// We publish the current and previous Vault key versions to support safe rotations.
    ///
    /// # Errors
    /// Returns an error if Vault keyset refresh fails and no cached keys exist.
    pub async fn paserk_snapshot(&self) -> Result<PaserkSnapshot> {
        let cached = { self.cache.read().await.clone() };
        if let Some(cache) = cached.clone()
            && cache.is_fresh()
        {
            return Ok(PaserkSnapshot {
                keyset: cache.keyset,
                latest_version: cache.latest_version,
                previous_version: cache.previous_version,
            });
        }

        match self.refresh_paserk().await {
            Ok(snapshot) => Ok(snapshot),
            Err(err) => {
                if let Some(cache) = cached {
                    warn!(
                        error = %err,
                        latest_version = cache.latest_version,
                        "using stale paserk cache"
                    );
                    Ok(PaserkSnapshot {
                        keyset: cache.keyset,
                        latest_version: cache.latest_version,
                        previous_version: cache.previous_version,
                    })
                } else {
                    Err(err)
                }
            }
        }
    }

    /// Refresh PASERK keyset from Vault transit and update the in-memory cache.
    async fn refresh_paserk(&self) -> Result<PaserkSnapshot> {
        let transit = vault::transit::fetch_ed25519_keys(
            &self.client,
            &self.vault_url,
            &self.vault_token,
            &self.transit_mount,
            &self.key_name,
        )
        .await
        .context("failed to fetch transit keys")?;

        let snapshot = build_paserk_snapshot(&transit)?;

        info!(
            latest_version = snapshot.latest_version,
            previous_version = snapshot.previous_version.unwrap_or(0),
            "paserk cache refreshed"
        );

        let mut state = self.cache.write().await;
        *state = Some(CachedKeySet {
            keyset: snapshot.keyset.clone(),
            fetched_at: Instant::now(),
            latest_version: snapshot.latest_version,
            previous_version: snapshot.previous_version,
        });

        Ok(snapshot)
    }
}

fn build_paserk_snapshot(transit: &vault::transit::TransitKeySet) -> Result<PaserkSnapshot> {
    let latest = transit.latest_version;
    let previous = latest.checked_sub(1).filter(|v| *v >= 1);

    let mut keys = Vec::new();
    let mut active_kid = None;
    for version in [Some(latest), previous] {
        let Some(version) = version else {
            continue;
        };
        let Some(public_key) = transit.keys.get(&version) else {
            warn!(version, "missing public key for transit key version");
            continue;
        };
        let key = PaserkKey::from_ed25519_public_key_base64(public_key)
            .context("failed to parse transit public key")?;
        if version == latest {
            active_kid = Some(key.kid.clone());
        }
        keys.push(key);
    }

    if keys.is_empty() {
        return Err(anyhow!("no public keys available from vault transit"));
    }

    let active_kid = active_kid.ok_or_else(|| anyhow!("missing active key id"))?;

    let keyset = PaserkKeySet {
        version: "v4".to_string(),
        purpose: "public".to_string(),
        active_kid,
        keys,
    };

    keyset
        .validate()
        .context("invalid paserk keyset from transit")?;

    Ok(PaserkSnapshot {
        keyset,
        latest_version: latest,
        previous_version: previous,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
    use std::collections::BTreeMap;

    fn test_signer() -> Result<AdmissionSigner> {
        let client = reqwest::Client::builder().build()?;
        Ok(AdmissionSigner {
            issuer: "https://issuer.test".to_string(),
            audience: "permesi".to_string(),
            action: ADMISSION_ACTION.to_string(),
            key_name: TRANSIT_KEY_NAME.to_string(),
            transit_mount: TRANSIT_MOUNT_DEFAULT.to_string(),
            vault_url: "http://vault.test".to_string(),
            vault_token: SecretString::from("token".to_string()),
            client,
            cache: Arc::new(RwLock::new(None)),
        })
    }

    #[test]
    fn make_claims_rejects_out_of_range_ttl() -> Result<()> {
        let signer = test_signer()?;
        let now = 1_000;
        let too_short = signer.make_claims(
            now,
            now + MIN_TOKEN_TTL_SECONDS - 1,
            "jti".to_string(),
            None,
        );
        assert!(too_short.is_err());

        let too_long = signer.make_claims(
            now,
            now + MAX_TOKEN_TTL_SECONDS + 1,
            "jti".to_string(),
            None,
        );
        assert!(too_long.is_err());
        Ok(())
    }

    #[test]
    fn build_paserk_snapshot_includes_latest_and_previous() -> Result<()> {
        let public_key_latest = BASE64_STANDARD.encode([42u8; 32]);
        let public_key_previous = BASE64_STANDARD.encode([43u8; 32]);
        let mut keys = BTreeMap::new();
        keys.insert(1, public_key_previous);
        keys.insert(2, public_key_latest);

        let transit = vault::transit::TransitKeySet {
            latest_version: 2,
            keys,
        };

        let snapshot = build_paserk_snapshot(&transit)?;
        assert_eq!(snapshot.latest_version, 2);
        assert_eq!(snapshot.previous_version, Some(1));
        assert_eq!(snapshot.keyset.keys.len(), 2);
        snapshot.keyset.validate()?;
        let active_matches = snapshot
            .keyset
            .keys
            .iter()
            .any(|key| key.kid == snapshot.keyset.active_kid);
        assert!(active_matches);
        Ok(())
    }

    #[test]
    fn build_paserk_snapshot_sets_active_kid_to_latest() -> Result<()> {
        let public_key_latest = BASE64_STANDARD.encode([11u8; 32]);
        let public_key_previous = BASE64_STANDARD.encode([12u8; 32]);
        let mut keys = BTreeMap::new();
        keys.insert(1, public_key_previous);
        keys.insert(2, public_key_latest.clone());

        let transit = vault::transit::TransitKeySet {
            latest_version: 2,
            keys,
        };

        let snapshot = build_paserk_snapshot(&transit)?;
        let latest_key = PaserkKey::from_ed25519_public_key_base64(&public_key_latest)?;
        assert_eq!(snapshot.keyset.active_kid, latest_key.kid);
        Ok(())
    }

    #[test]
    fn build_paserk_snapshot_skips_missing_previous() -> Result<()> {
        let public_key_latest = BASE64_STANDARD.encode([9u8; 32]);
        let mut keys = BTreeMap::new();
        keys.insert(2, public_key_latest.clone());

        let transit = vault::transit::TransitKeySet {
            latest_version: 2,
            keys,
        };

        let snapshot = build_paserk_snapshot(&transit)?;
        assert_eq!(snapshot.keyset.keys.len(), 1);
        let latest_key = PaserkKey::from_ed25519_public_key_base64(&public_key_latest)?;
        assert_eq!(snapshot.keyset.active_kid, latest_key.kid);
        Ok(())
    }

    #[test]
    fn build_paserk_snapshot_rejects_empty_keys() {
        let transit = vault::transit::TransitKeySet {
            latest_version: 1,
            keys: BTreeMap::new(),
        };

        let result = build_paserk_snapshot(&transit);
        assert!(result.is_err());
    }
}
