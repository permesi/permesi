//! Admission token signing and PASERK management.
//!
//! Genesis mints short-lived "admission" PASETOs for Permesi. This module
//! handles signing via OpenBao Transit (keeping private keys out of process)
//! and maintains a local cache of PASERK public keys.
//!
//! ## Flow Overview
//! 1. `AdmissionSigner` is initialized with OpenBao Transit details.
//! 2. `sign` fetches the latest signing key version from the local PASERK cache.
//! 3. Claims are signed via OpenBao's Transit API.
//! 4. A v4.public PASETO is constructed with the resulting signature.
//! 5. `paserk_snapshot` provides the keyset for offline verification by Permesi.

use admission_token::{
    AdmissionTokenClaims, AdmissionTokenFooter, PaserkKey, PaserkKeySet, build_token,
    encode_signing_input, rfc3339_from_unix,
};
use anyhow::{Context, Result, anyhow};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64_STANDARD};
use secrecy::SecretString;
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::RwLock;
use tracing::{info, warn};

use crate::{cli::globals::GlobalArgs, openbao};

const PASERK_CACHE_TTL_SECONDS: u64 = 300;
const TRANSIT_KEY_NAME: &str = "genesis-signing";
#[cfg(test)]
const TRANSIT_MOUNT_DEFAULT: &str = "transit/genesis";
const ADMISSION_ACTION: &str = "admission";

pub const MIN_TOKEN_TTL_SECONDS: i64 = 60;
pub const MAX_TOKEN_TTL_SECONDS: i64 = 180;

/// `AdmissionSigner` encapsulates OpenBao-backed signing and PASERK refresh for admission tokens.
/// It keeps the openbao details + PASERK cache together so handlers stay simple and stateless.
#[derive(Debug, Clone)]
pub struct AdmissionSigner {
    signing_version: u32,
    issuer: String,
    audience: String,
    action: String,
    key_name: String,
    transit_mount: String,
    openbao_token: Option<SecretString>,
    openbao_transport: openbao::OpenBaoTransport,
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
    /// Initialize the admission signer using OpenBao transit. The issuer and audience
    /// are the validated CLI settings and go into every token unchanged.
    ///
    /// # Errors
    /// Returns an error if PASERK refresh fails.
    pub async fn new(
        globals: &GlobalArgs,
        signing_version: u32,
        issuer: String,
        audience: String,
    ) -> Result<Self> {
        let transit_mount = globals.openbao_transit_mount.clone();

        let openbao_transport = globals.openbao_transport.clone();
        let openbao_token = if openbao_transport.is_tcp() {
            Some(globals.openbao_token.clone())
        } else {
            None
        };

        let signer = Self {
            signing_version,
            issuer,
            audience,
            action: ADMISSION_ACTION.to_string(),
            key_name: TRANSIT_KEY_NAME.to_string(),
            transit_mount,
            openbao_token,
            openbao_transport,
            cache: Arc::new(RwLock::new(None)),
        };

        signer.refresh_paserk().await?;

        Ok(signer)
    }

    /// Verify signing availability with a fixed non-token message. The probe never
    /// creates a receipt or a usable admission token.
    pub(crate) async fn probe(&self) -> Result<()> {
        let snapshot = self.paserk_snapshot().await?;
        let sig = openbao::transit::sign_ed25519(
            &self.openbao_transport,
            self.openbao_token.as_ref(),
            &self.transit_mount,
            &self.key_name,
            snapshot.latest_version,
            b"genesis readiness v1",
        )
        .await?;
        anyhow::ensure!(
            sig.key_version == snapshot.latest_version
                && BASE64_STANDARD.decode(sig.signature_base64)?.len() == 64,
            "unexpected readiness signature"
        );
        Ok(())
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

    /// Sign the provided claims using OpenBao transit.
    /// The `kid` is the PASERK public-key ID for the active key version.
    ///
    /// # Errors
    /// Returns an error if the PASERK cache cannot be refreshed or OpenBao signing fails.
    pub async fn sign(&self, claims: &AdmissionTokenClaims) -> Result<String> {
        let snapshot = self.paserk_snapshot().await?;
        let key_version = snapshot.latest_version;
        let footer = AdmissionTokenFooter {
            kid: snapshot.keyset.active_kid.clone(),
        };
        let signing_input = encode_signing_input(claims, &footer)?;

        let start = Instant::now();
        let signature = openbao::transit::sign_ed25519(
            &self.openbao_transport,
            self.openbao_token.as_ref(),
            &self.transit_mount,
            &self.key_name,
            key_version,
            signing_input.pre_auth.as_slice(),
        )
        .await
        .context("OpenBao transit sign failed")?;

        let latency_ms = start.elapsed().as_millis();
        info!(
            key_version = signature.key_version,
            latency_ms, "openbao transit sign completed"
        );

        if signature.key_version != key_version {
            return Err(anyhow!(
                "openbao returned key version {} but expected {key_version}",
                signature.key_version
            ));
        }

        let signature_bytes = BASE64_STANDARD
            .decode(signature.signature_base64.as_bytes())
            .context("failed to decode openbao signature")?;
        let signature_bytes: [u8; 64] = signature_bytes
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("invalid transit signature length"))?;
        Ok(build_token(
            signing_input.payload.as_slice(),
            signing_input.footer.as_slice(),
            &signature_bytes,
        ))
    }

    /// Return the cached PASERK keyset (refreshing if stale) for offline verification.
    /// We publish the current and previous OpenBao key versions to support safe rotations.
    ///
    /// # Errors
    /// Returns an error if OpenBao keyset refresh fails and no cached keys exist.
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

    /// Refresh PASERK keyset from OpenBao transit and update the in-memory cache.
    async fn refresh_paserk(&self) -> Result<PaserkSnapshot> {
        let transit = openbao::transit::fetch_ed25519_keys(
            &self.openbao_transport,
            self.openbao_token.as_ref(),
            &self.transit_mount,
            &self.key_name,
        )
        .await
        .context("failed to fetch transit keys")?;

        let snapshot = build_paserk_snapshot(&transit, self.signing_version)?;

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

/// Select the operator-activated version. Staging a newer Transit key cannot
/// switch the signer before all core readers have observed its publication.
fn build_paserk_snapshot(
    transit: &openbao::transit::TransitKeySet,
    latest: u32,
) -> Result<PaserkSnapshot> {
    anyhow::ensure!(
        latest > 0 && latest <= transit.latest_version,
        "invalid active admission signing version"
    );
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
        return Err(anyhow!("no public keys available from openbao transit"));
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
        let target = crate::openbao::OpenBaoTarget::parse("http://openbao.test")?;
        let openbao_transport =
            crate::openbao::OpenBaoTransport::from_target("test-agent", target)?;
        Ok(AdmissionSigner {
            signing_version: 1,
            issuer: "https://issuer.test".to_string(),
            audience: "permesi".to_string(),
            action: ADMISSION_ACTION.to_string(),
            key_name: TRANSIT_KEY_NAME.to_string(),
            transit_mount: TRANSIT_MOUNT_DEFAULT.to_string(),
            openbao_token: Some(SecretString::from("token".to_string())),
            openbao_transport,
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

    #[tokio::test]
    async fn paserk_snapshot_returns_cached_when_fresh() -> Result<()> {
        let public_key_latest = BASE64_STANDARD.encode([42u8; 32]);
        let key = PaserkKey::from_ed25519_public_key_base64(&public_key_latest)?;
        let keyset = PaserkKeySet {
            version: "v4".to_string(),
            purpose: "public".to_string(),
            active_kid: key.kid.clone(),
            keys: vec![key],
        };

        let cached = CachedKeySet {
            keyset: keyset.clone(),
            fetched_at: Instant::now(),
            latest_version: 1,
            previous_version: None,
        };

        let signer = test_signer()?;
        {
            let mut cache = signer.cache.write().await;
            *cache = Some(cached);
        }

        let snapshot = signer.paserk_snapshot().await?;
        assert_eq!(snapshot.latest_version, 1);
        assert_eq!(snapshot.previous_version, None);
        assert_eq!(snapshot.keyset.active_kid, keyset.active_kid);
        Ok(())
    }

    #[test]
    fn build_paserk_snapshot_includes_latest_and_previous() -> Result<()> {
        let public_key_latest = BASE64_STANDARD.encode([42u8; 32]);
        let public_key_previous = BASE64_STANDARD.encode([43u8; 32]);
        let mut keys = BTreeMap::new();
        keys.insert(1, public_key_previous);
        keys.insert(2, public_key_latest);

        let transit = openbao::transit::TransitKeySet {
            latest_version: 2,
            keys,
        };

        let staged = build_paserk_snapshot(&transit, 1)?;
        assert_eq!(staged.latest_version, 1);
        assert_eq!(staged.keyset.keys.len(), 1);
        assert!(build_paserk_snapshot(&transit, 3).is_err());
        let snapshot = build_paserk_snapshot(&transit, transit.latest_version)?;
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

        let transit = openbao::transit::TransitKeySet {
            latest_version: 2,
            keys,
        };

        let snapshot = build_paserk_snapshot(&transit, transit.latest_version)?;
        let latest_key = PaserkKey::from_ed25519_public_key_base64(&public_key_latest)?;
        assert_eq!(snapshot.keyset.active_kid, latest_key.kid);
        Ok(())
    }

    #[test]
    fn build_paserk_snapshot_skips_missing_previous() -> Result<()> {
        let public_key_latest = BASE64_STANDARD.encode([9u8; 32]);
        let mut keys = BTreeMap::new();
        keys.insert(2, public_key_latest.clone());

        let transit = openbao::transit::TransitKeySet {
            latest_version: 2,
            keys,
        };

        let snapshot = build_paserk_snapshot(&transit, transit.latest_version)?;
        assert_eq!(snapshot.keyset.keys.len(), 1);
        let latest_key = PaserkKey::from_ed25519_public_key_base64(&public_key_latest)?;
        assert_eq!(snapshot.keyset.active_kid, latest_key.kid);
        Ok(())
    }

    #[test]
    fn build_paserk_snapshot_rejects_empty_keys() {
        let transit = openbao::transit::TransitKeySet {
            latest_version: 1,
            keys: BTreeMap::new(),
        };

        let result = build_paserk_snapshot(&transit, transit.latest_version);
        assert!(result.is_err());
    }
}
