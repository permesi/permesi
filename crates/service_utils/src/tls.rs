//! TLS configuration shared utilities.
//!
//! Loads Vault-issued certificates from disk and builds a rustls server config that
//! always enforces HTTPS. The CA bundle is also loaded at startup to fail closed if
//! runtime trust material is missing.

use anyhow::{Context, Result, anyhow};
use reqwest::Certificate;
use rustls::{
    RootCertStore, ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer},
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};
use rustls_pemfile::{certs, ec_private_keys, pkcs8_private_keys};
use std::{
    fs::{self, File},
    io::BufReader,
    path::{Path, PathBuf},
    sync::{Arc, OnceLock, RwLock},
};
use tokio::time::{Duration, interval};
use tracing::{debug, error};

static TLS_PATHS: OnceLock<TlsPaths> = OnceLock::new();

#[derive(Debug, Clone)]
pub struct TlsPaths {
    cert: PathBuf,
    key: PathBuf,
    ca: PathBuf,
    extra_ca: Option<PathBuf>,
}

impl TlsPaths {
    #[must_use]
    pub fn new(cert: PathBuf, key: PathBuf, ca: PathBuf, extra_ca: Option<PathBuf>) -> Self {
        Self {
            cert,
            key,
            ca,
            extra_ca,
        }
    }

    #[must_use]
    pub fn cert_path(&self) -> &Path {
        &self.cert
    }

    #[must_use]
    pub fn key_path(&self) -> &Path {
        &self.key
    }

    #[must_use]
    pub fn ca_path(&self) -> &Path {
        &self.ca
    }

    #[must_use]
    pub fn extra_ca_path(&self) -> Option<&Path> {
        self.extra_ca.as_deref()
    }
}

/// Set the global TLS paths configuration.
///
/// This should be called once at application startup before any TLS operations
/// are attempted.
pub fn set_runtime_paths(paths: TlsPaths) {
    let _ = TLS_PATHS.set(paths);
}

/// Access configured TLS paths.
///
/// # Errors
/// Returns an error if TLS paths have not been configured.
pub fn runtime_paths() -> Result<&'static TlsPaths> {
    TLS_PATHS
        .get()
        .ok_or_else(|| anyhow!("TLS paths were not configured"))
}

#[derive(Debug)]
struct DynamicCertResolver {
    cert_key: Arc<RwLock<Arc<CertifiedKey>>>,
}

impl ResolvesServerCert for DynamicCertResolver {
    fn resolve(&self, _client_hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        self.cert_key.read().ok().map(|k| k.clone())
    }
}

/// Load the TLS server configuration.
///
/// # Errors
/// Returns an error if certificate, key, or CA bundle cannot be read or parsed.
pub fn load_server_config() -> Result<ServerConfig> {
    let paths = runtime_paths()?;
    load_server_config_from(paths)
}

/// Load the CA certificate for outbound HTTPS clients (reqwest).
/// Returns `None` if no extra CA is configured (implying system roots should be used).
///
/// # Errors
/// Returns an error if the configured CA bundle cannot be read or parsed.
pub fn load_reqwest_ca() -> Result<Option<Certificate>> {
    let paths = runtime_paths()?;
    if let Some(path) = paths.extra_ca_path() {
        return Ok(Some(load_reqwest_ca_from(path)?));
    }
    Ok(None)
}

fn load_reqwest_ca_from(path: &Path) -> Result<Certificate> {
    let pem = fs::read(path)
        .with_context(|| format!("Failed to read TLS CA bundle: {}", path.display()))?;
    Certificate::from_pem(&pem).context("Failed to parse TLS CA bundle for outbound HTTPS")
}

fn load_server_config_from(paths: &TlsPaths) -> Result<ServerConfig> {
    let (cert_chain, key) = load_cert_key_pair(paths)?;

    let signing_key = rustls::crypto::aws_lc_rs::sign::any_supported_type(&key)
        .map_err(|_| anyhow!("Failed to parse private key"))?;

    let initial_cert_key = Arc::new(CertifiedKey::new(cert_chain, signing_key));
    let shared_cert_key = Arc::new(RwLock::new(initial_cert_key));

    let resolver = Arc::new(DynamicCertResolver {
        cert_key: shared_cert_key.clone(),
    });

    spawn_watcher(shared_cert_key, paths.clone(), Duration::from_secs(10));

    let _ca = load_root_store(paths.ca_path())?;

    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(config)
}

fn load_cert_key_pair(
    paths: &TlsPaths,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let certs = load_cert_chain(paths.cert_path())?;
    let key = load_private_key(paths.key_path())?;
    Ok((certs, key))
}

fn spawn_watcher(target: Arc<RwLock<Arc<CertifiedKey>>>, paths: TlsPaths, poll_interval: Duration) {
    tokio::spawn(async move {
        let mut interval = interval(poll_interval);
        let mut last_modified_cert = std::time::SystemTime::UNIX_EPOCH;
        let mut last_modified_key = std::time::SystemTime::UNIX_EPOCH;

        // Initialize timestamps
        if let Ok(m) = tokio::fs::metadata(paths.cert_path()).await {
            #[allow(clippy::collapsible_if)]
            if let Ok(t) = m.modified() {
                last_modified_cert = t;
            }
        }
        if let Ok(m) = tokio::fs::metadata(paths.key_path()).await {
            #[allow(clippy::collapsible_if)]
            if let Ok(t) = m.modified() {
                last_modified_key = t;
            }
        }

        loop {
            interval.tick().await;

            let cert_meta = tokio::fs::metadata(paths.cert_path()).await;
            let key_meta = tokio::fs::metadata(paths.key_path()).await;

            match (cert_meta, key_meta) {
                (Ok(cm), Ok(km)) => {
                    let cm_mod = cm.modified().unwrap_or(std::time::SystemTime::UNIX_EPOCH);
                    let km_mod = km.modified().unwrap_or(std::time::SystemTime::UNIX_EPOCH);

                    if cm_mod > last_modified_cert || km_mod > last_modified_key {
                        let paths_clone = paths.clone();
                        // Offload blocking file I/O to a dedicated thread
                        match tokio::task::spawn_blocking(move || load_cert_key_pair(&paths_clone))
                            .await
                        {
                            Ok(Ok((certs, key))) => {
                                match rustls::crypto::aws_lc_rs::sign::any_supported_type(&key) {
                                    Ok(signing_key) => {
                                        let new_key =
                                            Arc::new(CertifiedKey::new(certs, signing_key));
                                        if let Ok(mut w) = target.write() {
                                            *w = new_key;
                                            debug!("TLS certificate reloaded");
                                            last_modified_cert = cm_mod;
                                            last_modified_key = km_mod;
                                        }
                                    }
                                    Err(e) => {
                                        error!("Failed to parse reloaded private key: {:?}", e);
                                    }
                                }
                            }
                            Ok(Err(e)) => {
                                debug!("TLS reload check failed (expected during rotation): {}", e);
                            }
                            Err(e) => {
                                error!("TLS watcher spawn_blocking failed: {}", e);
                            }
                        }
                    }
                }
                (Err(e), _) | (_, Err(e)) => {
                    debug!("TLS watcher failed to read metadata (transient?): {}", e);
                }
            }
        }
    });
}

fn load_cert_chain(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let file = File::open(path)
        .with_context(|| format!("Failed to open TLS certificate: {}", path.display()))?;
    let mut reader = BufReader::new(file);
    let certs = certs(&mut reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| format!("Failed to read TLS certificate: {}", path.display()))?;
    if certs.is_empty() {
        return Err(anyhow!("TLS certificate is empty: {}", path.display()));
    }
    Ok(certs)
}

fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    let file =
        File::open(path).with_context(|| format!("Failed to open TLS key: {}", path.display()))?;
    let mut reader = BufReader::new(file);
    let mut keys = pkcs8_private_keys(&mut reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| format!("Failed to read PKCS#8 TLS key: {}", path.display()))?;
    if let Some(key) = keys.pop() {
        return Ok(PrivateKeyDer::Pkcs8(key));
    }

    let file =
        File::open(path).with_context(|| format!("Failed to open TLS key: {}", path.display()))?;
    let mut reader = BufReader::new(file);
    let mut keys = ec_private_keys(&mut reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| format!("Failed to read SEC1 TLS key: {}", path.display()))?;
    if let Some(key) = keys.pop() {
        return Ok(PrivateKeyDer::Sec1(key));
    }

    Err(anyhow!("TLS private key not found: {}", path.display()))
}

fn load_root_store(path: &Path) -> Result<RootCertStore> {
    let file = File::open(path)
        .with_context(|| format!("Failed to open TLS CA bundle: {}", path.display()))?;
    let mut reader = BufReader::new(file);
    let certs = certs(&mut reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| format!("Failed to read TLS CA bundle: {}", path.display()))?;
    if certs.is_empty() {
        return Err(anyhow!("TLS CA bundle is empty: {}", path.display()));
    }
    let mut store = RootCertStore::empty();
    let (added, _) = store.add_parsable_certificates(certs);
    if added == 0 {
        return Err(anyhow!(
            "No valid CA certificates found in {}",
            path.display()
        ));
    }
    Ok(store)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use uuid::Uuid;

    fn missing_path(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!("utils-tls-test-{label}-{}", Uuid::new_v4()))
    }

    #[test]
    fn load_private_key_missing_fails() {
        let path = missing_path("key");
        assert!(load_private_key(&path).is_err());
    }

    #[test]
    fn load_root_store_missing_fails() {
        let path = missing_path("ca");
        assert!(load_root_store(&path).is_err());
    }

    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn test_load_valid_cert_config() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let dir = std::env::temp_dir().join(format!("utils-tls-test-valid-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let cert_path = dir.join("tls.crt");
        let key_path = dir.join("tls.key");
        let ca_path = dir.join("ca.pem");

        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_pem = cert.cert.pem();
        let key_pem = cert.signing_key.serialize_pem();

        std::fs::write(&cert_path, &cert_pem).unwrap();
        std::fs::write(&key_path, &key_pem).unwrap();
        std::fs::write(&ca_path, &cert_pem).unwrap(); // Self-signed CA

        let paths = TlsPaths {
            cert: cert_path,
            key: key_path,
            ca: ca_path,
            extra_ca: None,
        };

        let config = load_server_config_from(&paths);
        assert!(
            config.is_ok(),
            "Failed to load valid server config: {:?}",
            config.err()
        );
    }
}
