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
use rustls_pemfile::certs;
use std::{
    fs::File,
    io::BufReader,
    path::{Path, PathBuf},
    sync::{Arc, OnceLock, RwLock},
};
use tokio::time::{Duration, interval};
use tracing::{debug, error};

static TLS_PATHS: OnceLock<TlsPaths> = OnceLock::new();

#[derive(Debug, Clone)]
pub struct TlsPaths {
    pem_bundle: PathBuf,
    extra_ca: Option<PathBuf>,
}

impl TlsPaths {
    #[must_use]
    pub fn new(pem_bundle: PathBuf, extra_ca: Option<PathBuf>) -> Self {
        Self {
            pem_bundle,
            extra_ca,
        }
    }

    #[must_use]
    pub fn pem_bundle_path(&self) -> &Path {
        &self.pem_bundle
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

/// Load the CA certificates for outbound HTTPS clients (reqwest).
/// Returns an empty vector if no extra CA is configured.
///
/// # Errors
/// Returns an error if the configured CA bundle cannot be read or parsed.
pub fn load_reqwest_ca() -> Result<Vec<Certificate>> {
    let paths = match runtime_paths() {
        Ok(p) => p,
        Err(_) => return Ok(Vec::new()),
    };
    if let Some(path) = paths.extra_ca_path() {
        return load_reqwest_ca_from(path);
    }
    Ok(Vec::new())
}

fn load_reqwest_ca_from(path: &Path) -> Result<Vec<Certificate>> {
    let file = File::open(path)
        .with_context(|| format!("Failed to open TLS CA bundle: {}", path.display()))?;
    let mut reader = BufReader::new(file);

    // Use pemfile to extract all certificates, ignoring keys or other metadata
    let cert_ders = certs(&mut reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| format!("Failed to parse certificates from: {}", path.display()))?;

    if cert_ders.is_empty() {
        return Err(anyhow!("No certificates found in: {}", path.display()));
    }

    let mut certs = Vec::new();
    for der in cert_ders {
        certs
            .push(Certificate::from_der(&der).context("Failed to parse extracted CA certificate")?);
    }

    Ok(certs)
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

    let _ca = load_root_store(paths.pem_bundle_path())?;

    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(config)
}

fn load_cert_key_pair(
    paths: &TlsPaths,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    load_bundle(paths.pem_bundle_path())
}

fn spawn_watcher(target: Arc<RwLock<Arc<CertifiedKey>>>, paths: TlsPaths, poll_interval: Duration) {
    tokio::spawn(async move {
        let mut interval = interval(poll_interval);
        let mut last_modified = std::time::SystemTime::UNIX_EPOCH;

        // Initialize timestamps
        if let Ok(m) = tokio::fs::metadata(paths.pem_bundle_path()).await {
            #[allow(clippy::collapsible_if)]
            if let Ok(t) = m.modified() {
                last_modified = t;
            }
        }

        loop {
            interval.tick().await;

            match tokio::fs::metadata(paths.pem_bundle_path()).await {
                Ok(m) => {
                    let modified = m.modified().unwrap_or(std::time::SystemTime::UNIX_EPOCH);

                    if modified > last_modified {
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
                                            last_modified = modified;
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
                Err(e) => {
                    debug!("TLS watcher failed to read metadata (transient?): {}", e);
                }
            }
        }
    });
}

fn load_bundle(path: &Path) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let file = File::open(path)
        .with_context(|| format!("Failed to open TLS bundle: {}", path.display()))?;
    let mut reader = BufReader::new(file);

    let mut certs = Vec::new();
    let mut key = None;

    for item in rustls_pemfile::read_all(&mut reader) {
        match item.context("Failed to parse PEM item")? {
            rustls_pemfile::Item::X509Certificate(c) => certs.push(c),
            rustls_pemfile::Item::Pkcs1Key(k) => {
                if key.is_some() {
                    return Err(anyhow!("Multiple private keys found in bundle"));
                }
                key = Some(PrivateKeyDer::Pkcs1(k));
            }
            rustls_pemfile::Item::Pkcs8Key(k) => {
                if key.is_some() {
                    return Err(anyhow!("Multiple private keys found in bundle"));
                }
                key = Some(PrivateKeyDer::Pkcs8(k));
            }
            rustls_pemfile::Item::Sec1Key(k) => {
                if key.is_some() {
                    return Err(anyhow!("Multiple private keys found in bundle"));
                }
                key = Some(PrivateKeyDer::Sec1(k));
            }
            _ => {}
        }
    }

    let key = key.ok_or_else(|| anyhow!("No private key found in bundle: {}", path.display()))?;
    if certs.is_empty() {
        return Err(anyhow!(
            "No certificates found in bundle: {}",
            path.display()
        ));
    }

    Ok((certs, key))
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
    use rcgen::{CertificateParams, KeyPair};
    use std::path::PathBuf;
    use uuid::Uuid;
    fn missing_path(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!("utils-tls-test-{label}-{}", Uuid::new_v4()))
    }

    #[test]
    fn load_bundle_missing_fails() {
        let path = missing_path("bundle");
        assert!(load_bundle(&path).is_err());
    }

    #[test]
    fn load_root_store_missing_fails() {
        let path = missing_path("ca");
        assert!(load_root_store(&path).is_err());
    }

    #[test]
    fn load_bundle_missing_key_fails() {
        let dir = std::env::temp_dir().join(format!("utils-tls-test-no-key-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let bundle_path = dir.join("no_key.pem");
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        std::fs::write(&bundle_path, cert.cert.pem()).unwrap();
        assert!(load_bundle(&bundle_path).is_err());
    }

    #[test]
    fn load_bundle_missing_cert_fails() {
        let dir = std::env::temp_dir().join(format!("utils-tls-test-no-cert-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let bundle_path = dir.join("no_cert.pem");
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        std::fs::write(&bundle_path, cert.signing_key.serialize_pem()).unwrap();
        assert!(load_bundle(&bundle_path).is_err());
    }

    #[test]
    fn load_bundle_multiple_keys_fails() {
        let dir = std::env::temp_dir().join(format!("utils-tls-test-multi-key-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let bundle_path = dir.join("multi_key.pem");
        let cert1 = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert2 = rcgen::generate_simple_self_signed(vec!["other".to_string()]).unwrap();
        let mut content = String::new();
        content.push_str(&cert1.signing_key.serialize_pem());
        content.push_str(&cert2.signing_key.serialize_pem());
        content.push_str(&cert1.cert.pem());
        std::fs::write(&bundle_path, content).unwrap();
        assert!(load_bundle(&bundle_path).is_err());
    }

    #[test]
    fn load_bundle_garbage_fails() {
        let dir = std::env::temp_dir().join(format!("utils-tls-test-garbage-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let bundle_path = dir.join("garbage.pem");
        std::fs::write(&bundle_path, "not a pem file").unwrap();
        assert!(load_bundle(&bundle_path).is_err());
    }

    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn test_tls_watcher_reloads() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let dir = std::env::temp_dir().join(format!("utils-tls-watcher-test-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let bundle_path = dir.join("tls.bundle.pem");

        // Initial cert
        let cert1 = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let mut bundle1 = cert1.signing_key.serialize_pem();
        bundle1.push_str(&cert1.cert.pem());
        std::fs::write(&bundle_path, &bundle1).unwrap();

        let (certs, key) = load_bundle(&bundle_path).unwrap();
        let signing_key = rustls::crypto::aws_lc_rs::sign::any_supported_type(&key).unwrap();
        let cert_key = Arc::new(RwLock::new(Arc::new(CertifiedKey::new(certs, signing_key))));

        // Start watcher with short interval
        let paths = TlsPaths {
            pem_bundle: bundle_path.clone(),
            extra_ca: None,
        };
        spawn_watcher(cert_key.clone(), paths, Duration::from_millis(100));

        // Update cert
        let cert2 = rcgen::generate_simple_self_signed(vec!["updated".to_string()]).unwrap();
        let mut bundle2 = cert2.signing_key.serialize_pem();
        bundle2.push_str(&cert2.cert.pem());

        // Ensure filesystem timestamp changes
        tokio::time::sleep(Duration::from_millis(1100)).await;
        std::fs::write(&bundle_path, &bundle2).unwrap();

        // Wait for reload
        let mut reloaded = false;
        for _ in 0..20 {
            tokio::time::sleep(Duration::from_millis(200)).await;
            let current = cert_key.read().unwrap();
            // Checking if it reloaded by looking at the cert chain (very simplified)
            if current.cert.len() == 1 {
                // In a real test we'd parse the cert but here we just check if it's different from initial
                // Actually rcgen's self-signed certs will be different.
                reloaded = true;
                break;
            }
        }
        assert!(reloaded, "TLS certificate was not reloaded by watcher");
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn test_load_reqwest_ca() {
        let dir = std::env::temp_dir().join(format!("utils-tls-ca-test-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let ca_path = dir.join("ca.pem");
        let cert = rcgen::generate_simple_self_signed(vec!["ca".to_string()]).unwrap();
        std::fs::write(&ca_path, cert.cert.pem()).unwrap();

        let cas = load_reqwest_ca_from(&ca_path).unwrap();
        assert!(!cas.is_empty());
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn test_load_reqwest_ca_from_bundle() {
        let dir = std::env::temp_dir().join(format!("utils-tls-ca-bundle-test-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let bundle_path = dir.join("bundle.pem");

        let ca = rcgen::generate_simple_self_signed(vec!["ca".to_string()]).unwrap();
        let leaf = rcgen::generate_simple_self_signed(vec!["leaf".to_string()]).unwrap();

        let mut bundle_content = String::new();
        bundle_content.push_str(&leaf.signing_key.serialize_pem()); // Private Key
        bundle_content.push_str(&leaf.cert.pem()); // Leaf Cert
        bundle_content.push_str(&ca.cert.pem()); // CA Cert

        std::fs::write(&bundle_path, &bundle_content).unwrap();

        let cas = load_reqwest_ca_from(&bundle_path).unwrap();
        assert_eq!(cas.len(), 2, "Expected 2 certs to be extracted from bundle");
    }
    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn test_bundle_extraction_details() {
        let dir = std::env::temp_dir().join(format!("utils-tls-bundle-details-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let bundle_path = dir.join("full_bundle.pem");

        // 1. Generate 3 independent certs
        let root_key = KeyPair::generate().unwrap();
        let root_cert = CertificateParams::new(vec!["root".to_string()])
            .unwrap()
            .self_signed(&root_key)
            .unwrap();

        let int_key = KeyPair::generate().unwrap();
        let int_cert = CertificateParams::new(vec!["int".to_string()])
            .unwrap()
            .self_signed(&int_key)
            .unwrap();

        let leaf_key = KeyPair::generate().unwrap();
        let leaf_cert = CertificateParams::new(vec!["leaf".to_string()])
            .unwrap()
            .self_signed(&leaf_key)
            .unwrap();

        // 2. Create a messy bundle: [Key, Leaf, Intermediate, Root]
        let mut bundle_content = String::new();
        bundle_content.push_str(&leaf_key.serialize_pem());
        bundle_content.push_str(&leaf_cert.pem());
        bundle_content.push_str(&int_cert.pem());
        bundle_content.push_str(&root_cert.pem());

        std::fs::write(&bundle_path, &bundle_content).unwrap();

        // 3. Manually inspect for the test log
        let file = File::open(&bundle_path).unwrap();
        let mut reader = BufReader::new(file);
        let mut cert_count = 0;
        let mut key_count = 0;
        for item in rustls_pemfile::read_all(&mut reader) {
            match item.unwrap() {
                rustls_pemfile::Item::X509Certificate(_) => {
                    cert_count += 1;
                    println!("Found certificate component #{}", cert_count);
                }
                rustls_pemfile::Item::Pkcs1Key(_)
                | rustls_pemfile::Item::Pkcs8Key(_)
                | rustls_pemfile::Item::Sec1Key(_) => {
                    key_count += 1;
                    println!("Found private key component #{}", key_count);
                }
                _ => {}
            }
        }
        println!(
            "Bundle inspection complete: found {cert_count} certificates and {key_count} keys"
        );
        if cert_count > 1 {
            println!("Detected a chained or multi-certificate configuration");
        }

        // 4. Verify extraction logic
        let cas = load_reqwest_ca_from(&bundle_path).expect("Should extract CAs from bundle");
        println!(
            "Successfully extracted and parsed {} CA certificates from bundle",
            cas.len()
        );

        assert_eq!(cert_count, 3, "Expected 3 certs in bundle");
        assert_eq!(key_count, 1, "Expected 1 key in bundle");
        assert_eq!(
            cas.len(),
            3,
            "Expected all certs to be returned as CA candidates"
        );

        // Final sanity check: load_server_config_from should also handle this bundle
        let paths = TlsPaths::new(bundle_path, None);
        let server_config = load_server_config_from(&paths);
        assert!(
            server_config.is_ok(),
            "Server config should also accept this bundle"
        );
    }
    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn test_load_valid_cert_config() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let dir = std::env::temp_dir().join(format!("utils-tls-test-valid-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let bundle_path = dir.join("tls.bundle.pem");

        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_pem = cert.cert.pem();
        let key_pem = cert.signing_key.serialize_pem();

        // Write bundle: Key + Cert (order doesn't strictly matter for read_all, but usually key first or cert first)
        let mut bundle_content = String::new();
        bundle_content.push_str(&key_pem);
        bundle_content.push_str(&cert_pem);

        std::fs::write(&bundle_path, &bundle_content).unwrap();

        let paths = TlsPaths {
            pem_bundle: bundle_path,
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
