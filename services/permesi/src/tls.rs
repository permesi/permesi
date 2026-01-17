//! TLS configuration for Permesi.
//!
//! Loads Vault-issued certificates from disk and builds a rustls server config that
//! always enforces HTTPS. The CA bundle is also loaded at startup to fail closed if
//! runtime trust material is missing.
//!
//! ## Flow Overview
//! 1) Read PEM-encoded cert chain, private key, and CA bundle from configured paths.
//! 2) Build a rustls server config with no client auth.
//! 3) Expose helpers for outbound HTTPS clients that must trust the same CA.
//!
//! Security boundary: the service refuses to start without valid TLS assets.

use anyhow::{Context, Result, anyhow};
use reqwest::Certificate;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{RootCertStore, ServerConfig};
use rustls_pemfile::{certs, ec_private_keys, pkcs8_private_keys};
use std::fs;
use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

static TLS_PATHS: OnceLock<TlsPaths> = OnceLock::new();

#[derive(Debug, Clone)]
pub struct TlsPaths {
    cert: PathBuf,
    key: PathBuf,
    ca: PathBuf,
    paserk_ca: PathBuf,
}

impl TlsPaths {
    #[must_use]
    pub fn from_cli(cert: String, key: String, ca: String, paserk_ca: Option<String>) -> Self {
        let ca_path = PathBuf::from(ca);
        Self {
            cert: PathBuf::from(cert),
            key: PathBuf::from(key),
            ca: ca_path.clone(),
            paserk_ca: paserk_ca.map(PathBuf::from).unwrap_or(ca_path),
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
    pub fn paserk_ca_path(&self) -> &Path {
        &self.paserk_ca
    }
}

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

/// Load the TLS server configuration for Permesi.
///
/// # Errors
/// Returns an error if certificate, key, or CA bundle cannot be read or parsed.
pub fn load_server_config() -> Result<ServerConfig> {
    let paths = runtime_paths()?;
    load_server_config_from(paths)
}

/// Load the CA certificate for outbound HTTPS clients (reqwest).
///
/// # Errors
/// Returns an error if the CA bundle cannot be read or parsed.
pub fn load_reqwest_ca() -> Result<Certificate> {
    let paths = runtime_paths()?;
    load_reqwest_ca_from(paths.paserk_ca_path())
}

fn load_reqwest_ca_from(path: &Path) -> Result<Certificate> {
    let pem = fs::read(path)
        .with_context(|| format!("Failed to read TLS CA bundle: {}", path.display()))?;
    Certificate::from_pem(&pem).context("Failed to parse TLS CA bundle for outbound HTTPS")
}

fn load_server_config_from(paths: &TlsPaths) -> Result<ServerConfig> {
    let cert_chain = load_cert_chain(paths.cert_path())?;
    let key = load_private_key(paths.key_path())?;
    let _ca = load_root_store(paths.ca_path())?;

    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)
        .context("Failed to build TLS server config")?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(config)
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
        std::env::temp_dir().join(format!("permesi-tls-test-{label}-{}", Uuid::new_v4()))
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
}
