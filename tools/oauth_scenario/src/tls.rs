//! Private certificate authority trusted only by this run's native clients and browser container.

use crate::{
    error::{Result, Safe},
    files::PrivateDir,
};
use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, KeyUsagePurpose};
use std::{net::TcpListener, path::PathBuf, time::Duration};

/// Paths stay private; only the public CA is mounted into the isolated browser.
pub struct Tls {
    pub ca: PathBuf,
    pub cert: Vec<u8>,
    pub key: Vec<u8>,
}

impl Tls {
    /// Generates fresh keys with OS entropy and a CA-signed localhost leaf; verification stays enabled.
    pub fn new(directory: &PrivateDir) -> Result<Self> {
        // Unit tests do not run main's explicit provider selection; use the same policy.
        #[cfg(test)]
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let mut root =
            CertificateParams::new(Vec::<String>::new()).safe("Cannot configure private CA.")?;
        root.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        root.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::CrlSign,
        ];
        let root_key = KeyPair::generate().safe("Cannot generate CA key.")?;
        let root_cert = root
            .self_signed(&root_key)
            .safe("Cannot generate private CA.")?;
        let issuer = Issuer::from_params(&root, &root_key);
        let leaf = CertificateParams::new(vec!["localhost".into(), "127.0.0.1".into()])
            .safe("Cannot configure test certificate.")?;
        let leaf_key = KeyPair::generate().safe("Cannot generate TLS key.")?;
        let leaf_cert = leaf
            .signed_by(&leaf_key, &issuer)
            .safe("Cannot sign test certificate.")?;
        let ca = directory.write("ca.pem", root_cert.pem().as_bytes())?;
        let cert = format!("{}{}", leaf_cert.pem(), root_cert.pem()).into_bytes();
        let key = leaf_key.serialize_pem().into_bytes();
        Ok(Self { ca, cert, key })
    }

    /// Disables proxy inheritance and trusts only the run CA, keeping redirects under scenario control.
    pub fn client(&self, seconds: u64) -> Result<reqwest::Client> {
        let ca =
            reqwest::Certificate::from_pem(&std::fs::read(&self.ca).safe("Cannot read test CA.")?)
                .safe("Cannot parse test CA.")?;
        reqwest::Client::builder()
            .tls_certs_only([ca])
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(seconds))
            .build()
            .safe("Cannot configure verified HTTPS client.")
    }
}

/// Reserves a loopback listener rather than checking then reopening an ephemeral port.
pub fn listener() -> Result<TcpListener> {
    let listener = TcpListener::bind("127.0.0.1:0").safe("Cannot reserve a loopback listener.")?;
    listener
        .set_nonblocking(true)
        .safe("Cannot configure loopback listener.")?;
    Ok(listener)
}
