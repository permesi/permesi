//! Owned verified-HTTPS transport controls for resource-cache and client rejection tests.
//!
//! Flow Overview: generate a private CA, reserve an owned loopback listener, serve
//! controlled bodies/statuses and count requests, then close the listener on Drop.
//! Reachable controls distinguish policy rejection from incidental network failure;
//! received bearer/request values are never retained or reported.

use crate::{
    error::{Result, Safe},
    files::PrivateDir,
    interop::Transport,
    tls::{Tls, listener},
};
use axum::{
    Router,
    extract::State,
    http::{StatusCode, header},
    response::IntoResponse as _,
};
use axum_server::{Handle, tls_rustls::RustlsConfig};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use tokio::task::JoinHandle;

/// A unit-test issuer owns its keyless HTTPS listener and temporary CA directory.
pub struct Issuer {
    pub transport: Transport,
    pub requests: Arc<AtomicU64>,
    handle: Handle<std::net::SocketAddr>,
    server: JoinHandle<std::io::Result<()>>,
    _directory: PrivateDir,
}

/// Emits controlled bodies/statuses without recording requests or bearer material.
async fn response(
    State((body, status, count)): State<(String, StatusCode, Arc<AtomicU64>)>,
) -> axum::response::Response {
    count.fetch_add(1, Ordering::SeqCst);
    let mut response = (status, [(header::CONTENT_TYPE, "application/json")], body).into_response();
    if status.is_redirection() {
        response.headers_mut().insert(
            header::LOCATION,
            axum::http::HeaderValue::from_static("https://attacker.invalid"),
        );
    }
    response
}

impl Issuer {
    /// Binds once; tests trust only this generated CA and retain normal TLS verification.
    pub async fn start(body: String, status: StatusCode) -> Result<Self> {
        let directory = PrivateDir::new()?;
        let tls = Tls::new(&directory)?;
        let listener = listener()?;
        let issuer = format!(
            "https://localhost:{}",
            listener.local_addr().safe("Test port unavailable.")?.port()
        );
        let requests = Arc::new(AtomicU64::new(0));
        let router = Router::new()
            .fallback(response)
            .with_state((body, status, requests.clone()));
        let transport = Transport {
            client: tls.client(2)?,
            issuer,
        };
        let config = RustlsConfig::from_pem(tls.cert, tls.key)
            .await
            .safe("Test TLS unavailable.")?;
        let handle = Handle::new();
        let server = tokio::spawn(
            axum_server::from_tcp_rustls(listener, config)
                .safe("Test TLS bind failed.")?
                .handle(handle.clone())
                .serve(router.into_make_service()),
        );
        Ok(Self {
            transport,
            requests,
            handle,
            server,
            _directory: directory,
        })
    }
}

impl Drop for Issuer {
    /// Stops the owned listener even when a test assertion exits before explicit cleanup.
    fn drop(&mut self) {
        self.handle.shutdown();
        self.server.abort();
    }
}
