//! Test-only HTTPS issuer gateway over real, private Unix-socket service listeners.
//!
//! The browser sees one stable issuer while the harness selects A or B. This is
//! equivalent to a load balancer, not a product test hook. OPAQUE, OAuth and
//! management traffic all follow that selection and share PostgreSQL state.
//! Genesis admission has its own fixed backend. No request or callback URL is logged.

use crate::{
    error::{Result, Safe},
    tls::{Tls, listener},
};
use axum::{
    Router,
    body::{Body, to_bytes},
    extract::{Request, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use axum_server::{Handle, tls_rustls::RustlsConfig};
use serde_json::json;
use std::{
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::task::JoinHandle;
use tower::ServiceExt as _;
use tower_http::services::ServeDir;

#[derive(Clone)]
struct Proxy {
    a: reqwest::Client,
    b: reqwest::Client,
    genesis: reqwest::Client,
    use_b: Arc<AtomicBool>,
    config: Arc<String>,
    assets: ServeDir<tower_http::services::ServeFile>,
}

/// Owned gateway and callback listeners, with explicit shutdown after every outcome.
pub struct Gateway {
    token_clients: [reqwest::Client; 2],
    pub origin: String,
    pub callback: String,
    pub use_b: Arc<AtomicBool>,
    handle: Handle<std::net::SocketAddr>,
    server: JoinHandle<std::io::Result<()>>,
    callback_server: JoinHandle<std::io::Result<()>>,
}

impl Gateway {
    /// Binds loopback once, verifies public TLS, and mounts only the selected compiled Web assets.
    pub async fn start(
        tls: &Tls,
        assets: &Path,
        sockets: [&Path; 3],
        seconds: u64,
    ) -> Result<Self> {
        let bound = listener()?;
        let origin = format!(
            "https://localhost:{}",
            bound.local_addr().safe("Cannot read issuer port.")?.port()
        );
        let callback_listener = listener()?;
        let callback = format!(
            "http://127.0.0.1:{}/callback",
            callback_listener
                .local_addr()
                .safe("Cannot read callback port.")?
                .port()
        );
        let use_b = Arc::new(AtomicBool::new(false));
        let client = |socket: &Path| {
            reqwest::Client::builder()
                .unix_socket(socket)
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(seconds))
                .build()
                .safe("Cannot configure private service transport.")
        };
        let [a, b, genesis] = sockets;
        let config = format!(
            "window.PERMESI_CONFIG = {};",
            json!({"api_base_url":origin,"token_base_url":format!("{origin}/admission"),"client_id":UuidString::ZERO,"opaque_server_id":"api.permesi.dev"})
        );
        let token_clients = [client(a)?, client(b)?];
        let proxy = Proxy {
            a: client(a)?,
            b: client(b)?,
            genesis: client(genesis)?,
            use_b: use_b.clone(),
            config: Arc::new(config),
            assets: ServeDir::new(assets).fallback(tower_http::services::ServeFile::new(
                assets.join("index.html"),
            )),
        };
        let app = Router::new().fallback(forward).with_state(proxy);
        let handle = Handle::new();
        let rustls = RustlsConfig::from_pem(tls.cert.clone(), tls.key.clone())
            .await
            .safe("Cannot configure issuer TLS.")?;
        let serve = axum_server::from_tcp_rustls(bound, rustls.clone())
            .safe("Cannot bind issuer TLS server.")?
            .handle(handle.clone())
            .serve(app.into_make_service());
        let server = tokio::spawn(serve);
        let callback_listener = tokio::net::TcpListener::from_std(callback_listener)
            .safe("Cannot configure callback listener.")?;
        let callback_server = tokio::spawn(async move {
            axum::serve(
                callback_listener,
                Router::new().route("/callback", axum::routing::get(callback_response)),
            )
            .await
        });
        Ok(Self {
            token_clients,
            origin,
            callback,
            use_b,
            handle,
            server,
            callback_server,
        })
    }

    /// Restores all Permesi traffic, including password exchanges, to replica A.
    pub fn replica_a(&self) {
        self.use_b.store(false, Ordering::SeqCst);
    }

    /// Switches all Permesi traffic; no browser-controlled input can select a replica.
    pub fn replica_b(&self) {
        self.use_b.store(true, Ordering::SeqCst);
    }

    /// Pins one native token request to an owned private service socket for a real A/B race.
    /// Browser traffic has no replica selector; issuer and delegated state remain shared.
    pub async fn token_replica(
        &self,
        second: bool,
        fields: &[(&str, &str)],
    ) -> Result<reqwest::Response> {
        let client = self
            .token_clients
            .get(usize::from(second))
            .ok_or_else(|| crate::error::Failure::harness("Missing replica client."))?;
        let mut form = url::form_urlencoded::Serializer::new(String::new());
        form.extend_pairs(fields.iter().copied());
        client
            .post("http://localhost/token")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(form.finish())
            .send()
            .await
            .safe("Owned replica token request failed.")
    }

    /// Shuts down both listeners and waits for owned tasks; cancellation cannot leave detached servers.
    pub async fn stop(&mut self) -> Result<()> {
        self.handle.shutdown();
        self.callback_server.abort();
        (&mut self.server)
            .await
            .safe("Issuer task failed.")?
            .safe("Issuer shutdown failed.")?;
        let _ = (&mut self.callback_server).await;
        Ok(())
    }
}

impl Drop for Gateway {
    fn drop(&mut self) {
        self.handle.shutdown();
        self.server.abort();
        self.callback_server.abort();
    }
}

struct UuidString;
impl UuidString {
    const ZERO: &'static str = "00000000-0000-0000-0000-000000000000";
}

/// Keeps callback output constant: codes/state are observed through private browser IPC only.
async fn callback_response() -> Response {
    (
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::REFERRER_POLICY, "no-referrer"),
        ],
        "Authorization complete.",
    )
        .into_response()
}

/// Forwards controlled route prefixes without following Location or emitting access logs.
async fn forward(State(proxy): State<Proxy>, request: Request) -> Response {
    let path = request.uri().path();
    if path == "/client-callback" {
        return callback_response().await;
    }
    if path == "/config.js" {
        return (
            [
                (header::CONTENT_TYPE, "application/javascript"),
                (header::CACHE_CONTROL, "no-store"),
            ],
            proxy.config.as_str().to_owned(),
        )
            .into_response();
    }
    let is_genesis = path.starts_with("/admission/");
    if !is_genesis
        && !path.starts_with("/v1/")
        && !path.starts_with("/authorize")
        && !matches!(
            path,
            "/.well-known/openid-configuration" | "/jwks.json" | "/health" | "/token"
        )
    {
        return proxy.assets.oneshot(request).await.map_or_else(
            |_| StatusCode::INTERNAL_SERVER_ERROR.into_response(),
            IntoResponse::into_response,
        );
    }
    let client = if is_genesis {
        &proxy.genesis
    } else if !proxy.use_b.load(Ordering::SeqCst) {
        &proxy.a
    } else {
        &proxy.b
    };
    let uri = request
        .uri()
        .path_and_query()
        .map_or("/", axum::http::uri::PathAndQuery::as_str);
    let uri = if is_genesis {
        uri.strip_prefix("/admission").unwrap_or("/")
    } else {
        uri
    };
    let destination = format!("http://localhost{uri}");
    let mut outbound = client.request(request.method().clone(), destination);
    // HTTP/2 may split Cookie into several fields. HTTP/1.1 backend adapters
    // must join them; forwarding duplicate fields loses one of the session/binding proofs.
    let cookies = request
        .headers()
        .get_all(header::COOKIE)
        .iter()
        .map(|value| value.to_str())
        .collect::<std::result::Result<Vec<_>, _>>();
    let Ok(cookies) = cookies else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    if !cookies.is_empty() {
        outbound = outbound.header(header::COOKIE, cookies.join("; "));
    }
    for (name, value) in request.headers() {
        if !matches!(
            name.as_str(),
            "host" | "connection" | "content-length" | "transfer-encoding" | "cookie"
        ) {
            outbound = outbound.header(name, value);
        }
    }
    let Ok(body) = to_bytes(request.into_body(), 1024 * 1024).await else {
        return StatusCode::PAYLOAD_TOO_LARGE.into_response();
    };
    let Ok(response) = outbound.body(body).send().await else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let status = response.status();
    let headers = response.headers().clone();
    let Ok(bytes) = response.bytes().await else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let mut response = Response::new(Body::from(bytes));
    *response.status_mut() = status;
    for (name, value) in &headers {
        if !matches!(
            name.as_str(),
            "connection" | "content-length" | "transfer-encoding"
        ) {
            response.headers_mut().append(name, value.clone());
        }
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        error::{Result, check},
        files::PrivateDir,
    };

    /// Real distinct backends must observe the selected replica for every OPAQUE phase.
    #[tokio::test]
    async fn proxy_routes_password_exchanges_to_selected_replica() -> Result<()> {
        let private = PrivateDir::new()?;
        let mut clients = Vec::new();
        let mut servers = Vec::new();
        for label in ["replica-a", "replica-b", "genesis"] {
            let socket = private.0.join(format!("{label}.sock"));
            let listener =
                tokio::net::UnixListener::bind(&socket).safe("Cannot bind test backend.")?;
            servers.push(tokio::spawn(async move {
                axum::serve(
                    listener,
                    Router::new().fallback(move || async move { label }),
                )
                .await
            }));
            clients.push(
                reqwest::Client::builder()
                    .unix_socket(socket)
                    .no_proxy()
                    .build()
                    .safe("Cannot build test transport.")?,
            );
        }
        let mut clients = clients.into_iter();
        let proxy = Proxy {
            a: clients
                .next()
                .ok_or_else(|| crate::error::Failure::harness("Missing test replica A."))?,
            b: clients
                .next()
                .ok_or_else(|| crate::error::Failure::harness("Missing test replica B."))?,
            genesis: clients
                .next()
                .ok_or_else(|| crate::error::Failure::harness("Missing test Genesis."))?,
            use_b: Arc::new(AtomicBool::new(false)),
            config: Arc::new(String::new()),
            assets: ServeDir::new(&private.0).fallback(tower_http::services::ServeFile::new(
                private.0.join("index.html"),
            )),
        };
        let mut observed = Vec::new();
        for second in [false, true] {
            proxy.use_b.store(second, Ordering::SeqCst);
            for path in [
                "/v1/auth/opaque/login/start",
                "/v1/auth/opaque/login/finish",
                "/v1/auth/opaque/reauth/start",
                "/v1/auth/opaque/reauth/finish",
                "/admission/token",
            ] {
                let request = Request::builder()
                    .uri(path)
                    .body(Body::empty())
                    .safe("Cannot build test request.")?;
                let response = forward(State(proxy.clone()), request).await;
                let bytes = to_bytes(response.into_body(), 1024)
                    .await
                    .safe("Cannot read test response.")?;
                observed.push((second, path, bytes));
            }
        }
        for server in servers {
            server.abort();
        }
        for (second, path, bytes) in observed {
            let expected = if path.starts_with("/admission/") {
                "genesis"
            } else if second {
                "replica-b"
            } else {
                "replica-a"
            };
            assert_eq!(
                bytes.as_ref(),
                expected.as_bytes(),
                "Wrong backend for {path}."
            );
        }
        Ok(())
    }

    /// Exercises the actual proxy across HTTP/2-style split cookies and an HTTP/1 Unix backend.
    #[tokio::test]
    async fn proxy_preserves_session_and_binding_cookies() -> Result<()> {
        let private = PrivateDir::new()?;
        let socket = private.0.join("backend.sock");
        let listener = tokio::net::UnixListener::bind(&socket).safe("Cannot bind test backend.")?;
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                Router::new().fallback(|request: Request| async move {
                    request
                        .headers()
                        .get(header::COOKIE)
                        .and_then(|value| value.to_str().ok())
                        .unwrap_or("")
                        .to_owned()
                }),
            )
            .await
        });
        let client = reqwest::Client::builder()
            .unix_socket(socket)
            .no_proxy()
            .build()
            .safe("Cannot build test transport.")?;
        let proxy = Proxy {
            a: client.clone(),
            b: client.clone(),
            genesis: client,
            use_b: Arc::new(AtomicBool::new(false)),
            config: Arc::new(String::new()),
            assets: ServeDir::new(&private.0).fallback(tower_http::services::ServeFile::new(
                private.0.join("index.html"),
            )),
        };
        let request = Request::builder()
            .uri("/v1/auth/session")
            .header(header::COOKIE, "permesi_session=session-proof")
            .header(header::COOKIE, "permesi_oauth_binding=binding-proof")
            .body(Body::empty())
            .safe("Cannot build test request.")?;
        let response = forward(State(proxy), request).await;
        server.abort();
        let bytes = to_bytes(response.into_body(), 1024)
            .await
            .safe("Cannot read test response.")?;
        check(
            bytes.as_ref() == b"permesi_session=session-proof; permesi_oauth_binding=binding-proof",
            "Proxy lost a cookie proof.",
        )
    }
}
