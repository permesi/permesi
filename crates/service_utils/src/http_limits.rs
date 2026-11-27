//! Server-wide HTTP deadlines shared by the services.
//!
//! Handlers that talk to PostgreSQL or OpenBao set deadlines for their own work, but
//! nothing bounded a connection that never finished sending its request, or a request
//! on a route that had no deadline of its own. Both hold a connection, and a request in
//! a handler usually holds a database connection with it.
//!
//! ## Flow Overview
//! 1. A new connection has `header_read_timeout` to deliver a complete first request,
//!    and every later HTTP/1 request the same time to deliver its headers
//!    ([`HttpLimits::bound_connections`]). This applies to the TCP/TLS listener. The
//!    Unix socket listener is reachable only by a same-host reverse proxy, which
//!    enforces its own client timeouts, and `axum::serve` exposes no such setting.
//! 2. Every routed request has `request_timeout` to produce a response
//!    ([`HttpLimits::bound_requests`]). One that does not is answered with `503` and
//!    its handler is dropped, which rolls back any open transaction. An
//!    operation-specific deadline shorter than this still fires first.
//! 3. On shutdown, in-flight requests get `drain_timeout` to finish
//!    ([`crate::shutdown::drain_ended`]); what is still in a handler then is abandoned
//!    ([`crate::shutdown::Cutoff`]).
//!
//! ## What the connection timers do not cover
//! Three timers act before a request reaches a handler, and they are not one deadline:
//! the TLS handshake has the TLS acceptor's own fixed limit, the first request of a
//! connection has `header_read_timeout` counted from the end of that handshake, and
//! each later HTTP/1 request has `header_read_timeout` for its headers. On an idle
//! HTTP/1 keep-alive connection that last timer closes the connection, so clients
//! reconnect after `header_read_timeout` of silence. HTTP/2, which the TLS listener
//! negotiates, has no equivalent for requests after the first: a peer that opens a
//! stream and never completes its header block is not timed out here. A deployment
//! that exposes the TLS listener to untrusted HTTP/2 clients needs that bound from the
//! proxy or load balancer in front.
//!
//! The values come from each service's CLI and are validated again here, so a bad
//! combination fails startup.

use anyhow::{Result, bail};
use axum::{
    Router,
    extract::Request,
    http::{HeaderValue, StatusCode, header::CACHE_CONTROL},
    middleware::Next,
    response::IntoResponse,
};
use std::{fmt, time::Duration};

const REQUEST_TIMEOUT_MAX: Duration = Duration::from_mins(10);
const HEADER_READ_TIMEOUT_MAX: Duration = Duration::from_mins(1);
/// The drain and the 8 s of worker and pool shutdown after it must fit in the 60 s of
/// validity a lease keeps when its renewal gives up, so connections still hold valid
/// credentials while they finish.
const DRAIN_TIMEOUT_MAX: Duration = Duration::from_secs(50);
const TIMEOUT_MIN: Duration = Duration::from_secs(1);

/// Validated HTTP deadlines of one service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HttpLimits {
    request: Duration,
    header_read: Duration,
    drain: Duration,
}

impl HttpLimits {
    /// Validate and build the limits.
    ///
    /// # Errors
    /// Returns an error when a value is outside its range, or when reading the headers
    /// may take longer than the whole request. None of them can be switched off.
    pub fn new(
        request_timeout: Duration,
        header_read_timeout: Duration,
        drain_timeout: Duration,
    ) -> Result<Self> {
        if !(TIMEOUT_MIN..=REQUEST_TIMEOUT_MAX).contains(&request_timeout) {
            bail!("request timeout must be between 1 s and 10 min");
        }
        if !(TIMEOUT_MIN..=HEADER_READ_TIMEOUT_MAX).contains(&header_read_timeout) {
            bail!("header read timeout must be between 1 s and 60 s");
        }
        if header_read_timeout > request_timeout {
            bail!("header read timeout must not exceed the request timeout");
        }
        if !(TIMEOUT_MIN..=DRAIN_TIMEOUT_MAX).contains(&drain_timeout) {
            bail!("shutdown drain must be between 1 s and 50 s");
        }
        Ok(Self {
            request: request_timeout,
            header_read: header_read_timeout,
            drain: drain_timeout,
        })
    }

    #[must_use]
    pub const fn request_timeout(&self) -> Duration {
        self.request
    }

    #[must_use]
    pub const fn header_read_timeout(&self) -> Duration {
        self.header_read
    }

    #[must_use]
    pub const fn drain_timeout(&self) -> Duration {
        self.drain
    }

    /// Give every route registered so far `request_timeout` to answer.
    ///
    /// Apply it to the routed router before the error envelope, so the `503` it
    /// produces is rewritten into the JSON envelope and passes through CORS and request
    /// correlation like any other error. `503` matches what the handlers' own deadlines
    /// return; `408` would invite some clients to resend a request that may have had
    /// an effect. The answer carries `Cache-Control: no-store`: it describes a moment,
    /// and a route that forbids caching must not lose that on this path.
    pub fn bound_requests<S>(&self, router: Router<S>) -> Router<S>
    where
        S: Clone + Send + Sync + 'static,
    {
        let limit = self.request;
        router.layer(axum::middleware::from_fn(
            move |request: Request, next: Next| async move {
                // The deadline is checked before the handler is polled again, so a handler
                // that becomes ready only after the deadline, as after a scheduling stall,
                // is still cut off.
                let deadline = tokio::time::sleep(limit);
                tokio::select! {
                    biased;
                    () = deadline => (
                        StatusCode::SERVICE_UNAVAILABLE,
                        [(CACHE_CONTROL, HeaderValue::from_static("no-store"))],
                    )
                        .into_response(),
                    response = next.run(request) => response,
                }
            },
        ))
    }

    /// Bound how long a connection may take to deliver a request to `server`: the
    /// first complete request on a new connection, and the headers of each HTTP/1
    /// request after it.
    #[must_use]
    pub fn bound_connections<A, Acc>(
        &self,
        mut server: axum_server::Server<A, Acc>,
    ) -> axum_server::Server<A, Acc>
    where
        A: axum_server::Address,
    {
        server
            .http_builder()
            .http1()
            .header_read_timeout(self.header_read);
        server.first_request_timeout(self.header_read)
    }
}

/// One-line summary for startup logs.
impl fmt::Display for HttpLimits {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "request={}s header_read={}s drain={}s",
            self.request.as_secs(),
            self.header_read.as_secs(),
            self.drain.as_secs()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::HttpLimits;
    use crate::api_error;
    use anyhow::{Context, Result};
    use axum::{
        Router,
        body::Body,
        http::{Request, StatusCode},
        routing::get,
    };
    use std::time::{Duration, Instant};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpStream,
    };
    use tower::ServiceExt;

    fn limits(request: u64, header: u64, drain: u64) -> Result<HttpLimits> {
        HttpLimits::new(
            Duration::from_secs(request),
            Duration::from_secs(header),
            Duration::from_secs(drain),
        )
    }

    #[test]
    fn limits_are_bounded_and_ordered() -> Result<()> {
        assert!(limits(60, 10, 50).is_ok());
        let accepted = limits(60, 10, 20)?;
        assert_eq!(
            accepted.to_string(),
            "request=60s header_read=10s drain=20s"
        );
        for (request, header, drain) in [
            (0, 10, 20),
            (601, 10, 20),
            (60, 0, 20),
            (60, 61, 20),
            // Reading the headers may not take longer than the whole request.
            (5, 6, 20),
            (60, 10, 0),
            // A longer drain would outlast the credentials of a lease that is ending.
            (60, 10, 51),
        ] {
            assert!(
                limits(request, header, drain).is_err(),
                "{request}/{header}/{drain}"
            );
        }
        Ok(())
    }

    /// When the handler and the deadline are ready at the same moment, as after a stall
    /// of the scheduler, the deadline wins. The replaced middleware polled the handler
    /// first and let an overdue request through.
    #[tokio::test(start_paused = true)]
    async fn a_handler_ready_only_at_the_deadline_is_still_cut_off() -> Result<()> {
        let app =
            api_error::with_error_envelope(limits(2, 1, 5)?.bound_requests(Router::new().route(
                "/late",
                get(|| async {
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    "too late"
                }),
            )));
        for _ in 0..16 {
            let late = app
                .clone()
                .oneshot(Request::get("/late").body(Body::empty())?)
                .await?;
            assert_eq!(late.status(), StatusCode::SERVICE_UNAVAILABLE);
        }
        Ok(())
    }

    /// A handler with no deadline of its own is cut off at the request timeout and the
    /// caller gets the JSON `503`; a handler that answers in time is untouched.
    #[tokio::test(start_paused = true)]
    async fn request_without_its_own_deadline_is_answered_at_the_request_timeout() -> Result<()> {
        let app = || -> Result<Router> {
            Ok(api_error::with_error_envelope(
                limits(2, 1, 5)?.bound_requests(
                    Router::new()
                        .route("/fast", get(|| async { "done" }))
                        .route("/stuck", get(std::future::pending::<&'static str>)),
                ),
            ))
        };
        let fast = app()?
            .oneshot(Request::get("/fast").body(Body::empty())?)
            .await?;
        assert_eq!(fast.status(), StatusCode::OK);

        let started = tokio::time::Instant::now();
        let stuck = app()?
            .oneshot(Request::get("/stuck").body(Body::empty())?)
            .await?;
        assert_eq!(stuck.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(started.elapsed(), Duration::from_secs(2));
        // A route that forbids caching keeps that on this path too.
        assert_eq!(
            stuck
                .headers()
                .get("cache-control")
                .and_then(|value| value.to_str().ok()),
            Some("no-store")
        );
        let body = axum::body::to_bytes(stuck.into_body(), 4096).await?;
        let body: serde_json::Value = serde_json::from_slice(&body)?;
        assert_eq!(
            body.pointer("/error/code")
                .and_then(serde_json::Value::as_str),
            Some("dependency_unavailable"),
            "{body}"
        );
        Ok(())
    }

    /// Read until the peer closes, returning how long that took; `None` if it never did.
    async fn closed_after(mut stream: TcpStream, patience: Duration) -> Option<Duration> {
        let started = Instant::now();
        let mut sink = [0_u8; 512];
        tokio::time::timeout(patience, async {
            loop {
                match stream.read(&mut sink).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
            }
        })
        .await
        .ok()
        .map(|()| started.elapsed())
    }

    /// A client that opens a connection and never finishes its request is disconnected
    /// at the header read timeout, whether it sent nothing or half a request. Without
    /// the limit the same server keeps both connections for as long as the client likes.
    #[tokio::test]
    async fn connection_that_never_completes_a_request_is_closed() -> Result<()> {
        fn serve(
            bounded: bool,
        ) -> Result<(
            std::net::SocketAddr,
            axum_server::Handle<std::net::SocketAddr>,
        )> {
            let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
            listener.set_nonblocking(true)?;
            let address = listener.local_addr()?;
            let handle = axum_server::Handle::new();
            let mut server = axum_server::from_tcp(listener)?.handle(handle.clone());
            if bounded {
                server = limits(5, 1, 5)?.bound_connections(server);
            }
            let app = Router::new().route("/", get(|| async { "ok" }));
            tokio::spawn(server.serve(app.into_make_service()));
            Ok((address, handle))
        }
        async fn half_request(address: std::net::SocketAddr) -> Result<TcpStream> {
            let mut stream = TcpStream::connect(address).await?;
            stream
                .write_all(b"GET / HTTP/1.1\r\nHost: service.test\r\nX-Slow: ")
                .await?;
            Ok(stream)
        }

        let (address, handle) = serve(true)?;
        // A complete request is still answered.
        let mut complete = TcpStream::connect(address).await?;
        complete
            .write_all(b"GET / HTTP/1.1\r\nHost: service.test\r\nConnection: close\r\n\r\n")
            .await?;
        let mut answer = String::new();
        complete.read_to_string(&mut answer).await?;
        assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");

        for half in [false, true] {
            let name = if half { "half a request" } else { "silent" };
            let stream = if half {
                half_request(address).await?
            } else {
                TcpStream::connect(address).await?
            };
            let closed = closed_after(stream, Duration::from_secs(4))
                .await
                .with_context(|| format!("the {name} connection was never closed"))?;
            assert!(
                closed >= Duration::from_millis(800),
                "{name} was closed after only {closed:?}"
            );
        }
        // A connection that already completed a request and stalls in the middle of the
        // next one is closed as well; that path has its own timer.
        let mut reused = TcpStream::connect(address).await?;
        reused
            .write_all(b"GET / HTTP/1.1\r\nHost: service.test\r\n\r\n")
            .await?;
        let mut first = Vec::new();
        while !first.ends_with(b"ok") {
            let mut chunk = [0_u8; 256];
            let read = reused.read(&mut chunk).await?;
            anyhow::ensure!(read > 0, "the connection closed before the first answer");
            first.extend_from_slice(chunk.get(..read).unwrap_or_default());
        }
        reused
            .write_all(b"GET / HTTP/1.1\r\nHost: service.test\r\nX-Slow: ")
            .await?;
        closed_after(reused, Duration::from_secs(4))
            .await
            .context("a connection stalled in its second request was never closed")?;
        handle.shutdown();

        let (address, handle) = serve(false)?;
        assert_eq!(
            closed_after(half_request(address).await?, Duration::from_secs(3)).await,
            None,
            "the unbounded server closed a stalled connection by itself"
        );
        handle.shutdown();
        Ok(())
    }
}
