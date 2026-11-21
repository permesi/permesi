#![allow(clippy::unwrap_used, clippy::expect_used)]

use http::{Method, Request, Response, StatusCode};
use http_body_util::Full;
use hyper::{body::Bytes, service::service_fn};
use hyper_util::rt::TokioIo;
use openbao_client::{OpenBaoTarget, OpenBaoTransport};
use serde_json::json;
use std::path::PathBuf;
use tokio::net::UnixListener;

async fn mock_agent_service(
    req: Request<hyper::body::Incoming>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let path = req.uri().path();
    let method = req.method();

    if method == Method::GET && path == "/v1/auth/token/lookup-self" {
        let body = json!({
            "data": {
                "id": "agent-token",
                "ttl": 3600,
                "policies": ["default", "permesi-operators"]
            }
        });
        return Ok(Response::new(Full::new(Bytes::from(
            serde_json::to_vec(&body).expect("failed to serialize json"),
        ))));
    }

    if method == Method::POST && path == "/v1/sys/leases/renew" {
        let body = json!({
            "lease_duration": 3600
        });
        return Ok(Response::new(Full::new(Bytes::from(
            serde_json::to_vec(&body).expect("failed to serialize json"),
        ))));
    }

    Ok(Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(Full::new(Bytes::from(r#"{"errors":["path not found"]}"#)))
        .expect("failed to build response"))
}

#[tokio::test]
async fn test_agent_socket_transport() -> anyhow::Result<()> {
    // 1. Setup a temporary path for the socket
    let dir = temp_env::with_vars(Vec::<(&str, Option<&str>)>::new(), std::env::temp_dir);
    let socket_path = dir.join(format!("openbao-agent-{}.sock", uuid::Uuid::new_v4()));
    // Ensure cleanup
    let _guard = SocketGuard {
        path: socket_path.clone(),
    };

    // 2. Start the mock agent server
    let listener = UnixListener::bind(&socket_path)?;
    let server_handle = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let io = TokioIo::new(stream);
            tokio::spawn(async move {
                if let Err(err) = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, service_fn(mock_agent_service))
                    .await
                {
                    eprintln!("Error serving connection: {err:?}");
                }
            });
        }
    });

    // 3. Initialize OpenBaoTransport with the socket path
    let target = OpenBaoTarget::parse(&format!("unix://{}", socket_path.display()))?;
    let transport = OpenBaoTransport::from_target("test-suite", target)?;

    // 4. Perform a request (lookup-self)
    let response = transport
        .request_json(Method::GET, "/v1/auth/token/lookup-self", None, None)
        .await?;

    assert_eq!(response.status, StatusCode::OK);
    let id = response
        .body
        .get("data")
        .and_then(|d| d.get("id"))
        .and_then(|v| v.as_str());
    assert_eq!(id, Some("agent-token"));

    // 5. Cleanup
    server_handle.abort();
    Ok(())
}

#[tokio::test]
async fn test_agent_socket_renewal() -> anyhow::Result<()> {
    // 1. Setup a temporary path for the socket
    let dir = temp_env::with_vars(Vec::<(&str, Option<&str>)>::new(), std::env::temp_dir);
    let socket_path = dir.join(format!("openbao-agent-renew-{}.sock", uuid::Uuid::new_v4()));
    let _guard = SocketGuard {
        path: socket_path.clone(),
    };

    // 2. Start the mock agent server
    let listener = UnixListener::bind(&socket_path)?;
    let server_handle = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let io = TokioIo::new(stream);
            tokio::spawn(async move {
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, service_fn(mock_agent_service))
                    .await;
            });
        }
    });

    // 3. Initialize OpenBaoTransport with the socket path
    let target = OpenBaoTarget::parse(&format!("unix://{}", socket_path.display()))?;
    let transport = OpenBaoTransport::from_target("test-suite", target)?;

    // 4. Perform renewal request
    // This previously failed with "relative URL without a base" when called with a unix socket path.
    let lease_duration = transport.renew_db_lease(None, "lease-123", 3600).await?;

    assert_eq!(lease_duration, 3600);

    // 5. Cleanup
    server_handle.abort();
    Ok(())
}

struct SocketGuard {
    path: PathBuf,
}

impl Drop for SocketGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// An Agent that answers with headers and then stalls must hit the request
/// deadline instead of holding the caller (and its renewal loop) open.
#[tokio::test(start_paused = true)]
async fn agent_socket_request_times_out_when_the_body_stalls() -> anyhow::Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let dir = temp_env::with_vars(Vec::<(&str, Option<&str>)>::new(), std::env::temp_dir);
    let socket_path = dir.join(format!("openbao-agent-stall-{}.sock", uuid::Uuid::new_v4()));
    let _guard = SocketGuard {
        path: socket_path.clone(),
    };

    let listener = UnixListener::bind(&socket_path)?;
    let (headers_sent, mut headers_seen) = tokio::sync::mpsc::unbounded_channel();
    let server_handle = tokio::spawn(async move {
        let Ok((mut stream, _)) = listener.accept().await else {
            return;
        };
        let mut request = [0_u8; 1024];
        let _ = stream.read(&mut request).await;
        let _ = stream
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 64\r\n\r\n",
            )
            .await;
        let _ = headers_sent.send(());
        // Keep the connection open without ever sending the promised body.
        std::future::pending::<()>().await;
    });

    let target = OpenBaoTarget::parse(&format!("unix://{}", socket_path.display()))?;
    let transport = OpenBaoTransport::from_target("test-suite", target)?;
    let request = tokio::spawn(async move {
        transport
            .request_json(Method::GET, "/v1/auth/token/lookup-self", None, None)
            .await
            .map(|response| response.status)
    });

    assert!(headers_seen.recv().await.is_some());
    let error = request
        .await?
        .expect_err("a stalled body must not be awaited forever");
    assert!(error.to_string().contains("timed out"), "{error}");

    server_handle.abort();
    Ok(())
}
