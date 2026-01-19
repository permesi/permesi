#![allow(clippy::unwrap_used, clippy::expect_used)]

use http::{Method, Request, Response, StatusCode};
use http_body_util::Full;
use hyper::{body::Bytes, service::service_fn};
use hyper_util::rt::TokioIo;
use serde_json::json;
use std::path::PathBuf;
use tokio::net::UnixListener;
use vault_client::{VaultTarget, VaultTransport};

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
    let socket_path = dir.join(format!("vault-agent-{}.sock", uuid::Uuid::new_v4()));
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

    // 3. Initialize VaultTransport with the socket path
    let target = VaultTarget::parse(&format!("unix://{}", socket_path.display()))?;
    let transport = VaultTransport::from_target("test-suite", target)?;

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
    let socket_path = dir.join(format!("vault-agent-renew-{}.sock", uuid::Uuid::new_v4()));
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

    // 3. Initialize VaultTransport with the socket path
    let target = VaultTarget::parse(&format!("unix://{}", socket_path.display()))?;
    let transport = VaultTransport::from_target("test-suite", target)?;

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
