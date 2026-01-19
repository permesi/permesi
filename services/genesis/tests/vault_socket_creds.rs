#![allow(clippy::unwrap_used, clippy::expect_used)]

use genesis::cli::globals::GlobalArgs;
use genesis::vault::{VaultTarget, VaultTransport};
use http::{Method, Request, Response, StatusCode};
use http_body_util::Full;
use hyper::{body::Bytes, service::service_fn};
use hyper_util::rt::TokioIo;
use secrecy::ExposeSecret;
use serde_json::json;
use std::path::PathBuf;
use tokio::net::UnixListener;

async fn mock_agent_service(
    req: Request<hyper::body::Incoming>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let path = req.uri().path();
    let method = req.method();

    if method == Method::GET && path == "/v1/database/creds/genesis" {
        // We can verify that no X-Vault-Token header is sent if we want,
        // but the main goal is to return creds.
        let body = json!({
            "lease_id": "lease-socket-123",
            "lease_duration": 300,
            "data": {
                "username": "socket-user",
                "password": "socket-password"
            }
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
async fn test_database_creds_via_socket() -> anyhow::Result<()> {
    // 1. Setup a temporary path for the socket
    let dir = temp_env::with_vars(Vec::<(&str, Option<&str>)>::new(), std::env::temp_dir);
    let socket_path = dir.join(format!("vault-agent-creds-{}.sock", uuid::Uuid::new_v4()));
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

    // 3. Initialize GlobalArgs with VaultTransport pointing to the socket
    // The user configures GENESIS_VAULT_URL to the socket path.
    // VaultTarget handles parsing "unix://..." or just "/..." or "http://..."

    // Test with unix:// scheme
    let socket_url = format!("unix://{}", socket_path.display());
    let target = VaultTarget::parse(&socket_url)?;
    let transport = VaultTransport::from_target("test-suite", target)?;

    let mut globals = GlobalArgs::new(socket_url, transport);

    // 4. Call database_creds (which should use the transport)
    genesis::vault::database::database_creds(&mut globals).await?;

    // 5. Verify results
    assert_eq!(globals.vault_db_lease_id, "lease-socket-123");
    assert_eq!(globals.vault_db_username, "socket-user");

    assert_eq!(globals.vault_db_password.expose_secret(), "socket-password");

    // 6. Cleanup
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
