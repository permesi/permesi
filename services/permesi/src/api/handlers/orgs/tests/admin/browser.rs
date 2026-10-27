//! Compiled WASM through real session/operator authorization and PostgreSQL hierarchy reads.

use super::*;
use crate::api::handlers::auth::{AdminConfig, AdminState};
use std::{sync::Arc, time::Duration};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

/// Exercises admin navigation and ordinary owner navigation without mocking the inspection API.
#[tokio::test]
#[ignore = "requires Chromium, Node and built WASM; run just web-test-browser"]
async fn admin_inspection_browser_real_postgres() -> Result<()> {
    let mut f = Fixture::new().await?;
    let vault = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/auth/token/lookup-self"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"data":{"policies":["permesi-operators"],"ttl":3600}})),
        )
        .expect(1)
        .mount(&vault)
        .await;
    let transport = vault_client::VaultTransport::from_target(
        crate::APP_USER_AGENT,
        vault_client::VaultTarget::Tcp {
            base_url: vault.uri(),
        },
    )?;
    let mut state = crate::api::AppState::for_tests(f.db.pool.clone())?;
    state.admin = Arc::new(AdminState::new(
        AdminConfig::new(vault.uri()),
        f.db.pool.clone(),
        transport,
    )?);
    f.router = crate::api::with_response_policy(
        crate::api::router().split_for_parts().0.with_state(state),
    );
    sqlx::query("INSERT INTO organizations(slug,name,created_by,created_at) SELECT 'page-org-'||n,'Page organization '||n,$1,'2000-01-01T00:00:00Z' FROM generate_series(1,49) n")
        .bind(f.operator).execute(&f.db.pool).await?;
    sqlx::query("UPDATE applications SET name=$2 WHERE id=$1")
        .bind(f.foreign.application)
        .bind("Application <img src=x onerror=\"window.__inspectionXss=true\">")
        .execute(&f.db.pool)
        .await?;
    let before = f.snapshot().await?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let origin = format!("http://{}", listener.local_addr()?);
    let stop = tokio_util::sync::CancellationToken::new();
    let signal = stop.clone();
    let app = f.router.clone();
    let server = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(signal.cancelled_owned())
            .await
    });
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let output = tokio::process::Command::new("node")
        .arg(root.join("apps/web/tests/admin_inspection.mjs"))
        .env("PERMESI_INSPECTION_TEST_API", origin)
        .env("PERMESI_INSPECTION_TEST_SESSION", &f.token)
        .env("PERMESI_INSPECTION_TEST_OTHER_SESSION", &f.ordinary_token)
        .env(
            "PERMESI_INSPECTION_TEST_APP",
            f.foreign.application.to_string(),
        )
        .kill_on_drop(true)
        .output();
    let result = tokio::time::timeout(Duration::from_secs(150), output).await;
    stop.cancel();
    server.await??;
    let output = result??;
    ensure!(
        output.status.success(),
        "Admin inspection browser failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    ensure!(
        String::from_utf8_lossy(&output.stdout).contains("admin inspection browser passed"),
        "Browser completion marker missing"
    );
    assert_eq!(f.snapshot().await?, before);
    Ok(())
}
