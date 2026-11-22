//! The renewal worker against a real OpenBao token that hits its max TTL.
//!
//! The unit tests pin the decisions; this pins the server behaviour they rest on:
//! OpenBao grants a full TTL until the max TTL is closer than that, and from then
//! on returns only what is left. The worker must recognise the first shortened
//! lease and ask for a restart while the token still works.

use anyhow::{Context, Result, bail};
use http::{Method, StatusCode};
use openbao_client::{OpenBaoTarget, OpenBaoTransport};
use secrecy::SecretString;
use service_utils::{
    globals::GlobalArgs,
    openbao::renew::{ShutdownSignal, try_renew},
};
use std::time::{Duration, Instant};
use test_support::{openbao::OpenBaoContainer, runtime};
use tokio::{sync::mpsc, time::timeout};

const POLICY: &str = r#"
path "auth/token/renew-self" { capabilities = ["update"] }
path "auth/token/lookup-self" { capabilities = ["read"] }
"#;

#[tokio::test]
async fn token_at_max_ttl_requests_restart_while_still_valid() -> Result<()> {
    runtime::ensure_container_runtime()?;
    let openbao = OpenBaoContainer::start("bridge").await?;
    openbao.write_policy("renew-live", POLICY).await?;
    // A 6 s TTL that may be renewed, but never past 14 s after creation.
    let token = openbao
        .create_token_with_max_ttl(&["renew-live"], "6s", "14s")
        .await?;
    let created = Instant::now();

    let transport = OpenBaoTransport::from_target(
        "renew-live-test",
        OpenBaoTarget::parse(openbao.base_url())?,
    )?;
    let mut globals = GlobalArgs::new(openbao.base_url().to_string(), transport.clone());
    globals.set_token(SecretString::from(token.clone()));
    globals.set_token_lease(6);
    // The database lease task has nothing real to renew here; a failure from it
    // would arrive as `DbLeaseRenewalFailed`, which the loop below skips.
    globals.openbao_db_lease_id = "database/creds/none/renew-live".to_string();
    globals.openbao_db_lease_duration = 3600;

    let (tx, mut rx) = mpsc::unbounded_channel();
    try_renew(&globals, tx).await?;

    let signal = loop {
        match timeout(Duration::from_secs(40), rx.recv()).await {
            Ok(Some(ShutdownSignal::DbLeaseRenewalFailed)) => {}
            Ok(Some(signal)) => break signal,
            Ok(None) => bail!("renewal tasks ended without a token signal"),
            Err(_) => bail!("no shutdown signal before the token's max TTL passed"),
        }
    };
    let elapsed = created.elapsed();

    assert_eq!(signal, ShutdownSignal::TokenExhausted);
    assert!(
        elapsed > Duration::from_secs(6),
        "the token must have been renewed past its first TTL (signal after {elapsed:?})"
    );
    assert!(
        elapsed < Duration::from_secs(14),
        "the restart must be requested before max TTL (signal after {elapsed:?})"
    );

    // The credential the service would drain with is still accepted.
    let lookup = transport
        .request_json(
            Method::GET,
            "/v1/auth/token/lookup-self",
            Some(&token),
            None,
        )
        .await?;
    assert_eq!(lookup.status, StatusCode::OK);
    let remaining = lookup
        .body
        .pointer("/data/ttl")
        .and_then(serde_json::Value::as_u64)
        .context("lookup-self returned no ttl")?;
    assert!(remaining > 0, "token already expired at shutdown");
    Ok(())
}
