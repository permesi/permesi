//! Live contract tests against a disposable OpenBao dev server.
//!
//! The unit tests in this crate pin the request shapes with mocks; these pin the
//! behaviour of a real OpenBao for the calls Permesi and Genesis depend on, with
//! the emphasis on rejection: wrong, replayed, expired and revoked credentials,
//! policy denials, an unreachable server, and recovery once it is back.
//!
//! Every test owns its container, root token and data, and nothing here reaches
//! a shared instance. A missing container runtime is an error, not a skip.

use anyhow::{Context, Result, anyhow, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signature, VerifyingKey};
use http::{Method, StatusCode};
use openbao_client::{OpenBaoTarget, OpenBaoTransport, approle_login, approle_login_url, unwrap};
use serde_json::{Value, json};
use std::{
    net::TcpListener,
    time::{Duration, Instant},
};
use test_support::{openbao::OpenBaoContainer, runtime};

const USER_AGENT: &str = "openbao-client-live-test";
const TRANSIT_MOUNT: &str = "transit/live";
const SIGNING_KEY: &str = "signing";

const SERVICE_POLICY: &str = r#"
path "auth/token/renew-self" { capabilities = ["update"] }
path "auth/token/lookup-self" { capabilities = ["read"] }
path "transit/live/sign/signing" { capabilities = ["update"] }
path "transit/live/keys/signing" { capabilities = ["read"] }
path "kv-live/data/config" { capabilities = ["read"] }
"#;

async fn start() -> Result<OpenBaoContainer> {
    runtime::ensure_container_runtime()?;
    OpenBaoContainer::start("bridge").await
}

fn transport(openbao: &OpenBaoContainer) -> Result<OpenBaoTransport> {
    OpenBaoTransport::from_target(USER_AGENT, OpenBaoTarget::parse(openbao.base_url())?)
}

/// Mounts transit, a KV-v2 engine and the least-privilege policy the tests log in with.
async fn provision(openbao: &OpenBaoContainer) -> Result<()> {
    openbao
        .enable_secrets_engine(TRANSIT_MOUNT, "transit")
        .await?;
    openbao
        .create_transit_key(TRANSIT_MOUNT, SIGNING_KEY, "ed25519")
        .await?;
    openbao
        .create_transit_key(TRANSIT_MOUNT, "other", "ed25519")
        .await?;
    openbao.enable_secrets_engine("kv-live", "kv-v2").await?;
    openbao.write_policy("live", SERVICE_POLICY).await?;
    openbao.enable_auth("approle", "approle").await?;
    openbao.create_approle("approle", "live", &["live"]).await?;
    Ok(())
}

async fn sign(
    transport: &OpenBaoTransport,
    token: &str,
    key: &str,
    version: u32,
    message: &[u8],
) -> Result<(StatusCode, Value)> {
    let response = transport
        .request_json(
            Method::POST,
            &format!("/v1/{TRANSIT_MOUNT}/sign/{key}"),
            Some(token),
            Some(&json!({ "input": STANDARD.encode(message), "key_version": version })),
        )
        .await?;
    Ok((response.status, response.body))
}

async fn public_keys(transport: &OpenBaoTransport, token: &str) -> Result<Value> {
    let response = transport
        .request_json(
            Method::GET,
            &format!("/v1/{TRANSIT_MOUNT}/keys/{SIGNING_KEY}"),
            Some(token),
            None,
        )
        .await?;
    ensure!(response.status.is_success(), "key read failed");
    response
        .body
        .pointer("/data/keys")
        .cloned()
        .context("missing key versions")
}

/// Verifies a `vault:v<N>:<base64>` transit signature with the published public key.
fn verify_offline(keys: &Value, version: u32, signature: &str, message: &[u8]) -> Result<()> {
    let prefix = format!("vault:v{version}:");
    let raw = STANDARD.decode(
        signature
            .strip_prefix(&prefix)
            .with_context(|| format!("signature lacks the {prefix} prefix"))?,
    )?;
    let public = keys
        .pointer(&format!("/{version}/public_key"))
        .and_then(Value::as_str)
        .context("missing public key for version")?;
    let public: [u8; 32] = STANDARD
        .decode(public)?
        .try_into()
        .map_err(|_| anyhow!("public key is not 32 bytes"))?;
    let signature = Signature::from_slice(&raw)?;
    VerifyingKey::from_bytes(&public)?.verify_strict(message, &signature)?;
    Ok(())
}

#[tokio::test]
async fn approle_login_issues_a_renewable_least_privilege_token() -> Result<()> {
    let openbao = start().await?;
    provision(&openbao).await?;
    let transport = transport(&openbao)?;
    let role_id = openbao.read_role_id("approle", "live").await?;
    let secret_id = openbao.create_secret_id("approle", "live").await?;
    let login_url = approle_login_url(openbao.base_url())?;

    let (token, lease) = approle_login(USER_AGENT, &login_url, &secret_id, &role_id).await?;
    assert!(lease > 0);
    assert!(transport.renew_token(Some(&token), None).await? > 0);

    let lookup = transport
        .request_json(
            Method::GET,
            "/v1/auth/token/lookup-self",
            Some(&token),
            None,
        )
        .await?;
    let policies = lookup
        .body
        .pointer("/data/policies")
        .and_then(Value::as_array)
        .context("missing policies")?;
    assert!(policies.contains(&json!("live")));
    assert!(!policies.contains(&json!("root")));
    Ok(())
}

#[tokio::test]
async fn approle_login_rejects_wrong_credentials_without_echoing_them() -> Result<()> {
    let openbao = start().await?;
    provision(&openbao).await?;
    let role_id = openbao.read_role_id("approle", "live").await?;
    let login_url = approle_login_url(openbao.base_url())?;
    let wrong_secret = "00000000-dead-beef-0000-000000000000";

    let error = approle_login(USER_AGENT, &login_url, wrong_secret, &role_id)
        .await
        .err()
        .context("a wrong secret_id must not log in")?;
    let message = format!("{error:#}");
    assert!(message.contains("400"), "unexpected rejection: {message}");
    assert!(!message.contains(wrong_secret));

    let secret_id = openbao.create_secret_id("approle", "live").await?;
    let error = approle_login(USER_AGENT, &login_url, &secret_id, "unknown-role-id")
        .await
        .err()
        .context("an unknown role_id must not log in")?;
    assert!(!format!("{error:#}").contains(&secret_id));
    Ok(())
}

#[tokio::test]
async fn wrapped_secret_id_unwraps_once_and_rejects_replay() -> Result<()> {
    let openbao = start().await?;
    provision(&openbao).await?;
    let role_id = openbao.read_role_id("approle", "live").await?;
    let wrapped = openbao
        .create_wrapped_secret_id("approle", "live", "60s")
        .await?;

    let secret_id = unwrap(USER_AGENT, openbao.base_url(), &wrapped).await?;
    let login_url = approle_login_url(openbao.base_url())?;
    approle_login(USER_AGENT, &login_url, &secret_id, &role_id).await?;

    let replay = unwrap(USER_AGENT, openbao.base_url(), &wrapped).await;
    assert!(replay.is_err(), "a wrapping token must be single use");
    Ok(())
}

#[tokio::test]
async fn revoked_and_expired_tokens_are_refused() -> Result<()> {
    let openbao = start().await?;
    provision(&openbao).await?;
    let transport = transport(&openbao)?;

    let revoked = openbao.create_token(&["live"], "1h").await?;
    assert!(transport.renew_token(Some(&revoked), None).await? > 0);
    openbao.revoke_token(&revoked).await?;
    assert!(transport.renew_token(Some(&revoked), None).await.is_err());
    let (status, _) = sign(&transport, &revoked, SIGNING_KEY, 1, b"after revoke").await?;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let expiring = openbao.create_token(&["live"], "2s").await?;
    let (status, _) = sign(&transport, &expiring, SIGNING_KEY, 1, b"while valid").await?;
    assert_eq!(status, StatusCode::OK);
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let (status, _) = sign(&transport, &expiring, SIGNING_KEY, 1, b"after expiry").await?;
        if status == StatusCode::FORBIDDEN {
            break;
        }
        ensure!(Instant::now() < deadline, "token outlived its 2s TTL");
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert!(transport.renew_token(Some(&expiring), None).await.is_err());

    let (status, _) = sign(&transport, "not-a-token", SIGNING_KEY, 1, b"forged").await?;
    assert_eq!(status, StatusCode::FORBIDDEN);
    Ok(())
}

#[tokio::test]
async fn policy_denies_everything_outside_the_granted_paths() -> Result<()> {
    let openbao = start().await?;
    provision(&openbao).await?;
    openbao
        .write_kv_v2("kv-live", "config", json!({ "seed": "c2VlZA==" }))
        .await?;
    openbao
        .write_kv_v2("kv-live", "other", json!({ "seed": "b3RoZXI=" }))
        .await?;
    let transport = transport(&openbao)?;
    let token = openbao.create_token(&["live"], "1h").await?;

    let allowed = transport
        .request_json(Method::GET, "/v1/kv-live/data/config", Some(&token), None)
        .await?;
    assert_eq!(allowed.status, StatusCode::OK);
    assert_eq!(
        allowed.body.pointer("/data/data/seed"),
        Some(&json!("c2VlZA=="))
    );

    let denied: [(Method, String, Option<Value>); 6] = [
        (Method::GET, "/v1/kv-live/data/other".into(), None),
        (
            Method::POST,
            "/v1/kv-live/data/config".into(),
            Some(json!({ "data": { "seed": "overwritten" } })),
        ),
        (
            Method::POST,
            format!("/v1/{TRANSIT_MOUNT}/sign/other"),
            Some(json!({ "input": STANDARD.encode(b"x") })),
        ),
        (
            Method::POST,
            format!("/v1/{TRANSIT_MOUNT}/keys/{SIGNING_KEY}/rotate"),
            Some(json!({})),
        ),
        (
            Method::GET,
            format!("/v1/{TRANSIT_MOUNT}/export/signing-key/{SIGNING_KEY}"),
            None,
        ),
        (Method::GET, "/v1/sys/policies/acl/live".into(), None),
    ];
    for (method, path, body) in denied {
        let response = transport
            .request_json(method.clone(), &path, Some(&token), body.as_ref())
            .await?;
        assert_eq!(
            response.status,
            StatusCode::FORBIDDEN,
            "{method} {path} must be denied"
        );
    }

    let unchanged = transport
        .request_json(Method::GET, "/v1/kv-live/data/config", Some(&token), None)
        .await?;
    assert_eq!(
        unchanged.body.pointer("/data/data/seed"),
        Some(&json!("c2VlZA=="))
    );
    let keys = public_keys(&transport, &token).await?;
    assert_eq!(keys.as_object().map(serde_json::Map::len), Some(1));
    Ok(())
}

#[tokio::test]
async fn transit_signatures_verify_offline_across_rotation() -> Result<()> {
    let openbao = start().await?;
    provision(&openbao).await?;
    let transport = transport(&openbao)?;
    let token = openbao.create_token(&["live"], "1h").await?;
    let message = b"permesi transit contract";

    let (status, body) = sign(&transport, &token, SIGNING_KEY, 1, message).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.pointer("/data/key_version"), Some(&json!(1)));
    let first = body
        .pointer("/data/signature")
        .and_then(Value::as_str)
        .context("missing signature")?
        .to_string();
    let before = public_keys(&transport, &token).await?;
    verify_offline(&before, 1, &first, message)?;
    assert!(verify_offline(&before, 1, &first, b"another message").is_err());

    openbao
        .rotate_transit_key(TRANSIT_MOUNT, SIGNING_KEY)
        .await?;
    let after = public_keys(&transport, &token).await?;
    assert_eq!(after.as_object().map(serde_json::Map::len), Some(2));
    assert_eq!(
        before.pointer("/1/public_key"),
        after.pointer("/1/public_key"),
        "rotation must not change a published key version"
    );
    assert_ne!(
        after.pointer("/1/public_key"),
        after.pointer("/2/public_key")
    );
    verify_offline(&after, 1, &first, message)?;

    let (_, body) = sign(&transport, &token, SIGNING_KEY, 2, message).await?;
    let second = body
        .pointer("/data/signature")
        .and_then(Value::as_str)
        .context("missing signature")?;
    verify_offline(&after, 2, second, message)?;
    let cross_version = second.replacen("vault:v2:", "vault:v1:", 1);
    assert!(verify_offline(&after, 1, &cross_version, message).is_err());

    // The previous version stays usable for signing until operators retire it.
    let (status, body) = sign(&transport, &token, SIGNING_KEY, 1, message).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.pointer("/data/key_version"), Some(&json!(1)));
    Ok(())
}

#[tokio::test]
async fn unreachable_server_fails_fast_instead_of_hanging() -> Result<()> {
    // Reserve a port and release it so nothing is listening there.
    let port = TcpListener::bind("127.0.0.1:0")?.local_addr()?.port();
    let base_url = format!("http://127.0.0.1:{port}");
    let transport = OpenBaoTransport::from_target(USER_AGENT, OpenBaoTarget::parse(&base_url)?)?;

    let started = Instant::now();
    assert!(
        transport
            .request_json(Method::GET, "/v1/sys/health", None, None)
            .await
            .is_err()
    );
    assert!(transport.renew_token(Some("token"), None).await.is_err());
    let login_url = approle_login_url(&base_url)?;
    assert!(
        approle_login(USER_AGENT, &login_url, "secret", "role")
            .await
            .is_err()
    );
    assert!(unwrap(USER_AGENT, &base_url, "wrapped").await.is_err());
    assert!(started.elapsed() < Duration::from_secs(20));
    Ok(())
}

#[tokio::test]
async fn transport_recovers_after_the_server_restarts() -> Result<()> {
    let mut openbao = start().await?;
    provision(&openbao).await?;
    let before = transport(&openbao)?;
    let token = openbao.create_token(&["live"], "1h").await?;
    let (status, _) = sign(&before, &token, SIGNING_KEY, 1, b"before outage").await?;
    assert_eq!(status, StatusCode::OK);
    let original_url = openbao.base_url().to_string();

    openbao.stop().await?;
    assert!(
        before
            .request_json(Method::GET, "/v1/sys/health", None, None)
            .await
            .is_err(),
        "requests must fail while the server is down"
    );
    assert!(before.renew_token(Some(&token), None).await.is_err());

    openbao.restart().await?;
    // Podman keeps the published port across a restart; other engines may not,
    // in which case only a fresh transport can prove the server is back.
    let after = if openbao.base_url() == original_url {
        before
    } else {
        transport(&openbao)?
    };
    let health = after
        .request_json(Method::GET, "/v1/sys/health", None, None)
        .await?;
    assert_eq!(health.status, StatusCode::OK);
    assert_eq!(health.body.get("sealed"), Some(&json!(false)));

    // Dev mode is in-memory: the pre-outage token is gone and must be refused,
    // and a new login against re-provisioned state works on the same transport.
    assert!(after.renew_token(Some(&token), None).await.is_err());
    provision(&openbao).await?;
    let token = openbao.create_token(&["live"], "1h").await?;
    let (status, _) = sign(&after, &token, SIGNING_KEY, 1, b"after outage").await?;
    assert_eq!(status, StatusCode::OK);
    Ok(())
}
