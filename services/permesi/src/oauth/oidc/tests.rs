//! Signing metadata tests reject malformed keys and exercise shared Vault rotation.

#![allow(clippy::indexing_slicing)]

use super::*;
use rsa::{
    RsaPrivateKey,
    pkcs8::{EncodePublicKey, LineEnding},
    rand_core::OsRng,
};
use serde_json::json;

/// A delayed signing metadata read must not replace a newer public JWKS snapshot.
#[tokio::test]
async fn oidc_review_regression_signing_read_cannot_downgrade_refreshed_jwks() -> Result<()> {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use tokio::sync::Notify;
    let first_key = RsaPrivateKey::new(&mut OsRng, 2048)?
        .to_public_key()
        .to_public_key_pem(LineEnding::LF)?;
    let next_key = RsaPrivateKey::new(&mut OsRng, 2048)?
        .to_public_key()
        .to_public_key_pem(LineEnding::LF)?;
    let first = json!({"data":{"type":"rsa-2048","latest_version":1,"keys":{"1":{"public_key":first_key}}}});
    let rotated = json!({"data":{"type":"rsa-2048","latest_version":2,"keys":{"1":{"public_key":first_key},"2":{"public_key":next_key}}}});
    let started = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let counter = Arc::new(AtomicUsize::new(0));
    let router = axum::Router::new().route(
        "/v1/transit/permesi/keys/oidc-signing",
        axum::routing::get({
            let started = started.clone();
            let release = release.clone();
            move || {
                let started = started.clone();
                let release = release.clone();
                let first = first.clone();
                let rotated = rotated.clone();
                let counter = counter.clone();
                async move {
                    if counter.fetch_add(1, Ordering::SeqCst) == 0 {
                        started.notify_one();
                        release.notified().await;
                        axum::Json(first)
                    } else {
                        axum::Json(rotated)
                    }
                }
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let mut server = tokio::task::JoinSet::new();
    server.spawn(async move { axum::serve(listener, router).await });
    let uri = format!("http://{address}");
    let transport = VaultTransport::from_target("test", vault_client::VaultTarget::parse(&uri)?)?;
    let mut globals = crate::cli::globals::GlobalArgs::new(uri, transport);
    globals.vault_transit_mount = "transit/permesi".into();
    let state = OAuthState::new(OAuthConfig::disabled(), &globals);
    let reader = state.clone();
    let mut readers = tokio::task::JoinSet::new();
    readers.spawn(async move { reader.signing_key().await });
    tokio::time::timeout(Duration::from_secs(5), started.notified()).await?;
    let fresh = serde_json::to_value(state.refresh_jwks().await?)?;
    assert_eq!(fresh["keys"].as_array().context("keys")?.len(), 2);
    release.notify_one();
    tokio::time::timeout(Duration::from_secs(5), readers.join_next())
        .await?
        .context("missing signing read")???;
    assert_eq!(serde_json::to_value(state.jwks().await?)?, fresh);
    Ok(())
}

#[tokio::test]
async fn oidc_signer_rejects_wrong_version_missing_and_invalid_signatures() -> Result<()> {
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };
    let server = MockServer::start().await;
    let key = RsaPrivateKey::new(&mut OsRng, 2048)?;
    let pem = key.to_public_key().to_public_key_pem(LineEnding::LF)?;
    Mock::given(method("GET"))
        .and(path("/v1/transit/permesi/keys/oidc-signing"))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            json!({"data":{"type":"rsa-2048","latest_version":1,"keys":{"1":{"public_key":pem}}}}),
        ))
        .mount(&server)
        .await;
    let transport =
        VaultTransport::from_target("test", vault_client::VaultTarget::parse(&server.uri())?)?;
    let mut globals = crate::cli::globals::GlobalArgs::new(server.uri(), transport);
    globals.vault_transit_mount = "transit/permesi".into();
    let state = OAuthState::new(OAuthConfig::disabled(), &globals);
    let key = state.signing_key().await?;
    server.reset().await;
    for body in [
        json!({}),
        json!({"data":{"signature":"vault:v2:AAAA"}}),
        json!({"data":{"signature":"vault:v1:AAAA"}}),
    ] {
        Mock::given(method("POST"))
            .and(path("/v1/transit/permesi/sign/oidc-signing"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(&server)
            .await;
        assert!(
            state
                .sign_jwt(&key, "at+jwt", &json!({"iss":"https://issuer.test"}))
                .await
                .is_err()
        );
        server.reset().await;
    }
    Ok(())
}

#[test]
fn oidc_jwks_rejects_incompatible_or_incomplete_keysets() {
    for body in [
        json!({}),
        json!({"data":{"type":"ed25519","keys":{},"latest_version":1}}),
        json!({"data":{"type":"rsa-2048","keys":{},"latest_version":1}}),
        json!({"data":{"type":"rsa-2048","keys":{"1":{"public_key":"invalid"}},"latest_version":1}}),
    ] {
        assert!(parse_jwks(&body).is_err());
    }
}

#[test]
fn oidc_jwks_retains_prior_versions_and_never_exports_private_material() -> Result<()> {
    let key = RsaPrivateKey::new(&mut OsRng, 2048)?;
    let pem = key.to_public_key().to_public_key_pem(LineEnding::LF)?;
    let body = json!({"data":{"type":"rsa-2048","latest_version":2,"keys":{"2":{"public_key":pem},"1":{"public_key":pem}}}});
    let keys = parse_jwks(&body)?;
    let encoded = serde_json::to_value(keys)?;
    assert_eq!(encoded["keys"].as_array().context("keys")?.len(), 2);
    assert_eq!(encoded["keys"][0]["kid"], encoded["keys"][1]["kid"]);
    for field in ["d", "p", "q", "dp", "dq", "qi", "private_key"] {
        assert!(encoded["keys"][0].get(field).is_none());
    }
    assert_eq!(encoded["keys"][0]["alg"], "RS256");
    Ok(())
}

#[tokio::test]
async fn oidc_jwks_rotation_is_shared_across_replicas() -> Result<()> {
    use crate::cli::globals::GlobalArgs;
    use test_support::{runtime, vault::VaultContainer};
    runtime::ensure_container_runtime()?;
    let vault = VaultContainer::start("bridge").await?;
    vault
        .enable_secrets_engine("transit/permesi", "transit")
        .await?;
    vault
        .create_transit_key("transit/permesi", "oidc-signing", "rsa-2048")
        .await?;
    let transport =
        VaultTransport::from_target("test", vault_client::VaultTarget::parse(vault.base_url())?)?;
    let mut globals = GlobalArgs::new(vault.base_url().into(), transport.clone());
    globals.set_token(SecretString::from("root-token"));
    globals.vault_transit_mount = "transit/permesi".into();
    let mut config = OAuthConfig::disabled();
    config.issuer = Some("https://issuer.test".into());
    config.audience = Some("jobs-api".into());
    config.jwks_cache_ttl = 1;
    let first = OAuthState::new(config.clone(), &globals);
    let second = OAuthState::new(config, &globals);
    let original = serde_json::to_value(first.jwks().await?)?;
    let response = transport
        .request_json(
            Method::POST,
            "/v1/transit/permesi/keys/oidc-signing/rotate",
            Some("root-token"),
            Some(&json!({})),
        )
        .await?;
    ensure!(response.status.is_success(), "rotation failed");
    let rotated = serde_json::to_value(second.jwks().await?)?;
    assert_eq!(rotated["keys"].as_array().context("keys")?.len(), 2);
    assert_eq!(original["keys"][0], rotated["keys"][0]);
    assert_ne!(rotated["keys"][0]["kid"], rotated["keys"][1]["kid"]);
    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert_eq!(rotated, serde_json::to_value(first.jwks().await?)?);
    Ok(())
}

#[tokio::test]
async fn oidc_review_regression_concurrent_jwks_requests_coalesce_vault_reads() -> Result<()> {
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };
    let server = MockServer::start().await;
    let key = RsaPrivateKey::new(&mut OsRng, 2048)?;
    let pem = key.to_public_key().to_public_key_pem(LineEnding::LF)?;
    Mock::given(method("GET"))
        .and(path("/v1/transit/permesi/keys/oidc-signing"))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            json!({"data":{"type":"rsa-2048","latest_version":1,"keys":{"1":{"public_key":pem}}}}),
        ))
        .mount(&server)
        .await;
    let transport =
        VaultTransport::from_target("test", vault_client::VaultTarget::parse(&server.uri())?)?;
    let mut globals = crate::cli::globals::GlobalArgs::new(server.uri(), transport);
    globals.vault_transit_mount = "transit/permesi".into();
    let mut config = OAuthConfig::disabled();
    config.jwks_cache_ttl = 1;
    let state = OAuthState::new(config, &globals);
    let mut requests = tokio::task::JoinSet::new();
    for _ in 0..16 {
        let state = state.clone();
        requests.spawn(async move { state.jwks().await });
    }
    while let Some(result) = requests.join_next().await {
        result??;
    }
    assert_eq!(
        server
            .received_requests()
            .await
            .context("no request log")?
            .len(),
        1
    );
    server.reset().await;
    Mock::given(method("GET"))
        .and(path("/v1/transit/permesi/keys/oidc-signing"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&server)
        .await;
    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert!(state.jwks().await.is_err());
    assert!(state.jwks().await.is_err());
    assert_eq!(
        server
            .received_requests()
            .await
            .context("no request log")?
            .len(),
        1
    );
    Ok(())
}
