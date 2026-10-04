//! Signing metadata tests reject malformed keys and exercise shared Vault rotation.

#![allow(clippy::indexing_slicing)]

use super::*;
use rsa::{
    RsaPrivateKey,
    pkcs8::{EncodePublicKey, LineEnding},
    rand_core::OsRng,
};
use serde_json::json;

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
