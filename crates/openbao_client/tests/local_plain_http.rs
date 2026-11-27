//! A plain-`http` OpenBao address on this machine is reached directly.
//!
//! The transport policy lets `http://127.0.0.1` and `http://localhost` through because
//! nothing leaves the machine. That only holds if the HTTP client does not hand the
//! request to a proxy named in the environment, which it would do by default, and if a
//! `localhost` name is not left to whatever the resolver says later.

use anyhow::{Context, Result};
use http::Method;
use openbao_client::{
    OpenBaoTarget, OpenBaoTransport,
    kubernetes::{KubernetesAuth, kubernetes_login},
};
use serde_json::json;
use wiremock::{Mock, MockServer, ResponseTemplate, matchers::any};

const PROXY_VARIABLES: [&str; 6] = [
    "HTTP_PROXY",
    "http_proxy",
    "ALL_PROXY",
    "all_proxy",
    "NO_PROXY",
    "no_proxy",
];

/// Every kind of request a service sends to a TCP address: through the transport, a
/// login helper and the Kubernetes login, each of which builds its own client.
async fn every_client(base: &str, jwt: &std::path::Path) -> Result<()> {
    let transport = OpenBaoTransport::from_target("test", OpenBaoTarget::parse(base)?)?;
    let _ = transport
        .request_json(Method::GET, "/v1/sys/health", None, None)
        .await;
    let _ = openbao_client::unwrap("test", base, "wrapped-token").await;
    let auth = KubernetesAuth {
        mount: "kubernetes".to_string(),
        role: "permesi".to_string(),
        token_path: jwt.to_path_buf(),
    };
    let _ = kubernetes_login("test", base, &auth).await;
    Ok(())
}

/// With `HTTP_PROXY` set and no exclusion, the default client sends every plain request
/// to the proxy. A login or a token for an OpenBao on loopback went there in clear
/// text, although the address was accepted for staying on the machine.
#[test]
fn local_plain_address_is_never_sent_through_the_environment_proxy() -> Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let (openbao, proxy) = runtime.block_on(async {
        let (openbao, proxy) = (MockServer::start().await, MockServer::start().await);
        for server in [&openbao, &proxy] {
            Mock::given(any())
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data":{}})))
                .mount(server)
                .await;
        }
        (openbao, proxy)
    });
    let jwt = std::env::temp_dir().join(format!("openbao-client-jwt-{}", uuid::Uuid::new_v4()));
    std::fs::write(&jwt, "header.payload.signature")?;
    let port = openbao.address().port();
    let through_proxy = |base: String| -> Result<usize> {
        let before = runtime
            .block_on(proxy.received_requests())
            .unwrap_or_default()
            .len();
        let settings = PROXY_VARIABLES.map(|name| {
            let value = (!name.eq_ignore_ascii_case("no_proxy")).then(|| proxy.uri());
            (name, value)
        });
        temp_env::with_vars(settings, || runtime.block_on(every_client(&base, &jwt)))?;
        let after = runtime
            .block_on(proxy.received_requests())
            .unwrap_or_default()
            .len();
        Ok(after - before)
    };

    // The proxy setting is in force in this process: an address that is not local uses it.
    let remote = through_proxy("http://openbao.proxied.invalid:8200".to_string())?;
    assert_eq!(remote, 3, "the control address goes through the proxy");

    for base in [
        format!("http://127.0.0.1:{port}"),
        format!("http://localhost:{port}"),
        format!("http://LOCALHOST:{port}"),
    ] {
        let direct_before = runtime
            .block_on(openbao.received_requests())
            .unwrap_or_default()
            .len();
        assert_eq!(through_proxy(base.clone())?, 0, "{base}");
        let direct = runtime
            .block_on(openbao.received_requests())
            .unwrap_or_default()
            .len()
            - direct_before;
        assert_eq!(direct, 3, "{base}: every client reached OpenBao itself");
    }
    std::fs::remove_file(&jwt).context("remove the JWT fixture")?;
    Ok(())
}
