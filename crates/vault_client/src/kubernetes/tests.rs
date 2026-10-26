use super::*;
use serde_json::json;
use std::{fs, os::unix::fs::symlink};
use uuid::Uuid;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_json, method, path},
};

struct JwtFixture {
    directory: PathBuf,
    config: KubernetesAuth,
}

impl JwtFixture {
    fn new() -> Result<Self> {
        let directory = std::env::temp_dir().join(format!("vault-kubernetes-{}", Uuid::new_v4()));
        fs::create_dir(&directory)?;
        let token_path = directory.join("token");
        fs::write(&token_path, "projected-jwt")?;
        Ok(Self {
            config: KubernetesAuth {
                mount: "team/kubernetes".to_string(),
                role: "workload".to_string(),
                token_path,
            },
            directory,
        })
    }
}

impl Drop for JwtFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

fn login_response() -> Value {
    json!({"auth": {"client_token": "hvs.secret", "lease_duration": 120, "renewable": true}})
}

#[test]
fn auth_mount_rejects_ambiguous_and_traversal_paths() {
    for mount in [
        "",
        "/",
        "/kubernetes",
        "kubernetes/",
        "a//b",
        ".",
        "..",
        "a/../b",
        "a/./b",
        "/v1/auth/kubernetes",
        "v1/auth/kubernetes",
        "auth/kubernetes",
        "a?b",
        "a#b",
        "a%2fb",
        "a\\b",
        "a b",
        "a\nb",
        "https://vault",
    ] {
        assert!(validate_auth_mount(mount).is_err(), "accepted {mount:?}");
    }
    for mount in ["kubernetes", "cluster-1/k8s_auth.v2"] {
        assert_eq!(validate_auth_mount(mount), Ok(mount.to_string()));
    }
}

#[test]
fn kubernetes_endpoint_requires_unambiguous_vault_origin() -> Result<()> {
    assert_eq!(
        kubernetes_login_url("https://vault.example:8200/", "team/kubernetes")?,
        "https://vault.example:8200/v1/auth/team/kubernetes/login"
    );
    assert_eq!(
        kubernetes_login_url("http://[::1]:8200", "kubernetes")?,
        "http://[::1]:8200/v1/auth/kubernetes/login"
    );
    for origin in [
        "unix:///tmp/vault.sock",
        "file:///tmp/a",
        "not a url",
        "https://vault/path",
        "https://vault/?jwt=secret",
        "https://vault/#secret",
        "https://user:password@vault/",
    ] {
        assert!(kubernetes_login_url(origin, "kubernetes").is_err());
    }
    Ok(())
}

#[tokio::test]
async fn kubernetes_login_posts_role_and_current_projected_jwt() -> Result<()> {
    let server = MockServer::start().await;
    let fixture = JwtFixture::new()?;
    fs::remove_file(&fixture.config.token_path)?;
    fs::write(fixture.directory.join("version-1"), "first-jwt\n")?;
    fs::write(fixture.directory.join("version-2"), "second-jwt\n")?;
    symlink("version-1", &fixture.config.token_path)?;
    for jwt in ["first-jwt", "second-jwt"] {
        Mock::given(method("POST"))
            .and(path("/v1/auth/team/kubernetes/login"))
            .and(body_json(json!({"role": "workload", "jwt": jwt})))
            .respond_with(ResponseTemplate::new(200).set_body_json(login_response()))
            .expect(1)
            .mount(&server)
            .await;
    }
    let (token, lease) = kubernetes_login("test", &server.uri(), &fixture.config).await?;
    assert_eq!(token.expose_secret(), "hvs.secret");
    assert_eq!(lease, 120);
    symlink("version-2", fixture.directory.join("next-token"))?;
    fs::rename(
        fixture.directory.join("next-token"),
        &fixture.config.token_path,
    )?;
    let (token, lease) = kubernetes_login("test", &server.uri(), &fixture.config).await?;
    assert_eq!(token.expose_secret(), "hvs.secret");
    assert_eq!(lease, 120);
    Ok(())
}

#[tokio::test]
async fn kubernetes_login_rejects_unreadable_and_empty_jwt_before_request() -> Result<()> {
    let server = MockServer::start().await;
    let fixture = JwtFixture::new()?;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;
    for bytes in [b"".as_slice(), b" \n\t".as_slice(), &[0xff]] {
        fs::write(&fixture.config.token_path, bytes)?;
        let error = kubernetes_login("test", &server.uri(), &fixture.config)
            .await
            .err()
            .ok_or_else(|| anyhow!("accepted invalid JWT file"))?;
        assert!(error.to_string().contains("JWT file"));
    }
    fs::remove_file(&fixture.config.token_path)?;
    let error = kubernetes_login("test", &server.uri(), &fixture.config)
        .await
        .err()
        .ok_or_else(|| anyhow!("accepted missing JWT"))?;
    assert!(error.to_string().contains("could not read"));
    Ok(())
}

#[tokio::test]
async fn kubernetes_login_rejects_invalid_token_lease_and_renewability() -> Result<()> {
    let server = MockServer::start().await;
    let fixture = JwtFixture::new()?;
    let invalid = [
        json!({}),
        json!({"auth": {"client_token": "", "lease_duration": 120, "renewable": true}}),
        json!({"auth": {"client_token": "hvs.\nsecret", "lease_duration": 120, "renewable": true}}),
        json!({"auth": {"client_token": "hvs.secret", "lease_duration": 0, "renewable": true}}),
        json!({"auth": {"client_token": "hvs.secret", "lease_duration": -1, "renewable": true}}),
        json!({"auth": {"client_token": "hvs.secret", "lease_duration": "120", "renewable": true}}),
        json!({"auth": {"client_token": "hvs.secret", "renewable": true}}),
        json!({"auth": {"client_token": "hvs.secret", "lease_duration": 120, "renewable": false}}),
        json!({"auth": {"client_token": "hvs.secret", "lease_duration": 120}}),
    ];
    for body in invalid {
        server.reset().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .expect(1)
            .mount(&server)
            .await;
        let error = kubernetes_login("test", &server.uri(), &fixture.config)
            .await
            .err()
            .ok_or_else(|| anyhow!("accepted invalid login response"))?;
        let error = format!("{error:?}");
        assert!(!error.contains("hvs.secret"));
        assert!(!error.contains("projected-jwt"));
    }
    Ok(())
}

#[tokio::test]
async fn kubernetes_login_redacts_remote_errors_and_malformed_responses() -> Result<()> {
    let server = MockServer::start().await;
    let fixture = JwtFixture::new()?;
    for (status, body) in [
        (403, r#"{"errors":["projected-jwt hvs.secret"]}"#),
        (500, "projected-jwt hvs.secret"),
        (200, "projected-jwt hvs.secret"),
    ] {
        server.reset().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(status).set_body_string(body))
            .expect(1)
            .mount(&server)
            .await;
        let error = kubernetes_login("test", &server.uri(), &fixture.config)
            .await
            .err()
            .ok_or_else(|| anyhow!("accepted invalid response"))?;
        let message = format!("{error:?}");
        assert!(!message.contains("projected-jwt"));
        assert!(!message.contains("hvs.secret"));
        assert!(message.contains(if status == 200 {
            "invalid Vault Kubernetes login response"
        } else {
            "Vault Kubernetes login rejected"
        }));
    }
    Ok(())
}

#[tokio::test]
async fn kubernetes_login_refuses_redirect_without_forwarding_jwt() -> Result<()> {
    let vault = MockServer::start().await;
    let attacker = MockServer::start().await;
    let fixture = JwtFixture::new()?;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(login_response()))
        .expect(0)
        .mount(&attacker)
        .await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(307).insert_header("Location", attacker.uri()))
        .expect(1)
        .mount(&vault)
        .await;
    let error = kubernetes_login("test", &vault.uri(), &fixture.config)
        .await
        .err()
        .ok_or_else(|| anyhow!("followed redirect"))?;
    assert!(error.to_string().contains("307"));
    Ok(())
}
