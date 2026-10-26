use super::*;

/// Ignore ambient service env so parallel configuration tests remain isolated.
fn matches(url: &str, extra: &[&str]) -> Result<clap::ArgMatches> {
    let mut args = vec![
        "genesis",
        "--dsn",
        "postgres://",
        "--socket-path",
        "/tmp/native-config.sock",
        "--vault-url",
        url,
    ];
    args.extend_from_slice(extra);
    Ok(crate::cli::commands::new()
        .mut_args(|arg| arg.env(None::<&str>))
        .try_get_matches_from(args)?)
}

#[test]
fn native_auth_auto_preserves_socket_and_approle_modes() -> Result<()> {
    for url in ["/tmp/vault.sock", "unix:///tmp/vault.sock"] {
        assert!(vault_auth(&matches(url, &[])?)?.is_none());
        assert!(
            vault_auth(&matches(
                url,
                &["--vault-role-id", "ignored", "--vault-secret-id", "ignored"]
            )?)?
            .is_none()
        );
    }
    for method in ["auto", "approle"] {
        assert!(
            vault_auth(&matches(
                "https://vault.example",
                &[
                    "--vault-auth-method",
                    method,
                    "--vault-role-id",
                    "role",
                    "--vault-secret-id",
                    "secret"
                ]
            )?)?
            .is_none()
        );
        assert!(
            vault_auth(&matches(
                "https://vault.example",
                &[
                    "--vault-auth-method",
                    method,
                    "--vault-role-id",
                    "role",
                    "--vault-wrapped-token",
                    "wrapped"
                ]
            )?)?
            .is_none()
        );
        assert!(
            vault_auth(&matches(
                "https://vault.example",
                &["--vault-auth-method", method, "--vault-role-id", "role"]
            )?)
            .is_err()
        );
    }
    Ok(())
}

#[test]
fn native_auth_dispatches_projected_token_without_approle() -> Result<()> {
    let parsed = matches(
        "https://vault.example:8200",
        &[
            "--vault-auth-method",
            "kubernetes",
            "--vault-kubernetes-role",
            "genesis",
            "--vault-kubernetes-auth-mount",
            "cluster/k8s",
            "--vault-kubernetes-token-path",
            "/run/projected/jwt",
        ],
    )?;
    let Action::Server(args) = handler(&parsed)?;
    let config = args
        .vault_kubernetes
        .context("missing Kubernetes login config")?;
    assert_eq!(config.mount, "cluster/k8s");
    assert_eq!(config.role, "genesis");
    assert_eq!(
        config.token_path,
        std::path::PathBuf::from("/run/projected/jwt")
    );
    assert!(args.vault_role_id.is_none());
    assert!(args.vault_secret_id.is_none());
    assert!(args.vault_wrapped_token.is_none());
    Ok(())
}

#[test]
fn native_auth_rejects_missing_role_and_incompatible_credentials() -> Result<()> {
    assert!(
        vault_auth(&matches(
            "https://vault.example",
            &["--vault-auth-method", "kubernetes"]
        )?)
        .is_err()
    );
    for credential in [
        "--vault-role-id",
        "--vault-secret-id",
        "--vault-wrapped-token",
    ] {
        let error = vault_auth(&matches(
            "https://vault.example",
            &[
                "--vault-auth-method",
                "kubernetes",
                "--vault-kubernetes-role",
                "workload",
                credential,
                "secret",
            ],
        )?)
        .err()
        .context("accepted AppRole credential")?;
        assert!(
            error
                .to_string()
                .contains("AppRole credentials are forbidden")
        );
    }
    for method in ["approle", "kubernetes"] {
        let error = vault_auth(&matches(
            "unix:///tmp/vault.sock",
            &["--vault-auth-method", method],
        )?)
        .err()
        .context("accepted explicit auth over Agent")?;
        assert!(error.to_string().contains("requires a TCP"));
    }
    Ok(())
}

#[test]
fn native_auth_rejects_implicit_activation_and_invalid_mounts() -> Result<()> {
    for setting in [
        "--vault-kubernetes-role",
        "--vault-kubernetes-auth-mount",
        "--vault-kubernetes-token-path",
    ] {
        let error = vault_auth(&matches("/tmp/vault.sock", &[setting, "value"])?)
            .err()
            .context("silently ignored Kubernetes setting")?;
        assert!(
            error
                .to_string()
                .contains("require --vault-auth-method kubernetes")
        );
    }
    for mount in ["", "../k8s", "/v1/auth/kubernetes", "k8s?query", "k8s/"] {
        assert!(
            matches(
                "https://vault.example",
                &[
                    "--vault-auth-method",
                    "kubernetes",
                    "--vault-kubernetes-role",
                    "workload",
                    "--vault-kubernetes-auth-mount",
                    mount
                ]
            )
            .is_err()
        );
    }
    for origin in [
        "https://vault.example/v1/auth/approle/login",
        "https://vault.example/?query",
    ] {
        assert!(
            vault_auth(&matches(
                origin,
                &[
                    "--vault-auth-method",
                    "kubernetes",
                    "--vault-kubernetes-role",
                    "workload"
                ]
            )?)
            .is_err()
        );
    }
    Ok(())
}
