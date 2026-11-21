use super::*;

/// Ignore ambient service env so parallel configuration tests remain isolated.
fn matches(url: &str, extra: &[&str]) -> Result<clap::ArgMatches> {
    let mut args = vec![
        "genesis",
        "--dsn",
        "postgres://",
        "--socket-path",
        "/tmp/native-config.sock",
        "--openbao-url",
        url,
    ];
    args.extend_from_slice(extra);
    Ok(crate::cli::commands::new()
        .mut_args(|arg| arg.env(None::<&str>))
        .try_get_matches_from(args)?)
}

#[test]
fn native_auth_auto_preserves_socket_and_approle_modes() -> Result<()> {
    for url in ["/tmp/openbao.sock", "unix:///tmp/openbao.sock"] {
        assert!(openbao_auth(&matches(url, &[])?)?.is_none());
        assert!(
            openbao_auth(&matches(
                url,
                &[
                    "--openbao-role-id",
                    "ignored",
                    "--openbao-secret-id",
                    "ignored"
                ]
            )?)?
            .is_none()
        );
    }
    for method in ["auto", "approle"] {
        assert!(
            openbao_auth(&matches(
                "https://openbao.example",
                &[
                    "--openbao-auth-method",
                    method,
                    "--openbao-role-id",
                    "role",
                    "--openbao-secret-id",
                    "secret"
                ]
            )?)?
            .is_none()
        );
        assert!(
            openbao_auth(&matches(
                "https://openbao.example",
                &[
                    "--openbao-auth-method",
                    method,
                    "--openbao-role-id",
                    "role",
                    "--openbao-wrapped-token",
                    "wrapped"
                ]
            )?)?
            .is_none()
        );
        assert!(
            openbao_auth(&matches(
                "https://openbao.example",
                &["--openbao-auth-method", method, "--openbao-role-id", "role"]
            )?)
            .is_err()
        );
    }
    Ok(())
}

#[test]
fn native_auth_dispatches_projected_token_without_approle() -> Result<()> {
    let parsed = matches(
        "https://openbao.example:8200",
        &[
            "--openbao-auth-method",
            "kubernetes",
            "--openbao-kubernetes-role",
            "genesis",
            "--openbao-kubernetes-auth-mount",
            "cluster/k8s",
            "--openbao-kubernetes-token-path",
            "/run/projected/jwt",
        ],
    )?;
    let Action::Server(args) = handler(&parsed)?;
    let config = args
        .openbao_kubernetes
        .context("missing Kubernetes login config")?;
    assert_eq!(config.mount, "cluster/k8s");
    assert_eq!(config.role, "genesis");
    assert_eq!(
        config.token_path,
        std::path::PathBuf::from("/run/projected/jwt")
    );
    assert!(args.openbao_role_id.is_none());
    assert!(args.openbao_secret_id.is_none());
    assert!(args.openbao_wrapped_token.is_none());
    Ok(())
}

#[test]
fn native_auth_rejects_missing_role_and_incompatible_credentials() -> Result<()> {
    assert!(
        openbao_auth(&matches(
            "https://openbao.example",
            &["--openbao-auth-method", "kubernetes"]
        )?)
        .is_err()
    );
    for credential in [
        "--openbao-role-id",
        "--openbao-secret-id",
        "--openbao-wrapped-token",
    ] {
        let error = openbao_auth(&matches(
            "https://openbao.example",
            &[
                "--openbao-auth-method",
                "kubernetes",
                "--openbao-kubernetes-role",
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
        let error = openbao_auth(&matches(
            "unix:///tmp/openbao.sock",
            &["--openbao-auth-method", method],
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
        "--openbao-kubernetes-role",
        "--openbao-kubernetes-auth-mount",
        "--openbao-kubernetes-token-path",
    ] {
        let error = openbao_auth(&matches("/tmp/openbao.sock", &[setting, "value"])?)
            .err()
            .context("silently ignored Kubernetes setting")?;
        assert!(
            error
                .to_string()
                .contains("require --openbao-auth-method kubernetes")
        );
    }
    for mount in ["", "../k8s", "/v1/auth/kubernetes", "k8s?query", "k8s/"] {
        assert!(
            matches(
                "https://openbao.example",
                &[
                    "--openbao-auth-method",
                    "kubernetes",
                    "--openbao-kubernetes-role",
                    "workload",
                    "--openbao-kubernetes-auth-mount",
                    mount
                ]
            )
            .is_err()
        );
    }
    for origin in [
        "https://openbao.example/v1/auth/approle/login",
        "https://openbao.example/?query",
    ] {
        assert!(
            openbao_auth(&matches(
                origin,
                &[
                    "--openbao-auth-method",
                    "kubernetes",
                    "--openbao-kubernetes-role",
                    "workload"
                ]
            )?)
            .is_err()
        );
    }
    Ok(())
}
