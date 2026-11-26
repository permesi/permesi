use crate::cli::actions::{Action, server::Args};
use anyhow::{Context, Result, anyhow};

#[cfg(test)]
mod native_tests;

const ARG_OPENBAO_TRANSIT_MOUNT: &str = "openbao-transit-mount";

/// Normalize an OpenBao mount path received from CLI/env.
///
/// Mounts are stored without leading/trailing slashes and must not be empty
/// after normalization.
fn normalize_openbao_mount(arg: &str, value: &str) -> Result<String> {
    let normalized = value.trim_matches('/').to_string();
    if normalized.is_empty() {
        return Err(anyhow!("invalid argument: --{arg} must not be empty"));
    }
    if normalized.chars().any(char::is_whitespace) {
        return Err(anyhow!(
            "invalid argument: --{arg} must not contain whitespace"
        ));
    }
    Ok(normalized)
}

/// Revalidate auth selection at dispatch; Kubernetes settings never activate fallback.
/// Auto sockets retain Agent behavior, including ignored legacy `AppRole` arguments.
pub(crate) fn openbao_auth(
    matches: &clap::ArgMatches,
) -> Result<Option<openbao_client::kubernetes::KubernetesAuth>> {
    let url = matches
        .get_one::<String>("openbao-url")
        .context("missing --openbao-url")?;
    let target = openbao_client::OpenBaoTarget::parse(url)?;
    let method = matches
        .get_one::<String>("openbao-auth-method")
        .context("missing --openbao-auth-method")?;
    let role_id = matches.get_one::<String>("openbao-role-id");
    let secret_id = matches.get_one::<String>("openbao-secret-id");
    let wrapped = matches.get_one::<String>("openbao-wrapped-token");
    let mount = matches
        .get_one::<String>("openbao-kubernetes-auth-mount")
        .context("missing Kubernetes auth mount")?;
    openbao_client::kubernetes::validate_auth_mount(mount).map_err(|e| anyhow!(e))?;
    let role = matches.get_one::<String>("openbao-kubernetes-role");
    let token_path = matches
        .get_one::<String>("openbao-kubernetes-token-path")
        .context("missing Kubernetes token path")?;
    if token_path.trim().is_empty() {
        return Err(anyhow!("--openbao-kubernetes-token-path must not be empty"));
    }
    if !matches!(method.as_str(), "auto" | "approle" | "kubernetes") {
        return Err(anyhow!("invalid --openbao-auth-method"));
    }
    if method != "auto" && !target.is_tcp() {
        return Err(anyhow!(
            "explicit --openbao-auth-method requires a TCP OpenBao URL"
        ));
    }
    if method == "kubernetes" {
        if role_id.is_some() || secret_id.is_some() || wrapped.is_some() {
            return Err(anyhow!(
                "AppRole credentials are forbidden with --openbao-auth-method kubernetes"
            ));
        }
        let role = role
            .filter(|r| !r.trim().is_empty())
            .context("--openbao-kubernetes-role is required for Kubernetes authentication")?;
        openbao_client::kubernetes::kubernetes_login_url(url, mount)?;
        return Ok(Some(openbao_client::kubernetes::KubernetesAuth {
            mount: mount.clone(),
            role: role.clone(),
            token_path: token_path.into(),
        }));
    }
    if role.is_some()
        || [
            "openbao-kubernetes-auth-mount",
            "openbao-kubernetes-token-path",
        ]
        .iter()
        .any(|arg| {
            matches
                .value_source(arg)
                .is_some_and(|source| source != clap::parser::ValueSource::DefaultValue)
        })
    {
        return Err(anyhow!(
            "Kubernetes settings require --openbao-auth-method kubernetes"
        ));
    }
    if target.is_tcp() {
        if role_id.is_none_or(|r| r.trim().is_empty()) {
            return Err(anyhow!(
                "--openbao-role-id is required for AppRole TCP mode"
            ));
        }
        if secret_id.is_some() && wrapped.is_some() {
            return Err(anyhow!(
                "--openbao-secret-id conflicts with --openbao-wrapped-token"
            ));
        }
        if secret_id.or(wrapped).is_none_or(|s| s.trim().is_empty()) {
            return Err(anyhow!(
                "--openbao-secret-id or --openbao-wrapped-token is required for AppRole TCP mode"
            ));
        }
    }
    Ok(None)
}
/// Construct the service budget from clap-validated limits and recheck all three bounds.
fn work_limits(
    matches: &clap::ArgMatches,
    group: &str,
) -> anyhow::Result<service_utils::work_limit::Limits> {
    let value = |suffix| {
        matches
            .get_one::<u32>(&format!("{group}-{suffix}"))
            .copied()
            .ok_or_else(|| anyhow::anyhow!("missing work limit"))
    };
    service_utils::work_limit::Limits::new(
        value("requests-per-second")?,
        value("burst")?,
        value("max-in-flight")?,
    )
}

/// The issuer and audience written into every admission token, rechecked after clap: an
/// empty or padded value would produce tokens Permesi can never accept.
fn admission_identity(matches: &clap::ArgMatches) -> Result<(String, String)> {
    let value = |name: &str| {
        let value = matches
            .get_one::<String>(name)
            .cloned()
            .with_context(|| format!("missing required argument: --{name}"))?;
        anyhow::ensure!(
            !value.is_empty() && value.trim() == value,
            "--{name} must not be empty or padded with whitespace"
        );
        Ok(value)
    };
    Ok((value("admission-issuer")?, value("admission-audience")?))
}

/// Which peers may supply forwarded client metadata. Trusting the Unix socket peer is
/// refused without a Unix socket: on TCP it would name no peer and silently do nothing.
fn request_metadata(matches: &clap::ArgMatches) -> Result<crate::api::peer::RequestMetadataPolicy> {
    let header = |name: &str| {
        matches
            .get_one::<String>(name)
            .with_context(|| format!("missing required argument: --{name}"))
    };
    let trust_unix_proxy = matches.get_flag("trust-unix-proxy");
    anyhow::ensure!(
        !trust_unix_proxy || matches.get_one::<String>("socket-path").is_some(),
        "--trust-unix-proxy requires --socket-path"
    );
    crate::api::peer::RequestMetadataPolicy::new(
        header("client-ip-header")?,
        header("client-country-header")?,
        matches
            .get_many::<sqlx::types::ipnetwork::IpNetwork>("trusted-proxy")
            .map_or_else(Vec::new, |ranges| ranges.copied().collect()),
        trust_unix_proxy,
    )
}

/// # Errors
/// Returns an error if required arguments are missing or inconsistent.
pub fn handler(matches: &clap::ArgMatches) -> Result<Action> {
    let port = matches.get_one::<u16>("port").copied().unwrap_or(8080);
    let dsn = matches
        .get_one::<String>("dsn")
        .cloned()
        .context("missing required argument: --dsn")?;

    let openbao_url = matches
        .get_one::<String>("openbao-url")
        .cloned()
        .context("missing required argument: --openbao-url")?;
    let openbao_target = crate::openbao::OpenBaoTarget::parse(&openbao_url)
        .context("invalid GENESIS_OPENBAO_URL")?;

    let openbao_kubernetes = openbao_auth(matches)?;

    let openbao_role_id = matches.get_one::<String>("openbao-role-id").cloned();
    let openbao_secret_id = matches.get_one::<String>("openbao-secret-id").cloned();
    let openbao_wrapped_token = matches.get_one::<String>("openbao-wrapped-token").cloned();
    let openbao_transit_mount = matches
        .get_one::<String>(ARG_OPENBAO_TRANSIT_MOUNT)
        .cloned()
        .context("missing required argument: --openbao-transit-mount")?;
    let openbao_transit_mount =
        normalize_openbao_mount(ARG_OPENBAO_TRANSIT_MOUNT, &openbao_transit_mount)?;
    let tls_pem_bundle = matches.get_one::<String>("tls-pem-bundle").cloned();
    let socket_path = matches.get_one::<String>("socket-path").cloned();

    let db_pool = crate::cli::commands::database::parse(matches)?;

    let signing_version = matches
        .get_one::<u32>("admission-signing-version")
        .copied()
        .filter(|version| *version > 0)
        .context("expected a positive admission signing version")?;
    let (admission_issuer, admission_audience) = admission_identity(matches)?;
    Ok(Action::Server(Args {
        signing_version,
        admission_issuer,
        admission_audience,
        metadata: request_metadata(matches)?,
        public_limits: work_limits(matches, "public")?,

        port,
        socket_path,
        dsn,
        db_pool,
        openbao_url,
        openbao_target,
        openbao_kubernetes,
        openbao_role_id,
        openbao_secret_id,
        openbao_wrapped_token,
        openbao_transit_mount,
        tls_pem_bundle,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transit_mount_is_normalized_in_dispatch() {
        let command = crate::cli::commands::new();
        let matches = command.get_matches_from(vec![
            "genesis",
            "--dsn",
            "postgres://",
            "--tls-pem-bundle",
            "bundle",
            "--openbao-url",
            "http://openbao:8200",
            "--openbao-role-id",
            "role",
            "--openbao-secret-id",
            "secret",
            "--openbao-transit-mount",
            "/transit/genesis/",
        ]);

        let action = handler(&matches);
        assert!(action.is_ok(), "dispatch should succeed");
        if let Ok(Action::Server(args)) = action {
            assert_eq!(args.openbao_transit_mount, "transit/genesis");
        }
    }

    const BASE: [&str; 11] = [
        "genesis",
        "--dsn",
        "postgres://",
        "--tls-pem-bundle",
        "bundle",
        "--openbao-url",
        "http://openbao:8200",
        "--openbao-role-id",
        "role",
        "--openbao-secret-id",
        "secret",
    ];

    fn dispatch(extra: &[&str]) -> anyhow::Result<Args> {
        let matches = crate::cli::commands::new()
            .try_get_matches_from(BASE.iter().chain(extra))
            .map_err(|error| anyhow::anyhow!("{}", error.kind()))?;
        let Action::Server(args) = handler(&matches)?;
        Ok(args)
    }

    /// The four settings Genesis used to read from the environment at request time are
    /// CLI configuration now: defaults, overrides and refusals all happen at startup.
    #[test]
    fn admission_identity_and_client_metadata_are_cli_settings() -> anyhow::Result<()> {
        temp_env::with_vars(
            [
                ("GENESIS_ADMISSION_ISS", None::<&str>),
                ("GENESIS_ADMISSION_AUD", None),
                ("GENESIS_IP_HEADER", None),
                ("GENESIS_COUNTRY_HEADER", None),
                ("GENESIS_TRUSTED_PROXIES", None),
                ("GENESIS_TRUST_UNIX_PROXY", None),
                ("GENESIS_SOCKET_PATH", None),
            ],
            || {
                let defaults = dispatch(&[])?;
                assert_eq!(defaults.admission_issuer, "https://genesis.permesi.dev");
                assert_eq!(defaults.admission_audience, "permesi");
                assert_eq!(
                    defaults.metadata.summary(),
                    "address=cf-connecting-ip country=cf-ipcountry trusted_proxies=none trust_unix_proxy=false"
                );

                let set = dispatch(&[
                    "--admission-issuer",
                    "https://genesis.example.test",
                    "--admission-audience",
                    "core",
                    "--client-ip-header",
                    "X-Real-IP",
                    "--client-country-header",
                    "X-Country",
                    "--trusted-proxy",
                    "192.0.2.0/24,2001:db8::/32",
                ])?;
                assert_eq!(set.admission_issuer, "https://genesis.example.test");
                assert_eq!(set.admission_audience, "core");
                assert_eq!(
                    set.metadata.summary(),
                    "address=x-real-ip country=x-country trusted_proxies=192.0.2.0/24,2001:db8::/32 trust_unix_proxy=false"
                );

                for refused in [
                    &["--admission-issuer", ""][..],
                    &["--admission-audience", " permesi"],
                    &["--client-ip-header", "bad name"],
                    &["--client-country-header", ""],
                    &["--trusted-proxy", "attacker.example"],
                    &["--trusted-proxy", "192.0.2.0/33"],
                    // Meaningless on a TCP listener, so it is not accepted there.
                    &["--trust-unix-proxy"],
                ] {
                    assert!(dispatch(refused).is_err(), "{refused:?}");
                }
                anyhow::Ok(())
            },
        )?;

        // The environment names operators already use keep working.
        temp_env::with_vars(
            [
                ("GENESIS_ADMISSION_ISS", Some("https://edge.example.test")),
                ("GENESIS_ADMISSION_AUD", Some("iam")),
                ("GENESIS_IP_HEADER", Some("X-Client-IP")),
                ("GENESIS_COUNTRY_HEADER", Some("X-Client-Country")),
                ("GENESIS_TRUSTED_PROXIES", Some("10.0.0.0/8")),
                ("GENESIS_TRUST_UNIX_PROXY", None),
                ("GENESIS_SOCKET_PATH", None),
            ],
            || {
                let args = dispatch(&[])?;
                assert_eq!(args.admission_issuer, "https://edge.example.test");
                assert_eq!(args.admission_audience, "iam");
                assert_eq!(
                    args.metadata.summary(),
                    "address=x-client-ip country=x-client-country trusted_proxies=10.0.0.0/8 trust_unix_proxy=false"
                );
                anyhow::Ok(())
            },
        )
    }

    #[test]
    fn unix_proxy_trust_is_accepted_with_a_unix_socket() -> anyhow::Result<()> {
        // A developer shell can export the TCP listener's settings, which conflict with
        // a Unix socket; the test supplies everything it needs itself.
        temp_env::with_vars_unset(
            [
                "GENESIS_TLS_PEM_BUNDLE",
                "GENESIS_PORT",
                "GENESIS_OPENBAO_ROLE_ID",
                "GENESIS_OPENBAO_SECRET_ID",
                "GENESIS_OPENBAO_WRAPPED_TOKEN",
                "GENESIS_OPENBAO_AUTH_METHOD",
            ],
            || {
                let matches = crate::cli::commands::new().try_get_matches_from([
                    "genesis",
                    "--dsn",
                    "postgres://",
                    "--socket-path",
                    "/run/genesis/genesis.sock",
                    "--openbao-url",
                    "/run/openbao/agent.sock",
                    "--trust-unix-proxy",
                ])?;
                let Action::Server(args) = handler(&matches)?;
                assert!(args.metadata.summary().ends_with("trust_unix_proxy=true"));
                Ok(())
            },
        )
    }

    #[test]
    fn empty_transit_mount_is_rejected() {
        let command = crate::cli::commands::new();
        let matches = command.get_matches_from(vec![
            "genesis",
            "--dsn",
            "postgres://",
            "--tls-pem-bundle",
            "bundle",
            "--openbao-url",
            "http://openbao:8200",
            "--openbao-role-id",
            "role",
            "--openbao-secret-id",
            "secret",
            "--openbao-transit-mount",
            "///",
        ]);

        let result = handler(&matches);
        assert!(result.is_err(), "expected validation error");
        if let Err(err) = result {
            assert!(err.to_string().contains("--openbao-transit-mount"));
        }
    }
}
