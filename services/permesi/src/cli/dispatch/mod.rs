//! Command-line argument dispatch and server initialization.
//!
//! This module parses validated CLI arguments and maps them to the appropriate
//! action, such as starting the API server with its full configuration state.

use crate::cli::actions::{Action, server::Args};
use crate::cli::commands::{admission, auth, database, openbao, tls};
use anyhow::{Context, Result, anyhow};

#[cfg(test)]
mod native_tests;

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

fn require_positive(arg: &str, value: i64) -> Result<i64> {
    if value > 0 {
        Ok(value)
    } else {
        Err(anyhow!(
            "invalid argument: --{arg} must be greater than zero"
        ))
    }
}

/// Resolves trusted RP/origin defaults and revalidates clap-defined `WebAuthn` policy.
fn passkey_config(
    matches: &clap::ArgMatches,
    options: &auth::Options,
) -> Result<crate::webauthn::PasskeyConfig> {
    // Revalidate clap settings and resolve implicit RP/origin defaults from trusted auth configuration.
    let base_auth = crate::api::handlers::auth::AuthConfig::new(options.frontend_base_url.clone())
        .with_cors_allowed_origins(options.cors_allowed_origins.clone());
    crate::webauthn::PasskeyConfig::new(
        matches
            .get_one::<String>("passkeys-rp-id")
            .cloned()
            .unwrap_or_else(|| base_auth.webauthn_rp_id().to_owned()),
        matches
            .get_one::<String>("passkeys-rp-name")
            .cloned()
            .context("missing passkey RP name")?,
        matches
            .get_one::<String>("passkeys-allowed-origins")
            .map_or_else(
                || base_auth.webauthn_allowed_origins(),
                |s| Ok(s.split(',').map(|v| v.trim().to_owned()).collect()),
            )?,
        std::time::Duration::from_secs(
            *matches
                .get_one::<u64>("passkeys-challenge-ttl-seconds")
                .context("missing passkey TTL")?,
        ),
        *matches
            .get_one::<bool>("passkeys-preview-mode")
            .context("missing passkey preview policy")?,
    )
}

/// Reads the clap-validated MFA requirement; an unparseable value never reaches here.
fn mfa_required(matches: &clap::ArgMatches) -> Result<bool> {
    matches
        .get_one::<bool>("mfa-required")
        .copied()
        .context("missing MFA requirement policy")
}

/// Revalidates tenant budgets, slug attempts and deadline ordering after clap parsing.
fn tenant_mutation_policy(
    matches: &clap::ArgMatches,
) -> Result<crate::api::tenant::MutationPolicy> {
    crate::api::tenant::MutationPolicy::new(
        *matches
            .get_one::<i64>("tenant-lock-timeout-ms")
            .context("missing tenant lock timeout")?,
        *matches
            .get_one::<u64>("tenant-mutation-timeout-ms")
            .context("missing tenant mutation timeout")?,
        *matches
            .get_one::<u16>("tenant-slug-attempts")
            .context("missing tenant slug attempts")?,
    )
}

/// Rechecks the challenge budget after clap so programmatic matches cannot bypass bounds.
fn mfa_challenge_limit(matches: &clap::ArgMatches) -> Result<i32> {
    let limit = *matches
        .get_one::<i32>("mfa-challenge-max-attempts")
        .context("missing MFA challenge attempt limit")?;
    if !(1..=20).contains(&limit) {
        return Err(anyhow!("invalid MFA challenge attempt limit"));
    }
    Ok(limit)
}

/// Revalidates pending-state capacity against both process and PostgreSQL integer bounds.
fn pending_state_limit(value: u64) -> Result<usize> {
    let auth_max_pending_states = usize::try_from(value)
        .context("--auth-max-pending-states exceeds this platform's capacity")?;
    if auth_max_pending_states == 0 {
        return Err(anyhow!(
            "invalid argument: --{} must be greater than zero",
            auth::ARG_AUTH_MAX_PENDING_STATES
        ));
    }
    i64::try_from(auth_max_pending_states)
        .context("--auth-max-pending-states exceeds PostgreSQL capacity")?;
    Ok(auth_max_pending_states)
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

/// Recheck the clock-skew allowance on admission tokens: it only moves the earliest
/// acceptable issue time, and stays far below the 60 second minimum token lifetime.
fn admission_iat_leeway(matches: &clap::ArgMatches) -> Result<i64> {
    let leeway = *matches
        .get_one::<i64>("admission-iat-leeway-seconds")
        .context("missing admission issue-time leeway")?;
    anyhow::ensure!(
        (0..=admission_token::MAX_IAT_LEEWAY_SECONDS).contains(&leeway),
        "admission issue-time leeway must be between 0 and 30 seconds"
    );
    Ok(leeway)
}

/// Recheck the refresh interval against the maximum withdrawal window at startup.
fn admission_timing(
    matches: &clap::ArgMatches,
) -> Result<(std::time::Duration, std::time::Duration)> {
    let refresh = *matches
        .get_one::<u64>("admission-refresh-seconds")
        .context("missing admission refresh interval")?;
    let max_age = *matches
        .get_one::<u64>("admission-max-age-seconds")
        .context("missing admission maximum age")?;
    anyhow::ensure!(
        refresh > 0 && refresh < max_age && max_age <= 60,
        "admission refresh must precede the maximum age of at most 60 seconds"
    );
    Ok((
        std::time::Duration::from_secs(refresh),
        std::time::Duration::from_secs(max_age),
    ))
}

/// Recheck the timeout and lifetime of persisted OPAQUE exchanges before dispatch.
fn validate_opaque_limits(auth_opts: &auth::Options) -> Result<()> {
    if !(1..=3600).contains(&auth_opts.opaque.login_ttl_seconds) {
        return Err(anyhow!(
            "invalid argument: --{} must be between 1 and 3600",
            auth::ARG_OPAQUE_LOGIN_TTL
        ));
    }
    if !(1..=10_000).contains(&auth_opts.opaque.exchange_timeout_ms) {
        return Err(anyhow!(
            "invalid argument: --{} must be between 1 and 10000",
            auth::ARG_OPAQUE_EXCHANGE_TIMEOUT
        ));
    }
    Ok(())
}

/// Rechecks the operator elevation lifetime after clap. Outside the range every
/// elevation would be refused, so the server does not start with such a value.
fn admin_ttl(value: i64) -> Result<i64> {
    if auth::PLATFORM_ADMIN_TTL_RANGE.contains(&value) {
        Ok(value)
    } else {
        Err(anyhow!(
            "invalid argument: --{} must be between {} and {}",
            auth::ARG_PLATFORM_ADMIN_TTL,
            auth::PLATFORM_ADMIN_TTL_RANGE.start(),
            auth::PLATFORM_ADMIN_TTL_RANGE.end()
        ))
    }
}

/// Refuse a clear-text OpenBao address unless the host is loopback or the operator opted
/// in, and say so on every start when the opt-in is what let the address through.
fn require_encrypted_openbao(
    matches: &clap::ArgMatches,
    target: &openbao_client::OpenBaoTarget,
) -> Result<()> {
    let allow_insecure_http = matches.get_flag("openbao-allow-insecure-http");
    target.require_encrypted_transport(allow_insecure_http)?;
    if allow_insecure_http && target.require_encrypted_transport(false).is_err() {
        // Error level is the default verbosity; this must show on every start.
        tracing::error!(
            "OpenBao is reached over plain http: tokens and secrets cross the network in \
             clear text (--openbao-allow-insecure-http)"
        );
    }
    Ok(())
}

/// The HTTP deadlines, checked against the token endpoint's own. That endpoint answers
/// a slow exchange in the OAuth error format when its deadline passes; a request timeout
/// at or below that deadline would cut the request off first, with the generic answer.
fn http_limits(
    matches: &clap::ArgMatches,
    oauth: &crate::oauth::config::OAuthConfig,
) -> Result<service_utils::http_limits::HttpLimits> {
    let http = crate::cli::commands::http::parse(matches)?;
    anyhow::ensure!(
        http.request_timeout() > std::time::Duration::from_millis(oauth.tokens.timeout_ms),
        "--request-timeout-seconds must be longer than --oauth-token-timeout-ms"
    );
    Ok(http)
}

/// Map validated CLI matches to a server action.
///
/// # Errors
/// Returns an error if required arguments are missing or inconsistent.
pub fn handler(matches: &clap::ArgMatches) -> Result<Action> {
    let port = matches.get_one::<u16>("port").copied().unwrap_or(8080);
    let dsn = matches
        .get_one::<String>("dsn")
        .cloned()
        .context("missing required argument: --dsn")?;

    let openbao_kubernetes = openbao_auth(matches)?;

    let openbao_opts = openbao::Options::parse(matches)?;
    let openbao_kv_mount =
        normalize_openbao_mount(openbao::ARG_OPENBAO_KV_MOUNT, &openbao_opts.kv_mount)?;
    let openbao_transit_mount = normalize_openbao_mount(
        openbao::ARG_OPENBAO_TRANSIT_MOUNT,
        &openbao_opts.transit_mount,
    )?;
    let openbao_target = openbao_client::OpenBaoTarget::parse(&openbao_opts.url)
        .context("invalid PERMESI_OPENBAO_URL")?;
    require_encrypted_openbao(matches, &openbao_target)?;

    let admission_opts = admission::Options::parse(matches)?;
    let auth_opts = auth::Options::parse(matches)?;
    validate_opaque_limits(&auth_opts)?;
    let auth_max_pending_states = pending_state_limit(auth_opts.max_pending_states)?;
    let auth_rate_limit_window_seconds = require_positive(
        auth::ARG_AUTH_RATE_LIMIT_WINDOW,
        auth_opts.rate_limit.window_seconds,
    )?;
    let auth_rate_limit_ip_attempts = require_positive(
        auth::ARG_AUTH_RATE_LIMIT_IP_ATTEMPTS,
        auth_opts.rate_limit.ip_attempts,
    )?;
    let auth_rate_limit_account_attempts = require_positive(
        auth::ARG_AUTH_RATE_LIMIT_ACCOUNT_ATTEMPTS,
        auth_opts.rate_limit.account_attempts,
    )?;
    let passkeys = passkey_config(matches, &auth_opts)?;
    let mfa_challenge_max_attempts = mfa_challenge_limit(matches)?;
    let tls_opts = tls::Options::parse(matches)?;
    let socket_path = matches.get_one::<String>("socket-path").cloned();

    let db_pool = database::parse(matches)?;
    let database = database::connection_target(matches, &dsn)?;
    let oauth = crate::oauth::config::OAuthConfig::from_matches(matches)?;
    let http = http_limits(matches, &oauth)?;
    let tenant_mutations = tenant_mutation_policy(matches)?;

    let registration = crate::api::handlers::auth::registration::Policy::from_matches(matches)?;
    let email_delivery = crate::api::email::DeliveryConfig::from_matches(matches)?;
    let (admission_refresh, admission_max_age) = admission_timing(matches)?;
    let admission_iat_leeway = admission_iat_leeway(matches)?;
    Ok(Action::Server(Args {
        public_limits: work_limits(matches, "public")?,
        protocol_limits: work_limits(matches, "protocol")?,

        registration,
        email_delivery,
        port,
        socket_path,
        dsn,
        database,
        db_pool,
        http,
        oauth,
        tenant_mutations,
        openbao_url: openbao_opts.url,
        openbao_target,
        openbao_kubernetes,
        openbao_role_id: openbao_opts.role_id,
        openbao_secret_id: openbao_opts.secret_id,
        openbao_wrapped_token: openbao_opts.wrapped_token,
        admission_refresh,
        admission_max_age,
        admission_iat_leeway,
        admission_issuer: admission_opts.issuer,
        admission_audience: admission_opts.audience,
        tls_pem_bundle: tls_opts.map(|o| o.pem_bundle),
        frontend_base_url: auth_opts.frontend_base_url,
        cors_allowed_origins: auth_opts.cors_allowed_origins,
        email_token_ttl_seconds: auth_opts.email_token_ttl_seconds,
        email_resend_cooldown_seconds: auth_opts.email_resend_cooldown_seconds,
        session_ttl_seconds: auth_opts.session_ttl_seconds,
        email_outbox_poll_seconds: auth_opts.email_outbox.poll_seconds,
        email_outbox_batch_size: auth_opts.email_outbox.batch_size,
        email_outbox_max_attempts: auth_opts.email_outbox.max_attempts,
        email_outbox_backoff_base_seconds: auth_opts.email_outbox.backoff_base_seconds,
        email_outbox_backoff_max_seconds: auth_opts.email_outbox.backoff_max_seconds,
        passkeys,
        mfa_challenge_max_attempts,
        mfa_required: mfa_required(matches)?,
        opaque_server_id: auth_opts.opaque.server_id,
        opaque_login_ttl_seconds: auth_opts.opaque.login_ttl_seconds,
        opaque_exchange_timeout_ms: auth_opts.opaque.exchange_timeout_ms,
        auth_max_pending_states,
        auth_operations: crate::api::handlers::auth::operations::OperationsConfig::from_matches(
            matches,
        )?,
        auth_rate_limit_window_seconds,
        auth_rate_limit_ip_attempts,
        auth_rate_limit_account_attempts,
        platform_admin_ttl_seconds: admin_ttl(auth_opts.admin.ttl_seconds)?,
        platform_recent_auth_seconds: auth_opts.admin.recent_auth_seconds,
        openbao_kv_mount,
        openbao_kv_path: openbao_opts.kv_path,
        openbao_transit_mount,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// With a request timeout at or below the token endpoint's deadline the generic
    /// timeout answered first, without the OAuth error format or its cache headers.
    #[test]
    fn request_timeout_must_exceed_the_token_endpoint_deadline() {
        let start = |extra: &[&str]| {
            let matches = crate::cli::commands::new().try_get_matches_from(
                [
                    "permesi",
                    "--tls-pem-bundle",
                    "bundle",
                    "--openbao-role-id",
                    "role",
                    "--openbao-secret-id",
                    "secret",
                    "--openbao-url",
                    "https://openbao.internal:8200",
                    "--dsn",
                    "postgres://localhost/app",
                ]
                .into_iter()
                .chain(extra.iter().copied()),
            );
            matches
                .map_err(|error| error.kind().to_string())
                .and_then(|matches| handler(&matches).map(|_| ()).map_err(|e| format!("{e:#}")))
        };
        temp_env::with_vars_unset(
            [
                "PERMESI_SOCKET_PATH",
                "PERMESI_REQUEST_TIMEOUT_SECONDS",
                "PGHOST",
                "PGHOSTADDR",
                "PGSSLMODE",
            ],
            || {
                assert_eq!(start(&[]), Ok(()));
                assert_eq!(
                    start(&[
                        "--request-timeout-seconds",
                        "6",
                        "--header-read-timeout-seconds",
                        "5"
                    ]),
                    Ok(())
                );
                for refused in [
                    &[
                        "--request-timeout-seconds",
                        "5",
                        "--header-read-timeout-seconds",
                        "5",
                    ][..],
                    &[
                        "--request-timeout-seconds",
                        "1",
                        "--header-read-timeout-seconds",
                        "1",
                    ],
                    &[
                        "--oauth-token-timeout-ms",
                        "30000",
                        "--request-timeout-seconds",
                        "30",
                    ],
                ] {
                    let error = start(refused).err().unwrap_or_default();
                    assert!(
                        error.contains("--oauth-token-timeout-ms"),
                        "{refused:?}: {error}"
                    );
                }
            },
        );
    }

    /// Dispatch repeats clap's bound, so a value that reaches it another way still cannot
    /// start a server on which no elevation would ever succeed.
    #[test]
    fn admin_ttl_is_rechecked_after_clap() {
        for value in [i64::MIN, -1, 0, 46_801, i64::MAX] {
            let refused = admin_ttl(value).map_err(|error| error.to_string());
            assert_eq!(
                refused,
                Err(
                    "invalid argument: --platform-admin-ttl-seconds must be between 1 and 46800"
                        .to_string()
                ),
                "{value}"
            );
        }
        for value in [1, 43_200, 46_800] {
            assert_eq!(admin_ttl(value).ok(), Some(value));
        }
    }

    /// Collects what is logged at the service's default level while a closure runs.
    fn logged_at_default_level(run: impl FnOnce()) -> String {
        #[derive(Clone, Default)]
        struct Captured(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
        impl std::io::Write for Captured {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                if let Ok(mut buffer) = self.0.lock() {
                    buffer.extend_from_slice(bytes);
                }
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let captured = Captured::default();
        let writer = captured.clone();
        // ERROR is what the service logs when no verbosity is asked for.
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::ERROR)
            .with_ansi(false)
            .with_writer(move || writer.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, run);
        let bytes = captured
            .0
            .lock()
            .map_or_else(|_| Vec::new(), |buffer| buffer.clone());
        String::from_utf8_lossy(&bytes).into_owned()
    }

    /// An opt-out that is in effect is announced on every start, and it has to be seen.
    /// The notices were logged as warnings, which the default level drops, so a service
    /// started without `-v` said nothing. An opt-out that changes nothing stays silent.
    #[test]
    fn effective_transport_opt_outs_are_announced_at_the_default_log_level() {
        const OPENBAO_NOTICE: &str = "--openbao-allow-insecure-http";
        const DATABASE_NOTICE: &str = "--db-allow-unverified-tls";
        let start = |openbao: &str, dsn: &str| {
            let matches = crate::cli::commands::new().try_get_matches_from([
                "permesi",
                "--tls-pem-bundle",
                "bundle",
                "--openbao-role-id",
                "role",
                "--openbao-secret-id",
                "role-secret",
                "--openbao-url",
                openbao,
                "--dsn",
                dsn,
                "--openbao-allow-insecure-http",
                "--db-allow-unverified-tls",
            ]);
            assert!(matches.is_ok_and(|matches| handler(&matches).is_ok()));
        };
        temp_env::with_vars_unset(
            ["PERMESI_SOCKET_PATH", "PGHOST", "PGHOSTADDR", "PGSSLMODE"],
            || {
                let logged = logged_at_default_level(|| {
                    start(
                        "http://openbao.internal:8200",
                        "postgres://app:dsn-secret@db.internal/app",
                    );
                });
                assert!(logged.contains(OPENBAO_NOTICE), "{logged}");
                assert!(logged.contains(DATABASE_NOTICE), "{logged}");
                // Neither notice names an address or a credential.
                for private in ["dsn-secret", "role-secret", "internal"] {
                    assert!(!logged.contains(private), "{logged}");
                }

                // The same flags with connections that never needed them.
                let logged = logged_at_default_level(|| {
                    start(
                        "https://openbao.internal:8200",
                        "postgres://db.internal/app?sslmode=verify-full",
                    );
                    start("http://127.0.0.1:8200", "postgres://127.0.0.1/app");
                });
                assert_eq!(logged, "");
            },
        );
    }

    /// Startup refuses an OpenBao address that would carry tokens in clear text and a
    /// DSN whose connection nobody verifies, unless the host is local or the operator
    /// opted in by name. Both used to be accepted silently.
    #[test]
    fn startup_refuses_clear_text_openbao_and_unverified_database_connections() {
        fn start(openbao: &str, dsn: &str, extra: &[&str]) -> Result<(), String> {
            let matches = crate::cli::commands::new()
                .try_get_matches_from(
                    [
                        "permesi",
                        "--tls-pem-bundle",
                        "bundle",
                        "--openbao-role-id",
                        "role",
                        "--openbao-secret-id",
                        "secret",
                        "--openbao-url",
                        openbao,
                        "--dsn",
                        dsn,
                    ]
                    .into_iter()
                    .chain(extra.iter().copied()),
                )
                .map_err(|error| error.kind().to_string())?;
            handler(&matches)
                .map(|_| ())
                .map_err(|error| format!("{error:#}"))
        }
        const TLS_OPENBAO: &str = "https://openbao.internal:8200";
        const PLAIN_OPENBAO: &str = "http://openbao.internal:8200";
        const VERIFIED_DSN: &str = "postgres://db.internal/app?sslmode=verify-full";
        const UNVERIFIED_DSN: &str = "postgres://app:dsn-secret@db.internal/app";

        temp_env::with_vars_unset(
            [
                "PERMESI_OPENBAO_ALLOW_INSECURE_HTTP",
                "PERMESI_DB_ALLOW_UNVERIFIED_TLS",
                "PERMESI_SOCKET_PATH",
                "PGHOST",
                "PGSSLMODE",
            ],
            || {
                assert_eq!(start(TLS_OPENBAO, VERIFIED_DSN, &[]), Ok(()));
                // Nothing leaves the machine on loopback.
                assert_eq!(
                    start("http://127.0.0.1:8200", "postgres://localhost/app", &[]),
                    Ok(())
                );

                let refused = start(PLAIN_OPENBAO, VERIFIED_DSN, &[])
                    .err()
                    .unwrap_or_default();
                assert!(refused.contains("plain http"), "{refused}");
                assert_eq!(
                    start(
                        PLAIN_OPENBAO,
                        VERIFIED_DSN,
                        &["--openbao-allow-insecure-http"]
                    ),
                    Ok(())
                );

                let refused = start(TLS_OPENBAO, UNVERIFIED_DSN, &[])
                    .err()
                    .unwrap_or_default();
                assert!(refused.contains("verify-full"), "{refused}");
                assert!(!refused.contains("dsn-secret"), "{refused}");
                assert_eq!(
                    start(TLS_OPENBAO, UNVERIFIED_DSN, &["--db-allow-unverified-tls"]),
                    Ok(())
                );

                // One opt-in does not cover the other.
                assert!(
                    start(
                        PLAIN_OPENBAO,
                        UNVERIFIED_DSN,
                        &["--db-allow-unverified-tls"]
                    )
                    .is_err()
                );
                assert!(
                    start(
                        PLAIN_OPENBAO,
                        UNVERIFIED_DSN,
                        &["--openbao-allow-insecure-http"]
                    )
                    .is_err()
                );
            },
        );
        // A chart sets the opt-ins through the environment.
        temp_env::with_vars(
            [
                ("PERMESI_OPENBAO_ALLOW_INSECURE_HTTP", Some("true")),
                ("PERMESI_DB_ALLOW_UNVERIFIED_TLS", Some("true")),
                ("PERMESI_SOCKET_PATH", None),
                ("PGHOST", None),
                ("PGSSLMODE", None),
            ],
            || assert_eq!(start(PLAIN_OPENBAO, UNVERIFIED_DSN, &[]), Ok(())),
        );
    }

    #[test]
    fn mfa_challenge_limit_rejects_out_of_range_clap_and_programmatic_values() -> Result<()> {
        let base = [
            "permesi",
            "--dsn",
            "postgres://",
            "--tls-pem-bundle",
            "bundle",
            "--openbao-url",
            "https://openbao:8200",
            "--openbao-role-id",
            "role",
            "--openbao-secret-id",
            "secret",
        ];
        for value in ["0", "21"] {
            assert!(
                crate::cli::commands::new()
                    .try_get_matches_from(
                        base.into_iter()
                            .chain(["--mfa-challenge-max-attempts", value])
                    )
                    .is_err()
            );
            let matches = crate::cli::commands::new()
                .mut_arg("mfa-challenge-max-attempts", |arg| {
                    arg.value_parser(clap::value_parser!(i32))
                })
                .try_get_matches_from(
                    base.into_iter()
                        .chain(["--mfa-challenge-max-attempts", value]),
                )?;
            assert!(mfa_challenge_limit(&matches).is_err());
        }
        Ok(())
    }

    /// The clock-skew allowance defaults to five seconds and is bounded by clap and again
    /// by dispatch, and the value dispatch hands to the server is the one that was given.
    #[test]
    fn admission_iat_leeway_defaults_and_rejects_out_of_range_values() -> Result<()> {
        temp_env::with_vars(
            [("PERMESI_ADMISSION_IAT_LEEWAY_SECONDS", None::<&str>)],
            || {
                let base = [
                    "permesi",
                    "--dsn",
                    "postgres://",
                    "--tls-pem-bundle",
                    "bundle",
                    "--openbao-url",
                    "https://openbao:8200",
                    "--openbao-role-id",
                    "role",
                    "--openbao-secret-id",
                    "secret",
                ];
                let dispatched = |matches: &clap::ArgMatches| -> Result<i64> {
                    let Action::Server(args) = handler(matches)?;
                    Ok(args.admission_iat_leeway)
                };
                let matches = crate::cli::commands::new().try_get_matches_from(base)?;
                assert_eq!(admission_iat_leeway(&matches)?, 5);
                assert_eq!(dispatched(&matches)?, 5);
                for (value, expected) in [("0", 0), ("7", 7), ("30", 30)] {
                    let matches = crate::cli::commands::new().try_get_matches_from(
                        base.into_iter()
                            .chain(["--admission-iat-leeway-seconds", value]),
                    )?;
                    assert_eq!(admission_iat_leeway(&matches)?, expected);
                    assert_eq!(dispatched(&matches)?, expected);
                }
                for value in ["-1", "31", "60", "abc"] {
                    assert!(
                        crate::cli::commands::new()
                            .try_get_matches_from(
                                base.into_iter()
                                    .chain(["--admission-iat-leeway-seconds", value])
                            )
                            .is_err(),
                        "{value}"
                    );
                }
                for value in ["-1", "31"] {
                    let matches = crate::cli::commands::new()
                        .mut_arg("admission-iat-leeway-seconds", |arg| {
                            arg.value_parser(clap::value_parser!(i64))
                                .allow_negative_numbers(true)
                        })
                        .try_get_matches_from(
                            base.into_iter()
                                .chain(["--admission-iat-leeway-seconds", value]),
                        )?;
                    assert!(admission_iat_leeway(&matches).is_err(), "{value}");
                    assert!(handler(&matches).is_err(), "{value}");
                }
                Ok(())
            },
        )
    }

    /// Clap bounds and dispatch revalidation must both reject invalid operator budgets.
    #[test]
    fn tenant_mutation_budgets_are_validated_by_clap_and_dispatch() -> Result<()> {
        temp_env::with_vars(
            [
                ("PERMESI_TENANT_LOCK_TIMEOUT_MS", None::<&str>),
                ("PERMESI_TENANT_MUTATION_TIMEOUT_MS", None::<&str>),
                ("PERMESI_TENANT_SLUG_ATTEMPTS", None::<&str>),
            ],
            || {
                let base = [
                    "permesi",
                    "--dsn",
                    "postgres://",
                    "--tls-pem-bundle",
                    "bundle",
                    "--openbao-url",
                    "https://openbao:8200",
                    "--openbao-role-id",
                    "role",
                    "--openbao-secret-id",
                    "secret",
                ];
                for (lock, total) in [
                    ("0", "5000"),
                    ("10001", "30000"),
                    ("1", "0"),
                    ("1", "30001"),
                ] {
                    let args = base.into_iter().chain([
                        "--tenant-lock-timeout-ms",
                        lock,
                        "--tenant-mutation-timeout-ms",
                        total,
                    ]);
                    assert!(
                        crate::cli::commands::new()
                            .try_get_matches_from(args)
                            .is_err()
                    );
                    // Programmatic matches can bypass clap's range validators; dispatch cannot.
                    let matches = crate::cli::commands::new()
                        .mut_arg("tenant-lock-timeout-ms", |arg| {
                            arg.value_parser(clap::value_parser!(i64))
                        })
                        .mut_arg("tenant-mutation-timeout-ms", |arg| {
                            arg.value_parser(clap::value_parser!(u64))
                        })
                        .try_get_matches_from(base.into_iter().chain([
                            "--tenant-lock-timeout-ms",
                            lock,
                            "--tenant-mutation-timeout-ms",
                            total,
                        ]))?;
                    assert!(handler(&matches).is_err());
                }
                let matches =
                    crate::cli::commands::new().try_get_matches_from(base.into_iter().chain([
                        "--tenant-lock-timeout-ms",
                        "1000",
                        "--tenant-mutation-timeout-ms",
                        "999",
                    ]))?;
                assert!(handler(&matches).is_err());
                for attempts in ["0", "129"] {
                    let args = base.into_iter().chain(["--tenant-slug-attempts", attempts]);
                    assert!(
                        crate::cli::commands::new()
                            .try_get_matches_from(args)
                            .is_err()
                    );
                    let matches = crate::cli::commands::new()
                        .mut_arg("tenant-slug-attempts", |arg| {
                            arg.value_parser(clap::value_parser!(u16))
                        })
                        .try_get_matches_from(
                            base.into_iter().chain(["--tenant-slug-attempts", attempts]),
                        )?;
                    assert!(handler(&matches).is_err());
                }
                let matches = crate::cli::commands::new().try_get_matches_from(base)?;
                assert!(handler(&matches).is_ok());
                Ok(())
            },
        )
    }

    #[test]
    fn openbao_mounts_are_normalized_in_dispatch() {
        let command = crate::cli::commands::new();
        let matches = command.get_matches_from(vec![
            "permesi",
            "--dsn",
            "postgres://",
            "--tls-pem-bundle",
            "bundle",
            "--openbao-url",
            "https://openbao:8200",
            "--openbao-role-id",
            "role",
            "--openbao-secret-id",
            "secret",
            "--openbao-kv-mount",
            "/secret/permesi/",
            "--openbao-transit-mount",
            "/transit/permesi/",
        ]);

        let action = handler(&matches);
        assert!(action.is_ok(), "dispatch should succeed");
        if let Ok(Action::Server(args)) = action {
            assert_eq!(args.openbao_kv_mount, "secret/permesi");
            assert_eq!(args.openbao_transit_mount, "transit/permesi");
        }
    }

    #[test]
    fn empty_transit_mount_is_rejected() {
        let command = crate::cli::commands::new();
        let matches = command.get_matches_from(vec![
            "permesi",
            "--dsn",
            "postgres://",
            "--tls-pem-bundle",
            "bundle",
            "--openbao-url",
            "https://openbao:8200",
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
