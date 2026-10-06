//! Real Genesis and two Permesi processes using the existing local Unix-socket mode.
//!
//! The issuer gateway terminates verified HTTPS. Backend sockets and TLS private
//! keys live in the run's mode-0700 directory. Service configuration is supplied
//! through existing clap/dispatch inputs, with inherited deployment settings removed.

use crate::{
    cli::Options,
    error::{Result, Safe},
    infrastructure::Infrastructure,
    process::Process,
};
use permesi::{cli::actions::Action, oauth::config::OAuthConfig};
use std::{
    path::{Path, PathBuf},
    time::Duration,
};

/// Effective public policies read through the product CLI, rather than duplicated test defaults.
pub struct Policy {
    pub oauth: OAuthConfig,
    pub credential_grace_seconds: i64,
    pub access_token_ttl_seconds: i64,
    pub auth_rate_limit_ip_attempts: i64,
}

/// Child processes are stored immediately after spawn, including during partial startup.
#[derive(Default)]
pub struct Services {
    pub genesis: Option<Process>,
    pub a: Option<Process>,
    pub b: Option<Process>,
}

impl Services {
    /// Records only owned process IDs and Linux birth ticks for safe manual recovery after SIGKILL.
    pub fn identities(&self) -> Vec<serde_json::Value> {
        [&self.genesis, &self.a, &self.b]
            .into_iter()
            .flatten()
            .filter_map(|child| {
                let pid = child.0.id()?;
                let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
                let ticks = stat
                    .rsplit_once(')')?
                    .1
                    .split_whitespace()
                    .nth(19)?
                    .parse::<u64>()
                    .ok()?;
                Some(serde_json::json!({"pid":pid,"start_ticks":ticks}))
            })
            .collect()
    }

    /// Starts actual binaries with bounded bulk-fixture admission and otherwise normal authentication policy.
    pub fn start(
        &mut self,
        binaries: [&Path; 2],
        sockets: &[PathBuf; 3],
        infra: &Infrastructure,
        origin: &str,
        ca: &Path,
        options: &Options,
    ) -> Result<Policy> {
        let [permesi, genesis] = binaries;
        let genesis_args = vec![
            "--socket-path".into(),
            sockets
                .last()
                .ok_or_else(|| crate::error::Failure::harness("Missing Genesis socket."))?
                .display()
                .to_string(),
            "--dsn".into(),
            infra.genesis_dsn.clone(),
            "--vault-url".into(),
            infra.vault_url.clone(),
        ];
        self.genesis = Some(Process::service(
            genesis,
            &genesis_args,
            &[
                ("GENESIS_VAULT_ROLE_ID", &infra.genesis_role.role),
                ("GENESIS_VAULT_SECRET_ID", &infra.genesis_role.secret),
            ],
        )?);
        let make_args = |socket: &Path| {
            vec![
                "--socket-path".into(),
                socket.display().to_string(),
                "--dsn".into(),
                infra.permesi_dsn.clone(),
                "--vault-url".into(),
                infra.vault_url.clone(),
                "--oidc-issuer".into(),
                origin.into(),
                "--oauth-audience".into(),
                "scenario-api".into(),
                "--oauth-access-token-ttl-seconds".into(),
                options.access_token_ttl_seconds.to_string(),
                "--auth-rate-limit-ip-attempts".into(),
                options.auth_rate_limit_ip_attempts.to_string(),
                "--frontend-base-url".into(),
                origin.into(),
                "--admission-paserk-url".into(),
                format!("{origin}/admission/paserk.json"),
                "--admission-paserk-ca-path".into(),
                ca.display().to_string(),
            ]
        };
        let [a_socket, b_socket, _] = sockets;
        let a_args = make_args(a_socket);
        let b_args = make_args(b_socket);
        let secrets = [
            ("PERMESI_VAULT_ROLE_ID", infra.permesi_role.role.as_str()),
            (
                "PERMESI_VAULT_SECRET_ID",
                infra.permesi_role.secret.as_str(),
            ),
        ];
        self.a = Some(Process::service(permesi, &a_args, &secrets)?);
        self.b = Some(Process::service(permesi, &b_args, &secrets)?);
        // Domain tests use the same explicit product policy, with env sources removed.
        let mut args = vec!["permesi".to_owned()];
        args.extend(a_args);
        args.extend([
            "--vault-role-id".to_owned(),
            infra.permesi_role.role.clone(),
            "--vault-secret-id".to_owned(),
            infra.permesi_role.secret.clone(),
        ]);
        let matches = permesi::cli::commands::new()
            .mut_args(|arg| arg.env(None::<&str>))
            .try_get_matches_from(args)
            .safe("Cannot parse isolated service policy.")?;
        let Action::Server(args) = permesi::cli::dispatch::handler(&matches)
            .safe("Cannot validate isolated service policy.")?;
        Ok(Policy {
            oauth: args.oauth,
            auth_rate_limit_ip_attempts: args.auth_rate_limit_ip_attempts,
            access_token_ttl_seconds: *matches
                .get_one::<i64>("oauth-access-token-ttl-seconds")
                .ok_or_else(|| crate::error::Failure::harness("Missing access lifetime policy."))?,
            credential_grace_seconds: *matches
                .get_one::<i64>("oauth-client-secret-grace-seconds")
                .ok_or_else(|| {
                    crate::error::Failure::harness("Missing credential grace policy.")
                })?,
        })
    }

    /// Verifies both replicas independently, rather than treating one healthy gateway as two replicas.
    pub async fn ready(sockets: &[PathBuf; 3], seconds: u64) -> Result<()> {
        for socket in sockets {
            let client = reqwest::Client::builder()
                .unix_socket(socket.as_path())
                .no_proxy()
                .timeout(Duration::from_secs(2))
                .build()
                .safe("Cannot configure readiness transport.")?;
            tokio::time::timeout(Duration::from_secs(seconds), async {
                loop {
                    if let Ok(response) = client.get("http://localhost/health").send().await
                        && response.status().is_success()
                    {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
            })
            .await
            .safe("An owned service did not become ready.")?;
        }
        Ok(())
    }

    /// Stops all children despite individual errors; this runs before the database containers are removed.
    pub async fn stop(&mut self) -> Vec<crate::error::Failure> {
        let mut errors = Vec::new();
        for child in [&mut self.a, &mut self.b, &mut self.genesis]
            .into_iter()
            .flatten()
        {
            if let Err(error) = child.stop().await {
                errors.push(error);
            }
        }
        errors
    }
}
