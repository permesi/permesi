//! Owned Genesis and bounded Permesi replicas with recoverable process incarnations.
//!
//! Flow Overview: retain each child before publishing its PID/birth ticks, verify
//! every private socket, then stop or restart only explicitly selected owned children.
//! TLS, issuer, PostgreSQL and Vault inputs remain identical across restarts. Secrets
//! stay in memory and child environments, never command output or recovery journals.

use crate::{
    cli::Options,
    error::{Failure, Result, Safe, check},
    infrastructure::Infrastructure,
    journal::{Journal, ProcessIdentity},
    process::Process,
    topology::Topology,
};
use permesi::{cli::actions::Action, oauth::config::OAuthConfig};
use secrecy::{ExposeSecret as _, SecretString};
use std::{
    os::unix::fs::FileTypeExt as _,
    path::{Path, PathBuf},
    time::Duration,
};

/// Effective public policies read through the product CLI, rather than duplicated test defaults.
pub struct Policy {
    pub oauth: OAuthConfig,
    pub credential_grace_seconds: i64,
    pub access_token_ttl_seconds: i64,
    pub auth_rate_limit_ip_attempts: i64,
    pub auth_rate_limit_account_attempts: i64,
    pub oauth_token_rate_ip_attempts: i64,
    pub oauth_token_rate_client_ip_attempts: i64,
}

impl Policy {
    /// Reads only product-validated CLI values so the report matches every launched replica.
    fn from_matches(
        matches: &clap::ArgMatches,
        oauth: OAuthConfig,
        auth_rate_limit_ip_attempts: i64,
    ) -> Result<Self> {
        let required = |name: &'static str, message: &'static str| {
            matches
                .get_one::<i64>(name)
                .copied()
                .ok_or_else(|| Failure::harness(message))
        };
        Ok(Self {
            oauth,
            auth_rate_limit_ip_attempts,
            auth_rate_limit_account_attempts: required(
                "auth-rate-limit-account-attempts",
                "Missing account budget policy.",
            )?,
            oauth_token_rate_ip_attempts: required(
                "oauth-token-rate-ip-attempts",
                "Missing token IP budget policy.",
            )?,
            oauth_token_rate_client_ip_attempts: required(
                "oauth-token-rate-client-ip-attempts",
                "Missing token client budget policy.",
            )?,
            access_token_ttl_seconds: required(
                "oauth-access-token-ttl-seconds",
                "Missing access lifetime policy.",
            )?,
            credential_grace_seconds: required(
                "oauth-client-secret-grace-seconds",
                "Missing credential grace policy.",
            )?,
        })
    }
}

/// Fault injection distinguishes a graceful rolling replacement from sudden backend loss.
pub enum StopMode {
    Graceful,
    Abrupt,
}

struct Replica {
    socket: PathBuf,
    arguments: Vec<String>,
    process: Option<Process>,
}

/// Restart inputs remain private and cannot be serialized or formatted into diagnostics.
struct Launch {
    binary: PathBuf,
    role: SecretString,
    secret: SecretString,
    genesis_socket: PathBuf,
    readiness_seconds: u64,
}

/// Child handles survive failed startup, injected outages and cancellation until cleanup.
#[derive(Default)]
pub struct Services {
    genesis: Option<Process>,
    replicas: Vec<Replica>,
    launch: Option<Launch>,
    journal: Option<Journal>,
    recovery_failed: bool,
    browser: Option<ProcessIdentity>,
}

impl Services {
    /// Installs recovery metadata before any process starts; subsequent writes retain current children.
    pub fn journal(&mut self, journal: Journal) -> Result<()> {
        self.journal = Some(journal);
        self.record()
    }

    /// Preserves the separately owned browser controller through every service-generation journal update.
    /// The runtime clears it only after `Browser::stop` has reaped that child; failed cleanup retains its identity.
    pub fn browser_identity(&mut self, identity: Option<ProcessIdentity>) -> Result<()> {
        self.browser = identity;
        self.record()
    }

    /// Retains the public resource origin when recording later process replacements.
    pub fn resource_origin(&mut self, origin: &str) -> Result<()> {
        self.journal
            .as_mut()
            .ok_or_else(|| Failure::harness("Missing ownership journal."))?
            .resource_origin(origin);
        self.record()
    }

    /// Atomically records all current owned incarnations, excluding reaped children.
    fn record(&mut self) -> Result<()> {
        let processes = self
            .genesis
            .iter()
            .chain(self.replicas.iter().filter_map(|r| r.process.as_ref()))
            .map(|child| ProcessIdentity::read(&child.0))
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .flatten()
            .chain(self.browser.clone())
            .collect();
        self.journal
            .as_mut()
            .ok_or_else(|| Failure::harness("Missing ownership journal."))?
            .record(processes)
    }

    /// Reports configured process slots even while one is deliberately unavailable.
    pub fn replica_count(&self) -> usize {
        self.replicas.len()
    }

    /// Reads the selected live child's identity, never an unverified external PID.
    pub fn identity(&self, index: usize) -> Result<ProcessIdentity> {
        let child = self
            .replicas
            .get(index)
            .and_then(|replica| replica.process.as_ref())
            .ok_or_else(|| Failure::harness("Missing owned replica."))?;
        ProcessIdentity::read(&child.0)?
            .ok_or_else(|| Failure::harness("Missing live replica identity."))
    }

    /// Starts actual binaries through existing product CLI/dispatch inputs and a bounded local topology.
    pub fn start(
        &mut self,
        binaries: [&Path; 2],
        topology: &Topology,
        infra: &Infrastructure,
        origin: &str,
        ca: &Path,
        options: &Options,
    ) -> Result<Policy> {
        check(
            self.journal.is_some() && self.genesis.is_none() && self.replicas.is_empty(),
            "Invalid initial service ownership.",
        )?;
        let [permesi, genesis] = binaries;
        self.launch = Some(Launch {
            binary: permesi.into(),
            role: infra.permesi_role.role.clone().into(),
            secret: infra.permesi_role.secret.clone().into(),
            genesis_socket: topology.genesis.clone(),
            readiness_seconds: options.readiness_seconds,
        });
        self.replicas = topology
            .replicas
            .iter()
            .map(|socket| Replica {
                socket: socket.clone(),
                process: None,
                arguments: vec![
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
                    "--auth-rate-limit-account-attempts".into(),
                    options.auth_rate_limit_account_attempts.to_string(),
                    "--oauth-token-rate-ip-attempts".into(),
                    options.oauth_token_rate_ip_attempts.to_string(),
                    "--oauth-token-rate-client-ip-attempts".into(),
                    options.oauth_token_rate_client_ip_attempts.to_string(),
                    "--email-delivery".into(),
                    "outbox".into(),
                    "--signup-development-domain".into(),
                    "example.test".into(),
                    "--frontend-base-url".into(),
                    origin.into(),
                    "--admission-paserk-url".into(),
                    format!("{origin}/admission/paserk.json"),
                    "--admission-paserk-ca-path".into(),
                    ca.display().to_string(),
                ],
            })
            .collect();
        self.genesis = Some(Process::service(
            genesis,
            &[
                "--socket-path".into(),
                topology.genesis.display().to_string(),
                "--dsn".into(),
                infra.genesis_dsn.clone(),
                "--vault-url".into(),
                infra.vault_url.clone(),
            ],
            &[
                ("GENESIS_VAULT_ROLE_ID", &infra.genesis_role.role),
                ("GENESIS_VAULT_SECRET_ID", &infra.genesis_role.secret),
            ],
        )?);
        self.record()?;
        for index in 0..self.replicas.len() {
            self.spawn_replica(index)?;
        }
        let mut args = vec!["permesi".to_owned()];
        args.extend(
            self.replicas
                .first()
                .ok_or_else(|| Failure::harness("Missing replica policy."))?
                .arguments
                .clone(),
        );
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
        Policy::from_matches(&matches, args.oauth, args.auth_rate_limit_ip_attempts)
    }

    /// Stores and journals the replacement before readiness awaits; a live slot cannot be overwritten.
    fn spawn_replica(&mut self, index: usize) -> Result<()> {
        let launch = self
            .launch
            .as_ref()
            .ok_or_else(|| Failure::harness("Missing restart configuration."))?;
        let replica = self
            .replicas
            .get_mut(index)
            .ok_or_else(|| Failure::harness("Unknown replica index."))?;
        check(replica.process.is_none(), "Cannot replace a live replica.")?;
        clear_socket(&replica.socket)?;
        replica.process = Some(Process::service(
            &launch.binary,
            &replica.arguments,
            &[
                ("PERMESI_VAULT_ROLE_ID", launch.role.expose_secret()),
                ("PERMESI_VAULT_SECRET_ID", launch.secret.expose_secret()),
            ],
        )?);
        self.record()
    }

    /// Requires a live owned child before fault injection; pre-existing death cannot masquerade as an intended outage.
    /// Reaps the child before exposing an empty slot or unlinking its socket.
    pub async fn stop_replica(&mut self, index: usize, mode: StopMode) -> Result<()> {
        let replica = self
            .replicas
            .get_mut(index)
            .ok_or_else(|| Failure::harness("Unknown replica index."))?;
        let process = replica
            .process
            .as_mut()
            .ok_or_else(|| Failure::harness("Missing live replica for fault injection."))?;
        check(
            process
                .0
                .try_wait()
                .safe("Cannot inspect replica before fault injection.")?
                .is_none(),
            "Replica exited before fault injection.",
        )?;
        let result = match mode {
            StopMode::Graceful => process.terminate().await,
            StopMode::Abrupt => process.stop().await,
        };
        let cleanup = self.retire_replica(index).await;
        self.recovery_failed |= cleanup.is_err();
        result.and(cleanup)
    }

    /// Starts an explicitly stopped slot with identical policy and requires its own socket to become ready.
    /// Failed readiness removes the bad incarnation before any later case can use it.
    pub async fn restart_replica(&mut self, index: usize) -> Result<()> {
        check(
            self.replicas
                .get(index)
                .is_some_and(|replica| replica.process.is_none()),
            "Cannot restart an unknown or live replica.",
        )?;
        let result = async {
            self.spawn_replica(index)?;
            let replica = self
                .replicas
                .get(index)
                .ok_or_else(|| Failure::harness("Unknown replica index."))?;
            ready(
                &replica.socket,
                self.launch
                    .as_ref()
                    .ok_or_else(|| Failure::harness("Missing restart policy."))?
                    .readiness_seconds,
            )
            .await
        }
        .await;
        if result.is_err() {
            let cleanup_failed = self.retire_replica(index).await.is_err();
            self.recovery_failed |= cleanup_failed;
        }
        result
    }

    /// Forces retirement after a planned transition, retaining the handle if killing or reaping fails.
    async fn retire_replica(&mut self, index: usize) -> Result<()> {
        let replica = self
            .replicas
            .get_mut(index)
            .ok_or_else(|| Failure::harness("Unknown replica index."))?;
        if let Some(process) = &mut replica.process {
            process.stop().await?;
        }
        replica.process = None;
        self.record()
    }

    /// Restores deliberately stopped slots after every case, including assertion failures.
    /// Unexpectedly crashed children remain failures rather than receiving an invisible retry.
    pub async fn restore_stopped(&mut self) -> Result<()> {
        check(
            !self.recovery_failed,
            "Owned replica recovery is incomplete.",
        )?;
        for index in 0..self.replicas.len() {
            if self
                .replicas
                .get(index)
                .is_some_and(|replica| replica.process.is_none())
            {
                self.restart_replica(index).await?;
            }
            let process = self
                .replicas
                .get_mut(index)
                .and_then(|replica| replica.process.as_mut())
                .ok_or_else(|| Failure::harness("Missing restored replica."))?;
            check(
                process
                    .0
                    .try_wait()
                    .safe("Cannot inspect replica after case.")?
                    .is_none(),
                "Owned replica exited unexpectedly.",
            )?;
        }
        let genesis = self
            .genesis
            .as_mut()
            .ok_or_else(|| Failure::harness("Missing admission process."))?;
        check(
            genesis
                .0
                .try_wait()
                .safe("Cannot inspect admission process.")?
                .is_none(),
            "Owned admission process exited unexpectedly.",
        )?;
        self.ready().await
    }

    /// Verifies every backend independently; a healthy gateway cannot substitute for a missing replica.
    pub async fn ready(&self) -> Result<()> {
        let launch = self
            .launch
            .as_ref()
            .ok_or_else(|| Failure::harness("Missing readiness policy."))?;
        for socket in self
            .replicas
            .iter()
            .map(|replica| &replica.socket)
            .chain([&launch.genesis_socket])
        {
            ready(socket, launch.readiness_seconds).await?;
        }
        Ok(())
    }

    /// Reaps all children despite individual errors, preserving live identities if any stop fails.
    pub async fn stop(&mut self) -> Vec<Failure> {
        let mut errors = Vec::new();
        for process in self
            .replicas
            .iter_mut()
            .filter_map(|r| r.process.as_mut())
            .chain(self.genesis.iter_mut())
        {
            if let Err(error) = process.stop().await {
                errors.push(error);
            }
        }
        if let Err(error) = self.record() {
            errors.push(error);
        }
        errors
    }
}

/// Removes only an old owned socket after its child was reaped; other file types fail closed.
fn clear_socket(socket: &Path) -> Result<()> {
    match std::fs::symlink_metadata(socket) {
        Ok(metadata) => {
            check(
                metadata.file_type().is_socket(),
                "Restart socket has an unexpected file type.",
            )?;
            std::fs::remove_file(socket).safe("Cannot remove stopped replica socket.")
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).safe("Cannot inspect restart socket."),
    }
}

/// Bounds direct socket health polling without following redirects or using proxy configuration.
async fn ready(socket: &Path, seconds: u64) -> Result<()> {
    let client = reqwest::Client::builder()
        .unix_socket(socket)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
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
    .safe("An owned service did not become ready.")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::files::PrivateDir;

    const HEALTH_PROCESS: &str = r"
import http.server, signal, socketserver, sys
class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'healthy')
    def log_message(self, *args):
        pass
signal.signal(signal.SIGTERM, lambda *args: sys.exit(0))
socketserver.UnixStreamServer(sys.argv[1], Handler).serve_forever()
";

    /// Starts only a test health process; authentication/HA protocol evidence uses real product binaries separately.
    fn health_arguments(socket: &Path) -> Vec<String> {
        vec![
            "-I".into(),
            "-c".into(),
            HEALTH_PROCESS.into(),
            socket.display().to_string(),
        ]
    }

    /// Reads actual journaled identities without accepting command arguments or credentials as metadata.
    fn journal_processes(directory: &Path) -> Result<Vec<(u32, u64)>> {
        let bytes = std::fs::read(directory.join("ownership-1.json"))
            .safe("Cannot read lifecycle journal.")?;
        check(
            !String::from_utf8_lossy(&bytes).contains("SECRET_SENTINEL"),
            "Recovery journal exposed restart credentials.",
        )?;
        let value: serde_json::Value =
            serde_json::from_slice(&bytes).safe("Invalid lifecycle journal.")?;
        value
            .get("processes")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| Failure::harness("Missing process records."))?
            .iter()
            .map(|entry| {
                let pid = entry
                    .get("pid")
                    .and_then(serde_json::Value::as_u64)
                    .ok_or_else(|| Failure::harness("Missing process ID."))?;
                Ok((
                    u32::try_from(pid).safe("Invalid process ID.")?,
                    entry
                        .get("start_ticks")
                        .and_then(serde_json::Value::as_u64)
                        .ok_or_else(|| Failure::harness("Missing birth ticks."))?,
                ))
            })
            .collect()
    }

    /// Starts real owned health children without provisioning OAuth infrastructure.
    fn health_services(directory: &Path, count: u16) -> Result<Services> {
        let topology = Topology::new(directory, count)?;
        let genesis = Process::service(
            Path::new("python3"),
            &health_arguments(&topology.genesis),
            &[],
        )?;
        let replicas = topology
            .replicas
            .iter()
            .map(|socket| Replica {
                socket: socket.clone(),
                arguments: health_arguments(socket),
                process: None,
            })
            .collect();
        let mut services = Services {
            genesis: Some(genesis),
            replicas,
            journal: None,
            recovery_failed: false,
            browser: None,
            launch: Some(Launch {
                binary: "python3".into(),
                role: "SECRET_SENTINEL_ROLE".to_owned().into(),
                secret: "SECRET_SENTINEL_VALUE".to_owned().into(),
                genesis_socket: topology.genesis.clone(),
                readiness_seconds: 5,
            }),
        };
        services.journal(Journal::new(directory, 1, "owned", "network", directory))?;
        for index in 0..usize::from(count) {
            services.spawn_replica(index)?;
        }
        Ok(services)
    }

    /// Verifies real owned-child replacement, updated recovery identities, restoration and fail-closed unexpected exits.
    #[tokio::test]
    async fn supervision_journals_all_generations_and_rejects_unplanned_exit() -> Result<()> {
        for count in [3, 5] {
            let directory = PrivateDir::new()?;
            let mut services = health_services(&directory.0, count)?;
            services.ready().await?;
            assert_eq!(
                journal_processes(&directory.0)?.len(),
                usize::from(count) + 1
            );
            let index = usize::from(count) - 1;
            let previous = services.identity(index)?;
            services.stop_replica(index, StopMode::Graceful).await?;
            assert!(services.identity(index).is_err());
            assert!(
                !journal_processes(&directory.0)?.contains(&(previous.pid, previous.start_ticks))
            );
            services.restart_replica(index).await?;
            let current = services.identity(index)?;
            assert_ne!(
                (previous.pid, previous.start_ticks),
                (current.pid, current.start_ticks)
            );
            let records = journal_processes(&directory.0)?;
            assert_eq!(records.len(), usize::from(count) + 1);
            assert!(records.contains(&(current.pid, current.start_ticks)));
            assert!(!records.contains(&(previous.pid, previous.start_ticks)));
            services.stop_replica(0, StopMode::Abrupt).await?;
            services.restore_stopped().await?;
            services.ready().await?;
            assert_eq!(
                journal_processes(&directory.0)?.len(),
                usize::from(count) + 1
            );
            let process = services
                .replicas
                .get_mut(1)
                .and_then(|replica| replica.process.as_mut())
                .ok_or_else(|| Failure::harness("Missing test replica."))?;
            process.stop().await?;
            let error = services
                .restore_stopped()
                .await
                .err()
                .ok_or_else(|| Failure::assertion("Unplanned child death was hidden."))?;
            assert_eq!(error.message, "Owned replica exited unexpectedly.");
            let errors = services.stop().await;
            assert!(errors.is_empty(), "Owned child cleanup failed");
            assert_eq!(journal_processes(&directory.0)?, Vec::<(u32, u64)>::new());
        }
        Ok(())
    }

    /// The long-lived browser host controller must survive all service journal rewrites until explicitly reaped.
    #[tokio::test]
    async fn service_replacement_preserves_the_browser_controller_identity() -> Result<()> {
        let directory = PrivateDir::new()?;
        let mut services = health_services(&directory.0, 3)?;
        services.ready().await?;
        let mut browser = Process::service(
            Path::new("python3"),
            &[
                "-I".into(),
                "-c".into(),
                "import time; time.sleep(30)".into(),
                "run".into(),
                "--interactive".into(),
                "--volume".into(),
                format!(
                    "{}:/scenario-ca.pem:ro",
                    directory.0.join("ca.pem").display()
                ),
            ],
            &[],
        )?;
        let identity = ProcessIdentity::read(&browser.0)?
            .ok_or_else(|| Failure::harness("Missing browser fixture identity."))?;
        let key = (identity.pid, identity.start_ticks);
        services.browser_identity(Some(identity))?;
        assert_eq!(journal_processes(&directory.0)?.len(), 5);
        assert!(journal_processes(&directory.0)?.contains(&key));
        services.stop_replica(0, StopMode::Abrupt).await?;
        services.restore_stopped().await?;
        assert_eq!(journal_processes(&directory.0)?.len(), 5);
        assert!(journal_processes(&directory.0)?.contains(&key));
        browser.stop().await?;
        services.browser_identity(None)?;
        assert!(!journal_processes(&directory.0)?.contains(&key));
        assert!(services.stop().await.is_empty());
        assert_eq!(journal_processes(&directory.0)?, Vec::<(u32, u64)>::new());
        Ok(())
    }

    /// Browser ownership is published immediately and survives unrelated metadata writes before any readiness wait.
    #[tokio::test]
    async fn browser_identity_is_published_before_readiness() -> Result<()> {
        let directory = PrivateDir::new()?;
        let mut browser = Process::service(
            Path::new("python3"),
            &[
                "-I".into(),
                "-c".into(),
                "import time; time.sleep(30)".into(),
                directory.0.join("ca.pem").display().to_string(),
            ],
            &[],
        )?;
        let identity = ProcessIdentity::read(&browser.0)?
            .ok_or_else(|| Failure::harness("Missing browser fixture identity."))?;
        let key = (identity.pid, identity.start_ticks);
        let mut services = Services::default();
        services.journal(Journal::new(
            &directory.0,
            1,
            "owned",
            "network",
            &directory.0,
        ))?;
        services.browser_identity(Some(identity))?;
        services.resource_origin("https://localhost:1234")?;
        assert_eq!(journal_processes(&directory.0)?, vec![key]);
        browser.stop().await?;
        services.browser_identity(None)?;
        assert_eq!(journal_processes(&directory.0)?, Vec::<(u32, u64)>::new());
        Ok(())
    }

    /// An already dead process retains its slot and fails instead of becoming an authorized restart.
    #[tokio::test]
    async fn fault_injection_rejects_a_previously_exited_replica() -> Result<()> {
        let directory = PrivateDir::new()?;
        let mut process =
            Process::spawn(tokio::process::Command::new("sh").args(["-c", "exit 7"]))?;
        let status = process.0.wait().await.safe("Cannot reap crash fixture.")?;
        assert_eq!(status.code(), Some(7));
        let mut services = Services {
            replicas: vec![Replica {
                socket: directory.0.join("unused.sock"),
                arguments: Vec::new(),
                process: Some(process),
            }],
            ..Services::default()
        };
        services.journal(Journal::new(
            &directory.0,
            1,
            "owned",
            "network",
            &directory.0,
        ))?;
        for mode in [StopMode::Abrupt, StopMode::Graceful] {
            let error = services.stop_replica(0, mode).await.err();
            assert_eq!(
                error.map(|error| error.message),
                Some("Replica exited before fault injection.")
            );
            assert!(
                services
                    .replicas
                    .first()
                    .is_some_and(|replica| replica.process.is_some())
            );
        }
        assert!(services.stop().await.is_empty());
        Ok(())
    }

    /// Failed graceful draining must remain red while retiring the bad generation before restoring topology.
    #[tokio::test]
    async fn graceful_timeout_retires_and_journals_before_restoring() -> Result<()> {
        let directory = PrivateDir::new()?;
        let mut services = health_services(&directory.0, 3)?;
        services.ready().await?;
        services.stop_replica(0, StopMode::Abrupt).await?;
        let replica = services
            .replicas
            .first_mut()
            .ok_or_else(|| Failure::harness("Missing test slot."))?;
        replica.arguments = health_arguments(&replica.socket);
        if let Some(script) = replica.arguments.get_mut(2) {
            *script = HEALTH_PROCESS.replace("lambda *args: sys.exit(0)", "signal.SIG_IGN");
        }
        services.restart_replica(0).await?;
        let previous = services.identity(0)?;
        let error = services.stop_replica(0, StopMode::Graceful).await.err();
        assert_eq!(
            error.map(|error| error.message),
            Some("Owned process did not terminate gracefully.")
        );
        assert!(services.identity(0).is_err());
        assert!(!journal_processes(&directory.0)?.contains(&(previous.pid, previous.start_ticks)));
        services.restore_stopped().await?;
        assert_eq!(journal_processes(&directory.0)?.len(), 4);
        assert!(services.stop().await.is_empty());
        Ok(())
    }

    /// A live unready replacement cannot leak into the next case or masquerade as recovered topology.
    #[tokio::test]
    async fn failed_readiness_retires_replacement_and_checks_all_live_slots() -> Result<()> {
        let directory = PrivateDir::new()?;
        let mut services = health_services(&directory.0, 3)?;
        services.ready().await?;
        services.stop_replica(0, StopMode::Abrupt).await?;
        let launch = services
            .launch
            .as_mut()
            .ok_or_else(|| Failure::harness("Missing test launch."))?;
        launch.readiness_seconds = 1;
        let replica = services
            .replicas
            .first_mut()
            .ok_or_else(|| Failure::harness("Missing test slot."))?;
        replica.arguments = vec![
            "-I".into(),
            "-c".into(),
            "import time; time.sleep(30)".into(),
            replica.socket.display().to_string(),
        ];
        assert!(services.restart_replica(0).await.is_err());
        assert!(services.identity(0).is_err());
        assert_eq!(journal_processes(&directory.0)?.len(), 3);
        services.spawn_replica(0)?;
        assert!(services.restore_stopped().await.is_err());
        assert!(services.stop().await.is_empty());
        Ok(())
    }

    /// A failed retirement journal blocks later cases even when the child itself was reaped successfully.
    #[tokio::test]
    async fn retirement_journal_failure_blocks_recovery() -> Result<()> {
        let directory = PrivateDir::new()?;
        let mut process = Process::spawn(tokio::process::Command::new("python3").args([
            "-I",
            "-c",
            "import time; time.sleep(30)",
        ]))?;
        check(
            process
                .0
                .try_wait()
                .safe("Cannot inspect test child.")?
                .is_none(),
            "Test child exited.",
        )?;
        let mut services = Services {
            replicas: vec![Replica {
                socket: directory.0.join("unused.sock"),
                arguments: Vec::new(),
                process: Some(process),
            }],
            ..Services::default()
        };
        services.journal(Journal::new(
            &directory.0,
            1,
            "owned",
            "network",
            &directory.0,
        ))?;
        let path = directory.0.join("ownership-1.json");
        std::fs::remove_file(&path).safe("Cannot prepare journal fault.")?;
        std::fs::create_dir(&path).safe("Cannot inject journal fault.")?;
        assert!(services.stop_replica(0, StopMode::Abrupt).await.is_err());
        let error = services.restore_stopped().await.err();
        assert_eq!(
            error.map(|error| error.message),
            Some("Owned replica recovery is incomplete.")
        );
        assert!(services.identity(0).is_err());
        std::fs::remove_dir(path).safe("Cannot clear journal fault.")?;
        assert!(services.stop().await.is_empty());
        Ok(())
    }

    /// A nonzero SIGTERM exit remains a failure but cannot leave a spent incarnation in the next case's topology.
    #[tokio::test]
    async fn nonzero_graceful_exit_retires_and_updates_the_journal() -> Result<()> {
        let directory = PrivateDir::new()?;
        let marker = directory.0.join("handler-ready");
        let script = "import signal,time,sys; from pathlib import Path; signal.signal(signal.SIGTERM,lambda *args:sys.exit(7)); Path(sys.argv[1]).write_text('ready'); time.sleep(30)";
        let process = Process::service(
            Path::new("python3"),
            &[
                "-I".into(),
                "-c".into(),
                script.into(),
                marker.display().to_string(),
            ],
            &[],
        )?;
        let mut services = Services {
            replicas: vec![Replica {
                socket: directory.0.join("unused.sock"),
                arguments: Vec::new(),
                process: Some(process),
            }],
            ..Services::default()
        };
        services.journal(Journal::new(
            &directory.0,
            1,
            "owned",
            "network",
            &directory.0,
        ))?;
        tokio::time::timeout(Duration::from_secs(5), async {
            while !marker.exists() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .safe("Signal fixture did not become ready.")?;
        let error = services.stop_replica(0, StopMode::Graceful).await.err();
        assert_eq!(
            error.map(|error| error.message),
            Some("Owned process did not exit cleanly after SIGTERM.")
        );
        assert!(
            services
                .replicas
                .first()
                .is_some_and(|replica| replica.process.is_none())
        );
        assert_eq!(journal_processes(&directory.0)?, Vec::<(u32, u64)>::new());
        assert!(services.stop().await.is_empty());
        Ok(())
    }

    /// Files and symlinks at an owned socket path must fail without destructive replacement.
    #[test]
    fn restart_socket_rejects_files_and_symlinks_without_removing_them() -> Result<()> {
        let directory = PrivateDir::new()?;
        let file = directory.write("file", b"keep")?;
        let link = directory.0.join("link");
        std::os::unix::fs::symlink(&file, &link).safe("Cannot create test symlink.")?;
        assert!(clear_socket(&file).is_err());
        assert!(clear_socket(&link).is_err());
        assert_eq!(
            std::fs::read(&file).safe("Cannot read test file.")?,
            b"keep"
        );
        assert!(link.symlink_metadata().is_ok());
        clear_socket(&directory.0.join("absent"))?;
        let socket = directory.0.join("stopped.sock");
        let listener =
            std::os::unix::net::UnixListener::bind(&socket).safe("Cannot bind test socket.")?;
        drop(listener);
        clear_socket(&socket)?;
        assert!(!socket.exists());
        Ok(())
    }
}
