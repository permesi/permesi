//! Owned Better Auth interoperability fixture process for the disposable stack.
//!
//! Flow Overview: register a real confidential client through management APIs,
//! start the Node fixture with private environment configuration and run-owned
//! TLS/storage, then register its exact callback URI. The fixture performs real
//! discovery and token exchange out of band; this module only owns its process
//! lifetime, readiness handshake and unconditional cleanup. Fixture secrets live
//! exclusively in the child environment and private mode-0700 files, never in
//! command lines, journals or reports.

use crate::{
    client::{Api, Fixture, text_field},
    error::{Failure, Result, Safe, check},
    files::PrivateDir,
    journal::ProcessIdentity,
    process::Process,
    tls::Tls,
};
use base64::Engine as _;
use reqwest::{Method, StatusCode};
use secrecy::{ExposeSecret as _, SecretString};
use serde_json::{Value, json};
use std::{
    path::{Path, PathBuf},
    process::Stdio,
    sync::Arc,
    time::Duration,
};
use tokio::io::{AsyncBufReadExt, BufReader};
use uuid::Uuid;

/// Only the two Better Auth interoperability cases require Node and the fixture.
pub fn required(case: &str) -> bool {
    matches!(
        case,
        "interop.better_auth_login" | "interop.better_auth_state_reject"
    )
}

/// Per-case confidential-client inputs delivered only through the child environment.
pub struct Config {
    organization_id: Uuid,
    client_id: String,
    client_secret: SecretString,
    issuer: String,
    secret: SecretString,
}

/// Configures the ordinary confidential registration with exact OIDC scopes and a fresh secret.
pub async fn configure(api: &Api, fixture: &Fixture) -> Result<Config> {
    let application = fixture.app()?;
    let path = format!(
        "{}/oauth/clients/{}",
        application.path, application.confidential.client_id
    );
    let _: Value = api
        .json(
            Method::PUT,
            &format!("{path}/scopes"),
            Some(json!({"scopes":["openid","profile","email"]})),
            StatusCode::OK,
        )
        .await?;
    let issued: Value = api
        .json(
            Method::POST,
            &format!("{path}/secrets"),
            Some(json!({})),
            StatusCode::CREATED,
        )
        .await?;
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes).safe("Fixture session-secret entropy is unavailable.")?;
    Ok(Config {
        organization_id: fixture.org.id,
        client_id: application.confidential.client_id.to_string(),
        client_secret: SecretString::from(text_field(&issued, "client_secret")?),
        issuer: api.origin.clone(),
        secret: SecretString::from(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)),
    })
}

/// Registers the fixture's exact callback URI and requires a full read-back match.
pub async fn register_callback(api: &Api, fixture: &Fixture, app: &BetterAuth) -> Result<()> {
    let application = fixture.app()?;
    let path = format!(
        "{}/oauth/clients/{}",
        application.path, application.confidential.client_id
    );
    let _: Value = api
        .json(
            Method::PUT,
            &format!("{path}/redirect-uris"),
            Some(json!({"redirect_uris":[app.callback.clone()]})),
            StatusCode::OK,
        )
        .await?;
    let persisted: Vec<String> = api
        .json(
            Method::GET,
            &format!("{path}/redirect-uris"),
            None,
            StatusCode::OK,
        )
        .await?;
    check(
        persisted.len() == 1 && persisted.first().is_some_and(|uri| uri == &app.callback),
        "Registered Better Auth callback did not round-trip exactly.",
    )
}

/// Owned fixture process with its run-generated endpoints and TLS trust anchor.
pub struct BetterAuth {
    process: Process,
    reader: Option<BufReader<tokio::process::ChildStdout>>,
    drain: Option<tokio::task::JoinHandle<()>>,
    seconds: u64,
    readiness: u64,
    ca: reqwest::Certificate,
    pub origin: String,
    pub callback: String,
}

impl BetterAuth {
    /// Spawns the fixture child on fresh run-owned storage and returns ownership
    /// immediately, before readiness, so the runtime can journal the process identity
    /// first. The private storage path is a process argument, letting the existing
    /// PID/birth-tick/private-directory recovery guard recognize this child.
    pub fn spawn(
        private: &PrivateDir,
        tls: &Tls,
        directory: Option<&Path>,
        seconds: u64,
        readiness: u64,
        config: &Config,
    ) -> Result<Self> {
        let root = directory
            .unwrap_or_else(|| Path::new("tools/better_auth_interop"))
            .canonicalize().safe(
            "Missing Better Auth fixture; run npm ci in tools/better_auth_interop or pass --better-auth-fixture.",
        )?;
        let installed = root.join("node_modules/better-auth/package.json");
        let declared = std::fs::read(root.join("package.json"))
            .safe("Missing Better Auth fixture package.json.")?;
        let declared: Value =
            serde_json::from_slice(&declared).safe("Invalid Better Auth fixture package.json.")?;
        let installed_version = package_version(&installed)?;
        check(
            declared
                .get("devDependencies")
                .and_then(|deps| deps.get("better-auth"))
                .and_then(Value::as_str)
                == Some(installed_version.as_str()),
            "Better Auth fixture dependency drift; run npm ci in tools/better_auth_interop.",
        )?;
        let id = Uuid::new_v4().simple().to_string();
        let cert = private.write(&format!("better-auth-{id}.pem"), &tls.cert)?;
        let key = private.write(&format!("better-auth-{id}.key"), &tls.key)?;
        let database = private.0.join(format!("better-auth-{id}.sqlite"));
        let mut command = command(&root, tls, &cert, &key, &database, config)?;
        let mut child = command
            .spawn()
            .safe("Cannot start Better Auth fixture; Node.js 24 must be available.")?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| Failure::harness("Missing Better Auth fixture output channel."))?;
        Ok(Self {
            process: Process(child),
            reader: Some(BufReader::new(stdout)),
            drain: None,
            seconds,
            readiness,
            ca: reqwest::Certificate::from_pem(
                &std::fs::read(&tls.ca).safe("Cannot read test CA.")?,
            )
            .safe("Cannot parse test CA.")?,
            origin: String::new(),
            callback: String::new(),
        })
    }

    /// Completes the private startup handshake and publishes the run's fixture endpoints.
    ///
    /// Readiness requires the pinned installed dependency, a completed discovery
    /// registration and the private ready handshake; any shortfall is a case failure,
    /// never silently successful coverage.
    pub async fn ready(&mut self) -> Result<()> {
        let mut reader = self
            .reader
            .take()
            .ok_or_else(|| Failure::harness("Missing Better Auth fixture output channel."))?;
        let ready =
            tokio::time::timeout(Duration::from_secs(self.readiness), handshake(&mut reader))
                .await
                .safe("Better Auth fixture readiness exceeded its deadline.")
                .and_then(std::convert::identity)?;
        self.drain = Some(tokio::spawn(async move {
            let _ = tokio::io::copy(&mut reader, &mut tokio::io::sink()).await;
        }));
        self.origin = format!("https://127.0.0.1:{}", ready.port);
        self.callback = format!("https://127.0.0.1:{}{}", ready.port, ready.callback);
        Ok(())
    }

    /// Supplies only the owned child's PID/birth ticks for the recovery journal.
    pub fn identity(&self) -> Result<Option<ProcessIdentity>> {
        ProcessIdentity::read(&self.process.0)
    }

    /// A fresh unauthenticated cookie jar bound to the run CA with redirects un-followed.
    pub fn jar(&self) -> Result<(Arc<reqwest::cookie::Jar>, reqwest::Client)> {
        let jar = Arc::new(reqwest::cookie::Jar::default());
        let client = reqwest::Client::builder()
            .tls_certs_only([self.ca.clone()])
            .cookie_provider(jar.clone())
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(self.seconds))
            .build()
            .safe("Cannot configure verified Better Auth fixture transport.")?;
        Ok((jar, client))
    }

    /// Stops and reaps only this fixture child; repeated cleanup is harmless.
    pub async fn stop(&mut self) -> Result<()> {
        if let Some(drain) = self.drain.take() {
            drain.abort();
        }
        self.process.stop().await
    }
}

/// Builds the fixture child command; the private storage path is a process argument so
/// the recovery guard's private-directory check in `/proc/<pid>/cmdline` recognizes it.
fn command(
    root: &Path,
    tls: &Tls,
    cert: &Path,
    key: &Path,
    database: &Path,
    config: &Config,
) -> Result<tokio::process::Command> {
    let mut command = tokio::process::Command::new(node_binary()?);
    command
        .env_clear()
        .env("PATH", "/usr/local/bin:/usr/bin:/bin")
        .current_dir(root)
        .arg("server.mjs")
        .arg(database)
        .env("NODE_EXTRA_CA_CERTS", &tls.ca)
        .env("PERMESI_FIXTURE_CERT", cert)
        .env("PERMESI_FIXTURE_KEY", key)
        .env("PERMESI_FIXTURE_SECRET", config.secret.expose_secret())
        .env("PERMESI_FIXTURE_ISSUER", &config.issuer)
        .env("PERMESI_FIXTURE_CLIENT_ID", &config.client_id)
        .env(
            "PERMESI_FIXTURE_CLIENT_SECRET",
            config.client_secret.expose_secret(),
        )
        .env(
            "PERMESI_FIXTURE_ORGANIZATION_ID",
            config.organization_id.to_string(),
        )
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    Ok(command)
}

struct Ready {
    port: u16,
    callback: String,
}

/// Resolves the Node.js entrypoint before the child environment is cleared.
fn node_binary() -> Result<PathBuf> {
    let paths = std::env::var_os("PATH").unwrap_or_default();
    std::env::split_paths(&paths)
        .map(|directory| directory.join("node"))
        .find(|path| path.is_file())
        .ok_or_else(|| {
            Failure::infrastructure(
                "Cannot start Better Auth fixture; Node.js 24 must be available.",
            )
        })
}

/// Reads the single private startup handshake, discarding any other output line.
async fn handshake(reader: &mut BufReader<tokio::process::ChildStdout>) -> Result<Ready> {
    loop {
        let mut line = String::new();
        let read = reader
            .read_line(&mut line)
            .await
            .safe("Cannot read Better Auth fixture handshake.")?;
        check(
            read > 0,
            "Better Auth fixture exited before readiness; run npm ci in tools/better_auth_interop.",
        )?;
        let Ok(value): std::result::Result<Value, _> = serde_json::from_str(line.trim()) else {
            continue;
        };
        if value.get("ready").and_then(Value::as_bool) != Some(true) {
            continue;
        }
        let port = value
            .get("port")
            .and_then(Value::as_u64)
            .and_then(|port| u16::try_from(port).ok())
            .ok_or_else(|| Failure::harness("Better Auth fixture reported an invalid port."))?;
        let callback = value
            .get("callback")
            .and_then(Value::as_str)
            .filter(|path| path.starts_with('/') && !path.contains(['?', '#']))
            .map(str::to_owned)
            .ok_or_else(|| Failure::harness("Better Auth fixture reported an invalid callback."))?;
        return Ok(Ready { port, callback });
    }
}

/// Compares the installed library version against the fixture's exact pin.
fn package_version(path: &Path) -> Result<String> {
    let manifest = std::fs::read(path).safe(
        "Better Auth fixture dependencies are missing; run npm ci in tools/better_auth_interop.",
    )?;
    let manifest: Value =
        serde_json::from_slice(&manifest).safe("Invalid installed Better Auth manifest.")?;
    manifest
        .get("version")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| Failure::harness("Installed Better Auth version is missing."))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The recovery guard recognizes an owned child only when its command line carries
    /// the private directory path; the fixture storage argument must preserve that.
    #[test]
    fn fixture_command_carries_the_private_storage_path() -> Result<()> {
        let private = PrivateDir::new()?;
        let tls = Tls::new(&private)?;
        let database = private.0.join("better-auth-test.sqlite");
        let config = Config {
            organization_id: Uuid::nil(),
            client_id: "client".to_owned(),
            client_secret: SecretString::from("secret"),
            issuer: "https://localhost:1".to_owned(),
            secret: SecretString::from("session-secret"),
        };
        let command = command(
            &private.0,
            &tls,
            &private.0.join("cert.pem"),
            &private.0.join("key.pem"),
            &database,
            &config,
        )?;
        let arguments = command
            .as_std()
            .get_args()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert!(
            arguments.contains(&database.to_string_lossy().into_owned())
                && arguments
                    .iter()
                    .any(|argument| argument.contains(&private.0.to_string_lossy().into_owned())),
            "fixture command must carry its private storage path for recovery"
        );
        Ok(())
    }
}
