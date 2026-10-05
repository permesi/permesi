//! Run ownership and unconditional cleanup, including cancellation and partial startup.

use crate::{
    browser::Browser,
    cases,
    cli::Options,
    client::{Actor, Api, Fixture},
    error::{Failure, Result, Safe},
    files::PrivateDir,
    gateway::Gateway,
    infrastructure::Infrastructure,
    manifest::Manifest,
    podman::Podman,
    registry::Case,
    report::Report,
    services::Services,
    tls::Tls,
};
use serde_json::json;
use std::{path::Path, time::Instant};

/// Validated immutable inputs, separate from mutable resources that must survive cancellation.
pub struct Inputs<'a> {
    pub options: &'a Options,
    pub selected: &'a [Case],
    pub manifest: &'a Manifest,
    pub binaries: [&'a Path; 2],
    pub web: &'a Path,
}

/// Every resource handle remains here when the scenario future is cancelled.
pub struct Runtime {
    private: PrivateDir,
    engine: Podman,
    services: Services,
    gateway: Option<Gateway>,
    browser: Option<Browser>,
    infra: Option<Infrastructure>,
}

impl Runtime {
    /// Performs read-only engine preflight; no container or network exists until execute begins.
    pub async fn new(id: String) -> Result<Self> {
        Ok(Self {
            private: PrivateDir::new()?,
            engine: Podman::new(id).await?,
            services: Services::default(),
            gateway: None,
            browser: None,
            infra: None,
        })
    }

    /// Writes a non-secret ownership record before startup so interrupted runs can be recovered manually.
    pub fn ownership(&self, directory: &Path, repetition: u32) -> Result<()> {
        let ownership = json!({"schema_version":1,"run_id":self.engine.run_id,"engine":"local Podman","network":self.engine.network,"containers":[format!("ps-{}-postgres",self.engine.run_id),format!("ps-{}-vault",self.engine.run_id),format!("ps-{}-browser",self.engine.run_id)],"private_directory":self.private.0,"processes":self.services.identities()});
        std::fs::write(
            directory.join(format!("ownership-{repetition}.json")),
            serde_json::to_vec_pretty(&ownership).safe("Cannot encode ownership record.")?,
        )
        .safe("Cannot write ownership record.")
    }

    /// Starts the stack in recorded ownership order; partial startup always stays available for cleanup.
    pub async fn execute(
        &mut self,
        inputs: &Inputs<'_>,
        repetition: u32,
        report: &mut Report,
        directory: &Path,
    ) -> Result<()> {
        let options = inputs.options;
        self.engine.create_network().await?;
        println!("Starting disposable PostgreSQL and Vault.");
        self.infra = Some(
            Infrastructure::start(&mut self.engine, &self.private, options.readiness_seconds)
                .await?,
        );
        let infra = self
            .infra
            .as_ref()
            .ok_or_else(|| Failure::harness("Infrastructure state missing."))?;
        let tls = Tls::new(&self.private)?;
        let sockets = [
            self.private.0.join("a.sock"),
            self.private.0.join("b.sock"),
            self.private.0.join("genesis.sock"),
        ];
        let [a, b, g] = &sockets;
        self.gateway =
            Some(Gateway::start(&tls, inputs.web, [a, b, g], options.request_seconds).await?);
        let gateway = self
            .gateway
            .as_ref()
            .ok_or_else(|| Failure::harness("Issuer state missing."))?;
        println!("Starting real Genesis and Permesi replicas A/B.");
        let policy =
            self.services
                .start(inputs.binaries, &sockets, infra, &gateway.origin, &tls.ca)?;
        self.ownership(directory, repetition)?;
        Services::ready(&sockets, options.readiness_seconds).await?;
        let browser_files = PrivateDir::new()?;
        browser_files.write("Containerfile", include_bytes!("../browser/Containerfile"))?;
        browser_files.write("browser.mjs", include_bytes!("../browser/browser.mjs"))?;
        browser_files.write("entrypoint.sh", include_bytes!("../browser/entrypoint.sh"))?;
        println!("Starting isolated Chromium with the run CA.");
        let image = self
            .engine
            .browser_image(&options.browser_image, &browser_files.0)
            .await?;
        report.components.browser_image = self.engine.image_identity(&image).await?;
        report.components.postgres_image = self
            .engine
            .image_identity(crate::infrastructure::POSTGRES_IMAGE)
            .await?;
        report.components.vault_image = self
            .engine
            .image_identity(crate::infrastructure::VAULT_IMAGE)
            .await?;
        self.browser =
            Some(Browser::start(&mut self.engine, &image, &tls.ca, options.browser_seconds).await?);
        self.engine.verify_private_logs().await?;
        let browser = self
            .browser
            .as_mut()
            .ok_or_else(|| Failure::harness("Browser state missing."))?;
        let anonymous =
            Api::anonymous(gateway.origin.clone(), tls.client(options.request_seconds)?);
        println!("Registering and authenticating real fixture accounts.");
        let owner = Actor::signup(&anonymous, &infra.pool).await?;
        let api = owner
            .login(browser, &anonymous, &gateway.callback, "owner")
            .await?;
        let outsider = Actor::signup(&anonymous, &infra.pool).await?;
        let outsider = outsider
            .login(browser, &anonymous, &gateway.callback, "outsider")
            .await?;
        for case in inputs.selected {
            gateway.replica_a();
            let started = Instant::now();
            let result = async {
                let fixture =
                    Fixture::create(&api, inputs.manifest, options.seed, &gateway.callback).await?;
                let mut context = cases::Context {
                    browser,
                    services: &mut self.services,
                    gateway,
                    owner: &owner,
                    api: &api,
                    outsider: &outsider,
                    pool: &infra.pool,
                    admin_dsn: &infra.admin_dsn,
                    policy: &policy.oauth,
                    credential_grace_seconds: policy.credential_grace_seconds,
                };
                cases::execute(case.id, &mut context, &fixture).await
            }
            .await;
            report.record(*case, repetition, started, result);
        }
        Ok(())
    }

    /// Attempts every resource cleanup independently; failed process stops do not prevent container removal.
    pub async fn cleanup(&mut self, seconds: u64) -> Vec<Failure> {
        let mut errors = Vec::new();
        if let Some(browser) = &mut self.browser {
            let result = tokio::time::timeout(std::time::Duration::from_secs(5), browser.stop())
                .await
                .safe("Browser shutdown exceeded its deadline.")
                .and_then(std::convert::identity);
            if let Err(error) = result {
                errors.push(error);
            }
        }
        errors.extend(self.services.stop().await);
        if let Some(gateway) = &mut self.gateway {
            let result = tokio::time::timeout(std::time::Duration::from_secs(5), gateway.stop())
                .await
                .safe("Gateway shutdown exceeded its deadline.")
                .and_then(std::convert::identity);
            if let Err(error) = result {
                errors.push(error);
            }
        }
        if let Some(infra) = &self.infra
            && tokio::time::timeout(std::time::Duration::from_secs(5), infra.pool.close())
                .await
                .is_err()
        {
            errors.push(Failure::harness(
                "Database pool shutdown exceeded its deadline.",
            ));
        }
        // Each owned removal has its own deadline; one timeout must not cancel the remaining cleanup.
        errors.extend(self.engine.cleanup_bounded(seconds).await);
        if let Err(error) = self.private.remove() {
            errors.push(error);
        }
        for error in &mut errors {
            error.kind = crate::error::Kind::Cleanup;
        }
        errors
    }
}

/// Runs one independent stack under the whole-run deadline, then cleans up outside that cancelled future.
pub async fn repetition(
    inputs: &Inputs<'_>,
    number: u32,
    directory: &Path,
    deadline: tokio::time::Instant,
    report: &mut Report,
) -> Result<()> {
    let mut runtime = Runtime::new(format!("{}-{number}", report.run_id)).await?;
    runtime.ownership(directory, number)?;
    let result = tokio::select! {
        result=tokio::time::timeout_at(deadline,runtime.execute(inputs,number,report,directory))=>result.safe("Scenario run exceeded its total deadline.").and_then(std::convert::identity),
        ()=interrupted()=>Err(Failure::harness("Scenario run interrupted; owned resources are being removed.")),
    };
    println!("Cleaning up owned processes and containers.");
    report
        .cleanup_failures
        .extend(runtime.cleanup(inputs.options.cleanup_seconds).await);
    result
}

/// SIGINT/SIGTERM cancel scenario work while preserving the separate cleanup phase.
async fn interrupted() {
    let Ok(mut term) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
    else {
        std::future::pending::<()>().await;
        return;
    };
    tokio::select! { _=tokio::signal::ctrl_c()=>{}, _=term.recv()=>{} }
}
