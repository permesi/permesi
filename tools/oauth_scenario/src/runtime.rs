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
    interop::Transport,
    journal::Journal,
    manifest::Manifest,
    podman::Podman,
    registry::Case,
    report::Report,
    resource::ResourceServer,
    services::Services,
    tls::Tls,
    topology::Topology,
};
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
    resource: Option<ResourceServer>,
}

impl Runtime {
    /// Performs read-only engine preflight; no container or network exists until execute begins.
    pub async fn new(id: String) -> Result<Self> {
        let private = PrivateDir::new()?;
        let engine = Podman::new(id).await?;
        private.write("owner", engine.run_id.as_bytes())?;
        Ok(Self {
            private,
            engine,
            services: Services::default(),
            gateway: None,
            browser: None,
            infra: None,
            resource: None,
        })
    }

    /// Writes a non-secret ownership record before startup so interrupted runs can be recovered manually.
    pub fn ownership(&mut self, directory: &Path, repetition: u32) -> Result<()> {
        self.services.journal(Journal::new(
            directory,
            repetition,
            &self.engine.run_id,
            &self.engine.network,
            &self.private.0,
        ))
    }

    /// Starts the stack in recorded ownership order; partial startup always stays available for cleanup.
    pub async fn execute(
        &mut self,
        inputs: &Inputs<'_>,
        repetition: u32,
        report: &mut Report,
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
        let topology = Topology::new(&self.private.0, options.replicas)?;
        self.gateway =
            Some(Gateway::start(&tls, inputs.web, &topology, options.request_seconds).await?);
        let gateway = self
            .gateway
            .as_ref()
            .ok_or_else(|| Failure::harness("Issuer state missing."))?;
        println!(
            "Starting real Genesis and {} Permesi replicas.",
            options.replicas
        );
        let policy = self.services.start(
            inputs.binaries,
            &topology,
            infra,
            &gateway.origin,
            &tls.ca,
            options,
        )?;
        report.record_rate_budgets(&policy);
        self.resource =
            Some(start_resource(&tls, gateway, &policy.oauth, options.request_seconds).await?);
        self.services.resource_origin(
            &self
                .resource
                .as_ref()
                .ok_or_else(|| Failure::harness("Resource server state missing."))?
                .origin,
        )?;
        self.services.ready().await?;
        start_browser(
            &mut self.engine,
            &mut self.browser,
            &mut self.services,
            &tls,
            options,
            report,
        )
        .await?;
        let browser = self
            .browser
            .as_mut()
            .ok_or_else(|| Failure::harness("Browser state missing."))?;
        let anonymous =
            Api::anonymous(gateway.origin.clone(), tls.client(options.request_seconds)?);
        println!("Registering and authenticating real fixture accounts.");
        let (owner, api, outsider) =
            fixture_actors(browser, &anonymous, &infra.pool, &gateway.callback).await?;
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
                    access_token_ttl_seconds: policy.access_token_ttl_seconds,
                    resource: self
                        .resource
                        .as_ref()
                        .ok_or_else(|| Failure::harness("Resource server state missing."))?,
                    infrastructure: infra,
                    manifest: inputs.manifest,
                    fixture_seed: options.seed,
                };
                cases::execute(case.id, &mut context, &fixture).await
            }
            .await;
            if let Err(error) = self.services.restore_stopped().await {
                report.record(*case, repetition, started, result.and(Err(error.clone())));
                return Err(error);
            }
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
            } else if let Err(error) = self.services.browser_identity(None) {
                errors.push(error);
            }
        }
        errors.extend(self.services.stop().await);
        if let Some(resource) = &mut self.resource {
            let result = tokio::time::timeout(std::time::Duration::from_secs(5), resource.stop())
                .await
                .safe("Resource shutdown exceeded its deadline.")
                .and_then(std::convert::identity);
            if let Err(error) = result {
                errors.push(error);
            }
        }
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

/// Creates both real accounts and browser sessions through the product; no session or role row is seeded.
async fn fixture_actors(
    browser: &mut Browser,
    anonymous: &Api,
    pool: &sqlx::PgPool,
    callback: &str,
) -> Result<(Actor, Api, Api)> {
    let owner = Actor::signup(anonymous, pool).await?;
    let api = owner.login(browser, anonymous, callback, "owner").await?;
    let outsider = Actor::signup(anonymous, pool).await?;
    let outsider = outsider
        .login(browser, anonymous, callback, "outsider")
        .await?;
    Ok((owner, api, outsider))
}

/// Starts the owned TLS resource with the product-parsed issuer/audience and normal verification.
async fn start_resource(
    tls: &Tls,
    gateway: &Gateway,
    policy: &permesi::oauth::config::OAuthConfig,
    seconds: u64,
) -> Result<ResourceServer> {
    ResourceServer::start(
        tls,
        Transport {
            client: tls.client(seconds)?,
            issuer: gateway.origin.clone(),
        },
        policy
            .audience
            .clone()
            .ok_or_else(|| Failure::harness("Missing resource audience."))?,
    )
    .await
}

/// Builds/verifies the private browser worker and retains its handle across cancellation.
async fn start_browser(
    engine: &mut Podman,
    browser: &mut Option<Browser>,
    services: &mut Services,
    tls: &Tls,
    options: &Options,
    report: &mut Report,
) -> Result<()> {
    let files = PrivateDir::new()?;
    files.write("Containerfile", include_bytes!("../browser/Containerfile"))?;
    files.write("browser.mjs", include_bytes!("../browser/browser.mjs"))?;
    files.write("entrypoint.sh", include_bytes!("../browser/entrypoint.sh"))?;
    println!("Starting isolated Chromium with the run CA.");
    let image = engine
        .browser_image(&options.browser_image, &files.0)
        .await?;
    report.components.browser_image = engine.image_identity(&image).await?;
    report.components.postgres_image = engine
        .image_identity(crate::infrastructure::POSTGRES_IMAGE)
        .await?;
    report.components.vault_image = engine
        .image_identity(crate::infrastructure::VAULT_IMAGE)
        .await?;
    *browser = Some(Browser::spawn(
        engine,
        &image,
        &tls.ca,
        options.browser_seconds,
    )?);
    let browser = browser
        .as_mut()
        .ok_or_else(|| Failure::harness("Missing browser ownership."))?;
    services.browser_identity(browser.identity()?)?;
    browser.ready().await?;
    engine.verify_private_logs().await
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
        result=tokio::time::timeout_at(deadline,runtime.execute(inputs,number,report))=>result.safe("Scenario run exceeded its total deadline.").and_then(std::convert::identity),
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
