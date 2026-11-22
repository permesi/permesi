//! Shared state for the Genesis HTTP router.
//!
//! The router is finished with `with_state(AppState)`, so a handler asking for a
//! dependency the router does not provide fails to compile instead of returning
//! a runtime 500 from a missing `Extension` layer. `#[derive(FromRef)]` lets
//! handlers extract only the parts they use (`State<PgPool>`, ...). Per-request
//! values such as the `RequestId` remain request extensions.

use crate::{api::admission::AdmissionSigner, openbao::renew::ShutdownSignal};
use axum::extract::FromRef;
use sqlx::PgPool;
use std::sync::Arc;
use tokio::sync::mpsc;

/// Dependencies shared by every Genesis route.
#[derive(Clone, FromRef)]
pub struct AppState {
    #[from_ref(skip)]
    pub public_budget: Arc<service_utils::work_limit::Budget>,

    /// Last bounded background readiness observation.
    pub observation: service_utils::health::Observation,
    /// Admission token signer (OpenBao transit) and PASERK keyset source.
    pub admission: Arc<AdmissionSigner>,
    /// Fail-closed shutdown channel used by readiness probes.
    pub shutdown: mpsc::UnboundedSender<ShutdownSignal>,
    /// Shared PostgreSQL pool.
    pub pool: PgPool,
}
