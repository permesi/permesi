//! Health endpoints expose a process heartbeat and fresh background observations.
//! Each public request reads local state. Dependency access belongs to the monitor.

use axum::{
    extract::State,
    http::{Method, StatusCode},
    response::{IntoResponse, Json},
};
use serde::Serialize;
use service_utils::health::Observation;
use utoipa::ToSchema;

#[derive(ToSchema, Serialize)]
pub struct Health {
    commit: &'static str,
    status: &'static str,
}

#[utoipa::path(get, path="/live", responses((status=200, description="Process is alive")),tag="health")]
/// Report process liveness independently of dependencies.
pub async fn live() -> StatusCode {
    StatusCode::OK
}

#[utoipa::path(get, path="/ready", responses((status=200, description="Ready"),(status=503, description="Unavailable")),tag="health")]
/// Report whether this replica can receive traffic from the service.
pub async fn ready(State(observation): State<Observation>) -> StatusCode {
    if observation.healthy() {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}

#[utoipa::path(get, path="/health", responses((status=200, description="Service available",body=Health),(status=503, description="Unavailable",body=Health)),tag="health")]
/// Return coarse service status and build identity from local state.
pub async fn health(method: Method, State(observation): State<Observation>) -> impl IntoResponse {
    let (code, status) = if observation.healthy() {
        (StatusCode::OK, "ok")
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "unavailable")
    };
    let body = if method == Method::GET {
        Json(Health {
            commit: crate::GIT_COMMIT_HASH,
            status,
        })
        .into_response()
    } else {
        ().into_response()
    };
    (
        code,
        [(
            "X-App",
            concat!(env!("CARGO_PKG_NAME"), ":", env!("CARGO_PKG_VERSION")),
        )],
        body,
    )
}
