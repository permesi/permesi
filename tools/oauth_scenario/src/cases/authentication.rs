//! Runtime-role HTTP verification of shared OPAQUE state across actual Permesi processes.
//! Client proofs never enter SQL or artifacts; gateway routing changes between start and finish.

use super::Context;
use crate::{
    client::{Api, PasswordFlow},
    error::{Result, check},
};
use reqwest::{Method, StatusCode};
use serde_json::Value;

/// Authenticate across replicas, reject replay, then verify purpose-specific session elevation.
pub async fn shared_exchanges(context: &mut Context<'_>) -> Result<()> {
    let anonymous = Api::anonymous(context.api.origin.clone(), context.api.client.clone());
    context.gateway.replica_a();
    let login = context
        .owner
        .password_proof(&anonymous, PasswordFlow::Login)
        .await?;
    context.gateway.replica_b();
    let response = login.finish(&anonymous).await?;
    let session = anonymous.authenticated_response(&response).await?;
    check(
        session.user_id == context.api.user_id,
        "Cross-replica login changed the verified user.",
    )?;
    check(
        login.finish(&anonymous).await?.status() == StatusCode::UNAUTHORIZED,
        "Cross-replica login replay issued authority.",
    )?;
    context.gateway.replica_a();
    let elevation = context
        .owner
        .password_proof(&session, PasswordFlow::Reauthenticate)
        .await?;
    context.gateway.replica_b();
    check(
        elevation.finish(&session).await?.status() == StatusCode::NO_CONTENT,
        "Cross-replica reauthentication failed.",
    )?;
    check(
        elevation.finish(&session).await?.status() == StatusCode::UNAUTHORIZED,
        "Cross-replica reauthentication replay succeeded.",
    )?;
    context.gateway.replica_a();
    let bound = context
        .owner
        .password_proof(&session, PasswordFlow::Reauthenticate)
        .await?;
    context.gateway.replica_b();
    check(
        bound.finish(context.api).await?.status() == StatusCode::UNAUTHORIZED,
        "A different session of the same user reused an elevation proof.",
    )?;
    check(
        bound.finish(&session).await?.status() == StatusCode::UNAUTHORIZED,
        "Rejected session binding did not consume the exchange.",
    )?;
    let current: Value = session
        .json(Method::GET, "/v1/auth/session", None, StatusCode::OK)
        .await?;
    check(
        current.get("session_kind").and_then(Value::as_str) == Some("full"),
        "Shared exchanges changed the established session kind.",
    )?;
    context.gateway.replica_a();
    Ok(())
}
