//! Confidential-client credential lifecycle assertions.
//! Each case retains its own tenant fixture and verifies the real service boundary.

use crate::error::Safe;

use super::{
    Context, Failure, Fixture, Method, Result, StatusCode, Value, check, json, text_field,
};

/// Checks one-time secrets, metadata-only reads, overlap rotation and immediate revocation.
pub(super) async fn credentials(context: &mut Context<'_>, fixture: &Fixture) -> Result<()> {
    let app = fixture.app()?;
    let path = format!(
        "{}/oauth/clients/{}/secrets",
        app.path, app.confidential.client_id
    );
    let first: Value = context
        .api
        .json(Method::POST, &path, Some(json!({})), StatusCode::CREATED)
        .await?;
    let plaintext = text_field(&first, "client_secret")?;
    let id = first
        .pointer("/credential/id")
        .and_then(Value::as_str)
        .ok_or_else(|| Failure::harness("Secret identifier missing."))?;
    let metadata: Value = context
        .api
        .json(Method::GET, &path, None, StatusCode::OK)
        .await?;
    check(
        !serde_json::to_string(&metadata)
            .safe("Cannot inspect secret metadata.")?
            .contains(&plaintext),
        "Metadata exposed a client secret.",
    )?;
    let rotation_started = chrono::Utc::now();
    let rotated: Value = context
        .api
        .json(
            Method::POST,
            &format!("{path}/rotate"),
            Some(json!({"current_secret_id":id})),
            StatusCode::CREATED,
        )
        .await?;
    let rotation_finished = chrono::Utc::now();
    let expires = rotated
        .pointer("/previous/expires_at")
        .and_then(Value::as_str)
        .ok_or_else(|| Failure::assertion("Rotation omitted overlap expiration."))?;
    let expires =
        chrono::DateTime::parse_from_rfc3339(expires).safe("Invalid overlap timestamp.")?;
    let grace = chrono::Duration::seconds(context.credential_grace_seconds);
    let tolerance = chrono::Duration::seconds(1);
    check(
        text_field(&rotated, "client_secret")? != plaintext
            && expires > rotation_finished
            && expires >= rotation_started + grace - tolerance
            && expires <= rotation_finished + grace + tolerance,
        "Secret rotation did not enforce the configured overlap lifetime.",
    )?;
    let new_id = rotated
        .pointer("/credential/id")
        .and_then(Value::as_str)
        .ok_or_else(|| Failure::harness("Rotated identifier missing."))?;
    for id in [id, new_id] {
        context
            .api
            .status(
                Method::DELETE,
                &format!("{path}/{id}"),
                None,
                StatusCode::NO_CONTENT,
            )
            .await?;
    }
    let metadata: Vec<Value> = context
        .api
        .json(Method::GET, &path, None, StatusCode::OK)
        .await?;
    check(metadata.is_empty(), "Revoked client secrets remain active.")?;
    context
        .api
        .status(
            Method::POST,
            &format!(
                "{}/oauth/clients/{}/secrets",
                app.path, app.public.client_id
            ),
            Some(json!({})),
            StatusCode::BAD_REQUEST,
        )
        .await?;
    Ok(())
}
