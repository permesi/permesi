//! Authorization validation, saved consent and tenant-boundary assertions.
//! Each case retains its own tenant fixture and verifies the real service boundary.

use crate::error::Safe;

use super::{
    Api, Context, Failure, Fixture, Method, Request, Resource, Result, StatusCode, Url, Uuid,
    Value, begin, callback, check, issue, json, snapshot,
};
use secrecy::ExposeSecret as _;

/// Starts anonymously on A, then resumes the stored request after actual Web OPAQUE login.
pub(super) async fn login_resume(context: &mut Context<'_>, fixture: &Fixture) -> Result<()> {
    let request = Request::new(context, fixture)?;
    context.browser.call(json!({"action":"new","actor":"resume","origin":context.api.origin,"callback":context.gateway.callback})).await?;
    let page = begin(context, &request, "resume").await?;
    check(
        page.get("stage").and_then(Value::as_str) == Some("login"),
        "Anonymous authorization did not enter existing login.",
    )?;
    context.gateway.replica_b();
    let login = context.browser.call(json!({"action":"login","actor":"resume","navigate":false,"email":context.owner.email,"password":context.owner.password.expose_secret()})).await?;
    let _ = context.api.authenticated(&login).await?;
    let callback_result = context
        .browser
        .call(json!({"action":"decision","actor":"resume","decision":"allow"}))
        .await?;
    let code = callback(
        &callback_result,
        &context.gateway.callback,
        &request.state,
        "code",
        &context.api.origin,
    )?;
    snapshot(context, fixture, &request, &code).await
}

/// Cancellation issues no code; saved consent covers only the exact request and prompt=consent is honored.
pub(super) async fn cancel_saved(context: &mut Context<'_>, fixture: &Fixture) -> Result<()> {
    let request = Request::new(context, fixture)?;
    let _ = begin(context, &request, "owner").await?;
    let result = context
        .browser
        .call(json!({"action":"decision","actor":"owner","decision":"cancel"}))
        .await?;
    check(
        callback(
            &result,
            &context.gateway.callback,
            &request.state,
            "error",
            &context.api.origin,
        )? == "access_denied",
        "Cancellation did not return access_denied.",
    )?;
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM oauth_authorization_codes WHERE client_id=$1")
            .bind(fixture.app()?.public.id)
            .fetch_one(context.pool)
            .await
            .safe("Cannot inspect cancellation state.")?;
    check(
        count == 0,
        "Cancelled request issued an authorization code.",
    )?;
    let first_code = issue(context, &request).await?;
    snapshot(context, fixture, &request, &first_code).await?;
    let saved_request = Request::new(context, fixture)?;
    let saved = begin(context, &saved_request, "owner").await?;
    let saved_code = callback(
        &saved,
        &context.gateway.callback,
        &saved_request.state,
        "code",
        &context.api.origin,
    )?;
    check(
        saved_code != first_code,
        "Saved consent reused a prior code.",
    )?;
    snapshot(context, fixture, &saved_request, &saved_code).await?;
    let mut prompted = Request::new(context, fixture)?;
    prompted.url = prompted.changed("prompt", Some("consent"));
    let page = begin(context, &prompted, "owner").await?;
    check(
        page.get("stage").and_then(Value::as_str) == Some("consent"),
        "prompt=consent was incorrectly skipped.",
    )?;
    let tampered = context
        .browser
        .call(json!({"action":"tamper","actor":"owner"}))
        .await?;
    check(
        tampered.get("status").and_then(Value::as_u64) == Some(400),
        "Browser consent accepted an added scope field.",
    )?;
    let fresh = begin(context, &prompted, "owner").await?;
    check(
        fresh.get("stage").and_then(Value::as_str) == Some("consent"),
        "Tampered consent prevented a fresh validated consent request.",
    )?;
    let form_widening = context
        .browser
        .call(json!({"action":"decision","actor":"owner","decision":"cancel"}))
        .await?;
    check(
        callback(
            &form_widening,
            &context.gateway.callback,
            &prompted.state,
            "error",
            &context.api.origin,
        )? == "access_denied",
        "Explicit consent cancellation failed.",
    )
}

/// Validates trusted-redirect errors independently; unsafe redirects must receive a direct error.
async fn protocol_error(
    api: &Api,
    url: &Url,
    expected: &str,
    trusted: bool,
    callback_uri: &str,
    state: &str,
) -> Result<()> {
    let path = format!("{}?{}", url.path(), url.query().unwrap_or(""));
    let response = api.response(Method::GET, &path, None).await?;
    if !trusted {
        return check(
            response.status() == StatusCode::BAD_REQUEST
                && response.headers().get(reqwest::header::LOCATION).is_none(),
            "Untrusted authorization request received an error redirect.",
        );
    }
    check(
        response.status() == StatusCode::SEE_OTHER,
        "Trusted protocol error did not redirect as specified.",
    )?;
    let location = response
        .headers()
        .get(reqwest::header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| Failure::assertion("Protocol error omitted validated redirect."))?;
    check(
        callback(
            &json!({"url":location}),
            callback_uri,
            state,
            "error",
            &api.origin,
        )? == expected,
        "Incorrect OAuth protocol error.",
    )
}

/// Exercises redirect attacks, PKCE downgrade, invalid scopes/response types and client lifecycle negatives.
pub(super) async fn validation(context: &mut Context<'_>, fixture: &Fixture) -> Result<()> {
    let request = Request::new(context, fixture)?;
    for uri in [
        format!("{}/extra", context.gateway.callback),
        format!("{}.attacker.test", context.gateway.callback),
        "https://attacker.example/callback".to_owned(),
        format!("{}?extra=1", context.gateway.callback),
    ] {
        protocol_error(
            context.api,
            &request.changed("redirect_uri", Some(&uri)),
            "invalid_request",
            false,
            &context.gateway.callback,
            &request.state,
        )
        .await?;
    }
    let unknown_scope = format!("unregistered-{}:read", Uuid::new_v4().simple());
    for (key, value, error) in [
        (
            "client_id",
            Some(Uuid::nil().to_string()),
            "invalid_request",
        ),
        (
            "response_type",
            Some("token".into()),
            "unsupported_response_type",
        ),
        ("scope", Some(unknown_scope), "invalid_scope"),
        (
            "scope",
            Some(
                fixture
                    .app()?
                    .scopes
                    .get(1)
                    .ok_or_else(|| Failure::harness("Missing disallowed scope."))?
                    .clone(),
            ),
            "invalid_scope",
        ),
        ("scope", Some("openid openid".into()), "invalid_scope"),
        ("scope", Some("platform:admin".into()), "invalid_scope"),
        ("code_challenge", None, "invalid_request"),
        ("code_challenge", Some("short".into()), "invalid_request"),
        (
            "code_challenge_method",
            Some("plain".into()),
            "invalid_request",
        ),
        ("code_challenge_method", None, "invalid_request"),
        ("nonce", None, "invalid_request"),
    ] {
        protocol_error(
            context.api,
            &request.changed(key, value.as_deref()),
            error,
            key != "client_id",
            &context.gateway.callback,
            &request.state,
        )
        .await?;
    }
    let app = fixture.app()?;
    let path = format!("{}/oauth/clients/{}", app.path, app.public.client_id);
    let _: Value = context
        .api
        .json(
            Method::PATCH,
            &path,
            Some(json!({"disabled":true})),
            StatusCode::OK,
        )
        .await?;
    protocol_error(
        context.api,
        &request.url,
        "invalid_request",
        false,
        &context.gateway.callback,
        &request.state,
    )
    .await?;
    context
        .api
        .status(Method::DELETE, &path, None, StatusCode::NO_CONTENT)
        .await?;
    protocol_error(
        context.api,
        &request.url,
        "invalid_request",
        false,
        &context.gateway.callback,
        &request.state,
    )
    .await
}

/// Non-member management fails without enumeration and a browser-supplied foreign tenant cannot override ancestry.
pub(super) async fn tenant_isolation(context: &mut Context<'_>, fixture: &Fixture) -> Result<()> {
    let app = fixture.app()?;
    context
        .outsider
        .status(
            Method::GET,
            &format!("{}/oauth/clients", app.path),
            None,
            StatusCode::NOT_FOUND,
        )
        .await?;
    context
        .outsider
        .status(Method::DELETE, &app.path, None, StatusCode::NOT_FOUND)
        .await?;
    let foreign: Resource = context
        .outsider
        .json(
            Method::POST,
            "/v1/orgs",
            Some(
                json!({"name":"Other tenant","slug":format!("foreign-{}",Uuid::new_v4().simple())}),
            ),
            StatusCode::CREATED,
        )
        .await?;
    let request = Request::new(context, fixture)?;
    protocol_error(
        context.api,
        &request.changed("organization_id", Some(&foreign.id.to_string())),
        "access_denied",
        true,
        &context.gateway.callback,
        &request.state,
    )
    .await?;
    protocol_error(
        context.outsider,
        &request.url,
        "access_denied",
        true,
        &context.gateway.callback,
        &request.state,
    )
    .await?;
    Ok(())
}
