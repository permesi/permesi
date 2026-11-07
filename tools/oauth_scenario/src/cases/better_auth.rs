//! Real Better Auth sign-in and tampered-state rejection over the disposable stack.
//!
//! Flow Overview: a fresh cookie jar drives the library's standard sign-in and
//! callback handlers while a real browser completes Permesi login and consent.
//! The success case proves the full authenticated link and usable local session.
//! The negative case delivers an actual callback with only its state tampered,
//! requires rejection with unchanged protected state, and finishes with a valid
//! control so a fixture that rejects everything can never pass.

use super::{
    Context, Failure, Fixture, Result, Row, Safe, StatusCode, Url, Value, callback, check, json,
    text_field,
};
use crate::better_auth::BetterAuth;
use reqwest::cookie::CookieStore as _;
use secrecy::ExposeSecret as _;

/// Exact protocol scope labels rendered by the real Permesi consent page.
const LABELS: [&str; 3] = [
    "Sign in and identify your account",
    "Read your profile",
    "Read your verified email address",
];

/// Better Auth fixture storage counts: local users, linked accounts, sessions, pending states.
type Counts = (i64, i64, i64, i64);

/// A library-generated authorization request with its actual stored state.
struct SignIn {
    url: Url,
    state: String,
}

/// One complete Better Auth sign-in: real consent, real callback and verified linked identity.
pub(super) async fn login(context: &mut Context<'_>, fixture: &Fixture) -> Result<()> {
    let app = context
        .better_auth
        .ok_or_else(|| Failure::harness("Missing Better Auth fixture."))?;
    let actor = "better-auth-login";
    context
        .browser
        .call(json!({
            "action":"new","actor":actor,
            "origin":context.api.origin,
            "callback":app.callback,
            "app":app.origin
        }))
        .await?;
    let page = context
        .browser
        .call(json!({"action":"app_start","actor":actor}))
        .await?;
    check(
        page.get("stage").and_then(Value::as_str) == Some("login"),
        "Better Auth sign-in did not reach Permesi login.",
    )?;
    let login = context
        .browser
        .call(json!({"action":"login","actor":actor,"navigate":false,
            "email":context.owner.email,"password":context.owner.password.expose_secret()}))
        .await?;
    let _ = context.api.authenticated(&login).await?;
    consent_labels(context, actor).await?;
    let result = context
        .browser
        .call(json!({"action":"decision","actor":actor,"decision":"allow"}))
        .await?;
    check(
        result.get("stage").and_then(Value::as_str) == Some("app_done"),
        "Better Auth did not complete the real callback into its authenticated page.",
    )?;
    let session = fetch(context, actor, "/api/auth/get-session").await?;
    let identity = fetch(context, actor, "/fixture/identity").await?;
    verify_identity(context, &session, &identity)?;
    check(
        counts(context, app).await? == (1, 1, 1, 0),
        "Better Auth did not persist exactly one user, account and session.",
    )?;
    check(
        issuances(context, fixture).await? == vec![scopes()],
        "Permesi did not commit exactly one openid/profile/email issuance.",
    )
}

/// A tampered state on an actual callback is rejected without touching protected state;
/// the same actual callback delivered unmodified is accepted as the valid control.
pub(super) async fn state_reject(context: &mut Context<'_>, fixture: &Fixture) -> Result<()> {
    let app = context
        .better_auth
        .ok_or_else(|| Failure::harness("Missing Better Auth fixture."))?;
    let (jar, client) = app.jar()?;
    let sign_in = sign_in(&client, app, context.api.origin.as_str(), fixture).await?;
    check(
        jar.cookies(&Url::parse(&app.origin).safe("Invalid Better Auth origin.")?)
            .is_some_and(|cookies| !cookies.is_empty()),
        "Better Auth sign-in did not set its library-managed state cookie.",
    )?;
    check(
        counts(context, app).await? == (0, 0, 0, 1),
        "Better Auth did not store exactly one pending state.",
    )?;
    let actor = "better-auth-state";
    let result = actual_callback(context, app, &sign_in, actor).await?;
    let raw = text_field(&result, "url")?;
    let _code = callback(
        &result,
        &app.callback,
        &sign_in.state,
        "code",
        &context.api.origin,
    )?;
    // The negative delivery differs from the actual callback only in one state character.
    let tampered = tamper_state(&raw, &sign_in.state)?;
    let response = client
        .get(&tampered)
        .send()
        .await
        .safe("Better Auth tampered callback request failed.")?;
    check(
        response.status().is_redirection()
            && redirect_location(&response)
                == format!("{}/api/auth/error?error=state_mismatch", app.origin),
        "Better Auth did not reject a tampered callback state.",
    )?;
    check(
        counts(context, app).await? == (0, 0, 0, 1),
        "A tampered callback state changed Better Auth protected state.",
    )?;
    let (status, body) = jar_json(&client, app, "/api/auth/get-session").await?;
    check(
        status == StatusCode::OK && body == Value::Null,
        "A tampered callback created an authenticated Better Auth session.",
    )?;
    let (status, _) = jar_json(&client, app, "/fixture/identity").await?;
    check(
        status == StatusCode::UNAUTHORIZED,
        "A tampered callback reached protected fixture state.",
    )?;
    check(
        issuances(context, fixture).await? == Vec::<Vec<String>>::new(),
        "A tampered callback state consumed the authorization code.",
    )?;
    // Fresh valid control: the same actual callback and jar, only without the tampering.
    let response = client
        .get(&raw)
        .send()
        .await
        .safe("Better Auth valid control request failed.")?;
    check(
        response.status().is_redirection()
            && redirect_location(&response) == format!("{}/done", app.origin),
        "Better Auth rejected a genuine unmodified callback.",
    )?;
    let (status, session) = jar_json(&client, app, "/api/auth/get-session").await?;
    check(
        status == StatusCode::OK && session.is_object(),
        "The valid control did not establish a usable local session.",
    )?;
    let (status, identity) = jar_json(&client, app, "/fixture/identity").await?;
    check(
        status == StatusCode::OK,
        "The valid control did not reach the authenticated fixture identity.",
    )?;
    verify_identity(context, &session, &identity)?;
    check(
        counts(context, app).await? == (1, 1, 1, 0),
        "The valid control did not persist exactly one user, account and session.",
    )?;
    check(
        issuances(context, fixture).await? == vec![scopes()],
        "The valid control did not commit exactly one openid/profile/email issuance.",
    )
}

/// Drives real Permesi login and consent and captures the actual callback the browser delivered.
/// The browser holds no sign-in jar state cookie, so the library rejects this first delivery
/// without consuming the stored state or the authorization code.
async fn actual_callback(
    context: &mut Context<'_>,
    app: &BetterAuth,
    sign_in: &SignIn,
    actor: &str,
) -> Result<Value> {
    context
        .browser
        .call(json!({
            "action":"new","actor":actor,
            "origin":context.api.origin,
            "callback":app.callback,
            "app":app.origin
        }))
        .await?;
    let page = context
        .browser
        .call(json!({"action":"authorize","actor":actor,"url":sign_in.url.as_str()}))
        .await?;
    check(
        page.get("stage").and_then(Value::as_str) == Some("login"),
        "Better Auth authorization did not reach Permesi login.",
    )?;
    let login = context
        .browser
        .call(json!({"action":"login","actor":actor,"navigate":false,
            "email":context.owner.email,"password":context.owner.password.expose_secret()}))
        .await?;
    let _ = context.api.authenticated(&login).await?;
    consent_labels(context, actor).await?;
    let result = context
        .browser
        .call(json!({"action":"decision","actor":actor,"decision":"allow",
            "capture":app.callback}))
        .await?;
    check(
        result.get("stage").and_then(Value::as_str) == Some("app_error")
            && result.get("error").and_then(Value::as_str) == Some("state_mismatch"),
        "A callback without the sign-in jar's state cookie was not rejected.",
    )?;
    Ok(result)
}

/// Starts a real library sign-in and requires the exact expected authorization request.
async fn sign_in(
    client: &reqwest::Client,
    app: &BetterAuth,
    issuer: &str,
    fixture: &Fixture,
) -> Result<SignIn> {
    let response = client
        .post(format!("{}/api/auth/sign-in/social", app.origin))
        .json(&json!({
            "provider":"permesi",
            "callbackURL":format!("{}/done", app.origin),
            "errorCallbackURL":format!("{}/sign-in-error", app.origin),
            "disableRedirect":true
        }))
        .send()
        .await
        .safe("Better Auth sign-in request failed.")?;
    check(
        response.status() == StatusCode::OK,
        "Better Auth sign-in handler rejected the request.",
    )?;
    let body: Value = response
        .json()
        .await
        .safe("Invalid Better Auth sign-in response.")?;
    let url =
        Url::parse(&text_field(&body, "url")?).safe("Invalid Better Auth authorization URL.")?;
    let pairs = url
        .query_pairs()
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect::<Vec<_>>();
    let one = |name: &str| -> Result<&str> {
        let mut values = pairs.iter().filter(|(key, _)| key == name);
        let value = values
            .next()
            .ok_or_else(|| Failure::assertion("Better Auth authorization parameter missing."))?;
        check(
            values.next().is_none(),
            "Better Auth duplicated a library-managed authorization parameter.",
        )?;
        Ok(value.1.as_str())
    };
    let state = one("state")?.to_owned();
    check(
        url.origin().ascii_serialization() == issuer
            && url.path() == "/authorize"
            && one("response_type")? == "code"
            && one("client_id")? == fixture.app()?.confidential.client_id.to_string()
            && one("redirect_uri")? == app.callback
            && one("scope")? == "openid profile email"
            && one("code_challenge_method")? == "S256"
            && !one("code_challenge")?.is_empty()
            && !one("nonce")?.is_empty()
            && !state.is_empty()
            && one("organization_id")? == fixture.org.id.to_string(),
        "Better Auth authorization request differs from the expected OIDC flow.",
    )?;
    Ok(SignIn { url, state })
}

/// Asserts the real consent surface requested exactly the configured protocol scopes.
async fn consent_labels(context: &mut Context<'_>, actor: &str) -> Result<()> {
    let page = context
        .browser
        .call(json!({"action":"stage","actor":actor}))
        .await?;
    check(
        page.get("stage").and_then(Value::as_str) == Some("consent"),
        "Better Auth flow unexpectedly skipped Permesi consent.",
    )?;
    let mut displayed = page
        .get("items")
        .and_then(Value::as_array)
        .ok_or_else(|| Failure::assertion("Consent omitted scope labels."))?
        .iter()
        .map(|item| {
            item.as_str()
                .map(str::to_owned)
                .ok_or_else(|| Failure::assertion("Invalid consent label."))
        })
        .collect::<Result<Vec<_>>>()?;
    let mut expected = LABELS
        .iter()
        .copied()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    displayed.sort();
    expected.sort();
    check(
        displayed == expected,
        "Consent displayed incorrect or widened scope descriptions.",
    )
}

/// Reads one fixture JSON response through the browser's own session cookie jar.
async fn fetch(context: &mut Context<'_>, actor: &str, path: &str) -> Result<Value> {
    let result = context
        .browser
        .call(json!({"action":"fetch","actor":actor,"path":path}))
        .await?;
    check(
        result.get("status").and_then(Value::as_u64) == Some(200),
        "Better Auth fixture request was not authenticated.",
    )?;
    serde_json::from_str(&text_field(&result, "body")?)
        .safe("Invalid Better Auth fixture response.")
}

/// Sends one fixture request from a case cookie jar without following the redirect.
async fn jar_json(
    client: &reqwest::Client,
    app: &BetterAuth,
    path: &str,
) -> Result<(StatusCode, Value)> {
    let response = client
        .get(format!("{}{path}", app.origin))
        .send()
        .await
        .safe("Better Auth fixture request failed.")?;
    let status = response.status();
    let body: Value = response
        .json()
        .await
        .safe("Invalid Better Auth fixture response.")?;
    Ok((status, body))
}

/// Compares the authenticated session identity and linked provider subject with the fixture owner.
fn verify_identity(context: &Context<'_>, session: &Value, identity: &Value) -> Result<()> {
    let owner = context
        .api
        .user_id
        .ok_or_else(|| Failure::harness("Missing authenticated scenario subject."))?;
    let session_user = text_field(
        session
            .get("user")
            .ok_or_else(|| Failure::assertion("Better Auth session omitted its user."))?,
        "id",
    )?;
    check(
        session.get("session").is_some()
            && text_field(identity, "userId")? == session_user
            && text_field(identity, "email")? == context.owner.email,
        "Better Auth session identity differs from the fixture owner.",
    )?;
    check(
        identity
            .get("linked")
            .and_then(Value::as_array)
            .is_some_and(|linked| {
                linked.len() == 1
                    && linked.first().is_some_and(|entry| {
                        entry == &json!({"providerId":"permesi","accountId":owner.to_string()})
                    })
            }),
        "Better Auth linked account subject differs from the fixture owner.",
    )
}

/// Reads current fixture storage counts from the unauthenticated inspection route.
async fn counts(context: &Context<'_>, app: &BetterAuth) -> Result<Counts> {
    let response = context
        .api
        .client
        .get(format!("{}/fixture/state", app.origin))
        .send()
        .await
        .safe("Better Auth fixture state request failed.")?;
    check(
        response.status() == StatusCode::OK,
        "Better Auth fixture state request was rejected.",
    )?;
    let body: Value = response
        .json()
        .await
        .safe("Invalid Better Auth fixture state.")?;
    let field = |name: &str| -> Result<i64> {
        body.get(name)
            .and_then(Value::as_i64)
            .ok_or_else(|| Failure::assertion("Better Auth fixture state field missing."))
    };
    Ok((
        field("users")?,
        field("accounts")?,
        field("sessions")?,
        field("verifications")?,
    ))
}

/// Reads committed Permesi issuance scopes for this client and owner.
async fn issuances(context: &Context<'_>, fixture: &Fixture) -> Result<Vec<Vec<String>>> {
    let rows = sqlx::query(
        "SELECT i.scope_names FROM oauth_token_issuances i \
         JOIN oauth_clients c ON c.id=i.client_id \
         WHERE c.client_id=$1 AND i.user_id=$2 AND i.organization_id=$3",
    )
    .bind(fixture.app()?.confidential.client_id)
    .bind(
        context
            .api
            .user_id
            .ok_or_else(|| Failure::harness("Missing authenticated scenario subject."))?,
    )
    .bind(fixture.org.id)
    .fetch_all(context.pool)
    .await
    .safe("Cannot inspect Better Auth token issuances.")?;
    rows.iter()
        .map(|row| {
            let mut scopes: Vec<String> = row
                .try_get("scope_names")
                .safe("Missing issuance scopes.")?;
            scopes.sort();
            Ok(scopes)
        })
        .collect()
}

/// The exact consented protocol scopes in their sorted issuance form.
fn scopes() -> Vec<String> {
    let mut scopes = ["email", "openid", "profile"]
        .iter()
        .copied()
        .map(str::to_string)
        .collect::<Vec<_>>();
    scopes.sort();
    scopes
}

/// Rewrites only the actual callback's state field, preserving every other parameter.
fn tamper_state(raw: &str, expected: &str) -> Result<String> {
    let mut url = Url::parse(raw).safe("Invalid actual Better Auth callback.")?;
    let pairs = url
        .query_pairs()
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect::<Vec<_>>();
    check(
        pairs.iter().filter(|(key, _)| key == "state").count() == 1,
        "Actual Better Auth callback does not carry exactly one state.",
    )?;
    let mut tampered = expected.to_owned();
    let last = tampered
        .pop()
        .ok_or_else(|| Failure::harness("Empty Better Auth state."))?;
    tampered.push(if last == 'z' { 'y' } else { 'z' });
    check(
        tampered != expected
            && pairs
                .iter()
                .any(|(key, value)| key == "state" && value == expected),
        "Actual Better Auth callback state was not the library's stored state.",
    )?;
    url.set_query(None);
    url.query_pairs_mut()
        .extend_pairs(pairs.iter().map(|(key, value)| {
            (
                key.as_str(),
                if key == "state" {
                    tampered.as_str()
                } else {
                    value.as_str()
                },
            )
        }));
    Ok(url.into())
}

/// Reads the exact un-followed redirect target without reporting its request context.
fn redirect_location(response: &reqwest::Response) -> String {
    response
        .headers()
        .get(reqwest::header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned()
}
