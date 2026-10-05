//! Standard OIDC client and separate resource API over the real disposable stack.
//!
//! Flow Overview: configure only real client allow-lists, discover with an external
//! library, drive existing browser consent on A, exchange on B, and use bearer
//! authority at the independent HTTPS fixture. Negative cases preserve successful
//! controls and use no private token fixtures or production bypass endpoints.

use super::*;
use crate::interop::{Authorization, RelyingParty, Transport};
use openidconnect::{Nonce, OAuth2TokenResponse as _, TokenResponse as _, core::CoreTokenResponse};
use std::sync::atomic::Ordering;

/// Adds the fixture API's scope through management if a custom manifest omitted it.
async fn jobs_description(context: &Context<'_>, fixture: &Fixture) -> Result<String> {
    let app = fixture.app()?;
    if let Some(index) = app.scopes.iter().position(|scope| scope == "jobs:read") {
        return app
            .descriptions
            .get(index)
            .cloned()
            .ok_or_else(|| Failure::harness("Missing jobs description."));
    }
    let description = "Read fixture jobs";
    let _: Value = context
        .api
        .json(
            Method::POST,
            &format!("{}/oauth/scopes", app.path),
            Some(json!({"name":"jobs:read","description":description})),
            StatusCode::CREATED,
        )
        .await?;
    Ok(description.to_owned())
}

/// Configures explicit openid/jobs authority and real confidential credentials, never SQL-seeded consent.
async fn party(
    context: &Context<'_>,
    fixture: &Fixture,
    confidential: bool,
) -> Result<RelyingParty> {
    let app = fixture.app()?;
    let registration = if confidential {
        &app.confidential
    } else {
        &app.public
    };
    let path = format!("{}/oauth/clients/{}", app.path, registration.client_id);
    let _: Vec<String> = context
        .api
        .json(
            Method::PUT,
            &format!("{path}/scopes"),
            Some(json!({"scopes":["openid","jobs:read"]})),
            StatusCode::OK,
        )
        .await?;
    let secret = if confidential {
        let issued: Value = context
            .api
            .json(
                Method::POST,
                &format!("{path}/secrets"),
                Some(json!({})),
                StatusCode::CREATED,
            )
            .await?;
        Some(text_field(&issued, "client_secret")?)
    } else {
        None
    };
    let redirect = if confidential {
        format!("{}/client-callback", context.api.origin)
    } else {
        context.gateway.callback.clone()
    };
    RelyingParty::discover(
        Transport {
            client: context.api.client.clone(),
            issuer: context.api.origin.clone(),
        },
        registration.client_id.to_string(),
        secret,
        redirect,
    )
    .await
}

/// Projects typed library state into existing consent-display assertions without regenerating entropy.
fn request(authorization: &Authorization, description: &str, delegated: bool) -> Request {
    let mut scopes = vec!["openid".to_owned()];
    let mut labels = vec!["Sign in and identify your account".to_owned()];
    if delegated {
        scopes.push("jobs:read".to_owned());
        labels.push(description.to_owned());
    }
    Request {
        url: authorization.url.clone(),
        verifier: String::new(),
        state: authorization.state.secret().clone(),
        nonce: authorization.nonce.secret().clone(),
        scopes,
        labels,
    }
}

/// Real consent and strict callback validation precede the one-time cookie-free library exchange.
async fn exchange(
    context: &mut Context<'_>,
    fixture: &Fixture,
    party: &RelyingParty,
    description: &str,
    delegated: bool,
) -> Result<CoreTokenResponse> {
    context.gateway.replica_a();
    let authorization = party.authorize(fixture.org.id, delegated);
    let callback =
        consent_callback(context, &request(&authorization, description, delegated)).await?;
    let code = party.callback(&text_field(&callback, "url")?, &authorization)?;
    context.gateway.replica_b();
    let response = party.exchange(code, authorization).await?;
    let expected = if delegated {
        ["openid", "jobs:read"].as_slice()
    } else {
        ["openid"].as_slice()
    };
    let returned = response
        .scopes()
        .ok_or_else(|| Failure::assertion("Standard OIDC exchange omitted scopes."))?;
    check(
        returned
            .iter()
            .map(|scope| scope.as_str())
            .collect::<Vec<_>>()
            == expected
            && response.refresh_token().is_none(),
        "Standard OIDC exchange widened consent or returned a refresh token.",
    )?;
    Ok(response)
}

/// Makes a cookie-free HTTPS resource request, checking generic error and cache/challenge semantics.
async fn resource_status(
    context: &Context<'_>,
    organization: Uuid,
    application: Uuid,
    token: Option<&str>,
    expected: StatusCode,
) -> Result<()> {
    let mut request = context.api.client.get(format!(
        "{}/orgs/{organization}/apps/{application}/jobs",
        context.resource.origin
    ));
    if let Some(token) = token {
        request = request.bearer_auth(token);
    }
    let response = request
        .send()
        .await
        .safe("Protected resource HTTP request failed.")?;
    check(
        response.status() == expected
            && response
                .headers()
                .get(reqwest::header::CACHE_CONTROL)
                .is_some_and(|value| value == "no-store")
            && (expected != StatusCode::UNAUTHORIZED
                || response
                    .headers()
                    .get(reqwest::header::WWW_AUTHENTICATE)
                    .is_some_and(|value| value == "Bearer")),
        "Protected resource status/cache/challenge differs from policy.",
    )?;
    let body: Value = response
        .json()
        .await
        .safe("Invalid protected resource response.")?;
    check(
        body == if expected == StatusCode::OK {
            json!({"jobs":[{"name":"fixture-job"}]})
        } else {
            json!({"error":"resource_access_denied"})
        },
        "Protected resource leaked authority or diagnostics.",
    )
}

/// Public S256 code flow generated by a standard library succeeds across A/B and at the resource API.
pub(super) async fn public(context: &mut Context<'_>, fixture: &Fixture) -> Result<()> {
    let description = jobs_description(context, fixture).await?;
    let party = party(context, fixture, false).await?;
    let response = exchange(context, fixture, &party, &description, true).await?;
    resource_status(
        context,
        fixture.org.id,
        fixture.app()?.resource.id,
        Some(response.access_token().secret()),
        StatusCode::OK,
    )
    .await
}

/// Confidential HTTP Basic authentication and S256 use the library's protocol encoding.
pub(super) async fn confidential(context: &mut Context<'_>, fixture: &Fixture) -> Result<()> {
    let description = jobs_description(context, fixture).await?;
    let party = party(context, fixture, true).await?;
    let response = exchange(context, fixture, &party, &description, true).await?;
    resource_status(
        context,
        fixture.org.id,
        fixture.app()?.resource.id,
        Some(response.access_token().secret()),
        StatusCode::OK,
    )
    .await
}

/// Bad callback state/mix-up/destination/duplicates never exchange; ID nonce/hash/signature checks reject substitution.
pub(super) async fn rejection(context: &mut Context<'_>, fixture: &Fixture) -> Result<()> {
    let description = jobs_description(context, fixture).await?;
    let party = party(context, fixture, false).await?;
    let authorization = party.authorize(fixture.org.id, true);
    let result = consent_callback(context, &request(&authorization, &description, true)).await?;
    let raw = text_field(&result, "url")?;
    for bad in [
        format!("{raw}&state=duplicate"),
        raw.replace("/callback?", "/callback/evil?"),
        raw.replace("iss=", "issuer="),
        raw.replace("state=", "invalid_state="),
        format!("{raw}#fragment"),
        raw.replace("code=", "error="),
    ] {
        check(
            party.callback(&bad, &authorization).is_err(),
            "Standard relying party accepted a bad callback.",
        )?;
    }
    let nonce = Nonce::new(authorization.nonce.secret().clone());
    let code = party.callback(&raw, &authorization)?;
    context.gateway.replica_b();
    let response = party.exchange(code, authorization).await?;
    party.verify(&response, &nonce)?;
    let mut tampered =
        serde_json::to_value(&response).safe("Cannot construct ID signature control.")?;
    let id = response
        .id_token()
        .ok_or_else(|| Failure::assertion("ID token missing."))?
        .to_string();
    tampered
        .as_object_mut()
        .ok_or_else(|| Failure::harness("Invalid ID signature control."))?
        .insert(
            "id_token".into(),
            json!(changed(&id, false, "sub", json!(Uuid::new_v4()))?),
        );
    let tampered: CoreTokenResponse =
        serde_json::from_value(tampered).safe("Cannot parse ID signature control.")?;
    check(
        party.verify(&tampered, &nonce).is_err(),
        "Standard ID verifier accepted a tampered signature.",
    )?;
    check(
        party
            .verify(&response, &Nonce::new("wrong-nonce".into()))
            .is_err(),
        "Standard ID verifier accepted another nonce.",
    )?;
    let wrong_client = RelyingParty::discover(
        Transport {
            client: context.api.client.clone(),
            issuer: context.api.origin.clone(),
        },
        fixture.app()?.confidential.client_id.to_string(),
        None,
        context.gateway.callback.clone(),
    )
    .await?;
    check(
        wrong_client.verify(&response, &nonce).is_err(),
        "Standard ID verifier accepted another client audience.",
    )?;
    let mut changed =
        serde_json::to_value(&response).safe("Cannot construct ID negative control.")?;
    changed
        .as_object_mut()
        .ok_or_else(|| Failure::harness("Invalid ID negative control."))?
        .insert("access_token".into(), json!("substituted-access-token"));
    let bad: CoreTokenResponse =
        serde_json::from_value(changed).safe("Cannot parse ID negative control.")?;
    check(
        party.verify(&bad, &nonce).is_err(),
        "Standard ID verifier accepted a mismatched at_hash.",
    )?;
    resource_status(
        context,
        fixture.org.id,
        fixture.app()?.resource.id,
        Some(response.access_token().secret()),
        StatusCode::OK,
    )
    .await
}

/// Allow-list permission alone does not grant jobs; another org/app and session cookies cannot supply authority.
pub(super) async fn resource(context: &mut Context<'_>, fixture: &Fixture) -> Result<()> {
    let description = jobs_description(context, fixture).await?;
    let party = party(context, fixture, false).await?;
    let without = exchange(context, fixture, &party, &description, false).await?;
    resource_status(
        context,
        fixture.org.id,
        fixture.app()?.resource.id,
        Some(without.access_token().secret()),
        StatusCode::FORBIDDEN,
    )
    .await?;
    let other =
        Fixture::create(context.api, context.manifest, 1, &context.gateway.callback).await?;
    let response = exchange(context, fixture, &party, &description, true).await?;
    let access = response.access_token().secret();
    resource_status(
        context,
        fixture.org.id,
        fixture.app()?.resource.id,
        Some(access),
        StatusCode::OK,
    )
    .await?;
    resource_status(
        context,
        other.org.id,
        other.app()?.resource.id,
        Some(access),
        StatusCode::NOT_FOUND,
    )
    .await?;
    resource_status(
        context,
        fixture.org.id,
        other.app()?.resource.id,
        Some(access),
        StatusCode::NOT_FOUND,
    )
    .await?;
    resource_status(
        context,
        fixture.org.id,
        fixture.app()?.resource.id,
        None,
        StatusCode::UNAUTHORIZED,
    )
    .await?;
    let reply = context
        .api
        .client
        .get(format!(
            "{}/orgs/{}/apps/{}/jobs",
            context.resource.origin,
            fixture.org.id,
            fixture.app()?.resource.id
        ))
        .header(
            reqwest::header::COOKIE,
            "session=browser-controlled; scopes=platform:admin",
        )
        .send()
        .await
        .safe("Cookie-only resource request failed.")?;
    check(
        reply.status() == StatusCode::UNAUTHORIZED,
        "Resource API trusted session/internal authority.",
    )
}

/// Mutates a compact JWT without resigning; genuine issuer signatures must reject the modified token.
fn changed(token: &str, header: bool, field: &str, value: Value) -> Result<String> {
    let segments = token.split('.').collect::<Vec<_>>();
    check(segments.len() == 3, "Invalid fixture JWT.")?;
    let index = usize::from(!header);
    let part = segments
        .get(index)
        .ok_or_else(|| Failure::harness("JWT part missing."))?;
    let mut object: Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(part)
            .safe("JWT fixture decoding failed.")?,
    )
    .safe("JWT fixture JSON failed.")?;
    object
        .as_object_mut()
        .ok_or_else(|| Failure::harness("Invalid JWT fixture."))?
        .insert(field.to_owned(), value);
    let changed =
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&object).safe("JWT fixture encoding failed.")?);
    Ok(segments
        .iter()
        .enumerate()
        .map(|(i, part)| if i == index { changed.as_str() } else { *part })
        .collect::<Vec<_>>()
        .join("."))
}

/// Invalid tokens and unknown-key floods fail closed; issued JWT authority persists only until real expiry.
pub(super) async fn invalid_access(context: &mut Context<'_>, fixture: &Fixture) -> Result<()> {
    let description = jobs_description(context, fixture).await?;
    let party = party(context, fixture, false).await?;
    let response = exchange(context, fixture, &party, &description, true).await?;
    let access = response.access_token().secret();
    let app = fixture.app()?;
    context.resource.verifier.reset().await;
    resource_status(
        context,
        fixture.org.id,
        app.resource.id,
        Some(access),
        StatusCode::OK,
    )
    .await?;
    for bad in [
        "malformed".to_owned(),
        response
            .id_token()
            .ok_or_else(|| Failure::assertion("ID token missing."))?
            .to_string(),
        changed(access, false, "scope", json!("jobs:write"))?,
        changed(access, true, "alg", json!("none"))?,
        changed(access, true, "jku", json!("https://attacker.invalid/jwks"))?,
    ] {
        resource_status(
            context,
            fixture.org.id,
            app.resource.id,
            Some(&bad),
            StatusCode::UNAUTHORIZED,
        )
        .await?;
    }
    unknown_key_flood(context, fixture, access).await?;
    let _: Value = context
        .api
        .json(
            Method::PATCH,
            &format!("{}/oauth/clients/{}", app.path, app.public.client_id),
            Some(json!({"disabled":true})),
            StatusCode::OK,
        )
        .await?;
    resource_status(
        context,
        fixture.org.id,
        app.resource.id,
        Some(access),
        StatusCode::OK,
    )
    .await?;
    // Wait for the genuine issued TTL, without updating DB timestamps or fixture clocks.
    let payload = access
        .split('.')
        .nth(1)
        .ok_or_else(|| Failure::assertion("JWT claims missing."))?;
    let claims: Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(payload)
            .safe("JWT fixture decoding failed.")?,
    )
    .safe("JWT fixture JSON failed.")?;
    let expiration = claims
        .get("exp")
        .and_then(Value::as_i64)
        .ok_or_else(|| Failure::assertion("JWT expiration missing."))?;
    while chrono::Utc::now().timestamp() < expiration {
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    resource_status(
        context,
        fixture.org.id,
        app.resource.id,
        Some(access),
        StatusCode::UNAUTHORIZED,
    )
    .await
}

/// Concurrent unknown kids cannot allocate negative entries or fan out JWKS requests.
async fn unknown_key_flood(context: &Context<'_>, fixture: &Fixture, access: &str) -> Result<()> {
    let app = fixture.app()?;
    let before = context.resource.verifier.fetches.load(Ordering::SeqCst);
    let mut pending = tokio::task::JoinSet::new();
    for _ in 0..16 {
        let unknown = changed(access, true, "kid", json!(Uuid::new_v4().to_string()))?;
        let client = context.api.client.clone();
        let url = format!(
            "{}/orgs/{}/apps/{}/jobs",
            context.resource.origin, fixture.org.id, app.resource.id
        );
        pending.spawn(async move {
            client
                .get(url)
                .bearer_auth(unknown)
                .send()
                .await
                .safe("Concurrent resource request failed.")
        });
    }
    while let Some(reply) = pending.join_next().await {
        check(
            reply.safe("Concurrent resource task failed.")??.status() == StatusCode::UNAUTHORIZED,
            "Resource accepted an unknown signing key.",
        )?;
    }
    check(
        context.resource.verifier.fetches.load(Ordering::SeqCst) == before + 1,
        "Unknown-kid refresh was not bounded/single-flight.",
    )
}

/// A cached relying party and resource refresh the fixed issuer once after real Vault rotation.
pub(super) async fn rotation(context: &mut Context<'_>, fixture: &Fixture) -> Result<()> {
    let description = jobs_description(context, fixture).await?;
    let party = party(context, fixture, false).await?;
    let old = exchange(context, fixture, &party, &description, true).await?;
    context.resource.verifier.reset().await;
    resource_status(
        context,
        fixture.org.id,
        fixture.app()?.resource.id,
        Some(old.access_token().secret()),
        StatusCode::OK,
    )
    .await?;
    let before = context.resource.verifier.fetches.load(Ordering::SeqCst);
    context.infrastructure.rotate_oidc_key().await?;
    let authorization = party.authorize(fixture.org.id, true);
    let nonce = Nonce::new(authorization.nonce.secret().clone());
    context.gateway.replica_a();
    let result = consent_callback(context, &request(&authorization, &description, true)).await?;
    let code = party.callback(&text_field(&result, "url")?, &authorization)?;
    context.gateway.replica_b();
    let new = party.exchange(code, authorization).await?;
    check(
        party.verify(&new, &nonce).is_err(),
        "Rotation did not exercise the relying party's cached unknown-kid path.",
    )?;
    resource_status(
        context,
        fixture.org.id,
        fixture.app()?.resource.id,
        Some(new.access_token().secret()),
        StatusCode::OK,
    )
    .await?;
    check(
        context.resource.verifier.fetches.load(Ordering::SeqCst) == before + 1,
        "Resource rotation did not refresh unknown kid exactly once.",
    )?;
    resource_status(
        context,
        fixture.org.id,
        fixture.app()?.resource.id,
        Some(old.access_token().secret()),
        StatusCode::OK,
    )
    .await
}
