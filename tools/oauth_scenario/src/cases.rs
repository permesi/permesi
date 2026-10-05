//! Independent assertions against real HTTP, browser and PostgreSQL behavior.
//!
//! Each case provisions its own tenant hierarchy. Positive requests use fresh OS
//! entropy, and negative requests intentionally bypass manifest validation. Code
//! redemption cases call the transaction-owned domain interface on separate pools.
//! Token cases exercise real runtime-role HTTP exchange and independently verify JWTs.

use crate::{
    browser::Browser,
    client::{Actor, Api, Fixture, Resource, text_field},
    error::{Failure, Result, Safe, check},
    gateway::Gateway,
    services::Services,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use permesi::oauth::{
    authorization::redemption::{RedemptionInput, redeem_authorization_code},
    config::OAuthConfig,
};
use reqwest::{Method, StatusCode};
use secrecy::ExposeSecret as _;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row};
use url::Url;
use uuid::Uuid;

mod interop;
mod lifecycle;
mod token;

/// Already authenticated actors and owned infrastructure; no case shares another case's tenant.
pub struct Context<'a> {
    pub browser: &'a mut Browser,
    pub services: &'a mut Services,
    pub gateway: &'a Gateway,
    pub owner: &'a Actor,
    pub api: &'a Api,
    pub outsider: &'a Api,
    pub pool: &'a PgPool,
    pub admin_dsn: &'a str,
    pub policy: &'a OAuthConfig,
    pub credential_grace_seconds: i64,
    pub access_token_ttl_seconds: i64,
    pub resource: &'a crate::resource::ResourceServer,
    pub infrastructure: &'a crate::infrastructure::Infrastructure,
    pub manifest: &'a crate::manifest::Manifest,
}

/// Security-sensitive request material stays in memory and has no Debug/Serialize implementation.
struct Request {
    url: Url,
    verifier: String,
    state: String,
    nonce: String,
    scopes: Vec<String>,
    labels: Vec<String>,
}

impl Request {
    /// Computes S256 independently of production validators; the fixture seed never supplies entropy.
    fn new(context: &Context<'_>, fixture: &Fixture) -> Result<Self> {
        let app = fixture.app()?;
        let mut bytes = [0_u8; 32];
        getrandom::fill(&mut bytes).safe("PKCE entropy is unavailable.")?;
        let verifier = URL_SAFE_NO_PAD.encode(bytes);
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        let state = format!("scenario +%&=雪/{}", Uuid::new_v4());
        let nonce = Uuid::new_v4().to_string();
        let scopes = vec![
            "openid".to_owned(),
            app.scopes
                .first()
                .ok_or_else(|| Failure::harness("Missing scope."))?
                .clone(),
        ];
        let mut url = Url::parse(&format!("{}/authorize", context.api.origin))
            .safe("Invalid generated issuer.")?;
        url.query_pairs_mut().extend_pairs([
            ("response_type", "code"),
            ("client_id", &app.public.client_id.to_string()),
            ("redirect_uri", context.gateway.callback.as_str()),
            ("scope", &scopes.join(" ")),
            ("state", &state),
            ("nonce", &nonce),
            ("code_challenge", &challenge),
            ("code_challenge_method", "S256"),
            ("organization_id", &fixture.org.id.to_string()),
        ]);
        Ok(Self {
            url,
            verifier,
            state,
            nonce,
            scopes,
            labels: vec![
                "Sign in and identify your account".to_owned(),
                app.descriptions
                    .first()
                    .ok_or_else(|| Failure::harness("Missing fixture scope description."))?
                    .clone(),
            ],
        })
    }

    /// Changes one negative input without normalizing the submitted redirect value into a match.
    fn changed(&self, key: &str, value: Option<&str>) -> Url {
        let mut url = self.url.clone();
        let pairs = url
            .query_pairs()
            .filter(|(name, _)| name != key)
            .map(|(name, value)| (name.into_owned(), value.into_owned()))
            .collect::<Vec<_>>();
        url.set_query(None);
        url.query_pairs_mut().extend_pairs(&pairs);
        if let Some(value) = value {
            url.query_pairs_mut().append_pair(key, value);
        }
        url
    }
}

/// Dispatches stable case IDs; missing implementations are errors, not silently successful skips.
pub async fn execute(id: &str, context: &mut Context<'_>, fixture: &Fixture) -> Result<()> {
    match id {
        "interop.public_client" => interop::public(context, fixture).await,
        "interop.confidential_client" => interop::confidential(context, fixture).await,
        "interop.callback_identity_rejection" => interop::rejection(context, fixture).await,
        "interop.resource_scope_tenant" => interop::resource(context, fixture).await,
        "interop.invalid_access_tokens" => interop::invalid_access(context, fixture).await,
        "interop.signing_key_rotation" => interop::rotation(context, fixture).await,
        "token.public_claims" => token::public_claims(context, fixture).await,
        "token.confidential_credentials" => token::confidential(context, fixture).await,
        "token.validation" => token::validation(context, fixture).await,
        "token.replica_replay_race" => token::race(context, fixture).await,
        "token.signing_rollback_rotation" => token::signing(context, fixture).await,
        "foundation.provisioning" => foundation(context, fixture).await,
        "authorization.consent" => {
            let request = Request::new(context, fixture)?;
            let code = issue(context, &request).await?;
            snapshot(context, fixture, &request, &code).await
        }
        "authorization.login_resume" => login_resume(context, fixture).await,
        "authorization.cancel_saved" => cancel_saved(context, fixture).await,
        "authorization.validation" => validation(context, fixture).await,
        "authorization.tenant_isolation" => tenant_isolation(context, fixture).await,
        "redemption.bindings" => bindings(context, fixture).await,
        "redemption.expiration_race" => expiration_race(context, fixture).await,
        "credentials.lifecycle" => credentials(context, fixture).await,
        "authorization.replica_failover" => failover(context, fixture).await,
        "tenant.bottom_up_deletion" => deletion(context, fixture).await,
        "authorization.client_disabled_during_consent" => {
            lifecycle::pending_consent(context, fixture, lifecycle::Mutation::Client).await
        }
        "authorization.scope_removed_during_consent" => {
            lifecycle::pending_consent(context, fixture, lifecycle::Mutation::Scopes).await
        }
        "authorization.redirect_removed_during_consent" => {
            lifecycle::pending_consent(context, fixture, lifecycle::Mutation::Redirects).await
        }
        "redemption.client_disable_restore" => {
            lifecycle::restore_code(context, fixture, lifecycle::Mutation::Client).await
        }
        "redemption.scope_remove_restore" => {
            lifecycle::restore_code(context, fixture, lifecycle::Mutation::Scopes).await
        }
        "redemption.redirect_remove_restore" => {
            lifecycle::restore_code(context, fixture, lifecycle::Mutation::Redirects).await
        }
        _ => Err(Failure::harness("Case has no implementation.")),
    }
}

/// Checks real configuration reads and implemented discovery without overstating token support.
async fn foundation(context: &mut Context<'_>, fixture: &Fixture) -> Result<()> {
    let orgs: Vec<Resource> = context
        .api
        .json(Method::GET, "/v1/orgs", None, StatusCode::OK)
        .await?;
    check(
        orgs.iter().any(|org| org.id == fixture.org.id),
        "Created organization missing from active list.",
    )?;
    let projects: Vec<Resource> = context
        .api
        .json(
            Method::GET,
            &format!("/v1/orgs/{}/projects", fixture.org.slug),
            None,
            StatusCode::OK,
        )
        .await?;
    check(
        projects.iter().any(|project| {
            project.id == fixture.project.id && project.name == fixture.project.name
        }),
        "Project identity/name did not round-trip.",
    )?;
    let envs: Vec<Resource> = context
        .api
        .json(
            Method::GET,
            &format!("{}/envs", fixture.project_path),
            None,
            StatusCode::OK,
        )
        .await?;
    check(
        envs.len() == fixture.environments.len(),
        "Environment manifest did not round-trip.",
    )?;
    for (expected, _, _) in &fixture.environments {
        check(
            envs.iter().any(|actual| {
                actual.id == expected.id
                    && actual.slug == expected.slug
                    && actual.name == expected.name
            }),
            "Environment identity/slug/name changed in the API.",
        )?;
    }
    let app = fixture.app()?;
    check(
        app.public.application_id == app.resource.id
            && app.public.client_type == "public"
            && app.confidential.client_type == "confidential",
        "Client classification/application binding is incorrect.",
    )?;
    let registry: Vec<Value> = context
        .api
        .json(
            Method::GET,
            &format!("{}/oauth/scopes", app.path),
            None,
            StatusCode::OK,
        )
        .await?;
    check(
        app.scopes.iter().all(|scope| {
            registry
                .iter()
                .any(|entry| entry.get("name").and_then(Value::as_str) == Some(scope))
        }),
        "Custom scope registry did not round-trip.",
    )?;
    immutable_protocol_scopes(context.api, &app.path, &registry).await?;
    // A successful custom DELETE proves the immutable-scope 404s came from an implemented route.
    let probe: Value = context.api.json(Method::POST, &format!("{}/oauth/scopes", app.path), Some(json!({"name":format!("probe-{}:read", Uuid::new_v4().simple()), "description":"Disposable deletion probe"})), StatusCode::CREATED).await?;
    context
        .api
        .status(
            Method::DELETE,
            &format!("{}/oauth/scopes/{}", app.path, text_field(&probe, "id")?),
            None,
            StatusCode::NO_CONTENT,
        )
        .await?;
    oidc_metadata(context.api).await?;
    let console = app.path.replacen("/v1/", "/console/", 1);
    context.browser.call(json!({"action":"inspect","actor":"owner","path":format!("{console}/oauth/scopes"),"labels":app.scopes})).await?;
    Ok(())
}

/// Requires every immutable OIDC row before testing deletion; an empty list cannot pass vacuously.
async fn immutable_protocol_scopes(api: &Api, app_path: &str, registry: &[Value]) -> Result<()> {
    let rows = registry
        .iter()
        .filter(|entry| entry.get("kind").and_then(Value::as_str) == Some("protocol"))
        .collect::<Vec<_>>();
    let names = rows
        .iter()
        .filter_map(|entry| entry.get("name").and_then(Value::as_str))
        .collect::<std::collections::HashSet<_>>();
    let expected = [
        "openid",
        "profile",
        "email",
        "address",
        "phone",
        "offline_access",
    ];
    check(
        rows.len() == expected.len()
            && names.len() == expected.len()
            && expected.iter().all(|name| names.contains(name)),
        "Immutable protocol registry is missing or incorrect.",
    )?;
    for entry in rows {
        let id: Uuid = text_field(entry, "id")?
            .parse()
            .safe("Invalid protocol scope identity.")?;
        api.status(
            Method::DELETE,
            &format!("{app_path}/oauth/scopes/{id}"),
            None,
            StatusCode::NOT_FOUND,
        )
        .await?;
    }
    Ok(())
}

/// Checks implemented discovery against explicit issuer/token capabilities and real public keys.
async fn oidc_metadata(api: &Api) -> Result<()> {
    let discovery: Value = api
        .json(
            Method::GET,
            "/.well-known/openid-configuration",
            None,
            StatusCode::OK,
        )
        .await?;
    check(
        discovery.get("issuer").and_then(Value::as_str) == Some(api.origin.as_str())
            && discovery.get("token_endpoint").and_then(Value::as_str)
                == Some(format!("{}/token", api.origin).as_str())
            && discovery
                .get("authorization_response_iss_parameter_supported")
                .and_then(Value::as_bool)
                == Some(true),
        "Discovery overstates implementation or changes issuer.",
    )?;
    let jwks: Value = api
        .json(Method::GET, "/jwks.json", None, StatusCode::OK)
        .await?;
    check(
        jwks.get("keys")
            .and_then(Value::as_array)
            .is_some_and(|keys| {
                !keys.is_empty()
                    && keys.iter().all(|key| {
                        key.get("kty").and_then(Value::as_str) == Some("RSA")
                            && ["d", "p", "q", "dp", "dq", "qi", "oth", "k"]
                                .iter()
                                .all(|private| key.get(private).is_none())
                    })
            }),
        "JWKS omitted public signing keys or exposed private material.",
    )?;
    Ok(())
}

/// Starts real browser authorization and requires fresh consent rather than trusting allow-list authority.
async fn begin(context: &mut Context<'_>, request: &Request, actor: &str) -> Result<Value> {
    context
        .browser
        .call(json!({"action":"authorize","actor":actor,"url":request.url.as_str()}))
        .await
}

/// Approves a validated browser form and receives the raw code only through private IPC.
async fn issue(context: &mut Context<'_>, request: &Request) -> Result<String> {
    let registered = context.gateway.callback.clone();
    issue_for(context, request, &registered).await
}

/// Approves stored consent for a registered public or confidential callback.
async fn issue_for(
    context: &mut Context<'_>,
    request: &Request,
    registered: &str,
) -> Result<String> {
    let result = consent_callback(context, request).await?;
    callback(
        &result,
        registered,
        &request.state,
        "code",
        &context.api.origin,
    )
}

/// Shares real browser consent assertions with the standard relying-party callback parser.
async fn consent_callback(context: &mut Context<'_>, request: &Request) -> Result<Value> {
    let page = begin(context, request, "owner").await?;
    check(
        page.get("stage").and_then(Value::as_str) == Some("consent"),
        "Fresh client unexpectedly skipped user consent.",
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
    let mut expected = request.labels.clone();
    displayed.sort();
    expected.sort();
    check(
        displayed == expected,
        "Consent displayed incorrect or widened scope descriptions.",
    )?;
    let result = context
        .browser
        .call(json!({"action":"decision","actor":"owner","decision":"allow"}))
        .await?;
    check(
        result.get("stage").and_then(Value::as_str) != Some("consent_incomplete"),
        match result.get("status").and_then(Value::as_u64) {
            Some(400) => "Consent POST returned a protocol error (400).",
            Some(403) => "Consent POST rejected browser origin (403).",
            Some(200) => "Browser retained an HTML page after consent (200).",
            _ => "Consent navigation failed before a callback response.",
        },
    )?;
    Ok(result)
}

/// Verifies exact callback destination and only protocol-required parameters; state is compared unchanged.
fn callback(
    result: &Value,
    registered: &str,
    state: &str,
    field: &str,
    issuer: &str,
) -> Result<String> {
    let url = Url::parse(&text_field(result, "url")?).safe("Invalid browser callback URL.")?;
    let expected = Url::parse(registered).safe("Invalid generated callback.")?;
    check(
        url.origin() == expected.origin()
            && url.path() == expected.path()
            && url.fragment().is_none(),
        "Authorization escaped the exact callback.",
    )?;
    let pairs = url.query_pairs().collect::<Vec<_>>();
    check(
        pairs.len() == 3
            && pairs
                .iter()
                .filter(|(key, value)| key == "iss" && value == issuer)
                .count()
                == 1
            && pairs.iter().filter(|(key, _)| key == "state").count() == 1
            && pairs
                .iter()
                .find(|(key, _)| key == "state")
                .is_some_and(|(_, value)| value == state),
        "Callback widened parameters or changed state.",
    )?;
    let result = pairs
        .iter()
        .find(|(key, _)| key == field)
        .map(|(_, value)| value.to_string())
        .ok_or_else(|| Failure::assertion("Expected callback parameter missing."))?;
    if field == "code" {
        check(
            URL_SAFE_NO_PAD
                .decode(&result)
                .is_ok_and(|bytes| bytes.len() == 32),
            "Authorization code lacks expected entropy.",
        )?;
    }
    Ok(result)
}

/// Independently checks durable binding, exact scopes/nonce/TTL and hash-only storage.
async fn snapshot(
    context: &Context<'_>,
    fixture: &Fixture,
    request: &Request,
    code: &str,
) -> Result<()> {
    let row = sqlx::query("SELECT *, EXTRACT(EPOCH FROM expires_at-created_at)::bigint AS ttl FROM oauth_authorization_codes WHERE code_hash=$1")
        .bind(Sha256::digest(code.as_bytes()).to_vec()).fetch_one(context.pool).await.safe("Issued code was not persisted by hash.")?;
    let app = fixture.app()?;
    let scopes: Vec<String> = row
        .try_get("scope_names")
        .safe("Missing code scope snapshot.")?;
    let mut expected = request.scopes.clone();
    let mut scopes = scopes;
    expected.sort();
    scopes.sort();
    check(
        scopes == expected
            && !scopes
                .iter()
                .any(|scope| scope == "platform:admin" || scope == "users:write"),
        "Code scopes were widened or crossed internal permissions.",
    )?;
    check(
        row.try_get::<Uuid, _>("client_id")
            .safe("Missing code client.")?
            == app.public.id
            && row
                .try_get::<Uuid, _>("application_id")
                .safe("Missing code application.")?
                == app.resource.id
            && row
                .try_get::<Uuid, _>("organization_id")
                .safe("Missing code tenant.")?
                == fixture.org.id
            && Some(
                row.try_get::<Uuid, _>("user_id")
                    .safe("Missing code user.")?,
            ) == context.api.user_id,
        "Code user/tenant/client/application binding is incorrect.",
    )?;
    let consented: Vec<String> = sqlx::query_scalar("SELECT s.name FROM oauth_grant_scopes gs JOIN oauth_scopes s ON s.id=gs.scope_id WHERE gs.grant_id=$1 ORDER BY s.name")
        .bind(row.try_get::<Uuid, _>("grant_id").safe("Missing code grant.")?).fetch_all(context.pool).await.safe("Cannot inspect saved consent scopes.")?;
    check(
        consented == expected,
        "Saved consent widened the requested authority.",
    )?;
    check(
        row.try_get::<String, _>("redirect_uri")
            .safe("Missing code redirect.")?
            == context.gateway.callback
            && row
                .try_get::<String, _>("nonce")
                .safe("Missing OIDC nonce.")?
                == request.nonce
            && row
                .try_get::<i64, _>("ttl")
                .safe("Missing code lifetime.")?
                == context.policy.code_ttl,
        "Code redirect/nonce/TTL binding is incorrect.",
    )?;
    let persisted: String = sqlx::query_scalar(
        "SELECT to_jsonb(c)::text FROM oauth_authorization_codes c WHERE code_hash=$1",
    )
    .bind(Sha256::digest(code.as_bytes()).to_vec())
    .fetch_one(context.pool)
    .await
    .safe("Cannot inspect isolated code row.")?;
    check(
        !persisted.contains(code),
        "Raw code was persisted in the code row.",
    )
}

/// Starts anonymously on A, then resumes the stored request after actual Web OPAQUE login.
async fn login_resume(context: &mut Context<'_>, fixture: &Fixture) -> Result<()> {
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
async fn cancel_saved(context: &mut Context<'_>, fixture: &Fixture) -> Result<()> {
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
async fn validation(context: &mut Context<'_>, fixture: &Fixture) -> Result<()> {
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
async fn tenant_isolation(context: &mut Context<'_>, fixture: &Fixture) -> Result<()> {
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

/// Invokes internal redemption in a caller-owned transaction; this helper performs no HTTP token exchange.
async fn redeem(
    pool: &PgPool,
    policy: &OAuthConfig,
    fixture: &Fixture,
    request: &Request,
    code: &str,
    callback: &str,
    commit: bool,
) -> Result<bool> {
    let mut tx = pool
        .begin()
        .await
        .safe("Cannot start isolated redemption transaction.")?;
    let result = redeem_authorization_code(
        &mut tx,
        policy,
        RedemptionInput {
            code,
            client_id: fixture.app()?.public.client_id,
            redirect_uri: callback,
            code_verifier: &request.verifier,
            organization_id: fixture.org.id,
        },
    )
    .await;
    if let Ok(redeemed) = &result {
        let mut scopes = redeemed
            .scopes
            .iter()
            .map(|scope| scope.as_str().to_owned())
            .collect::<Vec<_>>();
        scopes.sort();
        let mut expected = request.scopes.clone();
        expected.sort();
        check(
            scopes == expected
                && redeemed.client_id == fixture.app()?.public.client_id
                && redeemed.nonce.as_deref() == Some(request.nonce.as_str())
                && redeemed.organization_id == fixture.org.id
                && redeemed.application_id == fixture.app()?.resource.id
                && redeemed.issuer == pool_issuer(policy)?
                && Some(redeemed.audience.as_str()) == policy.audience.as_deref(),
            "Redeemed code snapshot was widened or incorrectly bound.",
        )?;
    }
    let valid = result.is_ok();
    if commit && valid {
        tx.commit().await.safe("Cannot commit code consumption.")?;
    } else {
        tx.rollback()
            .await
            .safe("Cannot roll back code consumption.")?;
    }
    Ok(valid)
}

/// Reads explicit issuer configuration without inventing a fallback from request headers.
fn pool_issuer(policy: &OAuthConfig) -> Result<&str> {
    policy
        .issuer
        .as_deref()
        .ok_or_else(|| Failure::harness("Issuer policy missing."))
}

/// Wrong context/verifier/client/redirect never consumes; rollback restores usability, replay fails after commit.
async fn bindings(context: &mut Context<'_>, fixture: &Fixture) -> Result<()> {
    let request = Request::new(context, fixture)?;
    let code = issue(context, &request).await?;
    snapshot(context, fixture, &request, &code).await?;
    negative_bindings(context, fixture, &request, &code).await?;
    let independent = PgPool::connect(context.admin_dsn)
        .await
        .safe("Cannot connect independent redemption instance.")?;
    check(
        redeem(
            &independent,
            context.policy,
            fixture,
            &request,
            &code,
            &context.gateway.callback,
            false,
        )
        .await?,
        "Separate-instance validation failed.",
    )?;
    check(
        redeem(
            &independent,
            context.policy,
            fixture,
            &request,
            &code,
            &context.gateway.callback,
            true,
        )
        .await?,
        "Rollback consumed the code.",
    )?;
    check(
        !redeem(
            context.pool,
            context.policy,
            fixture,
            &request,
            &code,
            &context.gateway.callback,
            true,
        )
        .await?,
        "Committed authorization code replay succeeded.",
    )?;
    independent.close().await;
    Ok(())
}

/// Wrong authenticated-client/resource/PKCE inputs fail before consumption and leave the valid code untouched.
async fn negative_bindings(
    context: &Context<'_>,
    fixture: &Fixture,
    request: &Request,
    code: &str,
) -> Result<()> {
    let app = fixture.app()?;
    let other_client = crate::client::create_client(
        context.api,
        &app.path,
        "public",
        &context.gateway.callback,
        &request.scopes,
    )
    .await?;
    for (client_id, org, redirect, verifier) in [
        (
            other_client.client_id,
            fixture.org.id,
            context.gateway.callback.clone(),
            request.verifier.clone(),
        ),
        (
            app.public.client_id,
            Uuid::new_v4(),
            context.gateway.callback.clone(),
            request.verifier.clone(),
        ),
        (
            app.public.client_id,
            fixture.org.id,
            format!("{}/alternate", context.gateway.callback),
            request.verifier.clone(),
        ),
        (
            app.public.client_id,
            fixture.org.id,
            context.gateway.callback.clone(),
            "a".repeat(43),
        ),
        (
            app.public.client_id,
            fixture.org.id,
            context.gateway.callback.clone(),
            "short".to_owned(),
        ),
    ] {
        let mut tx = context
            .pool
            .begin()
            .await
            .safe("Cannot start negative redemption.")?;
        let result = redeem_authorization_code(
            &mut tx,
            context.policy,
            RedemptionInput {
                code,
                client_id,
                redirect_uri: &redirect,
                code_verifier: &verifier,
                organization_id: org,
            },
        )
        .await;
        check(result.is_err(), "Wrong code binding/verifier was accepted.")?;
        tx.rollback()
            .await
            .safe("Cannot rollback negative redemption.")?;
    }
    Ok(())
}

/// Expires a real-issued code by waiting its actual TTL; immutable database fields are never patched.
async fn expiration_race(context: &mut Context<'_>, fixture: &Fixture) -> Result<()> {
    let request = Request::new(context, fixture)?;
    let code = issue(context, &request).await?;
    let independent = PgPool::connect(context.admin_dsn)
        .await
        .safe("Cannot connect concurrent redemption instance.")?;
    snapshot(context, fixture, &request, &code).await?;
    let a = context
        .pool
        .begin()
        .await
        .safe("Cannot start first concurrent transaction.")?;
    let b = independent
        .begin()
        .await
        .safe("Cannot start second concurrent transaction.")?;
    let barrier = tokio::sync::Barrier::new(2);
    let client_id = fixture.app()?.public.client_id;
    let input = || RedemptionInput {
        code: &code,
        client_id,
        redirect_uri: &context.gateway.callback,
        code_verifier: &request.verifier,
        organization_id: fixture.org.id,
    };
    let (a, b) = tokio::join!(
        raced_redemption(a, context.policy, input(), &barrier),
        raced_redemption(b, context.policy, input(), &barrier)
    );
    check(
        usize::from(a?) + usize::from(b?) == 1,
        "Concurrent redemption did not have exactly one committed winner.",
    )?;
    let mut expired = Request::new(context, fixture)?;
    expired.url = expired.changed("prompt", Some("consent"));
    let code = issue(context, &expired).await?;
    check(
        redeem(
            &independent,
            context.policy,
            fixture,
            &expired,
            &code,
            &context.gateway.callback,
            false,
        )
        .await?,
        "Fresh code failed validation before the expiry wait.",
    )?;
    tokio::time::sleep(std::time::Duration::from_secs(
        u64::try_from(context.policy.code_ttl).safe("Invalid code TTL.")? + 1,
    ))
    .await;
    check(
        !redeem(
            &independent,
            context.policy,
            fixture,
            &expired,
            &code,
            &context.gateway.callback,
            true,
        )
        .await?,
        "Expired authorization code was redeemed.",
    )?;
    independent.close().await;
    Ok(())
}

/// Releases two established database transactions together; only a successful committed consumption wins.
async fn raced_redemption(
    mut tx: sqlx::Transaction<'_, sqlx::Postgres>,
    policy: &OAuthConfig,
    input: RedemptionInput<'_>,
    barrier: &tokio::sync::Barrier,
) -> Result<bool> {
    barrier.wait().await;
    let valid = redeem_authorization_code(&mut tx, policy, input)
        .await
        .is_ok();
    if valid {
        tx.commit()
            .await
            .safe("Cannot commit concurrent code consumption.")?;
    } else {
        tx.rollback()
            .await
            .safe("Cannot roll back concurrent code consumption.")?;
    }
    Ok(valid)
}

/// Checks one-time secrets, metadata-only reads, overlap rotation and immediate revocation.
async fn credentials(context: &mut Context<'_>, fixture: &Fixture) -> Result<()> {
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

/// Persists consent on A, stops A, and completes that unchanged authorization on B.
async fn failover(context: &mut Context<'_>, fixture: &Fixture) -> Result<()> {
    let request = Request::new(context, fixture)?;
    // Ensure this case starts on A even if an earlier independent login-resume selected B.
    context
        .gateway
        .use_b
        .store(false, std::sync::atomic::Ordering::SeqCst);
    let page = begin(context, &request, "owner").await?;
    check(
        page.get("stage").and_then(Value::as_str) == Some("consent"),
        "Replica A did not persist consent request.",
    )?;
    context
        .services
        .a
        .as_mut()
        .ok_or_else(|| Failure::harness("Replica A handle missing."))?
        .stop()
        .await?;
    context.gateway.replica_b();
    let result = context
        .browser
        .call(json!({"action":"decision","actor":"owner","decision":"allow"}))
        .await?;
    let code = callback(
        &result,
        &context.gateway.callback,
        &request.state,
        "code",
        &context.api.origin,
    )?;
    snapshot(context, fixture, &request, &code).await?;
    check(
        redeem(
            context.pool,
            context.policy,
            fixture,
            &request,
            &code,
            &context.gateway.callback,
            true,
        )
        .await?,
        "Replica-independent code redemption failed after A stopped.",
    )
}

/// Populated parents conflict, clients are explicitly removed, then resources soft-delete bottom-up.
async fn deletion(context: &mut Context<'_>, fixture: &Fixture) -> Result<()> {
    context
        .api
        .delete_org(&fixture.org, StatusCode::CONFLICT)
        .await?;
    context
        .api
        .status(
            Method::DELETE,
            &fixture.project_path,
            None,
            StatusCode::CONFLICT,
        )
        .await?;
    let request = Request::new(context, fixture)?;
    let code = issue(context, &request).await?;
    for (_, env_path, applications) in &fixture.environments {
        context
            .api
            .status(Method::DELETE, env_path, None, StatusCode::CONFLICT)
            .await?;
        remove_applications(context, applications).await?;
        context
            .api
            .status(Method::DELETE, env_path, None, StatusCode::NO_CONTENT)
            .await?;
    }
    check(
        !redeem(
            context.pool,
            context.policy,
            fixture,
            &request,
            &code,
            &context.gateway.callback,
            true,
        )
        .await?,
        "Deleted application retained redeemable OAuth authority.",
    )?;
    context
        .api
        .status(
            Method::DELETE,
            &fixture.project_path,
            None,
            StatusCode::NO_CONTENT,
        )
        .await?;
    context
        .api
        .delete_org(&fixture.org, StatusCode::NO_CONTENT)
        .await?;
    context
        .api
        .status(
            Method::GET,
            &format!("/v1/orgs/{}/projects", fixture.org.slug),
            None,
            StatusCode::NOT_FOUND,
        )
        .await?;
    let orgs: Vec<Resource> = context
        .api
        .json(Method::GET, "/v1/orgs", None, StatusCode::OK)
        .await?;
    check(
        !orgs.iter().any(|org| org.id == fixture.org.id),
        "Deleted tenant remains in active organization list.",
    )?;
    Ok(())
}

/// Explicitly removes every client before leaf deletion and verifies database rows remain soft-deleted.
async fn remove_applications(
    context: &Context<'_>,
    applications: &[crate::client::Application],
) -> Result<()> {
    for app in applications {
        context
            .api
            .status(Method::DELETE, &app.path, None, StatusCode::CONFLICT)
            .await?;
        for client in [&app.public, &app.confidential] {
            context
                .api
                .status(
                    Method::DELETE,
                    &format!("{}/oauth/clients/{}", app.path, client.client_id),
                    None,
                    StatusCode::NO_CONTENT,
                )
                .await?;
        }
        context
            .api
            .status(Method::DELETE, &app.path, None, StatusCode::NO_CONTENT)
            .await?;
        context
            .api
            .status(
                Method::GET,
                &format!("{}/oauth/scopes", app.path),
                None,
                StatusCode::NOT_FOUND,
            )
            .await?;
        context
            .api
            .status(Method::DELETE, &app.path, None, StatusCode::NOT_FOUND)
            .await?;
        let deleted: bool =
            sqlx::query_scalar("SELECT deleted_at IS NOT NULL FROM applications WHERE id=$1")
                .bind(app.resource.id)
                .fetch_one(context.pool)
                .await
                .safe("Cannot verify application soft deletion.")?;
        check(
            deleted,
            "Application deletion physically removed or retained active row.",
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn callback_rejects_changed_state_extra_metadata_and_wrong_origin() {
        for uri in [
            "http://127.0.0.1:99/callback?code=x&state=changed",
            "http://attacker.test/callback?code=x&state=expected",
            "http://127.0.0.1:99/callback?code=x&state=expected&scope=openid",
        ] {
            assert!(
                callback(
                    &json!({"url":uri}),
                    "http://127.0.0.1:99/callback",
                    "expected",
                    "code",
                    "https://issuer.test"
                )
                .is_err()
            );
        }
    }
}
