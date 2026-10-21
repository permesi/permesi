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
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row};
use url::Url;
use uuid::Uuid;

mod foundation;
use foundation::foundation;

mod authorization;
use authorization::{cancel_saved, login_resume, tenant_isolation, validation};

mod redemption;
use redemption::{bindings, expiration_race};

mod credentials;
use credentials::credentials;

mod hierarchy;
use hierarchy::{deletion, failover};

mod authentication;
mod ha;
mod interop;
mod lifecycle;
mod refresh;
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
    pub fixture_seed: u64,
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
        "ha.rolling_restart" => ha::rolling_restart(context, fixture).await,
        "ha.replica_outage" => ha::replica_outage(context, fixture).await,
        "authentication.shared_exchanges" => authentication::shared_exchanges(context).await,
        "interop.public_client" => interop::public(context, fixture).await,
        "interop.confidential_client" => interop::confidential(context, fixture).await,
        "interop.callback_identity_rejection" => interop::rejection(context, fixture).await,
        "interop.resource_scope_tenant" => interop::resource(context, fixture).await,
        "interop.invalid_access_tokens" => interop::invalid_access(context, fixture).await,
        "interop.signing_key_rotation" => interop::rotation(context, fixture).await,
        "interop.userinfo_cross_replica" => interop::userinfo_cross_replica(context, fixture).await,
        "refresh.rotation_reuse" => refresh::rotation(context, fixture).await,
        "refresh.replica_race" => refresh::race(context, fixture).await,
        "refresh.lifecycle" => refresh::lifecycle(context, fixture).await,
        "refresh.client_revocation" => refresh::client_revocation(context, fixture).await,
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
    crate::browser::expect_stage(
        &page,
        "consent",
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
    crate::browser::expect_stage(
        &result,
        "callback",
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
