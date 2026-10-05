//! Owned resource-server fixture; never part of the Permesi router or `OpenAPI`.
//!
//! Flow Overview: authenticate a bounded bearer JWT against fixed issuer JWKS,
//! verify RS256/at+jwt, time and resource audience, then enforce exact tenant/app
//! and jobs:read. A single-flight bounded cache refreshes unknown kids at most once
//! per cooldown. Header URLs, browser cookies and internal Principal permissions
//! confer no authority. This stateless JWT policy deliberately retains authority
//! until expiration; live grant revocation/introspection is a separate milestone.

use crate::{
    error::{Failure, Result, Safe, check},
    interop::Transport,
    tls::{Tls, listener},
};
use axum::{
    Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse as _, Response},
    routing::get,
};
use axum_server::{Handle, tls_rustls::RustlsConfig};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rsa::{BigUint, Pkcs1v15Sign, RsaPublicKey};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::{sync::Mutex, task::JoinHandle};
use uuid::Uuid;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    alg: String,
    typ: String,
    kid: String,
}

#[derive(Deserialize)]
struct Claims {
    iss: String,
    aud: String,
    sub: Uuid,
    client_id: Uuid,
    jti: Uuid,
    organization_id: Uuid,
    application_id: Uuid,
    grant_id: Uuid,
    scope: String,
    iat: i64,
    exp: i64,
    nbf: Option<i64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Jwk {
    kty: String,
    alg: String,
    r#use: String,
    kid: String,
    n: String,
    e: String,
}

#[derive(Default)]
struct Cache {
    keys: HashMap<String, RsaPublicKey>,
    loaded: Option<Instant>,
    unknown_refresh: Option<Instant>,
}

/// Verification uses only public keys and configured issuer/audience; no production token parser.
pub struct Verifier {
    transport: Transport,
    audience: String,
    cache: Mutex<Cache>,
    pub fetches: AtomicU64,
}

impl Verifier {
    /// Constructs fixture policy, independent of session roles and OAuth client-supplied claims.
    pub fn new(transport: Transport, audience: String) -> Self {
        Self {
            transport,
            audience,
            cache: Mutex::new(Cache::default()),
            fetches: AtomicU64::new(0),
        }
    }

    /// Serializes fetches and negative lookups; unknown kid strings are never retained as cache entries.
    async fn key(&self, kid: &str) -> Result<RsaPublicKey> {
        let mut cache = self.cache.lock().await;
        if cache
            .loaded
            .is_none_or(|when| when.elapsed() >= Duration::from_secs(60))
        {
            // Clear expired authority before awaiting; cancellation must not renew stale keys.
            cache.keys.clear();
            cache.loaded = Some(Instant::now());
            cache.unknown_refresh = Some(Instant::now());
            self.fetches.fetch_add(1, Ordering::SeqCst);
            let loaded = self
                .transport
                .keys(false)
                .await
                .and_then(|document| parse_keys(&document));
            match loaded {
                Ok(keys) => {
                    cache.keys = keys;
                    cache.loaded = Some(Instant::now());
                    cache.unknown_refresh = None;
                }
                Err(error) => {
                    // A failed/stale load must neither retain stale authority nor flood the issuer.
                    cache.keys.clear();
                    cache.unknown_refresh = Some(Instant::now());
                    return Err(error);
                }
            }
        }
        if let Some(key) = cache.keys.get(kid) {
            return Ok(key.clone());
        }
        if cache
            .unknown_refresh
            .is_none_or(|when| when.elapsed() >= Duration::from_secs(2))
        {
            // Record the attempt before I/O, so failures cannot produce an unbounded retry storm.
            cache.unknown_refresh = Some(Instant::now());
            self.fetches.fetch_add(1, Ordering::SeqCst);
            let loaded = self.transport.keys(true).await;
            cache.unknown_refresh = Some(Instant::now());
            cache.keys = parse_keys(&loaded?)?;
            cache.loaded = Some(Instant::now());
        }
        cache
            .keys
            .get(kid)
            .cloned()
            .ok_or_else(|| Failure::assertion("Bearer signing key is unknown."))
    }

    /// Verifies cryptography and resource claims before using any tenant or scope field.
    async fn authenticate(&self, token: &str) -> Result<Claims> {
        let (header, payload, signature) = parts(token)?;
        let decoded: Header =
            serde_json::from_slice(&decode(header)?).safe("Invalid bearer header.")?;
        check(
            decoded.alg == "RS256"
                && decoded.typ == "at+jwt"
                && !decoded.kid.is_empty()
                && decoded.kid.len() <= 128,
            "Bearer algorithm, type or key identifier is invalid.",
        )?;
        let key = self.key(&decoded.kid).await?;
        key.verify(
            Pkcs1v15Sign::new::<opaque_sha2::Sha256>(),
            &Sha256::digest(format!("{header}.{payload}").as_bytes()),
            &decode(signature)?,
        )
        .safe("Bearer signature is invalid.")?;
        let claims: Claims =
            serde_json::from_slice(&decode(payload)?).safe("Invalid bearer claims.")?;
        validate_claims(
            &claims,
            &self.transport.issuer,
            &self.audience,
            chrono::Utc::now().timestamp(),
        )?;
        Ok(claims)
    }

    /// Starts a fresh cache for the owned rotation case, without exposing a reset HTTP endpoint.
    pub async fn reset(&self) {
        *self.cache.lock().await = Cache::default();
        self.fetches.store(0, Ordering::SeqCst);
    }
}

/// Accepts only canonical URL-safe encodings, rejecting padding/alternate representations.
fn decode(segment: &str) -> Result<Vec<u8>> {
    let bytes = URL_SAFE_NO_PAD
        .decode(segment)
        .safe("Invalid bearer encoding.")?;
    check(
        URL_SAFE_NO_PAD.encode(&bytes) == segment,
        "Noncanonical bearer encoding.",
    )?;
    Ok(bytes)
}

/// Rejects oversized/noncompact tokens before JSON parsing, network I/O or cryptography.
fn parts(token: &str) -> Result<(&str, &str, &str)> {
    check(token.len() <= 8192, "Bearer token exceeded its size limit.")?;
    let mut parts = token.split('.');
    let header = parts
        .next()
        .ok_or_else(|| Failure::assertion("Bearer header missing."))?;
    let payload = parts
        .next()
        .ok_or_else(|| Failure::assertion("Bearer payload missing."))?;
    let signature = parts
        .next()
        .ok_or_else(|| Failure::assertion("Bearer signature missing."))?;
    check(
        parts.next().is_none()
            && !header.is_empty()
            && !payload.is_empty()
            && !signature.is_empty(),
        "Invalid bearer segment count.",
    )?;
    Ok((header, payload, signature))
}

/// Installs only unique public RSA signature keys, with bounded count and modulus size.
fn parse_keys(document: &Value) -> Result<HashMap<String, RsaPublicKey>> {
    let rows = document
        .get("keys")
        .and_then(Value::as_array)
        .ok_or_else(|| Failure::assertion("JWKS keys missing."))?;
    check(
        !rows.is_empty() && rows.len() <= 32,
        "JWKS key count outside fixture bounds.",
    )?;
    let mut keys = HashMap::new();
    for row in rows {
        let key: Jwk = serde_json::from_value(row.clone()).safe("Invalid public JWK.")?;
        check(
            key.kty == "RSA"
                && key.alg == "RS256"
                && key.r#use == "sig"
                && !key.kid.is_empty()
                && key.kid.len() <= 128,
            "Unsupported public signing key.",
        )?;
        let n = decode(&key.n)?;
        let e = decode(&key.e)?;
        check(
            (256..=512).contains(&n.len()) && e.len() <= 8,
            "Public RSA key outside fixture bounds.",
        )?;
        let rsa = RsaPublicKey::new(BigUint::from_bytes_be(&n), BigUint::from_bytes_be(&e))
            .safe("Invalid public RSA key.")?;
        check(
            keys.insert(key.kid, rsa).is_none(),
            "Duplicate public key identifier.",
        )?;
    }
    Ok(keys)
}

/// Exact issuer/resource audience and finite time bounds authorize bearer authentication only.
fn validate_claims(claims: &Claims, issuer: &str, audience: &str, now: i64) -> Result<()> {
    check(
        claims.iss == issuer
            && claims.aud == audience
            && claims.iat <= now
            && claims.exp > now
            && claims.nbf.is_none_or(|nbf| nbf <= now)
            && claims.exp > claims.iat
            && claims
                .exp
                .checked_sub(claims.iat)
                .is_some_and(|ttl| ttl <= 3600)
            && !claims.sub.is_nil()
            && !claims.client_id.is_nil()
            && !claims.jti.is_nil()
            && !claims.organization_id.is_nil()
            && !claims.application_id.is_nil()
            && !claims.grant_id.is_nil(),
        "Bearer issuer, audience, time or identity is invalid.",
    )?;
    let scopes = claims.scope.split(' ').collect::<Vec<_>>();
    check(
        !scopes.is_empty()
            && scopes.iter().all(|scope| {
                !scope.is_empty()
                    && scope.bytes().all(|b| {
                        b == 0x21 || (0x23..=0x5b).contains(&b) || (0x5d..=0x7e).contains(&b)
                    })
            })
            && scopes
                .iter()
                .enumerate()
                .all(|(i, scope)| !scopes.iter().skip(i + 1).any(|other| scope == other)),
        "Invalid bearer scope syntax.",
    )
}

/// Tenant/app equality and jobs:read authorize fixture jobs, never internal session permissions.
fn access(claims: &Claims, organization: Uuid, application: Uuid) -> StatusCode {
    if claims.organization_id != organization || claims.application_id != application {
        return StatusCode::NOT_FOUND;
    }
    if !claims.scope.split(' ').any(|scope| scope == "jobs:read") {
        return StatusCode::FORBIDDEN;
    }
    StatusCode::OK
}

/// Duplicate/non-Bearer headers fail closed; cookies are intentionally ignored.
fn bearer(headers: &HeaderMap) -> Result<&str> {
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let token = values
        .next()
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or_else(|| Failure::assertion("Bearer authentication required."))?;
    check(
        values.next().is_none(),
        "Ambiguous bearer authorization header.",
    )?;
    Ok(token)
}

/// Returns only fixture data or value-free errors; malformed tokens never enter diagnostics.
async fn jobs(
    State(verifier): State<Arc<Verifier>>,
    Path((org, app)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Response {
    let status = match bearer(&headers) {
        Ok(token) => match verifier.authenticate(token).await {
            Ok(claims) => access(&claims, org, app),
            Err(_) => StatusCode::UNAUTHORIZED,
        },
        Err(_) => StatusCode::UNAUTHORIZED,
    };
    let body = if status == StatusCode::OK {
        json!({"jobs":[{"name":"fixture-job"}]})
    } else {
        json!({"error":"resource_access_denied"})
    };
    let mut response = (status, axum::Json(body)).into_response();
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    if status == StatusCode::UNAUTHORIZED {
        response.headers_mut().insert(
            header::WWW_AUTHENTICATE,
            axum::http::HeaderValue::from_static("Bearer"),
        );
    }
    response
}

/// Runtime-owned TLS listener and cache survive scenario cancellation until explicit cleanup.
pub struct ResourceServer {
    pub origin: String,
    pub verifier: Arc<Verifier>,
    handle: Handle<std::net::SocketAddr>,
    server: JoinHandle<std::io::Result<()>>,
}

impl ResourceServer {
    /// Reserves a loopback socket once and starts a separate HTTPS resource boundary.
    pub async fn start(tls: &Tls, transport: Transport, audience: String) -> Result<Self> {
        let listener = listener()?;
        let origin = format!(
            "https://localhost:{}",
            listener
                .local_addr()
                .safe("Cannot read resource port.")?
                .port()
        );
        let config = RustlsConfig::from_pem(tls.cert.clone(), tls.key.clone())
            .await
            .safe("Cannot configure resource TLS.")?;
        let handle = Handle::new();
        let verifier = Arc::new(Verifier::new(transport, audience));
        let router = Router::new()
            .route("/orgs/{org}/apps/{app}/jobs", get(jobs))
            .with_state(verifier.clone());
        let server = tokio::spawn(
            axum_server::from_tcp_rustls(listener, config)
                .safe("Cannot bind resource TLS.")?
                .handle(handle.clone())
                .serve(router.into_make_service()),
        );
        Ok(Self {
            origin,
            verifier,
            handle,
            server,
        })
    }

    /// Gracefully closes the listener; Runtime bounds this await and Drop aborts any remaining task.
    pub async fn stop(&mut self) -> Result<()> {
        self.handle.shutdown();
        (&mut self.server)
            .await
            .safe("Resource task failed.")?
            .safe("Resource shutdown failed.")
    }
}

impl Drop for ResourceServer {
    /// Signals owned connections and aborts the accept task when bounded cleanup is cancelled.
    fn drop(&mut self) {
        self.handle.shutdown();
        self.server.abort();
    }
}

#[cfg(test)]
mod tests;
