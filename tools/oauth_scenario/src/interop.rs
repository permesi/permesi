//! Standard relying-party interoperability, isolated from Permesi's token validators.
//!
//! Flow Overview: discover the owned HTTPS issuer, generate state/nonce/S256 with
//! openidconnect-rs, validate the exact browser callback, exchange once without a
//! session cookie, then verify the ID token and access-token hash. Transport pins
//! destinations and bounds bodies; library diagnostics containing bearer values
//! never cross the runner's static-error/report boundary.

use crate::error::{Failure, Result, Safe, check};
use openidconnect::{
    AccessTokenHash, AuthorizationCode, ClaimsVerificationError, ClientId, ClientSecret, CsrfToken,
    EndpointMaybeSet, EndpointNotSet, EndpointSet, HttpRequest, HttpResponse, IssuerUrl, Nonce,
    OAuth2TokenResponse as _, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope,
    SignatureVerificationError, TokenResponse as _,
    core::{
        CoreAuthenticationFlow, CoreClient, CoreIdTokenVerifier, CoreJsonWebKeySet,
        CoreJwsSigningAlgorithm, CoreProviderMetadata, CoreTokenResponse,
    },
};
use subtle::ConstantTimeEq as _;
use url::Url;

type Client = CoreClient<
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointMaybeSet,
    EndpointMaybeSet,
>;

/// Only owned issuer endpoints are reachable, including when discovery is malicious.
#[derive(Clone)]
pub struct Transport {
    pub client: reqwest::Client,
    pub issuer: String,
}

impl Transport {
    /// Preserves protocol headers but never follows redirects or sends a browser cookie.
    pub async fn send(&self, request: HttpRequest) -> Result<HttpResponse> {
        let destination = request.uri().to_string();
        let allowed = match request.method().as_str() {
            "GET" => ["/.well-known/openid-configuration", "/jwks.json"]
                .iter()
                .any(|path| destination == format!("{}{path}", self.issuer)),
            "POST" => destination == format!("{}/token", self.issuer),
            _ => false,
        };
        check(
            allowed && request.body().len() <= 8192,
            "OIDC transport rejected an untrusted destination or oversized request.",
        )?;
        check(
            !request.headers().contains_key(reqwest::header::COOKIE),
            "OIDC transport received a session cookie.",
        )?;
        let (parts, body) = request.into_parts();
        let response = self
            .client
            .request(parts.method, destination)
            .headers(parts.headers)
            .body(body)
            .send()
            .await
            .safe("OIDC HTTP request failed.")?;
        let status = response.status();
        check(
            !status.is_redirection(),
            "OIDC endpoint attempted a redirect.",
        )?;
        let headers = response.headers().clone();
        let body = bounded(response).await?;
        let mut result = HttpResponse::new(body);
        *result.status_mut() = status;
        *result.headers_mut() = headers;
        Ok(result)
    }

    /// Fetches only the configured issuer's keys; no token header can supply a URL.
    pub async fn keys(&self, refresh: bool) -> Result<serde_json::Value> {
        let mut request = self.client.get(format!("{}/jwks.json", self.issuer));
        if refresh {
            request = request.header(reqwest::header::CACHE_CONTROL, "no-cache");
        }
        let response = request.send().await.safe("JWKS request failed.")?;
        check(
            response.status() == reqwest::StatusCode::OK,
            "JWKS endpoint unavailable.",
        )?;
        serde_json::from_slice(&bounded(response).await?).safe("Invalid JWKS document.")
    }
}

/// Bounds chunked bodies too; checking Content-Length alone would leave an allocation bypass.
async fn bounded(mut response: reqwest::Response) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.safe("OIDC response body failed.")? {
        check(
            body.len() + chunk.len() <= 65_536,
            "OIDC response exceeded its size limit.",
        )?;
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// Secret-bearing library values have no runner Debug/Serialize implementation.
pub struct Authorization {
    pub url: Url,
    pub state: CsrfToken,
    pub nonce: Nonce,
    verifier: PkceCodeVerifier,
}

/// A standard library client configured exclusively from real discovery metadata.
pub struct RelyingParty {
    client: Client,
    transport: Transport,
    redirect: String,
}

impl RelyingParty {
    /// Validates discovery issuer/endpoints; advertised signing algorithms cannot relax RS256.
    pub async fn discover(
        transport: Transport,
        client: String,
        secret: Option<String>,
        redirect: String,
    ) -> Result<Self> {
        let metadata = CoreProviderMetadata::discover_async(
            IssuerUrl::new(transport.issuer.clone()).safe("Invalid OIDC issuer.")?,
            &|request| transport.send(request),
        )
        .await
        .safe("OIDC discovery failed.")?;
        check(
            metadata.issuer().as_str() == transport.issuer
                && metadata.authorization_endpoint().as_str()
                    == format!("{}/authorize", transport.issuer)
                && metadata
                    .token_endpoint()
                    .is_some_and(|url| url.as_str() == format!("{}/token", transport.issuer))
                && metadata.jwks_uri().as_str() == format!("{}/jwks.json", transport.issuer),
            "OIDC discovery advertised an untrusted endpoint.",
        )?;
        let client = CoreClient::from_provider_metadata(
            metadata,
            ClientId::new(client),
            secret.map(ClientSecret::new),
        )
        .set_redirect_uri(RedirectUrl::new(redirect.clone()).safe("Invalid OIDC redirect.")?);
        Ok(Self {
            client,
            transport,
            redirect,
        })
    }

    /// Library-generated entropy and mandatory S256 bind this exact organization and scope request.
    pub fn authorize(&self, organization: uuid::Uuid, delegated: bool) -> Authorization {
        let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
        let mut request = self
            .client
            .authorize_url(
                CoreAuthenticationFlow::AuthorizationCode,
                CsrfToken::new_random,
                Nonce::new_random,
            )
            .set_pkce_challenge(challenge)
            .add_extra_param("organization_id", organization.to_string())
            .add_extra_param("prompt", "consent");
        if delegated {
            request = request.add_scope(Scope::new("jobs:read".to_owned()));
        }
        let (url, state, nonce) = request.url();
        Authorization {
            url,
            state,
            nonce,
            verifier,
        }
    }

    /// Rejects callback substitution, duplicate protocol fields and mix-up before any exchange.
    /// Exact prefix matching preserves the registered URI rather than normalizing attacker input.
    pub fn callback(&self, raw: &str, authorization: &Authorization) -> Result<AuthorizationCode> {
        callback(
            raw,
            &self.redirect,
            &self.transport.issuer,
            authorization.state.secret(),
        )
    }

    /// Exchanges exactly once and validates identity before returning bearer authority to the caller.
    pub async fn exchange(
        &self,
        code: AuthorizationCode,
        authorization: Authorization,
    ) -> Result<CoreTokenResponse> {
        let nonce = authorization.nonce;
        let response = self
            .client
            .exchange_code(code)
            .safe("OIDC token endpoint missing.")?
            .set_pkce_verifier(authorization.verifier)
            .request_async(&|request| self.transport.send(request))
            .await
            .safe("OIDC code exchange failed.")?;
        let id = response
            .id_token()
            .ok_or_else(|| Failure::assertion("OIDC response omitted an ID token."))?;
        let verifier = self
            .client
            .id_token_verifier()
            .set_allowed_algs([CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256]);
        if matches!(
            id.claims(&verifier, &nonce),
            Err(ClaimsVerificationError::SignatureVerification(
                SignatureVerificationError::NoMatchingKey
            ))
        ) {
            // Only unknown keys permit one fixed-origin refresh, never a second code exchange.
            let keys: CoreJsonWebKeySet = serde_json::from_value(self.transport.keys(true).await?)
                .safe("Invalid refreshed OIDC keys.")?;
            let client = CoreClient::new(
                self.client.client_id().clone(),
                IssuerUrl::new(self.transport.issuer.clone()).safe("Invalid OIDC issuer.")?,
                keys,
            );
            verify_response(&response, &nonce, client.id_token_verifier())?;
        } else {
            self.verify(&response, &nonce)?;
        }
        Ok(response)
    }

    /// Requires signature, exact issuer/client audience, expiration, nonce and a matching `at_hash`.
    pub fn verify(&self, response: &CoreTokenResponse, nonce: &Nonce) -> Result<()> {
        verify_response(response, nonce, self.client.id_token_verifier())
    }
}

/// Pins ID-token JOSE policy as well as the standard library's signature/claim/hash validation.
fn verify_response(
    response: &CoreTokenResponse,
    nonce: &Nonce,
    verifier: CoreIdTokenVerifier<'_>,
) -> Result<()> {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    let id = response
        .id_token()
        .ok_or_else(|| Failure::assertion("OIDC response omitted an ID token."))?;
    let raw = id.to_string();
    check(raw.len() <= 8192, "OIDC ID token exceeded its size limit.")?;
    let header = raw
        .split('.')
        .next()
        .ok_or_else(|| Failure::assertion("Missing ID header."))?;
    let header: serde_json::Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(header)
            .safe("Invalid ID header encoding.")?,
    )
    .safe("Invalid ID header.")?;
    check(
        header.get("typ").and_then(serde_json::Value::as_str) == Some("JWT")
            && header.get("alg").and_then(serde_json::Value::as_str) == Some("RS256")
            && header.as_object().is_some_and(|object| {
                object
                    .keys()
                    .all(|key| ["typ", "alg", "kid"].contains(&key.as_str()))
            }),
        "OIDC ID token type or header policy failed.",
    )?;
    let verifier = verifier.set_allowed_algs([CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256]);
    let claims = id
        .claims(&verifier, nonce)
        .safe("OIDC ID token verification failed.")?;
    let hash = AccessTokenHash::from_token(
        response.access_token(),
        id.signing_alg().safe("Invalid ID algorithm.")?,
        id.signing_key(&verifier).safe("Invalid ID signing key.")?,
    )
    .safe("ID access-token hash calculation failed.")?;
    check(
        claims.access_token_hash() == Some(&hash),
        "OIDC at_hash does not bind the access token.",
    )
}

/// Parses only the supported code/error response; state is compared in constant time.
fn callback(raw: &str, redirect: &str, issuer: &str, state: &str) -> Result<AuthorizationCode> {
    check(
        !redirect.contains(['?', '#']),
        "Interop callback must have no pre-existing query or fragment.",
    )?;
    let query = raw
        .strip_prefix(redirect)
        .and_then(|tail| tail.strip_prefix('?'))
        .ok_or_else(|| Failure::assertion("OIDC callback destination changed."))?;
    check(
        raw.len() <= 8192 && !query.contains('#'),
        "Invalid OIDC callback size or fragment.",
    )?;
    let pairs = url::form_urlencoded::parse(query.as_bytes()).collect::<Vec<_>>();
    check(
        pairs.len() == 3,
        "OIDC callback contains unexpected or duplicate parameters.",
    )?;
    let one = |name: &str| -> Result<&str> {
        let mut values = pairs.iter().filter(|(key, _)| key == name);
        let value = values
            .next()
            .ok_or_else(|| Failure::assertion("OIDC callback parameter missing."))?;
        check(
            values.next().is_none(),
            "Duplicate OIDC callback parameter.",
        )?;
        Ok(value.1.as_ref())
    };
    check(
        one("iss")? == issuer && bool::from(one("state")?.as_bytes().ct_eq(state.as_bytes())),
        "OIDC callback issuer or state changed.",
    )?;
    let code = one("code")?;
    check(!code.is_empty(), "OIDC callback did not authorize a code.")?;
    Ok(AuthorizationCode::new(code.to_owned()))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing)]
    use super::*;

    #[tokio::test]
    async fn transport_rejects_redirects_oversized_bodies_and_session_cookies() -> Result<()> {
        for (status, body) in [
            (reqwest::StatusCode::FOUND, "{}".into()),
            (reqwest::StatusCode::OK, "x".repeat(65_537)),
        ] {
            let issuer = crate::test_http::Issuer::start(body, status).await?;
            let request = axum::http::Request::builder()
                .uri(format!("{}/jwks.json", issuer.transport.issuer))
                .body(Vec::new())
                .safe("Invalid test request.")?;
            assert!(issuer.transport.send(request).await.is_err());
            assert_eq!(issuer.requests.load(std::sync::atomic::Ordering::SeqCst), 1);
            let cookie = axum::http::Request::builder()
                .uri(format!("{}/jwks.json", issuer.transport.issuer))
                .header(reqwest::header::COOKIE, "session=untrusted")
                .body(Vec::new())
                .safe("Invalid test request.")?;
            assert!(issuer.transport.send(cookie).await.is_err());
            assert_eq!(issuer.requests.load(std::sync::atomic::Ordering::SeqCst), 1);
        }
        Ok(())
    }

    /// Supplies real library metadata and public keys, with all endpoint states established.
    fn party() -> Result<RelyingParty> {
        let metadata: CoreProviderMetadata = serde_json::from_value(serde_json::json!({
            "issuer":"https://localhost:1234","authorization_endpoint":"https://localhost:1234/authorize",
            "token_endpoint":"https://localhost:1234/token","jwks_uri":"https://localhost:1234/jwks.json",
            "response_types_supported":["code"],"subject_types_supported":["public"],"id_token_signing_alg_values_supported":["RS256"]
        })).safe("Invalid test metadata.")?;
        let keys =
            serde_json::from_value(crate::test_tokens::jwks()?).safe("Invalid test keys.")?;
        let client = CoreClient::from_provider_metadata(
            metadata.set_jwks(keys),
            ClientId::new("test-client".into()),
            None,
        );
        Ok(RelyingParty {
            client,
            transport: Transport {
                client: reqwest::Client::new(),
                issuer: "https://localhost:1234".into(),
            },
            redirect: "http://127.0.0.1:2345/callback".into(),
        })
    }

    /// Encodes a correctly signed ID response; failed claims remain cryptographically valid.
    fn response(
        header: &serde_json::Value,
        claims: &serde_json::Value,
    ) -> Result<CoreTokenResponse> {
        response_raw(&crate::test_tokens::sign(header, claims)?)
    }

    /// Builds a library response around a signed or deliberately tampered compact ID token.
    fn response_raw(id: &str) -> Result<CoreTokenResponse> {
        serde_json::from_value(
            serde_json::json!({"access_token":"opaque-access","token_type":"Bearer","id_token":id}),
        )
        .safe("Invalid test token response.")
    }

    /// Shares a genuinely valid nonce/hash/claim control across parser and signature regressions.
    fn id_claims(now: i64) -> Result<serde_json::Value> {
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
        use sha2::{Digest as _, Sha256};
        let digest = Sha256::digest(b"opaque-access");
        let hash = URL_SAFE_NO_PAD.encode(
            digest
                .get(..16)
                .ok_or_else(|| Failure::harness("Invalid hash fixture."))?,
        );
        Ok(
            serde_json::json!({"iss":"https://localhost:1234","aud":"test-client","sub":"test-user","iat":now,"exp":now+60,"nonce":"test-nonce","at_hash":hash}),
        )
    }

    #[test]
    fn standard_id_verifier_rejects_signed_bad_issuer_audience_expiry_nonce_and_hash() -> Result<()>
    {
        let party = party()?;
        let now = chrono::Utc::now().timestamp();
        let claims = id_claims(now)?;
        let header = serde_json::json!({"alg":"RS256","typ":"JWT","kid":"test-key"});
        let nonce = Nonce::new("test-nonce".into());
        party.verify(&response(&header, &claims)?, &nonce)?;
        for (field, value) in [
            ("iss", serde_json::json!("https://attacker.invalid")),
            ("aud", serde_json::json!("another-client")),
            ("aud", serde_json::json!("jobs-api")),
            ("exp", serde_json::json!(now - 1)),
            ("nonce", serde_json::json!("different")),
            ("at_hash", serde_json::json!("substitution")),
        ] {
            let mut bad = claims.clone();
            bad[field] = value;
            assert!(party.verify(&response(&header, &bad)?, &nonce).is_err());
        }
        let mut missing = claims.clone();
        missing
            .as_object_mut()
            .ok_or_else(|| Failure::harness("Invalid test claims."))?
            .remove("at_hash");
        assert!(party.verify(&response(&header, &missing)?, &nonce).is_err());
        for (field, value) in [
            ("typ", serde_json::json!("at+jwt")),
            ("alg", serde_json::json!("RS384")),
            ("jku", serde_json::json!("https://attacker.invalid/keys")),
        ] {
            let mut bad = header.clone();
            bad[field] = value;
            assert!(party.verify(&response(&bad, &claims)?, &nonce).is_err());
        }
        Ok(())
    }

    #[test]
    fn standard_id_verifier_rejects_missing_type_and_tampered_known_key_signature() -> Result<()> {
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
        let party = party()?;
        let claims = id_claims(chrono::Utc::now().timestamp())?;
        let header = serde_json::json!({"alg":"RS256","typ":"JWT","kid":"test-key"});
        let nonce = Nonce::new("test-nonce".into());
        let valid = response(&header, &claims)?;
        party.verify(&valid, &nonce)?;
        let mut missing = header.clone();
        missing
            .as_object_mut()
            .ok_or_else(|| Failure::harness("Invalid header fixture."))?
            .remove("typ");
        assert!(party.verify(&response(&missing, &claims)?, &nonce).is_err());
        let raw = valid
            .id_token()
            .ok_or_else(|| Failure::harness("Missing ID fixture."))?
            .to_string();
        let signature = raw
            .rsplit('.')
            .next()
            .ok_or_else(|| Failure::harness("Missing signature fixture."))?;
        let mut altered = claims.clone();
        altered["sub"] = serde_json::json!("another-user");
        let tampered = format!(
            "{}.{}.{}",
            URL_SAFE_NO_PAD.encode(header.to_string()),
            URL_SAFE_NO_PAD.encode(altered.to_string()),
            signature
        );
        assert!(party.verify(&response_raw(&tampered)?, &nonce).is_err());
        // A different, correctly signed subject is valid: signature is the sole rejection reason above.
        party.verify(&response(&header, &altered)?, &nonce)?;
        Ok(())
    }

    #[test]
    fn standard_id_parser_rejects_duplicate_header_and_claim_members() -> Result<()> {
        let party = party()?;
        let claims = id_claims(chrono::Utc::now().timestamp())?;
        let header = serde_json::json!({"alg":"RS256","typ":"JWT","kid":"test-key"});
        party.verify(
            &response(&header, &claims)?,
            &Nonce::new("test-nonce".into()),
        )?;
        let duplicate_header = format!(
            "{},\"kid\":\"test-key\"}}",
            header.to_string().trim_end_matches('}')
        );
        let duplicate_claims = format!(
            "{},\"aud\":\"test-client\"}}",
            claims.to_string().trim_end_matches('}')
        );
        assert!(
            response_raw(&crate::test_tokens::sign_raw(
                &duplicate_header,
                &claims.to_string()
            )?)
            .is_err()
        );
        assert!(
            response_raw(&crate::test_tokens::sign_raw(
                &header.to_string(),
                &duplicate_claims
            )?)
            .is_err()
        );
        Ok(())
    }

    #[tokio::test]
    async fn transport_rejects_untrusted_metadata_destinations_before_io() -> Result<()> {
        let issuer = crate::test_http::Issuer::start("{}".into(), reqwest::StatusCode::OK).await?;
        for (method, path) in [
            ("GET", "/authorize"),
            ("GET", "/jwks.json?url=evil"),
            ("POST", "/jwks.json"),
            ("GET", "/token"),
        ] {
            let request = axum::http::Request::builder()
                .method(method)
                .uri(format!("{}{path}", issuer.transport.issuer))
                .body(Vec::new())
                .safe("Invalid test request.")?;
            assert!(issuer.transport.send(request).await.is_err());
            assert_eq!(issuer.requests.load(std::sync::atomic::Ordering::SeqCst), 0);
        }
        for (method, path) in [
            ("POST", "/token"),
            ("GET", "/jwks.json"),
            ("GET", "/.well-known/openid-configuration"),
        ] {
            let request = axum::http::Request::builder()
                .method(method)
                .uri(format!(
                    "{}{path}",
                    issuer.transport.issuer.replacen("https://", "http://", 1)
                ))
                .body(Vec::new())
                .safe("Invalid test request.")?;
            // Check the policy failure itself: TLS rejection must not mask a downgrade.
            let failure = issuer.transport.send(request).await.err().ok_or_else(|| {
                Failure::harness("HTTP downgrade unexpectedly reached transport.")
            })?;
            assert_eq!(failure.kind, crate::error::Kind::Assertion);
            assert_eq!(
                failure.message,
                "OIDC transport rejected an untrusted destination or oversized request."
            );
            assert_eq!(issuer.requests.load(std::sync::atomic::Ordering::SeqCst), 0);
        }
        let foreign = crate::test_http::Issuer::start("{}".into(), reqwest::StatusCode::OK).await?;
        // Trust the second owned CA for this control; TLS failure cannot mask an origin-pinning defect.
        let transport = Transport {
            client: foreign.transport.client.clone(),
            issuer: issuer.transport.issuer.clone(),
        };
        let request = axum::http::Request::builder()
            .uri(format!("{}/jwks.json", foreign.transport.issuer))
            .body(Vec::new())
            .safe("Invalid test request.")?;
        assert!(transport.send(request).await.is_err());
        assert_eq!(
            foreign.requests.load(std::sync::atomic::Ordering::SeqCst),
            0
        );
        let request = axum::http::Request::builder()
            .uri(format!("{}/jwks.json", issuer.transport.issuer))
            .body(Vec::new())
            .safe("Invalid test request.")?;
        assert_eq!(
            issuer.transport.send(request).await?.status(),
            reqwest::StatusCode::OK
        );
        assert_eq!(issuer.requests.load(std::sync::atomic::Ordering::SeqCst), 1);
        Ok(())
    }

    #[test]
    fn callback_rejects_substitution_duplicates_errors_and_fragments() -> Result<()> {
        let redirect = "http://127.0.0.1:1234/callback";
        let issuer = "https://localhost:2345";
        let good = format!(
            "{redirect}?code=opaque&state=unchanged%2B%E9%9B%AA&iss=https%3A%2F%2Flocalhost%3A2345"
        );
        callback(&good, redirect, issuer, "unchanged+雪")?;
        for bad in [
            good.replace("callback?", "callback/evil?"),
            good.replace("1234", "1235"),
            good.replace("unchanged", "modified"),
            good.replace("2345", "2346"),
            format!("{good}&state=other"),
            format!("{good}#fragment"),
            good.replace("code=opaque", "error=access_denied"),
            good.replace("code=opaque", "code="),
            good.replace("&state=", "&code="),
        ] {
            assert!(callback(&bad, redirect, issuer, "unchanged+雪").is_err());
        }
        Ok(())
    }
}
