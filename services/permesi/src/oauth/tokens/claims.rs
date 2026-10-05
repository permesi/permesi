//! Minimal delegated access claims and OIDC authentication claims, signed before commit.
//!
//! PostgreSQL supplies time; exact redeemed scopes/tenant/user/nonce supply authority.
//! Access and ID tokens use distinct typ/audience boundaries. No internal Principal scopes,
//! profile attributes, refresh tokens or browser-submitted authority enter these claims.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Duration, Utc};
use secrecy::{ExposeSecret as _, SecretString};
use serde::{Serialize, Serializer, ser::SerializeStruct as _};
use sha2::{Digest as _, Sha256};
use sqlx::{Postgres, Transaction};
use utoipa::ToSchema;
use uuid::Uuid;

use super::{
    super::{authorization::redemption::RedeemedCode, oidc::OAuthState},
    TokenError,
};

/// Successful protocol response. Secrets have no Debug and serialize only at the wire boundary.
#[derive(ToSchema)]
pub(crate) struct TokenResponse {
    #[schema(value_type=String)]
    pub access_token: SecretString,
    pub token_type: &'static str,
    pub expires_in: i64,
    pub scope: String,
    #[schema(value_type=Option<String>)]
    pub id_token: Option<SecretString>,
}

impl Serialize for TokenResponse {
    /// Exposes bearer material exclusively at the response encoder; omits absent ID tokens.
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut output = serializer
            .serialize_struct("TokenResponse", if self.id_token.is_some() { 5 } else { 4 })?;
        output.serialize_field("access_token", self.access_token.expose_secret())?;
        output.serialize_field("token_type", self.token_type)?;
        output.serialize_field("expires_in", &self.expires_in)?;
        output.serialize_field("scope", &self.scope)?;
        if let Some(token) = &self.id_token {
            output.serialize_field("id_token", token.expose_secret())?;
        }
        output.end()
    }
}

/// Internal immutable receipt inputs; signed bearer strings remain redacted.
pub(super) struct Issued {
    pub response: TokenResponse,
    pub jti: Uuid,
    pub created_at: DateTime<Utc>,
    pub access_expires_at: DateTime<Utc>,
    pub id_expires_at: Option<DateTime<Utc>>,
}

/// RFC 9068 access token with an explicit single tenant/application/grant boundary.
#[derive(Serialize)]
struct AccessClaims<'a> {
    iss: &'a str,
    sub: Uuid,
    aud: &'a str,
    iat: i64,
    exp: i64,
    jti: Uuid,
    client_id: Uuid,
    scope: &'a str,
    organization_id: Uuid,
    application_id: Uuid,
    grant_id: Uuid,
}

/// OIDC identity proof; client audience and access-token hash prevent token substitution.
#[derive(Serialize)]
struct IdClaims<'a> {
    iss: &'a str,
    sub: Uuid,
    aud: Uuid,
    iat: i64,
    exp: i64,
    auth_time: i64,
    nonce: &'a str,
    at_hash: String,
}

/// Uses a fresh shared Vault key and DB clock, signing both tokens before receipt/commit.
pub(super) async fn issue(
    oauth: &OAuthState,
    tx: &mut Transaction<'_, Postgres>,
    code: &RedeemedCode,
) -> Result<Issued, TokenError> {
    let issued_at: DateTime<Utc> =
        sqlx::query_scalar("SELECT date_trunc('second',clock_timestamp())")
            .fetch_one(&mut **tx)
            .await?;
    let access_expires_at = issued_at + Duration::seconds(oauth.config.tokens.access_ttl);
    let mut random = [0; 16];
    getrandom::fill(&mut random).map_err(|_| TokenError::Unavailable)?;
    let jti = uuid::Builder::from_random_bytes(random).into_uuid();
    let scope = code
        .scopes
        .iter()
        .map(crate::oauth::scope::OAuthScope::as_str)
        .collect::<Vec<_>>()
        .join(" ");
    let key = oauth
        .signing_key()
        .await
        .map_err(|_| TokenError::Unavailable)?;
    let access_token = oauth
        .sign_jwt(
            &key,
            "at+jwt",
            &AccessClaims {
                iss: &code.issuer,
                sub: code.user_id,
                aud: &code.audience,
                iat: issued_at.timestamp(),
                exp: access_expires_at.timestamp(),
                jti,
                client_id: code.client_id,
                scope: &scope,
                organization_id: code.organization_id,
                application_id: code.application_id,
                grant_id: code.grant_id,
            },
        )
        .await
        .map_err(|_| TokenError::Unavailable)?;
    let (id_token, id_expires_at) = if code.scopes.iter().any(|s| s.as_str() == "openid") {
        let nonce = code.nonce.as_deref().ok_or(TokenError::InvalidGrant)?;
        let expires = issued_at + Duration::seconds(oauth.config.tokens.id_ttl);
        let digest = Sha256::digest(access_token.expose_secret().as_bytes());
        let token = oauth
            .sign_jwt(
                &key,
                "JWT",
                &IdClaims {
                    iss: &code.issuer,
                    sub: code.user_id,
                    aud: code.client_id,
                    iat: issued_at.timestamp(),
                    exp: expires.timestamp(),
                    auth_time: code.auth_time.timestamp(),
                    nonce,
                    at_hash: URL_SAFE_NO_PAD
                        .encode(digest.get(..16).ok_or(TokenError::Unavailable)?),
                },
            )
            .await
            .map_err(|_| TokenError::Unavailable)?;
        (Some(token), Some(expires))
    } else {
        (None, None)
    };
    Ok(Issued {
        response: TokenResponse {
            access_token,
            token_type: "Bearer",
            expires_in: oauth.config.tokens.access_ttl,
            scope,
            id_token,
        },
        jti,
        created_at: issued_at,
        access_expires_at,
        id_expires_at,
    })
}
