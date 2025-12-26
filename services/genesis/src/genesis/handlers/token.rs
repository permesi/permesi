use admission_token::AdmissionTokenClaims;
use axum::{
    Json,
    extract::rejection::QueryRejection,
    extract::{Extension, Query},
    http::{HeaderMap, HeaderValue, StatusCode, header::CACHE_CONTROL},
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row, postgres::PgDatabaseError};
use std::{env, future::Future, net::IpAddr, pin::Pin, process, sync::Arc};
use tracing::{Instrument, debug, error, info_span, instrument};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::genesis::admission::AdmissionSigner;

pub const TOKEN_EXPIRATION: i64 = 120; // 2 minutes

#[derive(ToSchema, Serialize, Deserialize, Debug)]
pub struct Token {
    token: String,
}

#[derive(IntoParams, Debug, Deserialize, Default)]
#[into_params(parameter_in = Query)]
pub struct ClientArgs {
    // uuid of the client
    client_id: String,
}

#[derive(Debug)]
struct RequestMetadata {
    ip_address: Option<IpAddr>,
    country: Option<String>,
    user_agent: Option<String>,
}

type TokenResponse = Result<(StatusCode, HeaderMap, Json<Token>), (StatusCode, String)>;

trait AdmissionSignerLike {
    fn make_claims(
        &self,
        now: i64,
        exp: i64,
        jti: String,
        sub: Option<String>,
    ) -> anyhow::Result<AdmissionTokenClaims>;
    fn sign<'a>(
        &'a self,
        claims: &'a AdmissionTokenClaims,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<String>> + Send + 'a>>;
}

impl AdmissionSignerLike for AdmissionSigner {
    fn make_claims(
        &self,
        now: i64,
        exp: i64,
        jti: String,
        sub: Option<String>,
    ) -> anyhow::Result<AdmissionTokenClaims> {
        self.make_claims(now, exp, jti, sub)
    }

    fn sign<'a>(
        &'a self,
        claims: &'a AdmissionTokenClaims,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<String>> + Send + 'a>> {
        Box::pin(self.sign(claims))
    }
}

#[utoipa::path(
    get,
    path= "/token",
    params(ClientArgs),
    responses (
        (status = 200, description = "Return token", body = Token),
        (status = 400, description = "Missing or invalid client ID", body = String),
        (status = 500, description = "Error creating the token", body = String)
    ),
    tag = "token",
)]
#[instrument(skip(pool, admission, headers, query))]
pub async fn token(
    Extension(pool): Extension<PgPool>,
    Extension(admission): Extension<Arc<AdmissionSigner>>,
    headers: HeaderMap,
    query: Result<Query<ClientArgs>, QueryRejection>,
) -> TokenResponse {
    let args = parse_client_args(query)?;
    let client_uuid = parse_client_uuid(&args.client_id)?;

    debug!("Client UUID: {}", client_uuid);

    let metadata = extract_metadata(&headers);

    // get client id from the payload
    let client_id = fetch_client_id(&pool, client_uuid).await?;
    let client_id = client_id.ok_or_else(|| {
        debug!("Unknown client UUID: {}", client_uuid);
        (StatusCode::BAD_REQUEST, "Invalid Client ID".to_string())
    })?;

    debug!("Client ID: {}", client_id);

    let token_id = insert_token_and_metadata(&pool, client_id, &metadata).await?;
    let token = issue_admission_token(&*admission, token_id, client_uuid).await?;
    let mut response_headers = HeaderMap::new();
    response_headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok((StatusCode::OK, response_headers, Json(token)))
}

fn parse_client_args(
    query: Result<Query<ClientArgs>, QueryRejection>,
) -> Result<ClientArgs, (StatusCode, String)> {
    if let Ok(Query(args)) = query {
        Ok(args)
    } else {
        error!("Failed to parse query parameters");
        Err((StatusCode::BAD_REQUEST, "Missing Client ID".to_string()))
    }
}

fn parse_client_uuid(client_id: &str) -> Result<Uuid, (StatusCode, String)> {
    client_id.parse::<Uuid>().map_err(|err| {
        error!("Failed to parse uuid: {}", err);
        (
            StatusCode::BAD_REQUEST,
            "Invalid Client ID format".to_string(),
        )
    })
}

fn extract_metadata(headers: &HeaderMap) -> RequestMetadata {
    let ip_header =
        env::var("GENESIS_IP_HEADER").unwrap_or_else(|_| "CF-Connecting-IP".to_string());
    let country_header =
        env::var("GENESIS_COUNTRY_HEADER").unwrap_or_else(|_| "CF-IPCountry".to_string());

    let ip_address = ip_from_headers(&ip_header, headers);
    let country = headers
        .get(country_header)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    let user_agent = headers
        .get("User-Agent")
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);

    RequestMetadata {
        ip_address,
        country,
        user_agent,
    }
}

fn ip_from_headers(header: &str, headers: &HeaderMap) -> Option<IpAddr> {
    headers
        .get(header)
        .and_then(|hv| hv.to_str().ok())
        .and_then(|s| s.parse::<IpAddr>().ok())
}

async fn fetch_client_id(
    pool: &PgPool,
    client_uuid: Uuid,
) -> Result<Option<i16>, (StatusCode, String)> {
    let query = "SELECT id, is_reserved FROM clients WHERE uuid = $1";
    let span = info_span!(
        "db.query",
        db.system = "postgresql",
        db.operation = "SELECT",
        db.statement = query
    );
    let row = match sqlx::query(query)
        .bind(client_uuid)
        .fetch_optional(pool)
        .instrument(span)
        .await
    {
        Ok(row) => row,
        Err(err) => match err {
            sqlx::Error::Database(db_err)
                if db_err
                    .as_error()
                    .downcast_ref::<PgDatabaseError>()
                    .map(PgDatabaseError::code)
                    == Some("42501") =>
            {
                error!(
                    "DB Error 42501 - Insufficient privilege: {}",
                    db_err.message()
                );
                process::exit(1);
            }
            _ => {
                error!("Failed to retrieve client ID from database: {}", err);
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Failed to retrieve client ID".to_string(),
                ));
            }
        },
    };

    let Some(row) = row else {
        return Ok(None);
    };

    let client_id: i16 = row.try_get("id").map_err(|err| {
        error!("Failed to read client ID from database: {}", err);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to retrieve client ID".to_string(),
        )
    })?;

    let is_reserved: bool = row.try_get("is_reserved").map_err(|err| {
        error!(
            "Failed to read client reservation flag from database: {}",
            err
        );
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to retrieve client ID".to_string(),
        )
    })?;

    if is_reserved {
        debug!("Reserved client UUID refused: {}", client_uuid);
        return Ok(None);
    }

    Ok(Some(client_id))
}

async fn insert_token_and_metadata(
    pool: &PgPool,
    client_id: i16,
    metadata: &RequestMetadata,
) -> Result<Uuid, (StatusCode, String)> {
    let query = "INSERT INTO tokens (client_id, ip_address, country, user_agent) VALUES ($1, $2, $3, $4) RETURNING id";
    let span = info_span!(
        "db.query",
        db.system = "postgresql",
        db.operation = "INSERT",
        db.statement = query
    );
    let row = sqlx::query(query)
        .bind(client_id)
        .bind(metadata.ip_address)
        .bind(metadata.country.as_deref())
        .bind(metadata.user_agent.as_deref())
        .fetch_one(pool)
        .instrument(span)
        .await
        .map_err(|err| {
            error!("Failed to insert token into database: {}", err);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to persist token".to_string(),
            )
        })?;
    let token_id: Uuid = row.get("id");
    Ok(token_id)
}

async fn issue_admission_token<S: AdmissionSignerLike>(
    admission: &S,
    token_id: Uuid,
    client_uuid: Uuid,
) -> Result<Token, (StatusCode, String)> {
    let now = Utc::now().timestamp();
    let exp = now + TOKEN_EXPIRATION;

    let claims = admission
        .make_claims(
            now,
            exp,
            token_id.to_string(),
            Some(client_uuid.to_string()),
        )
        .map_err(|err| {
            error!("Failed to build admission claims: {err:#}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to build token claims".to_string(),
            )
        })?;

    let token_paseto = admission.sign(&claims).await.map_err(|err| {
        error!("Failed to sign admission token: {err:#}");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to sign token".to_string(),
        )
    })?;

    Ok(Token {
        token: token_paseto,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{Result, anyhow};
    use axum::extract::Query;
    use axum::http::HeaderValue;
    use axum::http::Uri;
    use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode};
    use std::time::Duration;
    use temp_env;

    #[test]
    fn token_serializes_without_expires() -> Result<(), serde_json::Error> {
        let token = Token {
            token: "test-token".to_string(),
        };
        let value = serde_json::to_value(token)?;
        assert_eq!(value, serde_json::json!({ "token": "test-token" }));
        Ok(())
    }

    #[test]
    fn ip_from_headers_parses_valid_ip() {
        let mut headers = HeaderMap::new();
        headers.insert("X-Client-IP", HeaderValue::from_static("203.0.113.10"));
        let ip = ip_from_headers("X-Client-IP", &headers);
        assert_eq!(ip, Some(IpAddr::from([203, 0, 113, 10])));
    }

    #[test]
    fn ip_from_headers_rejects_invalid_ip() {
        let mut headers = HeaderMap::new();
        headers.insert("X-Client-IP", HeaderValue::from_static("not-an-ip"));
        let ip = ip_from_headers("X-Client-IP", &headers);
        assert!(ip.is_none());
    }

    #[test]
    fn parse_client_args_accepts_valid_query() {
        let query = Ok(Query(ClientArgs {
            client_id: "client-123".to_string(),
        }));
        let parsed = parse_client_args(query);
        assert!(matches!(parsed, Ok(args) if args.client_id == "client-123"));
    }

    #[test]
    fn parse_client_args_rejects_missing_client_id() -> Result<()> {
        let uri: Uri = "http://example.com/token".parse()?;
        let rejection = Query::<ClientArgs>::try_from_uri(&uri)
            .err()
            .ok_or_else(|| anyhow!("expected query rejection"))?;
        let parsed = parse_client_args(Err(rejection));
        assert!(matches!(
            parsed,
            Err((StatusCode::BAD_REQUEST, msg)) if msg == "Missing Client ID"
        ));
        Ok(())
    }

    #[test]
    fn parse_client_uuid_accepts_valid_uuid() {
        let uuid = Uuid::new_v4();
        let parsed = parse_client_uuid(&uuid.to_string());
        assert!(matches!(parsed, Ok(value) if value == uuid));
    }

    #[test]
    fn parse_client_uuid_rejects_invalid_uuid() {
        let parsed = parse_client_uuid("not-a-uuid");
        assert!(matches!(
            parsed,
            Err((StatusCode::BAD_REQUEST, msg)) if msg == "Invalid Client ID format"
        ));
    }

    #[test]
    fn extract_metadata_uses_default_headers() {
        temp_env::with_vars(
            [
                ("GENESIS_IP_HEADER", None::<String>),
                ("GENESIS_COUNTRY_HEADER", None::<String>),
            ],
            || {
                let mut headers = HeaderMap::new();
                headers.insert("CF-Connecting-IP", HeaderValue::from_static("203.0.113.10"));
                headers.insert("CF-IPCountry", HeaderValue::from_static("US"));
                headers.insert("User-Agent", HeaderValue::from_static("agent"));

                let metadata = extract_metadata(&headers);
                assert_eq!(metadata.ip_address, Some(IpAddr::from([203, 0, 113, 10])));
                assert_eq!(metadata.country.as_deref(), Some("US"));
                assert_eq!(metadata.user_agent.as_deref(), Some("agent"));
            },
        );
    }

    #[test]
    fn extract_metadata_respects_env_override() {
        temp_env::with_vars(
            [
                ("GENESIS_IP_HEADER", Some("X-Client-IP")),
                ("GENESIS_COUNTRY_HEADER", Some("X-Client-Country")),
            ],
            || {
                let mut headers = HeaderMap::new();
                headers.insert("X-Client-IP", HeaderValue::from_static("198.51.100.5"));
                headers.insert("X-Client-Country", HeaderValue::from_static("BR"));
                headers.insert("User-Agent", HeaderValue::from_static("agent"));

                let metadata = extract_metadata(&headers);
                assert_eq!(metadata.ip_address, Some(IpAddr::from([198, 51, 100, 5])));
                assert_eq!(metadata.country.as_deref(), Some("BR"));
                assert_eq!(metadata.user_agent.as_deref(), Some("agent"));
            },
        );
    }

    #[test]
    fn extract_metadata_overrides_ip_only() {
        temp_env::with_vars(
            [
                ("GENESIS_IP_HEADER", Some("X-Real-IP")),
                ("GENESIS_COUNTRY_HEADER", None::<&str>),
            ],
            || {
                let mut headers = HeaderMap::new();
                headers.insert("X-Real-IP", HeaderValue::from_static("192.0.2.55"));
                headers.insert("CF-IPCountry", HeaderValue::from_static("CA"));

                let metadata = extract_metadata(&headers);
                assert_eq!(metadata.ip_address, Some(IpAddr::from([192, 0, 2, 55])));
                assert_eq!(metadata.country.as_deref(), Some("CA"));
            },
        );
    }

    #[test]
    fn extract_metadata_overrides_country_only() {
        temp_env::with_vars(
            [
                ("GENESIS_IP_HEADER", None::<&str>),
                ("GENESIS_COUNTRY_HEADER", Some("X-Geo-Country")),
            ],
            || {
                let mut headers = HeaderMap::new();
                headers.insert(
                    "CF-Connecting-IP",
                    HeaderValue::from_static("198.51.100.25"),
                );
                headers.insert("X-Geo-Country", HeaderValue::from_static("DE"));

                let metadata = extract_metadata(&headers);
                assert_eq!(metadata.ip_address, Some(IpAddr::from([198, 51, 100, 25])));
                assert_eq!(metadata.country.as_deref(), Some("DE"));
            },
        );
    }

    fn unreachable_pool() -> PgPool {
        let options = PgConnectOptions::new()
            .host("127.0.0.1")
            .port(1)
            .username("invalid")
            .database("invalid")
            .ssl_mode(PgSslMode::Disable);
        PgPoolOptions::new()
            .acquire_timeout(Duration::from_millis(200))
            .connect_lazy_with(options)
    }

    #[tokio::test]
    async fn fetch_client_id_returns_error_on_db_failure() {
        let pool = unreachable_pool();
        let result = fetch_client_id(&pool, Uuid::new_v4()).await;
        assert!(matches!(
            result,
            Err((StatusCode::INTERNAL_SERVER_ERROR, _))
        ));
    }

    #[tokio::test]
    async fn insert_token_and_metadata_fails_without_db() {
        let pool = unreachable_pool();
        let metadata = RequestMetadata {
            ip_address: Some(IpAddr::from([203, 0, 113, 10])),
            country: Some("US".to_string()),
            user_agent: Some("agent".to_string()),
        };

        let result = insert_token_and_metadata(&pool, 1, &metadata).await;
        assert!(matches!(
            result,
            Err((StatusCode::INTERNAL_SERVER_ERROR, _))
        ));
    }

    #[derive(Debug)]
    struct TestSigner {
        expected_jti: String,
        expected_sub: String,
        token: String,
        fail_claims: bool,
        fail_sign: bool,
    }

    impl AdmissionSignerLike for TestSigner {
        fn make_claims(
            &self,
            now: i64,
            exp: i64,
            jti: String,
            sub: Option<String>,
        ) -> anyhow::Result<AdmissionTokenClaims> {
            if self.fail_claims {
                return Err(anyhow!("claims error"));
            }
            if jti != self.expected_jti {
                return Err(anyhow!("unexpected jti"));
            }
            let sub = sub.ok_or_else(|| anyhow!("missing sub"))?;
            if sub != self.expected_sub {
                return Err(anyhow!("unexpected sub"));
            }
            Ok(AdmissionTokenClaims {
                iss: "issuer".to_string(),
                aud: "permesi".to_string(),
                exp: exp.to_string(),
                iat: now.to_string(),
                jti,
                action: "admission".to_string(),
                sub: Some(sub),
            })
        }

        fn sign<'a>(
            &'a self,
            _claims: &'a AdmissionTokenClaims,
        ) -> Pin<Box<dyn Future<Output = anyhow::Result<String>> + Send + 'a>> {
            Box::pin(async move {
                if self.fail_sign {
                    Err(anyhow!("sign error"))
                } else {
                    Ok(self.token.clone())
                }
            })
        }
    }

    #[tokio::test]
    async fn issue_admission_token_returns_signed_token() -> Result<()> {
        let token_id = Uuid::new_v4();
        let client_uuid = Uuid::new_v4();
        let signer = TestSigner {
            expected_jti: token_id.to_string(),
            expected_sub: client_uuid.to_string(),
            token: "signed-token".to_string(),
            fail_claims: false,
            fail_sign: false,
        };

        let token = issue_admission_token(&signer, token_id, client_uuid)
            .await
            .map_err(|err| anyhow!("issue_admission_token failed: {err:?}"))?;
        assert_eq!(token.token, "signed-token");
        Ok(())
    }

    #[tokio::test]
    async fn issue_admission_token_handles_claims_error() {
        let token_id = Uuid::new_v4();
        let client_uuid = Uuid::new_v4();
        let signer = TestSigner {
            expected_jti: token_id.to_string(),
            expected_sub: client_uuid.to_string(),
            token: "signed-token".to_string(),
            fail_claims: true,
            fail_sign: false,
        };

        let result = issue_admission_token(&signer, token_id, client_uuid).await;
        assert!(matches!(
            result,
            Err((StatusCode::INTERNAL_SERVER_ERROR, msg)) if msg == "Failed to build token claims"
        ));
    }

    #[tokio::test]
    async fn issue_admission_token_handles_sign_error() {
        let token_id = Uuid::new_v4();
        let client_uuid = Uuid::new_v4();
        let signer = TestSigner {
            expected_jti: token_id.to_string(),
            expected_sub: client_uuid.to_string(),
            token: "signed-token".to_string(),
            fail_claims: false,
            fail_sign: true,
        };

        let result = issue_admission_token(&signer, token_id, client_uuid).await;
        assert!(matches!(
            result,
            Err((StatusCode::INTERNAL_SERVER_ERROR, msg)) if msg == "Failed to sign token"
        ));
    }
}
