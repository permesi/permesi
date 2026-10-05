//! Organization step-up regressions using real OPAQUE proofs, sessions and PostgreSQL.
//! The ignored browser test runs explicitly in the normal web-browser recipe.

#![allow(clippy::too_many_lines, clippy::too_many_arguments)]

use super::*;
use crate::api::{AppState, handlers::AdmissionVerifier};
use admission_token::{
    AdmissionTokenClaims, AdmissionTokenFooter, PaserkKey, PaserkKeySet, build_token,
    encode_signing_input,
};
use ed25519_dalek::Signer;
use serde_json::Value;

const ORG: &str = "/v1/orgs/deletion-browser";
const EMAIL: &str = "owner@deletion-browser.test";

/// Owns an actual password registration, stale full session, and empty owner-authorized tenant.
struct Fixture {
    db: TestDb,
    state: AppState,
    router: Router,
    token: String,
    other_token: String,
    password: String,
    user: Uuid,
    org: Uuid,
    admission: String,
}

impl Fixture {
    /// Installs compatible OPAQUE registration material and a signed admission verifier fixture.
    async fn new() -> Result<Option<Self>> {
        let Some(db) = TestDb::new().await? else {
            return Ok(None);
        };
        let password = Uuid::new_v4().to_string();
        let mut state = AppState::for_tests(db.pool.clone())?;
        let mut rng = opaque_rand_core::OsRng;
        let start = ClientRegistration::<OpaqueSuite>::start(&mut rng, password.as_bytes())?;
        let response = ServerRegistration::<OpaqueSuite>::start(
            state.auth.opaque().server_setup(),
            start.message,
            EMAIL.as_bytes(),
        )?;
        let ksf = opaque_argon2::Argon2::default();
        let finish = start.state.finish(
            &mut rng,
            password.as_bytes(),
            response.message,
            ClientRegistrationFinishParameters::new(
                identifiers(EMAIL.as_bytes(), b"api.permesi.dev"),
                Some(&ksf),
            ),
        )?;
        let record = ServerRegistration::finish(finish.message);
        let user = Uuid::new_v4();
        sqlx::query("INSERT INTO users (id,email,opaque_registration_record,status) VALUES ($1,$2,$3,'active')")
            .bind(user).bind(EMAIL).bind(record.serialize().to_vec()).execute(&db.pool).await?;
        let token = generate_session_token()?;
        sqlx::query("INSERT INTO user_sessions (user_id,session_hash,created_at,auth_time,expires_at) VALUES ($1,$2,NOW()-INTERVAL '20 minutes',NOW()-INTERVAL '20 minutes',NOW()+INTERVAL '1 hour')")
            .bind(user).bind(hash_session_token(&token)).execute(&db.pool).await?;
        let signing = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let key = PaserkKey::from_ed25519_public_key_bytes(&signing.verifying_key().to_bytes())?;
        state.admission = Arc::new(AdmissionVerifier::new(
            PaserkKeySet {
                version: "v4".to_owned(),
                purpose: "public".to_owned(),
                active_kid: key.kid.clone(),
                keys: vec![key.clone()],
            },
            "https://genesis.test".to_owned(),
            "permesi".to_owned(),
        ));
        let now = unix_now();
        let input = encode_signing_input(
            &AdmissionTokenClaims {
                iss: "https://genesis.test".to_owned(),
                aud: "permesi".to_owned(),
                iat: admission_token::rfc3339_from_unix(now)?,
                exp: admission_token::rfc3339_from_unix(now + 120)?,
                jti: Uuid::new_v4().to_string(),
                sub: None,
                action: "admission".to_owned(),
            },
            &AdmissionTokenFooter { kid: key.kid },
        )?;
        let admission = build_token(
            &input.payload,
            &input.footer,
            &signing.sign(&input.pre_auth).to_bytes(),
        );
        let router = service_utils::api_error::with_error_envelope(
            crate::api::router()
                .split_for_parts()
                .0
                .with_state(state.clone()),
        );
        let response = call(
            &router,
            &token,
            &admission,
            "POST",
            "/v1/orgs",
            Some(json!({"name":"Deletion browser","slug":"deletion-browser"})),
            None,
        )
        .await?;
        assert_eq!(response.0, StatusCode::CREATED);
        let org = Uuid::parse_str(
            response
                .1
                .get("id")
                .and_then(Value::as_str)
                .context("org id")?,
        )?;
        let other = Uuid::new_v4();
        sqlx::query("INSERT INTO users (id,email,opaque_registration_record,status) VALUES ($1,'other@deletion-browser.test',$2,'active')")
            .bind(other).bind(record.serialize().to_vec()).execute(&db.pool).await?;
        sqlx::query("INSERT INTO org_memberships (org_id,user_id,status) VALUES ($1,$2,'active')")
            .bind(org)
            .bind(other)
            .execute(&db.pool)
            .await?;
        sqlx::query(
            "INSERT INTO org_member_roles (org_id,user_id,role_name) VALUES ($1,$2,'owner')",
        )
        .bind(org)
        .bind(other)
        .execute(&db.pool)
        .await?;
        let other_token = generate_session_token()?;
        sqlx::query("INSERT INTO user_sessions (user_id,session_hash,expires_at) VALUES ($1,$2,NOW()+INTERVAL '1 hour')").bind(other).bind(hash_session_token(&other_token)).execute(&db.pool).await?;
        Ok(Some(Self {
            db,
            state,
            router,
            token,
            other_token,
            password,
            user,
            org,
            admission,
        }))
    }

    /// Captures server authentication time without exposing session hashes or passwords.
    async fn auth_time(&self) -> Result<i64> {
        Ok(sqlx::query_scalar(
            "SELECT EXTRACT(EPOCH FROM auth_time)::bigint FROM user_sessions WHERE session_hash=$1",
        )
        .bind(hash_session_token(&self.token))
        .fetch_one(&self.db.pool)
        .await?)
    }

    /// Runs the real start/finish transcript; wrong passwords cannot generate a valid finalization.
    async fn proof(&self, password: &str) -> Result<bool> {
        let mut rng = opaque_rand_core::OsRng;
        let start = ClientLogin::<OpaqueSuite>::start(&mut rng, password.as_bytes())?;
        let response = call(
            &self.router,
            &self.token,
            &self.admission,
            "POST",
            "/v1/auth/opaque/reauth/start",
            Some(json!({"credential_request":STANDARD.encode(start.message.serialize())})),
            None,
        )
        .await?;
        assert_eq!(response.0, StatusCode::OK);
        let credential = CredentialResponse::<OpaqueSuite>::deserialize(
            &STANDARD.decode(
                response
                    .1
                    .get("credential_response")
                    .and_then(Value::as_str)
                    .context("credential response")?,
            )?,
        )?;
        let ksf = opaque_argon2::Argon2::default();
        let finish = start.state.finish(
            &mut rng,
            password.as_bytes(),
            credential,
            ClientLoginFinishParameters::new(
                None,
                identifiers(EMAIL.as_bytes(), b"api.permesi.dev"),
                Some(&ksf),
            ),
        );
        let Ok(finish) = finish else {
            return Ok(false);
        };
        let payload = json!({"login_id":response.1.get("login_id").context("login id")?,"credential_finalization":STANDARD.encode(finish.message.serialize())});
        assert_eq!(
            call(
                &self.router,
                &self.other_token,
                &self.admission,
                "POST",
                "/v1/auth/opaque/reauth/finish",
                Some(payload.clone()),
                None
            )
            .await?
            .0,
            StatusCode::UNAUTHORIZED
        );
        // A foreign-session attempt consumes the single-use exchange; restart the valid proof.
        Ok(true)
    }
}

/// Executes a production handler without recording cookies, transcripts or secrets in logs.
async fn call(
    router: &Router,
    token: &str,
    admission: &str,
    method: &str,
    path: &str,
    payload: Option<Value>,
    expected: Option<Uuid>,
) -> Result<(StatusCode, Value)> {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header(COOKIE, format!("permesi_session={token}"))
        .header("X-Permesi-Zero-Token", admission);
    if let Some(expected) = expected {
        request = request.header("X-Permesi-Expected-Organization-Id", expected.to_string());
    }
    let body = if let Some(payload) = payload {
        request = request.header(CONTENT_TYPE, "application/json");
        Body::from(payload.to_string())
    } else {
        Body::empty()
    };
    let response = router.clone().oneshot(request.body(body)?).await?;
    let status = response.status();
    let body = to_bytes(response.into_body(), 65536).await?;
    Ok((
        status,
        if body.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&body)?
        },
    ))
}

/// Password success refreshes only the session; replay and wrong-account proofs cannot authorize deletion.
#[tokio::test]
async fn organization_reauthentication_requires_real_proof_and_separate_delete() -> Result<()> {
    let Some(f) = Fixture::new().await? else {
        return Ok(());
    };
    let before = f.auth_time().await?;
    let blocked = call(
        &f.router,
        &f.token,
        &f.admission,
        "DELETE",
        ORG,
        None,
        Some(f.org),
    )
    .await?;
    assert_eq!(blocked.0, StatusCode::UNAUTHORIZED);
    assert_eq!(
        blocked
            .1
            .get("error")
            .and_then(|e| e.get("code"))
            .context("error code")?,
        "reauthentication_required"
    );
    assert!(!f.proof("wrong-password").await?);
    assert_eq!(f.auth_time().await?, before);
    assert!(f.proof(&f.password).await?);
    assert_eq!(
        f.auth_time().await?,
        before,
        "Foreign-session proof must not refresh owner"
    );
    let mut rng = opaque_rand_core::OsRng;
    let start = ClientLogin::<OpaqueSuite>::start(&mut rng, f.password.as_bytes())?;
    let response = call(
        &f.router,
        &f.token,
        &f.admission,
        "POST",
        "/v1/auth/opaque/reauth/start",
        Some(json!({"credential_request":STANDARD.encode(start.message.serialize())})),
        None,
    )
    .await?;
    let credential = CredentialResponse::<OpaqueSuite>::deserialize(
        &STANDARD.decode(
            response
                .1
                .get("credential_response")
                .and_then(Value::as_str)
                .context("credential response")?,
        )?,
    )?;
    let ksf = opaque_argon2::Argon2::default();
    let finish = start.state.finish(
        &mut rng,
        f.password.as_bytes(),
        credential,
        ClientLoginFinishParameters::new(
            None,
            identifiers(EMAIL.as_bytes(), b"api.permesi.dev"),
            Some(&ksf),
        ),
    )?;
    let payload = json!({"login_id":response.1.get("login_id").context("login id")?,"credential_finalization":STANDARD.encode(finish.message.serialize())});
    assert_eq!(
        call(
            &f.router,
            &f.token,
            &f.admission,
            "POST",
            "/v1/auth/opaque/reauth/finish",
            Some(payload.clone()),
            None
        )
        .await?
        .0,
        StatusCode::NO_CONTENT
    );
    assert!(f.auth_time().await? > before);
    assert_eq!(
        call(
            &f.router,
            &f.token,
            &f.admission,
            "POST",
            "/v1/auth/opaque/reauth/finish",
            Some(payload),
            None
        )
        .await?
        .0,
        StatusCode::UNAUTHORIZED
    );
    let active: bool =
        sqlx::query_scalar("SELECT deleted_at IS NULL FROM organizations WHERE id=$1")
            .bind(f.org)
            .fetch_one(&f.db.pool)
            .await?;
    assert!(active, "Reauthentication alone must never delete");
    assert_eq!(
        call(
            &f.router,
            &f.token,
            &f.admission,
            "DELETE",
            ORG,
            None,
            Some(f.org)
        )
        .await?
        .0,
        StatusCode::NO_CONTENT
    );
    Ok(())
}

/// Loopback-only fixture controls simulate independent membership changes against real PostgreSQL.
#[derive(Clone)]
struct Control {
    pool: PgPool,
    user: Uuid,
    org: Uuid,
}

/// Mutates only the isolated test database; this handler is never part of the production router.
async fn control(
    axum::extract::State(c): axum::extract::State<Control>,
    axum::Json(value): axum::Json<Value>,
) -> Result<axum::Json<Value>, StatusCode> {
    let result: Result<Value> = async {
        match value.get("action").and_then(Value::as_str) {
            Some("stale") => {
                sqlx::query("UPDATE user_sessions SET created_at=NOW()-INTERVAL '20 minutes',auth_time=NOW()-INTERVAL '20 minutes' WHERE user_id=$1").bind(c.user).execute(&c.pool).await?;
            }
            Some("role_lost") => {
                sqlx::query("DELETE FROM org_member_roles WHERE org_id=$1 AND user_id=$2").bind(c.org).bind(c.user).execute(&c.pool).await?;
            }
            Some("owner") => {
                sqlx::query("INSERT INTO org_member_roles (org_id,user_id,role_name) VALUES ($1,$2,'owner') ON CONFLICT DO NOTHING").bind(c.org).bind(c.user).execute(&c.pool).await?;
            }
            Some("status") => {}
            _ => anyhow::bail!("Unknown fixture control"),
        }
        let active: bool = sqlx::query_scalar("SELECT deleted_at IS NULL FROM organizations WHERE id=$1").bind(c.org).fetch_one(&c.pool).await?;
        let auth_time: i64 = sqlx::query_scalar("SELECT EXTRACT(EPOCH FROM auth_time)::bigint FROM user_sessions WHERE user_id=$1 LIMIT 1").bind(c.user).fetch_one(&c.pool).await?;
        Ok(json!({"active":active,"auth_time":auth_time}))
    }.await;
    result
        .map(axum::Json)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

/// Runs the compiled CSR console against real OPAQUE, PostgreSQL and signed admission verification.
#[tokio::test]
#[ignore = "requires Chromium, Node and built WASM; run just web-test-browser"]
async fn organization_deletion_browser_real_opaque_and_postgres() -> Result<()> {
    let Some(f) = Fixture::new().await? else {
        anyhow::bail!("Browser fixture requires a container runtime");
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let origin = format!("http://{}", listener.local_addr()?);
    let admission = f.admission.clone();
    let fixture = Router::new()
        .route("/test/control", post(control))
        .with_state(Control {
            pool: f.db.pool.clone(),
            user: f.user,
            org: f.org,
        })
        .route(
            "/test/admission",
            get(move || {
                let admission = admission.clone();
                async move { axum::Json(json!({"token":admission})) }
            }),
        );
    let app = service_utils::api_error::with_error_envelope(
        crate::api::router()
            .split_for_parts()
            .0
            .with_state(f.state.clone()),
    )
    .merge(fixture);
    let stop = tokio_util::sync::CancellationToken::new();
    let signal = stop.clone();
    let server = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(signal.cancelled_owned())
            .await
    });
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let output = tokio::process::Command::new("node")
        .arg(root.join("apps/web/tests/tenant_deletion.mjs"))
        .env("PERMESI_DELETION_TEST_API", origin)
        .env("PERMESI_DELETION_TEST_SESSION", &f.token)
        .env("PERMESI_DELETION_TEST_OTHER_SESSION", &f.other_token)
        .env("PERMESI_DELETION_TEST_PASSWORD", &f.password)
        .kill_on_drop(true)
        .output();
    let result = tokio::time::timeout(Duration::from_secs(100), output).await;
    stop.cancel();
    server.await??;
    let output = result??;
    anyhow::ensure!(
        output.status.success(),
        "Browser test failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    anyhow::ensure!(
        String::from_utf8_lossy(&output.stdout).contains("browser passed"),
        "Browser completion marker missing"
    );
    let active: bool =
        sqlx::query_scalar("SELECT deleted_at IS NULL FROM organizations WHERE id=$1")
            .bind(f.org)
            .fetch_one(&f.db.pool)
            .await?;
    assert!(
        active,
        "Original renamed tenant must survive stale confirmation"
    );
    let replacement_deleted: bool = sqlx::query_scalar(
        "SELECT deleted_at IS NOT NULL FROM organizations WHERE slug='deletion-browser'",
    )
    .fetch_one(&f.db.pool)
    .await?;
    assert!(
        replacement_deleted,
        "Only the newly opened replacement confirmation deletes"
    );
    Ok(())
}
