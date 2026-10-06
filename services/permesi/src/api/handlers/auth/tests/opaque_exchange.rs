//! Real OPAQUE transcripts across independent service instances sharing PostgreSQL.
//! No fixture copies pending protocol state between replicas; only the Vault seed
//! and server identifier are shared. Replay never creates an additional session.

use super::super::{
    opaque::exchange::{ExchangeIdentity, ExchangePurpose, hash_id, lock_identity},
    session_kind::SessionKind,
};
use super::*;
use axum::response::Response;
use serde_json::Value;
use sha2::{Digest, Sha256};

/// Retains a client proof only in test memory, never in failure diagnostics.
struct Proof {
    id: Uuid,
    email: String,
    finalization: String,
}

impl Proof {
    /// Constructs the unchanged public finish payload without adding authority fields.
    fn payload(&self) -> Value {
        json!({"login_id":self.id.to_string(),"email":self.email,"credential_finalization":self.finalization})
    }
}

/// Sends a real admission-protected request with an optional verified session cookie.
async fn post(
    router: &Router,
    path: &str,
    payload: Value,
    admission: &str,
    cookie: Option<&str>,
) -> Result<Response> {
    let mut request = Request::builder()
        .method("POST")
        .uri(path)
        .header(CONTENT_TYPE, "application/json")
        .header("X-Permesi-Zero-Token", admission);
    if let Some(cookie) = cookie {
        request = request.header(COOKIE, format!("permesi_session={cookie}"));
    }
    Ok(router
        .clone()
        .oneshot(request.body(Body::from(payload.to_string()))?)
        .await?)
}

/// Completes the client side of a real exchange using the existing suite and identifiers.
async fn proof(
    router: &Router,
    email: &str,
    password: &[u8],
    admission: &str,
    cookie: Option<&str>,
) -> Result<Proof> {
    let mut rng = opaque_rand_core::OsRng;
    let client = ClientLogin::<OpaqueSuite>::start(&mut rng, password)?;
    let path = if cookie.is_some() {
        "/v1/auth/opaque/reauth/start"
    } else {
        "/v1/auth/opaque/login/start"
    };
    let response = post(
        router,
        path,
        json!({"email":email,"credential_request":STANDARD.encode(client.message.serialize())}),
        admission,
        cookie,
    )
    .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(&to_bytes(response.into_body(), 16_384).await?)?;
    let id = body
        .get("login_id")
        .and_then(Value::as_str)
        .context("exchange id")?
        .parse()?;
    let message = STANDARD.decode(
        body.get("credential_response")
            .and_then(Value::as_str)
            .context("credential response")?,
    )?;
    let ksf = opaque_argon2::Argon2::default();
    let finish = client.state.finish(
        &mut rng,
        password,
        CredentialResponse::deserialize(&message)?,
        ClientLoginFinishParameters::new(
            None,
            identifiers(email.as_bytes(), b"api.permesi.dev"),
            Some(&ksf),
        ),
    )?;
    Ok(Proof {
        id,
        email: email.to_owned(),
        finalization: STANDARD.encode(finish.message.serialize()),
    })
}

#[tokio::test]
async fn opaque_login_completes_after_replica_restart_and_rejects_replay() -> Result<()> {
    let Some(db) = TestDb::new().await? else {
        return Ok(());
    };
    let (admission, signing, kid) = test_admission_context()?;
    let token = issue_zero_token(&signing, &kid)?;
    let router_a = opaque_router(auth_state(), admission.clone(), db.pool.clone());
    let email = "shared-exchange@example.com";
    let password = test_password();
    run_opaque_signup(&router_a, email, &password, &token, [17; 32]).await?;
    sqlx::query("UPDATE users SET status='active',email_verified_at=NOW() WHERE email=$1")
        .bind(email)
        .execute(&db.pool)
        .await?;
    let proof = proof(&router_a, email, &password, &token, None).await?;
    drop(router_a);
    let router_b = opaque_router(auth_state(), admission, db.pool.clone());
    let response = post(
        &router_b,
        "/v1/auth/opaque/login/finish",
        proof.payload(),
        &token,
        None,
    )
    .await?;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert!(response.headers().contains_key(SET_COOKIE));
    let response = post(
        &router_b,
        "/v1/auth/opaque/login/finish",
        proof.payload(),
        &token,
        None,
    )
    .await?;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM user_sessions")
        .fetch_one(&db.pool)
        .await?;
    assert_eq!(count, 1);
    Ok(())
}

/// Real registered account, two stale full sessions and independently constructed replicas.
struct Fixture {
    db: TestDb,
    a: Router,
    b: Router,
    admission: Arc<crate::api::handlers::AdmissionVerifier>,
    zero: String,
    password: Vec<u8>,
    user: Uuid,
    first: String,
    second: String,
}

const EMAIL: &str = "opaque-shared@test.example";

/// Release the adversarial lock even when an unbounded handler misses its deadline.
async fn finish_under_lock(
    f: &Fixture,
    proof: &Proof,
    cookie: Option<&str>,
    blocker: sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<Response> {
    let path = if cookie.is_some() {
        "/v1/auth/opaque/reauth/finish"
    } else {
        "/v1/auth/opaque/login/finish"
    };
    let result = tokio::time::timeout(
        Duration::from_secs(2),
        post(&f.b, path, proof.payload(), &f.zero, cookie),
    )
    .await;
    blocker.rollback().await?;
    result.context("OPAQUE finish remained blocked beyond the configured deadline")?
}

/// A stalled writer cannot monopolize every replica's start connections indefinitely.
#[tokio::test]
async fn opaque_exchange_capacity_lock_wait_is_bounded() -> Result<()> {
    let Some(f) = Fixture::new(Duration::from_secs(300), 100).await? else {
        return Ok(());
    };
    let mut blocker = f.db.pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended('permesi:opaque-exchanges:v1',0))")
        .execute(&mut *blocker)
        .await?;
    let client = ClientLogin::<OpaqueSuite>::start(&mut opaque_rand_core::OsRng, &f.password)?;
    let result = tokio::time::timeout(
        Duration::from_secs(2),
        post(
            &f.a,
            "/v1/auth/opaque/login/start",
            json!({"email":EMAIL,"credential_request":STANDARD.encode(client.message.serialize())}),
            &f.zero,
            None,
        ),
    )
    .await;
    blocker.rollback().await?;
    let response =
        result.context("OPAQUE start remained blocked beyond the configured deadline")??;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(!response.headers().contains_key(SET_COOKIE));
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM opaque_exchanges")
            .fetch_one(&f.db.pool)
            .await?,
        0
    );
    assert_eq!(f.proof(None).await?.email, EMAIL);
    Ok(())
}

/// A blocked consume fails closed without deleting state; a later valid retry can finish.
#[tokio::test]
async fn opaque_exchange_consumption_lock_wait_is_bounded() -> Result<()> {
    let Some(f) = Fixture::new(Duration::from_secs(300), 100).await? else {
        return Ok(());
    };
    let proof = f.proof(None).await?;
    let mut blocker = f.db.pool.begin().await?;
    sqlx::query("SELECT id_hash FROM opaque_exchanges WHERE id_hash=$1 FOR UPDATE")
        .bind(hash_id(proof.id).as_slice())
        .execute(&mut *blocker)
        .await?;
    let response = finish_under_lock(&f, &proof, None, blocker).await?;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(!response.headers().contains_key(SET_COOKIE));
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM opaque_exchanges")
            .fetch_one(&f.db.pool)
            .await?,
        1
    );
    assert_eq!(
        post(
            &f.b,
            "/v1/auth/opaque/login/finish",
            proof.payload(),
            &f.zero,
            None
        )
        .await?
        .status(),
        StatusCode::NO_CONTENT
    );
    Ok(())
}

/// Current-credential locks bound login/elevation waits and never grant authority on timeout.
#[tokio::test]
async fn opaque_exchange_identity_lock_wait_is_bounded() -> Result<()> {
    let Some(f) = Fixture::new(Duration::from_secs(300), 100).await? else {
        return Ok(());
    };
    let before = f.time(&f.first).await?;
    for cookie in [None, Some(f.first.as_str())] {
        let proof = f.proof(cookie).await?;
        let mut blocker = f.db.pool.begin().await?;
        sqlx::query("SELECT id FROM users WHERE id=$1 FOR UPDATE")
            .bind(f.user)
            .execute(&mut *blocker)
            .await?;
        let response = finish_under_lock(&f, &proof, cookie, blocker).await?;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(!response.headers().contains_key(SET_COOKIE));
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM opaque_exchanges")
                .fetch_one(&f.db.pool)
                .await?,
            0
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM user_sessions")
                .fetch_one(&f.db.pool)
                .await?,
            2
        );
        assert_eq!(f.time(&f.first).await?, before);
        let path = if cookie.is_some() {
            "/v1/auth/opaque/reauth/finish"
        } else {
            "/v1/auth/opaque/login/finish"
        };
        assert_eq!(
            post(&f.b, path, proof.payload(), &f.zero, cookie)
                .await?
                .status(),
            StatusCode::UNAUTHORIZED
        );
    }
    Ok(())
}

/// Scheduled maintenance must remove expired exchanges while preserving a real live proof.
#[tokio::test]
async fn opaque_exchange_maintenance_prunes_only_expired_state() -> Result<()> {
    let Some(f) = Fixture::new(Duration::from_secs(300), 100).await? else {
        return Ok(());
    };
    let expired = f.proof(None).await?;
    let live = f.proof(None).await?;
    // Privileged fixture clock adjustment isolates maintenance; real TTL expiry is tested separately.
    sqlx::query("UPDATE opaque_exchanges SET created_at=clock_timestamp()-INTERVAL '2 seconds',expires_at=clock_timestamp()-INTERVAL '1 second' WHERE id_hash=$1")
        .bind(hash_id(expired.id).as_slice()).execute(&f.db.pool).await?;
    sqlx::query("SELECT cleanup_expired_tokens()")
        .execute(&f.db.pool)
        .await?;
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM opaque_exchanges")
            .fetch_one(&f.db.pool)
            .await?,
        1
    );
    assert!(
        !sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM opaque_exchanges WHERE id_hash=$1)"
        )
        .bind(hash_id(expired.id).as_slice())
        .fetch_one(&f.db.pool)
        .await?
    );
    assert_eq!(
        post(
            &f.b,
            "/v1/auth/opaque/login/finish",
            live.payload(),
            &f.zero,
            None
        )
        .await?
        .status(),
        StatusCode::NO_CONTENT
    );
    Ok(())
}

/// Syntax errors before state lookup cannot destroy a valid pending proof or extend its lifetime.
#[tokio::test]
async fn opaque_exchange_malformed_finalization_preserves_pending_proof() -> Result<()> {
    let Some(f) = Fixture::new(Duration::from_secs(300), 100).await? else {
        return Ok(());
    };
    for cookie in [None, Some(f.first.as_str())] {
        let path = if cookie.is_some() {
            "/v1/auth/opaque/reauth/finish"
        } else {
            "/v1/auth/opaque/login/finish"
        };
        let proof = f.proof(cookie).await?;
        let expires: chrono::DateTime<chrono::Utc> =
            sqlx::query_scalar("SELECT expires_at FROM opaque_exchanges WHERE id_hash=$1")
                .bind(hash_id(proof.id).as_slice())
                .fetch_one(&f.db.pool)
                .await?;
        for malformed in ["!".to_owned(), STANDARD.encode([0; 1])] {
            let mut payload = proof.payload();
            *payload
                .get_mut("credential_finalization")
                .context("finalization field")? = json!(malformed);
            let response = post(&f.b, path, payload, &f.zero, cookie).await?;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            assert!(!response.headers().contains_key(SET_COOKIE));
            assert_eq!(
                sqlx::query_scalar::<_, chrono::DateTime<chrono::Utc>>(
                    "SELECT expires_at FROM opaque_exchanges WHERE id_hash=$1"
                )
                .bind(hash_id(proof.id).as_slice())
                .fetch_one(&f.db.pool)
                .await?,
                expires
            );
        }
        assert_eq!(
            post(&f.b, path, proof.payload(), &f.zero, cookie)
                .await?
                .status(),
            StatusCode::NO_CONTENT
        );
    }
    Ok(())
}

/// Operator overrides govern real statement execution and never escape their transaction.
#[tokio::test]
async fn opaque_exchange_uses_configured_deadline_and_restores_connection_policy() -> Result<()> {
    let Some(f) = Fixture::new(Duration::from_secs(300), 100).await? else {
        return Ok(());
    };
    let single = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(f.db.pool.connect_options().as_ref().clone())
        .await?;
    let settings = "SELECT current_setting('lock_timeout'), current_setting('statement_timeout')";
    let original: (String, String) = sqlx::query_as(settings).fetch_one(&single).await?;
    let record: Vec<u8> =
        sqlx::query_scalar("SELECT opaque_registration_record FROM users WHERE id=$1")
            .bind(f.user)
            .fetch_one(&f.db.pool)
            .await?;
    let identity = ExchangeIdentity {
        user_id: f.user,
        credential_hash: Sha256::digest(record).into(),
    };
    let mut guard = lock_identity(&single, &identity, 5000)
        .await?
        .context("verified identity")?;
    let configured: (String, String) = sqlx::query_as(settings).fetch_one(&mut *guard).await?;
    assert_eq!(configured, ("5s".to_owned(), "5s".to_owned()));
    sqlx::query("SELECT pg_sleep(1.5)")
        .execute(&mut *guard)
        .await?;
    guard.commit().await?;
    let restored: (String, String) = sqlx::query_as(settings).fetch_one(&single).await?;
    assert_eq!(restored, original);
    single.close().await;
    Ok(())
}

/// Typed adversarial database mutations must not retarget a valid client proof.
#[derive(Clone, Copy)]
enum MetadataTamper {
    Purpose,
    Session,
    Identity,
    User,
    Reference,
    Issuance,
    Credential,
}

impl MetadataTamper {
    /// Use a genuine full session that would match the malicious metadata without AEAD.
    fn cookie(self, f: &Fixture) -> Option<&str> {
        match self {
            Self::Purpose => Some(&f.first),
            Self::Session => Some(&f.second),
            _ => None,
        }
    }

    /// Privileged fixture writes test the cryptographic binding beyond normal runtime-role restrictions.
    async fn apply(
        self,
        f: &Fixture,
        proof: &mut Proof,
        other: Uuid,
        other_record: &[u8],
    ) -> Result<()> {
        let old = hash_id(proof.id);
        match self {
            Self::Purpose => {
                sqlx::query(
                    "UPDATE opaque_exchanges SET purpose='reauth',session_hash=$1 WHERE id_hash=$2",
                )
                .bind(hash_session_token(&f.first))
                .bind(old.as_slice())
                .execute(&f.db.pool)
                .await?;
            }
            Self::Session => {
                sqlx::query("UPDATE opaque_exchanges SET session_hash=$1 WHERE id_hash=$2")
                    .bind(hash_session_token(&f.second))
                    .bind(old.as_slice())
                    .execute(&f.db.pool)
                    .await?;
            }
            Self::Identity => {
                sqlx::query(
                    "UPDATE opaque_exchanges SET user_id=$1,credential_hash=$2 WHERE id_hash=$3",
                )
                .bind(other)
                .bind(Sha256::digest(other_record).as_slice())
                .bind(old.as_slice())
                .execute(&f.db.pool)
                .await?;
            }
            Self::User => {
                // Duplicate credential bytes only in this privileged fixture: the current-record
                // check must not mask a missing authenticated user ID in the encrypted exchange.
                sqlx::query("UPDATE users AS target SET opaque_registration_record=source.opaque_registration_record FROM users AS source WHERE target.id=$1 AND source.id=$2")
                    .bind(other).bind(f.user).execute(&f.db.pool).await?;
                sqlx::query("UPDATE opaque_exchanges SET user_id=$1 WHERE id_hash=$2")
                    .bind(other)
                    .bind(old.as_slice())
                    .execute(&f.db.pool)
                    .await?;
            }
            Self::Reference => {
                proof.id = Uuid::new_v4();
                sqlx::query("UPDATE opaque_exchanges SET id_hash=$1 WHERE id_hash=$2")
                    .bind(hash_id(proof.id).as_slice())
                    .bind(old.as_slice())
                    .execute(&f.db.pool)
                    .await?;
            }
            Self::Issuance => {
                sqlx::query("UPDATE opaque_exchanges SET created_at=created_at-INTERVAL '1 second' WHERE id_hash=$1").bind(old.as_slice()).execute(&f.db.pool).await?;
            }
            Self::Credential => {
                let replacement = opaque_test_record()?;
                assert!(
                    super::super::storage::rotate_password_and_clear_sessions(
                        &f.db.pool,
                        f.user,
                        &replacement
                    )
                    .await?
                );
                sqlx::query("UPDATE opaque_exchanges SET credential_hash=$1 WHERE id_hash=$2")
                    .bind(Sha256::digest(replacement).as_slice())
                    .bind(old.as_slice())
                    .execute(&f.db.pool)
                    .await?;
            }
        }
        Ok(())
    }
}

/// AEAD rejects identity/revision, purpose/session, reference and issuance retargeting.
#[tokio::test]
async fn opaque_exchange_authenticates_every_authority_metadata_binding() -> Result<()> {
    let Some(f) = Fixture::new(Duration::from_secs(300), 100).await? else {
        return Ok(());
    };
    let other_email = "other-binding@test.example";
    run_opaque_signup(&f.a, other_email, &f.password, &f.zero, [37; 32]).await?;
    sqlx::query("UPDATE users SET status='active',email_verified_at=NOW() WHERE email=$1")
        .bind(other_email)
        .execute(&f.db.pool)
        .await?;
    let other = lookup_user_id(&f.db.pool, other_email).await?;
    let other_record: Vec<u8> =
        sqlx::query_scalar("SELECT opaque_registration_record FROM users WHERE id=$1")
            .bind(other)
            .fetch_one(&f.db.pool)
            .await?;
    let valid = f.proof(None).await?;
    assert_eq!(
        post(
            &f.b,
            "/v1/auth/opaque/login/finish",
            valid.payload(),
            &f.zero,
            None
        )
        .await?
        .status(),
        StatusCode::NO_CONTENT
    );
    let original_time = f.time(&f.second).await?;
    for tamper in [
        MetadataTamper::Purpose,
        MetadataTamper::Session,
        MetadataTamper::Identity,
        MetadataTamper::Reference,
        MetadataTamper::Issuance,
        MetadataTamper::User,
        MetadataTamper::Credential,
    ] {
        let mut proof = f
            .proof(if matches!(tamper, MetadataTamper::Session) {
                Some(&f.first)
            } else {
                None
            })
            .await?;
        tamper.apply(&f, &mut proof, other, &other_record).await?;
        let cookie = tamper.cookie(&f);
        let path = if cookie.is_some() {
            "/v1/auth/opaque/reauth/finish"
        } else {
            "/v1/auth/opaque/login/finish"
        };
        let response = post(&f.b, path, proof.payload(), &f.zero, cookie).await?;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(!response.headers().contains_key(SET_COOKIE));
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM opaque_exchanges")
                .fetch_one(&f.db.pool)
                .await?,
            0
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM user_sessions WHERE user_id=$1")
                .bind(other)
                .fetch_one(&f.db.pool)
                .await?,
            0
        );
        if !matches!(tamper, MetadataTamper::Credential) {
            assert_eq!(f.time(&f.second).await?, original_time);
        }
    }
    Ok(())
}

/// Keep test configuration consistent while deliberately constructing independent setup objects.
fn state_with(seed: [u8; 32], server: &str, ttl: Duration, maximum: usize) -> Arc<AuthState> {
    Arc::new(AuthState::new(
        auth_config(),
        OpaqueState::from_seed(seed, server.to_owned(), ttl, maximum),
        Arc::new(RateLimiter::noop()),
        MfaConfig::new(),
    ))
}

impl Fixture {
    /// Register through production handlers; seed fixtures never bypass proof validation.
    async fn new(ttl: Duration, maximum: usize) -> Result<Option<Self>> {
        let Some(db) = TestDb::new().await? else {
            return Ok(None);
        };
        let (admission, signing, kid) = test_admission_context()?;
        let zero = issue_zero_token(&signing, &kid)?;
        let a = opaque_router(
            state_with([0; 32], "api.permesi.dev", ttl, maximum),
            admission.clone(),
            db.pool.clone(),
        );
        let b = opaque_router(
            state_with([0; 32], "api.permesi.dev", ttl, maximum),
            admission.clone(),
            db.pool.clone(),
        );
        let password = test_password();
        run_opaque_signup(&a, EMAIL, &password, &zero, [13; 32]).await?;
        sqlx::query("UPDATE users SET status='active',email_verified_at=NOW() WHERE email=$1")
            .bind(EMAIL)
            .execute(&db.pool)
            .await?;
        let user = lookup_user_id(&db.pool, EMAIL).await?;
        let first = generate_session_token()?;
        let second = generate_session_token()?;
        for token in [&first, &second] {
            sqlx::query("INSERT INTO user_sessions (user_id,session_hash,created_at,auth_time,expires_at) VALUES ($1,$2,NOW()-INTERVAL '20 minutes',NOW()-INTERVAL '20 minutes',NOW()+INTERVAL '1 hour')").bind(user).bind(hash_session_token(token)).execute(&db.pool).await?;
        }
        Ok(Some(Self {
            db,
            a,
            b,
            admission,
            zero,
            password,
            user,
            first,
            second,
        }))
    }

    /// Run the client against one replica without moving server state in the fixture.
    async fn proof(&self, cookie: Option<&str>) -> Result<Proof> {
        proof(&self.a, EMAIL, &self.password, &self.zero, cookie).await
    }

    /// Session timestamps establish that rejected or foreign proofs cannot elevate any session.
    async fn time(&self, token: &str) -> Result<chrono::DateTime<chrono::Utc>> {
        Ok(
            sqlx::query_scalar("SELECT auth_time FROM user_sessions WHERE session_hash=$1")
                .bind(hash_session_token(token))
                .fetch_one(&self.db.pool)
                .await?,
        )
    }
}

/// Build an independent finishing replica with server-selected MFA policy.
fn replica_with_mfa(f: &Fixture, required: bool) -> Router {
    opaque_router(
        Arc::new(AuthState::new(
            auth_config(),
            OpaqueState::from_seed(
                [0; 32],
                "api.permesi.dev".into(),
                Duration::from_secs(300),
                100,
            ),
            Arc::new(RateLimiter::noop()),
            MfaConfig::new().with_required(required),
        )),
        f.admission.clone(),
        f.db.pool.clone(),
    )
}

/// Shared password proofs retain bootstrap/challenge gating and required-MFA revocation.
#[tokio::test]
async fn opaque_login_cross_replica_preserves_mfa_session_authority() -> Result<()> {
    for enabled in [false, true] {
        let Some(f) = Fixture::new(Duration::from_secs(300), 100).await? else {
            return Ok(());
        };
        if enabled {
            sqlx::query("INSERT INTO user_mfa_state (user_id,state) VALUES ($1,'enabled')")
                .bind(f.user)
                .execute(&f.db.pool)
                .await?;
        }
        let proof = f.proof(None).await?;
        let replica = replica_with_mfa(&f, true);
        let response = post(
            &replica,
            "/v1/auth/opaque/login/finish",
            proof.payload(),
            &f.zero,
            None,
        )
        .await?;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let cookie = response
            .headers()
            .get(SET_COOKIE)
            .context("scoped session cookie")?
            .to_str()?;
        let cookie = extract_session_cookie_token(cookie).context("scoped session token")?;
        let expected = if enabled {
            SessionKind::MfaChallenge
        } else {
            SessionKind::MfaBootstrap
        };
        assert_eq!(SessionKind::from_token(&cookie), expected);
        let hash = hash_session_token(&cookie);
        let record = if enabled {
            super::super::storage::lookup_mfa_challenge_session(&f.db.pool, &hash).await?
        } else {
            super::super::storage::lookup_mfa_bootstrap_session(&f.db.pool, &hash).await?
        }
        .context("persisted scoped session")?;
        assert_eq!(record.kind, expected);
        assert_eq!(record.user_id, f.user);
        assert!(
            super::super::storage::lookup_full_session(&f.db.pool, &hash)
                .await?
                .is_none()
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM user_sessions")
                .fetch_one(&f.db.pool)
                .await?,
            if enabled { 2 } else { 0 }
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM user_mfa_bootstrap_sessions")
                .fetch_one(&f.db.pool)
                .await?,
            i64::from(!enabled)
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM user_mfa_challenge_sessions")
                .fetch_one(&f.db.pool)
                .await?,
            i64::from(enabled)
        );
        assert_eq!(
            post(
                &replica,
                "/v1/auth/opaque/login/finish",
                proof.payload(),
                &f.zero,
                None
            )
            .await?
            .status(),
            StatusCode::UNAUTHORIZED
        );
    }
    Ok(())
}

/// An issuance failure rolls back full-session revocation and never discloses a bootstrap cookie.
#[tokio::test]
async fn opaque_login_mfa_issuance_failure_rolls_back_session_changes() -> Result<()> {
    let Some(f) = Fixture::new(Duration::from_secs(300), 100).await? else {
        return Ok(());
    };
    let proof = f.proof(None).await?;
    sqlx::query("CREATE FUNCTION reject_test_bootstrap() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'test-only issuance failure'; END $$")
        .execute(&f.db.pool).await?;
    sqlx::query("CREATE TRIGGER reject_test_bootstrap BEFORE INSERT ON user_mfa_bootstrap_sessions FOR EACH ROW EXECUTE FUNCTION reject_test_bootstrap()")
        .execute(&f.db.pool).await?;
    let replica = replica_with_mfa(&f, true);
    let response = post(
        &replica,
        "/v1/auth/opaque/login/finish",
        proof.payload(),
        &f.zero,
        None,
    )
    .await?;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(!response.headers().contains_key(SET_COOKIE));
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM user_sessions")
            .fetch_one(&f.db.pool)
            .await?,
        2
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM user_mfa_bootstrap_sessions")
            .fetch_one(&f.db.pool)
            .await?,
        0
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM opaque_exchanges")
            .fetch_one(&f.db.pool)
            .await?,
        0
    );
    assert_eq!(
        post(
            &replica,
            "/v1/auth/opaque/login/finish",
            proof.payload(),
            &f.zero,
            None
        )
        .await?
        .status(),
        StatusCode::UNAUTHORIZED
    );
    Ok(())
}

/// Two concurrent replicas can create only one session from one client finalization.
#[tokio::test]
async fn opaque_login_concurrent_finish_has_one_winner() -> Result<()> {
    let Some(f) = Fixture::new(Duration::from_secs(300), 100).await? else {
        return Ok(());
    };
    let proof = f.proof(None).await?;
    let (a, b) = tokio::join!(
        post(
            &f.a,
            "/v1/auth/opaque/login/finish",
            proof.payload(),
            &f.zero,
            None
        ),
        post(
            &f.b,
            "/v1/auth/opaque/login/finish",
            proof.payload(),
            &f.zero,
            None
        )
    );
    let mut statuses = [a?.status(), b?.status()];
    statuses.sort();
    assert_eq!(statuses, [StatusCode::NO_CONTENT, StatusCode::UNAUTHORIZED]);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM user_sessions")
            .fetch_one(&f.db.pool)
            .await?,
        3
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM opaque_exchanges")
            .fetch_one(&f.db.pool)
            .await?,
        0
    );
    Ok(())
}

/// Reauthentication on B updates only the full session verified at start on A.
#[tokio::test]
async fn opaque_reauth_cross_replica_is_bound_to_original_session() -> Result<()> {
    let Some(f) = Fixture::new(Duration::from_secs(300), 100).await? else {
        return Ok(());
    };
    let before = f.time(&f.first).await?;
    let other = f.time(&f.second).await?;
    let proof = f.proof(Some(&f.first)).await?;
    assert_eq!(
        post(
            &f.b,
            "/v1/auth/opaque/reauth/finish",
            proof.payload(),
            &f.zero,
            Some(&f.first)
        )
        .await?
        .status(),
        StatusCode::NO_CONTENT
    );
    assert!(f.time(&f.first).await? > before);
    assert_eq!(f.time(&f.second).await?, other);
    assert_eq!(
        post(
            &f.a,
            "/v1/auth/opaque/reauth/finish",
            proof.payload(),
            &f.zero,
            Some(&f.first)
        )
        .await?
        .status(),
        StatusCode::UNAUTHORIZED
    );
    Ok(())
}

/// Knowing a user's other full-session cookie cannot move an elevation proof to that session.
#[tokio::test]
async fn opaque_reauth_rejects_another_session_of_the_same_user() -> Result<()> {
    let Some(f) = Fixture::new(Duration::from_secs(300), 100).await? else {
        return Ok(());
    };
    let first = f.time(&f.first).await?;
    let second = f.time(&f.second).await?;
    let proof = f.proof(Some(&f.first)).await?;
    assert_eq!(
        post(
            &f.b,
            "/v1/auth/opaque/reauth/finish",
            proof.payload(),
            &f.zero,
            Some(&f.second)
        )
        .await?
        .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        post(
            &f.a,
            "/v1/auth/opaque/reauth/finish",
            proof.payload(),
            &f.zero,
            Some(&f.first)
        )
        .await?
        .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(f.time(&f.first).await?, first);
    assert_eq!(f.time(&f.second).await?, second);
    Ok(())
}

/// Login and session-elevation transcripts cannot be exchanged between endpoint purposes.
#[tokio::test]
async fn opaque_exchange_rejects_cross_purpose_reuse() -> Result<()> {
    let Some(f) = Fixture::new(Duration::from_secs(300), 100).await? else {
        return Ok(());
    };
    let proof = f.proof(None).await?;
    assert_eq!(
        post(
            &f.b,
            "/v1/auth/opaque/reauth/finish",
            proof.payload(),
            &f.zero,
            Some(&f.first)
        )
        .await?
        .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        post(
            &f.a,
            "/v1/auth/opaque/login/finish",
            proof.payload(),
            &f.zero,
            None
        )
        .await?
        .status(),
        StatusCode::UNAUTHORIZED
    );
    let proof = f.proof(Some(&f.first)).await?;
    assert_eq!(
        post(
            &f.b,
            "/v1/auth/opaque/login/finish",
            proof.payload(),
            &f.zero,
            None
        )
        .await?
        .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        post(
            &f.a,
            "/v1/auth/opaque/reauth/finish",
            proof.payload(),
            &f.zero,
            Some(&f.first)
        )
        .await?
        .status(),
        StatusCode::UNAUTHORIZED
    );
    Ok(())
}

/// A valid proof cannot bypass database time after its issuing replica disappears.
#[tokio::test]
async fn opaque_exchange_real_ttl_expiration_rejects_finish() -> Result<()> {
    let Some(f) = Fixture::new(Duration::from_secs(2), 100).await? else {
        return Ok(());
    };
    let proof = f.proof(None).await?;
    tokio::time::sleep(Duration::from_secs(3)).await;
    let response = post(
        &f.b,
        "/v1/auth/opaque/login/finish",
        proof.payload(),
        &f.zero,
        None,
    )
    .await?;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(!response.headers().contains_key(SET_COOKIE));
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM opaque_exchanges")
            .fetch_one(&f.db.pool)
            .await?,
        0
    );
    Ok(())
}

/// Credential revisions and active-user state are checked again before authority is issued.
#[tokio::test]
async fn opaque_exchange_rejects_password_rotation_and_disabled_user() -> Result<()> {
    let Some(f) = Fixture::new(Duration::from_secs(300), 100).await? else {
        return Ok(());
    };
    let proof = f.proof(None).await?;
    sqlx::query("UPDATE users SET status='disabled' WHERE id=$1")
        .bind(f.user)
        .execute(&f.db.pool)
        .await?;
    assert_eq!(
        post(
            &f.b,
            "/v1/auth/opaque/login/finish",
            proof.payload(),
            &f.zero,
            None
        )
        .await?
        .status(),
        StatusCode::UNAUTHORIZED
    );
    sqlx::query("UPDATE users SET status='active' WHERE id=$1")
        .bind(f.user)
        .execute(&f.db.pool)
        .await?;
    let proof = f.proof(None).await?;
    super::super::storage::rotate_password_and_clear_sessions(
        &f.db.pool,
        f.user,
        &opaque_test_record()?,
    )
    .await?;
    assert_eq!(
        post(
            &f.b,
            "/v1/auth/opaque/login/finish",
            proof.payload(),
            &f.zero,
            None
        )
        .await?
        .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM user_sessions")
            .fetch_one(&f.db.pool)
            .await?,
        0
    );
    Ok(())
}

/// The same database row cannot authenticate under another seed or server identifier.
#[tokio::test]
async fn opaque_exchange_rejects_wrong_seed_or_server_id() -> Result<()> {
    let Some(f) = Fixture::new(Duration::from_secs(300), 100).await? else {
        return Ok(());
    };
    for (seed, server) in [
        ([1; 32], "api.permesi.dev"),
        ([0; 32], "another.permesi.dev"),
    ] {
        let proof = f.proof(None).await?;
        let wrong = opaque_router(
            state_with(seed, server, Duration::from_secs(300), 100),
            f.admission.clone(),
            f.db.pool.clone(),
        );
        assert_eq!(
            post(
                &wrong,
                "/v1/auth/opaque/login/finish",
                proof.payload(),
                &f.zero,
                None
            )
            .await?
            .status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            post(
                &f.a,
                "/v1/auth/opaque/login/finish",
                proof.payload(),
                &f.zero,
                None
            )
            .await?
            .status(),
            StatusCode::UNAUTHORIZED
        );
    }
    Ok(())
}

/// Changing either ciphertext or the authenticated database metadata fails closed.
#[tokio::test]
async fn opaque_exchange_rejects_ciphertext_and_expiry_tampering() -> Result<()> {
    let Some(f) = Fixture::new(Duration::from_secs(300), 100).await? else {
        return Ok(());
    };
    for query in [
        "UPDATE opaque_exchanges SET sealed_state=set_byte(sealed_state,12,get_byte(sealed_state,12)#1) WHERE id_hash=$1",
        "UPDATE opaque_exchanges SET expires_at=expires_at+INTERVAL '1 second' WHERE id_hash=$1",
    ] {
        let proof = f.proof(None).await?;
        sqlx::query(query)
            .bind(hash_id(proof.id).as_slice())
            .execute(&f.db.pool)
            .await?;
        assert_eq!(
            post(
                &f.b,
                "/v1/auth/opaque/login/finish",
                proof.payload(),
                &f.zero,
                None
            )
            .await?
            .status(),
            StatusCode::UNAUTHORIZED
        );
    }
    Ok(())
}

/// Shared bounded capacity replaces the old per-process cache limit and safely reclaims expiry.
#[tokio::test]
async fn opaque_state_enforces_pending_login_capacity_across_replicas() -> Result<()> {
    let Some(f) = Fixture::new(Duration::from_secs(1), 1).await? else {
        return Ok(());
    };
    let mut rng = opaque_rand_core::OsRng;
    let first = ClientLogin::<OpaqueSuite>::start(&mut rng, b"unknown password")?;
    let second = ClientLogin::<OpaqueSuite>::start(&mut rng, b"unknown password")?;
    let (a, b) = tokio::join!(
        post(
            &f.a,
            "/v1/auth/opaque/login/start",
            json!({"email":"absent@example.com","credential_request":STANDARD.encode(first.message.serialize())}),
            &f.zero,
            None
        ),
        post(
            &f.b,
            "/v1/auth/opaque/login/start",
            json!({"email":"absent@example.com","credential_request":STANDARD.encode(second.message.serialize())}),
            &f.zero,
            None
        )
    );
    let mut statuses = [a?.status(), b?.status()];
    statuses.sort();
    assert_eq!(statuses, [StatusCode::OK, StatusCode::TOO_MANY_REQUESTS]);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM opaque_exchanges")
            .fetch_one(&f.db.pool)
            .await?,
        1
    );
    tokio::time::sleep(Duration::from_millis(1200)).await;
    let next = ClientLogin::<OpaqueSuite>::start(&mut rng, b"unknown password")?;
    assert_eq!(post(&f.b,"/v1/auth/opaque/login/start",json!({"email":"absent@example.com","credential_request":STANDARD.encode(next.message.serialize())}),&f.zero,None).await?.status(),StatusCode::OK);
    Ok(())
}

/// Fair unknown-account admission and reserved reauthentication capacity are shared across replicas.
#[tokio::test]
async fn opaque_pending_subject_quotas_preserve_other_accounts_and_reauthentication() -> Result<()>
{
    let Some(f) = Fixture::new(Duration::from_secs(300), 100).await? else {
        return Ok(());
    };
    let mut policy = super::super::operations::OperationsConfig::defaults();
    policy.subject_limit = 1;
    policy.login_limit = 2;
    policy.reauth_limit = 1;
    let config = auth_config().with_operations(policy);
    let a = opaque_router(
        Arc::new(AuthState::new(
            config.clone(),
            OpaqueState::from_seed(
                [0; 32],
                "api.permesi.dev".into(),
                Duration::from_secs(300),
                100,
            ),
            Arc::new(RateLimiter::noop()),
            MfaConfig::new(),
        )),
        f.admission.clone(),
        f.db.pool.clone(),
    );
    let b = opaque_router(
        Arc::new(AuthState::new(
            config,
            OpaqueState::from_seed(
                [0; 32],
                "api.permesi.dev".into(),
                Duration::from_secs(300),
                100,
            ),
            Arc::new(RateLimiter::noop()),
            MfaConfig::new(),
        )),
        f.admission.clone(),
        f.db.pool.clone(),
    );
    for (router, email, expected) in [
        (&a, "absent@example.com", StatusCode::OK),
        (&b, "absent@example.com", StatusCode::TOO_MANY_REQUESTS),
        (&b, "another@example.com", StatusCode::OK),
        (&a, "third@example.com", StatusCode::TOO_MANY_REQUESTS),
    ] {
        let client = ClientLogin::<OpaqueSuite>::start(&mut opaque_rand_core::OsRng, b"unknown")?;
        assert_eq!(post(router,"/v1/auth/opaque/login/start",json!({"email":email,"credential_request":STANDARD.encode(client.message.serialize())}),&f.zero,None).await?.status(),expected);
    }
    proof(&b, EMAIL, &f.password, &f.zero, Some(&f.first)).await?;
    let client = ClientLogin::<OpaqueSuite>::start(&mut opaque_rand_core::OsRng, &f.password)?;
    assert_eq!(
        post(
            &a,
            "/v1/auth/opaque/reauth/start",
            json!({"credential_request":STANDARD.encode(client.message.serialize())}),
            &f.zero,
            Some(&f.second)
        )
        .await?
        .status(),
        StatusCode::TOO_MANY_REQUESTS
    );
    let rows: Vec<(String, Vec<u8>)> =
        sqlx::query_as("SELECT purpose,subject_tag FROM opaque_exchanges")
            .fetch_all(&f.db.pool)
            .await?;
    assert_eq!(rows.len(), 3);
    assert!(
        rows.iter()
            .all(|(_, tag)| tag.len() == 32
                && tag != Sha256::digest(b"absent@example.com").as_slice())
    );
    Ok(())
}

/// Wait until both competing starts reach a database lock, before releasing the insertion gate.
async fn capacity_requests_reach_gate(pool: &PgPool) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let blocked: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM pg_stat_activity WHERE datname=current_database() AND cardinality(pg_blocking_pids(pid))>0 AND (query LIKE 'INSERT INTO opaque_exchanges %' OR query LIKE '%permesi:opaque-exchanges:v1%')").fetch_one(pool).await?;
            if blocked >= 2 { return Ok::<_,anyhow::Error>(()); }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await.context("both authorization-state reservations must reach the database gate")?
}

/// Hold insertion after the capacity count so removing serialization deterministically overfills it.
#[tokio::test]
async fn opaque_capacity_reservation_serializes_check_and_insert_across_replicas() -> Result<()> {
    let Some(f) = Fixture::new(Duration::from_secs(300), 1).await? else {
        return Ok(());
    };
    // This private trigger is a test scheduling barrier, never a production capacity mechanism.
    sqlx::raw_sql("CREATE FUNCTION test_opaque_insertion_gate() RETURNS TRIGGER LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock_shared(911562017401); RETURN NEW; END; $$; CREATE TRIGGER test_opaque_insertion_gate BEFORE INSERT ON opaque_exchanges FOR EACH ROW EXECUTE FUNCTION test_opaque_insertion_gate();")
        .execute(&f.db.pool).await?;
    let mut blocker = f.db.pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(911562017401)")
        .execute(&mut *blocker)
        .await?;
    let mut workers = Vec::new();
    for _ in 0..2 {
        let replica = opaque_router(
            Arc::new(AuthState::new(
                auth_config().with_opaque_exchange_timeout_ms(10_000),
                OpaqueState::from_seed(
                    [0; 32],
                    "api.permesi.dev".into(),
                    Duration::from_secs(300),
                    1,
                ),
                Arc::new(RateLimiter::noop()),
                MfaConfig::new(),
            )),
            f.admission.clone(),
            f.db.pool.clone(),
        );
        let mut rng = opaque_rand_core::OsRng;
        let client = ClientLogin::<OpaqueSuite>::start(&mut rng, b"unknown password")?;
        let payload = json!({"email":"absent@example.com","credential_request":STANDARD.encode(client.message.serialize())});
        let zero = f.zero.clone();
        workers.push(tokio::spawn(async move {
            post(
                &replica,
                "/v1/auth/opaque/login/start",
                payload,
                &zero,
                None,
            )
            .await
        }));
    }
    let ready = capacity_requests_reach_gate(&f.db.pool).await;
    // Always release our scheduling lock and drain the requests before reporting a failed assertion.
    blocker.rollback().await?;
    let mut statuses = Vec::new();
    for worker in workers {
        statuses.push(
            tokio::time::timeout(Duration::from_secs(5), worker)
                .await???
                .status(),
        );
    }
    ready?;
    statuses.sort();
    assert_eq!(statuses, [StatusCode::OK, StatusCode::TOO_MANY_REQUESTS]);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM opaque_exchanges")
            .fetch_one(&f.db.pool)
            .await?,
        1
    );
    Ok(())
}

/// Storage failures cannot silently recover an exchange from a process-local fallback.
#[tokio::test]
async fn opaque_exchange_storage_outage_issues_no_session() -> Result<()> {
    let Some(f) = Fixture::new(Duration::from_secs(300), 100).await? else {
        return Ok(());
    };
    let proof = f.proof(None).await?;
    f.db.pool.close().await;
    let response = post(
        &f.b,
        "/v1/auth/opaque/login/finish",
        proof.payload(),
        &f.zero,
        None,
    )
    .await?;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(!response.headers().contains_key(SET_COOKIE));
    let body = to_bytes(response.into_body(), 1024).await?;
    assert_eq!(body.as_ref(), b"Login failed");
    Ok(())
}

/// Only a hash of the external reference and authenticated ciphertext reach PostgreSQL.
#[tokio::test]
async fn opaque_exchange_persists_no_plaintext_reference_or_transcript() -> Result<()> {
    let Some(db) = TestDb::new().await? else {
        return Ok(());
    };
    let state = OpaqueState::from_seed(
        [0; 32],
        "api.permesi.dev".to_owned(),
        Duration::from_secs(300),
        10,
    );
    let mut rng = opaque_rand_core::OsRng;
    let client = ClientLogin::<OpaqueSuite>::start(&mut rng, b"unregistered")?;
    let server = opaque_ke::ServerLogin::start(
        &mut rng,
        state.server_setup(),
        None,
        client.message,
        b"unknown@example.com",
        opaque_ke::ServerLoginParameters::default(),
    )?;
    let plaintext = server.state.serialize().to_vec();
    let id = state
        .store_login_state(
            &db.pool,
            server.state,
            None,
            ExchangePurpose::Login,
            super::super::opaque::exchange::Admission {
                subject: "test",
                policy: &super::super::operations::OperationsConfig::defaults(),
                timeout_ms: 1000,
            },
        )
        .await?
        .context("exchange persisted")?;
    let (stored_hash, ciphertext): (Vec<u8>, Vec<u8>) =
        sqlx::query_as("SELECT id_hash,sealed_state FROM opaque_exchanges")
            .fetch_one(&db.pool)
            .await?;
    assert_eq!(stored_hash, Sha256::digest(id.as_bytes()).as_slice());
    assert_ne!(stored_hash, id.as_bytes());
    assert_eq!(ciphertext.len(), plaintext.len() + 40);
    assert!(
        !ciphertext
            .windows(plaintext.len())
            .any(|value| value == plaintext)
    );
    assert!(!ciphertext.windows(16).any(|value| value == id.as_bytes()));
    let other = OpaqueState::from_seed(
        [0; 32],
        "api.permesi.dev".to_owned(),
        Duration::from_secs(300),
        10,
    );
    let opened = other
        .take_login_state(&db.pool, id, ExchangePurpose::Login, 1000)
        .await?
        .context("cross-instance decryption")?;
    assert_eq!(opened.state.serialize().as_slice(), plaintext);
    Ok(())
}

/// A well-formed wrong proof consumes the exchange; a later correct proof cannot replay it.
#[tokio::test]
async fn opaque_exchange_invalid_proof_is_single_attempt() -> Result<()> {
    let Some(f) = Fixture::new(Duration::from_secs(300), 100).await? else {
        return Ok(());
    };
    let proof = f.proof(None).await?;
    let mut wrong = proof.payload();
    *wrong
        .get_mut("credential_finalization")
        .context("proof field")? = Value::String(bogus_credential_finalization());
    assert_eq!(
        post(&f.b, "/v1/auth/opaque/login/finish", wrong, &f.zero, None)
            .await?
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        post(
            &f.a,
            "/v1/auth/opaque/login/finish",
            proof.payload(),
            &f.zero,
            None
        )
        .await?
        .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM user_sessions")
            .fetch_one(&f.db.pool)
            .await?,
        2
    );
    Ok(())
}

/// Revoking the original full session removes its pending elevation exchange by foreign key.
#[tokio::test]
async fn opaque_reauth_revoked_session_cannot_complete() -> Result<()> {
    let Some(f) = Fixture::new(Duration::from_secs(300), 100).await? else {
        return Ok(());
    };
    let other = f.time(&f.second).await?;
    let proof = f.proof(Some(&f.first)).await?;
    sqlx::query("DELETE FROM user_sessions WHERE session_hash=$1")
        .bind(hash_session_token(&f.first))
        .execute(&f.db.pool)
        .await?;
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM opaque_exchanges")
            .fetch_one(&f.db.pool)
            .await?,
        0
    );
    assert_eq!(
        post(
            &f.b,
            "/v1/auth/opaque/reauth/finish",
            proof.payload(),
            &f.zero,
            Some(&f.first)
        )
        .await?
        .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(f.time(&f.second).await?, other);
    Ok(())
}

/// The compatibility email field at finish cannot override the server-bound identity.
#[tokio::test]
async fn opaque_login_browser_email_cannot_change_bound_identity() -> Result<()> {
    let Some(f) = Fixture::new(Duration::from_secs(300), 100).await? else {
        return Ok(());
    };
    let proof = f.proof(None).await?;
    let mut payload = proof.payload();
    *payload
        .get_mut("email")
        .context("compatibility email field")? = json!("foreign@example.com");
    assert_eq!(
        post(&f.b, "/v1/auth/opaque/login/finish", payload, &f.zero, None)
            .await?
            .status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM user_sessions WHERE user_id=$1")
            .bind(f.user)
            .fetch_one(&f.db.pool)
            .await?,
        3
    );
    Ok(())
}

/// Real password rotation waits for verified issuance, then revokes the newly issued session too.
#[tokio::test]
async fn opaque_identity_lock_prevents_password_rotation_from_racing_issuance() -> Result<()> {
    let Some(f) = Fixture::new(Duration::from_secs(300), 100).await? else {
        return Ok(());
    };
    let record: Vec<u8> =
        sqlx::query_scalar("SELECT opaque_registration_record FROM users WHERE id=$1")
            .bind(f.user)
            .fetch_one(&f.db.pool)
            .await?;
    let identity = ExchangeIdentity {
        user_id: f.user,
        credential_hash: Sha256::digest(&record).into(),
    };
    let mut guard = lock_identity(&f.db.pool, &identity, 1000)
        .await?
        .context("verified identity lock")?;
    let pool = f.db.pool.clone();
    let user = f.user;
    let replacement = opaque_test_record()?;
    let worker = tokio::spawn(async move {
        super::super::storage::rotate_password_and_clear_sessions(&pool, user, &replacement).await
    });
    tokio::time::timeout(Duration::from_secs(3),async {
        loop {
            let blocked:bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND query LIKE 'UPDATE users SET opaque_registration_record = $1%WHERE id = $2%' AND cardinality(pg_blocking_pids(pid))>0)").fetch_one(&f.db.pool).await?;
            if blocked {return Ok::<_,anyhow::Error>(());}
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await.context("password rotation must block on the verified identity")??;
    let token = super::super::storage::insert_session_on(&mut guard, f.user, 3600).await?;
    guard.commit().await?;
    assert!(worker.await??);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM user_sessions WHERE session_hash=$1")
            .bind(hash_session_token(&token))
            .fetch_one(&f.db.pool)
            .await?,
        0
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM user_sessions")
            .fetch_one(&f.db.pool)
            .await?,
        0
    );
    Ok(())
}

/// Observe which authority mutation is blocked without racing the release of the issuer lock.
async fn rotation_waits_for_http_identity(pool: &PgPool) -> Result<bool> {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let blocked: (bool,bool) = sqlx::query_as("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND query LIKE 'UPDATE users SET opaque_registration_record = $1%WHERE id = $2%' AND cardinality(pg_blocking_pids(pid))>0),EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND query LIKE 'DELETE FROM user_sessions WHERE user_id = $1%' AND cardinality(pg_blocking_pids(pid))>0)").fetch_one(pool).await?;
            if blocked.0 { return Ok(true); }
            if blocked.1 { return Ok(false); }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await.context("credential rotation never reached its authority lock")?
}

/// The real finish handler holds identity until issuance commits, then rotation revokes its cookie.
#[tokio::test]
async fn opaque_login_http_issuance_retains_identity_guard_until_commit() -> Result<()> {
    let Some(f) = Fixture::new(Duration::from_secs(300), 100).await? else {
        return Ok(());
    };
    let proof = f.proof(None).await?;
    let replica = opaque_router(
        Arc::new(AuthState::new(
            auth_config().with_opaque_exchange_timeout_ms(10_000),
            OpaqueState::from_seed(
                [0; 32],
                "api.permesi.dev".into(),
                Duration::from_secs(300),
                100,
            ),
            Arc::new(RateLimiter::noop()),
            MfaConfig::new(),
        )),
        f.admission.clone(),
        f.db.pool.clone(),
    );
    let mut blocker = f.db.pool.begin().await?;
    sqlx::query("LOCK TABLE user_sessions IN ACCESS EXCLUSIVE MODE")
        .execute(&mut *blocker)
        .await?;
    let payload = proof.payload();
    let zero = f.zero.clone();
    let finish = tokio::spawn(async move {
        post(
            &replica,
            "/v1/auth/opaque/login/finish",
            payload,
            &zero,
            None,
        )
        .await
    });
    let issuance_ready = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let issuance_waiting: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND query LIKE '%INSERT INTO user_sessions%' AND cardinality(pg_blocking_pids(pid))>0)").fetch_one(&f.db.pool).await?;
            if issuance_waiting { return Ok::<_,anyhow::Error>(()); }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await;
    let pool = f.db.pool.clone();
    let user = f.user;
    let replacement = opaque_test_record()?;
    let rotate = tokio::spawn(async move {
        super::super::storage::rotate_password_and_clear_sessions(&pool, user, &replacement).await
    });
    let ordered = rotation_waits_for_http_identity(&f.db.pool).await;
    blocker.rollback().await?;
    let response = tokio::time::timeout(Duration::from_secs(5), finish).await???;
    let rotated = tokio::time::timeout(Duration::from_secs(5), rotate).await???;
    issuance_ready.context("HTTP issuance never reached the session write")??;
    assert!(
        ordered?,
        "Password rotation passed identity before the HTTP issuance committed"
    );
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert!(response.headers().contains_key(SET_COOKIE));
    assert!(rotated);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM user_sessions")
            .fetch_one(&f.db.pool)
            .await?,
        0
    );
    Ok(())
}

/// Reauthentication retains verified identity until its exact original session is elevated.
#[tokio::test]
async fn opaque_reauth_http_elevation_retains_identity_guard_until_commit() -> Result<()> {
    let Some(f) = Fixture::new(Duration::from_secs(300), 100).await? else {
        return Ok(());
    };
    let proof = f.proof(Some(&f.first)).await?;
    let replica = opaque_router(
        Arc::new(AuthState::new(
            auth_config().with_opaque_exchange_timeout_ms(10_000),
            OpaqueState::from_seed(
                [0; 32],
                "api.permesi.dev".into(),
                Duration::from_secs(300),
                100,
            ),
            Arc::new(RateLimiter::noop()),
            MfaConfig::new(),
        )),
        f.admission.clone(),
        f.db.pool.clone(),
    );
    // Unlike a table lock, this barrier permits require_auth to read the original cookie first.
    sqlx::raw_sql("CREATE FUNCTION test_opaque_elevation_gate() RETURNS TRIGGER LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock_shared(911562017402); RETURN NEW; END; $$; CREATE TRIGGER test_opaque_elevation_gate BEFORE UPDATE OF auth_time ON user_sessions FOR EACH ROW EXECUTE FUNCTION test_opaque_elevation_gate();")
        .execute(&f.db.pool).await?;
    let mut blocker = f.db.pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(911562017402)")
        .execute(&mut *blocker)
        .await?;
    let payload = proof.payload();
    let zero = f.zero.clone();
    let cookie = f.first.clone();
    let finish = tokio::spawn(async move {
        post(
            &replica,
            "/v1/auth/opaque/reauth/finish",
            payload,
            &zero,
            Some(&cookie),
        )
        .await
    });
    let elevation_ready = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let elevation_waiting: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND query LIKE '%UPDATE user_sessions%SET auth_time%' AND cardinality(pg_blocking_pids(pid))>0)").fetch_one(&f.db.pool).await?;
            if elevation_waiting { return Ok::<_,anyhow::Error>(()); }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await;
    let pool = f.db.pool.clone();
    let user = f.user;
    let replacement = opaque_test_record()?;
    let rotate = tokio::spawn(async move {
        super::super::storage::rotate_password_and_clear_sessions(&pool, user, &replacement).await
    });
    let ordered = rotation_waits_for_http_identity(&f.db.pool).await;
    blocker.rollback().await?;
    let response = tokio::time::timeout(Duration::from_secs(5), finish).await???;
    let rotated = tokio::time::timeout(Duration::from_secs(5), rotate).await???;
    elevation_ready.context("HTTP elevation never reached its original session write")??;
    assert!(
        ordered?,
        "Password rotation passed identity before HTTP elevation committed"
    );
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert!(!response.headers().contains_key(SET_COOKIE));
    assert!(rotated);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM user_sessions")
            .fetch_one(&f.db.pool)
            .await?,
        0
    );
    Ok(())
}

/// Canonical schema reapplication preserves a live sealed exchange and applies narrow role grants.
#[tokio::test]
async fn opaque_schema_reapplication_preserves_pending_exchange_and_runtime_permissions()
-> Result<()> {
    let Some(f) = Fixture::new(Duration::from_secs(300), 100).await? else {
        return Ok(());
    };
    let proof = f.proof(None).await?;
    sqlx::query("CREATE ROLE permesi_runtime")
        .execute(&f.db.pool)
        .await?;
    // Bootstrap's broad ALL grant includes PostgreSQL 17+ MAINTAIN; reapplication must narrow it.
    sqlx::query("GRANT ALL PRIVILEGES ON opaque_exchanges TO permesi_runtime")
        .execute(&f.db.pool)
        .await?;
    let mut connection = f.db.pool.acquire().await?;
    test_support::sql::execute_script(&mut connection, "02_permesi.sql", PERMESI_SCHEMA_SQL)
        .await?;
    test_support::sql::execute_script(
        &mut connection,
        "verify_permesi.sql",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../db/sql/verify_permesi.sql"
        )),
    )
    .await?;
    drop(connection);
    assert_eq!(
        post(
            &f.b,
            "/v1/auth/opaque/login/finish",
            proof.payload(),
            &f.zero,
            None
        )
        .await?
        .status(),
        StatusCode::NO_CONTENT
    );
    Ok(())
}
