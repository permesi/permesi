//! Real PostgreSQL and cryptographic authenticator proofs across independent replicas.
//! The test authenticator signs challenges with a fresh RSA key; no proof verifier is mocked.

use super::*;
use crate::webauthn::exchange::{Binding, ExchangeStore, Purpose};
use crate::webauthn::{PasskeyConfig, PasskeyService, SecurityKeyService};
use rsa::{Pkcs1v15Sign, RsaPrivateKey, traits::PublicKeyParts};
use serde_cbor_2::Value as Cbor;
use serde_json::Value;
use sha2::{Digest, Sha256};
use webauthn_rs::prelude::{DiscoverableKey, PublicKeyCredential, RegisterPublicKeyCredential};

const ORIGIN: &str = "https://example.com";

/// A minimal test-only authenticator with real RSA signatures and UV/UP assertions.
struct Authenticator {
    key: RsaPrivateKey,
    id: Vec<u8>,
    counter: u32,
}

impl Authenticator {
    fn new() -> Result<Self> {
        Ok(Self {
            key: RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048)?,
            id: Uuid::new_v4().as_bytes().to_vec(),
            counter: 0,
        })
    }

    /// Encodes browser client data without borrowing authority from the service state.
    fn client_data(challenge: &Value, kind: &str) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(
            &json!({"type":kind,"challenge":challenge.pointer("/publicKey/challenge").context("challenge field")?,"origin":ORIGIN,"crossOrigin":false}),
        )?)
    }

    fn register(&self, challenge: &impl serde::Serialize) -> Result<RegisterPublicKeyCredential> {
        let challenge = serde_json::to_value(challenge)?;
        let public = self.key.to_public_key();
        let cose = Cbor::Map(std::collections::BTreeMap::from([
            (Cbor::Integer(1), Cbor::Integer(3)),
            (Cbor::Integer(3), Cbor::Integer(-257)),
            (Cbor::Integer(-1), Cbor::Bytes(public.n().to_bytes_be())),
            (Cbor::Integer(-2), Cbor::Bytes(public.e().to_bytes_be())),
        ]));
        let mut data = Sha256::digest(b"example.com").to_vec();
        data.push(0x45); // user presence, verification, and attested credential data
        data.extend(0u32.to_be_bytes());
        data.extend([0; 16]);
        data.extend(u16::try_from(self.id.len())?.to_be_bytes());
        data.extend(&self.id);
        data.extend(serde_cbor_2::to_vec(&cose)?);
        let attest = Cbor::Map(std::collections::BTreeMap::from([
            (Cbor::Text("fmt".into()), Cbor::Text("none".into())),
            (Cbor::Text("authData".into()), Cbor::Bytes(data)),
            (
                Cbor::Text("attStmt".into()),
                Cbor::Map(std::collections::BTreeMap::new()),
            ),
        ]));
        Ok(serde_json::from_value(
            json!({"id":URL_SAFE_NO_PAD.encode(&self.id),"rawId":URL_SAFE_NO_PAD.encode(&self.id),"type":"public-key","response":{"attestationObject":URL_SAFE_NO_PAD.encode(serde_cbor_2::to_vec(&attest)?),"clientDataJSON":URL_SAFE_NO_PAD.encode(Self::client_data(&challenge,"webauthn.create")?)}}),
        )?)
    }

    fn authenticate(
        &mut self,
        challenge: &impl serde::Serialize,
        user: Uuid,
    ) -> Result<PublicKeyCredential> {
        self.counter += 1;
        let client = Self::client_data(&serde_json::to_value(challenge)?, "webauthn.get")?;
        let mut data = Sha256::digest(b"example.com").to_vec();
        data.push(0x05);
        data.extend(self.counter.to_be_bytes());
        let mut signed = data.clone();
        signed.extend(Sha256::digest(&client));
        let signature = self.key.sign(
            Pkcs1v15Sign::new::<opaque_sha2::Sha256>(),
            &Sha256::digest(&signed),
        )?;
        Ok(serde_json::from_value(
            json!({"id":URL_SAFE_NO_PAD.encode(&self.id),"rawId":URL_SAFE_NO_PAD.encode(&self.id),"type":"public-key","response":{"authenticatorData":URL_SAFE_NO_PAD.encode(data),"clientDataJSON":URL_SAFE_NO_PAD.encode(client),"signature":URL_SAFE_NO_PAD.encode(signature),"userHandle":URL_SAFE_NO_PAD.encode(user.as_bytes())}}),
        )?)
    }
}

fn passkeys(pool: PgPool, ttl: u64, maximum: usize) -> Result<PasskeyService> {
    PasskeyService::new(
        PasskeyConfig::new(
            "example.com".into(),
            "Permesi".into(),
            vec![ORIGIN.into()],
            Duration::from_secs(ttl),
            false,
        )?,
        maximum,
        pool,
        &[1; 32],
        1000,
    )
}

async fn insert_test_user(pool: &PgPool) -> Result<Uuid> {
    Ok(sqlx::query_scalar("INSERT INTO users (email,opaque_registration_record,status) VALUES ($1,$2,'active') RETURNING id").bind(format!("{}@example.com",Uuid::new_v4())).bind(vec![0u8;32]).fetch_one(pool).await?)
}

#[tokio::test]
async fn webauthn_passkey_registration_and_login_survive_replica_restart() -> Result<()> {
    let Some(db) = TestDb::new().await? else {
        return Ok(());
    };
    let user = insert_test_user(&db.pool).await?;
    let a = passkeys(db.pool.clone(), 300, 100)?;
    let mut authenticator = Authenticator::new()?;
    let (id, challenge) = a
        .register_begin(user, "user@example.com", "User", vec![1; 32], ORIGIN)
        .await?;
    let proof = authenticator.register(&challenge)?;
    drop(a);
    let b = passkeys(db.pool.clone(), 300, 100)?;
    let key = b
        .register_finish(id, user, &[1; 32], ORIGIN, proof.clone())
        .await
        .map_err(|_| anyhow!("registration failed"))?;
    assert!(
        b.register_finish(id, user, &[1; 32], ORIGIN, proof)
            .await
            .is_err()
    );
    let (id, challenge) = b.auth_begin(ORIGIN).await?;
    assert!(challenge.public_key.allow_credentials.is_empty());
    let proof = authenticator.authenticate(&challenge, user)?;
    drop(b);
    let c = passkeys(db.pool.clone(), 300, 100)?;
    let credentials = [DiscoverableKey::from(&key)];
    let verified = c
        .auth_finish(id, ORIGIN, proof.clone(), &credentials)
        .await
        .map_err(|_| anyhow!("authentication failed"))?;
    assert_eq!(verified.cred_id().as_slice(), authenticator.id);
    assert!(
        c.auth_finish(id, ORIGIN, proof, &credentials)
            .await
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn webauthn_security_key_ceremonies_are_shared_and_session_bound() -> Result<()> {
    let Some(db) = TestDb::new().await? else {
        return Ok(());
    };
    let user = insert_test_user(&db.pool).await?;
    let a = SecurityKeyService::new(
        db.pool.clone(),
        "example.com",
        &[ORIGIN.into()],
        &[1; 32],
        300,
        100,
        1000,
    )?;
    let b = SecurityKeyService::new(
        db.pool.clone(),
        "example.com",
        &[ORIGIN.into()],
        &[1; 32],
        300,
        100,
        1000,
    )?;
    let mut authenticator = Authenticator::new()?;
    let (challenge, id) = a
        .register_begin(user, "user@example.com", ORIGIN, &[1; 32])
        .await?;
    let proof = authenticator.register(&challenge)?;
    b.register_finish(id, ORIGIN, proof.clone(), user, "Key", &[1; 32])
        .await?;
    assert!(
        a.register_finish(id, ORIGIN, proof, user, "Key", &[1; 32])
            .await
            .is_err()
    );
    let (challenge, id) = a.auth_begin(user, ORIGIN, &[2; 32]).await?;
    let proof = authenticator.authenticate(&challenge, user)?;
    assert_eq!(
        b.auth_finish(id, ORIGIN, proof.clone(), user, &[2; 32])
            .await?,
        user
    );
    assert!(
        a.auth_finish(id, ORIGIN, proof, user, &[2; 32])
            .await
            .is_err()
    );
    let (challenge, id) = a.auth_begin(user, ORIGIN, &[2; 32]).await?;
    let proof = authenticator.authenticate(&challenge, user)?;
    assert!(
        b.auth_finish(id, ORIGIN, proof.clone(), user, &[3; 32])
            .await
            .is_err()
    );
    assert!(
        a.auth_finish(id, ORIGIN, proof, user, &[2; 32])
            .await
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn webauthn_store_rejects_all_binding_changes_and_persists_only_sealed_hashes() -> Result<()>
{
    let Some(db) = TestDb::new().await? else {
        return Ok(());
    };
    let user = insert_test_user(&db.pool).await?;
    let other = insert_test_user(&db.pool).await?;
    let store = ExchangeStore::new(
        db.pool.clone(),
        &[1; 32],
        "example.com".into(),
        300,
        100,
        1000,
    )?;
    for change in 0..7 {
        let id = store
            .put(
                Binding {
                    purpose: Purpose::PasskeyRegistration,
                    origin: ORIGIN,
                    user: Some(user),
                    session: Some(&[1; 32]),
                },
                &json!({"proof":"private-test-transcript"}),
            )
            .await?;
        let row = sqlx::query("SELECT id_hash,sealed_state FROM webauthn_exchanges")
            .fetch_one(&db.pool)
            .await?;
        assert_eq!(
            row.get::<Vec<u8>, _>("id_hash"),
            Sha256::digest(id.as_bytes()).as_slice()
        );
        assert!(
            !row.get::<Vec<u8>, _>("sealed_state")
                .windows(23)
                .any(|w| w == b"private-test-transcript")
        );
        let changed = Binding {
            purpose: if change == 0 {
                Purpose::SecurityKeyRegistration
            } else {
                Purpose::PasskeyRegistration
            },
            origin: if change == 1 {
                "https://other.example.com"
            } else {
                ORIGIN
            },
            user: Some(if change == 2 { other } else { user }),
            session: Some(if change == 3 { &[2; 32] } else { &[1; 32] }),
        };
        let changed_store = ExchangeStore::new(
            db.pool.clone(),
            if change == 4 { &[2; 32] } else { &[1; 32] },
            if change == 5 {
                "other.example.com"
            } else {
                "example.com"
            }
            .into(),
            300,
            100,
            1000,
        )?;
        if change == 6 {
            sqlx::query("UPDATE webauthn_exchanges SET expires_at=expires_at+INTERVAL '1 second'")
                .execute(&db.pool)
                .await?;
        }
        assert!(changed_store.take::<Value>(id, changed).await.is_err());
        assert!(
            store
                .take::<Value>(
                    id,
                    Binding {
                        purpose: Purpose::PasskeyRegistration,
                        origin: ORIGIN,
                        user: Some(user),
                        session: Some(&[1; 32])
                    }
                )
                .await
                .is_err()
        );
    }
    Ok(())
}

#[tokio::test]
async fn webauthn_store_expiry_capacity_and_concurrent_consumption_are_global() -> Result<()> {
    let Some(db) = TestDb::new().await? else {
        return Ok(());
    };
    let a = ExchangeStore::new(db.pool.clone(), &[1; 32], "example.com".into(), 1, 1, 1000)?;
    let b = ExchangeStore::new(db.pool.clone(), &[1; 32], "example.com".into(), 1, 1, 1000)?;
    let bind = || Binding {
        purpose: Purpose::PasskeyLogin,
        origin: ORIGIN,
        user: None,
        session: None,
    };
    let id = a.put(bind(), &json!({"challenge":"private"})).await?;
    assert!(b.put(bind(), &json!({})).await.is_err());
    let (first, second) = tokio::join!(a.take::<Value>(id, bind()), b.take::<Value>(id, bind()));
    assert_eq!(usize::from(first.is_ok()) + usize::from(second.is_ok()), 1);
    let id = b.put(bind(), &json!({})).await?;
    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert!(a.take::<Value>(id, bind()).await.is_err());
    assert!(a.put(bind(), &json!({})).await.is_ok());
    Ok(())
}

/// Runs real handler issuance, including credential locks/audit FKs and limited MFA authority.
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn webauthn_http_login_commits_authority_and_rejects_replay_or_disabled_user() -> Result<()> {
    use crate::api::{
        handlers::auth::{passkeys, principal::require_auth, storage},
        state::AppState,
    };
    use crate::webauthn::{PasskeyRepo, serialize_passkey};
    use service_utils::request_id::with_request_correlation;
    let Some(db) = TestDb::new().await? else {
        return Ok(());
    };
    let user = insert_test_user(&db.pool).await?;
    let a = self::passkeys(db.pool.clone(), 300, 100)?;
    let mut authenticator = Authenticator::new()?;
    let (id, challenge) = a
        .register_begin(user, "user@example.com", "User", vec![1; 32], ORIGIN)
        .await?;
    let key = a
        .register_finish(
            id,
            user,
            &[1; 32],
            ORIGIN,
            authenticator.register(&challenge)?,
        )
        .await
        .map_err(|_| anyhow!("registration"))?;
    PasskeyRepo::create_passkey(
        &db.pool,
        user,
        &authenticator.id,
        &serialize_passkey(&key)?,
        None,
    )
    .await?;
    let (admission, signer, kid) = test_admission_context()?;
    let zero = issue_zero_token(&signer, &kid)?;
    let state = AppState {
        admission,
        passkeys: Arc::new(self::passkeys(db.pool.clone(), 300, 100)?),
        ..AppState::for_tests(db.pool.clone())?
    };
    let router = with_request_correlation(
        Router::new()
            .route("/finish", post(passkeys::passkey_login_finish))
            .with_state(state),
    );
    let (id, challenge) = a.auth_begin(ORIGIN).await?;
    let proof = authenticator.authenticate(&challenge, user)?;
    let body = serde_json::to_vec(&json!({"auth_id":id,"response":proof}))?;
    let request = || {
        Request::builder()
            .method("POST")
            .uri("/finish")
            .header("Origin", ORIGIN)
            .header("X-Permesi-Zero-Token", &zero)
            .body(Body::from(body.clone()))
    };
    let response =
        tokio::time::timeout(Duration::from_secs(5), router.clone().oneshot(request()?)).await??;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let cookie = response
        .headers()
        .get(SET_COOKIE)
        .context("cookie")?
        .to_str()?;
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        COOKIE,
        cookie.split(';').next().context("cookie pair")?.parse()?,
    );
    assert_eq!(
        require_auth(&headers, &db.pool)
            .await
            .map_err(|_| anyhow!("session"))?
            .user_id,
        user
    );
    assert_eq!(
        router.clone().oneshot(request()?).await?.status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM passkey_audit_log WHERE user_id=$1 AND action='verify_success'"
        )
        .bind(user)
        .fetch_one(&db.pool)
        .await?,
        1
    );

    // A challenge session never becomes a full session merely by existing.
    let challenge_token = storage::insert_mfa_challenge_session(&db.pool, user, 300).await?;
    headers.insert(
        COOKIE,
        format!("permesi_session={challenge_token}").parse()?,
    );
    assert!(require_auth(&headers, &db.pool).await.is_err());
    let (id, challenge) = a.auth_begin(ORIGIN).await?;
    let proof = authenticator.authenticate(&challenge, user)?;
    sqlx::query("UPDATE users SET status='disabled' WHERE id=$1")
        .bind(user)
        .execute(&db.pool)
        .await?;
    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/finish")
                .header("Origin", ORIGIN)
                .header("X-Permesi-Zero-Token", &zero)
                .body(Body::from(serde_json::to_vec(
                    &json!({"auth_id":id,"response":proof}),
                )?))?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(response.headers().get(SET_COOKIE).is_none());
    Ok(())
}

#[tokio::test]
async fn webauthn_current_security_key_counter_never_regresses() -> Result<()> {
    let Some(db) = TestDb::new().await? else {
        return Ok(());
    };
    let user = insert_test_user(&db.pool).await?;
    let id = vec![7u8; 32];
    crate::webauthn::SecurityKeyRepo::create_key(&db.pool, user, &id, b"{}", "test", 0).await?;
    crate::webauthn::SecurityKeyRepo::update_key_usage(&db.pool, &id, 2).await?;
    assert!(
        crate::webauthn::SecurityKeyRepo::update_key_usage(&db.pool, &id, 1)
            .await
            .is_err()
    );
    assert!(
        crate::webauthn::SecurityKeyRepo::update_key_usage(&db.pool, &id, 2)
            .await
            .is_err()
    );
    assert!(
        crate::webauthn::SecurityKeyRepo::update_key_usage(&db.pool, &id, 0)
            .await
            .is_err()
    );
    let (a, b) = tokio::join!(
        crate::webauthn::SecurityKeyRepo::update_key_usage(&db.pool, &id, 3),
        crate::webauthn::SecurityKeyRepo::update_key_usage(&db.pool, &id, 3)
    );
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    Ok(())
}

/// Runs the repository's transactional schema smoke script before and after reapplication.
#[tokio::test]
async fn webauthn_schema_reapplication_preserves_runtime_backstops() -> Result<()> {
    let Some(db) = TestDb::new().await? else {
        return Ok(());
    };
    let mut connection = db.pool.acquire().await?;
    sqlx::query("CREATE ROLE permesi_runtime NOLOGIN")
        .execute(&mut *connection)
        .await?;
    test_support::sql::execute_script(&mut *connection, "02_permesi.sql", PERMESI_SCHEMA_SQL)
        .await?;
    let verify = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../db/sql/verify_permesi.sql"
    ));
    test_support::sql::execute_script(&mut *connection, "verify_permesi.sql", verify).await?;
    // Reproduce the broad development bootstrap before the restrictive grants reapply.
    sqlx::query("GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO permesi_runtime")
        .execute(&mut *connection)
        .await?;
    test_support::sql::execute_script(&mut *connection, "02_permesi.sql", PERMESI_SCHEMA_SQL)
        .await?;
    test_support::sql::execute_script(&mut *connection, "verify_permesi.sql", verify).await?;
    Ok(())
}
