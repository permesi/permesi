//! Real HTTP/PostgreSQL/Vault refresh rotation, current authority and replay regressions.
#![allow(clippy::too_many_lines, clippy::indexing_slicing)]
use super::*;

/// Only explicit offline consent may mint the original family, never a client allow-list alone.
async fn issue(t: &TokenFixture) -> Result<Value> {
    issue_as(t, None).await
}

/// Uses the same real consent flow with confidential Basic proof when supplied.
async fn issue_as(t: &TokenFixture, basic: Option<&str>) -> Result<Value> {
    let page =
        t.f.start(&[
            (
                "scope",
                Some("openid offline_access jobs:read runs:read".into()),
            ),
            ("nonce", Some("offline-nonce".into())),
            ("prompt", Some("consent".into())),
        ])
        .await?;
    assert_eq!(page.status, StatusCode::OK);
    let reply = t.f.decide(&page, "allow", "").await?;
    let code = parameter(reply.location.as_deref().context("redirect")?, "code")?;
    let (status, body) = exchange(
        &t.f.router,
        &fields(&code, &t.f.client.to_string(), REDIRECT, VERIFIER),
        basic,
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    ensure!(
        body.get("refresh_token").is_some() && body.get("id_token").is_some(),
        "offline response missing authority"
    );
    Ok(body)
}

/// Supplies only the authenticated client, opaque token and optional narrowing scope.
async fn refresh(
    router: &Router,
    client: Uuid,
    token: &str,
    scope: Option<&str>,
) -> Result<(StatusCode, Value)> {
    let client = client.to_string();
    let mut fields = vec![
        ("grant_type", "refresh_token"),
        ("client_id", &client),
        ("refresh_token", token),
    ];
    if let Some(scope) = scope {
        fields.push(("scope", scope));
    }
    exchange(router, &fields, None).await
}

/// Starts an independent signing/client service and pool, sharing only durable PostgreSQL/Vault authority.
async fn replica(t: &TokenFixture) -> Result<Router> {
    let mut state = t.f.state.clone();
    state.pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&t.f.postgres.admin_dsn())
        .await?;
    let transport =
        VaultTransport::from_target("refresh-replica", VaultTarget::parse(t.vault.base_url())?)?;
    let mut globals = crate::cli::globals::GlobalArgs::new(t.vault.base_url().into(), transport);
    globals.set_token(SecretString::from("root-token"));
    globals.vault_transit_mount = "transit/permesi".into();
    state.oauth = Arc::new(OAuthState::new(state.oauth.config.clone(), &globals));
    Ok(router(&state))
}

#[tokio::test]
async fn refresh_public_rotation_preserves_family_scope_and_revokes_on_reuse() -> Result<()> {
    let t = TokenFixture::new().await?;
    let first = issue(&t).await?;
    let original = first["refresh_token"].as_str().context("refresh")?;
    let b = replica(&t).await?;
    for scope in [
        "jobs:write",
        "platform:admin",
        "jobs:read jobs:read",
        "profile",
        "offline_access",
        "",
    ] {
        let (status, error) = refresh(&b, t.f.client, original, Some(scope)).await?;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(error, json!({"error":"invalid_scope"}));
    }
    let (status, narrow) = refresh(&b, t.f.client, original, Some("jobs:read")).await?;
    assert_eq!(status, StatusCode::OK);
    ensure!(
        narrow["scope"] == "jobs:read" && narrow.get("id_token").is_none(),
        "refresh widened scopes or fabricated identity"
    );
    let keys = serde_json::to_value(t.f.state.oauth.jwks().await?)?;
    let claims = verify(
        narrow["access_token"].as_str().context("access")?,
        &keys,
        "at+jwt",
    )?;
    ensure!(
        claims["organization_id"] == t.f.organization.to_string()
            && claims["application_id"] == t.f.application.to_string()
            && claims["sub"] == t.f.user.to_string()
            && claims["scope"] == "jobs:read",
        "tenant or scope changed"
    );
    let next = narrow["refresh_token"].as_str().context("successor")?;
    ensure!(next != original, "refresh reused bearer");
    let (status, full) = refresh(&t.f.router, t.f.client, next, None).await?;
    assert_eq!(status, StatusCode::OK);
    ensure!(
        full["scope"] == "openid offline_access jobs:read runs:read",
        "family authority changed during per-request narrowing"
    );
    let stored: (Vec<u8>,Vec<String>)=sqlx::query_as("SELECT t.token_hash,f.scope_names FROM oauth_refresh_tokens t JOIN oauth_refresh_families f ON f.id=t.family_id WHERE t.previous_hash IS NULL").fetch_one(&t.f.pool).await?;
    assert_eq!(stored.0, Sha256::digest(original.as_bytes()).to_vec());
    assert_eq!(
        stored.1,
        vec!["openid", "offline_access", "jobs:read", "runs:read"]
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM oauth_token_issuances")
            .fetch_one(&t.f.pool)
            .await?,
        3
    );
    let (status, error) = refresh(&b, t.f.client, original, None).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(error, json!({"error":"invalid_grant"}));
    assert_eq!(
        sqlx::query_scalar::<_, String>("SELECT revocation_reason FROM oauth_refresh_families")
            .fetch_one(&t.f.pool)
            .await?,
        "reuse"
    );
    assert_eq!(
        refresh(
            &t.f.router,
            t.f.client,
            full["refresh_token"].as_str().context("latest")?,
            None
        )
        .await?
        .0,
        StatusCode::BAD_REQUEST
    );
    Ok(())
}

#[tokio::test]
async fn refresh_concurrent_replicas_have_one_winner_then_revoke_the_winner_family() -> Result<()> {
    let t = TokenFixture::new().await?;
    let first = issue(&t).await?;
    let token = first["refresh_token"].as_str().context("refresh")?;
    let b = replica(&t).await?;
    let (a, b) = tokio::join!(
        refresh(&t.f.router, t.f.client, token, None),
        refresh(&b, t.f.client, token, None)
    );
    let replies = [a?, b?];
    assert_eq!(
        replies.iter().filter(|(s, _)| *s == StatusCode::OK).count(),
        1
    );
    assert_eq!(
        replies
            .iter()
            .filter(|(s, _)| *s == StatusCode::BAD_REQUEST)
            .count(),
        1
    );
    let winner = &replies
        .iter()
        .find(|(s, _)| *s == StatusCode::OK)
        .context("winner")?
        .1;
    assert_eq!(
        refresh(
            &t.f.router,
            t.f.client,
            winner["refresh_token"].as_str().context("winner refresh")?,
            None
        )
        .await?
        .0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM oauth_refresh_tokens")
            .fetch_one(&t.f.pool)
            .await?,
        2
    );
    Ok(())
}

#[tokio::test]
async fn refresh_wrong_client_or_tenant_input_cannot_burn_another_family() -> Result<()> {
    let t = TokenFixture::new().await?;
    let first = issue(&t).await?;
    let token = first["refresh_token"].as_str().context("refresh")?;
    let other = Uuid::new_v4();
    sqlx::query("INSERT INTO oauth_clients (application_id,client_id,name,client_type) VALUES ($1,$2,'Another client','public')").bind(t.f.application).bind(other).execute(&t.f.pool).await?;
    let (status, error) = refresh(&t.f.router, other, token, None).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(error, json!({"error":"invalid_grant"}));
    let fields = [
        ("grant_type", "refresh_token"),
        ("client_id", &t.f.client.to_string()),
        ("refresh_token", token),
        ("organization_id", &Uuid::new_v4().to_string()),
    ];
    assert_eq!(
        exchange(&t.f.router, &fields, None).await?.1,
        json!({"error":"invalid_request"})
    );
    assert_eq!(
        refresh(&t.f.router, t.f.client, token, None).await?.0,
        StatusCode::OK
    );
    Ok(())
}

/// Every family use requires current tenant membership, exact grant, user and registry/allow-list edges.
#[tokio::test]
async fn refresh_current_authority_loss_revokes_permanently_without_consuming() -> Result<()> {
    let t = TokenFixture::new().await?;
    for mutation in ["user", "membership", "grant", "scope"] {
        let first = issue(&t).await?;
        let token = first["refresh_token"].as_str().context("refresh")?;
        let hash = Sha256::digest(token.as_bytes()).to_vec();
        let family: Uuid =
            sqlx::query_scalar("SELECT family_id FROM oauth_refresh_tokens WHERE token_hash=$1")
                .bind(&hash)
                .fetch_one(&t.f.pool)
                .await?;
        let query = match mutation {
            "user" => "UPDATE users SET status='disabled' WHERE id=$1",
            "membership" => "UPDATE org_memberships SET status='suspended' WHERE user_id=$1",
            "grant" => {
                "UPDATE oauth_grants SET revoked_at=clock_timestamp() WHERE user_id=$1 AND revoked_at IS NULL"
            }
            _ => {
                "DELETE FROM oauth_client_scopes WHERE client_id IN (SELECT client_id FROM oauth_grants WHERE user_id=$1) AND scope_id IN (SELECT id FROM oauth_scopes WHERE name='jobs:read')"
            }
        };
        sqlx::query(query).bind(t.f.user).execute(&t.f.pool).await?;
        assert_eq!(
            refresh(&t.f.router, t.f.client, token, None).await?.1,
            json!({"error":"invalid_grant"}),
            "{mutation}"
        );
        assert_eq!(
            sqlx::query_scalar::<_, String>(
                "SELECT revocation_reason FROM oauth_refresh_families WHERE id=$1"
            )
            .bind(family)
            .fetch_one(&t.f.pool)
            .await?,
            "authority"
        );
        sqlx::query("UPDATE users SET status='active' WHERE id=$1")
            .bind(t.f.user)
            .execute(&t.f.pool)
            .await?;
        sqlx::query("UPDATE org_memberships SET status='active' WHERE user_id=$1")
            .bind(t.f.user)
            .execute(&t.f.pool)
            .await?;
        sqlx::query("INSERT INTO oauth_client_scopes (client_id,application_id,scope_id) SELECT $1,application_id,id FROM oauth_scopes WHERE application_id=$2 ON CONFLICT DO NOTHING").bind(t.f.client_internal).bind(t.f.application).execute(&t.f.pool).await?;
        assert_eq!(
            refresh(&t.f.router, t.f.client, token, None).await?.0,
            StatusCode::BAD_REQUEST
        );
        assert!(
            sqlx::query_scalar::<_, bool>(
                "SELECT consumed_at IS NULL FROM oauth_refresh_tokens WHERE token_hash=$1"
            )
            .bind(hash)
            .fetch_one(&t.f.pool)
            .await?
        );
    }
    Ok(())
}

#[tokio::test]
async fn refresh_password_rotation_revokes_families_and_pending_code_revision() -> Result<()> {
    let t = TokenFixture::new().await?;
    let first = issue(&t).await?;
    let code = t.f.issue().await?;
    crate::api::handlers::auth::rotate_password_for_test(&t.f.pool, t.f.user, &[8; 32]).await?;
    assert_eq!(
        refresh(
            &t.f.router,
            t.f.client,
            first["refresh_token"].as_str().context("refresh")?,
            None
        )
        .await?
        .1,
        json!({"error":"invalid_grant"})
    );
    assert_eq!(
        sqlx::query_scalar::<_, String>("SELECT revocation_reason FROM oauth_refresh_families")
            .fetch_one(&t.f.pool)
            .await?,
        "password"
    );
    assert_eq!(
        exchange(
            &t.f.router,
            &fields(&code, &t.f.client.to_string(), REDIRECT, VERIFIER),
            None
        )
        .await?
        .1,
        json!({"error":"invalid_grant"})
    );
    Ok(())
}

#[tokio::test]
async fn refresh_expiry_uses_database_clock_and_never_extends_absolute_lifetime() -> Result<()> {
    let mut t = TokenFixture::new().await?;
    let mut oauth = (*t.f.state.oauth).clone();
    oauth.config.tokens.refresh_absolute_ttl = 3;
    oauth.config.tokens.refresh_idle_ttl = 2;
    t.f.state.oauth = Arc::new(oauth);
    t.f.router = router(&t.f.state);
    let first = issue(&t).await?;
    sleep(Duration::from_millis(1200)).await;
    let (status, next) = refresh(
        &t.f.router,
        t.f.client,
        first["refresh_token"].as_str().context("refresh")?,
        None,
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    let capped:bool=sqlx::query_scalar("SELECT t.expires_at=f.expires_at FROM oauth_refresh_tokens t JOIN oauth_refresh_families f ON f.id=t.family_id WHERE t.previous_hash IS NOT NULL").fetch_one(&t.f.pool).await?;
    assert!(capped);
    sleep(Duration::from_secs(2)).await;
    assert_eq!(
        refresh(
            &t.f.router,
            t.f.client,
            next["refresh_token"].as_str().context("refresh")?,
            None
        )
        .await?
        .1,
        json!({"error":"invalid_grant"})
    );
    Ok(())
}

#[tokio::test]
async fn refresh_signing_failure_rolls_back_consumption_and_successor() -> Result<()> {
    let t = TokenFixture::new().await?;
    let first = issue(&t).await?;
    let token = first["refresh_token"].as_str().context("refresh")?;
    let mut denied = t.f.state.clone();
    let transport = VaultTransport::from_target("denied", VaultTarget::parse(t.vault.base_url())?)?;
    let mut globals = crate::cli::globals::GlobalArgs::new(t.vault.base_url().into(), transport);
    globals.set_token(SecretString::from("invalid-vault-credential"));
    globals.vault_transit_mount = "transit/permesi".into();
    denied.oauth = Arc::new(OAuthState::new(denied.oauth.config.clone(), &globals));
    assert_eq!(
        refresh(&router(&denied), t.f.client, token, None).await?.0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM oauth_refresh_tokens")
            .fetch_one(&t.f.pool)
            .await?,
        1
    );
    assert_eq!(
        refresh(&t.f.router, t.f.client, token, None).await?.0,
        StatusCode::OK
    );
    Ok(())
}

/// Reapplying schema cannot grant the runtime permission to rewrite or erase replay evidence.
#[tokio::test]
async fn refresh_schema_reapplication_preserves_bindings_history_and_runtime_permissions()
-> Result<()> {
    let t = TokenFixture::new().await?;
    let body = issue(&t).await?;
    let token = body["refresh_token"].as_str().context("refresh")?;
    sqlx::raw_sql(
        "CREATE ROLE permesi_runtime; GRANT ALL ON ALL TABLES IN SCHEMA public TO permesi_runtime;",
    )
    .execute(&t.f.pool)
    .await?;
    // Simulate an older format constraint and pending short state before upgrading in place.
    sqlx::raw_sql("ALTER TABLE opaque_exchanges DROP CONSTRAINT opaque_exchanges_sealed_state_check; ALTER TABLE opaque_exchanges ADD CONSTRAINT opaque_exchanges_sealed_state_check CHECK(octet_length(sealed_state) BETWEEN 29 AND 4096);")
        .execute(&t.f.pool).await?;
    let legacy = Sha256::digest(b"legacy-exchange-fixture").to_vec();
    sqlx::query("INSERT INTO opaque_exchanges(id_hash,purpose,sealed_state,created_at,expires_at) VALUES($1,'login',$2,clock_timestamp(),clock_timestamp()+INTERVAL '5 minutes')").bind(&legacy).bind(vec![0u8;40]).execute(&t.f.pool).await?;
    let mut conn = t.f.pool.acquire().await?;
    test_support::sql::execute_script(&mut conn, "02_permesi.sql", SCHEMA).await?;
    test_support::sql::execute_script(
        &mut conn,
        "verify_permesi.sql",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../db/sql/verify_permesi.sql"
        )),
    )
    .await?;
    drop(conn);
    assert!(
        !sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM opaque_exchanges WHERE id_hash=$1)"
        )
        .bind(legacy)
        .fetch_one(&t.f.pool)
        .await?
    );
    for query in [
        "UPDATE oauth_refresh_families SET expires_at=expires_at+INTERVAL '1 second'",
        "UPDATE oauth_refresh_families SET scope_names=ARRAY['openid','offline_access','jobs:write','runs:read']",
        "DELETE FROM oauth_refresh_families",
        "DELETE FROM oauth_refresh_tokens",
        "TRUNCATE oauth_refresh_tokens",
    ] {
        let mut tx = t.f.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE permesi_runtime")
            .execute(&mut *tx)
            .await?;
        let error = sqlx::query(query)
            .execute(&mut *tx)
            .await
            .err()
            .context("runtime rewrote refresh authority/history")?;
        assert_eq!(
            error
                .as_database_error()
                .and_then(sqlx::error::DatabaseError::code)
                .as_deref(),
            Some("42501")
        );
        tx.rollback().await?;
    }
    let mut runtime_state = t.f.state.clone();
    runtime_state.pool = PgPoolOptions::new()
        .max_connections(2)
        .after_connect(|conn, _| {
            Box::pin(async move {
                sqlx::query("SET ROLE permesi_runtime")
                    .execute(conn)
                    .await?;
                Ok(())
            })
        })
        .connect(&t.f.postgres.admin_dsn())
        .await?;
    assert_eq!(
        refresh(&router(&runtime_state), t.f.client, token, None)
            .await?
            .0,
        StatusCode::OK
    );
    assert_eq!(
        refresh(&router(&runtime_state), t.f.client, token, None)
            .await?
            .0,
        StatusCode::BAD_REQUEST
    );
    for query in [
        "UPDATE oauth_refresh_families SET revoked_at=NULL,revocation_reason=NULL",
        "UPDATE oauth_refresh_tokens SET consumed_at=NULL WHERE consumed_at IS NOT NULL",
    ] {
        let mut tx = t.f.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE permesi_runtime")
            .execute(&mut *tx)
            .await?;
        let error = sqlx::query(query)
            .execute(&mut *tx)
            .await
            .err()
            .context("runtime reversed consumed/revoked state")?;
        assert_eq!(
            error
                .as_database_error()
                .and_then(sqlx::error::DatabaseError::code)
                .as_deref(),
            Some("23514")
        );
        tx.rollback().await?;
    }
    Ok(())
}

#[tokio::test]
async fn refresh_code_cleanup_does_not_erase_the_live_family() -> Result<()> {
    let t = TokenFixture::new().await?;
    let body = issue(&t).await?;
    sqlx::query("DELETE FROM oauth_authorization_requests")
        .execute(&t.f.pool)
        .await?;
    assert_eq!(
        refresh(
            &t.f.router,
            t.f.client,
            body["refresh_token"].as_str().context("refresh")?,
            None
        )
        .await?
        .0,
        StatusCode::OK
    );
    Ok(())
}

#[tokio::test]
async fn refresh_confidential_proof_rotation_and_revocation_cannot_burn_without_authentication()
-> Result<()> {
    let mut t = TokenFixture::new().await?;
    let client = Uuid::new_v4();
    let internal:Uuid=sqlx::query_scalar("INSERT INTO oauth_clients (application_id,client_id,name,client_type) VALUES ($1,$2,'Offline confidential','confidential') RETURNING id").bind(t.f.application).bind(client).fetch_one(&t.f.pool).await?;
    sqlx::query("INSERT INTO oauth_client_redirect_uris (client_id,redirect_uri) VALUES ($1,$2)")
        .bind(internal)
        .bind(REDIRECT)
        .execute(&t.f.pool)
        .await?;
    sqlx::query("INSERT INTO oauth_client_scopes (client_id,application_id,scope_id) SELECT $1,application_id,id FROM oauth_scopes WHERE application_id=$2").bind(internal).bind(t.f.application).execute(&t.f.pool).await?;
    sqlx::query("INSERT INTO org_roles (org_id,name) VALUES ($1,'owner')")
        .bind(t.f.organization)
        .execute(&t.f.pool)
        .await?;
    sqlx::query("INSERT INTO org_member_roles (org_id,user_id,role_name) VALUES ($1,$2,'owner')")
        .bind(t.f.organization)
        .bind(t.f.user)
        .execute(&t.f.pool)
        .await?;
    t.f.client = client;
    t.f.client_internal = internal;
    let context = crate::oauth::service::ApplicationContext::resolved(t.f.application, t.f.user);
    let first =
        t.f.state
            .oauth
            .credentials
            .issue(&t.f.pool, &context, client, None)
            .await?;
    let basic = format!(
        "Basic {}",
        STANDARD.encode(format!("{client}:{}", first.client_secret.expose_secret()))
    );
    let body = issue_as(&t, Some(&basic)).await?;
    let token = body["refresh_token"].as_str().context("refresh")?;
    let input = [
        ("grant_type", "refresh_token"),
        ("client_id", &client.to_string()),
        ("refresh_token", token),
    ];
    assert_eq!(
        exchange(&t.f.router, &input, None).await?.1,
        json!({"error":"invalid_client"})
    );
    assert_eq!(
        exchange(&t.f.router, &input, Some("Basic bad")).await?.0,
        StatusCode::UNAUTHORIZED
    );
    let current =
        t.f.state
            .oauth
            .credentials
            .issue(&t.f.pool, &context, client, Some(first.credential.id))
            .await?;
    let (status, next) = exchange(&t.f.router, &input, Some(&basic)).await?;
    assert_eq!(status, StatusCode::OK);
    t.f.state
        .oauth
        .credentials
        .revoke(&t.f.pool, &context, client, first.credential.id)
        .await?;
    let token = next["refresh_token"].as_str().context("successor")?;
    let input = [
        ("grant_type", "refresh_token"),
        ("client_id", &client.to_string()),
        ("refresh_token", token),
    ];
    assert_eq!(
        exchange(&t.f.router, &input, Some(&basic)).await?.0,
        StatusCode::UNAUTHORIZED
    );
    let basic = format!(
        "Basic {}",
        STANDARD.encode(format!(
            "{client}:{}",
            current.client_secret.expose_secret()
        ))
    );
    assert_eq!(
        exchange(&t.f.router, &input, Some(&basic)).await?.0,
        StatusCode::OK
    );
    Ok(())
}

#[tokio::test]
async fn refresh_mfa_recovery_revokes_family_and_pre_recovery_code() -> Result<()> {
    use crate::api::handlers::auth::{
        self, OpaqueState,
        mfa::{self, MfaState},
    };
    let mut t = TokenFixture::new().await?;
    let first = issue(&t).await?;
    let code = t.f.issue().await?;
    let pepper = Arc::from(vec![1, 2, 3, 4]);
    let batch = mfa::recovery::RecoveryCodeBatch::generate(&pepper)?;
    let mut tx = t.f.pool.begin().await?;
    mfa::storage::insert_recovery_codes_on(&mut tx, t.f.user, batch.batch_id, &batch.code_hashes)
        .await?;
    mfa::storage::upsert_mfa_state(&mut *tx, t.f.user, MfaState::Enabled, Some(batch.batch_id))
        .await?;
    tx.commit().await?;
    let challenge = auth::challenge_session_for_test(&t.f.pool, t.f.user).await?;
    t.f.state.auth = Arc::new(AuthState::new(
        t.f.state.auth.config().clone(),
        OpaqueState::from_seed([1; 32], "issuer.test".into(), Duration::from_secs(30), 100),
        Arc::new(auth::RateLimiter::noop()),
        t.f.state.auth.mfa().clone().with_recovery_pepper(pepper),
    ));
    t.f.router = router(&t.f.state);
    let response =
        t.f.router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/auth/mfa/recovery")
                    .header(COOKIE, format!("permesi_session={challenge}"))
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        json!({"code":batch.codes.first().context("recovery code")?}).to_string(),
                    ))?,
            )
            .await?;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert!(response.headers().get(SET_COOKIE).is_some());
    assert_eq!(
        refresh(
            &t.f.router,
            t.f.client,
            first["refresh_token"].as_str().context("refresh")?,
            None
        )
        .await?
        .1,
        json!({"error":"invalid_grant"})
    );
    assert_eq!(
        sqlx::query_scalar::<_, String>("SELECT revocation_reason FROM oauth_refresh_families")
            .fetch_one(&t.f.pool)
            .await?,
        "recovery"
    );
    assert_eq!(
        exchange(
            &t.f.router,
            &fields(&code, &t.f.client.to_string(), REDIRECT, VERIFIER),
            None
        )
        .await?
        .1,
        json!({"error":"invalid_grant"})
    );
    Ok(())
}

#[tokio::test]
async fn refresh_password_revocation_failure_rolls_back_revision_password_and_authority()
-> Result<()> {
    let t = TokenFixture::new().await?;
    let first = issue(&t).await?;
    let revision: Uuid = sqlx::query_scalar("SELECT authorization_revision FROM users WHERE id=$1")
        .bind(t.f.user)
        .fetch_one(&t.f.pool)
        .await?;
    sqlx::raw_sql("CREATE FUNCTION reject_family_revocation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected revocation failure'; END $$; CREATE TRIGGER reject_family_revocation BEFORE UPDATE ON oauth_refresh_families FOR EACH ROW EXECUTE FUNCTION reject_family_revocation();").execute(&t.f.pool).await?;
    assert!(
        crate::api::handlers::auth::rotate_password_for_test(&t.f.pool, t.f.user, &[8; 32])
            .await
            .is_err()
    );
    assert_eq!(
        sqlx::query_scalar::<_, Uuid>("SELECT authorization_revision FROM users WHERE id=$1")
            .bind(t.f.user)
            .fetch_one(&t.f.pool)
            .await?,
        revision
    );
    assert_eq!(
        sqlx::query_scalar::<_, Vec<u8>>(
            "SELECT opaque_registration_record FROM users WHERE id=$1"
        )
        .bind(t.f.user)
        .fetch_one(&t.f.pool)
        .await?,
        vec![0; 16]
    );
    assert_eq!(
        refresh(
            &t.f.router,
            t.f.client,
            first["refresh_token"].as_str().context("refresh")?,
            None
        )
        .await?
        .0,
        StatusCode::OK
    );
    Ok(())
}

#[tokio::test]
async fn refresh_rejects_every_inactive_ancestor_before_token_authority() -> Result<()> {
    let t = TokenFixture::new().await?;
    let first = issue(&t).await?;
    let token = first["refresh_token"].as_str().context("refresh")?;
    for (deactivate, restore, id) in [
        (
            "UPDATE applications SET deleted_at=clock_timestamp() WHERE id=$1",
            "UPDATE applications SET deleted_at=NULL WHERE id=$1",
            t.f.application,
        ),
        (
            "UPDATE environments SET deleted_at=clock_timestamp() WHERE id=$1",
            "UPDATE environments SET deleted_at=NULL WHERE id=$1",
            t.f.environment,
        ),
        (
            "UPDATE projects SET deleted_at=clock_timestamp() WHERE id=$1",
            "UPDATE projects SET deleted_at=NULL WHERE id=$1",
            t.f.project,
        ),
        (
            "UPDATE organizations SET deleted_at=clock_timestamp() WHERE id=$1",
            "UPDATE organizations SET deleted_at=NULL WHERE id=$1",
            t.f.organization,
        ),
    ] {
        sqlx::query(deactivate).bind(id).execute(&t.f.pool).await?;
        assert_eq!(
            refresh(&t.f.router, t.f.client, token, None).await?.1,
            json!({"error":"invalid_client"})
        );
        sqlx::query(restore).bind(id).execute(&t.f.pool).await?;
    }
    assert_eq!(
        refresh(&t.f.router, t.f.client, token, None).await?.0,
        StatusCode::OK
    );
    Ok(())
}

/// Saved grants cannot replace fresh explicit offline consent or its OIDC dependencies.
#[tokio::test]
async fn refresh_offline_authority_requires_explicit_consent_even_with_a_saved_grant() -> Result<()>
{
    let t = TokenFixture::new().await?;
    issue(&t).await?;
    for (scope, prompt) in [
        ("openid offline_access jobs:read", None),
        ("openid offline_access jobs:read", Some("none")),
        ("offline_access jobs:read", Some("consent")),
    ] {
        let reply =
            t.f.start(&[
                ("scope", Some(scope.into())),
                ("nonce", Some("offline-nonce".into())),
                ("prompt", prompt.map(str::to_owned)),
            ])
            .await?;
        protocol_error(&reply, "invalid_scope")?;
    }
    let page =
        t.f.start(&[
            ("scope", Some("openid offline_access jobs:read".into())),
            ("nonce", Some("offline-nonce".into())),
            ("prompt", Some("consent".into())),
        ])
        .await?;
    assert_eq!(page.status, StatusCode::OK);
    assert!(page.body.contains("Maintain access while you are offline"));
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM oauth_refresh_families")
            .fetch_one(&t.f.pool)
            .await?,
        1
    );
    Ok(())
}

/// An unused idle-expired token is denied even while its absolute family lifetime remains valid.
#[tokio::test]
async fn refresh_idle_expiry_does_not_consume_or_extend_authority() -> Result<()> {
    let mut t = TokenFixture::new().await?;
    let mut oauth = (*t.f.state.oauth).clone();
    oauth.config.tokens.refresh_absolute_ttl = 30;
    oauth.config.tokens.refresh_idle_ttl = 1;
    t.f.state.oauth = Arc::new(oauth);
    t.f.router = router(&t.f.state);
    let first = issue(&t).await?;
    sleep(Duration::from_millis(1200)).await;
    assert_eq!(
        refresh(
            &t.f.router,
            t.f.client,
            first["refresh_token"].as_str().context("refresh")?,
            None
        )
        .await?
        .1,
        json!({"error":"invalid_grant"})
    );
    let untouched: bool = sqlx::query_scalar("SELECT t.consumed_at IS NULL AND f.revoked_at IS NULL AND f.expires_at>clock_timestamp() FROM oauth_refresh_tokens t JOIN oauth_refresh_families f ON f.id=t.family_id").fetch_one(&t.f.pool).await?;
    assert!(untouched);
    Ok(())
}

/// Captures actual production HTTP/SQL tracing for issuance, rotation and reuse rejection.
#[tokio::test]
async fn refresh_production_tracing_excludes_original_and_successor_bearers() -> Result<()> {
    use tracing::instrument::WithSubscriber as _;
    let mut t = TokenFixture::new().await?;
    t.f.router = service_utils::request_id::with_request_correlation(t.f.router.clone());
    let output = Arc::new(std::sync::Mutex::new(Vec::new()));
    let sink = LogSink(output.clone());
    let subscriber = Arc::new(
        tracing_subscriber::fmt()
            .without_time()
            .with_ansi(false)
            .with_max_level(tracing::Level::TRACE)
            .with_writer(move || sink.clone())
            .finish(),
    );
    let first = issue(&t).with_subscriber(subscriber.clone()).await?;
    let original = first["refresh_token"].as_str().context("refresh")?;
    let (status, next) = refresh(&t.f.router, t.f.client, original, None)
        .with_subscriber(subscriber.clone())
        .await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        refresh(&t.f.router, t.f.client, original, None)
            .with_subscriber(subscriber)
            .await?
            .0,
        StatusCode::BAD_REQUEST
    );
    let logs = String::from_utf8(
        output
            .lock()
            .map_err(|_| anyhow::anyhow!("log capture failed"))?
            .clone(),
    )?;
    for secret in [
        original,
        next["refresh_token"].as_str().context("successor")?,
        first["access_token"].as_str().context("initial access")?,
        first["id_token"].as_str().context("initial ID")?,
        next["access_token"].as_str().context("rotated access")?,
        "offline-nonce",
    ] {
        ensure!(
            !logs.contains(secret),
            "bearer material appeared in production tracing"
        );
    }
    Ok(())
}

/// Observes an actual PostgreSQL lock wait so the test controls the ordering rather than guessing it.
async fn wait_for_lock(pool: &PgPool, statement: &str) -> Result<()> {
    timeout(Duration::from_secs(3), async {
        loop {
            let blocked: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid() AND wait_event_type='Lock' AND starts_with(query,$1))").bind(statement).fetch_one(pool).await?;
            if blocked { return Ok::<_, anyhow::Error>(()); }
            sleep(Duration::from_millis(10)).await;
        }
    }).await.context("expected SQL lock ordering not observed")?
}

/// A password writer queued behind an in-flight refresh revokes its committed successor without deadlock.
#[tokio::test]
async fn refresh_and_password_rotation_serialize_user_before_family_authority() -> Result<()> {
    let t = TokenFixture::new().await?;
    let first = issue(&t).await?;
    let token = first["refresh_token"]
        .as_str()
        .context("refresh")?
        .to_owned();
    let mut blocker = t.f.pool.begin().await?;
    sqlx::query("SELECT id FROM oauth_refresh_families FOR UPDATE")
        .execute(&mut *blocker)
        .await?;
    let router = replica(&t).await?;
    let client = t.f.client;
    let refreshing = tokio::spawn(async move { refresh(&router, client, &token, None).await });
    wait_for_lock(
        &t.f.pool,
        "SELECT *,expires_at>clock_timestamp() AS alive FROM oauth_refresh_families",
    )
    .await?;
    let pool = t.f.pool.clone();
    let user = t.f.user;
    let rotating = tokio::spawn(async move {
        crate::api::handlers::auth::rotate_password_for_test(&pool, user, &[8; 32]).await
    });
    wait_for_lock(&t.f.pool, "UPDATE users SET opaque_registration_record").await?;
    blocker.commit().await?;
    let (status, next) = timeout(Duration::from_secs(5), refreshing).await???;
    assert_eq!(status, StatusCode::OK);
    timeout(Duration::from_secs(5), rotating).await???;
    assert_eq!(
        refresh(
            &t.f.router,
            client,
            next["refresh_token"].as_str().context("successor")?,
            None
        )
        .await?
        .1,
        json!({"error":"invalid_grant"})
    );
    assert_eq!(
        sqlx::query_scalar::<_, String>("SELECT revocation_reason FROM oauth_refresh_families")
            .fetch_one(&t.f.pool)
            .await?,
        "password"
    );
    Ok(())
}
