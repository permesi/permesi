//! Credential API/security tests using isolated real PostgreSQL and independent services.

use super::*;
use crate::oauth::{
    credentials::{CredentialConfig, CredentialError, CredentialService},
    service::ApplicationContext,
};
use secrecy::ExposeSecret;
use sqlx::postgres::PgPoolOptions;

/// Verifies on another service and pool; plaintext never needs issuing-process state.
async fn verify(pool: &PgPool, client: Uuid, secret: &str) -> Result<bool> {
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect_with((*pool.connect_options()).clone())
        .await?;
    let service = CredentialService::new(CredentialConfig::for_tests());
    let mut tx = pool.begin().await?;
    let result = service.authenticate(&mut tx, client, secret).await;
    if let Ok(proof) = &result {
        assert_eq!(proof.client_id(), client);
    }
    tx.commit().await?;
    pool.close().await;
    Ok(result.is_ok())
}

/// Extracts synthetic one-time plaintext without including it in diagnostic messages.
fn raw(value: &Value) -> Result<&str> {
    value
        .get("client_secret")
        .and_then(Value::as_str)
        .context("missing one-time secret")
}

#[tokio::test]
async fn oauth_credentials_are_hash_only_one_time_and_cross_replica_verifiable() -> Result<()> {
    let Some(f) = Fixture::new().await? else {
        return Ok(());
    };
    let registration = f.client("credentials").await?;
    let public = id(&registration, "client_id")?;
    let path = format!("/clients/{public}/secrets");
    let (status, issued) = f.call("POST", &path, &f.token, Some(json!({}))).await?;
    assert_eq!(status, StatusCode::CREATED);
    let credential = id(field(&issued, "credential")?, "id")?;
    let secret = raw(&issued)?;
    assert!(verify(&f.db.pool, public, secret).await?);
    assert!(!verify(&f.db.pool, Uuid::new_v4(), secret).await?);
    let other_client = id(&f.client("other-known-client").await?, "client_id")?;
    assert!(!verify(&f.db.pool, other_client, secret).await?);
    let wrong = format!(
        "{}{}",
        secret.get(..41).context("secret prefix")?,
        "A".repeat(43)
    );
    assert!(!verify(&f.db.pool, public, &wrong).await?);
    let hash: String =
        sqlx::query_scalar("SELECT secret_hash FROM oauth_client_secrets WHERE id=$1")
            .bind(credential)
            .fetch_one(&f.db.pool)
            .await?;
    assert!(hash.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"));
    assert!(!hash.contains(secret));
    for suffix in [&path, &format!("/clients/{public}"), "/clients"] {
        let (status, value) = f.call("GET", suffix, &f.token, None).await?;
        assert_eq!(status, StatusCode::OK);
        assert!(!value.to_string().contains(secret));
        assert!(!value.to_string().contains("secret_hash"));
        assert!(!value.to_string().contains("client_secret"));
    }
    assert_eq!(
        f.call("POST", &path, &f.token, Some(json!({}))).await?.0,
        StatusCode::CONFLICT
    );
    for _ in 0..2 {
        assert_eq!(
            f.call("DELETE", &format!("{path}/{credential}"), &f.token, None)
                .await?
                .0,
            StatusCode::NO_CONTENT
        );
    }
    assert!(!verify(&f.db.pool, public, secret).await?);
    assert_eq!(f.call("GET", &path, &f.token, None).await?.1, json!([]));
    Ok(())
}

#[tokio::test]
async fn oauth_credentials_rotation_overlap_stale_ids_and_lost_response_recovery() -> Result<()> {
    let Some(f) = Fixture::new().await? else {
        return Ok(());
    };
    let client = id(&f.client("rotation").await?, "client_id")?;
    let path = format!("/clients/{client}/secrets");
    let (_, first) = f.call("POST", &path, &f.token, Some(json!({}))).await?;
    let first_id = id(field(&first, "credential")?, "id")?;
    let rotate = format!("{path}/rotate");
    assert_eq!(
        f.call(
            "POST",
            &rotate,
            &f.token,
            Some(json!({"current_secret_id":Uuid::new_v4()}))
        )
        .await?
        .0,
        StatusCode::CONFLICT
    );
    let (status, next) = f
        .call(
            "POST",
            &rotate,
            &f.token,
            Some(json!({"current_secret_id":first_id})),
        )
        .await?;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(id(field(&next, "previous")?, "id")?, first_id);
    assert!(field(field(&next, "previous")?, "expires_at")?.is_string());
    assert!(verify(&f.db.pool, client, raw(&first)?).await?);
    assert!(verify(&f.db.pool, client, raw(&next)?).await?);
    let next_id = id(field(&next, "credential")?, "id")?;
    assert_eq!(
        f.call(
            "POST",
            &rotate,
            &f.token,
            Some(json!({"current_secret_id":next_id}))
        )
        .await?
        .0,
        StatusCode::CONFLICT
    );
    let deadline: chrono::DateTime<chrono::Utc> =
        sqlx::query_scalar("SELECT expires_at FROM oauth_client_secrets WHERE id=$1")
            .bind(first_id)
            .fetch_one(&f.db.pool)
            .await?;
    // Lost response: revoke the unseen current credential, then create fresh.
    f.call("DELETE", &format!("{path}/{next_id}"), &f.token, None)
        .await?;
    let (status, recovered) = f.call("POST", &path, &f.token, Some(json!({}))).await?;
    assert_eq!(status, StatusCode::CREATED);
    let after: chrono::DateTime<chrono::Utc> =
        sqlx::query_scalar("SELECT expires_at FROM oauth_client_secrets WHERE id=$1")
            .bind(first_id)
            .fetch_one(&f.db.pool)
            .await?;
    assert_eq!(after, deadline);
    assert!(!verify(&f.db.pool, client, raw(&next)?).await?);
    assert!(verify(&f.db.pool, client, raw(&recovered)?).await?);
    sqlx::query("UPDATE oauth_client_secrets SET expires_at=clock_timestamp()-INTERVAL '1 second' WHERE id=$1").bind(first_id).execute(&f.db.pool).await?;
    assert!(!verify(&f.db.pool, client, raw(&first)?).await?);
    assert_eq!(
        f.call("GET", &path, &f.token, None)
            .await?
            .1
            .as_array()
            .context("metadata")?
            .len(),
        1
    );
    assert_eq!(
        f.call(
            "POST",
            &rotate,
            &f.token,
            Some(json!({"current_secret_id":id(field(&recovered,"credential")?,"id")?}))
        )
        .await?
        .0,
        StatusCode::CREATED
    );
    Ok(())
}

#[tokio::test]
async fn oauth_credentials_concurrent_creation_and_rotation_have_one_winner() -> Result<()> {
    let Some(f) = Fixture::new().await? else {
        return Ok(());
    };
    let client = id(&f.client("race").await?, "client_id")?;
    let pool_b = PgPoolOptions::new()
        .max_connections(2)
        .connect_with((*f.db.pool.connect_options()).clone())
        .await?;
    let mut a = CredentialService::new(CredentialConfig::for_tests());
    let mut b = CredentialService::new(CredentialConfig::for_tests());
    let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(3));
    a.after_preflight = Some(barrier.clone());
    b.after_preflight = Some(barrier.clone());
    let context = ApplicationContext::resolved(f.application, f.owner);
    let (first, other, ()) = tokio::join!(
        a.issue(&f.db.pool, &context, client, None),
        b.issue(&pool_b, &context, client, None),
        async {
            barrier.wait().await;
            barrier.wait().await;
        }
    );
    assert_eq!(usize::from(first.is_ok()) + usize::from(other.is_ok()), 1);
    let (issued, failed) = if let Ok(value) = first {
        (value, other)
    } else {
        (
            other.map_err(|_| anyhow::anyhow!("no creation winner"))?,
            first,
        )
    };
    assert!(matches!(failed, Err(CredentialError::Conflict)));
    let current_id = issued.credential.id;
    let (first, other, ()) = tokio::join!(
        a.issue(&f.db.pool, &context, client, Some(current_id)),
        b.issue(&pool_b, &context, client, Some(current_id)),
        async {
            barrier.wait().await;
            barrier.wait().await;
        }
    );
    assert_eq!(usize::from(first.is_ok()) + usize::from(other.is_ok()), 1);
    let failed = if first.is_err() { first } else { other };
    assert!(matches!(failed, Err(CredentialError::Conflict)));
    let mut tx = pool_b.begin().await?;
    let proof = b
        .authenticate(&mut tx, client, issued.client_secret.expose_secret())
        .await?;
    assert_eq!(proof.organization_id(), f.org);
    assert_eq!(proof.application_id(), f.application);
    tx.rollback().await?;
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM oauth_client_secrets WHERE client_id=$1 AND revoked_at IS NULL",
    )
    .bind(id(
        &f.call("GET", &format!("/clients/{client}"), &f.token, None)
            .await?
            .1,
        "id",
    )?)
    .fetch_one(&f.db.pool)
    .await?;
    assert_eq!(count, 2);
    pool_b.close().await;
    Ok(())
}

#[tokio::test]
async fn oauth_credentials_enforce_tenant_roles_public_clients_and_current_lifecycle() -> Result<()>
{
    let Some(f) = Fixture::new().await? else {
        return Ok(());
    };
    let client = f.client("acl").await?;
    let public = id(&client, "client_id")?;
    let path = format!("/clients/{public}/secrets");
    for role in ["readonly", "admin"] {
        let user = insert_active_user(&f.db.pool, &format!("{role}@credential.test")).await?;
        insert_member_role(&f.db.pool, f.org, user, role).await?;
        let token = insert_session(&f.db.pool, user).await?;
        assert_eq!(f.call("GET", &path, &token, None).await?.0, StatusCode::OK);
        let status = f.call("POST", &path, &token, Some(json!({}))).await?.0;
        assert_eq!(
            status,
            if role == "admin" {
                StatusCode::CREATED
            } else {
                StatusCode::NOT_FOUND
            }
        );
        sqlx::query("UPDATE org_memberships SET status='suspended' WHERE user_id=$1 AND org_id=$2")
            .bind(user)
            .bind(f.org)
            .execute(&f.db.pool)
            .await?;
        assert_eq!(
            f.call("GET", &path, &token, None).await?.0,
            StatusCode::NOT_FOUND
        );
    }
    let outsider = insert_active_user(&f.db.pool, "outsider@credential.test").await?;
    let token = insert_session(&f.db.pool, outsider).await?;
    assert_eq!(
        f.call("POST", &path, &token, Some(json!({}))).await?.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        f.call("GET", &path, "", None).await?.0,
        StatusCode::UNAUTHORIZED
    );
    let (_, public_client) = f
        .call(
            "POST",
            "/clients",
            &f.token,
            Some(json!({"name":"public","client_type":"public"})),
        )
        .await?;
    assert_eq!(
        f.call(
            "POST",
            &format!("/clients/{}/secrets", id(&public_client, "client_id")?),
            &f.token,
            Some(json!({}))
        )
        .await?
        .0,
        StatusCode::BAD_REQUEST
    );
    let (_, metadata) = f.call("GET", &path, &f.token, None).await?;
    let secret = id(
        metadata.get(0).context("missing credential metadata")?,
        "id",
    )?;
    let foreign = id(&f.client("foreign").await?, "client_id")?;
    assert_eq!(
        f.call(
            "DELETE",
            &format!("/clients/{foreign}/secrets/{secret}"),
            &f.token,
            None
        )
        .await?
        .0,
        StatusCode::NOT_FOUND
    );
    f.call(
        "PATCH",
        &format!("/clients/{public}"),
        &f.token,
        Some(json!({"disabled":true})),
    )
    .await?;
    assert_eq!(
        f.call("POST", &path, &f.token, Some(json!({}))).await?.0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        f.call("DELETE", &format!("{path}/{secret}"), &f.token, None)
            .await?
            .0,
        StatusCode::NO_CONTENT
    );
    f.call("DELETE", &format!("/clients/{public}"), &f.token, None)
        .await?;
    assert_eq!(
        f.call("GET", &path, &f.token, None).await?.0,
        StatusCode::NOT_FOUND
    );
    Ok(())
}

#[tokio::test]
async fn oauth_credentials_reject_unknown_fields_origins_and_cache_disclosure() -> Result<()> {
    let Some(f) = Fixture::new().await? else {
        return Ok(());
    };
    let client = id(&f.client("http").await?, "client_id")?;
    let path = format!("{}/clients/{client}/secrets", f.base);
    for (origin, body, expected) in [
        ("https://attacker.test", "{}", StatusCode::FORBIDDEN),
        ("null", "{}", StatusCode::FORBIDDEN),
        (
            "https://permesi.dev",
            "{\"client_secret\":\"injected\"}",
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
        ("https://permesi.dev", "{}", StatusCode::CREATED),
    ] {
        let response = f
            .router
            .clone()
            .oneshot(
                Request::post(&path)
                    .header(COOKIE, format!("permesi_session={}", f.token))
                    .header(CONTENT_TYPE, "application/json")
                    .header("origin", origin)
                    .body(Body::from(body))?,
            )
            .await?;
        assert_eq!(response.status(), expected);
        assert_eq!(
            response
                .headers()
                .get("cache-control")
                .context("missing cache policy")?,
            "no-store"
        );
    }
    let response = f
        .router
        .clone()
        .oneshot(
            Request::post(&path)
                .header(COOKIE, format!("permesi_session={}", f.token))
                .header(CONTENT_TYPE, "application/json")
                .header("sec-fetch-site", "cross-site")
                .body(Body::from("{}"))?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    Ok(())
}

#[tokio::test]
async fn oauth_credentials_database_protects_hash_identity_expiry_and_revocation() -> Result<()> {
    let Some(f) = Fixture::new().await? else {
        return Ok(());
    };
    let client = id(&f.client("constraints").await?, "client_id")?;
    let path = format!("/clients/{client}/secrets");
    let (_, issued) = f.call("POST", &path, &f.token, Some(json!({}))).await?;
    let secret = id(field(&issued, "credential")?, "id")?;
    for query in [
        "UPDATE oauth_client_secrets SET secret_hash='$argon2id$changed' WHERE id=$1",
        "UPDATE oauth_client_secrets SET created_at=clock_timestamp() WHERE id=$1",
        "UPDATE oauth_client_secrets SET client_id=uuidv4() WHERE id=$1",
    ] {
        assert!(
            sqlx::query(query)
                .bind(secret)
                .execute(&f.db.pool)
                .await
                .is_err()
        );
    }
    assert!(sqlx::query("UPDATE oauth_client_secrets SET expires_at=clock_timestamp()+INTERVAL '100 years' WHERE id=$1").bind(secret).execute(&f.db.pool).await.is_err());
    sqlx::query("UPDATE oauth_client_secrets SET expires_at=clock_timestamp()+INTERVAL '1 hour' WHERE id=$1").bind(secret).execute(&f.db.pool).await?;
    for query in [
        "UPDATE oauth_client_secrets SET expires_at=NULL WHERE id=$1",
        "UPDATE oauth_client_secrets SET expires_at=clock_timestamp()+INTERVAL '2 hours' WHERE id=$1",
    ] {
        assert!(
            sqlx::query(query)
                .bind(secret)
                .execute(&f.db.pool)
                .await
                .is_err()
        );
    }
    f.call("DELETE", &format!("{path}/{secret}"), &f.token, None)
        .await?;
    assert!(
        sqlx::query("UPDATE oauth_client_secrets SET revoked_at=NULL WHERE id=$1")
            .bind(secret)
            .execute(&f.db.pool)
            .await
            .is_err()
    );
    Ok(())
}

/// Reads an expected JSON field without indexing panics or secret-bearing diagnostics.
fn field<'a>(value: &'a Value, name: &str) -> Result<&'a Value> {
    value.get(name).context("missing response field")
}

#[tokio::test]
async fn oauth_credentials_revalidate_each_ancestor_and_reject_other_organization_paths()
-> Result<()> {
    let Some(f) = Fixture::new().await? else {
        return Ok(());
    };
    let client = id(&f.client("ancestry").await?, "client_id")?;
    let suffix = format!("/clients/{client}/secrets");
    let (_, issued) = f.call("POST", &suffix, &f.token, Some(json!({}))).await?;
    let other = create_org_with_roles(&f.db.pool, f.owner, "Other", "other-org")
        .await
        .map_err(|_| anyhow::anyhow!("other org setup"))?;
    insert_application(&f.db.pool, Uuid::parse_str(&other.id)?).await?;
    let wrong = f.base.replace("oauth-org", "other-org");
    assert_eq!(
        request(
            &f.router,
            "GET",
            &format!("{wrong}{suffix}"),
            &f.token,
            None
        )
        .await?
        .0,
        StatusCode::NOT_FOUND
    );
    for (disable, restore, id) in [
        (
            "UPDATE applications SET deleted_at=NOW() WHERE id=$1",
            "UPDATE applications SET deleted_at=NULL WHERE id=$1",
            f.application,
        ),
        (
            "UPDATE environments SET deleted_at=NOW() WHERE id=$1",
            "UPDATE environments SET deleted_at=NULL WHERE id=$1",
            f.environment,
        ),
        (
            "UPDATE projects SET deleted_at=NOW() WHERE id=$1",
            "UPDATE projects SET deleted_at=NULL WHERE id=$1",
            f.project,
        ),
        (
            "UPDATE organizations SET deleted_at=NOW() WHERE id=$1",
            "UPDATE organizations SET deleted_at=NULL WHERE id=$1",
            f.org,
        ),
    ] {
        sqlx::query(disable).bind(id).execute(&f.db.pool).await?;
        assert!(!verify(&f.db.pool, client, raw(&issued)?).await?);
        assert_eq!(
            f.call("GET", &suffix, &f.token, None).await?.0,
            StatusCode::NOT_FOUND
        );
        sqlx::query(restore).bind(id).execute(&f.db.pool).await?;
        assert!(verify(&f.db.pool, client, raw(&issued)?).await?);
    }
    Ok(())
}

#[tokio::test]
async fn oauth_credentials_authentication_locks_authority_until_transaction_finishes() -> Result<()>
{
    let Some(f) = Fixture::new().await? else {
        return Ok(());
    };
    let client = id(&f.client("transaction").await?, "client_id")?;
    let context = ApplicationContext::resolved(f.application, f.owner);
    let a = CredentialService::new(CredentialConfig::for_tests());
    let issued = a.issue(&f.db.pool, &context, client, None).await?;
    let b = CredentialService::new(CredentialConfig::for_tests());
    let mut tx = f.db.pool.begin().await?;
    a.authenticate(&mut tx, client, issued.client_secret.expose_secret())
        .await?;
    let revoke = b.revoke(&f.db.pool, &context, client, issued.credential.id);
    tokio::pin!(revoke);
    assert!(
        timeout(Duration::from_millis(50), &mut revoke)
            .await
            .is_err()
    );
    tx.rollback().await?;
    revoke.await?;
    assert!(!verify(&f.db.pool, client, issued.client_secret.expose_secret()).await?);
    Ok(())
}

#[tokio::test]
async fn oauth_credentials_mutation_budgets_are_shared_and_separate_from_login() -> Result<()> {
    use crate::api::handlers::auth::{
        RateLimitAction, RateLimitConfig, RateLimitDecision, RateLimiter, SubjectKey,
    };
    let Some(f) = Fixture::new().await? else {
        return Ok(());
    };
    let make = || -> Result<RateLimiter> {
        Ok(RateLimiter::postgres(
            f.db.pool.clone(),
            RateLimitConfig::new(60, 10, 1),
            SubjectKey::derive(&[9; 32])?,
        ))
    };
    let a = make()?;
    let b = make()?;
    let subject = format!("oauth-credential-management/{}/{}", f.owner, Uuid::new_v4());
    assert_eq!(
        a.check_email(&subject, RateLimitAction::ClientCredentials)
            .await,
        RateLimitDecision::Allowed
    );
    assert_eq!(
        b.check_email(&subject, RateLimitAction::ClientCredentials)
            .await,
        RateLimitDecision::Limited
    );
    assert_eq!(
        b.check_email(&subject, RateLimitAction::Login).await,
        RateLimitDecision::Allowed
    );
    let count:i64=sqlx::query_scalar("SELECT count(*) FROM auth_rate_limits WHERE action='client_credentials_management' AND octet_length(subject_hash)=32 AND attempts=2").fetch_one(&f.db.pool).await?;
    assert_eq!(count, 1);
    Ok(())
}

#[tokio::test]
async fn oauth_credentials_schema_reapplication_and_repository_verification_pass() -> Result<()> {
    let Some(f) = Fixture::new().await? else {
        return Ok(());
    };
    let client = id(&f.client("reapply").await?, "client_id")?;
    let (_, issued) = f
        .call(
            "POST",
            &format!("/clients/{client}/secrets"),
            &f.token,
            Some(json!({})),
        )
        .await?;
    sqlx::query("DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='permesi_runtime') THEN CREATE ROLE permesi_runtime NOLOGIN; END IF; END $$").execute(&f.db.pool).await?;
    let mut connection = f.db.pool.acquire().await?;
    test_support::sql::execute_script(
        &mut connection,
        "02_permesi.sql",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../db/sql/02_permesi.sql"
        )),
    )
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
    let mut tx = f.db.pool.begin().await?;
    sqlx::query("SET LOCAL ROLE permesi_runtime")
        .execute(&mut *tx)
        .await?;
    let error = sqlx::query("DELETE FROM oauth_client_secrets")
        .execute(&mut *tx)
        .await
        .err()
        .context("runtime deletion permitted")?;
    assert_eq!(
        error
            .as_database_error()
            .and_then(sqlx::error::DatabaseError::code)
            .as_deref(),
        Some("42501")
    );
    tx.rollback().await?;
    assert!(verify(&f.db.pool, client, raw(&issued)?).await?);
    Ok(())
}

#[tokio::test]
async fn oauth_credentials_failed_rotation_rolls_back_retirement() -> Result<()> {
    let Some(f) = Fixture::new().await? else {
        return Ok(());
    };
    let client = id(&f.client("rollback").await?, "client_id")?;
    let path = format!("/clients/{client}/secrets");
    let (_, issued) = f.call("POST", &path, &f.token, Some(json!({}))).await?;
    let current = id(field(&issued, "credential")?, "id")?;
    let mut connection = f.db.pool.acquire().await?;
    test_support::sql::execute_script(&mut connection,"reject test issuance", "CREATE FUNCTION reject_test_credential() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='injected persistence failure'; END $$; CREATE TRIGGER reject_test_credential BEFORE INSERT ON oauth_client_secrets FOR EACH ROW EXECUTE FUNCTION reject_test_credential();").await?;
    drop(connection);
    assert_eq!(
        f.call(
            "POST",
            &format!("{path}/rotate"),
            &f.token,
            Some(json!({"current_secret_id":current}))
        )
        .await?
        .0,
        StatusCode::INTERNAL_SERVER_ERROR
    );
    let expiry: Option<chrono::DateTime<chrono::Utc>> =
        sqlx::query_scalar("SELECT expires_at FROM oauth_client_secrets WHERE id=$1")
            .bind(current)
            .fetch_one(&f.db.pool)
            .await?;
    assert!(
        expiry.is_none(),
        "Failed persistence must roll back the retirement deadline"
    );
    assert!(verify(&f.db.pool, client, raw(&issued)?).await?);
    Ok(())
}

/// A tenant blocked in PostgreSQL must not reserve another tenant's hashing capacity.
#[tokio::test]
async fn oauth_credentials_database_waits_do_not_reserve_hash_workers() -> Result<()> {
    let Some(f) = Fixture::new().await? else {
        return Ok(());
    };
    let client_a = id(&f.client("blocked").await?, "client_id")?;
    let client_b = id(&f.client("unblocked").await?, "client_id")?;
    let application = f.application;
    let owner = f.owner;
    let service = CredentialService::new(CredentialConfig::for_tests());
    let mut blocker = f.db.pool.begin().await?;
    sqlx::query("SELECT id FROM oauth_clients WHERE client_id=$1 FOR UPDATE")
        .bind(client_a)
        .execute(&mut *blocker)
        .await?;
    let pool = f.db.pool.clone();
    let a = service.clone();
    let first = tokio::spawn(async move {
        a.issue(
            &pool,
            &ApplicationContext::resolved(application, owner),
            client_a,
            None,
        )
        .await
    });
    let pool = f.db.pool.clone();
    let a = service.clone();
    let second = tokio::spawn(async move {
        a.issue(
            &pool,
            &ApplicationContext::resolved(application, owner),
            client_a,
            None,
        )
        .await
    });
    timeout(Duration::from_secs(2), async {
        loop {
            let waiting:i64=sqlx::query_scalar("SELECT count(*) FROM pg_locks l JOIN pg_stat_activity a ON a.pid=l.pid WHERE a.datname=current_database() AND NOT l.granted").fetch_one(&f.db.pool).await?;
            if waiting >= 2 { break; }
            sleep(Duration::from_millis(10)).await;
        }
        Ok::<_,sqlx::Error>(())
    }).await??;
    let result = service
        .issue(
            &f.db.pool,
            &ApplicationContext::resolved(f.application, f.owner),
            client_b,
            None,
        )
        .await;
    blocker.rollback().await?;
    let _ = first.await?;
    let _ = second.await?;
    assert!(
        result.is_ok(),
        "Unrelated client must retain hashing capacity"
    );
    Ok(())
}

/// Recovery revocation has an independent shared budget from issuance failures.
#[tokio::test]
async fn oauth_credentials_http_revocation_survives_exhausted_issuance_budget() -> Result<()> {
    use crate::api::handlers::auth::{
        AuthConfig, AuthState, OpaqueState, RateLimitConfig, RateLimiter, SubjectKey,
        mfa::MfaConfig,
    };
    use std::sync::Arc;
    let Some(mut f) = Fixture::new().await? else {
        return Ok(());
    };
    let client = id(&f.client("http-budget").await?, "client_id")?;
    let mut state = AppState::for_tests(f.db.pool.clone())?;
    state.auth = Arc::new(AuthState::new(
        AuthConfig::new("https://permesi.dev".to_owned()),
        OpaqueState::from_seed(
            [1; 32],
            "api.permesi.dev".to_owned(),
            Duration::from_secs(30),
            10_000,
        ),
        Arc::new(RateLimiter::postgres(
            f.db.pool.clone(),
            RateLimitConfig::new(60, 10, 1),
            SubjectKey::derive(&[9; 32])?,
        )),
        MfaConfig::new(),
    ));
    let (router, _) = crate::api::router().split_for_parts();
    f.router = router.with_state(state);
    let path = format!("/clients/{client}/secrets");
    assert_eq!(
        f.call(
            "POST",
            &format!("/clients/{}/secrets", Uuid::new_v4()),
            &f.token,
            Some(json!({}))
        )
        .await?
        .0,
        StatusCode::NOT_FOUND
    );
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM auth_rate_limits")
        .fetch_one(&f.db.pool)
        .await?;
    assert_eq!(count, 0);
    let (status, issued) = f.call("POST", &path, &f.token, Some(json!({}))).await?;
    assert_eq!(status, StatusCode::CREATED);
    let secret = id(field(&issued, "credential")?, "id")?;
    assert_eq!(
        f.call(
            "POST",
            &format!("{path}/rotate"),
            &f.token,
            Some(json!({"current_secret_id":secret}))
        )
        .await?
        .0,
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(
        f.call("DELETE", &format!("{path}/{secret}"), &f.token, None)
            .await?
            .0,
        StatusCode::NO_CONTENT
    );
    assert!(!verify(&f.db.pool, client, raw(&issued)?).await?);
    Ok(())
}

/// A queued lifecycle writer cannot be bypassed by a later authentication reader.
#[tokio::test]
async fn oauth_credentials_queued_revocation_precedes_new_authentication() -> Result<()> {
    let Some(f) = Fixture::new().await? else {
        return Ok(());
    };
    let client = id(&f.client("fair-locks").await?, "client_id")?;
    let context = ApplicationContext::resolved(f.application, f.owner);
    let service = CredentialService::new(CredentialConfig::for_tests());
    let issued = service.issue(&f.db.pool, &context, client, None).await?;
    let mut holder = f.db.pool.begin().await?;
    service
        .authenticate(&mut holder, client, issued.client_secret.expose_secret())
        .await?;
    let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(2));
    let mut reader = CredentialService::new(CredentialConfig::for_tests());
    reader.after_verification = Some(barrier.clone());
    let mut later = f.db.pool.begin().await?;
    let authentication =
        reader.authenticate(&mut later, client, issued.client_secret.expose_secret());
    tokio::pin!(authentication);
    // Finish hashing before the writer queues, but acquire no authority locks yet.
    tokio::select! {
        _ = &mut authentication => anyhow::bail!("Authentication bypassed the test checkpoint"),
        _ = barrier.wait() => {}
    }
    let pool = f.db.pool.clone();
    let writer = service.clone();
    let secret = issued.credential.id;
    let revocation =
        tokio::spawn(async move { writer.revoke(&pool, &context, client, secret).await });
    timeout(Duration::from_secs(2),async {
        loop {
            let waiting:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_locks l JOIN pg_stat_activity a ON a.pid=l.pid WHERE a.datname=current_database() AND l.locktype='advisory' AND NOT l.granted)").fetch_one(&f.db.pool).await?;
            if waiting {break;}
            sleep(Duration::from_millis(10)).await;
        }
        Ok::<_,sqlx::Error>(())
    }).await??;
    barrier.wait().await;
    assert!(
        timeout(Duration::from_millis(100), &mut authentication)
            .await
            .is_err()
    );
    holder.rollback().await?;
    timeout(Duration::from_millis(1000), revocation).await???;
    assert!(matches!(
        authentication.await,
        Err(CredentialError::InvalidCredentials)
    ));
    Ok(())
}

/// Stale preflight authorization never survives a role removal before persistence.
#[tokio::test]
async fn oauth_credentials_recheck_roles_after_preflight() -> Result<()> {
    let Some(f) = Fixture::new().await? else {
        return Ok(());
    };
    let client = id(&f.client("preflight-role").await?, "client_id")?;
    let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(2));
    let mut service = CredentialService::new(CredentialConfig::for_tests());
    service.after_preflight = Some(barrier.clone());
    let context = ApplicationContext::resolved(f.application, f.owner);
    let (result, ()) = tokio::join!(service.issue(&f.db.pool, &context, client, None), async {
        barrier.wait().await;
        // Removal commits while preflight has released its authority locks.
        let result = sqlx::query("DELETE FROM org_member_roles WHERE org_id=$1 AND user_id=$2")
            .bind(f.org)
            .bind(f.owner)
            .execute(&f.db.pool)
            .await;
        barrier.wait().await;
        assert!(result.is_ok());
    });
    assert!(matches!(result, Err(CredentialError::NotFound)));
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM oauth_client_secrets")
        .fetch_one(&f.db.pool)
        .await?;
    assert_eq!(count, 0);
    Ok(())
}

/// Candidate lookup is not authentication; expiry/revocation must be reloaded after hashing.
#[tokio::test]
async fn oauth_credentials_recheck_candidate_revocation_expiry_and_client_disable() -> Result<()> {
    let Some(f) = Fixture::new().await? else {
        return Ok(());
    };
    for (name, query) in [
        (
            "candidate-revoke",
            "UPDATE oauth_client_secrets SET revoked_at=clock_timestamp() WHERE id=$1",
        ),
        (
            "candidate-expire",
            "UPDATE oauth_client_secrets SET expires_at=clock_timestamp()-INTERVAL '1 second' WHERE id=$1",
        ),
        (
            "candidate-disable",
            "UPDATE oauth_clients SET disabled_at=clock_timestamp() WHERE client_id=$1",
        ),
    ] {
        let client = id(&f.client(name).await?, "client_id")?;
        let context = ApplicationContext::resolved(f.application, f.owner);
        let mut service = CredentialService::new(CredentialConfig::for_tests());
        let issued = service.issue(&f.db.pool, &context, client, None).await?;
        let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(2));
        service.after_verification = Some(barrier.clone());
        let mut tx = f.db.pool.begin().await?;
        let (result, ()) = tokio::join!(
            service.authenticate(&mut tx, client, issued.client_secret.expose_secret()),
            async {
                barrier.wait().await;
                let target = if name == "candidate-disable" {
                    client
                } else {
                    issued.credential.id
                };
                let result = sqlx::query(query).bind(target).execute(&f.db.pool).await;
                barrier.wait().await;
                assert!(result.is_ok());
            }
        );
        assert!(matches!(result, Err(CredentialError::InvalidCredentials)));
        tx.rollback().await?;
    }
    Ok(())
}

/// Direct writes cannot forge initial state or expand the bounded overlap.
#[tokio::test]
async fn oauth_credentials_database_rejects_initial_state_and_second_overlap() -> Result<()> {
    let Some(f) = Fixture::new().await? else {
        return Ok(());
    };
    let registration = f.client("insert-guards").await?;
    let client = id(&registration, "client_id")?;
    let internal = id(&registration, "id")?;
    for query in [
        "INSERT INTO oauth_client_secrets(client_id,secret_hash,revoked_at) VALUES($1,'$argon2id$stub',clock_timestamp())",
        "INSERT INTO oauth_client_secrets(client_id,secret_hash,expires_at) VALUES($1,'$argon2id$stub',clock_timestamp()+INTERVAL '100 years')",
    ] {
        let error = sqlx::query(query)
            .bind(internal)
            .execute(&f.db.pool)
            .await
            .err()
            .context("forged initial state accepted")?;
        assert_eq!(
            error
                .as_database_error()
                .and_then(sqlx::error::DatabaseError::code)
                .as_deref(),
            Some("23514")
        );
    }
    let path = format!("/clients/{client}/secrets");
    let (_, first) = f.call("POST", &path, &f.token, Some(json!({}))).await?;
    let first_id = id(field(&first, "credential")?, "id")?;
    let (_, second) = f
        .call(
            "POST",
            &format!("{path}/rotate"),
            &f.token,
            Some(json!({"current_secret_id":first_id})),
        )
        .await?;
    let current = id(field(&second, "credential")?, "id")?;
    let error=sqlx::query("UPDATE oauth_client_secrets SET expires_at=clock_timestamp()+INTERVAL '10 minutes' WHERE id=$1").bind(current).execute(&f.db.pool).await.err().context("second overlap accepted")?;
    assert_eq!(
        error
            .as_database_error()
            .and_then(sqlx::error::DatabaseError::code)
            .as_deref(),
        Some("23514")
    );
    let error = sqlx::query(
        "INSERT INTO oauth_client_secrets(client_id,secret_hash) VALUES($1,'$argon2id$stub')",
    )
    .bind(internal)
    .execute(&f.db.pool)
    .await
    .err()
    .context("second current accepted")?;
    assert_eq!(
        error
            .as_database_error()
            .and_then(sqlx::error::DatabaseError::code)
            .as_deref(),
        Some("23505")
    );
    // Physical client cleanup by the schema owner continues to cascade credential rows.
    sqlx::query("DELETE FROM oauth_clients WHERE id=$1")
        .bind(internal)
        .execute(&f.db.pool)
        .await?;
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM oauth_client_secrets WHERE client_id=$1")
            .bind(internal)
            .fetch_one(&f.db.pool)
            .await?;
    assert_eq!(count, 0);
    // The insert trigger assigns creation time, including for backdated direct inserts.
    let next = id(&f.client("fresh-timestamp").await?, "id")?;
    let fresh:bool=sqlx::query_scalar("INSERT INTO oauth_client_secrets(client_id,secret_hash,created_at) VALUES($1,'$argon2id$stub',clock_timestamp()-INTERVAL '100 years') RETURNING created_at>clock_timestamp()-INTERVAL '1 minute'").bind(next).fetch_one(&f.db.pool).await?;
    assert!(fresh);
    Ok(())
}

/// Saturation rejects real verification promptly, while metadata remains independent of hashing.
#[tokio::test]
async fn oauth_credentials_authentication_saturation_and_statement_timeout_fail_closed()
-> Result<()> {
    let Some(f) = Fixture::new().await? else {
        return Ok(());
    };
    let client = id(&f.client("capacity").await?, "client_id")?;
    let context = ApplicationContext::resolved(f.application, f.owner);
    let service = CredentialService::new(CredentialConfig::for_tests());
    let issued = service.issue(&f.db.pool, &context, client, None).await?;
    let _capacity = service.saturate_for_test()?;
    let mut tx = f.db.pool.begin().await?;
    assert!(matches!(
        service
            .authenticate(&mut tx, client, issued.client_secret.expose_secret())
            .await,
        Err(CredentialError::Unavailable)
    ));
    // The helper's configured statement deadline stays local to the caller transaction.
    let error = timeout(
        Duration::from_millis(1600),
        sqlx::query("SELECT pg_sleep(2)").execute(&mut *tx),
    )
    .await?
    .err()
    .context("statement timeout absent")?;
    assert_eq!(
        error
            .as_database_error()
            .and_then(sqlx::error::DatabaseError::code)
            .as_deref(),
        Some("57014")
    );
    tx.rollback().await?;
    assert_eq!(service.list(&f.db.pool, &context, client).await?.len(), 1);
    Ok(())
}

/// Foreign tenant paths must fail before joining the victim client's global lock queue.
#[tokio::test]
async fn oauth_credentials_foreign_management_never_queues_client_locks() -> Result<()> {
    let Some(f) = Fixture::new().await? else {
        return Ok(());
    };
    let client = id(&f.client("foreign-lock-victim").await?, "client_id")?;
    let owner = insert_active_user(&f.db.pool, "foreign-owner@example.com").await?;
    let token = insert_session(&f.db.pool, owner).await?;
    let org = create_org_with_roles(&f.db.pool, owner, "Foreign", "foreign-lock-org")
        .await
        .map_err(|_| anyhow::anyhow!("foreign org setup"))?;
    let (_, _, application) = insert_application(&f.db.pool, Uuid::parse_str(&org.id)?).await?;
    let foreign = f
        .base
        .replace("oauth-org", "foreign-lock-org")
        .replace(&f.application.to_string(), &application.to_string());
    let service = CredentialService::new(CredentialConfig::for_tests());
    let issued = service
        .issue(
            &f.db.pool,
            &ApplicationContext::resolved(f.application, f.owner),
            client,
            None,
        )
        .await?;
    let mut holder = f.db.pool.begin().await?;
    service
        .authenticate(&mut holder, client, issued.client_secret.expose_secret())
        .await?;
    let operations = [
        ("PATCH", "", Some(json!({"name":"forbidden"}))),
        ("DELETE", "", None),
        (
            "PUT",
            "/redirect-uris",
            Some(json!({"redirect_uris":["https://example.com/callback"]})),
        ),
        ("PUT", "/scopes", Some(json!({"scopes":["openid"]}))),
    ];
    let mut statuses = Vec::new();
    for (method, suffix, payload) in operations {
        let status = timeout(
            Duration::from_millis(250),
            request(
                &f.router,
                method,
                &format!("{foreign}/clients/{client}{suffix}"),
                &token,
                payload,
            ),
        )
        .await;
        if status.is_err() {
            holder.rollback().await?;
            anyhow::bail!("Foreign writer waited on victim client");
        }
        statuses.push(status);
    }
    let wrong = ApplicationContext::resolved(application, owner);
    let direct = timeout(
        Duration::from_millis(250),
        service.issue(&f.db.pool, &wrong, client, None),
    )
    .await;
    let queued:i64=sqlx::query_scalar("SELECT count(*) FROM pg_locks l JOIN pg_stat_activity a ON a.pid=l.pid WHERE a.datname=current_database() AND l.locktype='advisory' AND NOT l.granted").fetch_one(&f.db.pool).await?;
    // Legitimate readers remain usable while the first replica holds its transaction.
    let valid = verify(&f.db.pool, client, issued.client_secret.expose_secret()).await?;
    holder.rollback().await?;
    for status in statuses {
        assert_eq!(
            status.context("Foreign writer waited on victim")??.0,
            StatusCode::NOT_FOUND
        );
    }
    assert!(matches!(direct, Ok(Err(CredentialError::NotFound))));
    assert_eq!(queued, 0);
    assert!(valid);
    Ok(())
}

/// All existing client writer routes obey operator deadlines and leave state unchanged.
#[tokio::test]
async fn oauth_credentials_client_management_deadlines_return_service_unavailable() -> Result<()> {
    let Some(mut f) = Fixture::new().await? else {
        return Ok(());
    };
    let client = id(&f.client("bounded-writers").await?, "client_id")?;
    let service = CredentialService::new(CredentialConfig::for_tests());
    let issued = service
        .issue(
            &f.db.pool,
            &ApplicationContext::resolved(f.application, f.owner),
            client,
            None,
        )
        .await?;
    let mut state = AppState::for_tests(f.db.pool.clone())?;
    std::sync::Arc::make_mut(&mut state.oauth)
        .config
        .lock_timeout_ms = 50;
    f.router = crate::api::router().split_for_parts().0.with_state(state);
    let mut holder = f.db.pool.begin().await?;
    service
        .authenticate(&mut holder, client, issued.client_secret.expose_secret())
        .await?;
    let operations = [
        ("PATCH", "", Some(json!({"disabled":true}))),
        ("DELETE", "", None),
        (
            "PUT",
            "/redirect-uris",
            Some(json!({"redirect_uris":["https://example.com/changed"]})),
        ),
        ("PUT", "/scopes", Some(json!({"scopes":[]}))),
    ];
    let mut statuses = Vec::new();
    for (method, suffix, payload) in operations {
        // The database deadline stays 50 ms. This outer watchdog also includes
        // session extraction and CI/coverage scheduling; without a database
        // deadline the held transaction prevents completion for its entire span.
        let status = timeout(
            Duration::from_secs(5),
            f.call(
                method,
                &format!("/clients/{client}{suffix}"),
                &f.token,
                payload,
            ),
        )
        .await;
        if status.is_err() {
            holder.rollback().await?;
            anyhow::bail!("Client writer deadline absent");
        }
        statuses.push(status);
    }
    holder.rollback().await?;
    for status in statuses {
        assert_eq!(
            status.context("Client writer deadline absent")??.0,
            StatusCode::SERVICE_UNAVAILABLE
        );
    }
    assert!(verify(&f.db.pool, client, issued.client_secret.expose_secret()).await?);
    let (_, registration) = f
        .call("GET", &format!("/clients/{client}"), &f.token, None)
        .await?;
    assert_eq!(
        registration.get("name").and_then(Value::as_str),
        Some("bounded-writers")
    );
    assert_eq!(
        f.call(
            "GET",
            &format!("/clients/{client}/redirect-uris"),
            &f.token,
            None
        )
        .await?
        .1,
        json!(["https://example.com/callback"])
    );
    assert_eq!(
        f.call("GET", &format!("/clients/{client}/scopes"), &f.token, None)
            .await?
            .1,
        json!(["openid"])
    );
    Ok(())
}

/// Bounded coordination must not cancel successful bulk consent revocation work.
#[tokio::test]
async fn oauth_credentials_bulk_revocation_outlives_coordination_deadline() -> Result<()> {
    let Some(mut f) = Fixture::new().await? else {
        return Ok(());
    };
    let mut state = AppState::for_tests(f.db.pool.clone())?;
    std::sync::Arc::make_mut(&mut state.oauth)
        .config
        .lock_timeout_ms = 50;
    f.router = crate::api::router().split_for_parts().0.with_state(state);
    let mut connection = f.db.pool.acquire().await?;
    // Model bulk work beyond the coordination budget, without host-speed-dependent row counts.
    test_support::sql::execute_script(&mut connection,"slow revocation test", "CREATE FUNCTION slow_test_grant_revocation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(0.15); RETURN NEW; END $$; CREATE TRIGGER slow_test_grant_revocation BEFORE UPDATE ON oauth_grants FOR EACH ROW EXECUTE FUNCTION slow_test_grant_revocation();").await?;
    drop(connection);
    for operation in ["disable", "delete", "redirects", "scopes"] {
        let registration = f.client(&format!("bulk-{operation}")).await?;
        let client = id(&registration, "client_id")?;
        let internal = id(&registration, "id")?;
        let grant:Uuid=sqlx::query_scalar("INSERT INTO oauth_grants(user_id,client_id,application_id,organization_id) VALUES($1,$2,$3,$4) RETURNING id").bind(f.owner).bind(internal).bind(f.application).bind(f.org).fetch_one(&f.db.pool).await?;
        let (_, issued) = f
            .call(
                "POST",
                &format!("/clients/{client}/secrets"),
                &f.token,
                Some(json!({})),
            )
            .await?;
        let (method, suffix, payload, expected) = match operation {
            "delete" => ("DELETE", "", None, StatusCode::NO_CONTENT),
            "redirects" => (
                "PUT",
                "/redirect-uris",
                Some(json!({"redirect_uris":["https://example.com/changed"]})),
                StatusCode::OK,
            ),
            "scopes" => ("PUT", "/scopes", Some(json!({"scopes":[]})), StatusCode::OK),
            _ => ("PATCH", "", Some(json!({"disabled":true})), StatusCode::OK),
        };
        let result = timeout(
            Duration::from_secs(2),
            f.call(
                method,
                &format!("/clients/{client}{suffix}"),
                &f.token,
                payload,
            ),
        )
        .await??;
        assert_eq!(result.0, expected);
        let revoked: bool =
            sqlx::query_scalar("SELECT revoked_at IS NOT NULL FROM oauth_grants WHERE id=$1")
                .bind(grant)
                .fetch_one(&f.db.pool)
                .await?;
        assert!(revoked);
        assert_eq!(
            verify(&f.db.pool, client, raw(&issued)?).await?,
            matches!(operation, "redirects" | "scopes")
        );
    }
    Ok(())
}
