//! PostgreSQL regressions for password/session lifecycle ordering and rollback.
use super::*;
use crate::api::handlers::auth::{
    authority_guard::{AuthorityGuard, Policy},
    storage,
};

async fn user(pool: &PgPool) -> Result<Uuid> {
    Ok(sqlx::query_scalar("INSERT INTO users (email,opaque_registration_record,status) VALUES ($1,$2,'active') RETURNING id").bind(format!("{}@example.com",Uuid::new_v4())).bind(vec![1u8;32]).fetch_one(pool).await?)
}

fn headers(token: &str) -> Result<axum::http::HeaderMap> {
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(COOKIE, format!("permesi_session={token}").parse()?);
    Ok(headers)
}

#[tokio::test]
async fn password_rotation_revokes_full_and_both_limited_sessions_and_ceremonies() -> Result<()> {
    let Some(db) = TestDb::new().await? else {
        return Ok(());
    };
    let user = user(&db.pool).await?;
    let full = storage::insert_session(&db.pool, user, 300).await?;
    let bootstrap = storage::insert_mfa_bootstrap_session(&db.pool, user, 300).await?;
    let challenge = storage::insert_mfa_challenge_session(&db.pool, user, 300).await?;
    for (token, policy) in [
        (&full, Policy::Full),
        (&bootstrap, Policy::Enrollment),
        (&challenge, Policy::Challenge),
    ] {
        AuthorityGuard::acquire(&db.pool, &headers(token)?, user, policy, 1000)
            .await
            .map_err(|_| anyhow!("valid authority"))?
            .commit()
            .await?;
    }
    sqlx::query("INSERT INTO webauthn_exchanges (id_hash,purpose,origin,rp_id,user_id,session_hash,sealed_state,created_at,expires_at) VALUES ($1,'security_key_authentication','https://example.com','example.com',$2,$3,$4,NOW(),NOW()+INTERVAL '5 minutes')").bind(vec![3u8;32]).bind(user).bind(hash_session_token(&challenge)).bind(vec![0u8;40]).execute(&db.pool).await?;
    assert!(storage::rotate_password_and_clear_sessions(&db.pool, user, &[2; 32]).await?);
    for (token, policy) in [
        (&full, Policy::Full),
        (&bootstrap, Policy::Enrollment),
        (&challenge, Policy::Challenge),
    ] {
        assert!(matches!(
            AuthorityGuard::acquire(&db.pool, &headers(token)?, user, policy, 1000).await,
            Err(StatusCode::UNAUTHORIZED)
        ));
    }
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM webauthn_exchanges WHERE user_id=$1")
            .bind(user)
            .fetch_one(&db.pool)
            .await?,
        0
    );
    Ok(())
}

/// Elevation holds the identity lock before a concurrent password mutation queues.
#[tokio::test]
async fn password_rotation_after_concurrent_elevation_revokes_new_authority() -> Result<()> {
    let Some(db) = TestDb::new().await? else {
        return Ok(());
    };
    let user = user(&db.pool).await?;
    let challenge = storage::insert_mfa_challenge_session(&db.pool, user, 300).await?;
    let mut guard = AuthorityGuard::acquire(
        &db.pool,
        &headers(&challenge)?,
        user,
        Policy::Challenge,
        1000,
    )
    .await
    .map_err(|_| anyhow!("challenge guard"))?;
    let pool = db.pool.clone();
    let rotation = tokio::spawn(async move {
        storage::rotate_password_and_clear_sessions(&pool, user, &[2; 32]).await
    });
    // Observe the real blocked writer, rather than guessing scheduler order with a sleep.
    tokio::time::timeout(Duration::from_secs(5),async {
        loop {
            let waiting: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE 'UPDATE users SET opaque_registration_record%')").fetch_one(&db.pool).await?;
            if waiting {return Ok::<_,anyhow::Error>(());}
            tokio::task::yield_now().await;
        }
    }).await??;
    let full = storage::insert_session_on(guard.connection(), user, 300).await?;
    guard.consume_original().await?;
    guard.commit().await?;
    assert!(rotation.await??);
    assert!(matches!(
        AuthorityGuard::acquire(&db.pool, &headers(&full)?, user, Policy::Full, 1000).await,
        Err(StatusCode::UNAUTHORIZED)
    ));
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM user_sessions WHERE user_id=$1")
            .bind(user)
            .fetch_one(&db.pool)
            .await?,
        0
    );
    Ok(())
}

#[tokio::test]
async fn mfa_authority_consumes_exact_original_and_rolls_back_failed_issuance() -> Result<()> {
    let Some(db) = TestDb::new().await? else {
        return Ok(());
    };
    let user = user(&db.pool).await?;
    let a = storage::insert_mfa_challenge_session(&db.pool, user, 300).await?;
    let b = storage::insert_mfa_challenge_session(&db.pool, user, 300).await?;
    let mut guard = AuthorityGuard::acquire(&db.pool, &headers(&a)?, user, Policy::Challenge, 1000)
        .await
        .map_err(|_| anyhow!("challenge guard"))?;
    storage::insert_session_on(guard.connection(), user, 300).await?;
    guard.consume_original().await?;
    drop(guard); // canceled/failed factor-state transaction cannot publish authority
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM user_sessions WHERE user_id=$1")
            .bind(user)
            .fetch_one(&db.pool)
            .await?,
        0
    );
    let mut guard = AuthorityGuard::acquire(&db.pool, &headers(&a)?, user, Policy::Challenge, 1000)
        .await
        .map_err(|_| anyhow!("rollback preserved challenge"))?;
    guard.consume_original().await?;
    guard.commit().await?;
    assert!(matches!(
        AuthorityGuard::acquire(&db.pool, &headers(&a)?, user, Policy::Challenge, 1000).await,
        Err(StatusCode::UNAUTHORIZED)
    ));
    AuthorityGuard::acquire(&db.pool, &headers(&b)?, user, Policy::Challenge, 1000)
        .await
        .map_err(|_| anyhow!("unrelated challenge survives"))?
        .commit()
        .await?;
    assert!(matches!(
        AuthorityGuard::acquire(&db.pool, &headers(&b)?, user, Policy::Enrollment, 1000).await,
        Err(StatusCode::UNAUTHORIZED)
    ));
    Ok(())
}

/// A revocation failure must roll back both the password revision and every session deletion.
#[tokio::test]
async fn password_rotation_rolls_back_when_limited_revocation_fails() -> Result<()> {
    let Some(db) = TestDb::new().await? else {
        return Ok(());
    };
    let user = user(&db.pool).await?;
    let full = storage::insert_session(&db.pool, user, 300).await?;
    let bootstrap = storage::insert_mfa_bootstrap_session(&db.pool, user, 300).await?;
    sqlx::raw_sql("CREATE FUNCTION reject_bootstrap_revocation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected revocation failure'; END $$; CREATE TRIGGER reject_bootstrap_revocation BEFORE DELETE ON user_mfa_bootstrap_sessions FOR EACH ROW EXECUTE FUNCTION reject_bootstrap_revocation();").execute(&db.pool).await?;
    assert!(
        storage::rotate_password_and_clear_sessions(&db.pool, user, &[2; 32])
            .await
            .is_err()
    );
    assert_eq!(
        sqlx::query_scalar::<_, Vec<u8>>(
            "SELECT opaque_registration_record FROM users WHERE id=$1"
        )
        .bind(user)
        .fetch_one(&db.pool)
        .await?,
        vec![1; 32]
    );
    for (token, policy) in [(&full, Policy::Full), (&bootstrap, Policy::Enrollment)] {
        AuthorityGuard::acquire(&db.pool, &headers(token)?, user, policy, 1000)
            .await
            .map_err(|_| anyhow!("failed rotation must preserve original authority"))?
            .commit()
            .await?;
    }
    Ok(())
}
