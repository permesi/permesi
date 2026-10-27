//! Negative authorization, read-only and active-ancestry regressions on the actual router.

use super::*;

/// Every hierarchy route rechecks trusted operator authority rather than accepting global user roles.
#[tokio::test]
async fn inspection_rejects_nonoperators_and_retired_authority() -> Result<()> {
    let f = Fixture::new().await?;
    let paths = f.foreign.paths("/v1/admin/orgs");
    for role in ["member", "editor", "admin", "owner"] {
        sqlx::query("INSERT INTO user_roles(user_id,role) VALUES($1,$2) ON CONFLICT(user_id) DO UPDATE SET role=$2")
            .bind(f.ordinary).bind(role).execute(&f.db.pool).await?;
        assert_statuses(&f, &f.ordinary_token, &paths, StatusCode::FORBIDDEN).await?;
    }
    assert_statuses(&f, "", &paths, StatusCode::UNAUTHORIZED).await?;
    sqlx::query("UPDATE platform_operators SET enabled=false WHERE user_id=$1")
        .bind(f.operator)
        .execute(&f.db.pool)
        .await?;
    assert_statuses(&f, &f.token, &paths, StatusCode::FORBIDDEN).await?;
    sqlx::query("UPDATE platform_operators SET enabled=true WHERE user_id=$1")
        .bind(f.operator)
        .execute(&f.db.pool)
        .await?;
    sqlx::query("UPDATE users SET status='disabled' WHERE id=$1")
        .bind(f.operator)
        .execute(&f.db.pool)
        .await?;
    assert_statuses(&f, &f.token, &paths, StatusCode::UNAUTHORIZED).await?;
    Ok(())
}

/// Token prefixes remain limited authority even for an enabled operator with a matching stored hash.
#[tokio::test]
async fn inspection_rejects_limited_expired_and_revoked_sessions() -> Result<()> {
    let f = Fixture::new().await?;
    let paths = f.foreign.paths("/v1/admin/orgs");
    for prefix in ["mfa_setup_", "mfa_challenge_"] {
        let token = format!("{prefix}{}", Uuid::new_v4());
        sqlx::query("INSERT INTO user_sessions(user_id,session_hash,expires_at) VALUES($1,$2,NOW()+INTERVAL '1 hour')")
            .bind(f.operator).bind(crate::api::handlers::auth::hash_session_token(&token)).execute(&f.db.pool).await?;
        assert_statuses(&f, &token, &paths, StatusCode::UNAUTHORIZED).await?;
    }
    sqlx::query("UPDATE user_sessions SET created_at=NOW()-INTERVAL '2 hours',auth_time=NOW()-INTERVAL '2 hours',expires_at=NOW()-INTERVAL '1 hour' WHERE user_id=$1")
        .bind(f.operator).execute(&f.db.pool).await?;
    assert_statuses(&f, &f.token, &paths, StatusCode::UNAUTHORIZED).await?;
    let fresh = insert_session(&f.db.pool, f.operator).await?;
    sqlx::query("DELETE FROM user_sessions WHERE user_id=$1")
        .bind(f.operator)
        .execute(&f.db.pool)
        .await?;
    assert_statuses(&f, &fresh, &paths, StatusCode::UNAUTHORIZED).await?;
    Ok(())
}

/// Confirms status, absence of tenant data and cache policy on each authorization failure.
async fn assert_statuses(
    f: &Fixture,
    token: &str,
    paths: &[String],
    expected: StatusCode,
) -> Result<()> {
    for path in paths {
        let (status, value) = request(&f.router, token, "GET", path, None).await?;
        assert_eq!(status, expected, "inspection rejection for {path}");
        assert!(value.get("items").is_none());
        assert!(value.get("name").is_none());
    }
    Ok(())
}

/// New admin methods cannot mutate data, and old tenant routes keep their existing ACLs.
#[tokio::test]
async fn inspection_is_read_only_and_all_responses_prohibit_caching() -> Result<()> {
    let f = Fixture::new().await?;
    let before = f.snapshot().await?;
    for path in f.foreign.paths("/v1/admin/orgs") {
        for method in ["POST", "PATCH", "DELETE"] {
            assert_eq!(
                request(
                    &f.router,
                    &f.token,
                    method,
                    &path,
                    Some(json!({"name":"Forbidden"}))
                )
                .await?
                .0,
                StatusCode::METHOD_NOT_ALLOWED
            );
        }
        for (token, suffix, expected) in [
            (&*f.token, "", StatusCode::OK),
            ("", "", StatusCode::UNAUTHORIZED),
        ] {
            let response = f
                .router
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(format!("{path}{suffix}"))
                        .header(COOKIE, format!("permesi_session={token}"))
                        .body(Body::empty())?,
                )
                .await?;
            assert_eq!(response.status(), expected);
            assert_eq!(
                response
                    .headers()
                    .get("cache-control")
                    .context("cache policy")?,
                "no-store"
            );
        }
    }
    for (path, method) in [
        ("/v1/admin/orgs?after=invalid", "GET"),
        ("/v1/admin/orgs", "POST"),
        ("/v1/admin/orgs/missing-org", "GET"),
    ] {
        let response = f
            .router
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .header(COOKIE, format!("permesi_session={}", f.token))
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(
            response
                .headers()
                .get("cache-control")
                .with_context(|| format!(
                    "failure cache policy {method} {path}: {}",
                    response.status()
                ))?,
            "no-store"
        );
    }
    assert_eq!(f.snapshot().await?, before);
    Ok(())
}

/// Complete ancestry prevents substituted UUIDs and hides retained rows beneath deleted parents.
#[tokio::test]
async fn inspection_rejects_wrong_ancestry_and_deleted_hierarchy() -> Result<()> {
    let f = Fixture::new().await?;
    let paths = f.foreign.paths("/v1/admin/orgs");
    let wrong = format!(
        "/v1/admin/orgs/{}/projects/main/envs/test/apps/{}",
        f.own.slug, f.foreign.application
    );
    assert_eq!(
        request(&f.router, &f.token, "GET", &wrong, None).await?.0,
        StatusCode::NOT_FOUND
    );
    for (table, id, first_hidden) in [
        ("applications", f.foreign.application, 7),
        ("environments", f.foreign.environment, 5),
        ("projects", f.foreign.project, 3),
        ("organizations", f.foreign.org, 1),
    ] {
        sqlx::QueryBuilder::<sqlx::Postgres>::new("UPDATE ")
            .push(table)
            .push(" SET deleted_at=NOW() WHERE id=")
            .push_bind(id)
            .build()
            .execute(&f.db.pool)
            .await?;
        for path in paths.iter().skip(first_hidden) {
            assert_eq!(
                request(&f.router, &f.token, "GET", path, None).await?.0,
                StatusCode::NOT_FOUND,
                "deleted {table}: {path}"
            );
        }
        let collection = paths
            .get(first_hidden - 1)
            .context("collection before detail")?;
        let (status, body) = request(&f.router, &f.token, "GET", collection, None).await?;
        assert_eq!(status, StatusCode::OK);
        assert!(
            body.get("items")
                .and_then(Value::as_array)
                .context("page")?
                .iter()
                .all(|row| row["id"] != id.to_string())
        );
    }
    Ok(())
}

/// Inspection must neither reactivate inactive tenant membership nor use it as admin authority.
#[tokio::test]
async fn inspection_preserves_inactive_membership_and_ordinary_anti_enumeration() -> Result<()> {
    let f = Fixture::new().await?;
    sqlx::query("UPDATE org_memberships SET status='suspended' WHERE org_id=$1 AND user_id=$2")
        .bind(f.own.org)
        .bind(f.operator)
        .execute(&f.db.pool)
        .await?;
    let before = f.snapshot().await?;
    let (status, body) = request(&f.router, &f.token, "GET", "/v1/orgs", None).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_array().context("ordinary page")?.len(), 0);
    let own = format!("/v1/orgs/{}", f.own.slug);
    assert_eq!(
        request(&f.router, &f.token, "GET", &own, None).await?.0,
        StatusCode::NOT_FOUND
    );
    for path in f.own.paths("/v1/admin/orgs") {
        assert_eq!(
            request(&f.router, &f.token, "GET", &path, None).await?.0,
            StatusCode::OK
        );
    }
    assert_eq!(f.snapshot().await?, before);
    Ok(())
}
