//! Real PostgreSQL coverage for presentation capabilities and confirmation UUID restrictions.

use super::*;

const CAPS: &str = "/v1/orgs/oauth-org/capabilities";

/// Capabilities expose role eligibility only and never grant platform operators tenant authority.
#[tokio::test]
async fn tenant_capabilities_are_current_no_store_and_omit_raw_authority() -> Result<()> {
    let Some(f) = Fixture::new().await? else {
        return Ok(());
    };
    for (role, manage, delete) in [
        ("owner", true, true),
        ("admin", true, false),
        ("member", false, false),
        ("readonly", false, false),
    ] {
        let user = insert_active_user(&f.db.pool, &format!("{role}@caps.test")).await?;
        insert_member_role(&f.db.pool, f.org, user, role).await?;
        sqlx::query("INSERT INTO platform_operators (user_id,enabled) VALUES ($1,true)")
            .bind(user)
            .execute(&f.db.pool)
            .await?;
        let token = insert_session(&f.db.pool, user).await?;
        let response = f
            .router
            .clone()
            .oneshot(
                Request::get(CAPS)
                    .header(COOKIE, format!("permesi_session={token}"))
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get("cache-control")
                .context("cache policy")?,
            "no-store"
        );
        let body: Value = serde_json::from_slice(&to_bytes(response.into_body(), 4096).await?)?;
        assert_eq!(
            body,
            json!({"organization_id":f.org.to_string(), "can_manage_resources":manage, "can_delete_organization":delete})
        );
        assert_eq!(
            request(&f.router, "DELETE", "/v1/orgs/oauth-org", &token, None)
                .await?
                .0,
            if delete {
                StatusCode::CONFLICT
            } else {
                StatusCode::NOT_FOUND
            }
        );
        sqlx::query("UPDATE org_memberships SET status='suspended' WHERE org_id=$1 AND user_id=$2")
            .bind(f.org)
            .bind(user)
            .execute(&f.db.pool)
            .await?;
        assert_eq!(
            request(&f.router, "GET", CAPS, &token, None).await?.0,
            StatusCode::NOT_FOUND
        );
    }
    Ok(())
}

/// Full active sessions are mandatory; foreign and deleted organizations stay inaccessible.
#[tokio::test]
async fn tenant_capabilities_fail_closed_for_session_and_tenant_changes() -> Result<()> {
    let Some(f) = Fixture::new().await? else {
        return Ok(());
    };
    let unauthenticated = f
        .router
        .clone()
        .oneshot(Request::get(CAPS).body(Body::empty())?)
        .await?;
    assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        unauthenticated
            .headers()
            .get("cache-control")
            .context("error cache policy")?,
        "no-store"
    );
    for prefix in ["mfa_setup_", "mfa_challenge_"] {
        let token = format!(
            "{prefix}{}",
            crate::api::handlers::auth::generate_session_token()?
        );
        sqlx::query("INSERT INTO user_sessions (user_id,session_hash,expires_at) VALUES ($1,$2,NOW()+INTERVAL '1 hour')")
            .bind(f.owner).bind(crate::api::handlers::auth::hash_session_token(&token)).execute(&f.db.pool).await?;
        assert_eq!(
            request(&f.router, "GET", CAPS, &token, None).await?.0,
            StatusCode::UNAUTHORIZED
        );
    }
    let stranger = insert_active_user(&f.db.pool, "foreign@caps.test").await?;
    let stranger_token = insert_session(&f.db.pool, stranger).await?;
    assert_eq!(
        request(&f.router, "GET", CAPS, &stranger_token, None)
            .await?
            .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        request(&f.router, "GET", CAPS, "", None).await?.0,
        StatusCode::UNAUTHORIZED
    );
    sqlx::query("UPDATE users SET status='disabled' WHERE id=$1")
        .bind(f.owner)
        .execute(&f.db.pool)
        .await?;
    assert_eq!(
        request(&f.router, "GET", CAPS, &f.token, None).await?.0,
        StatusCode::UNAUTHORIZED
    );
    sqlx::query("UPDATE users SET status='active' WHERE id=$1")
        .bind(f.owner)
        .execute(&f.db.pool)
        .await?;
    sqlx::query("UPDATE organizations SET deleted_at=NOW() WHERE id=$1")
        .bind(f.org)
        .execute(&f.db.pool)
        .await?;
    assert_eq!(
        request(&f.router, "GET", CAPS, &f.token, None).await?.0,
        StatusCode::NOT_FOUND
    );
    Ok(())
}

/// Sends an optional/repeated expected-ID header through the production deletion handler.
async fn pinned_delete(f: &Fixture, slug: &str, ids: &[String]) -> Result<StatusCode> {
    let mut request = Request::delete(format!("/v1/orgs/{slug}"))
        .header(COOKIE, format!("permesi_session={}", f.token));
    for id in ids {
        request = request.header("X-Permesi-Expected-Organization-Id", id);
    }
    Ok(f.router
        .clone()
        .oneshot(request.body(Body::empty())?)
        .await?
        .status())
}

/// A header can only narrow the authorized target and rejects malformed or ambiguous values.
#[tokio::test]
async fn organization_deletion_expected_id_is_a_restriction_never_authority() -> Result<()> {
    let Some(f) = Fixture::new().await? else {
        return Ok(());
    };
    for ids in [
        vec!["invalid".to_owned()],
        vec![f.org.to_string(), f.org.to_string()],
    ] {
        assert_eq!(
            pinned_delete(&f, "oauth-org", &ids).await?,
            StatusCode::BAD_REQUEST
        );
    }
    assert_eq!(
        pinned_delete(&f, "oauth-org", &[Uuid::new_v4().to_string()]).await?,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        pinned_delete(&f, "oauth-org", &[f.org.to_string()]).await?,
        StatusCode::CONFLICT
    );
    // A forged capability flag/header does not override an owner role removed after the GET.
    sqlx::query("DELETE FROM org_member_roles WHERE org_id=$1 AND user_id=$2")
        .bind(f.org)
        .bind(f.owner)
        .execute(&f.db.pool)
        .await?;
    assert_eq!(
        pinned_delete(&f, "oauth-org", &[f.org.to_string()]).await?,
        StatusCode::NOT_FOUND
    );
    Ok(())
}

/// A minutes-old console confirmation cannot delete a new tenant reusing the same slug.
#[tokio::test]
async fn organization_confirmation_rejects_committed_slug_reuse_and_allows_exact_id() -> Result<()>
{
    let Some(f) = Fixture::new().await? else {
        return Ok(());
    };
    sqlx::query("UPDATE organizations SET slug='renamed' WHERE id=$1")
        .bind(f.org)
        .execute(&f.db.pool)
        .await?;
    let replacement = create_org_with_roles(&f.db.pool, f.owner, "Replacement", "oauth-org")
        .await
        .map_err(|e| anyhow::anyhow!("{e:?}"))?;
    assert_eq!(
        pinned_delete(&f, "oauth-org", &[f.org.to_string()]).await?,
        StatusCode::NOT_FOUND
    );
    let active: bool =
        sqlx::query_scalar("SELECT deleted_at IS NULL FROM organizations WHERE id=$1")
            .bind(Uuid::parse_str(&replacement.id)?)
            .fetch_one(&f.db.pool)
            .await?;
    assert!(active);
    assert_eq!(
        pinned_delete(&f, "oauth-org", &[replacement.id]).await?,
        StatusCode::NO_CONTENT
    );
    let compatible = create_org_with_roles(&f.db.pool, f.owner, "Compatible", "compatible")
        .await
        .map_err(|e| anyhow::anyhow!("{e:?}"))?;
    assert_eq!(
        pinned_delete(&f, "compatible", &[]).await?,
        StatusCode::NO_CONTENT
    );
    assert_ne!(compatible.id, f.org.to_string());
    Ok(())
}
