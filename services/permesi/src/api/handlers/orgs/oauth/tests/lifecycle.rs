//! Production-router lifecycle regressions with real PostgreSQL and session roles.
//!
//! Blocking transactions establish both orders of the creation/deletion race, so
//! the tests prove synchronization rather than hoping concurrent tasks overlap.

#![allow(clippy::too_many_lines)]

use super::*;

const ORG: &str = "/v1/orgs/oauth-org";
const PROJECT: &str = "/v1/orgs/oauth-org/projects/project";
const ENV: &str = "/v1/orgs/oauth-org/projects/project/envs/prod";

/// Sends arbitrary hierarchy requests through the same production router as OAuth.
async fn call(f: &Fixture, method: &str, path: &str, token: &str) -> Result<(StatusCode, Value)> {
    request(&f.router, method, path, token, None).await
}

/// Requires the public collection to omit deleted rows, without querying hidden metadata.
async fn assert_empty(f: &Fixture, path: &str) -> Result<()> {
    let (status, rows) = call(f, "GET", path, &f.token).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(rows, json!([]));
    Ok(())
}

/// Verifies only explicitly removed resources disappear and stale storage contexts cannot mutate them.
#[tokio::test]
async fn tenant_deletion_is_bottom_up_retains_rows_and_hides_deleted_ancestry() -> Result<()> {
    let Some(f) = Fixture::new().await? else {
        return Ok(());
    };
    let app = f.base.trim_end_matches("/oauth");
    let old_context =
        super::super::super::storage::resolve_org_context(&f.db.pool, f.owner, "oauth-org")
            .await?
            .context("original owner context")?;
    for (path, message) in [
        (ORG, "Organization contains active projects."),
        (PROJECT, "Project contains active environments."),
        (ENV, "Environment contains active applications."),
    ] {
        let (status, body) = call(&f, "DELETE", path, &f.token).await?;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body, json!(message));
    }
    // Seeded immutable protocol rows are metadata, not a deletion prerequisite.
    let protocol: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM oauth_scopes WHERE application_id=$1 AND kind='protocol'",
    )
    .bind(f.application)
    .fetch_one(&f.db.pool)
    .await?;
    assert_eq!(protocol, 6);
    for (path, list, table, id) in [
        (
            app,
            format!("{ENV}/apps"),
            "SELECT deleted_at IS NOT NULL FROM applications WHERE id=$1",
            f.application,
        ),
        (
            ENV,
            format!("{PROJECT}/envs"),
            "SELECT deleted_at IS NOT NULL FROM environments WHERE id=$1",
            f.environment,
        ),
        (
            PROJECT,
            format!("{ORG}/projects"),
            "SELECT deleted_at IS NOT NULL FROM projects WHERE id=$1",
            f.project,
        ),
        (
            ORG,
            "/v1/orgs".to_owned(),
            "SELECT deleted_at IS NOT NULL FROM organizations WHERE id=$1",
            f.org,
        ),
    ] {
        assert_eq!(
            call(&f, "DELETE", path, &f.token).await?.0,
            StatusCode::NO_CONTENT
        );
        assert_eq!(
            call(&f, "DELETE", path, &f.token).await?.0,
            StatusCode::NOT_FOUND
        );
        assert_empty(&f, &list).await?;
        let retained: bool = sqlx::query_scalar(table)
            .bind(id)
            .fetch_one(&f.db.pool)
            .await?;
        assert!(retained);
        assert_eq!(
            f.call("GET", "/clients", &f.token, None).await?.0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            f.call(
                "POST",
                "/scopes",
                &f.token,
                Some(json!({"name":"jobs:read"}))
            )
            .await?
            .0,
            StatusCode::NOT_FOUND
        );
    }
    assert_eq!(
        call(&f, "GET", ORG, &f.token).await?.0,
        StatusCode::NOT_FOUND
    );
    assert!(matches!(
        super::super::super::storage::update_org_record(
            &f.db.pool,
            &old_context,
            Some("Changed after deletion"),
            None
        )
        .await,
        Err(super::super::super::storage::OrgError::NotFound)
    ));
    assert!(matches!(
        super::super::super::storage::insert_project(&f.db.pool, f.org, "Stale", "stale").await,
        Err(super::super::super::storage::OrgError::NotFound)
    ));
    assert!(matches!(
        super::super::super::storage::insert_environment(
            &f.db.pool,
            f.project,
            "Stale",
            "stale",
            super::super::super::types::EnvironmentTier::NonProduction
        )
        .await,
        Err(super::super::super::storage::OrgError::NotFound)
    ));
    assert!(matches!(
        super::super::super::storage::insert_application(&f.db.pool, f.environment, "Stale").await,
        Err(super::super::super::storage::OrgError::NotFound)
    ));
    assert_eq!(
        request(
            &f.router,
            "PATCH",
            ORG,
            &f.token,
            Some(json!({"name":"Restored"}))
        )
        .await?
        .0,
        StatusCode::NOT_FOUND
    );
    for (path, payload) in [
        (format!("{ORG}/projects"), json!({"name":"Another"})),
        (
            format!("{PROJECT}/envs"),
            json!({"name":"Another","slug":"new"}),
        ),
        (format!("{ENV}/apps"), json!({"name":"Another"})),
    ] {
        assert_eq!(
            request(&f.router, "POST", &path, &f.token, Some(payload))
                .await?
                .0,
            StatusCode::NOT_FOUND
        );
    }
    Ok(())
}

/// Exercises manager membership, owner-only tenant deletion and the existing recent-authentication rule.
#[tokio::test]
async fn tenant_deletion_requires_current_membership_and_org_owner_for_tenant() -> Result<()> {
    let Some(f) = Fixture::new().await? else {
        return Ok(());
    };
    let app = f.base.trim_end_matches("/oauth");
    let foreign = insert_active_user(&f.db.pool, "foreign@lifecycle.test").await?;
    let token = insert_session(&f.db.pool, foreign).await?;
    sqlx::query("INSERT INTO platform_operators(user_id) VALUES($1)")
        .bind(foreign)
        .execute(&f.db.pool)
        .await?;
    for path in [ORG, PROJECT, ENV, app] {
        assert_eq!(
            call(&f, "DELETE", path, &token).await?.0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            call(&f, "DELETE", path, "").await?.0,
            StatusCode::UNAUTHORIZED
        );
    }
    for role in ["member", "readonly", "admin"] {
        let user = insert_active_user(&f.db.pool, &format!("{role}@lifecycle.test")).await?;
        let token = insert_session(&f.db.pool, user).await?;
        insert_member_role(&f.db.pool, f.org, user, role).await?;
        assert_eq!(
            call(&f, "DELETE", ORG, &token).await?.0,
            StatusCode::NOT_FOUND
        );
        if role == "admin" {
            sqlx::query(
                "UPDATE org_memberships SET status='suspended' WHERE org_id=$1 AND user_id=$2",
            )
            .bind(f.org)
            .bind(user)
            .execute(&f.db.pool)
            .await?;
            for path in [ORG, PROJECT, ENV, app] {
                assert_eq!(
                    call(&f, "DELETE", path, &token).await?.0,
                    StatusCode::NOT_FOUND
                );
            }
            sqlx::query(
                "UPDATE org_memberships SET status='active' WHERE org_id=$1 AND user_id=$2",
            )
            .bind(f.org)
            .bind(user)
            .execute(&f.db.pool)
            .await?;
            for path in [app, ENV, PROJECT] {
                assert_eq!(
                    call(&f, "DELETE", path, &token).await?.0,
                    StatusCode::NO_CONTENT
                );
            }
            assert_eq!(
                call(&f, "DELETE", ORG, &token).await?.0,
                StatusCode::NOT_FOUND
            );
        } else {
            for path in [PROJECT, ENV, app] {
                assert_eq!(
                    call(&f, "DELETE", path, &token).await?.0,
                    StatusCode::NOT_FOUND
                );
            }
        }
    }
    // The owner must reuse the existing recent-authentication policy.
    sqlx::query("UPDATE user_sessions SET auth_time=NOW()-INTERVAL '1 hour',created_at=NOW()-INTERVAL '1 hour' WHERE user_id=$1")
        .bind(f.owner).execute(&f.db.pool).await?;
    let (status, body) = call(&f, "DELETE", ORG, &f.token).await?;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        body,
        json!({"error": {
            "code": "reauthentication_required",
            "message": "Recent authentication required. Sign in again before deleting the organization."
        }})
    );
    sqlx::query("UPDATE user_sessions SET auth_time=NOW() WHERE user_id=$1")
        .bind(f.owner)
        .execute(&f.db.pool)
        .await?;
    assert_eq!(
        call(&f, "DELETE", ORG, &f.token).await?.0,
        StatusCode::NO_CONTENT
    );
    Ok(())
}

/// Ensures application teardown cannot bypass client revocation or choose an application in another tenant.
#[tokio::test]
async fn application_deletion_requires_explicit_client_revocation_and_exact_ancestry() -> Result<()>
{
    let Some(f) = Fixture::new().await? else {
        return Ok(());
    };
    let app = f.base.trim_end_matches("/oauth");
    let client = f.client("delete-client-first").await?;
    let public = id(&client, "client_id")?;
    let internal = id(&client, "id")?;
    let grant: Uuid = sqlx::query_scalar("INSERT INTO oauth_grants(user_id,client_id,application_id,organization_id) VALUES($1,$2,$3,$4) RETURNING id")
        .bind(f.owner).bind(internal).bind(f.application).bind(f.org).fetch_one(&f.db.pool).await?;
    sqlx::query("INSERT INTO oauth_client_secrets(client_id,secret_hash) VALUES($1,'$argon2id$test-only-hash')")
        .bind(internal).execute(&f.db.pool).await?;
    let other = create_org_with_roles(&f.db.pool, f.owner, "Other", "other-org")
        .await
        .map_err(|e| anyhow::anyhow!("{e:?}"))?;
    insert_application(&f.db.pool, Uuid::parse_str(&other.id)?).await?;
    let foreign = format!(
        "/v1/orgs/other-org/projects/project/envs/prod/apps/{}",
        f.application
    );
    assert_eq!(
        call(&f, "DELETE", &foreign, &f.token).await?.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        call(&f, "DELETE", app, &f.token).await?.0,
        StatusCode::CONFLICT
    );
    let suffix = format!("/clients/{public}");
    assert_eq!(
        f.call("PATCH", &suffix, &f.token, Some(json!({"disabled":true})))
            .await?
            .0,
        StatusCode::OK
    );
    assert_eq!(
        call(&f, "DELETE", app, &f.token).await?.0,
        StatusCode::CONFLICT,
        "Disabled registrations still require explicit deletion"
    );
    assert_eq!(
        f.call("DELETE", &suffix, &f.token, None).await?.0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        call(&f, "DELETE", app, &f.token).await?.0,
        StatusCode::NO_CONTENT
    );
    let revoked: bool = sqlx::query_scalar("SELECT g.revoked_at IS NOT NULL AND s.revoked_at IS NOT NULL FROM oauth_grants g JOIN oauth_client_secrets s ON s.client_id=g.client_id WHERE g.id=$1")
        .bind(grant).fetch_one(&f.db.pool).await?;
    assert!(revoked);
    assert!(load_active_client(&f.db.pool, public).await?.is_none());
    assert_eq!(
        f.call("GET", "/scopes", &f.token, None).await?.0,
        StatusCode::NOT_FOUND
    );
    // A context resolved before deletion cannot create fresh OAuth authority afterward.
    let context = crate::oauth::service::ApplicationContext::resolved(f.application, f.owner);
    let config = crate::oauth::client::ClientConfiguration::new(
        "stale-context",
        crate::oauth::client::ClientType::Public,
        vec!["https://example.com/callback".to_owned()],
        vec!["openid".to_owned()],
    )?;
    assert!(matches!(
        crate::oauth::service::create_client(&f.db.pool, &context, config).await,
        Err(crate::oauth::service::Error::NotFound)
    ));
    assert!(matches!(
        crate::oauth::service::create_scope(
            &f.db.pool,
            &context,
            "jobs:read".to_owned(),
            String::new()
        )
        .await,
        Err(crate::oauth::service::Error::NotFound)
    ));
    Ok(())
}

/// Ensures a racing OAuth registration either blocks application deletion or loses to it.
#[tokio::test]
async fn application_deletion_and_oauth_client_creation_have_only_valid_race_outcomes() -> Result<()>
{
    for delete_first in [true, false] {
        let Some(f) = Fixture::new().await? else {
            return Ok(());
        };
        let app = f.base.trim_end_matches("/oauth").to_owned();
        let mut barrier = f.db.pool.begin().await?;
        sqlx::query("SELECT id FROM applications WHERE id=$1 FOR UPDATE")
            .bind(f.application)
            .execute(&mut *barrier)
            .await?;
        let spawn = |delete: bool| {
            let router = f.router.clone();
            let token = f.token.clone();
            let path = if delete {
                app.clone()
            } else {
                format!("{}/clients", f.base)
            };
            tokio::spawn(async move {
                request(&router,if delete {"DELETE"} else {"POST"},&path,&token,
                if delete {None} else {Some(json!({"name":"Race","client_type":"public","redirect_uris":["https://example.com/callback"],"scopes":["openid"]}))}).await
            })
        };
        let first = spawn(delete_first);
        wait_for_waiters(&f.db.pool, 1).await?;
        let second = spawn(!delete_first);
        wait_for_waiters(&f.db.pool, 2).await?;
        barrier.commit().await?;
        let first = timeout(Duration::from_secs(10), first).await???;
        let second = timeout(Duration::from_secs(10), second).await???;
        let (deleted, created) = if delete_first {
            (first.0, second.0)
        } else {
            (second.0, first.0)
        };
        assert_eq!(
            deleted,
            if delete_first {
                StatusCode::NO_CONTENT
            } else {
                StatusCode::CONFLICT
            }
        );
        assert_eq!(
            created,
            if delete_first {
                StatusCode::NOT_FOUND
            } else {
                StatusCode::CREATED
            }
        );
        let invalid: bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM applications a JOIN oauth_clients c ON c.application_id=a.id WHERE a.id=$1 AND a.deleted_at IS NOT NULL AND c.deleted_at IS NULL)")
            .bind(f.application).fetch_one(&f.db.pool).await?;
        assert!(!invalid);
    }
    Ok(())
}

/// Waits for actual PostgreSQL lock contention; no scheduler timing assumptions authorize a race.
async fn wait_for_waiters(pool: &PgPool, count: i64) -> Result<()> {
    timeout(Duration::from_secs(10),async {
        loop {
            let waiting: i64 = sqlx::query_scalar("SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock'")
                .fetch_one(pool).await?;
            if waiting >= count { return Ok::<_,anyhow::Error>(()); }
            sleep(Duration::from_millis(10)).await;
        }
    }).await.context("Lifecycle contenders did not reach PostgreSQL locks")??;
    Ok(())
}

/// Models two replicas using real HTTP requests queued in both orders behind a held row lock.
async fn race(
    table: &str,
    _child_table: &str,
    delete_path: &str,
    create_path: &str,
    payload: Value,
    delete_first: bool,
) -> Result<()> {
    let Some(f) = Fixture::new().await? else {
        return Ok(());
    };
    // Make exactly the tested parent empty without bypassing application OAuth lifecycle.
    assert_eq!(
        call(&f, "DELETE", f.base.trim_end_matches("/oauth"), &f.token)
            .await?
            .0,
        StatusCode::NO_CONTENT
    );
    if table != "environments" {
        assert_eq!(
            call(&f, "DELETE", ENV, &f.token).await?.0,
            StatusCode::NO_CONTENT
        );
    }
    if table == "organizations" {
        assert_eq!(
            call(&f, "DELETE", PROJECT, &f.token).await?.0,
            StatusCode::NO_CONTENT
        );
    }
    let parent = match table {
        "organizations" => f.org,
        "projects" => f.project,
        _ => f.environment,
    };
    let mut barrier = f.db.pool.begin().await?;
    sqlx::query(match table {
        "organizations" => "SELECT id FROM organizations WHERE id=$1 FOR UPDATE",
        "projects" => "SELECT id FROM projects WHERE id=$1 FOR UPDATE",
        _ => "SELECT id FROM environments WHERE id=$1 FOR UPDATE",
    })
    .bind(parent)
    .execute(&mut *barrier)
    .await?;
    let spawn = |delete: bool| {
        let router = f.router.clone();
        let token = f.token.clone();
        let path = if delete { delete_path } else { create_path }.to_owned();
        let payload = payload.clone();
        tokio::spawn(async move {
            request(
                &router,
                if delete { "DELETE" } else { "POST" },
                &path,
                &token,
                if delete { None } else { Some(payload) },
            )
            .await
        })
    };
    let first = spawn(delete_first);
    wait_for_waiters(&f.db.pool, 1).await?;
    let second = spawn(!delete_first);
    wait_for_waiters(&f.db.pool, 2).await?;
    barrier.commit().await?;
    let first = timeout(Duration::from_secs(10), first).await???;
    let second = timeout(Duration::from_secs(10), second).await???;
    let (deleted, created) = if delete_first {
        (first.0, second.0)
    } else {
        (second.0, first.0)
    };
    assert_eq!(
        deleted,
        if delete_first {
            StatusCode::NO_CONTENT
        } else {
            StatusCode::CONFLICT
        }
    );
    assert_eq!(
        created,
        if delete_first {
            StatusCode::NOT_FOUND
        } else {
            StatusCode::CREATED
        }
    );
    let query = match table {
        "organizations" => {
            "SELECT EXISTS(SELECT 1 FROM organizations p JOIN projects c ON c.org_id=p.id WHERE p.id=$1 AND p.deleted_at IS NOT NULL AND c.deleted_at IS NULL)"
        }
        "projects" => {
            "SELECT EXISTS(SELECT 1 FROM projects p JOIN environments c ON c.project_id=p.id WHERE p.id=$1 AND p.deleted_at IS NOT NULL AND c.deleted_at IS NULL)"
        }
        _ => {
            "SELECT EXISTS(SELECT 1 FROM environments p JOIN applications c ON c.environment_id=p.id WHERE p.id=$1 AND p.deleted_at IS NOT NULL AND c.deleted_at IS NULL)"
        }
    };
    let invalid: bool = sqlx::query_scalar(query)
        .bind(parent)
        .fetch_one(&f.db.pool)
        .await?;
    assert!(
        !invalid,
        "Deletion must never leave an active child beneath a deleted parent"
    );
    Ok(())
}

/// Exercises both queue orders of empty environment deletion against application creation.
#[tokio::test]
async fn environment_deletion_and_application_creation_have_only_valid_race_outcomes() -> Result<()>
{
    for first in [true, false] {
        race(
            "environments",
            "applications",
            ENV,
            &format!("{ENV}/apps"),
            json!({"name":"Race"}),
            first,
        )
        .await?;
    }
    Ok(())
}

/// Exercises both queue orders of empty project deletion against environment creation.
#[tokio::test]
async fn project_deletion_and_environment_creation_have_only_valid_race_outcomes() -> Result<()> {
    for first in [true, false] {
        race(
            "projects",
            "environments",
            PROJECT,
            &format!("{PROJECT}/envs"),
            json!({"name":"Race","slug":"race"}),
            first,
        )
        .await?;
    }
    Ok(())
}

/// Exercises both queue orders of empty organization deletion against project creation.
#[tokio::test]
async fn organization_deletion_and_project_creation_have_only_valid_race_outcomes() -> Result<()> {
    for first in [true, false] {
        race(
            "organizations",
            "projects",
            ORG,
            &format!("{ORG}/projects"),
            json!({"name":"Race"}),
            first,
        )
        .await?;
    }
    Ok(())
}

/// Inaccessible callers must not join a foreign tenant's exclusive lifecycle lock queue.
#[tokio::test]
async fn organization_deletion_rejects_nonowners_before_foreign_coordination() -> Result<()> {
    let Some(f) = Fixture::new().await? else {
        return Ok(());
    };
    let foreign = insert_active_user(&f.db.pool, "no-foreign-lock@lifecycle.test").await?;
    let foreign_token = insert_session(&f.db.pool, foreign).await?;
    let admin = insert_active_user(&f.db.pool, "no-admin-lock@lifecycle.test").await?;
    let admin_token = insert_session(&f.db.pool, admin).await?;
    insert_member_role(&f.db.pool, f.org, admin, "admin").await?;
    let mut barrier = f.db.pool.begin().await?;
    sqlx::query("SELECT id FROM organizations WHERE id=$1 FOR UPDATE")
        .bind(f.org)
        .execute(&mut *barrier)
        .await?;
    for token in [&foreign_token, &admin_token] {
        let reply = timeout(Duration::from_secs(5), call(&f, "DELETE", ORG, token))
            .await
            .context("Inaccessible deletion joined tenant lock queue")??;
        assert_eq!(reply.0, StatusCode::NOT_FOUND);
    }
    barrier.rollback().await?;
    Ok(())
}

/// A session authorized before a lock wait must lose deletion authority after membership revocation.
#[tokio::test]
async fn application_deletion_rechecks_membership_after_waiting() -> Result<()> {
    let Some(f) = Fixture::new().await? else {
        return Ok(());
    };
    let mut barrier = f.db.pool.begin().await?;
    sqlx::query("SELECT org_id FROM org_memberships WHERE org_id=$1 AND user_id=$2 FOR UPDATE")
        .bind(f.org)
        .bind(f.owner)
        .execute(&mut *barrier)
        .await?;
    let router = f.router.clone();
    let token = f.token.clone();
    let path = f.base.trim_end_matches("/oauth").to_owned();
    let deletion =
        tokio::spawn(async move { request(&router, "DELETE", &path, &token, None).await });
    wait_for_waiters(&f.db.pool, 1).await?;
    sqlx::query("UPDATE org_memberships SET status='suspended' WHERE org_id=$1 AND user_id=$2")
        .bind(f.org)
        .bind(f.owner)
        .execute(&mut *barrier)
        .await?;
    barrier.commit().await?;
    assert_eq!(
        timeout(Duration::from_secs(5), deletion).await???.0,
        StatusCode::NOT_FOUND
    );
    let active: bool =
        sqlx::query_scalar("SELECT deleted_at IS NULL FROM applications WHERE id=$1")
            .bind(f.application)
            .fetch_one(&f.db.pool)
            .await?;
    assert!(active);
    Ok(())
}

/// A user disabled during a root lock wait must lose resource deletion authority.
#[tokio::test]
async fn application_deletion_rechecks_active_user_after_waiting() -> Result<()> {
    let Some(f) = Fixture::new().await? else {
        return Ok(());
    };
    let mut barrier = f.db.pool.begin().await?;
    sqlx::query("SELECT id FROM organizations WHERE id=$1 FOR UPDATE")
        .bind(f.org)
        .execute(&mut *barrier)
        .await?;
    let router = f.router.clone();
    let token = f.token.clone();
    let path = f.base.trim_end_matches("/oauth").to_owned();
    let deletion =
        tokio::spawn(async move { request(&router, "DELETE", &path, &token, None).await });
    wait_for_waiters(&f.db.pool, 1).await?;
    sqlx::query("UPDATE users SET status='disabled' WHERE id=$1")
        .bind(f.owner)
        .execute(&mut *barrier)
        .await?;
    barrier.commit().await?;
    assert_eq!(
        timeout(Duration::from_secs(5), deletion).await???.0,
        StatusCode::NOT_FOUND
    );
    let active: bool =
        sqlx::query_scalar("SELECT deleted_at IS NULL FROM applications WHERE id=$1")
            .bind(f.application)
            .fetch_one(&f.db.pool)
            .await?;
    assert!(active);
    Ok(())
}

/// A rename while deletion waits must invalidate its original row lookup and preserve both tenants.
#[tokio::test]
async fn organization_deletion_preserves_a_reused_slug_and_renamed_original() -> Result<()> {
    let Some(f) = Fixture::new().await? else {
        return Ok(());
    };
    let mut barrier = f.db.pool.begin().await?;
    sqlx::query("SELECT id FROM organizations WHERE id=$1 FOR UPDATE")
        .bind(f.org)
        .execute(&mut *barrier)
        .await?;
    let router = f.router.clone();
    let token = f.token.clone();
    let deletion = tokio::spawn(async move { request(&router, "DELETE", ORG, &token, None).await });
    wait_for_waiters(&f.db.pool, 1).await?;
    sqlx::query("UPDATE organizations SET slug='original-renamed' WHERE id=$1")
        .bind(f.org)
        .execute(&mut *barrier)
        .await?;
    let replacement: Uuid=sqlx::query_scalar("INSERT INTO organizations(slug,name,created_by) VALUES('oauth-org','Replacement',$1) RETURNING id")
        .bind(f.owner).fetch_one(&mut *barrier).await?;
    sqlx::query("INSERT INTO org_memberships(org_id,user_id,status) VALUES($1,$2,'active')")
        .bind(replacement)
        .bind(f.owner)
        .execute(&mut *barrier)
        .await?;
    sqlx::query("INSERT INTO org_roles(org_id,name) VALUES($1,'owner')")
        .bind(replacement)
        .execute(&mut *barrier)
        .await?;
    sqlx::query("INSERT INTO org_member_roles(org_id,user_id,role_name) VALUES($1,$2,'owner')")
        .bind(replacement)
        .bind(f.owner)
        .execute(&mut *barrier)
        .await?;
    barrier.commit().await?;
    assert_eq!(
        timeout(Duration::from_secs(5), deletion).await???.0,
        StatusCode::NOT_FOUND
    );
    let active: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM organizations WHERE id=ANY($1) AND deleted_at IS NULL",
    )
    .bind(vec![f.org, replacement])
    .fetch_one(&f.db.pool)
    .await?;
    assert_eq!(
        active, 2,
        "Neither the renamed original nor the replacement tenant may be deleted"
    );
    Ok(())
}

/// Revoking the specific granting role during a lock wait must defeat deletion.
async fn revoke_role_during_deletion(role: &str, organization: bool) -> Result<()> {
    let Some(f) = Fixture::new().await? else {
        return Ok(());
    };
    let (user, token) = if role == "admin" {
        let user = insert_active_user(&f.db.pool, "role-revoked@lifecycle.test").await?;
        insert_member_role(&f.db.pool, f.org, user, role).await?;
        (user, insert_session(&f.db.pool, user).await?)
    } else {
        (f.owner, f.token.clone())
    };
    if organization {
        for path in [f.base.trim_end_matches("/oauth"), ENV, PROJECT] {
            assert_eq!(
                call(&f, "DELETE", path, &f.token).await?.0,
                StatusCode::NO_CONTENT
            );
        }
    }
    let mut barrier = f.db.pool.begin().await?;
    sqlx::query("SELECT id FROM organizations WHERE id=$1 FOR UPDATE")
        .bind(f.org)
        .execute(&mut *barrier)
        .await?;
    let router = f.router.clone();
    let path = if organization {
        ORG.to_owned()
    } else {
        f.base.trim_end_matches("/oauth").to_owned()
    };
    let deletion =
        tokio::spawn(async move { request(&router, "DELETE", &path, &token, None).await });
    wait_for_waiters(&f.db.pool, 1).await?;
    sqlx::query("DELETE FROM org_member_roles WHERE org_id=$1 AND user_id=$2 AND role_name=$3")
        .bind(f.org)
        .bind(user)
        .bind(role)
        .execute(&mut *barrier)
        .await?;
    barrier.commit().await?;
    assert_eq!(
        timeout(Duration::from_secs(5), deletion).await???.0,
        StatusCode::NOT_FOUND
    );
    let active: bool = if organization {
        sqlx::query_scalar("SELECT deleted_at IS NULL FROM organizations WHERE id=$1")
            .bind(f.org)
            .fetch_one(&f.db.pool)
            .await?
    } else {
        sqlx::query_scalar("SELECT deleted_at IS NULL FROM applications WHERE id=$1")
            .bind(f.application)
            .fetch_one(&f.db.pool)
            .await?
    };
    assert!(active);
    Ok(())
}

/// Both management roles are rechecked independently of still-active membership.
#[tokio::test]
async fn application_deletion_rechecks_owner_and_admin_roles_after_waiting() -> Result<()> {
    for role in ["owner", "admin"] {
        revoke_role_during_deletion(role, false).await?;
    }
    Ok(())
}

/// Removing ownership while an empty tenant deletion waits must retain the tenant.
#[tokio::test]
async fn organization_deletion_rechecks_owner_role_after_waiting() -> Result<()> {
    revoke_role_during_deletion("owner", true).await
}

/// Scope registry rows are retained metadata; creation must reject already-deleted applications.
#[tokio::test]
async fn application_deletion_and_scope_creation_preserve_metadata_lifecycle() -> Result<()> {
    for delete_first in [true, false] {
        let Some(f) = Fixture::new().await? else {
            return Ok(());
        };
        let mut barrier = f.db.pool.begin().await?;
        sqlx::query("SELECT id FROM applications WHERE id=$1 FOR UPDATE")
            .bind(f.application)
            .execute(&mut *barrier)
            .await?;
        let spawn = |delete: bool| {
            let router = f.router.clone();
            let token = f.token.clone();
            let path = if delete {
                f.base.trim_end_matches("/oauth").to_owned()
            } else {
                format!("{}/scopes", f.base)
            };
            tokio::spawn(async move {
                request(
                    &router,
                    if delete { "DELETE" } else { "POST" },
                    &path,
                    &token,
                    if delete {
                        None
                    } else {
                        Some(json!({"name":"jobs:read","description":"Retained registry metadata"}))
                    },
                )
                .await
            })
        };
        let first = spawn(delete_first);
        wait_for_waiters(&f.db.pool, 1).await?;
        let second = spawn(!delete_first);
        wait_for_waiters(&f.db.pool, 2).await?;
        barrier.commit().await?;
        let first = timeout(Duration::from_secs(5), first).await???;
        let second = timeout(Duration::from_secs(5), second).await???;
        let (deleted, created) = if delete_first {
            (first.0, second.0)
        } else {
            (second.0, first.0)
        };
        assert_eq!(
            deleted,
            StatusCode::NO_CONTENT,
            "Registry metadata never blocks application deletion"
        );
        assert_eq!(
            created,
            if delete_first {
                StatusCode::NOT_FOUND
            } else {
                StatusCode::CREATED
            }
        );
        let count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM oauth_scopes WHERE application_id=$1 AND name='jobs:read'",
        )
        .bind(f.application)
        .fetch_one(&f.db.pool)
        .await?;
        assert_eq!(count, i64::from(!delete_first));
        assert_eq!(
            f.call("GET", "/scopes", &f.token, None).await?.0,
            StatusCode::NOT_FOUND
        );
    }
    Ok(())
}
