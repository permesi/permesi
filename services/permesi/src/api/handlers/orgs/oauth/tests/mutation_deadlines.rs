//! Real PostgreSQL contention and cancellation coverage for hierarchy mutation budgets.

use super::*;
use crate::api::{
    handlers::orgs::storage::{self, OrgError},
    tenant::MutationPolicy,
};
use axum::response::IntoResponse;
use sqlx::postgres::PgPoolOptions;

mod begin;

struct Mutation {
    method: &'static str,
    path: String,
    payload: Option<Value>,
    table: &'static str,
    target: Uuid,
}

/// Enumerates every hierarchy mutation; fixed lock targets are fixture-owned, never request SQL.
fn mutations(f: &Fixture) -> Vec<Mutation> {
    let org = "/v1/orgs/oauth-org";
    let project = format!("{org}/projects/project");
    let environment = format!("{project}/envs/prod");
    vec![
        Mutation {
            method: "POST",
            path: "/v1/orgs".into(),
            payload: Some(json!({"name":"Blocked new org","slug":"blocked-org"})),
            table: "users",
            target: f.owner,
        },
        Mutation {
            method: "PATCH",
            path: org.into(),
            payload: Some(json!({"name":"Blocked rename"})),
            table: "organizations",
            target: f.org,
        },
        Mutation {
            method: "DELETE",
            path: org.into(),
            payload: None,
            table: "organizations",
            target: f.org,
        },
        Mutation {
            method: "POST",
            path: format!("{org}/projects"),
            payload: Some(json!({"name":"Blocked project","slug":"blocked-project"})),
            table: "organizations",
            target: f.org,
        },
        Mutation {
            method: "DELETE",
            path: project.clone(),
            payload: None,
            table: "projects",
            target: f.project,
        },
        Mutation {
            method: "POST",
            path: format!("{project}/envs"),
            payload: Some(
                json!({"name":"Blocked env","slug":"blocked-env","tier":"non_production"}),
            ),
            table: "projects",
            target: f.project,
        },
        Mutation {
            method: "DELETE",
            path: environment.clone(),
            payload: None,
            table: "environments",
            target: f.environment,
        },
        Mutation {
            method: "POST",
            path: format!("{environment}/apps"),
            payload: Some(json!({"name":"Blocked application"})),
            table: "environments",
            target: f.environment,
        },
        Mutation {
            method: "DELETE",
            path: format!("{environment}/apps/{}", f.application),
            payload: None,
            table: "applications",
            target: f.application,
        },
    ]
}

/// Uses the actual documented routes and served error envelope with an explicit test policy.
fn router(f: &Fixture, policy: MutationPolicy) -> Result<Router> {
    router_with_pool(f.db.pool.clone(), policy)
}

/// Uses a dedicated pool to distinguish its acquire deadline from the outer handler budget.
fn router_with_pool(pool: PgPool, policy: MutationPolicy) -> Result<Router> {
    let mut state = AppState::for_tests(pool)?;
    state.tenant_mutations = policy;
    let (router, _) = crate::api::router().split_for_parts();
    Ok(service_utils::api_error::with_error_envelope(
        router.with_state(state),
    ))
}

/// Captures retained hierarchy/role state, excluding session fields and credentials.
async fn snapshot(pool: &PgPool) -> Result<String> {
    Ok(sqlx::query_scalar("SELECT jsonb_build_array((SELECT jsonb_agg(to_jsonb(t) ORDER BY id) FROM organizations t),(SELECT jsonb_agg(to_jsonb(t) ORDER BY id) FROM projects t),(SELECT jsonb_agg(to_jsonb(t) ORDER BY id) FROM environments t),(SELECT jsonb_agg(to_jsonb(t) ORDER BY id) FROM applications t),(SELECT count(*) FROM org_memberships),(SELECT count(*) FROM org_member_roles))::text").fetch_one(pool).await?)
}

/// Checks the entire transient envelope, so SQL, names, identifiers and policy details cannot leak.
fn unavailable(response: &(StatusCode, Value)) {
    assert_eq!(response.0, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        response.1,
        json!({"error":{"code":"dependency_unavailable","message":"a required service is unavailable"}})
    );
}

/// Exhausted suffix probes conflict promptly without creating or renaming tenant state.
#[tokio::test]
async fn tenant_mutation_slug_candidates_are_bounded_independently_of_deadlines() -> Result<()> {
    let Some(f) = Fixture::new().await? else {
        return Ok(());
    };
    let policy = MutationPolicy::new(50, 2000, 3)?;
    assert_eq!(policy.slug_attempts(), 3);
    for index in 2..=3 {
        storage::create_org_with_roles(
            &f.db.pool,
            f.owner,
            &format!("Occupied suffix {index}"),
            &format!("oauth-org-{index}"),
            policy,
        )
        .await
        .map_err(|error| anyhow::anyhow!("{error:?}"))?;
    }
    storage::create_org_with_roles(
        &f.db.pool,
        f.owner,
        "Rename target",
        "rename-target",
        policy,
    )
    .await
    .map_err(|error| anyhow::anyhow!("{error:?}"))?;
    let router = router(&f, policy)?;
    let before = snapshot(&f.db.pool).await?;
    for (method, path, name) in [
        ("POST", "/v1/orgs", "New bounded organization"),
        (
            "PATCH",
            "/v1/orgs/rename-target",
            "Renamed bounded organization",
        ),
    ] {
        let response = timeout(
            Duration::from_secs(1),
            request(
                &router,
                method,
                path,
                &f.token,
                Some(json!({"name":name,"slug":"oauth-org"})),
            ),
        )
        .await
        .context("Slug candidate cap depended on handler cancellation")??;
        assert_eq!(response.0, StatusCode::CONFLICT);
        assert_eq!(snapshot(&f.db.pool).await?, before);
    }
    let response = request(
        &router,
        "POST",
        "/v1/orgs",
        &f.token,
        Some(json!({"name":"Free slug control","slug":"free-slug"})),
    )
    .await?;
    assert_eq!(response.0, StatusCode::CREATED);
    assert_eq!(response.1.get("slug"), Some(&json!("free-slug")));
    Ok(())
}

/// Duplicate creator names return 409 without mutation; genuine slug collisions still suffix.
#[tokio::test]
async fn tenant_mutation_duplicate_org_name_conflicts_without_retrying() -> Result<()> {
    let Some(f) = Fixture::new().await? else {
        return Ok(());
    };
    let policy = MutationPolicy::new(50, 2000, 16)?;
    let router = router(&f, policy)?;
    let other = storage::create_org_with_roles(
        &f.db.pool,
        f.owner,
        "Other organization",
        "other-org",
        policy,
    )
    .await
    .map_err(|error| anyhow::anyhow!("{error:?}"))?;
    let before = snapshot(&f.db.pool).await?;
    for payload in [
        json!({"name":"OAuth Org"}),
        json!({"name":"OAuth Org","slug":"fresh-org"}),
        json!({"name":"OAuth Org","slug":"oauth-org"}),
    ] {
        let response = timeout(
            Duration::from_secs(4),
            request(
                &router,
                "PATCH",
                "/v1/orgs/other-org",
                &f.token,
                Some(payload),
            ),
        )
        .await
        .context("duplicate name retry escaped the handler budget")??;
        assert_eq!(response.0, StatusCode::CONFLICT, "{response:?}");
        assert_eq!(snapshot(&f.db.pool).await?, before);
    }
    let response = request(
        &router,
        "PATCH",
        "/v1/orgs/other-org",
        &f.token,
        Some(json!({"name":"Renamed organization","slug":"oauth-org"})),
    )
    .await?;
    assert_eq!(response.0, StatusCode::OK, "{response:?}");
    assert_eq!(
        response.1.get("id").and_then(Value::as_str),
        Some(other.id.as_str())
    );
    assert_eq!(
        response.1.get("name").and_then(Value::as_str),
        Some("Renamed organization")
    );
    assert_eq!(
        response.1.get("slug").and_then(Value::as_str),
        Some("oauth-org-2")
    );
    Ok(())
}

/// A stale name-only request cannot undo a concurrent slug change or steal a reused slug.
#[tokio::test]
async fn tenant_mutation_name_only_update_preserves_concurrently_changed_slug() -> Result<()> {
    let Some(f) = Fixture::new().await? else {
        return Ok(());
    };
    let policy = MutationPolicy::new(50, 2000, 16)?;
    let context = storage::resolve_org_context(&f.db.pool, f.owner, "oauth-org")
        .await?
        .context("missing original organization")?;
    let router = router(&f, policy)?;
    let renamed = request(
        &router,
        "PATCH",
        "/v1/orgs/oauth-org",
        &f.token,
        Some(json!({"slug":"current-org"})),
    )
    .await?;
    assert_eq!(renamed.0, StatusCode::OK);
    let reused =
        storage::create_org_with_roles(&f.db.pool, f.owner, "Reused slug", "oauth-org", policy)
            .await
            .map_err(|error| anyhow::anyhow!("{error:?}"))?;
    let updated = storage::update_org_record(
        &f.db.pool,
        &context,
        Some("Changed name only"),
        None,
        policy,
    )
    .await
    .map_err(|error| anyhow::anyhow!("{error:?}"))?;
    assert_eq!(updated.id, f.org.to_string());
    assert_eq!(updated.name, "Changed name only");
    assert_eq!(updated.slug, "current-org");
    let retained: (String, String) =
        sqlx::query_as("SELECT slug,name FROM organizations WHERE id=$1 AND deleted_at IS NULL")
            .bind(Uuid::parse_str(&reused.id)?)
            .fetch_one(&f.db.pool)
            .await?;
    assert_eq!(retained, ("oauth-org".to_owned(), "Reused slug".to_owned()));
    Ok(())
}

/// Every writer rejects contention without a partial rename, child, membership or soft deletion.
#[tokio::test]
async fn tenant_mutation_all_routes_bound_locks_and_leave_state_unchanged() -> Result<()> {
    let Some(f) = Fixture::new().await? else {
        return Ok(());
    };
    let router = router(&f, MutationPolicy::new(50, 2000, 16)?)?;
    let before = snapshot(&f.db.pool).await?;
    for mutation in mutations(&f) {
        let sql = match mutation.table {
            "users" => "SELECT id FROM users WHERE id=$1 FOR UPDATE",
            "organizations" => "SELECT id FROM organizations WHERE id=$1 FOR UPDATE",
            "projects" => "SELECT id FROM projects WHERE id=$1 FOR UPDATE",
            "environments" => "SELECT id FROM environments WHERE id=$1 FOR UPDATE",
            _ => "SELECT id FROM applications WHERE id=$1 FOR UPDATE",
        };
        let mut held = f.db.pool.begin().await?;
        sqlx::query(sql)
            .bind(mutation.target)
            .execute(&mut *held)
            .await?;
        let response = timeout(
            Duration::from_secs(1),
            request(
                &router,
                mutation.method,
                &mutation.path,
                &f.token,
                mutation.payload,
            ),
        )
        .await;
        held.rollback().await?;
        unavailable(&response.context("unbounded mutation handler")??);
        assert_eq!(
            snapshot(&f.db.pool).await?,
            before,
            "{} {}",
            mutation.method,
            mutation.path
        );
    }
    Ok(())
}

/// A direct persistence call must time out in PostgreSQL, independently of the HTTP watchdog.
#[tokio::test]
async fn tenant_mutation_storage_deadline_is_enforced_before_parent_locks() -> Result<()> {
    let Some(f) = Fixture::new().await? else {
        return Ok(());
    };
    let before = snapshot(&f.db.pool).await?;
    let mut held = f.db.pool.begin().await?;
    sqlx::query("SELECT id FROM organizations WHERE id=$1 FOR UPDATE")
        .bind(f.org)
        .execute(&mut *held)
        .await?;
    let result = timeout(
        Duration::from_secs(2),
        storage::insert_project(
            &f.db.pool,
            f.org,
            "Blocked",
            "blocked",
            MutationPolicy::new(50, 1000, 16)?,
        ),
    )
    .await;
    held.rollback().await?;
    assert!(matches!(
        result.context("server lock deadline absent")?,
        Err(OrgError::Unavailable)
    ));
    assert_eq!(snapshot(&f.db.pool).await?, before);
    Ok(())
}

/// A saturated pool cannot bypass the handler budget by stalling before its transaction starts.
#[tokio::test]
async fn tenant_mutation_all_routes_bound_session_lookup_and_pool_waits() -> Result<()> {
    let Some(f) = Fixture::new().await? else {
        return Ok(());
    };
    let router = router(&f, MutationPolicy::new(25, 75, 16)?)?;
    let before = snapshot(&f.db.pool).await?;
    let mut held = Vec::new();
    for _ in 0..5 {
        held.push(f.db.pool.acquire().await?);
    }
    for mutation in mutations(&f) {
        let response = timeout(
            Duration::from_secs(2),
            request(
                &router,
                mutation.method,
                &mutation.path,
                &f.token,
                mutation.payload,
            ),
        )
        .await
        .context("session/pool wait escaped handler budget")??;
        unavailable(&response);
    }
    drop(held);
    assert_eq!(snapshot(&f.db.pool).await?, before);
    Ok(())
}

/// Short pool-acquisition failures close session and write-storage paths before the handler timer.
#[tokio::test]
async fn tenant_mutation_pool_deadline_precedes_handler_and_recovers() -> Result<()> {
    let Some(f) = Fixture::new().await? else {
        return Ok(());
    };
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_millis(100))
        .connect_with(f.db.pool.connect_options().as_ref().clone())
        .await?;
    let policy = MutationPolicy::new(50, 2000, 16)?;
    let router = router_with_pool(pool.clone(), policy)?;
    let held = pool.acquire().await?;
    let before = snapshot(&f.db.pool).await?;
    for mutation in mutations(&f) {
        let response = timeout(
            Duration::from_secs(1),
            request(
                &router,
                mutation.method,
                &mutation.path,
                &f.token,
                mutation.payload,
            ),
        )
        .await
        .context("Pool failure depended on the longer handler timer")??;
        unavailable(&response);
    }
    let write = timeout(
        Duration::from_secs(1),
        storage::insert_project(&pool, f.org, "Pool recovery", "pool-recovery", policy),
    )
    .await
    .context("Write storage escaped pool acquisition deadline")?;
    assert!(matches!(write, Err(OrgError::Unavailable)));
    drop(held);
    assert_eq!(snapshot(&f.db.pool).await?, before);
    assert_eq!(
        request(
            &router,
            "POST",
            "/v1/orgs/oauth-org/projects",
            &f.token,
            Some(json!({"name":"Pool recovery","slug":"pool-recovery"}))
        )
        .await?
        .0,
        StatusCode::CREATED
    );
    pool.close().await;
    Ok(())
}

/// Explicit future cancellation during live SQL restores GUCs and releases acquired ancestry locks.
#[tokio::test]
async fn tenant_mutation_aborted_future_rolls_back_active_query() -> Result<()> {
    let Some(f) = Fixture::new().await? else {
        return Ok(());
    };
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(f.db.pool.connect_options().as_ref().clone())
        .await?;
    let settings = "SELECT current_setting('lock_timeout'),current_setting('statement_timeout')";
    let original: (String, String) = sqlx::query_as(settings).fetch_one(&pool).await?;
    let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&pool)
        .await?;
    let pending_pool = pool.clone();
    let org = f.org;
    let operation = tokio::spawn(async move {
        let mut tx = MutationPolicy::new(50, 2000, 16)?
            .begin(&pending_pool)
            .await?;
        sqlx::query("SELECT id FROM organizations WHERE id=$1 FOR SHARE")
            .bind(org)
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT pg_sleep(60)").execute(&mut *tx).await?;
        Ok::<_, anyhow::Error>(())
    });
    timeout(Duration::from_secs(1), async {
        while !sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_stat_activity WHERE pid=$1 AND state='active' AND wait_event='PgSleep')")
            .bind(pid).fetch_one(&f.db.pool).await? {
            sleep(Duration::from_millis(5)).await;
        }
        Ok::<_, anyhow::Error>(())
    }).await??;
    operation.abort();
    assert!(operation.await.is_err_and(|error| error.is_cancelled()));
    let restored: (String, String) = timeout(
        Duration::from_secs(3),
        sqlx::query_as(settings).fetch_one(&pool),
    )
    .await
    .context("Abandoned SQL outlived its server deadline")??;
    assert_eq!(restored, original);
    let mut writer = f.db.pool.begin().await?;
    sqlx::query("SELECT id FROM organizations WHERE id=$1 FOR UPDATE NOWAIT")
        .bind(org)
        .execute(&mut *writer)
        .await?;
    writer.rollback().await?;
    pool.close().await;
    Ok(())
}

/// Foreign/non-manager requests must fail before queuing behind a known tenant's locked row.
#[tokio::test]
async fn tenant_mutation_foreign_and_nonmanager_requests_do_not_join_lock_queues() -> Result<()> {
    let Some(f) = Fixture::new().await? else {
        return Ok(());
    };
    let foreign = insert_active_user(&f.db.pool, "foreign-deadline@example.com").await?;
    let member = insert_active_user(&f.db.pool, "member-deadline@example.com").await?;
    insert_member_role(&f.db.pool, f.org, member, "member").await?;
    let tokens = [
        insert_session(&f.db.pool, foreign).await?,
        insert_session(&f.db.pool, member).await?,
    ];
    let router = router(&f, MutationPolicy::new(50, 2000, 16)?)?;
    let before = snapshot(&f.db.pool).await?;
    let mut held = f.db.pool.begin().await?;
    sqlx::query("SELECT id FROM organizations WHERE id=$1 FOR UPDATE")
        .bind(f.org)
        .execute(&mut *held)
        .await?;
    for token in &tokens {
        for mutation in mutations(&f).into_iter().skip(1) {
            let response = timeout(
                Duration::from_secs(3),
                request(
                    &router,
                    mutation.method,
                    &mutation.path,
                    token,
                    mutation.payload,
                ),
            )
            .await
            .context("unauthorized mutation queued")??;
            assert_eq!(response.0, StatusCode::NOT_FOUND);
        }
    }
    held.rollback().await?;
    assert_eq!(snapshot(&f.db.pool).await?, before);
    Ok(())
}

/// Independent pools model three/five replicas holding overlapping ancestry readers.
#[tokio::test]
async fn tenant_mutation_overlapping_replica_readers_have_bounded_failure_and_recovery()
-> Result<()> {
    let Some(f) = Fixture::new().await? else {
        return Ok(());
    };
    let router = router(&f, MutationPolicy::new(50, 2000, 16)?)?;
    for count in [3, 5] {
        let mut pools = Vec::new();
        for _ in 0..count {
            pools.push(
                PgPoolOptions::new()
                    .max_connections(1)
                    .connect_with(f.db.pool.connect_options().as_ref().clone())
                    .await?,
            );
        }
        let mut readers = Vec::new();
        for pool in &pools {
            let mut tx = pool.begin().await?;
            sqlx::query("SELECT id FROM organizations WHERE id=$1 FOR SHARE")
                .bind(f.org)
                .execute(&mut *tx)
                .await?;
            readers.push(tx);
        }
        let before = snapshot(&f.db.pool).await?;
        let response = timeout(
            Duration::from_secs(3),
            request(
                &router,
                "PATCH",
                "/v1/orgs/oauth-org",
                &f.token,
                Some(json!({"name":"After contention"})),
            ),
        )
        .await
        .context("overlapping readers starved writer indefinitely")??;
        unavailable(&response);
        assert_eq!(snapshot(&f.db.pool).await?, before);
        for tx in readers {
            tx.rollback().await?;
        }
        assert_eq!(
            request(
                &router,
                "PATCH",
                "/v1/orgs/oauth-org",
                &f.token,
                Some(json!({"name":"After contention"}))
            )
            .await?
            .0,
            StatusCode::OK
        );
        for pool in pools {
            pool.close().await;
        }
    }
    Ok(())
}

/// Commit, rollback and cancellation must restore settings and release partially acquired locks.
#[tokio::test]
async fn tenant_mutation_deadlines_are_local_and_cancellation_releases_ancestry() -> Result<()> {
    let Some(f) = Fixture::new().await? else {
        return Ok(());
    };
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(f.db.pool.connect_options().as_ref().clone())
        .await?;
    let settings = "SELECT current_setting('lock_timeout'),current_setting('statement_timeout')";
    let original: (String, String) = sqlx::query_as(settings).fetch_one(&pool).await?;
    let policy = MutationPolicy::new(50, 500, 16)?;
    for commit in [false, true] {
        let mut tx = policy.begin(&pool).await?;
        let actual: (String, String) = sqlx::query_as(settings).fetch_one(&mut *tx).await?;
        assert_eq!(actual, ("50ms".into(), "500ms".into()));
        if commit {
            tx.commit().await?;
        } else {
            tx.rollback().await?;
        }
        assert_eq!(
            sqlx::query_as::<_, (String, String)>(settings)
                .fetch_one(&pool)
                .await?,
            original
        );
    }
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let cancelled_pool = pool.clone();
    let org = f.org;
    let operation = tokio::spawn(async move {
        policy
            .respond(async move {
                let Ok(mut tx) = policy.begin(&cancelled_pool).await else {
                    return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                };
                if sqlx::query("SELECT id FROM organizations WHERE id=$1 FOR SHARE")
                    .bind(org)
                    .execute(&mut *tx)
                    .await
                    .is_err()
                {
                    return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                }
                let _ = started_tx.send(());
                let response = match sqlx::query("SELECT pg_sleep(10)").execute(&mut *tx).await {
                    Ok(_) => StatusCode::NO_CONTENT.into_response(),
                    Err(error) => OrgError::from(error).into_response(),
                };
                tx.rollback().await.ok();
                response
            })
            .await
    });
    timeout(Duration::from_secs(2), started_rx).await??;
    assert_eq!(
        timeout(Duration::from_secs(2), operation).await??.status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    // Reusing the sole connection flushes SQLx's queued rollback before the assertion.
    assert_eq!(
        sqlx::query_as::<_, (String, String)>(settings)
            .fetch_one(&pool)
            .await?,
        original
    );
    let mut writer = f.db.pool.begin().await?;
    sqlx::query("SELECT id FROM organizations WHERE id=$1 FOR UPDATE NOWAIT")
        .bind(f.org)
        .execute(&mut *writer)
        .await?;
    writer.rollback().await?;
    sqlx::query("SELECT set_config('lock_timeout','25ms',false),set_config('statement_timeout','250ms',false)")
        .execute(&pool).await?;
    let mut tx = policy.begin(&pool).await?;
    let stricter: (String, String) = sqlx::query_as(settings).fetch_one(&mut *tx).await?;
    assert_eq!(stricter, ("25ms".into(), "250ms".into()));
    tx.rollback().await?;
    assert_eq!(
        sqlx::query_as::<_, (String, String)>(settings)
            .fetch_one(&pool)
            .await?,
        stricter
    );
    pool.close().await;
    Ok(())
}
