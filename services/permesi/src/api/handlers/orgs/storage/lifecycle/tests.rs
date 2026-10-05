//! Direct regressions for the gap between tenant resolution and locked authorization.

use anyhow::{Context, Result};

use super::*;
use crate::api::handlers::orgs::{
    storage::{create_org_with_roles, update_org_record},
    tests::{TestDb, insert_active_user},
};

/// A committed slug replacement must not redirect an already-resolved deletion to another tenant.
#[tokio::test]
async fn organization_deletion_lock_rejects_a_reused_slug_with_stale_context() -> Result<()> {
    let Some(db) = TestDb::new().await? else {
        return Ok(());
    };
    let owner = insert_active_user(&db.pool, "slug-pin@lifecycle.test").await?;
    create_org_with_roles(&db.pool, owner, "Original", "reused")
        .await
        .map_err(|error| anyhow::anyhow!("{error:?}"))?;
    let original = resolve_org_context(&db.pool, owner, "reused")
        .await?
        .context("original tenant context")?;
    update_org_record(&db.pool, &original, None, Some("renamed"))
        .await
        .map_err(|error| anyhow::anyhow!("{error:?}"))?;
    let replacement = create_org_with_roles(&db.pool, owner, "Replacement", "reused")
        .await
        .map_err(|error| anyhow::anyhow!("{error:?}"))?;
    let replacement = Uuid::parse_str(&replacement.id)?;
    assert_ne!(replacement, original.id());

    // The replacement is committed before the locking statement starts. A query
    // using only the old slug would see and authorize the replacement owner here.
    let mut tx = db.pool.begin().await?;
    let result = lock_org(&mut tx, owner, "reused", original.id(), true).await;
    assert!(
        matches!(result, Err(OrgError::NotFound)),
        "The locked lookup must reject a reused slug bound to a different tenant UUID: {result:?}"
    );
    tx.rollback().await?;
    let active: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM organizations WHERE id=ANY($1) AND deleted_at IS NULL",
    )
    .bind(vec![original.id(), replacement])
    .fetch_one(&db.pool)
    .await?;
    assert_eq!(active, 2, "Both tenants must remain active");
    Ok(())
}
