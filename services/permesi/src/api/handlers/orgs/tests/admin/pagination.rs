//! Independent page-oracle regressions, including equal timestamps and foreign cursor anchors.

use super::*;

/// All four collections remain bounded, complete and duplicate-free with timestamp ties.
#[tokio::test]
async fn inspection_paginates_every_level_without_omissions_or_duplicates() -> Result<()> {
    let f = Fixture::new().await?;
    let paths = f.foreign.paths("/v1/admin/orgs");
    for (table, sql, parent, initial, index) in [
        (
            "organizations",
            "INSERT INTO organizations(id,slug,name,created_by) VALUES($1,$2,$2,$3)",
            f.operator,
            vec![f.own.org, f.foreign.org],
            0,
        ),
        (
            "projects",
            "INSERT INTO projects(id,slug,name,org_id) VALUES($1,$2,$2,$3)",
            f.foreign.org,
            vec![f.foreign.project],
            2,
        ),
        (
            "environments",
            "INSERT INTO environments(id,slug,name,project_id) VALUES($1,$2,$2,$3)",
            f.foreign.project,
            vec![f.foreign.environment],
            4,
        ),
        (
            "applications",
            "INSERT INTO applications(id,name,environment_id) VALUES($1,$2,$3)",
            f.foreign.environment,
            vec![f.foreign.application],
            6,
        ),
    ] {
        let mut expected = initial;
        for index in 1..=60 {
            let id = Uuid::from_u128(index);
            sqlx::query(sql)
                .bind(id)
                .bind(format!("page-item-{index}"))
                .bind(parent)
                .execute(&f.db.pool)
                .await?;
            expected.push(id);
        }
        sqlx::QueryBuilder::<sqlx::Postgres>::new("UPDATE ")
            .push(table)
            .push(" SET created_at='2026-01-01T00:00:00Z'")
            .build()
            .execute(&f.db.pool)
            .await?;
        expected.sort_unstable_by(|a, b| b.cmp(a));
        let path = paths.get(index).context("collection path")?;
        assert_eq!(collect_pages(&f, path).await?, expected);
        for cursor in ["invalid".to_owned(), Uuid::new_v4().to_string()] {
            assert_eq!(
                request(
                    &f.router,
                    &f.token,
                    "GET",
                    &format!("{path}?after={cursor}"),
                    None
                )
                .await?
                .0,
                StatusCode::BAD_REQUEST
            );
        }
    }
    let wrong_cursor = format!(
        "/v1/admin/orgs/{}/projects?after={}",
        f.foreign.slug, f.own.project
    );
    assert_eq!(
        request(&f.router, &f.token, "GET", &wrong_cursor, None)
            .await?
            .0,
        StatusCode::BAD_REQUEST
    );
    Ok(())
}

/// Walks actual response cursors and enforces bounded pages and the metadata allowlist.
async fn collect_pages(f: &Fixture, path: &str) -> Result<Vec<Uuid>> {
    let mut seen = Vec::new();
    let mut cursor = None;
    for _ in 0..4 {
        let path = cursor.as_ref().map_or_else(
            || path.to_owned(),
            |cursor| format!("{path}?after={cursor}"),
        );
        let (status, body) = request(&f.router, &f.token, "GET", &path, None).await?;
        assert_eq!(status, StatusCode::OK);
        let items = body
            .get("items")
            .and_then(Value::as_array)
            .context("page items")?;
        assert_ne!(items.len(), 0);
        assert!(items.len() <= 50);
        for row in items {
            assert!(
                row.as_object().context("metadata")?.keys().all(|key| [
                    "id",
                    "name",
                    "slug",
                    "tier",
                    "created_at"
                ]
                .contains(&key.as_str()))
            );
            let id = Uuid::parse_str(row["id"].as_str().context("metadata id")?)?;
            assert!(!seen.contains(&id));
            seen.push(id);
        }
        cursor = body
            .get("next_cursor")
            .and_then(Value::as_str)
            .map(str::to_owned);
        if cursor.is_none() {
            return Ok(seen);
        }
        assert_eq!(items.len(), 50);
    }
    anyhow::bail!("Pagination never reached its final page")
}
