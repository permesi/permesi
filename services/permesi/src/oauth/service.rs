//! Transactional OAuth registration storage behind an authenticated application context.
//!
//! HTTP adapters resolve the full active tenant hierarchy using existing org policy.
//! This layer accepts only that context, typed configuration, and path-bound client IDs;
//! no body can select another application. Composite foreign keys prevent cross-application
//! scope assignments. Client row locks serialize configuration/lifecycle changes;
//! requested registry rows are locked before changing consent or scope edges to avoid
//! lock-order cycles with scope deletion. Allow-list replacements revoke saved consent.

use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use super::{
    ValidationError,
    client::{Client, ClientConfiguration},
    redirect_uri::RedirectUri,
    scope::{ApplicationScope, OAuthScope, PROTOCOL_SCOPES, ScopeRecord},
};

/// Trusted application boundary resolved from session membership and active ancestry.
pub(crate) struct ApplicationContext {
    application_id: Uuid,
}

impl ApplicationContext {
    /// Constructs a context ONLY after verifying session, org roles, and full ancestry.
    /// This is not proof of an OAuth resource owner's delegated authority.
    pub(crate) fn resolved(application_id: Uuid) -> Self {
        Self { application_id }
    }
}

#[derive(Debug)]
pub(crate) enum Error {
    NotFound,
    Invalid(ValidationError),
    Conflict,
    Database(sqlx::Error),
}

impl From<ValidationError> for Error {
    fn from(error: ValidationError) -> Self {
        Self::Invalid(error)
    }
}

impl From<sqlx::Error> for Error {
    /// Maps integrity failures without exposing database detail or configured values.
    fn from(error: sqlx::Error) -> Self {
        match error
            .as_database_error()
            .and_then(sqlx::error::DatabaseError::code)
            .as_deref()
        {
            Some("23505") => Self::Conflict,
            Some("23503" | "23514") => {
                Self::Invalid(ValidationError("Invalid OAuth configuration."))
            }
            _ => Self::Database(error),
        }
    }
}

/// Creates a registration and both allow-lists atomically under the resolved application.
pub(crate) async fn create_client(
    pool: &PgPool,
    context: &ApplicationContext,
    config: ClientConfiguration,
) -> Result<Client, Error> {
    let mut tx = pool.begin().await?;
    let scope_ids = resolve_scope_ids(&mut tx, context, &config.scopes).await?;
    let client = sqlx::query_as::<_, Client>(
        "INSERT INTO oauth_clients (application_id, name, client_type) VALUES ($1, $2, $3) RETURNING *",
    )
    .bind(context.application_id).bind(config.name).bind(config.client_type.as_str())
    .fetch_one(&mut *tx).await?;
    write_redirects(&mut tx, client.id, &config.redirects).await?;
    write_scopes(&mut tx, context, client.id, &scope_ids).await?;
    tx.commit().await?;
    Ok(client)
}

/// Lists registrations including disabled clients, excluding soft-deleted rows.
pub(crate) async fn list_clients(
    pool: &PgPool,
    context: &ApplicationContext,
) -> Result<Vec<Client>, Error> {
    Ok(sqlx::query_as("SELECT * FROM oauth_clients WHERE application_id = $1 AND deleted_at IS NULL ORDER BY created_at, id")
        .bind(context.application_id).fetch_all(pool).await?)
}

/// Resolves a public identifier exclusively within the authenticated application.
pub(crate) async fn get_client(
    pool: &PgPool,
    context: &ApplicationContext,
    client_id: Uuid,
) -> Result<Client, Error> {
    sqlx::query_as("SELECT * FROM oauth_clients WHERE application_id = $1 AND client_id = $2 AND deleted_at IS NULL")
        .bind(context.application_id).bind(client_id).fetch_optional(pool).await?
        .ok_or(Error::NotFound)
}

/// Locks a registration in its resolved application; disabled rows remain manageable.
async fn lock_client(
    tx: &mut Transaction<'_, Postgres>,
    context: &ApplicationContext,
    client_id: Uuid,
) -> Result<Client, Error> {
    sqlx::query_as("SELECT * FROM oauth_clients WHERE application_id = $1 AND client_id = $2 AND deleted_at IS NULL FOR UPDATE")
        .bind(context.application_id).bind(client_id).fetch_optional(&mut **tx).await?
        .ok_or(Error::NotFound)
}

/// Updates display/lifecycle fields; client type and identifiers cannot be changed.
/// Disabling irreversibly revokes credentials and saved grants; re-enabling does not restore them.
pub(crate) async fn patch_client(
    pool: &PgPool,
    context: &ApplicationContext,
    client_id: Uuid,
    name: Option<String>,
    disabled: Option<bool>,
) -> Result<Client, Error> {
    if name.is_none() && disabled.is_none() {
        return Err(ValidationError("At least one client field is required.").into());
    }
    let name = name
        .as_deref()
        .map(super::client::validate_name)
        .transpose()?;
    let mut tx = pool.begin().await?;
    let client = lock_client(&mut tx, context, client_id).await?;
    if disabled == Some(true) {
        revoke_grants(&mut tx, client.id).await?;
        sqlx::query("UPDATE oauth_client_secrets SET revoked_at = NOW() WHERE client_id = $1 AND revoked_at IS NULL")
            .bind(client.id).execute(&mut *tx).await?;
    }
    let updated = sqlx::query_as(
        "UPDATE oauth_clients SET name = COALESCE($2, name), disabled_at = CASE
         WHEN $3 = TRUE THEN COALESCE(disabled_at, NOW()) WHEN $3 = FALSE THEN NULL ELSE disabled_at END
         WHERE id = $1 RETURNING *",
    ).bind(client.id).bind(name).bind(disabled).fetch_one(&mut *tx).await?;
    tx.commit().await?;
    Ok(updated)
}

/// Soft-deletes a client, retaining its globally reserved public ID and revoking authority.
pub(crate) async fn delete_client(
    pool: &PgPool,
    context: &ApplicationContext,
    client_id: Uuid,
) -> Result<(), Error> {
    let mut tx = pool.begin().await?;
    let client = lock_client(&mut tx, context, client_id).await?;
    revoke_grants(&mut tx, client.id).await?;
    sqlx::query("UPDATE oauth_client_secrets SET revoked_at = NOW() WHERE client_id = $1 AND revoked_at IS NULL")
        .bind(client.id).execute(&mut *tx).await?;
    sqlx::query("UPDATE oauth_clients SET disabled_at = COALESCE(disabled_at, NOW()), deleted_at = NOW() WHERE id = $1")
        .bind(client.id).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(())
}

/// Reads exact registered redirect strings only after application-scoped client resolution.
pub(crate) async fn get_redirects(
    pool: &PgPool,
    context: &ApplicationContext,
    client_id: Uuid,
) -> Result<Vec<String>, Error> {
    let client = get_client(pool, context, client_id).await?;
    Ok(sqlx::query_scalar("SELECT redirect_uri FROM oauth_client_redirect_uris WHERE client_id = $1 ORDER BY redirect_uri")
        .bind(client.id).fetch_all(pool).await?)
}

/// Replaces redirects atomically under a client lock; no partial registration survives validation.
pub(crate) async fn replace_redirects(
    pool: &PgPool,
    context: &ApplicationContext,
    client_id: Uuid,
    values: Vec<String>,
) -> Result<Vec<String>, Error> {
    let mut tx = pool.begin().await?;
    let client = lock_client(&mut tx, context, client_id).await?;
    let redirects = RedirectUri::validate_list(values, client.client_type)?;
    revoke_grants(&mut tx, client.id).await?;
    sqlx::query("DELETE FROM oauth_client_redirect_uris WHERE client_id = $1")
        .bind(client.id)
        .execute(&mut *tx)
        .await?;
    write_redirects(&mut tx, client.id, &redirects).await?;
    touch_client(&mut tx, client.id).await?;
    tx.commit().await?;
    Ok(redirects
        .iter()
        .map(|uri| uri.as_str().to_owned())
        .collect())
}

/// Inserts validated original URI strings, relying on a primary key to reject duplicates.
async fn write_redirects(
    tx: &mut Transaction<'_, Postgres>,
    client_id: Uuid,
    redirects: &[RedirectUri],
) -> Result<(), Error> {
    for redirect in redirects {
        sqlx::query(
            "INSERT INTO oauth_client_redirect_uris (client_id, redirect_uri) VALUES ($1, $2)",
        )
        .bind(client_id)
        .bind(redirect.as_str())
        .execute(&mut **tx)
        .await?;
    }
    Ok(())
}

/// Reads the explicit configured allow-list, never Principal.scopes or request claims.
pub(crate) async fn get_client_scopes(
    pool: &PgPool,
    context: &ApplicationContext,
    client_id: Uuid,
) -> Result<Vec<String>, Error> {
    let client = get_client(pool, context, client_id).await?;
    Ok(sqlx::query_scalar(
        "SELECT s.name FROM oauth_scopes s JOIN oauth_client_scopes cs ON cs.scope_id = s.id
         WHERE cs.client_id = $1 AND cs.application_id = $2 ORDER BY s.name",
    )
    .bind(client.id)
    .bind(context.application_id)
    .fetch_all(pool)
    .await?)
}

/// Replaces the allow-list atomically, rejecting unknown/cross-application names.
/// Removing scope edges cascades to saved grant scopes and all saved consent is revoked.
pub(crate) async fn replace_client_scopes(
    pool: &PgPool,
    context: &ApplicationContext,
    client_id: Uuid,
    values: Vec<String>,
) -> Result<Vec<String>, Error> {
    let scopes = OAuthScope::validate_list(values)?;
    let mut tx = pool.begin().await?;
    let client = lock_client(&mut tx, context, client_id).await?;
    let scope_ids = resolve_scope_ids(&mut tx, context, &scopes).await?;
    revoke_grants(&mut tx, client.id).await?;
    sqlx::query("DELETE FROM oauth_client_scopes WHERE client_id = $1")
        .bind(client.id)
        .execute(&mut *tx)
        .await?;
    write_scopes(&mut tx, context, client.id, &scope_ids).await?;
    touch_client(&mut tx, client.id).await?;
    tx.commit().await?;
    Ok(scopes
        .iter()
        .map(|scope| scope.as_str().to_owned())
        .collect())
}

/// Resolves and key-share-locks the entire requested registry set before acquiring
/// grant/edge locks. A concurrent scope deletion either completes first (unknown scope)
/// or waits for this transaction, without a scope/edge lock-order cycle.
async fn resolve_scope_ids(
    tx: &mut Transaction<'_, Postgres>,
    context: &ApplicationContext,
    scopes: &[OAuthScope],
) -> Result<Vec<Uuid>, Error> {
    for scope in scopes {
        if !PROTOCOL_SCOPES.contains(&scope.as_str()) {
            ApplicationScope::parse(scope.as_str().to_owned())?;
        }
    }
    let names: Vec<&str> = scopes.iter().map(OAuthScope::as_str).collect();
    let ids: Vec<Uuid> = sqlx::query_scalar(
        "SELECT id FROM oauth_scopes WHERE application_id = $1 AND name = ANY($2)
         ORDER BY id FOR KEY SHARE",
    )
    .bind(context.application_id)
    .bind(names)
    .fetch_all(&mut **tx)
    .await?;
    if ids.len() != scopes.len() {
        return Err(ValidationError("Unknown application OAuth scope.").into());
    }
    Ok(ids)
}

/// Inserts application-constrained edges only after all registry rows have been locked.
async fn write_scopes(
    tx: &mut Transaction<'_, Postgres>,
    context: &ApplicationContext,
    client_id: Uuid,
    scope_ids: &[Uuid],
) -> Result<(), Error> {
    for scope_id in scope_ids {
        sqlx::query("INSERT INTO oauth_client_scopes (client_id, application_id, scope_id) VALUES ($1, $2, $3)")
            .bind(client_id).bind(context.application_id).bind(scope_id).execute(&mut **tx).await?;
    }
    Ok(())
}

/// Revokes saved consent under a client lock, without exposing user or grant metadata.
async fn revoke_grants(tx: &mut Transaction<'_, Postgres>, client_id: Uuid) -> Result<(), Error> {
    sqlx::query(
        "UPDATE oauth_grants SET revoked_at = NOW() WHERE client_id = $1 AND revoked_at IS NULL",
    )
    .bind(client_id)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// Advances client configuration time when child allow-lists change.
async fn touch_client(tx: &mut Transaction<'_, Postgres>, client_id: Uuid) -> Result<(), Error> {
    sqlx::query("UPDATE oauth_clients SET updated_at = clock_timestamp() WHERE id = $1")
        .bind(client_id)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

/// Lists both immutable protocol entries and mutable application scope records.
pub(crate) async fn list_scopes(
    pool: &PgPool,
    context: &ApplicationContext,
) -> Result<Vec<ScopeRecord>, Error> {
    Ok(
        sqlx::query_as("SELECT * FROM oauth_scopes WHERE application_id = $1 ORDER BY name")
            .bind(context.application_id)
            .fetch_all(pool)
            .await?,
    )
}

/// Validates and bounds scope descriptions without changing the scope name's case.
fn validate_description(value: &str) -> Result<(), ValidationError> {
    if value.chars().count() > 2048 || value.chars().any(|ch| ch.is_control() && ch != '\n') {
        return Err(ValidationError("Invalid OAuth scope description."));
    }
    Ok(())
}

/// Creates application API authority; reserved protocol/internal names cannot be defined.
pub(crate) async fn create_scope(
    pool: &PgPool,
    context: &ApplicationContext,
    name: String,
    description: String,
) -> Result<ScopeRecord, Error> {
    let name = ApplicationScope::parse(name)?;
    validate_description(&description)?;
    Ok(sqlx::query_as("INSERT INTO oauth_scopes (application_id, name, description, kind) VALUES ($1, $2, $3, 'application') RETURNING *")
        .bind(context.application_id).bind(name.as_str()).bind(description).fetch_one(pool).await?)
}

/// Updates descriptive text only; renaming delegated authority requires a new scope.
/// Protocol entries are not mutable through management APIs and resolve as 404.
pub(crate) async fn patch_scope(
    pool: &PgPool,
    context: &ApplicationContext,
    scope_id: Uuid,
    description: String,
) -> Result<ScopeRecord, Error> {
    validate_description(&description)?;
    sqlx::query_as("UPDATE oauth_scopes SET description = $3 WHERE application_id = $1 AND id = $2 AND kind = 'application' RETURNING *")
        .bind(context.application_id).bind(scope_id).bind(description).fetch_optional(pool).await?
        .ok_or(Error::NotFound)
}

/// Deletes API authority and cascades its allow-list/grant edges. Recreating the name
/// produces a new ID, so existing clients and consent cannot regain it implicitly.
pub(crate) async fn delete_scope(
    pool: &PgPool,
    context: &ApplicationContext,
    scope_id: Uuid,
) -> Result<(), Error> {
    let deleted = sqlx::query(
        "DELETE FROM oauth_scopes WHERE application_id = $1 AND id = $2 AND kind = 'application'",
    )
    .bind(context.application_id)
    .bind(scope_id)
    .execute(pool)
    .await?;
    if deleted.rows_affected() == 0 {
        return Err(Error::NotFound);
    }
    Ok(())
}
