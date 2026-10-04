//! Short transactions serialize consent, request completion, and client configuration.
//!
//! Shared client locks precede request/grant/code locks, allowing independent users
//! while excluding configuration writes. Grant insertion handles unique-index races;
//! configured lock waits are bounded. Shared ancestry, membership, user,
//! session, registry and allow-list locks prevent lifecycle changes during issuance.
//! Request handles and browser cookies alone authorize nothing; full sessions and
//! current tenant authority are independently required before consent or code issuance.

use chrono::{DateTime, Utc};
use sqlx::{PgPool, Postgres, Row, Transaction, postgres::PgRow};
use subtle::ConstantTimeEq;
use uuid::Uuid;

use super::{
    Error, ProtocolError,
    crypto::SecretValue,
    request::{AuthorizationInput, RequestedScope, ValidatedRequest},
};
use crate::oauth::{client::ClientType, config::OAuthConfig, redirect_uri::RedirectUri};

/// Exact active ancestry resolved from PostgreSQL, never a browser-selected resource.
pub(super) struct ClientContext {
    pub id: Uuid,
    pub application_id: Uuid,
    pub organization_id: Uuid,
    pub client_type: ClientType,
    pub client_name: String,
    pub application_name: String,
    pub organization_name: String,
}

/// Existing full session identity and its hash; the transaction rechecks active state.
pub(crate) struct SessionBinding {
    pub user_id: Uuid,
    pub hash: Vec<u8>,
}

/// Explicit user action; only Allow adds the exact request to saved consent.
pub(crate) enum Decision {
    Resume,
    Allow(SecretValue),
    Cancel(SecretValue),
}

/// Results expose presentation metadata or protocol responses, never raw persisted authority.
pub(crate) enum Outcome {
    Login {
        request_id: Uuid,
        expires_at: DateTime<Utc>,
    },
    Consent {
        request_id: Uuid,
        csrf: SecretValue,
        client: String,
        application: String,
        organization: String,
        scopes: Vec<RequestedScope>,
    },
    Redirect {
        redirect: RedirectUri,
        code: SecretValue,
        state: Option<String>,
    },
    Denied {
        redirect: RedirectUri,
        state: Option<String>,
    },
}

/// Stateless service instances share only PostgreSQL and explicit deployment policy.
pub(crate) struct AuthorizationService<'a> {
    pub pool: &'a PgPool,
    pub config: &'a OAuthConfig,
}

/// Persisted authority snapshot. Raw browser cookies, CSRF tokens and codes are absent.
pub(super) struct RequestRecord {
    pub id: Uuid,
    pub public_id: Uuid,
    pub client_id: Uuid,
    pub application_id: Uuid,
    pub organization_id: Uuid,
    pub redirect: String,
    pub scope_ids: Vec<Uuid>,
    pub scope_names: Vec<String>,
    pub state: Option<String>,
    pub challenge: String,
    pub nonce: Option<String>,
    pub prompt: String,
    pub user_id: Option<Uuid>,
    pub session_hash: Option<Vec<u8>>,
    pub csrf_hash: Option<Vec<u8>>,
    pub expires_at: DateTime<Utc>,
}

impl RequestRecord {
    /// Decodes only reviewed binding fields after browser/expiry/issuer filtering.
    fn decode(row: &PgRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            id: row.try_get("id")?,
            public_id: row.try_get("public_id")?,
            client_id: row.try_get("client_id")?,
            application_id: row.try_get("application_id")?,
            organization_id: row.try_get("organization_id")?,
            redirect: row.try_get("redirect_uri")?,
            scope_ids: row.try_get("scope_ids")?,
            scope_names: row.try_get("scope_names")?,
            state: row.try_get("state")?,
            challenge: row.try_get("code_challenge")?,
            nonce: row.try_get("nonce")?,
            prompt: row.try_get("prompt")?,
            user_id: row.try_get("user_id")?,
            session_hash: row.try_get("session_hash")?,
            csrf_hash: row.try_get("csrf_hash")?,
            expires_at: row.try_get("expires_at")?,
        })
    }
}

impl AuthorizationService<'_> {
    /// Validates and persists an immutable request snapshot before login, excluding raw
    /// browser capability material. Database time controls expiration on every replica.
    pub(crate) async fn start(
        &self,
        input: AuthorizationInput,
        browser: &SecretValue,
    ) -> Result<Uuid, Error> {
        let mut tx = self.pool.begin().await?;
        set_lock_timeout(&mut tx, self.config).await?;
        let request = input.validate(&mut tx).await?;
        let id = self.persist_request(&mut tx, &request, browser).await?;
        tx.commit().await?;
        Ok(id)
    }

    /// Persists only validated redirect/scope/PKCE/tenant inputs with configured TTL.
    async fn persist_request(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        request: &ValidatedRequest,
        browser: &SecretValue,
    ) -> Result<Uuid, Error> {
        let ids: Vec<_> = request.scopes.iter().map(|s| s.id).collect();
        let names: Vec<_> = request.scopes.iter().map(|s| s.name.as_str()).collect();
        Ok(sqlx::query_scalar("INSERT INTO oauth_authorization_requests (client_id,application_id,organization_id,redirect_uri,scope_ids,scope_names,code_challenge,state,nonce,prompt,issuer,audience,browser_hash,expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,statement_timestamp()+($14::bigint * INTERVAL '1 second')) RETURNING id")
            .bind(request.context.id).bind(request.context.application_id).bind(request.context.organization_id).bind(request.redirect.as_str())
            .bind(ids).bind(names).bind(request.challenge.as_str()).bind(&request.state).bind(&request.nonce).bind(&request.prompt)
            .bind(&self.config.issuer).bind(&self.config.audience).bind(browser.hash()).bind(self.config.request_ttl)
            .fetch_one(&mut **tx).await?)
    }

    /// Resumes under current lifecycle and session locks. Browser input can only select
    /// an opaque request and Allow/Cancel; it cannot submit or enlarge the stored scopes.
    pub(crate) async fn advance(
        &self,
        id: Uuid,
        browser: &SecretValue,
        session: Option<&SessionBinding>,
        decision: Decision,
    ) -> Result<Outcome, Error> {
        let mut tx = self.pool.begin().await?;
        set_lock_timeout(&mut tx, self.config).await?;
        let initial = self.load_request(&mut tx, id, browser, false).await?;
        let context = lock_client(&mut tx, initial.public_id).await?;
        let request = self.load_request(&mut tx, id, browser, true).await?;
        let redirect = RedirectUri::parse(request.redirect.clone(), context.client_type)
            .map_err(|_| Error::protocol(ProtocolError::InvalidRequest))?;
        if request.client_id != context.id
            || request.application_id != context.application_id
            || request.organization_id != context.organization_id
            || !registered_redirect(&mut tx, &context, redirect.as_str()).await?
        {
            return Err(Error::protocol(ProtocolError::InvalidRequest));
        }
        let result = self
            .advance_locked(&mut tx, &request, &context, session, decision, &redirect)
            .await
            .map_err(|err| err.with_redirect(redirect, request.state.clone()))?;
        tx.commit().await?;
        Ok(result)
    }

    /// Filters request handles with browser binding and database clock before decoding.
    async fn load_request(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        id: Uuid,
        browser: &SecretValue,
        lock: bool,
    ) -> Result<RequestRecord, Error> {
        let query = if lock {
            "SELECT r.*, c.client_id AS public_id FROM oauth_authorization_requests r JOIN oauth_clients c ON c.id=r.client_id WHERE r.id=$1 AND r.browser_hash=$2 AND r.completed_at IS NULL AND r.expires_at>clock_timestamp() AND r.issuer=$3 AND r.audience=$4 FOR UPDATE OF r"
        } else {
            "SELECT r.*, c.client_id AS public_id FROM oauth_authorization_requests r JOIN oauth_clients c ON c.id=r.client_id WHERE r.id=$1 AND r.browser_hash=$2 AND r.completed_at IS NULL AND r.expires_at>clock_timestamp() AND r.issuer=$3 AND r.audience=$4"
        };
        let row = sqlx::query(query)
            .bind(id)
            .bind(browser.hash())
            .bind(&self.config.issuer)
            .bind(&self.config.audience)
            .fetch_optional(&mut **tx)
            .await?
            .ok_or_else(|| Error::protocol(ProtocolError::InvalidRequest))?;
        Ok(RequestRecord::decode(&row)?)
    }

    /// Rechecks registry snapshots and active tenant/session authority before considering
    /// saved consent. Existing consent only skips UI when it covers every requested ID.
    async fn advance_locked(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        request: &RequestRecord,
        context: &ClientContext,
        session: Option<&SessionBinding>,
        decision: Decision,
        redirect: &RedirectUri,
    ) -> Result<Outcome, Error> {
        let scopes = current_scopes(
            tx,
            context.id,
            context.application_id,
            &request.scope_ids,
            &request.scope_names,
        )
        .await?;
        let Some(session) = session else {
            if !matches!(decision, Decision::Resume) {
                return Err(Error::protocol(ProtocolError::AccessDenied));
            }
            return if request.prompt == "none" {
                Err(Error::protocol(ProtocolError::LoginRequired))
            } else {
                Ok(Outcome::Login {
                    request_id: request.id,
                    expires_at: request.expires_at,
                })
            };
        };
        let auth_time = lock_session_membership(tx, context.organization_id, session).await?;
        if request.user_id.is_some_and(|id| id != session.user_id)
            || request
                .session_hash
                .as_ref()
                .is_some_and(|hash| !bool::from(hash.ct_eq(&session.hash)))
        {
            return Err(Error::protocol(ProtocolError::AccessDenied));
        }
        bind_session(tx, request.id, session).await?;
        match &decision {
            Decision::Allow(csrf) | Decision::Cancel(csrf) => {
                if request.user_id.is_none()
                    || !request
                        .csrf_hash
                        .as_ref()
                        .is_some_and(|hash| bool::from(hash.ct_eq(&csrf.hash())))
                {
                    return Err(Error::protocol(ProtocolError::AccessDenied));
                }
            }
            Decision::Resume => {}
        }
        if matches!(decision, Decision::Cancel(_)) {
            complete_request(tx, request.id).await?;
            // Commit cancellation before returning the protocol error to prevent replay.
            return Ok(Outcome::Denied {
                redirect: redirect.clone(),
                state: request.state.clone(),
            });
        }
        let grant = active_grant(tx, request, session.user_id).await?;
        let covered = match grant {
            Some(id) => grant_covers(tx, id, &request.scope_ids).await?,
            None => false,
        };
        if matches!(decision, Decision::Resume) && (!covered || request.prompt == "consent") {
            if request.prompt == "none" {
                return Err(Error::protocol(ProtocolError::ConsentRequired));
            }
            let csrf = SecretValue::generate()?;
            sqlx::query("UPDATE oauth_authorization_requests SET user_id=$2,session_hash=$3,csrf_hash=$4 WHERE id=$1")
                .bind(request.id).bind(session.user_id).bind(&session.hash).bind(csrf.hash()).execute(&mut **tx).await?;
            return Ok(Outcome::Consent {
                request_id: request.id,
                csrf,
                client: context.client_name.clone(),
                application: context.application_name.clone(),
                organization: context.organization_name.clone(),
                scopes,
            });
        }
        let grant_id = if matches!(decision, Decision::Allow(_)) {
            save_grant(tx, request, session.user_id, grant).await?
        } else {
            grant.ok_or_else(|| Error::protocol(ProtocolError::ConsentRequired))?
        };
        self.issue_code(tx, request, session.user_id, grant_id, auth_time, redirect)
            .await
    }

    /// Completes the one-use request and inserts only a code hash in the same transaction.
    async fn issue_code(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        request: &RequestRecord,
        user_id: Uuid,
        grant_id: Uuid,
        auth_time: DateTime<Utc>,
        redirect: &RedirectUri,
    ) -> Result<Outcome, Error> {
        let code = SecretValue::generate()?;
        sqlx::query("INSERT INTO oauth_authorization_codes (code_hash,request_id,grant_id,client_id,application_id,organization_id,user_id,redirect_uri,scope_ids,scope_names,code_challenge,nonce,issuer,audience,auth_time,expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,statement_timestamp()+($16::bigint * INTERVAL '1 second'))")
            .bind(code.hash()).bind(request.id).bind(grant_id).bind(request.client_id).bind(request.application_id).bind(request.organization_id).bind(user_id).bind(&request.redirect).bind(&request.scope_ids).bind(&request.scope_names).bind(&request.challenge).bind(&request.nonce).bind(&self.config.issuer).bind(&self.config.audience).bind(auth_time).bind(self.config.code_ttl)
            .execute(&mut **tx).await?;
        complete_request(tx, request.id).await?;
        Ok(Outcome::Redirect {
            redirect: redirect.clone(),
            code,
            state: request.state.clone(),
        })
    }
}

/// Locks active client and all ancestors against management/lifecycle mutations.
/// These locks prove registration status, not membership or delegated scope authority.
pub(super) async fn lock_client(
    tx: &mut Transaction<'_, Postgres>,
    public_id: Uuid,
) -> Result<ClientContext, Error> {
    crate::oauth::locking::client(tx, public_id, false).await?;
    let row = sqlx::query("SELECT c.id,c.application_id,c.client_type,c.name AS client_name,a.name AS application_name,o.name AS organization_name,o.id AS organization_id FROM oauth_clients c JOIN applications a ON a.id=c.application_id JOIN environments e ON e.id=a.environment_id JOIN projects p ON p.id=e.project_id JOIN organizations o ON o.id=p.org_id WHERE c.client_id=$1 AND c.disabled_at IS NULL AND c.deleted_at IS NULL AND a.deleted_at IS NULL AND e.deleted_at IS NULL AND p.deleted_at IS NULL AND o.deleted_at IS NULL FOR SHARE OF c,a,e,p,o")
        .bind(public_id).fetch_optional(&mut **tx).await?.ok_or_else(|| Error::protocol(ProtocolError::InvalidRequest))?;
    let client_type = match row.try_get::<&str, _>("client_type")? {
        "public" => ClientType::Public,
        "confidential" => ClientType::Confidential,
        _ => return Err(Error::protocol(ProtocolError::InvalidRequest)),
    };
    Ok(ClientContext {
        id: row.try_get("id")?,
        application_id: row.try_get("application_id")?,
        organization_id: row.try_get("organization_id")?,
        client_type,
        client_name: row.try_get("client_name")?,
        application_name: row.try_get("application_name")?,
        organization_name: row.try_get("organization_name")?,
    })
}

/// Authorizes a redirect only by exact bytes in this locked client's registration.
pub(super) async fn registered_redirect(
    tx: &mut Transaction<'_, Postgres>,
    context: &ClientContext,
    redirect: &str,
) -> Result<bool, Error> {
    Ok(sqlx::query_scalar::<_, String>("SELECT redirect_uri FROM oauth_client_redirect_uris WHERE client_id=$1 AND redirect_uri=$2 FOR SHARE")
        .bind(context.id).bind(redirect).fetch_optional(&mut **tx).await?.is_some())
}

/// Rechecks all scope IDs/names and locks registry and client edges against removal.
/// This verifies configured authority only; consent and membership are separate checks.
pub(super) async fn current_scopes(
    tx: &mut Transaction<'_, Postgres>,
    client_id: Uuid,
    application_id: Uuid,
    ids: &[Uuid],
    names: &[String],
) -> Result<Vec<RequestedScope>, Error> {
    let rows = sqlx::query("SELECT s.id,s.name,s.description FROM oauth_scopes s JOIN oauth_client_scopes cs ON cs.scope_id=s.id AND cs.application_id=s.application_id WHERE cs.client_id=$1 AND s.application_id=$2 AND s.id=ANY($3) ORDER BY s.id FOR SHARE OF s,cs")
        .bind(client_id).bind(application_id).bind(ids).fetch_all(&mut **tx).await?;
    if rows.len() != ids.len() || ids.len() != names.len() {
        return Err(Error::protocol(ProtocolError::InvalidScope));
    }
    let mut result = Vec::new();
    for (id, name) in ids.iter().zip(names) {
        let row = rows
            .iter()
            .find(|r| {
                r.try_get::<Uuid, _>("id").is_ok_and(|v| v == *id)
                    && r.try_get::<String, _>("name").is_ok_and(|v| v == *name)
            })
            .ok_or_else(|| Error::protocol(ProtocolError::InvalidScope))?;
        result.push(RequestedScope {
            id: *id,
            name: name.clone(),
            description: row.try_get("description")?,
        });
    }
    Ok(result)
}

/// Authorizes only an active full session/user with active membership in the client's
/// owning org. No platform role bypass or cross-org membership expansion is allowed.
async fn lock_session_membership(
    tx: &mut Transaction<'_, Postgres>,
    org: Uuid,
    session: &SessionBinding,
) -> Result<DateTime<Utc>, Error> {
    sqlx::query_scalar("SELECT s.auth_time FROM user_sessions s JOIN users u ON u.id=s.user_id JOIN org_memberships m ON m.user_id=u.id WHERE s.session_hash=$1 AND s.user_id=$2 AND m.org_id=$3 AND s.expires_at>clock_timestamp() AND u.status='active' AND m.status='active' FOR SHARE OF s,u,m")
        .bind(&session.hash).bind(session.user_id).bind(org).fetch_optional(&mut **tx).await?.ok_or_else(|| Error::protocol(ProtocolError::AccessDenied))
}

/// Locks current consent in the exact user/client/application/organization context.
async fn active_grant(
    tx: &mut Transaction<'_, Postgres>,
    request: &RequestRecord,
    user: Uuid,
) -> Result<Option<Uuid>, Error> {
    Ok(sqlx::query_scalar("SELECT id FROM oauth_grants WHERE client_id=$1 AND application_id=$2 AND organization_id=$3 AND user_id=$4 AND revoked_at IS NULL FOR UPDATE")
        .bind(request.client_id).bind(request.application_id).bind(request.organization_id).bind(user).fetch_optional(&mut **tx).await?)
}

/// Authorizes skipping consent only when the locked saved grant covers every requested
/// registry ID. This is a server-side upper-bound intersection, never a browser flag.
pub(super) async fn grant_covers(
    tx: &mut Transaction<'_, Postgres>,
    grant: Uuid,
    scopes: &[Uuid],
) -> Result<bool, Error> {
    let rows = sqlx::query_scalar::<_, Uuid>(
        "SELECT scope_id FROM oauth_grant_scopes WHERE grant_id=$1 AND scope_id=ANY($2) FOR SHARE",
    )
    .bind(grant)
    .bind(scopes)
    .fetch_all(&mut **tx)
    .await?;
    Ok(rows.len() == scopes.len())
}

/// Records explicit consent for exactly the stored request, preserving prior consent
/// as a superset without adding any of that prior authority to the newly issued code.
async fn save_grant(
    tx: &mut Transaction<'_, Postgres>,
    request: &RequestRecord,
    user: Uuid,
    existing: Option<Uuid>,
) -> Result<Uuid, Error> {
    let grant = if let Some(id) = existing {
        id
    } else {
        let inserted = sqlx::query_scalar("INSERT INTO oauth_grants (user_id,client_id,application_id,organization_id) VALUES ($1,$2,$3,$4) ON CONFLICT (user_id,client_id,organization_id) WHERE revoked_at IS NULL DO NOTHING RETURNING id")
                .bind(user).bind(request.client_id).bind(request.application_id).bind(request.organization_id).fetch_optional(&mut **tx).await?;
        match inserted {
            Some(id) => id,
            None => active_grant(tx, request, user)
                .await?
                .ok_or_else(|| Error::protocol(ProtocolError::AccessDenied))?,
        }
    };
    for scope in &request.scope_ids {
        sqlx::query("INSERT INTO oauth_grant_scopes (grant_id,client_id,application_id,scope_id) VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING")
            .bind(grant).bind(request.client_id).bind(request.application_id).bind(scope).execute(&mut **tx).await?;
    }
    Ok(grant)
}

/// Bounds lock attempts and complete statements independently of pool acquisition; applies only to this
/// transaction and never changes authorization predicates or transaction isolation.
pub(super) async fn set_lock_timeout(
    tx: &mut Transaction<'_, Postgres>,
    config: &OAuthConfig,
) -> Result<(), Error> {
    crate::oauth::locking::deadline(tx, config.lock_timeout_ms).await?;
    Ok(())
}

/// Irreversibly completes one unexpired request while its row lock is held.
async fn complete_request(tx: &mut Transaction<'_, Postgres>, id: Uuid) -> Result<(), Error> {
    let updated = sqlx::query("UPDATE oauth_authorization_requests SET completed_at=clock_timestamp() WHERE id=$1 AND completed_at IS NULL AND expires_at>clock_timestamp()")
        .bind(id).execute(&mut **tx).await?;
    if updated.rows_affected() != 1 {
        return Err(Error::protocol(ProtocolError::InvalidRequest));
    }
    Ok(())
}

/// Binds the first successful full session permanently, including when saved consent skips UI.
async fn bind_session(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
    session: &SessionBinding,
) -> Result<(), Error> {
    sqlx::query("UPDATE oauth_authorization_requests SET user_id=$2,session_hash=$3 WHERE id=$1")
        .bind(id)
        .bind(session.user_id)
        .bind(&session.hash)
        .execute(&mut **tx)
        .await?;
    Ok(())
}
