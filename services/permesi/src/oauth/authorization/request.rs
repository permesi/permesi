//! Authorization input validation before HTTP authentication or consent behavior.
//!
//! Flow Overview: establish an active registration and exact trusted redirect first,
//! then parse response/scopes/S256/nonce/context. Errors carry a redirect only after
//! that boundary succeeds. Scope IDs and names are snapshotted together so deleting
//! and recreating a registry token cannot revive a pending authorization.

use serde::Deserialize;
use sqlx::{Postgres, Row, Transaction};
use utoipa::IntoParams;
use uuid::Uuid;

use super::{Error, ProtocolError, crypto::PkceChallenge, storage::ClientContext};
use crate::oauth::{redirect_uri::RedirectUri, scope::OAuthScope};

/// Decoded authorization parameters. Duplicate known parameters fail in Axum's parser;
/// unrecognized extensions are ignored, while unsupported authority inputs fail closed.
#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct AuthorizationInput {
    #[param(required = true)]
    pub client_id: Option<String>,
    #[param(required = true)]
    pub redirect_uri: Option<String>,
    #[param(required = true)]
    pub response_type: Option<String>,
    #[param(required = true)]
    pub scope: Option<String>,
    pub state: Option<String>,
    #[param(required = true)]
    pub code_challenge: Option<String>,
    #[param(required = true)]
    pub code_challenge_method: Option<String>,
    pub nonce: Option<String>,
    #[param(value_type=Option<String>, format="uuid")]
    pub organization_id: Option<Uuid>,
    pub prompt: Option<String>,
    pub response_mode: Option<String>,
    pub request: Option<String>,
    pub request_uri: Option<String>,
    pub claims: Option<String>,
    pub resource: Option<String>,
    pub audience: Option<String>,
    pub max_age: Option<String>,
    pub id_token_hint: Option<String>,
    pub acr_values: Option<String>,
}

/// Trusted and typed request snapshot; no session permissions are accepted by this type.
pub(super) struct ValidatedRequest {
    pub context: ClientContext,
    pub redirect: RedirectUri,
    pub scopes: Vec<RequestedScope>,
    pub state: Option<String>,
    pub challenge: PkceChallenge,
    pub nonce: Option<String>,
    pub prompt: String,
}

/// Registry-derived authority and description, never a Principal capability.
pub(crate) struct RequestedScope {
    pub id: Uuid,
    pub name: String,
    pub description: String,
}

impl AuthorizationInput {
    /// Resolves redirect trust before validating the protocol. No normalization or
    /// prefix comparison is permitted, even when the registered URI has a query string.
    pub(super) async fn validate(
        self,
        tx: &mut Transaction<'_, Postgres>,
    ) -> Result<ValidatedRequest, Error> {
        if self
            .state
            .as_ref()
            .is_some_and(|s| s.len() > 2048 || s.chars().any(char::is_control))
        {
            return Err(Error::protocol(ProtocolError::InvalidRequest));
        }
        let public_id = self
            .client_id
            .as_deref()
            .and_then(|s| Uuid::parse_str(s).ok())
            .ok_or_else(|| Error::protocol(ProtocolError::InvalidRequest))?;
        let context = super::storage::lock_client(tx, public_id).await?;
        let redirect = self
            .redirect_uri
            .as_deref()
            .ok_or_else(|| Error::protocol(ProtocolError::InvalidRequest))?;
        let trusted = super::storage::registered_redirect(tx, &context, redirect).await?;
        if !trusted {
            return Err(Error::protocol(ProtocolError::InvalidRequest));
        }
        let redirect = RedirectUri::parse(redirect.to_owned(), context.client_type)
            .map_err(|_| Error::protocol(ProtocolError::InvalidRequest))?;
        let result = self.validate_protocol(tx, context, redirect.clone()).await;
        result.map_err(|error| error.with_redirect(redirect, self.state.clone()))
    }

    /// Checks protocol semantics and client allow-list. Tenant/user authority and
    /// consent are independently required later under row locks, never inferred here.
    async fn validate_protocol(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        context: ClientContext,
        redirect: RedirectUri,
    ) -> Result<ValidatedRequest, Error> {
        if self.response_type.as_deref() != Some("code") {
            return Err(Error::protocol(if self.response_type.is_some() {
                ProtocolError::UnsupportedResponseType
            } else {
                ProtocolError::InvalidRequest
            }));
        }
        if self
            .organization_id
            .is_some_and(|id| id != context.organization_id)
        {
            return Err(Error::protocol(ProtocolError::AccessDenied));
        }
        if [
            self.response_mode.as_ref(),
            self.request.as_ref(),
            self.request_uri.as_ref(),
            self.claims.as_ref(),
            self.resource.as_ref(),
            self.audience.as_ref(),
            self.max_age.as_ref(),
            self.id_token_hint.as_ref(),
            self.acr_values.as_ref(),
        ]
        .iter()
        .any(Option::is_some)
        {
            return Err(Error::protocol(ProtocolError::InvalidRequest));
        }
        let prompt = match self.prompt.as_deref() {
            None => "default",
            Some("none") => "none",
            Some("consent") => "consent",
            _ => return Err(Error::protocol(ProtocolError::InvalidRequest)),
        }
        .to_owned();
        let challenge = PkceChallenge::parse(
            self.code_challenge.as_deref().unwrap_or_default(),
            self.code_challenge_method.as_deref().unwrap_or_default(),
        )
        .map_err(|_| Error::protocol(ProtocolError::InvalidRequest))?;
        let names = self
            .scope
            .as_deref()
            .ok_or_else(|| Error::protocol(ProtocolError::InvalidScope))?;
        let scopes = requested_scopes(tx, &context, names).await?;
        let openid = scopes.iter().any(|scope| scope.name == "openid");
        let nonce_valid = self
            .nonce
            .as_ref()
            .is_some_and(|n| !n.is_empty() && n.len() <= 2048 && !n.chars().any(char::is_control));
        if openid != nonce_valid || (!openid && self.nonce.is_some()) {
            return Err(Error::protocol(ProtocolError::InvalidRequest));
        }
        Ok(ValidatedRequest {
            context,
            redirect,
            scopes,
            state: self.state.clone(),
            challenge,
            nonce: self.nonce.clone(),
            prompt,
        })
    }
}

/// Parses exact space-delimited scopes, rejecting duplicates, unsupported offline access,
/// claim scopes without openid, and every token outside the client's registry allow-list.
async fn requested_scopes(
    tx: &mut Transaction<'_, Postgres>,
    context: &ClientContext,
    names: &str,
) -> Result<Vec<RequestedScope>, Error> {
    if names.len() > 8192 {
        return Err(Error::protocol(ProtocolError::InvalidScope));
    }
    let scopes = OAuthScope::validate_list(names.split(' ').map(str::to_owned).collect())
        .map_err(|_| Error::protocol(ProtocolError::InvalidScope))?;
    if scopes.len() > 64 || scopes.iter().any(|s| s.as_str() == "offline_access") {
        return Err(Error::protocol(ProtocolError::InvalidScope));
    }
    let openid = scopes.iter().any(|s| s.as_str() == "openid");
    if !openid
        && scopes
            .iter()
            .any(|s| matches!(s.as_str(), "profile" | "email" | "address" | "phone"))
    {
        return Err(Error::protocol(ProtocolError::InvalidScope));
    }
    let mut result = Vec::new();
    for scope in scopes {
        let row = sqlx::query("SELECT s.id, s.name, s.description FROM oauth_scopes s JOIN oauth_client_scopes cs ON cs.scope_id=s.id AND cs.application_id=s.application_id WHERE cs.client_id=$1 AND s.application_id=$2 AND s.name=$3 FOR SHARE OF s, cs")
            .bind(context.id).bind(context.application_id).bind(scope.as_str()).fetch_optional(&mut **tx).await?.ok_or_else(|| Error::protocol(ProtocolError::InvalidScope))?;
        result.push(RequestedScope {
            id: row.try_get("id")?,
            name: row.try_get("name")?,
            description: row.try_get("description")?,
        });
    }
    Ok(result)
}
