//! Transaction-owned authorization-code exchange, independent of session permissions.
//!
//! Flow Overview: the HTTP adapter bounds/parses/throttles the request, this service
//! authenticates its client in an owned PostgreSQL transaction, redeems the exact
//! S256 code, signs access/optional ID tokens through Vault, records hashes only,
//! and commits once before exposing tokens. Failures before commit roll back the
//! code and receipt. An interrupted commit can leave a consumed code without a response;
//! retries still cannot issue twice. Authentication proofs cannot escape into a different transaction.
//! JWTs carry delegated tenant authority; they never authenticate Permesi sessions.

mod claims;
pub(crate) mod request;
mod storage;

use anyhow::{Context, Result, ensure};
use clap::ArgMatches;
use secrecy::ExposeSecret as _;
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use super::{
    authorization::{
        redemption::{RedeemedCode, RedemptionInput, redeem_authorization_code},
        storage::lock_client,
    },
    client::ClientType,
    credentials::CredentialError,
    oidc::OAuthState,
};
pub(crate) use claims::TokenResponse;
use request::{ClientAuthentication, TokenRequest};

/// Dispatch-validated token lifetimes and complete-request resource limits.
#[derive(Clone, Debug)]
pub struct TokenConfig {
    pub(crate) rate_window: i64,
    pub(crate) ip_attempts: i64,
    pub(crate) client_ip_attempts: i64,
    pub(crate) access_ttl: i64,
    pub(crate) id_ttl: i64,
    pub(crate) timeout_ms: u64,
    pub(crate) max_body_bytes: usize,
}

impl TokenConfig {
    /// Reads only clap-defined values and rechecks bounds before constructing state.
    pub(crate) fn from_matches(matches: &ArgMatches) -> Result<Self> {
        let policy = Self {
            rate_window: *matches
                .get_one::<i64>("oauth-token-rate-window-seconds")
                .context("missing token rate window")?,
            ip_attempts: *matches
                .get_one::<i64>("oauth-token-rate-ip-attempts")
                .context("missing token IP budget")?,
            client_ip_attempts: *matches
                .get_one::<i64>("oauth-token-rate-client-ip-attempts")
                .context("missing token client/IP budget")?,
            access_ttl: *matches
                .get_one::<i64>("oauth-access-token-ttl-seconds")
                .context("missing access TTL")?,
            id_ttl: *matches
                .get_one::<i64>("oidc-id-token-ttl-seconds")
                .context("missing ID TTL")?,
            timeout_ms: *matches
                .get_one::<u64>("oauth-token-timeout-ms")
                .context("missing token deadline")?,
            max_body_bytes: usize::try_from(
                *matches
                    .get_one::<u32>("oauth-token-max-body-bytes")
                    .context("missing token body bound")?,
            )?,
        };
        ensure!(
            (1..=3600).contains(&policy.rate_window)
                && (1..=100_000).contains(&policy.ip_attempts)
                && (1..=100_000).contains(&policy.client_ip_attempts)
                && (1..=3600).contains(&policy.access_ttl)
                && (1..=3600).contains(&policy.id_ttl)
                && (1..=30000).contains(&policy.timeout_ms)
                && (1024..=65536).contains(&policy.max_body_bytes),
            "invalid token policy"
        );
        Ok(policy)
    }

    /// Mirrors inert test policy; production defaults are exclusively clap-defined.
    #[cfg(test)]
    pub(crate) const fn for_tests() -> Self {
        Self {
            rate_window: 60,
            ip_attempts: 120,
            client_ip_attempts: 30,
            access_ttl: 300,
            id_ttl: 300,
            timeout_ms: 5000,
            max_body_bytes: 8192,
        }
    }
}

/// Protocol-only errors; SQL, Vault and supplied authentication values are discarded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TokenError {
    InvalidRequest,
    InvalidClient,
    InvalidGrant,
    UnsupportedGrant,
    Unavailable,
    Limited,
}

impl TokenError {
    /// Emits registered protocol tokens without submitted identifiers or descriptions.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::InvalidClient => "invalid_client",
            Self::InvalidGrant => "invalid_grant",
            Self::UnsupportedGrant => "unsupported_grant_type",
            Self::Unavailable | Self::Limited => "temporarily_unavailable",
        }
    }
}

impl From<sqlx::Error> for TokenError {
    /// Storage failures fail closed without retaining an error that could reveal parameters.
    fn from(_: sqlx::Error) -> Self {
        Self::Unavailable
    }
}

/// Owns the SAME transaction from current client authentication through committed issuance.
/// Private fields and construction prevent detached or caller-substituted client proofs.
struct AuthenticatedExchange<'a> {
    tx: Transaction<'a, Postgres>,
    client: Uuid,
    application: Uuid,
    organization: Uuid,
}

impl<'a> AuthenticatedExchange<'a> {
    /// Authenticates confidential Basic credentials or verifies an active public registration.
    /// Session cookies and browser-supplied tenant/role values are never authority inputs.
    async fn authenticate(
        pool: &'a PgPool,
        oauth: &OAuthState,
        auth: ClientAuthentication,
    ) -> std::result::Result<Self, TokenError> {
        let mut tx = pool.begin().await?;
        super::locking::deadline(&mut tx, oauth.config.lock_timeout_ms).await?;
        let (client, application, organization) = match auth {
            ClientAuthentication::Basic { client, secret } => {
                let proof = oauth
                    .credentials
                    .authenticate(&mut tx, client, secret.expose_secret())
                    .await
                    .map_err(|error| match error {
                        CredentialError::Unavailable | CredentialError::Database(_) => {
                            TokenError::Unavailable
                        }
                        _ => TokenError::InvalidClient,
                    })?;
                (
                    proof.client_id(),
                    proof.application_id(),
                    proof.organization_id(),
                )
            }
            ClientAuthentication::Public(client) => {
                let context = lock_client(&mut tx, client).await.map_err(|error| {
                    if error.database {
                        TokenError::Unavailable
                    } else {
                        TokenError::InvalidClient
                    }
                })?;
                if context.client_type != ClientType::Public {
                    return Err(TokenError::InvalidClient);
                }
                (client, context.application_id, context.organization_id)
            }
        };
        Ok(Self {
            tx,
            client,
            application,
            organization,
        })
    }

    /// Redeems only this authenticated client and its server-resolved tenant in the owned transaction.
    async fn redeem(
        &mut self,
        oauth: &OAuthState,
        request: &TokenRequest,
    ) -> std::result::Result<RedeemedCode, TokenError> {
        let code = redeem_authorization_code(
            &mut self.tx,
            &oauth.config,
            RedemptionInput {
                code: request.code.expose_secret(),
                client_id: self.client,
                redirect_uri: &request.redirect_uri,
                code_verifier: request.verifier.expose_secret(),
                organization_id: self.organization,
            },
        )
        .await
        .map_err(|_| TokenError::InvalidGrant)?;
        if code.client_id != self.client
            || code.application_id != self.application
            || code.organization_id != self.organization
        {
            return Err(TokenError::InvalidGrant);
        }
        Ok(code)
    }
}

/// Signs and commits a single-use exchange before returning any bearer material.
/// Signing/receipt failure drops the owned transaction and preserves code usability.
/// An interrupted COMMIT may have succeeded; a retry fails closed instead of duplicating issuance.
pub(crate) async fn exchange(
    pool: &PgPool,
    oauth: &OAuthState,
    request: TokenRequest,
    auth: ClientAuthentication,
) -> std::result::Result<TokenResponse, TokenError> {
    let mut guard = AuthenticatedExchange::authenticate(pool, oauth, auth).await?;
    let code = guard.redeem(oauth, &request).await?;
    let issued = claims::issue(oauth, &mut guard.tx, &code).await?;
    storage::record(&mut guard.tx, &request, &issued).await?;
    guard.tx.commit().await?;
    Ok(issued.response)
}
