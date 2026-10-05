//! Transient console confirmation state, never tenant authority or durable authentication state.
//!
//! Flow Overview: load server capabilities for the current account and route, pin a
//! confirmation to their immutable IDs, and discard stale asynchronous results. Password
//! verification refreshes session identity, capabilities and organization children before
//! returning to confirmation. Only a later explicit submit can issue DELETE.

use leptos::{prelude::*, task::spawn_local};
use leptos_router::hooks::use_location;

use super::DeleteTarget;
use crate::{
    app_lib::AppError,
    features::{
        auth::{
            client as auth_client,
            opaque::reauthenticate,
            state::{AuthContext, use_auth},
            types::SessionKind,
        },
        orgs::{client, types::OrgCapabilities},
    },
    routes::oauth::common::error_message,
};

/// Original account and tenant selected by an explicit confirmation opening.
#[derive(Clone)]
struct Confirmation {
    user: String,
    organization: String,
}

/// Signals shared by the deletion form and its asynchronous operations.
#[derive(Clone, Copy)]
pub(super) struct DeletionState {
    pub open: RwSignal<bool>,
    pub typed: RwSignal<String>,
    pub password: RwSignal<String>,
    pub reauth: RwSignal<bool>,
    pub busy: RwSignal<bool>,
    pub error: RwSignal<String>,
    pub children: RwSignal<Option<String>>,
    capabilities: RwSignal<Option<OrgCapabilities>>,
    confirmation: StoredValue<Option<Confirmation>>,
    generation: StoredValue<u64>,
    target: StoredValue<DeleteTarget>,
    path: StoredValue<String>,
    pathname: Memo<String>,
    auth: AuthContext,
    refresh: Callback<()>,
}

impl DeletionState {
    /// Loads role hints only for a full session and invalidates drafts on account changes.
    pub fn new(target: DeleteTarget, refresh: Callback<()>) -> Self {
        let location = use_location();
        let state = Self {
            open: RwSignal::new(false),
            typed: RwSignal::new(String::new()),
            password: RwSignal::new(String::new()),
            reauth: RwSignal::new(false),
            busy: RwSignal::new(false),
            error: RwSignal::new(String::new()),
            children: RwSignal::new(None),
            capabilities: RwSignal::new(None),
            confirmation: StoredValue::new(None),
            generation: StoredValue::new(0),
            target: StoredValue::new(target),
            path: StoredValue::new(location.pathname.get_untracked()),
            pathname: location.pathname,
            auth: use_auth(),
            refresh,
        };
        let last_user = StoredValue::new(None::<String>);
        Effect::new(move |_| {
            let user = state
                .auth
                .session
                .get()
                .filter(|s| s.session_kind == SessionKind::Full)
                .map(|s| s.user_id);
            if user != last_user.get_value() {
                last_user.set_value(user.clone());
                state.generation.update_value(|n| *n += 1);
                state.reset();
                state.capabilities.set(None);
                state.busy.set(false);
                if user.is_some() {
                    state.refresh();
                }
            }
        });
        Effect::new(move |_| {
            if !state.open.get() {
                state.password.set(String::new());
                state.reauth.set(false);
            }
        });
        on_cleanup(move || {
            state.generation.try_update_value(|n| *n += 1);
            state.password.try_set(String::new());
        });
        state
    }

    /// Checks server-issued owner/admin eligibility for presentation only.
    pub fn eligible(self) -> bool {
        self.capabilities.get().is_some_and(|caps| {
            if self.target.get_value().organization() {
                caps.can_delete_organization
            } else {
                caps.can_manage_resources
            }
        })
    }

    /// Opens a draft pinned to the loaded account and immutable tenant ID, then refreshes hints.
    pub fn begin(self) {
        if self.busy.get_untracked() || !self.eligible() {
            return;
        }
        let Some(caps) = self.capabilities.get_untracked() else {
            return;
        };
        let Some(session) = self.auth.session.get_untracked() else {
            return;
        };
        self.reset();
        self.confirmation.set_value(Some(Confirmation {
            user: session.user_id,
            organization: caps.organization_id,
        }));
        self.open.set(true);
        self.refresh();
    }

    /// Clears sensitive/transient input when a confirmation is cancelled or invalidated.
    fn reset(self) {
        self.open.set(false);
        self.typed.set(String::new());
        self.password.set(String::new());
        self.reauth.set(false);
        self.confirmation.set_value(None);
    }

    /// Discards responses for a disposed component, changed account, route, or newer refresh.
    fn current(self, generation: u64, user: &str) -> bool {
        self.generation.try_get_value() == Some(generation)
            && self.pathname.try_get().as_ref() == self.path.try_get_value().as_ref()
            && self
                .auth
                .session
                .try_get()
                .flatten()
                .is_some_and(|s| s.user_id == user && s.session_kind == SessionKind::Full)
    }

    /// Rechecks session identity, role eligibility and org children without performing DELETE.
    async fn reload(self, user: &str) -> Result<Snapshot, AppError> {
        let target = self.target.get_value();
        let caps = client::capabilities(target.org_slug()).await?;
        let children = if target.organization() {
            let projects = client::list_projects(target.org_slug()).await?;
            (!projects.is_empty())
                .then(|| "Delete all projects before deleting this organization.".to_owned())
        } else {
            None
        };
        let session = auth_client::fetch_session()
            .await?
            .filter(|s| s.session_kind == SessionKind::Full && s.user_id == user)
            .ok_or_else(|| AppError::Http {
                status: 401,
                code: None,
                message: "Your account changed or session expired. Open a new confirmation."
                    .to_owned(),
            })?;
        Ok(Snapshot {
            session,
            caps,
            children,
        })
    }

    /// Applies a freshness-checked snapshot, rejecting slug reuse or lost role eligibility.
    fn apply(self, snapshot: Snapshot) -> Result<(), AppError> {
        let Snapshot {
            session,
            caps,
            children,
        } = snapshot;
        if let Some(pin) = self.confirmation.get_value() {
            if pin.user != session.user_id || pin.organization != caps.organization_id {
                self.reset();
                return Err(AppError::Config(
                    "The organization changed. Open a new confirmation.".to_owned(),
                ));
            }
        }
        self.capabilities.set(Some(caps));
        self.children.set(children);
        self.auth.set_session_preserving_mfa(session);
        if self.open.get_untracked() && !self.eligible() {
            self.reset();
            self.error
                .set("Your organization role no longer permits this deletion.".to_owned());
        }
        if self.open.get_untracked() {
            self.refresh.run(());
        }
        Ok(())
    }

    /// Starts an identity-bound refresh and applies only the latest response to this route.
    pub fn refresh(self) {
        let Some(session) = self.auth.session.get_untracked() else {
            return;
        };
        self.generation.update_value(|n| *n += 1);
        let generation = self.generation.get_value();
        self.busy.set(true);
        spawn_local(async move {
            let result = self
                .reload_checked(generation, &session.user_id, false, String::new())
                .await;
            if self.current(generation, &session.user_id) {
                self.finish(result);
            }
        });
    }

    /// Verifies a password for the pinned account and returns to confirmation after refresh.
    pub fn verify(self) {
        if self.busy.get_untracked() {
            return;
        }
        let Some(pin) = self.confirmation.get_value() else {
            return;
        };
        let password = self.password.get_untracked();
        self.password.set(String::new());
        if password.is_empty() {
            return;
        }
        self.generation.update_value(|n| *n += 1);
        let generation = self.generation.get_value();
        self.busy.set(true);
        self.error.set(String::new());
        spawn_local(async move {
            let result = self
                .reload_checked(generation, &pin.user, true, password)
                .await;
            if self.current(generation, &pin.user) {
                if result.is_ok() {
                    self.reauth.set(false);
                }
                self.finish(result);
            }
        });
    }

    /// Verifies identity before the proof and rejects stale responses before applying hints.
    async fn reload_checked(
        self,
        generation: u64,
        user: &str,
        verify: bool,
        password: String,
    ) -> Result<(), AppError> {
        let session = auth_client::fetch_session()
            .await?
            .filter(|s| s.session_kind == SessionKind::Full && s.user_id == user);
        let Some(session) = session else {
            if self.current(generation, user) {
                self.reset();
                self.capabilities.set(None);
            }
            return Err(AppError::Config(
                "Your account changed or session expired. Open a new confirmation.".to_owned(),
            ));
        };
        if !self.current(generation, user) {
            return Ok(());
        }
        if verify {
            reauthenticate(&session.email, password).await?;
        }
        if !self.current(generation, user) {
            return Ok(());
        }
        let snapshot = self.reload(user).await?;
        if !self.current(generation, user) {
            return Ok(());
        }
        self.apply(snapshot)
    }

    /// Fails closed when capability refresh fails, retaining only a recoverable reauth draft.
    fn finish(self, result: Result<(), AppError>) {
        self.busy.set(false);
        if let Err(error) = result {
            self.error.set(match &error {
                AppError::Config(message) => message.clone(),
                _ => error_message(&error),
            });
            if !self.reauth.get_untracked()
                || matches!(
                    error,
                    AppError::Http {
                        status: 401 | 404,
                        ..
                    }
                )
            {
                self.capabilities.set(None);
                self.reset();
            }
        }
    }

    /// Returns the originally confirmed tenant only while current local account hints still match.
    pub fn confirmed_id(self) -> Option<String> {
        let pin = self.confirmation.get_value()?;
        let session = self.auth.session.get_untracked()?;
        let caps = self.capabilities.get_untracked()?;
        (session.user_id == pin.user && caps.organization_id == pin.organization && self.eligible())
            .then_some(pin.organization)
    }
}

/// Complete server snapshot; no partial refresh can enable the destructive button.
struct Snapshot {
    session: crate::features::auth::types::UserSession,
    caps: OrgCapabilities,
    children: Option<String>,
}
