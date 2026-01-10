//! Auth session state and context for the frontend. The provider hydrates the
//! session once on mount using cookie-based API calls and exposes derived auth
//! signals for guards and routes. Session tokens stay in memory, and admin
//! elevation tokens are also kept in-memory only for security.

use crate::features::auth::{
    client,
    types::{AdminElevateResponse, UserSession},
};
use leptos::{prelude::*, task::spawn_local};

#[derive(Clone, Copy)]
/// Auth session context shared through Leptos.
pub struct AuthContext {
    pub session: RwSignal<Option<UserSession>>,
    pub session_token: RwSignal<Option<String>>,
    pub admin_token: RwSignal<Option<AdminElevateResponse>>,
    pub is_authenticated: Signal<bool>,
    pub is_operator: Signal<bool>,
    pub is_loading: RwSignal<bool>,
}

impl AuthContext {
    /// Builds a context around the provided session signal.
    fn new(
        session: RwSignal<Option<UserSession>>,
        session_token: RwSignal<Option<String>>,
        admin_token: RwSignal<Option<AdminElevateResponse>>,
        is_loading: RwSignal<bool>,
    ) -> Self {
        let is_authenticated = Signal::derive(move || session.get().is_some());
        let is_operator = Signal::derive(move || {
            session
                .get()
                .map(|session| session.is_operator)
                .unwrap_or(false)
        });
        Self {
            session,
            session_token,
            admin_token,
            is_authenticated,
            is_operator,
            is_loading,
        }
    }

    /// Updates the in-memory session after login.
    pub fn set_session(&self, session: UserSession) {
        self.session.set(Some(session));
    }

    /// Stores the session token for Authorization headers.
    pub fn set_session_token(&self, token: String) {
        self.session_token.set(Some(token));
    }

    /// Stores the admin elevation token (in-memory only).
    pub fn set_admin_token(&self, token: AdminElevateResponse) {
        self.admin_token.set(Some(token));
    }

    /// Clears the in-memory session, typically on logout.
    pub fn clear_session(&self) {
        self.session.set(None);
        self.session_token.set(None);
        self.admin_token.set(None);
    }

    /// Clears only the admin elevation token.
    pub fn clear_admin_token(&self) {
        self.admin_token.set(None);
    }

    /// Refetches the session from the server to update roles/flags.
    pub fn refresh_session(&self) {
        let auth = self.clone();
        let token = self.session_token.get_untracked();
        spawn_local(async move {
            if let Ok(Some(session)) = client::fetch_session(token.as_deref()).await {
                auth.set_session(session);
            }
        });
    }
}

/// Provides auth context and hydrates the session once on mount.
#[component]
pub fn AuthProvider(children: Children) -> impl IntoView {
    let session = RwSignal::new(None);
    let session_token = RwSignal::new(None);
    let admin_token = RwSignal::new(None);
    let is_loading = RwSignal::new(true);
    let auth = AuthContext::new(session, session_token, admin_token, is_loading);
    provide_context(auth.clone());

    // Automatically clear admin token when it expires.
    Effect::new(move |_| {
        if let Some(token) = auth.admin_token.get() {
            let expires_at_ms = js_sys::Date::parse(&token.expires_at);
            if expires_at_ms.is_nan() {
                return;
            }
            let now_ms = js_sys::Date::now();
            let diff = expires_at_ms - now_ms;

            if diff <= 0.0 {
                auth.clear_admin_token();
            } else {
                let auth_retry = auth.clone();
                spawn_local(async move {
                    gloo_timers::future::sleep(std::time::Duration::from_millis(diff as u64)).await;
                    // Double check if the token we wanted to clear is still the same one
                    if let Some(current) = auth_retry.admin_token.get_untracked() {
                        if current.admin_token == token.admin_token {
                            auth_retry.clear_admin_token();
                        }
                    }
                });
            }
        }
    });

    let auth_for_fetch = auth.clone();
    spawn_local(async move {
        let storage = web_sys::window()
            .and_then(|w| w.local_storage().ok())
            .flatten();
        let should_fetch = storage
            .as_ref()
            .and_then(|s| s.get_item("permesi_logged_in").ok().flatten())
            .map(|v| v == "true")
            .unwrap_or(false);

        if should_fetch {
            match client::fetch_session(None).await {
                Ok(Some(session)) => {
                    auth_for_fetch.set_session(session);
                }
                Ok(None) => {
                    // Session is invalid or expired; clear the marker.
                    if let Some(s) = storage {
                        let _ = s.remove_item("permesi_logged_in");
                    }
                }
                Err(_) => {
                    // Network error or timeout; keep the marker so we retry next time,
                    // but we can't set the session now.
                }
            }
        }
        auth_for_fetch.is_loading.set(false);
    });

    view! { {children()} }
}

/// Returns the current auth context or a fallback empty context.
pub fn use_auth() -> AuthContext {
    use_context::<AuthContext>().unwrap_or_else(|| {
        let session = RwSignal::new(None);
        let session_token = RwSignal::new(None);
        let admin_token = RwSignal::new(None);
        let is_loading = RwSignal::new(false); // Not loading if provider is missing
        AuthContext::new(session, session_token, admin_token, is_loading)
    })
}
