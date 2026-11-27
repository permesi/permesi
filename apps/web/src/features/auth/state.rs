//! Auth session state and context for the frontend. The provider hydrates the
//! session once on mount using cookie-based API calls and exposes derived auth
//! signals for guards and routes. The admin elevation lives on the server; only
//! its expiry is kept here, in memory.

use crate::features::auth::{
    client,
    types::{AdminElevateResponse, UserSession},
};
use leptos::{prelude::*, task::spawn_local};

#[derive(Clone, Copy)]
/// Auth session context shared through Leptos.
pub struct AuthContext {
    pub session: RwSignal<Option<UserSession>>,
    pub admin_elevation: RwSignal<Option<AdminElevateResponse>>,
    pub is_authenticated: Signal<bool>,
    pub is_full_session: Signal<bool>,
    pub is_operator: Signal<bool>,
    pub is_loading: RwSignal<bool>,
}

impl AuthContext {
    /// Builds a context around the provided session signal.
    fn new(
        session: RwSignal<Option<UserSession>>,
        admin_elevation: RwSignal<Option<AdminElevateResponse>>,
        is_loading: RwSignal<bool>,
    ) -> Self {
        let is_authenticated = Signal::derive(move || session.get().is_some());
        let is_full_session = Signal::derive(move || {
            session
                .get()
                .is_some_and(|s| s.session_kind == crate::features::auth::types::SessionKind::Full)
        });
        let is_operator =
            Signal::derive(move || session.get().is_some_and(|session| session.is_operator));
        Self {
            session,
            admin_elevation,
            is_authenticated,
            is_full_session,
            is_operator,
            is_loading,
        }
    }

    /// Updates the session and resumes a pending OAuth login before route navigation.
    /// Only full sessions on login/challenge resume; MFA setup waits for recovery-code acknowledgement.
    /// The backend validates every stored binding.
    pub fn set_session(&self, session: UserSession) {
        let full = session.session_kind == crate::features::auth::types::SessionKind::Full;
        self.set_session_preserving_mfa(session);
        if full
            && web_sys::window().is_some_and(|window| {
                window
                    .location()
                    .pathname()
                    .is_ok_and(|path| super::authorization::automatic_resume_path(&path))
            })
        {
            let _ = super::authorization::resume_after_authentication(
                &crate::app_lib::config::AppConfig::load().api_base_url,
            );
        }
    }

    /// Updates a verified server session without leaving an MFA recovery/enrollment flow.
    /// This changes presentation only; the server still enforces session authentication.
    pub fn set_session_preserving_mfa(&self, session: UserSession) {
        self.session.set(Some(session));
    }

    /// Remembers until when the server holds this session elevated (in-memory only).
    pub fn set_admin_elevation(&self, elevation: AdminElevateResponse) {
        self.admin_elevation.set(Some(elevation));
    }

    /// Clears the in-memory session, typically on logout.
    pub fn clear_session(&self) {
        self.session.set(None);
        self.admin_elevation.set(None);
    }

    /// Forgets the elevation; the server-side grant ends with the session or its expiry.
    pub fn clear_admin_elevation(&self) {
        self.admin_elevation.set(None);
    }

    /// Refetches the session from the server to update roles/flags.
    pub fn refresh_session(&self) {
        let auth = *self;
        spawn_local(async move {
            if let Ok(Some(session)) = client::fetch_session().await {
                auth.set_session(session);
            }
        });
    }
}

/// Provides auth context and hydrates the session once on mount.
#[component]
pub fn AuthProvider(children: Children) -> impl IntoView {
    super::authorization::capture_request();
    let session = RwSignal::new(None);
    let admin_elevation = RwSignal::new(None);
    let is_loading = RwSignal::new(true);
    let auth = AuthContext::new(session, admin_elevation, is_loading);
    provide_context(auth);

    // Automatically forget the elevation when it expires.
    Effect::new(move |_| {
        if let Some(token) = auth.admin_elevation.get() {
            let expires_at_ms = js_sys::Date::parse(&token.expires_at);
            if expires_at_ms.is_nan() {
                return;
            }
            let now_ms = js_sys::Date::now();
            let diff = expires_at_ms - now_ms;

            if diff <= 0.0 {
                auth.clear_admin_elevation();
            } else {
                let Ok(delay) = std::time::Duration::try_from_secs_f64(diff / 1000.0) else {
                    auth.clear_admin_elevation();
                    return;
                };
                let auth_retry = auth;
                spawn_local(async move {
                    gloo_timers::future::sleep(delay).await;
                    // Clear only the elevation this timer was started for.
                    if let Some(current) = auth_retry.admin_elevation.get_untracked()
                        && current.expires_at == token.expires_at
                    {
                        auth_retry.clear_admin_elevation();
                    }
                });
            }
        }
    });

    let auth_for_fetch = auth;
    spawn_local(async move {
        let storage = web_sys::window()
            .and_then(|w| w.local_storage().ok())
            .flatten();
        let should_fetch = storage
            .as_ref()
            .and_then(|s| s.get_item("permesi_logged_in").ok().flatten())
            .is_some_and(|v| v == "true");

        if should_fetch {
            match client::fetch_session().await {
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
        let admin_elevation = RwSignal::new(None);
        let is_loading = RwSignal::new(false); // Not loading if provider is missing
        AuthContext::new(session, admin_elevation, is_loading)
    })
}
