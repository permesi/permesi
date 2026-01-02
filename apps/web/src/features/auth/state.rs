//! Auth session state and context for the frontend. The provider hydrates the
//! session once on mount using cookie-based API calls and exposes derived auth
//! signals for guards and routes. Only non-sensitive metadata is stored in
//! memory; cookies remain `HttpOnly`.

use crate::features::auth::{client, types::UserSession};
use leptos::{prelude::*, task::spawn_local};

#[derive(Clone, Copy)]
/// Auth session context shared through Leptos.
pub struct AuthContext {
    pub session: RwSignal<Option<UserSession>>,
    pub is_authenticated: Signal<bool>,
}

impl AuthContext {
    /// Builds a context around the provided session signal.
    fn new(session: RwSignal<Option<UserSession>>) -> Self {
        let is_authenticated = Signal::derive(move || session.get().is_some());
        Self {
            session,
            is_authenticated,
        }
    }

    /// Updates the in-memory session after login.
    pub fn set_session(&self, session: UserSession) {
        self.session.set(Some(session));
    }

    /// Clears the in-memory session, typically on logout.
    pub fn clear_session(&self) {
        self.session.set(None);
    }
}

/// Provides auth context and hydrates the session once on mount.
#[component]
pub fn AuthProvider(children: Children) -> impl IntoView {
    let session = RwSignal::new(None);
    let auth = AuthContext::new(session);
    provide_context(auth.clone());

    let auth_for_fetch = auth.clone();
    spawn_local(async move {
        if let Ok(Some(session)) = client::fetch_session().await {
            auth_for_fetch.set_session(session);
        }
    });

    view! { {children()} }
}

/// Returns the current auth context or a fallback empty context.
pub fn use_auth() -> AuthContext {
    use_context::<AuthContext>().unwrap_or_else(|| {
        let session = RwSignal::new(None);
        AuthContext::new(session)
    })
}
