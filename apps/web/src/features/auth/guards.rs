//! UI-only auth guards for protected routes. These guards improve UX by
//! redirecting unauthenticated users but do not enforce security; the API
//! must still validate sessions.

use crate::features::auth::state::use_auth;
use leptos::prelude::*;
use leptos_router::hooks::use_navigate;

/// Renders children and redirects to login when unauthenticated.
#[component]
pub fn RequireAuth(children: Children) -> impl IntoView {
    let auth = use_auth();
    let navigate = use_navigate();

    Effect::new(move |_| {
        if !auth.is_authenticated.get() {
            // UX-only guard; real access control must live on the API.
            navigate("/login", Default::default());
        }
    });

    view! { {children()} }
}
