//! UI-only auth guards for protected routes. These guards improve UX by
//! redirecting unauthenticated users but do not enforce security; the API
//! must still validate sessions.

use crate::components::ui::ElevationPrompt;
use crate::features::auth::state::use_auth;
use crate::routes::NotFoundPage;
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

/// Renders children only for elevated platform operators.
#[component]
pub fn RequireAdmin<F, IV>(children: F) -> impl IntoView
where
    F: Fn() -> IV + Send + Sync + 'static,
    IV: IntoView,
{
    let auth = use_auth();

    view! {
        {move || {
            if auth.is_loading.get() {
                view! { <div class="flex justify-center py-12"><crate::components::ui::Spinner /></div> }.into_any()
            } else if !auth.is_authenticated.get() {
                ().into_any()
            } else if !auth.is_operator.get() {
                view! { <NotFoundPage /> }.into_any()
            } else if auth.admin_token.get().is_none() {
                view! { <ElevationPrompt /> }.into_any()
            } else {
                children().into_any()
            }
        }}
    }
}
