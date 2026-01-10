//! UI-only auth guards for protected routes. These guards improve UX by
//! showing 404 to unauthenticated users (GitHub-style) but do not enforce
//! security; the API must still validate sessions.

use crate::components::ui::{ElevationPrompt, Spinner};
use crate::features::auth::state::use_auth;
use crate::routes::NotFoundContent;
use leptos::prelude::*;

/// Renders children only for elevated platform operators.
/// Shows 404 to unauthenticated users or non-operators.
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
                view! { <div class="flex justify-center py-12"><Spinner /></div> }.into_any()
            } else if !auth.is_authenticated.get() {
                view! { <NotFoundContent /> }.into_any()
            } else if !auth.is_operator.get() {
                view! { <NotFoundContent /> }.into_any()
            } else if auth.admin_token.get().is_none_or(|token| {
                crate::features::auth::client::is_token_expired(&token.expires_at)
            }) {
                view! { <ElevationPrompt /> }.into_any()
            } else {
                children().into_any()
            }
        }}
    }
}
