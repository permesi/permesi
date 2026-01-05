use crate::components::ui::{ElevationPrompt, Spinner};
use crate::features::auth::{client, state::use_auth};
use crate::routes::{NotFoundPage, paths};
use leptos::prelude::*;
use leptos_router::components::Outlet;
use leptos_router::hooks::use_location;

/// Layout wrapper for the admin subtree. It enforces access control based on
/// operator status or bootstrap mode.
#[component]
pub fn AdminLayout() -> impl IntoView {
    let auth = use_auth();
    let location = use_location();

    // Resource to fetch admin status (bootstrap mode and operator status).
    let status = LocalResource::new(move || {
        let token = auth.session_token.get();
        async move { client::admin_status(token.as_deref()).await }
    });

    view! {
        {move || {
            view! {
                <Suspense fallback=|| {
                    view! {
                        <div class="flex justify-center items-center min-h-[50vh]">
                            <Spinner />
                        </div>
                    }
                }>
                    {move || {
                        match status.get() {
                            // Access control: allowed if bootstrap is open or user is an operator.
                            Some(Ok(res)) if res.bootstrap_open || res.operator => {
                                let is_claim_page = location.pathname.get() == paths::ADMIN_CLAIM;
                                let has_token = auth.admin_token.get().is_some();

                                if is_claim_page || has_token {
                                    // Already elevated or on the claim page.
                                    view! { <Outlet /> }.into_any()
                                } else {
                                    // Operator but not elevated, and not on the claim page.
                                    view! { <ElevationPrompt /> }.into_any()
                                }
                            }
                            // Deny access with a 404 UX if not allowed or on error.
                            Some(_) => view! { <NotFoundPage /> }.into_any(),
                            // Loading state (should be handled by Suspense).
                            None => {
                                view! {
                                    <div class="flex justify-center items-center min-h-[50vh]">
                                        <Spinner />
                                    </div>
                                }
                                .into_any()
                            }
                        }
                    }}
                </Suspense>
            }
            .into_any()
        }}
    }
}
