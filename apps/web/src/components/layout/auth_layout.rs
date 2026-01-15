use crate::components::layout::AppShell;
use crate::features::auth::state::use_auth;
use crate::routes::{NotFoundPage, paths};
use leptos::prelude::*;
use leptos_router::components::Outlet;
use leptos_router::hooks::{use_location, use_navigate};

#[component]
pub fn AuthLayout() -> impl IntoView {
    let auth = use_auth();
    let location = use_location();
    let navigate = use_navigate();

    // Funnel restricted sessions to the correct page.
    // This runs reactively whenever the session or path changes.
    Effect::new(move |_| {
        if let Some(session) = auth.session.get() {
            let path = location.pathname.get();
            match session.session_kind {
                crate::features::auth::types::SessionKind::MfaChallenge => {
                    if path != paths::MFA_CHALLENGE {
                        navigate(paths::MFA_CHALLENGE, Default::default());
                    }
                }
                crate::features::auth::types::SessionKind::MfaBootstrap => {
                    if path != paths::MFA_SETUP {
                        navigate(paths::MFA_SETUP, Default::default());
                    }
                }
                crate::features::auth::types::SessionKind::Full => {
                    // Only redirect away from challenge if we are fully authenticated.
                    // Allow setup page for re-enrollment.
                    if path == paths::MFA_CHALLENGE {
                        navigate(paths::DASHBOARD, Default::default());
                    }
                }
            }
        }
    });

    let is_loading = auth.is_loading;
    let has_session = Signal::derive(move || auth.session.get().is_some());

    view! {
        <Show
            when=move || !is_loading.get()
            fallback=|| view! {
                <div class="flex justify-center items-center min-h-screen bg-white dark:bg-gray-900">
                    <div class="animate-pulse text-gray-400">"Loading..."</div>
                </div>
            }
        >
            <Show
                when=move || has_session.get()
                fallback=|| view! { <NotFoundPage /> }
            >
                // AppShell and Outlet must remain stable to avoid re-mounting nested routes
                // when session properties change.
                <AppShell>
                    <Outlet />
                </AppShell>
            </Show>
        </Show>
    }
}
