use crate::components::layout::AppShell;
use crate::features::auth::state::use_auth;
use crate::routes::NotFoundPage;
use leptos::prelude::*;
use leptos_router::components::Outlet;

#[component]
pub fn AuthLayout() -> impl IntoView {
    let auth = use_auth();

    view! {
        {move || {
            if auth.is_loading.get() {
                // Session::Unknown -> Neutral loading state (no chrome)
                 view! {
                     <div class="flex justify-center items-center min-h-screen bg-white dark:bg-gray-900">
                         <div class="animate-pulse text-gray-400">"Loading..."</div>
                     </div>
                 }.into_any()
            } else if auth.is_authenticated.get() {
                // Session::Authenticated -> Render AppShell + content
                view! {
                    <AppShell>
                        <Outlet />
                    </AppShell>
                }.into_any()
            } else {
                // Session::Anonymous -> 404 UX (hide existence of route)
                view! { <NotFoundPage /> }.into_any()
            }
        }}
    }
}
