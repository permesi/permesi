use leptos::prelude::*;
use leptos_router::components::Outlet;

#[component]
pub fn PublicLayout() -> impl IntoView {
    view! {
        <main class="min-h-screen bg-white dark:bg-gray-900">
            <Outlet />
        </main>
    }
}
