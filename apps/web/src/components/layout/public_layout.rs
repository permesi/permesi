use crate::components::layout::AppShell;
use leptos::prelude::*;
use leptos_router::components::Outlet;

#[component]
pub fn PublicLayout() -> impl IntoView {
    view! {
        <AppShell>
            <Outlet />
        </AppShell>
    }
}
