use crate::components::AppShell;
use leptos::prelude::*;

#[component]
pub fn DashboardPage() -> impl IntoView {
    view! {
        <AppShell>
            <h1>"Home"</h1>
        </AppShell>
    }
}
