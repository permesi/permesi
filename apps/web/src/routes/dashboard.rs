//! Default landing page for the app. It is intentionally minimal during early
//! development and does not expose sensitive data.

use leptos::prelude::*;

/// Renders the dashboard page shell.
#[component]
pub fn DashboardPage() -> impl IntoView {
    view! {
        <h1>"Home"</h1>
    }
}
