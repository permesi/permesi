//! Root UI component that wires providers and routing. It centralizes global context
//! setup so routes can stay focused on UI and flow handling, at the cost of a single
//! provider tree that can grow over time. No secrets are handled here; session state
//! is managed by the auth provider and propagated to routes.

use crate::{features::auth::state::AuthProvider, routes::AppRoutes};
use leptos::prelude::*;
use leptos_router::components::Router;

/// Renders the root auth provider and router for the CSR app.
#[component]
pub fn App() -> impl IntoView {
    view! {
        <AuthProvider>
            <Router>
                <AppRoutes />
            </Router>
        </AuthProvider>
    }
}
