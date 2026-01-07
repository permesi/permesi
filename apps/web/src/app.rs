//! Root UI component that wires providers and routing.
//!
//! ## Application Structure
//!
//! - **`src/routes/`**: Page-level components and route definitions.
//! - **`src/components/`**: Shared UI pieces and layout templates.
//! - **`src/features/`**: Domain-specific logic (e.g., Auth state, User lists).
//! - **`src/lib/`**: Configuration, API wrappers, and error handling.
//!
//! ## Defined Routes
//!
//! - `/`: Dashboard (Home)
//! - `/login` / `/signup`: Authentication flows.
//! - `/verify-email`: Token consumption and resend logic.
//! - `/users` / `/users/:id`: User management.
//! - `/admin/claim`: Administrative elevation (operator step-up).
//!
//! Global context is managed here so routes can stay focused on UI handling.
//! Session state is propagated via the `AuthProvider`.

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
