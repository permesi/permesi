use crate::features::auth::state::AuthProvider;
use crate::routes::AppRoutes;
use leptos::prelude::*;
use leptos_router::components::Router;

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
