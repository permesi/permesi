//! Friendly 404 page for unknown routes. It keeps messaging simple and does not
//! expose internal route details.

use crate::components::AppShell;
use leptos::prelude::*;

/// Renders the not-found page.
#[component]
pub fn NotFoundPage() -> impl IntoView {
    view! {
        <AppShell>
            <h1>
                "Uh oh!"
                <br />
                "We couldn't find that page!"
            </h1>
        </AppShell>
    }
}
