use crate::components::AppShell;
use leptos::prelude::*;

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
