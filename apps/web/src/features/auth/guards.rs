use crate::features::auth::state::use_auth;
use leptos::prelude::*;
use leptos_router::hooks::use_navigate;

#[component]
pub fn RequireAuth(children: Children) -> impl IntoView {
    let auth = use_auth();
    let navigate = use_navigate();

    Effect::new(move |_| {
        if !auth.is_authenticated.get() {
            // UX-only guard; real access control must live on the API.
            navigate("/login", Default::default());
        }
    });

    view! { {children()} }
}
