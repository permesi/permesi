//! OAuth configuration console beneath application routes.
//!
//! Pages manage registrations and allow-lists only. Native dialogs confirm
//! destructive actions; API helpers enforce cookie handling and the backend
//! remains authoritative for all tenant and validation decisions.

mod clients;
pub(crate) mod common;
mod credentials;
mod detail;
mod scopes;

pub(crate) use clients::ClientsPage;
pub(crate) use detail::ClientDetailPage;
pub(crate) use scopes::ScopesPage;

use crate::{
    components::{Alert, AlertKind},
    features::oauth::client,
};
use common::{CARD, LINK, Loading, OAuthNav, application_context, error_message};
use leptos::prelude::*;
use leptos_router::components::A;

/// Summarizes configured clients and scopes without suggesting working protocol flows.
#[component]
pub fn OAuthOverviewPage() -> impl IntoView {
    let Some(context) = application_context() else {
        return view! { <Alert kind=AlertKind::Error message="Application unavailable.".to_owned() /> }.into_any();
    };
    let paths = context.paths;
    let fetch_path = paths.clone();
    let summary = LocalResource::new(move || {
        let path = fetch_path.clone();
        async move {
            let clients = client::list_clients(&path).await?;
            let scopes = client::list_scopes(&path).await?;
            Ok::<_, crate::app_lib::AppError>((clients.len(), scopes.len()))
        }
    });
    view! { <div class="space-y-6">
        <OAuthNav paths=paths.clone() />
        <h2 class="text-xl font-semibold">"OAuth Configuration"</h2>
        <p class="text-sm text-gray-500 dark:text-gray-400">"Manage client registrations, credentials, redirect URIs and delegated scopes. Authorization Code + PKCE is available; token issuance is planned."</p>
        <Suspense fallback=|| view! { <Loading message="Loading OAuth configuration…" /> }>
            {move || match summary.get() {
                Some(Ok((clients, scopes))) => view! { <div class="grid gap-4 sm:grid-cols-2"><div class=CARD><h3 class="font-medium">"Clients"</h3><p class="my-3 text-3xl">{clients}</p><A href=paths.clients() attr:class=LINK>"Manage clients →"</A></div><div class=CARD><h3 class="font-medium">"Scopes"</h3><p class="my-3 text-3xl">{scopes}</p><A href=paths.scopes() attr:class=LINK>"Manage scopes →"</A></div></div> }.into_any(),
                Some(Err(err)) => view! { <Alert kind=AlertKind::Error message=error_message(&err) /> }.into_any(),
                None => view! { <Loading message="Loading OAuth configuration…" /> }.into_any(),
            }}
        </Suspense>
    </div> }.into_any()
}
