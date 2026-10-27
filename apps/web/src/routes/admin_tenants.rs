//! Read-only platform hierarchy views with independent state for each path and identity.
//!
//! Flow Overview: the existing operator/elevation UI guard mounts an identity-keyed
//! inspection page; metadata and a bounded child page come only from admin GET APIs.
//! Navigation never mounts tenant edit/delete/OAuth controls. Account/path changes
//! discard the previous page and cursor rather than retaining foreign cached state.

use crate::{
    app_lib::AppError,
    components::{Alert, AlertKind, Spinner},
    features::{
        admin_tenants::{self, Inspection, InspectionPath, Metadata},
        auth::{RequireAdmin, state::use_auth},
    },
};
use leptos::prelude::*;
use leptos_router::{components::A, hooks::use_params, params::Params};

const LINK: &str =
    "cursor-pointer text-blue-600 hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-300";
const BUTTON: &str = "cursor-pointer rounded border border-gray-300 px-3 py-2 text-sm hover:bg-gray-100 dark:border-gray-600 dark:hover:bg-gray-700";

#[derive(Clone, PartialEq, Params)]
struct InspectionParams {
    slug: Option<String>,
    project_slug: Option<String>,
    env_slug: Option<String>,
    app_id: Option<String>,
}

impl InspectionParams {
    /// Accepts complete ancestry only; partial paths cannot select a broader resource.
    fn path(self) -> Result<InspectionPath, AppError> {
        match (self.slug, self.project_slug, self.env_slug, self.app_id) {
            (None, None, None, None) => Ok(InspectionPath::Organizations),
            (Some(org), None, None, None) => Ok(InspectionPath::Organization(org)),
            (Some(org), Some(project), None, None) => Ok(InspectionPath::Project(org, project)),
            (Some(org), Some(project), Some(env), None) => {
                Ok(InspectionPath::Environment(org, project, env))
            }
            (Some(org), Some(project), Some(env), Some(app)) => {
                Ok(InspectionPath::Application(org, project, env, app))
            }
            _ => Err(AppError::Config("Invalid inspection ancestry.".to_owned())),
        }
    }
}

/// Keeps the existing elevation gate and remounts all data/cursors when identity or path changes.
#[component]
pub fn AdminTenantsPage() -> impl IntoView {
    let params = use_params::<InspectionParams>();
    let auth = use_auth();
    let path = Signal::derive(move || {
        params
            .get()
            .map_err(|_| AppError::Config("Invalid inspection path.".to_owned()))
            .and_then(InspectionParams::path)
    });
    let entries = move || {
        path.get()
            .ok()
            .map(|path| (path, auth.session.get().map(|session| session.user_id)))
            .into_iter()
            .collect::<Vec<_>>()
    };
    view! { <RequireAdmin children=move || view! {
        {move || path.get().err().map(|error| view! { <Alert kind=AlertKind::Error message=error.to_string() /> })}
        <For each=entries key=|key| key.clone() children={move |(path, _)| view! { <InspectionPage path=path /> }} />
    } /> }
}

/// Owns one identity/path's paginated reads; refresh can restart a stale cursor safely.
#[component]
fn InspectionPage(path: InspectionPath) -> impl IntoView {
    let after = RwSignal::new(None::<String>);
    let history = RwSignal::new(Vec::<Option<String>>::new());
    let fetch_path = path.clone();
    let data = LocalResource::new(move || {
        let path = fetch_path.clone();
        let cursor = after.get();
        async move { admin_tenants::load(&path, cursor.as_deref()).await }
    });
    let mut breadcrumbs = Vec::new();
    let mut parent = path.parent();
    while let Some(path) = parent {
        breadcrumbs.push((path.console(), path.label()));
        parent = path.parent();
    }
    breadcrumbs.reverse();
    view! { <section class="space-y-6 text-gray-900 dark:text-white" aria-label="Read-only platform inspection">
        <nav aria-label="Breadcrumb" class="flex flex-wrap gap-3 text-sm">
            {breadcrumbs.into_iter().map(|(href, label)| view! { <A href attr:class=LINK>{label}</A> }).collect_view()}
        </nav>
        <div class="flex flex-wrap items-center justify-between gap-3">
            <div><h1 class="break-words text-2xl font-semibold">{move || data.get().and_then(Result::ok).and_then(|value| value.metadata.map(|row| row.name)).unwrap_or_else(|| "Global Organizations".to_owned())}</h1>
                <p class="text-sm text-gray-500 dark:text-gray-400">"Read-only platform inspection"</p></div>
            <button class=BUTTON on:click=move |_| { history.set(Vec::new()); after.set(None); data.refetch(); }>"Refresh"</button>
        </div>
        <Suspense fallback=move || view! { <Spinner /> }>
            {move || match data.get() {
                Some(Ok(value)) => view! { <InspectionBody value path=path.clone() after history /> }.into_any(),
                Some(Err(error)) => view! { <Alert kind=AlertKind::Error message=error.to_string() /> }.into_any(),
                None => view! { <Spinner /> }.into_any(),
            }}
        </Suspense>
    </section> }
}

/// Renders allowlisted metadata and admin links, with no tenant-management controls.
#[component]
fn InspectionBody(
    value: Inspection,
    path: InspectionPath,
    after: RwSignal<Option<String>>,
    history: RwSignal<Vec<Option<String>>>,
) -> impl IntoView {
    let next = value
        .page
        .as_ref()
        .and_then(|page| page.next_cursor.clone());
    let collection = path.children();
    view! {
        {value.metadata.map(|metadata| view! { <MetadataFields metadata /> })}
        {value.page.map(|page| view! { <div class="space-y-4">
            <h2 class="text-lg font-semibold">{collection.unwrap_or_default()}</h2>
            {if page.items.is_empty() { view! { <p class="text-gray-500">"No active resources found."</p> }.into_any() }
            else { view! { <div class="grid grid-cols-1 gap-4 md:grid-cols-2">
                {page.items.into_iter().map(|metadata| {
                    let href = path.child(&metadata).map(|child| child.console());
                    let name = metadata.name.clone();
                    view! { <article class="min-w-0 rounded-lg border border-gray-200 bg-white p-5 dark:border-gray-700 dark:bg-gray-800">
                        {href.map(|href| view! { <A href attr:class=LINK>{name}</A> })}
                        <MetadataFields metadata />
                    </article> }
                }).collect_view()}
            </div> }.into_any() }}
            <div class="flex gap-3" aria-label="Pagination">
                <Show when=move || !history.get().is_empty()>
                    <button class=BUTTON on:click=move |_| { let mut previous = history.get(); if let Some(cursor) = previous.pop() { history.set(previous); after.set(cursor); } }>"Previous"</button>
                </Show>
                {next.map(|cursor| view! { <button class=BUTTON on:click=move |_| { history.update(|items| items.push(after.get_untracked())); after.set(Some(cursor.clone())); }>"Next"</button> })}
            </div>
        </div> })}
    }
}

/// Shows only server-returned identity, classification and creation metadata as escaped text.
#[component]
fn MetadataFields(metadata: Metadata) -> impl IntoView {
    view! { <dl class="mt-3 space-y-1 break-words text-sm text-gray-500 dark:text-gray-400">
        <div><dt class="inline font-medium">"ID: "</dt><dd class="inline">{metadata.id}</dd></div>
        {metadata.slug.map(|slug| view! { <div><dt class="inline font-medium">"Slug: "</dt><dd class="inline">{slug}</dd></div> })}
        {metadata.tier.map(|tier| view! { <div><dt class="inline font-medium">"Tier: "</dt><dd class="inline">{tier}</dd></div> })}
        <div><dt class="inline font-medium">"Created: "</dt><dd class="inline">{metadata.created_at}</dd></div>
    </dl> }
}
