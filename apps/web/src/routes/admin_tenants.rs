//! Read-only platform hierarchy views with independent state for each path and identity.
//!
//! Flow Overview: the existing operator/elevation UI guard mounts an identity-keyed
//! inspection page; metadata and a bounded child page come only from admin GET APIs.
//! Navigation never mounts tenant edit/delete/OAuth controls. Copyable identifiers and
//! UTC dates aid inspection; account/path changes discard previous metadata and cursors.

use crate::{
    app_lib::AppError,
    components::{
        Alert, AlertKind, CopyValue, DateTime, EmptyValue, EntityHeader, Icon, IconName, MetaItem,
        Spinner, icon_size,
    },
    features::{
        admin_tenants::{self, Inspection, InspectionPath, Metadata},
        auth::{RequireAdmin, state::use_auth},
    },
};
use leptos::prelude::*;
use leptos_router::{components::A, hooks::use_params, params::Params};

const LINK: &str = "cursor-pointer rounded text-gray-700 hover:text-blue-600 focus-visible:ring-2 focus-visible:ring-blue-500 dark:text-gray-300 dark:hover:text-blue-400";
const BUTTON: &str = "inline-flex cursor-pointer items-center gap-2 rounded border border-gray-300 px-3 py-2 text-sm hover:bg-gray-100 focus-visible:ring-2 focus-visible:ring-blue-500 dark:border-gray-600 dark:hover:bg-gray-700";

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
            <div class="min-w-0"><h1 class="break-words text-2xl font-semibold">{move || data.get().and_then(Result::ok).and_then(|value| value.metadata.map(|row| row.name)).unwrap_or_else(|| "Global Organizations".to_owned())}</h1>
                <p class="text-sm text-gray-500 dark:text-gray-400">"Read-only platform inspection"</p></div>
            <button type="button" class=BUTTON on:click=move |_| { history.set(Vec::new()); after.set(None); data.refetch(); }>
                <Icon name=IconName::Refresh size=icon_size::INLINE />"Refresh"
            </button>
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
    let owner_detail = matches!(&path, InspectionPath::Organization(_));
    let owner_cards = matches!(&path, InspectionPath::Organizations);
    let child_icon = match &path {
        InspectionPath::Organizations => IconName::Organizations,
        InspectionPath::Organization(_) => IconName::Projects,
        InspectionPath::Project(..) => IconName::Environments,
        InspectionPath::Environment(..) | InspectionPath::Application(..) => IconName::Clients,
    };
    view! {
        {value.metadata.map(|metadata| view! { <MetadataFields metadata show_owners=owner_detail /> })}
        {value.page.map(|page| view! { <div class="space-y-4">
            <h2 class="text-lg font-medium">{collection.unwrap_or_default()}</h2>
            {if page.items.is_empty() { view! { <p class="text-gray-500 dark:text-gray-400">"No active resources found."</p> }.into_any() }
            else { view! { <div class="grid grid-cols-1 gap-4 md:grid-cols-2">
                {page.items.into_iter().map(|metadata| {
                    let href = path.child(&metadata).map(|child| child.console());
                    let name = metadata.name.clone();
                    view! { <article class="min-w-0 rounded-lg border border-gray-200 bg-white p-5 dark:border-gray-700 dark:bg-gray-800">
                        {href.map(|href| view! { <EntityHeader icon=child_icon><A href attr:class=LINK>{name}</A></EntityHeader> })}
                        <MetadataFields metadata show_owners=owner_cards />
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
fn MetadataFields(metadata: Metadata, show_owners: bool) -> impl IntoView {
    view! { <dl class="mt-3 min-w-0">
        <MetaItem icon=IconName::Identifier label="ID">
            <CopyValue value=metadata.id label="resource ID" compact=true />
        </MetaItem>
        {metadata.slug.map(|slug| view! { <MetaItem icon=IconName::Tag label="Slug" mono=true>{slug}</MetaItem> })}
        {metadata.tier.map(|tier| view! { <MetaItem icon=IconName::Environments label="Tier">{tier}</MetaItem> })}
        <MetaItem icon=IconName::Calendar label="Created">
            <DateTime value=metadata.created_at />
        </MetaItem>
        {show_owners.then(|| {
            let unavailable = metadata.owners.is_none();
            let owners = metadata.owners.unwrap_or_default();
            let label = if owners.len() > 1 { "Owners" } else { "Owner" };
            view! { <MetaItem icon=IconName::Person label=label>
                {if owners.is_empty() {
                    view! { <EmptyValue text=if unavailable { "Unavailable" } else { "None" } /> }.into_any()
                } else {
                    view! { <span class="flex flex-wrap gap-x-3 gap-y-1">
                        {owners.into_iter().map(|owner| {
                            let href = crate::routes::paths::user_detail(&owner.user_id);
                            let name = owner.display_name.filter(|name| !name.trim().is_empty()).unwrap_or(owner.email);
                            view! { <span class="min-w-0 max-w-full break-all"><A href attr:class=LINK>{name}</A></span> }
                        }).collect_view()}
                    </span> }.into_any()
                }}
            </MetaItem> }
        })}
    </dl> }
}
