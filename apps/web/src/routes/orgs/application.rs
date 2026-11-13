//! Environment/application navigation completing the existing tenant hierarchy.
//!
//! Flow Overview: resolve the route through collection APIs, then provide trusted
//! application metadata to nested configuration pages. No roles are inferred from
//! platform scopes; the backend enforces every mutation independently.
//! Environment headers resolve display metadata through the existing project collection;
//! application cards stay whole-card links, with copyable IDs reserved for the overview.

use super::deletion::{DeleteResource, DeleteTarget};

use crate::{
    app_lib::AppError,
    components::{
        Alert, AlertKind, Button, CopyValue, DateTime, EmptyValue, EntityHeader, Icon, IconName,
        MetaItem, icon_size,
    },
    features::{
        oauth::paths::EnvironmentPaths,
        orgs::{
            client,
            types::{ApplicationResponse, CreateApplicationRequest, EnvironmentResponse},
        },
    },
    routes::oauth::common::{
        ApplicationContext, ApplicationNav, CARD, EmptyState, FormError, INPUT, LABEL, LINK,
        Loading, ResourceParams, application_context, error_message,
    },
};
use leptos::prelude::*;
use leptos_router::{
    components::{A, Outlet},
    hooks::use_params,
};

/// Lists applications with environment metadata; creation still uses the existing scoped API.
#[component]
pub fn EnvironmentDetailPage() -> impl IntoView {
    let params = use_params::<ResourceParams>();
    let context = Signal::derive(move || {
        params
            .get()
            .map_err(|_| AppError::Config("Invalid resource path.".to_owned()))
            .and_then(|value| value.environment())
    });
    let environment = LocalResource::new(move || {
        let path = context.get();
        async move {
            let path = path?;
            client::list_environments(&path.org, &path.project)
                .await
                .map(|items| items.into_iter().find(|env| env.slug == path.environment))
        }
    });
    let applications = LocalResource::new(move || {
        let path = context.get();
        async move { client::list_applications(&path?).await }
    });
    let name = RwSignal::new(String::new());
    let error = RwSignal::new(String::new());
    let create = Action::new_local(
        move |(path, request): &(EnvironmentPaths, CreateApplicationRequest)| {
            let path = path.clone();
            let request = request.clone();
            async move {
                client::create_application(&path.org, &path.project, &path.environment, &request)
                    .await
            }
        },
    );
    Effect::new(move |_| {
        if let Some(result) = create.value().get() {
            match result {
                Ok(_) => {
                    name.set(String::new());
                    error.set(String::new());
                    applications.refetch();
                }
                Err(err) => error.set(error_message(&err)),
            }
        }
    });
    view! { <div class="min-w-0 space-y-6 text-gray-900 dark:text-white">
        {move || context.get().ok().map(|path| view! { <nav aria-label="Breadcrumb"><A href=path.project_console() attr:class=LINK>{path.project}</A></nav> })}
        <EnvironmentHeader context=context environment=environment applications=applications />
        <Suspense fallback=|| view! { <Loading message="Loading applications…" /> }>
            {move || match applications.get() {
                Some(Ok(items)) if items.is_empty() => view! { <EmptyState title="No applications" message="Create an application to organize its OAuth clients and delegated scopes." /> }.into_any(),
                Some(Ok(items)) => view! {
                    <div class="grid gap-4 sm:grid-cols-2">
                        {items.into_iter().map(|app| {
                            let path = context.get().ok().map_or_default(|value| value.application(&app.id).console());
                            view! {
                                <A href=path attr:class="block min-w-0 cursor-pointer rounded-lg border border-gray-200 bg-white p-5 hover:border-gray-400 focus-visible:ring-2 focus-visible:ring-blue-500 dark:border-gray-700 dark:bg-gray-800 dark:hover:border-gray-500">
                                    <EntityHeader icon=IconName::Clients navigable=true>{app.name}</EntityHeader>
                                    <dl class="mt-3">
                                        <MetaItem icon=IconName::Calendar label="Created"><DateTime value=app.created_at /></MetaItem>
                                    </dl>
                                </A>
                            }
                        }).collect_view()}
                    </div>
                }.into_any(),
                Some(Err(err)) => view! { <Alert kind=AlertKind::Error message=error_message(&err) /> }.into_any(),
                None => view! { <Loading message="Loading applications…" /> }.into_any(),
            }}
        </Suspense>
        <details class=CARD><summary class="cursor-pointer rounded font-medium hover:text-gray-600 focus-visible:ring-2 focus-visible:ring-blue-500 dark:hover:text-gray-300">"Create Application"</summary>
            <form class="mt-4 space-y-4" on:submit=move |ev| { ev.prevent_default(); if create.pending().get_untracked() { return; }
                if let Ok(path) = context.get_untracked() { error.set(String::new()); create.dispatch((path, CreateApplicationRequest { name: name.get_untracked().trim().to_owned() })); } }>
                <label for="application-name" class=LABEL>"Application name"</label>
                <input id="application-name" required maxlength="255" class=INPUT prop:value=move || name.get() disabled=move || create.pending().get() aria-describedby="application-error" on:input=move |ev| name.set(event_target_value(&ev)) />
                <FormError id="application-error" error=error />
                <Button button_type="submit" disabled=create.pending()>"Create Application"</Button>
            </form>
        </details>
        {move || context.get().ok().map(|path| view! { <DeleteResource refresh=Callback::new(move |()| applications.refetch()) confirmation_name=path.environment.clone() target=DeleteTarget::Environment(path) blocked=Signal::derive(move || match applications.get() {
            Some(Ok(items)) if items.is_empty() => None,
            Some(Ok(_)) => Some("Delete all applications before deleting this environment.".to_owned()),
            Some(Err(_)) => Some("Unable to verify active applications. Reload this page before deleting.".to_owned()),
            None => Some("Checking active applications…".to_owned()),
        }) /> })}
    </div> }
}

/// Displays collection-resolved environment metadata and refreshes existing resources.
#[component]
fn EnvironmentHeader(
    context: Signal<Result<EnvironmentPaths, AppError>>,
    environment: LocalResource<Result<Option<EnvironmentResponse>, AppError>>,
    applications: LocalResource<Result<Vec<ApplicationResponse>, AppError>>,
) -> impl IntoView {
    view! {
        <header class="flex flex-wrap items-start justify-between gap-4">
            <div class="min-w-0 w-full sm:w-auto sm:flex-1">
                <h1 class="break-words text-2xl font-semibold">
                    {move || environment.get().and_then(Result::ok).flatten().map_or_else(
                        || context.get().ok().map_or_default(|path| path.environment),
                        |env| env.name,
                    )}
                </h1>
                <p class="mt-1 text-sm text-gray-500 dark:text-gray-400">"Applications in this environment. Organization owners and admins can create applications and manage OAuth configuration."</p>
                <div class="min-h-28 pt-3" role="group" aria-label="Environment metadata">
                    <Suspense fallback=|| view! { <Loading message="Loading environment…" /> }>
                        {move || match environment.get() {
                            Some(Ok(Some(env))) => view! {
                                <dl>
                                    <MetaItem icon=IconName::Tag label="Slug" mono=true>{env.slug}</MetaItem>
                                    <MetaItem icon=IconName::Identifier label="Environment ID">
                                        <CopyValue value=env.id label="environment ID" compact=true />
                                    </MetaItem>
                                    <MetaItem icon=IconName::Environments label="Tier">{if env.tier == "production" { "Production" } else { "Non-Production" }}</MetaItem>
                                    <MetaItem icon=IconName::Calendar label="Created"><DateTime value=env.created_at /></MetaItem>
                                </dl>
                            }.into_any(),
                            Some(Err(_) | Ok(None)) => view! { <EmptyValue text="Unavailable" /> }.into_any(),
                            None => ().into_any(),
                        }}
                    </Suspense>
                </div>
            </div>
            <button type="button" on:click=move |_| { applications.refetch(); environment.refetch(); }
                class="inline-flex cursor-pointer items-center gap-1.5 rounded px-2 py-2 text-sm text-gray-500 hover:bg-gray-100 hover:text-gray-900 focus-visible:ring-2 focus-visible:ring-blue-500 dark:text-gray-400 dark:hover:bg-gray-800 dark:hover:text-white">
                <Icon name=IconName::Refresh size=icon_size::INLINE />"Refresh"
            </button>
        </header>
    }
}

/// Resolves application metadata through the actual list endpoint before mounting children.
#[component]
pub fn ApplicationLayout() -> impl IntoView {
    let params = use_params::<ResourceParams>();
    let application = LocalResource::new(move || {
        let path = params
            .get()
            .map_err(|_| AppError::Config("Invalid path.".to_owned()))
            .and_then(|value| value.application());
        async move {
            let path = path?;
            let app = client::list_applications(&path.environment)
                .await?
                .into_iter()
                .find(|app| app.id == path.application)
                .ok_or_else(|| AppError::Http {
                    status: 404,
                    code: None,
                    message: String::new(),
                })?;
            Ok::<_, AppError>(ApplicationContext {
                paths: path,
                application: app,
            })
        }
    });
    view! { <Suspense fallback=|| view! { <Loading message="Loading application…" /> }>
        {move || match application.get() {
            Some(Ok(context)) => view! { <ApplicationFrame context=context /> }.into_any(),
            Some(Err(err)) => view! { <Alert kind=AlertKind::Error message=error_message(&err) /> }.into_any(),
            None => view! { <Loading message="Loading application…" /> }.into_any(),
        }}
    </Suspense> }
}

/// Provides scoped context and consistent application navigation to nested routes.
#[component]
fn ApplicationFrame(context: ApplicationContext) -> impl IntoView {
    provide_context(context.clone());
    let path = context.paths;
    let org_href = crate::routes::paths::org_detail(&path.environment.org);
    let project_href = path.environment.project_console();
    let environment_href = path.environment.console();
    let navigation_paths = path.clone();
    let org_name = path.environment.org.clone();
    let project_name = path.environment.project.clone();
    let environment_name = path.environment.environment.clone();
    let environment_subtitle = path.environment.environment;
    view! { <div class="min-w-0 space-y-6 text-gray-900 dark:text-white">
        <nav aria-label="Breadcrumb" class="flex flex-wrap gap-2 text-sm">
            <A href=crate::routes::paths::ORGS attr:class=LINK>"Organizations"</A><span>"/"</span>
            <A href=org_href attr:class=LINK>{org_name}</A><span>"/"</span>
            <A href=project_href attr:class=LINK>{project_name}</A><span>"/"</span>
            <A href=environment_href attr:class=LINK>{environment_name}</A>
        </nav>
        <header class="min-w-0">
            <h1 class="break-words text-2xl font-semibold">{context.application.name}</h1>
            <dl class="mt-3">
                <MetaItem icon=IconName::Environments label="Environment" mono=true>{environment_subtitle}</MetaItem>
            </dl>
        </header>
        <ApplicationNav paths=navigation_paths />
        <Outlet />
    </div> }
}

/// Shows copyable application identity, readable creation metadata and OAuth configuration.
#[component]
pub fn ApplicationOverviewPage() -> impl IntoView {
    let Some(context) = application_context() else {
        return view! { <Alert kind=AlertKind::Error message="Application unavailable.".to_owned() /> }.into_any();
    };
    let fetch_path = context.paths.clone();
    let clients = LocalResource::new(move || {
        let path = fetch_path.clone();
        async move { crate::features::oauth::client::list_clients(&path).await }
    });
    let target = DeleteTarget::Application(context.paths.clone());
    let confirmation_name = context.application.name.clone();
    view! { <div class="space-y-6">
        <div class=CARD>
            <EntityHeader icon=IconName::Overview>"Application overview"</EntityHeader>
            <dl class="mt-3">
                <MetaItem icon=IconName::Identifier label="Application ID">
                    <CopyValue value=context.application.id label="application ID" compact=true />
                </MetaItem>
                <MetaItem icon=IconName::Calendar label="Created"><DateTime value=context.application.created_at /></MetaItem>
            </dl>
            <p class="mt-4 text-sm">"Configure separate OAuth clients for this application's browser, CLI, or server integrations."</p>
            <div class="mt-4"><A href=context.paths.oauth() attr:class=LINK>"Manage OAuth configuration →"</A></div>
        </div>
        <DeleteResource refresh=Callback::new(move |()| clients.refetch()) target=target confirmation_name=confirmation_name blocked=Signal::derive(move || match clients.get() {
            Some(Ok(items)) if items.is_empty() => None,
            Some(Ok(_)) => Some("Delete all OAuth clients, including disabled clients, before deleting this application.".to_owned()),
            Some(Err(_)) => Some("Unable to verify OAuth clients. Reload this page before deleting.".to_owned()),
            None => Some("Checking OAuth clients…".to_owned()),
        }) />
    </div> }.into_any()
}
