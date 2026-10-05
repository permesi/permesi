//! Environment/application navigation completing the existing tenant hierarchy.
//!
//! Flow Overview: resolve the route through collection APIs, then provide trusted
//! application metadata to nested configuration pages. No roles are inferred from
//! platform scopes; the backend enforces every mutation independently.

use super::deletion::{DeleteResource, DeleteTarget};

use crate::{
    app_lib::AppError,
    components::{Alert, AlertKind, Button},
    features::{
        oauth::paths::EnvironmentPaths,
        orgs::{client, types::CreateApplicationRequest},
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

/// Lists applications in one environment and creates logical applications via its API.
#[component]
pub fn EnvironmentDetailPage() -> impl IntoView {
    let params = use_params::<ResourceParams>();
    let context = Signal::derive(move || {
        params
            .get()
            .map_err(|_| AppError::Config("Invalid resource path.".to_owned()))
            .and_then(|value| value.environment())
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
    view! { <div class="space-y-6 text-gray-900 dark:text-white">
        {move || context.get().ok().map(|path| view! { <nav aria-label="Breadcrumb"><A href=path.project_console() attr:class=LINK>{path.project}</A></nav> })}
        <h1 class="text-2xl font-semibold">{move || context.get().ok().map(|path| path.environment).unwrap_or_default()}</h1>
        <p class="text-sm text-gray-500 dark:text-gray-400">"Applications in this environment. Organization owners and admins can create applications and manage OAuth configuration."</p>
        <Suspense fallback=|| view! { <Loading message="Loading applications…" /> }>
            {move || match applications.get() {
                Some(Ok(items)) if items.is_empty() => view! { <EmptyState title="No applications" message="Create an application to organize its OAuth clients and delegated scopes." /> }.into_any(),
                Some(Ok(items)) => view! { <div class="grid gap-4 sm:grid-cols-2">{items.into_iter().map(|app| { let path = context.get().ok().map(|value| value.application(&app.id).console()).unwrap_or_default(); view! { <A href=path attr:class="block min-w-0 cursor-pointer rounded-lg border border-gray-200 bg-white p-6 shadow-sm hover:border-blue-500 focus:ring-2 focus:ring-blue-500 dark:border-gray-700 dark:bg-gray-800 dark:hover:border-blue-500"><h2 class="break-words text-lg font-medium">{app.name}</h2><p class="mt-2 text-xs text-gray-500">"Created " {app.created_at}</p></A> } }).collect_view()}</div> }.into_any(),
                Some(Err(err)) => view! { <Alert kind=AlertKind::Error message=error_message(&err) /> }.into_any(),
                None => view! { <Loading message="Loading applications…" /> }.into_any(),
            }}
        </Suspense>
        <details class=CARD><summary class="cursor-pointer font-medium hover:text-blue-600">"Create Application"</summary>
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
        <header><h1 class="break-words text-2xl font-semibold">{context.application.name}</h1><p class="mt-1 text-sm text-gray-500 dark:text-gray-400">{environment_subtitle}</p></header>
        <ApplicationNav paths=navigation_paths />
        <Outlet />
    </div> }
}

/// Shows logical application metadata and the OAuth configuration entry point.
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
    view! { <div class="space-y-6"><div class=CARD><h2 class="text-lg font-medium">"Application overview"</h2><p class="mt-2 text-sm text-gray-500">"Created " {context.application.created_at}</p><p class="mt-4 text-sm">"Configure separate OAuth clients for this application's browser, CLI, or server integrations."</p><div class="mt-4"><A href=context.paths.oauth() attr:class=LINK>"Manage OAuth configuration →"</A></div></div>
        <DeleteResource refresh=Callback::new(move |()| clients.refetch()) target=target confirmation_name=confirmation_name blocked=Signal::derive(move || match clients.get() {
            Some(Ok(items)) if items.is_empty() => None,
            Some(Ok(_)) => Some("Delete all OAuth clients, including disabled clients, before deleting this application.".to_owned()),
            Some(Err(_)) => Some("Unable to verify OAuth clients. Reload this page before deleting.".to_owned()),
            None => Some("Checking OAuth clients…".to_owned()),
        }) />
    </div> }.into_any()
}
