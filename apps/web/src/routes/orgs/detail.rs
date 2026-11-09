//! Organization detail route. Shows projects and allows management of the tenant.
//! Header metadata is resolved from the existing membership-scoped organization list;
//! linked project cards omit interactive identifiers and use readable creation dates.

use super::deletion::{DeleteResource, DeleteTarget};

use crate::{
    app_lib::AppError,
    components::{
        Alert, AlertKind, Button, CopyValue, DateTime, EmptyValue, EntityHeader, Icon, IconName,
        MetaItem, Spinner, icon_size,
    },
    features::orgs::{
        client,
        types::{CreateProjectRequest, OrgResponse, ProjectResponse},
    },
    routes::paths,
};
use leptos::prelude::*;
use leptos_router::components::A;
use leptos_router::{hooks::use_params, params::Params};

#[derive(Params, PartialEq, Clone)]
struct OrgParams {
    slug: Option<String>,
}

/// Renders organization metadata and projects without changing management authorization.
#[component]
pub fn OrgDetailPage() -> impl IntoView {
    let params = use_params::<OrgParams>();
    let organization = LocalResource::new(move || {
        let slug = params.get().ok().and_then(|p| p.slug).unwrap_or_default();
        async move {
            client::list_orgs()
                .await
                .map(|items| items.into_iter().find(|org| org.slug == slug))
        }
    });

    let projects = LocalResource::new(move || {
        let slug = params.get().ok().and_then(|p| p.slug).unwrap_or_default();
        async move {
            if slug.is_empty() {
                return Err(AppError::Config(
                    "Organization slug is required".to_string(),
                ));
            }
            client::list_projects(&slug).await
        }
    });

    view! {
        <div class="space-y-6">
            <OrganizationHeader organization=organization projects=projects />

            <Suspense fallback=move || view! { <Spinner /> }>
                {move || match projects.get() {
                    Some(Ok(list)) if list.is_empty() => {
                        view! {
                            <div class="text-center py-12 bg-white dark:bg-gray-800 rounded-lg border border-dashed border-gray-300 dark:border-gray-700">
                                <Icon name=IconName::Projects size=icon_size::EMPTY class="text-gray-400 dark:text-gray-500" />
                                <h3 class="mt-2 text-sm font-medium text-gray-900 dark:text-white">"No projects"</h3>
                                <p class="mt-1 text-sm text-gray-500 dark:text-gray-400">"Add your first project to this organization."</p>
                            </div>
                        }.into_any()
                    }
                    Some(Ok(list)) => {
                        view! {
                            <div class="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
                                <For
                                    each=move || list.clone()
                                    key=|proj| proj.id.clone()
                                    children=move |proj| {
                                        let org_slug = params.get().ok().and_then(|p| p.slug).unwrap_or_default();
                                        view! {
                                            <A
                                                href={paths::project_detail(&org_slug, &proj.slug)}
                                                {..}
                                                class="block min-w-0 cursor-pointer p-5 bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 hover:border-gray-400 dark:hover:border-gray-500 focus-visible:ring-2 focus-visible:ring-blue-500 transition-colors"
                                            >
                                                <EntityHeader icon=IconName::Projects navigable=true>{proj.name}</EntityHeader>
                                                <dl class="mt-3">
                                                    <MetaItem icon=IconName::Tag label="Slug" mono=true>{proj.slug}</MetaItem>
                                                    <MetaItem icon=IconName::Calendar label="Created"><DateTime value=proj.created_at /></MetaItem>
                                                </dl>
                                            </A>
                                        }
                                    }
                                />
                            </div>
                        }.into_any()
                    }
                    Some(Err(err)) => {
                        view! { <Alert kind=AlertKind::Error message=err.to_string() /> }.into_any()
                    }
                    None => view! { <Spinner /> }.into_any(),
                }}
            </Suspense>
            {move || params.get().ok().and_then(|p| p.slug).map(|slug| {

                view! { <DeleteResource refresh=Callback::new(move |()| projects.refetch()) target=DeleteTarget::Organization(slug.clone()) confirmation_name=slug blocked=Signal::derive(move || match projects.get() {
                    Some(Ok(items)) if items.is_empty() => None,
                    Some(Ok(_)) => Some("Delete all projects before deleting this organization.".to_owned()),
                    Some(Err(_)) => Some("Unable to verify active children. Reload this page before deleting.".to_owned()),
                    None => Some("Checking active children…".to_owned()),
                }) /> }
            })}
        </div>
    }
}

/// Shows membership-scoped organization metadata and existing project actions.
#[component]
fn OrganizationHeader(
    organization: LocalResource<Result<Option<OrgResponse>, AppError>>,
    projects: LocalResource<Result<Vec<ProjectResponse>, AppError>>,
) -> impl IntoView {
    let params = use_params::<OrgParams>();
    view! {
        <div class="flex flex-wrap items-start justify-between gap-4">
            <div class="min-w-0 w-full space-y-1 sm:w-auto sm:flex-1">
                <h1 class="break-words text-2xl font-semibold text-gray-900 dark:text-white">
                    {move || organization.get().and_then(Result::ok).flatten().map_or_else(
                        || params.get().ok().and_then(|p| p.slug).unwrap_or_else(|| "Organization".to_owned()),
                        |org| org.name,
                    )}
                </h1>
                <p class="text-sm text-gray-500 dark:text-gray-400">
                    "Manage projects and environments for this organization."
                </p>
                <div class="min-h-24 pt-2" role="group" aria-label="Organization metadata">
                    <Suspense fallback=move || view! { <Spinner /> }>
                        {move || match organization.get() {
                            Some(Ok(Some(org))) => view! {
                                <dl>
                                    <MetaItem icon=IconName::Tag label="Slug" mono=true>{org.slug}</MetaItem>
                                    <MetaItem icon=IconName::Identifier label="Organization ID">
                                        <CopyValue value=org.id label="organization ID" compact=true />
                                    </MetaItem>
                                    <MetaItem icon=IconName::Calendar label="Created"><DateTime value=org.created_at /></MetaItem>
                                </dl>
                            }.into_any(),
                            Some(Err(_) | Ok(None)) => view! { <EmptyValue text="Unavailable" /> }.into_any(),
                            None => ().into_any(),
                        }}
                    </Suspense>
                </div>
            </div>
            <div class="flex flex-wrap items-center gap-3">
                <button type="button" on:click=move |_| { projects.refetch(); organization.refetch(); }
                    class="inline-flex cursor-pointer items-center gap-1.5 rounded px-2 py-2 text-sm text-gray-500 hover:bg-gray-100 hover:text-gray-900 focus-visible:ring-2 focus-visible:ring-blue-500 dark:text-gray-400 dark:hover:bg-gray-800 dark:hover:text-white">
                    <Icon name=IconName::Refresh size=icon_size::INLINE />"Refresh"
                </button>
                <CreateProjectModal
                    org_slug=move || params.get().ok().and_then(|p| p.slug).unwrap_or_default()
                    on_success=Callback::new(move |_| projects.refetch())
                />
            </div>
        </div>
    }
}

/// Creates a project with the existing organization-scoped request and validation.
#[component]
fn CreateProjectModal<F>(org_slug: F, on_success: Callback<ProjectResponse>) -> impl IntoView
where
    F: Fn() -> String + Send + Sync + 'static,
{
    let (is_open, set_is_open) = signal(false);
    let (name, set_name) = signal(String::new());
    let (slug, set_slug) = signal(String::new());
    let (error, set_error) = signal::<Option<AppError>>(None);

    let create_action =
        Action::new_local(move |(slug_val, req): &(String, CreateProjectRequest)| {
            let slug_val = slug_val.clone();
            let req = req.clone();
            async move { client::create_project(&slug_val, &req).await }
        });

    Effect::new(move |_| {
        if let Some(result) = create_action.value().get() {
            match result {
                Ok(proj) => {
                    set_is_open.set(false);
                    set_name.set(String::new());
                    set_slug.set(String::new());
                    set_error.set(None);
                    on_success.run(proj);
                }
                Err(err) => set_error.set(Some(err)),
            }
        }
    });

    let on_submit = StoredValue::new(move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        let name_val = name.get_untracked().trim().to_string();
        let slug_val = slug.get_untracked().trim().to_string();

        if name_val.is_empty() {
            set_error.set(Some(AppError::Config("Name is required".to_string())));
            return;
        }

        create_action.dispatch((
            org_slug(),
            CreateProjectRequest {
                name: name_val,
                slug: if slug_val.is_empty() {
                    None
                } else {
                    Some(slug_val)
                },
            },
        ));
    });

    view! {
        <div>
            <Button on_click=move |_| set_is_open.set(true)>
                "New Project"
            </Button>

            <Show when=move || is_open.get()>
                <div class="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/50 backdrop-blur-sm">
                    <div class="bg-white dark:bg-gray-800 rounded-xl shadow-xl border border-gray-200 dark:border-gray-700 w-full max-w-md overflow-hidden animate-in fade-in zoom-in duration-200">
                        <div class="px-6 py-4 border-b border-gray-100 dark:border-gray-700 flex items-start justify-between gap-3">
                            <h2 class="min-w-0 break-words text-lg font-medium text-gray-900 dark:text-white">"Create Project"</h2>
                            <button
                                on:click=move |_| set_is_open.set(false)
                                type="button"
                                class="shrink-0 cursor-pointer p-1 text-gray-400 hover:bg-gray-100 hover:text-gray-600 focus-visible:ring-2 focus-visible:ring-blue-500 rounded dark:hover:bg-gray-700 dark:hover:text-gray-200"
                                aria-label="Close dialog"
                                title="Close dialog"
                            >
                                <Icon name=IconName::Cancel size=icon_size::CONTROL />
                            </button>
                        </div>

                        <form on:submit=move |ev| on_submit.with_value(|f| f(ev)) class="p-6 space-y-4">
                            <div>
                                <label class="block mb-2 text-sm font-medium text-gray-900 dark:text-white">"Project Name"</label>
                                <input
                                    type="text"
                                    required
                                    class="bg-gray-50 border border-gray-300 text-gray-900 text-sm rounded-lg focus:ring-blue-500 focus:border-blue-500 block w-full p-2.5 dark:bg-gray-700 dark:border-gray-600 dark:placeholder-gray-400 dark:text-white dark:focus:ring-blue-500 dark:focus:border-blue-500"
                                    placeholder="Payments Service"
                                    on:input=move |ev| set_name.set(event_target_value(&ev))
                                    value=move || name.get()
                                />
                            </div>

                            <div>
                                <label class="block mb-2 text-sm font-medium text-gray-900 dark:text-white">"Slug (optional)"</label>
                                <input
                                    type="text"
                                    class="bg-gray-50 border border-gray-300 text-gray-900 text-sm rounded-lg focus:ring-blue-500 focus:border-blue-500 block w-full p-2.5 dark:bg-gray-700 dark:border-gray-600 dark:placeholder-gray-400 dark:text-white dark:focus:ring-blue-500 dark:focus:border-blue-500 font-mono"
                                    placeholder="payments-api"
                                    on:input=move |ev| set_slug.set(event_target_value(&ev))
                                    value=move || slug.get()
                                />
                                <p class="mt-1 text-xs text-gray-500">"Leave blank to auto-generate from name."</p>
                            </div>

                            <Show when=move || error.get().is_some()>
                                <Alert kind=AlertKind::Error message=error.get().map_or_else(String::new, |err| err.to_string()) />
                            </Show>

                            <div class="pt-4 flex flex-col-reverse sm:flex-row gap-3 sm:justify-end">
                                <button
                                    type="button"
                                    on:click=move |_| set_is_open.set(false)
                                    class="cursor-pointer px-5 py-2.5 text-sm font-medium text-gray-700 bg-white border border-gray-300 rounded-lg hover:bg-gray-50 focus:ring-4 focus:ring-gray-100 dark:bg-gray-800 dark:text-gray-300 dark:border-gray-600 dark:hover:bg-gray-700 dark:focus:ring-gray-700"
                                >
                                    "Cancel"
                                </button>
                                <Button button_type="submit" disabled=create_action.pending()>
                                    {move || if create_action.pending().get() { "Creating..." } else { "Create Project" }}
                                </Button>
                            </div>
                        </form>
                    </div>
                </div>
            </Show>
        </div>
    }
}
