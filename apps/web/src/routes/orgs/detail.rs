//! Organization detail route. Shows projects and allows management of the tenant.

use crate::{
    app_lib::AppError,
    components::{Alert, AlertKind, Button, Spinner},
    features::orgs::{
        client,
        types::{CreateProjectRequest, ProjectResponse},
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

/// Renders the organization detail view.
#[component]
pub fn OrgDetailPage() -> impl IntoView {
    let params = use_params::<OrgParams>();

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
            <div class="flex items-center justify-between">
                <div class="space-y-1">
                    <h1 class="text-2xl font-semibold text-gray-900 dark:text-white">
                        {move || params.get().ok().and_then(|p| p.slug).unwrap_or_else(|| "Organization".to_string())}
                    </h1>
                    <p class="text-sm text-gray-500 dark:text-gray-400">
                        "Manage projects and environments for this organization."
                    </p>
                </div>

                <CreateProjectModal
                    org_slug=move || params.get().ok().and_then(|p| p.slug).unwrap_or_default()
                    on_success=Callback::new(move |_| projects.refetch())
                />
            </div>

            <Suspense fallback=move || view! { <Spinner /> }>
                {move || match projects.get() {
                    Some(Ok(list)) if list.is_empty() => {
                        view! {
                            <div class="text-center py-12 bg-white dark:bg-gray-800 rounded-lg border border-dashed border-gray-300 dark:border-gray-700">
                                <span class="material-symbols-outlined text-4xl text-gray-400">"account_tree"</span>
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
                                                class="block p-6 bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 hover:border-blue-500 dark:hover:border-blue-500 transition-colors shadow-sm"
                                            >
                                                <div class="flex items-start justify-between">
                                                    <span class="material-symbols-outlined text-green-600 dark:text-green-400">
                                                        "account_tree"
                                                    </span>
                                                    <span class="text-xs text-gray-400 dark:text-gray-500 uppercase font-mono tracking-wider">
                                                        {proj.slug}
                                                    </span>
                                                </div>
                                                <h2 class="mt-4 text-lg font-medium text-gray-900 dark:text-white truncate">
                                                    {proj.name}
                                                </h2>
                                                <p class="mt-1 text-xs text-gray-500 dark:text-gray-400">
                                                    "Created " {proj.created_at}
                                                </p>
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
        </div>
    }
}

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
                <div class="flex items-center gap-2">
                    <span class="material-symbols-outlined text-base">"add"</span>
                    "New Project"
                </div>
            </Button>

            <Show when=move || is_open.get()>
                <div class="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/50 backdrop-blur-sm">
                    <div class="bg-white dark:bg-gray-800 rounded-xl shadow-xl border border-gray-200 dark:border-gray-700 w-full max-w-md overflow-hidden animate-in fade-in zoom-in duration-200">
                        <div class="px-6 py-4 border-b border-gray-100 dark:border-gray-700 flex items-center justify-between">
                            <h2 class="text-lg font-semibold text-gray-900 dark:text-white">"Create Project"</h2>
                            <button
                                on:click=move |_| set_is_open.set(false)
                                class="text-gray-400 hover:text-gray-600 dark:hover:text-gray-200"
                            >
                                <span class="material-symbols-outlined">"close"</span>
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
                                <Alert kind=AlertKind::Error message=error.get().unwrap().to_string() />
                            </Show>

                            <div class="pt-4 flex flex-col-reverse sm:flex-row gap-3 sm:justify-end">
                                <button
                                    type="button"
                                    on:click=move |_| set_is_open.set(false)
                                    class="px-5 py-2.5 text-sm font-medium text-gray-700 bg-white border border-gray-300 rounded-lg hover:bg-gray-50 focus:ring-4 focus:ring-gray-100 dark:bg-gray-800 dark:text-gray-300 dark:border-gray-600 dark:hover:bg-gray-700 dark:focus:ring-gray-700"
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
