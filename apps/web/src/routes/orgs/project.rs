//! Project detail route for independent sibling environments and their applications.
//!
//! The session-backed list supplies tier-selection hints only. Creation order is
//! unrestricted; org management authorization and the production limit remain server-side.

use crate::features::oauth::paths::EnvironmentPaths;
use crate::{
    app_lib::AppError,
    components::{Alert, AlertKind, Button, Spinner, ui::Dialog},
    features::orgs::{
        client,
        types::{CreateEnvironmentRequest, EnvironmentResponse, production_tier_present},
    },
};
use leptos::prelude::*;
use leptos_router::{components::A, hooks::use_params, params::Params};

#[derive(Params, PartialEq, Clone)]
struct ProjectParams {
    slug: Option<String>,
    project_slug: Option<String>,
}

/// Renders the project detail view.
#[component]
pub fn ProjectDetailPage() -> impl IntoView {
    let params = use_params::<ProjectParams>();

    let envs = LocalResource::new(move || {
        let p = params.get().ok();
        let org_slug = p.as_ref().and_then(|p| p.slug.clone()).unwrap_or_default();
        let project_slug = p
            .as_ref()
            .and_then(|p| p.project_slug.clone())
            .unwrap_or_default();

        async move {
            if org_slug.is_empty() || project_slug.is_empty() {
                return Err(AppError::Config("Missing route parameters".to_string()));
            }
            client::list_environments(&org_slug, &project_slug).await
        }
    });

    view! {
        <div class="space-y-6">
            <div class="flex flex-wrap items-center justify-between gap-3">
                <div class="space-y-1">
                    <h1 class="text-2xl font-semibold text-gray-900 dark:text-white">
                        {move || params.get().ok().and_then(|p| p.project_slug).unwrap_or_else(|| "Project".to_string())}
                    </h1>
                    <p class="text-sm text-gray-500 dark:text-gray-400">
                        "Manage environments and applications for this project."
                    </p>
                </div>

                <CreateEnvModal
                    org_slug=move || params.get().ok().and_then(|p| p.slug).unwrap_or_default()
                    project_slug=move || params.get().ok().and_then(|p| p.project_slug).unwrap_or_default()
                    production_exists=Signal::derive(move || envs.get().is_some_and(|result| result.is_ok_and(|list| production_tier_present(&list))))
                    on_success=Callback::new(move |_| envs.refetch())
                />
            </div>

            <Suspense fallback=move || view! { <Spinner /> }>
                {move || match envs.get() {
                    Some(Ok(list)) if list.is_empty() => {
                        view! {
                            <div class="text-center py-12 bg-white dark:bg-gray-800 rounded-lg border border-dashed border-gray-300 dark:border-gray-700">
                                <span class="material-symbols-outlined text-4xl text-gray-400">"lan"</span>
                                <h3 class="mt-2 text-sm font-medium text-gray-900 dark:text-white">"No environments"</h3>
                                <p class="mt-1 text-sm text-gray-500 dark:text-gray-400">"Create an environment to get started. Either tier can be created first."</p>
                            </div>
                        }.into_any()
                    }
                    Some(Ok(list)) => {
                        view! {
                            <div class="grid grid-cols-1 gap-4 sm:grid-cols-2">
                                <For
                                    each=move || list.clone()
                                    key=|env| env.id.clone()
                                    children=move |env| {
                                        let tier_class = if env.tier == "production" {
                                            "bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-300"
                                        } else {
                                            "bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-300"
                                        };
                                        view! {
                                            <A href=EnvironmentPaths {
                                                org: params.get().ok().and_then(|p| p.slug).unwrap_or_default(),
                                                project: params.get().ok().and_then(|p| p.project_slug).unwrap_or_default(),
                                                environment: env.slug.clone(),
                                            }.console() attr:class="block cursor-pointer p-6 bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 shadow-sm hover:border-blue-500 dark:hover:border-blue-500 focus:ring-2 focus:ring-blue-500 transition-colors">
                                                <div class="flex items-center justify-between mb-4">
                                                    <span class=format!("text-xs font-semibold px-2.5 py-0.5 rounded-full {}", tier_class)>
                                                        {env.tier.to_uppercase()}
                                                    </span>
                                                    <span class="text-xs font-mono text-gray-400">{env.slug}</span>
                                                </div>
                                                <h2 class="text-lg font-medium text-gray-900 dark:text-white">{env.name}</h2>
                                                <div class="mt-4 pt-4 border-t border-gray-50 dark:border-gray-700">
                                                    <p class="text-sm text-blue-600 dark:text-blue-400">"Manage applications →"</p>
                                                </div>
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

/// Creates either tier without prerequisites, using the current list only to avoid
/// offering a second production tier. Server authorization and validation remain authoritative.
#[component]
fn CreateEnvModal<O, P>(
    org_slug: O,
    project_slug: P,
    #[prop(into)] production_exists: Signal<bool>,
    on_success: Callback<EnvironmentResponse>,
) -> impl IntoView
where
    O: Fn() -> String + Send + Sync + 'static,
    P: Fn() -> String + Send + Sync + 'static,
{
    let is_open = RwSignal::new(false);
    let (name, set_name) = signal(String::new());
    let (slug, set_slug) = signal(String::new());
    let (tier, set_tier) = signal("non_production".to_string());
    let (error, set_error) = signal::<Option<AppError>>(None);

    Effect::new(move |_| {
        if production_exists.get() && tier.get_untracked() == "production" {
            set_tier.set("non_production".to_owned());
        }
    });

    let create_action = Action::new_local(
        move |(o, p, req): &(String, String, CreateEnvironmentRequest)| {
            let o = o.clone();
            let p = p.clone();
            let req = req.clone();
            async move { client::create_environment(&o, &p, &req).await }
        },
    );

    Effect::new(move |_| {
        if let Some(result) = create_action.value().get() {
            match result {
                Ok(env) => {
                    is_open.set(false);
                    set_name.set(String::new());
                    set_slug.set(String::new());
                    set_error.set(None);
                    on_success.run(env);
                }
                Err(err) => set_error.set(Some(err)),
            }
        }
    });

    let on_submit = StoredValue::new(move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        if create_action.pending().get_untracked() {
            return;
        }
        if production_exists.get_untracked() && tier.get_untracked() == "production" {
            set_error.set(Some(AppError::Config(
                "This project already has an active production environment.".to_owned(),
            )));
            return;
        }
        let name_val = name.get_untracked().trim().to_string();
        let slug_val = slug.get_untracked().trim().to_string();

        if name_val.is_empty() || slug_val.is_empty() {
            set_error.set(Some(AppError::Config(
                "Name and slug are required".to_string(),
            )));
            return;
        }

        create_action.dispatch((
            org_slug(),
            project_slug(),
            CreateEnvironmentRequest {
                name: name_val,
                slug: slug_val,
                tier: tier.get_untracked(),
            },
        ));
    });

    view! {
        <div>
            <Button on_click=move |_| { set_error.set(None); is_open.set(true); }>
                <div class="flex items-center gap-2">
                    <span class="material-symbols-outlined text-base" aria-hidden="true">"add"</span>
                    "New Environment"
                </div>
            </Button>

            <Dialog id="create-environment" title="Create Environment" open=is_open busy=create_action.pending()>
                        <form on:submit=move |ev| on_submit.with_value(|f| f(ev)) class="space-y-4" aria-describedby="environment-error">
                            <fieldset disabled=move || create_action.pending().get() class="space-y-4"><legend class="sr-only">"Environment configuration"</legend>
                            <div>
                                <label for="environment-name" class="block mb-2 text-sm font-medium text-gray-900 dark:text-white">"Environment Name"</label>
                                <input
                                    id="environment-name"
                                    type="text"
                                    required
                                    class="bg-gray-50 border border-gray-300 text-gray-900 text-sm rounded-lg focus:ring-blue-500 focus:border-blue-500 block w-full p-2.5 dark:bg-gray-700 dark:border-gray-600 dark:placeholder-gray-400 dark:text-white dark:focus:ring-blue-500 dark:focus:border-blue-500"
                                    placeholder="Development"
                                    on:input=move |ev| set_name.set(event_target_value(&ev))
                                    prop:value=move || name.get()
                                />
                            </div>

                            <div>
                                <label for="environment-slug" class="block mb-2 text-sm font-medium text-gray-900 dark:text-white">"Slug"</label>
                                <input
                                    id="environment-slug"
                                    type="text"
                                    required
                                    minlength="2"
                                    maxlength="32"
                                    class="bg-gray-50 border border-gray-300 text-gray-900 text-sm rounded-lg focus:ring-blue-500 focus:border-blue-500 block w-full p-2.5 dark:bg-gray-700 dark:border-gray-600 dark:placeholder-gray-400 dark:text-white dark:focus:ring-blue-500 dark:focus:border-blue-500 font-mono"
                                    placeholder="dev"
                                    on:input=move |ev| set_slug.set(event_target_value(&ev))
                                    prop:value=move || slug.get()
                                />
                            </div>

                            <div>
                                <label for="environment-tier" class="block mb-2 text-sm font-medium text-gray-900 dark:text-white">"Tier"</label>
                                <select
                                    id="environment-tier"
                                    aria-describedby="environment-tier-help"
                                    class="bg-gray-50 border border-gray-300 text-gray-900 text-sm rounded-lg focus:ring-blue-500 focus:border-blue-500 block w-full p-2.5 dark:bg-gray-700 dark:border-gray-600 dark:placeholder-gray-400 dark:text-white"
                                    on:change=move |ev| set_tier.set(event_target_value(&ev))
                                >
                                    <option value="production" disabled=move || production_exists.get() prop:selected=move || tier.get() == "production">"Production"</option>
                                    <option value="non_production" prop:selected=move || tier.get() == "non_production">"Non-Production"</option>
                                </select>
                                <p id="environment-tier-help" class="mt-2 text-xs text-gray-500 dark:text-gray-400">"Tier is a classification. Production: one active environment per project. Non-Production: development, testing, QA or staging."</p>
                                <Show when=move || production_exists.get()><p class="mt-1 text-xs text-gray-500 dark:text-gray-400">"This project already has an active production environment."</p></Show>
                            </div>
                            </fieldset>

                            <div id="environment-error" role="alert">{move || error.get().map(|error| view! { <Alert kind=AlertKind::Error message=error.to_string() /> })}</div>

                            <div class="pt-4 flex flex-col-reverse sm:flex-row gap-3 sm:justify-end">
                                <button
                                    type="button"
                                    disabled=move || create_action.pending().get()
                                    on:click=move |_| is_open.set(false)
                                    class="cursor-pointer px-5 py-2.5 text-sm font-medium text-gray-700 bg-white border border-gray-300 rounded-lg hover:bg-gray-50 focus:ring-4 focus:ring-gray-100 dark:bg-gray-800 dark:text-gray-300 dark:border-gray-600 dark:hover:bg-gray-700 dark:focus:ring-gray-700"
                                >
                                    "Cancel"
                                </button>
                                <Button button_type="submit" disabled=create_action.pending()>
                                    {move || if create_action.pending().get() { "Creating..." } else { "Create Environment" }}
                                </Button>
                            </div>
                        </form>
            </Dialog>
        </div>
    }
}
