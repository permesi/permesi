//! Organizations list route. Shows all tenants the user belongs to and allows
//! administrators to create new ones.

use crate::{
    app_lib::AppError,
    components::{Alert, AlertKind, AppShell, Button, Spinner},
    features::{
        auth::RequireAuth,
        orgs::{
            client,
            types::{CreateOrgRequest, OrgResponse},
        },
    },
};
use leptos::prelude::*;
use leptos_router::components::A;

/// Renders the organizations list view.
#[component]
pub fn OrgsListPage() -> impl IntoView {
    let orgs = LocalResource::new(move || async move { client::list_orgs().await });

    view! {
        <AppShell>
            <RequireAuth children=move || view! {
            <div class="space-y-6">
                <div class="flex items-center justify-between">
                    <div class="space-y-1">
                        <h1 class="text-2xl font-semibold text-gray-900 dark:text-white">
                            "Organizations"
                        </h1>
                        <p class="text-sm text-gray-500 dark:text-gray-400">
                            "Manage your tenants, projects, and environments."
                        </p>
                    </div>
                    <CreateOrgModal on_success=Callback::new(move |_| orgs.refetch()) />
                </div>

                <Suspense fallback=move || view! { <Spinner /> }>
                    {move || match orgs.get() {
                        Some(Ok(list)) if list.is_empty() => {
                            view! {
                                <div class="text-center py-12 bg-white dark:bg-gray-800 rounded-lg border border-dashed border-gray-300 dark:border-gray-700">
                                    <span class="material-symbols-outlined text-4xl text-gray-400">"corporate_fare"</span>
                                    <h3 class="mt-2 text-sm font-medium text-gray-900 dark:text-white">"No organizations"</h3>
                                    <p class="mt-1 text-sm text-gray-500 dark:text-gray-400">"Get started by creating a new organization."</p>
                                </div>
                            }.into_any()
                        }
                        Some(Ok(list)) => {
                            view! {
                                <div class="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
                                    <For
                                        each=move || list.clone()
                                        key=|org| org.id.clone()
                                        children=|org| {
                                            view! {
                                                <A
                                                    href=format!("/orgs/{}", org.slug)
                                                    {..}
                                                    class="block p-6 bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 hover:border-blue-500 dark:hover:border-blue-500 transition-colors shadow-sm"
                                                >
                                                    <div class="flex items-start justify-between">
                                                        <span class="material-symbols-outlined text-blue-600 dark:text-blue-400">
                                                            "corporate_fare"
                                                        </span>
                                                        <span class="text-xs text-gray-400 dark:text-gray-500 uppercase font-mono tracking-wider">
                                                            {org.slug}
                                                        </span>
                                                    </div>
                                                    <h2 class="mt-4 text-lg font-medium text-gray-900 dark:text-white truncate">
                                                        {org.name}
                                                    </h2>
                                                    <p class="mt-1 text-xs text-gray-500 dark:text-gray-400">
                                                        "Created " {org.created_at}
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
            } />
        </AppShell>
    }
}

#[component]
fn CreateOrgModal(on_success: Callback<OrgResponse>) -> impl IntoView {
    let (is_open, set_is_open) = signal(false);
    let (name, set_name) = signal(String::new());
    let (slug, set_slug) = signal(String::new());
    let (error, set_error) = signal::<Option<AppError>>(None);

    let create_action = Action::new_local(move |req: &CreateOrgRequest| {
        let req = req.clone();
        async move { client::create_org(&req).await }
    });

    Effect::new(move |_| {
        if let Some(result) = create_action.value().get() {
            match result {
                Ok(org) => {
                    set_is_open.set(false);
                    set_name.set(String::new());
                    set_slug.set(String::new());
                    set_error.set(None);
                    on_success.run(org);
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

        create_action.dispatch(CreateOrgRequest {
            name: name_val,
            slug: if slug_val.is_empty() {
                None
            } else {
                Some(slug_val)
            },
        });
    });

    view! {
        <div>
            <Button on_click=move |_| set_is_open.set(true)>
                <div class="flex items-center gap-2">
                    <span class="material-symbols-outlined text-base">"add"</span>
                    "New Organization"
                </div>
            </Button>

            <Show when=move || is_open.get()>
                <div class="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/50 backdrop-blur-sm">
                    <div class="bg-white dark:bg-gray-800 rounded-xl shadow-xl border border-gray-200 dark:border-gray-700 w-full max-w-md overflow-hidden animate-in fade-in zoom-in duration-200">
                        <div class="px-6 py-4 border-b border-gray-100 dark:border-gray-700 flex items-center justify-between">
                            <h2 class="text-lg font-semibold text-gray-900 dark:text-white">"Create Organization"</h2>
                            <button
                                on:click=move |_| set_is_open.set(false)
                                class="text-gray-400 hover:text-gray-600 dark:hover:text-gray-200"
                            >
                                <span class="material-symbols-outlined">"close"</span>
                            </button>
                        </div>

                        <form on:submit=move |ev| on_submit.with_value(|f| f(ev)) class="p-6 space-y-4">
                            <div>
                                <label class="block mb-2 text-sm font-medium text-gray-900 dark:text-white">"Organization Name"</label>
                                <input
                                    type="text"
                                    required
                                    class="bg-gray-50 border border-gray-300 text-gray-900 text-sm rounded-lg focus:ring-blue-500 focus:border-blue-500 block w-full p-2.5 dark:bg-gray-700 dark:border-gray-600 dark:placeholder-gray-400 dark:text-white dark:focus:ring-blue-500 dark:focus:border-blue-500"
                                    placeholder="Acme Corp"
                                    on:input=move |ev| set_name.set(event_target_value(&ev))
                                    value=move || name.get()
                                />
                            </div>

                            <div>
                                <label class="block mb-2 text-sm font-medium text-gray-900 dark:text-white">"Slug (optional)"</label>
                                <input
                                    type="text"
                                    class="bg-gray-50 border border-gray-300 text-gray-900 text-sm rounded-lg focus:ring-blue-500 focus:border-blue-500 block w-full p-2.5 dark:bg-gray-700 dark:border-gray-600 dark:placeholder-gray-400 dark:text-white dark:focus:ring-blue-500 dark:focus:border-blue-500 font-mono"
                                    placeholder="acme-corp"
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
                                    {move || if create_action.pending().get() { "Creating..." } else { "Create Organization" }}
                                </Button>
                            </div>
                        </form>
                    </div>
                </div>
            </Show>
        </div>
    }
}
