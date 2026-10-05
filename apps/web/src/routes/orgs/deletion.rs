//! Explicit bottom-up deletion UI using the existing dialog and feature clients.
//!
//! Flow Overview: show immediate-child blockers, require the exact displayed name
//! or slug, submit a single scoped DELETE, then navigate to the parent. Browser
//! checks are usability hints only; current membership, emptiness and concurrency
//! are enforced transactionally by PostgreSQL-backed handlers.

use leptos::prelude::*;
use leptos_router::hooks::use_navigate;

use crate::{
    app_lib::AppError,
    components::ui::Dialog,
    features::{
        oauth::paths::{ApplicationPaths, EnvironmentPaths},
        orgs::client,
    },
    routes::{
        oauth::common::{DESTRUCTIVE, FormError, INPUT, LABEL, SECONDARY, error_message},
        paths,
    },
};

/// Full route ancestry for one deletion; no target contains recursive options.
#[derive(Clone)]
pub(super) enum DeleteTarget {
    Organization(String),
    Project(String, String),
    Environment(EnvironmentPaths),
    Application(ApplicationPaths),
}

impl DeleteTarget {
    /// Gives each modal an understandable visible action and stable accessible title.
    fn title(&self) -> &'static str {
        match self {
            Self::Organization(_) => "Delete Organization",
            Self::Project(..) => "Delete Project",
            Self::Environment(_) => "Delete Environment",
            Self::Application(_) => "Delete Application",
        }
    }

    /// Explains the server lifecycle without suggesting implicit child destruction.
    fn description(&self) -> &'static str {
        match self {
            Self::Organization(_) => {
                "Only an organization owner can delete this empty organization. Recent authentication is required; sign in again if requested. Projects must be explicitly deleted first."
            }
            Self::Project(..) => {
                "Delete all environments before deleting this project. Organization owners and admins can delete an empty project."
            }
            Self::Environment(_) => {
                "Delete all applications before deleting this environment. Organization owners and admins can delete an empty environment."
            }
            Self::Application(_) => {
                "Delete this application's OAuth clients first. Client deletion revokes credentials and saved consent. Deleting the application then removes access to its retained OAuth configuration."
            }
        }
    }

    /// Returns the immediate surviving parent; route mounting refreshes its collection.
    fn parent(&self) -> String {
        match self {
            Self::Organization(_) => paths::ORGS.to_owned(),
            Self::Project(org, _) => paths::org_detail(org),
            Self::Environment(path) => path.project_console(),
            Self::Application(path) => path.environment.console(),
        }
    }

    /// Uses session-authenticated feature clients; backend authority is never inferred here.
    async fn delete(&self) -> Result<(), AppError> {
        match self {
            Self::Organization(org) => client::delete_organization(org).await,
            Self::Project(org, project) => client::delete_project(org, project).await,
            Self::Environment(path) => client::delete_environment(path).await,
            Self::Application(path) => client::delete_application(path).await,
        }
    }
}

/// Requires exact typed confirmation and a loaded empty child list before submitting.
/// A stale list never bypasses the backend's transactionally enforced 409 conflict.
/// Conflicts refresh children without clearing the draft; recent-authentication errors
/// retain the backend's public guidance instead of implying that a valid session expired.
#[component]
pub(super) fn DeleteResource(
    target: DeleteTarget,
    confirmation_name: String,
    #[prop(into)] blocked: Signal<Option<String>>,
    refresh: Callback<()>,
) -> impl IntoView {
    let title = target.title();
    let description = target.description();
    let target = StoredValue::new(target);
    let expected = StoredValue::new(confirmation_name);
    let open = RwSignal::new(false);
    let typed = RwSignal::new(String::new());
    let error = RwSignal::new(String::new());
    let delete = Action::new_local(move |(): &()| {
        let target = target.get_value();
        async move { target.delete().await }
    });
    let navigate = use_navigate();
    Effect::new(move |_| {
        if let Some(result) = delete.value().get() {
            match result {
                Ok(()) => {
                    open.set(false);
                    navigate(&target.get_value().parent(), Default::default());
                }
                Err(err) => {
                    if matches!(err, AppError::Http { status: 409, .. }) {
                        refresh.run(());
                    }
                    let message = match &err {
                        AppError::Http {
                            status: 401,
                            code: Some(code),
                            message,
                        } if code == "reauthentication_required" => message.clone(),
                        _ => error_message(&err),
                    };
                    error.set(message);
                }
            }
        }
    });
    view! { <section aria-labelledby="resource-danger-title" class="space-y-3 rounded-lg border border-red-200 bg-white p-6 dark:border-red-900 dark:bg-gray-800">
        <h2 id="resource-danger-title" class="text-lg font-semibold text-gray-900 dark:text-white">"Danger Zone"</h2>
        <p class="text-sm text-gray-600 dark:text-gray-300">{description}</p>
        <p id="resource-delete-blocker" class="text-sm text-gray-600 dark:text-gray-300" aria-live="polite">{move || blocked.get().unwrap_or_default()}</p>
        <button type="button" class=DESTRUCTIVE aria-describedby="resource-delete-blocker" disabled=move || blocked.get().is_some() || delete.pending().get()
            on:click=move |_| { typed.set(String::new()); error.set(String::new()); open.set(true); }>
            <span class="material-symbols-outlined" aria-hidden="true">"delete"</span>{title}
        </button>
        <Dialog id="delete-resource" title=title icon="delete" open=open busy=delete.pending()>
            <form class="space-y-4" on:submit=move |ev| {
                ev.prevent_default();
                if !delete.pending().get_untracked() && blocked.get_untracked().is_none() && !expected.get_value().is_empty() && typed.get_untracked() == expected.get_value() {
                    error.set(String::new()); delete.dispatch(());
                }
            }>
                <p class="text-sm">{description}</p>
                <label for="resource-delete-confirmation" class=LABEL>"Type "<code class="break-all">{expected.get_value()}</code>" to confirm deletion"</label>
                <input id="resource-delete-confirmation" class=INPUT autofocus autocomplete="off" spellcheck="false" aria-describedby="resource-delete-error" prop:value=move || typed.get()
                    disabled=move || delete.pending().get() on:input=move |ev| typed.set(event_target_value(&ev)) />
                <FormError id="resource-delete-error" error=error />
                <div class="flex flex-wrap justify-end gap-3">
                    <button type="button" class=SECONDARY disabled=move || delete.pending().get() on:click=move |_| open.set(false)>"Cancel"</button>
                    <button type="submit" class=DESTRUCTIVE disabled=move || delete.pending().get() || blocked.get().is_some() || expected.get_value().is_empty() || typed.get() != expected.get_value()>
                        {move || if delete.pending().get() { "Deleting…" } else { title }}
                    </button>
                </div>
            </form>
        </Dialog>
    </section>
    }
}
