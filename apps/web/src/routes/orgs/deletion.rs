//! Explicit bottom-up deletion UI using the existing dialog and feature clients.
//!
//! Flow Overview: load current server capabilities, show immediate-child blockers,
//! pin the account and organization, and require exact typed confirmation. A stale
//! organization session opens password reauthentication, then refreshes authority
//! and children and returns to confirmation without automatically deleting. Browser
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

#[path = "deletion_state.rs"]
mod state;
use state::DeletionState;

/// Full route ancestry for one deletion; no target contains recursive options.
#[derive(Clone)]
pub(super) enum DeleteTarget {
    Organization(String),
    Project(String, String),
    Environment(EnvironmentPaths),
    Application(ApplicationPaths),
}

impl DeleteTarget {
    /// Resolves the organization whose server-issued capability hints govern presentation.
    fn org_slug(&self) -> &str {
        match self {
            Self::Organization(org) | Self::Project(org, _) => org,
            Self::Environment(path) => &path.org,
            Self::Application(path) => &path.environment.org,
        }
    }

    /// Selects owner-only presentation for tenant deletion, without granting authority.
    fn organization(&self) -> bool {
        matches!(self, Self::Organization(_))
    }
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
                "Only an organization owner can delete this empty organization. Verify your password here if recent authentication is required. Projects must be explicitly deleted first."
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
    async fn delete(&self, expected_id: &str) -> Result<(), AppError> {
        match self {
            Self::Organization(org) => client::delete_organization(org, expected_id).await,
            Self::Project(org, project) => client::delete_project(org, project).await,
            Self::Environment(path) => client::delete_environment(path).await,
            Self::Application(path) => client::delete_application(path).await,
        }
    }
}

/// Requires exact typed confirmation and a loaded empty child list before submitting.
/// A stale list never bypasses the backend's transactionally enforced 409 conflict.
/// Conflicts refresh children without clearing the draft; recent-authentication errors
/// open password verification and return to an explicit confirmation on success.
/// Identity, tenant and role changes invalidate the draft rather than preserving stale hints.
/// Auto-repeated Enter is ignored so holding the password-submit key cannot confirm deletion.
#[component]
pub(super) fn DeleteResource(
    target: DeleteTarget,
    confirmation_name: String,
    #[prop(into)] blocked: Signal<Option<String>>,
    refresh: Callback<()>,
) -> impl IntoView {
    let title = target.title();
    let description = target.description();
    let state = DeletionState::new(target.clone(), refresh);
    let auth = crate::features::auth::state::use_auth();
    let target = StoredValue::new(target);
    let expected = StoredValue::new(confirmation_name);
    let blocker = Signal::derive(move || state.children.get().or_else(|| blocked.get()));
    let delete = Action::new_local(move |(): &()| {
        let target = target.get_value();
        let id = state.confirmed_id();
        async move {
            let id =
                id.ok_or_else(|| AppError::Config("Open a new deletion confirmation.".to_owned()))?;
            target.delete(&id).await
        }
    });
    let busy = Signal::derive(move || state.busy.get() || delete.pending().get());
    let confirmation = NodeRef::<leptos::html::Input>::new();
    let password = NodeRef::<leptos::html::Input>::new();
    Effect::new(move |_| {
        if state.open.get() && !busy.get() {
            if state.reauth.get() {
                if let Some(node) = password.get() {
                    let _ = node.focus();
                }
            } else if let Some(node) = confirmation.get() {
                let _ = node.focus();
            }
        }
    });
    let navigate = use_navigate();
    Effect::new(move |_| {
        if let Some(result) = delete.value().get() {
            match result {
                Ok(()) => {
                    state.open.set(false);
                    navigate(&target.get_value().parent(), Default::default());
                }
                Err(err) => {
                    let reauth = matches!(&err, AppError::Http { status: 401, code: Some(code), .. } if code == "reauthentication_required");
                    if reauth && target.get_value().organization() {
                        state.reauth.set(true);
                        state.error.set("Verify your password to continue. You will confirm deletion again afterwards.".to_owned());
                    } else {
                        state.error.set(error_message(&err));
                        if matches!(
                            err,
                            AppError::Http {
                                status: 401 | 404 | 409,
                                ..
                            }
                        ) {
                            state.refresh();
                        }
                    }
                }
            }
        }
    });
    view! {
        <Show when=move || state.eligible()>
            <section aria-labelledby="resource-danger-title" class="space-y-3 rounded-lg border border-red-200 bg-white p-6 dark:border-red-900 dark:bg-gray-800">
                <h2 id="resource-danger-title" class="text-lg font-semibold text-gray-900 dark:text-white">"Danger Zone"</h2>
                <p class="text-sm text-gray-600 dark:text-gray-300">{description}</p>
                <p id="resource-delete-blocker" class="text-sm text-gray-600 dark:text-gray-300" aria-live="polite">{move || blocker.get().unwrap_or_default()}</p>
                <button type="button" class=DESTRUCTIVE aria-describedby="resource-delete-blocker" disabled=move || blocker.get().is_some() || busy.get()
                    on:click=move |_| { state.error.set(String::new()); state.begin(); }>
                    <span class="material-symbols-outlined" aria-hidden="true">"delete"</span>{title}
                </button>
            </section>
        </Show>
        <Show when=move || !state.open.get() && !state.error.get().is_empty()>
            <p role="alert" class="text-sm text-red-700 dark:text-red-300">{move || state.error.get()}</p>
        </Show>
        <Dialog id="delete-resource" title=title icon="delete" open=state.open busy=busy>
            <form class="space-y-4" on:keydown=move |ev: leptos::ev::KeyboardEvent| {
                if ev.key() == "Enter" && ev.repeat() { ev.prevent_default(); }
            } on:submit=move |ev| {
                ev.prevent_default();
                if busy.get_untracked() { return; }
                if state.reauth.get_untracked() { state.verify(); }
                else if blocker.get_untracked().is_none() && !expected.get_value().is_empty()
                    && state.typed.get_untracked() == expected.get_value() && state.confirmed_id().is_some() {
                    state.error.set(String::new()); delete.dispatch(());
                }
            }>
                <Show when=move || state.reauth.get() fallback=move || view! {
                    <p class="text-sm">{description}</p>
                    <p class="text-sm" aria-live="polite">{move || blocker.get().unwrap_or_default()}</p>
                    <label for="resource-delete-confirmation" class=LABEL>"Type "<code class="break-all">{expected.get_value()}</code>" to confirm deletion"</label>
                    <input node_ref=confirmation id="resource-delete-confirmation" class=INPUT autofocus autocomplete="off" spellcheck="false" aria-describedby="resource-delete-error" prop:value=move || state.typed.get()
                        disabled=move || busy.get() on:input=move |ev| state.typed.set(event_target_value(&ev)) />
                }>
                    <p class="text-sm">"Verify your password for "<strong>{move || auth.session.get().map(|s| s.email).unwrap_or_default()}</strong>". Deletion still requires your confirmation afterwards."</p>
                    <label for="resource-delete-password" class=LABEL>"Password"</label>
                    <input node_ref=password id="resource-delete-password" type="password" class=INPUT autocomplete="current-password" aria-describedby="resource-delete-error" prop:value=move || state.password.get()
                        disabled=move || busy.get() on:input=move |ev| state.password.set(event_target_value(&ev)) />
                </Show>
                <FormError id="resource-delete-error" error=state.error />
                <div class="flex flex-wrap justify-end gap-3">
                    <button type="button" class=SECONDARY disabled=move || busy.get() on:click=move |_| state.open.set(false)>"Cancel"</button>
                    <button type="submit" class=move || if state.reauth.get() { SECONDARY } else { DESTRUCTIVE }
                        disabled=move || busy.get() || if state.reauth.get() { state.password.get().is_empty() } else { blocker.get().is_some() || expected.get_value().is_empty() || state.typed.get() != expected.get_value() || !state.eligible() }>
                        {move || if state.reauth.get() { if busy.get() { "Verifying…" } else { "Verify password" } } else if busy.get() { "Please wait…" } else { title }}
                    </button>
                </div>
            </form>
        </Dialog>
    }
}
