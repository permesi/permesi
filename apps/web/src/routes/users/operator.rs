//! Minimal operator designation controls; all authority lives in the API.
//!
//! Flow Overview: load server-issued designation hints, require exact account
//! confirmation and the actor's OPAQUE password, then submit one fixed operation.
//! Another operator approves restoration; the browser never selects an approver.

use leptos::prelude::*;

use crate::{
    app_lib::AppError,
    components::{Alert, AlertKind, Spinner, ui::Dialog},
    features::{
        auth::{opaque::reauthenticate, state::use_auth},
        users::{client, types::OperatorStatus},
    },
};

#[derive(Clone, Copy)]
enum Operation {
    Request,
    Approve,
    Disable,
}

impl Operation {
    /// Maps one visible action to its fixed API route.
    const fn api(self) -> &'static str {
        match self {
            Self::Request => "request-enable",
            Self::Approve => "enable",
            Self::Disable => "disable",
        }
    }

    /// Names the operation for an explicit confirmation.
    const fn label(self) -> &'static str {
        match self {
            Self::Request => "Request operator designation",
            Self::Approve => "Approve operator designation",
            Self::Disable => "Disable operator designation",
        }
    }
}

#[derive(Clone, Copy)]
enum OperatorReason {
    Administrative,
    IncidentRecovery,
    SuspectedCompromise,
}

impl OperatorReason {
    /// Sends only one of the API's fixed audit classifications.
    const fn as_str(self) -> &'static str {
        match self {
            Self::Administrative => "administrative",
            Self::IncidentRecovery => "incident_recovery",
            Self::SuspectedCompromise => "suspected_compromise",
        }
    }

    /// Rejects unrecognized browser values rather than storing free-form audit text.
    fn from_value(value: &str) -> Option<Self> {
        match value {
            "administrative" => Some(Self::Administrative),
            "incident_recovery" => Some(Self::IncidentRecovery),
            "suspected_compromise" => Some(Self::SuspectedCompromise),
            _ => None,
        }
    }
}

/// Shows only actions suggested by current server state; the API rechecks every condition.
#[component]
pub(super) fn OperatorManager(user_id: String, email: String) -> impl IntoView {
    let id_for_fetch = user_id.clone();
    let status = LocalResource::new(move || {
        let id = id_for_fetch.clone();
        async move { client::get_operator(&id).await }
    });
    let auth = use_auth();
    let open = RwSignal::new(false);
    let selected = RwSignal::new(Operation::Request);
    let reason = RwSignal::new(OperatorReason::Administrative);
    let typed = RwSignal::new(String::new());
    let password = RwSignal::new(String::new());
    let error = RwSignal::new(String::new());
    let id_for_action = user_id;
    let action = Action::new_local(
        move |(operation, actor_email, password, reason): &(
            Operation,
            String,
            String,
            OperatorReason,
        )| {
            let operation = *operation;
            let actor_email = actor_email.clone();
            let password = password.clone();
            let reason = *reason;
            let id = id_for_action.clone();
            async move {
                reauthenticate(&actor_email, password).await?;
                client::operator_action(&id, operation.api(), reason.as_str()).await
            }
        },
    );
    Effect::new(move |_| {
        if let Some(result) = action.value().get() {
            match result {
                Ok(()) => {
                    password.set(String::new());
                    typed.set(String::new());
                    error.set(String::new());
                    open.set(false);
                    status.refetch();
                }
                Err(err) => error.set(match err {
                    AppError::Http { status: 409, .. } =>
                        "This designation changed or requires a different operator. Refresh and try again.".to_owned(),
                    _ => err.to_string(),
                }),
            }
        }
    });
    let busy = Signal::derive(move || action.pending().get());
    let email_for_confirm = email.clone();
    view! {
        <section class="rounded-lg border border-gray-200 bg-white shadow-sm dark:border-gray-700 dark:bg-gray-800">
            <div class="border-b border-gray-100 px-6 py-4 dark:border-gray-700">
                <h2 class="text-sm font-semibold uppercase tracking-wider text-gray-900 dark:text-white">"Platform Operator"</h2>
            </div>
            <div class="space-y-3 p-6">
                <p class="text-sm text-gray-600 dark:text-gray-300">"This designation is separate from platform roles, organization membership and OAuth scopes."</p>
                {status_controls(status, selected, typed, password, error, open)}
            </div>
        </section>
        <Dialog id="operator-designation" title="Manage Operator Designation" icon="verified_user" open=open busy=busy>
            <form class="space-y-4" on:submit=move |ev| {
                ev.prevent_default();
                let actor_email = auth.session.get_untracked().map(|session| session.email).unwrap_or_default();
                if !busy.get_untracked() && typed.get_untracked() == email_for_confirm
                    && !password.get_untracked().is_empty() && !actor_email.is_empty() {
                    error.set(String::new());
                    action.dispatch((selected.get_untracked(), actor_email, password.get_untracked(), reason.get_untracked()));
                }
            }>
                <p class="text-sm text-gray-700 dark:text-gray-200">{move || selected.get().label()}</p>
                <p class="text-sm text-gray-600 dark:text-gray-300">"Confirm the target account and verify your own password. Approval and current authority are checked again by the server."</p>
                <ReasonSelect reason />
                <label for="operator-target-confirm" class="block text-sm font-medium">"Type "<code>{email.clone()}</code>" to confirm"</label>
                <input id="operator-target-confirm" class="w-full rounded border border-gray-300 bg-white px-3 py-2 text-gray-900 dark:border-gray-600 dark:bg-gray-900 dark:text-white"
                    autocomplete="off" spellcheck="false" prop:value=move || typed.get()
                    on:input=move |ev| typed.set(event_target_value(&ev)) />
                <label for="operator-actor-password" class="block text-sm font-medium">"Your password"</label>
                <input id="operator-actor-password" type="password" autocomplete="current-password"
                    class="w-full rounded border border-gray-300 bg-white px-3 py-2 text-gray-900 dark:border-gray-600 dark:bg-gray-900 dark:text-white"
                    prop:value=move || password.get() on:input=move |ev| password.set(event_target_value(&ev)) />
                <p role="alert" class="text-sm text-red-700 dark:text-red-300">{move || error.get()}</p>
                <div class="flex justify-end gap-3">
                    <button type="button" class="cursor-pointer rounded px-3 py-2 text-sm hover:bg-gray-100 dark:hover:bg-gray-700" disabled=move || busy.get() on:click=move |_| open.set(false)>"Cancel"</button>
                    <button type="submit" class="cursor-pointer rounded bg-blue-700 px-3 py-2 text-sm font-medium text-white hover:bg-blue-800 disabled:opacity-50"
                        disabled=move || busy.get() || typed.get() != email || password.get().is_empty()>
                        {move || if busy.get() { "Please wait…" } else { selected.get().label() }}
                    </button>
                </div>
            </form>
        </Dialog>
    }
}

/// Offers only the API's fixed reason codes with explicit readable labels.
#[component]
fn ReasonSelect(reason: RwSignal<OperatorReason>) -> impl IntoView {
    view! {
        <label for="operator-reason" class="block text-sm font-medium">"Reason"</label>
        <select id="operator-reason" class="w-full rounded border border-gray-300 bg-white px-3 py-2 text-gray-900 dark:border-gray-600 dark:bg-gray-900 dark:text-white"
            prop:value=move || reason.get().as_str()
            on:change=move |ev| {
                if let Some(value) = OperatorReason::from_value(&event_target_value(&ev)) {
                    reason.set(value);
                }
            }>
            <option value="administrative">"Administrative"</option>
            <option value="incident_recovery">"Incident recovery"</option>
            <option value="suspected_compromise">"Suspected compromise"</option>
        </select>
    }
}

/// Renders current server hints without treating them as an authorization decision.
fn status_controls(
    status: LocalResource<Result<OperatorStatus, AppError>>,
    selected: RwSignal<Operation>,
    typed: RwSignal<String>,
    password: RwSignal<String>,
    error: RwSignal<String>,
    open: RwSignal<bool>,
) -> impl IntoView {
    move || match status.get() {
        Some(Ok(current)) => {
            let designation = current.designation.clone();
            view! {
                <p class="text-sm text-gray-900 dark:text-gray-100">"Designation: "<strong>{designation}</strong></p>
                <div class="flex flex-wrap gap-3">
                    {if current.designation == "enabled" {
                        view! { <button type="button" class="cursor-pointer rounded border border-red-600 px-3 py-2 text-sm font-medium text-red-700 hover:bg-red-50 focus:ring-2 focus:ring-red-500 dark:text-red-300 dark:hover:bg-red-950"
                            on:click=move |_| begin(Operation::Disable, selected, typed, password, error, open)>
                            <span class="material-symbols-outlined mr-1 align-middle" aria-hidden="true">"person_off"</span>"Disable operator"
                        </button> }.into_any()
                    } else if current.pending_enable {
                        view! { <p class="text-sm text-gray-600 dark:text-gray-300">"A designation request is pending."</p> }.into_any()
                    } else {
                        view! { <button type="button" class="cursor-pointer rounded border border-gray-300 px-3 py-2 text-sm font-medium text-gray-800 hover:bg-gray-50 focus:ring-2 focus:ring-blue-500 dark:border-gray-600 dark:text-gray-100 dark:hover:bg-gray-700"
                            on:click=move |_| begin(Operation::Request, selected, typed, password, error, open)>
                            "Request designation"
                        </button> }.into_any()
                    }}
                    {if current.pending_enable && current.can_approve {
                        view! { <button type="button" class="cursor-pointer rounded border border-blue-600 px-3 py-2 text-sm font-medium text-blue-700 hover:bg-blue-50 focus:ring-2 focus:ring-blue-500 dark:text-blue-300 dark:hover:bg-blue-950"
                            on:click=move |_| begin(Operation::Approve, selected, typed, password, error, open)>
                            "Approve request"
                        </button> }.into_any()
                    } else { view! { <span></span> }.into_any() }}
                </div>
                {current.requested_by_email.map(|requester| view! {
                    <div class="text-sm text-gray-600 dark:text-gray-300">
                        <p>"Requested by "<strong>{requester}</strong></p>
                        {current.requested_reason.clone().map(|reason| view! {
                            <p>"Reason: "{reason.replace('_', " ")}</p>
                        })}
                        {current.requested_at.clone().map(|at| view! {
                            <p>"Requested at "{at}" UTC (expires after ten minutes)"</p>
                        })}
                    </div>
                })}
                {if current.pending_enable && current.requested_by_me && !current.can_approve {
                    view! { <p class="text-sm text-gray-600 dark:text-gray-300">"Another enabled operator must approve this request."</p> }.into_any()
                } else { view! { <span></span> }.into_any() }}
            }.into_any()
        }
        Some(Err(err)) => {
            view! { <Alert kind=AlertKind::Error message=err.to_string() /> }.into_any()
        }
        None => view! { <Spinner /> }.into_any(),
    }
}

/// Clears all confirmation state whenever a distinct operation is opened.
fn begin(
    operation: Operation,
    selected: RwSignal<Operation>,
    typed: RwSignal<String>,
    password: RwSignal<String>,
    error: RwSignal<String>,
    open: RwSignal<bool>,
) {
    selected.set(operation);
    typed.set(String::new());
    password.set(String::new());
    error.set(String::new());
    open.set(true);
}
