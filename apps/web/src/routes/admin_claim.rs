//! Admin claim page for platform operator bootstrap and elevation.
//!
//! Flow Overview: Fetch admin status, render the appropriate form, then submit
//! the Vault token to bootstrap or elevate. The admin token is stored in memory
//! and must be re-issued after expiration.

use crate::{
    app_lib::AppError,
    components::{Alert, AlertKind, Button, Spinner},
    features::auth::{
        client::{self, is_token_expired},
        state::use_auth,
        types::{
            AdminBootstrapRequest, AdminElevateRequest, AdminElevateResponse, AdminStatusResponse,
        },
    },
    routes::paths,
};
use leptos::{ev::SubmitEvent, prelude::*};
use leptos_router::{components::A, hooks::use_navigate};

#[derive(Clone)]
struct ClaimInput {
    status: AdminStatusResponse,
    token: String,
    note: Option<String>,
}

#[derive(Clone)]
enum ClaimOutcome {
    Elevated(AdminElevateResponse),
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum PageState {
    Form,
    Success,
}

#[component]
pub fn AdminClaimPage() -> impl IntoView {
    let auth = use_auth();
    let navigate = use_navigate();
    let (vault_token, set_vault_token) = signal(String::new());
    let (note, set_note) = signal(String::new());
    let (error, set_error) = signal::<Option<AppError>>(None);
    let (success, set_success) = signal::<Option<String>>(None);
    let (page_state, set_page_state) = signal(PageState::Form);

    let status_key = Signal::derive(move || auth.session.get().map(|session| session.user_id));

    let status_resource = LocalResource::new(move || {
        let user_id = status_key.get();
        async move {
            if user_id.is_none() {
                // Should not happen if AuthLayout works, but safe fallback
                return Err(AppError::Config("Sign in required.".to_string()));
            }
            client::admin_status().await
        }
    });

    let status_signal = Signal::derive(move || {
        status_resource
            .get()
            .and_then(|result| result.ok())
            .map(|status| status.clone())
    });

    Effect::new(move |_| {
        if let Some(status) = status_signal.get() {
            // Security Fix: If the backend says bootstrap is open (meaning no operators exist),
            // any client-side admin token is semantically invalid. Clear it to prevent
            // "persistent admin token" issues when the DB is wiped.
            if status.bootstrap_open {
                if auth.admin_token.get_untracked().is_some() {
                    auth.clear_admin_token();
                }
            }
        }
    });

    let claim_action = Action::new_local(move |input: &ClaimInput| {
        let input = input.clone();
        async move {
            // 1. If bootstrap is needed, do it first.
            if input.status.bootstrap_open && !input.status.operator {
                let request = AdminBootstrapRequest {
                    vault_token: input.token.clone(),
                    note: input.note.clone(),
                };
                let response = client::admin_bootstrap(&request).await?;
                if !response.ok {
                    return Err(AppError::Config("Bootstrap failed.".to_string()));
                }
            }

            // 2. Always elevate immediately using the same token.
            // This ensures the user gets the admin token in one go, avoiding "enter token again" UX.
            let request = AdminElevateRequest {
                vault_token: input.token.clone(),
            };
            let response = client::admin_elevate(&request).await?;
            Ok(ClaimOutcome::Elevated(response))
        }
    });

    let auth_for_claim = auth.clone();
    Effect::new(move |_| {
        if claim_action.pending().get() {
            set_success.set(None); // Clear previous success messages when a new elevation starts
        }
        if let Some(result) = claim_action.value().get() {
            match result {
                Ok(outcome) => {
                    set_error.set(None);
                    set_vault_token.set(String::new());
                    set_note.set(String::new());
                    match outcome {
                        ClaimOutcome::Elevated(token) => {
                            auth_for_claim.set_admin_token(token);
                            // We set success state, but simpler logic below relies on has_active_token
                            set_page_state.set(PageState::Success);
                            set_success.set(Some(
                                "Claimed successfully. You are now a platform operator."
                                    .to_string(),
                            ));
                        }
                    }
                    status_resource.refetch();
                    auth_for_claim.refresh_session();
                }
                Err(err) => {
                    set_error.set(Some(err));
                    set_success.set(None);
                }
            }
        }
    });

    let on_claim_submit = move |event: SubmitEvent| {
        event.prevent_default();
        set_error.set(None);
        set_success.set(None);
        let token = vault_token.get_untracked();
        if token.trim().is_empty() {
            set_error.set(Some(AppError::Config(
                "Vault token is required.".to_string(),
            )));
            return;
        }
        let Some(status) = status_signal.get_untracked() else {
            set_error.set(Some(AppError::Config(
                "Unable to load admin status.".to_string(),
            )));
            return;
        };
        let note_value = note.get_untracked().trim().to_string();
        claim_action.dispatch(ClaimInput {
            status,
            token: token.trim().to_string(),
            note: if note_value.is_empty() {
                None
            } else {
                Some(note_value)
            },
        });
    };

    view! {
        <div class="max-w-xl mx-auto space-y-6">
            <div class="space-y-2">
                <h1 class="text-2xl font-semibold text-gray-900 dark:text-white">
                    "Admin Claim"
                </h1>
                <p class="text-sm text-gray-600 dark:text-gray-300">
                    "Use a short-lived Vault token to bootstrap or elevate platform admin privileges."
                </p>
            </div>

            {move || {
                if page_state.get() == PageState::Success {
                     view! {
                         <div class="space-y-4">
                             {move || success.get().map(|msg| view! { <Alert kind=AlertKind::Success message=msg /> })}
                             <div class="mt-4">
                                <button
                                    type="button"
                                    on:click={
                                        let navigate = navigate.clone();
                                        move |_| navigate(paths::ADMIN, Default::default())
                                    }
                                    class="inline-flex items-center px-5 py-2.5 text-sm font-medium text-white bg-green-600 rounded-lg hover:bg-green-700 focus:ring-4 focus:outline-none focus:ring-green-300 dark:bg-green-500 dark:hover:bg-green-600 dark:focus:ring-green-800 transition-all cursor-pointer"
                                >
                                    <span class="material-symbols-outlined mr-2 text-base">
                                        "settings"
                                    </span>
                                    "Go Admin"
                                </button>
                             </div>
                         </div>
                     }.into_any()
                } else {
                    status_resource
                        .get()
                        .map(|result: Result<AdminStatusResponse, _>| match result {
                            Ok(status) => render_admin_forms(
                                status,
                                vault_token,
                                set_vault_token,
                                note,
                                set_note,
                                on_claim_submit,
                                claim_action.pending().into(),
                                auth.admin_token,
                            ).into_any(),
                            Err(err) => view! {
                                <Alert kind=AlertKind::Error message=err.to_string() />
                            }
                            .into_any(),
                        })
                        .unwrap_or_else(|| view! { <Spinner /> }.into_any())
                }
            }}

            {move || {
                if page_state.get() == PageState::Form {
                     view! {
                         {move || error.get().map(|err| view! { <Alert kind=AlertKind::Error message=err.to_string() /> })}
                         {move || success.get().map(|msg| view! { <Alert kind=AlertKind::Success message=msg /> })}
                     }.into_any()
                } else {
                    ().into_any()
                }
            }}
        </div>
    }
}

#[allow(clippy::too_many_arguments)]
fn render_admin_forms(
    status: AdminStatusResponse,
    vault_token: ReadSignal<String>,
    set_vault_token: WriteSignal<String>,
    note: ReadSignal<String>,
    set_note: WriteSignal<String>,
    on_claim_submit: impl Fn(SubmitEvent) + Copy + Send + 'static,
    claim_pending: Signal<bool>,
    admin_token: RwSignal<Option<crate::features::auth::types::AdminElevateResponse>>,
) -> impl IntoView {
    let cooldown_message = if status.cooldown_seconds > 0 {
        Some(format!(
            "Cooldown active: {}s remaining.",
            status.cooldown_seconds
        ))
    } else {
        None
    };
    let has_active_token = Signal::derive(move || {
        admin_token
            .get()
            .map_or(false, |token| !is_token_expired(&token.expires_at))
    });

    view! {
        <div class="space-y-4">
            {cooldown_message.map(|message| {
                view! { <Alert kind=AlertKind::Info message=message /> }
            })}
            {move || {
                admin_token
                    .get()
                    .and_then(|token| {
                        if is_token_expired(&token.expires_at) {
                            None
                        } else {
                            Some(
                                view! {
                                <Alert
                                    kind=AlertKind::Success
                                    message=format!("Admin token active until {}.", token.expires_at)
                                />
                                <div class="mt-4">
                                    <A
                                        href={paths::ADMIN}
                                        {..}
                                        class="inline-flex items-center px-5 py-2.5 text-sm font-medium text-white bg-green-600 rounded-lg hover:bg-green-700 focus:ring-4 focus:outline-none focus:ring-green-300 dark:bg-green-500 dark:hover:bg-green-600 dark:focus:ring-green-800 transition-all"
                                    >
                                        <span class="material-symbols-outlined mr-2 text-base">
                                            "settings"
                                        </span>
                                        "Go Admin"
                                    </A>
                                </div>
                            }
                                .into_any(),
                            )
                        }
                    })
                    .unwrap_or_else(|| ().into_any())
            }}
        </div>

        {move || {
            if has_active_token.get() {
                ().into_any()
            } else if status.bootstrap_open && !status.operator {
                view! {
                    <form class="space-y-4" on:submit=on_claim_submit>
                        <div>
                            <label class="block mb-2 text-sm font-medium text-gray-900 dark:text-white">
                                "Vault token"
                            </label>
                            <input
                                type="password"
                                class="bg-gray-50 border border-gray-300 text-gray-900 text-sm rounded-lg focus:ring-blue-500 focus:border-blue-500 block w-full p-2.5 dark:bg-gray-700 dark:border-gray-600 dark:placeholder-gray-400 dark:text-white dark:focus:ring-blue-500 dark:focus:border-blue-500"
                                on:input=move |event| set_vault_token.set(event_target_value(&event))
                                value=vault_token.get()
                                placeholder="s.xxxxx"
                            />
                        </div>
                        <div>
                            <label class="block mb-2 text-sm font-medium text-gray-900 dark:text-white">
                                "Note"
                            </label>
                            <input
                                type="text"
                                class="bg-gray-50 border border-gray-300 text-gray-900 text-sm rounded-lg focus:ring-blue-500 focus:border-blue-500 block w-full p-2.5 dark:bg-gray-700 dark:border-gray-600 dark:placeholder-gray-400 dark:text-white dark:focus:ring-blue-500 dark:focus:border-blue-500"
                                on:input=move |event| set_note.set(event_target_value(&event))
                                value=note.get()
                                placeholder="Initial operator"
                            />
                        </div>
                        <Button button_type="submit" disabled=claim_pending>
                            "Bootstrap operator"
                        </Button>
                        {move || claim_pending.get().then_some(view! { <Spinner /> })}
                    </form>
                }
                .into_any()
            } else if status.operator && !has_active_token.get() {
                view! {
                    <form class="space-y-4" on:submit=on_claim_submit>
                        <div>
                            <label class="block mb-2 text-sm font-medium text-gray-900 dark:text-white">
                                "Vault token"
                            </label>
                            <input
                                type="password"
                                class="bg-gray-50 border border-gray-300 text-gray-900 text-sm rounded-lg focus:ring-blue-500 focus:border-blue-500 block w-full p-2.5 dark:bg-gray-700 dark:border-gray-600 dark:placeholder-gray-400 dark:text-white dark:focus:ring-blue-500 dark:focus:border-blue-500"
                                on:input=move |event| set_vault_token.set(event_target_value(&event))
                                value=vault_token.get()
                                placeholder="s.xxxxx"
                            />
                        </div>
                        <Button button_type="submit" disabled=claim_pending>
                            "Elevate"
                        </Button>
                        {move || claim_pending.get().then_some(view! { <Spinner /> })}
                    </form>
                }
                .into_any()
            } else {
                ().into_any()
            }
        }}
    }
}
