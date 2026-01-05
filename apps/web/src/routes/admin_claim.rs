//! Admin claim page for platform operator bootstrap and elevation.
//!
//! Flow Overview: Fetch admin status, render the appropriate form, then submit
//! the Vault token to bootstrap or elevate. The admin token is stored in memory
//! and must be re-issued after expiration.

use crate::{
    app_lib::AppError,
    components::{Alert, AlertKind, AppShell, Button, Spinner},
    features::auth::{
        client::{self, is_token_expired},
        state::use_auth,
        types::{AdminBootstrapRequest, AdminElevateRequest, AdminStatusResponse},
    },
    routes::NotFoundPage,
};
use leptos::{ev::SubmitEvent, prelude::*};
use leptos_router::components::A;

#[component]
pub fn AdminClaimPage() -> impl IntoView {
    let auth = use_auth();
    let (vault_token, set_vault_token) = signal(String::new());
    let (note, set_note) = signal(String::new());
    let (error, set_error) = signal::<Option<AppError>>(None);
    let (success, set_success) = signal::<Option<String>>(None);

    let status_key = Signal::derive(move || {
        (
            auth.session.get().map(|session| session.user_id),
            auth.session_token.get(),
        )
    });

    let status_resource = LocalResource::new(move || {
        let (user_id, token) = status_key.get();
        async move {
            if user_id.is_none() {
                return Err(AppError::Config("Sign in required.".to_string()));
            }
            client::admin_status(token.as_deref()).await
        }
    });

    Effect::new(move |_| {
        let _ = status_key.get();
        status_resource.refetch();
    });

    let bootstrap_action = Action::new_local(move |token: &String| {
        let token = token.trim().to_string();
        let note_value = note.get_untracked().trim().to_string();
        let auth_header = auth.session_token.get_untracked();
        async move {
            let request = AdminBootstrapRequest {
                vault_token: token,
                note: if note_value.is_empty() {
                    None
                } else {
                    Some(note_value)
                },
            };
            client::admin_bootstrap(auth_header.as_deref(), &request).await?;
            Ok(())
        }
    });

    let elevate_action = Action::new_local(move |token: &String| {
        let token = token.trim().to_string();
        let auth_header = auth.session_token.get_untracked();
        async move {
            let request = AdminElevateRequest { vault_token: token };
            let response = client::admin_elevate(auth_header.as_deref(), &request).await?;
            Ok(response)
        }
    });

    Effect::new(move |_| {
        if let Some(result) = bootstrap_action.value().get() {
            match result {
                Ok(()) => {
                    set_success.set(Some("Bootstrap complete. Elevating...".to_string()));
                    set_error.set(None);
                    // UX Improvement: Auto-trigger elevation after bootstrap using the same token
                    let token = vault_token.get_untracked();
                    if !token.trim().is_empty() {
                        elevate_action.dispatch(token);
                    }
                    set_note.set(String::new());
                    status_resource.refetch();
                }
                Err(err) => {
                    set_error.set(Some(err));
                    set_success.set(None);
                }
            }
        }
    });

    let auth_for_elevate = auth.clone();
    Effect::new(move |_| {
        if elevate_action.pending().get() {
            set_success.set(None); // Clear previous success messages when a new elevation starts
        }
        if let Some(result) = elevate_action.value().get() {
            match result {
                Ok(token) => {
                    auth_for_elevate.set_admin_token(token);
                    set_success.set(None);
                    set_error.set(None);
                    set_vault_token.set(String::new());
                }
                Err(err) => {
                    set_error.set(Some(err));
                    set_success.set(None);
                }
            }
        }
    });

    let on_bootstrap_submit = move |event: SubmitEvent| {
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
        bootstrap_action.dispatch(token);
    };

    let on_elevate_submit = move |event: SubmitEvent| {
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
        elevate_action.dispatch(token);
    };

    view! {
        {move || {
            if auth.is_loading.get() {
                view! {
                    <AppShell>
                        <Spinner />
                    </AppShell>
                }
                .into_any()
            } else if !auth.is_authenticated.get() {
                view! { <NotFoundPage /> }.into_any()
            } else {
                view! {
                    <AppShell>
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
                                status_resource
                                    .get()
                                    .map(|result: Result<AdminStatusResponse, _>| match result {
                                        Ok(status) if status.operator || status.bootstrap_open => render_admin_forms(
                                            status,
                                            vault_token,
                                            set_vault_token,
                                            note,
                                            set_note,
                                            on_bootstrap_submit,
                                            on_elevate_submit,
                                            bootstrap_action.pending().into(),
                                            elevate_action.pending().into(),
                                            auth.admin_token,
                                        ).into_any(),
                                        Ok(_) => view! { <NotFoundPage /> }.into_any(),
                                        Err(err) => view! {
                                            <Alert kind=AlertKind::Error message=err.to_string() />
                                        }
                                        .into_any(),
                                    })
                                    .unwrap_or_else(|| view! { <Spinner /> }.into_any())
                            }}

                            {move || {
                                error
                                    .get()
                                    .map(|err| view! { <Alert kind=AlertKind::Error message=err.to_string() /> })
                            }}
                            {move || {
                                success
                                    .get()
                                    .map(|message| view! { <Alert kind=AlertKind::Success message=message /> })
                            }}
                        </div>
                    </AppShell>
                }
                .into_any()
            }
        }}
    }
}

#[allow(clippy::too_many_arguments)]
fn render_admin_forms(
    status: AdminStatusResponse,
    vault_token: ReadSignal<String>,
    set_vault_token: WriteSignal<String>,
    note: ReadSignal<String>,
    set_note: WriteSignal<String>,
    on_bootstrap_submit: impl Fn(SubmitEvent) + Copy + Send + 'static,
    on_elevate_submit: impl Fn(SubmitEvent) + Copy + Send + 'static,
    bootstrap_pending: Signal<bool>,
    elevate_pending: Signal<bool>,
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
                            Some(view! {
                                <Alert
                                    kind=AlertKind::Success
                                    message=format!("Admin token active until {}.", token.expires_at)
                                />
                                <div class="mt-4">
                                    <A
                                        href="/admin"
                                        {..}
                                        class="inline-flex items-center px-5 py-2.5 text-sm font-medium text-white bg-green-600 rounded-lg hover:bg-green-700 focus:ring-4 focus:outline-none focus:ring-green-300 dark:bg-green-500 dark:hover:bg-green-600 dark:focus:ring-green-800 transition-all"
                                    >
                                        <span class="material-symbols-outlined mr-2 text-base">
                                            "settings"
                                        </span>
                                        "Go Admin"
                                    </A>
                                </div>
                            })
                        }
                    })
            }}
        </div>

        {move || {
            let has_active_token = admin_token.get().map_or(false, |t| !is_token_expired(&t.expires_at));

            if status.bootstrap_open && !status.operator {
                view! {
                    <form class="space-y-4" on:submit=on_bootstrap_submit>
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
                        <Button button_type="submit" disabled=bootstrap_pending>
                            "Bootstrap operator"
                        </Button>
                        {move || bootstrap_pending.get().then_some(view! { <Spinner /> })}
                    </form>
                }
                .into_any()
            } else if status.operator && !has_active_token {
                view! {
                    <form class="space-y-4" on:submit=on_elevate_submit>
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
                        <Button button_type="submit" disabled=elevate_pending>
                            "Elevate"
                        </Button>
                        {move || elevate_pending.get().then_some(view! { <Spinner /> })}
                    </form>
                }
                .into_any()
            } else if status.operator && has_active_token {
                // If we have a token, don't show the form, just the success alert (handled above)
                ().into_any()
            } else {
                // This branch is logically unreachable due to the guard in the parent component
                ().into_any()
            }
        }}
    }
}
