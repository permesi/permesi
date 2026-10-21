//! Password rotation through OPAQUE; success clears the old browser session.
//!
//! Flow Overview: The section collects browser-local input, completes the existing
//! authentication ceremony and calls its session-authenticated mutation API.

use crate::{
    app_lib::{AppError, config::AppConfig, theme::Theme},
    components::{Alert, AlertKind, Button, Spinner},
    features::auth::{
        client as auth_client,
        opaque::{OpaqueSuite, identifiers, ksf, normalize_email, reauthenticate},
        state::use_auth,
        token,
        types::{OpaquePasswordFinishRequest, OpaquePasswordStartRequest},
    },
    routes::paths,
};
use base64::Engine;
use leptos::{ev::SubmitEvent, prelude::*};
use leptos_router::hooks::use_navigate;
use opaque_ke::{ClientRegistration, ClientRegistrationFinishParameters, RegistrationResponse};
use opaque_rand_core::OsRng;

/// Minimum password length enforced by the client for early UX feedback.
const MIN_PASSWORD_LENGTH: usize = 12;

#[derive(Clone)]
struct ChangePasswordInput {
    email: String,
    current_password: String,
    new_password: String,
}

/// Owns the password-rotation ceremony and clears the old session on success.
#[component]
pub(super) fn PasswordSection(email: StoredValue<String>, configured: bool) -> impl IntoView {
    let auth = use_auth();
    let (current_password, set_current_password) = signal(String::new());
    let (new_password, set_new_password) = signal(String::new());
    let (confirm_password, set_confirm_password) = signal(String::new());
    let (password_error, set_password_error) = signal::<Option<AppError>>(None);
    let (show_password_form, set_show_password_form) = signal(false);

    let change_password_action = Action::new_local(move |input: &ChangePasswordInput| {
        let input = input.clone();
        change_password(input)
    });

    let auth_for_effect = auth;
    Effect::new(move |_| {
        if let Some(result) = change_password_action.value().get() {
            match result {
                Ok(()) => {
                    auth_for_effect.clear_session();
                    if let Some(storage) = web_sys::window()
                        .and_then(|w| w.local_storage().ok())
                        .flatten()
                    {
                        let _ = storage.remove_item("permesi_logged_in");
                    }
                    let navigate = use_navigate();
                    navigate(paths::LOGIN, leptos_router::NavigateOptions::default());
                }
                Err(err) => set_password_error.set(Some(err)),
            }
        }
    });

    view! {
                                        // Password Row
                                        <div class=Theme::ROW>
                                            <div class="flex items-center justify-between">
                                                <div class="flex items-center space-x-3">
                                                    <span class=Theme::ICON>
                                                        "password"
                                                    </span>
                                                    <div>
                                                        <p class="text-sm font-medium text-gray-900 dark:text-white">
                                                            "Password"
                                                        </p>
                                                        <p class="text-xs text-gray-500 dark:text-gray-400">
                                                            {if configured {
                                                                "Password is set"
                                                            } else {
                                                                "No password set"
                                                            }}
                                                        </p>
                                                    </div>
                                                </div>
                                                <button
                                                    on:click=move |_| set_show_password_form.update(|v| *v = !*v)
                                                    class="text-sm font-medium text-gray-700 dark:text-gray-200 bg-white dark:bg-gray-900 border border-gray-300 dark:border-gray-600 rounded-md px-3 py-1.5 hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors cursor-pointer"
                                                >
                                                    {move || if show_password_form.get() { "Cancel" } else { "Change password" }}
                                                </button>
                                            </div>

                                            <Show when=move || show_password_form.get()>
                                                {password_change_form(PasswordChangeForm { email, current_password, new_password, confirm_password, password_error, set_password_error, change_password_action, set_current_password, set_new_password, set_confirm_password })}
                                            </Show>
                                        </div>

    }
}

/// Proves the current password before uploading the new OPAQUE registration.
async fn change_password(input: ChangePasswordInput) -> Result<(), AppError> {
    let config = AppConfig::load();
    let client_id = normalize_email(&input.email);
    let server_id = config.opaque_server_id;

    let mut rng = OsRng;
    reauthenticate(&input.email, input.current_password).await?;
    let ksf_params = ksf();

    let reg_start =
        ClientRegistration::<OpaqueSuite>::start(&mut rng, input.new_password.as_bytes())
            .map_err(|_| AppError::Config("Unable to start password change.".to_string()))?;
    let reg_start_request = OpaquePasswordStartRequest {
        registration_request: base64::engine::general_purpose::STANDARD
            .encode(reg_start.message.serialize()),
    };
    let zero_token = token::fetch_zero_token().await?;
    let reg_start_response =
        auth_client::opaque_password_start(&reg_start_request, &zero_token).await?;

    let response_bytes = base64::engine::general_purpose::STANDARD
        .decode(reg_start_response.registration_response)
        .map_err(|_| AppError::Config("Invalid password change response.".to_string()))?;
    let registration_response =
        RegistrationResponse::<OpaqueSuite>::deserialize(&response_bytes)
            .map_err(|_| AppError::Config("Unable to complete password change.".to_string()))?;

    let params = ClientRegistrationFinishParameters::new(
        identifiers(client_id.as_bytes(), server_id.as_bytes()),
        Some(&ksf_params),
    );
    let reg_finish = reg_start
        .state
        .finish(
            &mut rng,
            input.new_password.as_bytes(),
            registration_response,
            params,
        )
        .map_err(|_| AppError::Config("Unable to complete password change.".to_string()))?;

    let finish_request = OpaquePasswordFinishRequest {
        registration_record: base64::engine::general_purpose::STANDARD
            .encode(reg_finish.message.serialize()),
    };
    let zero_token = token::fetch_zero_token().await?;
    auth_client::opaque_password_finish(&finish_request, &zero_token).await?;
    Ok(())
}

#[derive(Clone, Copy)]
struct PasswordChangeForm {
    email: StoredValue<String>,
    current_password: ReadSignal<String>,
    new_password: ReadSignal<String>,
    confirm_password: ReadSignal<String>,
    password_error: ReadSignal<Option<AppError>>,
    set_password_error: WriteSignal<Option<AppError>>,
    change_password_action: Action<ChangePasswordInput, Result<(), AppError>>,
    set_current_password: WriteSignal<String>,
    set_new_password: WriteSignal<String>,
    set_confirm_password: WriteSignal<String>,
}

/// Renders the confirmation form using only its owning section's state.
fn password_change_form(state: PasswordChangeForm) -> impl IntoView {
    let PasswordChangeForm {
        email,
        current_password,
        new_password,
        confirm_password,
        password_error,
        set_password_error,
        change_password_action,
        set_current_password,
        set_new_password,
        set_confirm_password,
    } = state;
    view! {
    <form
                                                        class="mt-6 space-y-4 max-w-md bg-gray-50 dark:bg-gray-900/50 p-4 rounded-lg border border-gray-100 dark:border-gray-700"
                                                        on:submit=move |event: SubmitEvent| {
                                                            event.prevent_default();
                                                            set_password_error.set(None);
                                                            let current_value = current_password.get_untracked();
                                                            let new_value = new_password.get_untracked();
                                                            let confirm_value = confirm_password.get_untracked();
                                                            if current_value.trim().is_empty()
                                                                || new_value.trim().is_empty()
                                                                || confirm_value.trim().is_empty()
                                                            {
                                                                set_password_error.set(Some(AppError::Config(
                                                                    "Current and new password fields are required.".to_string(),
                                                                )));
                                                                return;
                                                            }
                                                            if new_value != confirm_value {
                                                                set_password_error.set(Some(AppError::Config(
                                                                    "New passwords do not match.".to_string(),
                                                                )));
                                                                return;
                                                            }
                                                            if new_value.trim().len() < MIN_PASSWORD_LENGTH {
                                                                set_password_error.set(Some(AppError::Config(format!(
                                                                    "New password must be at least {MIN_PASSWORD_LENGTH} characters."
                                                                ))));
                                                                return;
                                                            }
                                                            change_password_action.dispatch(ChangePasswordInput {
                                                                email: email.get_value(),
                                                                current_password: current_value,
                                                                new_password: new_value,
                                                            });
                                                        }
                                                    >
                                                        {password_inputs(PasswordInputs { current: set_current_password, replacement: set_new_password, confirmation: set_confirm_password })}
    <div class="pt-2 flex items-center gap-4">
                                                            <Button button_type="submit" disabled=change_password_action.pending()>
                                                                "Update password"
                                                            </Button>
                                                            {move || {
                                                                change_password_action
                                                                    .pending()
                                                                    .get()
                                                                    .then_some(view! { <Spinner /> })
                                                            }}
                                                        </div>
                                                        {move || {
                                                            password_error
                                                                .get()
                                                                .map(|err| {
                                                                    view! { <Alert kind=AlertKind::Error message=err.to_string() /> }
                                                                })
                                                        }}
                                                    </form>
    }
}

#[derive(Clone, Copy)]
struct PasswordInputs {
    current: WriteSignal<String>,
    replacement: WriteSignal<String>,
    confirmation: WriteSignal<String>,
}

/// Keeps current/new/confirmation inputs together without granting mutation authority.
fn password_inputs(state: PasswordInputs) -> impl IntoView {
    let PasswordInputs {
        current: set_current_password,
        replacement: set_new_password,
        confirmation: set_confirm_password,
    } = state;
    view! { <div>
        <label class="block mb-1 text-sm font-medium text-gray-700 dark:text-gray-300" for="current_password">
            "Current password"
        </label>
        <input
            id="current_password"
            type="password"
            class="bg-white border border-gray-300 text-gray-900 text-sm rounded-lg focus:ring-blue-500 focus:border-blue-500 block w-full p-2.5 dark:bg-gray-700 dark:border-gray-600 dark:text-white"
            autocomplete="current-password"
            required
            on:input=move |event| set_current_password.set(event_target_value(&event))
        />
    </div>
    <div>
        <label class="block mb-1 text-sm font-medium text-gray-700 dark:text-gray-300" for="new_password">
            "New password"
        </label>
        <input
            id="new_password"
            type="password"
            class="bg-white border border-gray-300 text-gray-900 text-sm rounded-lg focus:ring-blue-500 focus:border-blue-500 block w-full p-2.5 dark:bg-gray-700 dark:border-gray-600 dark:text-white"
            autocomplete="new-password"
            required
            on:input=move |event| set_new_password.set(event_target_value(&event))
        />
    </div>
    <div>
        <label class="block mb-1 text-sm font-medium text-gray-700 dark:text-gray-300" for="confirm_password">
            "Confirm new password"
        </label>
        <input
            id="confirm_password"
            type="password"
            class="bg-white border border-gray-300 text-gray-900 text-sm rounded-lg focus:ring-blue-500 focus:border-blue-500 block w-full p-2.5 dark:bg-gray-700 dark:border-gray-600 dark:text-white"
            autocomplete="new-password"
            required
            on:input=move |event| set_confirm_password.set(event_target_value(&event))
        />
    </div>
     }
}
