//! Security settings route for the authenticated user.
//!
//! Provides a centralized interface for managing "Sign-in methods" (GitHub-style layout).
//! Users can manage their credentials here without exposing sensitive data to the UI.
//!
//! ### Password Change Flow (OPAQUE)
//!
//! Password changes are performed via a secure 4-step cryptographic handshake:
//! 1. **Secure Re-auth (Start)**: Authenticate the user with their current password.
//! 2. **Secure Re-auth (Finish)**: Verify the client's proof of the current password.
//! 3. **Password Rotation (Start)**: Initiate registration of the new password.
//! 4. **Password Rotation (Finish)**: Seal and store the new registration record.
//!
//! This ensures the plaintext password never leaves the user's browser.
//!
//! ### Feature Support
//! - **Password**: Fully implemented with OPAQUE.
//! - **Passkeys**: UI placeholder for future WebAuthn implementation.
//! - **2FA**: UI placeholder for future TOTP/Hardware key implementation.

use crate::{
    app_lib::{AppError, config::AppConfig},
    components::{Alert, AlertKind, Button, Spinner},
    features::{
        auth::{
            client as auth_client,
            opaque::{OpaqueSuite, identifiers, ksf, normalize_email},
            state::use_auth,
            token,
            types::{
                OpaquePasswordFinishRequest, OpaquePasswordStartRequest, OpaqueReauthFinishRequest,
                OpaqueReauthStartRequest,
            },
        },
        me::client,
    },
    routes::paths,
};
use base64::Engine;
use leptos::{ev::SubmitEvent, prelude::*};
use leptos_router::hooks::use_navigate;
use opaque_ke::{
    ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, CredentialResponse, RegistrationResponse,
};
use rand::rngs::OsRng;

/// Minimum password length enforced by the client for early UX feedback.
const MIN_PASSWORD_LENGTH: usize = 12;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct SecurityStatus {
    pub password_configured: bool,
    pub passkey_count: u32,
    pub two_factor_enabled: bool,
}

#[derive(Clone)]
struct ChangePasswordInput {
    email: String,
    current_password: String,
    new_password: String,
}

#[component]
pub fn MeSecurityPage() -> impl IntoView {
    let auth = use_auth();
    let navigate = use_navigate();
    let profile = LocalResource::new(move || async move { client::fetch_me().await });
    let (current_password, set_current_password) = signal(String::new());
    let (new_password, set_new_password) = signal(String::new());
    let (confirm_password, set_confirm_password) = signal(String::new());
    let (password_error, set_password_error) = signal::<Option<AppError>>(None);
    let (show_password_form, set_show_password_form) = signal(false);

    // Placeholder security status - in the future this will be a real API call
    let security_status = LocalResource::new(move || async move {
        Ok::<SecurityStatus, AppError>(SecurityStatus {
            password_configured: true,
            passkey_count: 0,
            two_factor_enabled: false,
        })
    });

    let change_password_action = Action::new_local(move |input: &ChangePasswordInput| {
        let input = input.clone();
        async move {
            let config = AppConfig::load();
            let client_id = normalize_email(&input.email);
            let server_id = config.opaque_server_id;

            let mut rng = OsRng;
            let start =
                ClientLogin::<OpaqueSuite>::start(&mut rng, input.current_password.as_bytes())
                    .map_err(|_| AppError::Config("Unable to start secure re-auth.".to_string()))?;
            let start_request = OpaqueReauthStartRequest {
                credential_request: base64::engine::general_purpose::STANDARD
                    .encode(start.message.serialize()),
            };
            let zero_token = token::fetch_zero_token().await?;
            let start_response =
                auth_client::opaque_reauth_start(&start_request, &zero_token).await?;

            let response_bytes = base64::engine::general_purpose::STANDARD
                .decode(start_response.credential_response)
                .map_err(|_| AppError::Config("Invalid re-auth response.".to_string()))?;
            let credential_response =
                CredentialResponse::<OpaqueSuite>::deserialize(&response_bytes).map_err(|_| {
                    AppError::Config("Unable to complete secure re-auth.".to_string())
                })?;

            let ksf_params = ksf();
            let params = ClientLoginFinishParameters::new(
                None,
                identifiers(client_id.as_bytes(), server_id.as_bytes()),
                Some(&ksf_params),
            );
            let finish = start
                .state
                .finish(
                    input.current_password.as_bytes(),
                    credential_response,
                    params,
                )
                .map_err(|_| AppError::Config("Unable to complete secure re-auth.".to_string()))?;

            let finish_request = OpaqueReauthFinishRequest {
                login_id: start_response.login_id,
                credential_finalization: base64::engine::general_purpose::STANDARD
                    .encode(finish.message.serialize()),
            };
            let zero_token = token::fetch_zero_token().await?;
            auth_client::opaque_reauth_finish(&finish_request, &zero_token).await?;

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
            let registration_response = RegistrationResponse::<OpaqueSuite>::deserialize(
                &response_bytes,
            )
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
    });

    let auth_for_effect = auth.clone();
    let navigate_for_effect = navigate.clone();
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
                    navigate_for_effect(paths::LOGIN, Default::default());
                }
                Err(err) => set_password_error.set(Some(err)),
            }
        }
    });

    view! {
        <div class="space-y-6">
            <div>
                <h1 class="text-2xl font-bold text-gray-900 dark:text-white">
                    "Security"
                </h1>
                <p class="text-gray-500 dark:text-gray-400">
                    "Manage your account security and authentication methods."
                </p>
            </div>

            <Suspense fallback=move || view! { <Spinner /> }>
                {move || match (profile.get(), security_status.get()) {
                    (Some(Ok(me)), Some(Ok(status))) => {
                        let email = me.email.clone();
                        let on_submit = move |event: SubmitEvent| {
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
                                email: email.clone(),
                                current_password: current_value,
                                new_password: new_value,
                            });
                        };

                        view! {
                            <div class="space-y-6">
                                // Sign-in methods section
                                <div class="bg-white dark:bg-gray-800 shadow rounded-lg overflow-hidden">
                                    <div class="px-6 py-4 border-b border-gray-200 dark:border-gray-700">
                                        <h2 class="text-lg font-medium text-gray-900 dark:text-white">
                                            "Sign-in methods"
                                        </h2>
                                    </div>

                                    <div class="divide-y divide-gray-200 dark:divide-gray-700">
                                        // Password Row
                                        <div class="px-6 py-4">
                                            <div class="flex items-center justify-between">
                                                <div class="flex items-center space-x-3">
                                                    <span class="material-symbols-outlined text-gray-400 dark:text-gray-500">
                                                        "key"
                                                    </span>
                                                    <div>
                                                        <p class="text-sm font-medium text-gray-900 dark:text-white">
                                                            "Password"
                                                        </p>
                                                        <p class="text-xs text-gray-500 dark:text-gray-400">
                                                            {if status.password_configured {
                                                                "Password is set"
                                                            } else {
                                                                "No password set"
                                                            }}
                                                        </p>
                                                    </div>
                                                </div>
                                                <button
                                                    on:click=move |_| set_show_password_form.update(|v| *v = !*v)
                                                    class="text-sm font-medium text-blue-600 hover:text-blue-500 dark:text-blue-400 dark:hover:text-blue-300"
                                                >
                                                    {move || if show_password_form.get() { "Cancel" } else { "Change password" }}
                                                </button>
                                            </div>

                                            <Show when=move || show_password_form.get()>
                                                <form class="mt-6 space-y-4 max-w-md bg-gray-50 dark:bg-gray-900/50 p-4 rounded-lg" on:submit=on_submit.clone()>
                                                    <div>
                                                        <label class="block mb-1 text-sm font-medium text-gray-700 dark:text-gray-300" for="current_password">
                                                            "Current password"
                                                        </label>
                                                        <input
                                                            id="current_password"
                                                            type="password"
                                                            class="bg-gray-50 border border-gray-300 text-gray-900 text-sm rounded-lg focus:ring-blue-500 focus:border-blue-500 block w-full p-2.5 dark:bg-gray-700 dark:border-gray-600 dark:text-white"
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
                                                            class="bg-gray-50 border border-gray-300 text-gray-900 text-sm rounded-lg focus:ring-blue-500 focus:border-blue-500 block w-full p-2.5 dark:bg-gray-700 dark:border-gray-600 dark:text-white"
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
                                                            class="bg-gray-50 border border-gray-300 text-gray-900 text-sm rounded-lg focus:ring-blue-500 focus:border-blue-500 block w-full p-2.5 dark:bg-gray-700 dark:border-gray-600 dark:text-white"
                                                            autocomplete="new-password"
                                                            required
                                                            on:input=move |event| set_confirm_password.set(event_target_value(&event))
                                                        />
                                                    </div>
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
                                            </Show>
                                        </div>

                                        // Passkeys Row
                                        <div class="px-6 py-4">
                                            <div class="flex items-center justify-between">
                                                <div class="flex items-center space-x-3">
                                                    <span class="material-symbols-outlined text-gray-400 dark:text-gray-500">
                                                        "fingerprint"
                                                    </span>
                                                    <div>
                                                        <p class="text-sm font-medium text-gray-900 dark:text-white">
                                                            "Passkeys"
                                                        </p>
                                                        <p class="text-xs text-gray-500 dark:text-gray-400">
                                                            {format!("{} passkeys configured", status.passkey_count)}
                                                        </p>
                                                    </div>
                                                </div>
                                                <button class="text-sm font-medium text-gray-400 dark:text-gray-500 cursor-not-allowed" disabled=true>
                                                    "Add passkey"
                                                </button>
                                            </div>
                                        </div>
                                    </div>
                                </div>

                                // Two-factor authentication section
                                <div class="bg-white dark:bg-gray-800 shadow rounded-lg overflow-hidden">
                                    <div class="px-6 py-4 border-b border-gray-200 dark:border-gray-700">
                                        <h2 class="text-lg font-medium text-gray-900 dark:text-white">
                                            "Two-factor authentication"
                                        </h2>
                                    </div>
                                    <div class="px-6 py-4 flex items-center justify-between">
                                        <div class="flex items-center space-x-3">
                                            <span class="material-symbols-outlined text-gray-400 dark:text-gray-500">
                                                "phonelink_lock"
                                            </span>
                                            <div>
                                                <p class="text-sm font-medium text-gray-900 dark:text-white">
                                                    "Two-factor authentication"
                                                </p>
                                                <p class="text-xs text-gray-500 dark:text-gray-400">
                                                    {if status.two_factor_enabled {
                                                        "Two-factor authentication is enabled"
                                                    } else {
                                                        "Two-factor authentication is not enabled"
                                                    }}
                                                </p>
                                            </div>
                                        </div>
                                        <button class="text-sm font-medium text-gray-400 dark:text-gray-500 cursor-not-allowed" disabled=true>
                                            "Enable"
                                        </button>
                                    </div>
                                </div>
                            </div>
                        }.into_any()
                    }
                    (Some(Err(err)), _) | (_, Some(Err(err))) => {
                        view! { <Alert kind=AlertKind::Error message=err.to_string() /> }
                            .into_any()
                    }
                    _ => view! { <Spinner /> }.into_any(),
                }}
            </Suspense>
        </div>
    }
}
