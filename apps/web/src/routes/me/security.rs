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

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SecurityStatus {
    pub password_configured: bool,
    pub passkey_count: u32,
    pub two_factor_enabled: bool,
    pub totp_enabled: bool,
}

#[derive(Clone)]
struct ChangePasswordInput {
    email: String,
    current_password: String,
    new_password: String,
}

#[derive(Clone)]
struct MfaAuthInput {
    email: String,
    password: String,
}

#[component]
pub fn MeSecurityPage() -> impl IntoView {
    let auth = use_auth();
    let profile = LocalResource::new(move || async move { client::fetch_me().await });
    let (current_password, set_current_password) = signal(String::new());
    let (new_password, set_new_password) = signal(String::new());
    let (confirm_password, set_confirm_password) = signal(String::new());
    let (password_error, set_password_error) = signal::<Option<AppError>>(None);
    let (show_password_form, set_show_password_form) = signal(false);

    // Recovery codes signals
    let (show_recovery_codes_form, set_show_recovery_codes_form) = signal(false);
    let (recovery_password, set_recovery_password) = signal(String::new());
    let (regenerated_codes, set_regenerated_codes) = signal::<Option<Vec<String>>>(None);

    // Delete MFA signals
    let (show_delete_totp_form, set_show_delete_totp_form) = signal(false);
    let (delete_password, set_delete_password) = signal(String::new());

    // Security keys signals
    let security_keys =
        LocalResource::new(move || async move { client::list_security_keys().await });
    let (show_add_key_form, set_show_add_key_form) = signal(false);
    let (new_key_label, set_new_key_label) = signal(String::new());
    let (show_delete_key_form, set_show_delete_key_form) = signal::<Option<String>>(None); // Credential ID
    let (delete_key_password, set_delete_key_password) = signal(String::new());

    let delete_key_action =
        Action::new_local(move |(credential_id, password): &(String, String)| {
            let credential_id = credential_id.clone();
            let password = password.clone();
            let auth = auth.clone();
            async move {
                let config = AppConfig::load();
                let client_id = normalize_email(
                    &auth
                        .session
                        .get_untracked()
                        .map(|s| s.email)
                        .unwrap_or_default(),
                );
                let server_id = config.opaque_server_id;

                let mut rng = OsRng;
                // 1. Re-auth
                let start = ClientLogin::<OpaqueSuite>::start(&mut rng, password.as_bytes())
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
                let credential_response = CredentialResponse::<OpaqueSuite>::deserialize(
                    &response_bytes,
                )
                .map_err(|_| AppError::Config("Unable to complete secure re-auth.".to_string()))?;

                let ksf_params = ksf();
                let params = ClientLoginFinishParameters::new(
                    None,
                    identifiers(client_id.as_bytes(), server_id.as_bytes()),
                    Some(&ksf_params),
                );
                let finish = start
                    .state
                    .finish(password.as_bytes(), credential_response, params)
                    .map_err(|_| {
                        AppError::Config("Unable to complete secure re-auth.".to_string())
                    })?;

                let finish_request = OpaqueReauthFinishRequest {
                    login_id: start_response.login_id,
                    credential_finalization: base64::engine::general_purpose::STANDARD
                        .encode(finish.message.serialize()),
                };
                let zero_token = token::fetch_zero_token().await?;
                auth_client::opaque_reauth_finish(&finish_request, &zero_token).await?;

                // 2. Call delete
                let token = auth.session_token.get_untracked();
                client::delete_security_key(&credential_id, token.as_deref()).await
            }
        });

    Effect::new(move |_| {
        if let Some(Ok(())) = delete_key_action.value().get() {
            set_show_delete_key_form.set(None);
            set_delete_key_password.set(String::new());
            security_keys.refetch();
        }
    });

    let add_key_action = Action::new_local(move |label: &String| {
        let label = label.clone();
        async move {
            // 1. Start WebAuthn registration
            let start_response = auth_client::mfa_webauthn_register_start().await?;

            // 2. Browser interaction (YubiKey touch)
            let reg_response =
                crate::features::auth::webauthn::register_key(&start_response.challenge).await?;

            // 3. Finish registration
            auth_client::mfa_webauthn_register_finish(
                &crate::features::auth::types::WebauthnRegisterFinishRequest {
                    reg_id: start_response.reg_id,
                    label,
                    response: reg_response,
                },
            )
            .await
        }
    });

    Effect::new(move |_| {
        if let Some(Ok(())) = add_key_action.value().get() {
            set_show_add_key_form.set(false);
            set_new_key_label.set(String::new());
            security_keys.refetch();
        }
    });

    // Derived security status from profile
    let security_status = Memo::new(move |_| {
        profile
            .get()
            .and_then(|result| result.ok())
            .map(|me| SecurityStatus {
                password_configured: true, // Always true for now as we only support password auth
                passkey_count: 0,
                two_factor_enabled: me.mfa_enabled,
                totp_enabled: me.totp_enabled,
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

    let regenerate_codes_action = Action::new_local(move |input: &MfaAuthInput| {
        let input = input.clone();
        let auth = auth.clone();
        async move {
            let config = AppConfig::load();
            let client_id = normalize_email(&input.email);
            let server_id = config.opaque_server_id;

            let mut rng = OsRng;
            // 1. Re-auth via OPAQUE
            let start = ClientLogin::<OpaqueSuite>::start(&mut rng, input.password.as_bytes())
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
                .finish(input.password.as_bytes(), credential_response, params)
                .map_err(|_| AppError::Config("Unable to complete secure re-auth.".to_string()))?;

            let finish_request = OpaqueReauthFinishRequest {
                login_id: start_response.login_id,
                credential_finalization: base64::engine::general_purpose::STANDARD
                    .encode(finish.message.serialize()),
            };
            let zero_token = token::fetch_zero_token().await?;
            auth_client::opaque_reauth_finish(&finish_request, &zero_token).await?;

            // 2. Call regeneration endpoint
            let token = auth.session_token.get_untracked();
            let response = auth_client::regenerate_recovery_codes(token.as_deref()).await?;
            Ok::<Vec<String>, AppError>(response.codes)
        }
    });

    Effect::new(move |_| {
        if let Some(Ok(codes)) = regenerate_codes_action.value().get() {
            set_regenerated_codes.set(Some(codes));
            set_show_recovery_codes_form.set(false);
            set_recovery_password.set(String::new());
        }
    });

    let disable_totp_action = Action::new_local(move |input: &MfaAuthInput| {
        let input = input.clone();
        let auth = auth.clone();
        async move {
            let config = AppConfig::load();
            let client_id = normalize_email(&input.email);
            let server_id = config.opaque_server_id;

            let mut rng = OsRng;
            // 1. Re-auth via OPAQUE
            let start = ClientLogin::<OpaqueSuite>::start(&mut rng, input.password.as_bytes())
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
                .finish(input.password.as_bytes(), credential_response, params)
                .map_err(|_| AppError::Config("Unable to complete secure re-auth.".to_string()))?;

            let finish_request = OpaqueReauthFinishRequest {
                login_id: start_response.login_id,
                credential_finalization: base64::engine::general_purpose::STANDARD
                    .encode(finish.message.serialize()),
            };
            let zero_token = token::fetch_zero_token().await?;
            auth_client::opaque_reauth_finish(&finish_request, &zero_token).await?;

            // 2. Call disable endpoint
            let token = auth.session_token.get_untracked();
            auth_client::mfa_totp_disable(token.as_deref()).await
        }
    });

    Effect::new(move |_| {
        if let Some(Ok(())) = disable_totp_action.value().get() {
            set_show_delete_totp_form.set(false);
            set_delete_password.set(String::new());
            profile.refetch();
            auth.refresh_session();
        }
    });

    let auth_for_effect = auth.clone();
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
                    navigate(paths::LOGIN, Default::default());
                }
                Err(err) => set_password_error.set(Some(err)),
            }
        }
    });

    view! {
        <div class="space-y-8">
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
                    (Some(Ok(me)), Some(status)) => {
                        let email = StoredValue::new(me.email.clone());
                        let disable_totp_action = disable_totp_action.clone();

                        view! {
                            <div class="space-y-8">
                                // Sign-in methods section
                                <section class="space-y-4">
                                    <h2 class="text-lg font-medium text-gray-900 dark:text-white px-1">
                                        "Sign-in methods"
                                    </h2>
                                    <div class="border border-gray-200 dark:border-gray-700 rounded-lg overflow-hidden bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
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
                                                    class="text-sm font-medium text-blue-600 hover:text-blue-500 dark:text-blue-400 dark:hover:text-blue-300 cursor-pointer"
                                                >
                                                    {move || if show_password_form.get() { "Cancel" } else { "Change password" }}
                                                </button>
                                            </div>

                                            <Show when=move || show_password_form.get()>
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
                                                    <div>
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
                                </section>

                                // Two-factor authentication section
                                <section class="border border-gray-200 dark:border-gray-700 rounded-lg overflow-visible bg-white dark:bg-gray-800">
                                    <div class="px-6 py-3 bg-gray-50 dark:bg-gray-900/50 border-b border-gray-200 dark:border-gray-700">
                                        <h2 class="text-lg font-medium text-gray-900 dark:text-white">
                                            "Two-factor authentication"
                                        </h2>
                                    </div>

                                    <div class="divide-y divide-gray-200 dark:divide-gray-700">
                                        // Status Row
                                        <div class="px-6 py-4">
                                            <div class="flex items-center justify-between">
                                                <div class="flex items-center space-x-3">
                                                    <span class="material-symbols-outlined text-gray-400 dark:text-gray-500">
                                                        "phonelink_lock"
                                                    </span>
                                                    <div>
                                                        <p class="text-sm font-medium text-gray-900 dark:text-white">
                                                            "Two-factor methods"
                                                        </p>
                                                        <p class="text-xs text-gray-500 dark:text-gray-400">
                                                            {if status.two_factor_enabled {
                                                                "Two-factor authentication is enabled."
                                                            } else {
                                                                "Two-factor authentication is not enabled."
                                                            }}
                                                        </p>
                                                    </div>
                                                </div>
                                                <Show when=move || !status.two_factor_enabled>
                                                    {
                                                        let navigate = use_navigate();
                                                        view! {
                                                            <button
                                                                on:click=move |_| {
                                                                    navigate(paths::MFA_SETUP, Default::default());
                                                                }
                                                                class="text-sm font-medium text-blue-600 hover:text-blue-500 dark:text-blue-400 dark:hover:text-blue-300 cursor-pointer"
                                                            >
                                                                "Add"
                                                            </button>
                                                        }
                                                    }
                                                </Show>
                                            </div>

                                            <Show when=move || status.two_factor_enabled>
                                                <div class="mt-6 space-y-4 pb-4">
                                                    <h3 class="text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                                                        "Configured methods"
                                                    </h3>
                                                    <div class="flex items-center justify-between bg-gray-50 dark:bg-gray-900/50 p-3 rounded-lg border border-gray-200 dark:border-gray-700 shadow-sm">
                                                        <div class="flex items-center space-x-3">
                                                            <span class="material-symbols-outlined text-gray-400 dark:text-gray-500 text-sm">
                                                                "smartphone"
                                                            </span>
                                                            <span class="text-sm text-gray-700 dark:text-gray-300 font-medium">
                                                                "Authenticator app"
                                                            </span>
                                                        </div>
                                                        <div class="flex items-center space-x-4">
                                                            <span class="text-xs text-gray-500 dark:text-gray-400">
                                                                {if status.totp_enabled { "Configured" } else { "Not configured" }}
                                                            </span>

                                                            <Show when=move || status.totp_enabled>
                                                                <div class="relative inline-block text-left">
                                                                    {
                                                                        let (show_menu, set_show_menu) = signal(false);
                                                                        view! {
                                                                            <button
                                                                                type="button"
                                                                                on:click=move |ev| {
                                                                                    ev.stop_propagation();
                                                                                    set_show_menu.update(|v| *v = !*v);
                                                                                }
                                                                                class="p-1 rounded-md hover:bg-white dark:hover:bg-gray-800 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 transition-colors shadow-sm border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800 cursor-pointer"
                                                                            >
                                                                                <span class="material-symbols-outlined text-xl">"more_horiz"</span>
                                                                            </button>

                                                                            <Show when=move || show_menu.get()>
                                                                                <div
                                                                                    class="absolute right-0 z-20 mt-2 w-48 origin-top-right rounded-md bg-white dark:bg-gray-800 shadow-lg ring-1 ring-black ring-opacity-5 focus:outline-none border border-gray-200 dark:border-gray-700"
                                                                                    on:click=move |ev| ev.stop_propagation()
                                                                                    on:mouseleave=move |_| set_show_menu.set(false)
                                                                                >
                                                                                    <div class="py-1">
                                                                                        <leptos_router::components::A
                                                                                            href={paths::MFA_SETUP}
                                                                                            {..}
                                                                                            on:click=move |_| set_show_menu.set(false)
                                                                                            class="flex w-full items-center px-4 py-2 text-sm text-gray-700 dark:text-gray-200 hover:bg-gray-100 dark:hover:bg-gray-700 cursor-pointer"
                                                                                        >
                                                                                            <span class="material-symbols-outlined mr-3 text-sm">"edit"</span>
                                                                                            "Edit"
                                                                                        </leptos_router::components::A>
                                                                                        <button
                                                                                            type="button"
                                                                                            on:click={
                                                                                                move |_| {
                                                                                                    set_show_menu.set(false);
                                                                                                    set_show_delete_totp_form.set(true);
                                                                                                }
                                                                                            }
                                                                                            class="flex w-full items-center px-4 py-2 text-sm text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/20 cursor-pointer text-left"
                                                                                        >
                                                                                            <span class="material-symbols-outlined mr-3 text-sm">"delete"</span>
                                                                                            "Delete"
                                                                                        </button>
                                                                                    </div>
                                                                                </div>
                                                                            </Show>
                                                                        }
                                                                    }
                                                                </div>
                                                            </Show>

                                                            <Show when=move || !status.totp_enabled>
                                                                {
                                                                    let navigate = use_navigate();
                                                                    view! {
                                                                        <button
                                                                            on:click=move |_| navigate(paths::MFA_SETUP, Default::default())
                                                                            class="text-sm font-medium text-blue-600 hover:text-blue-500 dark:text-blue-400 dark:hover:text-blue-300 cursor-pointer"
                                                                        >
                                                                            "Add"
                                                                        </button>
                                                                    }
                                                                }
                                                            </Show>
                                                        </div>
                                                    </div>
                                                </div>

                                                <Show when=move || show_delete_totp_form.get()>
                                                    <div class="mt-4 pb-4">
                                                        <form
                                                            class="space-y-4 max-w-md bg-red-50 dark:bg-red-900/10 p-4 rounded-lg border border-red-100 dark:border-red-900/30"
                                                            on:submit=move |event: SubmitEvent| {
                                                                event.prevent_default();
                                                                let password = delete_password.get_untracked();
                                                                if password.trim().is_empty() {
                                                                    return;
                                                                }
                                                                disable_totp_action.dispatch(MfaAuthInput {
                                                                    email: email.get_value(),
                                                                    password,
                                                                });
                                                            }
                                                        >
                                                            <div class="flex items-start space-x-3 mb-2">
                                                                <span class="material-symbols-outlined text-red-600 dark:text-red-400">"warning"</span>
                                                                <p class="text-sm text-red-800 dark:text-red-200 font-medium">
                                                                    "Confirm removal of Authenticator app"
                                                                </p>
                                                            </div>
                                                            <p class="text-xs text-red-700 dark:text-red-300 mb-4">
                                                                "This will disable two-factor authentication for your account. Please enter your password to confirm."
                                                            </p>
                                                            <div>
                                                                <label class="block mb-1 text-xs font-medium text-red-900 dark:text-red-200" for="delete_password">
                                                                    "Password"
                                                                </label>
                                                                <input
                                                                    id="delete_password"
                                                                    type="password"
                                                                    class="bg-white border border-red-200 text-gray-900 text-sm rounded-lg focus:ring-red-500 focus:border-red-500 block w-full p-2 dark:bg-gray-800 dark:border-red-900/50 dark:text-white"
                                                                    required
                                                                    on:input=move |event| set_delete_password.set(event_target_value(&event))
                                                                />
                                                            </div>
                                                            <div class="pt-2 flex items-center gap-3">
                                                                <button
                                                                    type="submit"
                                                                    disabled=disable_totp_action.pending()
                                                                    class="px-4 py-2 bg-red-600 hover:bg-red-700 text-white text-sm font-medium rounded-lg transition-colors disabled:opacity-50 shadow-sm cursor-pointer"
                                                                >
                                                                    "Remove method"
                                                                </button>
                                                                <button
                                                                    type="button"
                                                                    on:click=move |_| set_show_delete_totp_form.set(false)
                                                                    class="px-4 py-2 text-gray-600 dark:text-gray-400 text-sm font-medium hover:underline cursor-pointer"
                                                                >
                                                                    "Cancel"
                                                                </button>
                                                                {move || {
                                                                    disable_totp_action
                                                                        .pending()
                                                                        .get()
                                                                        .then_some(view! { <Spinner /> })
                                                                }}
                                                            </div>
                                                            {move || {
                                                                disable_totp_action
                                                                    .value()
                                                                    .get()
                                                                    .and_then(|res| res.err())
                                                                    .map(|err| {
                                                                        view! { <div class="mt-4"><Alert kind=AlertKind::Error message=err.to_string() /></div> }
                                                                    })
                                                            }}
                                                        </form>
                                                    </div>
                                                </Show>
                                            </Show>
                                        </div>

                                        // Recovery Codes Row
                                        <Show when=move || status.two_factor_enabled && status.totp_enabled>
                                            <div class="px-6 py-4">
                                                <div class="flex items-center justify-between">
                                                    <div class="flex items-center space-x-3">
                                                        <span class="material-symbols-outlined text-gray-400 dark:text-gray-500">
                                                            "settings_backup_restore"
                                                        </span>
                                                        <div>
                                                            <p class="text-sm font-medium text-gray-900 dark:text-white">
                                                                "Recovery codes"
                                                            </p>
                                                            <p class="text-xs text-gray-500 dark:text-gray-400">
                                                                "Fallback access via one-time codes."
                                                            </p>
                                                        </div>
                                                    </div>
                                                    <button
                                                        on:click=move |_| {
                                                            set_show_recovery_codes_form.update(|v| *v = !*v);
                                                            set_regenerated_codes.set(None);
                                                        }
                                                        class="text-sm font-medium text-blue-600 hover:text-blue-500 dark:text-blue-400 dark:hover:text-blue-300 cursor-pointer"
                                                    >
                                                        {move || if show_recovery_codes_form.get() { "Cancel" } else { "Regenerate" }}
                                                    </button>
                                                </div>

                                                <Show when=move || show_recovery_codes_form.get()>
                                                    <form
                                                        class="mt-6 space-y-4 max-w-md bg-gray-50 dark:bg-gray-900/50 p-4 rounded-lg border border-gray-100 dark:border-gray-700 shadow-sm"
                                                        on:submit=move |event: SubmitEvent| {
                                                            event.prevent_default();
                                                            let password = recovery_password.get_untracked();
                                                            if password.trim().is_empty() {
                                                                return;
                                                            }
                                                            regenerate_codes_action.dispatch(MfaAuthInput {
                                                                email: email.get_value(),
                                                                password,
                                                            });
                                                        }
                                                    >
                                                        <p class="text-xs text-gray-600 dark:text-gray-400 mb-4">
                                                            "Regenerating codes will invalidate your existing set. Enter your password to continue."
                                                        </p>
                                                        <div>
                                                            <label class="block mb-1 text-xs font-medium text-gray-700 dark:text-gray-300" for="recovery_password">
                                                                "Password"
                                                            </label>
                                                            <input
                                                                id="recovery_password"
                                                                type="password"
                                                                class="bg-white border border-gray-300 text-gray-900 text-sm rounded-lg focus:ring-blue-500 focus:border-blue-500 block w-full p-2.5 dark:bg-gray-700 dark:border-gray-600 dark:text-white"
                                                                required
                                                                on:input=move |event| set_recovery_password.set(event_target_value(&event))
                                                            />
                                                        </div>
                                                        <div class="pt-2 flex items-center gap-4">
                                                            <Button button_type="submit" disabled=regenerate_codes_action.pending()>
                                                                "Regenerate codes"
                                                            </Button>
                                                            {move || {
                                                                regenerate_codes_action
                                                                    .pending()
                                                                    .get()
                                                                    .then_some(view! { <Spinner /> })
                                                            }}
                                                        </div>
                                                        {move || {
                                                            regenerate_codes_action
                                                                .value()
                                                                .get()
                                                                .and_then(|res| res.err())
                                                                .map(|err| {
                                                                    view! { <div class="mt-4"><Alert kind=AlertKind::Error message=err.to_string() /></div> }
                                                                })
                                                        }}
                                                    </form>
                                                </Show>

                                                <Show when=move || regenerated_codes.get().is_some()>
                                                    <div class="mt-6 space-y-4">
                                                        <Alert kind=AlertKind::Info message="New recovery codes have been generated. Please save them in a safe place.".to_string() />
                                                        <div class="bg-white dark:bg-gray-800 p-4 rounded-lg border border-gray-200 dark:border-gray-700 shadow-inner">
                                                            <div class="grid grid-cols-2 gap-2 font-mono text-sm">
                                                                {move || regenerated_codes.get().unwrap_or_default().into_iter().map(|code| {
                                                                    view! { <div class="p-2 bg-gray-50 dark:bg-gray-900 rounded border border-gray-100 dark:border-gray-700 shadow-sm text-center">{code}</div> }
                                                                }).collect::<Vec<_>>()}
                                                            </div>
                                                        </div>
                                                        <button
                                                            on:click=move |_| set_regenerated_codes.set(None)
                                                            class="text-sm text-gray-500 hover:text-gray-700 dark:hover:text-gray-300 underline cursor-pointer"
                                                        >
                                                            "Close"
                                                        </button>
                                                    </div>
                                                </Show>
                                            </div>
                                        </Show>

                                        // Security Keys Row
                                        <div class="px-6 py-4">
                                            <div class="flex items-center justify-between">
                                                <div class="flex items-center space-x-3">
                                                    <span class="material-symbols-outlined text-gray-400 dark:text-gray-500">
                                                        "usb"
                                                    </span>
                                                    <div>
                                                        <p class="text-sm font-medium text-gray-900 dark:text-white">
                                                            "Security keys"
                                                        </p>
                                                        <p class="text-xs text-gray-500 dark:text-gray-400">
                                                            {move || match security_keys.get() {
                                                                Some(Ok(keys)) => format!("{} security keys configured", keys.len()),
                                                                _ => "0 security keys configured".to_string(),
                                                            }}
                                                        </p>
                                                    </div>
                                                </div>
                                                <button
                                                    on:click=move |_| {
                                                        set_show_add_key_form.update(|v| *v = !*v);
                                                        set_new_key_label.set(String::new());
                                                    }
                                                    class="text-sm font-medium text-blue-600 hover:text-blue-500 dark:text-blue-400 dark:hover:text-blue-300 cursor-pointer"
                                                >
                                                    {move || if show_add_key_form.get() { "Cancel" } else { "Add" }}
                                                </button>
                                            </div>

                                            <Show when=move || show_add_key_form.get()>
                                                <form
                                                    class="mt-6 space-y-4 max-w-md bg-gray-50 dark:bg-gray-900/50 p-4 rounded-lg border border-gray-100 dark:border-gray-700"
                                                    on:submit=move |event: SubmitEvent| {
                                                        event.prevent_default();
                                                        let label = new_key_label.get_untracked();
                                                        if label.trim().is_empty() {
                                                            return;
                                                        }
                                                        add_key_action.dispatch(label);
                                                    }
                                                >
                                                    <p class="text-xs text-gray-600 dark:text-gray-400 mb-4">
                                                        "Security keys are hardware devices that can be used as a second factor. Give your key a nickname to help you identify it later."
                                                    </p>
                                                    <div>
                                                        <label class="block mb-1 text-xs font-medium text-gray-700 dark:text-gray-300" for="key_label">
                                                            "Key nickname"
                                                        </label>
                                                        <input
                                                            id="key_label"
                                                            type="text"
                                                            placeholder="e.g. Blue YubiKey"
                                                            class="bg-white border border-gray-300 text-gray-900 text-sm rounded-lg focus:ring-blue-500 focus:border-blue-500 block w-full p-2.5 dark:bg-gray-700 dark:border-gray-600 dark:text-white"
                                                            required
                                                            on:input=move |event| set_new_key_label.set(event_target_value(&event))
                                                        />
                                                    </div>
                                                    <div class="pt-2 flex items-center gap-4">
                                                        <Button button_type="submit" disabled=add_key_action.pending()>
                                                            "Register hardware key"
                                                        </Button>
                                                        {move || {
                                                            add_key_action
                                                                .pending()
                                                                .get()
                                                                .then_some(view! { <Spinner /> })
                                                        }}
                                                    </div>
                                                    <p class="text-[10px] text-gray-500 dark:text-gray-400 mt-2">
                                                        "After clicking register, follow your browser's instructions to touch or insert your hardware key."
                                                    </p>
                                                    {move || {
                                                        add_key_action
                                                            .value()
                                                            .get()
                                                            .and_then(|res| res.err())
                                                            .map(|err| {
                                                                view! { <div class="mt-4"><Alert kind=AlertKind::Error message=err.to_string() /></div> }
                                                            })
                                                    }}
                                                </form>
                                            </Show>

                                            <Show when=move || {
                                                security_keys.get().map(|r| r.map(|keys| !keys.is_empty()).unwrap_or(false)).unwrap_or(false)
                                            }>
                                                <div class="mt-6 space-y-4 pb-4">
                                                    <h3 class="text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                                                        "Registered keys"
                                                    </h3>
                                                    <For
                                                        each=move || security_keys.get().and_then(|res| res.ok()).unwrap_or_default()
                                                        key=|key| key.credential_id.clone()
                                                        children={
                                                            let show_delete_key_form = show_delete_key_form.clone();
                                                            let delete_key_action = delete_key_action.clone();
                                                            move |key| {
                                                                let credential_id = key.credential_id.clone();
                                                                let label = key.label.clone();
                                                                let (show_menu, set_show_menu) = signal(false);

                                                                let credential_id_for_show = credential_id.clone();
                                                                let credential_id_for_delete = credential_id.clone();

                                                                view! {
                                                                    <div class="flex flex-col space-y-4">
                                                                        <div class="flex items-center justify-between bg-gray-50 dark:bg-gray-900/50 p-3 rounded-lg border border-gray-200 dark:border-gray-700 shadow-sm">
                                                                            <div class="flex items-center space-x-3">
                                                                                <span class="material-symbols-outlined text-gray-400 dark:text-gray-500 text-sm">
                                                                                    "key"
                                                                                </span>
                                                                                <div>
                                                                                    <p class="text-sm text-gray-700 dark:text-gray-300 font-medium">
                                                                                        {label}
                                                                                    </p>
                                                                                    <p class="text-[10px] text-gray-500 dark:text-gray-400">
                                                                                        "Registered on " {key.created_at}
                                                                                    </p>
                                                                                </div>
                                                                            </div>
                                                                            <div class="flex items-center space-x-4">
                                                                                <div class="relative inline-block text-left">
                                                                                    <button
                                                                                        type="button"
                                                                                        on:click=move |ev| {
                                                                                            ev.stop_propagation();
                                                                                            set_show_menu.update(|v| *v = !*v);
                                                                                        }
                                                                                        class="p-1 rounded-md hover:bg-white dark:hover:bg-gray-800 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 transition-colors shadow-sm border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800 cursor-pointer"
                                                                                    >
                                                                                        <span class="material-symbols-outlined text-xl">"more_horiz"</span>
                                                                                    </button>

                                                                                    <Show when=move || show_menu.get()>
                                                                                        <div
                                                                                            class="absolute right-0 z-20 mt-2 w-48 origin-top-right rounded-md bg-white dark:bg-gray-800 shadow-lg ring-1 ring-black ring-opacity-5 focus:outline-none border border-gray-200 dark:border-gray-700"
                                                                                            on:click=move |ev| ev.stop_propagation()
                                                                                            on:mouseleave=move |_| set_show_menu.set(false)
                                                                                        >
                                                                                            <div class="py-1">
                                                                                                <button
                                                                                                    type="button"
                                                                                                    on:click={
                                                                                                        let credential_id = credential_id.clone();
                                                                                                        move |_| {
                                                                                                            set_show_menu.set(false);
                                                                                                            set_show_delete_key_form.set(Some(credential_id.clone()));
                                                                                                        }
                                                                                                    }
                                                                                                    class="flex w-full items-center px-4 py-2 text-sm text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/20 cursor-pointer text-left"
                                                                                                >
                                                                                                    <span class="material-symbols-outlined mr-3 text-sm">"delete"</span>
                                                                                                    "Delete key"
                                                                                                </button>
                                                                                            </div>
                                                                                        </div>
                                                                                    </Show>
                                                                                </div>
                                                                            </div>
                                                                        </div>

                                                                        <Show when=move || show_delete_key_form.get() == Some(credential_id_for_show.clone())>
                                                                            <div class="px-2">
                                                                                <form
                                                                                    class="space-y-4 max-w-md bg-red-50 dark:bg-red-900/10 p-4 rounded-lg border border-red-100 dark:border-red-900/30"
                                                                                    on:submit={
                                                                                        let credential_id = credential_id_for_delete.clone();
                                                                                        let delete_key_action = delete_key_action.clone();
                                                                                        move |event: SubmitEvent| {
                                                                                            event.prevent_default();
                                                                                            let password = delete_key_password.get_untracked();
                                                                                            if password.trim().is_empty() {
                                                                                                return;
                                                                                            }
                                                                                            delete_key_action.dispatch((credential_id.clone(), password));
                                                                                        }
                                                                                    }
                                                                                >
                                                                                    <p class="text-xs text-red-700 dark:text-red-300 mb-4">
                                                                                        "Deleting this hardware key will remove it as a sign-in method. Please enter your password to confirm."
                                                                                    </p>
                                                                                    <div>
                                                                                        <label class="block mb-1 text-xs font-medium text-red-900 dark:text-red-200" for="delete_key_password">
                                                                                            "Password"
                                                                                        </label>
                                                                                        <input
                                                                                            id="delete_key_password"
                                                                                            type="password"
                                                                                            class="bg-white border border-red-200 text-gray-900 text-sm rounded-lg focus:ring-red-500 focus:border-red-500 block w-full p-2 dark:bg-gray-800 dark:border-red-900/50 dark:text-white"
                                                                                            required
                                                                                            on:input=move |event| set_delete_key_password.set(event_target_value(&event))
                                                                                        />
                                                                                    </div>
                                                                                    <div class="pt-2 flex items-center gap-3">
                                                                                        <button
                                                                                            type="submit"
                                                                                            disabled=delete_key_action.pending()
                                                                                            class="px-4 py-2 bg-red-600 hover:bg-red-700 text-white text-sm font-medium rounded-lg transition-colors disabled:opacity-50 shadow-sm cursor-pointer"
                                                                                        >
                                                                                            "Remove key"
                                                                                        </button>
                                                                                        <button
                                                                                            type="button"
                                                                                            on:click=move |_| set_show_delete_key_form.set(None)
                                                                                            class="px-4 py-2 text-gray-600 dark:text-gray-400 text-sm font-medium hover:underline cursor-pointer"
                                                                                        >
                                                                                            "Cancel"
                                                                                        </button>
                                                                                        {move || {
                                                                                            delete_key_action.pending().get().then_some(view! { <Spinner /> })
                                                                                        }}
                                                                                    </div>
                                                                                    {move || {
                                                                                        delete_key_action
                                                                                            .value()
                                                                                            .get()
                                                                                            .and_then(|res| res.err())
                                                                                            .map(|err| {
                                                                                                view! { <div class="mt-4"><Alert kind=AlertKind::Error message=err.to_string() /></div> }
                                                                                            })
                                                                                    }}
                                                                                </form>
                                                                            </div>
                                                                        </Show>
                                                                    </div>
                                                                }
                                                            }
                                                        }
                                                    />
                                                </div>
                                            </Show>
                                        </div>
                                    </div>
                                </section>
                            </div>
                        }.into_any()
                    }
                    (Some(Err(err)), _) => {
                        view! { <Alert kind=AlertKind::Error message=err.to_string() /> }
                            .into_any()
                    }
                    _ => view! { <Spinner /> }.into_any(),
                }}
            </Suspense>
        </div>
    }
}
