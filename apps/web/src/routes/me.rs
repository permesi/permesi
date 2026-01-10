//! Account route for the authenticated user's profile.

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

#[derive(Clone)]
struct ChangePasswordInput {
    email: String,
    current_password: String,
    new_password: String,
}

/// Renders the current user's profile.
#[component]
pub fn MePage() -> impl IntoView {
    let auth = use_auth();
    let navigate = use_navigate();
    let profile = LocalResource::new(move || async move { client::fetch_me().await });
    let (current_password, set_current_password) = signal(String::new());
    let (new_password, set_new_password) = signal(String::new());
    let (confirm_password, set_confirm_password) = signal(String::new());
    let (password_error, set_password_error) = signal::<Option<AppError>>(None);

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
        <div class="block rounded-lg border border-neutral-200 bg-white p-6 dark:border-neutral-300 dark:bg-neutral-600 space-y-4">
            <h1 class="text-lg font-semibold text-gray-900 dark:text-white">
                "Me"
            </h1>
            <Suspense fallback=move || view! { <Spinner /> }>
                {move || match profile.get() {
                    Some(Ok(me)) => {
                        let display_name = me
                            .display_name
                            .clone()
                            .unwrap_or_else(|| "Not set".to_string());
                        let role_list = if me.roles.is_empty() {
                            "user".to_string()
                        } else {
                            me.roles.join(", ")
                        };
                        let on_submit = {
                            let email = me.email.clone();
                            move |event: SubmitEvent| {
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
                            }
                        };
                        view! {
                            <div class="space-y-4">
                                <div>
                                    <span class="block text-sm font-medium text-gray-500 dark:text-gray-200">
                                        "Email"
                                    </span>
                                    <div class="text-gray-900 dark:text-white">
                                        {me.email}
                                    </div>
                                </div>
                                <div>
                                    <span class="block text-sm font-medium text-gray-500 dark:text-gray-200">
                                        "Display name"
                                    </span>
                                    <div class="text-gray-900 dark:text-white">
                                        {display_name}
                                    </div>
                                </div>
                                <div>
                                    <span class="block text-sm font-medium text-gray-500 dark:text-gray-200">
                                        "Roles"
                                    </span>
                                    <div class="text-gray-900 dark:text-white">
                                        {role_list}
                                    </div>
                                </div>
                                <div class="pt-4 border-t border-neutral-200 dark:border-neutral-500 space-y-4">
                                    <div>
                                        <span class="block text-sm font-medium text-gray-500 dark:text-gray-200">
                                            "Change password"
                                        </span>
                                        <p class="text-xs text-gray-500 dark:text-gray-300">
                                            "Requires your current password and signs out all active sessions."
                                        </p>
                                    </div>
                                    <form class="space-y-3" on:submit=on_submit>
                                        <div>
                                            <label class="block mb-1 text-sm font-medium text-gray-500 dark:text-gray-200" for="current_password">
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
                                            <label class="block mb-1 text-sm font-medium text-gray-500 dark:text-gray-200" for="new_password">
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
                                            <label class="block mb-1 text-sm font-medium text-gray-500 dark:text-gray-200" for="confirm_password">
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
                                        <Button button_type="submit" disabled=change_password_action.pending()>
                                            "Update password"
                                        </Button>
                                        {move || {
                                            change_password_action
                                                .pending()
                                                .get()
                                                .then_some(view! { <div class="mt-2"><Spinner /></div> })
                                        }}
                                        {move || {
                                            password_error
                                                .get()
                                                .map(|err| {
                                                    view! { <Alert kind=AlertKind::Error message=err.to_string() /> }
                                                })
                                        }}
                                    </form>
                                </div>
                            </div>
                        }
                        .into_any()
                    }
                    Some(Err(err)) => {
                        view! { <Alert kind=AlertKind::Error message=err.to_string() /> }
                            .into_any()
                    }
                    None => view! { <Spinner /> }.into_any(),
                }}
            </Suspense>
        </div>
    }
}
