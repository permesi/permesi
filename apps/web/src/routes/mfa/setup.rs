//! MFA Setup route.
//!
//! Handles TOTP enrollment:
//! 1. Fetch enrollment data (secret + QR code).
//! 2. Display QR code to the user.
//! 3. Verify the first TOTP token.
//! 4. Display recovery codes.

use crate::{
    app_lib::AppError,
    components::{Alert, AlertKind, Button, Spinner},
    features::auth::{
        client,
        state::use_auth,
        types::{MfaTotpEnrollFinishRequest, RecoveryCodesResponse},
    },
    routes::paths,
};
use leptos::prelude::*;
use leptos_router::hooks::use_navigate;

#[component]
pub fn MfaSetupPage() -> impl IntoView {
    let _auth = use_auth();
    let navigate = use_navigate();
    let navigate_for_success = navigate.clone();
    let (code, set_code) = signal(String::new());

    let (error, set_error) = signal::<Option<AppError>>(None);
    let (recovery_codes, set_recovery_codes) = signal::<Option<RecoveryCodesResponse>>(None);

    let enroll_data =
        LocalResource::new(move || async move { client::mfa_totp_enroll_start().await });

    let enroll_finish_action =
        Action::new_local(move |(code, credential_id): &(String, String)| {
            let code = code.clone();
            let credential_id = credential_id.clone();
            async move {
                let (recovery_codes, session_token) =
                    client::mfa_totp_enroll_finish(&MfaTotpEnrollFinishRequest {
                        code,
                        credential_id,
                    })
                    .await?;

                // After successful enrollment, fetch the new full session using the updated token
                let session = client::fetch_session(session_token.as_deref())
                    .await?
                    .ok_or_else(|| {
                        AppError::Config("Enrollment succeeded but session not found.".to_string())
                    })?;

                Ok::<
                    (
                        RecoveryCodesResponse,
                        crate::features::auth::types::UserSession,
                        Option<String>,
                    ),
                    AppError,
                >((recovery_codes, session, session_token))
            }
        });

    Effect::new(move |_| {
        if let Some(Ok((codes, session, session_token))) = enroll_finish_action.value().get() {
            set_recovery_codes.set(Some(codes));
            _auth.set_session(session);
            if let Some(token) = session_token {
                _auth.set_session_token(token);
            }
        } else if let Some(Err(err)) = enroll_finish_action.value().get() {
            set_error.set(Some(err));
        }
    });

    view! {
        <div class="max-w-md mx-auto space-y-8 py-8">
            <div class="text-center">
                <h1 class="text-2xl font-bold text-gray-900 dark:text-white">
                    "Setup Multi-Factor Authentication"
                </h1>
                <p class="mt-2 text-gray-600 dark:text-gray-400">
                    "Protect your account with a second factor."
                </p>
            </div>

            {move || {
                if let Some(codes) = recovery_codes.get() {
                    let navigate_for_success = navigate_for_success.clone();
                    view! {
                        <div class="space-y-6">
                            <Alert kind=AlertKind::Info message="MFA has been successfully enabled. Please save these recovery codes in a safe place. You will need them if you lose access to your authenticator app.".to_string() />
                            <div class="bg-gray-50 dark:bg-gray-800 p-4 rounded-lg border border-gray-200 dark:border-gray-700">
                                <div class="grid grid-cols-2 gap-2 font-mono text-sm">
                                    {codes.codes.into_iter().map(|code| view! { <div class="p-2 bg-white dark:bg-gray-900 rounded border border-gray-100 dark:border-gray-700 shadow-sm">{code}</div> }).collect::<Vec<_>>()}
                                </div>
                            </div>
                            <Button on:click=move |_| navigate_for_success(paths::DASHBOARD, Default::default())>
                                "I've saved my codes - Go to Dashboard"
                            </Button>
                        </div>
                    }.into_any()
                } else {
                    match enroll_data.get() {
                        Some(Ok(data)) => {
                            let credential_id = data.credential_id.clone();
                            view! {
                                <div class="space-y-6">
                                    <div class="flex justify-center bg-white p-4 rounded-lg">
                                        <img src=data.qr_code_url alt="MFA QR Code" class="w-64 h-64" />
                                    </div>
                                    <div class="text-center space-y-1">
                                        <p class="text-sm text-gray-600 dark:text-gray-400">
                                            "Scan this QR code with your authenticator"
                                        </p>
                                        <p class="text-xs text-gray-500 dark:text-gray-400">
                                            "(like "
                                            <a href="https://ente.io/auth" target="_blank" rel="noopener noreferrer" class="text-blue-500 hover:underline">"Ente Auth"</a>
                                            ", "
                                            <a href="https://authy.com/" target="_blank" rel="noopener noreferrer" class="text-blue-500 hover:underline">"Authy"</a>
                                            ")"
                                        </p>
                                        <p class="text-xs font-mono text-gray-500 break-all pt-2">
                                            "Secret: " {data.secret}
                                        </p>
                                    </div>

                                    <div class="space-y-4">
                                        <div>
                                            <label class="block mb-2 text-sm font-medium text-gray-900 dark:text-white">
                                                "Verification Code"
                                            </label>
                                            <input
                                                type="text"
                                                class="bg-gray-50 border border-gray-300 text-gray-900 text-sm rounded-lg focus:ring-blue-500 focus:border-blue-500 block w-full p-2.5 dark:bg-gray-700 dark:border-gray-600 dark:text-white"
                                                on:input=move |ev| set_code.set(event_target_value(&ev))
                                            />
                                        </div>
                                        <Button
                                            disabled=enroll_finish_action.pending()
                                            on:click={
                                                let credential_id = credential_id.clone();
                                                move |_| { enroll_finish_action.dispatch((code.get(), credential_id.clone())); }
                                            }
                                        >
                                            "Verify and Enable"
                                        </Button>

                                        {move || {
                                            enroll_finish_action.pending().get().then_some(view! { <Spinner /> })
                                        }}
                                        {move || {
                                            error.get().map(|err| view! { <Alert kind=AlertKind::Error message=err.to_string() /> })
                                        }}
                                    </div>
                                </div>
                            }.into_any()
                        }
                        Some(Err(err)) => {
                            view! { <Alert kind=AlertKind::Error message=err.to_string() /> }.into_any()
                        }
                        None => {
                            view! { <Spinner /> }.into_any()
                        }
                    }
                }
            }}
        </div>
    }
}
