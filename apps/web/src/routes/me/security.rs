//! Security settings route for the authenticated user. Small sections own password
//! rotation, passkeys, authenticator settings, hardware keys and recovery codes.
//! The route resolves the current profile and passes only its presentation state.
//!
//! Flow Overview: Password and factor mutations first prove the current password
//! through OPAQUE or a `WebAuthn` ceremony, then call the server mutation API.
//! Server-side recent-authentication and factor policy remain authoritative;
//! browser state never grants permission. Password rotation clears the old session.

mod authenticator;
mod display;
mod passkeys;
mod password;
mod recovery;
mod security_keys;

use self::{
    authenticator::AuthenticatorSection, passkeys::PasskeysSection, password::PasswordSection,
    recovery::RecoveryCodesSection, security_keys::SecurityKeysSection,
};
use crate::{
    app_lib::{AppError, theme::Theme},
    components::{Alert, AlertKind, Spinner},
    features::me::client,
    routes::paths,
};
use leptos::prelude::*;
use leptos_router::hooks::use_navigate;

/// Gives a useful recovery path when the server's recent-authentication guard rejects a factor change.
fn factor_mutation_error(error: &AppError) -> String {
    if matches!(error, AppError::Http { status: 401, .. }) {
        "Sign in again before changing authentication factors.".to_string()
    } else {
        error.to_string()
    }
}

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SecurityStatus {
    pub password_configured: bool,
    pub passkey_count: u32,
    pub two_factor_enabled: bool,
    pub totp_enabled: bool,
}

#[derive(Clone)]
struct MfaAuthInput {
    email: String,
    password: String,
}

#[component]
pub fn MeSecurityPage() -> impl IntoView {
    let profile = LocalResource::new(move || async move { client::fetch_me().await });
    let security_status = Memo::new(move |_| {
        profile
            .get()
            .and_then(std::result::Result::ok)
            .map(|me| SecurityStatus {
                password_configured: true, // Always true for now as we only support password auth
                passkey_count: 0,
                two_factor_enabled: me.mfa_enabled,
                totp_enabled: me.totp_enabled,
            })
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

                        view! {
                            <div class="space-y-8">
                                // Sign-in methods section
                                <section class="space-y-4">
                                    <h2 class="text-lg font-medium text-gray-900 dark:text-white px-1">
                                        "Sign-in methods"
                                    </h2>
                                    <div class="border border-gray-200 dark:border-gray-700 rounded-lg overflow-hidden bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
                                        <PasswordSection email configured=status.password_configured />

                                        <PasskeysSection />
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
                                        <div class=Theme::ROW>
                                            <div class="flex items-center justify-between">
                                                <div class="flex items-center space-x-3">
                                                    <span class=Theme::ICON>
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
                                                                    navigate(paths::MFA_SETUP, leptos_router::NavigateOptions::default());
                                                                }
                                                                class="text-sm font-medium text-gray-700 dark:text-gray-200 bg-white dark:bg-gray-900 border border-gray-300 dark:border-gray-600 rounded-md px-3 py-1.5 hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors cursor-pointer"
                                                            >
                                                                "Add"
                                                            </button>
                                                        }
                                                    }
                                                </Show>
                                            </div>
                                        </div>

                                        <AuthenticatorSection email enabled=status.two_factor_enabled totp_enabled=status.totp_enabled profile />

                                        <SecurityKeysSection />

                                        <RecoveryCodesSection email enabled=status.two_factor_enabled && status.totp_enabled />
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
