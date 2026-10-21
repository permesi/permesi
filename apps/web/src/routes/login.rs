//! Login route that implements the client-side OPAQUE exchange. It keeps passwords
//! local, uses zero-token headers for permesi calls, and hydrates session state
//! via cookie-based auth.
//!
//! Flow Overview: Start OPAQUE with the server, finish the exchange, then fetch
//! the session and redirect to the home route.

mod passkey;
mod password;

use crate::{
    components::{Alert, AlertKind, AlreadySignedInPanel},
    features::auth::{
        state::use_auth,
        types::{SessionKind, UserSession},
    },
    routes::paths,
};
use leptos::prelude::*;
use password::LoginForm;

/// Session returned after the server has established its authentication cookie.
#[derive(Clone)]
struct LoginResult {
    session: UserSession,
}

/// Renders the login form and drives the OPAQUE login flow.
/// On success it fetches the session cookie and updates auth state.
#[component]
pub fn LoginPage() -> impl IntoView {
    let auth = use_auth();
    let expired_authorization = crate::features::auth::authorization::expired_request_hint();
    view! {
        {move || {
            if auth.is_authenticated.get() {
                view! {
                    {expired_authorization.then(|| view! { <Alert kind=AlertKind::Info message="The authorization request expired. Start sign-in again from the application; this login cannot resume it.".to_owned() /> })}
                    <AlreadySignedInPanel />
                }.into_any()
            } else {
                view! { <LoginForm expired_authorization /> }.into_any()
            }
        }}
    }
}

/// Applies only a server-issued session and follows its full or limited session kind.
fn accept_login<N>(
    auth: crate::features::auth::state::AuthContext,
    navigate: N,
    session: &UserSession,
) where
    N: Fn(&str, leptos_router::NavigateOptions),
{
    auth.set_session(session.clone());
    match session.session_kind {
        SessionKind::Full => {
            if let Some(storage) = web_sys::window()
                .and_then(|w| w.local_storage().ok())
                .flatten()
            {
                let _ = storage.set_item("permesi_logged_in", "true");
            }
            navigate(paths::DASHBOARD, leptos_router::NavigateOptions::default());
        }
        SessionKind::MfaBootstrap => {
            navigate(paths::MFA_SETUP, leptos_router::NavigateOptions::default());
        }
        SessionKind::MfaChallenge => {
            navigate(
                paths::MFA_CHALLENGE,
                leptos_router::NavigateOptions::default(),
            );
        }
    }
}
