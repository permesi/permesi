use crate::features::auth::types::UserSession;
use leptos::prelude::*;

#[derive(Clone)]
pub struct AuthContext {
    pub session: RwSignal<Option<UserSession>>,
    pub is_authenticated: Signal<bool>,
}

impl AuthContext {
    fn new(session: RwSignal<Option<UserSession>>) -> Self {
        let is_authenticated = Signal::derive(move || session.get().is_some());
        Self {
            session,
            is_authenticated,
        }
    }

    pub fn set_session(&self, session: UserSession) {
        self.session.set(Some(session));
    }
}

#[component]
pub fn AuthProvider(children: Children) -> impl IntoView {
    let session = RwSignal::new(None);
    let auth = AuthContext::new(session);
    provide_context(auth);

    view! { {children()} }
}

pub fn use_auth() -> AuthContext {
    use_context::<AuthContext>().unwrap_or_else(|| {
        let session = RwSignal::new(None);
        AuthContext::new(session)
    })
}
