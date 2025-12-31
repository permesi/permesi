mod dashboard;
mod health;
mod login;
mod not_found;
mod signup;
mod users;
mod verify_email;

pub(crate) use dashboard::DashboardPage;
pub(crate) use health::HealthPage;
pub(crate) use login::LoginPage;
pub(crate) use not_found::NotFoundPage;
pub(crate) use signup::SignUpPage;
pub(crate) use users::{UserDetailPage, UsersListPage};
pub(crate) use verify_email::VerifyEmailPage;

use leptos::prelude::*;
use leptos_router::components::{Route, Routes};
use leptos_router::path;

#[component]
pub fn AppRoutes() -> impl IntoView {
    view! {
        <Routes fallback=|| view! { <NotFoundPage /> }>
            <Route path=path!("/") view=DashboardPage />
            <Route path=path!("/health") view=HealthPage />
            <Route path=path!("/login") view=LoginPage />
            <Route path=path!("/signup") view=SignUpPage />
            <Route path=path!("/verify-email") view=VerifyEmailPage />
            <Route path=path!("/users") view=UsersListPage />
            <Route path=path!("/users/:id") view=UserDetailPage />
            <Route path=path!("/*any") view=NotFoundPage />
        </Routes>
    }
}
