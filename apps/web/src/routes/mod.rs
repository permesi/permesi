//! Frontend route definitions wired into the root `App` component. Routing is
//! client-side only, so backend endpoints must enforce access control.

mod admin;
mod admin_claim;
mod dashboard;
mod health;
mod login;
mod me;
mod not_found;
mod orgs;
mod signup;
mod users;
mod verify_email;

pub(crate) use admin::AdminPage;
pub(crate) use admin_claim::AdminClaimPage;
pub(crate) use dashboard::DashboardPage;
pub(crate) use health::HealthPage;
pub(crate) use login::LoginPage;
pub(crate) use me::MePage;
pub(crate) use not_found::NotFoundPage;
pub(crate) use orgs::{OrgDetailPage, OrgsListPage, ProjectDetailPage};
pub(crate) use signup::SignUpPage;
pub(crate) use users::{UserDetailPage, UsersListPage};
pub(crate) use verify_email::VerifyEmailPage;

use leptos::prelude::*;
use leptos_router::{
    components::{Route, Routes},
    path,
};

/// Declares the application route tree.
#[component]
pub fn AppRoutes() -> impl IntoView {
    view! {
        <Routes fallback=|| view! { <NotFoundPage /> }>
            <Route path=path!("/") view=DashboardPage />
            <Route path=path!("/health") view=HealthPage />
            <Route path=path!("/login") view=LoginPage />
            <Route path=path!("/signup") view=SignUpPage />
            <Route path=path!("/verify-email") view=VerifyEmailPage />
            <Route path=path!("/me") view=MePage />
            <Route path=path!("/admin") view=AdminPage />
            <Route path=path!("/admin/claim") view=AdminClaimPage />
            <Route path=path!("/orgs") view=OrgsListPage />
            <Route path=path!("/orgs/:slug") view=OrgDetailPage />
            <Route path=path!("/orgs/:slug/projects/:project_slug") view=ProjectDetailPage />
            <Route path=path!("/users") view=UsersListPage />
            <Route path=path!("/users/:id") view=UserDetailPage />
            <Route path=path!("/*any") view=NotFoundPage />
        </Routes>
    }
}
