//! User route group re-exported by the top-level routing module.

mod detail;
mod list;

pub(crate) use detail::UserDetailPage;
pub(crate) use list::UsersListPage;
