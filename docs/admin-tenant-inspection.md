# Read-only platform tenant inspection

The admin dashboard Organizations card and Platform Admin → Global Organizations
open `/console/admin/orgs`. Enabled platform operators can inspect every active
organization, project, environment and application without joining those tenants.
The separate Workspace → Organizations page continues to list only the signed-in
user's active memberships and retains its existing tenant-management controls.

## Flow and authorization

The existing admin UI requires operator status and a live elevation. Each
inspection API request independently requires a valid full-session cookie and the
current database-derived `platform:admin` capability, represented internally by
`InspectTenants`. The API follows the global user-data session boundary and does
not require an elevation. Global user roles, organization roles and delegated
OAuth scopes do not grant inspection authority. Disabled operators, suspended
accounts, expired/revoked sessions and limited MFA sessions cannot read the data.

The new GET-only hierarchy starts at `/v1/admin/orgs`, with organization detail,
`projects`, project detail, `envs`, environment detail, `apps` and application
detail under the complete parent path. Responses allow only IDs, names, creation
dates, slugs where applicable and environment tiers. They expose no credentials,
membership information or OAuth configuration. All responses use `Cache-Control:
no-store`, including extraction, authorization and unsupported-method errors.

Each query checks active ancestry. Deleted resources and children of deleted
parents are hidden; missing or mismatched paths return 404. Collections use pages
of 50 ordered by creation time and UUID descending. An optional `after` UUID is
resolved inside the same active collection; malformed, missing or foreign cursor
anchors return 400. A `next_cursor` indicates another page. Refresh restarts at
the first page if a cursor becomes stale during concurrent deletion.

The console shows read-only breadcrumbs, metadata, pagination and error/empty
states. Its data and cursor state are isolated by path and signed-in identity.
Inspection creates no memberships and grants no tenant write authority. Existing
tenant-owner/member APIs still enforce their own roles, recent-authentication
requirements and deletion ordering. Cross-tenant administrative deletion remains
outside this feature.

## Regression protection

The production-router PostgreSQL tests seed operator-owned and foreign tenants.
They require visibility through the foreign hierarchy while checking that the
operator's ordinary organization list remains membership-scoped and foreign reads
and writes through tenant-management routes remain rejected. Protected tenant rows,
memberships and roles are compared before and after inspection/rejected mutations.
Other cases cover non-operator global roles, retired/limited authority, deleted
ancestry, substituted application IDs, cache policy and every collection's page
boundaries with equal timestamps.

`admin_inspection_browser_real_postgres` uses compiled WASM, actual sessions and
operator authorization, the production router and PostgreSQL. Only the external
OpenBao step-up lookup is simulated. It checks the dashboard target, global paging,
foreign-resource navigation, absence of write controls, ordinary owner controls
and retirement of displayed data after a rejected read. The test runs explicitly
through `just web-test-browser-built` beside the existing OAuth console,
authorization and OPAQUE tenant-deletion browser coverage. Missing test discovery,
dependency setup failure or a skipped browser test does not establish coverage.

The OpenAPI contract also includes a regression verifying that administrator
inspection operations use unique `admin_*` operation IDs without shadowing existing
tenant-management operation IDs.
