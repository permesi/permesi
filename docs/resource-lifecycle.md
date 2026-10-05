# Tenant resource lifecycle

Permesi's tenant hierarchy is Organization → Project → Environment → Application.
Applications own OAuth clients and their delegated scope registry. Resources are
soft-deleted explicitly from the bottom up; no endpoint recursively deletes a
populated tenant hierarchy. Existing rows and historical bindings remain in PostgreSQL.

Delete each application's OAuth clients first, including disabled registrations.
The existing client deletion transaction disables and soft-deletes the client and
permanently revokes its credentials and saved consent. The application can then be
deleted. Immutable OIDC registry entries (`openid`, `profile`, `email`, `address`,
`phone`, `offline_access`) and application scope descriptions are retained metadata
and do not block application deletion. Keeping client deletion explicit reuses the
reviewed OAuth revocation lifecycle and prevents an application action from silently
destroying several independently configured integrations.

Delete all active applications before deleting an environment, all active environments
before deleting a project, and all active projects before deleting an organization.
Each populated parent returns 409 with its immediate child type. Soft-deleted children
do not block their parent, and deletion never physically removes a row. Normal tenant
resolution and OAuth management filter deleted ancestors; authorization, pending
consent and transactional code redemption reject inactive ancestry and revoked clients.
Outstanding authorization codes do not regain validity if a name or slug is reused.

## API and authorization

| DELETE endpoint | Required empty child set | Organization role |
| --- | --- | --- |
| `/v1/orgs/{org_slug}/projects/{project_slug}/envs/{env_slug}/apps/{app_id}` | Undeleted OAuth clients, including disabled clients | Owner or admin |
| `/v1/orgs/{org_slug}/projects/{project_slug}/envs/{env_slug}` | Active applications | Owner or admin |
| `/v1/orgs/{org_slug}/projects/{project_slug}` | Active environments | Owner or admin |
| `/v1/orgs/{org_slug}` | Active projects | Owner only, with recent authentication |

All operations require an active user account, a full authenticated session and current
active organization membership. Platform administrator permissions do not bypass tenant
roles. Missing or unsuitable sessions return 401; inaccessible, foreign, deleted and
repeated targets return 404. Successful deletion returns 204. Organization deletion reuses the existing
ten-minute recent-authentication policy used for high-risk account operations; a
stale authentication returns the stable `reauthentication_required` error code and
the owner must sign in again. Production errors use the standard JSON envelope.

Deletion locks ancestry from the organization toward the target inside one PostgreSQL
transaction. Ancestors use SHARE locks, the target uses UPDATE, and current membership
and role rows, plus the active user row, remain locked through commit. The immediate-child
check happens after the target lock is acquired. Project, environment and application
creation hold SHARE locks on active parents in their own insertion transactions; OAuth client/scope creation
likewise rechecks and locks application ancestry. For hierarchy children and OAuth
clients, PostgreSQL serialization guarantees that creation wins and deletion returns
409, or deletion wins and creation returns 404. Scope creation also rejects a deletion
that wins first; a scope created before deletion remains retained metadata and does
not prevent application deletion.
This works across independent replicas without local state. The coordination is in
the API storage layer; arbitrary administrative SQL is not a supported lifecycle API.

## Console

Each resource page has a separate Danger Zone. Immediate-child blockers explain the
next necessary action. A native Dialog requires the exact application name or resource
slug, preserves errors and typed confirmation after a failed request, and prevents
dismissal during a pending mutation. A 409 refreshes the immediate-child list while
preserving the dialog's error and typed confirmation. After success the console navigates
to the parent and loads its current collection; organization deletion returns to `/console/orgs`.
Browser emptiness checks are usability hints, and the backend enforces current state.

OAuth scope actions use the existing Material Symbols `edit` and `delete` alongside
visible labels. Delete has destructive light/dark styling and both actions remain
keyboard accessible. System OIDC entries remain read-only.

The current phase adds no restore, purge, resource move or recursive cascade API.
Token issuance and refresh-token policy remain separate OAuth milestones. Sustained
load testing and bounded ancestor-writer coordination remain part of the operations
roadmap; row locks establish lifecycle consistency, not a production latency guarantee.
The current organization DTOs omit roles, so action visibility is a usability hint:
the page explains the required role and the backend enforces it with 404. Permission-aware
button visibility would require a separate server-issued capability contract.

## Validation and review

Database regressions establish both queue orders for child/client creation against
deletion, recheck membership, management roles and user status after waits, and pin
the resolved organization UUID across committed slug reuse. Mutation checks demonstrate
that the child-creation race, disabled-user and slug-pin regressions fail without their
guards. Authorization tests reject pending consent and outstanding codes after teardown,
including redemption through an independent PostgreSQL pool.

Workspace tests, formatting, Clippy, schema verification, native builds, OpenAPI
consistency, the release WASM build and Chromium tests pass. Browser coverage includes
keyboard/focus, dark/mobile scope actions, typed confirmation, pending-dialog protection,
409 child-list refresh, recent-authentication guidance and parent navigation.
Claude reviewed the implementation and corrections through Herdr in three rounds.
Accepted fixes cover user-status locking, accurate reauthentication errors, missing
negative tests, conflict refresh and precise documentation. The final review reported
no remaining defects; bounded coordination and permission-aware visibility remain
explicitly tracked follow-ups.
