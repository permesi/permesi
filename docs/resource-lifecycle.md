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
the console offers inline password verification. Verification only refreshes authentication
time; a separate explicit confirmation is still required. Production errors use the standard JSON envelope.

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

`GET /v1/orgs/{org_slug}/capabilities` requires a full active session and active membership.
It returns only `organization_id`, `can_manage_resources` (owner/admin) and
`can_delete_organization` (owner), with `Cache-Control: no-store` on every response produced by the handler.
Framework path-extraction errors contain no capability hints and bypass the handler.
These flags describe role eligibility, not emptiness or recent authentication, and never
supply authority to a mutation. Raw roles and internal platform permissions are omitted.

Organization DELETE accepts the optional `X-Permesi-Expected-Organization-Id` UUID header.
The console always sends the originally confirmed organization ID; a slug resolving to
a different UUID returns 404, malformed or repeated headers return 400. The condition
only narrows an already authorized target. Existing clients omitting it remain compatible,
and the usual UUID pin inside the deletion transaction remains enforced. The configured
CORS allow-list permits this header without broadening allowed origins.

Each eligible resource page has a separate Danger Zone. Controls remain hidden until
capabilities load: members/read-only users see none, admins see child-resource actions,
and owners may see organization deletion. Immediate-child blockers explain the
next necessary action. A native Dialog requires the exact application name or resource
slug, preserves errors and typed confirmation on conflicts and transient deletion failures, and prevents
dismissal during a pending mutation. A 409 refreshes the immediate-child list while
preserving the dialog's error and typed confirmation. After success the console navigates
to the parent and loads its current collection; organization deletion returns to `/console/orgs`.
Capability hints refresh when a confirmation opens and after authorization failures.
Changed account/organization identity or lost eligibility closes the dialog and clears
the draft; permission loss is announced by an alert outside the dialog. A failed
capability refresh also hides the action until the page is reloaded, except a transient
failure during password verification keeps a recoverable password step that cannot submit DELETE.
Organization recent-authentication errors open a password step in the same Dialog. The
existing admission-protected OPAQUE start/finish handlers verify the password without
receiving plaintext, then the console reloads session identity, capabilities and projects.
Successful verification preserves the typed slug and returns focus to confirmation; it
never automatically retries DELETE. Auto-repeated Enter is ignored in the form so a
held password-submit key cannot confirm deletion; a fresh Enter press remains accessible.
New projects block confirmation, loss of the owner
role closes it, and changed accounts or organization IDs invalidate the draft. Stale
responses after route/account changes are ignored. Password fields clear on every
attempt, cancellation and unmount; passwords are absent from URLs, storage and logs.
Browser checks remain usability hints, and the backend enforces current state.

OAuth scope actions use the existing Material Symbols `edit` and `delete` alongside
visible labels. Delete has destructive light/dark styling and both actions remain
keyboard accessible. System OIDC entries remain read-only.

The current phase adds no restore, purge, resource move or recursive cascade API.
Token issuance and refresh-token policy remain separate OAuth milestones. Sustained
load testing and bounded ancestor-writer coordination remain part of the operations
roadmap; row locks establish lifecycle consistency, not a production latency guarantee.
Existing organization metadata DTOs continue to omit roles; the separate capability
contract supplies presentation hints without changing mutation authorization.

OPAQUE exchange state for login and reauthentication is bounded and single-use but
currently process-local. Start/finish reaching different replicas can fail; this phase
adds no sticky-session mechanism and does not claim shared authentication exchanges.
Migrating that state to transactional shared storage is tracked separately in TODO.md.
OAuth authorization requests/codes and tenant lifecycle coordination remain PostgreSQL-backed.

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
409 child-list refresh and parent navigation. Additional real OPAQUE/PostgreSQL browser
coverage exercises password rejection, throttle/unavailable responses, explicit post-proof
confirmation, new children, role loss, account changes and committed slug reuse.
The earlier lifecycle implementation received three independent Claude/Herdr reviews.
The capability/reauthentication extension's first review found no critical, high or
medium defects, and identified missing permission-loss feedback and stale failure-flow
documentation. Both were corrected. An informational held-Enter concern was independently
reproduced in real Chromium: a trusted repeat event submitted another DELETE after
password proof. The regression failed before the repeat-key guard, and now checks both
rejection of repeat Enter and successful fresh Enter confirmation. The second independent
review verified the corrected diff and found no remaining critical, high, medium or low
defects. Its documentation observation about recoverable password-step failures was
verified against the state machine and corrected; accepting a fresh deliberate Enter
press after successful verification remains the explicit confirmation policy.

The corrected workspace suites pass 509 tests with default features and 539 with all
features. Their two ignored real browser tests are run explicitly and pass through
`just web-test-browser`, alongside the console browser suite. Formatting, native Clippy,
both native builds, PostgreSQL schema verification, OpenAPI generation/consistency,
native Web checks and the release WASM build pass.

The remaining informational observations have explicit scope limits. Organization DELETE
authorizes the current cookie account even if another tab switched it after the final
refresh; only an owner of the pinned UUID with recent authentication can succeed. An
optional expected-account condition and UUID guards for slug-addressed child deletion
remain future UX hardening, without weakening current server authorization. Ambiguous
DELETE timeouts need explicit reconciliation and capability failures currently require
a page reload. These usability follow-ups are tracked in TODO.md.

Browser tests run explicitly during local validation; current CI builds WASM and runs
the native/database suites but has no browser-test job. Adding that gate is tracked
separately. Four other security-settings flows still contain inline OPAQUE exchanges;
sharing their helper is outside this focused milestone. Bounded ancestor coordination
and durable OPAQUE exchanges remain separate roadmap items.
