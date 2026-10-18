# Bounded tenant mutations

Hierarchy writes retain PostgreSQL ancestry locks and explicit bottom-up soft deletion.
This policy bounds organization creation/metadata updates, project/environment/application
creation, and deletion at all four levels. OAuth configuration and protocol exchanges
retain their separate policies. No process-local coordination or sticky session is required.

| CLI flag | Environment variable | Default | Accepted range |
| --- | --- | --- | --- |
| `--tenant-lock-timeout-ms` | `PERMESI_TENANT_LOCK_TIMEOUT_MS` | 1000 ms | 1–10000 ms |
| `--tenant-mutation-timeout-ms` | `PERMESI_TENANT_MUTATION_TIMEOUT_MS` | 5000 ms | 1–30000 ms |
| `--tenant-slug-attempts` | `PERMESI_TENANT_SLUG_ATTEMPTS` | 16 candidates | 1–128 candidates |

The lock budget cannot exceed the handler budget. Clap validates these values; dispatch
independently revalidates the ranges and their relationship before constructing router
state. The policy applies even when OAuth issuance is disabled.

## Flow overview

After framework input extraction, one handler deadline covers session lookup,
permission/resource resolution, connection acquisition, all persistence attempts and
commit. Each mutation transaction installs local PostgreSQL `lock_timeout` and
`statement_timeout` before taking ancestry or authority locks. Stricter nonzero database
limits remain in force. Commit and rollback restore the connection's prior settings.

The shared `service_utils::database::begin` acquires a pool connection in the cancellable
caller, then finishes BEGIN in an owned task. This closes SQLx 0.9's cancellation window
between server-side BEGIN and client-side transaction tracking. If the caller disappears,
the task finishes tracking the transaction and drops it, scheduling rollback before pool
reuse. It holds one existing pool permit, queues no additional pool acquisition, and
executes no application writes. Permesi's tenant, authentication, OAuth, factor and
background transactions use this shared startup path. Dropping a tracked transaction
also schedules rollback. A cancelled SQL statement remains bounded by its server deadline;
connection recovery and lock release can finish after the HTTP deadline.
If PostgreSQL stops acknowledging BEGIN, its already checked-out permit can remain
held until the socket recovers or errors. This policy bounds the HTTP response; it
does not establish network-partition recovery or replace database/network liveness policy.

Handler exhaustion, write-storage lock/statement timeouts, deadlocks and write transaction
pool saturation return generic `503 dependency_unavailable` errors. These responses expose
no SQL, resource identifiers, names, lock targets or budgets. Other `OrgError` storage
failures log only SQLSTATE. Existing authentication/read-only preflight error mappings
remain unchanged when they fail before the handler timer; this policy does not convert
all 500s to 503s. Session, inaccessible-resource and nonempty-parent rejection retain
existing 401/404/409 behavior. Roles, recent-authentication checks, UUID pinning and
child-creation/deletion serialization are unchanged.

Only exact organization slug-index conflicts retry, after rollback. Both creation and
rename stop at the configured candidate count, including the requested slug, and return
409 when exhausted. Creator-name conflicts return a neutral 409 immediately. A name-only
update preserves the current database slug, including a concurrent rename. The existing
`(created_by, name)` uniqueness policy still reveals name unavailability to an authorized
noncreator manager; changing that policy requires a separate product/authorization decision.

Transient or ambiguous mutations are never automatically replayed. A deadline or lost
response during commit can leave its outcome uncertain; refresh authoritative state
before deliberately retrying. Neither timeout nor a failed lock attempt authorizes a
partial mutation. Broader console reconciliation remains a separate UX milestone.

Independent three/five-reader pools cover bounded writer failure and recovery. This does
not establish writer fairness, multi-host partition handling, throughput, a production
latency SLO, or an HTTP body-read deadline. Fair hierarchical coordination, sanitized
operational metrics and load benchmarks remain follow-ups.

Run `cargo test --locked -p permesi --lib tenant_mutation -- --nocapture` and
`cargo test --locked -p permesi --lib mutation_policy`. Execution evidence, mutation
checks, independent review dispositions and live HA limits are recorded separately in
[the validation record](tenant-mutation-validation.md).
