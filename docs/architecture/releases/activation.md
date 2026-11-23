# Candidate activation and restart

Read the affected sections before changing this contract. Use the [topic map](README.md)
for related owners and required reading routes.

The same capability now exposes `apply({ idempotencyKey, version? })` for explicit
managing-operator requests. A state-owned `update_apply` action persists its operation
and activation UUIDs before mutation. Selection freezes one exact version; a stable
channel change cannot redirect a retry. Exact-version preparation identity is derived
from official identity, private storage and version, so concurrent requests reuse
the preparation lease and validated candidate rather than install twice. Recoverable
blocked outcomes remain in the intent; success completes its bounded receipt.
Receipts distinguish the outer package and pinned running versions from candidate
milestones. Same-key argument changes conflict; consumed activation is reconciled
through the original action without registry or native-effect replay.

The root update capability exposes `activate({ operationId, preparationId,
version })` and read-only `status({ preparationId, version })`. It shares the
official identity and development-managed gates with preparation; transports
remain separate. Activation holds both its own `update_activate` action lease
and the exact preparation lease. A completed validated preparation, unchanged
storage identity, complete immutable payload, frozen metadata and current
Node/configuration/state compatibility must verify again before selection.

The activation intent persists a separate runtime-operation UUID and candidate
before invoking serialized admission. It records the resulting active/deferred
versions and restart requirement before returning. Recovery reuses that UUID
and reconciles consumed selection rather than publishing it twice. Repeated
calls return the original receipt; `status` reads current admission state and
separate downloaded/installed milestones without querying the registry.
Neither action rewrites or removes a previous usable installation.

A running MCP server stays pinned and cannot restart its client. Selection
changes no saved run. A later compatible server may explicitly inspect/resume
through the existing leased migration path, original frozen roles/settings,
ownership and consumed-effect recovery. Unknown forward state remains rejected
without changing progress. No activation grants legacy/intermediate runs new
execution, refinement or replacement authority. Explicit version selection and
downgrade limits are documented in [RELEASING.md](../../RELEASING.md#local-version-selection-and-restart).
