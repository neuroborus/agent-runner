# Durable Workspace Preparation

Read the affected sections before changing this contract. Use the [topic map](README.md)
for related owners and required reading routes.

## Admission Record

Common envelope version 25 adds nullable `workspacePreparation`, separate from
trusted-command `preparation` process custody. The state capability accepts this
only at run creation, before recursive workspace inspection. State validation
owns its pure normalization and input fingerprinting; filesystem admission and
capture consume those definitions. Its version-1 record freezes the directory
policy (including any filesystem inspection roots,
file-only constraint and literal exclusions), canonical exclusion lease path,
real workspace/task/state/lease directory identities and routing ancestors,
and bounded exact admission-input hashes and file identities. Missing optional
task inputs remain explicit. Every admitted input requires its real parent
directory binding and complete routing ancestry, including absent inputs.
Resolved roles, input hashes, counters, source
lineage, configuration protection and pipeline settings/checkpoints are bound by
an admission fingerprint. The record is bounded to 1 MiB, 256 exact UTF-8 text
inputs of at most 1 MiB each, and 4,096 routing bindings. The root caller must
list every input consumed during admission; a selected configuration's exact
protected hash is mandatory. Exact input reads reuse the workspace capability's
bounded, descriptor-anchored reader. Admission performs no recursive source or control
discovery and grants no workspace/provider/publication or Git authority.

`captureWorkspacePreparation` requires the current execution lease, exact
revision and canonical workspace lease. It verifies frozen directories and exact
inputs, then asks the root caller to produce a fresh, fully verified workspace
binding from those declarations. The callback runs outside the short state
mutation boundary, while retaining workspace exclusion, so operator stops remain
publishable. Publication rechecks the owner, revision, inputs, directory
identities and cancellation, then journals one `workspace-preparation/captured`
transition atomically binding the completed workspace and clearing the pending
record. The resulting policy, exclusion key and absent inputs must match the
admission, including the exact absent-input list during journal replay.
Journal replay permits no other replacement or removal except the bounded
source-selection and migration transitions described below. Interrupted
capture publishes no partial fingerprints; recovery recaptures from frozen
declarations. An interrupted complete publication uses ordinary journal recovery
without repeating capture. Stale revisions, substituted inputs/roots, uncertain
ownership and canceled runs cannot publish.

## Capture and Publication

Pending preparation permits only activity, pauses, stop settlement and restoration
of the admission checkpoint; workflow/provider/effect work remains blocked.
Pause and cancellation preserve the record. A quiescent pending record is not
process custody and does not prevent lease release after stop settlement.
Legacy absence normalizes to null and preserves completed historical preparation,
existing workspace bindings and all pipeline evidence during ordinary leased
migration; it never schedules a new capture.

## Pending Preparation Migration

An explicit leased pipeline-version migration may rebind only the pending
preparation's `inputFingerprint` to the validated migrated state representation.
The original admission hash must still match its original state. Journal replay
requires increasing pipeline version and `runner/runtime/migrated` activity,
unchanged workflow state, and identical policy, source selection, root identities,
input bytes/identities, roles, hashes, counters and lineage. Both complete states
remain in history. This grants no capture, provider work, new inputs or changed
scope; ordinary transitions still reject any admitted-state drift.

## Source Selection

Common envelope version 26 adds optional `sourceSelection: {kind: "git",
fingerprint}` to pending and completed directory bindings. Only new Git-scoped
preparation starts with a null fingerprint and no inspection roots. Under both
owners, `captureWorkspacePreparation` obtains the Git-owned selection outside
the short mutation boundary, rechecks frozen inputs/revision/owners, then journals
`workspace-preparation/selected` before capture. This transition may add only the
confined file-only inspection declarations and non-null membership fingerprint;
all other admission evidence remains identical. Capture and journal replay must
preserve that exact selection. Interrupted selection publication recovers once;
later capture/reconstruction verifies existing membership rather than reselecting.
Partial capture supplies no authority. Version-25 preparation and completed
bindings remain unchanged on migration. That version established detached token
`1:26`, with matching package metadata and audit version 10 compatibility.

## Deferred Audit Preparation

Audit selects `preparation: "deferred"` in its directory workspace descriptor.
Runner and MCP boundary validation perform only canonical routing, configuration
and exact-input inspection before admission. They do not call recursive workspace
inspection. Runner creates the pending record with null provider receipts, then
publishes creation activity and the durable run ID. `create` returns that admitted
run; `run` and detached `resume` acquire execution ownership before the frozen
canonical exclusion lease and capture controls/content with a stop-monitor signal.
Directory audits share enclosing-worktree and overlapping-directory exclusion
with other workflows. No admission or partial capture grants Git authority.

An ordinary detached audit dispatch journals readiness under those leases before
capture. MCP can publish its receipt while preparation is held, and exact-key
recovery uses that readiness even after disconnect or lost receipt publication.
Readiness acknowledges supervised preparation, not provider capability, source
acceptance or completion. Status exposes nullable `workspacePreparation` with
`status: "pending"`; CLI creation activity prints the identifier and supervision
commands. Reads and waits remain observational. Stops during capture cancel
traversal and settle only after owned work retires; an uncaptured workspace is
never recursively inspected to settle a stop. Pause and cancellation preserve the
pending record. A resumed pause and ownerless recovery reuse its declarations
and exact input evidence without resolving configuration or selecting sources
again. Only complete capture publishes a binding; capability validation precedes
native role work. Other pipelines and legacy completed audit bindings retain
their existing lifecycle.

## Completed Workspace Binding

Common envelope version 24 adds a nullable immutable `workspace` binding. New
runner-created runs save their selected kind, lease policy and canonical key;
directory runs also save exact provider declarations, binding/protected-content
fingerprints and empty retrieval authority. Legacy absence stays null and
retains Git semantics during ordinary leased migration; resume never derives
directory authority or replaces a frozen selection from current configuration.
The detached compatibility token includes this envelope change.
