# Trusted Validation Requirements

Read the affected sections before changing this contract. Use the [topic map](README.md)
for related owners and required reading routes.

The public trusted-validation service also provides `inspectRequirements` for
pipeline-owned requirement discovery and writable-entry decisions. This is an
explicit preparation effect, never a required-check execution or attestation.
Construction, status reads, and ordinary preflight do not call it. Pipelines
retain their own reporting schemas, saved requests, migration, and pause policy;
the capability owns normalization, frozen authority matching, and availability.
Plan execution and polishing independently own reports in each active role's
bootstrap or validation-migration inventory and inspect their union at every
writable entry. Both pipelines' reports carry a closed `basis`; the union
contains only `assigned-executor` and legacy basis-less saved reports, without
the field, while saved `read-only-turn` observations describe the read-only turn
rather than the assigned executor, stay unproved and are never admitted. Plan
execution canonicalizes a provider's assigned-executor copy of an inherited
basis-less row to the saved bytes before its preservation checks. Cached
declaration preflight cannot bypass this gate. Execution
also checks unconsumed COMMIT; polishing inspects completed HANDOFF settlement
before discovery or preparation and checks availability before new staging.
Polishing state version 14 preserves historical handoff evidence while requiring
read-only capability discovery before further content work. State version 15
adds frozen finalization guidance, including a partial-preflight state that
durably retains the decision across backend-probe pauses. Terminal and
completed-handoff recovery stay verification-only; other unfinished legacy work
resolves the decision before provider work and repeats read-only validation
migration when prior evidence cannot prove the selected skill is part of the
established inventory. Neither pipeline imports the other's report schemas or
workflow internals.

## Requirement discovery

Plan execution and polishing each require a boolean `sourceProjection` field in
their own report schema and map only `true` into the shared capability request.
Their ordered migrations add `false` to historical concrete reports without
reloading configuration or changing immutable trusted snapshots, and preserve
null provisional reports for read-only rediscovery.

## Inspection request and authority

Inspection accepts `inventory` (up to 512 unique, trimmed, single-line exact
command strings, each at most 4,000 characters) and `requirements` (up to 1,024
reports, accommodating two role inventories with 256 needs and 256 blockers each).
Every selected frozen command must appear in the inventory. Each
report names an inventory `command` and may supply `commandIdentity` (null or a
lowercase SHA-256 identity), `capabilities` (the closed scratch, cache,
source-projection, and exact artifact declaration shape), and `unsupported` (up
to 16 unique lowercase capability labels of at most 64 characters). Unknown
fields, malformed parameters, or commands outside the inventory raise
`ERR_INVALID_TRUSTED_REQUIREMENTS` before effects. Unsupported labels describe
needs, never executable requests, paths, environment values, or authority. The
capability copies and freezes the accepted request before asynchronous work.

All reports for a command are additive; one role's smaller report cannot remove
another's requirement. A valid report without trusted selection, with unsupported
needs, or exceeding the saved command identity or capabilities returns `BLOCKED`
with bounded `not-selected`, `unsupported`, or `insufficient-authority` reasons.
Artifact authority matches both canonical URL and digest. Selected declarations
are always runner-known requirements even without reports. Authority for the
entire request is checked before any preparation; the snapshot is never changed.

## Capability blocker diagnostics

The same comparison derives every `BLOCKED` result's `diagnostic`, a closed
version-1 `{schemaVersion, blockers, omittedBlockers}` value validated by the
public `normalizeCapabilityMismatchDiagnostic`. Consumers never repeat the
comparison. It publishes the first 16 comparison blockers in inventory order and
counts the rest in `omittedBlockers`. Each contains only `checkIndex` (the
unique 0–511 inventory index), the comparison `reason`, `missingCapabilities` in
fixed `scratch`, `cache`, `sourceProjection` order, at most 32 lexically sorted
unique `unmatchedArtifactDigests` with an `omittedArtifactDigests` count,
and `commandIdentityMismatch`. The union of all reports supplies these details.
Digests are deduplicated only after exact URL-plus-digest pair comparison, so a
selected digest requested under another URL remains unmatched. Only
`insufficient-authority` carries details and requires at least one; other
reasons keep them empty or false. Unknown own fields, sparse arrays, invalid
values, duplicates, noncanonical order, inconsistent counts or overflow,
including evidence needing more than the shared 1,024 reports, raise
`ERR_INVALID_CAPABILITY_DIAGNOSTIC` without echoing input; output is copied from
the validated values. URLs, vectors, paths,
profiles, unsupported labels, reports and exception text are never included.
Availability blockers carry a null diagnostic. Diagnostics grant no authority.
When pausing, coding pipelines save a non-null diagnostic unchanged and bind
each published `checkIndex` to its required-check ID in the active step's
inventory in an exact `capabilityChecks` `{checkIndex, label}` list; role-local
bootstrap IDs and ambiguous commands bind null. The public
`projectCapabilityChecks` treats that saved list as untrusted. It returns one
association per diagnostic blocker by inventory index, never by position.
Missing, duplicated, non-`C<n>` or unbound labels project as null, as does an
ID saved for more than one published blocker index, counted before repeated
index bindings are discarded. Bindings for indexes outside the diagnostic are
ignored and never remove or change a blocker or suppress another label.
`projectCapabilityOwnership` returns at most 32 saved ownership envelopes after
platform revalidation and ignores all other evidence text.

## Capability declarations

Trusted declarations optionally carry `capabilities`, a closed object with
`scratch: true`, `cache: true`, `sourceProjection: true`, and
`artifacts: [{ url, sha256 }]`. Omit a capability to leave it disabled. Scratch
and cache request isolated per-execution storage with runner-defined paths and
environment bindings; declarations cannot choose host paths, mount points, or
environment names. Source projection requests an isolated writable copy of the
accepted staging-independent source rather than a host path. Artifacts request
pinned acquisition outside the check sandbox, never network permission for the
command.
The artifact list contains 1–32 unique canonical HTTPS URLs and lowercase
SHA-256 digests. URLs cannot carry credentials, fragments, nondefault ports,
IP literals, or local/reserved hostnames. Public DNS, connection pinning,
integrity, and resource limits must be enforced by the acquisition implementation.
Scratch and cache provide isolated transient storage. Artifact acquisition uses
the same durable allocation lifecycle and exposes verified files read-only.

## Frozen catalogs and availability

Root and safe project catalogs share strict normalization, including capability
parameters. Capability changes participate in catalog conflict detection and
command identities. New snapshots use schema version 4 with an explicit
`capabilities` object on every command and the resolved `timeoutMs`.
Configuration fingerprints bind the version, complete normalized request, and
timeout, while command identities and ordered-command fingerprints remain
independent of the deadline. Version-1 and version-2 snapshots retain their
original identities and fingerprints on migration/resume and deterministically
use the 60-minute fallback. Version 3 retains its frozen timeout and closed
pre-projection capability set. Legacy validation never grants source projection,
so already accepted evidence remains bound to its original policy. Each run
carries its own immutable snapshot; resume does not reload configuration, and
concurrent projects do not share deadline state.

Creation checks the frozen request before provider probes. A valid unavailable
request creates a durable `environment_blocked` run with incomplete preflight,
no repository baseline, backend versions, input hashes, or agent activity.
Malformed declarations remain configuration errors. Resume retries the saved
request under the execution/worktree leases before new provider work; successful
retry resumes ordinary preflight without reloading configuration. Later failures
retain the applicable pipeline checkpoint. Capability inspection does not execute
or attest checks. Consumed commits and completed handoffs are verified before
capability checks needed for new work; status and immutable terminal reads do no
capability work. Launcher discovery is lazy for the same reason.
