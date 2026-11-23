# Run Lifecycle

Read the affected sections before changing this contract. Use the [topic map](README.md)
for related owners and required reading routes.

The root runner first resolves the explicit pipeline workspace selection, then
resolves the canonical Git root or ordinary directory, safely loads runner and
project configuration, applies run-wide, role-specific, and accepted
pipeline-setting overrides, asks the descriptor for the active roles, and
persists those resolved roles, the resolved settings, artifact root, and
optional source-session reference and profile before pipeline work begins.
Common run-envelope version 8 persists effort for every active role and retains
the optional project-configuration protection record. Older runs normalize the
absent protection record to `null`; migration
never fabricates evidence by inspecting a current file.
Common run-envelope version 13 adds a provider-neutral policy-receipt slot for
every resolved role. A receipt contains only schema version `1`, a SHA-256 policy
fingerprint, and ordered supported access modes; it contains no provider flags,
payloads, prompts, credentials, stderr, or session storage. New runs persist
required-role receipts at capability preflight. Version-12 and older runs
migrate under the execution lease with null receipts before provider work and
then pin each required role's first valid receipt. Resume and reconstruction
reproduce the receipt before provider invocation; later policy drift fails
closed. The on-demand Arbiter receipt is pinned when first used. Pipeline
descriptors own role access requirements, so CLI and MCP receive the same
bounded `ERR_UNSUPPORTED_BACKEND` diagnosis without provider branches.
`run` then holds the new run's per-run lease while invoking its statically
registered workflow. Plan execution and polishing additionally hold one external lease
keyed by the canonical Git worktree before any workflow-owned mutation. The
runner always acquires the per-run lease first and releases the worktree lease
first. The narrow exception is plan execution's descriptor-proven initial
`CLARIFY` stop checkpoint: the runner retains the per-run lease but settles the
stop through the state-owned atomic checkpoint without acquiring an unrelated
canonical-worktree lease. Every checkpoint that may require repository
reconciliation or effect verification still requires the worktree lease.
`resume` recovers the durable event history and reconstructs the same
runtime from persisted state without reloading either configuration source or
requiring a live native session. `status` remains lock-free.
An optional descriptor-owned `workflow.nonResumableStates` list prevents further
preparation, provider probing or workflow invocation at those states. Runner
returns only after ordinary owned-process, resource and observation retirement;
pending operator stops retain their separate reconciliation path. Audit and init
declare `FAILED`; other pipelines retain their existing recovery gates.
Configuration-drift handling preserves a declared nonresumable disposition and
its terminal evidence. Recovery still validates saved state and canonical ownership
and retires owned work; retaining the failure accepts no changed configuration.

Descriptors declare `workspace.kind` (`git` or `directory`) and `workspace.lease`
(`none` or `exclusive`), alongside their existing role-access inventory. An
optional descriptor resolver selects those requirements from resolved explicit
configuration and run overrides;
MCP preflight and run creation supply the same normalized selections.
Missing Git never selects a directory workflow. Directory lifecycles require
exclusive ownership, use filesystem-only preflight/configuration/artifact
confinement and expose snapshot/guard operations through `runtime.workspace`.
They expose no Git effect capability. Runner `directorySafety` filters declared
artifacts from inspected snapshots; its `baseline({allowedPaths})` returns the
compact workspace baseline of that filtered snapshot plus `allowedPaths`,
`projectPath` and any frozen `sourceSelection`, and `assertUnchanged` accepts
compact or legacy full baselines. Its `outputBaseline({allowedPaths})` performs
one bound inspection with the same artifact filter and returns
`{snapshot, baseline}`: the transient complete filtered snapshot and its
output-partitioned projection plus `allowedPaths` and `projectPath`. Root
`runtimeFor` delegates `runtime.workspace.baseline` and
`runtime.workspace.outputBaseline` only for directory workspaces; complete
`snapshot()` results remain for consumers that read entries. Canonical enclosing
worktrees are found from filesystem Git layouts/pointers; a directory inside one
shares its exact exclusion key with commit workflows. An ordinary directory uses
its own key; state-owned admission also excludes overlapping parent/child scopes
atomically.
State placement must be disjoint from the resolved canonical exclusion root
before provider probing or durable run creation, including a sibling state path
inside an enclosing repository.
Outputs inside nested worktrees are rejected at inspection: their discovered
`.git` directories or pointers require a different exclusion key. Read-only
nested worktrees remain allowed.
Stop reconciliation, recovery and detached MCP ownership inspection use the
persisted key, with the same execution-before-workspace lease order.
Canonical path, current control confinement and exclusion checks precede owned
process/resource retirement. Frozen content is accepted only after retirement
and before provider probing or checkpoint continuation. Changed configuration
retains its configuration blocker; other directory input/content drift persists
`workspace_changed` in `WAITING_FOR_USER`. Pending stops retain that blocker
beneath their operator pause/cancellation without accepting changed inputs.
Clarification submission revalidates frozen directory inputs under the workspace
lease before writing answers or consuming the pending response authorization.

Directory bindings freeze normalized local inputs (including criterion files
when declared), sources, outputs, configuration, infrastructure and artifact
paths. Their fingerprints pin real ancestors, workspace/control identities and
protected content. Output identities may evolve; unrelated content and declared
reads remain frozen. Task-owned artifacts may evolve through the existing
clarification/publication protocol; task inputs remain pinned individually,
including the absence of optional files. Their later appearance blocks resume
and clarification submission before provider work or transcript mutation.
Creation discovers task-input presence through confined metadata inspection
before snapshotting; runtime input content uses guarded workspace reads.
Provider turns additionally compare complete before/after snapshots, permitting
only declared outputs for writable roles, including on failed retired attempts.
Trusted execution and capability preparation revalidate frozen directory bindings
before invoking their service as well as after it returns.
Access-specific provider proofs are combined into one immutable role receipt;
directory probes never request commit readiness. Continuation capability remains
available independently of the requested access. Authorized runner artifact
publication preserves receipts without unpinning explicit input/source bindings.
Read references convey no write
authority; persisted retrieval permissions are empty and authorize no fetching.
Project configuration retains confined reads, identity/content and ancestor
protection; only Git workspaces require ignored/untracked status. Repository
commit pipelines retain all existing ignore and Git guards.

The root runner, rather than a pipeline or provider, checks a non-null
protection record before recovery and stop reconciliation, immediately before
and after every provider turn, and before trusted execution, commit
authorization/consumption, and handoff. Removal, content drift, same-content
replacement, hard or symbolic links, changed ignored/tracked status, or
ancestor substitution produces only `ERR_PROJECT_CONFIGURATION_CHANGED` and
the bounded non-resumable `project_configuration_changed` pause. It does not
restore or replace the file. If an irreversible commit or handoff effect has
already begun, its existing verification-only accounting remains authoritative
before further execution is blocked.

`artifactRoot` defaults to `LOCAL_ARTIFACTS`. Plan execution and polishing use
it only for runner-owned transcripts beneath the frozen selected infrastructure
root at `<artifactRoot>/agent-runner/<run-id>/`; repository-local ignored-path, traversal, symlink,
overlap, and fingerprint guards apply to the resolved path. Legacy runs with no
persisted selection retain `LOCAL_ARTIFACTS`. Plan authoring continues to keep
its task-owned `clarifications.md` and `plan.md` beside `task.md`.

`--fork-from <backend>:<session-id>` is accepted only on a new run. The session
ID remains opaque after the first separator; `--fork-profile <alias>` supplies
its optional trusted profile without changing that syntax. Every participating
primary or review role must use the source backend and support native forking.
When the source profile is known, its `current` selections inherit that profile
and every explicit participating-role selection must match. When it is unknown,
participating roles must remain `current`, no native profile override is
supplied, and unavailable native forking fails closed. In independent mode,
each primary and review checkpoint's first eligible turn forks the source
directly and independently, while the Arbiter remains unconstrained. In lazy
mode, the source is forked exactly once into the
logical primary role for the entire run. Later checkpoints continue the
compatible child or reconstruct the same logical role in a disposable session;
they never fork the source again. Resume uses the persisted source, profile,
child lineage, and one-time lazy-fork marker and never asks for the flags again.

The CLI renders only persisted public activity and a concise current-state
projection. A user-action pause has a distinct exit status from an internal
failure; neither status output nor activity rendering exposes raw prompts or
model transcripts.

Each descriptor also owns a bounded public pause projection. CLI status, MCP
status, and MCP wait render that same projection as `null` or an object with
the finite public `reason`, an optional validated bounded diagnostic `code`, a
concise `explanation`, bounded `evidence`, the validated `resumeState` when one
exists, and `nextActions`. No other persisted pause field crosses this boundary:
in particular prompts, transcripts, credentials, native responses, raw
standard error, rejected values, internal diagnostics, and counters remain private.
Unknown pause reasons fail closed to `unknown_pause` without their persisted
text. A pipeline descriptor may derive bounded evidence from already validated
pipeline state when the derivation exposes only finite public identifiers;
`authentication_required` always projects the fixed
`ERR_AUTHENTICATION_REQUIRED` code, a fixed reauthentication explanation, the
saved logical checkpoint, and one null resume action. Provider-native
diagnostics never participate in that projection.
plan-execution finalization-backed `no_progress` exposes only the active
finalization issue IDs and never their commands, problems, evidence, or paths.
`read_only_agent_mutated_repository` projects exactly one evidence line,
`Changed snapshot domains: <labels>.` from the composed Git normalizer, or
`Changed snapshot domains: unavailable.` for absent, malformed, unknown, custom,
directory, or legacy diagnostics; its persisted evidence and causes never cross.
The coding pipelines' required-check capability pause, including historical
records, projects a fixed explanation and evidence from the composed
trusted-validation `projectCapabilityBlockerEvidence`: one line per published
blocker with its inventory index, allowlisted `C<n>` check label or `unknown`,
reason and bounded mismatch fields, an omitted-blocker count, and ownership
envelopes revalidated by the platform normalizer. Missing details project as
unknown, and an uncomposed call reports them as unavailable. Saved prose,
command text, URLs and arguments never cross.
Plan execution also projects `finalization_transition_invalid` as a resumable
`FINALIZE` checkpoint with a fixed bounded diagnostic when an unexpected
runner-owned finalization invariant rejects advancement. The retained state
contains neither the rejected evidence record nor provider, prompt,
transcript, trusted-process-output, or detached-log data.

Public next actions are concrete descriptor-owned operations. `respond`
identifies the exact pending request; `resume` carries either the validated
null retry or one valid extra-round or finding-override payload; and
`start-new-run` identifies a `revised-plan`, `uncontaminated-worktree`,
`resolved-finalization-blockers`, `resolved-commit-readiness`, or
`resolved-finalization-guidance` requirement. `resolved-finalization-blockers`
applies when correction has stopped with unresolved finalization failures and
no validated retry applies; it requires resolving the reported blockers,
restoring a clean baseline, and preparing a plan for the remaining work before
starting a fresh execution run. Only plan execution projects
`resolved-commit-readiness`, after a retired `COMMIT` authorization for a
provider-neutral readiness refusal with no pending commit; it preserves the
reviewed candidate for separately authorized follow-up and has no same-run
`COMMIT` retry or resume. Plan execution and polishing project
`resolved-finalization-guidance` when frozen finalization guidance is missing,
invalid, or changed; it requires repairing that guidance before a fresh run of
the same pipeline and is not an environment-recovery retry. The owning
[plan-execution](../../pipelines/plan-execution/docs/SPEC.md) and
[polishing](../../pipelines/polishing/docs/SPEC.md) specifications define the
exact conditions. A submitted input awaiting detached continuation exposes no
second action. Plan revision never projects resume of the stale run, and a
read-only repository mutation never projects acceptance of contaminated or
hybrid changes. This is a read-only projection of existing durable state and
does not change the root or pipeline state versions.
