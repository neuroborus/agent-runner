# Safety Model

Agent Runner treats repository content, Git control state, durable state, and
provider execution as separate trust boundaries. Convenience never overrides
proof of ownership or an unchanged accepted fingerprint.

## Repository permissions

Each role turn receives the narrowest access required by its phase:

- clarification, bootstrap, compatibility, review, confirmation,
  reconsideration, and arbitration are read-only;
- implementation, polishing, finalization, finding resolution, and lazy
  check-and-fix may change safe workspace content only;
- plan execution's constrained commit executor is a separate one-shot effect;
- polishing staging is a runner-owned handoff effect, not an agent permission.

The runner snapshots content, index state, `HEAD`, branch or detached context,
local refs, remotes, and Git identity around turns. Read-only mutation is a
safety failure. Writable turns still reject index, history, ref, remote, or
identity changes. The runner never discards unexpected user work
automatically.

## Git ownership

Plan execution permits exactly one ordinary local commit for each validated
plan step. Only the Worker may trigger it, only after the fingerprint-bound
gate, and only with a fresh one-shot authorization. The commit must use the
exact subject from the plan, the existing Git identity, and no body, footer, or
authorship trailer.

Polishing never commits and keeps `HEAD` unchanged. Its handoff stages the
complete finalized and reviewed change set, verifies that nothing accepted was
left unstaged, and leaves the result for the operator.

No pipeline may push, mutate a remote ref, call a hosting service to write,
change a remote, alter Git identity, amend, reset, rebase, stash, switch
branches, or create tags. A failed hook or unexpected repository state pauses
instead of being bypassed.

## Inputs, artifacts, and state

Task, plan, context, and clarification inputs are hashed and revalidated before
recovery. Clarification writes occur only through a persisted one-shot editor
or MCP authorization. Repository-local artifacts must be confined, ignored,
and non-overlapping with protected inputs.

An optional project configuration is protected input for the lifetime of its
run. Its parsed values and versioned protection evidence come from the same
confined read and pin content, file identity, and real ancestor directories.
The runner checks that evidence around provider turns and before recovery,
trusted validation, commit, handoff, and stop reconciliation. Removal,
replacement even with identical bytes, content drift, links, or ancestor
redirection fails closed as one bounded provider-neutral safety pause. The
runner never restores the file or derives missing evidence for a legacy run,
and begun irreversible effects remain verification-only.

Authoritative run state is external to both repository and task. These trees
must be disjoint: neither the project nor task may contain or be contained by
the state root. Atomic files,
write-ahead events, owner-token leases, canonical paths, link checks, and
bounded schemas make interruption recoverable without trusting a half-written
file or a surviving native session.

Operator-stop acceptance has its own short state mutation boundary, separate
from execution ownership. A durable request preserves the exact suspended
journal checkpoint and existing blockers; cancellation cannot be downgraded.
An immediate pending request blocks ordinary state writes; deferred requests
permit only target-step progress. Release of held execution/worktree leases
fails closed until accounting completes. Even after owner loss, another run
cannot reclaim that worktree until the original run records reconciliation.
Boot and process-start identity distinguish a recorded owner from a reused PID;
unverifiable owners remain conservative exclusion barriers. An acceptance
receipt may be recovered or replayed after later transitions without executing
work or changing a terminal outcome. The state protocol itself performs no
process signalling or repository effect.

The runner connects that protocol to an owned-process abort boundary. Provider
and trusted-command processes wait for durable registration before executing;
runner loss closes their private control pipe and starts bounded cleanup.
Private PID namespaces contain detached and reparented descendants. Provider
processes that require another native sandbox use that mode only when the full
nested shape is available. Otherwise, an explicitly declared provider alone may
use session/token ownership on the initial host namespace; verified live
ancestry and same-user token discovery retain descendants that create another
session or namespace. Complete unrelated ancestry independently excludes an
inaccessible candidate regardless of launch timing. Before provider work, the
initial-host session path records stable identities for visible pre-existing
processes; an exact PID/boot/start match is the narrow fallback when ancestry is
inconclusive, including an unchanged process reparented to PID 1. New, reused,
changed, owned, malformed, or otherwise unproven candidates fail closed.
Recovery has no launch baseline, so only complete unrelated ancestry can
exclude an inaccessible candidate. Nested runner tests inside the
trusted-validation namespace retain the owned-session path when that enclosing
sandbox denies another PID namespace; the enclosing namespace remains the
ultimate containment boundary. The runner records the owned supervisor
identity and verifies its death before clearing ownership; the outer launcher's
exit or an empty process group is insufficient.
Live shutdown signals only through the owned child handle/control channel;
recovery verifies parent-death teardown without signalling host PIDs.
For session ownership, the persisted PID/boot/start proof reconstructs the
token used to detect survivors after supervisor loss without signalling them.
Unverifiable ownership or surviving descendants retains exclusion.
Transiently incomplete completion inspection is retried only within one
non-resetting descendant-grace deadline. Persistent uncertainty keeps the same
fail-closed error and durable exclusion, but the parent unreferences the
detached supervisor and its IPC channel after the failure is reported. It does
not disconnect containment, signal an unverified process, or clear ownership;
the run owner can close protocol resources and exit while later recovery keeps
using the durable proof.
Codex observes owned-process failure independently of App Server protocol
completion. A retained containment boundary may keep protocol pipes open, but
the ownership failure still triggers bounded adapter cleanup and propagates as
the primary error through client teardown; successful process completion never
replaces the required protocol result.

Codex also retains the dynamic `AGENT_RUNNER_OWNED_PROCESS` marker in
model-issued commands through an exact environment allowlist. The shell policy
starts from the provider parent only so Codex can apply its standard automatic
secret exclusions, then overlays explicit workspace values and exposes only
standard core names, the ownership marker, and those workspace names. This
preserves descendant ownership proof without exposing unrelated parent
environment values or changing provider connectivity.

Reconciliation preserves safe partial
workspace content without staging or rollback and retains read-only mutation,
index, history/ref, remote, identity, and input findings as blockers.

CLI and MCP stop timing accepts only `immediate` or `after-current-commit`.
Omission is immediate. Neither transport refreshes stale inspected revisions;
retries bind timing to the same durable identity. Public stop and activity
summaries omit private checkpoints and request identities; receipts retain
bounded acceptance evidence, and waits never confer execution ownership.

A deferred commit-boundary stop reserves execution/worktree ownership while
its immutable target step advances. State rejects boundary crossing except via
atomic settlement of verified progress and the latest stop outcome. The monitor
continues to enforce superseding immediate cancellation. Interrupted or blocked
targets settle after quiescent reconciliation; no role, check, or commit is
invoked merely to satisfy the request. Terminal failure and protected-input
blockers survive inside the preserved checkpoint.

A stop racing a consumed commit or handoff runs verification only. The final
stop event records an observed completed effect and its progress once. An
operator pause preserves the reconciled checkpoint and existing blockers;
cancellation is terminal. Neither outcome authorizes replaying an effect,
restoring contaminated content, or adopting replacement configuration.

Local operating guidance uses the same new-run configuration and Git safety
boundaries. Its target and temporary files must be ignored, untracked, confined,
and separate from configuration and protected control paths. Linked, unsafe,
non-regular, malformed, or oversized documents fail closed, including unsafe
absent destinations. Reading does not create files. Both common and local
documents are bounded; document bodies never enter action metadata or errors.

Guidance replacement holds the canonical-worktree lease, excluding active
execution and competing publishers. It compares the expected hash inside the
publication boundary and atomically replaces only the local file. Pinned
directory descriptors prevent ancestor replacement from redirecting filesystem
effects. Durable temporary-file identity distinguishes an interrupted
publication from another writer's identical content; retries preserve later
edits and cannot redirect through changed configuration. A completed receipt
is replayed without repeating publication. Local additions cannot weaken
common contracts and never enter role prompts or run state.

## Effect reconciliation

Legacy terminal-confirmation recovery is gated by complete journal provenance,
current inputs and Git controls, unchanged finalized content, and valid
validation infrastructure and check evidence. Missing, discontinuous,
inconsistent, or migration-only proof fails closed. Recovery preserves an
already charged correction marker only when no concrete correction, findings,
disputes, directions, migration obligations, or effects remain. It never
replays a consumed commit authorization or previously completed work. The
recovery transition is revision-bound and write-ahead, and private history
does not cross public CLI or MCP projections.

Intent is durable before any commit, handoff, editor, or MCP mutation. If a
process stops after an effect may have started, recovery inspects the observed
state before acting. A consumed commit authorization stays on a verification-
only path; it is never replayed. A handoff may be accepted as already complete
or retried only from its exact unchanged pre-effect state. Ambiguous partial
effects fail closed.

Content-changing repairs invalidate candidate-review, finalization, and
terminal-confirmation evidence. The terminal formatter may transform an
accepted candidate, but finalization and confirmation must then bind its exact
resulting fingerprint. A commit or handoff proceeds only when current content
and validation infrastructure still match the accepted fingerprints and no
mutation can occur between the final read-only gate and the runner-owned
effect.

## Redaction and provider isolation

Native provider output is untrusted. Adapters validate and normalize it before
pipeline policy sees it, and public surfaces retain only bounded structured
summaries and allowlisted failure classes. Credentials, authorization data,
cookies, tokens, prompts, transcripts, denied commands, raw responses,
standard error, and chain-of-thought are neither logged nor persisted.

Provider sandboxes deny remote writes and Git metadata writes according to the
turn's access mode. Collaboration or subagent activity is forbidden for role
turns and fails closed when detected. An existing real project `.agents`
directory is eligible workspace content during Codex writable turns; a
symlinked `.agents` and the Git-control `.git` and provider-control `.codex`
paths remain protected. Eligibility does not imply task scope: role prompts
allow project `.agents` changes only when the user explicitly requests them,
and plan execution also requires the current planned commit to do so. A
violation is corrected through the normal finding loop rather than a user
question. The runner does not broaden network, filesystem, process, or
host-service access to overcome a validation blocker.
