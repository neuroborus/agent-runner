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
authorship trailer. Codex may inspect that existing author and committer
identity during readiness with read-only `git var`; the readiness turn still
cannot stage, commit, change configuration, rewrite history, mutate refs, or
write to a remote.

Polishing never commits and keeps `HEAD` unchanged. Its handoff stages the
complete finalized and reviewed change set, verifies that nothing accepted was
left unstaged, and leaves the result for the operator.

Execution never adopts an external commit as completed plan progress. A current
planned subject already at HEAD, or external HEAD movement from the saved
baseline, pauses for plan revision before new writable work, including on
resume. Step one remains visible even if bootstrap has not completed. Only
verified settlement of the runner's consumed COMMIT authorization advances
the plan; completed effects are verified before any stale-plan guard.

Agent context cannot change the runner-selected step. A claim that it already
landed, or a direction to skip, reorder, or implement a later step, requires plan
revision even when structured step fields match. Read-only context validation
distinguishes such directions from quoted examples and whole-plan discussion.
Legacy accepted context is rediscovered before further writable work.

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

The same protected resolution freezes `trustedCommandTimeoutMs` into each new
run's version-3 trusted-validation snapshot. It is a strict `1` through
`2147483647` millisecond integer, defaults to `3600000`, and resolves project
over root without a CLI or MCP bypass. Its fingerprinted value is reused on
resume and remains per-run under concurrency; legacy version-1 and version-2
snapshots use the one-hour fallback. Preparation keeps its independent
`Math.min(timeoutMs, 10_000)` safety cap.

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
The live execution lease, durable same-run recovery responsibility, and
persisted execution process are never treated as interchangeable proof. A held
worktree lease is reused during stop settlement; it is not recursively
reacquired, and a failed retirement keeps that same-run reservation without
masking the containment result.

Plan execution may omit canonical-worktree acquisition only when its descriptor
proves that an applicable immediate stop belongs to the unchanged initial
`CLARIFY` checkpoint: preflight and repository/artifact persistence are absent,
and no pause, active turn, process, or resource exists. The runner still owns
the execution lease and uses atomic state settlement. A canonical lease recorded
for an unrelated run cannot block that state-only outcome. Every failed proof,
persisted repository checkpoint, or possible in-flight effect retains ordinary
worktree exclusion and reconciliation.

The runner connects that protocol to an owned-process abort boundary. Provider
and trusted-command processes wait for durable registration before executing;
runner loss closes their private control pipe and starts bounded cleanup.
Trusted command capability requests are closed and fingerprinted. Scratch/cache
declarations cannot name host paths or environment bindings. Artifact declarations
pin canonical HTTPS URLs and SHA-256 digests; they do not authorize raw network,
credentials, proxies, redirects, arbitrary mounts, or project-controlled trust.
Unavailable capabilities block before provider work rather than broadening an
agent or validation sandbox. Legacy snapshots retain their original restricted
authority and evidence bindings. Scratch/cache and dependency allocations have
journaled intent and verified filesystem identity before downloading or launch,
remain outside protected project and control paths, and are cleaned only after owned descendants retire. Uncertain
ownership retains cleanup evidence and never authorizes deletion or cache reuse.
Only digest-verified dependencies mount read-only at the runner-defined path.
No partials, mutable shared downloads, automatic extraction, or host installation
are exposed. Extraction must target declared scratch in the exact command.
Acquisition validates and pins public HTTPS destinations, rejects redirects and
inherited trust or credentials, and bounds bytes, time, and cancellation.
The fixed safety envelope is 64 MiB per file, 256 MiB total, one A and one AAAA
lookup with one resolver try each in a five-second DNS phase, 10 seconds to
connect, 15 seconds of header/body inactivity, and five minutes overall, plus a
separate one-second transport-retirement bound. These limits bound untrusted
network resource ownership and are not configurable command-execution budgets.
Transports retire before publication or cleanup; uncertain retirement retains
ownership. Journaled acquisition process identity also blocks cleanup after
service reconstruction while the owner is live or unverifiable. Same-service
transport retirement or verified owner death permits cleanup.
Timeout configuration changes only the execution deadline. It does not weaken
isolation, make an incompatible sandbox usable, or cross the deliberate
no-output-retention boundary. Trusted stdout/stderr remain discarded, so a host
pass can still produce only a generic isolated nonzero exit result.
Plan-execution and polishing capability reports are exact-command, additive requirements stored
before availability inspection. They cannot replace frozen declarations or grant
permissions. Read-only bootstrap and legacy discovery precede writable entry;
missing authority or availability blocks without invoking a writable role. Each
new writable checkpoint rechecks the saved request under configuration guards,
cancellation, the execution lease, and durable resource ownership.
Status does not probe capabilities. Consumed commit/handoff verification precedes
capability checks needed for new work.
Private PID namespaces contain detached and reparented descendants. Provider
processes that require another native sandbox use that mode only when the full
nested shape is available. Otherwise, an explicitly declared provider alone may
use session/token ownership on the initial host namespace; verified live
ancestry and same-user token discovery retain descendants that create another
session or namespace. Complete unrelated ancestry excludes a candidate only
after every stabilized hop reaches an unchanged pre-launch identity. Before
provider work, the session path durably records a bounded,
ordered baseline of boot ID, PID, and start tick identities captured before
supervisor launch plus the supervisor's control-group identity. Parent loss
before target launch exits the inert supervisor
directly because no provider descendant can yet exist. Live supervision and
recovery traverse the same frozen evidence, checking observed session and token
ownership before accepting an anchor. An inaccessible intermediate environment
may be crossed only when the walk still reaches that exact anchor.
An inaccessible current environment is excluded only when its lineage reaches no
owned evidence and its stable control-group identity differs. PID reuse, a stale or missing anchor, a boot mismatch,
missing or matching current control-group evidence, cycles, owned evidence,
malformed identities, a recovery namespace mismatch, or otherwise unproven
candidates fail closed whenever the session scan is needed. Legacy records do
not gain baseline or control-group authority through migration or recovery.
A recorded previous boot remains independent proof that the old process tree
cannot survive. Nested runner tests inside the trusted-validation namespace
retain the owned-session path when that enclosing sandbox denies another PID
namespace; the enclosing namespace remains the ultimate containment boundary.
The runner records the owned supervisor identity and verifies its death before
clearing ownership; the outer launcher's exit or an empty process group is
insufficient.
Live shutdown signals only through the owned child handle/control channel;
recovery verifies parent-death teardown without signalling host PIDs.
For session ownership, the persisted PID/boot/start proof reconstructs the
token used to detect survivors after supervisor loss without signalling them.
PID replacement, unverifiable ownership, or surviving descendants retains
exclusion. A PID disappearing between the live and identity observations is
rechecked before it can be classified dead.
Each shared-host snapshot entry pins its first readable start tick and receives
at most three attempts to classify that same identity. Transient
`ENOENT`/`ESRCH` or a changed parent/session restarts the current PID and its
ancestry from scratch; a then-absent PID is an exited snapshot entry, while a
different start tick is reuse. Malformed metadata, permission denial outside
the stable-intermediate anchored-lineage rule, live ownership evidence,
surviving descendants, and attempt exhaustion remain fail-closed.
Transiently incomplete completion inspection is retried only within one
non-resetting one-second descendant-grace deadline. This cleanup grace verifies
containment after work has ended; it is a fixed safety invariant, not a
configurable user-work timeout. Persistent uncertainty keeps the original
fail-closed error while the current owner makes one bounded teardown through
its private child handle and control channel. It clears registration only after
an empty owned session is proved. Otherwise the parent leaves durable ownership
for replacement-lease recovery and never signals from the persisted PID alone.
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

Detached stop supervision correlates the launched child with the private stop
checkpoint and waits for durable settlement or that child's exit. A transient
execution lease does not prove reconciliation. Exit first preserves the
applicable stop and retryable recovery intent. Exact-revision MCP recovery uses
a new action-free idempotency intent, rejects live or duplicate owners, and does
not depend on the original stop key; CLI resume uses the same runner settlement
path. A conflicting canonical lease remains attributed to its recorded owner,
not to the ownerless pending run. Operators never manually delete, rewrite, or
bypass lease records; supported recovery uses the state-owned lease protocol.

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
only path; it is never replayed. A persisted explicit availability rejection with
validated proof that the executor never started permits retirement only after
Git verifies no commit and unchanged controls/content/index. Retirement and
scheduling a fresh authorization are one durable transition. Authorization
consumption alone never proves executor activity. A handoff may be accepted as already complete
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

Claude selects isolation separately for read-only, workspace-write, and local
commit access. It prefers the full native sandbox and considers the restricted
host fallback only after the exact effective probe identifies the known nested
user-namespace denial. The fallback leaves the Claude CLI, credentials, and
provider network path outside the isolation boundary. Its direct model-free
probe exercises the same provider-private launcher validation and execution
path used by each model-issued command. The launcher accepts only the supported
Claude bubblewrap grammar, rejects malformed or weakened input before spawning,
and strengthens the validated invocation into one user, PID, mount, and network
boundary with private `/proc`, `/tmp`, and `/run`, a read-only host root,
access-specific workspace writes, and read-only Git metadata. Its file and
containing directory are non-writable during the turn, and it pins canonical
host `bwrap` rather than resolving it through a workspace-writable path. The
launcher verifies an exact owner-read-only x64 or arm64 Runner seccomp filter,
unlinks the verified resource, passes its sealed descriptor to bubblewrap, and
executes bubblewrap directly once with the single validated user namespace.
The filter returns `EPERM` for Unix-socket creation and all io_uring entry
points that could bypass it, including x32 forms on x64. It
removes `ARGV0`, credentials, and its token before the payload. The proof denies
IP and host abstract and pathname Unix sockets, inherited credentials and host
provider-proc access, remote writes, Git metadata, and outside writes. The
fallback sets `allowAllUnixSockets: true` so Claude does not prepend a second
automatic helper dispatch. Unsupported architectures, filter drift, setup
failure, or cleanup failure fail closed. Native policy stays strict; the
[architecture contract](../ARCHITECTURE.md) owns the exact launcher grammar and
strengthening mechanics. Any failed or incomplete proof, argument rejection,
launcher failure, or cleanup leaves that access mode unavailable. The bounded
selected-policy receipt distinguishes the effective fallback settings and
architecture-specific filter and remains immutable for the run; resume or
reconstruction fails closed if the provider's policy proof drifts.

Within either proved isolation topology, Claude's read-only and local-commit
readiness turns may inspect autonomously with only Bash and read/search tools.
They do not rely on broad shell-command denials that can misclassify compound
inspection; collaboration, editing, and web restrictions remain explicit, and
the sandbox continues to deny repository content writes, Git and remote
mutation, credentials, process escape, network access, and host Unix sockets.
Workspace-write turns retain their existing command denials and
autonomous-write restrictions. The access-specific effective policy is part of
the immutable provider receipt, so resume fails closed after policy drift.
