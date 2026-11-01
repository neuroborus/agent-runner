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
- polishing staging is a runner-owned handoff effect, not an agent permission;
- every audit role remains read-only, including report corrections. Runner alone
  publishes its exact task-owned report artifacts. Findings grant no repair,
  Git, retrieval or issue-creation authority.

The runner snapshots content, index state, `HEAD`, branch or detached context,
local refs, remotes, and Git identity around turns. Read-only mutation is a
safety failure. Writable turns still reject index, history, ref, remote, or
identity changes. The runner never discards unexpected user work
automatically.

## Git ownership

Commit-plan execution permits exactly one ordinary local commit for each validated
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

Change measurement is read-only and bound to an inspected content fingerprint
and immutable baseline. It counts the final workspace rather than summing
staged and unstaged diffs, excludes ignored untracked files, and reports binary
changes separately. Link targets are never followed to obtain line counts.
Measurement grants no staging, commit, refinement, or acceptance authority.

Preservation saves unfinished changes in verified
external state storage before any checked removal. Both run and worktree
ownership are required. Raw bytes, deletions, executable modes and unfollowed
link targets remain recoverable through verified manifests and journaled
operation intents. Restoration changes only authorized paths whose saved
baseline remains valid; it rejects unrelated content, index, ancestor, control
or storage substitution. Saved work survives child commits, interruption,
cancellation and disconnect independently of transient resource cleanup.
Preservation grants no revision, commit or acceptance authority and never stages,
stashes, resets or clones a repository. New eligible execution runs publish
reviewed revision authority and complete validation receipts before separation,
then restore only the captured paths to the accepted baseline. Reconstruction
requires provider-compatible command access to all exact preserved manifests
and blobs before restoration. Unavailable access pauses with the candidate
intact; the runner never broadens the sandbox to expose hidden state storage.
Reconstruction ports only the active replacement; saved future bytes and earlier verified
commits retain separate ownership.

## Inputs, artifacts, and state

The directory-workspace inspection foundation protects unrelated content and
explicit inputs, references, configuration, artifacts, infrastructure and
filesystem-discovered Git/provider controls. Only declared confined outputs may
differ under its writable-content guard; redundant read declarations never
grant writes. It rejects escaping aliases, special files, overlapping protected outputs,
ancestor substitution and snapshot races without requiring Git. External state
cannot overlap workspace, task, infrastructure, declared reads or discovered controls. This capability
does not itself grant provider permissions. Codex enforces declared directory
outputs with a native permission profile; Claude uses authenticated command
mounts and omits native editing tools for directory turns. Both check protected
content after every retired attempt, including failures before reconstruction. Directory
access cannot request a Git commit, and unsupported providers fail closed.
Custom authoring uses read-only directory turns; custom execution grants only its frozen declared outputs to writable Worker phases. It never stages or commits. See the
[filesystem contract](../ARCHITECTURE.md#root-runner-ownership).

The runner can bind a descriptor-selected directory lifecycle without Git.
Workspace kind, permissions, exact local input/criterion paths, protected-content
and identity evidence, and the exclusion key are immutable run input. Directory
workspaces inside a repository contend with Git workflows on the same canonical
worktree key. Ordinary directory leases also exclude overlapping parent/child
scopes; stale reservations require recovery on their original key. Outputs cannot enter a nested worktree requiring a different
key; read-only nested worktrees remain supported. Recovery, stops and selected
trusted checks use the filesystem capability; a directory role receives no Git
effects. Resume retires verified owned execution before reporting frozen-content
drift, then persists a blocker without probing or invoking providers. References and URLs confer no fetching authority: retrieval permissions
remain empty. Legacy runs retain Git semantics. Explicit custom authoring uses read-only directory roles and frozen criteria
and source bindings; intended outputs grant no authoring writes. Runner alone
writes its task-owned clarification and plan artifacts. Custom execution uses the same frozen directory bindings without Git effects.

Task, plan, context, and clarification inputs are hashed and revalidated before
recovery. Clarification writes occur only through a persisted one-shot editor
or MCP authorization. Repository-local clarification artifacts must be confined,
ignored, untracked and non-overlapping with protected inputs, including custom
authoring. Ordinary-directory authoring uses confined task-owned artifacts;
neither placement adds ignore rules.

Init has a separate reviewed infrastructure-publication
boundary. Runner alone may publish the exact approved artifacts, destination
configuration and derived finalization procedure under exclusive ownership,
with write-ahead intents and verified identities/readback. Integrated publication
may also update the approved `.gitignore`. External publication writes only to
the selected target-bound infrastructure; target content and Git controls stay
unchanged, without pointer files, ignore edits or global registration. Existing
skills that predate the run and unrelated settings stay intact. Its task and
clarification artifacts remain external; ordinary pipeline artifact creation
still cannot change ignore rules.
Guidance publishes last through its existing durable expected-hash action under
the held leases. Completion requires distinct read-only confirmation of the
complete unchanged prepared snapshot. Recovery verifies exact original intents,
identities and receipts; it cannot redirect writes or adopt intervening edits.

An optional project configuration is protected input for the lifetime of its
run. Its parsed values and versioned protection evidence come from the same
confined read and pin content, file identity, and real ancestor directories.
Explicit external selection additionally requires a versioned binding to the
canonical target and disjoint infrastructure root. It pins the target directory
identity as well as the configuration ancestry and never broadens provider
access or project configuration authority. Integrated Git files retain their
ignored/untracked requirements; ordinary directories need no Git prerequisite.
The runner checks that evidence around provider turns and before recovery,
trusted validation, commit, handoff, and stop reconciliation. Removal,
replacement even with identical bytes, content drift, links, or ancestor
redirection fails closed as one bounded provider-neutral safety pause. The
runner never restores the file or derives missing evidence for a legacy run,
and begun irreversible effects remain verification-only.

Explicit finalization Markdown files use confined, identity-bound reads from
the selected infrastructure root. They grant no configuration authority or
parent-directory access, and cannot be replaced or redirected on resume. The
[validation contract](VALIDATION_AND_REVIEW.md#finalization-and-semantic-review)
owns selection, legacy decisions and the mandatory guidance gate.

The same protected resolution freezes `trustedCommandTimeoutMs` into each new
run's version-4 trusted-validation snapshot. It is a strict `1` through
`2147483647` millisecond integer, defaults to `3600000`, and resolves project
over root without a CLI or MCP bypass. Its fingerprinted value is reused on
resume and remains per-run under concurrency; legacy version-1 and version-2
snapshots use the one-hour fallback, while version 3 retains its timeout without
gaining source authority. Preparation keeps its independent
`Math.min(timeoutMs, 10_000)` safety cap.

Provider-visible client attribution comes only from runner-root configuration.
The runner normalizes and fingerprints it before persisting both values as an
immutable common run snapshot, validates custom support across active provider
descriptors before work, and reconstructs adapters from that saved snapshot on
resume. Project content and configuration, transports, pipelines, and prompts
cannot alter it. Legacy envelopes receive only the generic default without
configuration reload. Prompts, public projections, activity, and bounded
diagnostics retain neither attribution string.

Authoritative run state is external to both repository and task. These trees
must be disjoint: neither the project nor task may contain or be contained by
the state root. Atomic files,
write-ahead events, owner-token leases, canonical paths, link checks, and
bounded schemas make interruption recoverable without trusting a half-written
file or a surviving native session.

Journal reuse requires a certificate of the originally validated run/revision
prefix, ordered contiguous segment namespace, file identities and exact byte
ranges. Fresh consumed-byte digests and stable directory identity and file
handle/path observations establish unchanged history. Unrelated control-claim
publication cannot substitute for or invalidate that proof through directory
timestamps alone. Namespace, replacement, link, ownership and restored-mtime
tamper checks remain mandatory. Certificates are independent of optional bounded
checkpoint retention; absent cache evidence requires canonical validation.
Authorized tail repair proves the original prefix, namespace, directory and
captured file observations before truncation, then the same prefix and exact
repaired size through stable handle/path observations after syncing. Only that
proof produces an immutable recovery value with updated filesystem evidence;
the semantic certificate, state, revision endpoint and original capture stay
unchanged. Recovery and subsequent observation retirement consume this value
without redundant repair or replacement history. Failed verification grants no
repaired proof or diagnostic retirement, and ownership settlement retains
precedence.

Operator-stop acceptance has its own short state mutation boundary, separate
from execution ownership. A durable request preserves the exact suspended
journal checkpoint and existing blockers; cancellation cannot be downgraded.
An immediate pending request blocks ordinary state writes; deferred requests
permit only target-step progress. Release of held execution/worktree leases
fails closed until accounting completes. Even after owner loss, another run
cannot reclaim that worktree until the original run records reconciliation.
Boot and process-start identity distinguish a recorded owner from a reused PID.
A current same-host execution or worktree lease may be reclaimed without an age
delay only when that exact identity is dead or replaced; marker publication,
token and identity rechecks, and atomic replacement remain mandatory. Legacy,
identity-free, foreign-host, live, invalid, and unverifiable owners remain
conservative exclusion barriers. An acceptance
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
Trusted preparation uses one unchanged launch-to-close deadline, including
registration. Expiry and cancellation irreversibly deny payload release;
late registration must drain and retire rather than revive the attempt.
The supervisor independently checks the same absolute monotonic deadline before
admitting queued start IPC. Completion awaits registration and retirement;
uncertain durable publication or descendant retirement keeps ownership reserved.
Preparation's canonical launch reservation and bounded subordinate custody log
retain exclusion through verified retirement, canonical settlement and log removal.
A state-owned gate serializes admission with durable stop dispositions before
canonical acceptance, so delayed monitoring cannot admit a blocking stop accepted
before attachment. Matching deferred targets retain permission; explicit null
targets are valid without granting deferred-stop support. A replacement owner
can reconcile or retire an old attempt, never release it. Missing authority stays
reserved; legacy process proofs and independent descendant inspection are unchanged.
See [preparation custody](../ARCHITECTURE.md#preparation-custody).

Trusted command capability requests are closed and fingerprinted. Scratch/cache
declarations cannot name host paths or environment bindings. Artifact declarations
pin canonical HTTPS URLs and SHA-256 digests; they do not authorize raw network,
credentials, proxies, redirects, arbitrary mounts, or project-controlled trust.
Source projection is one boolean authority, not a path: the runner reconstructs
the accepted HEAD-plus-worktree source in its own mode-0700 allocation, omitting
ignored untracked files and Git metadata, and mounts only that copy writable.
The original worktree, index, control state, task/state trees, credentials, and
undeclared host paths are not exposed to the check. Projected mutations are
disposable and cannot become implementation or handoff content.
Unavailable capabilities block before provider work rather than broadening an
agent or validation sandbox. Legacy snapshots retain their original restricted
authority and evidence bindings. Scratch/cache and dependency allocations have
journaled intent and verified filesystem identity before downloading,
materializing, or launching, remain outside protected project and control paths,
and are cleaned only after owned descendants retire. Uncertain
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
Source materialization reconstructs the frozen repository HEAD plus the exact
fingerprinted tracked and non-ignored untracked worktree changes without taking
staged blob content from the mutable index. It matches the allocated source-
directory identity before writing, then verifies the projected tree's paths,
kinds, modes, sizes, and content hashes before rechecking repository and
allocation identity for launch. Stale fingerprints, HEAD or index drift,
projection substitution, protected control-path overlap, runtime exposure of an
external protected path, incomplete copies, original-repository changes, and
uncertain process or cleanup retirement reject the result. Accepted bounded
evidence remains tied to the source content fingerprint and HEAD, exact command
identity, frozen authority and trusted-configuration fingerprint, and the run's
validation bindings.
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
session or namespace. Live supervision and external recovery share one positive
association policy: owned-session membership, a matching launch token, or observed
owned ancestry. Available ancestry continues through inaccessible environments.
Each descendant is inspected independently, and observed association survives
session changes, reparenting and lost token access until absence is observed.
Unassociated processes neither block progress nor receive signals because their
metadata is unreadable, their session is newer or their cgroup is shared.
Shared-host discovery cannot prove absence against arbitrary same-user processes
hiding all ancestry and token evidence. Private PID namespaces remain the stronger
containment boundary.

No global pre-launch census or unrelated-process exclusion proof is required.
Historical ancestry and control-group fields retain strict shape, size, ordering
and boot validation but grant no authority; new launches store null values.
Valid historical records with or without those proofs follow the same policy.
Required supervisor identity and namespace remain mandatory. Parent loss before
payload release retires the inert supervisor directly because no provider work
can yet exist.
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
Each shared-host snapshot entry receives at most three classification attempts.
Transient disappearance or parent/session change restarts that entry. Positively
associated identities stay pinned across retries and live scans, including when
a later directory listing omits them. A cached ancestor grants no new descendant
association until its current identity and parent/session observations are
verified; failed checks retain only previously established ownership.
Replacement, unreadable or malformed identity, or exhausted owned-process churn
stays blocking; a fresh absent stat retires the association. Unassociated churn
supplies no ownership authority.
Transiently incomplete completion inspection is retried only within one
non-resetting one-second descendant-grace deadline. This cleanup grace verifies
containment after work has ended; it is a fixed safety invariant, not a
configurable user-work timeout. Persistent uncertainty keeps the original
fail-closed error while the current owner makes one bounded teardown through
its private child handle and control channel. It clears registration only after
an empty owned session is proved. Parent-side cleanup requires the supervisor's
frozen retained associations before it can prove absence; termination or a
watchdog cannot substitute an empty parent cache for a missing handoff.
IPC disconnect after handoff returns cleanup to the supervisor with its retained
identities. Its original termination deadline still applies, but exit requires
proven descendant absence; surviving or uncertain owned work keeps it live.
Otherwise the parent leaves durable ownership for replacement-lease recovery
and never signals from the persisted PID alone.
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

Local operating guidance uses the same new-run configuration and workspace safety
boundaries. Integrated target and temporary files in Git must be ignored and
untracked; external files stay confined to the explicitly selected target-bound
infrastructure without target writes. Ordinary directories need no Git.
All destinations stay separate from configuration, state and protected control paths. Linked, unsafe,
non-regular, malformed, or oversized documents fail closed, including unsafe
absent destinations. Reading does not create files. Both common and local
documents are bounded; document bodies never enter action metadata or errors.

Guidance replacement holds the canonical-worktree lease and, for external
destinations outside that scope, the infrastructure-root lease. These exclude
active execution and competing publishers, including other targets selecting
overlapping infrastructure. It compares the expected hash inside the
publication boundary and atomically replaces only the local file. Pinned
directory descriptors and durable selection ancestry prevent ancestor replacement from redirecting filesystem
effects. Durable temporary-file identity distinguishes an interrupted
publication from another writer's identical content; retries preserve later
edits and cannot redirect through changed configuration or placement on restart.
Directory targets share their enclosing worktree's exclusion lease. A completed receipt
is replayed without repeating publication. Local additions cannot weaken
common contracts or instruct pipeline roles. Ordinary pipeline prompts and run
state exclude them; init alone reviews and persists proposed guidance as setup
data for its publication, without acquiring instructions or permissions from it.

## Effect reconciliation

The private custom-result checkpoint persists acceptance intent before
settlement and verifies exact inspected outputs on reconstruction without Git
effects or provider replay. Output-directory preparation publishes only an
explicitly authorized root under an already existing pinned parent. A journaled
private-state allocation is pinned before owned no-clobber publication, preserving
even empty arriving or substituted roots without workspace sibling allocations.
The move never falls back to copying; missing-root preparation requires private
state storage on the same filesystem and the supported GNU move utility.
The no-follow descriptor stays open through identity verification. Accepted-output
fingerprints include symlink resolution hops and readable target trees.
A directory appearing after an absent intent without a published identity
remains ambiguous; recovery preserves it, its private allocation and the pending
evidence. Fresh cancellation checks after preflight prevent new allocation and
publication effects. Stops prevent new effects and
acceptance, and cancellation never disposes of output content. Frozen input or
earlier accepted-output drift requires revised planning and a new execution run.
Explicit custom execution settles criterion-bound results only after mode-required candidate, finalization and terminal confirmation gates. Result-only changes invalidate approvals; a settled receipt, never provider success, advances the cursor.

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
only path; it is never replayed. A persisted explicit availability or
authentication rejection with validated proof that the executor never started
permits retirement only after Git verifies no commit and unchanged
controls/content/index. Retirement and saving the retry or authentication
checkpoint are one durable transition. Authorization
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

### Ownership-repair operational acceptance

After both ownership fixes have passed their review and commit gates, the
supervising operator freezes a separate immutable runtime at a clean, quiescent
boundary, including all accepted prerequisites and both fixes. Before dependent
work, recheck the original repository's current user/worktree ownership and
frozen guards, then recover the
original interrupted ownership case through its unchanged pending idempotent
request. Separately recover the interrupted read/readiness case with its existing
key and arguments. Preserve frozen inputs, configuration, completed commits,
accounting and budgets in both cases. Retain the unrelated connection, old
immutable payload and uncommitted accepted candidate. Use the byte-for-byte saved
resume request without refreshing its key, revision or arguments, replacing the
run or granting correction rounds. Record actual recovery evidence and account
for integration of the repair into the feature/release lineage before final
handoff, without modifying the interrupted feature workspace during repair.
Synthetic tests, replacement runs and one case's recovery do not establish the
other's operational acceptance. If original recovery is unavailable, the ownership
prerequisite remains incomplete and
dependent work stops. Only normal journaled reconciliation may clear ownership;
never kill unknown processes or delete/rewrite records to pass this gate. The
original execution owner's disappearance remains unexplained.

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
access-specific workspace writes, and read-only Git metadata. Its launcher file
is non-writable and its private allocation is outside command write authority;
it pins canonical host `bwrap` rather than resolving it through a
workspace-writable path. The
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

Action-free process-proof failure preserves the active checkpoint instead of
terminally discarding it. No turn output, fingerprint, or validation evidence is
accepted before ownership is settled. Recovery reuses an owned worktree handle
or reclaims the same run's stale reservation under the existing exclusive lease
protocol. A retained reservation does not count as a live execution owner.

Shared-host inspection bounds total work and elapsed time across retained
associations, every candidate, ancestry traversal and churn. Exhaustion remains
unverifiable; recorded owners and associated descendants still require complete
retirement evidence.
Detached admission saves child identity before releasing its IPC barrier and
journals progress under the run lease. Matching acknowledgement evidence, not a
lease's mere existence or unrelated state advancement, permits receipt completion.
Public activity omits dispatch identities; persisted PIDs never grant signalling
authority. Caller disconnect cannot release another execution's ownership.

State-owned recovery-failure sidecars are diagnostic evidence only. Publication
does not require the execution lease whose acquisition may have failed, and
reading requires the exact run/dispatch/revision and recorded child identity.
Their immutable, bounded, closed records discard arbitrary error text and native
output. They cannot approve work, mark dispatch ready, complete a request, fail
resumable work terminally, or clear ownership; missing or mismatched records
provide no cause.

CLI resume diagnostics and MCP dispatch errors project only those safe cause
fields. Exit code and signal remain separate observations, with nulls for
unknown facts after restart; they cannot establish a recovery cause. Failed
diagnostic publication preserves the original error outcome. Detached native
streams remain ignored, and structured tool errors expose no child identity,
raw error text, provider output or transcripts. Identical-key retries retain
the existing readiness, settlement and ownership checks.

Claude sandbox scaffolding is adapter-owned content outside project and task
trees, including tool HOME/config projections and provider temporary storage.
Absent optional project masks cannot become host-visible mount-point files.
Existing project masks and runner-owned workspace, Git, network, and process
restrictions remain enforced. The repository view during execution is the same
unfiltered view used by Git fingerprints and subsequent trusted validation.

The adapter journals allocation ownership before launch. Neither cancellation
nor owner loss grants deletion authority: process retirement and canonical
owner/device/inode proof are required before removing the recorded allocation.
Replacement or cleanup uncertainty retains the reservation. No output or
fingerprint is accepted until cleanup completes; recovery reconciles the exact
checkpoint without weakening stronger containment or consumed-effect checks.

## Inactivity recovery boundaries

The shared provider watchdog journals a bounded expiry and configuration/content-
bound recovery marker before termination. Safe repository reconciliation and
verified process/resource retirement precede the one fresh reconstruction;
restart cannot replenish that allowance, and reconstruction never repeats a
source fork. Partial writes invalidate prior approvals and preserve charged
correction accounting. Recovery evidence clears only with a returned response
and matching reconciliation. Persistence failure grants no retry authority.
Reconstruction provenance alone, including legacy markers, proves no inactivity.
Output exhaustion requires a reconciled durable pause and explicit retry; it
cannot authorize automatic writable replay. Safe partial content, invalidated
gates, and charged corrections settle atomically with that pause. Commit effects
remain verification-only unless validated not-started proof and Git verification
retire an unused authorization.

Only validated semantic progress resets inactivity. Owned overlapping commands
suspend it until all complete; transport traffic and process liveness do not.
Readiness recovery requires existing pre-executor proof plus Git verification.
The constrained commit executor, trusted commands, and runner-owned handoff
remain outside this watchdog. Possible effects, unsafe repository controls,
operator stops, permission/isolation failures, and usage limits keep their
existing precedence. An MCP disconnect cannot reset a deadline or create a new
execution owner. See the [runtime contract](../ARCHITECTURE.md#provider-inactivity-deadlines).
