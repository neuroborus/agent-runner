# Operator Model

Agent Runner is a local CLI with an asynchronous STDIO MCP boundary over the
same durable runner. Operators start a named pipeline, observe its run ID and
public activity, answer bounded pending input, and resume explicit pauses. The
product does not require a daemon or network service.

The shared [operator guide](../OPERATOR_GUIDE.md) owns the practical procedure
for preparing, supervising, recovering, and completing work through either
transport. A pause is not completion: follow its current `nextActions`, resolve
only the permitted cause, and resume the same run when resumable. Do not finish,
validate, rewrite, discard, or commit resumable work manually.

For an implementation or finding-resolution result-format failure, execution
preserves candidate work and earlier accepted progress and attempts one
read-only result restatement. `writable_output_invalid` means that allowance was
consumed: resume the same checkpoint to authorize one further read-only retry.
It grants no writable replay, additional fix budget or approval. Resolve a
validated environment blocker before resuming; unsafe drift or contamination
retains its existing stop. See the
[execution recovery contract](../../pipelines/plan-execution/docs/SPEC.md#writable-result-recovery).

## Local application artifacts

Application distribution currently provides local candidate assembly with neutral
`@your-scope/agent-runner` metadata. The artifact bundles the locked production
application and operator guide; settings, native credentials and durable state
remain separate from payloads. Root and internal packages stay private, and the
candidate license remains `UNLICENSED`. Publication requires separately approved
owner/identity, scope, license, repository links and publisher configuration.
Local archive acceptance proves neither public availability nor clean external
installation or new native-platform support. Assembly changes no global/native
links and activates no controller. See [local artifacts](../../README.md#local-application-artifacts).

The separate package-install gate verifies the exact local archive through an
offline install in a disposable external prefix, installed CLI/MCP discovery,
immutable resources and complete teardown. Installation and one-time client
registration are distinct; clients launch the selected `agent-run mcp` and
require a restart after registration or package changes. This local gate neither
performs personal registration nor proves publication, live-provider behavior or
additional native platforms. See [isolated installation](../../README.md#isolated-candidate-installation).

The npm release workflow remains disabled until separate owner/scope, license,
repository and trusted-publisher approval. Explicit stable GitHub Releases must
point to the exact approved main commit/version tag and pass ordinary checks,
separate package installation and complete slow coverage. Publication consumes
only the tested artifact, uses protected OIDC/provenance and verifies anonymous
public installation. A matching existing version is verified without rewriting
it; uncertain publication remains a reported failure. This grants no automatic
settings migration, client restart, run resume or controller update. See the
[release procedure](../RELEASING.md).

An on-demand root update capability reports official identity, running/installed
and available versions, stable availability, compatibility, blockers and restart
requirements. The immutable approval policy is bundled with the application;
while unapproved, registry/update actions remain blocked. Linked development is
reported without modifying links or Git. No newer version is a successful no-op;
prereleases need an exact explicit selection. Node, configuration or state-contract
incompatibility blocks a newer candidate without changing saved runs.
Checking grants no installation, migration or resume authority. Automatic
behavior is disabled, model/status/activity reads never query the registry, and
CLI/MCP expose only explicit operator requests. Future preferences must remain user-global.

The same root capability can prepare an exact release candidate under a durable
operation UUID. Official approval remains mandatory. Exact registry integrity,
complete archive/resources, installed immutable payload and runtime/state
compatibility must pass before isolated CLI/MCP smoke and a validated receipt.
Owned private storage and process identities survive interruption; retry proves
retirement and reconciles completed installation before any fresh attempt.
Unknown ownership or substituted storage remains blocking. Failed attempts never
replace the previous usable payload, and smoke storage is removed only after
its owned processes retire. Preparation changes no global/native link or active
selector and cannot migrate settings, resume a run or acquire Git authority.
CLI `update --check` and MCP `update_check` perform on-demand checking; CLI
`update` and MCP `update_apply` share one durable apply coordinator. Apply requires
a managing-operator invocation; MCP additionally requires `operatorInitiated: true`.
Task content, project settings, findings and pipeline sessions grant no authority.
Identical retries reuse a frozen exact selection and receipt, including across
server replacement. Concurrent requests share exact-version installation. A
disconnect cancels only waiting. Check and activity reads never install anything.

Activation is another explicit root operation bound to the exact validated
preparation and version. Its durable receipt distinguishes downloaded, installed,
deferred and active versions; read-only lifecycle status does not query the
registry. Another live runtime keeps activation deferred until safe admission
after its users retire. An interrupted consumed activation is reconciled without
repeating selection. Earlier usable installations remain retained.

Installed executables verify and select a complete user-owned read-only payload
before loading application code. A running CLI/MCP process and its detached
continuations retain that payload's code, dependencies and resources after outer
package replacement. Changed or incomplete payloads and changed Node executable
identity block launch; bootstrap does not repair an existing payload. Interrupted
preparations are not active installations. Startup follows an already-published
selection before imports and rechecks it at admission; detached launches retain
their exact original selection. This grants no state migration or automatic
resume. Linked Git checkouts remain
development-managed. See [pinned payloads](../../README.md#pinned-application-payloads).

Runtime admission serializes explicit activation with positively associated
CLI/MCP users, new runs, resumes and detached continuations. Another live payload
defers activation; uncertain ownership remains blocking. Retirement preserves
the previous usable tree and never signals unrelated processes. An existing
MCP server stays pinned until it ends; selecting another payload cannot restart
its client, migrate saved progress or resume a run. A later compatible server
requires explicit resume with supported leased migrations and the original
frozen configuration. Unknown forward versions preserve progress and fail
clearly; retained payloads cannot undo persisted migrations. Legacy/intermediate
runs gain no execution authority. Activation currently has a root capability
boundary shared by the explicit CLI/MCP operator actions. See
[explicit versions and downgrade limits](../RELEASING.md#local-version-selection-and-restart).

## Configuration

Global user settings live outside the application installation, using the
platform paths listed in [README configuration](../../README.md#configuration).
The global layer is called runner-root configuration below. New reads prefer
the user file and use the legacy installation-local `.agent-runner.json` only
when it is absent; invalid or unreadable user files never trigger fallback.
No automatic migration or configuration write occurs. Explicit managing-operator
`agent-run config migrate --from <legacy-file>` validates and atomically copies
exact bytes to an absent destination before ordinary resolution. Equal bytes
are a no-op; conflicts never merge, overwrite or delete. Sources are retained.
Unsafe interruption remnants stay preserved and block loading or migration.
Settings survive upgrades and linked checkouts, while credentials and durable
state remain outside payloads. This changes neither project precedence nor
global-only authority and never reloads or migrates an active run's frozen
configuration. Location conventions do not imply new execution-platform support.

Authoring owns `planKind` (`commit` by default, or explicitly `custom`), optional
`criteriaPath` and source/output arrays. CLI exposes `--plan-kind`, `--criteria`,
repeatable `--source`/`--output`; MCP uses `planKind`, `criteriaPath`,
`sourceReferences`/`outputPaths`. Selection follows the normal configuration
precedence, freezes before work and cannot switch on resume. A criteria file or
missing Git never implies custom. Custom planning requires user-supplied criteria
agreed during clarification; its outputs are declarations, not write permissions.
Commit authoring retains fixed coding/safety rules even with supplemental criteria.

Execution separately owns `planKind` with the same explicit commit default.
Use CLI `--plan-kind custom`, MCP `planKind: "custom"` or
`pipelines.plan-execution.planKind`. Criteria and source/output declarations come
from the frozen custom plan; authoring-only selectors do not override it.
Successful custom status exposes accepted-step receipts and bounded results,
with no completed commit SHAs or staging effects. `finalization: auto` supplies
no automatic coding gate for custom work; explicit selected guidance remains
frozen. Independent remains default/recommended in either completion contract.

Execution's descriptor-owned `preferredCommitLineLimit` and
`commitSizeAssessmentMultiplier` default to 900 and 3, resolve independently
through root then project configuration and persist for resume. Positive safe
integers must produce a safe-integer product. By default, new commit-plan runs
assess work strictly above that product and may keep a justified atomic commit or execute a
separately reviewed replacement sequence. The strict boolean
`automaticCommitSplitting` defaults to `true`; `false` executes the predefined
plan unchanged without measurement or assessment while every ordinary gate
remains. All three values are frozen at creation, so configuration changes never
toggle an existing run; migrated and custom runs never gain eligibility.
See the [execution contract](../../pipelines/plan-execution/docs/SPEC.md#commit-size-assessment-foundation).

Runner-root configuration is the only source of trusted profile
implementations. Root and safe project configuration may define exact
trusted command vectors. Catalogs merge root then project, deduplicate identical
same-name definitions, and reject conflicts even when unselected. The merged
catalog permits 256 definitions; each pipeline may select at most 32 root or
project aliases. Project configuration may also select role preferences,
pipeline settings, and an artifact root, but cannot add provider binaries,
credentials, environment values, or new host authority. CLI and MCP overrides
have the documented highest precedence.

New runs may explicitly select an existing external project configuration using
CLI `--project-config` or MCP `projectConfigurationPath`. Its versioned
`infrastructure` declaration binds the canonical target and disjoint external
root; relative infrastructure resources resolve from that root. Explicit
selection replaces conventional integrated discovery without merging placements.
Integrated Git configuration retains ignored/untracked protections, while
ordinary directories require no Git prerequisite. Selection never creates,
relocates or registers infrastructure. Resume pins the selected file, its bytes,
identity, real ancestry and external target identity rather than rediscovering.
The exact binding schema belongs to [architecture](../ARCHITECTURE.md#runner-configuration). Explicit
execution/polishing `finalization` paths use that frozen infrastructure base and
accept Markdown procedures such as `finalization/SKILL.md` or an adjacent
`RUNNER.md`; conventional `auto` discovery stays inside the target. Selection
preserves the original skill and never rewrites the procedure. Frozen bytes,
identity and ancestry cannot be replaced or redirected on resume.

The registered `init` pipeline prepares reviewed infrastructure in either
placement through Runner-owned effects. CLI `--placement` / MCP `placement` is
independent of review mode; all three modes work with either placement. External preparation creates a bound
sibling with a canonical-path hash, or reuses an explicitly selected bound root
at its existing paths. It returns an exact configuration selector, keeps all
target content and Git metadata unchanged, and references existing project
finalization skills from an external finalization procedure. No target pointer,
ignore edit or global registration is needed. Merged local guidance publishes last, then a distinct read-only terminal
confirmation accepts the complete snapshot. Status reports created/reused/changed
resources and effective paths only after completion. Partial prerequisites are
not a setup-completion receipt. Explicit migration retains the old setup and
prepares the newly selected placement non-destructively. See the [init specification](../../pipelines/init/docs/SPEC.md).
Setup pauses expose concrete blockers. Operator stops preserve reserved turns
and clarification windows; cancellation remains terminal. An exceptional
material decision after clarification uses durable authorized input and renews
the proposal gates while retaining the exact selected placement and paths.
Interrupted reconstruction exposes a resumable provider pause without renewing
its consumed allowance. The managed local guide records the exact selected
finalization procedure and replaces its metadata without losing local instructions.

Only runner-root configuration accepts `clientAttribution`, an exact
`{ name, title }` provider-visible identity. It defaults to
`agent_runner` / `Agent Runner`; project configuration, CLI, MCP, pipelines,
prompts, and repository content cannot override it. A custom value must be
supported by every active role provider before work begins. Each new run saves
the normalized value and fingerprint, resume never reloads it, and legacy runs
migrate to the generic default. Public status, activity, and diagnostics do not
expose the value.

The top-level `trustedCommandTimeoutMs` sets the per-command runner-trusted
execution deadline in milliseconds. It is a strict integer from `1` through
`2147483647`, defaults to `3600000` (60 minutes), and may be set in either
configuration layer; the project value wins over the root value. Unlike role
and pipeline selections, it has no CLI or MCP override. A new run saves the
resolved value in its fingerprinted trusted-validation snapshot, and resume
reuses it unchanged. This permits concurrent projects to use distinct deadlines
without shared service state. For example, `"trustedCommandTimeoutMs": 7200000`
selects two hours. Legacy snapshot versions use the one-hour fallback, while
capability preparation remains capped at 10 seconds.

Root and project configuration accept `providerInactivityTimeoutMs`, a strict
integer from 1 through 2147483647 milliseconds with a 30-minute default and
project precedence. The run freezes and fingerprints it; neither resume nor
legacy migration reloads configuration. There is no CLI or MCP override.
An inactive provider records bounded recovery activity before termination,
reconciles safe partial work, and may reconstruct the same role once without
reforking a source. Native fresh fallback shares that durable allowance. A
second expiry pauses as `backend_unavailable` / `ERR_PROVIDER_INACTIVE`.
Follow the offered resume action for one invocation without renewed automatic
retries. CLI and MCP show the role, checkpoint, attempt, and recovery status;
client disconnect does not affect execution. Owned local commands suspend the
deadline, while keepalives do not. See the [provider contract](PROVIDER_MODEL.md#provider-inactivity).

Root and project configuration also accept `availabilityRetryMaxDelayMs`, a
strict integer from `5000` through `2147483647` milliseconds with a `1800000`
(30-minute) default. The project value wins, without CLI/MCP or role overrides.
Each run freezes the ceiling with a five-second initial delay. Resume preserves
it, and legacy migration supplies the documented default with no pending retry.
All registered pipelines retry eligible explicit provider availability failures after
repository reconciliation. Delays double to the ceiling and repeat there without
an attempt quota. A successful provider response resets the episode, even when
subsequent output validation rejects that response. A normalized authentication-
required or output-exhausted response instead retires the superseded episode
before its distinct operator pause. CLI/MCP activity and
status expose the saved role, checkpoint, normalized reason, attempt, delay, and
deadline. Stops interrupt the wait under the same exclusive owner. Foreground
CLI owner loss needs resume; detached MCP work survives client wait cancellation,
timeout, and disconnect. Resuming an overdue deadline permits one attempt.

Output exhaustion instead pauses as `output_exhausted` with the fixed
`ERR_OUTPUT_EXHAUSTED` code and the exact suspended role/checkpoint. Safe partial
progress and correction accounting survive; affected approvals are invalidated.
CLI/MCP offer explicit resume of that checkpoint or guidance to start a new run
with smaller work units if exhaustion repeats. No writable replay, availability
backoff, or output correction starts automatically. Commit recovery verifies the
consumed effect first; replacing an unused authorization requires validated
not-started proof and unchanged Git verification. Public recovery distinguishes
proven inactivity from generic reconstruction with `expiryProven`; legacy
reconstruction markers prove no timeout and grant no new allowance.

The separate `authentication_required` disposition never enters that retry
policy. After repository reconciliation, every pipeline pauses durably at its
exact logical checkpoint with the fixed `ERR_AUTHENTICATION_REQUIRED` code.
Any active availability episode superseded by that response is retired first.
CLI and MCP expose one redacted explanation and one null resume action. The
operator reauthenticates the selected provider and resumes the same run; saved
roles, session lineage, fingerprints, findings, and correction accounting are
preserved. A source fork is retried only with no-effect proof; possible-effect
evidence resumes the same logical role fresh without risking a duplicate native
child. Commit readiness still requires pre-effect proof and Git verification
before a consumed authorization is replaced.

Both configuration layers accept portable `defaultEffort` and role `effort`
values: `current`, `low`, `medium`, `high`, and `xhigh`. Effort stays separate
from model selection and follows shared execution-preference precedence through
CLI/MCP overrides. CLI `--effort` and MCP `run_start.effort` select run-wide
effort; `--<role>-effort` and `roleOverrides.<role>.effort` win for one role.
Start retries must retain both values under the same idempotency key; detached
execution reuses the saved selection. Inactive role vocabulary is validated
without
resolving or exposing those roles. Legacy runs receive `current` without
provider activity; public status and activity never expose saved role effort.

Resolved active roles, settings, artifact root, trusted commands, and optional
source-session lineage are frozen into a new run. Resume uses that snapshot and
does not silently adopt later configuration changes. `independent` is the
default mode; choosing `lazy` or `combined` is always an explicit
operator decision. In coding pipelines combined adds primary convergence before
independent review; audit uses separate read-only discovery and finding-recheck cycles.
All registered descriptors expose these modes through CLI/MCP discovery. Resume preserves the saved mode, approvals, and budgets.

Plan execution and polishing save exact-command capability needs and blocker evidence from
bootstrap and legacy read-only discovery. If the runner cannot satisfy them, it
pauses as `environment_blocked` before writable work. Repairing storage,
isolation, or dependency availability permits retry of that saved request;
changing selection or declarations requires a new run. Availability is checked
again at every writable entry, even within one invocation. Agents cannot grant
capabilities by reporting a need. An agent's sandbox limitation for an exactly
delegated check is resolved only when runner inspection succeeds. Required checks
remain exclusive to finalization, and consumed commit and completed handoff verification precede new
preparation effects.

Preparation reservations remain owned work even before a process proof is attached.
Interrupted registration, settlement or custody-log removal must reconcile before
cleanup, another command or lease release. Recovery never releases an old probe;
missing or ambiguous evidence retains exclusion. Operators must use normal resume
or stop reconciliation, preserving frozen configuration and prior accounting.
See [preparation custody](../ARCHITECTURE.md#preparation-custody). External saved-case
acceptance after reviewed implementation and installation remains operator-owned;
synthetic fixtures do not establish that acceptance.

Plan execution and polishing each independently require a boolean
source-projection need in every capability report. A role may identify only the
frozen exact command; it cannot choose a path or broaden authority. Ordered
legacy migration defaults that need to false without adopting current
configuration or changing saved progress, review evidence, correction
accounting, or effect recovery.

A trusted command that must write beside its inputs may declare
`"sourceProjection": true` in its closed capabilities object. The runner then
runs it from a private writable materialization of the accepted source rather
than the checkout. The projection contains the frozen HEAD plus tracked and
non-ignored untracked workspace content, but no index, Git metadata, ignored
dependency tree, project configuration, task/state artifacts, credentials, or
other undeclared host paths. Writes are discarded after verified process
retirement. Operators must declare scratch/cache or pinned artifacts separately
when the build needs them; source projection does not grant raw network, host
cache, or arbitrary mount authority. Legacy runs never gain it from current
configuration.

Execution pauses as `plan_revision_required` when runner-observed HEAD already
contains the current planned subject or moved outside verified commit settlement.
The operator must revise the plan and start a new run; external commits are never
adopted into progress. A reported first-step position can precede completed
bootstrap. Completed runner-owned effects retain verification-only recovery.

Plan authoring's `preferredCommitLineLimit` is a positive-integer planning
target, default 900, configured through runner settings or the safe project
overlay. It is persisted for the run; legacy runs receive 900 without adopting
current configuration. CLI pipeline listing and MCP pipeline metadata expose
the descriptor-owned default. It does not restrict execution diff size.

Pinned dependency declarations freeze canonical public HTTPS URLs and SHA-256
digests alongside command vectors. During finalization, the runner downloads
verified files into private storage and exposes a fixed read-only dependency
mount to the network-isolated check. Acquisition failures pause for environment
repair; resume cleans prior resources and retries the saved declarations. Changing
a URL or digest requires a new run. Checks perform any extraction in declared
scratch; the runner does not install host tools.

## CLI and MCP control

The CLI provides run, resume, pause, cancel, status, pipeline discovery, and
MCP server commands. MCP exposes matching `run_pause` and `run_cancel` actions
alongside the same static pipeline registry through STDIO and keeps standard
output exclusively for protocol traffic. It never launches an editor;
pending clarification and product-decision input is represented as a structured
request with a revision and stable request ID.

Mutating MCP calls require idempotency keys. Intent is persisted before
mutation and a receipt before return. Work continues in a detached process, so
a client disconnect or wait cancellation ends only that client's wait and does
not create a second execution owner. A compatibility token prevents an old MCP
process from dispatching a newer or otherwise incompatible workflow. An
ownerless applicable stop may be recovered by exact-revision, action-free
`run_resume` with a new key; that separate durable intent makes the original
pause/cancel key unnecessary without replaying its acceptance receipt.

Audit is available through `run audit` and MCP `run_start`. Pipeline discovery
exposes `sourceScope` (`directory` by default or explicit `git`) and `excludePaths`.
CLI uses `--source-scope` and repeatable `--exclude-path`; MCP uses the setting
names. Exclusions require directory scope, stay literal and confined, and cannot
hide required inputs, configuration, artifacts, controls or link dependencies.
Scope settings freeze before preparation and Git membership before capture.
Changed selection requires a new run. Status exposes `auditSource`; new reports
show the frozen source scope and literal exclusions. Legacy reports and bindings
remain unchanged. Pipeline discovery
exposes its Auditor/Reviewer roles, independent default/recommendation and finite
20-pass discovery/recheck settings. Status includes `auditReport` publication
path/status/hash, finding counts and consumed pass totals. Pending candidates
remain unverified; unavailable evidence stays in the report. Audit completion
with Critical findings creates no automatic issue and authorizes no repair.
Invalid audit role results expose bounded field/constraint diagnostics in the
shared CLI/MCP pause evidence. Resume targets the saved checkpoint with structured
correction feedback, preserving consumed passes, pending findings and prior
decisions; it never exposes rejected output or renews a budget. The
[audit specification](../../pipelines/audit/docs/SPEC.md#structured-report)
owns diagnostic and compatibility details.

Audit admission publishes a durable identifier before recursive preparation.
CLI creation activity includes status, pause and cancel commands; MCP start
acknowledges exclusively owned detached preparation without waiting for capture.
Status exposes pending `workspacePreparation` while the workflow stays in
`CLARIFY`. Pause/cancel can stop capture before any provider turn. Resume reuses
frozen inputs/configuration and reacquires the canonical exclusion owner;
cancellation retains that evidence and remains terminal. Status/activity/waits
cannot drive preparation, and a disconnected wait cannot stop detached work.
See the [audit lifecycle](../../pipelines/audit/docs/SPEC.md#read-only-discovery-lifecycle).

## Durable state and local artifacts

Run state lives under the user's OS state directory, outside both the target
repository and task directory. Each transition is a complete write-ahead event
followed by atomic current-state replacement. The human-readable progress file
is derived and can be regenerated; the event journal remains authoritative.
Execution also publishes a run-owned `plan.progress.md` beside unchanged
`plan.md`, showing size decisions, original/replacement progress and verified
SHAs. CLI/MCP status and activity derive the same information from state;
Markdown edits cannot accept revisions, complete work or replay effects. Resume
regenerates missing/stale owned output after interrupted publication. Other
owners and unsafe or nonignored repository-local paths are rejected. Artifact
conflicts cannot prevent operator pause/cancel settlement or safe lease release;
publication failures are reported after settlement. See the
[refinement progress contract](../../pipelines/plan-execution/docs/SPEC.md#derived-refinement-progress).
Accepted structured results have 2 MiB of serialized UTF-8 headroom, with finite
larger state and recovery containers. Journals roll over into bounded segments
while retaining the complete authoritative history and crash-recovery ordering;
capacity exhaustion preserves the last accepted state. See the exact
[storage and result budgets](../ARCHITECTURE.md#structured-result-headroom).
One leased recovery can repair an incomplete active tail and durably retire
interrupted observation accounting using the verified repair result. It keeps
the complete original history and publishes matching state and progress;
observation retirement still waits for process and resource ownership settlement.
Repair verification failure leaves retirement pending. A successful subsequent
recovery neither repeats truncation nor adds another retirement event.
Repeated reads may reuse bounded process-local validation checkpoints only after
fresh byte and identity verification of their complete cached prefixes. Current
snapshots still require exact journal matches; cold reads and uncertain bindings
use full validation. Reuse never removes history or changes recovery, revision,
progress, activity, or exclusive mutation guarantees.
Validated public records may also serve progress regeneration and activity
pagination within explicit record and byte caps. Overflow or an older activity
cursor streams the certified history without revalidating unchanged historical
states; every activity, event-specific stop summary, revision, and progress line
remains available. Even early-limit pages and atomic progress replacement
require proof of the entire original prefix. A full scan racing with append or
rotation retains its consumed-byte bindings independently of optional caches.
Bounded canonical validation must prove those original bytes, identities,
segment namespace and captured endpoint before certification; a later valid
history or equal endpoint alone is insufficient. Missing or uncertain proof
returns no page or replacement. Activity reads and waits permit two bounded
continuations only after each preceding certified prefix is proven unchanged
and extended by a later revision. This retains the original run identity and
byte proof through both continuations. Further proved publication exhausting
that bound returns `ERR_RUN_OBSERVATION_BUSY` with `retryable: true`; a later
explicit observation is safe and the run continues unchanged. MCP projects that
typed outcome without automatically retrying. Corruption, rollback, substitution or uncertain proof
still returns no page and grants no retryable classification. Publication
callbacks cannot replace the original certificate with different history,
including through snapshot rollback or nested reads. Full-scan certification
uses the same continuation bound and pairs each page's cursor with its snapshot;
it grants no mutation, recovery or stop authority.
Public projections remain bounded and exclude private results. These byte
limits are headroom, never token budgets or evidence of a native output ceiling.
Bounded diagnostic observations retain the latest 32 runner attempts, identified
by role and exact checkpoint, including failed and interrupted work. An omitted
attempt count makes retention explicit. Native cumulative usage keeps its scope;
snapshots are never summed into an invented attempt total, and unavailable
counters stay unknown. Interrupted, failed, or unobserved terminal accounting
remains incomplete. Legacy runs have absent observations until new attempts
occur. Observation publication is coalesced at native fallback and terminal
boundaries and uses the same write-ahead recovery; it grants no retry or effect
permission and stores no prompts, transcripts, or native session identifiers.
Runner results and MCP status/wait expose this bounded `observations` evidence;
CLI status shows the latest attempt, and activity records concise start,
fallback, and terminal summaries. Optional measurements distinguish supplied
prompt/reconstruction/schema bytes and returned output/structured JSON bytes
from provider tokens. Earlier attempts project absent measurements as null.
Referenced-file bytes and read counts remain unknown; including a path in a
prompt does not prove its contents were supplied or read. These figures exclude
native wrappers and existing session context and cannot establish service limits
or complete consumption. Diagnostics contain only allowlisted evidence, never
reasoning, tool output, secrets, arbitrary errors, or other provider content.
The common run envelope also holds one bounded provider-policy receipt slot per
resolved role. Legacy state migrates before provider work and pins a role's
first current receipt when that role is required; resume rejects policy drift
instead of re-resolving isolation.
The receipt exposes only a fingerprint and common supported access modes, never
provider flags, credentials, native output, prompts, or session storage.

Plan authoring writes its declared task artifacts. Plan execution and polishing
may place runner-owned clarification artifacts below the configured repository
artifact root only after Git proves the path is already ignored. The runner
does not edit target ignore rules.

One execution lease protects a mutating run. Plan execution and polishing also
hold a canonical-worktree lease so independently identified runs cannot mutate
the same checkout concurrently. Plan execution's descriptor-proven untouched
initial `CLARIFY` stop is the narrow state-only exception: it retains the run
lease and settles without acquiring a canonical lease recorded for an unrelated
run. Every checkpoint that may require repository reconciliation or effect
verification keeps normal worktree exclusion. Status and activity reads remain
lock-free.
An abandoned current same-host execution or canonical-worktree lease becomes
eligible for immediate recovery only when its complete boot/PID/start identity
proves the exact owner dead or replaced. Acquisition age is neither a delay nor
ownership proof. Legacy, identity-free, foreign-host, live, invalid, and
otherwise unverifiable records remain exclusion barriers. Short state
mutations observe competing claims at most 500 times with 10 milliseconds
between observations (about five seconds plus file system work), then return a
retryable busy result rather than risking two writers. The smaller fixed
publication and collision retry counts are correctness mechanics, not
operator-configurable workflow budgets.

Lease ownership, same-run recovery responsibility, and a persisted execution
process are independent facts. A current owner reuses its existing worktree
lease while stopping; after owner loss, the replacement execution owner may
reclaim only the exact same-run lease and must prove the recorded process and
all owned descendants absent before clearing the process record. Live,
replaced, unverifiable, or descendant-bearing process evidence remains a
blocking ownership condition. Retirement and stop settlement are separate
journaled transitions so an interruption safely retries either boundary.
Shared-host recovery uses positive association through owned-session membership,
a matching launch token or observed owned ancestry. It follows available parent
links through inaccessible environments and retains observed association through
later evidence loss. Unassociated processes neither block progress nor receive
signals because metadata is unreadable, their session is newer or their cgroup
is shared. Historical ancestry and control-group proofs remain strictly validated
but optional; no historical evidence is synthesized. Required owner identity,
namespace checks, live-owner exclusion and bounded inspection remain mandatory.
Shared-host discovery cannot prove absence against arbitrary same-user processes
hiding all ancestry and token evidence. The
[safety contract](SAFETY_MODEL.md#inputs-artifacts-and-state) owns exact retirement
rules. Public projections never expose private process proofs.

## Pauses, resume, and observability

The runner service distinguishes an operator pause from cancellation. A pause
retains the frozen run and its reconciled checkpoint; its null resume action
restores any existing blocker before ordinary work can continue. Cancellation
produces inspectable terminal `CANCELED` state and cannot be resumed. Safe
partial workspace changes and task artifacts remain available in either case.
CLI shorthand captures one status revision and key, while explicit CLI and MCP
requests require both values for repeatable automation. Exact retries replay
their durable receipt; stale requests are never refreshed implicitly.

The runner service supports `after-current-commit` for a selected execution
step, including suspended steps; other pipelines and pre-step checkpoints reject
it. CLI pause/cancel accepts `--timing`; MCP stop tools accept `timing`, both
with `immediate` and `after-current-commit` and omission equivalent to immediate.
Exact retries preserve timing as well as revision and key. A deferred request lets that target
finish normally while retaining ownership. An immediate cancellation can
supersede it. Verification records the commit and stop outcome before the next
step; a pause, failure, or interruption instead settles at the reconciled
quiescent checkpoint without extra work. Existing blockers and failure evidence
remain available. After the final commit, pause resumes through `DONE` without
agent work; cancellation retains completed history in `CANCELED`.
For newly eligible execution refinement, the target is the original logical
step: verified child commits retain the pending stop, and its last replacement
settles the stop atomically. Accepted revisions never shift that target to
unrelated later work.

Stop requests are durable before immediate owned execution is interrupted. Activity
reports stopping, repository reconciliation, and the resulting state, while
leases remain held until accounting completes. If a commit or handoff already
began, verification records the observed effect without undoing or replaying it.
Retained safety blockers remain visible through the bounded pause projection.
An ownerless accepted request starts detached same-run reconciliation, and a
client disconnect cancels only its wait. Public status and waits expose the
pending kind, accepted revision, requested/effective timing, and target step
without the request identity or private checkpoint. The bounded `stop` summary
also remains after settlement. Its state is `pending` while awaiting the target,
`applicable` for immediate requests or suspended/failed checkpoints awaiting
reconciliation, and `settled` after accounting. Ownership loss still requires
reconciliation even when the durable summary is pending. Settlement is nullable
for pending or legacy records, otherwise `quiescent` or `commit` with the verified
SHA. Activity projects the summary from each historical event, while receipts
replay immutable acceptance evidence. Cancellation is a terminal wait result
and older intents cannot revive it.

MCP supervises a stop child through durable settlement or that correlated
child's exit; transient run-lease ownership is never reported as reconciliation.
Exit first leaves the stop applicable and the recovery intent retryable, with a
distinct version-skew outcome when applicable. Fresh public recovery rejects a
stale revision, non-null action, live owner, or duplicate-owner race. When a
non-quiescent stop is blocked by a canonical lease, diagnostics distinguish the
ownerless pending run from the different run recorded as lease owner. Operators
must use supported recovery and reclamation rather than manually deleting or
bypassing lease records.

The state boundary can retain a bounded recovery cause separately from workflow
state and action receipts, even before a child acquires its execution lease.
Only exact correlation with the recorded dispatch and child identity makes that
cause available. Missing historical causes remain unavailable; an exit or signal
does not establish why recovery failed. Stored causes contain only recognized
Runner codes, finite stages and fixed explanations. The CLI publishes failed
detached resume causes and uses those same safe explanations. MCP tool errors
carry separate `dispatchFailure` exit-code/signal facts and nullable
`recoveryCause` stage/code/explanation fields in text JSON and structured content.
After restart, a retained correlated cause can remain available while both exit
facts are unknown. Missing, invalid or mismatched causes are explicitly
unavailable. Errors keep the intent incomplete, and live or unverifiable
ownership still excludes another child. Retry the identical key and arguments
after addressing the reported blocker; a retry itself is no repair guarantee.

Legacy opaque plan-execution failures during terminal confirmation can expose
an action-free retry in either mode when durable history proves acceptance and
finalization. CLI and MCP share that eligibility; status remains lock-free and
does not reopen the run. Execution rechecks proof and safety under the normal
leases before resuming confirmation. It preserves completed commits, settings,
lineage, evidence, and accounting. A true correction marker may represent an
already charged fix rather than pending work; operators must not edit it.
Absent or inconsistent provenance grants no retry, and MCP retains its exact
revision, durable receipt, idempotency, and detached ownership guarantees.

Normal work is autonomous. The runner pauses for identified clarification or a
material product decision, required provider authentication, provider
unavailability, an external validation
blocker, exhausted correction budgets, version skew, unsafe Git state, or an
ambiguous effect. Each public pause exposes a finite reason, bounded evidence,
the safe resume checkpoint when one exists, and concrete next actions. It does
not expose prompts, transcripts, credentials, rejected provider output, or raw
diagnostics.

An eligible pre-effect transient launch failure adds the same strict
`launchRecovery` value to CLI and MCP status: only its normalized failure class
and launch checkpoint. An operator pause preserves that projection with the
underlying availability blocker so action-free restoration shows the same
state. Accepted resume clears it with the pause, and cancellation removes it
from the retained private checkpoint. It never authorizes a second source fork
or a commit effect.

If an unexpected runner-owned invariant rejects a plan-execution finalization
transition, both CLI and MCP status expose the same bounded diagnostic and an
explicit retry from the retained `FINALIZE` checkpoint. Rejected finalization
evidence and native process output do not enter the pause record.

Increasing the trusted-command deadline does not change isolation or expose
discarded stdout/stderr. A command that passes on the host may still return only
a generic isolated exit failure; timeout configuration is not a sandbox or
diagnostics remedy.

Plan execution and polishing pause as `finalization_evidence_rejected` at
`FINALIZE` after two automatic semantic retries per execution step or polishing
run. CLI and MCP expose bounded finding identities and an explicit null retry
for exactly one additional complete finalization attempt. Applicable
independent-mode finding overrides remain tied
to the terminal content fingerprint; closing feedback still requires replacement
finalization and fresh confirmation. Provider availability or interruption
resumes an already pending attempt without charging another retry.

Public activity records the actor, phase, event kind, and concise message. The
workflow checkpoint, active role and phase combine with lease ownership to
distinguish running, interrupted, and idle work without polling a provider or
depending on a heartbeat. MCP status and wait additionally report the finite
lease-owner classification and whether a process record is persisted, without
exposing a PID or process identity. A held or new MCP wait also completes
promptly and reports `interrupted` when the lease owner is positively observed dead or
replaced at a checkpoint requiring continuation, even between turns with no
active turn, execution process, preparation record, or revision change. Terminal
states and unresolved user input keep their existing semantics. Unavailable
identity, another host, and released or transferring leases keep waiting. The
wait never writes state or replays effects; recovery is an explicit `run_resume`
with `action: null`, the inspected revision, and a new idempotency key. An interrupted owner
reconstructs work from durable state after revalidating inputs and the
repository.

Repeated choosing/ready and other control publications leave unchanged journal
prefixes eligible for byte-certified reuse. Directory metadata churn alone
does not force historical state normalization. Actual journal namespace or byte
changes still require conservative validation; a cold or evicted optional
checkpoint receives full canonical validation rather than a corruption diagnosis.
Status and activity reads remain lock-free, with complete durable history and
the same bounded retention and mutation exclusion.

Unexpected-issue reporting is an optional MCP-only operator action for behavior
that contradicts the documented runner contract. Expected pauses, invalid
input, configured limits, and environmental blockers are not unexpected
issues. Reports contain only caller-supplied bounded Markdown; the runner does
not attach logs or secrets automatically. Reports are published to the
[global issue store](#global-issue-store).

## Global issue store

Deliberately reported issues form one cross-project backlog in a private
per-user data store, not in any project: `$XDG_DATA_HOME/agent-runner/issues/`
on Linux with the `~/.local/share` fallback, user Application Support on macOS,
and local application data on Windows. The mapping adds no execution-platform
support. Reports are durable user data, separate from settings, installed
payloads, run state, and caches, and they remain after the originating
checkout, worktree, or directory is deleted. Publication requires no project
ignore rule, never changes ignore rules, and never writes to the project; the
origin is recorded as context, not used as a storage location.

Capture accepts Git worktrees and ordinary directories. A Git selector binds to
its canonical worktree root; a non-Git selector binds to the canonical selected
directory. Unsafe control-tree origins and failed Git inspection are rejected.
Origin selection reads no source-file contents, loads no project configuration,
and grants no Git effects.

Each issue has a stable opaque ID and one document combining the immutable
caller-authored Markdown with its single authoritative tracking record. The
record holds the origin project name and path, creation and update times,
revision, optional run ID and error code, and a status from the finite set
`open`, `queued`, `in_progress`, `resolved`, and `dismissed`. Resolved and
dismissed account for repaired and deliberately irrelevant issues. Optional
bounded plan references, resolving commit references, and a concise
disposition note are caller-supplied text; the runner never dereferences them,
inspects another project, or validates remote state. New issues start `open`
with empty references and no note.

Creation is idempotent and interruption-safe: an exact retry returns the
original receipt even after the origin is deleted, and recovery completes the
reserved issue in the reserved store without duplication. A changed store
location or replaced store directory fails rather than replaying elsewhere.
Unsafe permissions, symbolic or hard links, and overlap with projects,
settings, run state, or the installation are rejected.

The backlog is managed with list, read, and update operations, projected
identically through MCP (`issues_list`, `issues_read`, `issues_update`) and
the CLI (`agent-run issues list|read|update`). They remain available when
deliberate capture is disabled; disabling capture only removes new-report
creation, which stays MCP-only. They use only the issue store and issue coordination,
never inspect an origin project, and never take or pause a worktree lease, so
they work after the origin is deleted and while unrelated runs execute. Listing
covers all projects and statuses unless filtered by exact recorded origin path
or status. It is ordered by creation time, then ID, in bounded pages whose
cursors are bound to the store and filters. Pages are live: an issue whose
status changes between pages may enter or leave the filtered set, and no issue
is returned twice. Unfinished creations are not listed.

Updates change only status, plan and commit references, and the note; the
report, ID, origin, and creation information are immutable. Any status may
follow any other, so a resolved or dismissed issue can be reopened. Every update
names the inspected revision and document hash plus an idempotency key. A stale
update fails without change; an exact retry returns its receipt even after a
newer update, never overwriting it. An interrupted update is completed or
proven stale before another writer changes that issue, and it never replays
against a moved or replaced store.

Earlier repository-local reports and the optional repository-local issue index
are not current: the runner neither discovers, imports, nor migrates them and
never changes those files. A historical completed receipt still replays
unchanged. An incomplete historical local publication fails explicitly without
touching its files; retry with a new idempotency key to publish globally.

## Project-local operating guidance

The shared guidance capability composes the installed operator guide and the
entire optional `<artifactRoot>/agent-runner/rules.md`, using current new-run
configuration resolution. Its base is the selected infrastructure root, including
an explicitly selected external setup; without configuration it is the target.
Ordinary directories are supported without Git. Git selectors use the worktree
target, including explicit configuration selected from a subdirectory. An explicit
configuration bound to the supplied directory retains that scope and shares the
enclosing worktree's exclusion key.
Explicit selection never merges competing placements or initializes infrastructure.
Clear boundaries state that local additions may
specialize project operation but cannot weaken common safety or product
contracts. Before init, an absent, untracked local guide needs no ignore rule for
CLI/MCP reads. The result retains complete common guidance, empty local content,
a null local hash and the resolved metadata. Reading creates no files,
directories, bindings, ignore rules, editor session or state.

Local guidance is a complete, bounded, non-sensitive Markdown document. Whole
replacement uses an expected content hash, an idempotency key, atomic
publication, and the canonical-worktree lease. External publication also leases
the infrastructure tree to exclude writers from other targets selecting the
same destination. Stale concurrent edits fail;
completed retries return their original receipt even after subsequent edits or
configuration changes. Incomplete publication retains its selected paths,
configuration and directory identities across restart; substitution or drift
requires reconciliation, never automatic redirection. Existing integrated guides,
edit/update destinations and temporary files in Git remain ignored and untracked;
external resources require the exact target binding and confinement, with no
target or Git-control writes.
Empty content means no additions. The common guide is never replaced.

CLI operators use `agent-run guidance --project <directory>` to read both documents
and `agent-run guidance edit --project <directory>` to edit the entire local document.
Both accept `--project-config <path>`. Editing uses a private external copy in
`$VISUAL` or `$EDITOR`; failed or signalled closes preserve local guidance.
Unchanged closes still recheck safety and concurrency, and leave a missing
local document absent. No pipeline run is constructed for either command.

MCP supervisors call `guidance_read` once before first managing a run for each
project, including when issue reporting is disabled. It returns the complete
combined guide, separate common and local documents, resolved paths, and
`localHash`. Both guidance tools accept `projectPath` and optional
`projectConfigurationPath`. `guidance_update` replaces the whole local document
using full `localContent`, nullable `expectedHash`, and an `idempotencyKey`.
Null requires an absent file; an existing empty file has a hash. MCP never
opens an editor. Replacement is local, potentially destructive, and idempotent;
its bounded receipt contains paths, the resulting hash, and an `updated` flag.
Retry the same logical mutation with identical arguments and key after a lost
response. Completed receipt replay preserves later edits and is not a fresh
read. A stale edit requires rereading, reconciliation, and a new mutation key.

Record stable project operating lessons here after execution releases ownership.
Task requirements belong in task context or tracked project documents, universal
rules in the common guide, and genuine Runner defects in deliberate issue
reports. Guidance belongs only to the supervisor: pipeline roles do not receive
it, and runs neither persist nor reload it.

Valid dirty work left by a genuinely non-resumable run may be recovered through
polishing after ownership is gone and inputs are reconciled. Plan execution
still requires a clean worktree; polishing still stages without committing.
Contaminated or unsafe mixed content requires an uncontaminated worktree,
not adoption by a different pipeline.

Action-free continuation is shared by CLI and MCP, including a finalization turn
whose process-retirement proof is temporarily unverifiable. The saved turn stays
resumable while ownership remains safety-blocking; successful retirement precedes
ordinary checkpoint reconstruction. CLI may bind `--expected-revision`; MCP
always requires the exact revision. Action contention and bounded detached
observation return retryable ownership results with the original intent intact.
Identical-key retries use correlated durable dispatch evidence and cannot create
a second live owner. Cancellation, timeout, and disconnect end only the observing
wait, not reconciliation or receipt publication. A receipt acknowledges accepted
continuation or the particular stop's settlement, never content approval.
