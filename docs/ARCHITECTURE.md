# Architecture

Agent Runner is an npm-workspaces monorepo with one root CLI/runtime, shared
commit-plan and custom-plan contracts, and independently owned pipeline workspaces.

## Dependency Direction

```text
root CLI/runtime ──static registry──▶ pipeline workspaces
                                           ┊
                                           └┄ when consumed ┄▶ shared plan contracts
```

The root runner imports registered pipelines. Pipelines do not import the root
application; the runner supplies state, event, agent, and Git services through a
runtime context. Plan authoring and execution consume
`@agent-runner/commit-plan`; polishing has no shared-package dependency, and
pipelines never depend on each other. Do not declare an internal runtime
dependency before an actual import needs it.

## Root Runner Ownership

- CLI parsing, pipeline selection, and concise terminal output.
- Local STDIO MCP tool schemas, projections, and detached-run dispatch.
- Versioned runner configuration loading, validation, and role resolution.
- Run IDs, atomic state, append-only events, resume, and status.
- Clarification files, editor invocation, transcript updates, and input hashes.
- Common operator guidance, complete local additions, and safe durable replacement.
- Frozen provider registration plus adapter execution and access-mode
  enforcement.
- Git snapshots, content fingerprints, read-only guards, remote/identity guards,
  constrained local-commit verification, and verified polishing staging
  handoffs.
- Runner-trusted exact-vector validation outside agent turns, with bounded
  results and repository mutation guards.
- Static pipeline registration.

The root is one application, so these modules are not separate workspace
packages. Extract one only after it gains an independent consumer, release
lifecycle, or dependency boundary.

Each JavaScript source directory exposes outward-facing dependencies through
its `index.js`. Imports between modules in the same directory remain direct to
keep ownership visible and avoid barrel cycles. The source-boundary regression
checks those imports and the root-to-pipeline-to-shared-package dependency
direction from source and workspace manifests.

The state capability lives under `src/state/` behind its public `index.js`.
The index exposes only the run-store and runtime contracts used outside the
capability; its private service composes confined file operations, the
write-ahead journal, durable actions, execution leases, and state validation.

The Git capability lives under `src/git/` behind its public `index.js`. The
small index exposes only the service factory and shared safety error; its
private service composes command execution, content and snapshot inspection,
change measurement, exact source materialization, commit verification, and
polishing handoff modules without exposing their implementation contracts to
root consumers.

The filesystem-only workspace capability lives under `src/workspace/` behind
`createWorkspaceService` and `WorkspaceSafetyError` in its public `index.js`.
Private `paths.js`, `controls.js` and `snapshot.js` own confinement, filesystem
control discovery and guarded capture; `service.js` composes inspection and
mutation guards.
The runner's private `workspace.js` selects descriptor-owned workspace/lease
requirements before Git inspection and binds directory policies through this
capability. Authoring explicitly selects Git for commit plans or the directory
lifecycle for custom plans. Execution selects the same lifecycle explicitly.
Preliminary boundary discovery selects only the workspace policy; execution
parses declarations through a confined task-input capability after project
configuration and run overrides resolve, before Git inspection.
It is the directory inspection foundation for custom planning/execution, audit
and init. Custom authoring, execution and audit consume it; init publishes reviewed setup. Git snapshots remain Git-owned.
`inspect` accepts an existing `workspacePath`, external `stateRoot`, optional
`taskPath`, and arrays of `inputPaths`, `sourcePaths`, `outputPaths`,
`configurationPaths`, `artifactPaths` and `infrastructurePaths`. Relative paths
resolve from the workspace. Reads require existing paths; outputs, artifacts,
infrastructure and state may name missing destinations. Duplicate/descendant
read declarations collapse to their declared parent without granting writes.
Outputs must be proper workspace descendants disjoint from all protected
declarations and control trees. State is disjoint from workspace, task,
infrastructure, declared read trees and discovered controls. Inspection grants
no provider access, retrieval, publication, Git effect or write authority.

Filesystem discovery protects `.git`, `.codex`, `.claude`, `.agents` and
`.claude.json`, including nested controls and enclosing repository controls for
the workspace and declared external paths. Discovery also inspects protected
control directories for nested Git pointers and their external metadata,
including dependencies reached through other metadata directories.
Bare Git layouts are recognized by `HEAD`, `objects` and `refs`; their entire
metadata directory is protected and cannot contain the workspace.
Bounded regular-file reads resolve Git `gitdir:` and `commondir` pointers to
their real metadata directories without executing Git, rejecting aliases before
normalizing pointer dot segments. Arbitrary ancestor home
directories grant no provider-storage reads; their existing provider controls
still exclude overlapping state storage, including resolved alias targets.
Canonical provider-control targets overlapping the workspace are protected
against output authority; unrelated external provider storage is not captured.
Ancestor provider aliases resolve component by component and reject writable
output or state dependencies, including hops erased by later dot segments.
At the workspace root, its descendants and enclosing-repository ancestors, a
symlinked `.codex`, `.claude`, `.agents` or `.claude.json` is an internal
provider-control alias resolved by the same component-wise resolver. Its
canonical target must be a real directory with real ancestors strictly inside
the link's parent, outside Git metadata, not containing the workspace and
disjoint from state storage. Discovery then protects both the link and that
target and traverses the target for nested controls; the alias grants no reads,
outputs or mutable roots. Escaping, parent-equal, dangling, cyclic, file,
special-file and Git-metadata targets fail with control-specific diagnostics,
and a symlinked `.git` remains rejected as a non-ordinary Git control. Full
`inspect` still rejects any alias among its control bindings, because those
bindings feed directory workflows and provider projections; only the
controls-only `inspectControls` query accepts them.
Routing directories remain pinned by identity and mode, while links and files
retain full metadata checks. Unrelated sibling creation outside inspected trees
does not invalidate alias resolution; inspected trees retain their complete
listing and metadata race checks.
The state location's existing ancestors are also inspected for control overlap.
Git and shared metadata targets inside the workspace remain protected; unrelated
external state-ancestor metadata is traversed for nested Git pointers without
adding read or snapshot scope. This traversal preserves state-only scope through
pointer dependencies and terminates cycles.
Reserved output components stay
forbidden even before their control paths exist. Workspace roots cannot be
inside reserved control components, including outside Git repositories. All
declared ancestors must be real directories; aliases in declarations/ancestors,
multiply linked regular files, undecodable names and special files fail closed.
Snapshots hash link text without reading linked file bytes and confine
resolution to the declared tree or explicitly bound protected trees. Real
ancestors may connect those trees without granting reads of their other
children, supporting `.claude/skills` links to protected `.agents/skills`.
Unbound intermediate hops, escaping, dangling and cyclic links fail.
Resolution dependencies participate in snapshot
race checks; snapshots return sorted `linkResolutions` alongside entries so
output consumers can bind readable dependencies outside a selected subtree.
Existing entry and input fingerprints remain unchanged.
Links cannot cross writable boundaries in either direction, including
through intermediate resolution hops.

`snapshot({inspection})` rechecks pinned ancestors and control bindings and
captures the complete workspace plus explicit external protected paths. On the
current Linux runtime, pinned directory descriptors through `/proc/self/fd`
anchor enumeration and regular-file reads; unavailable descriptor access fails
closed. Handle/path metadata and directory listings are checked around reads
and again before completing capture, including missing-path ancestor bindings.
Workspace and protected-path identities remain pinned throughout capture.
Results contain sorted metadata and hashes, never file bytes. Content
fingerprints bind paths, kinds, modes, sizes and content; separate identity
fingerprints also bind inodes and file timestamps.
`snapshotInputs({paths, stateRoot})` captures only explicitly declared read trees
with the same confined, race-checked reads and ancestor bindings. It rejects
state overlap and grants no reads of unrelated workspace content. Supplemental
commit-authoring criteria and sources use this narrower capture while Git owns
the repository snapshot and mutation guards.
`assertUnchanged({before, after})` rejects content or identity drift; explicit
`allowOutputs: true` permits only declared outputs and newly required parent
directories, preserving unrelated files and all protected inputs. Filesystem
injection supports deterministic race tests without Git or providers.

Directory lifecycle protected fingerprints exempt only declared outputs and
artifacts. A task root coinciding with or containing the workspace never exempts
other project content; runner-owned task artifacts must be declared explicitly.

`readFile({path, projectPath, optional})` confines text input reads to a real
regular file beneath the supplied root, reusing descriptor-anchored snapshot
reads with no-follow, nonblocking opens and read-race checks. Only an absent
optional file returns null; aliases and special files fail before content reads.

`measureChanges({projectPath, baseHead, expectedContentFingerprint})` measures
the final worktree against the caller-verified immutable step-start commit
(or null for an unborn baseline). Existing staging-independent source inspection
discovers changed paths and verifies the candidate fingerprint before and after
measurement. Only discovered change candidates and index-hidden paths are read;
the latter retain the existing content checks. Each changed path is counted
once, including new non-ignored files, regardless of partial staging or
index-only bytes. Replacement refs cannot reinterpret the baseline. Guarded
reads supply raw baseline and worktree bytes to deterministic shortest-edit
line counting using Myers' algorithm, without temporary files, external diff
helpers or text conversion.
LF terminates a line; raw bytes, CR and missing final newlines remain significant.
Text additions and deletions sum to `changedLines`; a NUL in either side's first
8,000 bytes marks a binary path, reported separately in `binaryPaths` without
invented line counts. Symlinks contribute their target text without following
it; gitlinks are listed
separately in `gitlinkPaths`. The sorted `changedPaths` bind assessed scope
without reading unrelated files. Content drift rejects the measurement. This
capability does not stage, invoke agents or validation, assess thresholds, or
change workflow eligibility.

Unfinished-work preservation is a separate Git/state capability consumed by
execution replacement preparation. `capturePreservation` requires run and worktree leases at a
reconciled checkpoint. The state journal publishes an intent bound to the exact
run, revision and inspected snapshot before storage allocation. Git's
`captureChanges` reuses guarded source inspection and immutable baseline reads
to capture baseline/current bytes, deletions, executable modes and unfollowed
link targets for changed paths. Payloads and manifests remain in confined
external run storage under reserved `.preservation-*` names. State reads back
every blob and pins directory, manifest and blob identities before publishing
capture completion. Interrupted attempts remain retained and are never adopted
as verified payloads.

`restorePreservation` journals the exact authorized paths, accepted current
snapshot, restoration plan and identities of prepared files and their parents
before destructive effects. Git's `prepareRestoration` and `applyRestoration`
require selected paths to match their saved baseline or current content and their
current HEAD baseline to match the saved baseline. Later child commits on other
paths remain intact. Recovery verifies unrelated content, index, history, refs,
remotes, identity, repository/control identities and surviving parent directories,
including those created during restoration. Confined parent descriptors,
exclusive temporaries and atomic replacement prevent following aliases or
adopting substituted writes. Explicitly selected file or link ancestors hide
descendants without following links and are removed before descendants are
created. Unselected aliases remain forbidden. Selected directory identities are
pinned even when they have no saved children. Only empty directories may be
removed for checked file/directory or link/directory replacements; uninspected
children survive.
Each restoration blob read rechecks the journal-bound capture record's identity
and hash, ownership of the capture directory and stable manifest evidence,
including after prepared-file publication and before replacement. Completion
revalidates that capture authority. Final saved-blob reads precede the last
repository/control, ancestor and destination checks; destination content is
inspected through its pinned parent immediately before deletion or replacement.
Prepared and applied writes reconcile without replaying completed operations.
`reconcilePreservation` can settle only an existing restoration intent during
operator-stop recovery, under the same run/worktree leases and byte/control
guards. It returns no receipt for an unstarted operation and cannot start
capture or grant new restoration authority.
Recovery syncs the verified surviving parent before accepting an already-applied
write, completing durability even when interruption followed rename or unlink.
Temporary creation has its own journaled intent and parent bindings. Before
identity publication, recovery accepts only an empty regular file or the exact
saved link target; regular bytes are written only after identity publication.
Missing parents have a separate creation intent and a durable identity binding
before descendant work. Recovery rejects an existing parent whose creation
was interrupted before identity publication rather than adopting it.
Interrupted writes resume only on that inode with a saved-byte prefix. A ready
record binds the complete bytes and mode before atomic replacement.
Cancellation and transient `executionResource` cleanup never dispose of saved
work; no deletion API is exposed.

`inspectHead` reads the current commit object ID and that immutable object's
subject, including unborn HEAD as `{head: null, subject: null}`. Plan execution
uses this observation before writable entry and ahead of generic resume or
interruption drift handling. An exact leading-plan subject already at HEAD, or
external HEAD movement from the saved baseline, requires plan revision without
adopting the commit. Consumed runner-authorized commits settle verification-only
first; only that verified settlement changes plan progress.

Plan execution owns bounded step assessments and semantic context validation in
its private `plan-position.js` contract. Every context-producing phase receives
the runner-selected subject and verified completion evidence. A separate
read-only review checks narrative directions before acceptance; matching fields
cannot override contradictory prose. Its `plan-context` interruption marker
requires read-only reconciliation before replaying the producing checkpoint.
Version-19 migration invalidates legacy context before writable work while
preserving verification-only settlement of consumed commits. Root Git remains
the observation authority; agents and summaries never select the next step.

Plan execution also owns durable initial-implementation evidence. Its
`implementation-evidence.js` contract separates the original step/HEAD/content
baseline from mutable repository snapshots and reconstructs legacy evidence only
from the state-owned validated journal. State version 20 persists that evidence
before writable implementation and rejects unchanged initial results before
candidate convergence. Corrections retain their existing unchanged-result semantics;
verified commit settlement alone resets the record for the next step. Consumed
effects and stop recovery remain ahead of preparation for new writable work.

The trusted-validation capability lives under `src/trusted-validation/` behind
its public `index.js`. The index exposes only the contracts consumed by the
root runtime and capability tests; private service and execution modules keep
snapshot validation, exact command vectors, sandboxing, bounded evidence, and
repository mutation guards within the capability.

Execution's private `commit-size-assessment.js` owns safe threshold arithmetic,
fingerprint-bound atomic/split decisions and a three-attempt original-step
lineage ledger. Read-only assessment uses the continuing Worker in lazy mode
and a distinct configured Reviewer checkpoint in independent/combined modes,
before further convergence. Only scope/dependency expansion or more than one
additional preferred target renews assessment of an atomic exception. Proposal
and assessment allowances survive reconstruction and future replacement steps;
they grant no execution approval or effect authority. State version 29 persists
the resolved size settings and disabled eligibility, with a default-only
version-28 migration preserving existing progress. Version 32 activates dispatch
only for new commit-plan runs; migrations keep historical eligibility disabled.
State version 39 freezes `automaticCommitSplitting` in settings: new commit runs
are eligible only when it is `true`, disabled runs skip measurement and
assessment before any model call, and the version-38 migration derives the
switch from saved eligibility. See the
[owning contract](../pipelines/plan-execution/docs/SPEC.md#commit-size-assessment-foundation).

Execution's private `effective-plan.js` owns the reviewed-revision
contract. State version 30 persists proposals, exact flat plans, original-step
correspondence, completed-prefix provenance, complete versioned finding payloads
and ownership, and fingerprint-bound mode gates. The version-29 migration adds
empty authority without changing eligibility or progress. Lazy requires distinct
Worker plan convergence/confirmation; independent requires Reviewer approval; combined
requires both. Accepted authority must be journaled before boundary selection,
invalidates dependent content gates and retains consumed allowances.
Proposal bindings retain historical additional-round grants; reload enforces
cumulative lineage consumption, and any binding change requires fresh reports.
Deferred targets map to logical original work. Pending commits remain
verification-only.
Production routing selects only accepted effective authority while preserving
the unchanged canonical plan. See the
[revision contract](../pipelines/plan-execution/docs/SPEC.md#reviewed-effective-revision-foundation).

Execution's private `revision-validation.js` binds bounded discovery, complete
role inventories and compact schedules to accepted revision authority and exact
replacement positions. The public persisted validator composes this contract
with bootstrap progress. State version 31 retains separate additive revision
receipts without rewriting frozen-plan inventories. Validated splice
correspondence preserves unchanged assignments and future obligations; affected
applicability requires fresh read-only discovery from every active role. Only
complete roles produce the Worker-first schedule. Receipts bind confirmed
amendment commands, mapped applicability and infrastructure, enforcing them on
acceptance and reload independently of the active amendment's lifetime.
Capability preparation remains root-owned, and no receipt supplies check evidence
or materialization authority.
The version-30 migration adds empty receipts without inventing legacy proof,
preserving consumed effects and allowances. Revised implementation evidence
cannot be rebound by ordinal. See the
[validation foundation](../pipelines/plan-execution/docs/SPEC.md#revision-bound-validation-foundation).

Execution's private `plan-progress.js` derives refinement status and Markdown
from frozen plan text, assessment/revision ledgers, separation readiness and
verified completed commits. Its descriptor exposes the artifact projection and
`status.refinementProgress`; CLI and MCP use that same projection. Root Runner's
private `plan-progress.js` confines atomic publication to `plan.progress.md`
beside the frozen plan after state publication, with run ownership, regular-file,
canonical-parent and repository ignore checks. Reads, temporary writes,
replacement, synchronization and cleanup stay anchored to a validated open
directory descriptor. Runner defers publication throughout a consumed commit
until verification and durable settlement, so artifact failure cannot strand an
unattempted effect. Pending operator stops also defer publication until durable
reconciliation. Publication failure after settlement still permits state-checked
lease release, including reconciliation initiated during release.
A per-run publication queue serializes concurrent activity
producers and discards older snapshots after observing a newer state revision.
Publication failure preserves durable authority for leased
resume/regeneration; status remains read-only.
The artifact is never a workflow input. See the
[derived progress contract](../pipelines/plan-execution/docs/SPEC.md#derived-refinement-progress).

Execution's private `replacement-execution.js` coordinates assessment, reviewed
revision acceptance, complete role rediscovery and preservation through injected
capabilities. Version 32 persists separation IDs, the inspected snapshot,
capture revision and capture/restore/ready phases plus consumed lineage output
corrections. Root `runtimeFor` supplies the held run/worktree leases to the
state-owned preservation service; its capture binding uses the latest serialized
revision, including capability-preparation publications. After verifying every
saved byte, the state service supplies exact manifest/hash and content-addressed
blob references for read-only reconstruction. Complete file bytes stay external;
the cumulative reference context is bounded to 65,536 UTF-8 bytes. Before
restoration, the complete first reconstruction request must also fit the existing
32 MiB adapter limit. The Worker's provider-owned `canReadFiles` admission checks
every exact manifest and before/after blob path against its proved command
policy and host readability. Claude's runner-boundary masks make external
sources under `/tmp` or `/run` unavailable; native Read is not byte-exact binary
recovery. Missing admission support or inaccessible sources pauses as
`environment_blocked` before restoration, retaining the candidate and capture
for a fresh access check on resume without widening the sandbox.
References permit neither storage writes nor unrelated
state access and contain no native transcripts.

The complete unfinished candidate is captured before any removal. Restoration
reuses one journaled operation to restore all saved paths to their accepted
baseline. Its receipt reconciles before generic workspace-drift handling; ready
publication pins the clean baseline and retires completed bootstrap units while
retaining receipts and consumed subdivision/correction totals. It also retires
the former candidate's phase-local pending correction marker before `IMPLEMENT`.
Each replacement
then uses ordinary initial-implementation evidence, mode gates, finalization,
terminal confirmation and one-shot commit settlement. Saved future work remains
external, and earlier child commits are never overwritten by a later restore.
Sibling replacements retain correction budgets and semantic finalization retry
allowances within their original refinement lineage. Private
`replacement-findings.js` preserves finding-specific consumption and decisions
by reviewed version and ownership; sibling-local IDs cannot inherit an unrelated
finding's arbitration, dispute counts or exact override. Active version changes
retain the original version's decisions and pending requests separately, without
relabeling them or renewing lineage budgets. Owned pending disputes, their counts
and reconsideration requests stay in the ledger during reconstruction and return
at candidate convergence. Dispositions retain their final history even when
they remove the last active payload.
Revision discovery
routes capacity, product-decision and plan-revision outcomes through their owning
workflow handlers without discarding structured details or suspended authority.
Private `replacement-inputs.js` journals authorized clarification binding changes,
retains the suspended content checkpoint separately from the `IMPLEMENT`
compatibility route, preserves historical plan approval and role receipts, and requires fresh mode
approval and additive discovery before reuse. Assessment bindings follow only
that authorized chain without replacing history or renewing lineage allowances.
Rediscovery preserves parent amendment correspondence and exact replacement
targets for amendments accepted within the current revision.
Review normalization includes owned sibling payloads when enforcing stable IDs.
Deferred stops resolve the
original logical work and settle only when all its children verify. Consumed
commits reconcile before refinement. Read-only refinement violations persist
the ordinary contamination stop before preservation or new effects.
Input invalidation retains the historical role inventories and revision receipts
needed to validate that stop, while retiring active selection and approvals.
Pending separation records remain recoverable without reactivating invalid inputs.
The version-31 migration adds empty preparation records and keeps legacy and
intermediate runs disabled; it supplies no revision approval or preserved bytes.
Output-exhaustion pauses validate the exact pending refinement checkpoint rather
than treating its read-only phase as the suspended content phase. Reconstruction
retains assessment reservations and correction accounting.
An unchanged repair of a rejected plan preserves its report and offers an
explicit read-only repair retry through the shared CLI/MCP pause projection.

The configuration capability lives under `src/config/` behind its public
`index.js`. Strict runner and project parsing, confined file loading, trusted
profile interpretation, and precedence-based resolution remain private,
acyclic modules. Root consumers use only the index, while pipeline descriptors
continue to own role lists, settings, defaults, and persisted-run validation.

The runner capability lives under `src/runner/` behind its public `index.js`.
Private modules keep input normalization, role adapters and source-session
setup, pipeline migration, and run and resume orchestration distinct and
acyclic. Root consumers use the index; orchestration composes the other root
capabilities without exposing their private modules or moving workflow policy
out of pipeline descriptors.

The MCP capability lives under `src/mcp/` behind its public `index.js`. The
index exposes only the control-plane and STDIO server contracts consumed by
the root runtime and capability tests; private service and detached modules
keep protocol schemas, projections, revision waits, and detached dispatch
within the capability.

The issue capability lives under `src/issues/` behind its public `index.js`,
which exposes `createIssueService()` and the pure `resolveIssueStorePath()`
location mapping. Its private service owns the deliberate-report action
lifecycle and the list, read, and revisioned update operations over the run
store's durable action primitives and narrow per-issue lease. Private contract,
location, and store modules own the issue document schema, the per-user store
location, descriptor-bound filesystem guards, and interrupted-publication
recovery. MCP and the `agent-run issues` CLI project its operations without
duplicating action wrappers or effects.

The Claude provider lives under `src/agents/claude/` behind its provider
`index.js`. The root agent boundary imports only that index; the adapter,
local-commit executor, and isolation-policy selector remain private siblings
that own Claude processes, flags, parsing, sessions, sandbox composition, and
native failure recognition.

The Codex provider lives under `src/agents/codex/` behind its provider
`index.js`. The root agent boundary imports only that index; the adapter, App
Server transport, local-commit executor, and workspace storage remain private
siblings that own Codex processes, protocols, flags, parsing, and sessions.
`directory-policy.js` composes the public workspace inspection/snapshot service
with Codex named permissions; it never duplicates filesystem control discovery.
The private Codex `schema.js` validates the effective response schema before
any provider activity in `run`, including local-commit readiness. Its recursive
keyword allowlist and structural checks supplement the shared JSON,
strict-object, size, and depth checks without imposing Codex restrictions on
other adapters. It traverses schema positions rather than property names or
literal data, permits resolved local recursive references, and rejects
unsupported declarations with terminal `ERR_INVALID_CODEX_SCHEMA` before
probing, spawning, or recovery. This input-contract error is neither backend
unavailability nor malformed-output correction. Pipeline-owned normalizers
remain authoritative for semantic constraints such as terminal finding-ID
uniqueness that the portable response schemas cannot express.

The root `src/agents/index.js` is the only agent API consumed outside the agent
capability. Its private `registry.js` defines one frozen, source-controlled
descriptor per provider. A descriptor binds the backend ID to its adapter
factory, client-attribution support, execution-option validation,
trusted-profile normalization and resolution, source-session fork capability,
and one `failures` hook containing a finite class set and classifier. The
classifier is provider-private; the registry validates its provider-neutral
result before the public agent boundary exposes it. Configuration validation,
runner adapter construction and source checks, normalized failures, and MCP
backend schemas all derive from that registry. Tests may inject another complete
descriptor; production has no dynamic discovery, plugin loading, or
provider-specific pipeline branches.

The public agent boundary owns one strict, frozen client-attribution shape with
exactly `name` and `title`, plus the generic `agent_runner` / `Agent Runner`
default. Both strings are non-empty, trimmed, bounded to 256 characters, and
free of unsafe control, line-separator, and bidirectional formatting
characters. Registry construction passes only a normalized frozen value into
each adapter factory, while the descriptor states whether a provider can
transport a custom value. Codex sends both strings through App Server
`clientInfo` and keeps the package version in that same handshake. Claude's
documented CLI has no client-identity transport: its generic default remains
usable, while a custom value fails its capability probe before provider
activity. Neither adapter maps client attribution into native session names,
commit attribution, or undocumented environment variables, and bounded
failures retain none of its values. Provider-visible origin identity does not
promise a distinct provider dashboard category.

## Pipeline Ownership

The registered `pipelines/init/` workspace owns read-only infrastructure
proposals and Runner-owned integrated/external prerequisite publication. It
consumes injected public configuration and workspace capabilities, binding actual
instructions/checks, selected roots, resource
identities and live configuration exclusions. Its explicit reservation/result
agent transitions stop at `PROPOSAL_ACCEPTED`; its lifecycle then dispatches only
Runner-owned setup effects.
The separate `publishIntegratedInit` / `publishExternalInit` effects require those
approvals, unchanged setup bindings and the existing exclusive leases. The clarification capability
verifies the frozen transcript before baseline recording and throughout publication.
Workspace-owned infrastructure
methods reuse confined artifact replacement and private-state directory allocation;
run-store transition callbacks journal exact intents, identities and readback receipts.
Ignore protection precedes artifacts/finalization and configuration. Existing skills
and unrelated settings survive; exact derived `RUNNER.md` selections adapt manual
handoff rules to pipeline effect ownership. Finalization selection and proposal
validation preserve bare Git metadata protection even when its root coincides
with a conventional provider directory. External publication reuses the same
publisher with exact selected-root confinement, including journaled allocation
of a missing sibling root. Canonical target-path hashing distinguishes default
sibling names; full target-bound configuration protection is still required to
reuse existing roots. External policy permits only configured artifacts,
`finalization/SKILL.md` and configuration, returning the reusable exact selector.
Controls-only workspace inspection rejects external destinations inside Git or
provider storage before publication journaling and throughout recovery, including
canonical ancestor alias targets omitted from general workspace snapshots.
Existing target finalization skills are referenced without copying or editing; target content
and Git controls remain snapshot-protected with no ignore or pointer writes.
The caller holds both canonical target exclusion and selected-infrastructure
leases. The state lease capability supports exact absent infrastructure scopes
without creating the destination. An enclosing-worktree lease already covering
the external destination is reused instead of acquiring overlapping ownership.
Root retains infrastructure lease handles across failed release, reuses them on
same-run recovery, and releases them alongside canonical workspace ownership
after verified recovery or stop settlement.
Guidance publishes last through its existing
expected-hash, identity-bound durable action under those held leases. Init pins
the original guide identity and verifies its action-owned published inode before
acknowledgement, including completed-action replay. Placement resolves independently of review
mode during bounded clarification and freezes with the transcript hash. Lazy requires primary
check/fix plus distinct confirmation, independent requires separate review, and
combined requires both over the same proposal. Revisions invalidate approvals.
Placement-specific publication policies validate proposed content before it
becomes durable review input; invalid corrections preserve the prior proposal
and its resumable checkpoint without reserving filesystem effects.
Init validates reconciled operator stops against their preserved checkpoints,
including pending turns and editor windows. Shared clarification appends can
journal their exact result hash before replacement and recognize those bytes
on recovery. Exceptional post-closure decisions use the same durable answer
authorization, freeze a new clarification version and restart proposal gates
without redirecting selected paths or renewing correction budgets. Prepared
baselines continue protecting infrastructure and all other task content while
the clarification capability owns its exact transcript. Public pauses retain
bounded concrete setup findings and reason-specific explanations.
Init supplies its verified per-turn workspace snapshot through runtime turn
settlement for inactivity recovery, including after Runner publication. Pre-turn
reconstruction exhaustion persists a resumable provider interruption at the
same checkpoint without renewing attempt or correction allowances. Managed
guidance records the exact selected finalization resource alongside the effective
configuration, artifacts, working directory and checks.
The [init specification](../pipelines/init/docs/SPEC.md) owns this contract.
The distinct read-only terminal confirmation accepts the complete prepared
snapshot before the durable completion receipt. Authorized clarification may add exact
read trees before selection freezes, with fresh active-role read-only policy
receipts and a leased, revision-bound journal event; outputs and other permissions
cannot expand. After verified Runner publication, resume may refresh only the
read-policy identities changed by those effects. A separate frozen capability
authority fingerprint retains the original provider version, flags and access
requirements; resource rebinding cannot adopt a changed backend. Other pipelines retain immutable
workspace and provider-policy contracts. Terminal findings invalidate
dependent approvals and renew the selected proposal gates without resetting
revision accounting. Public CLI/MCP status exposes the effective selectors and
created/reused/changed resources. Directory recovery uses the original publication
baseline and exact intent/receipt paths; it never adopts unrelated drift. Existing
configured finalization procedures are reused at their exact reviewed paths when
they match the required procedure and checks; differing integrated skills stay
unchanged and select an adjacent `RUNNER.md`.
Terminal repairs may replace only a procedure originally created by the same
setup, bound to its verified prepared baseline. Atomic guide/procedure replacements
retain snapshot and publication-intent guards without stale immutable file bindings.

Each pipeline owns its input interpretation, roles, configuration settings and
defaults, accepted `run` options, prompts, structured-output schemas, explicit
JavaScript state machine, retry policy, and completion criteria. Roles, settings,
accepted and required options, task-input definitions, clarification and status
projections, resume-action validation, and persisted-run validation are exposed
through its static descriptor. The descriptor also selects the active roles
from its resolved settings, including all mode semantics; pipeline states remain
workspace-owned rather than becoming root runtime policy.

Execution's private `mode-policy.js` separates active roles, independent
bootstrap, primary convergence, independent review, terminal confirmer,
arbitration, and primary session scope. The workflow, persisted-state validator,
resume-action checks, migrations, and journal-proven confirmation recovery use
those decisions. Ordinary and stop-reconciled content repairs rejoin the same
candidate checkpoint. Session selection preserves one run-wide Worker source
fork in lazy mode, checkpoint forks in independent and combined modes, and fresh arbitration
and output-correction contexts. Permissions, one-shot commit verification, and bounded
correction accounting remain with their existing workflow operations; policy
selection grants no additional repository authority.

Combined execution runs Worker check/fix and a separate read-only clean
confirmation before the complete independent candidate Reviewer gate. Both
candidate approvals bind the same content fingerprint. Finalization may format
that content; a distinct Reviewer terminal confirmation approves its resulting
fingerprint and validation evidence before one-shot commit authorization.
Content repairs restart primary convergence. Self-findings go directly to fixing;
independent findings retain disputes, withdrawals, exact recorded overrides, and
fresh on-demand arbitration. Unresolved bootstrap disagreements and primary
exhaustion pause without arbitration. Corrections remain bounded and interrupted
work is charged once; resume preserves the saved mode and consumed commits remain
verification-only.

Execution's private `gate-evidence.js` composes primary clean evidence,
independent candidate approval, passing finalization, and terminal confirmation.
Persisted validation, normal routing, migration invalidation, journal-proven
recovery, stop reconciliation, and new commit authorization share these predicates
and resets. Candidate approval stays bound to the inspected content; finalization
may format it, so its resulting fingerprint requires distinct terminal approval.
Content repairs clear dependent evidence. Unchanged resolutions reconverge the
candidate and retain passing finalization only subject to fresh content and
infrastructure checks. Correction ledgers keep their existing bounded accounting.
Execution state version 17 adds bounded `primaryFindings` without renaming the
persisted lazy correction ledger. Leased version-16 migration adds an empty list
and preserves saved mode, counters, gate evidence, and pending effects. Combined
primary proof and independent approval remain distinct, including journal-proven
confirmation recovery.
Consumed effects still bypass new authorization and use verification-only recovery;
the shared predicates neither replace journal provenance nor grant Git authority.

The root CLI owns `--clarify` as a common run-lifecycle option. Role and
pipeline-specific options remain in pipeline descriptors.

V1 registers:

- `plan-authoring`: produces a validated commit or explicitly selected custom
  `plan.md` without changing project content or Git history outside its declared
  task-owned artifacts.
- `plan-execution`: consumes `plan.md` and implements one reviewed local commit per commit-plan step, or a durable criterion-bound accepted result per explicitly selected custom step.
- `polishing`: polishes, finalizes, and reviews an existing dirty worktree, then
  stages the complete result while leaving it uncommitted.
- `audit`: inspects an agreed Git or ordinary workspace read-only and publishes
  a resumable reviewed `audit.md` through Runner-owned artifact effects.
- `init`: prepares reviewed integrated or external infrastructure, publishes
  merged guidance last and confirms the complete setup without Git effects.

Polishing's private `mode-policy.js` separates active roles, bootstrap
independence, primary convergence, independent review, terminal confirmer,
arbitration eligibility, and primary session scope. Its workflow, persisted
validator, resume checks, and legacy migrations share those decisions. Ordinary
and interrupted repairs return through the same candidate checkpoint. Lazy keeps
one run-wide Worker source fork; independent checkpoints remain isolated and
Arbiter and correction contexts remain fresh. Persisted correction shapes and
budgets do not change. No policy grants index authority: staging remains the
runner-owned handoff effect. Polishing accepts independent, lazy, and combined.

Polishing's private `gate-evidence.js` composes primary clean, independent
candidate, finalization, terminal-confirmation, and handoff predicates. Routing,
persisted validation, legacy migration, and handoff authorization share these
checks. Candidate approval binds its inspected fingerprint; finalization can
format it into a different fingerprint that needs distinct terminal approval.
Content repair clears dependent evidence. Unchanged resolution retains only
fingerprint-bound passing finalization, subject to live content and infrastructure
rechecks after reconvergence. Legacy active evidence reconverges under the lease;
accepted handoff evidence survives migration and completed effects remain
verification-only. No persisted shape, mode, correction budget, or index permission
changes.

The pipeline registry is static. V1 has no dynamic plugins, workflow DSL, or
generic DAG executor.

The registered audit workspace owns report, discovery and finding-verification contracts behind
`pipelines/audit/src/index.js`: its canonical classification/criterion catalog,
strict immutable structured content and deterministic English renderer. One
catalog supplies classification validation, severity ordering and map text.
Confirmed findings require evidence, impact/severity rationale and labeled
concrete examples; unsupported claims remain separate hypotheses, and repeated
cause keys require consolidation. The renderer returns `audit.md` text without
filesystem or provider effects. Its descriptor selects read-only
directory inspection and an exclusive canonical workspace lease. The discovery
lifecycle uses injected workspace, clarification, adapter, session and durable
transition capabilities; it grants no new root authority. Frozen scope,
references, exclusions, criteria and snapshot/report bindings precede discovery.
Lazy retains one logical Auditor, while independent creates a fresh Auditor per
pass. A write-ahead pass history preserves the frozen run-wide budget capped at 20,
including interrupted reservations. New/revised candidates block discovery at
pending verification; clean discovery is separate from finding acceptance and
requires verified report publication before public completion. Logical turns establish existing inactivity/availability checkpoints
and use the common `repositoryBaseline` for recovery settlement. Distinct provider
dispositions survive pauses, terminal failures stay failed, and result acceptance
enforces enclosing persistent field/collection limits as well as aggregate bytes.
Report/ledger updates must also fit the escaped Markdown publisher's 32-MiB bound
before acceptance; overflow preserves the prior ledger and pauses resumably
without an impossible publication intent or a renewed pass budget.
The separate batch gate rechecks every new/material version before more discovery.
Lazy continues the discovering Auditor; independent creates a fresh read-only
finding Reviewer after each correction. Versioned entries/dispositions, retained
rejections, snapshot/report bindings, write-ahead recheck reservations and exact
accepted-batch receipts preserve a second finite run-wide budget capped at 20.
Corrections and review additions invalidate batch approval without changing
historical discovery cleanliness. State version 2 initializes these records from
version 1 through the descriptor migration without inventing acceptance.
Auditor-only legacy roles remain frozen: lazy can recheck, while independent
verification pauses before reserving work and requires a new run with a Reviewer.
State version 3 adds combined per-owner source-fork consumption without changing
earlier roles, histories, budgets or approvals. Combined derives discovery and
recheck cycle positions from preserved history; only clean closes a logical
owner's series, and reconstruction never grants another first-pass opportunity.
The initial Auditor continues from clarification until clean, then a fresh
successor must be clean on its first discovery pass. A finding-producing or
report-correcting successor finishes its own series before replacement. Each
batch first converges with that discovering Auditor, then passes to fresh finding
Reviewers. A correcting Reviewer finishes its own series before replacement;
only a fresh Reviewer's clean first pass accepts the exact batch. Intermediate
clean rechecks retain pending verification without acceptance receipts.
Batch acceptance resumes the same discovering owner. Both run-wide budgets and
all non-clean history survive reconstruction and replacement. State version 4
adds pending/published report bindings and temporary ownership without changing
earlier evidence or roles.
State version 5 persists proactive clarification and defaults legacy runs to no
proactive request. Audit uses the common one-shot editor and identified MCP input
requests before its first Auditor turn and for material clarification questions;
unanswered material requests remain pending without spending another round.
The public lifecycle projects confirmed findings only from current exact accepted
versions, retaining pending candidates and hypotheses as unverified. It persists a
rendered-content intent, invokes the Runner workspace artifact publisher, verifies
readback and unchanged frozen inputs/source, then saves its receipt. Publication
recovery precedes further discovery; `DONE` requires the selected clean gate,
no pending batch and the exact complete report receipt. CLI/MCP metadata and
`auditReport` projections remain descriptor-owned. Reports live at task-owned
`audit.md`; `.audit.md.tmp` and the report are declared exact Runner artifacts,
excluded from long-lived source guards but protected during every agent turn.
The workspace publisher anchors its atomic rename to a verified real parent and
journals temporary identity and writing/prepared phases before their effects.
Resume rewrites only its own incomplete temporary, preserving substituted files
and rejecting unexpected bytes/aliases. Report conflicts remain distinct from
immutable source drift. Root dispatch confines it to the descriptor's
filename and requires ignored, untracked repository-local paths. It grants no
source, index, Git, retrieval or automatic issue authority. Critical findings do
not block successful completion. Conflicting partial temporaries remain preserved.
See the [audit specification](../pipelines/audit/docs/SPEC.md).

## Structured Result Headroom

All registered pipelines accept structured role results through exactly 2 MiB
(2,097,152 bytes) of serialized UTF-8 JSON, rejecting one-byte overflow before
acceptance. Semantic text, item, path, inventory, dispute, and correction bounds
remain independent and unchanged. New size diagnostics use
`maximum-2-mebibytes`; persisted `maximum-256-kibibytes` diagnostics remain valid
historical evidence and are not rewritten.

The common state envelope permits 32 MiB of compact serialized JSON. Polishing
also enforces a 24 MiB whole-run budget: twelve result-sized slots accommodate
both role inventories, derived catalogs, finalization and review copies, and
bookkeeping, including common metadata. Both budgets apply to the complete run.
These are finite aggregate safety ceilings, not permission to enlarge semantic fields or
retain rejected output. Persisted evidence validates its individual fields and
runner provenance without reapplying the raw-result ceiling to augmented copies.

Adapter prompts and complete recovery prompts each permit 32 MiB so accepted
results, derived inventories, and reconstruction context have enclosing
headroom. Schema input remains capped at 1 MiB. Codex protocol lines and Claude
stream lines retain their 16 MiB bounds, sufficient for JSON string escaping and
Claude's duplicated text/structured terminal envelope; Claude retains its 64 MiB
stream/process bound. Native protocol limits still apply to unrelated traffic.

Codex hydrates a summarized or unloaded completion with one
`thread/turns/list` request (`limit: 1`, descending, `itemsView: "full"`),
requiring the exact completed turn ID and full terminal item view before
acceptance or native failure refinement. Missing, mismatched, partial, or
multiple turns fail closed without replay. The complete current turn remains
subject to the existing protocol cap and item audit; prior results cannot
inflate the response. Continuations and source forks request
`excludeTurns: true`, preserving native context and fork lineage without
returning history.
These fields were verified against Codex CLI 0.163.0's model-free public
`app-server generate-ts` contract; no pagination is added to `thread/read`.

Runner context artifacts contain only summaries of at most 20,000 characters,
so their 1 MiB cap remains sufficient. Configuration, clarification, and MCP
action caps do not carry complete role results and remain unchanged. Public
CLI/MCP projections retain their bounded summaries and diagnostics rather than
exposing larger private results. Byte headroom is neither a token budget nor a
native generation control; missing usage and incomplete accounting stay unknown.

## Local application packaging

`scripts/assemble-release.js` owns narrow release assembly from the existing npm
checkout. Root and private workspace `files` declarations are the publication
allowlists. The assembler validates root package/lock agreement and walks only
the locked production graph, checking installed names, versions, dependency
declarations and exact workspace links. Hoisted and nested dependency slots are
preserved while workspace links become real directories. Optional/peer closure
requires an explicit implementation before such dependencies can be packaged.
Installed dependencies must come from the committed lock through `npm ci`;
assembly verifies their lock identity and records the copied bytes, without
claiming to reconstruct upstream tarball integrity from expanded files.

Fresh output storage contains a standalone native-ESM package with the same bin,
exports and Node engine, declared runtime resources, upstream dependency notices,
and bundled production dependencies. Checkout-only workspaces, development
dependencies and scripts are omitted from its root metadata. Configuration,
credentials, state, task inputs, provider controls and unrelated development files
are outside the allowlists. The source workspace topology and links are untouched.

The generated release manifest records source-lock SHA-256, dependency identities,
and every payload file's path, size, executable mode and SHA-256. Its own exact
bytes and ordinary file mode are checked separately. `packRelease` invokes local offline npm packing with
disabled lifecycle scripts, private HOME/cache (including Node's compile cache) and separate empty user/global
configuration. Size-checked stdout uses an owned temporary file; stderr is discarded. The standard-
library `release-archive.js` verifier reads the actual gzip/tar bytes (bounded to
64 MiB expanded), accepts only regular file records and supported portable
extended headers, rejects unsafe paths, links, duplicates, extra/missing files,
invalid headers or changed bytes/modes, and verifies exact manifest readback.
Only supported portable extended fields are accepted, with size overrides
required to match their file headers.
It never installs, publishes, changes native links or activates a runtime.

Candidate metadata remains `@your-scope/agent-runner`, `private: true`, and
`UNLICENSED`; internal workspaces remain private. Approved public identity,
owner/scope, license, repository links and publisher configuration remain absent,
so publication is fail-closed. Local assembly is distinct from external-install
acceptance and adds no native-platform support. Ordinary development continues
through `npm ci` and `npm link`; there is no transpilation or general build system.

External-install acceptance is owned separately by
`test/package-install.slow.test.js`. It consumes the inspected tarball through
offline, script-free npm installation into a fresh private prefix, compares the
installed manifest and files, and launches the real installed CLI and STDIO MCP
server from an unrelated empty directory. Sanitized user locations and bounded,
awaited child lifetimes keep all effects in fixture storage. Private workspace
imports use actual bundled directories; immutable startup, delayed guide reads
after outer replacement and EOF admission retirement are exercised together.
README install commands and registration server vectors are inputs to this
acceptance; native client registration remains a separate operator action.
No source/dependency link, controller, native client configuration or registry
publication is changed. See [test ownership](TESTING.md#slow-gate).

Release automation belongs to `.github/workflows/release.yml` and the focused
standard-library scripts `release-policy.js` and `publish-release.js`. An explicit
stable published Release selects an exact version tag/commit in main; the
disabled immutable policy in `src/config/release/index.js` requires separately approved public metadata
before that path can validate or publish. The assembler accepts public metadata
only through that matching policy, preserving neutral private local candidates.
Ordinary checks, exact package installation and complete slow gate one inspected
tarball. A commit-bound receipt and independent job-output SHA-512 bind the
downloaded Actions artifact. Only the protected publishing job requests OIDC;
npm provenance and an anonymous download/isolated install verify publication.
Existing-version integrity is reconciled before effects, and uncertain/partial
failure remains failed without overwriting versions or moving tags. This tooling
has no runtime update, configuration-migration or run-resume authority.
See [release ownership and setup](RELEASING.md).

## On-demand release compatibility

`src/update/index.js` exposes `createUpdateService().check()` and an optional
exact `{ version }` selection. Construction, model turns, status and activity
reads perform no registry request. CLI/MCP delegate explicit requests to it and it
creates no automatic-update setting. Project configuration, role findings and
request fields cannot choose a source or acquire global-update authority.
Trusted root composition may inject effects for controlled tests.

The configuration-owned `src/config/release/index.js` is standard-library-only,
contains the disabled official approval policy, and shares identity validation
with release assembly/publication. It is included by the existing JavaScript
payload allowlist, replacing the checkout-only approval JSON. User settings
cannot override it. Approved package name, repository, license and public
registry metadata must agree before an anonymous request to the fixed npm
registry. Registry reads normalize npm's `git+https` repository form before
checking that same exact approved repository; publication inputs retain their
strict source metadata contract. Linked checkouts remain development-managed
and never query it.

Runtime-owned read-only inspection reuses complete payload verification and
Node identity checks. It distinguishes pinned running bytes from the current
outer installation without preparing storage, changing links or activating code.
Reports expose bounded versions, official identity, stable/explicit selection,
compatibility, blockers and restart requirements; raw paths, registry documents
and errors are excluded. Requests have a ten-second deadline and a one-MiB body
ceiling. A default check selects only a stable `latest`; prereleases require an
exact explicit version. Equal or older releases are successful no-ops.

Root package metadata carries versioned `agentRunnerCompatibility` independently
of package version: configuration schema, runner/run-envelope generations and
pipeline state versions. A candidate must declare the same supported contracts;
unknown metadata or a differing contract blocks a newer candidate. Node ranges
use the project's `>=major <major` form. This is conservative runtime-contract
comparison, not certification of any saved run or permission to migrate/resume
legacy state. Permission observations are informational and confer no install
authority. Reports require a restart when installed and running payload identities
differ, including same-version replacements and when no newer download is needed. No payload is downloaded,
installed, replaced, migrated or resumed by checking.

## Exact candidate preparation

The same update capability exposes `prepare({ operationId, version })`; both
fields are exact, bounded selections, not storage/source/role authority. The
official identity gate and development-managed exclusion precede mutation.
State-owned `update_prepare` actions persist the UUID, original arguments,
selection intent, exact metadata/integrity, storage identities, phases and owned
process proof. The existing recoverable action lease serializes each operation.
Completed receipts are reusable only while the pinned candidate still verifies.
A current version is a successful no-op. These actions do not create a run or
change any pipeline's compatibility or execution authority.
Preparation context version 2 records downloaded and installed versions separately
after their respective verification boundaries. Version-1 intents upgrade only
under their action lease; completed historical receipts retain their exact shape.

Default storage is private `updates/` under the user runtime root, disjoint from
the application, controls and authoritative state. Each of at most three fresh
attempts has an exclusive directory and persisted device/inode/owner identity.
Shell-free npm vectors select `name@exact-version` at the approved registry,
disable scripts/retries and bind anonymous settings/cache to owned storage.
The runtime-owned archive parser is shared with release tooling: actual SHA-512,
canonical complete manifest, resource bytes, paths and modes must agree before
offline installation from a retained read-only archive descriptor. Installed
metadata, manifest, dependency/resource closure and Node/configuration/state
contracts are verified again, then standard startup materializes and pins the
candidate's immutable payload.

Native commands use existing owned-process supervision plus bubblewrap with a
read-only filesystem and only the descriptor-bound attempt writable. Offline
installation and smoke have no network; the selected archive and smoke payload
are mounted read-only through retained descriptors. Private smoke settings/state
stay outside the payload. CLI help and MCP initialize/list-tools/transport-EOF
shutdown must complete before recording `validated`; no live provider, client
registration, target project or global link is involved. Output is capped at
two MiB and each native command has a 120-second launch-to-retirement deadline.
Process ownership is persisted before payload release, and children are awaited
before identity-checked smoke teardown. Unsupported containment fails closed.

Recovery inspects only the recorded owner/namespace and positively associated
session/token members; unavailable identity remains blocking and no recorded PID
is signaled. After owner retirement, a reused session number alone cannot
associate new members; token or verified ancestry evidence is required.
A fully installed interrupted attempt is reverified rather than
reinstalled. Partial/failed attempts remain quarantined, with bounded fresh
attempts and no deletion of unproved storage. A lost creation receipt or
substituted path blocks adoption. Validation/permission/network failures retain
the previous usable payload; no native effect overwrites it. Public receipts
contain only bounded IDs, versions, outcomes and redacted blockers. Preparation
changes no selector, restarts no client and migrates/resumes no settings or run.

## Candidate activation and restart

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
downgrade limits are documented in [RELEASING.md](RELEASING.md#local-version-selection-and-restart).

## Immutable application startup

`src/runtime/index.js` is the public startup and immutable-payload boundary.
The thin bin entry imports only this standard-library capability. Private
`contract.js` owns bounded manifest and location contracts, `files.js` owns
descriptor-bound reads and ancestor bindings, `payload.js` owns complete tree
inspection and atomic preparation, and `bootstrap.js` selects the root before
dynamically importing its public `src/index.js`.
The standard-library-only `src/state/location/index.js` shares the existing
state-root mapping with bootstrap. `runtime/selection.js` reads the bounded,
private state-owned selection without creating storage. Normal startup verifies
that selected payload and Node identity before imports, retaining the original
installation path for configuration fallback. Detached launches bypass this
selection and verify their exact frozen context. Unknown selection versions fail
clearly before any command; admission rechecks the selection under its mutation
boundary before effects, so a stale startup observation grants no admission.

An installed package requires the assembler's manifest, native-ESM metadata,
Node.js `>=24 <25`, the executable entry, runtime bootstrap, complete operator
guide and complete declared production dependency graph. All bootstrap modules
are mandatory manifest entries. Every declared file's
bytes, size and executable status must match; unlisted files/directories, links,
hard links, missing dependencies and changing inputs fail closed. The manifest
is limited to 2 MiB, 10,000 files and 64 MiB of payload bytes. Its SHA-256 is the
payload identity. The optional outer `.agent-runner.json` is excluded from
capture and remains a configuration-owned mutable legacy fallback.

Linux runtime storage uses XDG data/home fallback, with Application Support and
LOCALAPPDATA location mappings as documented in the README. Creation pins every
real ancestor through directory descriptors, verifies private user ownership,
and uses only a fresh preparation beside the destination.
The storage root and immediate payload container must retain private user-owned
`0700` permissions whenever a stored payload is inspected or launched.
File and directory data are synchronized before publication. Completed files become `0400` or
`0500`, directories become `0500`, and the complete tree is reverified before
publication. Each fresh tree retains its unique
`payloads/.payload-<manifest-hash>-<UUID>` location. Publication atomically creates
an exclusive relative symbolic reference at `payloads/<manifest-hash>`; it cannot
replace an arriving entry, including an empty directory. Bootstrap reads that
reference without traversing it, accepts only a matching sibling name, and
verifies its unchanged identity and the complete unaliased tree. Pinned roots
and executables use the physical tree path, never the reference. Existing
payloads are fully verified and never rewritten. Concurrent complete
preparations converge on the same published tree. Interrupted or redundant
preparation directories remain separate; bootstrap neither adopts nor deletes
them, even when they contain a complete sealed tree. There is no cleanup daemon.
Preparation retains its directory binding and verifies each created entry before
sealing through its matching descriptor; substituted paths cannot redirect
permission changes.

Only a checkout with workspace metadata and a real Git control entry is
development-managed. A present release manifest always selects installed
verification, even beside checkout metadata. Linked checkouts resolve to that source root. A missing
installed manifest cannot silently become development mode. The bootstrap freezes
one non-writable process context before application imports; duplicate module
graphs share that context through a process-local symbol. It carries the pinned
root/executable, original installation root, payload ID and Node identity, never
settings or run state. Configuration uses the original installation root only for
its existing absent-user-file legacy fallback. Direct source API imports do not
establish a bootstrapped process.

Every later application import and resource URL is rooted in the selected tree.
The MCP launcher rechecks its complete payload plus Node path, version and file
identity before spawning the pinned executable. Linux also compares the selected
Node file to the running `/proc/self/exe` identity. A bounded one-use internal
environment binding carries this tuple to the child, which verifies it before
application imports and removes it before provider/validation children can
inherit it. The existing runtime-compatibility token, leased revision admission,
durable ownership and same-key recovery remain separate mandatory gates.
Preparation grants no registry, update activation, migration or resume authority.

### Serialized runtime admission

`runtime/admission.js` stays standard-library-only and receives the state
capability from root composition. Installed CLI/MCP process lifetimes and Runner
create/run/resume calls verify their pinned payload and Node identity, then
register before effects and await retirement afterward. Development-managed
source calls bypass global admission. State effects use the immutable verified
descriptor rather than retaining caller-owned identity fields. Application,
project and task boundaries are checked before state creation, including
missing but confined paths.
The STDIO server handle exposes a settled-on-close lifetime promise; CLI keeps
its admission until transport closure, including startup failure or early EOF.
The MCP boundary closes the SDK transport when STDIO input ends or closes and
removes its input listeners when the lifetime settles.

`state/runtime-admission.js` owns a bounded private `runtime-admission/runtime.json`
projection under the existing state root. It records the active and pending
payload identities plus explicitly registered users, their host, PID namespace,
boot/start identity and operation UUID. Existing action intents and leases bind
each operation; the existing mutation boundary serializes admission, retirement
and activation. Runtime mutation claims bind their PID namespace before any
peer PID probe; ordinary run mutation claims retain their existing contract.
A write-ahead action records its expected projection revision and
outcome before atomic publication. Recovery completes a proved consumed write
without repeating it; intervening operations with uncertain consumption block.
Completed admission receipts cannot recreate retired users.
Activation and retirement receipts can be reconciled by a new owner only after
the original owner is proved dead or replaced. Admission never transfers an old
process association to that new owner.

Projection version 2 binds active and pending identities to their originating
activation operations. A consumed activation remains reconcilable after later
admissions or retirements while that exact selection and operation binding remain;
a superseding selection never authorizes replay. Version-1 records remain
readable but their pending identities acquire
no automatic selection authority. The first admission initializes selection.
Later admissions must match the active payload while users remain. Explicit
activation records a deferred selection while another positively associated
runtime remains live. After the last user retires, admission selects only that
proved pending payload, reconciling its original deferred action receipt first;
an obsolete racing start is deferred. A later successful explicit activation
supersedes any older pending request. Unknown ownership remains blocking.
This changes only the selector and admission record. It does not rewrite or
remove trees, restart a process, reload frozen configuration, migrate or resume
a run. Older software that cannot read the new projection must fail closed;
retaining old payload bytes is not persistence rollback authority.

Only recorded users are inspected. Proved exit, PID replacement or a prior boot
retires the corresponding association. Unknown identity, foreign host or a PID
namespace unavailable to this observer remains blocking; no PID-only guess,
host census or signal is permitted. Per-run leases, private PID containment,
compatibility, stop gates and consumed-effect recovery retain their authority.
Runtime admission grants no execution authority to legacy or intermediate runs.

## Runner Configuration

The root configuration capability owns global user settings behind
`src/config/index.js`. Private `user-settings.js` resolves Linux
`$XDG_CONFIG_HOME/agent-runner/config.json` (falling back to
`$HOME/.config/agent-runner/config.json` for unset, empty or relative XDG), macOS
`$HOME/Library/Application Support/agent-runner/config.json`, and Windows
`%APPDATA%\agent-runner\config.json` with a drive-qualified or UNC APPDATA root. This path
mapping does not extend Linux execution acceptance. User settings cannot reside
inside the installation. Loading creates no directories or files.
Only an absent user file permits the legacy installation-root
`.agent-runner.json` fallback; malformed, unreadable or unsafe user settings fail
closed. The layers never merge. Global files reuse the configuration boundary's
bounded UTF-8, no-link, real-ancestry reader. The selected global layer (also
called runner-root configuration) remains the only source of trusted profile
implementations and global-only settings. Project precedence is unchanged.

CLI `config migrate --from <legacy-file>` dispatches through the public
configuration boundary before runner creation or ordinary resolution. It
validates the source with the existing strict global schema before any writes.
`migrateRunnerConfiguration` creates missing mode-0700 parents through pinned
directory descriptors, writes and syncs a private mode-0600 temporary file, then
atomically links its complete bytes to the absent destination without replacement.
It removes only its owned temporary name, syncs the directory, verifies real
ancestor identities and reads back exact bytes. Descriptor-bound directory
access is required; it never falls back to an unsafe publication path. An existing
byte-identical destination returns unchanged; different bytes conflict without
merging, replacing or deleting either input. The source is always retained.
Interrupted temporary files are not configuration and are not removed by a later
invocation. Interruption between publication and temporary unlink can leave a
multi-link destination; both load and migration reject it without deleting
either name or the source. Only a completed publication with its temporary name
removed is recognized by an identical retry after lost acknowledgement.
No migration runs implicitly during load,
installation or resume, and no active run snapshot is re-resolved.

For a new run, the root also discovers an optional ignored and untracked
`<project>/LOCAL_ARTIFACTS/agent-runner.json`, or uses an explicitly selected
confined project path from CLI/MCP. Explicit CLI `--project-config` / MCP
`projectConfigurationPath` may also select a target-bound external file.
Both files require `schemaVersion: 1`; unknown versions, pipelines, roles,
settings, and fields are errors. Project
configuration may define exact trusted commands, select trusted aliases,
override execution defaults, pipeline roles and settings, and select a normalized
repository-relative artifact root. It cannot define profiles, credentials,
provider binaries, or arbitrary environment values. Integrated Git files must
remain ignored and untracked. Missing explicit, unsafe, and symbolic-link paths
are rejected without creating a file or changing ignore rules.

Project-only `infrastructure` is a closed version-1 object with `schemaVersion`,
`placement` (`integrated` or `external`), canonical absolute `projectPath` and
`rootPath`. The target must match the resolved workspace. Integrated roots equal
the target; external roots and targets must be disjoint, with the selected file
strictly below the root. External files require this binding and explicit
selection. Integrated discovery remains unchanged, and explicit selection
replaces discovery rather than merging competing placements. No sibling scan,
relocation, rewriting, registration or new host authority occurs.
The loader returns the binding as `infrastructure` and resolves `artifactPath`
from its root and the effective relative `artifactRoot`. Pipeline artifact and
guidance publication remain owned by their existing contracts. This resource
resolution grants no directory read or write permission. External configuration
can select custom directory semantics before Git inspection, just like an
integrated project overlay. For a Git selection supplied from a subdirectory,
external binding may resolve to the canonical worktree root while retaining the
exact selected file. Relative external selectors resolve before worktree-root
rebasing in fixed-workspace pipelines such as polishing as well as dynamic
pipelines. Fixed-workspace pipelines validate their workspace/state boundary
before loading configuration and retain that validated target during discovery.
Explicit external overlays resolve before a preliminary custom
default can prevent their higher-precedence commit selection. A custom directory
selection retains its requested scope; an external binding cannot widen it to
the enclosing worktree.

The confined read that supplies parsed project values also produces a
versioned protection record. It pins the canonical project and file paths,
repository-relative location, SHA-256 content hash, device/inode and bounded
file metadata, plus device/inode evidence for every real directory from the
project root to the file's parent. The initial read and every later inspection
use a bounded no-follow descriptor and compare path, descriptor, and ancestor
identity before and after reading. A project configuration must have one hard
link. Existing integrated protection remains version 1. External protection is
version 2 with the same content/file fields, an `infrastructureRoot`, a
root-relative `relativePath`, complete real ancestry from the filesystem root to the file's
parent, and `projectAncestors` through the target directory itself. Root identity
is included in that ancestry. Target ancestry is compared before and after the
read, so replacing an empty target also invalidates the binding. The state
boundary strictly validates both versions; legacy records are preserved without
rediscovery, inferred bindings or new execution authority.

The V1 shape is:

```json
{
  "schemaVersion": 1,
  "artifactRoot": "LOCAL_ARTIFACTS",
  "issueReporting": true,
  "clientAttribution": {
    "name": "agent_runner",
    "title": "Agent Runner"
  },
  "defaultBackend": "codex",
  "defaultProfile": "current",
  "defaultModel": "current",
  "defaultEffort": "current",
  "defaultContextSize": "current",
  "trustedCommandTimeoutMs": 3600000,
  "availabilityRetryMaxDelayMs": 1800000,
  "providerInactivityTimeoutMs": 1800000,
  "profiles": {
    "codex-work": {
      "backend": "codex",
      "profile": "work"
    },
    "claude-primary": {
      "backend": "claude",
      "configDirectory": "/profiles/claude-primary"
    }
  },
  "trustedCommands": {
    "service-tests": {
      "command": "npm run test:service",
      "executable": "npm",
      "arguments": ["run", "test:service"]
    }
  },
  "pipelines": {
    "plan-execution": {
      "mode": "independent",
      "finalization": "auto",
      "trustedChecks": ["service-tests"],
      "maxFixRoundsPerStep": 20,
      "roles": {
        "worker": {
          "backend": "claude",
          "profile": "claude-primary",
          "model": "sonnet",
          "contextSize": "200000"
        }
      }
    }
  }
}
```

`issueReporting` is runner-local, defaults to `true`, and is not accepted in a
project configuration. The MCP process loads it once at startup; applying a
change requires a restart. A disabled server omits the reporting tool, schema,
and related instructions from discovery. Other runner settings are reloaded
for each fresh report and persisted through its resolved reservation.

`clientAttribution` is also runner-root-only and defaults to the generic
`agent_runner` / `Agent Runner` identity. Configuration uses the public agent
contract to normalize the exact `{ name, title }` object, then rejects a custom
value when any active role's provider descriptor does not support it. There is
no project, CLI, MCP, pipeline, prompt, or repository-content override. The
normalized value and its SHA-256 fingerprint are immutable common run-envelope
fields. Production adapter sets are constructed through provider descriptors
from the resolved frozen value during creation and from the saved value on
resume; current configuration cannot replace it. Prompts, activity, public
status, and diagnostics omit both fields.

`trustedCommandTimeoutMs` is accepted by root and safe project configuration as
a strict integer from `1` through `2147483647` milliseconds and defaults to
`3600000` (60 minutes). The project value overrides the root value. It has no
CLI or MCP override because configuration resolution, not a transport-specific
surface, owns the deadline.

`availabilityRetryMaxDelayMs` is a common root/project setting, a strict integer
from `5000` through `2147483647` milliseconds, defaulting to `1800000` (30
minutes). Project configuration overrides root configuration; CLI, MCP, roles,
and pipelines do not introduce separate ceilings. Resolution freezes
`availabilityPolicy: { initialDelayMs: 5000, maxDelayMs }` when creating the run.
The state boundary owns the validated policy and deterministic schedule;
configuration consumes it through the public state index.

`defaultBackend` is optional. A role's `profile`, `model`, `contextSize`, and
`effort` resolve from its role-specific override, the run-wide override, its
project-role value, the corresponding project-wide default, its pipeline-role
runner value, the corresponding runner-wide default, then the built-in string
`current`; a role-specific CLI override has highest precedence. CLI/MCP expose
profile, model, context size, and effort through the same runner input contract.
CLI uses `--effort` and descriptor-derived `--<role>-effort`; MCP uses `effort`
and `roleOverrides.<role>.effort`. Both validate the portable enum before
dispatch. MCP action identities include both selections before mutation;
detached continuations resume the saved run without re-resolving them. Explicit
CLI/MCP pipeline-setting overrides take precedence over project pipeline
settings, which take precedence over runner settings and descriptor defaults.
A profile alias is trusted runner configuration, pins one backend, and maps
only to a native Codex profile name or an isolated Claude configuration
directory. A conflicting explicit backend is invalid; profile configuration
cannot inject credentials, binaries, or arbitrary environment variables.
Without a selected profile, the backend resolves from the role override,
pipeline-role value, then `defaultBackend`; absence is a preflight error.

`current` omits that native override. For models this means both Codex and
Claude use the model selected by their effective native profile, process, or
backend native default; Agent Runner does not hard-code a backend model ID. An
explicit context size is a decimal token string validated by the selected
adapter and mapped to Codex's context-window setting or Claude's
auto-compaction token window. These controls are not treated as otherwise
equivalent.

Both configuration layers accept `defaultEffort` and role `effort` using only
`current|low|medium|high|xhigh`. Vocabulary validation includes inactive roles;
provider capability validation applies only to resolved active roles. Effort
remains separate from model IDs, and native translation belongs to adapters.
An explicit `current` at any precedence level retains the effective provider
default instead of inheriting a lower-precedence effort selection.

Pipeline descriptors validate their own settings and supply built-in defaults.
The root loader owns only the versioned envelope, strict field validation, and
resolution precedence; it does not duplicate pipeline-specific role or setting
lists.

Descriptors may additionally validate relationships among resolved settings;
configuration applies this hook to complete root settings and merged project
settings before role resolution. Execution uses it to reject unsafe multiplication
of its positive-safe-integer `preferredCommitLineLimit` (900) and
`commitSizeAssessmentMultiplier` (3), including when its strict boolean
`automaticCommitSplitting` (default `true`) disables assessment. All three
values remain frozen on resume.

Plan authoring additionally owns the positive-safe-integer
`preferredCommitLineLimit`, default 900. Root configuration and a safe project
overlay resolve it through existing precedence before creation. It is a prompt
heuristic for anticipated additions plus deletions, including tests and
documentation: prefer cohesive commits within the target and explain genuinely
indivisible exceptions. It changes neither the shared plan contract nor execution
validation. Authoring state version 4 persists the value; the ordered version-3
migration supplies 900 to non-null legacy settings without configuration reload,
progress changes, or effect replay. The existing lease governs persistence of
that migration. Authoring planning, review, self-review, and recovery prompts
use the saved value. CLI `pipelines` displays descriptor-owned setting defaults;
MCP `pipelines_list` projects the same metadata.

Every built-in descriptor owns one string `mode` setting supporting
`independent`, `lazy`, and `combined`. A missing value resolves to
`independent`, which is the default and recommended option because its distinct primary and review
roles provide genuinely independent semantic review. That independence uses
more provider context and tokens. `lazy` is an explicit lower-consumption
choice that uses only the Planner for plan authoring or the Worker for execution
and polishing and does not provide independent review. Neither the root runner
nor a pipeline may select it automatically.

Runner and project configuration are deterministically validated for every
declared role. After settings resolve, the descriptor selects active roles.
Only those roles are resolved to a backend, profile, model, context size, and
effort; only they are probed, persisted in the run, checked against a source session,
and invoked. Public projections may identify an active role for bounded
activity, but expose neither provider-private values nor inactive role
configuration. Inactive Reviewer and Arbiter values remain untouched in the
configuration source for a later independent run. The resolved mode is
persisted when the run is created and is never reloaded on resume.

Plan execution and polishing own a string `finalization` setting. `auto`, the
default, discovers a conventional confined repository skill and otherwise
falls back to repository instructions and project-defined checks. `none`
selects that fallback directly. Any other accepted value is a normalized
infrastructure-relative Markdown path; a missing or unsafe explicit path blocks
the run. Runner configuration supplies the base value and a safe project
overlay may replace it. The configured policy is persisted with the other
pipeline settings; each owning workflow separately freezes the effective
guidance decision and does not reload it on resume.

The root configuration capability exposes confined finalization-file inspection
without interpreting the file as configuration or retaining its text. Explicit
paths resolve from the frozen infrastructure root; automatic conventional
discovery stays in the target. Plan execution resolves guidance after workspace
preflight and before bootstrap. Its pipeline state separately freezes the configured policy,
selected canonical regular Markdown file or fallback decision, selected-file
fingerprint when applicable, and complete decision fingerprint. New `file`
decisions bind bytes, file identity, real ancestors, target and infrastructure
root; legacy `skill` decisions retain their original repository path and
fingerprint algorithm. The existing `skillPath` field is the inventory label:
external procedures use `finalization://<infrastructure-relative-path>`, distinct
from every canonical repository-relative entry. The configured policy retains
the original relative selection. Both files participate when a repository
validation file has the same relative path as external guidance.
Bootstrap and validation migration receive only that label, exact absolute read
declaration or fallback, never copied procedure content; no additional provider
checkpoint is introduced. Only that selected label may refer to an external
file in validation infrastructure. Its identity-bound digest joins the ordinary
repository-infrastructure digest. Custom directory declarations use the bound
root for explicitly selected guidance and grant no Git effects. The
selected skill is part of established validation infrastructure. Execution
rechecks its exact path and fingerprint before guidance-consuming, correction,
and resumed work. Missing, invalid, or changed frozen guidance requires a fresh
run; automatic selection never switches late. This decision does not replace
the frozen trusted-validation snapshot, exact inventory matching, capability
reports, environment blockers, or requirement inspection.

Execution state version 36 and polishing version 19 preserve all older frozen
decisions, fingerprints, inventories, counters and effect evidence through leased
shape-preserving migrations. They never rediscover an existing selection or
manufacture identity proof. Consumed commits and completed handoffs remain
verification-only.

Polishing owns the same behavior through its separate workflow, schemas,
prompts, state validation, migration, and public pause projection; it does not
import plan-execution internals. It freezes guidance after dirty-worktree Git
preflight and before backend probing or bootstrap, includes any selected skill
in established validation infrastructure, and rechecks the exact path and
fingerprint before guidance-consuming, correction, and resumed work. Missing,
invalid, or changed guidance requires a fresh run while environment blockers
retain their existing resumable checkpoints. Completed `HANDOFF` recovery stays
verification-only, index mutation remains runner-owned, and no extra provider
turn is added.

`trustedCommands` is accepted in root and safe project configuration through
the same exact-vector validator. Each lowercase alias binds one exact inventory
command to one executable and argument vector. Definitions reject shell-string
substitutes and environment, credential, or host-authority fields.
Configuration privately merges normalized root then project catalogs in stable
order, deduplicates identical same-name definitions, and rejects conflicts even
when unselected. The merged catalog accepts at most 256 definitions, while each
immutable run snapshot remains limited to 32 selected commands. Direct argument
strings may contain line feeds for exact multiline scripts; other control
characters remain invalid. Plan execution and polishing each own a
`trustedChecks` setting; an ignored project configuration may replace that
pipeline's selection with root or project aliases. The default selection is
empty, and selected order determines snapshot order. Profile implementations
and trusted execution policy remain runner-owned. Before agent work, the root
resolves it into an immutable snapshot containing every selected vector,
deterministic command identities, an ordered command fingerprint, and a
trusted-configuration fingerprint. Resume uses that durable snapshot without
reloading either configuration source. Later project configuration changes
remain subject to the protected-input guard.

## Run Lifecycle

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

Descriptors declare `workspace.kind` (`git` or `directory`) and `workspace.lease`
(`none` or `exclusive`), alongside their existing role-access inventory. An
optional descriptor resolver selects those requirements from resolved explicit
configuration and run overrides;
MCP preflight and run creation supply the same normalized selections.
Missing Git never selects a directory workflow. Directory lifecycles require
exclusive ownership, use filesystem-only preflight/configuration/artifact
confinement and expose snapshot/guard operations through `runtime.workspace`.
They expose no Git effect capability. Canonical enclosing worktrees are found
from filesystem Git layouts/pointers; a directory inside one shares its exact
exclusion key with commit workflows. An ordinary directory uses its own key;
state-owned admission also excludes overlapping parent/child scopes atomically.
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
it only for runner-owned repository-local artifacts beneath
`<artifactRoot>/agent-runner/<run-id>/`; ignored-path, traversal, symlink,
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
Plan execution also projects `finalization_transition_invalid` as a resumable
`FINALIZE` checkpoint with a fixed bounded diagnostic when an unexpected
runner-owned finalization invariant rejects advancement. The retained state
contains neither the rejected evidence record nor provider, prompt,
transcript, trusted-process-output, or detached-log data.

Public next actions are concrete descriptor-owned operations. `respond`
identifies the exact pending request; `resume` carries either the validated
null retry or one valid extra-round or finding-override payload; and
`start-new-run` identifies a `revised-plan`, `uncontaminated-worktree`, or
`resolved-finalization-blockers` requirement. The last applies when correction
has stopped with unresolved finalization failures and no validated retry
applies; it requires resolving the reported blockers, restoring a clean
baseline, and preparing a plan for the remaining work before starting a fresh
execution run. A submitted input awaiting detached continuation exposes no
second action. Plan revision never projects resume of the stale run, and a
read-only repository mutation never projects acceptance of contaminated or
hybrid changes. This is a read-only projection of existing durable state and
does not change the root or pipeline state versions.

## Operator Guidance

`docs/OPERATOR_GUIDE.md` is the installed, canonical CLI/MCP operating procedure.
It distinguishes expected pauses, genuine unexpected defects, and stable
project lessons. Operators follow current actions and resume resumable work
without taking it over. Valid dirty work from a genuinely non-resumable run may
enter polishing after ownership ends and inputs are reconciled, preserving
contamination safeguards and the uncommitted outcome.

The guidance capability lives under `src/guidance/` behind its public `index.js`.
Private content, contract, file, selection, and service modules own composition, configuration
selection, confined access, and durable replacement. Its factory is deliberately
exported from `src/index.js`; transports consume the same capability rather
than duplicating policy. No pipeline depends on it.

`createGuidanceService().read({ projectPath, projectConfigurationPath? })` loads
the common guide from the installed runner and uses public configuration,
workspace and Git services to resolve `<artifactRoot>/agent-runner/rules.md` from the
selected infrastructure root, or the target when no configuration is selected.
Ordinary directories need no Git prerequisite. Git discovery keeps the worktree
target, including explicit integrated and external configuration selected from
subdirectories. Relative external selectors resolve from the originally supplied
directory before worktree rebasing; selection rechecks and durable action identities
retain that exact path. Integrated selectors retain worktree-relative recovery.
Only an explicit configuration bound to the supplied directory
retains that scope, with the enclosing worktree supplying the canonical exclusion key.
Explicit external selection uses the configuration capability's target-bound root
and never merges integrated guidance or discovers sibling infrastructure. Its result
contains canonical project/local/configuration paths, complete `commonContent`
and `localContent`, `combinedContent`, and `localHash`. Rendering separates the
documents and states that local additions cannot weaken common safety or
product contracts. Missing local content is an empty string with a null hash;
an existing document, including an empty one, has a SHA-256 hash. Reading
creates neither local artifacts nor external state.

Both documents have a 64 KiB UTF-8 byte limit. Reads and replacements reject
invalid encoding, unsafe control characters, and recognizable credential or
provider-transcript formats without echoing or partially redacting content.
Operators remain responsible for excluding sensitive material that cannot be
recognized deterministically. Integrated paths in a Git worktree must be ignored
and untracked. External paths use exact target-bound confinement without target
Git inspection or writes. All paths must be disjoint from project configuration
and protected control paths. The workspace capability's `inspectControls` reuses
control discovery along the exact target/destination ancestry, including Git
pointers, shared metadata and canonical ancestor provider alias targets containing
selected destinations. Resolved internal provider-control alias targets are
protected like the links themselves. Control-discovery failures use their own
controls diagnostic under the same `ERR_UNSAFE_GUIDANCE_PATH` code, while a
destination inside any control or resolved target still fails as an unsafe
guidance path. The query traverses discovered protected control trees and their
metadata dependencies, including nested Git pointers, without traversing unrelated
project content. Metadata reached only through state ancestors also protects
selected destinations; this query grants no snapshot reads. Missing
destinations receive the same safety inspection. Symlinks, hard links,
non-regular files, and unsafe ancestors fail closed.

The public `update` method accepts the same selectors plus complete
`localContent`, nullable `expectedHash`, and `idempotencyKey`. It validates the
external-state boundary before intent or lease writes, rejecting state and
project trees that contain one another. It binds the key to
canonical arguments and a content hash, and reserves the destination and a hash
of resolved configuration. Versioned selection evidence also pins the infrastructure
base, target exclusion key and existing real directory ancestry; newly prepared
publication ancestors are persisted before temporary-file writes. State storage
must be disjoint from the target, enclosing exclusion tree and infrastructure.
The existing action store accepts the narrow
`guidance_update` kind. Context and receipts contain paths, hashes, publication
phases, and filesystem identity, never document bodies. The state service's
`withGuidanceLease` holds the canonical-worktree lease with an opaque operation
owner, excluding mutating execution and other guidance writers across processes.
External publication also holds an infrastructure-root lease unless the target
lease already encloses that root. Overlapping infrastructure selections from
different targets therefore cannot publish concurrently; both leases are checked
before publication and released together.
A contender receives a conflict and may retry its same incomplete intent after
ownership is released.

Filesystem access is relative to pinned directory descriptors using
`/proc/self/fd` or `/dev/fd`; unavailable descriptor access fails closed.
Directory identities and lexical confinement are rechecked around effects so
ancestor replacement cannot redirect reads, writes, publication, or cleanup.
Atomic rename publishes an owner-only, synchronized temporary file in the
destination directory; integrated Git temporary paths must also be ignored. Publication
rechecks configuration, path safety, execution ownership, the expected hash,
and inspected file identities.

An intent records reserved, writing, prepared, and published phases. Temporary
inode provenance is persisted before writing, and complete file identity before
rename. Recovery removes a proven partial temporary write or recognizes its
own renamed inode. It never adopts another writer's identical bytes or
overwrites an intervening edit. An unproven temporary file left before
provenance was recorded is neither adopted nor deleted; retry reserves a fresh
name. Changed configuration or substituted bound ancestors cannot redirect
incomplete publication, including after restart. Legacy integrated intents retain
their original worktree-relative arguments, destination and configuration hash,
including for configuration selectors retried from Git subdirectories.
Compatibility lookup applies only to binding-free legacy actions and grants no
external authority. Current actions retain their exact selector identity. A durable
published record completes its receipt without replaying the effect. Completed
retries return the recorded bounded receipt (`projectPath`, `localPath`,
`localHash`, `updated`) without reapplying the old hash comparison or reloading
configuration. Receipts describe their operation, not the current document.

The CLI dispatches `guidance` and `guidance edit` directly to this capability
with project/configuration selectors; it never constructs a pipeline runner.
The capability's `edit` method reads and pins the complete original selection,
opens an owner-only temporary document outside the project, and validates the
entire result after the editor closes. It uses the same confined file access
and shared writer, retaining the original destination and configuration hash
through the publication boundary. Even unchanged content must pass current
path, hash, configuration, and execution-ownership checks. A missing document
left unchanged remains absent, with a null-hash no-op receipt; explicit empty
replacement still creates an empty document. Temporary copies are removed
through their pinned parent directory, without following substituted links.

`src/editor.js` owns shared shell-free command parsing, `$VISUAL`/`$EDITOR`
selection, launch fallback, and exit/signal outcomes. Only an unavailable or
unparseable editor command permits fallback. Guidance rejects a nonzero or
signalled close and never publishes that edit. Clarification retains its
existing policy: any launched editor close consumes its one-shot authorization,
even after a nonzero exit or signal. Authorization, document safety, and
publication remain in their owning capabilities. MCP never opens an editor.

Local guidance supplies instructions only to the supervisor. Ordinary pipeline
prompts, run state and resume configuration do not include it. Init retains and
reviews proposed local content as setup data, including its guidance publication
intent; that content grants no role instructions or permissions. Guidance never constructs a pipeline run,
changes ignore rules, replaces the common guide, mutates Git control state,
or performs finalization or commit work.

## MCP Control Plane

`update_check` and `update_apply` delegate to the single root update service with
the control plane's store. Both have strict schemas and no project/configuration,
source, role or run selectors. Apply requires `operatorInitiated: true` plus an
idempotency key; that acknowledgement is not authority inferred from task content.
Existing provider isolation keeps MCP disabled in pipeline sessions. Check is
read-only and on demand; apply is destructive and idempotent. Both declare their
fixed official registry interaction as open-world. Wait cancellation detaches only
the observer: receipt publication continues, and server loss recovers from the
persisted intent on the identical request. Neither restarts an MCP client or resumes
a run. CLI `update --check` and `update` use the same capability directly, without
constructing a pipeline or resolving project configuration; stdout contains one
bounded JSON result. Before effects, apply prints an automatically generated retry
key on stderr so an interrupted invocation remains retryable. Diagnostics stay on stderr.

`agent-run mcp` exposes the same static pipeline registry and runner through the
official Node MCP SDK over STDIO only. The private `src/mcp/service.js` module
owns the nine pipeline-control tools: `pipelines_list`, `run_start`, `run_status`,
`run_activity`, `run_wait`, `run_respond`, `run_resume`, `run_pause`, and
`run_cancel`; it also owns the shared-capability tools `guidance_read` and
`guidance_update`, `update_check`, `update_apply`, the issue-management tools
`issues_list`, `issues_read`, and `issues_update`, and the
conditionally registered MCP-only `unexpected_issue_report`. It contains
transport schemas and concise projections, not a second workflow
implementation. The issue tools delegate directly to `src/issues/index.js`,
sharing the control plane's run store. Management tools stay registered when
issue reporting is disabled.
Standard output belongs exclusively to MCP; bounded
protocol diagnostics go to standard error without prompts or model transcripts.

One compact startup instruction asks the supervisor to call `guidance_read`
once before first managing a run for each project. It remains present when
issue reporting is disabled; tool descriptions do not repeat the guide.
Both strict guidance schemas accept `projectPath` and optional
`projectConfigurationPath`. Reading returns complete common and local content,
combined rendering, resolved paths, and the nullable local hash. Replacement
also requires complete `localContent`, nullable `expectedHash`, and an
`idempotencyKey`, returning only the bounded publication receipt. An empty
document removes local additions. Reading is annotated read-only; replacement
is destructive, idempotent, and local.

MCP delegates both calls directly to `src/guidance/index.js`, sharing the
control plane's run store and current configuration loader. That capability
owns file safety, byte and content validation, composition, worktree exclusion,
action intents, interrupted-publication recovery, and receipts. MCP neither
opens an editor nor adds another action wrapper. Completed retries replay the
recorded receipt without overwriting later CLI or MCP edits; stale edits require
a fresh read, reconciliation, and a new mutation key. Guidance remains outside
role prompts, run state, and resume configuration.

Unexpected-issue reporting remains deliberate and caller-initiated. Its tool
description and server instructions limit it to a supervising client agent
that has explicitly concluded Agent Runner behaved genuinely unexpectedly or
contrary to its documented contract. Expected completion, exhausted configured
budgets, usage limits, expected user pauses, documented environment blockers,
and invalid user or configuration input are not reportable. Runner error paths
never invoke it, and backend role sessions are not exposed to the MCP server.

The caller supplies bounded English Markdown for every diagnostic section and
optional bounded details, run ID, and error code. The service never gathers or
attaches logs, transcripts, prompts, environment values, credentials, secrets,
or other diagnostic data automatically. The shared capability validates the
same field bounds as the MCP schema. It first replays a completed receipt for
the lexically resolved request, then canonicalizes the Git project and
validates the external-state boundary before action persistence. The origin is
recorded as bounded context and grants no storage authority; no configuration
is loaded and `projectConfigurationPath` only remains part of the request
identity.

Issues live in one private per-user store selected from environment, home, and
platform inputs injected at composition: `$XDG_DATA_HOME/agent-runner/issues`
on Linux, with unset or relative XDG values falling back to `~/.local/share`,
user Application Support on macOS, and `%LOCALAPPDATA%` on Windows. Mapping
requires bounded safe absolute paths and grants no execution-platform support.
The store must neither contain nor lie inside the origin project, the state
root, the user settings file, the installation, or the installed runtime
payload root; ordinary shared parents such as `agent-runner/` are allowed.
Every path component is opened without following links; missing components
are created with mode `0700`, and the final directory must belong to the
current user without group or other access. Operations use the
descriptor-bound directory and reverify each component identity and the
store's private ownership, so link, permission, or replacement attacks fail. Publication never touches the project or its ignore
rules.

Each issue is `<issueId>.json`, a canonical, bounded, schema-versioned JSON
document whose random UUID v4 ID is bound to its filename. It holds the
immutable rendered Markdown with its SHA-256 hash and one authoritative
tracking record: revision, a finite status (`open`, `queued`, `in_progress`,
`resolved`, or `dismissed`), origin name and canonical path, creation and
update times, optional run ID and error code, bounded plan and resolving commit
references, and an optional note. Creation writes revision `1`, status `open`,
and empty tracking metadata. Strict parsing rejects unknown or duplicate
fields, non-canonical bytes, and invalid IDs, statuses, hashes, or bounds.

Management opens the store without creating it; a missing store is an empty
backlog. It loads no configuration, inspects no origin, constructs no pipeline,
and takes no worktree lease. Listing reads every published `<issueId>.json`
through the descriptor-bound directory (at most 10,000 entries), skipping
hidden reservation files, foreign names, and a document still hard-linked to
its bound creation file. Exact filters compare the recorded origin path and
status; results sort by `createdAt`, then ID, with pages of 1 to 100 (default
50). The opaque base64url cursor holds the last key and a hash of the store
path, directory identity, and canonical filters; any other binding fails with
`ERR_INVALID_ISSUE_CURSOR`. Read returns Markdown, tracking, `documentHash`
(SHA-256 of the document bytes), and the path; absent and unfinished issues
fail with `ERR_ISSUE_NOT_FOUND`.

`issues_update` sets only `status`, `planReferences`, `commitReferences`, and
`note`; omitted fields are unchanged, `[]` and `null` clear, and at least one
field is required. It requires `expectedRevision`, `expectedHash`, and an
idempotency key. A mismatch fails with `ERR_ISSUE_REVISION_CONFLICT` without
mutation. Success increments the revision, advances `updatedAt` monotonically,
and returns `{ issueId, revision, documentHash }`.

`agent-run issues list`, `issues read`, and `issues update` call the same
service methods directly from `src/cli.js` with the CLI environment, without
constructing a runner, loading configuration, or consulting `issueReporting`.
They map `--origin`, repeatable `--status`, `--limit`, `--cursor`, `--issue`,
`--expected-revision`, `--expected-hash`, repeatable references, and `--note`
onto the shared inputs; `--clear-*` flags supply `[]` or `null`, and combining
a value with its clear flag fails before dispatch. Admission receives no origin
path, so the list filter remains uninspected. Stdout carries one JSON result;
an update without `--idempotency-key` first prints its generated key on stderr
and adds it to the receipt, under the same `issues_update` action identity as
MCP. Errors print their message on stderr with exit code `1`. Creation remains
MCP-only.

Mutating MCP calls require an opaque idempotency key. The state layer hashes the
key, binds it to the tool and canonical arguments, and durably records an action
intent before mutation and a receipt before returning. An exact retry returns
the receipt; reuse with different arguments fails. An incomplete run intent is
reconciled against the reserved run ID, current revision, submitted transcript
hash, and execution lease before work is launched again.

`run_start` persists the run before spawning `agent-run resume` as a detached
child with no inherited standard streams. An incomplete start first loads its
reserved run and validates the request paths against that run's frozen workspace
selection. Current configuration is resolved only when creating a new run;
changed defaults cannot change a reserved run's workspace or plan kind.
`run_respond` atomically writes the
identified answers, records their transcript hash in run state, then launches
the same detached continuation. `run_resume` normally accepts only an action
applicable to the persisted pause. Two exact-revision, action-free recovery
paths are additional: a nonterminal checkpoint with no pause or live owner, and
an ownerless applicable stop. Stop recovery persists its own idempotency intent
and private stop-checkpoint revision, so it uses a new key and does not require
the original stop key. A non-null action, stale revision, live owner, or
duplicate ownership race is rejected without weakening ordinary pause-action
validation.

An ordinary continuation child owns the existing per-run execution lease and,
for plan execution or polishing, the canonical-worktree lease. Before ordinary
detached dispatch, MCP rejects an already-owned worktree without completing the
idempotency intent, leaving the reserved durable run available for an exact
retry. After spawning an ordinary mutating continuation, MCP withholds the
receipt until journaled readiness correlates that dispatch with process retirement
and checkpoint continuation under the required leases. A child that loses a
concurrent ownership race leaves the intent incomplete and exactly retryable.
Child-exit and ownership notifications wake bounded inspection; unrelated
revision changes and transient lease ownership cannot acknowledge a launch.

Detached stop reconciliation has the stronger completion condition. MCP binds
the launched child to the exact stop checkpoint and follows it until that stop
is durably settled or that child exits; transient acquisition of the run lease
is not progress. Exit before settlement leaves the recovery intent retryable
and reports detached-start failure or the distinct runtime-version-skew error.
A delayed child carries the checkpoint revision and becomes a no-op after that
stop settles, so it cannot resume a reconciled pause or revive cancellation.
An MCP disconnect, tool timeout, worktree conflict, or duplicate recovery
launch cannot create a second workflow owner.

`run_pause` and `run_cancel` delegate directly to the state-owned stop action,
so the acceptance event and receipt are durable before either tool returns.
Both require the caller's exact inspected revision and idempotency key. An
exact retry replays the receipt; a stale or conflicting request never refreshes
itself. A live execution owner observes the durable request through the runner
monitor. If ownership was already lost, MCP launches a detached action-free
resume to perform the same-run reconciliation. If the child exits first, the
diagnostic identifies a conflicting canonical lease by its recorded owner run
ID, distinct from the ownerless run whose stop remains applicable. Execution
and worktree leases still exclude a second owner. Client cancellation stops
only the tool's wait and does not retract the request or terminate the detached
child.

MCP start fields remain additive. `run_start.mode` exposes the union of
descriptor modes (`independent`, `lazy`, `combined`); the selected pipeline
validates availability. It has the same highest precedence as CLI `--mode`.
MCP guidance states that `independent` is the default and recommended choice for genuinely
independent semantic review despite its higher context and token cost, and that
`lazy` is an opt-in lower-consumption tradeoff without independent review that
must never be selected automatically. `combined` adds primary
convergence before independent review. `sourceSession` defaults to unset. When
a compatible current native session is available, the controlling agent offers
a fresh start and a deliberate fork choice, including its trusted source
profile when known. An unknown profile permits only `current` inheritance; the
agent never guesses an alias, inspects provider-private storage, or interprets
the opaque native ID. The field is passed only after the user selects the fork.
Independent and combined modes fork the complete source context into primary
and review roles; lazy mode forks it once into the primary role. A fresh start is
recommended for a long, multi-topic, or uncertain source session to avoid
unnecessary provider context and quota use.

The role-backend and source-session backend enums are projections of the
provider registry. A descriptor that does not advertise source-session forks
does not appear in the latter enum; the selected installed adapter must still
prove native fork support at its capability probe.

`run_wait` is one revision-driven server-side wait that ends at an unresolved
`WAITING_FOR_USER`, `DONE`, `FAILED`, `CANCELED`, an `interrupted` execution
whose lease owner is positively `dead` or `replaced`, or its caller-selected
timeout. Positive owner loss interrupts a checkpoint requiring continuation even
between turns, with no active turn, execution process, preparation record, or
revision change. An owner can exit without changing any file, and Node reports
no exit for a non-child process, so the wait also watches lease files and runs a
read-only lease-owner probe once per second. The probe uses the same
classification as `run_status`, against the classification the caller already
inspected. Only a change to `dead` or `replaced` wakes the wait. The probe
reads no journal, takes no lease, and writes nothing, and a failed probe read
does not end the wait. `live`, `unverifiable`, and `none` (a released or
transferring lease) keep waiting, so recovery stays an explicit `run_resume`.
Optional MCP progress notifications carry only bounded public activity with
role labels; they do not wake a model or alter the run. Cancellation cancels
only that wait.

An omitted `run_wait.timeoutMs` means 30 seconds and the public maximum is 24
hours; either deadline ends only the client wait. Internal detached-dispatch
and detached reconciliation uses bounded event-driven observation, while the
operator-stop monitor waits for a revision for at most one second at a time.
These are fixed correctness mechanics rather than user-work retry budgets.

MCP status and wait also project one bounded `execution` object. Its finite
`leaseOwner` is `none`, `live`, `dead`, `replaced`, or `unverifiable`, while
`processRecord` is `none` or `persisted`; neither field exposes process
identity. `state` remains the conservative action summary: `running` while the
lease owner is live or unverifiable, `interrupted` when a persisted active turn
or execution process/preparation record has no exclusionary owner, or when a
positively dead or replaced owner leaves a checkpoint requiring continuation,
and `idle` otherwise. Terminal states and unresolved `WAITING_FOR_USER` retain
their existing semantics; owner loss alone does not make them interrupted.
Nullable `role` and `phase` come only from the common run envelope. A read
applies the same exact same-host process-identity classification used for
exclusive acquisition without changing ownership. A timeout therefore
distinguishes live lease ownership, unresolved lease identity, and durable
process ownership without a heartbeat or journal polling.
`pipelines_list` projects descriptor-owned setting values, defaults, and
recommendations. Status, wait, and activity project the persisted resolved mode
without inactive role configuration or provider-private data. `run_activity`
remains an explicit cursor-based history read rather than a polling primitive.
Status and wait additionally expose only the pending stop kind and accepted
revision while reconciliation is incomplete; the request hash, suspended
checkpoint, and internal ownership evidence remain private.

V1 does not require the MCP Tasks extension, a network transport,
authentication, or a daemon.

### Bounded action-free continuation

CLI resume accepts an optional `--expected-revision`; MCP resume always binds
its inspected revision. Both enter the same runner resume path. Admission
checks the revision under the execution lease before recovery. An ownerless
nonterminal checkpoint with no pause also accepts action-free continuation,
including a crash between admission and the first provider turn. Retained
process/resource reservations are exclusion evidence, not proof of a live
runner: only same-host owner inspection decides whether to dispatch a replacement.
Same-run worktree reclamation retains exact process identity, mutation, and
reclaim-marker checks, and recovery reuses an already-held worktree handle.

MCP action-lease contention returns `ERR_MCP_ACTION_IN_PROGRESS` immediately.
Detached dispatch uses revision/lease notifications and the correlated child's
exit, with at most 64 inspections within 30 seconds. Exhaustion returns
`ERR_DETACHED_OWNERSHIP_PENDING`; it does not clear ownership or cancel the child.
The client can retry the identical key. Client cancellation and disconnect affect
only observation; reconciliation and receipt publication keep their action lease.

Before IPC admission, the action intent saves a dispatch UUID, exact revision,
and the child's hostname/boot/PID/start identity. The inert child waits up to ten
seconds for admission and cannot execute after a pre-admission disconnect.
Under the execution lease it journals a correlated `dispatch-started` event
before potentially long recovery. After process/resource retirement and acquiring
the required worktree lease, `dispatch-ready` marks checkpoint continuation;
short input/configuration paths can acknowledge their durable return; stop
recovery uses its existing checkpoint-bound settlement without appending another
acknowledgement revision.
These events do not approve content or attest workflow completion. Public activity
and progress output omit the private correlation UUID. Legacy confirmation
proof accepts these events only when the complete state is unchanged apart
from revision and timestamp; it is rebuilt for the acknowledged snapshot. The detached compatibility token versions
this admission protocol independently of the run envelope.

A restarted control plane adopts only matching journal evidence, never arbitrary
revision movement or transient lease ownership. A live or unverifiable recorded
child prevents redispatch. A dead/replaced child without a ready event permits
same-key recovery only at its unchanged revision or while its admission is
followed exclusively by root reconciliation. Another admission or workflow turn
makes that request stale. A durable ready event permits receipt repair even after
later pauses or input changes. Stop receipts additionally require settlement of
the specific saved stop checkpoint. A different worktree owner remains identified
in the retryable diagnostic.

The state capability exposes `recordRecoveryFailure(runId, dispatch, { stage,
error })` and `readRecoveryFailure(runId, { id, expectedRevision, owner })` for
detached recovery diagnostics. Each dispatch has an immutable, exclusively and
atomically published `.recovery-failure-<uuid>.json` beside the run state, bounded
to 4 KiB on publication and reads, and reserved from ordinary run-artifact writes.
Publication derives hostname/PID/boot/start identity from the publishing child.
Reading requires the exact run UUID, dispatch UUID, expected revision and child
identity already recorded in the action intent; mismatches and missing historical
records return no cause. A late child cannot replace a later dispatch's record.
Identical writes are idempotent; conflicting records are rejected.

These sidecars use the existing durable exclusive-file publication protocol,
without acquiring the execution or action lease or reading the workflow journal.
They can therefore retain failures before execution-lease acquisition or durable
readiness. The closed record stores a finite recovery stage, recognized Runner
error code and fixed allowlisted explanation; unrecognized errors retain a null
code and an unavailable explanation. Error messages, causes, stacks, provider
output and transcripts are discarded. Exit codes and signals are separate
observations and are never inferred from a diagnostic. A diagnostic cannot
acknowledge dispatch, complete an action receipt, change acceptance or workflow
state, or release uncertain ownership.

The CLI resume boundary publishes this diagnostic after a failed admitted
dispatch, using the actual recovery stage reported by the runner. Runtime
compatibility and execution-lease failures can therefore be retained before
admission is journaled. Diagnostic publication failure preserves the original
failure and its exit status. CLI recovery explanations use the same allowlist;
native messages, causes and stacks never supply detached diagnostics.

The launcher forwards both child exit arguments. MCP dispatch errors expose
`dispatchFailure: { exitCode, signal }` separately from the nullable
`recoveryCause: { stage, code, explanation }`. Tool errors return `isError: true`
with these fields, the dispatch error `code` and safe `message` in both text JSON
and `structuredContent`. Only exact state-owned correlation admits a cause;
missing, invalid or mismatched diagnostics explicitly leave it unavailable.
Failed journal, status or ownership inspection for a recorded dispatch uses
the same safe projection, including identical-key retries after restart.
Stop recovery loads its saved action context before status or lease inspection,
including the original checkpoint retained by a superseding cancellation.
Inspection failure grants neither receipt completion nor replacement authority.
An unobserved exit has null facts, including after control-plane replacement;
neither a signal nor an exit code establishes a recovery cause. Version-skew
exit handling retains its distinct restart instruction. Admission errors also
discard arbitrary native error text. Bounded event-driven inspection, runtime
compatibility, readiness, stop settlement and exact-key retry rules are unchanged.
Failed dispatches retain incomplete intents and ownership exclusion. Retrying
does not repair the reported blocker or acknowledge workflow success.

Action-free provider process-proof failures leave the active turn and exact
pipeline checkpoint durable, including a finalization failure after command
execution. They do not become terminal `internal_failure` or accept output,
fingerprints, or checks while ownership is uncertain. Resume retires retained
processes first, then performs the pipeline's ordinary interrupted-turn Git/input
reconciliation. Consumed effects retain verification-only recovery.

## External Run State

Common envelope version 24 adds a nullable immutable `workspace` binding. New
runner-created runs save their selected kind, lease policy and canonical key;
directory runs also save exact provider declarations, binding/protected-content
fingerprints and empty retrieval authority. Legacy absence stays null and
retains Git semantics during ordinary leased migration; resume never derives
directory authority or replaces a frozen selection from current configuration.
The detached compatibility token includes this envelope change.

Common envelope version 23 adds `preservationRecords`: at most 1,024 compact
references to immutable external capture/restoration records. Each reference
binds an operation UUID to an exact record UUID, SHA-256 and file identity.
Only state-owned preservation transitions may append or replace one reference;
they preserve pipeline state and all other authority. Records, manifests and
payload bytes stay outside bounded state JSON. Legacy absence normalizes to an
empty list, and the ordinary leased runtime migration persists that absence
without inventing preservation authority or rewriting historical events.
Version-22 preparation recovery settles and clears custody under its issued
envelope before the ordinary migration; its certificate and custody history
remain unchanged.
Execution's version-29 eligibility remains disabled.

Common run-envelope version 18 adds nullable `observations`. Legacy absence
normalizes to `null` on lock-free reads; the existing leased runtime migration
persists that absence without inventing usage or rewriting historical events.
`src/state/observations.js` owns the closed version-1 observation record: the
latest 32 runner attempts and a saturating count of omitted attempts. Each
attempt binds its starting revision as its runner-owned ID to the exact role
and checkpoint, with at most nine sealed native attempt/turn records. Replacement
and recovery retain earlier facts and mark open attempts interrupted. Terminal
attempts and accepted native records are immutable; stale callbacks and duplicate
native ordinals cannot overwrite them. Journal continuity validates these rules.

The runner batches synchronous adapter observations in a bounded map, flushing
before native fresh-session fallback and at invocation termination, including
failure and cancellation. Observation notifications never trigger state writes or
timers. Unchanged batches do not publish revisions. Accepted batches
use the existing leased write-ahead append before atomic snapshot replacement;
recovery repairs interrupted publication and journals incomplete retirement.
Startup observation persistence precedes provider inactivity timing; fallback
flushes neither suspend nor reset the existing deadline. Terminal persistence
runs after the watchdog closes. Inactivity publication also uses the same
serialized write queue so expiry can race a diagnostic batch safely.
It shares the stop monitor's write queue with process and resource callbacks so
diagnostics cannot contend with the owner's stop publication.
Diagnostic writes may finish while process cleanup or a stop is pending, without
changing workflow, correction, retry, process, or effect authority. Interrupted
observation retirement alone qualifies as detached dispatch preparation only
when all other state remains unchanged.

Native `last` and `cumulative` snapshots, their scope and inclusion flags, and
nullable counters remain unchanged; no snapshots or inclusive subsets are added
together. Runner accounting is `reported` only for a completed invocation with
nonempty, entirely reported evidence and no known incomplete facts; otherwise
it is `incomplete`, including unobserved terminal attempts. This describes
observed reporting, not complete historical token consumption. Batches contain
only the normalized payload-free adapter contract. Persistence errors cannot
replace an established provider, safety, ownership, or effect failure.

Common run-envelope version 19 adds an optional closed `measurements` object
on each runner attempt in the version-1 observation record. Version 18 rejects
this field. Its records migrate through the leased runtime migration before
measurement-bearing attempts can begin, changing the detached compatibility
token so mixed-version dispatch rejects before accessing run state.
After migration, leased recovery retires interrupted observations before any
continuation, including verification-only recovery of a consumed commit.
Retirement waits for process-ownership proof and resource cleanup; an unresolved
ownership failure leaves diagnostic state unchanged.
Legacy attempts omit measurements and project `null`;
reads and later attempts preserve the historical shape without backfilling or
rewriting events. New attempts record nullable nonnegative safe integer
`promptBytes`, `recoveryPromptBytes`, `schemaBytes`, `resultBytes`, and
`structuredResultBytes`, plus explicitly unknown `referencedFileCount` and
`referencedFileBytes` (both null). The runner measures UTF-8 strings with
`Buffer.byteLength` and schema/structured JSON with `JSON.stringify`. These are
the supplied request prompt and complete reconstruction prompt, supplied schema,
and returned adapter output and structured object; they exclude native wrappers,
implicit provider schemas, prior session context, and referenced-file contents.
The reconstruction prompt is available context, not proof that fallback sent it.
An absent schema, missing response, or unavailable serialization remains null.
Result measurements settle only on completed invocations; source measurements
and terminal evidence cannot be rewritten. No content or file path is stored.

`projectObservations` is the state-owned allowlisted projection used by runner
results, CLI status, and MCP status/wait. It preserves attempt correlation,
retention omissions, uncertainty, native scopes, inclusion rules, and bounded
counts. CLI renders the latest attempt; MCP retains the bounded attempt list.
State-owned `observations` activity is journaled at start, changed fallback
batches, and terminal settlement, and the runner publishes the same concise
events live. No native payload or arbitrary failure text enters either surface.
Byte measurements and token snapshots are separate diagnostics, never capacity
controls, consumption totals, progress, or permission to replay an effect.

The state service's internal `loadRunHistory` operation returns the run and
complete validated events from one authoritative snapshot. Runtime callers use
`stream: true` to replay that prefix as a repeatable asynchronous iterable;
existing materialized inspection remains available for bounded histories.
Replay shares journal continuity, size, migration-envelope, and
snapshot-consistency checks with ordinary reads and preserves lock-free,
non-repairing status semantics.
Recovery still repairs incomplete tails and lagging snapshots only under the
run lease. Optional expected-revision transitions reject stale evidence before
appending anything.

The runner supplies this private history to a pipeline's optional
asynchronous `prepareRecovery` descriptor operation. Proofs consume events
incrementally and require the final replayed state to match the inspected run.
Plan execution binds legacy terminal confirmation eligibility to the inspected
run object and revision; no history or recovery authorization is serialized
into public run data. Status may project supported migrations in memory, while
execution first persists the existing migration chain and obtains fresh history
under both execution leases. Plan-execution resume revalidates canonical project and task boundaries
inside the worktree lease, including restart after a durable recovery transition.
Pipeline policy validates actual candidate/finalization transitions and their
intervening fingerprint lineage. A migrated terminal snapshot alone
cannot establish acceptance. The exact legacy opaque failure can then enter
`CONFIRM` through a revision-checked write-ahead transition carrying the
read-only active request. Existing interrupted-turn reconstruction handles a
crash at any persistence boundary without repeating a source fork or earlier
work. Non-actionable `pendingCorrection` accounting is retained with its
counters; concrete pending work and effects remain disqualifying.

The descriptor shares that eligibility with CLI/MCP projections and resume
action validation. MCP's detached launcher admits the proven failed state
without changing stale-revision, ownership, compatibility, or receipt rules.
The owning [execution specification](../pipelines/plan-execution/docs/SPEC.md)
defines eligibility and revalidation; the state layer owns all journal I/O.

The root runtime persists runs under `$XDG_STATE_HOME/agent-runner/`, falling
back to `~/.local/state/agent-runner/`. A run is addressed by an opaque ID and
stored beneath `runs/<run-id>/`. Preflight requires the canonical state tree
to be disjoint from both the project and task trees: neither may contain the
other.

MCP action intents and receipts live under `actions/<hashed-key>/` in the same
external root. The opaque key itself is not persisted. Action records are
atomically replaced and protected by a same-host process lease; they never live
inside the target or task directory. Read-only `readAction` accepts exact
arguments or a synchronous resolver over frozen saved context; both forms
require the same tool and canonical argument hash before returning the record.

An unexpected-issue action keeps the existing tool namespace and canonical
argument binding. Its intent reserves the request selector and canonical
origin, store path and directory identity, issue ID, creation time, document
hash, and a private temporary name before publication. A saved selector maps an
exact retry, including one naming a project subdirectory, to its verified
canonical arguments without consulting a deleted origin. The temporary file is
created exclusively with mode `0600`, its device, inode, and birth time are
bound in the intent before content is written, and it is synced and hard-linked to its final
name, which never replaces an existing file. The directory is synced and its
identity and private ownership are rechecked before the action records a
published phase, while the temporary link still proves ownership; it then
removes that link, verifies the published bytes, and persists the
`{ issueId, issuePath }` receipt before returning. Only the bound temporary
file is ever removed; an unbound or substituted entry is preserved and fails
with `ERR_ISSUE_REPORT_OWNERSHIP`. Recovery republishes
only in the reserved store with the reserved ID and bytes: a relocated or
replaced store directory fails with `ERR_ISSUE_STORE_CHANGED`, and an identity
collision or extra hard link fails without adoption. An exact retry returns the receipt, while key
reuse with different arguments fails. Historical completed receipts, including
repository-local `{ reportPath }` receipts, replay unchanged before any origin
inspection; an intent that
never reserved a local destination is rebound to the global store, and any
other incomplete local intent fails with
`ERR_ISSUE_REPORT_LEGACY_PUBLICATION` without touching its files.

Issue mutations are serialized by the state layer's same-host lease in the
store's private `.coordination/<issueId>/` directory, created with mode `0700`
through the descriptor-bound store and held after the action lease. Both
levels are opened without following links and used only through their
descriptors, and each level's parent is synced before the lease admits a
mutation; every store verification during the mutation also proves their
identities, so a replaced or linked directory fails with
`ERR_UNSAFE_ISSUE_STORE` before any destructive step. Because
it lives in the shared store, every writer to that store coordinates there,
whatever its state root; listing ignores the directory. Creation holds it from publication through its
receipt, so no update observes a half-published document; recovery then
compares only immutable report, origin, and creation fields, tolerating later
tracking updates. An `issues_update` action replays a completed receipt before
store resolution and binds the store path and identity in its intent; a moved,
replaced, or missing store fails with `ERR_ISSUE_STORE_CHANGED`. Under the
issue lease it checks the expected revision and hash, persists the next
document hash and update time in the intent, records that hash in the lease
directory's ledger for the next revision, and writes the previous bytes to a
private bound backup and the new bytes to a private synced temporary file. It
rechecks the exact document it read and the temporary file's bound identity,
isolation, and bytes immediately before atomically renaming it over the
document; the backup is removed only after the published identity and bytes
are verified and remains otherwise. Recovery syncs and reverifies the store before completing the
receipt when the current hash or that ledger entry matches its prepared hash,
reapplies identical bytes when the document is still at the expected revision,
and otherwise fails as stale. A later writer at the same revision overwrites the
ledger entry before replacing, so ledger entries prove which document each
published revision held. Only bound temporary and backup files are removed
after a failed replacement, and the backup only while the previous document is
still in place.

Canonical-worktree leases live under
`worktrees/<sha256(canonical-worktree-path)>/` in that external root. The hash
keeps filesystem-safe bounded keys while the owner record contains only the
run ID, an opaque token, process ID, hostname, acquisition time, and nullable
process identity. Version-2 lease records pin Linux boot identity and process
start ticks when available. A live reused PID is a replaced owner, not proof
that the recorded execution survives. Foreign-host, legacy, identity-free, and
otherwise unverifiable owners remain conservative exclusion barriers. Legacy
records are read without rewriting them; new acquisitions publish the current
lease format. New acquisitions pin the canonical scope in an immutable
`scope.json` beside the lease. The existing mutation boundary serializes scope
inspection and admission across keys; parent/child scopes cannot both acquire
exclusive ownership. A different overlapping key treats even dead lease or
reclaiming records as barriers until exact-key recovery reconciles them. Legacy
Git records retain exact-key exclusion without rewriting their owner format.
Scope records and key directories may remain after release. Ownership uses
`.lease`; a pending stop also retains an interrupted `.lease-reclaiming`
reservation until reconciliation permits its release.

Run, canonical-worktree, reclaiming, and MCP action leases share one durable
no-replace publication primitive. It writes and syncs the complete JSON record
to an isolated in-directory temporary file, atomically links that inode at the
lease path only when the path is absent, removes the temporary link, and syncs
the directory before acquisition returns. A lock-free reader therefore treats
an unpublished lease as absent and parses only a complete record. If it meets
the bounded internal link between publication and cleanup, including after an
interrupted publisher, it removes only the matching same-directory temporary
link to restore the isolated final file. Bounded retries cover replacement
publication between inspection and opening; each read still requires an
isolated regular file, and unrecognized or persistent hard links remain unsafe.
Exclusive contention, dead-owner recovery, and release all use the published
record and continue to verify its opaque owner token. A current same-host run
or worktree lease with a complete boot/PID/start identity is reclaimable
immediately only when that exact owner is dead or replaced. Acquisition time is
neither a delay nor ownership proof. Legacy, identity-free, foreign-host, live,
invalid, and otherwise unverifiable records remain exclusion barriers.

These state retry counts are fixed correctness guards rather than workflow
budgets. Managed-state reads make at most five attempts across an atomic
replacement; lease acquisition, including reclaim-marker and owner
reconciliation, makes at most five passes. Runner release of either an
execution or canonical-worktree lease makes at most five stop-aware attempts;
exhaustion leaves stop reconciliation pending. Generated run IDs try at most
ten candidates. None of these loops
waits for user work or makes an external service more available, so exposing
their counts as configuration would weaken the persistence proof without
creating a useful operator control.

### Provider inactivity deadlines

Common run envelope version 17 freezes `providerInactivityTimeoutMs` and
`providerInactivityFingerprint`. The fingerprint is SHA-256 of the canonical
JSON object containing that timeout. Root/project configuration accepts only
integers from 1 through 2147483647 milliseconds, defaults to 1800000, and resolves
project over root. No role, CLI, or MCP override exists. Versions 1–16 normalize
to that default and null recovery; leased migration journals it without loading
configuration or changing pipeline progress. Journal continuity protects both
immutable fields and rejects a fabricated legacy recovery allowance.

`src/runner/inactivity.js` owns one watchdog per adapter invocation inside the
operator-stop monitor. Its injected timer makes policy tests deterministic.
Only the closed validated `onProgress` vocabulary resets the timer. Paired
command events maintain the aggregate count; a positive count suspends the
deadline until all owned commands complete, then starts a full interval.
Keepalives, bytes, liveness, unrelated notifications, and public observation do
not count. Local tool lifecycle events are meaningful progress but do not
suspend the deadline. Settlement drains timer persistence before returning.

Before aborting an inactive provider, the run store durably journals the bounded
`inactivity/expired` activity and `inactivityRecovery`: exactly `role`,
`checkpoint`, `attempt` (1 or 2), `status` (`expired` or `reconstructing`),
`reconstructionRevision` (null before attempt 2), `expiryRevision`, `configurationFingerprint`,
and the observed `contentFingerprint`. The state store records expiry while ownership is still active without advancing
the pipeline or changing other run fields. The marker
is separate from availability episodes and contains no native payloads or tool
content. Failure to persist evidence retires owned work without authorizing a
retry. Process/resource retirement remains mandatory before reconciliation.

Each pipeline reconciles its own read-only or writable checkpoint and any
partial correction before reconstruction. Safe content invalidates stale gates;
the existing charged-correction marker prevents double counting. Reconstruction
uses the complete durable prompt for the same role and never reforks a source.
The transition to attempt 2 is durable before launch. The adapter's optional
awaited `onFreshSession` callback reserves this same allowance before native
fresh fallback; false forbids that fallback. An expired attempt 2 pauses as
resumable `backend_unavailable` rather than entering availability backoff. Owner
loss does not replenish the allowance. Explicit resume after that pause permits
one invocation with attempt 2 still consumed; separate classified availability
failures retain their existing backoff, not another inactivity allowance.
The reconstruction revision consumes that continuation durably: only an
availability failure reconciled at or after the last reservation may authorize
another launch. An older episode cannot authorize replay after owner loss.

Only a returned provider response plus matching repository reconciliation clears
the marker. Pipelines report failed reconciliation at turn settlement; safety
pauses retain the marker without substituting a recovery error for the original
repository failure. Safe content/counter changes and that reset share one durable
transition, before output validation. The adapter's awaited `onCommitExecution`
callback runs after validated readiness and before the constrained executor: it
drains the watchdog and reconciles the readiness response against the existing
baseline. The executor, trusted validation commands, and runner-owned handoff
are outside this watchdog. A readiness expiry may retry only after existing
validated `commitExecutor: "not_started"` evidence and Git verification retire
the consumed authorization. Possible effects, policy failures, usage limits,
authentication requirements, and operator stops retain their precedence.

Common-envelope version 20 adds nullable `expiryRevision`, journaled only by an
actual watchdog expiry. Generic reconstruction consumes `reconstructionRevision`
without proving timeout. Versions 17–19 normalize missing expiry proof to null;
leased migration preserves the consumed allowance without inventing timeout
history. Proven expiry is required for inactivity retry and timeout-specific
correction allowances. An interrupted consumed reconstruction without expiry
proof uses `ERR_PROVIDER_RECONSTRUCTION_EXHAUSTED` and explicit recovery.

CLI status and MCP `inactivityRecovery` expose only role, checkpoint, attempt,
status, and `expiryProven`. Unproven activity and CLI state say reconstruction
rather than inactivity. Bounded `expired`, `reconstructing`, and `recovered` activity uses
the existing journal/projection transport. Client disconnect or canceled waits
change observation only; they cannot cancel or reset the watchdog.

### Durable availability episodes

Common envelope version 16 adds the immutable normalized client attribution and
its matching fingerprint. Version 1 through version 15 runs normalize only to
the generic default; a leased runtime migration journals that value without
loading current configuration. Legacy state cannot claim a custom identity.

Common envelope version 15 adds immutable `availabilityPolicy` and nullable
`availabilityRetry`. Runtime compatibility includes this envelope version.
Legacy versions project the documented default policy and no pending episode;
the leased runtime migration journals those values without replacing saved
roles, checkpoints, modes, corrections, session lineage, or provider receipts.
Current configuration never replaces a frozen policy on resume. Legacy records
cannot claim a custom policy or pending episode.

The state service's `scheduleAvailabilityRetry` accepts an inspected revision,
active role, bounded logical checkpoint, finite provider-neutral reason, and
reconciled content fingerprint. It requires retired turn/process/resource
ownership and the existing exclusive mutation lease, then appends the complete
event before replacing state and returning. The episode stores a UUID, role,
checkpoint, reason, attempt, delay, scheduling time, retry deadline, content
fingerprint, and reconciled revision. The caller owns repository reconciliation;
a hash-shaped value alone does not prove Git safety.

Delays are `min(maxDelayMs, 5000 * 2^(attempt - 1))`: at the default ceiling,
5, 10, 20, 40, 80, 160, 320, 640, 1280, 1800 seconds, then 1800 repeatedly.
The attempt has no policy quota; its numeric representation saturates at the
largest safe integer without stopping capped retries. Journal validation rejects
policy drift, changed episode identity/role/checkpoint, skipped attempts,
inconsistent deadlines, and progression before the prior deadline. Deadlines
are calculated from the current scheduling time, so overdue recovery cannot
produce a catch-up schedule. Unrelated transitions and restart retain the episode;
clearing it is reserved for the successful-provider-turn coordinator path.

The runner injects one availability coordinator into all registered pipelines.
Logical checkpoints bind the original access mode as well as role and phase;
read-only dispute recovery cannot regain write access through an availability
episode when its correction budget is exhausted.
Each pipeline first reconciles repository controls, safe partial content, and
turn/process retirement, then requests scheduling. Correction accounting and
pending correction diagnostics remain bound to the same logical turn; partial
writes invalidate dependent approvals without charging that correction twice.
After restart the pipeline reconstructs the same role/checkpoint from durable
state, preserving lineage without reforking the source. Deadline waits retain
the execution/worktree leases and are abortable by immediate or deferred stops.
An overdue deadline permits one attempt, never a catch-up burst.

Scheduling and retry start are journaled before waiting or dispatch and immediately
published to CLI/MCP activity with bounded role, checkpoint, normalized reason,
attempt, delay, and deadline. Status projects the same fields in `availabilityRetry`.
A successfully returned provider response clears the episode at repository
reconciliation, before deterministic output validation; rejected output can
therefore still mark provider progress. A normalized authentication-required
response instead retires the superseded episode before persisting its distinct
operator pause. Reconciled content and correction accounting are persisted
atomically with either transition. Check/fix mutation claims are compared against
the attempt's starting fingerprint, including any safe content retained from
earlier failed attempts. Other availability errors, tool activity, partial output,
session replacement, operator resume, and restart do not reset it. Persistence or
wait failures retain the checkpoint and propagate without inventing a terminal
pipeline failure.

Plan-execution state version 24 permits a bounded availability reason and
`commitExecutor: "not_started"` in a persisted pre-effect rejection. Version 23
migrates without inventing that proof. Version 25 makes the plan-execution
source-projection need explicit and defaults version-24 reports to false without
changing frozen authority, workflow evidence, correction accounting, or effects.
Consumed authorization remains verification-only until Git proves no commit and
unchanged state; only then can one atomic journal transition retire it and
schedule a fresh authorization.
Potentially executed commit/handoff effects never enter availability replay.
Polishing state version 16 preserves charged partial resolutions at their original
checkpoint. Both writable pipelines persist whether the current provider-recovery
continuation has charged a check/fix round; authentication recovery also retains
the charge for a partially completed finding-resolution round. An earlier
pending correction does not exempt a new round, and availability reset or
authentication pause cannot erase an unfinished charge.
Legacy pipeline migration initializes that marker to false. Both retain unresolved blockers and historical
negative validation evidence during recovery; no stale passing evidence or
approval can authorize the changed content.
Polishing state version 17 makes its independently owned source-projection need
explicit and defaults version-16 reports to false without changing frozen
authority, workflow position, review or correction evidence, or handoff state.
Null provisional reports retain the existing read-only discovery barrier.
Foreground CLI owner loss requires resume; detached MCP ownership outlives a
client timeout or disconnect.

### Durable authentication-required pauses

The runner injects one provider-neutral authentication policy into all registered
pipelines. It accepts only a strict normalized adapter failure carrying
`disposition: "authentication_required"`; raw messages, diagnostic classes,
HTTP evidence, and provider-specific codes cannot activate the policy.
Authentication is an operator action, not availability: the runner schedules
no retry or backoff and persists no availability episode. When it supersedes an
active availability retry, that episode is retired before the authentication
pause is persisted.

After provider execution retires, each pipeline applies its ordinary repository
guard. Writable execution and polishing turns reconcile safe partial content,
invalidate stale fingerprint-bound approvals, and preserve correction charging.
One durable transition retires the active turn, saves any source-fork recovery
marker, and enters `WAITING_FOR_USER`; interrupted publication cannot leave a
finished turn without its authentication checkpoint. The pause contains exactly
`authentication_required`, `ERR_AUTHENTICATION_REQUIRED`, and the current
logical resume state. Role configuration, source and child session lineage,
content fingerprints, findings, and counters stay in their existing durable
fields. After the operator reauthenticates, a null resume reconstructs that
same checkpoint without requiring the failed native session. A partially
completed finding-resolution turn retains its writable access even when its
already charged round reached the fix budget; completing that round does not
consume another round or authorize a new one.

Authentication during an initial source-session fork additionally preserves a
nullable provider-neutral recovery marker containing only the logical role and
context key. Proof that the rejected request had no effect permits the source
fork to be retried. Possible-effect evidence instead persists the marker and
reconstructs the same role in a fresh session, never reforking a source whose
native child may already exist. The marker survives repeated authentication or
interruption and clears only after a child session is durably recorded.
If interruption precedes pause publication, authentication during fresh
recovery retains the earlier unrecorded fork's possible effect even when the
new request proves no effect.

Local-commit readiness remains effect-safe. The disposition qualifies only
when the normalized record also proves `commitExecutor: "not_started"`.
Plan execution persists that bounded proof with the consumed authorization,
performs the existing Git verification-only path, and retires the authorization
only after Git proves no commit. It then pauses at `COMMIT`; uncertain or
started effects never become authentication retries. Polishing handoff remains
runner-owned and uses its existing staged-effect verification path.

Plan-authoring state version 6, plan-execution version 26, and polishing
version 18 admit these new pause, proof, and source-fork recovery variants.
Their immediately prior migrations initialize the nullable recovery marker to
`null` while preserving workflow position, existing session lineage, evidence,
and correction accounting. They do not reload configuration or infer a native
child. The version bump makes older readers reject rather than misread the new
durable checkpoint.

### State-owned operator stop protocol

The common envelope version 7 extends the nullable bounded `stopRequest` with
requested and effective timing, immutable target evidence, and settlement
accounting. The state service's `requestOperatorStop` accepts a run ID,
`pause_requested` or `cancel_requested`, an inspected `expectedRevision`, an
`idempotencyKey`, and optional `timing` (`immediate` by default).
It persists a version-3 action intent, appends the complete acceptance event,
and publishes an acceptance receipt before returning. This capability does not
signal processes, reconcile Git, or expose CLI/MCP commands; those operations
belong to runner and transport integration.

Short, recoverable `.mutation-<uuid>` claims serialize requests with
execution-owned journal writes and lease release. Each contender durably
publishes a choosing claim before selecting its ordered ticket; it waits for
choosing peers and lower ticket/identity pairs. Dead claims have unique paths,
so recovery cannot unlink a newer owner at a reused lock pathname. Claims and
contention are observed at most 500 times with 10 milliseconds between blocked
observations, about five seconds plus filesystem work. Exhaustion returns the
retryable mutation-busy outcome, and unverifiable owners continue to exclude
mutation. Action-lease reclamation uses the same boundary, which does not grant
another execution lease. Worktree owners without a pipeline run, such as
guidance publishers, use claims in the worktree lease directory. Status and
activity reads remain lock-free.
The acceptance record contains the hashed request identity, request kind,
inspected and accepted revisions, request time, nullable reconciled revision,
and a suspended checkpoint. That checkpoint records the workflow state, active
turn, null resume action, and the exact earlier journal revision. Reading that
revision recovers the complete frozen state, including existing pause blockers
and pending input, without duplicating a potentially large pipeline payload.

Only nonterminal runs accept fresh requests. A cancellation may supersede a
pending pause using either its original inspected revision or the current
revision; it retains the original checkpoint. Other stale requests fail, as do
new competing requests that cannot supersede the pending stop. Exact retries
return their original receipt. If receipt publication was interrupted, the
acceptance event reconstructs it even after cancellation superseded a pause or
the run terminated. Receipt replay neither advances the run nor executes work.
Version-1 and version-2 action records remain readable; incomplete actions
upgrade when written, and completed receipts replay without migration writes.

Execution propagates commit-authorization preparation and consumption publication
failures without overwriting the journal with a stale local checkpoint. Deferred
stop recovery preserves the durable authorization, never invokes a prepared
effect to obtain a commit, and only verifies a consumed effect. Fault-injection
coverage includes acceptance versus advancement/completion, lost receipts,
lease transfer, and verified settlement publication for both stop actions.

New stop argument identities include timing and canonicalize omitted and explicit
`immediate`. Legacy timing-less identities accept those same immediate arguments
and retain their original receipt shape; a timing change conflicts. Legacy stop
records normalize to immediate timing without read-side writes. New receipts
include requested/effective timing and bounded target evidence. Target evidence
permits a null baseline HEAD only with no preceding completed commits, preserving
an unborn logical step's boundary across child commits. CLI `--timing` and MCP's
optional `timing` field expose the same two values; omission stays immediate.
Transport validation never refreshes an inspected revision or changes
retry arguments. MCP keeps `pendingStop` for pending requests and adds the
state-owned bounded `projectOperatorStop` summary as `stop` for current and settled
requests. CLI status uses the same summary; public activity derives it from each
event's state, and waits reuse status. It excludes identities and private
checkpoints, exposing kind, accepted revision, requested/effective timing,
target step, state, and nullable settlement. `applicable` denotes immediate
requests or suspended/failed checkpoints awaiting reconciliation; other pending
requests remain `pending`, including interrupted owners awaiting recovery.
`settled` denotes completed accounting, with `quiescent` or a verified commit
SHA when available. These projections do not decide ownership or enforcement.

Plan execution's descriptor classifies one stop checkpoint as `pre-work` only
when the applicable request is immediate, its saved journal revision matches
the unchanged current pipeline state, and both snapshots remain at initial
`CLARIFY` with incomplete preflight, empty input hashes, no repository baseline,
backend versions, clarification path, frozen artifact, pending edit, canonical
plan, selected step, pending commit, or completed commit, and no pause, active
turn, execution process, or execution resource. The runner holds the run lease and
uses the existing atomic stop settlement without acquiring a canonical lease
recorded for another run. Cancellation becomes terminal; pause preserves that
same resumable `CLARIFY` checkpoint. Any failed predicate retains the ordinary
worktree-lease requirement and full repository/effect reconciliation. Plan
execution state version 21 is an identity migration that rotates detached
runtime compatibility for this settlement-aware contract. Plan execution state
version 22 adds its frozen finalization-guidance decision. Terminal states and
consumed commits retain verification-only recovery. Other unfinished legacy
states establish the decision before more provider work and use the existing
read-only validation migration before writable work when their prior inventory
cannot prove the new contract.

The private `src/state/stop-policy.js` owns three distinct decisions: whether a
request awaits reconciliation, whether that request blocks execution, and
whether unresolved stop accounting or a recorded execution process retains
ownership. Immediate requests block execution. Deferred requests retain ownership
while allowing progress within their immutable target. The runner monitor keeps
watching for immediate cancellation supersession without aborting deferred work.
Envelope validation owns
shape; the stop service owns acceptance, supersession, and receipt accounting.

State accepts `after-current-commit` only with a trusted synchronous
`resolveStopBoundary` capability supplied to `createRunStore` by composition.
It resolves a frozen authoritative snapshot inside acceptance serialization.
The bounded `verified-commit-v1` evidence contains the positive step number,
completed-commit count, and baseline SHA; no provider data or free text is stored.
Ordinary writes cannot change that boundary; only leased atomic settlement can
record progress together with the stop outcome. Unsupported resolver results or
persisted capabilities fail closed, including during history reads. The root
pipeline registry supplies execution's boundary resolver to the runner
and MCP stores. Execution accepts a selected step, including suspended
checkpoints; clarification, bootstrap, absent steps, and the other pipelines
reject deferred requests. Direct state stores without that capability still
fail closed. Deferred CLI/MCP request inputs remain unavailable.

Cancellation supersession retains the original suspended checkpoint and cannot
delay an earlier immediate stop. Requested timing remains visible when effective
timing is immediate; a still-deferred cancellation retains the earlier target.
Settlement records either a verified commit SHA or a quiescent fallback, and
becomes immutable with the reconciliation revision. Workflow meaning and commit
verification remain the pipeline/runner's responsibility. Execution supplies the
verified SHA to both ordinary checkpoint settlement and verification-only recovery.
The state mutation records progress and the latest requested outcome together.
If the target pauses, fails, or loses its owner before verification, recovery
reconciles effects and applies the request at the quiescent checkpoint without
invoking another role. Underlying failures, blockers, and consumed authorization
evidence remain in the operator checkpoint. A final-commit pause suspends `DONE`;
resume reaches `DONE` without agent work. Final-commit cancellation retains all
completed commits in `CANCELED`.

The common advancement guard applies inside the mutation boundary to workflow
transitions, provider-turn records, session/artifact writes, and execution
registration. Pending stop enforcement takes precedence over process accounting,
then terminal cancellation blocks any further advancement. Retiring a recorded
process remains allowed while a stop is pending so reconciliation can finish.

Lease release, worktree reclamation, and durable `runIsLeased` exclusion consult
the separate ownership-retention policy. A reconciled cancellation remains
terminal without retaining ownership; a reconciled pause permits ordinary
resumption once other blockers are resolved. A pending stop prevents release
of held run/worktree ownership even after its process record has been retired.
A dead owner's existing worktree lease remains excluded from other runs while
the request is pending; only recovery of the same run can reclaim it.
Reclamation, including reclaim-marker recovery, rechecks the stop under the
original run's mutation boundary before replacing ownership. A crash leaving
only a reclaiming record retains that reservation until a replacement lease
exists, restricted to the same run while a stop is pending; failed
replacement publication restores the previous lease when possible.
The recorded lease owner and the run currently requesting reconciliation are
separate identities: diagnostics name both when they differ. Operators never
manually delete, rewrite, or bypass a lease record to make progress; recovery
uses the state-owned settlement and normal lease acquisition/reclamation rules.
`inspectRunLeaseOwner` exposes private identity and finite
live/dead/replaced/unverifiable classification for runner use; unverifiable
owners are not eligible signalling targets.

The runner separately tracks an in-process canonical-worktree lease handle,
durable same-run recovery responsibility, and the persisted execution-process
record. Stop reconciliation reuses a handle it already owns and releases it
only after durable settlement. If process retirement cannot be proved, the
same-run reservation remains for retry and the containment error escapes
unchanged; release recovery never reacquires that handle and cannot replace the
failure with a self-conflict. After owner loss, normal age, process-identity,
and competing-owner checks govern same-run stale reclamation before the same
retirement and settlement path runs.

Only the execution lease holder can call `completeOperatorStop`, after the
runner has reconciled the interrupted access contract and any begun effects.
That operation atomically records `WAITING_FOR_USER`/`operator_paused` or
`CANCELED`, clears active-turn activity, and marks reconciliation complete.
It does no repository work. The journal retains the suspended checkpoint and
prohibits cancellation downgrade or revival. Identical completion retries do
not add another transition. Lease release becomes possible only after this
durable accounting. Version-1 through version-3 run envelopes project a null
request without read-side writes; stop acceptance can upgrade only the common
envelope in its acceptance event while preserving pipeline state and history.

Verified commit settlement uses the leased `settleCheckpoint` state operation.
Its synchronous resolver reads the latest authoritative snapshot inside the
mutation boundary; the runner supplies workflow patches and the pipeline
validator checks the fully normalized result before journal publication. A
recorded execution process prevents settlement. A pending stop must settle to
its requested outcome, including a cancellation that superseded a pause during
verification. No provider, Git, or artifact effects run inside the resolver.

Execution's private `commit-checkpoint.js` constructs the verified SHA, clean
repository baseline, completed-commit list, next step or `DONE`, evidence resets,
and counters. Normal execution and verification-only stop recovery use that same
construction. The runner wraps the checkpoint in an operator pause or cancellation
when applicable and retains protected-configuration blockers beneath the stop.
Successful settlement clears the active commit turn and consumed authorization
in the same event as progress. Publication errors escape without writing failure
state from an older local snapshot; journal recovery preserves an already
published checkpoint without replaying the commit. Deferred requests use the
same settlement path and retain explicit commit or quiescent accounting.

### Common envelope and pipeline migrations

Common envelope version 5 adds nullable `executionProcess` ownership. Version
11 adds the supervisor's bounded boot/start launch cutoff and changes the
runtime compatibility token. Version 12 adds a nullable, ordered launch-time
ancestry baseline bounded to 4,096 entries, each containing the boot ID, PID,
and start tick observed immediately before supervisor launch. Version 14 adds
the nullable SHA-256 identity of the supervisor's exact Linux control-group
membership. Versions 5 through 10 derive the cutoff from a valid recorded
supervisor identity during normalization. Versions 5 through 11 normalize the
baseline to null; versions 5 through 13 normalize the control-group identity to
null. Neither migration rescans the host or synthesizes recovery authority.
Historical ancestry and control-group fields remain strictly validated, including
ordering, size, boot identity and digest shape, but neither supplies recovery
authority. New launches retain the same persisted shape with null ancestry and
control-group fields; no global pre-launch process census is required. Valid old
records with or without those optional proofs use the same ownership policy.
Before a provider or trusted command can execute, a private supervisor waits on
a separate inherited Node IPC channel while the runner journals its host PID,
hostname, boot/start identity, matching launch cutoff and PID namespace identity.
The shared agents boundary owns the
closed `ordinary` and `native-sandbox-provider` supervision modes. Ordinary
processes launch this supervisor as PID 1 in a private Linux namespace using
system-protected bubblewrap. Provider launches use that mode only when a cached,
namespace-local probe proves the complete outer-plus-inner user, PID, mount,
device, and network namespace shape. When nesting is unavailable on the initial
host PID namespace, only a declared provider may use a distinct owned session
before its mandatory native sandbox starts. When repository validation is
already inside the runner-trusted private PID namespace and that policy denies
another namespace, the existing owned-session mode remains available without
widening the enclosing sandbox. The private launcher preserves inherited filesystem/network
restrictions while replacing `/dev` with bubblewrap's minimal synthetic device
filesystem. Enclosing-session reuse retains the enclosing namespace's mounts
and restrictions. Provider and trusted-executor sandboxes still enforce their
narrower access contracts. The launcher's private status channel supplies the
host PID, verified against its parent and namespace before registration. No
provider work starts without that proof.

Launcher verification resolves the fixed system executable to a regular,
single-linked canonical file and checks that file plus every relevant ancestor
against the effective Linux mount table. A read-only mount is a protected
substitution anchor even when a namespace-root permission probe would otherwise
report writable. Paths without that anchor must deny runner-identity writes
through the root. Missing mount evidence, links, or a writable substitution
path fails closed.

Disconnecting IPC on runner loss starts bounded cleanup; bubblewrap also binds
the namespace lifetime to the runner. Exiting namespace PID 1 makes the kernel
retire all descendants, including detached sessions, double forks, and nested
namespaces. Normal completion reports surviving descendants before retiring
them, so trusted checks cannot pass with leaked work. Recovery inspects only the
recorded owner and waits for namespace-init death before clearing ownership;
the outer launcher's exit alone is insufficient. Live shutdown uses the original
child handle and control channel. The session token is derived from the already
persisted PID, boot, and process-start proof, so recovery can reject clearing a
dead session supervisor while matching descendants remain without signalling a
numeric host PID. Unverifiable ownership retains exclusion.
Identity-free records remain conservative until a verified reboot. Unavailable
ordinary namespace support fails before execution. Ordinary processes never
receive the initial-host session fallback.

Shared-host supervision and replacement-owner recovery use the same positive
association scanner. Owned-session membership, a matching per-launch inherited
token, or observed owned ancestry associates a process. Available parent links
are followed through inaccessible environments; a historical baseline never
short-circuits the search. Every snapshot descendant is inspected independently.
An unassociated process does not block progress or receive signals because its
metadata is unreadable, its session began later, or its cgroup is shared. There
is no unrelated-process custody, exited-candidate or control-group exclusion
proof. Shared-host discovery cannot prove absence against arbitrary same-user
processes hiding all ancestry and token evidence; private PID containment
remains the stronger kernel-enforced boundary.

Positive association is retained across retries and live scans until a fresh
stat proves the PID absent. Loss of a token, session change or reparenting cannot
discard that association. An associated identity that is replaced, unreadable,
malformed or unstable remains unverifiable rather than authorizing a signal or
an empty scan. Previously observed members are rechecked even when omitted from
a later directory listing. Session termination and containment failure freeze
supervisor discovery and pass its retained associations to parent-side cleanup.
Parent-side absence can clear registration only after that handoff is received;
a watchdog killing the supervisor before transfer retains the ownership blocker.
If IPC disconnects after handoff, the supervisor resumes discovery using its
retained associations and signals verified owned members. Any pending termination
check is upgraded to verified absence at its original deadline; surviving or
uncertain descendants keep the supervisor live as an ownership blocker.
Recovery remains inspection-only for persisted host PIDs. Recorded supervisor
identity and namespace validation, live-owner exclusion and journaled retirement
remain mandatory. Recovery rejects a current-boot
namespace mismatch; a previous boot independently proves the old work absent.
Parent loss before payload release retires the inert supervisor directly because
no provider descendants can yet exist.

Live and recovery scans share a 65,536-operation and 250-millisecond inspection
budget covering reads, snapshot entries, retained associations and ancestry
traversal. A final read exceeding the time budget fails closed. These limits do
not reset per PID or during churn, and exhaustion never proves process absence.

Runner construction supplies the same session inspector to ordinary recovery
and operator-stop reconciliation. Production uses the shared strict inspector;
synthetic-process orchestration tests inject their process-table view instead of
sampling unrelated host workers. Identity rechecks, namespace checks, and lease
ownership remain in the real retirement path.

Both scanners allow at most three attempts per snapshot entry. Transient
`ENOENT`/`ESRCH` or parent/session change restarts that entry's classification.
Unassociated churn supplies no ownership authority. Once ownership is observed,
identity replacement or exhausted retries retains the process record; only an
observed absent PID can retire that association. This retry policy does not
extend the completion grace below.

Completion-time descendant inspection retries transiently incomplete evidence
against one non-resetting one-second descendant-grace deadline. Complete
evidence resumes the ordinary success or bounded TERM/KILL path; uncertainty at
the deadline retains the existing fail-closed error. While the current owner
still holds the private child handle and control channel, it makes one bounded
teardown attempt through that boundary and rechecks the owned session. An empty
retained supervisor is retired and its durable process record is cleared before
the original containment error is returned. If owned descendants survive or
inspection remains incomplete, the process record and exclusion remain; the
parent never signals a host PID from persisted identity alone.

The runner service accepts revision-bound `requestOperatorStop` requests and
monitors durable revisions while executing. An accepted request aborts only
the owned provider or trusted execution and publishes stopping activity.
Provider recovery attempts and the constrained commit executor check the same
abort signal before starting. The run/worktree leases remain held through
process shutdown, read-only reconciliation, and the final stop event. The monitor
serializes process registration/retirement and stop-activity writes under that
lease, so abort-triggered cleanup cannot race publication of the stopping event.
Persisted
process ownership also prevents a different run from reclaiming the worktree
after owner loss, and prevents checkpoint advancement before process cleanup.
The only live-process registration is the active turn role acknowledging its new
child session; it changes lineage alone, and other roles, an absent turn,
preparation custody, pending stops and cancellation remain blocked.
`RunStore.recordSessionNaming` applies the same role rule to journal one finite
naming status for that recorded child under the lease, changing only the
revision and its bounded activity; generic transitions, including activity-only
ones, still reject live custody.
CLI/MCP command registration remains transport-owned.

After owner loss, the replacement execution lease inspects the recorded
PID/boot/start and namespace evidence. A PID that vanishes between liveness and
identity reads is checked again and classified dead only when that second read
proves absence. Same-boot PID replacement, a
live or unverifiable owner, an initial-host namespace hidden from the recovery
process, missing required owner identity, incomplete bounded inspection, or
surviving positively associated descendants all retain the record. A previous
boot or a dead same-namespace session with a complete empty descendant scan
permits journaled clearing under the replacement lease. Current-boot namespace
mismatch remains unverifiable even when the recorded owner PID is dead.
Crashes before clearing repeat retirement proof; crashes after clearing repeat
resource and checkpoint settlement without signalling the former PID.

Each pipeline has a reconciliation-only entry path with provider invocation,
trusted commands, and artifact writes disabled. It rechecks frozen inputs and
the interrupted access contract, preserves safe partial content, rejects index
or Git-control drift, and retains safety blockers. Content-changing partial
work invalidates dependent gates and charges correction work once; the exact
suspended journal checkpoint remains inspectable. Consumed commits are verified
without reinvoking their executor. Handoff reconciliation only inspects whether
the existing index is complete or untouched; it never stages. Verified effects
and step advancement are included atomically in the final stop event.
When the runner proves that an operator stop prevented commit invocation,
verification of unchanged Git state retires the unused authorization. Resume
can obtain a new authorization; uncertain or begun effects remain verification-only.
Provider error redaction retains that runner-owned pre-effect stop proof while
discarding native error wrappers; unrelated rejections remain blockers.

Reconciliation produces `WAITING_FOR_USER` with `operator_paused` and an
explicit null resume action, or terminal `CANCELED`. A bounded private
`operatorResume` record retains the reconciled workflow position, active-turn
reconstruction marker, and any preceding pause. Null resume restores an existing
pause without consuming its editor authorization or bypassing its blockers.
Otherwise it reconstructs the preserved logical role from frozen configuration
and session lineage only after reacquiring any required worktree lease.
Invalidated content returns through the pipeline's
candidate gate before further finalization. Cancellation cannot resume.
Cancellation superseding a pause during reconciliation changes only the final
outcome; verification never replays an effect or counts its progress twice.
Authorized clarification edits remain pending; stop reconciliation checks Git
safety without consuming them or classifying them as frozen-input drift. Input
drift outside that window cannot skip repository reconciliation.

`state.json` contains the common versioned envelope: monotonic revision,
pipeline ID and state version, an explicit runtime-compatibility tuple,
canonical paths, resolved roles, counters, hashes, pause state, session
lineage, nullable bounded active provider role/phase, timestamps, and opaque
pipeline-owned state, including its resolved settings from the initial
revision. The compatibility generation is maintained independently from the
package version, which is not a persistence contract.
The root validates JSON shape, size, and the common terminal/stop lifecycle;
pipeline-specific roles and outcomes remain opaque to the state capability.
Session lineage records an optional source-session reference, its resolved
trusted profile when known, and every direct child role/session ID with its
accepted-input and pipeline-checkpoint context key. Legacy role records missing
`profile` or `contextSize`, and missing or nullable `model`, normalize to
`current` in memory without rewriting state or event history. Envelope versions
1–7 also normalize absent active-role `effort` to `current`; version 8 requires
a portable effort value on every saved role. The leased runtime migration
persists those defaults without provider activity or configuration reload,
preserving prior journal records, progress, leases, and session evidence.
Changing runner configuration never re-resolves saved effort; changing protected
project configuration retains the safety pause without changing saved roles.
Native session resume remains an optimization rather than a correctness dependency.

Lock-free readers reject unsupported envelope, runtime, or pipeline versions
with an actionable version-skew error and never rewrite durable state. A
supported legacy envelope may be projected through the pipeline's explicit,
ordered migrations for status. Before workflow execution, the runner evaluates
the complete migration chain, validates the current pipeline shape, and appends
one complete migration event while holding the per-run execution lease. The
event upgrades the envelope and pipeline state atomically without rewriting
earlier history. Missing, failing, or forward-version migrations fail closed.

Plan execution persists each prepared or consumed one-shot commit authorization
and every verified commit SHA. After an ambiguous commit turn, resume verifies
the recorded authorization against Git state and never replays the effect.
An adapter may record `commitExecutor: "not_started"` only at the `commit`
checkpoint, with `none` or `possible` effect evidence, when it proves that its
isolated commit executor was never invoked. The boundary derives
`effectStarted: false` from that validated record. The pipeline durably records
that bounded proof on the consumed authorization before Git verification. After
Git independently confirms that no commit was created, the pipeline retires the
authorization before a later resume can issue a fresh ID. An absent marker or
executor failure keeps the consumed authorization on the verification-only
path, while interrupted verification retains any recorded proof for resume.
Polishing has no commit authorization and preserves the initial `HEAD`, refs,
remotes, and Git identity through completion.

Plan authoring state version 2 adds the resolved mode, the fingerprint accepted
by lazy clean confirmation, and the one-time lazy source-fork marker. Its
version-1 migration selects `independent` and initializes the new checkpoint
fields without moving the workflow, replaying a role turn, rewriting a draft or
artifact, or reviving a terminal run.

Plan authoring state version 3 adds a pipeline-owned lazy-checkpoint correction
ledger and nullable pending marker scoped to `CHECK_AND_FIX` or
`CLEAN_CONFIRM` and the exact draft fingerprint. Each record retains only
attempt `1` and bounded Planner field-and-constraint diagnostics. Its ordered
version-2 migration initializes both fields empty without moving active or
terminal workflow positions, reviving terminal work, replaying an accepted
checkpoint, consuming revision or correction budgets, or writing `plan.md`.

Plan execution state version 23 scopes validation to canonical plan steps. Its
private `validation-schedule.js` derives per-step inventories from immutable
Worker-first accepted role assignments, unioning applicability of identical
commands. Independent and combined retain both roles; lazy retains Worker only.
Each role must cover every step with its complete applicable procedure. Shared
infrastructure stays globally fingerprinted. The persisted schedule must match
its role evidence; only a confirmed current-step amendment may overlay the
active inventory. Verified advancement clears that amendment and prior gates
and selects the next schedule entry.

State version 27 stores that schedule as one ordered `commands` catalog and
per-step zero-based `commandIndexes`, expanding contiguous local check IDs only
for the selected step. This prevents long commands from multiplying by the
number of plan steps inside state and recovery prompts. The leased version-26
migration verifies the complete legacy schedule against its immutable role
assignments before replacing only its representation. It preserves amendments,
gate evidence, counters, and prepared or consumed commit effects.

Plan execution also owns private pure repository-discovery and bounded
applicability-unit contracts in `bootstrap-units.js` and
`bootstrap-unit-schemas.js`, with shared inventory fragments isolated in
`validation-schema-fragments.js` from complete response-schema exports. They
reuse its inventory validators and bind ordered complete coverage and shared
correction accounting to frozen inputs, role, catalog, and repository evidence.
They expose no runtime capability or public package API. Private
`bounded-bootstrap.js` activates discovery followed by focused applicability
turns for both bootstrap and validation migration; `bootstrap-progress.js`
validates the durable work and independent output-subdivision allowance.
Accepted discovery and each complete unit pass through the existing write-ahead
transition before advancement. Exhaustion can subdivide only the unfinished
read-only applicability unit, with its allowance consumed in the same durable
transition. Discovery and indivisible exhaustion pause; semantic corrections
remain a separate shared producing-role allowance. Catalog corrections and
unexpected drift invalidate dependent proof without replenishing allowances.

Execution state version 28 adds per-role nullable bound work and consumed split
counts. Its ordered version-27 migration preserves compatible complete
inventories, schedules, amendments, correction accounting, completed commits,
and historical confirmation proof without inventing batch evidence. Unfinished
roles use discovery; consumed effects settle first. Frozen inputs, accepted
catalogs, and pending units reconstruct requests without a native session or
routinely repeating the applicability matrix. Migration bootstrap turns retain
a distinct read-only identity across interruption and operator stops; repository
drift pauses and invalidates stale work without renewing allowances. Saved
version-27 availability and inactivity records keep their exact checkpoint for
the same role and suspended phase's read-only migration until successful
reconciliation, preserving consumed recovery accounting alongside the new turn
identity. The
[execution specification](../pipelines/plan-execution/docs/SPEC.md#durable-bounded-bootstrap)
owns exact bounds, state, acceptance, and recovery rules.

Finalization records its active step and exact ordered checks; terminal
confirmation hashes the complete canonical evidence tuple. Resume validates
both bindings before reuse. Confirmation also sees future requirements when
assessing shared infrastructure changes. Trusted capability inspection uses the
complete catalog and both roles' additive reports; finalization reserves and
executes only active selected commands. The frozen snapshot, vectors, identities,
and command/configuration fingerprints stay intact.

The explicit version-22 migration retains historical unscoped evidence under a
provisional legacy marker. It never infers applicability. Before unfinished
work advances, a read-only barrier invalidates active gates and requires scoped
discovery by every mode-required role. Accepted partial discovery survives
restart. Completed effects, pauses, configuration, and correction accounting
are preserved; terminal history remains readable. Consumed stagnation arbitration
and pending rework survive discovery; incompatible pending correction markers
retire without resetting their ledgers or fix accounting. Consumed commit
verification precedes discovery and capability preparation, with any subsequent
unfinished step subject to the same barrier. Older historical inventory contracts below
remain relevant to their migration chain.

Plan execution and polishing state version 2 persist the mode-specific
bootstrapped required-check inventory, the repository-relative files that own
validation infrastructure, and a runner-computed fingerprint of those files.
Plan execution and polishing each own a 256-item limit for each bootstrap role
inventory field and a separate 512-item limit for each derived, persisted,
finalization, and fingerprint-input field. A role exceeding its pipeline's limit
reports strict `CAPACITY_EXHAUSTED` with that `capacityField`
and per-role `capacityLimit`; required-check overflow takes priority. The
pipeline pauses without consuming a correction or accepting truncated evidence.
Validation infrastructure includes files owning commands, discovery, runners,
configuration, or mandatory finalization guidance, excluding ordinary source,
individual tests, fixtures, and generated output merely consumed by checks.
Classification uses responsibility rather than filename heuristics.
The Git validation-infrastructure fingerprint API accepts 512 paths; other Git
path lists retain their 256-path bounds. Execution state version 16 and polishing
state version 12 expand capacity with leased migrations preserving legacy 64/128
evidence, budgets, completed commits and handoffs, and one-shot effects. Those
capacity migrations left item and byte limits unchanged; current byte headroom
is specified above. Expanded schemas
retain strict Claude preflight and native sandbox restrictions. Only Claude's
independently proved command-boundary policy sets `allowAllUnixSockets: true`
so the authenticated launcher, rather than Claude's automatic command path,
orders the pinned seccomp helper before its single bubblewrap boundary. Neither
process encloses or weakens provider transport.
In independent mode, the runner establishes that inventory from accepted Worker
evidence followed by accepted Reviewer evidence; in lazy mode, accepted Worker
evidence is complete. It deduplicates exact commands and paths in stable
first-seen order and assigns contiguous `C1`-through-`Cn` IDs; independent-mode
reconciliation and arbitration resolve only summaries and material
disagreements and cannot add commands or paths. Validation-migration discovery
uses the same mode-specific derivation.
The version-1 migration preserves safe workspace content while invalidating
active aggregate finalization and review evidence. Paused legacy evidence is
explicitly provisional: before a retry, override, finalization, or review can
advance, fresh independent Worker and Reviewer checkpoints re-establish the
inventory and the runner fingerprints it again. A consumed plan-execution
commit authorization remains on the verification path until Git resolves its
effect; migration never converts it into a replayable authorization. Immutable
terminal history is shape-upgraded without replaying an effect.

Plan execution state version 3 adds the nullable bounded pre-effect rejection
record to each pending commit. Its version-2 migration sets that record to
`null`; it never infers proof for a legacy consumed authorization.

Plan execution state version 4 adds a bounded bootstrap-correction ledger. Its
version-3 migration initializes an empty ledger without changing accepted
bootstrap context, validation evidence, workspace content, commit authority, or
workflow position. Each producing role, phase, and contract may consume at most
one read-only correction attempt. The durable entry contains only attempt `1`
and the existing bounded role, phase, contract, field, and constraint
diagnostic; rejected values and provider output are never persisted. A bounded
pending copy distinguishes a correction that still must run from consumed
history and is cleared as soon as a valid replacement is accepted. Each adapter
maps its native structured-output failure to the shared bounded
`structured-output` failure class. Pipelines consume only that backend-neutral
class, and plan execution turns it into the bounded semantic diagnostic only
after read-only mutation checks complete.

Plan execution state version 5 adds the resolved trusted-validation snapshot
and executor provenance to every accepted per-check result. Its version-4
migration selects empty legacy trust and invalidates active finalization and
review gates through the existing independent validation-migration checkpoint.
Immutable terminal evidence is shape-upgraded, and a consumed one-shot commit
authorization remains on its verification-only path; migration never makes it
replayable.

Plan execution state version 6 makes validation inventories staging-independent
and assigns the Git index exclusively to `COMMIT`. Its version-5 migration
shape-upgrades clarification, preflight, and immutable terminal states without
rediscovery; clears partial bootstrap evidence at an unfinished bootstrap; and
routes every other prepared nonterminal run through fresh independent summaries,
resolved context, and validation before advancement. A consumed commit
authorization and its gate evidence stay on the verification-only path. Git
verification runs before reconciliation, migration discovery, or another role
turn, and any still-pending migration resumes only after that effect is resolved.

Plan execution state version 7 adds one finalization-correction record and a
matching pending marker scoped to the current commit step. Its version-6
migration initializes both to `null` without changing workflow position or
evidence. The first invalid Worker finalization result records only attempt `1`,
the step, bounded guidance and content-fingerprint scope, and the role, phase,
contract, field, and constraint diagnostic. The runner then reconstructs the
complete finalization request from durable state and uses the same schema for
one fresh-session, read-only correction turn. A valid replacement clears the
pending marker and rejoins the existing gate; a second invalid result fails
closed. Rejected values, commands, paths, provider text, and transcripts never
enter state or public activity. Interrupted correction recovery remains
read-only and does not require a native session.

Plan execution state version 8 replaces that single record with a two-entry
finalization-correction ledger and one pending attempt. Its version-7 migration
preserves a consumed or pending attempt as the first one-entry diagnostic batch
without changing workflow position, evidence, or correction scope.
Deterministic finalization validation batches independently detectable
violations where practical and always includes every staging-dependent required
command. The first batch may authorize attempt `1`; one wholly new batch may
authorize attempt `2`. Any repeated diagnostic, mixed repeated/new batch, or
invalid result after attempt `2` fails closed. Guidance identifies how to
reconstruct a pending request and never creates another budget. The ledger is
scoped to the current step and request content fingerprint and is cleared when
that content scope changes. Rejected commands, paths, values, provider text,
and transcripts remain outside state and public activity, while interruption
preserves the pending attempt without replaying or recounting it.

Plan execution state version 9 makes user finding overrides unique by exact
finding ID and reviewed content fingerprint and requires every finalization
validation-infrastructure candidate to pass the same existing canonical-file
inspection as bootstrap evidence before fingerprinting or review. Its version-8
migration deduplicates legacy override audit entries, preserves completed
commits, safe current-step content, counters, Git controls, and one-shot commit
effect safety, and marks active validation evidence provisional. Before
advancement, the existing validation-migration checkpoint independently
rediscovers the complete stable inventory and invalidates provisional
finalization and review evidence. Immutable terminal history is shape-upgraded
without replaying work.

Plan execution state version 10 replaces each consumed or pending bootstrap
correction's single field diagnostic with one bounded, deduplicated diagnostic
batch. Its version-9 migration losslessly wraps every existing diagnostic in a
one-entry batch without changing workflow position, accepted context, safe
content, gates, counters, or commit authority. Deterministic bootstrap and
validation-migration validation collects all independently detectable
violations from one candidate where practical, including every
staging-dependent required command and every lexically valid
validation-infrastructure path that canonical-file inspection rejects. The
producing role still receives exactly one correction attempt for its phase and
contract; a pending batch survives interruption and is cleared only after a
valid complete replacement is accepted. Repeated or still-invalid output fails
closed. Durable state and public activity contain only bounded diagnostic
identities, never rejected values, commands, paths, provider output, or
transcripts.

Plan execution state version 11 adds one final-Reviewer correction record and
a pending marker scoped to the current step, finalized content fingerprint,
and validation-infrastructure fingerprint. Its version-10 migration initializes
both to `null` without moving the workflow, altering accepted finalization or
review evidence, reviving terminal runs, or inferring rejected output that was
never retained. The first provider structured-output, normalization, or
validation-change consistency failure records attempt `1` and only bounded
Reviewer/review field-and-constraint diagnostics, then reconstructs the full
unchanged review request for a fresh-session, read-only correction with the
same schema. Interruption and backend unavailability preserve that pending
attempt without replay or recounting. A still-invalid replacement pauses at
the deliberately retryable `review_output_invalid` REVIEW checkpoint; an
explicit retry reruns the pending correction without approving content or
bypassing finalization, findings, fingerprints, Git guards, or commit
authorization. Rejected values, findings, commands, paths, provider output,
prompts, and transcripts never enter durable state or public activity.

Plan execution state version 12 adds the resolved mode, the fingerprint
accepted by lazy clean confirmation, and the one-time lazy source-fork marker.
Its version-11 migration selects `independent` without moving active or terminal
workflow positions, changing completed commits, or replaying a pending or
consumed one-shot commit effect.

Plan execution state version 13 adds a pipeline-owned lazy-checkpoint
correction ledger and pending marker. Each record is scoped to the current
step, `CHECK_AND_FIX` or `CLEAN_CONFIRM` phase, finalized content fingerprint,
and validation-infrastructure fingerprint and retains only attempt `1`, whether
actual fix work was already charged, and bounded Worker field-and-constraint
diagnostics. The version-12 migration
initializes both fields empty without moving active or terminal workflow
positions, changing accepted gates or completed commits, reviving terminal
runs, or replaying agent or commit effects.

Plan execution state version 14 separates semantic candidate convergence from
the terminal gate. Independent `REVIEW`, or lazy `CHECK_AND_FIX` plus candidate
`CLEAN_CONFIRM`, now precedes `FINALIZE`; passing finalization enters the new
read-only `CONFIRM` checkpoint before `COMMIT`. Candidate and terminal results,
fingerprints, correction diagnostics, and public activity are distinct. The
version-13 migration preserves terminal runs and consumed commit authorization
on verification-only paths and retains an unfinished `IMPLEMENT` checkpoint.
Evidence at every later active checkpoint that cannot prove the new ordering is
invalidated and routed to safe mode-specific candidate convergence. Retained
legacy terminal-Reviewer correction diagnostics are translated into the new
terminal-confirmation namespace on immutable paths.

Plan execution state version 15 adds bounded semantic finalization recovery.
Terminal roles share rejection routing: after the exact whole-result override
gate, `REJECTED` invalidates finalization immediately. The structured
`finalizationFindingIds` subset separates evidence-only findings from content
repairs. Pure rejection preserves candidate approval and re-enters `FINALIZE`
without code-fix accounting; mixed rejection resolves content first and still
requires replacement finalization. The complete deterministic gate preserves
established check IDs/commands and infrastructure entries, and fresh confirmation
binds the resulting fingerprint. Ordinary non-rejection reuse is unchanged.
Evidence rejection remains valid when inventories are unchanged; equality of
the inventory cannot substitute for sufficient check evidence.

The version-14 migration initializes metadata without interpreting missing
provider output or replaying workflow/effect history. Two semantic retries per
step are reserved durably before invocation. Pending attempts survive
interruption and unavailable providers without recounting; fingerprint drift
clears feedback without restoring allowance. Exhaustion exposes
`finalization_evidence_rejected` at `FINALIZE` with one explicit additional
attempt per null retry. Independent overrides use the saved terminal content
fingerprint; closing recovery feedback still requires replacement finalization
and fresh confirmation. Only bounded validated findings and control metadata
are retained. Each pipeline owns its recovery policy independently; polishing
adopts the same contract with a per-run allowance in state version 11.

Polishing state version 3 adopts the same resolved trusted-validation snapshot,
per-check executor provenance, and fingerprint-bound evidence tuple. Its
version-2 migration selects empty legacy trust, preserves safe workspace
content, and invalidates active finalization and review evidence through the
existing independent validation-migration checkpoint before advancement.
Retained `BLOCKED` and `NOT_RUN` entries in paused or immutable failed evidence
become `FAIL` without losing their bounded diagnostics. Immutable terminal
evidence is shape-upgraded without replaying work.

Polishing state version 4 adds its bounded bootstrap-correction ledger and
pending one-shot diagnostic. Its version-3 migration initializes both without
changing accepted bootstrap context, validation evidence, workspace content,
or workflow position. Each producing role, bootstrap or validation-migration
phase, and contract may consume one read-only correction;
only attempt `1` and the bounded role, phase, contract, field, and constraint
are durable. A valid replacement clears the pending copy, an interrupted turn
reconstructs it from state, and a second invalid result fails closed without
retaining rejected values or provider output. Validation migration also
persists its accepted bounded disagreement before arbitration, resumes that
checkpoint directly, and clears it when the migration completes.

Polishing state version 5 adds the durable runner-owned `HANDOFF` boundary.
Its version-4 migration preserves immutable terminal history and untouched
preflight state, clears partial bootstrap evidence, and routes applicable
prepared nonterminal runs through fresh independent staging-free validation
before they can advance. Legacy paused evidence remains provisional until
resume invalidates it through that checkpoint.

Polishing state version 6 makes bootstrap, validation-migration, and
finalization inventories staging-independent. Its version-5 migration preserves
immutable terminal history, frozen inputs, safe content, counters, Git controls,
and trusted-validation state; clears incompatible partial bootstrap evidence;
invalidates stale active finalization and review gates; and routes prepared
nonterminal work through fresh independent inventory discovery. A legacy
`HANDOFF` is reconciled first: a complete verified effect becomes immutable
completion, an untouched pre-effect state enters discovery without staging, and
an incomplete or contaminated index fails closed.

Polishing state version 7 adds one finalization-correction record and a
matching pending marker scoped to the current content fingerprint. Its
version-6 migration initializes both to `null` without changing workflow
position or evidence. The first invalid Worker finalization result records only
attempt `1`, bounded resolved-or-fallback guidance and content-fingerprint
scope, and the role, phase, contract, field, and constraint diagnostic. The
runner reconstructs the complete finalization request from durable state and
uses the same schema for one fresh-session, read-only correction turn. A valid
replacement clears the pending marker and rejoins the existing gate; a second
invalid result for the same content fails closed. Content changes clear stale
correction scope. Rejected values, commands, paths, provider text, and
transcripts never enter state or public activity. Interrupted correction
recovery remains read-only and does not require a native session. `HANDOFF`
remains the sole Git-index owner for both Codex and Claude turns.

Polishing state version 8 adds the resolved mode, the fingerprint accepted by
lazy clean confirmation, and the one-time lazy source-fork marker. Its
version-7 migration selects `independent` without moving active or terminal
workflow positions, changing safe workspace content, or replaying a pending or
completed `HANDOFF` effect.

Polishing state version 9 adds a pipeline-owned lazy-checkpoint correction
ledger and pending marker scoped to the checkpoint phase, finalized content
fingerprint, and validation-infrastructure fingerprint. Its version-8
migration initializes both fields empty without moving active or terminal
workflow positions, changing safe workspace content, or replaying a pending or
completed `HANDOFF` effect.

Polishing state version 10 separates semantic candidate convergence from the
terminal gate. Independent `REVIEW`, or lazy `CHECK_AND_FIX` plus candidate
`CLEAN_CONFIRM`, precedes `FINALIZE`; passing finalization enters the new
read-only `CONFIRM` checkpoint before `HANDOFF`. Candidate and terminal results,
fingerprints, and bounded correction diagnostics are distinct. The version-9
migration invalidates unprovable active gate evidence and routes it through safe
mode-specific candidate convergence, defers the same repair for paused runs,
and preserves `HANDOFF`, `DONE`, and `FAILED` without replaying staging.

Polishing state version 13 enables combined review with independent roles,
bootstrap, and isolated checkpoint sessions. Worker check/fix and separate
read-only clean confirmation precede independent candidate review of the same
fingerprint; independent terminal confirmation covers finalized content before
runner-only handoff. Durable `primaryFindings` keep self-findings separate from
independent findings. Content repairs clear both gates; unchanged resolutions
retain only current finalization. Only independent finding resolution permits
fresh arbitration; unresolved bootstrap and primary exhaustion pause. Version-12
migration adds an empty primary-findings record without changing saved mode,
correction budgets, or consumed handoff evidence.

Polishing state version 11 adds the same bounded semantic finalization recovery
as plan execution, with two automatic attempts per polishing run. Both terminal
roles share deterministic pure/mixed rejection routing within polishing. Exact
terminal-fingerprint overrides are checked first; otherwise rejected evidence is
invalidated immediately and replacement finalization plus fresh confirmation
must pass before runner-owned `HANDOFF`. Pending attempts survive interruption
and environment/provider blockage without recounting. Scope drift clears feedback
without restoring allowance; explicit retry after exhaustion grants one additional
attempt. The version-10 migration initializes metadata without moving checkpoints,
inferring old rejection output, or replaying pending or completed staging effects.
The existing polishing malformed-output correction budget and index restrictions
remain unchanged.

Common run-envelope version 3 adds `activeTurn`, either `null` or the current
bounded `{ role, phase }`. Version-1 and version-2 runs project it as `null`
without rewriting state or history; the next mutating continuation persists the
explicit ordered runtime migration under the execution lease.

## Agent Context Recovery

`runner/session-naming.js` derives bounded display context from the existing run
UUID, workspace basename, pipeline and active role at invocation. It overrides
any request-supplied context, preserves the full UUID and never changes client
attribution. The shared strict adapter request carries `sessionNaming`, awaited
`onSessionCreated` and optional `onSessionNaming` observers. Provider-native
naming effects remain adapter-owned and are not implemented by this context.

Codex's actual selection path acknowledges verified new start/fork children, then
calls `thread/name/set` before the first model turn. The full UUID prefix and a
128-code-point description are built from Runner context, never an inherited
title. Ordinary resume does not name; reconstruction names its newly acknowledged
child. The private App Server transport exposes whether it remains usable so an
RPC metadata rejection can continue once while transport/protocol loss emits a
bounded diagnosis and pauses without adapter reconstruction. This failure carries
no availability retry reason or unused source-fork proof, and commit readiness
still proves its executor has not started. Existing pipeline recovery owns resume.

Both adapters build the same bounded title through the private adapter contract.
Claude's native `--name` belongs to its original fresh/forked CLI launch, after
an exact installed-help flag check, and is omitted for ordinary continuation or
compaction. Unsupported naming before the first launch carries proof that
initialization did not start; later recovery retains any earlier effect
uncertainty. Native metadata rejection retains a positively correlated
stream initialization identity or validated child result before surfacing its
bounded diagnosis; it cannot trigger fallback launch, reconstruction or a Git
effect. The stream exposes only the verified identity, never a transcript or
title. This adds no persistent schema, migration, provider bound or session-store
inspection. Codex's acknowledgement-before-RPC ordering remains unchanged.

Every pipeline supplies the creation acknowledgement at its existing logical
session key, including audit cycles and commit readiness. It records the child
before a naming diagnosis or metadata failure reaches the workflow, then accepts
the same acknowledged response without recording it twice. Existing source-fork, continuation and reconstruction
selection remains authoritative. Old sessions are never enrolled by continuation.
Acknowledged children retain consumed source-fork authority across no-turn-effect
and ambiguous failures. The first continued request after authentication,
output exhaustion or a backend pause includes the complete recovery prompt because acknowledgement
does not prove that the child received its original request.
Fresh commit-readiness children remain recorded in a
separate, non-reusable context so they cannot replace a fully reconstructed Worker.
Naming diagnoses use existing immutable journaled activity, with only a closed
status and role; child records and envelope schemas remain unchanged. No metadata
receipt rewrites lineage or settles workflow, effects, retry or usage accounting.
See the [provider contract](product/PROVIDER_MODEL.md#sessions-and-context).

The strict provider-neutral turn contract also accepts an optional
`workspacePolicy` with `kind: "directory"`, canonical absolute `workspacePath`
and `stateRoot`, optional `taskPath`, and the workspace service's six path arrays:
`inputPaths`, `sourcePaths`, `outputPaths`, `configurationPaths`, `artifactPaths`
and `infrastructurePaths`. Omitted arrays are empty. The workspace must equal
`cwd`. Each array accepts at most 256 paths. Runner storage exclusions remove
duplicates and descendants already covered by a parent; directory requests allow
up to 1,539 exclusions for all six arrays plus workspace, task and state roots.
Every declared root remains protected. Unknown fields, relative paths and
directory `local-commit` requests are invalid. Execution-option validation
remains separate: `probe` additionally
accepts `access` and this policy, requiring explicit read-only or workspace-write
access for directory proofs. Unsupported adapters reject it before provider work.

Codex directory access requires stable CLI 0.164.0 or newer. Its access-specific
probe inspects bindings and snapshot safety without Git, an artificial repository,
or a local-commit executor probe. Frozen policy receipts bind the version,
access, declared paths and immutable input/control bindings; authorized output
and state creation do not change a receipt. `declaredWorkspace`
distinguishes this proof from legacy repository capabilities. Directory analysis
advertises read-only access; directory output advertises workspace-write access.
Neither advertises commit authority. Legacy requests and full capability probes
retain their existing behavior.

Each directory attempt installs an adapter-owned named permission profile at
App Server launch. Directory initialization negotiates `experimentalApi`, and
thread start/fork/resume and every turn explicitly select that profile through
the public `permissions` field. Selection must return its exact active profile,
without inheritance, and the requested working directory before a turn starts.
The profile retains Codex's host read baseline, reserves workspace roots
read-only, grants writes only to
declared outputs and the existing owner-only private command storage, and pins
inputs, sources, configuration, task, artifacts, infrastructure and discovered
controls read-only. Network remains denied. Effective configuration must match
before thread selection. Native permission paths containing glob metacharacters
(`*`, `?`, `[`, `]`, `{`, `}` or `\`) are rejected before capability approval or
launch, preserving literal declarations instead of granting pattern-based access.
Directory requests omit legacy thread/turn sandbox
overrides so those cannot widen the profile; reconstruction rebinds it to the
new private allocation. The same output-only snapshot guard runs before each
attempt and after process retirement and storage cleanup, including failures,
before retry or acceptance. Uncertain process retirement retains the original
failure and blocks reconstruction; successful post-retirement verification is
required before requesting a fresh session. Reported file edits
and move destinations must also lie inside declared outputs. These adapter permissions expose no directory
workflow, publication or Git effect; pipeline lifecycle integration is separate.

Claude directory access uses the existing stable CLI baseline and Linux isolation
requirements. Separate cached probes for each directory access mode use ordinary
directories, read-only controls and confined output roots; they never run Git,
initialize a repository or probe local-commit readiness. Repository proofs keep
their own policy selection. Immutable directory receipts bind the installed
version, isolation/tool policy, requested access and filesystem-owned declarations
and immutable bindings. Authorized output changes do not change those receipts.
Only the requested access is advertised, with no local-commit capability.
Restricted-host directory probes check write denial on the mounted reference file
and a separate host-root path; a reference's parent under private `/tmp` may be
writable namespace-local scratch.

Directory turns replace Git metadata preparation with workspace-service inspection
of all declared reads and discovered filesystem controls. Claude's mount
preparation stays read-only with no configured writable paths. Both authenticated
launchers keep the workspace read-only and bind only declared existing output
roots writable. Missing output roots fail closed rather than being materialized
or widening access to their parents; new descendants can be created inside an
existing output directory. Mount identities come from a fresh filesystem-owned
snapshot after storage allocation. Both launchers recheck canonical paths,
device/inode identity, ordinary file types and single-link files before admission.
Controls and external reads receive exact read-only mounts, including references
otherwise hidden by private temporary/runtime filesystems.
Incidental host write mounts are discarded. Provider-native Edit/Write are omitted
for directory requests: only sandboxed Bash can write, with the existing tool,
credential, network, socket, seccomp and no-fallback restrictions. Provider
authentication/connectivity and session storage remain separate.

Private turn storage excludes the declared state and protected trees in addition
to workspace/task exclusions. Missing exclusion suffixes resolve through their
nearest existing directory without creating declared paths. The workspace's
output-only snapshot guard runs before each attempt and after process retirement
and storage cleanup, including
failed attempts before compaction or fresh reconstruction. Uncertain retirement
retains its ownership failure and cannot authorize replay. Continuation, forks
and reconstructed sessions reinstall the same policy without manufacturing Git
or commit authority. This adapter capability does not expose directory workflows.

Backend sessions are disposable execution context, not durable workflow state.
Adapter capability probes inspect the installed CLI and enforceable local
isolation only. Codex additionally validates a selected named profile once per
adapter with the model-free
`--profile <name> app-server --strict-config --print-startup-config` startup
path, which `app-server --help` must advertise. Its output is discarded; a
missing flag or non-zero exit fails before any App Server launch as
`ERR_UNSUPPORTED_CODEX_CAPABILITY` / `capability_native_profile`, without the
profile name or native text, and the profile is never ignored or substituted.
Probes do not claim that authentication or the provider is usable; that is
established by the first real turn under the effective profile.

Turn requests accept an optional synchronous `onProgress` observer. The shared
internal contract emits frozen `{ kind, activeCommands }` records only. Its
closed kinds are `semantic`, `local-command-started`,
`local-command-completed`, `local-tool-started`, and `local-tool-completed`.
The nonnegative command count covers overlapping commands independently of
other local tools. Provider-private identities correlate starts and completions;
duplicate starts/completions and unmatched completions cannot change the count.
Each attempt bounds its retained tool identities to 16,384 and retires remaining
activity only after process retirement. Progress carries no native identifiers,
payloads, commands, output, diagnostics, or timestamps. It is not public CLI/MCP
activity; the shared inactivity watchdog consumes it without changing availability
backoff or emitting native events publicly.
Observer failures are redacted; retirement reporting cannot replace an already
established provider failure.

Turn requests also accept an optional synchronous `onObservation` consumer.
`src/agents/observations.js` owns the strict public
`normalizeProviderObservation` contract; native mapping stays in each provider.
Consumers receive frozen, payload-free records once an attempt is sealed, with
request-local `attempt` and `turn` ordinals (each bounded to three),
`kind: primary|recovery|compaction`, `outcome: completed|failed|incomplete`, and
`accounting: missing|incomplete|reported`. These are diagnostic observations,
not workflow state, progress, retry decisions, or proof of an effect. Without a
consumer, response shapes and execution selections are unchanged.

`last` and `cumulative` are separate nullable snapshots; `cumulativeScope` is
`thread` or `attempt`. Each snapshot contains nullable `inputTokens`,
`cachedInputTokens`, `cacheWriteInputTokens`, `outputTokens`,
`reasoningOutputTokens`, and `totalTokens`. `contextCapacity` is separately
nullable. All numeric evidence must be nonnegative safe integers. Unknown
values remain null, including unavailable totals; snapshots are never summed.
`inputIncludesCached` and nullable `outputIncludesReasoning` preserve provider
inclusion rules: cached input and reasoning are never added again to inclusive
input/output counters. `commandCompletions` and `compactions` count deduplicated
observed facts, each bounded to 16,384; `factsIncomplete` marks rejected excess
facts. Retirement-generated progress never increments observed completions.

Codex maps public `thread/tokenUsage/updated` notifications. `last` describes
the last model request and `total` is cumulative thread usage, including cached
input within input and reasoning within output. Private exact thread/turn IDs
route up to 1,024 pre-reply facts and matching late usage, including earlier
turns in the same attempt, until sealing after transport shutdown. Compaction
binds to the adapter-validated completion identity, discards mismatching
provisional facts, and retains failed or interrupted compaction usage as
incomplete accounting without confirming successful compaction. Successful
confirmation and its native item count as one fact. Duplicate terminal frames
cannot revise the first correlated outcome.
Thread-cumulative snapshots must respect turn order; matching late earlier-turn
usage remains acceptable within the surrounding accepted totals. Last-request
counters cannot exceed their corresponding cumulative counters. Unrelated,
stale, malformed, unsafe numeric, and regressing cumulative evidence is rejected.
`reported` requires usage observed after a successful terminal notification;
earlier-only or failed-turn usage remains `incomplete`, and absent valid usage
is `missing`. Even a reported snapshot does not establish historical failed
response accounting. Internal compaction and retry turns retain distinct ordinals.

Claude rejects observation facts outside the selected continuation or fork
lineage. It maps its session-checked terminal result's `usage` to attempt-cumulative
input, cache-read, cache-creation, and output counters. Input excludes cache
counters; separate reasoning and total usage remain unknown. A single model's
reported context window may supply capacity; multiple models do not imply one
aggregate capacity. Successful terminal usage is `reported`; failed accounting
is incomplete. Bash tool results, correlated background task completions, and
validated compaction boundaries supply bounded facts. Neither provider exposes
native identities, model keys, commands, payloads, diagnostics, or timestamps in
observations. Consumer failures are redacted and cannot replace an established
protocol, ownership, isolation, permission, cleanup, or effect failure.
During Codex shutdown, bounded protocol parsing continues to collect matching
observation facts without dispatching progress or retaining more notifications.
Late server requests and malformed frames fail inside the client; subsequent
frames cannot replace the first protocol failure. Proven process retirement
clears outstanding progress even when shutdown reports a protocol error.

The installed Codex CLI 0.163.0 public schema was inspected using model-free
`app-server generate-json-schema`: `turn/start` has no numeric generation-budget
field. Context-window and effort controls are not generation-budget controls.
The [official model contract](https://developers.openai.com/api/docs/models/gpt-6.1-sol)
lists a 128,000 maximum output-token ceiling; it does not establish a Codex
override or an effective service cap for this execution. The reviewed source
context supplied that ceiling; live documentation retrieval was unavailable
during implementation. Effective output limits and historical failed-turn usage
remain unknown. No output-budget option or byte-to-token conversion is added.

Codex derives progress from validated, matching thread/turn notifications for
turn and item lifecycle events and nonempty text/reasoning/plan deltas. Up to
1,024 payload-free facts can precede the `turn/start` reply; only facts matching
the returned turn are delivered. Command-output deltas, unrelated turns,
keepalives, and unknown traffic provide no semantic progress. Final turn-item
auditing and failure classification remain authoritative.

Claude consumes UTF-8 JSONL using `--output-format stream-json --verbose
--include-partial-messages`. The private parser bounds each line to 16 MiB and
the complete stdout stream to 64 MiB, validates message/block/session envelopes,
and retains one terminal result for the existing structured-output, permission,
failure, model, and session-lineage checks. Partial tool-input generation is
semantic progress; a complete Bash tool-use starts command activity, and its
matching tool-result completes it. Recognized background Bash tasks have their
own correlated lifetimes. File tools report separate start/completion events.
Token accounting, tool-progress heartbeats, and irrelevant records do not emit
progress. Malformed, duplicate, or missing results cannot become success;
permission failures and uncertain killed-process outcomes retain precedence.
A `system/init` after the result must match the session already established by
the earlier init or the result: a matching init is idempotent metadata, a
conflicting init rejects, and the stream is still consumed to EOF. Another
result or a post-result assistant, user, or stream-event record still rejects,
and other trailing system records keep their existing handling.
Owned process capture delivers bounded stdout chunks without bypassing durable
registration, containment, cancellation, retirement, or storage cleanup.

Every model-free subprocess used for version/help, Claude `socat` and isolation
policy checks, the local-commit executor proof, or owned-process namespace
proof has a 10-second deadline. Within that outer bound, a local-commit probe
has a one-second network-denial observation deadline; silence cannot prove
isolation, so exhaustion fails the capability closed. Claude's per-turn Git
metadata preparation uses the 10-second bound. Codex's pre-effect local-commit
Git metadata lookup uses a 60-second bound; Claude's pre-effect local-commit
Git metadata lookup retains the 10-second bound. These preparation deadlines
do not cap the authorized commit effect after it begins. Codex MCP configuration
discovery is the deliberate exception: it makes at most two `mcp list` attempts
with a 30-second subprocess deadline apiece and no added retry delay, then reports
recoverable provider unavailability. Codex model-catalog discovery issues at
most 32 page requests with a requested limit of 100 entries per page, and
rejects a repeated cursor. The 256-name MCP configuration capacity and
catalog-page cap are schema and protocol defenses, not operator-configurable
work budgets.

The shared adapter contract accepts optional `effort` in execution options and
turn requests, validated by each registered provider through that contract.
Its closed vocabulary is `current|low|medium|high|xhigh`; omission and `current`
normalize to no override. Model identifiers cannot contain whitespace, so a
combined model-and-effort string is rejected before provider activity.
Native translation stays within the providers: Codex supplies
`model_reasoning_effort` at process launch and `effort` on every `turn/start`;
Claude supplies `--effort`, translating portable `xhigh` to native `max`.
The supported Codex App Server baseline includes effort control. Claude's
model-free help probe must advertise the requested native tier. These checks
apply only to explicit selections and do not add requirements to `current`.
Codex uses `model/list` reasoning-tier metadata when present. An explicit model
is checked before thread selection; an inherited model uses the selected
thread's effective model, falling back to effective configuration or the
catalog default when unavailable. Missing tier metadata or an unlisted
inherited model defers support to the provider instead of guessing a model
capability. Every continued, forked, compacted, reconstructed, and
commit-readiness turn retains the same effort.
Both adapters normalize an unsupported explicit selection or bounded native
effort/model rejection to non-recoverable `ERR_UNSUPPORTED_EFFORT` and
`effort_unsupported`. Codex classifies relevant RPC errors before discarding
their payloads and preserves that classification through thread recovery.
Structured authentication, usage, and transient failures retain their existing
semantics. A specific Claude effort rejection takes precedence over a generic
turn-setup failure. Native rejection text is not retained, and commit-readiness
failure cannot start or replay the constrained executor.

On Linux, Claude selects an isolation policy independently for read-only,
workspace-write, and local-commit access. The selector first uses the fixed,
model-free provider/child probe around Claude's embedded `apply-seccomp` helper
for the full native sandbox. Only a positively recognized
nested-user-namespace denial may try the fallback. A bounded model-free version
invocation first proves that Claude accepts the spawning-parent policy option.
The isolation proofs invoke no model or provider transport. The native proof
invokes Claude's local embedded seccomp helper. The fallback proof supplies
representative effective arguments without that automatic dispatch through
the same provider-private command launcher, validation grammar, and
access-aware topology installed for model commands.
Fallback turns launch the Claude CLI directly so authentication and provider
transport retain the host environment and network path. The invocation-local
spawning-parent policy names the short-lived launcher as `bwrapPath`. Claude
honors that value only when its policy tier admits that source and otherwise
resolves `bwrap` through `PATH`, so the turn environment also places the
launcher's directory first on the provider's `PATH`. Either selection reaches
the same authenticated launcher; without it, Claude's own bubblewrap would
apply the read-only preparation reservation to every command. Administrator
managed settings outrank both selections because Claude takes their first
`bwrapPath`. Before any proof, the selector therefore reads the documented
Linux `/etc/claude-code/managed-settings.json` and its non-hidden `.json`
drop-ins; a `sandbox.bwrapPath`, a policy helper whose tier cannot be
inspected, or an unreadable or invalid document leaves every access mode
unavailable. Server-managed settings live in provider-private storage and are
not read, so selection is also enforced per command. The turn environment names
a generated Runner shell through `CLAUDE_CODE_SHELL`; it runs the pinned bash or
zsh only when `AGENT_RUNNER_CLAUDE_COMMAND_SHELL_PROOF` carries the launcher's
per-turn value and otherwise exits 125. Claude's credential denial removes that
variable inside every sandbox it starts, while its unsandboxed shell use keeps
it. Only the authenticated launchers set it again, after Claude's removal and
beside the read-only HOME projection that holds the shell, so a command started
through any other selected bubblewrap never runs. Probes require that refusal
and run their commands through the same shell. The launcher pins
the canonical host `bwrap` executable from the unchanged environment before the
turn instead of resolving it through a potentially workspace-writable path. The
launcher file is non-writable.
Its owner-only allocation is outside the project, task, and state trees, and
command namespaces cannot write the allocation. The adapter retains directory
authority for teardown.
The authenticated launcher accepts one closed Claude bubblewrap grammar: the
session and parent-lifetime flags; unique environment removals or non-protected
assignments; network unsharing, optionally followed by same-path proxy-bridge
binds strictly inside the private runtime trees and environment operations; a
read-only root followed by supported bind, read-only-bind, or tmpfs operations;
the synthetic device mount; PID and required user unsharing; an optional empty
capability set; Claude's weaker host `/proc` bind; trailing environment
operations; and exactly one absolute shell, `-c`, and opaque command payload
after `--`. Assignments after network unsharing point at Claude's discarded
proxy bridge, so each becomes a removal; a variable Claude already removed stays
removed. The
launcher translates the required user-unshare argument into exactly one
bubblewrap user namespace. Claude's fixed
incidental write binds for its temporary, npm-log, and debug paths are
recognized exactly but discarded rather than exposing their host paths. All
other writable binds must resolve inside the canonical workspace, must not
resolve inside Git metadata, and are accepted only for workspace-write access.
Read-only binds must preserve their source path except for Claude's `/dev/null`
or verified owner-only empty-directory masks beneath the canonical runtime
temporary root, both limited to strict workspace descendants. Empty-directory
masks are replaced by private read-only tmpfs mounts rather than exposing their
host temporary sources.
Exact workspace mounts of either kind and Git mounts, including redundant Git
descendants, are replaced by Runner-owned mounts. Claude's own mounts strictly
inside `/tmp`, `/run`, or the hidden allocation, without overlapping the
workspace or Git metadata, are discarded because the launcher's private mounts
replace those trees. Other same-path read-only workspace descendants and masks
preserve Claude's command-protection policy for every access; outside the
workspace, Claude may also mask an existing file with `/dev/null`. Every
remaining read-only bind must not overlap the writable workspace or any part of
the Runner-private device, process, runtime, or launcher trees. A tmpfs
destination is either `/tmp` or `/run`, replaced by the launcher's private
mounts, or an existing directory mask that overlaps none of the workspace, Git
metadata, or those private trees. A later writable bind may not overlap an established
read-only workspace restriction, and no later mount may re-expose a path hidden
by a private workspace mask.
Duplicate environment operations, assignments to `ARGV0`, credentials, or the
launcher token, writable roots, unsupported options, malformed namespace
arguments, malformed option arity or ordering, and extra payload arguments exit
before any child starts.

After validation the launcher drops Claude's host `/proc` bind and strengthens
the same invocation with PID-1 behavior, an empty capability set, private
procfs, private `/tmp` and `/run`, a private `/tmp/claude`, a hidden launcher
path, the exact workspace authority, read-only resolved Git metadata, missing
protected-environment removals, and the requested working directory. A private
Claude module serializes a classic seccomp BPF for little-endian x64 or arm64.
The program validates `seccomp_data.arch`, kills an architecture mismatch,
returns `EPERM` for `socket(AF_UNIX, ...)`, `io_uring_setup`,
`io_uring_enter`, and `io_uring_register`, and allows other syscalls. X64
covers both native and x32 syscall numbers. Unsupported architectures and
malformed programs fail before launch.

On every invocation the authenticated launcher decodes and hashes the exact
filter bytes, writes and syncs an owner-only no-follow file, reopens it
read-only, and unlinks it before verifying the link-free descriptor's owner,
mode, size, identity, and complete contents with positioned reads that leave
its offset at zero. It then removes its authorization token, `ARGV0`, and
provider credentials and invokes the pinned real `bwrap` directly once,
passing that sealed resource as inherited child descriptor `3` with
`--seccomp 3`. Filter creation, tampering, descriptor inheritance, bubblewrap
setup or execution, close, and resource cleanup errors all fail closed. The
fallback's `allowAllUnixSockets: true` setting suppresses Claude's automatic
helper dispatch so the Runner-owned filter is the only fallback socket policy.
The command crosses one user, PID, mount, and network namespace boundary; the
fallback never invokes Claude's seccomp helper or creates a nested user
namespace.

The direct fallback probe supplies Claude's producer-ordered arguments for the
same read-only preparation settings to that same validator and execution path:
credential removals, a private proxy-bridge bind with proxy rewrites, the
default workspace write, a private temporary bind, the final workspace
reservation without the masks it covers, the capability drop, and a trailing
removal. Native probes use the same workspace order. Both probes first prove
that the probe environment resolves `bwrap` to the generated launcher. For
repository access, native and
fallback child probes use a disposable committed repository to require compound
repository inspection and, for read-only access, reject workspace, Git, and local
remote-ref mutations. Workspace-write proofs create a source directory and
create, rename, and unlink a file there; read-only proofs require each change
to be denied. Repository proofs also reject writing a nested `.mcp.json`
control or renaming its pinned parent, and both policies reject writes beneath
`.claude`. They also check access-specific workspace writes, outside-write
denial, private temporary storage, IP isolation, inability to reach live host
abstract and pathname Unix sockets, credential and `ARGV0` removal, and host
provider-proc secrecy. The selected fallback sets
Claude's required weaker-nesting option and `allowAllUnixSockets: true`, so no
second automatic helper is added to the opaque command payload. Native policy
retains `allowAllUnixSockets: false` and its existing stricter topology.
Arbitrary native failures, launcher construction or execution failure,
incomplete proof, or cleanup failure do not enable the fallback.
Both policies keep model-command network, host Unix sockets, credentials, Git
metadata, remotes, and outside writes denied. Probes use fixed representative
arguments and a fixed validated shell payload, the credential-filtered command
environment, and bounded time and output; they retain no host diagnostic and
never apply a profile, authenticate, or invoke a model.
The local-commit executor proof remains independent and `localCommit` requires
both the local-commit turn policy and executor proof.
Both policies now install an authenticated adapter-owned projection launcher.
The native launcher preserves the native namespace/seccomp invocation; only the
restricted-host launcher replaces its known weaker topology. Both preserve
existing descendant masks. Claude prepares its filesystem arguments with an
explicit read-only project reservation and no extra configured write paths;
this prevents it from registering absent project targets for creation or later
cleanup. The authenticated launcher replaces only that exact reservation with
the runner-authorized workspace access. Writable access requires both the
original workspace bind and the preparation reservation.

Because the reservation covers workspace Git metadata, selected `readPaths`
inputs, and Claude's built-in shell, tool, and settings controls (`.gitconfig`,
`.gitmodules`, shell profiles, `.ripgreprc`, `.mcp.json`, `.claude.json`,
editor directories, and `.claude`), Claude omits their masks. For Git
workspace-write access both projections therefore normalize the complete
validated mount program before bubblewrap starts. Each destination is
classified canonically. Mounts away from the workspace keep their order, while
a later mount that encloses or replaces the workspace grant, an earlier
descendant tmpfs, a writable alias of workspace content, and a later writable
descendant overlapping an established restriction are rejected. The grant
hides earlier descendant mounts: earlier writable descendants are subsumed by
it, and earlier read-only restrictions are reapplied after it with their own
source and destination. The output order is the grant, ancestor pins
shallowest first, and then Git and selected-input protections, restored
controls, and Claude's descendant restrictions together, shallowest first, with
a restriction after a protection at the same destination. Restrictions with
different operations or sources at one destination are rejected, as is a mask
or tmpfs that would enclose a protection or another restriction, or a tmpfs at
one, because it replaces host content; a read-only mask may still cover a
protection at its destination. Before bubblewrap starts, the
normalized program is replayed with each later mount hiding every earlier mount
at or beneath its destination; every protection and restriction must remain
effective and read-only, and none may keep a movable ancestor. Like Claude's producer, discovery finds controls and nested `.git`
entries by name in the workspace and up to three non-symlinked directory levels
below it, outside `node_modules`. Only existing paths are mounted. A
symlinked control, a protected path behind an inner symlink, or a link whose
target encloses the workspace fails closed; a linked settings, commands,
agents, skills, or plugins entry inside a protected `.claude` directory also
protects its in-workspace target. Immutability is decided only from read-only
mounts in the final tree. Every other ancestor of a protected path or
restriction becomes a writable self-bind: its contents stay editable, but as a
mount point it cannot be renamed, removed, and recreated around the
protection. The restricted-host launcher keeps its final Runner-owned Git and
selected-input mounts after those pins. Directory projection admits Claude's
same-path binds strictly inside the turn's private temporary directory and
still rejects every other undeclared write. All project bind,
directory, tmpfs, device, and proc targets must resolve before bubblewrap starts.
Missing `.bashrc`, `.gitconfig`, `.mcp.json`, editor directories, and `.claude`
tooling paths must never be materialized inside a writable project bind. No project file is
ignored, filtered from a fingerprint, or cleaned by an agent.

Commands receive an empty, read-only HOME/config projection with private
namespace-local temporary, cache, and runtime directories. The real provider
HOME, authentication environment, selected config directory, and session store
remain separate and unchanged. Provider temporary scaffolding and the fallback
filter's temporary files belong to the same allocation. Probes exercise the
projection launcher too; the contract revisions are `claude-isolation-v3` and
`claude-command-boundary-v9`. Old receipts cannot authorize the new policy.

Before a turn launches, the adapter journals allocation intent and then the
private directory's device/inode identity through the optional `onResource`
request callback. The stop monitor serializes that callback with process and
stop-activity writes; cancellation does not cancel cleanup persistence.
`storageForbiddenPaths` supplies the task/state exclusions in
addition to cwd. The existing execution-resource slot holds the frozen adapter
preparation identity in `commandIdentity`; this identity never selects or
attests a trusted validation command. A provider descriptor may register one
unique resource identity and recovery hook. The runner dispatches retirement
cleanup through this hook without provider branches or changes to Codex.
Live directory cleanup and recovery add current filesystem-discovered controls
to the cleanup exclusions, even when frozen input files are missing. An
allocation newly referenced by a control pointer remains retained until that
overlap is resolved.

Cleanup verifies the host, canonical private root, owner, permissions, and child
identity, pins the root descriptor, removes only the recorded child, syncs the
parent, and journals removal. Missing children permit interrupted-removal
recovery; replaced or unverifiable storage remains blocking. Cleanup occurs
only after process and descendant retirement, before a response, fingerprint,
trusted validation, or commit executor can be accepted. Owner-loss resume and
operator stops use the same adapter cleanup under exclusive leases. A still-live
runner retains its private run/worktree lease handles after resource cleanup
failure; a sequential retry revalidates the run token through the state mutation
boundary before reuse, retaining the handle if inspection itself fails.
Concurrent resumes and other owners remain excluded, and stale revisions remain
errors. Restart uses normal identity-based owner reclamation.
`ERR_EXECUTION_RESOURCE_UNVERIFIABLE` preserves the active checkpoint for
repository/effect reconciliation on resume. A fully cleaned pre-launch failure
uses `ERR_AGENT_ENVIRONMENT_PREPARATION` and the existing safe provider pause,
including proven not-started source-fork recovery. Errors retain only finite
`environment_preparation` or `environment_cleanup` class/checkpoint evidence.
A journaled `environment/cleanup-pending` activity distinguishes unfinished
adapter cleanup from a repository check without retaining raw diagnostics.
A stronger provider or containment failure is preserved; the root marks retained
resource ownership so pipelines cannot accept content or finish the turn over
it. Terminal provider failures are persisted as failed checkpoints while their
cleanup reservations remain owned; subsequent cleanup cannot replay the turn.
Process-proof uncertainty stays resumable. Consumed commit effects remain
verification-only.

The provider-private policy identity binds the installed CLI version, selected
isolation policy, complete effective permission, tool, deny, and sandbox policy,
and, for fallback access, the direct-filter contract, architecture, and exact
byte hash. A receipt created for the superseded helper-based fallback, another
architecture, or a prior permission policy cannot authorize later provider
work.
Claude derives its advertised read-only capability and turn arguments from one
autonomous access envelope shared by read-only and local-commit readiness
turns. It exposes only repository-inspection tools and omits broad shell-command
denials that would reject compound inspection, while retaining collaboration,
editing, and web restrictions. Autonomous Bash is available only inside the
proved sandbox, which denies workspace and Git-metadata writes, closes command
network and Unix-socket access, and forbids unsandboxed fallback.
Workspace-write turns retain their separate `auto` permission policy,
background classifier, broader content tools, and existing command denials
while denying Git-directory writes and `git add`. Codex repository workspace-write
isolation likewise exposes safe content
writes without Git-metadata writes. Codex protects project-root `.agents` as
provider metadata by default, so a workspace-write turn adds it as an explicit
writable root only when it exists as a real directory. A missing or symlinked
`.agents` stays protected, as do `.git` and `.codex`. For each Codex app-server
attempt, the runner creates one canonical owner-only private root beneath the
fixed platform temporary location without consulting ambient temporary
variables. The effective writable set is the repository content, including an
eligible `.agents`, and that private root. `TMPDIR`, `XDG_CACHE_HOME`, and
`XDG_RUNTIME_DIR` project validated children of the root into command tooling
through the effective shell policy. The policy starts from the full provider
process environment, applies Codex's automatic secret-name exclusions and an
empty custom exclusion list, overlays those explicit workspace values, and then
keeps exactly Codex's standard core names (`HOME`, `LOGNAME`, `PATH`, `SHELL`,
and `USER`), `AGENT_RUNNER_OWNED_PROCESS`, and the three workspace names. This
preserves the dynamic ownership proof without exposing unrelated parent
variables. The provider process environment remains unchanged, ambient
`TMPDIR` and host `/tmp` remain excluded, shell profiles stay disabled, and
command network access remains denied. In-session compaction retains the
attempt's root. Every successful, failed, or freshly recovered attempt validates
and removes its root before returning or retrying, and unsafe preparation or
cleanup fails closed.
Codex observes owned-process completion as soon as the App Server starts and
races only its rejection against the complete protocol operation. An ownership
failure therefore starts bounded client and workspace cleanup promptly and
retains precedence over client-cleanup failures, even when containment
deliberately keeps protocol pipes open. Successful owned completion does not
satisfy a protocol request; the adapter still requires the complete App Server
result. App Server shutdown has up to three fixed one-second observation
windows: natural protocol close, TERM, then KILL. These post-turn cleanup phases
are containment invariants, not configurable provider-work deadlines.
Read-only and local-commit storage remain independently isolated. Both adapters
advertise `gitMetadataWriteBlocked`; the runner, not an agent turn, owns effects
that require the index.
Each pipeline's complete and recovery role-prompt envelope provides the
semantic boundary for eligible project `.agents` content: plan authoring
requires an explicit user task, polishing requires the same, and plan execution
additionally requires the current planned commit to authorize the guidance
change. The responsible roles must not propose, make, or approve a change
outside that scope. A compatible continuation inherits the boundary from its
native session, while every fresh or reconstructed context receives it again.
Violations use the owning pipeline's ordinary finding-and-fix route and do not
open a user question.
Every retryable request carries a turn prompt and a complete recovery prompt
reconstructed from validated run state, durable artifacts, and the observed
workspace. A role session is continued only when its persisted key matches the
accepted inputs, role, and pipeline-owned checkpoint. Clarification and normal
work use distinct checkpoints. In independent mode, plan execution also
isolates Worker and Reviewer by planned commit, while polishing isolates
bootstrap from Worker and Reviewer work. Compatible continuations receive only
the current instruction and state delta; first, forked, fresh, and
context-invalidated turns receive the complete prompt. Arbiters remain fresh.

A checkpoint's complete prompt is reconstructed from validated inputs, durable
resolved summaries, its current plan step or change-set fingerprint, active
blockers, and the pipeline's bounded decision history. These inputs remain
durable even when the native session is gone.
Every pipeline role turn also states that the authorized role must produce the
result itself without delegation, subagents, or multi-agent collaboration.
Prompt compliance supplements rather than replaces the adapters' fail-closed
collaboration audit.

Independent mode retains the original role topology: primary and review roles
have separate contexts and any required Arbiter starts fresh. Lazy mode has one
logical primary role and never resolves, probes, forks, invokes, or charges a
Reviewer or Arbiter. Plan authoring uses the Planner; plan execution and
polishing use the Worker. A reconstructed native session is still that same
logical role, and all clarification, no-delegation, provider recovery,
redaction, product-decision, durable-state, lease, and repository guards remain
unchanged.

Lazy convergence is a bounded pipeline-owned loop. A writable
`CHECK_AND_FIX` turn reviews the complete current result with the established
pipeline review criteria and fixes any problem immediately. An unchanged
result enters a separate read-only `CLEAN_CONFIRM` turn with the same criteria,
an explicit edit prohibition, and a strict `CLEAN` or concrete-findings result.
Advancement requires `CLEAN`, no repository mutation, and the exact inspected
content fingerprint. In plan execution and polishing this first converges the
candidate; `FINALIZE` follows, then a distinct read-only `CONFIRM` applies the
validation-change decision to the finalized evidence.
Content findings return directly to `CHECK_AND_FIX`, never to dispute or arbitration.
Ordinary terminal findings clear candidate and confirmation attestations but retain a
successful finalization record while its content and validation-infrastructure
fingerprints remain current. After candidate convergence, the runner recomputes
both fingerprints and retries `CONFIRM` directly on an exact match; otherwise it
invalidates the record and returns to `FINALIZE`. Declared fixes do not stand in
for observed repository mutation. Every actual content or validation-
infrastructure change, provider correction-scope drift, content-changing
interruption reconciliation, and plan-execution commit-step advancement
invalidates finalization evidence. Plan-authoring drafts stay
in external state and are deterministically validated only after confirmation.
Plan execution and polishing route pure validation-evidence rejection directly
to bounded replacement finalization; mixed rejection returns through candidate
convergence before fresh finalization. Both require a fresh terminal confirmation.
Existing fix/revision, stable-finding, stagnation, and additional-round budgets
bound the loop and never silently accept an unconfirmed result.

Plan authoring separates primary convergence, independent review, session scope,
correction accounting, and arbitration eligibility in its private
`review-policy.js`. The workflow and persisted-state contract share these pure
decisions. Turn implementations, effect guards, persistence, and plan writing
remain in the workflow. Combined mode enables both primary convergence and
independent review, retaining checkpoint-isolated sessions and the existing
durable lazy-checkpoint field names. Draft review invalidation
retains correction scopes so returning to an earlier fingerprint cannot reset
an automatic correction allowance.

Combined authoring records primary confirmation separately from Reviewer
approval. A revised draft clears both and restarts primary convergence; Reviewer
reconsideration of an unchanged draft can retain primary confirmation. Self
findings and structural failures return to check/fix, without arbitration on
exhaustion. Only independent finding resolution may request the fresh Arbiter.
Each accepted check/fix or revision consumes one bounded revision round; invalid
output and recovery cannot duplicate accepted work. Version 5 adds combined
mode while migrating saved version-4 independent/lazy state unchanged under
the lease; missing mode remains independent and unsupported old values reject.

Plan authoring owns primary-convergence structured-output recovery at both checkpoints.
Provider and deterministic contract failures become bounded diagnostics, then
one fresh repository-read-only Planner session receives the complete durable
draft-bound request and original schema. Only a valid replacement under the
unchanged draft fingerprint rejoins the ordinary route. Repeated invalid output
pauses at the exact checkpoint with a redacted explicit null retry; interruption
and resume preserve the pending marker without retaining rejected output,
replaying accepted progress, consuming revision or correction budgets, or
writing `plan.md` early.

Plan execution owns durable implementation/finding-resolution result recovery
in private `writable-result.js` and its workflow integration. State version 38
adds nullable `writableResult`; the version-37 migration initializes absence
without inferring recovery evidence or changing terminal history, accepted work
or consumed effects. Before invocation, the pipeline binds original phase,
step, content, blocker ownership, restrictions, inventories and accounting.
Reconciliation atomically publishes the inspected candidate, approval
invalidation and any fix charge before retiring the writable turn. Only
allowlisted normalization diagnostics are retained, never rejected output.
Unstarted prepared reservations resume under their existing authority after
unchanged-state checks; published invocations require result restatement.
Legacy writable continuations bind their reconciled baseline and retained fix
accounting before checkpoint creation, preserving original implementation proof.
Validated product decisions remain journaled settlement intents until the
transcript append and product-decision suspension complete. The existing
clarification service binds append replacement to a persisted result hash;
recovery reuses those exact bytes before input checks or another role turn.
The checkpoint retires atomically with the suspension and editor authorization.

One durably reserved read-only Worker restatement uses the original schema and
facts under unchanged content, frozen inputs, native policy and filesystem
permissions. Custom result data and output authority remain independently
validated and settle with the valid gate transition. Interrupted attempts remain
consumed; lost acceptance responses use the published state. Repeated invalid
output pauses with `writable_output_invalid`; explicit null-action resume
journals one additional read-only retry without renewing the automatic allowance.
Output-exhausted restatements require their exact read-only checkpoint bound to
Worker, the original implementation/resolution phase, step and consumed attempt.
Validated blockers remain blocking. Recovery precedes ordinary dispatch and
never repeats writable work, invents dispositions, duplicates fix charges or
commits, or replaces a mode-required gate. The owning
[execution specification](../pipelines/plan-execution/docs/SPEC.md#writable-result-recovery)
defines the checkpoint and pause contract.

Plan execution also owns lazy structured-output recovery. Provider and
deterministic checkpoint failures are reduced to bounded diagnostics, then one
fresh Worker session receives the complete durable checkpoint request with its
original schema. A writable check/fix correction may reconcile safe content
exactly once, invalidates dependent evidence, charges actual fix work once,
and must pass complete finalization before the pending checkpoint resumes. A
clean-confirmation correction is read-only and requires unchanged content and
validation-infrastructure fingerprints. Repeated invalid output pauses at the
exact checkpoint with a redacted explicit null retry; retry reconstructs the
pending attempt without recounting its automatic attempt or fix budget. No
correction result can act as early finalization, confirmation, review, or
commit evidence.

Polishing owns the corresponding lazy structured-output recovery before its
runner-owned handoff. A writable check/fix correction reconciles safe content
and charges actual fix work once, invalidates stale gate evidence, and returns
through candidate convergence. A candidate clean-confirmation correction
remains read-only and retains the index, content, and
validation-infrastructure guards. Terminal Reviewer and Worker corrections are
separately scoped to finalized evidence; scope drift invalidates that evidence
and returns through finalization. Repeated
invalid output pauses with bounded redacted diagnostics and an explicit null
retry; neither a correction nor its recovery can stage, approve, or enter
`HANDOFF` early.

When a native context is full, an adapter may compact it and retry the complete
recovery prompt once. If continuation still fails, writable and read-only work
can resume in a fresh session with the same complete prompt and a concise
recovery preface.

Claude turn failures use a finite adapter-owned diagnostic allowlist. Structured
`permission_denials`, `api_error_status`, result subtype, and `terminal_reason`
take precedence over bounded message matching. The adapter discards denied tool
input, native result text, raw standard error, and process causes; only its
fixed code, fixed message, allowlisted class, and safety fields cross the
boundary. Authentication remains terminal. A denial that identifies an
unexposed tool or a Bash command outside the narrow positive repository-
inspection allowlist is also terminal. Only an expected non-Bash tool or a
positively recognized safe Bash inspection may be a recoverable capability or
configuration failure. Structured provider recovery accepts only explicit
transient HTTP statuses; non-transient client statuses and an `api_error`
without a transient status fail closed with a fixed request-rejected error.

The shared failure record optionally carries `availabilityReason`, restricted to
`transport_unavailable`, `temporarily_overloaded`, `model_busy`, and
`server_unavailable`. The adapter contract and registry accept this evidence only
with transient retry eligibility, a `not_started`, `rejected`, or `exited`
outcome, and no started effects. A commit checkpoint additionally requires
validated `commitExecutor: "not_started"` proof. Possible workspace changes still
require repository reconciliation; ambiguous outcomes cannot carry this evidence.

The same exact record may instead carry the finite optional `disposition`,
either `authentication_required` or `output_exhausted`. The contract accepts it
only for a terminal rejected response without started-effect evidence, process
outcome, or availability evidence. These dispositions remain separate from
availability, authorization, permission, usage-limit, malformed-request, and
ambiguous-effect classifications.

Provider-private availability recognition maps explicit offline, DNS, refused or
reset connections, timeouts, overload, and model-busy errors. Both adapters map
statuses 408, 425, 500, 502, 503, 504, and 529 to the same finite reasons. Codex
also recognizes native connection/stream and internal-server variants through
closed variant payloads. Its private HTTP-wrapper parser requires bounded,
duplicate-free envelopes; matching transient native statuses may be corroborated
by closed server-error wrappers. Conflicting or malformed evidence cannot qualify.
Only native server-error RPC codes can establish availability at `turn/start`;
protocol/request codes retain precedence. Native text is bounded to 16 KiB for
Codex and below Claude's 4 KiB diagnostic truncation bound. Terminal evidence
excludes an availability reason, and existing structured classifications retain
precedence over text. A Claude budget-exhaustion terminal reason precedes transient
statuses but cannot replace a structured authentication, request, or output
rejection. Killed processes cannot use even parseable diagnostics to hide
uncertain effects.
Unknown errors receive no availability reason. Explicit eligible evidence enters
the runner's durable availability coordinator after repository reconciliation;
other failures retain their bounded recovery, pause, or terminal outcomes.

Codex App Server `usageLimitExceeded` and explicit Claude rate, quota, credit,
or spend-limit rejections bypass context recovery and provider fallback. Their
adapters own native recognition and expose only bounded normalized diagnostics;
pipelines consume the backend-neutral recoverable failure. Other allowlisted
backend, capability, configuration, usage, and provider failures use the same
durable pause path.

Codex recognizes output exhaustion only from the exact native message
`Incomplete response returned, reason: max_output_tokens` in a failed
completion whose `codexErrorInfo` is the unit `other` variant. App Server
`turn/start` request errors qualify with the same exact message, a server-error
RPC code (`-32603` or `-32000`), and the standard exact `code`, `message`, and
optional opaque `data` shape. Other variants, variant payloads, additional
details, RPC data, tool output, malformed or oversized messages, and prose
lookalikes cannot establish exhaustion. Protocol validation and reported-item
auditing precede completion classification. The adapter emits only fixed
`ERR_CODEX_OUTPUT_EXHAUSTED`, `turn_output_exhausted`,
`disposition: "output_exhausted"`, and `Codex response output was exhausted.`
diagnostics with terminal retry eligibility. This bypasses automatic fresh
replay, availability and quota recovery, structured-output correction, and
compaction; only explicit native context-window exhaustion invokes compaction.
Source forks remain isolated and rejected local-commit readiness retains
`commitExecutor: "not_started"`. Native evidence is discarded. The incomplete
reason establishes neither a numeric output ceiling nor context utilization,
and does not complete missing or incomplete usage accounting.

Each pipeline consumes normalized output exhaustion through its own durable
`output_exhausted` pause after process/resource retirement and repository safety
checks. Its closed pause retains only the fixed `ERR_OUTPUT_EXHAUSTED` code,
resume state, role, and complete logical checkpoint. CLI/MCP project bounded
checkpoint evidence and explicit retry or new-run guidance. Exhaustion supersedes
availability backoff without authorizing replay, compaction, or output correction.
Execution and polishing preserve safe partial writes, invalidate affected gates,
and persist charged correction work atomically with the pause. Explicit retry
reconstructs the saved request without reforking a possibly created source child
or replenishing recovery allowances. Compatibility-named authentication source-
fork markers also protect this rejected disposition. Consumed commits remain
verification-only; only validated not-started proof plus unchanged Git
verification can retire an unused authorization. Pipeline specifications own the
exact recovery and gate policies.

Other Codex App Server `other` failures use bounded native HTTP error recognition
before opaque recovery. A complete `unexpected status` wrapper with an
allowlisted non-transient client status and a parsed JSON `error` envelope
becomes terminal `ERR_CODEX_TURN_FAILED` / `turn_bad_request`, with the fixed
message `Codex turn failed.` and `recoverable: false`. This includes HTTP 400
`invalid_request_error` / `invalid_json_schema`; it starts no compaction, fresh
retry, backend-availability pause, or output correction.
Recognition is limited to 16 KiB, statuses 400, 401, 403, 404, 405, 413, 415, and
422, and a shallow envelope with scalar `message`, `type`, `param`, and `code`
fields. The type must identify an invalid request, or authentication/permission
failure at status 401/403 respectively. Optional non-null codes must be in the
adapter's finite client-error allowlist. Optional native URL, CF ray, and request
ID suffixes are discarded. Unknown codes, malformed JSON, duplicate fields or
metadata, inconsistent status text, oversized evidence, transient statuses,
and prose lookalikes remain opaque; additional details and variant payloads
are never alternative sources for this client-envelope refinement.
Within that parser, only status 401 with `authentication_error`, an absent or
null parameter, and an absent, null, or `invalid_api_key` code establishes the
shared `authentication_required` disposition. Completion evidence must agree
with any native HTTP status. App Server request errors additionally require a
native server-error RPC code and the standard exact `code`, `message`, and
optional opaque `data` shape. HTTP 403, permission/authorization evidence,
conflicting status or client codes, non-null parameters, unknown request-error
fields, and protocol/request RPC codes remain outside the authentication path.
The resulting fixed failure retains none of the native message, URL, request
ID, payload, or credential material. Claude and future providers remain
unchanged until their descriptors own an equivalent bounded classifier.
Opaque failures retain `turn_other`; the native `serverOverloaded` variant maps
to `turn_server_overloaded`. Both classes are recoverable after the turn-item
audit unless output exhaustion is recognized or a validated client envelope
rejects the request. Explicit native transport/server availability is
recoverable after the same audit. Neither path retains native messages,
variant payloads, additional details, or causes.
Completion notifications and hydrated turns accept only `completed`, `failed`,
and `interrupted` statuses before failure classification. For these failures,
the existing item audit and explicit-model reroute guard still reject policy,
protocol, and isolation violations before classification or recovery. For
recoverable non-commit failures without availability evidence outside a source fork, the existing recovery
path attempts one fresh session with the complete `recoveryPrompt` and observed
workspace. The failure itself does not request compaction, and the second
attempt's failure propagates unchanged without another reconstruction. Source
forks remain ineligible for adapter fallback; the runner reconstructs an eligible
availability failure without reforking its source. Local-commit readiness failures
record that the commit executor did not start; the boundary-derived
`effectStarted: false` projection therefore keeps an overload rejected before
the isolated executor as a proven pre-effect rejection.
Executor outcomes remain on their verification-only path and are never
replayed.

An otherwise unclassified valid read-only result or process failure is
recoverable only because the enforced read-only envelope and the pipeline's
post-turn repository guard prove that it could not mutate the repository.
Unknown writable process outcomes remain terminal after reconciliation;
classified usage and provider failures may pause only after safe workspace
changes and control state have been reconciled. After the adapter's applicable
retry policy is exhausted for failures without availability evidence, the owning
pipeline persists `backend_unavailable`,
the exact resumable workflow checkpoint, reconciled one-shot authorization
state, and any safe workspace changes before entering `WAITING_FOR_USER`. An
eligible normalized transient launch failure also persists only
`launchRecovery: { failureClass, checkpoint }`. Eligibility requires `none`
effect evidence, a `not_started` or `exited` outcome, one of `spawn`,
`initialize`, `session`, or `turn_start`, and no commit-executor evidence.
Deterministic incompatibilities, ambiguous effects, turn and commit failures,
and provider-native details remain ineligible. Resume clears the pause and
reconstructs the same durable request after availability returns. The optional
pause field requires no state-version migration.

A Worker returns a bounded structured blocker when sandbox, IPC, loopback,
process-isolation, missing-service, permission, or comparable external
constraints prevent work not delegated to an exact selected runner-trusted
command. A selected command's agent-sandbox limitation alone cannot block
applicable content repairs or semantic review; another command's selection
does not suppress a genuine blocker. Plan execution and polishing
persist `environment_blocked` rather than treating that condition as a code
failure, preserve safe workspace content, and invalidate any stale
fingerprint-bound candidate, finalization, and confirmation evidence. A
content-changing finding resolution resumes at `REVIEW` in independent mode or
`CHECK_AND_FIX` in lazy and combined modes; an unchanged turn resumes at its original
checkpoint. Finalization always resumes at `FINALIZE`. The workflow does not
weaken isolation or grant network or host temporary-directory access to bypass
the unavailable validation.

Finalization is fail closed. A `PASS` contains exactly one ordered result with
bounded direct evidence for every persisted required check; omitted, skipped,
substituted, replaced, or weakened checks are invalid output. The runner hashes
the identified package scripts, test-discovery and runner files, skill guidance,
and validation configuration rather than trusting an agent-supplied hash.
Changing that inventory, its file set, or its fingerprint is provisional until
the read-only terminal Reviewer in independent and combined modes, or the lazy
read-only terminal clean confirmation, accepts that the task or current plan
step authorizes the complete change for
the same content fingerprint. The confirming turn receives both the established
and candidate tuples, so acceptance cannot depend on a prior native session.
Both pipelines invalidate rejected evidence and use their independently owned
bounded semantic recovery routes. Commands and repository-relative infrastructure
paths are validated and compared without rewriting interior whitespace.
Host-reported results and user attestations are outside this trust boundary.
Plan execution builds both passing and failing persisted finalization evidence
through one deterministic pipeline contract before attempting advancement.
That contract normalizes the Worker and runner portions together, derives the
aggregate status, validates ordered executor provenance, and binds the result
to the content, validation-infrastructure, ordered-command, and trusted-
configuration fingerprints. An unexpected persisted-state invariant therefore
leaves the prior valid `FINALIZE` checkpoint available for the bounded public
retry instead of turning the run into an opaque terminal failure.

Plan execution gives each preparation phase one owner. Independent semantic
review, or lazy check/fix and candidate clean confirmation, converges first.
Implementation, finding-resolution, and lazy check/fix turns do not invoke project finalization
or perform generic commit preparation. The dedicated finalization turn follows
every substantive instruction in the pre-bootstrap frozen guidance. A selected
skill remains in the established validation-infrastructure inventory and must
match its frozen path and fingerprint through finalization and terminal
confirmation. Guidance repair or drift starts a new run rather than consuming
correction or review budgets. The finalization turn runs the writable
repository formatter first, treats its output as the content under finalization, then runs
generation, the non-mutating repository gate, Git whitespace checks, and
staging-independent content review. Bootstrap,
validation-migration, and finalization inventories deterministically reject
index mutation, staged or index-relative inspection, implicit
worktree-versus-index assertions, alternate-index workarounds, and commit
preparation; applicable content checks use `HEAD` or explicit trees.
Established checks are input only to `FINALIZE`.
After finalization and the distinct mode-specific terminal confirmation bind
the same content and validation-infrastructure fingerprints, the constrained local-commit executor
alone runs `git add -A`, fixed unstaged-clean, staged-diff whitespace, and
nonempty-diff hygiene, and the subject-only commit with the validated plan
subject. The contract is
identical for Codex and Claude and does not broaden ordinary Worker access to
Git metadata.

Polishing uses the same ownership rule without requesting `local-commit`.
Worker polishing, finalization, finding-resolution, and lazy or combined check/fix turns
are content-only, including when selected finalization guidance normally
requests staging. Its independently persisted pre-bootstrap decision supplies
only the frozen skill path or fallback to bootstrap and validation migration.
Any selected skill remains in established infrastructure and must retain its
path and fingerprint through correction, finalization, confirmation, and
resume; repair or drift requires a new run without consuming fix or review
rounds. Bootstrap, validation-migration, and finalization inventories
use the same deterministic staging-independence policy as plan execution;
applicable tracked content checks use `HEAD` or explicit trees, and established
checks are input only to `FINALIZE`. Once candidate convergence has completed
and finalization plus the distinct mode-specific terminal confirmation bind the
same staging-independent content and validation-infrastructure fingerprints,
the pipeline persists `HANDOFF`.
The root Git boundary then accepts either an unchanged pre-effect state or an
already-complete recovered effect, runs `git add -A` only for the former, and
verifies unchanged content and Git controls, a nonempty complete staged set,
no unstaged or non-ignored untracked remnants, and staged whitespace hygiene
before the pipeline can enter `DONE`.

Both pipelines project only exact command text from persisted
`trustedValidation.commands` into implementation or polishing, lazy or combined
`CHECK_AND_FIX`, and finding-resolution prompts. The existing snapshot bounds
limit the projection; an empty selection produces an empty array. Complete,
continued, reconstructed, and correction requests all carry it without
configuration reloads, provider settings, executable vectors, or a repeated
validation inventory. Established required-check execution and attestation
remain exclusive to `FINALIZE`. Selected trusted commands never execute inside
agent turns, and their agent-sandbox limitations do not prevent applicable
repairs and semantic review. Bootstrap inventory-reporting and finalization
`NOT_RUN` instructions stay in their existing contexts.

A selected runner-trusted command is the only exception to agent-side check
execution during finalization. The runner-derived bootstrap inventory must
contain its exact configured command.

The public trusted-validation service also provides `inspectRequirements` for
pipeline-owned requirement discovery and writable-entry decisions. This is an
explicit preparation effect, never a required-check execution or attestation.
Construction, status reads, and ordinary preflight do not call it. Pipelines
retain their own reporting schemas, saved requests, migration, and pause policy;
the capability owns normalization, frozen authority matching, and availability.
Plan execution and polishing independently own reports in each active role's
bootstrap or validation-migration inventory and inspect their union at every
writable entry. Cached declaration preflight cannot bypass this gate. Execution
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

Plan execution and polishing each require a boolean `sourceProjection` field in
their own report schema and map only `true` into the shared capability request.
Their ordered migrations add `false` to historical concrete reports without
reloading configuration or changing immutable trusted snapshots, and preserve
null provisional reports for read-only rediscovery.

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

For authorized requests, inspection prepares each selected command sequentially
under the existing durable storage, transport, and process lifecycle. It acquires
and verifies dependencies, constructs the same network-isolated mounts, checks
the declared executable's availability, and runs only a runner-defined empty Node
program in that sandbox, with a maximum ten-second process deadline. The check's
argument vector is never invoked. Preparation failures return bounded
`unavailable` blockers without native diagnostics, URLs, or process output.
Uncertain resource ownership, cancellation, and repository mutation preserve
their existing safety error contracts and recovery evidence. Successful
retirement journaling is required before inspecting another command; an
uncertain process registration stops preparation with its ownership intact.
Successful inspection returns only `READY` and an empty blocker list; it grants no check
pass or finalization evidence. Owned resources are retired and cleaned, and
finalization later acquires dependencies afresh and reverifies them.

The runner's private inspection adapter pins repository scope and snapshot to
the saved run, guards project configuration before and after the effect, and
uses the stop monitor's signal and leased process/resource callbacks. Outstanding
ownership must be recovered first. Stop reconciliation rejects inspection just
as it rejects new command execution. This adds no eager capability work ahead
of consumed-commit or completed-handoff verification; pipelines must keep that
verification-only recovery ahead of any new preparation.

### Preparation custody

Common envelope version 22 adds nullable `preparation` authority; older runtimes
reject it and legacy migration grants no process proof. Before the inert
supervisor launches, the state capability fully publishes a canonical reservation
and initializes its confined custody log. The reservation binds the attempt,
execution lease and owner, original certified journal prefix/revision, frozen
input/content and trusted command/configuration fingerprints, allocated resource
identity, initial stop state, and descriptor-proven commit target. An explicit
null target supports ordinary execution and polishing preparation; unsupported
deferred stops still reject. The reservation authorizes future work only.

Launch starts the unchanged absolute preparation deadline. Attachment and
one-shot admission use fresh stable custody/lease reads, directory identity and
process-identity rechecks. The log identifies the issued reservation by revision
and digest without copying or hashing its history certificate. It preserves the
complete process record within 16 records and 2 MiB; no historical field is
truncated. Attachment requires supervisor identity and namespace. Historical
ancestry and control-group proofs remain strictly validated when present, while
new launches attach null values for both obsolete fields. Cancellation during
attachment retains the captured proof with denied admission even if the
supervisor has exited; settlement still requires verified retirement. These compact operations
bypass canonical mutation queues, history loading/normalization and progress
generation.
The short state-owned custody gate serializes them with stop revocation. Stop
acceptance retains canonical mutation serialization and publishes its bounded
request/revision/timing/target disposition under that gate before canonical
acceptance. Immediate or mismatched stops deny admission independently of monitor
observation; matching deferred stops retain current-target permission. Interrupted
acceptance cannot reopen a denied reservation. Monitor abort precedes stop-activity
publication; all gate waits and attachment work consume the original deadline.

After verified close and descendant retirement, canonical settlement verifies the
original certificate and records the complete custody log with its exact endpoint.
Journal append/sync, state replacement and progress publication finish before log
removal and canonical clearing. Retries reuse settlement rather than duplicate
facts. Storage cleanup, further preparation, availability, checkpoint advancement
and ownership release wait for that lifecycle. A reservation remains visible to
lock-free ownership projections and blocks worktree reclamation. Recovery never
releases an old attempt: it reconciles attachment, applies the shared retirement
policy, and settles the same endpoint. An incomplete final record
can be removed only after original-prefix verification and phase-specific
no-launch or retirement proof. Truncation binds the inspected file's identity,
observations and exact prefix length, then rechecks the synced prefix and
handle/path evidence; changed or completed tails retain ownership.
Missing or conflicting authority stays reserved.
An orphan custody log also rejects state and ownership reads after cold canonical
rollback; a lock-free read first reloads to recognize concurrent reservation
publication or settlement.
Neither attachment nor admission proves that the probe ran, exited, or passed.
Canonical replay enforces reservation, immutable authority, settlement and clearing
in order; custody transitions cannot change workflow state or validation evidence.
Live custody-prefix evidence survives history-checkpoint eviction, and repeated
recovery reuses irreversible revocation without exhausting the bounded log.
Ordinary trusted-command execution retains its existing canonical process path.

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

The private `acquisition.js` primitive shares artifact declaration normalization
with the snapshot contract. The trusted executor invokes it privately after
journaling verified allocation ownership. The caller supplies an exclusively
owned mode-0700 directory handle, never a destination filename. Descriptor-relative
exclusive partials are hashed while streaming, synchronized, and published without replacing
existing entries under their lowercase SHA-256 names with mode 0444. Identical
digests share one published file, but every declared URL is acquired and verified.
Cleanup rechecks entries against the open file's identity and preserves substitutes.
Earlier verified files can remain after a later failure; callers must not expose
an incomplete acquisition and remain responsible for the owned directory.
The service exposes the dependency directory only after the complete request
succeeds, all transports retire, and allocation and subdirectory identities are
rechecked. Every execution acquires fresh files from its frozen declarations;
resume cleans previous allocations before downloading again.

Acquisition performs one DNS phase with one A and one AAAA lookup, one resolver
try each, and at most 64 combined answers. It rejects the entire answer set if
any address is not public unicast and pins one numeric destination.
The conservative address policy excludes IPv4 special-use ranges and IPv6 outside
2000::/3, plus special-use, documentation and transition ranges within it. The
declared hostname remains the HTTP Host and TLS verification name; the actual
peer must match the pinned address. Each request uses a fresh connection, explicit
Node built-in trust roots, TLS 1.2 or newer, no proxy environment, and a 16 KiB
header limit. Only HTTP 200 and identity content encoding are accepted; redirects,
ambiguous framing, incomplete bodies, and integrity mismatches fail closed.

Limits are 64 MiB per file and 256 MiB across a sequential acquisition, including
repeated digests. DNS has a 5-second deadline, connection establishment 10 seconds,
body/header inactivity 15 seconds, and the whole acquisition 5 minutes. Cancellation
and deadlines prevent subsequent publication. Requests, responses, and sockets
must close before publication or partial cleanup; retirement has a separate
1-second bound. Unverified retirement retains the partial for owned recovery.
The live service retains the resource while transport closure is uncertain and
rejects concurrent recovery; closure permits cleanup retry. Recovery also checks
the journaled acquisition owner, even after lease release and service
reconstruction.
A live or unverifiable owner blocks cleanup unless that same service observed
transport retirement. A dead or replaced owner permits confined cleanup. Late
callbacks cannot publish files. Errors expose finite acquisition categories,
not URLs, response bodies, or native transport diagnostics. Tests inject DNS,
HTTPS and deadline scheduling without network access.

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

Scratch and cache mount only at `/run/agent-runner/scratch` and
`/run/agent-runner/cache`. They provide `AGENT_RUNNER_SCRATCH`/`TMPDIR` and
`AGENT_RUNNER_CACHE`/`XDG_CACHE_HOME`/`npm_config_cache` respectively (npm uses
`/run/agent-runner/cache/npm`). These bindings are runner-defined; project
configuration chooses only the capability booleans. Without source projection,
build output must explicitly target scratch. Dependencies mount only at the read-only
`/run/agent-runner/dependencies`, with `AGENT_RUNNER_DEPENDENCIES` bound to that
path. Files use their declared lowercase SHA-256 digest as their name. No partial
file is exposed. Artifact-only requests allocate storage even without scratch or
cache. Extraction or setup must be part of the exact declared command and target
declared scratch; the runner does not extract archives or install host tools.
Without source projection the repository mount remains read-only; system mounts
are always read-only and networking remains private.
These capabilities do not change the agent sandbox.

`sourceProjection: true` makes the Git boundary materialize the immutable HEAD
selected by the pre-execution repository snapshot plus the exact current
tracked and non-ignored untracked content represented by its staging-independent
content fingerprint. It neither materializes staged blob content from the
mutable index nor carries ignored untracked files, and it never copies `.git`.
The owned allocation is journaled before its destination exists, and the source
directory must match its allocated device/inode before any source write.
Descriptor-anchored writes and a final kind, mode, size, and content-hash
comparison verify the complete owned tree before execution. Its root and
source-directory identities are also verified before and after materialization.
The executor rechecks the original repository snapshot before launch, mounts
only that source directory writable at the canonical project path inside the
namespace, and uses it as the command's working directory. Original worktree,
index, Git metadata, state, task paths, credentials, and undeclared host storage
are absent. The check may create or rewrite projected files, but those effects
are discarded with the owned allocation after the complete process tree
retires. A final repository guard rejects external or original-repository drift,
and accepted evidence retains the source content, HEAD, command-identity,
ordered-command, trusted-configuration, and validation-infrastructure bindings.
Stale content or HEAD, substituted directory identities, incomplete
materialization, projected entries overlapping protected control paths, runtime
mounts that would expose an external protected path, and uncertain cleanup fail
closed without reusable output.
Preflight checks storage-root writability and rejects fixed mount targets that
overlap protected paths before provider work; allocation rechecks that policy.
Private storage also cannot overlap system, executable, or PATH exposures;
the sandbox rechecks this before mounting. Protected Git paths include canonical
directory-symlink targets and shared metadata reached through Git directory
pointers or `commondir` files.

Common run-envelope version 9 adds private `executionResource` ownership next to
`executionProcess`. Legacy envelopes normalize it to null and migrate through the
existing leased journal transition without filesystem allocation, provider work,
or changes to session/progress evidence. Status reads never allocate or clean
resources. The resource record carries a random execution ID, host, command
identity, private root device/inode, and allocation phase; the allocated phase
also records the execution directory device/inode. Common run-envelope version
10 adds the `acquiring` phase, which journals the runner PID and boot/start
identity before transport activity. Version-9 state and journal records retain
their original closed allocation contract and load without writes; leased
migration preserves ownership, command identities, and progress without new
resource effects. The runtime compatibility token changes with this version.
Verified retirement restores `allocated` before launch or cleanup; only those
exact identity-preserving transitions are accepted. Acquisition journal failures
retain ownership and report the bounded resumable ownership blocker. Resource ownership is never publicly projected.

The trusted executor creates a runner-owned mode-0700 parent under the runner's
temporary directory, disjoint from project, task, Git metadata, and runner state.
A journaled allocation intent precedes exclusive per-execution directory creation;
verified identity is journaled before downloading, materializing source,
exposing mounts, or launching a process. The execution directory owns its
dependency and optional source subdirectories as well as scratch/cache; the
acquisition phase records transport ownership separately from command process
registration.
Directory creation is synchronized before publishing allocation identity, and
declared storage entries are synchronized before acquisition or launch. Cleanup
synchronizes removal before clearing journaled ownership, including retries
after removal.
Descriptor-anchored directory operations and identity checks reject symlink
substitution. Only declared scratch/cache subdirectories and the exact declared
source projection are mounted writable.
No mutable cache is reused across executions, including after interruption.

Each runner-trusted validation command derives its deadline from the validated
run snapshot. The public `trustedCommandTimeoutMs` default is 60 minutes, and
capability preparation uses `Math.min(timeoutMs, 10_000)`. The service has no
construction-time timeout override, so no second deadline of this operational
class can bypass the per-run configuration contract.
Preparation starts one absolute `process.hrtime.bigint()` deadline before
launch, including durable registration through observed close. The runner and
supervisor compare that same monotonic deadline after registration and at
payload admission; queued IPC never starts a new relative allowance. Expiry or
cancellation permanently closes release authority. Pending registration, IPC
callbacks, and verified retirement drain before completion, even after expiry;
uncertain publication or retirement retains ownership. A registration deadline
failure is distinguished from observed isolation failure, and an unobserved
payload exit or signal remains null rather than copying launcher status or a
requested termination signal. Preparation still runs only the empty sandbox
probe and grants no required-check evidence.

Command completion, failure, timeout, and cancellation retire descendants before
confined cleanup and repository mutation checks. Resume and operator-stop recovery
retire any recorded process before cleaning saved resources, even when interruption
preceded process registration. Cleanup uses the recorded root, not a newly selected
temporary directory. A missing child can be cleared idempotently. An existing child
without a journaled verified identity, a replaced directory/root, or uncertain
process ownership retains evidence and ownership for explicit recovery; the runner
never guesses which directory to remove. Checkpoint settlement and releasing
ownership remain closed until cleanup succeeds. After an operator restores the
recorded directory or removes an independently verified orphan, resume retries
cleanup before any new work. Acquisition failures return bounded, redacted
`BLOCKED` check evidence without launching the command. They and resource cleanup
uncertainty preserve an `environment_blocked` FINALIZE checkpoint and never attest the check. Cancellation
preserves the abort outcome after safe cleanup; uncertain retirement retains
ownership and blocks settlement.

The finalization agent returns `NOT_RUN` only for those selected entries; after
the agent turn reconciles, the root executor replaces each placeholder by
running the exact persisted executable/argument vector directly without a
shell. On Linux it requires bubblewrap and runs with a private network
namespace. The trusted sandbox selects `native-sandbox-provider` ownership;
the service and exact-command executor forward that mode to the owned-process
launcher so it probes the complete nested isolation shape. The trusted sandbox
explicitly creates its own user namespace, matching the nested probe rather than
relying on Bubblewrap's host-dependent implicit user-namespace selection. Executions whose
sandbox does not select a mode retain ordinary ownership. The trusted command's
isolation profile and process-containment requirements remain unchanged.
Before agent work, the root resolves bubblewrap only from fixed
system locations to a canonical absolute executable whose file and ancestor
directories are not writable by the runner identity. Project-relative or
project-writable `PATH` entries never participate, and resume and execution
reverify the pinned path. The namespace contains minimal read-only system mounts
and either the read-only repository view or the declared writable source
projection, private temporary storage, a hidden ambient home, private runtime
storage, and a finite non-credential environment. Isolated loopback
listeners remain available inside the command namespace, but raw host Unix
daemon and control sockets are masked.
A Docker daemon must be rootless, and every service must be command-owned inside
the same mount, network, and PID namespaces, so it cannot gain host mounts or
networking and is retired with the complete process tree. Remote network and
filesystem writes, hosting credentials, Git credential helpers, and ambient
authentication variables are unavailable. A private PID namespace and an outer
process group give every completed, readiness-confirmed command one fixed
one-second grace period for remaining descendants to retire naturally
regardless of exit code, then provide bounded TERM/KILL retirement when the
group remains active.
Timeout cleanup begins immediately. A one-byte readiness signal emitted inside
the completed isolation profile
distinguishes setup denial from an executed check failure without exposing
native output. The runner retains no stdout or stderr and records only bounded
status, exit/signal/timeout data, command identity, and fixed evidence.
The selected workspace snapshot before and after each command rejects mutation.
Directory checks use filesystem snapshots and exact read-only declared mounts,
including external references and controls, without invoking Git. They reject
Git source projection rather than granting repository or copy authority.
Normal and recovery cleanup rediscover current directory controls before
deleting owned storage. Changed pointers into an allocation or unverifiable
confinement retain both the allocation and its ownership record.
Preparation, execution and subsequent boundary-check errors preserve that
retention status so the live runner keeps its private lease handles for a
same-instance cleanup retry before any new work.
Persisted allocation ownership also preserves the run handle when configuration
drift replaces the cleanup error with a safety pause. Saved configuration and
workspace blockers reconcile owned execution and storage before returning;
restoring controls permits cleanup but never replays the blocked checkpoint.
Git snapshots reject workspace, index,
history/ref, remote-configuration, or identity mutation, and the complete
validation-infrastructure fingerprint is recomputed after trusted execution.
Missing isolation, an unterminated process tree, skipped, changed,
non-allowlisted, substituted, unmatched, or fingerprint-drifting checks fail
closed. The final evidence tuple binds agent and runner results to the same
content, validation-infrastructure, ordered-command, and trusted-configuration
fingerprints. This service does not broaden any agent turn's sandbox and
introduces no daemon or shell DSL.

The deadline changes only timeout behavior. It cannot make an incompatible
sandbox succeed or recover diagnostics discarded by the output-retention
boundary. Consequently, a full repository check may pass on the host yet fail
closed in trusted isolation with only a generic nonzero exit code; increasing
`trustedCommandTimeoutMs` neither explains nor fixes that difference.

The private `trusted-validation/test-attribution.js` producer/codec and
`scripts/test-reporter.js` cooperate with `scripts/test.js` through an optional
canonical request in `.agent-runner-test-attribution` under the existing
`AGENT_RUNNER_SCRATCH` binding. The request carries a fresh nonce and exact
command identity. An exclusive claim binds the original harness PID before test
launch; only its direct reporter children can update the preallocated report.
Both fast batches share that report, and selected slow files use the same
structured event stream. Reporting mode discards native output and performs no
diagnostic reruns; ordinary developer diagnostics retain their existing behavior.
Discovery, batching, order, concurrency, temporary storage, and original
exit/signal handling remain unchanged.

The complete canonical UTF-8 report is at most 4,096 bytes and retains at most
four locations independently of event count. Each location contains only a
canonical repository-relative test-source path of at most 256 UTF-8 bytes,
nullable integer line/column coordinates from 1 through 1,000,000, and a
metadata-derived class: `test-failure`, `subtests`, `timeout`, `cancelled`, or
`uncaught`. Titles, messages, assertion values, stacks, stdout/stderr, external
paths, and provider data are excluded. Invalid requests/reports and unavailable
storage cannot change test outcomes. This is producer-only infrastructure:
the trusted service neither allocates requests nor consumes reports yet, and
pipeline evidence and retry authority remain unchanged.

Plan execution can retry these opaque failures through an explicit resume from
an `environment_blocked` finding-resolution pause. Pipeline policy recognizes
only a complete persisted match between failed runner checks and their generated
issues, with no agent failure or other unresolved work. After input, repository,
and failure-fingerprint revalidation, one write-ahead transition clears terminal
evidence and enters complete `FINALIZE`, retaining candidate acceptance and
correction accounting. A repeated failure rejoins resolution and does not retry
automatically. The trusted executor's authority, output-retention policy, and
mode-specific confirmation gates remain unchanged; the
[execution specification](../pipelines/plan-execution/docs/SPEC.md) owns eligibility.

Before plan execution or polishing accepts a producing role's bootstrap or
legacy validation-migration inventory, and before either pipeline fingerprints
finalization evidence, the root Git or directory boundary verifies repository
validation entries are existing regular files whose canonical repository-relative
paths exactly match the proposed paths. The configuration capability inspects
the exact selected finalization-file label against its frozen root; external
labels retain their distinct `finalization://` namespace. Missing files,
directories, symlinks, and paths traversing a symlink are field-specific
violations; the runner does not follow or silently canonicalize them. Plan
execution collects every inspectable violation from the candidate into the
owning bounded bootstrap or finalization diagnostic batch, and a repeated
invalid result fails closed. The deterministic aggregate is therefore derived
only from independently accepted canonical role evidence.
Plan execution and polishing additionally reject each staging-dependent
required command with bounded field-specific diagnostics before accepting that
producing result; plan execution batches all such independently detectable
violations, and the same policy rejects a finalization candidate inventory
without delegating index ownership to an ordinary Worker turn.

An explicitly supplied source session is different. In independent and combined
modes, the
first eligible turn of each new primary or review checkpoint creates a direct
child and returns its ID without resuming or mutating the source. In lazy mode,
only the first eligible primary turn may create that child, and the durable
one-time marker forbids later source forks even when a native session must be
reconstructed. For failures without availability evidence, if an eligible `spawn` or `initialize` launch failure occurs
before a lazy fork can create a child, the same atomic availability-pause
transition restores the one-time marker. Resume then makes the run's single
fork for the same logical role. Recovery at `session` or `turn_start` is removed
from a fork request and the request becomes non-resumable because a native child
may already exist without durable lineage; recorded children are continued or
reconstructed and never reforked.
If the source cannot otherwise be forked, the turn fails before agent work
rather than silently losing lineage.

Adapter failures retain only bounded diagnostics. Every adapter classification
produces the same closed record: `failureClass`, `checkpoint`, `outcome`,
`effect`, and `retry`, with optional commit-executor proof, finite availability
reason, and an optional sanitized process outcome containing only an exit code
or signal.
`commitExecutor: "not_started"` is valid only at the `commit` checkpoint with
`none` or `possible` effect evidence; it is invalid with `started` evidence or
at any other checkpoint. Checkpoints are `probe`, `spawn`, `initialize`,
`session`, `turn_start`, `turn`, or `commit`; outcomes, effect evidence, and
retry eligibility are likewise finite shared vocabularies. The shared launch
classes cover process exit and version, argument, protocol, and configuration
incompatibility. Deterministic incompatibilities are terminal; process-exit
eligibility remains explicit in the record. The contract rejects unknown
fields, unbounded values, and contradictory combinations. Capability probes
produce a proof containing the version, required capabilities, and the existing
`adapter-capabilities-v1` policy receipt.

The root boundary derives launch recovery only from that validated record and
never from raw provider causes. The frozen projection contains exactly the
normalized failure class and checkpoint. Without availability evidence, fork
requests retain it only at
`spawn` and `initialize`; a later eligible checkpoint keeps its normalized
failure record but cannot enter pipeline retry policy. All other requests may
retain any eligible launch checkpoint. CLI and MCP status read the same
persisted projection, including through an operator pause. Accepted resume
removes it with the pause, while terminal cancellation removes it from the
retained private checkpoint.

Codex capability, isolation, prohibited-operation, and recognized App Server
failures and Claude session, profile, authentication, backend, capability,
configuration, usage, provider, permission, and process failures remain native
recognition owned by their provider directories. The root agent boundary
validates the descriptor classification once, derives pipeline control
properties only from the shared record, and maps an unclassified cause to a
terminal rejected outcome with possible effects. When an ambiguous provider
turn precedes a local commit, the record retains its possible provider effects
and may separately prove that the isolated commit executor never started. The
boundary derives `effectStarted` solely from that validated record; raw cause
fields cannot override it. It does not duplicate backend class lists or
traverse native cause chains. Every pipeline may persist the normalized class
for a terminal failure and projects it only through a deterministic CLI/MCP
explanation. Native messages, additional details, denied input, provider
responses, prompts, commands, credentials, transcripts, and process causes
never cross that boundary or enter durable state.

Codex `subAgentActivity` or another collaboration audit signal remains a
terminal `operation_multi_agent` isolation failure even though collaboration is
disabled at launch. A backend that ignores that disabled capability cannot be
accepted, reclassified as an environment blocker, or transparently retried.
Context exhaustion and interruption retain their dedicated recovery paths.

Interrupted one-shot effects are also different. In particular, a
`local-commit` turn is never replayed; control returns to the runner for pending
authorization and Git-state verification. Backend policy, profile, provider,
or turn rejection before the isolated executor may record
`commitExecutor: "not_started"`; the derived `effectStarted: false` proof
permits authorization renewal only after Git verifies that the effect did not
occur. It never makes the consumed authorization replayable.

Each state transition is a small write-ahead transaction:

1. append and sync a complete journal record containing the next state;
2. atomically replace `state.json` using a temporary file and rename;
3. atomically regenerate the derived `progress.md` projection.

Revisions start at `1` and remain contiguous. Recovery ignores and removes only
an incomplete final event fragment, rejects malformed durable records, advances
a lagging `state.json` from the last complete event, and regenerates stale or
missing progress. Valid event history is never discarded.

Each journal segment has the same 64 MiB writer and reader ceiling. The initial
segment remains `events.jsonl`; before an append would exceed its ceiling, the
writer atomically publishes a complete first event in the next contiguous
`events-000001.jsonl` segment (then `000002`, and so on). State replacement and
progress publication follow that event, including at rollover. At most 1,024
segments (64 GiB total headroom) are permitted; exhaustion rejects publication
with `ERR_EVENT_LOG_LIMIT` while retaining the readable accepted history. No
segment is compacted, overwritten during rollover, or discarded. The state cap
leaves enough room for one complete event and metadata within a segment.
Active waits observe segment publication as well as current-state replacement,
including interruption between those two durable boundaries. Replay retains
one bounded segment source, adjacent states, and the current stop's compact
checkpoint/acceptance proof, rather than all historical snapshots. Public
activity and recovery proofs use the same validated prefix; derived progress
is atomically streamed to disk. Replay memory therefore does not grow with the
number of segments, and no authoritative record is removed to save memory.

Each store instance may retain at most eight validated journal checkpoints with
a combined 16 MiB serialized footprint (counting shared references conservatively).
A checkpoint contains only the last two adjacent events, the current stop's
continuity proof, segment bindings, snapshot metadata, and bounded public
projection records. Each validated scan produces an operation-local prefix
certificate independently of optional checkpoint admission. It binds the run,
first and last revisions, directory identity, ordered contiguous segment names,
and each segment's revision endpoints, file identity, and exact `[0, length)`
byte range and digest. Before reuse, safely opened files stream fresh SHA-256
digests over every certified byte prefix and compare them to the original bindings.
The scan re-lists the recognized journal namespace before certifying its result.
Directory device/inode, mode, and ownership must remain stable; unrelated
choosing/ready claims and derived/control publications may change directory
timestamps or size without changing journal history. Full before/after file
handle and path observations, including link count and change time, must remain
stable across consumed-byte reading and semantic validation. Timestamps alone
grant no reuse. Changed bytes, replacement, namespace races, or unavailable
proof invalidate reuse conservatively without extra retry allowances.
Only appended records then need normalization and continuity validation. Every
read still rereads and validates `state.json` and proves its exact event match;
snapshots older than the retained adjacent pair require complete replay.
Cold reads, cache overflow, and eviction retain complete validation; missing
optional cache evidence is not a corruption diagnosis. Partial
tails are never cached, and failed publication discards retained checkpoints,
including any populated by publication callbacks. No checkpoint is authoritative
or persisted. Certificates retain no historical state sequence. Full history
and recovery-proof APIs continue canonical replay.

Cold validation and validated suffixes collect public activities with their
revision, timestamp, redacted dispatch message, and event-specific public stop
summary. Each checkpoint retains at most 1,024 activities and 1 MiB of serialized
activity data, also counted within the combined checkpoint cap. Overflow evicts
the oldest activities and retains their last revision as a coverage boundary;
it never drops authoritative events or retains historical states. Activity
pagination uses the retained range only when it covers the requested cursor.
Older requests stream one byte-certified record at a time, decoding only its
public projection through the owning activity and legacy stop normalizers.
They do not repeat semantic validation of unchanged historical states. A page
drains and verifies the entire original prefix even after reaching its limit;
no partial page escapes a failed digest, identity, or namespace observation.
Cursors still advance across revisions without activity and stop at the last
returned activity when a page is full. Stream observations cannot distinguish
an owner's append or rotation from an edit, so they stay unchanged. When a
lock-free page's drain fails with `ERR_INVALID_EVENT_LOG`, the journal's
`extendSnapshot` reloads through the original certificate as publication proof:
every original binding's digest, identity, link count and stable observation,
the recognized namespace, and continuity of the appended records. Only a
certified snapshot with a strictly later revision, passing the same custody and
state-root checks, permits exactly one second drain under the same cursor and
limit rules. Proof is unavailable only for `CheckpointInvalid`, which includes
a certificate-bound segment that can no longer be opened safely; then the
original error is rethrown. Every other extension failure, such as runtime
version skew, invalid or unsafe state, a filesystem or programming error, and
any authorization or second-drain failure propagates. The extension writes
nothing, takes no lease and populates no checkpoint.

Progress publication uses retained records when they cover the complete run;
overflow uses the same certified record stream with identical text. An
operation-local certificate survives cache eviction or oversized checkpoint
rejection. Missing bindings require one bounded canonical scan to certify the
same snapshot before projection streaming; unavailable proof rejects publication.
Certificates cover only complete consumed records, so partial tails stay
uncached while their complete prefix can still serve a verified projection.
Publication certifies the appended event before callbacks, then checks its
original prefix after every callback, including failures. Snapshot rollback or
callback-populated checkpoints cannot substitute different history. Canonical
matching of a lagging snapshot retains the original prefix's byte proof through
the same scan. Progress replacement occurs only after the complete stream's
proof; publication failure rechecks the original certificate without masking an
existing safety error.
Post-publication snapshot verification remains bound to that certificate and
never passes null evidence as a reusable checkpoint. Recovery repairs partial
tails and lagging snapshots before atomically regenerating progress from the
same certified prefix. Tail repair retains bounded filesystem observations
separately from the immutable semantic certificate. Before truncation it proves
the original consumed ranges and digests, exact recognized namespace, directory
identity and captured file observations through safe file access. It truncates
and syncs only the incomplete active tail, then proves that same prefix and
namespace with stable handle/path observations and the exact repaired size.
Only successful verification returns an immutable snapshot with post-truncation
observations and `hasPartialTail: false`; the original capture, certificate,
state and revision endpoint remain unchanged. The journal recovery wrapper
returns this value to `recoverRun`, which uses it for ownership checks and
observation retirement through `persistObservations` and `appendTransition`.
Independent appends also consume their own repair result. No latest-history
reload or callback-populated checkpoint substitutes for the original proof,
and read-only observers never authorize repair. Failed publication or recovery
discards retained evidence, including callback reads.
Runner monitoring and MCP activity/wait consumers continue using the state
capability; they own no projection cache or additional polling.

Lock-free readers discover an ordered segment prefix after reading current
state, prove every revision and cross-segment transition, and reject missing,
misnamed, oversized, or incomplete sealed segments. Only the last segment may
have an incomplete tail; leased recovery truncates that tail and republishes
lagging state and derived progress. Existing single-file journals load without
migration of their records on read. Common-envelope version 21 and detached
compatibility token `1:21` established the segmented format. New runs use
version 24 (`1:24`); legacy runs require an explicit leased migration publishing
a version-21-or-newer record in the original journal before rollover is permitted.
Even if state replacement is interrupted, older readers reject that original
journal instead of ignoring later segments and appending conflicting revisions.
If the original segment lacks space for the migration record, publication fails
with `ERR_EVENT_LOG_LIMIT` and retains the legacy history; migration cannot
silently publish its barrier in a new segment. Readers reject segmented history
without the original-segment barrier. Segment paths are reserved from
run-artifact writes.

Events may carry an optional bounded public activity record containing only
`actor`, `phase`, `kind`, and a concise one-line `message`. Pipelines derive
these messages from validated structured results; the state service validates
only their generic form. Cursor-based readers expose this projection without
returning private pipeline state, model output, credentials, or unhashed remote
and identity values. Persist concise structured decisions and summaries, never
raw model transcripts or chain-of-thought.

Immediately before every provider invocation, the runner appends and syncs a
complete `turn-started` transition whose next state contains the bounded active
role and pipeline phase. The active turn remains durable while the provider is
blocked and through repository or one-shot-effect reconciliation, then a
second write-ahead transition clears it. If the process stops first, the stale
activity remains without a live execution owner, even while its lease record
awaits stale recovery. A resumed owner
reconstructs the request from durable pipeline state, replaces ordinary stale
activity when it starts the reconstructed turn, and clears a one-shot commit
activity only after Git verification deterministically resolves the consumed
authorization. Native sessions, polling, model-token heartbeats, and daemons
are not part of this correctness path.

Before an ordinary interrupted turn is reconstructed, the runner revalidates
the canonical project and task directories and the owning pipeline revalidates
every durable task, context, plan, and accepted clarification input. The root
Git boundary then compares the persisted snapshot with the current repository.
Read-only turns still require an unchanged workspace and index. An interrupted
polishing Worker may retain content drift only for a phase that originally had
workspace-write authority; any index drift is rejected. Plan execution retains
its owning pipeline's one-shot commit reconciliation rules. `HEAD`, branch and
detached state, local refs, remotes, Git identity, canonical root, and allowed
runner paths must remain unchanged. The pipeline advances its baseline only
after those checks, invalidates its fingerprint-bound gate evidence when
content changed, and charges interrupted correction work once.
The reconstructed request uses the complete recovery prompt in a fresh native
session, and its `turn-started` event replaces the stale marker before normal
post-turn reconciliation clears it. If a correction transition was already
persisted before process loss, recovery clears its retained marker after the
same input and Git checks and continues from the advanced checkpoint without
replaying or recounting the correction. Consumed one-shot commit turns remain
on their verification-only path and are never reconstructed or replayed.

Every mutating run or resume holds one atomic per-run execution lease. Plan
execution and polishing also hold one atomic lease for the canonical Git
worktree throughout workflow execution and runner-authorized clarification
writes, preventing independently identified runs from mutating the same
worktree concurrently. Status and public activity reads acquire neither lease.
A competing owner is rejected. A current same-host lease is recoverable
immediately only when its complete boot/PID/start identity proves the exact
owner dead or replaced; the reclaim marker and mutation boundary recheck that
identity and the opaque token before atomic replacement. Acquisition age does
not delay recovery and never proves that ownership ended. Legacy,
identity-free, foreign-host, live, invalid, and unverifiable records remain
non-reclaimable. Release verifies the opaque owner token before removing a
lease. Pipeline-declared run artifacts are
atomically replaced beneath the run directory, with absolute paths, traversal,
reserved state files, and symlink escapes rejected. Managed state and lease
paths must be isolated regular files rather than symbolic or hard links.

At MCP startup, the root freezes one bounded detached-compatibility token
derived canonically from the detached protocol version, root run-envelope
compatibility tuple, and the sorted ID/state-version pairs of every loaded pipeline descriptor. Detached
launch passes that token in an internal environment field. After loading its
own registry, the child independently recomputes and compares the token before
acquiring a run lease, recovering state, or evaluating a migration. A mismatch
uses a distinct exit status that the parent converts to an actionable
version-skew error; `state.json`, the journal, leases, the durable run, and the
incomplete idempotency intent remain exactly at their pre-dispatch state for an
exact-key retry after the MCP process is restarted. Client disconnect and wait
cancellation still affect only the client-side operation.

For a bootstrapped installation this protocol runs inside the already pinned
payload. Payload and Node-identity admission happen before child application
imports; compatibility and dispatch admission still happen before run effects.
Replacing the outer npm path cannot redirect either the current server or its
detached continuation to another application tree.

## Clarification Lifecycle

Every pipeline starts with an explicit, pipeline-owned `CLARIFY` state. Its
primary agent studies the task and repository read-only, then returns `READY`,
structured questions whose answers could materially change the required
behavior, scope, or planned work, or a pipeline-owned blocking outcome.
`--clarify` opens the text editor before that turn so the user can add context
proactively; otherwise the editor opens only when the agent asks a question.

The fixed protocol limit is three agent question rounds for every pipeline.
Empty artifacts and authorized editor closes without changes consume no round.
Exhaustion pauses instead of extending the dialogue indefinitely; this is an
ambiguity-resolution bound, not a configurable duration or workflow budget.

The root runtime owns the common mechanics under `src/clarifications/` behind
its public `index.js`: creating the `clarifications.md` artifact, invoking
`$VISUAL` or `$EDITOR`, appending question rounds, and hashing the result.
Pipelines own the artifact location, prompt, round limit, transition out of
`CLARIFY`, and safe re-entry after an exceptional product decision. This is a
bounded preparation protocol, not a general chat or dialogue engine.

Before the first clarification turn, the runner creates the Markdown artifact
when missing and otherwise preserves its existing transcript. Keep the format
intentionally simple: the runner appends questions without rewriting prior
content. An existing empty clarification artifact is valid and must not be
replaced with a template. Closing an authorized editor without changes is also
valid. Both cases require no user text and do not consume an agent question
round. Unanswered questions already appended by an agent still require a
response.

During an authorized editor window, the resulting user edit is accepted as new
clarification input and invalidates every dependent result. Changes outside an
authorized editor window remain unexpected input changes.

MCP never launches `$VISUAL` or `$EDITOR`. It projects a pending edit as a
structured request with a stable ID, kind, identified questions and options,
rationale, artifact path, and run revision. An empty answer set is valid only
for optional proactive clarification. `run_respond` requires exactly one
non-empty answer for every identified question, preserves the supplied text,
and rejects stale or already answered requests. Editing the artifact externally
and calling `run_resume` remains available. A controlling agent answers from
explicit user context or asks the user; it must not invent a material product
decision.

```markdown
# Clarifications

## Context

<!-- Optional user context. -->

## Round 1

### Q1

Question text.

Why it matters: concise impact on scope, behavior, or planned work.

### A1

<!-- Write the answer here. -->
```

Product-decision pauses append a separate `## Product Decision N` section with
the question, concrete options when available, blocking evidence, and a user
decision field. After the authorized editor closes, the runner persists the new
artifact hash before re-entry. Store no model chain-of-thought or full agent
transcript.

Before opening the editor or pausing for an answer, persist the suspended
pipeline state, pending editor action, and last accepted artifact hash. Resume
accepts an edit only for that pending action and returns to the pipeline-owned
safe re-entry state. The authorization is one-shot and is consumed when the
editor closes or a resumed edit is accepted.

Repository-local clarification artifacts may be created only after
`git check-ignore` confirms the target repository ignores their resolved paths.
The runner never edits target ignore rules automatically.

When clarification closes, the runner freezes the artifact hash. Normal work
prompts prohibit further questions. An agent may return the structured
`PRODUCT_DECISION_REQUIRED` outcome only when progress is impossible without a
material product decision that existing task, plan, repository, conventions,
and clarification evidence cannot resolve. The runner pauses for the user and
invalidates dependent work after the answer; it never invents the requirement.
If the decision invalidates completed commits or the validated plan, the runner
requires a revised plan and a new execution run instead of rewriting history.

## Shared Plan Contracts

`@agent-runner/commit-plan` owns the deterministic commit `plan.md`
representation and subject validation consumed by authoring and execution.
`@agent-runner/custom-plan` separately owns an explicit `custom` kind, agreed
criterion IDs/conditions, input/output declarations and contiguous titled steps
with scoped work, expected results and criterion references. It validates closed
shapes and reference coverage, parses readable Markdown with a JSON declaration
and serializes canonically; analysis-only plans may declare no file outputs.
Its [package contract](../packages/custom-plan/README.md) owns the exact syntax.
Neither package owns prompts, roles, permissions, result acceptance or workflow
transitions. Declarations grant no filesystem, retrieval or Git authority.
Plan authoring consumes both contracts with an explicit descriptor-owned
`planKind` defaulting to `commit`. `criteriaPath`, `sourceReferences` and
`outputPaths` resolve through the same precedence and freeze in authoring state.
Dynamic workspace selection reads confined configuration through filesystem
inspection before Git preflight, then enforces Git ignored/untracked rules for
commit selection. Filesystem discovery checks configuration in the requested
directory before using the repository-root fallback for preliminary commit
selection. A local project configuration may select custom while retaining
that directory and its relative declarations; the enclosing repository supplies
only its canonical exclusion key. Commit selection canonicalizes the workspace
and retains the exact selected configuration file. The configuration boundary
resolves preliminary settings without requiring project-supplied role backends.
Artifact binding checks the final merged declarations for overlap with inputs,
sources and configuration; preliminary discovery cannot reject declarations
superseded by project overrides. Directory bindings also protect inputs,
infrastructure and controls before publication.
The descriptor's optional `resolveTaskInputs` supplies exact
additional read files; declared local sources bind content, identity and ancestors.
Custom selection uses the directory capability, exclusively read-only roles and
only task-owned artifact exclusions in long-lived baselines. Per-turn snapshots
still permit no artifact mutation. Output declarations confer no write paths and
retrieval permissions remain empty. Before creating a clarification transcript,
the runner discovers any enclosing Git worktree and requires its resolved path
to be ignored and untracked; ordinary-directory artifacts need no Git command.
The bounded clarification output adds agreed result criteria, normalized through
the shared contract before freezing. Canonical declarations and required step
scaffolding must leave 4,000 characters for step content within the unchanged
100,000-character draft budget before clarification can close. Deterministic
publication matches the complete custom header to
that frozen catalog and source/output selection. Authoring state version 7
migrates legacy runs to commit-only defaults without changing authority or
progress. Unchanged default commit inputs preserve existing session-context and
pending source-fork recovery keys.

Plan execution's private `step-policy.js` consumes both deterministic contracts
and isolates parsing, step/criterion context, workspace inspection, initial
content-change requirements, role access/capabilities and terminal effects from
its existing mode and review policies. `commit-workspace.js` retains two-pass
Git preflight, ignored artifacts and stale-plan inspection; the one-shot commit
route obtains Git effects only through the commit policy. Custom analysis needs
no artificial diff, uses only the already bound directory snapshot capability,
and cannot obtain commit authority. Explicit CLI/MCP/configuration selection enables custom execution through the same mode and finding loops. Execution state version 33
requires `planKind`; version-32 migration adds `commit` without changing any
gate, consumed effect, accounting or refinement eligibility. Legacy execution retains commit semantics and its existing session context.

Execution state version 34 adds nullable `customResults`; version-33 migration
sets it to `null` without inventing acceptance or output authority. Commit runs
reject non-null custom ledgers. The pipeline-owned checkpoint validates a
bounded, receipt-chained ledger over frozen criteria/inputs/permissions,
analysis/evidence and exact output fingerprints, including link resolution hops
and readable target trees. It consumes the shared mode-specific gate predicate
but never obtains Git effects or advances workflow
progress from a provider success claim. Revision-bound state transitions journal
pending acceptance before verifying and settling the same record on recovery.

The workspace capability owns exact output-directory inspection and preparation.
The runner's bound directory facade checks frozen controls and configuration,
and the existing stop monitor guards effects. The pipeline descriptor authorizes
creation only against the exact persisted root and private-state allocation
intent. Preparation pins the new directory in private durable state before
publishing it through an owned, no-clobber move. Missing roots require state
storage on the same filesystem and `/usr/bin/mv` supporting GNU coreutils 9.4's
`--no-clobber --no-copy --no-target-directory`; unsupported moves fail closed,
without copying or replacing an arriving directory. Existing roots need no move.
The directory descriptor stays open through identity verification and parent
synchronization. The execution workflow atomically saves the prepared identity
with a baseline allowing only that exact empty-root creation; intervening output
edits cannot be adopted. No workspace siblings or parents are created, and provider
mount authority stays unchanged. The runner returns refreshed state after
process retirement so the identity transition retains revision checking.
Cancellation is checked immediately before allocation and publication. Lost
creation proof, substitutions, drift and pending
stops preserve unfinished evidence and fail closed. Earlier accepted outputs
are verified on reconstruction; invalidated acceptance requires a revised plan
and new run. The [execution specification](../pipelines/plan-execution/docs/SPEC.md)
owns ledger bounds and the accepted-result completion contract.

Execution state version 35 adds nullable current custom-result data, a separately
pinned writable provider-policy receipt and a commit-default `planKind` setting;
migration creates neither custom authority
nor acceptance. `custom-workspace.js` adapts directory inspection without Git
effects; filesystem identity never masquerades as Git identity. Result
fingerprints include bounded analysis/evidence and workspace content. Custom
result fingerprints also bind the active authorized clarification version,
advanced only after read-only plan compatibility; earlier receipt versions and
immutable input/permission bindings remain unchanged. Custom
bootstrap supports criterion-dependent empty command schedules, retaining exact
trusted catalog provenance. Explicit guidance is optional and `auto` supplies
no automatic coding gate. All mode-required candidate gates precede finalization
and distinct terminal confirmation; only journaled `ACCEPT` settlement advances
the custom cursor. Result-only repairs clear dependent evidence. Interrupted
publication reconciles its exact receipt without replaying a model effect.
The runner supplies descriptor-selected role access. Custom startup proves
read-only access, then exact writable access is probed after journaled output
preparation and before use. Execution persists that separate receipt before the
first writable turn and reproduces it before later writes, including on resume;
policy drift fails closed without replacing the frozen startup receipt.
Missing directory roots require explicit trailing-slash declarations. Existing
file outputs grant no parent write. Legacy and commit execution retain their
Git effects, exact subjects, nonempty initial implementation and one-shot recovery.

## Global Safety Policy

Every pipeline inherits non-negotiable runner controls:

- no remote writes, pushes, or hosting-service mutations;
- no remote configuration or Git identity changes;
- no `Co-authored-by` trailers;
- active mutation checks around read-only turns;
- no repository-local clarification artifact outside an already ignored path;
- state outside target and task repositories;
- explicit pause on unsafe or unrecoverable state.
