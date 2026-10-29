# Testing

The [test-authoring skill](../.agents/skills/test-authoring/SKILL.md) owns test
necessity, minimalism, and determinism. Regressions belong around reproduced
defects and fragile boundaries, not around every edit.

## Ordinary gate

`npm run check` runs formatting verification, the fast test tier, and CLI help.
Its development budget is approximately 60 seconds. The fast tier retains
contract, policy, provider, Git, state, and focused integration checks.
`npm test -- path/to/file.test.js` runs selected coverage.

Fast `test/runner-authoring.test.js` owns public custom-authoring composition:
configured selection before Git, read-only provider declarations, frozen criteria
and source bindings, source-drift recovery, repository-local clarification ignore
requirements, artifact-only publication and non-Git commit rejection.
It also covers configuration/artifact collisions without byte replacement,
protected control destinations and canonical repository-root configuration
lookup when commit authoring starts from a subdirectory, while explicit,
globally configured and project-selected custom authoring retain their supplied
directory scope. Supplemental commit-authoring reads tolerate unrelated ignored
external links while detecting declared source-tree drift.
Artifact separation also covers effective project overrides of global
declarations.
MCP start recovery retains a reserved custom workspace after global plan-kind
defaults change, while preserving exact-request idempotency.
Pipeline-owned `workflow.test.js` covers all three
custom authoring gates, missing criteria, declaration correction and legacy
commit defaults with fake effects. Its regressions cover canonical criterion
publication, aggregate serialized declaration budgets before freezing, and correctable canonical draft expansion.

Fast `test/runner-custom-execution.test.js` uses lightweight transitions and
workspace effects for sequential analysis/output execution in all three modes,
criterion-bound gates, result-only repairs, output-preparation baseline recovery and drift rejection, bounded malformed-output correction, trusted provenance and interrupted acceptance. Repository-contained coverage also checks canonical exclusion and untouched Git controls.
Semantic-only finalization failures retain their issues across reconstruction
and require result repair and fresh combined gates without invented checks.
Root creation still proves descriptor selection, configuration and declared permissions.
Boundary validation and creation cover a project commit-kind override of a
runner custom default before plan parsing.
Focused reconstruction coverage rejects writable provider-policy drift before
another turn while preserving startup receipts, accepted results and permissions.
`test/runner-custom-execution.slow.test.js` owns real leased authoring-to-execution
composition and accepted-result recovery without Git; run it when changing public
custom selection, directory role probing, custom orchestration or settlement.
Its slow invocation is `npm run test:slow -- test/runner-custom-execution.slow.test.js`.
Fast recovery cases cover compatible authorized decisions before acceptance and
after an earlier receipt, fresh gates for the new clarification version, and
rejection of unauthorized drift or an answer invalidating accepted results.
The pure result-checkpoint suite rejects stale clarification approvals; execution
contract tests retain legacy finalization/trusted-check defaults in every mode.
The existing root orchestration, effect, stop and CLI/MCP slow suites retain their
separate guarantees and remain applicable to their documented boundaries.

Fast `packages/custom-plan/test/custom-plan.test.js` owns the pure custom-plan
contract: analysis/output plans, immutable parsing, canonical round trips,
closed declarations, explicit kind compatibility, sequential steps and complete
criterion references. It needs no Git, provider, command execution or temporary
storage. Commit-plan syntax remains covered by its separate package suites.

The fast `test/workspace/inspection.test.js` suite owns the filesystem-only
directory boundary: non-Git snapshots, enclosing and nested controls for the
workspace and external reads, Git pointer/shared and bare metadata, pointer
dependencies nested in protected controls, aliases hidden by dot segments,
redundant reads, protected output overlap, state-control exclusion through
workspace and unrelated state ancestors (including workspace metadata targets) and
provider aliases without added reads, nested state-only metadata pointers and
cycles, canonical workspace targets and writable intermediary dependencies of
ancestor provider aliases, protected cross-control skill links, content/identity drift,
unrelated sibling creation during alias resolution and routing-directory replacement,
escaping intermediate links, mutable hops across writable boundaries, hard links,
special files, exact UTF-8 filenames, undecodable names and deterministic
read/ancestor races.
Temporary directories and injected filesystem effects need neither Git nor live
providers. Workflow/provider integration remains separately owned as those
consumers land. Fast `test/agents/codex.test.js` owns the public adapter's
directory request/probe contract, access-specific receipts without Git or commit
preparation, native output-only permissions, protected-write rejection, effective
policy substitution, literal-path rejection for glob syntax, reconstruction,
observations and attempt retirement. It uses ordinary temporary directories and
model-free transport fixtures; live
provider/platform acceptance remains separate. Fast `test/agents/claude.test.js`
also owns Git-free directory proofs, access-specific immutable receipts, native
and fallback output-only command projection, protected external read mounts,
execution of the fallback probe payload against its emitted mount topology,
rejected write mounts, output substitution during allocation and admission,
missing nested artifact/state exclusions, post-failure mutation guards,
reconstruction and unsupported isolation. Controlled launchers preserve deterministic coverage;
the operator-owned post-install Claude acceptance below remains separate.
Retiring completed and failed turns retain Claude allocations when changed
control pointers reference storage or cannot be inspected, then permit the same
owner to clean up after restoring controls without replaying the turn.

Fast `test/runner-directory.test.js` owns descriptor-selected Git-independent
lifecycle composition: access-specific probes, frozen policy/configuration,
task-input rejection before content reads or provider probes,
near-limit declaration/storage-exclusion compatibility through the public adapter,
confined clarification artifacts, interrupted output reconstruction, failed-turn
mutation guards, canonical worktree contention (including confined Git control
aliases against legacy root leases without scope records), rejection of outputs
inside nested ordinary/linked worktrees under a held Git lease, operator pause/resume
and filesystem-bound trusted checks with exact external read mounts. It also covers
rejection of sibling state storage inside an enclosing repository before provider
probes or state creation, and trusted cleanup retaining allocations and Runner
lease handles after control-pointer overlap or malformed-pointer drift during
execution or preparation, followed by same-instance recovery without replay.
Coincident configuration drift exercises both `run()` and `resume()`, including
saved-blocker cleanup with configuration still changed or restored and release
of both leases without new provider work.
Other cases cover parent/child output contention, concurrent admission across
service instances, exact-key recovery of stale overlapping reservations, and retirement of owned
process/resources before configuration/input-drift pauses and pending-stop
settlement, including deleted inputs and actual confined storage cleanup.
Interrupted Claude recovery retains allocations and same-instance lease handles
when Git control pointers are malformed or reference owned storage, then permits
cleanup after restoring the pointers without accepting frozen-input drift.
Live cleanup failures also retain both Runner leases until same-instance
recovery removes the allocation and persists the input-drift blocker without
replaying the turn.
Clarification submissions and resume also reject newly created optional task
inputs without changing the transcript or pending authorization, or probing
providers. Coincident and ancestor task roots retain drift protection for
undeclared project content while allowing explicitly declared task artifacts.
Frozen-input identity drift blocks trusted
execution and capability preparation before service invocation. Injected
descriptor workflows isolate lifecycle behavior from pipeline execution; selected
trusted command execution is faked rather than invoking project checks.

The fast state `preservation.test.js` suite owns unfinished-work capture and
checked restoration through the public state/Git boundaries. Isolated
repositories cover binary/link/mode/deletion round trips, mixed-index
preservation, checked file/directory and symlink/directory replacements in both
directions, empty replacement directories, interrupted capture and restoration,
cancellation retention, future work after a child commit,
substitution rejection, destination edits during final blob reads and
version-22 migration without invented authority. Capture-record substitution
during prepared-file publication is rejected before replacement. Recovery cases
include interrupted parent sync after replacement or deletion,
temporary creation before identity publication and interrupted writes after
identity publication, with content and inode substitution rejection. Parent
creation is covered before and after durable identity publication, including a
failed blob read before temporary preparation. The slow
`runner-orchestration.slow.test.js` suite covers public Runner resume with
unsettled and settled version-22 preparation custody before envelope migration
and pending-stop settlement, without new agent or check work.
Preserved replacement execution consumes these primitives only after reviewed
revision acceptance and complete capability discovery. Common envelope/journal
changes also require the affected durable state, effect,
stop, migration and MCP workflow suites listed below; focused probes do not
replace those gates.

The fast execution `effective-plan.test.js` suite owns flat revision validation,
completed provenance, versioned finding payloads and inherited ownership,
maximum-sized finding batches, logical stop mapping, mode-specific
plan approval, stale scope/check rejection and idempotent interrupted acceptance.
It also covers unchanged-text reproposals after binding changes and persisted
lineage proposal limits, including historical grants across step advancement.
It uses pure policy plus one lightweight execution-state fixture. Version-29
migration adds empty authority without inferring approval or touching pending
effects; the durable legacy-migration and runner-orchestration suites own
persisted migration composition.

Its progress cases also cover proposed/accepted/executing/completed refinement,
atomic justification, exact original headings, display labels, measurements and
verified child SHAs without mutating authority, original Markdown body preservation,
and deferred legacy progress until size settings migrate. Fast `runner-plan-progress.test.js`
owns confined publication, interrupted replacement, missing/stale regeneration,
ownership/link/ignore rejection, ancestor substitution during ignore checks
without redirected writes or leaked temporaries, and inert manual Markdown
claims. Controlled overlapping publications cover serialization, stale-revision
suppression, same-revision retry and consumed-commit deferral. CLI and MCP unit
suites cover the shared projection and current-snapshot
activity revision.
The slow Runner orchestration suite additionally proves interruption after
durable state publication, deferral of artifact failures throughout consumed
COMMIT, and regeneration after verified commit settlement without duplicate
commit effects or changing the frozen plan. Progress ownership conflicts also
cover durable pause/cancel settlement and run/worktree lease release, including
reconciliation initiated during run-lease release, without overwriting the
conflicting file or invoking an agent.

The fast execution `revision-validation.test.js` suite owns accepted-revision
and exact-replacement bindings, mode-required complete role inventories,
additive commands/reports and future applicability, unchanged correspondence,
stale schedules and implementation evidence, interrupted bounded units and
version-30 migration without fabricated proof. It also covers confirmed amendment
command/infrastructure omissions on acceptance and reload, and rejects inherited
assignment omissions while their owning unit can still be corrected. Pure policy
and controlled bootstrap effects keep these cases deterministic. Durable legacy migrations,
effect recovery and Runner orchestration remain separate slow-tier obligations;
focused source tests do not establish their acceptance.

The fast execution `replacement-execution.test.js` suite owns new-run activation,
all-mode replacement gates, the exact threshold, preserved source reconstruction,
interrupted acceptance/restoration, consumed-commit verification without replay,
correction isolation from later unsplit steps,
bounded references for large cumulative captures, request admission before
restoration, inaccessible binary sources and absent admission support without
candidate removal, versioned sibling finding decisions and same-ID active version changes,
revision-discovery capacity
and product-decision outcomes, compatible-answer resume before and after a role
receipt in all modes, refresh after a verified sibling, and renamed owned-finding
rejection, interrupted clarification-bound plan rejection before any new effects,
correction-grown splits with interrupted restoration and revision-discovery
answers in all modes, clarification after an amendment on a later sibling,
and suspended versioned reconsideration requests across reconstruction, mixed
fix/dispute refinement in independent and combined modes through interrupted
restoration and recorded withdrawal,
read-only refinement contamination stops, exact output-exhaustion checkpoint
reconstruction, unchanged rejected-plan repair pauses, and disabled legacy
migration. Input-drift and read-only-contamination cases retain historical
inventories after revision preparation, including pending restoration.
They also cover the interval after receipt archival and before rediscovery.
Controlled effects keep it independent of native sessions. The
existing state preservation suite also covers verified manifest/blob references for saved
binary/deleted content and rejects new or changed restoration authority during
stop reconciliation. The slow runner-orchestration suite owns real leased
preservation, restart after restoration publication, and immediate pause/cancel
recovery after a path write; the slow state
operator-stop suite owns deferred logical-boundary admission, recovery and
settlement across verified children, including unborn baselines, and legacy
boundary admission/journal replay before migration.
These additions retain the existing exact slow commands and full
slow gate; focused checks do not replace their required acceptance.
The provider suites cover exact-file admission without model turns: Codex keeps
root reads separate from temporary write exclusions, and Claude rejects binary
sources hidden by the selected runner-boundary command masks. The runner policy
suite checks admission forwarding after immutable policy-receipt validation.

The test launcher uses a private temporary directory on executable runtime tmpfs
when available, otherwise the system temporary directory. This removes physical
disk latency from disposable fixtures without mocking filesystem operations or
disabling production synchronization. Set `AGENT_RUNNER_TEST_TMPDIR` to choose
an explicit writable, executable parent; an invalid override fails visibly.
Without an override, the launcher never uses a parent at or under Agent Runner's
fixed trusted mount root `/run/agent-runner`, using the sandbox's private `/tmp`
instead of the scratch mount inside trusted validation.
The parent must remain visible inside process namespaces; `/dev/shm` does not,
because their private device mount hides it. Runtime tmpfs (`XDG_RUNTIME_DIR`
or Linux `/run/user/<uid>`) avoids that conflict.
The launcher reports storage and total elapsed time and removes only its own
directory. Fast runs use the concise dot reporter. Selected and complete slow
runs use the concise spec reporter, which also reports the elapsed time of each
file without enforcing a duration limit. These tests exercise process recovery,
not survival of a machine power loss. Fast files use bounded host-aware
parallelism. The two system-wide process containment suites run in a separate
bounded batch so their process inspection cannot race unrelated file workers.
The durable slow tier retains its proven four-file concurrency bound.

The optional scratch-request reporter collects only bounded failure locations
from the original invocation, across both fast batches or selected slow files.
It streams structured events without capturing native output or running
diagnostic retries. An exclusive original-harness claim prevents nested harnesses
from updating its report. Ordinary developer runs retain their diagnostic
behavior, including the original failure outcome if a diagnostic rerun passes.
Request allocation and report consumption by trusted execution are inactive;
focused fixtures exercise the producer without granting check evidence.
`test/trusted-attribution.test.js` owns codec, redaction, bounds, claim and stream
coverage; `test/test-command.test.js` owns actual original-harness invocation,
batch partitioning, selected slow files, nested claims and storage cleanup.
The [validation contract](product/VALIDATION_AND_REVIEW.md) owns advisory limits.

## Slow gate

`npm run test:slow` runs every `*.slow.test.js` file. Both tiers together cover
all test files; neither silently excludes a failed test. Use
`npm run test:slow -- path/to/file.slow.test.js` to run an affected file, or
pass multiple paths for one affected batch; selected files retain the same
bounded runner and per-file timing output.

| Suite                                                                     | Distinct observable guarantee                                                                                     | Run when changing                                                                                                                       |
| ------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| `test/integration/cli-workflows.slow.test.js`                             | Root CLI composition produces one plan artifact, one exact-subject commit, and one uncommitted handoff            | CLI projection or root plan-authoring, plan-execution, polishing, real-Git commit, or handoff composition                               |
| `test/integration/mcp-workflows.slow.test.js`                             | A detached MCP workflow continues through durable runner state after the requesting client is replaced            | MCP-to-runner workflow composition, detached continuation, client replacement, or cross-capability durable state                        |
| `test/mcp/control-plane.slow.test.js`                                     | Detached STDIO dispatch preserves protocol cleanliness and exactly owned durable intents and receipts             | MCP STDIO, detached starts or stops, action receipts, disconnects, waits, restart or version skew, or execution-owner contention        |
| `test/runner-orchestration.slow.test.js`                                  | Root orchestration preserves configuration, sessions, migrations, trusted snapshots, and worktree order           | Runner configuration or source sessions, runtime migration, trusted preflight snapshots, worktree serialization, or root service wiring |
| `test/runner-operator-stops.slow.test.js`                                 | Runner stops settle owned processes and raced commit or handoff effects without losing writable content           | Runner operator stops, process settlement or containment, commit or handoff races, execution-storage cleanup, or partial-content resume |
| `test/runner-effects.slow.test.js`                                        | Commit effects settle exactly once across interruption, verification, and deferred checkpoints                    | Runner Git/state effect dispatch, commit authorization or verification, deferred settlement, or consumed-effect recovery                |
| `test/state/operator-stops.slow.test.js`                                  | State journals preserve bounded replay, stop publication, leases, ownership transfer, process identity, and races | State actions or journals, publication boundaries, leases, process identity, worktree ownership transfer, or stop concurrency           |
| `pipelines/plan-execution/test/legacy-confirmation-recovery.slow.test.js` | Journal-proven legacy confirmation reconciles one real commit through rejection, crash, and lease cases           | Plan-execution legacy confirmation eligibility or proof, journal publication boundaries, verified commit recovery, or execution leases  |
| `pipelines/plan-execution/test/legacy-migrations.slow.test.js`            | Authentic persisted migration history carries legacy confirmation proof into the current contract                 | Persisted plan-execution migration composition involving confirmation proof, inventories, implementation evidence, or historical events |
| `pipelines/polishing/test/handoff-recovery.slow.test.js`                  | Legacy handoff recovery distinguishes a completed real-Git effect from a partial effect                           | Polishing handoff settlement, legacy handoff migration, completed-effect reconciliation, or partial-effect failure                      |

Run the affected slow coverage once before handing off a change to the listed
contracts. After the ordinary `npm run check` gate, run the complete
`npm run test:slow` tier as the release gate. A documentation-only or unrelated
policy edit does not require replaying all durable workflow matrices. Record
exactly which tier/files ran; an unrun slow check is not a pass. Do not move a
test to this tier merely because it fails or has a slow fixture: first remove
redundant setup and use lightweight effects for policy. Pure migration
validation remains in the fast tier.

## Finalization

The canonical finalization skill applies both directly and inside Agent Runner;
there is no second divergent test policy. Establish affected slow checks before
work. Plan execution discovers a complete procedure for each canonical plan
step: `npm run check` applies to every step, while a slow check applies only to
steps changing its documented guarantee. Persist those assignments at bootstrap
and retain later checks for their owning steps. Trusted selection alone does
not make a command applicable to every step. Polishing retains its single
workspace inventory.

Run each applicable slow batch for the finalized fingerprint with the existing
concurrency. Reuse accepted evidence on unchanged-fingerprint confirmation
resume; repairs or invalidated evidence require fresh affected validation.
Preparation of the complete trusted catalog is separate from check execution.
Keep the ordinary gate as `npm run check`; never fold slow matrices into it.
The fast execution `validation-schedule.test.js` uses injected effects to cover
two-step selection in all modes, persisted reload, confirmation reuse, and
migration of pending rework and correction accounting.
The fast execution `step-policy.test.js` covers explicit plan-contract selection,
criterion context, analysis without an artificial diff, directory-only inspection,
absence of custom Git effects and explicit execution entry points. Its lightweight
all-mode fixtures verify that adding persisted kind preserves consumed commit
verification without another provider turn or renewed accounting. Existing
stale-plan, implementation-evidence, refinement and commit-safety suites retain
their distinct behavioral coverage. Persisted kind changes also require the
affected runner and legacy-migration slow coverage listed above.
The fast execution `custom-results.test.js` owns criterion-bound analysis and
output acceptance, receipt chaining, all-mode gates, interrupted publication,
input/output drift, accepted symlink target/intermediate-link drift and stops.
Real leased journal cases verify interruption during private allocation and before and after prepared-root
identity publication and output settlement without Git; other cases use lightweight
effects. `test/workspace/output-directory.test.js` owns exact-root preparation,
existing-content preservation, absent-parent rejection, ambiguous creation,
substitution before first root inspection, competing empty-directory publication,
owner loss before identity publication without sibling drift and
descriptor-confined effects under parent replacement. Runner directory coverage
owns cancellation during output preflight and the supervised no-copy publication
contract. Persisted checkpoint and
workspace-effect changes retain the affected runner, state-stop, integration
and legacy-migration slow coverage above; focused tests replace none of it.
The fast execution `bounded-bootstrap.test.js` uses lightweight effects to cover
multi-step discovery and batch acceptance, persisted interruption and reload,
role isolation in all modes, output subdivision, migration exhaustion pauses,
catalog correction, drift, read-only mutation guards, compatible inventory
migration, and confirmation provenance after rediscovery. Pure
`bootstrap-units.test.js` owns partition, binding, and malformed-coverage
rejection. Durable runner and legacy-migration slow suites own actual journal,
lease, and consumed-effect composition; changing bootstrap activation or its
persisted migration requires those affected suites.
The runner orchestration slow suite additionally proves that output-exhausted
Reviewer observations and the exact unfinished applicability unit survive runner
replacement, and that both role inventories finish before combined writable
entry. The focused state observation suite proves an accepted 2 MiB result
survives interrupted write-ahead publication without truncation. These protect
cross-capability composition rather than repeating the pure unit contracts.

Live provider tests remain opt-in as described in the repository README. Normal
tests never consume model turns. Repeated full-suite runs require a specific
unresolved risk, not a ritual.

The fast Git `change-measurement.test.js` suite owns staging-independent text
counts and separate binary paths, mixed staging, ignored files, index-hidden
changes, raw newline handling, link confinement, path replacements, exact size
inputs and stale-candidate rejection. It uses isolated repositories through the
public Git service; measurement itself runs no tests or agents and changes no
index or history. Adding this unused capability does not change workflow,
migration or effect ownership and requires no durable slow workflow matrix.

The fast state `journal-checkpoints.test.js` suite owns namespace certification:
real repeated choosing/ready claims during controlled directory observations
must preserve unchanged-prefix reuse, while cold reads validate every event.
It counts durable event decoding rather than timing or optimistic read attempts.
Controlled segment publication during suffix validation proves that recognized
namespace changes require canonical proof or rejection. Existing adjacent cases
retain segmented growth, replacement, restored-mtime tamper, cache eviction,
partial-tail recovery, publication interruption and complete projection coverage.
Journal changes also require the state/operator-stop and legacy-confirmation
slow coverage, plus the affected MCP workflow and control-plane composition
listed above; focused namespace fixtures do not replace those durable gates.
The same focused suite separates projection decoding from state normalization
and exercises record-count and byte-tail eviction separately and together,
checkpoint entry/combined-byte eviction, oversized unretained checkpoints,
missing evidence before/during/after streaming, and repeated real control claims
during overflow reads. Early-limit pages prove unread ranges; atomic progress,
callback failure, historical tampering with snapshot rollback, partial tails,
and legacy/redaction equivalence retain their original-prefix checks. A controlled
historical edit during lagging-snapshot matching also proves that canonical
validation cannot replace the original publication certificate. The state
slow suite's bounded-heap journal case also covers overflowed projections,
complete progress, old cursors and repeated transitions across segments.

The fast state `recovery-failures.test.js` suite owns the public state boundary
for pre-lease and pre-readiness diagnostic publication, interrupted publication,
exact dispatch/child correlation, immutable retries, absent historical causes and
redaction. It does not establish detached launcher or CLI/MCP projection behavior.
The fast MCP control-plane suite owns exit/signal forwarding and structured,
redacted tool-error projection, including unavailable causes and failed journal
inspection after child exit or control-plane replacement. Retry regressions cover
both resume lease checks and stop status/ownership checks before dispatch,
retaining correlated causes without receipt completion or a replacement child.
The fast state safety suite covers exact context-derived action reads without
mutation or weakened tool/argument matching. The CLI suite
owns safe explanations at execution-lease and state-recovery failures. The slow
MCP control-plane suite composes the real launcher, IPC admission, CLI diagnostic
publication, restart with unknown exit facts, ownership exclusion and identical-key
receipt recovery. It retains the existing STDIO protocol-cleanliness coverage.

Claude restricted-host launcher changes use deterministic public-adapter tests
with controlled bubblewrap processes for the commit gate. That coverage must
compare every x64 and arm64 BPF instruction, reject unsupported architectures
and filter tampering or setup failure, prove direct bubblewrap execution with
one user namespace and no fallback Claude helper, and retain provider
connectivity, environment scrubbing, argument rejection before payload
execution, and the complete command-isolation argument contract.
Access-policy coverage also proves that one compound `git log`, `git cat-file`,
`git branch -a`, and `ls` inspection succeeds in the read-only sandbox while
representative workspace, Git, and remote mutations fail, local-commit
readiness uses the same policy, and workspace-write settings stay unchanged.
One bounded capability-gated Linux process regression exercises the installed
bubblewrap direct-filter boundary without a model request, sleep, retry loop,
or slow-tier promotion. It does not replace post-install acceptance: after the
finalized commit is installed, the supervising agent starts a fresh real Claude
lazy plan-authoring run and requires preflight to advertise read-only,
workspace-write, and local-commit access plus a provider response before
dependent provider work continues.

Preparation custody regressions extend `test/state/journal-checkpoints.test.js`'s
real growing/rotating journal fixtures and normalization counters with byte,
hashing and publication work. The monitored service/executor/supervisor path
covers cold, warm, evicted and oversized checkpoints, nullable execution and
polishing targets, delayed stop observation, deadline/cancellation (including
supervisor exit before attachment's first identity check), both admission race
orders, owner replacement, partial-tail replacement/completion during repair and
endpoint-bound interrupted settlement/removal, and orphan custody after cold
canonical rollback. Existing journal tamper/rollback/rotation,
full result and process-custody proofs remain required. Runner orchestration covers both pipelines'
preparation retirement and canonical settlement before pending-stop completion
after owner replacement. This lifecycle affects every slow-suite
row above, plus the complete slow release gate; focused synthetic regressions do
not replace the operator's post-install saved-case acceptance.
