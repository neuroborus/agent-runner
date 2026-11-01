# Testing

The [test-authoring skill](../.agents/skills/test-authoring/SKILL.md) owns test
necessity, minimalism, and determinism. Regressions belong around reproduced
defects and fragile boundaries, not around every edit.

## Ordinary gate

`npm run check` runs formatting verification, the fast test tier, and CLI help.
Its development budget is approximately 60 seconds. The fast tier retains
contract, policy, provider, Git, state, and focused integration checks.
`npm test -- path/to/file.test.js` runs selected coverage.

Fast `test/runtime-payload.test.js` owns complete manifest/dependency/resource
inspection, read-only modes, isolated storage, interrupted and concurrent
preparation, substitution and drift rejection, delayed imports and development
checkout behavior. Exclusive publication covers an empty destination arriving
after the last absence check, preserving its identity, permissions and contents.
Unpublished sealed trees and references outside their sibling namespace are
rejected. Coverage also rejects missing bootstrap modules and lost private
storage permissions on existing payloads. It uses neutral constructed packages and never touches a live
controller. `test/runtime-pinning.slow.test.js` owns actual pre-import startup,
delayed resource/dependency reads and the real detached launcher after outer
replacement, plus launch rejection after payload drift. Its synthetic application
uses no providers, run store, native links, package installation or activation.
Runtime fixture teardown verifies its freshly created root identity, restores
write/search access only to owned fixture directories through descriptors, and
never follows links or changes the enclosing temporary-storage permissions.
Read-only fixture files need no permission change for removal.

Fast `test/state/runtime-admission.test.js` owns serialized admission/activation,
deferred restart, positive owner recovery, namespace/identity uncertainty and
write-ahead interruption without replay. It injects process observations and
uses only owned state storage. Fast `test/runtime-admission.test.js` verifies
CLI/MCP lifetime and Runner create/run/resume gates, old pinned resources after
outer replacement, retirement, state separation and development-managed bypass.
Its in-process MCP fixture supplies controlled positive process observations;
production admission still requires native owner identity and namespace proof.
Unavailable owner metadata must deny startup before state creation.
It also covers actual STDIO EOF retirement and caller-input mutation after
candidate verification.
Existing runtime-pinning slow coverage retains actual detached-process proof;
the new admission tests require no providers, host census, signals or installs.
Recovery also covers a consumed activation after owner loss and colliding PIDs
in separate namespaces before the first runtime projection is published.
Controlled concurrent admissions prove that a pending activation wins the next
safe boundary and rejects an obsolete racing start. Recovery binds that pending
selection to its consumed action across owner loss and intervening retirement;
active and deferred receipts also recover after intervening admissions without
republishing their selectors. A superseded selection retains its replay barrier;
historical projections gain no inferred authority, and a newer explicit choice
supersedes an older pending request.

Fast `test/release-assembly.test.js` owns isolated lock-closure assembly, real
private workspaces, nested dependencies, executable modes, allowlist exclusions,
metadata/resource/link rejection and no-overwrite output behavior. Synthetic tar
fixtures prove archive byte/mode identity, path confinement, extended-header
validation and link/extra-file rejection without npm or processes. `test/release-pack.slow.test.js` owns actual
offline npm packing and exact archive inspection of the current application,
complete immutable preparation, pinned standalone imports and operator-guide completeness. It performs no installation,
provider call, global link change or controller activation.

Fast `test/release-publication.test.js` owns approved stable-release selection,
commit/tag/main binding, complete validation ordering, exact artifact receipts,
version-integrity retries and partial-failure policy with injected effects.
It performs no npm, Git, registry, account, tag, hosting or publish effects.
Publication stays disabled in checked-in policy. Release automation ownership
and administrative approval requirements are in [RELEASING.md](RELEASING.md).

Fast `test/update.test.js` owns on-demand official identity gating, version
ordering and explicit prereleases, no-update success, Node/configuration/state
compatibility, registry/permission failure redaction and body bounds. Registry
effects are injected; no request, installation or provider is used. Small confined
runtime fixtures separately prove read-only running/installed inspection and
linked-checkout preservation using the existing positively owned teardown.
Source package compatibility declarations are checked against their owning
configuration, state and pipeline contracts. Existing slow/package requirements
remain unchanged.

Fast `test/update-candidate.test.js` owns exact candidate selection, archive
integrity/resources, installed-payload verification, interrupted/partial install
reconciliation, permission/smoke failures and substituted-storage preservation.
Focused durable-action cases retain actual leased receipts and ownership
across interrupted effects; other policy cases use lightweight action effects.
Neutral confined payloads prove previous-payload retention and owned smoke
teardown. npm/registry/smoke effects are injected, and a native-vector case
asserts the filesystem mounts, private PID namespace and network policy without
launching a process. A controlled clock proves retirement after command deadline
expiry; intent-write failures retain redacted results and clean positively owned
smoke allocations. Recovery coverage rejects token-owned uncertainty and ignores
unrelated reused sessions even after their new leader exits. This is not
native-platform acceptance.
Activation coverage holds a pinned MCP admission through deferred selection,
then verifies next-start selection, exact detached pinning, retained previous
payloads and consumed-effect recovery without a second publication. A saved run
remains byte-identical across activation; explicit later leased migration retains
its frozen configuration and consumed commit, while an unsupported forward
pipeline version preserves progress. These cases use the real state action/lease
boundary with injected native effects, without restarting a client or executing
the saved run. Existing Runner slow coverage retains full resume orchestration.
Lifecycle projection rejects malformed persisted versions without returning their
text or performing registry/native effects.
Existing package-install acceptance retains real CLI/MCP protocol and offline
installation ownership; its separately assigned exact invocation remains
required alongside complete slow coverage.

`test/package-install.slow.test.js` owns actual offline installation of the exact
inspected candidate tarball into a new private prefix outside the checkout. It
checks installed bytes/modes, Node metadata, real private workspace imports,
the executable on PATH, CLI help/version, MCP initialize/list-tools/read-only
discovery and transport-EOF shutdown. The installed processes use only bundled
dependencies, with no checkout module resolution, workspace links, inherited
Node overrides, personal settings or live providers. The test consumes the README
install vector and the server commands from both client-registration examples;
it never invokes clients or writes their registration. Delayed guidance remains
complete after moving only the fixture's outer package, and shutdown retires the
fixture admission without creating a run or project artifacts.
All home, XDG configuration/state/data, npm/Node cache and smoke storage is
private and disposable under the declared scratch/cache capabilities. Every
owned child is awaited before the existing descriptor-bound runtime fixture
cleanup restores only its own directories' write/search access and removes them.
No active controller, existing global/native link or publication is changed. This suite
proves local Linux installation/protocol acceptance, not live-provider or new
native-platform support. Required coverage is never satisfied by an unrun or
failed invocation; complete slow includes it and replaces no separately selected
`npm run test:slow -- test/package-install.slow.test.js` requirement.
Release CI may supply `AGENT_RUNNER_RELEASE_CANDIDATE` pointing to its exact
candidate receipt. That path verifies the archive/manifest, source commit and
lock identity and installs a private copy of the verified byte snapshot, without
repacking or reducing assertions.
Both the separate package-install command and complete slow still run. An unset
variable retains fresh candidate assembly for ordinary local validation.

Fast `test/config/user-settings.test.js` owns deterministic user-location mapping,
legacy fallback, invalid/unsafe path rejection, private exact-byte migration,
permissions, conflict/no-op behavior, competing publication, interruption remnants and settings survival
across replaced installations and development links. It uses isolated settings
and actual confined filesystem effects, never personal configuration or a live
controller. Existing configuration tests retain project precedence and authority;
runner configuration tests retain frozen-resume coverage. CLI tests own early
migration dispatch and argument validation without creating a runner.

Fast `pipelines/audit/test/report.test.js` owns the pure audit report contract:
strict evidence/examples and classification values, shared-cause consolidation,
stable severity/ID ordering, optional recommendations, separate uncertainty,
zero findings, and safe catalog-derived Markdown. It uses no providers,
processes, Git repositories, or temporary storage.
Fast `pipelines/audit/test/discovery.test.js` owns frozen scope, read-only discovery,
lazy/independent session isolation, duplicate/revised candidates, pending-batch
blocking, invalid/incomplete output, drift, write-ahead interruption and finite
exhaustion recovery using injected root capabilities. It also covers the two-MiB
role-result limit, complete frozen inputs/findings in fresh discovery prompts and
propagation of unsettled execution ownership.
Fast `pipelines/audit/test/verification.test.js` owns all five finding dispositions,
fresh independent versus continuing lazy rechecks, review additions, retained
rejections, version invalidation, stale/malformed/incomplete output, interrupted
reservations, exact acceptance recovery, Auditor-only legacy migration/resume
without fabricated approval or role expansion, and run-wide recheck exhaustion.
It shares injected effect-free fixtures with discovery through the pipeline's
test support index.
Fast `pipelines/audit/test/combined.test.js` owns initially clean and
finding-producing fresh discovery cycles, duplicate and report-only corrections,
same-Auditor batch convergence, correcting Reviewer continuity/additions and
clean-first replacement. Injected capabilities cover invalid/incomplete output,
interrupted reservations, lost-child reconstruction without reforking, rejected
premature acceptance and both finite run-wide budgets across replacement/resume.
Fast `test/runner-audit.test.js` owns audit composition with the existing confined
workspace/clarification services and persisted session contract: authorized
transcript edits preserve discovery, while source drift blocks it. It also uses
actual inactivity, availability and disposition policies with in-memory storage
to cover checkpoint initialization, bounded reconstruction, terminal isolation
failures, authentication/output pauses and source-fork recovery. Normalized
provider structured-output failures remain resumable invalid passes. The actual
transition normalizer proves persistent field/collection overflow is rejected
before acceptance without reducing the two-MiB aggregate role allowance. No provider
or Git process is needed for those policy tests.
Fast `pipelines/audit/test/publication.test.js` owns escaped report-size rejection
before ledger acceptance and resumable retry, exact confirmed/pending
projection, zero/Critical findings, all-mode completion, lost publication
acknowledgement and completion binding with injected effects.
Fast `test/runner-audit-publication.test.js` owns public Runner/CLI metadata and
MCP report projection for Git and ordinary directories, plus actual
confined artifact replacement, exact-byte and partial-write recovery without
replaying accepted discovery, edits and temporary/alias substitution rejection.
The slow `test/mcp/control-plane.slow.test.js` suite owns actual audit MCP
start/respond with optional and material clarification and persisted interactive
CLI editor windows. These real journal/action/lease cases remain outside the fast gate.
The existing slow CLI/MCP workflow, control-plane, runner and state-stop suites
retain durable shared-runtime ownership; focused audit tests replace none of them.

Fast `test/config/external-infrastructure.test.js` covers explicit target/root
bindings, relative resources, placement conflicts, unchanged integrated
discovery, and external configuration/target substitution without target writes.
State persistence covers strict protection-record reloads; authoring composition
also proves external custom selection before Git, frozen-configuration pauses,
exact external selectors from Git subdirectories and rejection of custom scope
widening.

Fast `test/guidance/external-infrastructure.test.js` owns selected infrastructure
guidance for Git and ordinary directories: complete common/local reads without
creation, external updates with unchanged target controls, competing placements,
worktree-bound selectors from Git subdirectories, explicitly directory-bound
targets, shared target/execution and external-destination leases across targets,
stale writers, publication recovery and pinned
configuration/ancestor identities. Pointer-resolved Git metadata, including
nested control dependencies and state-ancestor pointers, and canonical ancestor
provider alias targets cannot become external publication destinations.
Existing guidance content, editor and publication suites retain integrated ignore,
byte-limit and inode-provenance coverage. Publication tests also cover legacy
worktree-relative receipt recovery from Git subdirectories, including incomplete
published intents. Current external actions reject changed selector identities
rather than adopting legacy resolution. MCP guidance tests cover the same
selection through its thin transport.

Fast `test/runner-configuration.test.js` covers relative external selectors in
polishing and external project commit selections overriding runner custom
defaults from Git subdirectories in authoring and execution.

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
Unselected external-guidance labels in custom bootstrap and finalization
inventories receive bounded field diagnostics before workspace inspection.
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

| Suite                                                                     | Distinct observable guarantee                                                                                                       | Run when changing                                                                                                                                  |
| ------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| `test/runtime-pinning.slow.test.js`                                       | Running and detached synthetic applications retain the complete pinned payload after outer replacement; drift blocks another launch | Startup/bootstrap, runtime manifests or storage, delayed resources, Node identity, detached launch                                                 |
| `test/release-pack.slow.test.js`                                          | Actual npm tarball matches the complete assembled production application, real dependencies, modes and resources                    | Release assembly, file allowlists, lock closure, package metadata or runtime resources                                                             |
| `test/package-install.slow.test.js`                                       | Exact inspected bytes install outside the checkout and expose pinned CLI/MCP behavior with complete teardown                        | Packaging/release gates, candidate installation/activation, installed CLI/MCP update contracts, or final provider/operator installation acceptance |
| `test/integration/cli-workflows.slow.test.js`                             | Root CLI composition produces one plan artifact, one exact-subject commit, and one uncommitted handoff                              | CLI projection or root plan-authoring, plan-execution, polishing, real-Git commit, or handoff composition                                          |
| `test/integration/mcp-workflows.slow.test.js`                             | A detached MCP workflow continues through durable runner state after the requesting client is replaced                              | MCP-to-runner workflow composition, detached continuation, client replacement, or cross-capability durable state                                   |
| `test/mcp/control-plane.slow.test.js`                                     | Detached STDIO dispatch preserves protocol cleanliness and exactly owned durable intents and receipts                               | MCP STDIO, detached starts or stops, action receipts, disconnects, waits, restart or version skew, or execution-owner contention                   |
| `test/runner-orchestration.slow.test.js`                                  | Root orchestration preserves configuration, sessions, migrations, trusted snapshots, and worktree order                             | Runner configuration or source sessions, runtime migration, trusted preflight snapshots, worktree serialization, or root service wiring            |
| `test/runner-operator-stops.slow.test.js`                                 | Runner stops settle owned processes and raced commit or handoff effects without losing writable content                             | Runner operator stops, process settlement or containment, commit or handoff races, execution-storage cleanup, or partial-content resume            |
| `test/runner-effects.slow.test.js`                                        | Commit effects settle exactly once across interruption, verification, and deferred checkpoints                                      | Runner Git/state effect dispatch, commit authorization or verification, deferred settlement, or consumed-effect recovery                           |
| `test/state/operator-stops.slow.test.js`                                  | State journals preserve bounded replay, stop publication, leases, ownership transfer, process identity, and races                   | State actions or journals, publication boundaries, leases, process identity, worktree ownership transfer, or stop concurrency                      |
| `pipelines/plan-execution/test/legacy-confirmation-recovery.slow.test.js` | Journal-proven legacy confirmation reconciles one real commit through rejection, crash, and lease cases                             | Plan-execution legacy confirmation eligibility or proof, journal publication boundaries, verified commit recovery, or execution leases             |
| `pipelines/plan-execution/test/legacy-migrations.slow.test.js`            | Authentic persisted migration history carries legacy confirmation proof into the current contract                                   | Persisted plan-execution migration composition involving confirmation proof, inventories, implementation evidence, or historical events            |
| `pipelines/polishing/test/handoff-recovery.slow.test.js`                  | Legacy handoff recovery distinguishes a completed real-Git effect from a partial effect                                             | Polishing handoff settlement, legacy handoff migration, completed-effect reconciliation, or partial-effect failure                                 |

Run the affected slow coverage once before handing off a change to the listed
contracts. After the ordinary `npm run check` gate, run the complete
`npm run test:slow` tier as the release gate. A documentation-only or unrelated
policy edit does not require replaying all durable workflow matrices. Record
exactly which tier/files ran; an unrun slow check is not a pass. Do not move a
test to this tier merely because it fails or has a slow fixture: first remove
redundant setup and use lightweight effects for policy. Pure migration
validation remains in the fast tier.

## Finalization

The fast `pipelines/init/test/proposals.test.js` suite owns the pure
proposal contract: both placements across all modes, unchanged read-only
bindings, selection conflicts, frozen live-configuration protection, preserved
skills and discovered controls, directory/file distinctions, merged guidance
byte-limit rejection before proposal acceptance, frozen clarification
selection, one-shot clarification edits, approval invalidation and bounded revisions.
One focused shared-service case covers append receipts, structured answers and
unchanged answer windows without consuming additional question rounds.
Regressions keep unusable unselected siblings out of placement inspection and
protect exact task artifacts when their directory also contains setup destinations.
Injected read-only capabilities cover actual document hashing and configuration
substitution, including placement edits with unchanged destinations and additive
reinspection that preserves prior input, destination and ancestor identities,
without filesystem publication or provider activity. A focused workspace case
injects directory creation and ancestor replacement between the absence probe,
bound inspection and first snapshot to reject newly occupied external roots.
It also accepts an absent sibling covered by an enclosing task-tree snapshot.
The proposal suite also keeps external finalization references limited to the
target's finalization skills, without invoking unrelated inventoried skills.
That proposal suite establishes no CLI/MCP setup, durable publication or native-provider acceptance.

`pipelines/init/test/integrated-publication.slow.test.js` owns real-Git ignore
semantics and durable multi-resource publication through the public workspace
capability: absent resources, preserved skills/settings and negations, custom
artifact roots, verification-only reruns, file and artifact-directory substitution
rejection, input and frozen-clarification drift, missing closed transcripts,
lost file-receipt recovery, ignore protection on resumed
effects and lease loss after directory allocation. A bare repository occupying
the conventional provider root rejects setup before any prerequisite write. Its
controlled directory publisher and isolated fixtures use no providers. These
full snapshots, fsyncs and Git effects belong to the complete slow tier; pure
proposal policy remains fast.
This establishes integrated prerequisite preparation only, without guidance,
CLI/MCP registration or setup-completion acceptance.

`pipelines/init/test/external-publication.slow.test.js` owns sibling preparation
through the same public workspace effects: canonical-path name separation for
neighboring projects, occupied/wrong-target roots, explicit nondefault selectors,
custom artifacts, preserved skills/settings, lost root receipts and identity
substitution. It rejects ancestor provider storage and canonical alias targets
before publication intents or writes and rechecks them during recovery.
It verifies subsequent configuration/finalization selection and
unchanged Git and ordinary-directory targets, with no ignore inspection or
provider activity. Run it when changing external init publication or its confined
resource policy. Both publication suites belong to the complete slow tier;
`test/runner-init.slow.test.js` owns registered lifecycle composition: both
placements crossed with all three modes, proven unused source-fork recovery
without repeating possible effects, guidance-last publication, distinct
terminal confirmation, CLI/MCP setup projections, repeatable guidance,
resumable rejection of unsafe guidance, malformed configuration and invalid
placement-specific procedures before publication,
renewed proposal gates and actual procedure repairs after terminal findings,
atomic replacement of existing local guidance, pending ignore publication,
enclosing-worktree lease reuse, failed infrastructure-lease release across
same-run resume and stop settlement, lost prerequisite receipts,
intervening guidance edits, authorized pre-closure read-scope extension, and
retired terminal-turn recovery with identity-sensitive provider receipts, frozen
backend authority, and identical-byte guide substitution after a lost acknowledgement.
It also owns stop settlement during reserved proposal turns and clarification
windows, interrupted question/decision publication, structured decision answers
with frozen selections and renewed gates, and concrete CLI/MCP blocker projections.
Successful inactivity and provider-requested reconstruction cover both proposal
and terminal confirmation; interrupted second attempts retain consumption and
produce a resumable CLI/MCP pause before another provider invocation. Managed
guidance coverage verifies the exact finalization path and preserved local text;
the fast proposal suite also verifies metadata replacement when that path changes
on rerun.
The fast clarification lifecycle suite owns exact append-hash replay and
intervening-edit rejection for both shared append operations; the pure proposal
suite covers exceptional decision contracts at every post-closure proposal gate.
It uses neutral directories,
fake providers and a controlled directory publisher; the workspace tests retain
native publication safety ownership. Run it for init lifecycle, setup lease or
guidance integration changes, in addition to the affected prerequisite suites.
Provider/native-platform acceptance remains opt-in.

The fast configuration finalization-file suite owns confined reads and file,
target and ancestor substitution. `test/runner-finalization.test.js` composes
both coding pipelines with exact sibling/external file reads, frozen resume and
legacy selection preservation using lightweight effects. It also covers repository
validation and external guidance sharing a relative path without losing either
inventory identity or repository fingerprint input. Existing provider
suites own exact-read admission and command mounts. These cases do not replace
the durable migration, runner and handoff coverage listed above.

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
