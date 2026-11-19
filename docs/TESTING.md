# Testing

The [test-authoring skill](../.agents/skills/test-authoring/SKILL.md) owns test
necessity, minimalism, and determinism. Regressions belong around reproduced
defects and fragile boundaries, not around every edit.

Fast `pipelines/plan-execution/test/writable-result.test.js` owns durable
checkpoint policy with lightweight existing fixtures: read-only restatement,
exhaustion and explicit authorization, interruption accounting, unchanged content,
blocker ownership, unstarted registration recovery, legacy baseline reconciliation,
custom criterion/output bindings and mode routing. It uses no
provider or dependency installation. `test/runner-effects.slow.test.js` additionally
owns real journal reconstruction preserving an earlier accepted commit and the
candidate through exhausted result recovery, without a duplicate charge or
commit. Changes to this lifecycle require that slow suite and the complete slow
release gate; focused policy coverage does not attest those gates.
The same slow Runner/store/Git suite owns the two-step combined changed-BLOCKED
pause and cold null-action continuation: accepted first commit, retained candidate
and finding reports, once-only repair charge, renewed primary and independent
gates, distinct terminal confirmation and exactly one second commit. Fast
`pipelines/plan-execution/test/combined-review.test.js` owns the distinct
unchanged-BLOCKED and pending-output-correction cleanup branches.
That slow suite also owns real journal reconstruction of a lost polishing
writable finding-resolution report: one invalid read-only restatement, the
explicit null retry, a once-only writable call and fix charge, and the staged
handoff. Fast `pipelines/polishing/test/resolution-correction.test.js` keeps the
policy matrix. Changes to this lifecycle require that slow suite and the
complete slow release gate; focused fast coverage does not attest either.
Operator-stop slow fixtures retain separate prepared and invoked checkpoints:
native containment starts from proven unstarted work, while interrupted effects
resume read-only and keep their consumed accounting.

Fast `test/git/polishing-handoff.test.js` uses isolated real-Git fixtures with
preconfigured ignored hooks and a harmless `post-index-change` receipt outside
the repository. Assertions cover ordinary hook activation, unchanged accepted
fingerprints and configuration, hook-free exact staging of additions,
modifications and deletions, unchanged/no-op incomplete classification, and
inspection/completed recovery without `add` through a fixture-local Git recorder.
Existing authorized commit-hook refusal coverage remains in
`test/git/local-commit.test.js`. Slow polishing handoff recovery additionally
covers configured hooks for complete, untouched
and partial effects: no role/staging replay for complete recovery, validation
rediscovery before an untouched legacy effect, and no repair of a partial effect.
These fixtures require no live provider, network, paid service or live-project
hook execution; they do not replace the full slow gate or operator acceptance.

Fast `test/runner-configuration.test.js` owns selected external execution/polishing
transcripts, CLI/MCP path projection, integrated ignore rejection, reserved and
aliased provider-control rejection from both target and infrastructure owners,
and exact legacy pending-editor migration.
The workspace inspection suite owns absent nested control-name reservation;
the Runner regression rejects such transcripts before parent creation or role work.
Answer preview and submission reject newly aliased controls or changed external
ignore rules before reading or mutation; cold append recovery retains intent and
accounting without replay when a provider alias appears after admission.
Runner migration tests bind frozen roots to their protected resource owner.
Pipeline contract tests own strict saved roots and
preflight absence; `step-policy.test.js` owns custom artifact selection without
output authority. Existing configuration and clarification suites retain confined
identity, symlink, ancestor substitution and unauthorized-edit rejection. The
combined external product-decision case in `test/runner-effects.slow.test.js`
extends its existing append-replacement witness with creation, authorized answer
and freeze, and cold recovery without target artifacts or duplicate accounting.
It remains part of the complete slow gate, with no additional workflow matrix.

## Operator-owned Codex file-output acceptance

Existing-file output readiness regressions live in `test/agents/codex.test.js`,
`test/agents/registry.test.js` and `test/runner-directory.test.js`. Injected native
effects prove regular/dotfile refusal before work, mixed declarations without
preparation, read-only preservation, descriptor validation and shape substitution
after cached approval or pause. They establish no actual native enforcement.

Operator-owned model-free native acceptance is deliberately outside ordinary
fast/slow coverage and live-provider smoke. After pipeline gates, explicitly run:

```bash
node scripts/accept-codex-file-outputs.js --enable --candidate=/absolute/private/package --codex=/absolute/configured/cli
```

The candidate must be a separately installed package. The script uses owned
temporary ordinary directories and synthetic native settings without credentials
or model requests. It records named-profile configuration acceptance separately
from enforcement, requires the expected file-grant setup failure before its
command marker, verifies directory-write/read-only and protected-metadata/sibling
controls, and proves source/candidate adapter refusal before any injected native
inspection, allocation or launch. Missing interfaces, timeouts and failed controls
are failures, not acceptance; an unrun script remains NOT_RUN. Report failures,
skips and limits before installation/activation. This negative native witness
must never become a PASS-required agent check. Neither mocked tests nor CLI
version/help success grants native acceptance credit.

## Ownership diagnostic acceptance

Focused deterministic development coverage lives in
`test/platform/ownership-diagnostic.test.js`, the injected supervisor/parent
cases in `test/platform/owned-process.test.js`,
`test/runner-observations.test.js`, `test/state/observations.test.js` and
`test/state/recovery-failures.test.js`. It owns closed shape/site/branch rejection,
measured overruns and unavailable facts without additional inspection work,
adapter parity, unchanged failure policy, retained samples across cleanup,
terminal write-ahead reconstruction, immutable legacy records and correlated
recovery publication. CLI and MCP fixtures retain projection parity and redaction.
The parent/supervisor fixture also covers valid post-request pre-spawn expiry,
with no target spawn, no added inspection and close before deregistration.
Injected `test/trusted-timing.test.js` regressions cover synchronous and
asynchronous no-launch refusals, plus preparation refusals through receipts and
capability blockers; `test/agents/codex.test.js` covers storage allocation/cleanup
cause propagation. Both adapter suites cover launcher-failure mappings with
validated, unavailable and malformed diagnostics while preserving failure policy.
Both coding pipelines' `capability-requirements.test.js` fixtures cover retained
blocker evidence and caught inspection, preflight and cleanup diagnostics in
persisted pauses, with unchanged stopping behavior and redacted native errors.
Both retain malformed-evidence rejection and unchanged failure policy without
executing selected trusted commands or consuming native acceptance.
Existing state custody, stop, journal, migration, orchestration, CLI/MCP and release
slow suites remain required through the complete `npm run test:slow` gate; do not
repeat those selected files as additional equivalent slow commands. Release
assembly/archive verification and the separate exact-artifact
`npm run test:slow -- test/package-install.slow.test.js` gate remain additive.
Focused development results give none of those later gates acceptance credit.

After reviewed polishing HANDOFF, the separate authorized operator commit,
whole-result review and inactive candidate installation, the supervising operator
runs the smallest model-free native acceptance against exact committed Source and
a separately installed candidate:

```bash
node scripts/accept-ownership-diagnostics.js --enable --candidate=/absolute/private/package --commit=<source-commit>
```

The script verifies clean committed Source and identical platform bytes in the
separate installation. Both executions use the real supervisor/IPC with an owned
synthetic Node target: one controlled inspection refusal, a post-request pre-spawn
preparation expiry and a clean-retirement control. The expiry uses the existing
parent preparation-clock/deadline injection and a supervisor clock preload to
reach the absolute deadline when handling start, without sleeps or target effects.
It requires an actual parent request, recorded expiry, no target effect marker
and positive retirement/deregistration. The refusal injects a procfs read denial
and labels that condition separately from actual native launch, IPC and verified
retirement. Injected preparation clocks are likewise labeled separately from
native execution. It changes no supervision mode, sandbox, native inspection
limits or provider settings. It retains fixture storage if retirement is
uncertain. An unsupported environment,
missing evidence or failed control is a failure, never a skip credited as native
acceptance. Unrun acceptance stays NOT_RUN; injected tests and retained evidence
cannot substitute for Source/Installed execution. Historical cause and
Source-contract violation remain UNKNOWN. Live-model smoke remains opt-in.
Activation and default concurrent MCP acceptance remain separate operator
delivery work after these gates.

## Ordinary gate

Fast `test/state/workspace-preparation.test.js` owns bounded pending admission,
frozen declarations/inputs/identities, complete binding publication, interrupted
capture and write-ahead recovery, replacement ownership, stale capture rejection,
and concurrent pause/cancel settlement. Cold recovery rejects discarded
absent-input evidence and missing parent bindings for absent nested inputs;
replacement of a retained input parent blocks recapture. It uses isolated ordinary directories,
controlled callbacks and process identities with real journal/lease publication;
no providers, sleeps or host process census. Legacy version-24 migration retains
completed bindings without manufacturing preparation. Common-envelope changes
also retain state persistence/operator-stop, affected orchestration and legacy
migration slow coverage and release-pack validation; these focused fixtures do
not replace those gates or prove pipeline activation.

The same state suite owns one-time Git membership publication before capture,
malformed-selection rejection, lost publication recovery without reselection and
journal substitution rejection. The optional selection uses common envelope 26;
compatibility changes also require the release-pack slow check.

The state preparation suite also owns leased pipeline-migration rebinding of
the admission state fingerprint across cold reload. It preserves all source,
input, policy, role and accounting declarations and rejects attempted changes,
including workflow advancement or rebinding without increasing the version.
The Runner preparation suite's legacy pending-audit case exercises the actual
audit migrations through version 10, including the nullable recovery defaults,
before capture. These focused cases retain the complete slow release gate for
persisted/lifecycle changes.

Fast `test/runner-preparation.test.js` owns deferred audit activation through
real state and workspace services: bounded creation/boundary validation,
CLI identity before held traversal, cancellation without provider work,
pause/resume and interrupted capture from frozen inputs, substitution rejection,
detached readiness before capture and lost-receipt recovery after disconnect,
and canonical/overlapping lease contention. Controlled events propagate early
outcomes and always release/settle held operations; there are no sleeps or live
providers. Existing orchestration, CLI/MCP workflow/control, state/operator-stop
and effect-recovery slow suites retain their cross-capability coverage.

That preparation suite also covers explicit Git selection through held capture,
pause and cold resume, complete unchanged/ignored-tracked/dirty/deleted/untracked
membership, scoped provider requests, unchanged Git state and later membership
drift rejection. An independent Git-scope case with distinct Auditor and
Reviewer fixture backends starts through MCP detached acknowledgement, records
both provider policies, persists a bounded baseline without per-entry evidence
at the held clarify turn, pauses there and completes from a cold replacement
runner through the real `runtimeFor` interface without renewed budgets, then
rejects later membership drift. Ordinary-directory completion proves opaque
exclusions, frozen public/report context and deliberate directory-origin issue
capture. Its issue control-discovery fixture declares an ordinary origin
independently of the temporary parent's controls; the issue-reporting suite
retains real enclosing-Git discovery and rejection coverage. A version-25,
audit-version-6 pending fixture resumes without changing settings or budgets.
Audit publication coverage separately preserves completed legacy report bytes,
acceptance receipts and histories. Existing workspace/provider suites retain
control/input/link confinement, corruption and read-only effect denial. CLI,
configuration and MCP tests cover field mapping, precedence and strict settings.
Admission coverage includes a project scope override that makes CLI exclusions
valid despite a different runner default, while invalid final combinations and
individual paths still reject before traversal or probing. The directory
completion case passes Runner's request through both real adapters' normalization
and filesystem preparation, using a controlled CLI-capability failure before any
provider invocation; relative exclusions never enter storage protection. Both
provider suites cross 256 inspection roots through scoped receipt preparation and
reject a directory substituted for the final file-only root, retaining the 10,000
inspection-root bound and the 256-path bounds on other declarations.
The final integrated change requires the complete slow gate; these focused cases
do not attest unrun slow or opt-in live-provider acceptance.

`npm run check` runs formatting verification, the fast test tier, and CLI help.
Its development budget is approximately 60 seconds. The fast tier retains
contract, policy, provider, Git, state, and focused integration checks.
`npm test -- path/to/file.test.js` runs selected coverage.

Effort coverage in `test/config/effort.test.js`, `test/agents/effort.test.js`,
the provider suites, CLI/MCP tests and pipeline workflow fixtures includes
explicit `max`, unsupported native-tier refusal and unchanged legacy `xhigh`
translation. State persistence covers cold journal reads, and
`test/runner-orchestration.slow.test.js` covers resume with frozen `max`
instead of reloading changed configuration. These cases use no live providers.

Fast `test/trusted-timing.test.js` uses an injected monotonic clock and executor
to distinguish outcomes, pre-invocation blockage, preparation-only availability,
rejected admission and incomplete/unsafe attempts without sleeps or wall-clock
assertions. `test/trusted-storage.test.js` binds the interval to real resource
publication, controlled process retirement, cleanup and the final safety check;
uncertain cleanup cannot publish a receipt. The execution pipeline's
`trusted-timing.test.js` carries a real service-generated receipt through saved
state reload and terminal confirmation, rejecting changed tuple evidence without
rerunning the check. Existing unmeasured receipt and legacy fixtures remain
valid. These cases do not attest the orchestration, CLI/MCP workflow/control,
operator-stop, effect-recovery, legacy-compatibility or release-pack slow gates.
Use available Runner measurements for the advisory target and keep unavailable
historical/controller timing unknown; never rerun only for missing telemetry.

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
candidate verification, plus bounded CLI runtime diagnostics: exact recognized
codes, the unrecognized fallback, hostile message/cause/property redaction,
identical non-runtime rejections and original-failure precedence.
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

Fast `test/session-naming.test.js` owns strict Runner naming context, the full
existing run UUID across providers/pipelines/modes, inactive roles and creation
acknowledgement ordering. Provider fixtures prove native child acknowledgement
without live model calls. Codex fixtures additionally cover exact UUID prefixes,
bounded Unicode descriptions, acknowledgement/naming/turn ordering, direct fork
lineage, inherited titles, unchanged continuation, fresh reconstruction, redacted
metadata rejection and transport loss before model or commit effects. Runner
coverage retains the known child and full request through a backend pause without
retry accounting. The installed Codex 0.164.0 stable generated protocol schema
confirmed `ThreadSetNameParams`, `ThreadSetNameResponse` and `thread/name/set`;
this model-free schema inspection is not live naming acceptance. The opt-in Codex
smoke verifies naming only when explicitly enabled. Focused durable
authoring/audit cases cover bounded journaled diagnoses, unchanged retry/usage
accounting and known-child recovery without another source fork or owner cycle.
Coverage retains acknowledged children through authentication/output dispositions,
excludes commit-readiness children from Worker reuse and bounds concurrent diagnoses.
These checks add no retrospective naming or native acceptance claim. Existing
common and custom-execution slow assignments remain unchanged.

Claude's model-free fixtures cover the same full UUID and Unicode bound, exact
`--name` support, fresh/fork/continuation arguments, fresh reconstruction,
unchanged compaction and source lineage, acknowledgement before bounded receipts,
and metadata rejection with either a validated result or stream initialization.
They reject replacement launches and constrained commit effects after metadata
failure, and preserve permission, interruption and accounting boundaries.
Installed Claude Code 2.1.316 help advertises `-n, --name <name>`; help inspection
is not a live naming acceptance claim. Both provider smoke tests remain opt-in.
The shared context matrix retains every registered pipeline/mode and active role
on both providers, excluding inactive roles. Common slow coverage, exact package
installation and Agent custom-execution assignments remain required; no predecessor
gate evidence satisfies the final feature's current validation.

Fast `test/agents/claude.test.js` owns the exact terminal `protocol_*` class,
failure record, retry and single turn call for each malformed-stream, failed-exit,
observer and lineage rejection, including unchanged local-commit `not_started`
proof, while replayed completed-session init and accepted streams stay accepted.
`test/agents/registry.test.js` owns bounded boundary messages and rejection of
unregistered classes and native text; `test/cli.test.js` owns the printed line.
`pipelines/polishing/test/recovery.test.js` owns cold persisted FINALIZE
diagnosis, status and activity, classified and unclassified, without
finalization acceptance, fingerprints, staging, retry or resume.
The Claude test also owns factual permission classes through completed and
failed processes, order-independent mixed batches and local-commit
`not_started` proof; the registry, persistence, polishing recovery and CLI
tests own their terminal registration, legacy loading, redaction, cold pause
and printed line.

Fast polishing `convergence-and-review` owns the lazy clean-confirmation cold
null retry through a reopened run store: its bounded candidate-review diagnostic
and the latest accepted changed and unchanged check/fix summaries in the next
primary requests and saved state.

Fast polishing `finalization-diagnostics.test.js` owns valid controls and bounded
field/constraint rejection details, ordered check identities, exact commands,
trusted placeholders, status consistency, evidence and inactive fields. It
composes combined correction reconstruction, unchanged budgets and fingerprint
scope, latest-violation terminal CLI/MCP evidence, and redaction of unknown
diagnostic-like inputs. Existing `recovery` and `convergence-and-review` retain
interruption during correction, content-scope reset and read-only mutation
coverage. These focused model-free development tests do not replace the
Runner-owned fast, complete slow and distinct package-install FINALIZE checks
or subsequent operator-owned native and installed acceptance.

Fast polishing `resolution-correction` owns finding-resolution report recovery
in independent and combined modes: one fresh read-only restatement after an
invalid, lost or interrupted report, once-only fix charges, operator-stop
settlement, blocked, product-decision, drift and exhaustion stops, and the
explicit null retry. `contracts-and-migrations` owns the version-20 checkpoint
validator, migration and diagnostic allowlist.

Fast `test/git/repository-safety.test.js` owns the read-only snapshot-change
label normalizer and real-Git `readOnlyChanges` classification;
`test/state/persistence.test.js` owns durable label validation, including
operator-retained pauses; and `test/pipeline-registry.test.js` owns composed
and uncomposed contamination evidence. Polishing `mode-routing` and execution
`clarification-and-bootstrap` own the guard-to-pause path, cold reload,
activity and unchanged clearing; `test/runner-custom-execution.test.js` owns
the Git-free unavailable stop.

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
Durable apply coverage additionally proves exact-selection receipts, same-key
conflicts, concurrent-key installation sharing, recoverable blocked intents and
server-replacement recovery without native-effect replay. `test/mcp/update.test.js`
owns strict tool discovery and operator acknowledgement, unchanged protocol JSON,
wait-only cancellation, duplicate observation and CLI dispatch without pipelines.
It uses in-memory SDK transports and injected updater effects. Installed package
acceptance separately exercises the unapproved CLI/MCP update entry points without
registry requests or client registration; approval changes must revise that explicit
default-disabled expectation as part of their own reviewed acceptance.
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
zero findings, safe catalog-derived Markdown, and bounded sanitized semantic
diagnostics. Discovery/recheck fixtures verify role-field locations and exact
fingerprint rejection; the Codex schema compatibility fixture includes audit.
Report coverage uses no providers,
processes, Git repositories, or temporary storage.
Fast `pipelines/audit/test/discovery.test.js` owns frozen scope, read-only discovery,
lazy/independent session isolation, duplicate/revised candidates, pending-batch
blocking, invalid/incomplete output, drift, write-ahead interruption and finite
exhaustion recovery using injected root capabilities. It also covers the two-MiB
role-result limit, complete frozen inputs/findings in fresh discovery prompts and
propagation of unsettled execution ownership.
Discovery also covers persisted clarification/discovery correction feedback,
replacement, checkpoint confinement and rejection of unsafe diagnostics.
Its incomplete-work regression retains an already accepted batch, report,
limitations and uncertainty across reload without adopting proposed revisions.
Fast `pipelines/audit/test/clarification-append.test.js` owns injected append-intent,
replacement and editor-publication interruption, repeated recovery, verification-only
stops, strict payload/checkpoint validation and legacy absence. The existing
ordinary-directory case in `test/runner-audit.test.js` exercises real transcript
replacement and fresh clarification-service reconstruction without role replay.
These focused tests do not attest cold Runner-journal or slow release coverage.
Fast `pipelines/audit/test/verification.test.js` owns all five finding dispositions,
fresh independent versus continuing lazy rechecks, review additions, retained
rejections, version invalidation, stale/malformed/incomplete output, interrupted
reservations, exact acceptance recovery, Auditor-only legacy migration/resume
without fabricated approval or role expansion, and run-wide recheck exhaustion.
It shares injected effect-free fixtures with discovery through the pipeline's
test support index.
The coherent-batch fixture proves successive discovery batches each block more
discovery until verified, a complete recheck cannot omit one entry from a
multi-entry batch, and acceptance cannot establish clean discovery. Public
confirmed counts remain tied to exact accepted receipts. These effect-free
regressions belong to the ordinary gate; they add no slow-suite requirement.
Recheck feedback coverage preserves pending dispositions and prior rejection
history across lazy/independent resume and the version-5 migration; combined
coverage keeps an invalid Reviewer's original clean-first accounting.
Fast `pipelines/audit/test/output-recovery.test.js` owns audit retirement intent,
fresh native selection after explicit exhaustion resume, serialized reload before
launch, acknowledged replacement continuity, retired-identity rejection, exact
pending verification and old-version invalidation, and version-7 migration
acceptance/rejection without changing report bytes or dispositions. Its injected
fixtures exercise the complete combined finding gate; missing and incomplete
decisions never add confirmed results. These policy fixtures do not attest real
journal interruptions or live-provider behavior. Persisted audit recovery and
compatibility metadata changes require the complete `npm run test:slow` release
gate after `npm run check`, including existing orchestration, CLI/MCP, state,
release-pack and installation coverage. Selected Runner-trusted commands remain
reserved for the dedicated finalization boundary.

Slow `test/runner-audit-recovery.slow.test.js` owns actual cold journal reloads
across exhaustion retirement, pause clearing before launch and acknowledged-child
response loss. Combined directory coverage imports exercised version-7 evidence
through the store creation boundary and proves migration preserves pending
revisions, rejected/hypothesis dispositions, receipts, correction feedback,
report bytes, original reservations and finite budgets. Missing or incomplete
decisions add no confirmation; only the complete selected gate accepts current
versions. Lazy Git-scope coverage composes availability and controlled inactivity
with repeated exhaustion without another source fork or inactive-role work.
A Git-scope case with more than 10,000 synthetic files beneath the fixture
control directory reproduces the bounded-baseline regression through deferred
capture, provider-policy recording and continuation past the first CLARIFY
transition; snapshots of that tree take seconds each, so it stays in this tier.
Independent coverage retains finding-Reviewer separation and matching redacted
CLI status and MCP status/wait explanations, null-action recovery and inert
completion. Separate failure/cancellation cases retain terminal dispositions
after exhaustion without new provider work or report publication on cold resume.
Provider responses, clocks and interruption boundaries are injected;
these tests use no live provider, sleeps or canonical-journal edits.
Run `npm run test:slow -- test/runner-audit-recovery.slow.test.js` when changing
audit recovery, migration, native selection, persisted audit baselines or their
public projections. The complete slow release gate includes it automatically;
it replaces no existing or separately selected Runner-trusted check.

Cold clarification-append coverage uses the real transcript service, store and
Runner, with fresh instances after each interruption. The audit recovery suite
owns failed initial intent publication, durable intent/editor events ahead of
snapshot replacement, and legacy absence versus unsupported append ownership
with unavailable capabilities in an ordinary directory. Runner effects owns
execution readback loss, polishing editor-publication loss and nonsettlement
execution decisions. CLI workflows owns authoring reconstruction and one
event-synchronized owned Runner process loss after replacement/readback; that
case proves dead-owner lease recovery without normal exception cleanup. MCP
workflows owns recovered polishing decisions and idempotent answer publication;
control-plane coverage owns rejection of changed transcript, task and Git controls
before replay with matching sanitized CLI/status/wait projections. Runner
operator stops owns verification-only pause/cancel settlement for prior and
result bytes, including delayed stop dispatch. These distinct cases span the
three modes without duplicating the pipeline policy matrices. They assert exact
bytes, once-only accounting and no producing-role replay, use no sleeps or live
providers, and never edit canonical state to manufacture recovery evidence.
Audit recovery and Runner orchestration additionally own durable service-readback
rejection: a finite native replacement callback restores prior bytes before the
real service's readback. Repeated uncached store/service/Runner reconstruction
at prior and result bytes and real verification-only stop settlement preserve
intent, checkpoint, accounting and redacted CLI/MCP projections without replay
or editor authority. Orchestration covers authoring questions and execution
decisions; the owning fast workflow fixtures separately cover reconstruction
policy, including authoring decisions and execution questions. Workflow-only
reconstruction is not cold journal evidence.
Fast execution `clarification-and-bootstrap` also owns the terminal `CONFIRM`
product-decision append checkpoint with actual producing role results: changed
and missing ignored finalized-only infrastructure blocks replay, and drift after
readback blocks editor authority. Its unchanged control protects selected-file
composition, deduplicated inventories and once-only settlement separately from
the retained finalization tuple. Runner orchestration owns focused cold
store/service/Runner reconstruction through the same route, interrupted by a
finite service callback after durable intent but before replacement. Repeated
reconstruction retains rejected intent, accounting and redacted status/wait
projections, or settles unchanged bytes once without producing-role replay.
Existing init and coding settlement coverage retains its owners. Changes to this
cross-capability lifecycle retain the affected slow owners above and the complete
slow release gate; focused development cases do not attest those gates or the
separate package-install requirement.

Fast `pipelines/audit/test/combined.test.js` owns initially clean and
finding-producing fresh discovery cycles, duplicate and report-only corrections,
same-Auditor batch convergence, correcting Reviewer continuity/additions and
clean-first replacement. Injected capabilities cover invalid/incomplete output,
interrupted reservations, lost-child reconstruction without reforking, rejected
premature acceptance and both finite run-wide budgets across replacement/resume.
Fast `test/runner-audit.test.js` owns audit composition with the existing confined
workspace/clarification services and persisted session contract: authorized
transcript edits preserve discovery, while source drift blocks it under compact
and migrated legacy full baselines. Compact directory baselines exempt only
declared artifacts and reject undeclared exemptions; output baselines return the
filtered snapshot and its projection from one inspection. It also uses
actual inactivity, availability and disposition policies with in-memory storage
to cover checkpoint initialization, bounded reconstruction, terminal isolation
failures, authentication/output pauses and source-fork recovery. Normalized
provider structured-output failures remain resumable invalid passes. The actual
transition normalizer proves persistent field/collection overflow is rejected
before acceptance without reducing the two-MiB aggregate role allowance. No provider
or Git process is needed for those policy tests.
The same lightweight fixture verifies normalized feedback persistence and matching
sanitized CLI/MCP pause evidence without a new storage or provider integration.
Terminal provider fixtures retain registry-normalized classes, unknown/legacy
absence and redaction, rejecting unsupported classes and contradictory pauses.
Fast `pipelines/audit/test/publication.test.js` owns escaped report-size rejection
before ledger acceptance and resumable retry, exact confirmed/pending
projection, zero/Critical findings, all-mode completion, lost publication
acknowledgement and completion binding with injected effects.
Fast `test/runner-audit-publication.test.js` owns public Runner/CLI metadata and
MCP report projection for Git and ordinary directories, plus actual
confined artifact replacement, exact-byte and partial-write recovery without
replaying accepted discovery, edits and temporary/alias substitution rejection.
Its ordinary-directory terminal case reconstructs a failed audit from the real
journal and checks matching CLI status, MCP status/wait and safe activity without
replaying discovery or report publication on terminal continuation. Unexpected
provider probes and agent turns are rejected after terminal failure.
Changed and missing protected configuration preserve the exact terminal run,
diagnosis and revision without provider or report-publication calls.
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
byte-limit and inode-provenance coverage. The content-and-safety suite owns absent
bootstrap reads without ignore rules, strict edit/update rejection, deleted tracked
guidance and appearance/disappearance during read reinspection. It also covers
finite read-failure classification across guidance normalization, with unknown
corruption, recovery and mutation failures retaining their existing handling.
Native document/directory-open and returned pinned-directory verification failures
exercise the actual guidance helpers, including transient rejection, vanished
resources and unknown I/O codes. Descriptor-close failures retain unclassified
cleanup handling.
MCP guidance coverage compares CLI/MCP bootstrap reads with complete unchanged source/control
snapshots and no local or state creation. The content-and-safety suite also owns
integrated guidance beside an internal provider-control directory alias in Git
and ordinary directories, protected rejection after retargeting that alias to the
destination, and the controls diagnostic for an escaping alias. Publication tests also cover legacy
worktree-relative receipt recovery from Git subdirectories, including incomplete
published intents. Current external actions reject changed selector identities
rather than adopting legacy resolution. MCP guidance tests cover the same
selection through its thin transport.

Fast configuration loading and clarification lifecycle coverage own the existing
bounded-file guards' finite constraint metadata while retaining their error
codes. Configuration coverage also distinguishes explicit missing-file metadata
from valid implicit absence. These read-contract fixtures establish no init pause/resume behavior or
live-provider acceptance. Guidance integration changes also require the
registered init slow suite; runtime-resource changes retain release-pack coverage.

Fast `test/runner-configuration.test.js` covers relative external selectors in
polishing and external project commit selections overriding runner custom
defaults from Git subdirectories in authoring and execution.

Fast `test/runner-authoring.test.js` owns public custom-authoring composition:
configured selection before Git, read-only provider declarations, frozen criteria
and source bindings, source-drift recovery, repository-local clarification ignore
requirements, artifact-only publication and non-Git commit rejection. Its
configured case asserts that preflight persists the compact baseline with
exactly the artifact exemptions and no entries or link resolutions.
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
Directory-baseline cases reject unknown, scope, link-resolution and malformed
compact fields, resume a legacy full baseline through its unchanged guards with
and without drift, and keep the identity version-7 migration lossless.

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
The same fast owner distinguishes missing slashless rejection (no preparation or
writable calls), explicit slash-directory preparation and a backend proving
absent exact-file creation. A mixed-directory witness rejects a missing parent
before preparing any root. `test/runner-directory.test.js` checks the configured
descriptor readiness route against every root before preparation; adapter owners
inspect exact Codex permission and Claude mount projections and reject missing
unprepared roots before native work. The configured readiness route also rejects
nonliteral output roots for both backends before probes, creation or invocation.
Existing shape, parent, control and symlink witnesses retain their owners.
Its lightweight workspace matches real capture: complete unfiltered identity,
no synthetic missing-root entry and the real output projection. Cases assert the
compact prepared-root record, reconstruct existing-root preparation after an
authorized clarification edit without a drift stop, and stop an injected legacy
full baseline above state capacity with `ERR_CUSTOM_BASELINE_CAPACITY` and no
further provider turn.
`test/runner-custom-execution.slow.test.js` owns real leased authoring-to-execution
composition and accepted-result recovery without Git, plus a durable lazy
candidate-review diagnostic through its cold null retry; run it when changing public
custom selection, directory role probing, custom orchestration, settlement, or
candidate-review correction diagnostics and recovery.
Its existing combined authoring/execution witness also interrupts after the
prepared identity and baseline settle, then reconstructs with fresh Runner/store
instances. It retains prepared identities, startup/writable receipts, accepted
result chains and consumed budgets across preparation and confirmation recovery.
This adds no workflow/mode matrix and remains in the full slow gate.
One shared owned fixture writes 10,050 empty dependency-like `vendor/` files and
a small `.agents/` control file before creation. Real authoring and execution
pass preflight above the state array limit with compact baselines. Step 1
prepares the absent output root and writes the declared output; its accepted
receipt carries the output fingerprint and its baseline record the prepared
identity with descendant evidence. An interrupted resume after a `vendor/` edit
stops with the existing drift pause, no new provider turn and preserved
receipts. Snapshots of that tree take seconds, so it stays slow; run it when
changing custom baseline representations.
Its slow invocation is `npm run test:slow -- test/runner-custom-execution.slow.test.js`.
Fast recovery cases cover compatible authorized decisions before acceptance and
after an earlier receipt, fresh gates for the new clarification version, and
rejection of unauthorized drift or an answer invalidating accepted results.
The pure result-checkpoint suite rejects stale clarification approvals; execution
contract tests retain legacy finalization/trusted-check defaults in every mode,
accept only the legacy full or closed compact custom baseline and keep the
identity version-41 migration lossless. The fast pipeline-owned
`custom-workspace.test.js` injects in-memory complete/projection pairs to cover
exact missing- and existing-root preparation, rejected remainder, output,
identity and root drift, interrupted reconciliation, unchanged legacy entry
comparison and the legacy capacity stop.
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
read/ancestor races. It also owns bounded internal provider-control directory
aliases: canonical target protection, full-inspection alias-binding rejection,
control-specific escaping, dangling, cyclic, file, FIFO, parent, Git-metadata,
Git-link and state-overlap rejections, and target replacement during resolution.
Scoped fixtures reject reads of excluded/unselected trees through both ordinary
and descriptor paths, preserve protected inputs/controls and required link
dependencies, bind reconstructed selections and routing identities, and cancel
discovery/file hashing with verified handle closure and bounded anonymous progress.
Real captures prove compact baselines detect source and control drift and that
output baselines derive absent roots only from covered directory ancestors,
reject blocking file ancestors, uncovered roots and selected or excluded
snapshots, keep remainder digests across output-only changes and reject
`allowOutputs` or malformed partitions in the compact guard.
`test/workspace/output-directory.test.js` retains ordinary output preparation and
scoped output authority independently of source selection.
Temporary directories and injected filesystem effects need neither Git nor live
providers. Workflow/provider integration remains separately owned as those
consumers land. Fast `test/agents/codex.test.js` owns the public adapter's
directory request/probe contract, access-specific receipts without Git or commit
preparation, native output-only permissions, protected-write rejection, effective
policy substitution, literal-path rejection for glob syntax, reconstruction,
observations and attempt retirement. Codex 0.167.0-style `config/read` fixtures
carry explicit nullable permission defaults through launch, selection,
continuation, fork and reconstruction, retaining legacy omitted defaults and
rejecting unknown fields, non-null overrides, inheritance, changed grants and
scope. It uses ordinary temporary directories and model-free transport fixtures; live
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
Controlled 2.1.317-style initialization runs through the adapter's actual launch
options before the tool launcher, proving unchanged ordinary-directory sources,
controls and selected inputs, private mode-0700 atomic staging, separate command
cwd, continuation and retained allocations pending process retirement. It covers
missing controls and existing user bookkeeping without reading native provider
storage. This is model-free regression coverage, not live-provider acceptance;
version/help output does not prove native read-only behavior.

Scoped public-adapter fixtures use malformed control pointers and dangling links
inside excluded and unselected trees to reject unrestricted preparation or
verification. They bind receipts to inspection roots and exclusions, preserve
frozen scope through reconstruction despite caller mutation, reject selected
source/control drift and protected exclusions, and exercise Claude cleanup with
missing inputs under the same scope. Scoped mount preparation uses the verified
workspace binding even when capture omits that root. Omitted-scope fixtures retain
the existing native initialization and whole-directory contracts.

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
one cold-owner pending-assessment witness through the actual strict RunStore
guard with injected measurement and role effects (same reservation, checkpoint,
attempt and binding, durable matching decision, no preservation or commit),
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

Fast `test/source-boundaries.test.js` owns source index, dependency-direction
and provider-isolation boundaries. Its source walks cover the root runtime and
exactly the root manifest's `workspaces` declarations. A synthetic temporary
root proves that an undeclared hidden directory is not walked, declared regular
workspaces still are, and an explicitly declared hidden workspace is discovered
and strictly validated; run it when changing workspace layout or declarations.

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

| Suite                                                                     | Distinct observable guarantee                                                                                                           | Run when changing                                                                                                                                                           |
| ------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `test/runtime-pinning.slow.test.js`                                       | Running and detached synthetic applications retain the complete pinned payload after outer replacement; drift blocks another launch     | Startup/bootstrap, runtime manifests or storage, delayed resources, Node identity, detached launch                                                                          |
| `test/release-pack.slow.test.js`                                          | Actual npm tarball matches the complete assembled production application, real dependencies, modes and resources                        | Release assembly, file allowlists, lock closure, package metadata or runtime resources                                                                                      |
| `test/package-install.slow.test.js`                                       | Exact inspected bytes install outside the checkout and expose pinned CLI/MCP behavior with complete teardown                            | Packaging/release gates, candidate installation/activation, installed CLI/MCP update contracts, or final provider/operator installation acceptance                          |
| `test/integration/cli-workflows.slow.test.js`                             | Root CLI composition produces one plan artifact, one exact-subject commit, and one uncommitted handoff                                  | CLI projection or root plan-authoring, plan-execution, polishing, real-Git commit, or handoff composition                                                                   |
| `test/integration/mcp-workflows.slow.test.js`                             | A detached MCP workflow continues through durable runner state after the requesting client is replaced                                  | MCP-to-runner workflow composition, detached continuation, client replacement, or cross-capability durable state                                                            |
| `test/mcp/control-plane.slow.test.js`                                     | Detached STDIO dispatch preserves protocol cleanliness and exactly owned durable intents and receipts                                   | MCP STDIO, detached starts or stops, action receipts, disconnects, waits, restart or version skew, or execution-owner contention                                            |
| `test/runner-orchestration.slow.test.js`                                  | Root orchestration preserves configuration, sessions, migrations, trusted snapshots, and worktree order                                 | Runner configuration or source sessions, runtime migration, trusted preflight snapshots, worktree serialization, or root service wiring                                     |
| `test/runner-operator-stops.slow.test.js`                                 | Runner stops settle owned processes and raced commit or handoff effects without losing writable content                                 | Runner operator stops, process settlement or containment, commit or handoff races, execution-storage cleanup, or partial-content resume                                     |
| `test/runner-effects.slow.test.js`                                        | Commit effects, changed-BLOCKED progress and polishing finding-resolution checkpoints retain once-only accounting across reconstruction | Runner Git/state effect dispatch, commit authorization or verification, deferred settlement, consumed-effect recovery, or blocked/finding-resolution checkpoint publication |
| `test/runner-audit-recovery.slow.test.js`                                 | Cold audit reconstruction preserves pending verification, provenance, budgets and bounded baselines across replacement and migration    | Audit output recovery, persisted migration or baselines, native selection, availability/inactivity composition or public recovery projections                               |
| `test/state/operator-stops.slow.test.js`                                  | State journals preserve bounded replay, stop publication, leases, ownership transfer, process identity, and races                       | State actions or journals, publication boundaries, leases, process identity, worktree ownership transfer, or stop concurrency                                               |
| `pipelines/plan-execution/test/legacy-confirmation-recovery.slow.test.js` | Journal-proven legacy confirmation reconciles one real commit through rejection, crash, and lease cases                                 | Plan-execution legacy confirmation eligibility or proof, journal publication boundaries, verified commit recovery, or execution leases                                      |
| `pipelines/plan-execution/test/legacy-migrations.slow.test.js`            | Authentic persisted migration history carries legacy confirmation proof into the current contract                                       | Persisted plan-execution migration composition involving confirmation proof, inventories, implementation evidence, or historical events                                     |
| `pipelines/polishing/test/handoff-recovery.slow.test.js`                  | Configured-hook legacy recovery verifies complete effects, revalidates untouched effects, and rejects partial effects without repair    | Polishing handoff settlement, hook isolation, legacy handoff migration, completed-effect reconciliation, or partial-effect failure                                          |

Run the affected slow coverage once before handing off a change to the listed
contracts. After the ordinary `npm run check` gate, run the complete
`npm run test:slow` tier as the release gate. A documentation-only or unrelated
policy edit does not require replaying all durable workflow matrices. Record
exactly which tier/files ran; an unrun slow check is not a pass. Do not move a
test to this tier merely because it fails or has a slow fixture: first remove
redundant setup and use lightweight effects for policy. Pure migration
validation remains in the fast tier.

MCP control-plane and Runner orchestration fixtures race expected events against
their owning operations so early fulfillment or rejection propagates instead of
leaving an event wait pending. Teardown settles held operations, callbacks and
leases even after an assertion fails. Provider-activity teardown retires its
synthetic process, observation and active turn under the currently held lease,
including after replacement acquisition. Injected failures preserve the original
error and prove fresh lease acquisition. The existing protected-configuration
stop race and stop/recovery assertions remain unchanged; these fixture corrections
change no production lifecycle or inspection diagnosis.

The state operator-stop suite's interrupted checkpoint matrix also verifies
atomic retirement of active observations before publication, alongside the
saved stop outcome and exact receipt replay.

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

It also owns actual finite semantic-validator categories, diagnosis redaction,
original reservation/input binding checks, replacement/clearing of corrective
feedback, callback-code nonrecognition and null-initializing legacy migration,
including pending editor authorization. Configuration/guidance recognition uses
their public boundaries; no rejected payload enters the finite diagnosis.

Fast `pipelines/init/test/inspection-failure.test.js` owns finite inspection
constraints, complete over-capacity document rejection, redaction, strict pause
validation, trusted bounded-file constraint mapping and narrow transient recovery
policy, without filesystem/provider work. Clarification lifecycle coverage checks
the existing transcript-size guard's constraint; configuration loading coverage
checks the regular-file guard while preserving its existing read-error code.

Fast `test/workspace/setup-proof.test.js` constructs complete snapshots beyond
10,000 entries to prove compact persistence, exact publication allowances,
deferred-temporary absence, missing-coverage rejection and source/input/control/
link drift protection. `pipelines/init/test/inspection-proof.test.js` owns bounded
role projection in both placements, beyond-cap source and selected-input drift,
explicit destination evidence, additive reinspection, and authentic version-1
hash/approval migration without renewed accounting. These pure fixtures create
no source files or provider turns. Proof-version changes require the ordinary
gate, both init publication slow suites, registered init lifecycle, orchestration,
state persistence/journal compatibility and release-pack coverage; the focused
fixtures replace none of those gates.

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
resource policy. Both publication suites belong to the complete slow tier.
The external suite also injects complete large-source evidence around real
publication effects, proving bounded durable baselines and rejection of changes
beyond the former inspection cap before effects. Lost-root-receipt recovery
covers both compact records and real version-1 bindings through migration,
preserving identities, accepted approvals and accounting.

`test/runner-init.slow.test.js` owns registered lifecycle composition: both
placements' terminal provider failures, including early clarification/proposal,
review/self-confirmation, repairs over prepared baselines and failed terminal
confirmation retaining publication. Controlled failures cover exact reservation
retirement, strict state reload, registry normalization/redaction, consumed
fork/revision/reconstruction accounting, disposition precedence, failed retirement,
callback persistence, outcome writes and activity publication. A foreground CLI
case holds a real shared MCP wait through provider rejection and owner release;
fresh/held waits and status share the durable unsuccessful diagnosis. These
cases use model-free adapters and events without sleeps. Fast proposal tests own
matching reservation/terminal shape policy and legacy absence; registry tests own
boundary-only safe diagnosis. Fast session-naming coverage preserves Runner
callback errors through wrapped/swallowed native failures. These focused cases
do not attest unrun Runner-owned or live-provider checks.
The registered lifecycle suite also covers both
placements crossed with all three modes, proven unused source-fork recovery
without repeating possible effects, guidance-last publication, distinct
terminal confirmation, CLI/MCP setup projections, repeatable guidance,
resumable rejection of unsafe guidance, malformed configuration and invalid
placement-specific procedures before publication,
persisted semantic feedback across resume/reconstruction with matching CLI/MCP
status, fresh/held waits, activity and role requests, callback/persistence code
collisions, and terminal-feedback fingerprint binding with preserved publication,
renewed proposal gates and actual procedure repairs after terminal findings,
atomic replacement of existing local guidance, pending ignore publication,
enclosing-worktree lease reuse, failed infrastructure-lease release across
same-run resume and stop settlement, lost prerequisite receipts,
intervening guidance edits, authorized pre-closure read-scope extension, and
retired terminal-turn recovery with identity-sensitive provider receipts, frozen
backend authority, and identical-byte guide substitution after a lost acknowledgement.
It also owns stop settlement during reserved proposal turns and clarification
windows, pre-provider inspection rejection with zero provider/publication effects,
durable CLI/MCP status/wait diagnoses, start and exact-key ownerless resume receipt
replay, stale/live-owner rejection, transient unchanged-input recovery, post-turn
and additive reinspection rejection, and one-time inspection/stop races before
and during a reserved turn, including canonical
ownership acquisition after a recovery diagnosis. Further cases cover
editor authorization, authorized close and runtime adapter preparation/verification
rejection, initial oversized transcripts, and bounded/non-file configuration rejection during
additive reinspection without accepting partial evidence or publishing resources.
Append pre-read failures cover question and product-decision diagnosis and
same-request resume without duplicate sections or renewed accounting; write-error
interruption cases retain exact journaled replacement recovery. A fail-once
proactive preparation case requires authorization and an unchanged close before
provider work. The pure shared-clarification case checks that proactive completion
and the pending authorization are recorded together.
Initial task/context read failures retain an unstarted durable pause and verify
single initial capture on unchanged-input resume. Prepared-configuration read
rejection retains verified prerequisite receipts and resumes only guidance and
terminal confirmation.
Actual guidance-service control inspection and native directory-open failures
after prerequisite publication also cross normalization into a durable diagnosis, preserving
accepted receipts, selection and approvals before guidance/terminal recovery.
Returned directory verification covers trusted `ERR_GUIDANCE_STORAGE` metadata
through the same registered lifecycle. A selected integrated configuration
disappearing between discovery and loading retains the prior inspection and
produces a non-resumable diagnosis without provider or publication effects.
Foreground admission coverage observes the diagnosis while both execution and
workspace owners remain held, then checks release and
resume; input-submission coverage rejects acknowledgement of unwritten answers
after canonical validation, complete source-proof or clarification pre-read
rejection.
Shared clarification coverage separates initial/replacement reads from write and
post-write readback failures, preserving bytes and exact answer replay. Blocked
and exhausted init checkpoints retain their original diagnosis through failed
recovery, reload and rejected resume; pure validation rejects an inspection
pause over their state. Publication preparation read rejection retains approvals
without reserving an effect.
Proposal-policy source-read rejection remains distinct from invalid provider
content; persistent inspection rejection during stop settlement retains diagnosis.
It retains interrupted question/decision publication, structured decision answers
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
Provider/native-platform acceptance remains opt-in. Inspection-stop changes also
affect CLI/MCP workflow and control-plane
slow coverage, release packing and separate installed-package acceptance; the
complete slow gate remains required for integrated acceptance.

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
Its selected-check amendment fixture follows candidate acceptance, terminal
evidence rejection, bounded correction, amended execution and independent
confirmation across reloads. It verifies full-catalog reservation, explicit
candidate-only execution, unchanged later schedules and exact persisted executor
identity; unselected placeholders and selected agent attestations remain invalid.
The existing CLI workflow slow suite retains cross-capability execution coverage.
Fast execution `finalization-diagnostics.test.js` covers field/constraint
redaction, bounded independent batches, ordered check identity, reserved
placeholders, distinct corrections across interrupted reconstruction, Runner
replacement and terminal public evidence. Repeated, mixed and exhausted batches
retain the finite ledger. Existing contract/custom fixtures retain strict stored
evidence and empty-inventory compatibility. These focused fixtures do not replace
the affected journal, CLI/MCP, orchestration, recovery, release-pack, separate
package-install and complete slow gates for the integrated repair.
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

The fast Git `source-selection.test.js` suite owns complete HEAD/index and
non-ignored untracked membership, missing tracked paths, index-hidden worktree
content, ignored-tree non-visitation through workspace capture, unchanged Git
controls/index bytes, literal names, links, unsupported recursive boundaries,
unborn/non-Git directories and controlled membership publication races. It uses
isolated repositories and the public Git/workspace services without providers.
Controlled file and missing-leaf replacements at handoff, discovery and capture
assert zero descendant reads, including reconstructed declarations and absolute
links entering a selected missing root replaced during capture. Valid absolute
file links retain root dependency evidence. Provider
receipt fixtures separately bind the optional file-only constraint and reject
malformed declarations before activity.
This capability does not activate pipeline scope selection or change run state;
workflow and durable preparation coverage remains with their owning changes.

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
validation cannot replace the original publication certificate. A one-shot
file-handle hook awaits a real lease-owner transition after a drain's stream
opens: retained and overflow pages continue with exact cursors. The real MCP
wait and Runner status path also exercises two publications in successive drains
for a new warm wait, a held wait with cold activity proof, and an evicted
checkpoint. These controlled interleavings reproduce the formerly generic
second-drain failure; they do not establish the historical interleaving.
Three raced drains require one more certified extension before returning typed
retryable exhaustion. A same-length restored-mtime prefix edit beside a real
publication still rejects, including during the third drain after a nested
reader caches the edited history. Unavailable proof during that continuation
also rejects. The fast MCP control-plane suite checks the typed structured tool
error for both observation tools, without automatic retries or code-based
classification of an unproved failure. A negative table proves that
runtime version skew, malformed state, a hard-linked state file and injected
`EIO` and `TypeError` failures found by the extension propagate instead of the
original read error, while the overflow hard-link case stays unavailable proof.
The state slow suite's bounded-heap journal case also covers overflowed
projections, complete progress, old cursors and repeated transitions across
segments.

Full-scan certification cases retain consumed-byte capture evidence when a
lease-owner publication follows the actual read, and when append or a small
legal rotation follows decoding during semantic validation. Cold, evicted and
oversized unretained checkpoints exercise public page/cursor pairing; a cold
full-scan MCP wait reaches the real Runner status and activity consumers.
Both certified and full-scan starts retain the three-drain exhaustion bound.
Additional controlled owner publications during capture, canonical recertification
and extension exercise warm, cold, evicted and overflow pages. A separate stable
consumed-prefix proof binds the raced extension's activities and cursor, even
when canonical state is already later. Repeated raced extensions exhaust the
existing bound only after that proof; observations leave all canonical journal,
state and progress bytes unchanged. Original-prefix and newly consumed extension
edits, file controls, hard links, namespace gaps and a newly sealed incomplete
tail remain strict rejections. The real MCP activity/wait, Runner and cold CLI
status consumers share these fixtures without sleeps, polling or providers.
Custody-inspection hooks publish a complete reservation after a proved extension
capture, comparing initial capture, warm reuse, cold settlement, eviction and an
overflow page that must still drain its unread prefix. Exact pages and cursors
remain paired; canonical journal, state, progress and custody bytes stay unchanged
after owner publication. Repeated reservation/settlement preserves the three-drain
bound, and another reservation at the once-only reload is refused. Distinct
orphan and rolled-back custody survive unrelated advancement; edits to original
or newly consumed bytes, changed controls and an unsafe hard link cannot obtain
a replacement proof.
Shared MCP activity and new/held waits consume the repaired schedule through real
Runner/store calls, with exact progress consumption and a controlled client
deadline rather than a fabricated terminal run.
Activity edits with restored mtime at equal and advanced endpoints,
file/directory replacement, namespace gaps and changed file controls cannot be
certified by a later valid scan. Recovery and append reject a captured endpoint
superseded by publication without changing canonical bytes. These callback-controlled cases establish
the repaired contract, not the unavailable historical stack. The affected
state/operator-stop, Runner operator-stop, legacy confirmation/migration,
MCP control-plane, CLI/MCP workflow, orchestration, effect-recovery and
release-pack slow checks remain required at finalization.

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
Access-policy coverage also proves that one compound `git status`,
`git branch --show-current`, `git branch -a`, `git remote -v`, `git tag --list`,
`git log`, `git cat-file`, `git diff --check HEAD`, and `ls` inspection succeeds
under every access policy while index, branch, tag, remote, configuration,
identity-bearing commit, and push mutations fail; the read-only sandbox also
denies workspace writes, and local-commit readiness uses that policy.
Workspace-write settings share the autonomous envelope with no `Bash(...)` rule
or root-relative `Edit(/.git…)` entry and exactly the absolute protected-directory
Edit denials; declared-directory workspace-write keeps its Git-subcommand
denials, and a protected Git path with a rule metacharacter fails before any
turn starts.
Git workspace-write coverage resolves each generated native and fallback
launcher through the turn's `PATH`, feeds it Claude's producer-ordered
arguments for the read-only preparation settings, and replays the resulting
bubblewrap vector through an independent test model in which a later mount
hides earlier mounts at or beneath its destination and a mount point cannot be
renamed or unlinked. Ordinary source files must stay creatable, renamable, and
removable only for workspace-write, while Git metadata, a selected input beside
a nested control, restored controls, and external paths stay unwritable and
irreplaceable. The model first rejects both earlier failure compositions: an
earlier nested restriction hidden by the grant and an ancestor pin after a
selected-file protection. An earlier file mask survives a later read-only
ancestor. Enclosing or hidden unsupported mounts, a tmpfs hiding protections, a
same-destination bind removing a mask,
weakened restrictions, and symlinked controls must exit before bubblewrap
starts. A temporary managed-settings directory proves that an administrator
`bwrapPath`, policy helper, or invalid drop-in leaves every access unavailable
before any isolation proof starts. A non-file override is modeled by Claude's
credential denial removing the shell proof: the generated shell must refuse that
command, run Claude's unsandboxed use, and run the same command through the
authenticated launcher. Probes require the same refusal with real execution.
Directory-probe simulations execute the generated probe script against the
same mount view. A read-only fallback turn proves that Claude's existing
owner-only temporary self-bind follows the private `/tmp` and `/run` mounts
while no other allocation path is bound, and that the descriptor bind keeps
the validated directory when the path is substituted afterward; a substituted
symlink and a regular file at that destination exit before bubblewrap starts.
A separate authenticated producer stand-in runs both generated launchers
against controlled bubblewrap with Claude's end and info sockets as descriptors
5 and 6. Bubblewrap must receive only the info socket, as descriptor 3 natively and after the filter
and retained bind descriptors under the fallback, with no `--sync-fd`; its
record must reach the producer, and the end must arrive only after bubblewrap
has exited. Killing the launcher while bubblewrap still runs must still close
the end descriptor. The still-running bubblewrap is registered before that
kill and, even after a failure, signaled only under its recorded identity;
after its standard error ends, its process state must show it exiting or gone
before the launcher and fixtures are removed; uncertain retirement retains
those fixtures. Producer completion and stderr EOF waits have deadlines. The
supervisor also records producer and launcher identities, and kills all verified
owners before awaiting their shared stderr during failure cleanup. An injected
event regression proves bounded stalled-producer and EOF failure while retaining
unverified owners. Older programs omitting both options still run without
forwarding any socket. A closed, standard, non-canonical, swapped, shared,
repeated or unpaired descriptor, an unsupported descriptor option, a regular file, the launcher's own Node control channel or
an unrelated process's live control channel relayed as the info descriptor,
a relay of both endpoints whose peers belong to an enclosing supervisor
without the producer proof, a proof-bearing process that does not match the
configured producer file, a copied foreign interpreter running the pinned script,
an interpreter evaluating code with that script path as ordinary argument data,
and a pair beside a control channel or another
inherited socket must exit before bubblewrap starts while the producer descriptors end. Named,
listening and non-Unix sockets fail through the same socket-table rule; they
are not constructed because host socket policy may forbid it.
Running the pinned shebang script through its pinned interpreter must still
pass the producer gate, covering both direct and `/usr/bin/env` shebangs.
Two bounded capability-gated Linux process regressions exercise the installed
bubblewrap direct-filter boundary without a model request, sleep, retry loop,
or slow-tier promotion. In the first, read-only and workspace-write fallback
probes run for real, confirming source changes and pinned-control denial with
actual syscalls. The second runs both generated launchers with a literal
Claude TMPDIR and requires a parent-readable cwd receipt, unchanged project
content, and a hidden restricted-host launcher. They do not replace post-install acceptance: after the
finalized commit is installed, the supervising agent starts a fresh real Claude
lazy plan-authoring run and requires preflight to advertise read-only,
workspace-write, and local-commit access plus a provider response before
dependent provider work continues.

The slow `test/agents/claude-native-policy.slow.test.js` suite owns the
model-free reproduction of the Claude native permission policy and workspace
staging through the installed CLI. Enable it explicitly on the host with
`AGENT_RUNNER_NATIVE_CLAUDE=1 npm run test:slow -- test/agents/claude-native-policy.slow.test.js`.
It is operator-owned native-platform acceptance: the Runner-trusted executor's
outer isolation does not provide the nested Claude sandbox required by this test.
The ordinary slow gate skips it, so passing that gate never establishes native
acceptance. When enabled, it skips only on non-Linux hosts or when `claude` or
`bwrap` is absent from `PATH`; unavailable workspace-write isolation and any
other preflight or protocol failure still fail. Every turn runs through the real
adapter probe, generated settings, authenticated launcher, and stream
normalization against an owned Git repository or ordinary directory,
configuration directory, synthetic key, and loopback Messages stub that scripts
tool calls and refuses every other request. Adapter environment/settings enforce
foreground execution for permission and cwd scripts, and each turn is awaited
before snapshots.
Owned-process supervision bounds each turn with a deadline and test
cancellation; interruption fails independently of any later adapter error.
Fixture cleanup requires verified retirement of every registered process;
otherwise it retains the fixture and fails. Claude receives only a
fixture-owned environment; seeded conflicting host provider routing,
authentication, header and proxy settings must never reach a Claude invocation.
Only baseline turns replace the generated
settings with the superseded workspace policy: a subcommand-rule refusal of
ordinary inspection must end as terminal unclassified Bash, script-driven
content work outside Claude's accept-edits fast path must receive a terminal
classifier refusal, and a workspace Git-metadata `Write` must miss the
root-relative rule and reach a classifier decision. Corrected turns must admit
Git inspection, fast-path filesystem work and script-driven content work without
a permission denial, deny an absolute Git-metadata `Write` without a classifier
decision, and admit direct Bash writes to Git `HEAD` and `config` without a
native denial so each returns a command-sandbox permission error. Neither
corrected multi-command Git turn may create `.claude` in the workspace.
A further Git workspace-write Bash command uses a descriptor witness that
reports sockets in both the executed Node command and its parent shell. A
test-only metadata tap in the generated launcher records the authenticated
producer socket identities and original stdio before projection returns,
without changing arguments, forwarding, or isolation. The command must hold no
nonstandard socket. No producer socket may reach the shell; any remaining
shell socket must match captured launcher stdio, accounting for saved stdio
without attributing its origin to IPC. The exact encoded native tool result
is retained and decoded for assertions. A separate model-free child with a
deliberately inherited socket at descriptor 9 must trip the same witness;
this diagnostic negative control grants no native-policy acceptance credit.
Claude 2.1.326 or newer must actually exercise a producer pair in that turn;
legacy producers without IPC options remain supported by the tap.
Read-only ordinary-directory sources initially lack staging and have either
synthetic instructions with `.claude/skills` linked to a canonical skill tree,
or a sparse `.claude` control holding one ordinary file. The directory
differential removes only `CLAUDE_BASH_MAINTAIN_PROJECT_WORKING_DIR` from both
launch environments. Without retention, a lone `pwd` leaves the source
unchanged, but `pwd`, source `Read`, then another `pwd` must successfully
complete all tools and the native turn before the adapter rejects source drift.
Both control shapes must acquire an empty mode-0700 `.claude/.cc-writes` and
a changed source/control snapshot. With retention, both control shapes must
complete unchanged: both Bash commands still execute in the workspace, source
`Read` succeeds, and source/control snapshots
and root and `.claude` directory metadata remain unchanged, with no denial or
unscripted request. Ordinary slow runs skip this differential; only an enabled
host run proves the mechanism and its prevention for the candidate.
A retained-cwd workspace-write turn over a sparse control with one existing
declared `out` output root must advertise `workspaceWrite` and admit a scripted
Bash write of `out/result.md` without a denial or unscripted request, while
Bash writes to `source.txt` and `.claude/notes.md` each return a command-sandbox
permission error. A sibling write under namespace-private `/tmp` may succeed
inside scratch or return a permission error; the host sibling must remain
absent in either case. Its snapshot must be unchanged
outside declared outputs, root and `.claude` directory metadata unchanged, and
no `.claude/.cc-writes` created. This proves the launcher's output-only
directory write authority through the installed CLI. It is operator-only
acceptance: run it against the candidate, and as a read-only differential
against the previous implementation. Accept that differential only when the
previous implementation fails specifically at the declared-directory writer
and the repaired implementation passes; an earlier policy or IPC failure does
not establish the directory repair. Claude may
still require separate native approval for sensitive Git commands, so the suite
does not claim that every Git mutation reaches the sandbox; the effective access
proof exercises those mutations directly. Every case leaves HEAD, refs, index,
configuration, and remotes unchanged, owned decoys for the stripped ambient Git
routing stay untouched, and public errors, records, and diagnostics carry no
command, path, free-text reason, provider payload, or key. A loopback endpoint
leaves auto mode without its server-side check, so test-local native records
distinguish rule decisions from classifier decisions. Changes to Claude
permission settings, effective access proofs, or policy identity require a
separate enabled host run before installation in addition to the complete slow
gate. Record both results and report any skip explicitly. No live model is used.

The suite also keeps a separate native foreground/background differential.
Conflicting caller and fixture user settings set
`CLAUDE_CODE_DISABLE_BACKGROUND_TASKS=0`; only the baseline removes the adapter's
forced value from both launch surfaces. All other policy settings, including
private cwd retention and permissions, remain identical. The strict Messages
stub captures the offered Bash schema and refuses and counts requests beyond
its bounded script without retaining their payloads. The baseline Bash command
blocks on an owned FIFO. At the first result the stdout tap must observe no
effect before releasing the FIFO; the baseline then requires the completed
effect and actual rejected post-result model traffic or a duplicate result.
Repaired turns require no background schema option, a successful effect before
the sole result, and no task-start/progress/notification records. An unsupported
background request may fail as a tool request or complete synchronously, but
cannot produce a late effect. A timed-out blocked command must prove it started,
return a tool error and never complete its effect. No sleep supplies causal
ordering; deadlines only bound hangs.

Both native fixtures use public owned-process supervision with forwarded
cancellation and ownership proofs. Pending turns are aborted and awaited, and
every registered process must report `onProcess(null)` before FIFO or fixture
removal. Their separate host temporary roots survive the test launcher's scratch
cleanup on uncertain retirement; uncertainty fails and retains storage. Native
records remain test-local and public diagnostics stay redacted. These lifecycle
cases supplement the newer source-shaped cwd and permission differential above;
they do not replace it or establish the cause of historical protocol failures.
The enabled suite remains supervisor-owned post-completion acceptance after
reviewed HANDOFF and the separate operator commit, against exact committed main
and the installed-package adapter, before global installation and activation.
It is not a pipeline required check, and ordinary slow skips establish no native
acceptance. Applicable post-install provider acceptance remains separately
operator-owned.

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
