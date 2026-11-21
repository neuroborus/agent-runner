# Runner Composition Coverage

Read the affected sections before changing this contract. Use the [topic map](README.md)
for related owners and required reading routes.

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

## Interrupted finding repair continuation

The combined finding-repair regression in
`test/runner-operator-stops.slow.test.js` stops an owned resolution before repair
completion, cold-loads the settled journal and inspects the dirty candidate
read-only. It preserves the earlier accepted commit, original blockers, frozen
inputs/configuration, pending checks and once-only correction accounting.
Controlled authorization and invocation acknowledgement losses distinguish a
reusable unstarted reservation from a consumed invocation requiring reconciliation,
retirement and explicit read-only recovery. A newly authorized repair still passes
primary convergence, independent candidate review, finalization and distinct
terminal confirmation before one exact second commit. No sleep, polling, model
or surviving native session supplies correctness. The focused polishing
`resolution-correction` journal fixture additionally cold-loads its distinct
repair-required/authorized checkpoints and retains unfinished history in terminal
reconstruction. These development regressions do not replace the complete slow
gate, separate exact-artifact package-install check or operator acceptance.

## Deferred workspace preparation

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
explicit null retry. That suite also owns the
[cold repair continuation](#interrupted-finding-repair-continuation) fixture.
`contracts-and-migrations` owns the version-20 checkpoint validator, migration
and diagnostic allowlist.

Fast `test/git/repository-safety.test.js` owns the read-only snapshot-change
label normalizer and real-Git `readOnlyChanges` classification;
`test/state/persistence.test.js` owns durable label validation, including
operator-retained pauses; and `test/pipeline-registry.test.js` owns composed
and uncomposed contamination evidence. Polishing `mode-routing` and execution
`clarification-and-bootstrap` own the guard-to-pause path, cold reload,
activity and unchanged clearing; `test/runner-custom-execution.test.js` owns
the Git-free unavailable stop.

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
cross-capability lifecycle retain the affected [slow owners](slow-gates.md) and the complete
slow release gate; focused development cases do not attest those gates or the
separate package-install requirement.

## Audit composition

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
acknowledgement with its journaled prepared custody, completion binding, and
rendering-change and custody pauses that keep a suspended checkpoint, with
injected effects.
Fast `test/runner-audit-publication.test.js` owns public Runner/CLI metadata and
MCP report projection for Git and ordinary directories, plus actual
confined artifact replacement, prepared-custody and partial-write recovery without
replaying accepted discovery, the inert equal-hash receipt, and preserved
refusal of unproven custody, injected entry races, edits and
temporary/destination/alias substitution, with generic unrelated descriptor
errors. The final lookup fixtures hold sampled metadata equal, model pending
entry notifications at the closing directory read, and check drift precedence
for destination disappearance. One child process proves a quiet readback under
adverse parent runtime options and preloads.
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

## Custom authoring composition

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

## Shared plan contracts

Fast `packages/custom-plan/test/custom-plan.test.js` owns the pure custom-plan
contract: analysis/output plans, immutable parsing, canonical round trips,
closed declarations, explicit kind compatibility, sequential steps and complete
criterion references. It needs no Git, provider, command execution or temporary
storage. Commit-plan syntax remains covered by its separate package suites.

## Directory lifecycle

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

## Refinement progress publication

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

## Audit publication

Read the [current contract](#runner-composition-coverage).

## Custom execution composition

Read the [current contract](#runner-composition-coverage).

## Custom decision recovery

Read the [current contract](#runner-composition-coverage).

## Output preflight

Read the [current contract](finalization.md#finalization-applicability).

## MCP recovery diagnostics

Read the [current contract](state.md#state-and-journal-coverage).

## CLI recovery diagnostics

Read the [current contract](#runner-composition-coverage).
