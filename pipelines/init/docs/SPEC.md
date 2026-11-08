# Init infrastructure setup

## Status and ownership

`pipelines/init/` owns infrastructure inspection policy, proposal contracts,
read-only role requests, bounded clarification and proposal approval. It is registered as `init` through the existing CLI and asynchronous STDIO MCP
runner. Setup completion never grants a Git effect. `PROPOSAL_ACCEPTED` is an internal gate, never a claim that
infrastructure exists. Internal Runner-owned integrated and external prerequisite
publication is available after this gate. Guidance publication and distinct terminal confirmation precede public completion.

The private workspace has no runtime dependencies. Root composition supplies
the public workspace and configuration capabilities; the pipeline does not
import root implementation files or another pipeline. Its descriptor selects a
directory lifecycle and canonical exclusive workspace lease before Git
inspection. Planner and Reviewer have only `read-only` access.

## Inspection and placement

`inspectInitSetup` consumes explicit instruction, check, skill and guidance file
inventories discovered from actual project evidence. It reads them through the
workspace capability and retains paths and hashes, not their contents. Empty
inventories are valid when the project has no such files. Agents must inspect
actual requirements and commands; hashes do not invent validation requirements.
Existing guidance text remains supervisor input. Init reviews existing and
proposed guidance as setup data for merging and publication; it never becomes
instructions for those roles.

Candidate configurations are loaded through the configuration capability with
its existing target binding, precedence, ignored/untracked protections where
applicable, confined reads and provider-authority restrictions. The injected
loader is bound to the run's existing runner configuration and workspace kind;
Git inspection remains Git-owned. Candidate project settings are setup data,
never a second source of live role/settings resolution for init.
The caller supplies the resolved artifact root; its default stays configuration-owned.

Inspection binds the canonical target, task inputs, live configuration paths,
candidate roots, missing destinations, file contents/identities and real
ancestors. It rechecks configuration protection and snapshots around document
reads. The clarification service separately owns the transcript hash and
authorized edit windows. Task and clarification artifacts must be external to
the target, so initial setup requires no ignored target directory. Existing
repository-local artifact protections remain unchanged.

New inspections use schema version 2. Complete workspace capture still visits
and protects every source/control path, including sources beyond 10,000 entries.
Workspace-owned compact proofs bind full ordered content/identity evidence and
link resolutions; scope bindings additionally retain real ancestor and control
bindings. Only bounded setup documents, exact candidate destinations, their
relevant ancestors and bare-control markers appear in role-facing `entries`.
An explicit `kind: "missing"` entry proves absence from complete traversal;
omitted paths and file/link ancestors cannot prove absence. A proposal lacking
that exact destination evidence rejects before acceptance. Document groups retain
their 256-file bounds, candidates their 32-entry bound, and setup collections
their 10,000-entry bound; compact records are limited to two MiB. Unsupported
evidence capacity rejects completely before role work or publication authority.

Init descriptor state version 3 preserves version-1 and version-2 inspections unchanged,
including their original hashes, approvals, reservations, publication
records, accepted receipts and consumed accounting. Reinspection follows the
saved inspection version. Migration creates no missing evidence or allowance;
legacy limits remain applicable to legacy bindings. The explicit 2-to-3 migration
initializes only nullable `correctiveFeedback` to null and invents no diagnosis;
version 1 still passes through its identity migration. No shared collection limit,
workspace scope or provider permission changes.

Placement is separate from review mode. The descriptor reserves CLI
`--placement integrated|external` and MCP `placement`, separately from `mode`. Missing placement reuses one unambiguous established target-bound
candidate. With no candidate, it selects integrated. Explicit configuration and
placement must agree. Multiple matching candidates require a material selection
during clarification; their resources are never merged or moved. Only explicitly
supplied external configurations are loaded; there is no sibling scan or global
registration. Explicit placement can propose a new destination while retaining
the previous setup.

Inspection receives the current placement and configuration selection. It
inspects the default external sibling only when a new external destination is
selected; an unusable unselected sibling cannot block integrated setup or reuse
of another bound external root. An authorized pre-closure selection change
requires a fresh setup inspection before clarification can freeze the new binding.
It retains the original inspection while waiting. Passing `previousInspection`
to `inspectInitSetup` carries previous destinations and evidence forward,
adds newly selected scopes, and verifies each
prior scope's content, identities, real ancestors and controls. A placement edit
cannot adopt changed task inputs, live configuration or previously inspected
resources, even when the destination stays the same.

New integrated configuration is `<artifactRoot>/agent-runner.json`. New external
configuration is `agent-runner.json` under the sibling root
`.agent-runner-<safe-name>-<12-character-path-hash>`, using the canonical target
path's SHA-256 prefix. An existing unbound destination is not adopted. Relative
resources use the selected root, and existing bound resources keep their exact
paths. A new external root must remain missing from the initial probe through
the bound inspection and document snapshots, retaining the probe's real ancestor
identities. Selection and the clarification hash freeze together before proposals.

Active role turns carry the Runner-owned [session naming context](../../../docs/product/PROVIDER_MODEL.md#sessions-and-context).
The creation acknowledgement records a verified new child at this pipeline's
existing logical context key before a naming diagnosis or metadata failure is
returned; the eventual response does not record it twice. Naming diagnoses grant
no retry, source fork, replacement,
owner cycle or workflow/effect authority. Continuation preserves historical sessions.

## Read-only lifecycle

The proposal API uses explicit durable transitions. `prepareInitTurn` returns a
state reservation and a role request; the caller persists it before invoking an
adapter. Reloading a reservation retains its identity. `acceptInitResult`
requires that identity and a fresh unchanged setup inspection and transcript
hash. Consumed/stale results and read-only drift cannot advance the gate.

Every run starts in `CLARIFY`. Planner returns `READY`, material `QUESTIONS`, or
`BLOCKED`. Competing placements cannot close clarification. There are at most
three agent question rounds; this is not a configurable workflow budget.
Questions and their rationales use the shared service's 4,000-character plain-text limit.
An accepted question round first reserves a pending Runner-owned append.
The shared service journals the exact result hash before replacement through
the pipeline persistence callback. Resume accepts only the prior transcript or
those exact appended bytes, including interruption after replacement and before
editor authorization; it never duplicates questions or adopts unexpected edits.
After the shared clarification service appends the exact questions,
`acceptInitQuestionAppend` records its resulting hash against the reserved round,
previous hash and transcript path. The receipt is consumed before authorizing
an answer window and cannot be reused.
`authorizeInitEdit` is the clarification service's persist-before-open callback.
For proactive clarification it records `proactiveClarificationComplete` together
with the pending authorization in one transition. Preparation failure leaves the
proactive request incomplete, so unchanged-input resume retries authorization
before provider work. A persisted authorization still requires its one-shot close.
`acceptInitEdit` consumes the matching one-shot authorization, including an empty
or unchanged editor close, without spending another round. Material answers use
the shared `clarification-answers` action. An unchanged answer window leaves the
same questions pending; the caller authorizes a new window without invoking the
Planner or appending the questions again. An unchanged optional proactive window
returns to clarification normally. Only pre-closure
selection can change. The caller freezes the transcript through the existing
clarification service before `closeInitClarification`. There are no ordinary
question or editor paths after closure. Every later role schema, including
terminal confirmation, supports `PRODUCT_DECISION_REQUIRED` with a bounded
question, options, blocking rationale and nonempty evidence. Ordinary findings
and technical choices use revisions. Runner persists the suspended decision
and exact append intent, then authorizes a one-shot `product-decision` answer
window through the shared clarification service and CLI/MCP input contract.
An unchanged close keeps the same request without appending it again. A changed
answer freezes the new transcript hash and restarts the complete proposal gate;
the selected placement and paths stay frozen. Decisions after publication retain
the verified prepared baseline and original procedure-repair authority. They
grant no counter reset, new permissions or authority over another destination.

Planner returns a complete structured proposal with actual checks and exact
configuration, artifacts, finalization and guidance resources, their inspected
prior hashes, actions and proposed contents. Each of these resource kinds occurs
exactly once so guidance, publication and repair bind the same finalization
procedure. Results retain the two-MiB bound.
Ordinary proposal envelopes use `PROPOSAL`; review envelopes use `CLEAN` or
`FINDINGS`. Their question/rationale fields are empty strings and their
decision options/evidence are empty lists.
No role writes those resources. Proposed writes cannot overlap configuration
resolved for this run, skills that predate setup, Git/provider controls or symbolic links.
Inspection retains workspace-discovered control paths, including Git metadata
whose directory name is not `.git`. The only control-tree write destinations
are the conventional `.agents` or `.claude` finalization `SKILL.md`/`RUNNER.md`
files; pre-existing skills and nested controls remain protected. Writes inside nested
Git worktrees are prohibited because they require a different exclusion key.
Bare Git metadata remains protected even when its root is a conventional provider
directory; finalization selection and proposal validation reject that overlap before
any prerequisite publication.
Exact task inputs
(`task.md`, optional `context.md`) and `clarifications.md`, plus inspected
instructions/check definitions, cannot be overwritten. A parent task directory
does not exclude unrelated setup destinations beneath it. Artifacts are
directories with no file content; other resources cannot replace directories or
use file ancestors. The frozen placement must match the recorded clarification
selection on every reload.
Guidance uses the selected artifact root's `agent-runner/rules.md`; ignore
resources can name only the integrated target's `.gitignore`, and finalization
resources must be Markdown procedures.
External resources stay outside the target; external proposals grant no target,
ignore, pointer-file, global configuration or provider authority.

| Mode          | Proposal gate                                                                       |
| ------------- | ----------------------------------------------------------------------------------- |
| `independent` | Planner proposal, separate Reviewer approval                                        |
| `lazy`        | Planner proposal, CHECK_AND_FIX, distinct CLEAN_CONFIRM                             |
| `combined`    | Planner proposal, CHECK_AND_FIX, distinct CLEAN_CONFIRM, separate Reviewer approval |

Independent remains the default and recommendation; lazy is explicit opt-in.
Inactive Reviewer configuration is not resolved or invoked. Planner check/fix
returns the complete durable replacement without writing files. Confirmation
and independent approval bind the same proposal, inspection, selection and
clarification hash. Findings clear dependent approvals and return to Planner;
combined revisions restart primary convergence. No arbitration is introduced.
Revision accounting is bounded, persisted and never renewed by reload. Exhaustion
pauses. Proposal acceptance grants no publication, staging or commit authority.

## Semantic result rejection

Only actual result validators establish a trusted finite constraint. Init owns
`result_shape`, `resource_destination`, `resource_prior_hash`, `guidance_size`,
`finalization_procedure`, `configuration_policy` and `ignore_policy`.
The guidance capability additionally owns `guidance_encoding` and
`guidance_content`; its size guard also uses `guidance_size`. The project
configuration parser owns `configuration_shape` and `configuration_version`.
Original codes remain `ERR_INIT_PROPOSAL`, `ERR_INVALID_GUIDANCE`,
`ERR_INVALID_CONFIGURATION` or `ERR_UNSUPPORTED_CONFIGURATION_VERSION` as
established by that validator. Capability-owned recognition retains error identity;
matching an arbitrary error code, message, cause or provider field is insufficient.

After fresh unchanged-source/control/transcript verification and physical turn
retirement, Runner atomically persists the resumable `invalid_result` pause,
safe activity and init-owned `correctiveFeedback`. It retains only the finite
code/constraint, original reservation `{ id, role, phase, binding }` and settings hash.
Bindings cover settings, inspection, selection, clarification/transcript, proposal,
findings and consumed revision/question counts; `CONFIRM` additionally binds
the published snapshot fingerprint. Rejected contents, keys, values, paths,
messages and native data never enter diagnosis. The previous valid proposal and
unaffected approvals survive; no rejected resource is accepted or published.

Supported same-checkpoint resume and reconstruction receive the same code,
constraint and fixed corrective explanation through the role request. CLI/MCP
status, fresh/held waits and safe journaled activity agree with that explanation.
Another rejection replaces feedback; successful acceptance or a product decision
clears it. Invalid/stale bindings and phase transfers reject. Sequence, mode,
budgets, fork/reconstruction consumption and effect authority are never renewed.
Adapter structured-output rejection without semantic evidence remains generic
and clears previous diagnosis. Legacy absence stays unknown.

Persistence and Runner callback errors remain outside result-validation handling,
even when their codes collide. Ownership/isolation, source/configuration drift,
inspection, product decisions, terminal-provider failure and pending effects
retain their existing precedence. Diagnosis grants only the existing checkpoint's
correction opportunity and cannot bypass publication reconciliation.

## Integrated prerequisite publication

`publishIntegratedInit` is a separate Runner effect API, not an agent turn or
descriptor dispatch. It requires `PROPOSAL_ACCEPTED` in integrated placement,
the original frozen inspection, and the selected mode's exact proposal approvals.
The caller must hold the existing canonical exclusive workspace and execution
leases. It supplies public workspace/configuration/clarification/Git inspection
capabilities, the existing supervised no-replace directory publisher, a lease assertion and a
write-ahead persistence callback backed by run-store transitions. No second store
or provider write permission is introduced. Destination configuration remains
setup output; it never changes this run's resolved configuration.

Before recording the filesystem baseline and throughout publication, the
clarification capability verifies the actual transcript against the frozen
clarification hash. Changed or missing closed clarifications cannot be adopted
as setup input. Before effects, policy validates the complete proposal.
Configuration parsing uses the existing project-only schema. Only infrastructure binding, artifact root
and execution/polishing finalization selections may change; unrelated settings
survive. The exact selected finalization procedure is explicit in both pipelines.
New skills use the established `.agents/skills/finalization/SKILL.md` location,
or an existing `.claude` skills layout. An existing inspected finalization skill
is preserved byte-for-byte. A bound configuration may reuse its selected skill
when it already matches the required procedure and ordered checks; otherwise it
selects adjacent `RUNNER.md` instead. An existing
wrapper is reused only when it matches the reviewed procedure; conflicting
contents are preserved and rejected before effects. The derived
procedure is part of the reviewed proposal, contains its actual ordered checks,
reads actual project instructions and preserves the original skill's substantive
requirements. Its pipeline adaptation defers staging, index-relative inspection
and commit preparation to COMMIT/HANDOFF, translating applicable staged checks
to content checks during FINALIZE. It never weakens those checks or commits.

Publication preserves the original `.gitignore` bytes, including comments and
negations, adding a separator for a missing final newline and one literal anchored
exclusion per needed path. An earlier exclusion cancelled by a later negation is
reasserted literally without whitespace padding. This includes configured
artifacts, configuration, deferred guidance and exact publication temporaries.
An absent ignore file is created.
Applicable Git inspection rejects tracked infrastructure and verifies effective
ignoring after ignore publication and before later writes. Directory workspaces
need no Git initialization; Git-specific inspection remains capability-owned.
The artifact root is the frozen selected value, with the configuration-owned
default unchanged. No ignore/info-exclude/global-ignore or unrelated setting
outside the reviewed integrated `.gitignore` is changed.

Runner first journals the publication binding and unchanged filesystem baseline,
then each exact file/directory intent. Directory allocation reuses private state
and the existing no-replace primitive; its identity is persisted before publication.
Lease ownership is rechecked after that persistence and before publication.
File replacement reuses confined directory descriptors, exclusive temporary
creation, journaled temporary identity, synced bytes, atomic rename and verified
readback. Unknown temporaries, same-byte inode substitutions, ancestor changes
and intervening edits are rejected and preserved. Temporary paths remain stable
for each exact destination, avoiding new ignore entries on ordinary reruns.
Each resource receives a
verified identity/hash receipt before the next effect. Reload binds the original
proposal, selection, state storage and approved paths; a lost file receipt can
reconcile the exact prepared temporary identity already at its destination.
Recovery requires the new ignore exclusions only after the ignore publication
has a verified receipt; a pending ignore intent reconciles first under the same
baseline and identity guards.
Ambiguous directory allocations remain preserved for recovery, never adopted.
Completed prerequisite receipts are verification-only on rerun.

Version-2 publication baselines retain exact prior entries for reviewed files,
required directories, stable publication temporaries and deferred guidance,
plus a compact complete hash of the immutable remainder and all link resolutions.
Every guard recaptures the complete original scopes. Only pending intents and
verified receipts permit their exact paths to differ; a guidance-action temporary
outside the retained inventory must have been absent in the original remainder.
Existing bytes cannot disappear into a new allowance. Receipts still verify
published identities and contents independently. Same-run repair `setupBaseline`
uses the same compact proof with exact procedure evidence; only the shared
clarification transcript is excluded under its existing service authorization.
Terminal confirmation continues binding the complete resulting snapshot.
Version-1 publication and repair baselines retain their original comparison and
terminal-fingerprint algorithms, including pending-effect recovery.

The order is ignore protection, artifact preparation, finalization, then destination
configuration. Guidance is excluded from publication and remains deferred.
The `prepared` marker means only these prerequisites have verified receipts;
it is neither a completion receipt nor a claim that setup is usable. The registered lifecycle recovers these exact records before guidance publication
and terminal confirmation. This API never
stages, commits, changes Git controls/identity or starts another pipeline.

## External prerequisite publication

`publishExternalInit` applies the same approved-proposal, frozen-clarification,
write-ahead intent, lease and verified-readback contracts to the external
selection. It returns `{ publication, configurationPath }`; the exact absolute
selector can subsequently be supplied as CLI `--project-config` or MCP
`projectConfigurationPath`. The publication record is persisted through the same
callback and supplied unchanged for recovery. It prepares prerequisites only.

New external roots use the inspected canonical target's parent and
`.agent-runner-<safe-name>-<12-character-path-hash>` name. The safe name replaces
characters outside ASCII letters, digits and hyphens with hyphens and keeps at
most 48 characters; an empty name uses `project`. The hash is the first 12
hexadecimal characters of SHA-256 over the full canonical target path. The hash
is a naming aid, not binding proof: existing roots require explicitly selected
configuration whose complete versioned target/root protection has been verified.
Occupied unbound roots, wrong-target bindings and identity substitutions are
rejected. Selected bound roots retain their exact configuration and artifact
paths, including nondefault locations, without relocation or global registration.
Before publication is journaled and at each publication guard, including recovery,
controls-only workspace inspection rejects destinations inside Git or provider
storage, including canonical ancestor alias targets omitted from general snapshots.

Runner publishes the absent root using the existing private allocation and
no-replace directory primitive, then configured artifacts, `finalization/SKILL.md`
and destination configuration. A new configuration is root `agent-runner.json`.
Only these reviewed resources and their necessary directories receive effects;
the root's parent is a confinement anchor, never a parent-wide read/write scope.
The caller's lease assertion covers the canonical target exclusion and selected
infrastructure, including when the target is inside an enclosing worktree.
The full target, discovered controls and inspected setup inputs remain in the
unchanged snapshot throughout publication. Ordinary directories require no Git
initialization. No target file, instruction, skill, ignore rule, info-exclude,
global ignore, pointer or global prerequisite is created or changed.

External finalization is rendered for proposal review from actual instructions,
ordered checks and inspected project finalization skills. It references those
skills from the target working directory without copying or editing them.
Existing external procedures can be reused only with the exact reviewed contents; conflicts are
preserved and rejected. Configuration selects `finalization/SKILL.md` explicitly
for execution and polishing and resolves relative resources from the bound root.
Unrelated settings survive. Guidance remains proposed but unpublished until its
guidance-last gate; neither a selector nor `prepared` is setup completion.

## Inspection failures

Expected discovery, initial/additive inspection, turn preparation, post-turn
verification and publication preparation failures settle through the leased
lifecycle boundary before execution ownership is released. The same init-owned
policy covers root recovery verification before lifecycle dispatch. No provider
turn, approval or publication may proceed without complete accepted inspection.
An inspection rejection is not invalid provider output.
Editor authorization, clarification append reads, authorized-close reads and the
runtime adapter's before/after workspace snapshots use the same scoped inspection
policy. Append intents and receipt replay retain their exact hash bindings;
write failures are not converted into inspection retries. Provider invocation
and effect failures retain their separate handling.
Initial task/context hashes come from one scoped input capture. Prepared
configuration and prior-guidance verification remain scoped reads before a
guidance intent is reserved. Publication resource inspection and repair-baseline
capture use the same policy before reserving their effects. Input submission
diagnoses complete source verification and pre-write clarification read rejection
before writing answers, preserving its pending authorization. The clarification
service scopes its initial read and replacement recheck separately from writes
and post-write readback; failed or ambiguous writes retain exact recovery.
Proposal-policy source reads are scoped separately from validation of proposed
content, so read rejection cannot become an invalid provider-result pause.
Pre-dispatch canonical validation also settles
recognized rejection through this policy while both execution and workspace
ownership are verified and held. Acquisition and unknown ownership failures
remain fail-closed; rejected input submission cannot acknowledge an unwritten answer.

The durable `init_inspection_failed` pause uses code `ERR_INIT_INSPECTION` and
`inspectionFailure: { phase, constraint }`. Phases are `discovery`, `inspection`,
`reinspection`, `preparation`, `post-turn`, `publication-preparation` and `recovery`.
Constraints are `evidence_capacity`, `destination_unavailable`,
`configuration_invalid`, `workspace_changed`, `unsafe_path` and
`inspection_unavailable`. These finite values and fixed explanations exclude
native messages, rejected values, paths and private data. CLI and MCP status/wait
share the diagnosis and supported next action, including after reload.
Clarification/configuration file readers preserve their existing error codes and
attach only trusted `file_size` or `isolated_regular_file` constraints for their
size and regular-file/isolation guards. Init maps these to `evidence_capacity`
or `unsafe_path`. Explicit integrated configuration absence carries `missing_file`
and maps to non-resumable `workspace_changed`; implicit absence remains valid
discovery. No message parsing or blanket classification of generic read
errors is permitted. Unrecognized constraints and corruption remain fail-closed.
Guidance read normalization preserves these trusted inspection categories as
finite `readFailure` metadata under its original error code, including recognized
native I/O failures wrapped by guidance's own file/directory readers. Scoped init
reads accept only the recognized guidance/configuration read codes and categories;
this includes returned directory verification normalized as `ERR_GUIDANCE_STORAGE`
with trusted finite read metadata, never the storage code or nested causes alone.
Publication/recovery errors and unverified pending effects gain no retry authority.

Capacity, invalid configuration, changed evidence and unsafe/unavailable
destinations require preserving work, correcting prerequisites outside the run,
and starting a fresh init run. Only recognized transient inspection-access or
resource failures permit action-free resume: restore access/resources without
changing frozen inputs. Resume rechecks complete original bindings before any
new turn. No correction reopens clarification, resets accounting, changes frozen
selection or grants publication authority. A rejected reservation is retired
without accepting its result; sequence and consumed budgets remain unchanged.
An existing non-resumable blocker or exhausted checkpoint is never replaced by
a transient inspection pause. Recovery retains its original diagnosis and
continuation restrictions; reload rejects an inspection pause over blocked or
exhausted pipeline state. Operator-pause restoration and submitted-answer receipts
also retain their original checkpoints rather than becoming inspection retries.

Unknown errors/corruption and unavailable ownership propagate fail-closed.
Pending prerequisite or unacknowledged guidance effects retain their existing
exact recovery protocol; inspection diagnosis never turns failed or ambiguous
effects into generic retry authority. A concurrent operator stop settles ownership
and preserves the diagnosed pause in its suspended checkpoint; recovery acquires
canonical ownership before settlement when it is not already held. Repeated
recognized inspection rejection during settlement retains a diagnosed stop
without accepting partial evidence. Diagnosis, read-only reservation retirement
and any concurrent stop settle in one state-owned atomic checkpoint transition;
ordinary turn retirement cannot precede that settlement. Start/resume
receipts acknowledge admission/dispatch only; use status/wait for the diagnosed
outcome. Exact-key replay does not dispatch another owner.

Inspection diagnosis adds fields only to the existing extensible pause envelope.
It changes no proof versions; historical inspections, approvals, receipts,
reservations and counters are not migrated or fabricated.

## Terminal provider failures

After unchanged-workspace verification and physical turn/resource retirement,
an unhandled boundary-normalized terminal adapter failure persists `FAILED`
before execution ownership is released. Only the matching reserved read-only
turn is retired; `CONFIRM` has no proposal reservation. Sequence/revision counters,
consumed source forks and reconstruction allowances, acknowledged children,
frozen inputs, approvals and prepared/publication evidence remain unchanged.
A failed terminal confirmation retains its `PENDING` fingerprint and published
resources without a completion receipt. Pending or ambiguous publication effects
and retained execution resources keep their existing strict reconciliation paths.

The existing pause envelope carries `reason: "internal_failure"`, a bounded code
and optional registry-normalized `diagnosticClass`. The common envelope validates
class membership; init validates the exact terminal shape and settled ownership.
Unknown classes stay absent. Historical ownerless checkpoints are never inferred
to have failed, and authentic saved shapes require no state/proof version change.
Native messages, payloads, prompts, sessions, profiles and credentials never enter
the diagnosis. Read-only Runner callback failures retain their original error even when a
native adapter wraps or swallows them; they are not provider failure evidence.

Output exhaustion, authentication, structured-result correction, inactivity,
availability, recoverable interruption and operator stops retain precedence.
[Inspection failures](#inspection-failures), control drift, unrelated I/O,
malformed state, uncertain cleanup and persistence failures retain their safety
paths. Failed settlement or activity publication propagates without acknowledgement.

Foreground CLI returns the durable failure, prints its fixed guidance and exits
unsuccessfully. CLI/MCP status and fresh or already-held waits share the saved
bounded diagnosis; terminal waits finish with `timedOut: false`. A safe `failed`
activity is journaled with the outcome. Reads never acquire execution authority,
repair state or retry a provider. `FAILED` is descriptor-declared nonresumable:
owned cleanup may finish, but continuation performs no new provider work.
Preserve the failed init and any prepared resources, review the supported
diagnosis, and resolve established prerequisites before a separately authorized
new init run. Missing historical attribution remains unknown.

## Public completion and recovery

Use `agent-run run init --project <target> --task <external-task-dir>` or MCP
`run_start` with `pipelineId: "init"`. CLI `--placement` and MCP `placement`
select `integrated` or `external`; omission reuses an unambiguous established
setup and otherwise selects integrated. Both placements support every mode.
An explicit `--project-config` / `projectConfigurationPath` reuses its bound
infrastructure. Explicit migration selects a new placement without deleting the
old resources. Destination configuration cannot overwrite configuration resolved
for the active run. The external task directory supplies `task.md` and optional
`context.md`; neither transport initializes during ordinary reads.

Root composition supplies the existing workspace/configuration services, shared
clarification service, state-owned leases/actions and supervised directory move.
The canonical target exclusion stays leased throughout execution. External setup
also leases its exact destination, including an absent root, using the same
serialized overlapping-workspace admission, unless the already-held enclosing
worktree exclusion covers that destination. Every publication guard verifies
the applicable workspace ownership tokens and the execution lease. Failed release
retains the exact infrastructure lease handle for same-run recovery. Canonical
workspace release also settles retained infrastructure ownership after verified
recovery or operator stop settlement. Authorized
clarification changes may add exact inspected read scopes before selection freezes, reproving active
roles and journaling the new binding under both leases. Document discovery then
refreshes within those reads, preserving the first inspection's exact bindings;
outputs and all other permissions stay unchanged. After verified Runner publication, resumed read-only
policy proofs may bind the identities created by those effects. The original
provider version, capability flags and access requirements remain fingerprinted
and must match before any rebinding. No other run
receives workspace rebinding or provider-write authority. A pending publication permits
only its exact journaled paths to differ from the original baseline; receipts
still verify identities and bytes. This recovery proof does not grant provider
write access or exempt unrelated target content from inspection.

After prerequisites have verified receipts, Runner loads the published selected
configuration and verifies availability. It reads the complete local guide,
checks its reviewed prior hash, and reserves an exact guidance action before
publication through the guidance capability. The intent pins the original file
identity, and acknowledgement verifies the action-owned published identity even
after a lost receipt; an identical-byte replacement is never adopted. Guidance
is LAST. Reviewed useful
local instructions survive; a delimited managed section records placement,
canonical target, configuration selector, artifact path, exact selected
finalization resource, working directory and ordered checks. Reruns replace
only that section and do not duplicate it.
The complete merged document retains the existing 65,536-byte bound. All proposal
results validate that rendered bound before acceptance, including existing text
and setup metadata, so invalid output leaves the previous proposal retryable.
The guidance capability also validates the complete rendered document before
proposal persistence; unsafe content follows the resumable invalid-result path.
Placement-specific finalization, configuration and ignore policies are also
validated before a proposal becomes durable review input. Invalid content leaves
the previous proposal retryable without reserving publication effects.
All proposal reviewers see the resulting guide. Expected-hash replacement, pinned action
selection and prepared-file identity allow lost acknowledgements to reconcile
without overwriting an intervening edit or redirecting a prior intent.

A separate read-only `CONFIRM` turn inspects the complete prepared snapshot:
Planner in lazy, Reviewer in independent/combined. Every role request and its
reconstruction prompt include the task, optional context and current accepted
clarifications, including this distinct confirmation. Only structured `CLEAN` over
the unchanged fingerprint permits a durable completion receipt. Findings charge
one revision, clear dependent approvals and return to proposal work over the same
selected paths and verified prepared baseline. The mode's complete proposal gate
and publication verification run again; reload cannot renew the revision budget.
Only a finalization procedure created by this setup can be repaired against that
verified baseline. Skills that predate the run remain unchanged; a subsequent
run gains no repair authority over an existing procedure.
Completed setup is verification-only. Failure or cancellation preserves resources
and publication records; setup never stages, commits or launches another pipeline.
Operator pause/cancellation validates the preserved suspended checkpoint,
including a reserved proposal turn or pending clarification editor. Resume of a
pause restores that checkpoint; cancellation is terminal. Root safety blockers
retain reserved read-only bindings without granting continuation through drift.

CLI status and MCP status/wait expose placement, exact reusable selector,
artifacts, checks, working directory and created/reused/changed resources. Partial
preparation remains distinct from completion. Use a new separately authorized
workflow after setup; do not treat its finalization procedure as executed checks.
Paused status includes bounded concrete setup findings and reason-specific
explanations, including initial `BLOCKED` results and revision exhaustion.
Recoverable spawn or initialize failures restore a requested source-fork
reservation only with validated pre-fork launch recovery evidence. Possible
effects or later checkpoints retain consumption; retry never repeats an
unproved fork.
Successful inactivity or provider-requested reconstruction settles against the
verified per-turn workspace snapshot, including during terminal confirmation
after Runner publication. Pre-turn reconstruction exhaustion persists a resumable
`provider_interrupted` pause at the original checkpoint. Owner loss and explicit
resume retain attempt 2 consumption, source-fork reservations and revision
accounting; they never renew an automatic reconstruction allowance.
