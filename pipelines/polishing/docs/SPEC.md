# Polishing Pipeline — Specification

## Goal

The `polishing` pipeline takes an existing non-empty set of local repository
changes and brings it to a correct, idiomatic, minimal state that follows the
target project's conventions. It finalizes and reviews the exact result, then
stages the complete change set while leaving every change uncommitted.

The pipeline is independently owned. It reuses the root Agent Runner services
for Git inspection, clarification files, agent adapters, external state,
execution leases, public activity, CLI dispatch, and MCP control. It does not
depend on another pipeline or on `@agent-runner/commit-plan`, and it does not
introduce a workflow DSL or generic workflow engine.

## Technology And Ownership

Use plain JavaScript, native ES modules, Node.js `>=24 <25`, the standard
library, and `node:test`. Normal tests use fake adapters and temporary Git
repositories; live model calls remain opt-in.

Pipeline-owned files live under `pipelines/polishing/`:

```text
pipelines/polishing/
├── package.json
├── docs/
│   └── SPEC.md
├── src/
│   ├── capability-requirements.js
│   ├── gate-evidence.js
│   ├── index.js
│   ├── mode-policy.js
│   ├── prompts.js
│   ├── schemas.js
│   ├── workflow-contract.js
│   └── workflow.js
└── test/
```

The workspace owns its roles, settings, input interpretation, prompts, strict
schemas, persisted-state validation, explicit JavaScript state machine, retry
policy, and completion criteria. Root modules retain their documented
ownership; pipeline registration remains static.

The private `mode-policy.js` separates active roles, independent bootstrap,
primary convergence, independent review, terminal confirmer, arbitration, and
primary session scope. The workflow, persisted validator, resume-action checks,
and legacy migration use these decisions for the supported
`independent`, `lazy`, and `combined` modes.

The private `gate-evidence.js` composes primary clean evidence, independent
candidate approval, passing finalization, terminal confirmation, and handoff
readiness. Workflow routing, persisted validation, and legacy migration use the
same predicates. Candidate acceptance binds its result to the inspected
fingerprint; formatting may produce a different finalized fingerprint, which
requires its own terminal confirmation. Findings require exact fingerprint
scoped overrides where the existing independent review rules permit them.

Shared invalidation clears dependent approvals after content repairs. Unchanged
resolutions clear candidate and terminal approval but retain only fingerprint-bound
passing finalization; reuse still requires live content and infrastructure checks.
Correction budgets and durable ledgers retain their existing reset rules. Legacy
active evidence reconverges under the lease, while accepted handoff evidence is
preserved for recovery without rerunning agents or completed staging effects.
The existing evidence fields retain their persisted meaning.

Content repairs, interrupted repairs, and migration re-entry share candidate
routing: `REVIEW` for independent mode and `CHECK_AND_FIX` for lazy and combined modes.
Terminal content findings use independent finding resolution or direct primary
fixing; pure evidence rejection still repeats finalization. Policy selection
never grants permissions: agent turns remain unable to change the index, and
handoff staging remains runner-owned.

Session selection retains a single run-wide Worker source fork in lazy mode and
separate primary/review checkpoint forks in independent and combined modes. Recovery and output
correction can reconstruct fresh sessions; Arbiter contexts are always fresh.
The existing `lazyCorrections`, `pendingLazyCorrection`, and
`lazySourceForkConsumed` fields and bounded accounting remain unchanged. Large turn implementations and Git reconciliation stay in the workflow.

## Required Capability Discovery

Bootstrap and read-only validation migration persist `capabilityRequirements`
and `environmentBlockers` with each active role's exact inventory. The private
`capability-requirements.js` owns their bounded syntax; only the root
`inspectRequirements` capability evaluates authority, support, and availability.
There are at most 256 reports of each kind per role. Each need names an exact
inventory command, an optional frozen identity (`commandIdentity`, otherwise
null), `capabilities` with boolean `scratch`/`cache` and up to 32 exact
`{url, sha256}` artifacts, and up to 16 unique `unsupported` identifiers.
Each blocker names an inventory command, `source` (`agent-sandbox` or `runner`),
and 1–8 bounded single-line evidence strings. Non-READY outcomes use empty arrays.
Malformed reports use the existing bounded read-only bootstrap correction path.

Accepted reports from every active role remain additive regardless of the
reconciled or arbitrated summary. Reports cannot grant permissions, omit another
role's needs, or replace frozen declarations. Before every writable POLISH,
CHECK_AND_FIX, RESOLVE_FINDINGS, or FINALIZE invocation, inspect the saved request
again; cached declaration preflight cannot bypass this gate. Unsatisfied needs
pause as `environment_blocked` before content or index mutation, preserving the
checkpoint and bounded runner-derived evidence. Repairing the environment permits
retry; changing trusted selection or declarations requires a new run.

An agent-sandbox limitation is satisfied only for the exact delegated command
when runner inspection succeeds. A limitation on another command remains a
blocker. Preparation may acquire verified dependencies and probe isolation, but
never executes or attests required checks. Those checks execute only in FINALIZE,
which reacquires and reverifies dependencies. Configuration guards, cancellation,
leases, and resource ownership remain enforced by the root capability.

State version 14 marks legacy missing discovery with paired null report fields.
Passive migration preserves historical gate proof. Active legacy runs rediscover
requirements read-only before new writable work, using only Worker in lazy mode.
Pending migration cannot bypass safety or capacity-exhaustion pauses; only
retryable pauses and applicable explicit resume actions permit discovery.
Interrupted content corrections are reconciled and charged once before continuing. Completed and
failed historical states remain inert. HANDOFF first inspects whether staging
already completed: complete staging settles verification-only without providers
or capability preparation; untouched legacy staging returns to discovery and
candidate convergence. Current untouched handoffs recheck availability before
runner-owned staging. Stop reconciliation starts no new effects.

## Combined Review

Combined mode uses independent Worker/Reviewer bootstrap discovery and
reconciliation, all active roles, and independent source checkpoint forks.
Unresolved bootstrap or validation-migration disagreement pauses for explicit
retry without Arbiter. Independent remains the default and recommended mode.

After `POLISH`, Worker `CHECK_AND_FIX` and a separate read-only `CLEAN_CONFIRM`
must converge before independent `REVIEW`. Durable `primaryFindings` retain
self-findings for direct fixing; they never replace independent findings or
enter dispute/override/arbitration routes. Candidate confirmation and independent
approval bind the same fingerprint. `FINALIZE` follows, then independent Reviewer
`CONFIRM` covers the formatter's result and validation evidence before `HANDOFF`.

Independent findings retain the full fix, dispute, withdrawal, exact override,
and fresh finding-arbitration workflow. Content-changing repairs restart primary
convergence and invalidate dependent approval; unchanged resolution can reuse
current finalization only after both candidate gates reconverge. Neither primary
exhaustion nor non-finding failures permit arbitration. Corrections use existing
bounded ledgers and counters, including exact-once interrupted correction charging.
Every agent still lacks index authority. The runner alone stages the accepted
handoff and never creates a polishing commit.

State version 13 adds `primaryFindings`. The version-12 leased migration initializes
it empty and preserves saved mode, budgets, approvals, and completed handoff
recovery. Missing legacy mode remains independent.

## Inputs And Change Set

The task directory contains:

```text
task/
├── task.md
├── clarifications.md  # optional task-level transcript
└── context.md         # optional
```

`task.md` is required and non-empty. `clarifications.md` and `context.md` are
optional immutable inputs. The pipeline does not accept or parse `plan.md`.

The initial change set is all repository content represented by:

- staged, unstaged, or deleted tracked paths relative to `HEAD`;
- non-ignored untracked paths and their content.

Staging placement does not define content membership. Ignored untracked files
are outside the change set. Preflight requires at least one change.

Task inputs may be outside the repository or may be ignored untracked files
inside it. A repository-local task input is rejected when it is a dirty tracked
path regardless of ignore rules, or a non-ignored untracked path. This prevents
immutable hashed input from overlapping the writable change set. A clean
tracked input is allowed and remains protected by input-drift checks.

## Roles And Configuration

The descriptor declares independently configurable `worker`, `reviewer`, and
on-demand `arbiter` roles and owns active-role selection. Independent and
combined modes activate all three, with Arbiter still resolved on demand; lazy mode activates
only Worker. CLI and runner configuration use the common backend
and execution-preference precedence rules. Each role accepts string trusted
`profile`, backend-native `model`, decimal `contextSize`, and portable `effort` selections;
role-specific CLI/MCP values win over run-wide and runner values, with
`current` omitting the native override. Worker and Reviewer may use any
Codex/Claude combination; Arbiter supports either backend.

Effort accepts only `current|low|medium|high|xhigh`, independently of model IDs.
The shared root resolver applies role override → run override → project role →
project `defaultEffort` → runner role → runner `defaultEffort` → `current`.
CLI `--effort` and descriptor-derived `--<role>-effort` map to MCP
`run_start.effort` and `roleOverrides.<role>.effort` through the same runner
contract. Both reject values outside the portable enum before dispatch; MCP
intents bind the selections and detached continuations reuse saved effort.
Validate all configured vocabulary, but resolve and persist only active roles;
native translation stays in provider adapters. Every role turn carries saved explicit
effort, including recovery; `current` omits the request override.
Common envelope version 8 requires saved active-role effort. Legacy missing
values migrate to `current` under the run lease without provider activity,
configuration reload, or changes to progress and session evidence. Public
status and activity omit these provider-private values.

Worker capability preflight requires structured output, read-only inspection,
autonomous safe content writes, remote-write blocking, and the explicit
`gitMetadataWriteBlocked` guarantee. Codex satisfies it through workspace-write
isolation; Claude satisfies it through its Git-directory write and `git add`
denials. On Linux, Claude advertises those turn capabilities only when a fixed,
model-free exact-policy probe succeeds under the credential-filtered command
environment. Fixed no-shell bubblewrap arguments reproduce the outer user,
PID, mount, and network namespace shape for `allowAllUnixSockets: false` and
run an inert command through the resolved Claude executable's embedded
`apply-seccomp` helper. The probe has bounded output and time, retains no host
diagnostic, and does not apply a profile, authenticate, or invoke a model. This
native-turn proof remains independent from the Runner-owned local-commit
executor proof, which polishing never requires; structured-output and native
session capabilities remain CLI-derived. Neither backend receives broader
`.git` access for polishing.
Each Codex workspace-write app-server attempt receives one canonical owner-only
runner-created root beneath the fixed platform temporary location. Exactly the
repository and that private root are writable; host `/tmp`, ambient temporary
paths, Git metadata, and command network access remain excluded. The effective
shell policy projects validated `TMPDIR`, `XDG_CACHE_HOME`, and
`XDG_RUNTIME_DIR` children without changing the provider process environment.
In-session compaction retains the root, while every success, failure, or fresh
recovery validates and removes it before another attempt. Unsafe preparation or
cleanup fails closed. Read-only and local-commit isolation remain unchanged.

The pipeline owns these settings and defaults:

```text
mode = independent
maxFixRounds = 20
maxDisputesPerFinding = 5
maxSameFindingRounds = 5
stagnationWindowRounds = 3
```

`mode` accepts exactly `independent`, `lazy`, and `combined`. Missing values resolve to
`independent`, which is the default and recommended mode because its separate
Reviewer provides genuinely independent semantic review, at the cost of more
provider context and tokens. `lazy` is an explicit lower-consumption choice
that uses only Worker and does not provide independent review. It is never
selected automatically. CLI `--mode` and MCP `run_start.mode` provide the
explicit per-run override.

It also owns `finalization`, a string setting whose default `auto` discovers a
conventional confined repository `finalization` skill and otherwise falls back
to repository instructions and project-defined checks. `none` selects that
fallback directly. Any other valid value is a normalized repository-relative
path ending in `SKILL.md` and requires that exact skill.

`trustedChecks` is an array of unique runner-trusted command aliases and
defaults to empty. Root and safe project `trustedCommands` catalogs use the same
exact-vector validator for each alias's inventory command, executable, and
arguments. Normalized catalogs merge root then project in stable order;
identical same-name definitions deduplicate and conflicts reject even when
unselected. The merged catalog permits at most 256 definitions and a selection
at most 32 aliases. Project settings may replace the selection with root or
project aliases in the selected order. Definitions reject shell-string
substitutes and environment, credential, or host-authority fields. The root resolves
the complete selection and fingerprints it before agent work; resume uses the
persisted snapshot without reloading configuration. Later project configuration
edits trigger the existing protected-input guard.

Trusted declarations also accept the architecture's closed `capabilities`
object: `scratch: true`, `cache: true`, and bounded pinned HTTPS `artifacts`.
Root and project normalization are identical. Version-2 snapshots include
normalized capabilities in command identities and configuration fingerprints.
Legacy version-1 snapshots retain their restricted policy, exact fingerprints,
and evidence bindings without configuration reload or authority upgrades.

Unavailable frozen requests create a durable `environment_blocked` pause before
provider work. Early pauses retain `preflightComplete: false`, null baseline,
backend versions and clarification path, empty hashes, and no `resumeState`.
Null-action resume retries the saved request before ordinary `CLARIFY` preflight;
later pauses retain their applicable checkpoint, including an untouched HANDOFF.
Completed handoffs are verified before checking capabilities needed for new
work. Status and immutable terminal reads perform no capability work. Inspection
does not execute or attest required checks. Scratch/cache requests use isolated
transient storage; artifact requests use bounded runner-owned acquisition and
read-only mounts. Declaration preflight inspects storage and isolation without
downloading dependencies. Requirement inspection before writable work prepares
dependencies; finalization execution reacquires and reverifies them. Environment
repair permits retry; changing declarations requires a new run and never permits
weakened validation.

Settings are stored in pipeline state at run creation and are not reloaded on
resume. The root may load safe project overrides from an ignored
`LOCAL_ARTIFACTS/agent-runner.json` or an explicitly selected confined ignored
path. CLI/MCP execution selections win over project values, which win over
runner-root values. Alongside trusted command catalogs, a project file may select
runner-trusted profile aliases and safe role, setting, and repository-relative
artifact-root values; it cannot define profile implementations, credentials,
provider binaries, or environment values. Explicit CLI/MCP pipeline-setting
overrides win over project values, runner values, and descriptor defaults.
All configured roles are validated,
but only active roles are resolved, probed, persisted, source-session checked,
or invoked. Inactive values stay in the configuration source for a later
independent run and are not exposed through lazy state. The resolved active
roles, settings, and artifact root are persisted. In independent and combined modes the
Arbiter backend is probed when first needed; lazy mode never probes Reviewer or
Arbiter.
When a project configuration supplied those values, the root runner persists
its protection record and checks it before recovery, around every provider
turn, and before trusted execution, handoff, or stop reconciliation. Drift
produces the non-resumable `project_configuration_changed` safety pause;
already begun handoff effects remain verification-only. Complete and recovery
role envelopes explicitly prohibit modifying the resolved project
configuration.

## Clarification

Every run begins in a pipeline-owned `CLARIFY` state. The Worker studies the
task, current changes, task-level and execution clarifications, repository
instructions, relevant architecture, tests, skills, and Git history in
read-only mode. It returns strict structured `READY`, all currently actionable
material questions, or a narrowly valid `PRODUCT_DECISION_REQUIRED` outcome.

The run-specific transcript is:

```text
<repository>/<artifactRoot>/agent-runner/<run-id>/clarifications.md
```

`artifactRoot` is a normalized repository-relative selection that defaults to
`LOCAL_ARTIFACTS`; a legacy run without that persisted field keeps the default.
Before creating the transcript, preflight requires `git check-ignore` evidence
that the resolved path is ignored and untracked. The runner never changes
ignore rules.
The transcript is excluded from the repository content fingerprint and hashed
separately as immutable workflow input.

`--clarify` opens the authorized editor before the first agent turn. Otherwise
the editor opens only when questions exist. MCP never opens an editor and uses
the common structured pending-input projection.

An empty clarification artifact is valid. Closing an authorized editor without
changes is also valid. Neither case requires user text.
They do not consume an agent question
round. Unanswered agent questions still require a response.
Question rounds are bounded to three; exhaustion pauses rather than advancing.

The runner persists the suspended workflow state, one-shot pending editor
authorization, and accepted transcript hash before opening an editor or waiting
for input. Authorized edits update the accepted hash. Edits outside that window
pause as unexpected input changes. The transcript is frozen and hashed before
leaving `CLARIFY`.

After clarification closes, agents must not ask questions. A later
`PRODUCT_DECISION_REQUIRED` is valid only when progress is impossible without
choosing between materially different product requirements that the task,
changes, repository, conventions, and prior clarifications do not resolve. The
answer invalidates dependent bootstrap, finalization, and review results and
returns through a pipeline-owned safe re-entry path.

## Preflight And Bootstrap

Preflight:

1. resolves the canonical Git root without requiring a clean worktree;
2. reads and hashes the declared task inputs;
3. rejects task-input/change-set overlap;
4. verifies the ignored run clarification path;
5. records the dirty repository snapshot and requires at least one change;
6. probes Worker and Reviewer independently in independent and combined modes,
   or Worker alone in lazy mode;
7. resolves and persists the selected trusted-command vectors, identities,
   ordered-command fingerprint, and trusted-configuration fingerprint;
8. creates or preserves the run clarification transcript;
9. stores the artifact root, settings, hashes, backend versions, and the repository baseline.

In independent and combined modes, Worker and Reviewer bootstrap independently and read-only.
In lazy mode, Worker bootstraps alone and its complete accepted summary and
validation inventory become the resolved context after the same deterministic
validation, capacity, correction, staging-independence, trusted-check,
canonical-path, and infrastructure-fingerprint rules. Active bootstrap roles
study the repository, task, complete current changes, clarifications,
instructions, relevant skills and finalization guidance, repository-defined
project checks, tests, and useful Git history. They
must not see each other's interpretation before both summaries exist in
independent and combined modes. A source session supplied with `--fork-from` and optional
separate `--fork-profile` is forked directly and independently for the first
eligible turn of each Worker and Reviewer checkpoint in independent and combined
modes. A known source profile supplies the Worker and, in those modes, Reviewer's
`current` selection and every explicit participating backend/profile must
match; an unknown source profile requires `current` and omits a native
override. The Arbiter remains fresh. In lazy mode,
the source is forked exactly once into the logical Worker across clarification,
bootstrap, polishing, finalization, fixing, confirmation, and resume. A later
checkpoint continues that child when compatible or reconstructs the Worker
without reforking the source. MCP leaves the source unset unless the user
deliberately selects a compatible current session after being offered a fresh
start. It includes a known trusted profile with the fork choice, or offers only
`current` inheritance when the profile is unknown. Prefer a fresh start for a
long, multi-topic, or uncertain session, especially when independent mode would
fork its complete context more than once.

Each direct child session is persisted with a key over its accepted inputs and
pipeline-owned role checkpoint. Clarification, bootstrap, Worker work, and
Reviewer work are distinct checkpoints. In independent and combined modes, reconciliation
may continue the Worker bootstrap session, but polishing and review never
continue bootstrap sessions. In lazy mode, compatible checkpoints may continue
the single Worker child; otherwise durable state reconstructs the same logical
Worker in a disposable session without another source fork.
First, forked, fresh, and context-invalidated turns receive the complete durable
request. Compatible continuations receive only the current instruction and
state delta while retaining the complete request for adapter recovery after
unavailable continuation or failed compaction.
Every role request also requires the authorized role to produce its own result
without delegation, subagents, or multi-agent collaboration. Adapter
collaboration auditing remains independently fail closed.
Codex locally rejects incompatible response schemas with terminal
`ERR_INVALID_CODEX_SCHEMA`. A valid native `other` failure with bounded,
structured non-transient HTTP client evidence becomes terminal
`ERR_CODEX_TURN_FAILED` / `turn_bad_request`. Neither is an output-correction or
backend-availability failure. Opaque `turn_other` and explicit
`turn_server_overloaded` retain one fresh reconstruction outside source forks
before the next failure propagates. Turn-item policy, protocol, and isolation
auditing and the model-reroute guard take precedence, and native error details
are discarded; the adapter owns recognition and recovery.
Claude classifies structured permission denials, HTTP status, result subtype,
and terminal reason before consulting a bounded native-text slice. Only finite
allowlisted backend, capability, configuration, usage, provider, expected-tool
permission, and harmless read-only execution failures are resumable. Bash
permission recovery requires a positively recognized safe repository
inspection; every other Bash denial fails closed. Provider recovery requires an
explicit transient HTTP status, while non-transient client statuses and an
unqualified structured `api_error` are terminal. Authentication,
forbidden-operation denials, isolation or protocol failures, and unclassified
writable process outcomes remain terminal. Denied input,
native result text, raw standard error, and native process causes are discarded.
An explicit rate, quota, credit, or spend-limit rejection is not retried through
compaction, a fresh session, or provider fallback. Persist
`backend_unavailable`, safe Worker workspace changes, and invalidation of stale
fingerprint-bound results before pausing so the complete durable request can be
reconstructed after capacity returns. Classified usage and provider failures
from writable turns use this path only after workspace and repository-control
reconciliation; no native session is required.
The root agent boundary normalizes the selected adapter's finite diagnostic
class before workflow code sees a terminal failure. Only its fixed message,
bounded code, safe control flags, shared structured-output class, and validated
diagnostic class cross the boundary. Codex collaboration activity despite a
disabled multi-agent capability remains terminal `operation_multi_agent`; it is
not an environment blocker or a transparent retry. Native messages, prompts,
commands, provider responses, transcripts, credentials, and process causes are
discarded.

A writable Worker turn returns structured `BLOCKED` with bounded reason and
evidence when sandbox, IPC, loopback, process-isolation, missing-service,
permission, or comparable external constraints prevent work not delegated to
an exact selected runner-trusted command. Selecting another command does not
suppress a genuine blocker. The pipeline persists `environment_blocked`,
preserves safe workspace content, and never weakens sandbox, network, process, or host
temporary-directory boundaries to make validation pass.

The pipeline stores concise summaries as external run artifacts:

```text
context/worker.md
context/reviewer.md  # independent and combined modes
context/resolved.md
```

In independent and combined modes, the Worker reconciles both summaries from
repository evidence without forcing agreement. Only independent mode permits a
material disagreement to invoke one fresh, read-only Arbiter, which may select
the Worker summary, select the Reviewer
summary, synthesize an evidence-supported result, or require a genuine product
decision. Combined mode pauses unresolved disagreement for explicit retry
without arbitration. In lazy mode, the accepted Worker summary is copied
directly to the resolved context and no reconciliation or arbitration occurs. Only a resolved
context permits the workflow to enter `POLISH`.

Each active bootstrap role independently returns the complete ordered inventory
of stable `C`-prefixed required-check IDs and exact commands, plus every
repository-relative file that controls package scripts, test discovery, test
runners, skill guidance, or validation configuration. In independent and combined
modes, the runner establishes the inventory from accepted Worker evidence followed by
accepted Reviewer evidence; in lazy mode, accepted Worker evidence is the
complete inventory. It deduplicates exact commands and paths in stable
first-seen order,
ignores conflicting role IDs, and assigns final contiguous `C1`-through-`Cn`
IDs. Every command or path found by any active role is preserved. Reconciliation
and arbitration resolve only summaries and material disagreements; their output
contains no inventory fields and cannot invent, select, or omit commands or
paths. The runner—not an agent—fingerprints the derived files.
Validation infrastructure consists of files owning commands, discovery, runners,
configuration, or mandatory finalization guidance. Exclude ordinary source,
individual tests, fixtures, and generated output merely consumed by checks.
Classification is semantic, not a filename or extension heuristic.
Each role may return at most 256 `requiredChecks` and 256
`validationInfrastructure` entries. The independently derived, persisted,
finalization, and fingerprint-input inventories each allow at most 512 entries,
so two disjoint maximum role inventories remain representable. If a complete
role field would exceed 256 items, the role returns `CAPACITY_EXHAUSTED` with
empty inventory and ordinary result fields, `capacityField` equal to
`requiredChecks` or `validationInfrastructure`, and `capacityLimit: 256`.
It checks `requiredChecks` first when both fields are over capacity. The runner
pauses immediately with `bootstrap_inventory_capacity_exhausted` and public code
`ERR_BOOTSTRAP_INVENTORY_CAPACITY_EXHAUSTED`; it does not consume a correction
turn, accept truncation, or persist a placeholder.
Commands and paths retain interior whitespace exactly; unsafe, non-normalized,
multiline, or boundary-whitespace values are rejected instead of rewritten.
Every selected runner-trusted inventory command must appear exactly once in
each accepted inventory. Agents receive only its alias, exact inventory
command, and deterministic identity; they never receive authority to execute
the persisted vector outside their ordinary turn sandbox.

Every bootstrap summary and required-check inventory is staging-independent.
It must not require staging, staged handoff, index mutation or inspection, an
implicit worktree-versus-index assertion, an alternate index, or commit
preparation. Staging and staged-handoff inspection belong only to `HANDOFF`; an
applicable tracked-content check uses `HEAD` or explicit trees. Deterministic
validation reports an unsafe command as a field-specific bootstrap violation,
uses the producing role's one bounded read-only correction, and fails closed if
the replacement remains unsafe. Validation-migration discovery uses the same
policy, and finalization candidate inventories are rejected by it as well.

Before accepting an active role's bootstrap or validation-migration inventory,
the root Git boundary requires each proposed infrastructure path to identify an
existing regular file by its exact canonical repository-relative path. Missing
files, directories, symlinks, and paths traversing a symlink are field-specific
contract violations. Every producing role, bootstrap or validation-migration
phase, and bootstrap contract receives at most one read-only correction. The
runner persists only attempt `1` and the bounded role, phase, contract, field,
and constraint diagnostic before that turn. A valid replacement clears the
pending copy; resume reconstructs an interrupted correction from durable state;
a repeated invalid result fails closed. Rejected structured values, provider
text, prompts, commands, transcripts, credentials, and chain-of-thought are
never retained.

## Workflow

The explicit persisted states are:

```text
CLARIFY
BOOTSTRAP
POLISH
REVIEW
CHECK_AND_FIX
CLEAN_CONFIRM
FINALIZE
CONFIRM
RESOLVE_FINDINGS
HANDOFF
WAITING_FOR_USER
DONE
FAILED
```

`CHECK_AND_FIX` and `CLEAN_CONFIRM` are lazy and combined primary-convergence states.
`REVIEW` is the independent candidate-review state, while `CONFIRM` owns
the mode-specific terminal read-only confirmation. Only runner-owned transition
code advances the workflow.

### Polish

The Worker starts a fresh work checkpoint with the validated inputs, current
change-set fingerprint, resolved context, active blockers, and bounded decision
history. It receives workspace-write access and brings the whole existing
change set to a correct, idiomatic, minimal result, follows the task and project
conventions, and performs a concise self-review. Finding fixes reuse this
checkpoint. The Worker may add or remove safe workspace content when
correctness requires it. It must not stage or unstage changes, alter the index
or other Git metadata, create a commit, change `HEAD` or refs, reconfigure
remotes or Git identity, or perform a remote write. The runner owns final
staging after candidate convergence, finalization, and the distinct terminal
confirmation pass.
The complete and recovery prompt for each Worker and Reviewer checkpoint treats
project `.agents` changes as authorized only when the user's task explicitly
requires them; otherwise the role neither makes nor approves those changes.
Compatible continuation turns inherit this responsibility from their native
session without repeating it. A violation follows the ordinary finding-and-fix
path and never reopens user questions.

Polishing, lazy or combined `CHECK_AND_FIX`, and finding-resolution prompts
receive only the exact command text selected in persisted `trustedValidation.commands`.
The bounded projection accompanies complete, continued, reconstructed, and
correction requests and is an empty array for an empty selection. It does not
reload configuration, expose executable vectors or provider settings, or repeat
the complete validation inventory. Inventory-reporting and `NOT_RUN`
instructions remain in their existing bootstrap and finalization contexts.

Established required-check execution and attestation belong exclusively to
`FINALIZE`. Selected runner-trusted commands never execute inside agent turns.
Their agent-sandbox limitations must not cause `BLOCKED` or prevent applicable
content repairs and semantic review; the runner executes the persisted exact
vectors during `FINALIZE`.

An external environment constraint affecting nondelegated work pauses at
`POLISH` without discarding safe Worker changes. Any stale candidate,
finalization, and terminal-confirmation results are invalidated before the pause.

### Finalize

After mode-specific candidate convergence, run the target repository's complete
finalization procedure in a dedicated Worker turn in every policy mode. Locate
and validate resolved skill guidance first. When no skill is selected or
automatic discovery finds none, derive the same complete gate from repository
instructions and project-defined checks; never skip validation. Execute required
formatting first and then any other generated output, but do not stage, unstage,
or commit. When selected guidance requests staging,
index-relative handoff inspection, an alternate-index workaround, or commit
preparation, defer staging and staged inspection to `HANDOFF`, omit prohibited
commit preparation, and complete the staging-independent content gate. Express
an applicable tracked-content check against `HEAD` or explicit trees. This
deferral is neither a skipped check nor a validation blocker. Report strict
`PASS`, `FAIL`, `SKILL_MISSING`, `SKILL_INVALID`, `BLOCKED`, or the narrowly
allowed product decision outcome.

An explicitly selected missing, escaping, or invalid skill pauses. An
unavailable automatically discovered skill falls back to the skill-less gate.
Skill-less `PASS`, `FAIL`, and `BLOCKED` results carry no skill path.
Finalization-generated content changes are permitted without invalidating the
already accepted semantic candidate. Compute the content fingerprint after the
procedure and bind the result to it. A passing result enters `CONFIRM`; it cannot
enter `HANDOFF` directly. A failure becomes blocking findings for Worker
resolution. Unavailable explicit guidance or a blocked finalization procedure
pauses.

Before evidence is fingerprinted, the runner inspects every candidate
validation-infrastructure path as an existing canonical regular repository file.
An invalid path uses the existing bounded read-only finalization correction.
Every non-availability result repeats the complete inventory actually used and
contains exactly one ordered result with bounded direct evidence for every
required check. Agent-executed checks must pass; omissions, skips, exclusions,
substitutions, replacements, or weakening are invalid output. `NOT_RUN` is
valid only for an exact selected runner-trusted command. After the Worker turn
is reconciled, the root executor replaces each such placeholder by running the
persisted executable/argument vector directly without a shell or expanding the
agent turn's capabilities. Other host-reported results and user attestations
are not trusted. The Worker must not weaken package scripts, test discovery,
test runners, validation configuration, the inventory, or its file set to
evade an environment blocker.

Each runner result retains only bounded status, exit/signal/timeout data,
command identity, and fixed evidence; raw process output is discarded. Every
completed, readiness-confirmed command gives remaining descendants one bounded
grace period to retire naturally regardless of exit code before bounded
TERM/KILL cleanup; timeout cleanup starts immediately. Before and after
execution, the shared root service rejects workspace, index, history, ref,
remote, or identity mutation and recomputes validation-infrastructure
fingerprints. Missing isolation, an unterminated process tree, a changed
binding, a non-allowlisted command, infrastructure drift, or mutation fails
closed. A bounded environment failure pauses at `FINALIZE`; resume reuses the
durable command snapshot. The accepted ordered evidence tuple binds both agent
and runner results to the same content, validation-infrastructure,
ordered-command, and trusted-configuration fingerprints.

`BLOCKED` is reserved for required validation that cannot execute because of an
external environment constraint. It carries bounded reason and evidence,
pauses as `environment_blocked`, and resumes at `FINALIZE`; an executable check
that reports a legitimate failure remains `FAIL`.

If deterministic normalization rejects the first Worker finalization result
for the current content fingerprint, persist the version-7 bounded diagnostic
and publish one `finalization-correction` activity without rejected content.
Reconstruct the complete request from durable inputs and ask the Worker for one
complete replacement with the same finalization schema in a fresh-session,
read-only turn. The correction may re-execute corrected staging-independent
checks needed for complete direct evidence, but it does not execute the
rejected command or staging-dependent validation and cannot modify repository
content, staging, history, refs, remotes, or Git identity. Interruption before
or during that turn preserves the pending attempt, reconciles it as read-only,
and resumes without another attempt or a required native session. A valid
corrected availability or product-decision result uses its existing route;
corrected `BLOCKED`, `PASS`, and `FAIL` results rejoin the existing environment,
fingerprint, trusted-validation, review, and handoff gates. A repeated invalid
result for the same content fails closed without retaining either rejected
result. Content changes clear the consumed scope and permit one correction for
the new fingerprint. This attempt is independent of the bootstrap and
validation-migration correction ledger.

### Transient validation storage ownership

Common envelope version 9 records trusted storage allocation intent and verified
identity separately from process ownership. Version 10 adds the acquiring runner
identity and changes the runtime compatibility token. Leased migration preserves
version-9 allocation records without new resource effects. The root retires owned processes and
cleans recorded resources before resuming pipeline work or settling an operator
stop. Legacy envelopes migrate to null storage ownership without allocation or
provider activity. Only declared scratch/cache directories are writable, through
the fixed mounts and environment bindings owned by the trusted-validation
architecture. Required build output must stay outside the repository.

Cleanup uncertainty preserves the resource record and pauses finalization as
`environment_blocked` at `FINALIZE`; neither the check nor subsequent work is
accepted until ownership is verified and cleanup finishes. Interrupted mutable
cache contents and partial downloads are never reused. Pinned artifact requests
share this durable allocation lifecycle, including artifact-only commands. The
root journals verified directory ownership and the acquiring runner process
identity before downloading. Journal failures preserve a resumable ownership
blocker and the saved allocation. Recovery cannot delete its storage while that owner
is live or unverifiable without service-observed transport retirement. It exposes only
complete digest-verified files at `/run/agent-runner/dependencies`, read-only.
The exact check remains network-isolated; extraction or setup belongs to its
declared vector and must use declared scratch. Acquisition failures block
`FINALIZE` before command launch with bounded redacted evidence; repaired
environments retry the frozen request after cleanup. Status remains observational.

### Review And Findings

Finalization failures enter finding resolution in both modes. They must be
fixed, never disputed; in lazy mode their no-progress path cannot invoke an
Arbiter. A content-changing fix invalidates candidate, finalization, and
terminal-confirmation evidence and returns through mode-specific candidate
convergence before the complete finalization gate runs again.

Ordinary terminal findings without validation-evidence rejection clear candidate
and terminal-confirmation attestations while retaining a successful finalization
record provisionally. After mode-specific
candidate convergence, the runner recomputes the finalized content and
validation-infrastructure fingerprints. Exact matches return directly to
`CONFIRM`; a mismatch invalidates the record and re-enters `FINALIZE`. A
declared fix without a proven repository mutation does not invalidate evidence.
Actual content or infrastructure changes, provider correction-scope drift, and
content-changing interruption reconciliation always do. One fresh successful
terminal confirmation remains required immediately before `HANDOFF`.

Terminal `validationChange: REJECTED` has a separate recovery route shared by
both terminal roles. First honor the existing whole-result override gate for
all findings at the exact terminal content fingerprint. Otherwise immediately
invalidate finalization and confirmation evidence, including mixed rejections.
The required `finalizationFindingIds` array is a unique subset of at most 32
reported finding IDs identifying evidence-only concerns requiring no repository
edit. It must be empty outside a rejected terminal result; mixed concerns must
be separate findings. Candidate-review schemas do not carry this field, and
routing never classifies prose.
Evidence may be rejected even when the inventories and infrastructure are
unchanged. Such a rejection uses semantic recovery, not malformed-output
correction; inventory equality alone does not establish sufficient check evidence.

After exact applicable overrides, a pure evidence rejection preserves candidate
acceptance and returns directly to `FINALIZE` with bounded accepted findings.
It does not run candidate convergence or code check/fix, charge fix/correction
rounds, or update stable-finding/stagnation history. A mixed rejection routes
only content findings through ordinary mode-specific resolution and candidate
convergence, then requires fresh finalization even if content stays unchanged.
Neither withdrawal nor a later override can restore the invalidated PASS.
Ordinary non-rejection findings retain the existing reuse rule above.

Recovery invokes the complete finalization procedure with its ordinary
formatting permissions, canonical infrastructure inspection, ordered check
results, runner-trusted execution, and final evidence construction. A replacement
must retain every established exact check ID/command and infrastructure entry;
feedback cannot authorize an omission, substitution, removal, or weakening.
Every finalization request includes the saved established validation tuple,
including session-independent reconstruction after interruption.
Malformed replacement output follows the existing separate read-only correction
budget. A valid replacement and one fresh terminal confirmation must bind the
same resulting content and validation fingerprints before `HANDOFF`.

Pipeline state version 11 adds `finalizationRecovery`, containing consumed
`attempts`, explicit `additionalAttempts`, `required` and `pending` flags, and
nullable bounded `feedback`. Feedback retains only normalized findings, their
evidence-only ID subset, the terminal content fingerprint, and the current
established-infrastructure fingerprint. It never retains a rejected finalization
record, provider output, or transcript. The version-10 migration initializes
empty metadata without inferring lost rejection output, moving the workflow,
changing persisted mode, or replaying pending or completed handoff effects.

Two automatic semantic retries are available per polishing run, independently of
malformed-output and code-fix budgets. Before invocation, persist the consumed
attempt and pending marker. Interruption, provider unavailability, and external
validation blockage resume that pending attempt without recounting it. Content
or infrastructure scope drift discards stale feedback without replenishing the
run allowance. Content repair still returns through candidate convergence;
formatting within finalization retains its usual permissions and fingerprint
rules. Accepted replacement finalization clears pending recovery and feedback,
while the consumed allowance remains until the run ends.
A blocking product decision retires the pending attempt and its feedback before
returning through bootstrap and polishing; it does not restore
consumed allowance or remove the replacement-finalization requirement.

Exhaustion pauses as `finalization_evidence_rejected`, with `FINALIZE` as the
resume checkpoint, bounded actionable CLI/MCP evidence, and an explicit null
retry granting exactly one additional attempt. Independent-mode overrides use
the saved terminal content fingerprint, which may differ from candidate
approval after formatting. Partial overrides leave other feedback blocking;
resolving all recovery feedback authorizes one replacement attempt and still
requires complete finalization and fresh confirmation. Lazy mode exposes no
finding overrides. No retry grants index-write or commit authority; runner-owned
`HANDOFF` alone stages the accepted content.

#### Independent review and findings

In independent mode, an independent read-only Reviewer first checks the stable
candidate before `FINALIZE`. It reviews the task, resolved context, entire
current diff, tests, architecture, edge cases, minimality, and conventions, but
does not attest finalization or validation evidence. Its first candidate review
starts a separate checkpoint seeded from durable evidence; re-review and dispute
reconsideration reuse it. Findings use stable `R`-prefixed IDs and remain
blocking. Only an accepted candidate fingerprint may enter `FINALIZE`.

After finalization passes, `CONFIRM` runs one distinct read-only Reviewer turn
over the finalized content, established and candidate validation inventories,
runner-computed infrastructure fingerprints, and exact per-check evidence. The
request is reconstructed from durable state rather than depending on the
candidate-review session. It records `UNCHANGED`, explicitly `ACCEPTED` for a
complete task-authorized validation change, or `REJECTED` with a finding, all
bound to the finalized content fingerprint. Approval enters `HANDOFF` directly;
ordinary findings return to resolution, while evidence rejection follows the
shared terminal recovery route above.

The Worker resolves all current blockers in one batch by `FIX` or evidence-based
`DISPUTE`. Fixes return through candidate review and then either reuse matching
successful finalization evidence or rerun the complete finalization gate before
terminal confirmation. The Reviewer reconsiders disputes as `WITHDRAW` or
`UPHOLD`. An unresolved dispute reaches a fresh read-only Arbiter after the
configured budget. Every finding must be fixed, withdrawn, arbitrated, or
explicitly overridden by the user for the exact candidate or terminal
fingerprint that reported it.

If an external environment constraint blocks nondelegated work during finding
resolution, the Worker returns `BLOCKED` with no decisions and bounded reason
and evidence. A selected trusted command's agent-sandbox limitation alone
cannot block repairs; execution remains owned by `FINALIZE`. A
content-changing partial fix is preserved, invalidates all three gates, and
resumes at `REVIEW`; an unchanged turn retains its blockers and resumes at
`RESOLVE_FINDINGS`.

Exact finding IDs drive no-progress detection; fuzzy semantic matching is out
of scope. Exhausted fix, dispute, stable-finding, or stagnation budgets always
pause. Additional fix rounds do not reset history. One stagnation arbitration
may direct further fixes, implementation rework, or Reviewer reconsideration;
another complete blocked window pauses.

#### Lazy check/fix and clean confirmation

In lazy mode, polishing enters writable `CHECK_AND_FIX` before finalization and
never invokes Reviewer or Arbiter. The Worker receives the entire current
result, the bounded trusted-command projection specified for polishing, prior
candidate or terminal findings, and this mandatory review core:

```text
Review the changes and verify that they are correct, idiomatic, minimal, and consistent with the project's conventions. If you find any problems, fix them idiomatically and minimally, following the project's conventions.
```

This is a workspace-write turn. Its strict result reports changed or unchanged
content, an external blocker, or the narrow product-decision outcome, and the
runner compares that claim with the actual content fingerprint. Every change
clears candidate, finalization, and terminal-confirmation evidence and requires
another check/fix pass.

An unchanged pass is not approval. It enters a separate read-only
candidate `CLEAN_CONFIRM` over the exact current content and
validation-infrastructure fingerprints, using the same criteria while
explicitly forbidding edits and requiring structured `CLEAN` or concrete
findings. A status/content mismatch is invalid output, repository mutation is
rejected, and fingerprint drift pauses without advancing. Findings return
directly to `CHECK_AND_FIX`; they are not disputes and cannot invoke Reviewer or
Arbiter. Mutation-free `CLEAN` accepts the candidate and enters `FINALIZE`, or
returns directly to `CONFIRM` when retained finalization evidence still matches
the recomputed fingerprints.

After finalization passes, `CONFIRM` runs one distinct read-only Worker clean
confirmation over the finalized content and exact validation evidence. This
terminal result supplies the same validation-change decision required from the
independent terminal Reviewer. Only mutation-free `CLEAN` with unchanged
fingerprints and `UNCHANGED` or task-authorized `ACCEPTED` validation change
records the reviewed and terminal clean-confirmation fingerprints and enters
`HANDOFF`. Ordinary terminal findings return directly to `CHECK_AND_FIX` and require
candidate confirmation plus a fresh terminal confirmation; finalization reruns
only when the retained evidence no longer matches. Existing
fix, stable-finding, stagnation, and additional-round budgets bound the loop;
exhaustion never accepts a non-clean result.

Provider structured-output failure and deterministic candidate check/fix or
clean-confirmation contract failure are reduced to a bounded batch of Worker,
phase, contract, field, and constraint diagnostics. The first invalid result
for the exact phase, candidate content fingerprint, and
validation-infrastructure fingerprint persists attempt `1` and a pending
marker, then reconstructs the complete durable request with the original schema
in one fresh Worker session. Rejected output, provider text, prompts, commands,
paths, transcripts, and credentials are not retained.

A check/fix correction remains workspace-writable and index-read-only. Safe
content from an invalid or interrupted turn is reconciled once, stale gate
evidence is invalidated, and actual fix work is charged once. A candidate
clean-confirmation correction remains repository-read-only and requires the
unchanged content and validation-infrastructure fingerprints. A valid
replacement rejoins only its original route and cannot provide finalization,
confirmation, review, approval, or handoff evidence early. A repeated invalid
result pauses as `lazy_output_invalid` with bounded redacted diagnostics, the
exact resume checkpoint, and one explicit null retry. Resume reconstructs the
pending correction without adding another automatic attempt, replaying an
effect, recounting work, staging, or advancing to `HANDOFF`.

Independent candidate review and both terminal-confirmation variants own
separate one-attempt correction records scoped to their candidate or finalized
fingerprints. Candidate corrections cannot accept validation evidence, and
terminal corrections cannot themselves provide finalization or reuse a
candidate approval. Correction-scope drift invalidates the retained
finalization record and routes through `FINALIZE`.
Repeated invalid output pauses at the exact `REVIEW` or `CONFIRM` checkpoint
with bounded diagnostics and an explicit null retry.

### Handoff And Completion Gate

Completion requires:

```text
candidate review == APPROVED or candidate clean confirmation == CLEAN
finalization == PASS
open findings == 0
current content fingerprint == finalized fingerprint
current content fingerprint == reviewed fingerprint
terminal confirmation validation change == UNCHANGED or ACCEPTED
independent: unresolved disputes == 0 and pending arbitration == false
lazy: candidate and terminal clean-confirmation fingerprints are recorded
HEAD and repository control fingerprints == recorded baseline
```

After this staging-independent gate passes, the pipeline persists `HANDOFF`
before any index effect. The root Git boundary first requires the current
content fingerprint to equal both recorded fingerprints and verifies the
expected index, `HEAD`, branch/detached state, refs, remotes, and Git identity.
It then accepts only one of two recovery states: an already-complete verified
handoff, or the exact unchanged pre-effect state on which it runs `git add -A`.
An incomplete or contaminated index fails closed.

Before returning the post-effect snapshot, the Git boundary reverifies content
and every Git control, requires a nonempty staged diff whose staged content is
the complete tracked and non-ignored untracked change set, requires no unstaged
or non-ignored untracked remnants, and runs staged-diff whitespace hygiene. The
pipeline updates its baseline and enters `DONE` only after those postconditions
pass. It never invokes `local-commit` access or creates a commit.

## Safety Guards

The repository baseline records `HEAD`, branch/detached state, local refs,
tracked and untracked content, index state, effective remote configuration, and
effective Git identity. Remote and identity values are fingerprinted without
persisting credentials or personal data.

Clarification, bootstrap, compatibility, candidate and terminal lazy clean
confirmation, candidate and terminal Reviewer, reconsideration, and Arbiter
turns are read-only. Snapshot comparison before and after every such turn must
detect tracked or untracked content changes, deletions, index changes, `HEAD`,
refs, remotes, and identity. Mutation pauses without automatic rollback.

Writable Worker turns may change safe repository content only. The runner
rejects index drift as well as any `HEAD`, branch, ref, remote-configuration,
or Git-identity change. The persisted `HANDOFF` transition is the only
polishing owner allowed to stage. No role may push, mutate a remote ref, use a
hosting API to write, alter a remote, change Git identity, create a commit,
amend, reset,
rebase, stash, switch branches, or create tags. `HEAD` must remain unchanged for
the entire run.

The staging-independent content fingerprint includes current changed tracked
content, deletions, and non-ignored untracked content. It ignores whether
content is staged and excludes the ignored execution transcript. Every ordinary
content change invalidates candidate, finalization, and terminal-confirmation
evidence. A formatter change during `FINALIZE` preserves the accepted candidate
record but invalidates any prior terminal evidence.

## Operator Pause And Cancellation

The runner's durable stop protocol applies to every role, checkpoint, and mode.
An accepted request aborts only registered execution. The runner contains
owned processes in private PID namespaces. A runner nested inside the
runner-trusted validation namespace uses an owned session when that sandbox
denies another PID namespace, without widening the enclosing sandbox. It waits
for owned containment teardown, including detached descendants, before repository
reconciliation. The runner keeps its
execution lease and any held worktree lease until the pipeline's read-only
reconciliation path has accounted for the interrupted turn. That path cannot
invoke providers, trusted checks, or artifact writes. It revalidates frozen
inputs and the original access contract, preserves existing artifacts and safe
partial content, and retains unsafe input or repository changes as blockers.
It never rolls back content or changes Git controls.

A completed operator pause uses `WAITING_FOR_USER`, `operator_paused`, and a
null resume action. Its private checkpoint preserves the reconciled workflow
position, logical turn, and preceding pause. Resuming an already paused
checkpoint restores its blockers and pending editor authorization without
consuming them. Session reconstruction uses frozen roles, mode, settings, and
source lineage; an interrupted role does not refork its source. `CANCELED` is
terminal and inspectable, and every resume path rejects it.

Writable partial changes advance the baseline only after the unchanged-index
and Git-control checks pass. They invalidate candidate, finalization, and
confirmation evidence and charge actual correction work once. A request racing
`HANDOFF` performs inspection only: a fully staged accepted result is accounted
as completed, an untouched handoff remains pending, and an ambiguous index
retains a safety blocker. Stop reconciliation never stages or commits; resume
never restages an already verified handoff.

## Persistence And Resume

State lives outside both the target repository and task directory under the
common external run store. Pipeline state includes resolved settings, baseline,
input hashes, clarification status, backend versions, bootstrap summaries,
findings, disputes, arbitration, budgets, fingerprints, overrides, and pause
details, including distinct candidate and terminal review records and
fingerprints, candidate and terminal correction markers, the resolved mode,
one-time lazy source-fork marker, and candidate lazy-correction ledger. The
common versioned envelope also records an
explicit runtime
compatibility tuple maintained independently from the package version and, in
version 3, nullable bounded active provider role and phase. Version-1 and
version-2 envelopes project null activity without rewriting until the next
mutating continuation persists the explicit runtime migration.

Persist concise structured decisions and public summaries, never raw model
transcripts, chain-of-thought, credentials, or unhashed remote and identity
values.
Terminal failures may retain only the root-normalized finite adapter diagnostic
class, which the descriptor renders as a deterministic CLI/MCP explanation.

The descriptor projects each pause through one bounded public contract shared
by CLI status, MCP status, and MCP wait. It contains the finite reason, optional
validated bounded diagnostic code, concise explanation, bounded evidence,
validated resume checkpoint, and only applicable next actions. Prompts,
transcripts, credentials, native responses, raw standard error, rejected
values, internal diagnostics, pause-only paths, and counters remain private;
identified questions stay in the root pending-input projection. Input response,
safe null retry, one concrete valid extra-fix round, and exact finding overrides
continue to use the existing resume validation. A read-only repository mutation
instead instructs the user to abandon the contaminated run and start fresh from
an uncontaminated worktree. `environment_blocked` retains why nondelegated work
or finalization is blocked and the precise `POLISH`, `REVIEW`, `FINALIZE`, `CHECK_AND_FIX`, or
`RESOLVE_FINDINGS` retry checkpoint. This read-only projection does not itself
change the pipeline state version. The runner-owned handoff is represented by
pipeline state version 5.
Bootstrap capacity exhaustion instead has no retry action: its bounded public
diagnostic identifies the producing role, full inventory field, and 256-item
limit so the validation surface or Runner capacity can be addressed before a
new run.

CLI status and MCP status, wait, and activity also expose the persisted resolved
mode. `pipelines_list` exposes descriptor-owned values, default, and
recommendation. None of these projections exposes inactive role configuration
or provider-private data.

Each transition is a complete write-ahead event appended and synchronized
before atomic state replacement. `progress.md` is derived public activity.
Immediately before every Worker, Reviewer, or Arbiter provider call, the root
persists a complete `turn-started` transition. It clears the active turn only
after the pipeline reconciles read-only guards or safely snapshots and persists
writable workspace effects. If the process stops first, MCP status and timed-out
wait combine the retained role/phase with the absence of a live execution owner
to report `interrupted`, even before stale lease recovery; a live detached owner
reports `running`, and no owner or retained
turn reports `idle`. Same-host reads check owner process liveness immediately
without changing acquisition or stale-recovery thresholds. Resume reconstructs
the request from durable state and does not require polling, a heartbeat,
daemon, or surviving native session.
Mutating run/resume operations acquire the per-run execution lease first and an
external lease keyed by the canonical Git worktree second, then release them in
reverse order. Separate run IDs therefore cannot mutate one worktree
concurrently. Both leases use owner-checked release and permit stale recovery
only after the age threshold when the recorded same-host process is
demonstrably dead. Status reads acquire neither lease and remain lock-free.
Recovery accepts only an incomplete final journal fragment, advances lagging
state from complete events, and never depends on a native Codex or Claude
session surviving interruption.

Candidate `REVIEW`, lazy `CHECK_AND_FIX` and `CLEAN_CONFIRM`, terminal `CONFIRM`,
and `HANDOFF` are durable checkpoints. Their turn-start or effect-intent events
precede invocation, and accepted content, findings, fingerprints, round
accounting, and confirmation are persisted atomically before advancement.
Resume reconstructs an unfinished turn exactly once, reconciles a writable
partial change before returning through `REVIEW` or `CHECK_AND_FIX`, rejects any
mutation from read-only confirmation, and continues from an already advanced
checkpoint without replaying finalization, confirmation, staging, or round
accounting. The one-time fork marker is persisted before the first lazy source
fork, so reconstructed sessions never
fork the source again.

An exact-revision MCP continuation may resume a nonterminal, nonpaused
persisted active turn with a null action only when no live execution owner
remains; ordinary paused-run action validation is unchanged. Before replay,
resume revalidates the canonical project and task paths and every task, context,
task-clarification, and execution-clarification hash. The root Git boundary
requires an unchanged workspace and index for read-only phases. For an interrupted
Worker phase that had workspace-write authority, it may instead preserve
content drift, but any index drift is rejected after proving that `HEAD`,
branch/detached state,
refs, remotes, Git identity, canonical root, and allowed runner paths did not
change. The pipeline then advances its baseline, invalidates stale
fingerprint-bound candidate, finalization, and terminal evidence, and counts
interrupted correction content once. The reconstructed turn uses its complete
request in a fresh native session; the new `turn-started` event replaces the stale marker,
which clears only after normal workspace reconciliation. If correction
reconciliation already advanced the state to `REVIEW` or `CHECK_AND_FIX`,
resume instead clears the retained `worker`/`resolve-findings` marker after the
same safety checks and continues from candidate convergence without replaying
or recounting the correction.

Claude read-only recovery uses the common run envelope. A valid but otherwise
unclassified read-only result or process failure
may pause only after the read-only mutation guard succeeds. Resume rebuilds the
complete role request from the persisted inputs and checkpoint. No denied tool
input, native provider text, raw standard error, or new recovery field is
persisted. Writable usage/provider recovery first preserves safe content and
invalidates stale fingerprint-bound evidence; ambiguous writable failures fail
closed.

The descriptor owns one explicit ordered migration for every supported prior
pipeline state version. Lock-free status may project a compatible migration in
memory, but only a mutating continuation may persist it. Before workflow
execution the root evaluates the complete chain, validates the current
pipeline shape, and appends one atomic migration event under the per-run lease.
Unsupported forward versions, missing migrations, and incompatible runtime
tuples return a specific actionable version-skew error; invalid migration
output returns a specific migration failure. Neither changes the durable run.

Pipeline state version 2 adds the required-check and validation-infrastructure
evidence. Its version-1 migration preserves safe workspace content, invalidates
active aggregate finalization and review evidence, and marks paused legacy
evidence provisional. Before retry, override, finalization, or review advances,
fresh independent Worker and Reviewer checkpoints re-establish the inventory
and the runner fingerprints it again. Completed active work returns through
`FINALIZE`; immutable failed history is upgraded without replaying an effect.

Pipeline state version 3 adds the resolved trusted-validation snapshot and
executor provenance to every accepted per-check result. Its version-2 migration
selects empty legacy trust, preserves safe workspace content, and invalidates
active finalization and review evidence through the existing independent
validation-migration checkpoint before advancement. Paused legacy evidence
remains provisional until that checkpoint runs. Retained `BLOCKED` and
`NOT_RUN` entries in paused or immutable failed evidence become `FAIL` without
losing their bounded diagnostics. Immutable `DONE` and `FAILED` evidence is
shape-upgraded without replaying workspace work.

Pipeline state version 4 adds the bounded bootstrap-correction ledger and
pending diagnostic. Its version-3 migration initializes them empty without
changing accepted context, validation evidence, workspace content, or workflow
position. A correction is unique by producing role, bootstrap or
validation-migration phase, and contract; only its attempt and finite
field/constraint diagnostic are durable. Resume reconstructs a pending
read-only correction, acceptance clears it, and a repeated invalid result is
terminal. When validation migration requires arbitration, its accepted bounded
disagreement is persisted before the Arbiter turn, resumed directly after an
interruption, and cleared atomically with successful migration completion.

Pipeline state version 5 adds the durable `HANDOFF` boundary and makes every
ordinary polishing Worker turn content-only. Its version-4 migration preserves
immutable `DONE` and `FAILED` history and preflight-only state, clears unfinished
bootstrap evidence, and sends applicable prepared nonterminal runs through
fresh independent staging-free validation before advancement. Paused legacy
gate evidence remains provisional until resume invalidates it through that
checkpoint. A version-5 `HANDOFF` resume lets the Git boundary accept a proven
complete effect, retry an unchanged pre-effect state, or fail closed; it never
replays an ambiguous partial effect.

Pipeline state version 6 makes every accepted validation inventory
staging-independent while preserving `HANDOFF` as the sole Git-index owner. Its
version-5 migration shape-upgrades `CLARIFY`, incomplete preflight, `DONE`, and
`FAILED` without role work; clears incompatible partial bootstrap evidence;
and routes other prepared nonterminal work through fresh independent inventory
discovery before finalization can advance. Safe content, frozen inputs,
counters, Git controls, and trusted-validation state remain unchanged. A legacy
`HANDOFF` is inspected before any role turn: a complete verified effect enters
`DONE`, an untouched pre-effect state invalidates stale gate evidence and enters
discovery without staging, and any incomplete or contaminated index fails
closed.

Pipeline state version 7 adds a nullable consumed finalization correction and a
matching nullable pending marker scoped to the current content fingerprint.
The version-6 migration initializes both to `null` without changing safe
content, workflow position, validation evidence, counters, or handoff state. A
record contains only attempt `1`, resolved-or-fallback guidance scope, the
content fingerprint, and the bounded Worker/finalization contract field and
constraint diagnostic. It never contains rejected values, commands, paths,
prompts, provider text, transcripts, credentials, or raw structured output.
The pending marker is cleared only after a valid replacement; the consumed
record remains applicable while the fingerprint is unchanged so a later
invalid finalization result fails closed. A content change clears both records,
and completed `HANDOFF` clears the exhausted scope.

Pipeline state version 8 adds the resolved mode, the fingerprint accepted by
lazy clean confirmation, and the one-time lazy source-fork marker. Its
version-7 migration selects `independent` and initializes the new fields
without moving an active or terminal workflow position, changing safe workspace
content, or replaying a pending or completed `HANDOFF`. Every earlier supported
version reaches the same independent default through the ordered chain; no
migration replays role turns or repository effects.

Pipeline state version 9 adds the bounded lazy-correction ledger and nullable
pending marker scoped to phase, finalized content fingerprint, and
validation-infrastructure fingerprint. Its version-8 migration initializes the
ledger empty and the marker to `null` without moving active, paused, `HANDOFF`,
`DONE`, or `FAILED` workflows, changing safe workspace content, or replaying
role, finalization, or handoff effects. Pending writable reconciliation remains
subject to the ordinary Git controls and exact-once fix accounting; a migrated
`HANDOFF` is never routed back through a role checkpoint.

Pipeline state version 10 separates semantic candidate convergence from the
terminal gate. It adds `CONFIRM`, distinct candidate and terminal review
results and fingerprints, and independent bounded correction records for
candidate Reviewer and terminal-confirmation output. The version-9 migration
preserves safe content, inputs, counters, and control fingerprints; invalidates
unprovable active finalization and review evidence; and routes active work to
`REVIEW` or `CHECK_AND_FIX`. Paused work records that the same repair must occur
on safe resume. Existing `HANDOFF`, `DONE`, and `FAILED` gates are shape-upgraded
without replaying role turns, finalization, staging, or a completed handoff.

Pipeline state version 11 adds the bounded `finalizationRecovery` record described
above. The version-10 migration initializes empty recovery metadata without
moving active or terminal checkpoints, changing mode or counters, inferring
missing rejection output, or replaying role turns or pending/completed handoff
effects. Recovery-state validation rejects unknown fields, inconsistent attempt
allowances and pending markers, malformed feedback, and retained finalization
or confirmation evidence while replacement finalization is required.

Pipeline state version 12 expands inventory capacities to 256 per role and 512
for aggregate, persisted, finalization, and fingerprint evidence. Its leased
version-11 migration preserves legacy 64/128 inventories, counters, terminal
history, and pending or completed handoff effects without replaying role work
or reloading configuration. Per-item, structured-output, and durable byte limits
remain unchanged; count-valid output can still exceed the 256 KiB result limit.
Expanded schemas retain strict Claude preflight and existing sandbox restrictions,
without enabling `allowAllUnixSockets: true` or broader host access.

MCP uses the common STDIO tools, persists idempotency intents before mutation
and receipts before returning, and launches detached continuation under the
same lease rules. A worktree conflict leaves the durable run and incomplete
intent available for an exact retry instead of launching a conflicting child.
After spawn, the receipt remains incomplete until the run advances or that
child owns the worktree, so losing a concurrent acquisition race remains
retryable. A correlated child exit acknowledgement makes this deterministic
when the winning lease is released between MCP polls. A disconnected client
cannot create a second workflow owner. The dispatcher passes its runtime tuple
to the detached child, which rejects a mismatch before taking the run lease.
Its distinct skew exit becomes an actionable restart-and-retry error while the
incomplete idempotency intent and run remain durable.
Its additive start fields leave `sourceSession` unset until the user
deliberately selects a fork; native IDs remain opaque and an unknown source
profile permits only `current` inheritance.
`run_start.mode` has the same precedence as CLI `--mode`. MCP guidance
recommends `independent` for genuine semantic independence, discloses its higher
context/token cost, identifies `lazy` as an opt-in lower-consumption choice
without independent review, and prohibits automatic lazy selection. Registry,
status, wait, and activity projections expose descriptor metadata or the
resolved mode without inactive role or provider-private values.

On resume, verify the canonical paths, task hashes, accepted clarification hash,
repository baseline, `HEAD`, refs, remotes, identity, and current content.
Unsafe or ambiguous reconciliation pauses rather than discarding user work.

## Testing

Workflow policy tests use fake adapters with injected in-memory run-state and
repository effects. Their repository double models content fingerprints,
Git-control state, and handoff transitions deterministically while keeping task
inputs and validation-path fixtures confined to isolated temporary directories.
Shared builders are exposed only through `test/support/index.js`, and the
workflow suite is split by contracts and migrations, bootstrap, convergence and
review, recovery, and handoff.

Real run-store and Git services remain mandatory where persistence or repository
behavior is the subject. Keep focused cases for journals, interrupted recovery,
index ownership, staging, and handoff serial within their integration files.
Root state, Git, and cross-capability integration suites continue to own proof
of atomic files, journals, leases, recovery, filesystem durability, snapshot
semantics, and handoff behavior. Cover at least:

- dirty and clean preflight;
- staged, unstaged, deleted, and non-ignored untracked change membership;
- dirty tracked, non-ignored untracked, ignored untracked, and clean tracked
  task-input paths;
- default, configured, and legacy artifact roots plus ignored clarification
  creation and unauthorized clarification changes;
- empty and unchanged proactive clarification behavior;
- bounded questions and answer resume;
- independent Worker/Reviewer bootstrap and deliberate MCP source-session
  forks;
- omitted-mode preservation of independent probes, forks, review, disputes,
  arbitration, and completion gates;
- lazy primary-only probes and turns, exactly one Worker source fork across
  clarification, bootstrap, work, convergence, and resume, and no Reviewer or
  Arbiter invocation;
- reconciliation, arbitration, and product-decision pauses;
- stable runner derivation across conflicting role IDs, cross-role repeated
  commands and paths, role-only entries, trusted commands, and attempted
  reconciliation inventory invention;
- 256/257-item role boundaries, disjoint 512-item derived inventories and
  513-item rejection, semantic infrastructure classification, unchanged byte bounds,
  persistence, finalization round trips, infrastructure fingerprinting, and
  strict bounded capacity exhaustion;
- duplicate IDs or commands, multiline commands, missing files, directories,
  symlink aliases, successful bounded correction, interrupted reconstruction,
  validation-migration correction including interrupted Arbiter recovery, and
  repeated invalid bootstrap output;
- cached-diff fingerprints, index mutation and inspection, implicit
  worktree-versus-index checks, alternate indexes, and commit preparation in
  bootstrap, validation migration, and finalization, including corrected and
  repeated-invalid producing-role results;
- resolved and fallback finalization guidance, corrected availability,
  `BLOCKED`, `PASS`, and `FAIL` routes, interruption before and during the
  read-only correction, strict redaction, content-fingerprint reset, and
  repeated-invalid terminal behavior;
- read-only mutation plus ref, remote, and identity guards;
- durable transitions, interrupted turns, and journal recovery;
- action-free owner-loss continuation, input and Git-control drift rejection,
  read-only replay guards, preserved partial Worker content with rejected index drift,
  evidence invalidation, exact-once correction accounting, and activity-marker
  continuity;
- blocked provider activity plus lease-aware running, interrupted, and idle MCP
  projection;
- successful polishing, independent candidate review before finalization,
  formatter fingerprint changes, terminal Reviewer approval and findings,
  finalization failures, fixes, disputes, arbitration, stagnation, budgets,
  overrides, and complete gate invalidation;
- lazy changed and unchanged check/fix passes, candidate clean confirmation
  before finalization, distinct terminal clean confirmation, findings from both
  confirmations routed to fixing, required full reconvergence, matching-
  evidence reuse, change-triggered re-finalization, mutation and fingerprint
  rejection, bounded no-progress, and additional fix rounds;
- provider and deterministic lazy-checkpoint correction, repeated-invalid
  exhaustion and null retry, public redaction, fresh sessions, writable content
  and index reconciliation, exact-once budgets, fingerprint drift, gate and
  handoff preservation;
- interruption at candidate review, both lazy candidate checkpoints,
  finalization, terminal confirmation, and handoff without replay, double
  counting, duplicate staging, or a second source fork;
- automatic discovery, explicit skill selection, skill-less fallback, invalid
  explicit paths, resume, and matching finalization/review fingerprints;
- canonical-worktree conflicts across independently identified polishing or
  plan-execution runs, detached MCP retry, and same-host stale recovery;
- compatible legacy migration, incompatible reader and detached-child
  rejection, and disconnects that leave durable state unchanged;
- every supported legacy version migrating through state version 13 to safe
  candidate convergence while preserving paused and terminal runs without
  replaying `HANDOFF`;
- sandbox, IPC, loopback, process-isolation, missing-service, and permission
  blockers for nondelegated work, including fingerprint-aware preservation
  and resume while another command is selected for trusted execution;
- delegated repairs and candidate convergence in both modes, with persisted
  exact command text in every affected writable checkpoint, continued and
  reconstructed requests, and lazy corrections; empty selections and exact
  matching without unrelated configuration or repeated inventories; trusted
  execution only during `FINALIZE`;
- successful, blocked, failed, non-allowlisted, fingerprint-drifting, mutating,
  and resumed runner-trusted checks with the durable selected snapshot;
- finite redacted Claude failure classification, durable read-only request
  reconstruction, writable usage/provider reconciliation, and terminal
  authentication, forbidden-operation, and ambiguous writable boundaries;
- non-delegating role prompts plus terminal, redacted, durable, and publicly
  projected forbidden-collaboration diagnostics;
- actual Codex workspace-write and Claude Git-directory/`git add` access
  envelopes, content-only added and updated files, successful and recovered
  runner handoffs, version-5 complete, untouched, and contaminated handoff
  migration, correction turns that leave the index unchanged for both
  backends, and every staging postcondition;
- the invariant that `HEAD` never changes and completion never commits.

Root tests cover workspace imports and metadata, static registration,
configuration, runner behavior, CLI/MCP projections, applicable resume actions,
idempotent detached continuation, and regressions for existing pipelines.

Additional terminal-recovery coverage includes both modes, evidence-only and
mixed rejection, unchanged-inventory insufficiency, exact replacement inventory,
separate malformed-output budgets, durable retry reservation and exhaustion,
provider and interruption recovery, scope drift, formatter-bound whole and
partial overrides, safe CLI/MCP projections, strict version-10 migration, and
handoff blocked until replacement finalization and fresh confirmation pass.

## Non-Goals

Do not add a workflow framework, dynamic plugins, pipeline-to-pipeline imports,
commit-plan parsing, fuzzy finding matching, parallel reviewers, network
transport, daemon, remote mutation, automatic commits, or open-ended dialogue
after clarification closes.
