# Execution CLI And Configuration

Read the affected sections before changing this contract. Use the [topic map](README.md)
for related owners and required reading routes.

## CLI

Required commands:

```bash
agent-run run plan-execution --project <repo> --task <task-dir>
agent-run run plan-execution --project <directory> --task <task-dir> --plan-kind custom
agent-run resume --run <run-id>
agent-run status --run <run-id>
```

Use `--clarify` on `run` to open `$VISUAL`, falling back to `$EDITOR`, before
the Worker's clarification turn:

```bash
agent-run run plan-execution \
  --project /path/to/repo \
  --task /path/to/task \
  --clarify
```

Without the flag, `CLARIFY` still runs but opens the editor only if the Worker
returns questions. In a non-interactive environment, persist the pause and print
the clarification artifact path instead of attempting terminal dialogue.

Use run-wide or role-specific execution flags when native overrides are
required:

```bash
agent-run run plan-execution \
  --project /path/to/repo \
  --task /path/to/task \
  --worker codex \
  --worker-profile codex-work \
  --worker-model <codex-model-id> \
  --worker-context-size 200000 \
  --reviewer claude \
  --reviewer-profile claude-primary \
  --reviewer-model <claude-model-id> \
  --reviewer-context-size 200000
```

`--mode` accepts `independent`, `lazy`, and `combined`. `independent` is the default
and recommended mode because it provides genuinely independent semantic review,
although its separate roles use more provider context and tokens. `lazy` is an
explicit lower-consumption choice that uses only the Worker and does not provide
independent review. The runner never selects it automatically.

### Combined commit review

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

Combined mode uses the independent active roles, bootstrap discovery and union,
checkpoint source forks, and fresh output-correction contexts. The Arbiter is
confined to independent finding resolution, including finding-based stagnation.
An unresolved non-finding bootstrap or validation-migration disagreement pauses
with `bootstrap_disagreement`; retry repeats reconciliation without arbitration.

The normal route is `IMPLEMENT -> CHECK_AND_FIX -> CLEAN_CONFIRM -> REVIEW ->
FINALIZE -> CONFIRM -> COMMIT`. Worker check/fix retains workspace-write access;
its separate clean confirmation is read-only. `primaryFindings` stores only
combined self-confirmation blockers; it never replaces independent findings or
pending disputes. `candidateConfirmationFingerprint` records primary approval;
`candidateReviewResult` and `candidateReviewedFingerprint` record the independent
Reviewer gate. Primary confirmation alone cannot authorize finalization or commit.
Unchanged resolutions may retain passing finalization only when live content and
infrastructure still match, after both candidate gates reconverge. Persisted lazy
correction field names and their bounded accounting remain unchanged.

State version 17 adds empty primary findings through the existing leased migration
chain. Missing and legacy missing modes remain independent. Migration preserves
saved modes, evidence, counters, and prepared or consumed effect records; it never
constructs a combined approval from a historical single gate. Journal-proven
confirmation recovery requires both primary and independent candidate edges for
combined mode, followed by finalization and terminal confirmation provenance.

State version 18 adds `capabilityRequirements` and `environmentBlockers` to
accepted role validation inventories. Legacy active runs lacking discovery must
repeat read-only validation migration before writable work; lazy migration uses
only Worker. Null report fields mark provisional legacy evidence, never an empty
successful discovery. Passive migration preserves historical journal proof; live
resume invalidates provisional gates before discovery. Completed/failed historical
states remain inert except for already supported journal-proven recovery. A consumed
commit keeps its exact gate and authorization for verification first; discovery
continues only if settlement leaves more work. Migration preserves frozen
configuration, completed commits, and correction budgets.
State version 25 requires every plan-execution capability report to carry the
boolean `sourceProjection` need. The ordered version-24 migration sets it to
`false` without changing the trusted snapshot, workflow position, correction
accounting, review evidence, or prepared and consumed effects. It does not infer
authority from current configuration. Null provisional reports stay null and
continue through the existing read-only discovery barrier.
State version 26 admits the fixed authentication pause and bounded commit
pre-effect authentication proof. The ordered version-25 migration initializes
the nullable provider-neutral source-fork recovery marker to `null` while
preserving workflow position, session lineage, fingerprints, correction
accounting, and prepared or consumed effects. It does not infer a native child
or reload configuration, and it prevents older readers from accepting the
expanded durable vocabulary as version 25.
State version 40 requires `basis` on every new provider capability report. The
version-39 migration is the identity: it never edits saved or frozen reports,
unfinished bootstrap work including pending correction reports, completed
provenance, selections, schedules, prepared or consumed effects, budgets, or
workflow position. Saved reports without `basis` stay byte-identical and keep the
admission they were accepted under; reloaded work keeps its catalog fingerprint,
unit IDs and validation-fingerprint bindings until a later catalog change
regenerates them. Null provisional reports stay null for the existing discovery
barrier. A recovered provider result without `basis` receives bounded
correction, never an inferred `basis`. The version bump prevents older readers
from accepting reports that carry `basis`.
Discovery does not authorize leaving a safety pause. Interrupted correction
edits are reconciled and charged before new writable work, without recounting
them on a later resume.

## Source sessions

An independent or combined run may seed Worker and Reviewer from one existing session only
when both use its backend. A lazy run applies that requirement only to its
active Worker:

```bash
agent-run run plan-execution \
  --project /path/to/repo \
  --task /path/to/task \
  --worker codex \
  --reviewer codex \
  --fork-from codex:<session-id> \
  --fork-profile codex-work
```

The runner splits only the backend prefix, keeps the session ID opaque, probes
native fork support, and persists the resolved source and known trusted
profile. A known source profile supplies `current` for the Worker and, in
independent and combined modes, Reviewer and requires every explicit participating
backend/profile selection to match. An unknown source profile requires those
profiles to remain `current` and omits the native
profile override. In independent and combined modes, Worker and Reviewer checkpoints fork it
independently and every Arbiter remains fresh. In lazy mode, it is forked
exactly once into the logical Worker across clarification, bootstrap, all
planned commits, and every convergence checkpoint. Later checkpoints continue
that child when compatible or reconstruct the same Worker without reforking the
source. `resume` uses the persisted lineage and one-time marker. MCP leaves the
source unset unless the user deliberately selects a compatible current session
after being offered a fresh start. It includes a known trusted profile with the
fork choice, or offers only `current` inheritance when the profile is unknown.
Recommend a fresh start for a long, multi-topic, or uncertain session,
especially when independent mode would fork its complete context more than
once.

## Roles and execution options

Role backends must be independently configurable:

```bash
agent-run run plan-execution \
  --project /path/to/repo \
  --task /path/to/task \
  --worker codex \
  --reviewer claude \
  --arbiter codex
```

Supported V1 backend values:

```text
codex
claude
```

The following must work:

```text
Codex worker  + Codex reviewer
Claude worker + Claude reviewer
Codex worker  + Claude reviewer
Claude worker + Codex reviewer
```

The Arbiter must also support either backend.

The pipeline descriptor declares the `worker`, `reviewer`, and `arbiter` roles
and owns active-role selection. Independent and combined modes activate all three, with the
Arbiter still probed on demand; lazy mode activates only the Worker.
Role objects under `pipelines.plan-execution.roles` in the runner's
`.agent-runner.json` or its safe project overlay may provide optional string
`backend`, trusted `profile`, backend-specific `model`, decimal
`contextSize`, and portable `effort` selections. Project profile selections reference aliases defined
by runner-root configuration; the project cannot define profile implementations,
credentials, provider binaries, or environment values. Role-specific CLI/MCP
values take precedence over run-wide values, project values, runner values, and
built-in `current`. A trusted profile pins
its backend; conflicting explicit backend selection is invalid. `current`
omits the corresponding native override and uses the effective source-session,
process, profile, or backend default. Do not hard-code model names into
workflow logic.

Effort accepts only `current|low|medium|high|xhigh|max`, independently of model IDs.
The shared root resolver applies role override → run override → project role →
project `defaultEffort` → runner role → runner `defaultEffort` → `current`.
CLI `--effort` and descriptor-derived `--<role>-effort` map to MCP
`run_start.effort` and `roleOverrides.<role>.effort` through the same runner
contract. Both reject values outside the portable enum before dispatch; MCP
intents bind the selections and detached continuations reuse saved effort.
Validate all configured vocabulary, but resolve and persist only active roles;
native translation stays in provider adapters. Every role turn carries saved explicit
effort, including recovery and commit readiness; `current` omits the request override.
Common envelope version 8 requires saved active-role effort. Legacy missing
values migrate to `current` under the run lease without provider activity,
configuration reload, or changes to progress and session evidence. Public
status and activity omit these provider-private values.

## Pipeline settings and finalization guidance

The descriptor also owns the positive-integer settings and built-in defaults
listed under [Retry Limits and No-Progress Detection](escalation.md#retry-limits-and-no-progress-detection),
plus `mode` with default and recommended value `independent`. It additionally
owns the string `finalization` setting. Its default `auto`
selects the first safely inspectable canonical regular conventional
`finalization` skill and otherwise falls back to repository instructions and
project-defined checks. `none` selects that fallback directly; any other valid
value is a normalized infrastructure-relative Markdown path and requires that
exact procedure (including an adjacent `RUNNER.md`). The runner resolves this decision after workspace
preflight and before bootstrap, then persists the configured policy, selected
path or fallback, selected-file fingerprint when applicable, and a fingerprint
of the complete decision. Resume never rediscovers or switches guidance. Explicit paths resolve from the
frozen selected infrastructure root, while `auto` retains conventional discovery
inside the target. A bound external `finalization/SKILL.md` requires only that
exact file read; neither the original skill nor any parent is changed or granted
additional access. New `file` decisions fingerprint bytes, file identity, real
ancestors, target and root without retaining procedure text. The existing
`skillPath` field supplies its inventory label: an integrated repository-relative
path or `finalization://<infrastructure-relative-path>` for external guidance.
The latter never replaces repository-relative validation entries, including
same-relative-path files. Prompts also declare the exact absolute read. Only this selected label may name external
validation infrastructure. Replacement (even identical bytes), links, missing
files and drift block without switching guidance or consuming repair budgets.

State version 36 preserves version-35 decisions and all accounting and effect
evidence unchanged through its leased migration. Legacy `skill` decisions retain
their original repository path and fingerprint algorithm; no identity proof is
inferred and no frozen selection is rediscovered. Consumed commits and completed
handoffs remain verification-only. New selection adds no model checkpoint.

## Configuration precedence and protection

Runner overrides live directly under `pipelines.plan-execution`. The root
loader strictly validates both versioned envelopes and delegates these values
to the descriptor rather than duplicating pipeline policy. It discovers only
the ignored `LOCAL_ARTIFACTS/agent-runner.json` project file unless CLI/MCP
explicitly selects another integrated ignored path or target-bound external
configuration under the root configuration contract. It never creates the file or
changes ignore rules. All configured role objects are validated
deterministically. CLI/MCP pipeline-setting overrides then win over the project
overlay, runner values, and descriptor defaults. Only active roles are
resolved, probed, persisted, source-session checked, or invoked. Inactive
configured values remain in the configuration source for a later independent
run and are not exposed through lazy state. Resolved roles, settings, and
`artifactRoot` are persisted and never reloaded on resume.
When a project configuration supplied those values, the root runner persists
its protection record and checks it before recovery, around every provider
turn, and before trusted execution, commit, or stop reconciliation. Drift
produces the non-resumable `project_configuration_changed` safety pause;
already begun commit effects remain verification-only. Complete and recovery
role envelopes explicitly prohibit modifying the resolved project
configuration.

## Trusted command configuration

The descriptor also owns `trustedChecks`, an ordered list of unique lowercase
aliases that defaults to `[]`. Root and safe project `trustedCommands`
configuration use the same exact-vector validator for each alias, inventory
command, executable, and argument vector. Normalized catalogs merge root then
project in stable order, deduplicate identical same-name definitions, and reject
conflicts even when unselected. The merged catalog permits at most 256
definitions and each selection at most 32 aliases. Project `trustedChecks`
replaces the root selection and may reference root or project aliases; selection
order is preserved. Definitions cannot add environment, credentials,
shell-string substitutes, or broader host authority. Profile implementations
remain runner-owned. Before agent work,
the root persists every resolved vector and alias, deterministic command
identities, an ordered command fingerprint, and a trusted-configuration
fingerprint. Resume uses that durable snapshot without reloading configuration;
later project configuration edits trigger the existing protected-input guard.
The top-level `trustedCommandTimeoutMs` supplies its per-command deadline in
milliseconds. It is a strict integer from `1` through `2147483647`, defaults to
`3600000` (60 minutes), and resolves project over runner configuration without
a CLI or MCP override. Run creation fingerprints and persists the resolved
value once; resume and concurrent runs use their own unchanged snapshots. For
example, `"trustedCommandTimeoutMs": 7200000` selects a two-hour deadline.

Trusted declarations also accept the closed `capabilities` object described in
the architecture: `scratch: true`, `cache: true`, `sourceProjection: true`, and
bounded pinned HTTPS `artifacts`. Root and project normalization are identical.
New snapshots use version 4 and include normalized capabilities in identities
plus `timeoutMs` in the trusted-configuration fingerprint; the timeout does not
change command identities. Version 3 retains its saved timeout without gaining
source-projection authority. Version 1 and version 2 retain their exact policy
and evidence bindings and use the deterministic one-hour fallback. Migration
never upgrades authority or reloads declarations. Capability preparation uses
the smaller of the snapshot deadline and 10 seconds.
This is one absolute monotonic launch-to-close deadline including durable
registration, checked again by the supervisor at payload admission. Expiry or
cancellation permanently closes release; pending registration and verified
retirement must drain, with uncertain ownership retained. Reconciliation never
turns an expired preparation into availability or required-check evidence.
Common envelope version 22 routes only preparation through canonical reservation,
bounded attachment/admission, and endpoint-bound canonical settlement. The root's
custody gate preserves accepted immediate stops even with delayed observation;
matching deferred targets retain current-step permission, while an explicit null
target supports ordinary preparation. No restart releases an old attempt, and
custody settles before cleanup, availability or further work. Existing consumed-
effect verification remains first; see [preparation custody](../../../docs/ARCHITECTURE.md#preparation-custody).

## Capability discovery and admission

Bootstrap and validation migration report bounded exact-command needs alongside
each active role's inventory. `capabilityRequirements` permits 256 reports per
role: `command`, nullable frozen `commandIdentity`, `capabilities` with boolean
`scratch`, `cache`, and `sourceProjection`, up to 32 exact `{url, sha256}`
artifacts, and `unsupported` with up to 16 unique lowercase capability
identifiers. Each need and blocker also carries a closed `basis`.
`assigned-executor` entries describe the command's assigned executor and
checkpoint, either the ordinary Worker `FINALIZE` turn under its existing
workspace-write access or Runner-trusted execution of a selected command, never
the current read-only discovery, migration, applicability, or Reviewer turn.
They require static task, repository, or declaration evidence, or saved evidence
from that executor running the exact command at its checkpoint. A restriction
seen only through the current turn's read-only access may be recorded only as
`read-only-turn`; it is never upgraded. Ordinary safe Worker workspace output
needs no report. `sourceProjection` is separate frozen
authority, not a synonym for workspace-write, and may be true only when evidence
shows the actual executor must write beside the staging-independent source it
checks; agents cannot name a path or grant authority. `environmentBlockers` permits 256 reports per role:
`command`, `source` (`agent-sandbox` or `runner`), and 1–8 bounded single-line
evidence strings. Every command must occur in that role's exact inventory;
existing structured-result byte bounds also apply. Every capability report must
contain at least one scratch, cache, source-projection, artifact, or unsupported
need. A non-null `commandIdentity` must exactly equal the frozen identity supplied
for that selected command; the field may remain null. Both `basis` values keep
every structural rule.
Non-READY outcomes carry empty report arrays. Zero-need reports, substituted
identities, missing or unknown `basis`, malformed fields or parameters, and
invalid references use the existing bounded read-only bootstrap correction path. A corrected empty array
leaves the ordinary inventory command agent-runnable and creates no delegated
requirement for root inspection.

Only saved state and already accepted internal discovery may contain reports
without `basis`. A provider cannot repeat such an inherited row byte for byte,
so its exact copy with `basis: "assigned-executor"`, the semantics the row was
admitted under, is legacy-equivalent. Provider discovery replaces each
legacy-equivalent copy with the saved row's exact bytes before the existing
deep-equality preservation rules run. Its sources are the prior revision
inventory for revision discovery, and during catalog correction the pending
discovery and its saved correction reports, including a charged report that has
not yet entered discovery. Every other provider row stays strictly validated, so
an inherited copy marked `read-only-turn` or otherwise changed fails
`preserve-prior-revision-requirements` or `preserve-and-complete-catalog`. An
applicability correction report that deep-equals or is legacy-equivalent to an
accepted discovery row is not new evidence and fails `new-capability-evidence`.
The workflow publishes only that canonical discovery, never the raw provider
payload; an actually changed catalog still receives a new fingerprint and unit
IDs, clears accepted coverage and keeps the consumed correction attempt.
Applicability requests carry the same `basis` guidance: catalog correction may
add `read-only-turn` entries but never upgrades one or changes the basis of an
accepted entry.

Accepted reports are persisted before inspection. Requirements from Worker and
Reviewer remain saved and additive regardless of which reconciliation or
arbitration summary is selected. Root inspection receives only
`assigned-executor` reports and legacy reports without `basis`, never the field
itself. `read-only-turn` observations stay unproved for review and never become
requirements, so their ordinary check stays with Worker `FINALIZE`, where an
actual failure keeps its existing blocker semantics. Frozen trusted declarations
remain requirements without any report. Reports describe needs; only the frozen
runner declarations grant authority. Before IMPLEMENT, CHECK_AND_FIX, writable RESOLVE_FINDINGS,
FINALIZE, and unconsumed COMMIT, the root capability matches those reports and
selected declarations against the saved inventory and inspects actual runner
availability. This gate runs on every writable entry and retry independently of
once-per-invocation preflight. It prepares only runner-owned availability probes,
not required checks or check attestations. Dependencies are verified during
preparation and acquired and verified again for finalization.

Missing selection, insufficient authority, unsupported needs, and unavailable
resources pause as `environment_blocked` with bounded runner-derived evidence
and the same resume checkpoint, before a writable provider invocation. The saved
reports and snapshot survive resume; environment repair may retry, while changed
declarations require a new run. An agent-sandbox report for an exactly delegated
command is satisfied when root inspection succeeds; a report for another command
still blocks. Agent evidence never overrides the root's availability decision.
Required checks execute exclusively during FINALIZE.
A blocked inspection saves the comparison's optional shared diagnostic as
`capabilityDiagnostic` and binds each published inventory index to the ID of
its required check in the active step's inventory in `capabilityChecks`.
Role-local bootstrap IDs are never published; a command outside that inventory
or listed under several IDs binds null. Saved evidence keeps each blocker
reason and validated ownership envelopes but no command text. Caught
availability failures and legacy pauses save no diagnostic, so their mismatch
details are unknown. Public status, wait and activity for this pause,
including historical records, use a fixed explanation and project evidence only
from the validated diagnostic, allowlisted check IDs and revalidated ownership
envelopes through the root-injected trusted-validation projector. Unsafe,
missing, ambiguous or unbound labels, including an ID saved for more than one
published blocker index, project as unknown and never change the blocker.

Unavailable frozen capabilities produce a durable `environment_blocked` pause
before provider work. An early creation pause has `preflightComplete: false`,
null baseline, backend versions, clarification path, and canonical plan, empty
hashes, and no `resumeState`; null-action resume retries the saved request before
ordinary `CLARIFY` preflight. Later pauses preserve their current checkpoint.
This inspection neither executes nor attests checks. Scratch/cache requests use
isolated transient storage; artifact requests use bounded runner-owned acquisition and read-only mounts.
Acquisition availability is checked at writable entry and again when preparing
finalization execution; the earlier declaration preflight inspects storage and
isolation without downloading dependencies. A consumed COMMIT is
verified first, preserving its authorized progress before capabilities are
checked for subsequent work. If an authorization is prepared but unconsumed,
an unavailable trusted capability or isolation boundary, or a blocked
required-check capability inspection, preserves it in an `environment_blocked`
pause targeting `COMMIT`. Retry rechecks capabilities
before consuming that same authorization; it does not advance commit progress.
Repository drift or a plan-position conflict found before consumption instead
retires the unconsumed authorization within its existing `unsafe_git_state` or
`plan_revision_required` safety stop, as consumption does for a changed commit
gate; a later `COMMIT` must pass the complete gate and prepare a new one.
An interrupted safety pause without a resume checkpoint retains its original
reason; capability inspection cannot replace it with an environment retry.
Status and immutable terminal reads do not probe
capabilities. Environment repair permits retry; changed declarations require a
new run and cannot justify weakening validation.

Codex and Claude do **not** both need to be installed for every run. Independent
mode preflight validates the selected Worker and Reviewer; the Arbiter backend
may be validated when arbitration is first needed. Lazy mode validates only the
Worker and never probes Reviewer or Arbiter.

---
