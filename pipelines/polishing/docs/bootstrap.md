# Polishing Clarification And Bootstrap

Read the affected sections before changing this contract. Use the [topic map](README.md)
for related owners and required reading routes.

## Clarification

Every run begins in a pipeline-owned `CLARIFY` state. The Worker studies the
task, current changes, task-level and execution clarifications, repository
instructions, relevant architecture, tests, skills, and Git history in
read-only mode. It returns strict structured `READY`, all currently actionable
material questions, or a narrowly valid `PRODUCT_DECISION_REQUIRED` outcome.

The run-specific transcript is:

```text
<infrastructure-root>/<artifactRoot>/agent-runner/<run-id>/clarifications.md
```

The selected configuration supplies the infrastructure root and resolved artifact
path; without configuration the root is the target. Version 24 freezes
`clarificationRoot` for every transcript operation, pending edit, append recovery,
answer, freeze and product decision. `artifactRoot` remains infrastructure-relative
and defaults to `LOCAL_ARTIFACTS`. Explicit version-23 migration preserves exact
legacy repository-owned paths, pending authorizations/appends, hashes, receipts,
workspace policy and consumed allowances. Preflight-paused legacy runs discover
only their original repository root; resume never relocates artifacts or selects
current configuration.

Any enclosing repository must already ignore the untracked transcript. Runner
never changes ignore rules. Only an in-worktree transcript receives a target Git
baseline exemption; external placement grants only confined Runner transcript
effects, with protected configuration, real parents, control/task/state separation
and target/infrastructure leases. Provider output and Git authority do not expand.
The transcript has its own immutable-input hash in either placement.

`--clarify` opens the authorized editor before the first agent turn. Otherwise
the editor opens only when questions exist. MCP never opens an editor and uses
the common structured pending-input projection.

An empty clarification artifact is valid. Closing an authorized editor without
changes is also valid. Neither case requires user text.
They do not consume an agent question
round. Unanswered agent questions still require a response.
The fixed clarification protocol permits at most three agent question rounds;
it is not a configurable workflow budget, and exhaustion pauses rather than
advancing.

The runner persists the suspended workflow state, one-shot pending editor
authorization, and accepted transcript hash before opening an editor or waiting
for input. Authorized edits update the accepted hash. Edits outside that window
pause as unexpected input changes. The transcript is frozen and hashed before
leaving `CLARIFY`.

State version 23 journals question rounds and supported product decisions outside
`resolutionCorrection.productDecision` through the existing clarification
service's `persistAppend` callback before replacing transcript bytes. The closed
nullable `pendingClarificationAppend` contains `kind` (`questions` or
`product-decision`), normalized `questions` and nullable `decision`, next `number`,
`expectedHash`, `resultHash`, and a closed `checkpoint`. The checkpoint retains
the producing `workflowState`, safe `suspendedState`, complete pipeline/input/
counter/session-lineage `fingerprint`, inspected `infrastructureFingerprint`
(or null before inventory selection), and nullable normalized arbitration
`workReport`. Questions suspend only `CLARIFY`; supported decisions suspend
`CLARIFY` or return through `BOOTSTRAP` under the existing invalidation rules.
The two append owners cannot coexist; a pending append also excludes an editor
window, active turn and authentication source-fork recovery.

Before replay, verify the complete checkpoint, protected non-transcript inputs,
repository/content/control ownership, frozen guidance and applicable validation
infrastructure. The checkpoint infrastructure fingerprint covers the union of
the established inventory and any retained finalization inventory, including
ignored files added during finalization. Recognize only the prior transcript
bytes or exact journaled result before ordinary transcript-drift rejection.
Replay supplies `resultHash` to verify an already completed replacement without
another append or provider response. Verified readback precedes one atomic
publication of the resulting hash, once-only round/decision accounting, existing
work invalidation and retained
arbitration report, structured input request and one-shot editor authorization,
while retiring intent. Only after that publication may an editor open. An
unchanged material answer renews only its editor window, without a model turn or
another question charge; an empty proactive close remains accepted.

Recovery runs before interrupted-turn inspection or new role work. Interrupted
replacement, readback or state publication retains the original checkpoint and
intent. Transient clarification read/write failures expose only the bounded
`clarification_append_interrupted` reason and source-defined code; explicit resume
reverifies the original checkpoint. Changed inputs, bytes, controls or frozen
infrastructure remain non-resumable, including through later read failures.
Operator-stop reconciliation only verifies proof and retains intent: it never
appends, prepares/opens an editor or accepts an answer. Existing finding-resolution
settlement and handoff effect reconciliation keep their independent ownership.
The ordered version-22 migration initializes only absent legacy intent to null,
without inferring payload, hashes, session authority or renewed budgets. Existing
settings, mode routing, correction accounting and source-fork rules are unchanged.

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
6. resolves and fingerprints finalization guidance without reading its content
   into a prompt or activity;
7. probes Worker and Reviewer independently in independent and combined modes,
   or Worker alone in lazy mode;
8. resolves and persists the selected trusted-command vectors, identities,
   ordered-command fingerprint, and trusted-configuration fingerprint;
9. creates or preserves the run clarification transcript;
10. stores the artifact root, settings, frozen guidance, hashes, backend
    versions, and the repository baseline.

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

Active role turns carry the Runner-owned [session naming context](../../../docs/product/PROVIDER_MODEL.md#sessions-and-context).
The creation acknowledgement records a verified new child at this pipeline's
existing logical context key before a naming diagnosis or metadata failure is
returned; the eventual response does not record it twice. Naming diagnoses grant
no retry, source fork, replacement,
owner cycle or workflow/effect authority. Continuation preserves historical sessions.

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
backend-availability failure. Opaque `turn_other` retains one fresh
reconstruction outside source forks before the next failure propagates. Explicit
overload uses the runner's durable availability policy. Turn-item policy, protocol, and isolation
auditing and the model-reroute guard take precedence, and native error details
are discarded; the adapter owns recognition and recovery.
Recognized native output exhaustion remains a terminal failure with the shared
`output_exhausted` disposition and bypasses automatic replay, compaction, availability,
quota, and output-correction recovery. The
[provider model](../../../docs/product/PROVIDER_MODEL.md#normalized-failures-and-recovery)
owns its recognition and evidence limits.
Claude classifies structured permission denials, HTTP status, result subtype,
and terminal reason before consulting a bounded native-text slice. Only finite
allowlisted backend, capability, configuration, usage, provider, expected-tool
permission, and harmless read-only execution failures are resumable. Bash
permission recovery requires a positively recognized safe repository
inspection, an exact single-space command form that includes the
`HEAD`-relative `git diff --check HEAD`; every other Bash denial, including
whitespace variants and compounds, fails closed. Role requests carry the
established persisted required-check commands for diagnosis only; a denial
exactly equal to one is the terminal `permission_bash_required_check` class.
A closed native refusal reason uniquely matched to every non-safe Bash denial
in the batch yields the terminal `permission_reason_<code>` class instead,
without naming the operation.
Structured API-error recovery requires an explicit transient HTTP status,
while non-transient client statuses and an unqualified structured `api_error`
are terminal. A normalized
`authentication_required` disposition enters the fixed durable
reauthentication pause; other authentication evidence, unexposed-tool and
unclassified-Bash denials whose refusal cause is unknown, legacy
`permission_forbidden_operation` records, isolation or protocol failures, and
unclassified writable process outcomes remain terminal (see the
[provider permission classes](../../../docs/product/PROVIDER_MODEL.md#normalized-failures-and-recovery)). Denied input,
native result text, raw standard error, and native process causes are discarded.
Explicit native transport, overload, model-busy, and server availability use the
injected runner coordinator after repository reconciliation. The exact role and
logical checkpoint survive five-second exponential backoff capped by the frozen
policy, with indefinite repeats at the ceiling. Scheduling and start are durable
and immediately visible; overdue recovery dispatches once. A successful provider
response resets the episode before output validation. A normalized authentication-
required response instead retires the superseded episode before its distinct
operator pause. Partial output, partial writes, session changes, resume, and
restart do not reset it. Safe partial
content and pending corrections survive; stale approvals are invalidated and the
same correction is not charged again. Check/fix mutation claims use the successful
attempt's starting fingerprint, after retained partial content is reconciled.
Source forks are never replayed. An
abortable wait retains exclusive ownership and honors immediate/deferred stops.
See the common [availability contract](../../../docs/ARCHITECTURE.md#durable-availability-episodes).
An explicit rate, quota, credit, or spend-limit rejection is not retried through
compaction, a fresh session, or provider fallback. Persist
`backend_unavailable`, safe Worker workspace changes, and invalidation of stale
fingerprint-bound results before pausing so the complete durable request can be
reconstructed after capacity returns. Classified usage and provider failures
from writable turns use this path only after workspace and repository-control
reconciliation; no native session is required.
Authentication uses that same safe reconciliation but no availability episode
or automatic retry. Persist exactly `authentication_required`,
`ERR_AUTHENTICATION_REQUIRED`, and the current polishing state. Null resume
after reauthentication preserves safe partial content, role/session lineage,
fingerprints, and correction accounting and reconstructs the same logical
request. Provider-native diagnostics do not enter state or CLI/MCP projection;
runner-owned handoff staging retains its existing effect-recovery path. For a
failed source-session fork, normalized no-effect evidence permits the fork to
be retried. Possible-effect evidence instead persists only the role and logical
context key, resumes the same role in a fresh session without reforking, and
clears that marker only after a child session is durably recorded.
The pause and source-fork state are persisted atomically with active-turn
retirement. An interrupted write preserves recovery instead of converting the
run into a terminal failure. A partially completed finding-resolution round
retains its charged writable continuation even at the fix limit; it neither
consumes another round nor permits a new round beyond that limit.
If publication was interrupted before the pause was saved, authentication
during fresh recovery still preserves the earlier unrecorded source fork.
An eligible normalized transient pre-effect launch failure without availability
evidence adds only
`launchRecovery: { failureClass, checkpoint }` to that pause. If a lazy source
fork fails at `spawn` or `initialize` before a child exists, the same atomic
transition restores `lazySourceForkConsumed: false`; later fork checkpoints are
non-resumable because native lineage may already exist. Resume rebuilds an
eligible early request without charging correction work or duplicating a
handoff effect. Operator pause, resume, and cancellation use the common state
semantics.
The root agent boundary normalizes the selected adapter's finite diagnostic
class before workflow code sees a terminal failure. Only its bounded message
composed from fixed text, the code and the validated class, the bounded code,
safe control flags, shared structured-output class, and validated diagnostic
class cross the boundary. A terminal FINALIZE protocol failure persists
`internal_failure` with that class and grants no finalization acceptance,
fingerprint, staging, retry, or resume. Codex collaboration activity despite a
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
Bootstrap, its correction and validation migration catalogue only checks owned
by this pipeline's finalization, including selected Runner-trusted commands.
Acceptance explicitly assigned to the supervising operator or another owner
after the run completes stays pending external work in the summaries, with its
owner and timing, and reconciliation or arbitration keeps it there. This
semantic rule follows the
[validation ownership guarantee](../../../docs/product/VALIDATION_AND_REVIEW.md#bootstrap-inventory);
the runner does not parse task prose for ownership or remove a misclassified
accepted command.
Bootstrap and validation migration receive only the frozen selected path or
fallback decision, never skill content. A selected skill is mandatory
validation infrastructure; the runner retains it in the established inventory.
If otherwise valid maximum-sized role inventories omit it, the producing role's
bounded correction must reserve capacity instead of causing an unstructured
aggregate overflow.
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
existing regular file by its exact canonical repository-relative path. The sole
exception is the exact selected finalization-file label, inspected through the
root configuration capability against its frozen infrastructure root. Missing
files, directories, symlinks, and paths traversing a symlink are field-specific
contract violations. Every producing role, bootstrap or validation-migration
phase, and bootstrap contract receives at most one read-only correction. The
runner persists only attempt `1` and the bounded role, phase, contract, field,
and constraint diagnostic before that turn. A valid replacement clears the
pending copy; resume reconstructs an interrupted correction from durable state;
a repeated invalid result fails closed. Rejected structured values, provider
text, prompts, commands, transcripts, credentials, and chain-of-thought are
never retained.
