# Clarification Lifecycle

Read the affected sections before changing this contract. Use the [topic map](README.md)
for related owners and required reading routes.

Execution state version 44 and polishing version 24 persist `clarificationRoot`.
New runs freeze the configuration-owned infrastructure root (the canonical target
without selected configuration), and derive
`<artifactPath>/agent-runner/<run-id>/clarifications.md`. Every transcript read,
creation, append/recovery, editor authorization, answer, freeze, compatibility
check and product decision uses that same confinement owner. Public CLI/MCP
projections retain the exact transcript path without configuration contents.

Explicit migrations preserve the legacy repository root, transcript, pending
append/edit authorization, hashes, receipts, workspace policy and consumed
allowances. A legacy run paused before preflight keeps a null selection until
Git discovery supplies its original repository root; current configuration never
relocates it. Runner verifies the owner against protected configuration or the
legacy repository; pipeline validators bind the derived transcript and pending
edit without reading configuration protection. Git baselines allow only the
transcript actually inside their worktree; external transcripts add no target Git
exemption. Custom directory policies keep
only their exact declared artifact exemption. External operations reuse the
infrastructure lease alongside target exclusion, retain configuration identity
and ancestry checks and confined real parents, and cannot overlap task, state,
configuration, output or Git/provider controls, including their aliased targets.
Every transcript operation inspects controls from both the target workspace and
frozen infrastructure owner, and revalidates enclosing-worktree ignored/untracked
status through the existing workspace and Git owners. Answer previews remain
read-only; submission and cold append recovery hold the existing leases.
This grants only Runner transcript effects, never provider outputs,
parent writes, staging or commit authority.

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

Audit state version 10 journals question appends through the clarification
service's existing `persistAppend` callback before transcript replacement.
Its closed nullable intent binds exact normalized questions, round, prior/result
hashes and checkpoint settlement data. Before replay it verifies protected
non-transcript inputs, workspace/control ownership and checkpoint bindings,
then accepts only prior bytes or the exact journaled result. `resultHash`
reconciles an already completed replacement without duplicating it or invoking
another role. Verified readback precedes one atomic hash/round/editor-request
publication that retires intent and clears accepted correction/recovery feedback;
only then may an editor open. Interrupted replacement or publication retains
proof for supported resume, while unexpected edits remain non-resumable.
The descriptor migrates legacy absence to null without inferring append
authority. Audit operator-stop reconciliation only inspects this proof and
retains intent; it never appends, creates an editor window or accepts an answer.
Existing init and coding settlement append owners remain independent.

Plan-authoring state version 9 applies the same journal-before-replacement
protocol to question rounds and supported product decisions. Its closed intent
binds normalized payload, numbering, prior/result hashes, original checkpoint,
pipeline/input/accounting/lineage fingerprint and Arbiter settlement marker.
Recovery precedes interrupted-turn transcript inspection and role dispatch,
retains commit/custom selection and directory guards, and publishes hash,
once-only accounting and the editor request atomically with intent retirement.
Product decisions preserve existing draft/review invalidation and consecutive
stagnation reset without renewing cumulative revision or arbitration allowances.
Legacy absence migrates to null without authority. Stop reconciliation only
verifies proof; unsafe input remains blocking and transient read/write failures
retain bounded resumable diagnostics. Editor authorization stays separate from
append intent, including unanswered material-window renewal.

Plan-execution state version 43 extends that contract to question rounds and
supported nonsettlement product decisions, without competing with
`writableResult.productDecision`. Its closed intent retains normalized payload,
number, prior/result hashes, the producing checkpoint fingerprint, suspended
state, inspected validation infrastructure, lineage requirements and any
arbitration report required for settlement.
Protected inputs, repository/controls and applicable custom accepted-output
bindings precede replay; verified readback precedes atomic hash/count/editor
publication with the established invalidations and once-only report retention.
Recovery precedes interrupted-turn inspection and fresh role work. Legacy
absence migrates to null without authority. Bounded read/write interruption
retains resumable intent, while changed inputs/bytes/controls remain
non-resumable. Operator stops only inspect append proof and retain intent;
existing writable-result and commit effects keep their independent ownership.

Execution's terminal `CONFIRM` product-decision route retains finalization
evidence while preparing the append that suspends to `IMPLEMENT`. Append
inspection measures the deduplicated established and retained-finalization
infrastructure inventories before intent creation/replay and after transcript
readback, before editor authority. Ignored finalized-only files therefore remain
protected even when ordinary content snapshots are unchanged. Measurement uses
the existing fingerprint owner, including selected-file composition and
ordinary/legacy domains, independently of the finalization evidence tuple.
Missing or changed infrastructure retains the original intent and accounting
under the existing validation-infrastructure safety pause. No state shape or
version changes, and recovery never rebinds an old intent to observed bytes.

Audit, plan-authoring and plan-execution compare the service's returned hash
with the durable append intent's `resultHash` before publication. A mismatch
persists the owning non-resumable rejection (`input_changed` for audit,
`clarifications_changed` for authoring/execution), retaining the complete intent,
prior hashes, checkpoint, counters and unsettled work without editor authority.
Fresh workflow or cold Runner/store recovery and verification-only stops keep
that rejection even when later bytes match the prior or result hash. This uses
the existing strict intent and pause contracts without a state-version change;
transient I/O and unknown publication failures retain their existing policies.

Polishing state version 23 extends the same protocol to question rounds and
supported product decisions outside `resolutionCorrection.productDecision`.
Its pipeline-owned closed intent retains exact normalized payload, prior/result
hashes, next numbering, producing checkpoint fingerprint, safe re-entry state,
inspected infrastructure and optional arbitration report. Replay verifies
protected inputs, repository/content/controls, frozen guidance and applicable
infrastructure, including additions in retained finalization evidence, before
accepting prior or exact result bytes. Verified readback precedes atomic
hash/count/work-invalidation/editor publication and intent retirement, retaining
the existing correction and arbitration accounting rules.
Recovery precedes interrupted-turn inspection and fresh role work; stop handling
only verifies proof and retains intent. Legacy absence migrates to null without
authority. Bounded transient append diagnostics remain resumable, while proven
input/control drift remains non-resumable. Finding-resolution settlement and
runner-owned handoff keep their independent effect ownership.

The transcript reader retains its existing error codes and 1 MiB limit. Its
size and regular-file/single-link guards add optional `constraint` metadata of
`file_size` or `isolated_regular_file`, respectively. Other path, read, decoding
and write failures retain their existing handling; these tags grant no edit,
retry or continuation authority.

`writeEditAnswers` accepts an optional Runner-owned `inspectRead` callback. It
wraps only the initial transcript inspection and the confined replacement
recheck, before any write. Answer validation, replacement effects and post-write
readback remain outside that callback. Callers without it retain the existing
error and exact-hash replay behavior.

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
