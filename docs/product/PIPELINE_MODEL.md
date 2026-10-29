# Pipeline Model

Agent Runner hosts three explicit local workflows. They share runtime safety and
durability services, but each pipeline owns its roles, prompts, settings, state,
and completion rules. The product is not a general workflow framework, and one
pipeline never calls another.

## Plan authoring

Plan authoring turns a task into a reviewed `plan.md`. Omitted `planKind` stays
`commit`, with exact Conventional Commit subjects. Explicit `custom` selects
criterion-driven planning in a Git-independent directory workspace. Material
missing criteria are resolved during bounded clarification; criteria may be
ordinary Markdown. The reviewed custom plan carries agreed stable criterion
references, observable results and input/output declarations. Sources remain
read-only, URLs grant no retrieval, and declared outputs grant no authoring
writes. Custom prompts inherit coding requirements only when selected by the
user. Plan authoring may
clarify material requirements first, but it keeps the target project read-only
apart from the resolved clarification and plan artifact paths. Commit-plan
headings contain the exact subject-only Conventional Commit messages that plan
execution will later consume unchanged.

The authoring setting `preferredCommitLineLimit` defaults to 900 anticipated
changed lines per commit, counting additions plus deletions including tests and
documentation. Planner and Plan Reviewer prefer smaller cohesive boundaries;
larger indivisible changes remain valid with a concise explanation in the plan.
The target is a planning heuristic and does not impose a new plan-format rule
or execution limit.

Plan authoring proposes work; it does not implement the task, create a commit,
or guarantee that a later worktree will remain compatible with the plan.

## Plan execution

Plan execution accepts an explicitly selected, deterministically validated commit or custom plan and implements one step at a time. Omitted kind stays commit. Custom execution uses agreed criteria in an ordinary directory, including analysis-only steps, and accepts durable result receipts after all mode-required candidate, finalization and terminal-confirmation gates. Analysis/evidence and inspected outputs bind those gates. It never stages or commits, even inside a repository; coding checks apply only when selected requirements make them relevant.

For commit plans, each accepted step becomes exactly one verified local commit
with the subject from its plan heading. Findings are resolved within that step,
not by adding separate review-fix commits. A completed earlier commit is durable
history and is never rewritten automatically when later work encounters a
problem.

Each step converges semantically before its terminal gate: independent mode
uses candidate Reviewer passes, while lazy mode alternates Worker check/fix and
read-only candidate confirmation. Combined mode requires primary convergence
followed by the complete independent candidate review. The stable candidate
then passes full finalization and one distinct read-only terminal confirmation
before its selected commit or accepted-result checkpoint.

The plan defines the authorized commit boundaries. New eligible commit-plan
runs may replace an oversized unfinished step with a reviewed flat sequence,
without changing the frozen input. Mode-specific plan approval, complete
replacement validation and verified external preservation precede separation.
Every replacement passes all ordinary gates independently; the original step
and its deferred stop complete only after every replacement commits. Legacy
and intermediate runs never acquire this eligibility by resuming. Clarification may explain a
requirement, but it cannot silently expand, reorder, or reinterpret those
boundaries. A conflicting clarification or product decision requires a revised
plan and a new execution run.

## Polishing

Polishing starts from an existing non-empty local change set rather than a
plan. It makes that whole change set correct, idiomatic, minimal, finalized, and
reviewed. Independent Reviewer convergence, lazy Worker convergence, or both
in combined mode occurs before finalization; a distinct read-only terminal confirmation then accepts
the finalized content and validation evidence. The runner stages that complete
accepted result and leaves it uncommitted. Polishing never requests local-commit
access and never changes `HEAD`.

Ignored files are outside the polishing change set. Task inputs inside the
repository must not overlap writable changes.

## Unregistered audit foundation

The unregistered audit workspace currently supplies finding contracts and an
English report renderer and internal read-only discovery and batch-verification
lifecycles. Findings have
independent severity/category classification, stable report-local identities,
supporting evidence, impact rationale and concrete observed or code-derived
examples. Shared causes must be consolidated; unsupported claims stay explicitly
unverified. Recommendations are optional and zero findings is valid. The static
classification map is generated from one catalog without a model turn. Report
rendering grants no source writes or publication authority. Discovery freezes
scope, references, exclusions and criteria during bounded clarification. Lazy
retains one logical Auditor; independent uses a fresh Auditor per pass. New or
revised findings block discovery pending a separate verification gate. A clean
pass has no candidates or substantive report corrections; rejected candidates
cannot make their historical pass clean. Interrupted and incomplete work consumes
the same finite 20-pass run-wide budget, which survives reconstruction and
exhaustion. Every new or materially revised finding batch requires a distinct
recheck before more discovery. Lazy continues its discovering Auditor;
independent uses a fresh finding Reviewer after every substantive correction.
Confirmations, corrections, rejections, merges and explicit hypotheses retain
exact versioned decisions, including rejected claims; review additions must
also be verified. A separate finite run-wide 20-recheck budget survives all
batches and reconstruction. Batch acceptance cannot clean discovery or complete
an audit. Combined audit cycles and public publication remain unavailable. The
[audit specification](../../pipelines/audit/docs/SPEC.md) owns exact shapes,
criteria, state and ordering; the three supported workflows and their gates are unchanged.

## Review modes

`independent` is the default and recommended mode. A primary role produces the
work and a separately configured Reviewer supplies genuine semantic review;
an Arbiter is available only for the pipeline's bounded disagreements. This
costs more provider context and tokens because the review context is genuinely
separate.

`lazy` is an explicit lower-consumption choice. It resolves and invokes only
the Planner or Worker and provides no independent review. The primary role
alternates between a check-and-fix pass and a distinct read-only clean
confirmation. Authoring returns draft changes as structured output; execution
and polishing may change safe workspace content during check/fix. Findings go
directly back to fixing; lazy mode never invokes a Reviewer or Arbiter. The runner never selects lazy mode automatically.

`combined` is available in every pipeline. In authoring it converges the
durable draft with Planner check/fix and a separate clean confirmation, then
requires the full independent Reviewer gate. Reviewer revisions restart primary
convergence; self findings return to fixing. Self-review and structural
exhaustion pause without arbitration. Only independent finding resolution may
invoke the fresh Arbiter. Every authoring agent turn remains repository-read-only;
the runner writes the deterministically validated artifact. Pipeline descriptors
own mode availability.

Combined execution runs Worker check/fix and a separate read-only clean
confirmation before the complete independent candidate Reviewer gate. Both
candidate approvals bind the same content fingerprint. Finalization may format
that content; a distinct Reviewer terminal confirmation approves its resulting
fingerprint and validation evidence before its selected commit or accepted-result checkpoint.
Content repairs restart primary convergence. Self-findings go directly to fixing;
independent findings retain disputes, withdrawals, exact recorded overrides, and
fresh on-demand arbitration. Unresolved bootstrap disagreements and primary
exhaustion pause without arbitration. Corrections remain bounded and interrupted
work is charged once; resume preserves the saved mode and consumed commits remain
verification-only.

Combined polishing uses independent bootstrap, Worker check/fix and read-only
clean confirmation, independent candidate review, finalization, and a distinct
Reviewer terminal confirmation. Content repairs restart primary convergence;
unchanged resolutions reuse only fingerprint-current finalization. Self-findings
return directly to fixing; only independent finding resolution may invoke Arbiter.
Unresolved bootstrap and exhausted primary budgets pause. Handoff remains
runner-owned staging without a commit, and resume preserves accepted evidence
and correction accounting.

All supported modes retain the same clarification, persistence, Git, redaction, and
effect-safety guarantees.

## Clarification and product decisions

Every pipeline begins with a read-only clarification phase whose fixed protocol
limit is three agent question rounds. Empty artifacts and authorized editor
closes without changes consume no round. Exhaustion pauses instead of extending
the dialogue indefinitely; this ambiguity bound is not a configurable workflow
budget. Agents ask
only questions whose answers can materially change behavior, scope, or the
planned implementation, and they must use repository evidence for questions it
can answer. An empty clarification file and an authorized editor close without
changes are valid inputs.

The runner freezes the clarification artifact before work begins. Ordinary
questions are prohibited after that point. `PRODUCT_DECISION_REQUIRED` is the
only later question path and is reserved for progress that is impossible
without a genuinely unresolved choice between materially different product
requirements. Technical preferences, naming, implementation difficulty, and
ordinary findings do not qualify.

When a decision would invalidate a validated plan or completed commit, the
current execution run stops. The operator carries the recorded decision into a
revised plan and a new run instead of letting the runner invent requirements or
rewrite history.

All pipelines use the same injected runner availability policy after their own
repository reconciliation. Explicit transient failures resume the exact logical
role and checkpoint with durable capped exponential delays; no pipeline parses
provider-native errors. Correction budgets remain distinct from availability
attempts, and commit/handoff effects retain their verification-only safety gates.
