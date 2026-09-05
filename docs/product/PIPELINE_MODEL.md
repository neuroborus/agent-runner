# Pipeline Model

Agent Runner hosts three explicit local workflows. They share runtime safety and
durability services, but each pipeline owns its roles, prompts, settings, state,
and completion rules. The product is not a general workflow framework, and one
pipeline never calls another.

## Plan authoring

Plan authoring turns a task into a reviewed, commit-by-commit `plan.md`. It may
clarify material requirements first, but it keeps the target project read-only
apart from the resolved clarification and plan artifact paths. The resulting
headings contain the exact subject-only Conventional Commit messages that plan
execution will later consume unchanged.

Plan authoring proposes work; it does not implement the task, create a commit,
or guarantee that a later worktree will remain compatible with the plan.

## Plan execution

Plan execution accepts a deterministically validated plan and implements one
step at a time. Each accepted step becomes exactly one verified local commit
with the subject from its plan heading. Findings are resolved within that step,
not by adding separate review-fix commits. A completed earlier commit is durable
history and is never rewritten automatically when later work encounters a
problem.

Each step converges semantically before its terminal gate: independent mode
uses candidate Reviewer passes, while lazy mode alternates Worker check/fix and
read-only candidate confirmation. The stable candidate then passes full
finalization and one distinct read-only terminal confirmation immediately
before the constrained commit.

The plan defines the authorized commit boundaries. Clarification may explain a
requirement, but it cannot silently expand, reorder, or reinterpret those
boundaries. A conflicting clarification or product decision requires a revised
plan and a new execution run.

## Polishing

Polishing starts from an existing non-empty local change set rather than a
plan. It makes that whole change set correct, idiomatic, minimal, finalized, and
reviewed. Independent Reviewer convergence, or lazy Worker convergence, occurs
before finalization; a distinct read-only terminal confirmation then accepts
the finalized content and validation evidence. The runner stages that complete
accepted result and leaves it uncommitted. Polishing never requests local-commit
access and never changes `HEAD`.

Ignored files are outside the polishing change set. Task inputs inside the
repository must not overlap writable changes.

## Independent and lazy modes

`independent` is the default and recommended mode. A primary role produces the
work and a separately configured Reviewer supplies genuine semantic review;
an Arbiter is available only for the pipeline's bounded disagreements. This
costs more provider context and tokens because the review context is genuinely
separate.

`lazy` is an explicit lower-consumption choice. It resolves and invokes only
the Planner or Worker and provides no independent review. The primary role
alternates between a writable check-and-fix pass and a distinct read-only clean
confirmation. Findings go directly back to fixing; lazy mode never invokes a
Reviewer or Arbiter. The runner never selects lazy mode automatically.

Both modes retain the same clarification, persistence, Git, redaction, and
effect-safety guarantees.

## Clarification and product decisions

Every pipeline begins with a bounded read-only clarification phase. Agents ask
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
