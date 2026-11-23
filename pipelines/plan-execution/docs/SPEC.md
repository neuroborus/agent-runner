# Plan Execution Pipeline — Implementation Specification

Read the affected sections before changing this contract. Use the [topic map](README.md)
for related owners and required reading routes.

## 1. Goal

Define the `plan-execution` pipeline that executes a reviewed commit or custom
plan sequentially through the shared Agent Runner CLI/runtime. Commit plans
produce verified local commits; custom plans settle criterion-bound results.

The runner must:

- support both Codex CLI and Claude Code in V1;
- allow Worker, Reviewer, and Arbiter to use different backends;
- complete a bounded clarification phase before implementation begins;
- let the Worker operate unattended during normal execution;
- converge each implementation semantically before a dedicated, optionally
  skill-guided finalization gate;
- independently review each candidate by default, or run bounded primary-only
  candidate convergence when lazy mode is explicitly selected;
- allow the Worker to fix findings and, in independent and combined modes, dispute Reviewer
  findings;
- advance only when the exact current workspace has passed candidate
  convergence, finalization, and one distinct mode-specific read-only terminal
  confirmation with no unresolved findings;
- pause for the user when a material product decision is genuinely blocking, automated resolution reaches its limits, or execution cannot proceed safely;
- persist enough state to resume after interruption.

Core principle:

> Clarify before work. Stay autonomous afterward except for a genuinely blocking product decision or another explicit escalation.

This is a local orchestration CLI, not a general agent framework.

---

The descriptor explicitly selects a Git workspace for commit plans or a directory
workspace for custom plans, with an exclusive canonical exclusion lease.
The root resolves that selection before Git-specific inspection; a missing Git
repository never selects a directory workflow. Role access and repository-local
ignored artifacts retain their existing guarantees.

### Historical validation noncompliance

Read [Historical validation noncompliance](validation-history.md#historical-validation-noncompliance).

## 2. Technology Baseline

Implement the runner as plain modern JavaScript on Node.js with native ES modules.

Verified baseline as of **2026-08-16**:

- Node.js: **24.x LTS**
- latest npm release: **12.0.2**
- npm: use the version bundled with the selected Node.js 24.x release
- Codex CLI stable release used as the V1 compatibility baseline: **0.147.0**
- Claude Code current release used as the V1 compatibility baseline: **2.1.233**
- Git: required for commit execution; ordinary-directory custom execution needs no Git

Use Node.js 24.x LTS. The supported range is **`>=24 <25`**. Do not target the Current Node.js line.

`package.json` should be minimal:

```json
{
  "type": "module",
  "engines": {
    "node": ">=24 <25"
  }
}
```

Do not pin npm in `package.json`: the runner should not depend on a specific npm version.

### Dependency policy

V1 should have **no external runtime npm dependencies unless implementation
proves one is necessary**. Internal npm-workspace dependencies are explicit
repository boundaries, not third-party runtime dependencies.

The local MCP boundary is that demonstrated exception: use the exact locked
official Node MCP server SDK and its Zod peer for protocol schemas. Do not use
them to replace deterministic pipeline or commit-plan validation.

Prefer the Node.js standard library:

- `node:child_process`
- `node:fs/promises`
- `node:path`
- `node:os`
- `node:crypto`
- `node:util`
- `node:readline/promises`
- `node:test`
- `node:assert`

Use `util.parseArgs()` for CLI parsing.

Do not add:

- TypeScript;
- a transpilation/build step;
- a CLI framework;
- a state-machine library;
- a general application validation framework;
- a logging framework;
- a database;
- a network service or daemon;
- a DI container.

Codex CLI and Claude Code are external prerequisites, not npm dependencies; the
official MCP packages are the narrow protocol-boundary exception above.

Do not hard-pin their versions in workflow logic. Detect and log installed versions during preflight. The adapters should target the current stable capabilities described below and fail clearly if the installed CLI cannot provide a required capability.

---

## 3. Inputs

Read [3. Inputs](admission.md#inputs).

## 4. Plan Format

Read [4. Plan Format](admission.md#plan-format).

### Plan-kind step policies

Read [Plan-kind step policies](admission.md#plan-kind-step-policies).

### Custom execution and accepted results

Read [Custom execution and accepted results](custom-execution.md#custom-execution-and-accepted-results).

## 5. CLI

Read [5. CLI](configuration.md#cli).

### Combined commit review

Read [Combined commit review](configuration.md#combined-commit-review).

## 6. Persistent State

Read [6. Persistent State](persistence.md#persistent-state).

### `state.json`

Read [`state.json`](persistence.md#statejson).

### Event journal

Read [Event journal](persistence.md#event-journal).

### `progress.md`

Read [`progress.md`](persistence.md#progressmd).

## 7. Agent Adapter Contract

Read [7. Agent Adapter Contract](adapters.md#agent-adapter-contract).

## 8. Backend Behavior

Read [8. Backend Behavior](backends.md).

### Codex

Read [Codex](backends.md#codex).

### Claude Code

Read [Claude Code](backends.md#claude-code).

### Backend-neutral finalization guidance

Read [Backend-neutral finalization guidance](backends.md#backend-neutral-finalization-guidance).

## 9. Repository Safety Guards

Read the [repository safety contract](repository-safety.md).

### Initial implementation must change step content

Read [Initial implementation must change step content](implementation.md#initial-implementation-must-change-step-content).

### Context cannot change plan position

Read [Context cannot change plan position](repository-safety.md#context-cannot-change-plan-position).

### Stale plans and externally committed steps

Read [Stale plans and externally committed steps](repository-safety.md#stale-plans-and-externally-committed-steps).

### Git history/ref and configuration guard

Read [Git history/ref and configuration guard](repository-safety.md#git-historyref-and-configuration-guard).

### Read-only mutation guard

Read [Read-only mutation guard](repository-safety.md#read-only-mutation-guard).

## 10. Content Fingerprint

Read [10. Content Fingerprint](repository-safety.md#content-fingerprint).

## 11. Workflow

Read [11. Workflow](workflow.md#workflow).

## 12. Clarification And Bootstrap

Read [12. Clarification And Bootstrap](bootstrap.md#12-clarification-and-bootstrap).

### Clarification

Read [Clarification](bootstrap.md#clarification).

### Bootstrap

Read [Bootstrap](bootstrap.md#bootstrap).

### Durable bounded bootstrap

Read [Durable bounded bootstrap](bootstrap.md#durable-bounded-bootstrap).

### Reconciliation

Read [Reconciliation](bootstrap.md#reconciliation).

## 13. Per-Commit Workflow

In independent mode, start one fresh Worker checkpoint and one fresh Reviewer
checkpoint for every planned commit. Reuse those role sessions for
implementation, finalization, finding resolution, complete re-review, and
dispute reconsideration within that commit. Never carry either work checkpoint
into the next commit, and keep every Arbiter turn fresh. In lazy mode, the one
logical Worker uses a durable per-commit convergence checkpoint while retaining
the single source-fork lineage across commits; a reconstructed native session
does not become a new logical role.

Reconstruct each checkpoint from the validated inputs, resolved bootstrap
summary, current plan step, active blockers, and bounded prior decisions. A
product-decision edit invalidates the affected work checkpoint before execution
resumes. Native continuation remains optional.

For each plan step:

Keep role prompts short. Their mandatory English cores are:

```text
Worker: Implement the changes described in the following planned commit. Keep the implementation idiomatic and minimal, and follow the project's conventions.
Reviewer: Review the changes and verify that they are correct, idiomatic, minimal, and consistent with the project's conventions.
Lazy check/fix: Review the changes and verify that they are correct, idiomatic, minimal, and consistent with the project's conventions. If you find any problems, fix them idiomatically and minimally, following the project's conventions.
Lazy clean confirmation: Review the changes using the same criteria without editing. Return CLEAN only when there are no problems; otherwise return concrete findings.
Finding resolution: For each finding below, fix it idiomatically and minimally, following the project's conventions.
Every role: Produce this turn's result yourself as the authorized role. Do not delegate, spawn subagents, or use multi-agent collaboration.
```

The complete and recovery prompt for each Worker and Reviewer checkpoint treats
project `.agents` changes as authorized only when both the user's task and the
current planned commit explicitly require them; otherwise the role neither
makes nor approves those changes. Compatible continuation turns inherit this
responsibility from their native session without repeating it.
A violation follows the ordinary finding-and-fix path and never reopens user
questions.

The pipeline may append turn-specific context, access restrictions, and output
requirements. The Reviewer returns structured findings rather than a free-form
handoff prompt; the pipeline attaches the canonical finding-resolution
instruction before sending those findings to the Worker.

After an authorized product-decision edit, the compatibility check uses this
minimal contract:

```text
Review the updated clarifications against the task, validated plan, completed commits, and repository.
Do not ask questions or modify the repository.
Using the provided schema, return READY when compatible; otherwise return PLAN_REVISION_REQUIRED with concise evidence.
```

After `CLARIFY` closes, every role prompt prohibits questions and permits only
the narrowly defined `PRODUCT_DECISION_REQUIRED` exception. Technical
uncertainty, naming preferences, implementation difficulty, and ordinary review
findings do not qualify.

### 13.1 Worker implementation

Read [13.1 Worker implementation](implementation.md#worker-implementation).

### Commit-size assessment foundation

Read [Commit-size assessment foundation](implementation.md#commit-size-assessment-foundation).

### Durable preservation foundation

Read [Durable preservation foundation](replacement-execution.md#durable-preservation-foundation).

### Reviewed effective revision foundation

Read [Reviewed effective revision foundation](effective-revisions.md#reviewed-effective-revision-foundation).

### Revision-bound validation foundation

Read [Revision-bound validation foundation](effective-revisions.md#revision-bound-validation-foundation).

### Preserved replacement execution

Read [Preserved replacement execution](replacement-execution.md#preserved-replacement-execution).

### Derived refinement progress

Read [Derived refinement progress](refinement-progress.md#derived-refinement-progress).

### 13.2 Candidate convergence and finalization

Read [13.2 Candidate convergence and finalization](finalization.md#candidate-convergence-and-phase-ownership).

### Transient validation storage ownership

Read [Transient validation storage ownership](validation-storage.md#transient-validation-storage-ownership).

### 13.3 Mode-specific candidate review and terminal confirmation

Read [13.3 Mode-specific candidate review and terminal confirmation](review.md).

#### Independent review

Read [Independent review](review.md#independent-review).

#### Lazy check/fix and clean confirmation

Read [Lazy check/fix and clean confirmation](review.md#lazy-checkfix-and-clean-confirmation).

### Legacy terminal-confirmation recovery

Read [Legacy terminal-confirmation recovery](recovery.md#legacy-terminal-confirmation-recovery).

### 13.4 Resolve findings

Read [13.4 Resolve findings](findings.md#resolve-findings).

#### FIX

Read [FIX](findings.md#fix).

#### DISPUTE

Read [DISPUTE](findings.md#dispute).

### 13.5 Arbiter

Read [13.5 Arbiter](findings.md#arbiter).

### 13.6 Commit gate

Read [13.6 Commit gate](commit.md#commit-gate).

### 13.7 Commit

Read [13.7 Commit](commit.md#commit).

## 14. Retry Limits and No-Progress Detection

Read [14. Retry Limits and No-Progress Detection](escalation.md#retry-limits-and-no-progress-detection).

## 15. User Escalation

Read [15. User Escalation](escalation.md#user-escalation).

## Operator Pause And Cancellation

Read [Operator Pause And Cancellation](operator-stops.md#operator-pause-and-cancellation).

### Writable result recovery

Read [Writable result recovery](recovery.md#writable-result-recovery).

## 16. Resume

Read [16. Resume](recovery.md#resume).

### Action-free ownership recovery

Read [Action-free ownership recovery](recovery.md#action-free-ownership-recovery).

## 17. Terminal UX

Keep normal output concise and state-oriented:

```text
[3/7] Add market cache

Implementation    done
Finalization      pass
Review            1 finding

R7                 dispute
Reviewer           withdraw

Finalization      pass
Review            pass
Commit             2ac1d38

Proceeding to step 4.
```

Do not stream full model transcripts by default.

A debug mode may expose backend stdout/stderr.

`status` should show:

- resolved mode;
- current step/state;
- clarification status, round count, and artifact path;
- open findings;
- fix/dispute counters;
- expected/current HEAD;
- last finalized/reviewed fingerprint;
- state directory;
- bounded pause reason, explanation, evidence, retry checkpoint, and applicable
  next actions when present.

---

## 18. Testing

Read [18. Testing](testing.md#18-testing).

## 19. Monorepo Placement

Keep execution-specific behavior inside its pipeline workspace:

```text
pipelines/plan-execution/
├── package.json
├── docs/
│   └── SPEC.md
├── src/
│   ├── index.js
│   ├── prompts.js
│   ├── schemas.js
│   ├── workflow-contract.js
│   └── workflow.js
└── test/
```

Shared plan parsing and validation belong in `packages/commit-plan/`. CLI,
clarification artifacts/editor handling, state, Git, and backend-adapter
services remain in the root runtime because both pipelines consume them there.

Split modules only when they gain a distinct responsibility or become
meaningfully large. Avoid speculative abstractions.

---

## 20. Non-Goals for V1

Do not build:

- TypeScript;
- a build step;
- a web UI;
- a network service or daemon;
- a database;
- cloud execution;
- multi-user support;
- GitHub/PR automation;
- distributed workers;
- a generic workflow engine;
- a plugin framework;
- vector memory;
- parallel reviewers;
- semantic/fuzzy finding matching;
- an open-ended agent/user dialogue after clarification closes;
- automatic pushing;
- any write operation against `origin` or another Git remote;
- PR creation/update or other remote-repository mutation.

---

## 21. Mandatory Invariants

1. In independent mode, Worker and Reviewer independently study
   project/task/plan before implementation; lazy mode uses Worker alone under
   the same deterministic bootstrap rules.
2. Clarification, plan-compatibility, bootstrap, independent review, lazy clean-
   confirmation, and arbitration turns are read-only.
3. A dedicated finalization turn always defines the project validation gate.
4. Finalization is backend-neutral and must work through either Worker adapter,
   with a frozen explicit skill, frozen automatic selection, or no skill
   guidance.
5. Skill-less finalization derives checks from repository evidence; the runner
   never substitutes generic hard-coded test commands.
6. The Worker is autonomous during normal implementation.
7. Only the Worker creates planned commits, one at a time, in a dedicated turn
   authorized by the runner after the commit gate passes.
8. Git history/refs must not change outside that authorized `COMMIT` turn.
9. Reviewer, Arbiter, and lazy clean-confirmation turns never modify repository state.
10. In independent mode, Worker may dispute Reviewer findings with evidence.
11. Every independent Reviewer finding must be fixed, withdrawn, arbitrated, or
    explicitly overridden by the user; every lazy confirmation finding returns
    directly to fixing.
12. Any content change invalidates finalization/review for the previous content fingerprint.
13. Staging alone does not invalidate the content fingerprint.
14. Only the runner may advance to the next planned commit.
15. Retry exhaustion always pauses; it never accepts unresolved work.
16. Runner correctness does not depend on native agent-session resume.
17. Codex and Claude Code are both first-class V1 backends.
18. Independent and combined Worker, Reviewer, and Arbiter backend choices are
    independent; lazy mode resolves only Worker.
19. Workflow logic is backend-agnostic.
20. State survives process termination and never pollutes the target repository.
21. The runner and all agents are strictly local-only for writes: they must never
    push, change remote configuration, or otherwise mutate `origin` or another
    remote repository.
22. Planned commit messages never contain `Co-authored-by` trailers, and the
    Worker does not change the repository's configured Git identity.
23. `CLARIFY` completes before bootstrap or implementation and keeps its agent turn read-only.
24. Clarification questions are material, structured, bounded, and persisted in the declared artifact.
25. The clarification artifact is frozen and hashed before normal work begins.
26. Questions after clarification closes are prohibited except for a blocking `PRODUCT_DECISION_REQUIRED` outcome.
27. `CLARIFY` never closes while clarification input conflicts with the validated plan.
28. A product decision invalidates dependent work, and a plan-changing answer requires a revised validated plan.
29. The runner never creates a repository-local clarification artifact unless its resolved path is ignored.
30. Environment constraints affecting nondelegated work or runner-trusted
    execution in `FINALIZE` pause as `environment_blocked`; they never become
    code failures or justify weakening the execution boundary. Selected-command
    agent-sandbox limitations alone cannot block pre-finalization repairs.
31. Bootstrap role inventories use unique check IDs, unique normalized exact
    commands, and unique existing canonical repository-relative validation
    files plus the exact selected external guidance label when applicable; the
    runner derives the final stable union and assigns contiguous IDs, while
    invalid output receives at most one read-only diagnostic-batch
    correction per producing role, phase, and contract.
32. Provider usage-exhaustion recovery persists no denied input or native
    provider text, never retries the rejected turn, and reconstructs the request
    from durable runner state without making a native session authoritative;
    other Claude recovery retries only finite allowlisted failures.
33. Root and safe project configuration define exact trusted command vectors
    without additional environment, credential, or host-authority fields; selected
    commands execute outside agent turns as exact persisted vectors, and their
    bounded evidence cannot pass unless every fingerprint and repository guard
    remains unchanged. The isolated executor denies remote writes and ambient
    credentials and retires the complete process tree before reconciliation.
34. Every role produces its own result without delegation; adapter collaboration
    auditing remains fail closed and a violation is never an environment pause
    or transparent retry.
35. Plan-execution implementation and finding-resolution turns do not perform
    project finalization, established checks, or generic commit preparation;
    bootstrap, migration, and finalization inventories are staging-independent,
    and the constrained `COMMIT` executor alone stages, applies fixed staged
    hygiene, and creates the exact validated subject-only commit.
36. An invalid Worker finalization result receives at most two read-only
    corrections for the current step and content-fingerprint scope, with the
    second available only for a wholly new field-diagnostic batch. Repeated,
    mixed, and exhausted invalid results fail closed; only bounded diagnostics
    are durable or public, and corrected evidence must still pass every existing
    trusted-validation, Git, and fingerprint gate.
37. User finding overrides are unique durable audit decisions and suppress only
    the exact finding on the applicable candidate-reviewed or terminal-confirmed content; they never record Reviewer
    acceptance or weaken another finding or validation gate.
38. Every finalization validation-infrastructure candidate is an ordered set of
    existing canonical repository-relative regular files, plus the exact selected
    external guidance label when applicable, before it can be fingerprinted,
    trusted, or reviewed.
39. Detached MCP compatibility binds the root run-envelope tuple and every
    loaded pipeline ID/state version, is frozen at server startup, and fails
    before lease acquisition, recovery, or migration without changing durable
    run or idempotency state.
40. Invalid candidate-Reviewer and terminal-confirmation contracts each consume
    only one automatic read-only correction for their exact scope. A still-
    invalid result pauses at `REVIEW` or `CONFIRM` for explicit retry, only
    bounded field-and-constraint diagnostics are durable or public, and no
    correction path weakens candidate review, finalization, findings,
    fingerprints, Git safety, or commit authorization.
41. `independent` is the persisted default and recommended mode; `lazy` is
    explicit, primary-only, never automatic, and never invokes Reviewer or
    Arbiter.
42. Lazy advancement requires writable check/fix and mutation-free candidate
    `CLEAN` convergence before full finalization, then one separate terminal
    `CLEAN` confirmation over unchanged content and validation fingerprints.
    Every change returns through candidate convergence and full finalization,
    and bounded-loop exhaustion pauses.
43. Each exact lazy checkpoint scope receives one automatic fresh-session
    structured-output correction. Repeated invalid output pauses for explicit
    null retry with only redacted field-and-constraint diagnostics; mutation,
    interruption, resume, budget, fingerprint, finalization, confirmation,
    review, Git, and commit gates remain unchanged.
44. A deliberately supplied source forks independently by checkpoint in
    independent and combined modes and exactly once into the logical Worker in lazy mode;
    native-session reconstruction never changes that lineage.

---

## 22. Acceptance Criteria

V1 is complete when:

- it runs as a plain Node.js 24 LTS ESM CLI with no unnecessary runtime dependencies;
- `run`, `resume`, and `status` work;
- Codex and Claude adapters both work;
- `independent` remains the default and recommended reviewed path, while
  explicit `lazy` completes with one logical Worker through bounded check/fix
  and clean-confirm checkpoints;
- Codex-only, Claude-only, and mixed Worker/Reviewer configurations work;
- independent-mode Worker and Reviewer bootstrap independently, while lazy
  mode bootstraps with Worker alone;
- a bounded clarification phase with read-only agent turns completes before bootstrap;
- `--clarify` and agent-generated questions use the declared Markdown artifact and configured text editor;
- execution does not start when clarification input conflicts with the validated plan;
- clarification input changes are detected and post-start questions require a blocking product decision;
- preflight refuses to create the configured artifact path when the target repository does not ignore it;
- read-only agent-turn guarantees are actively checked;
- task/plan input changes are detected;
- each plan step is implemented separately;
- project finalization is the validation gate;
- finalization follows all substantive project guidance while commit preparation
  remains owned by the constrained `COMMIT` executor;
- candidate convergence has fingerprint-bound evidence, while finalization and
  terminal confirmation bind the same staging-independent post-format content
  fingerprint;
- in independent mode, Worker can fix or dispute Reviewer findings and
  unresolved disputes can be arbitrated;
- in lazy mode, confirmation findings return directly to fixing without dispute
  or arbitration;
- retry/no-progress limits pause for the user;
- only a zero-finding finalized and terminal-confirmed workspace can be committed;
- only the Worker creates one local commit per plan step, after explicit runner
  authorization and successful gate verification;
- planned commit messages contain no `Co-authored-by` trailers;
- unexpected agent Git history/ref changes are detected;
- no workflow path can push commits, change remote configuration, or mutate a
  remote repository;
- detached MCP launches reject root or loaded-pipeline version skew before
  recovery and remain exactly retryable after a fresh control-plane start;
- ownerless applicable stops have action-free CLI and exact-revision MCP
  recovery without the original stop key, and detached stop reconciliation
  cannot report success on transient run-lease ownership;
- interruption and resume are safe;
- tests cover workflow behavior using fake agents and temporary Git repositories;
- the implementation remains a small local CLI rather than growing into a framework.

Implementation priority:

1. workflow correctness;
2. Git safety;
3. persistence/resume correctness;
4. backend isolation;
5. review/fix/dispute behavior;
6. minimal code/dependencies;
7. terminal UX.

## Adapter environment recovery

Read [Adapter environment recovery](recovery.md#adapter-environment-recovery).

## Output-exhausted checkpoints

Read [Output-exhausted checkpoints](recovery.md#output-exhausted-checkpoints).

## Provider inactivity recovery

Read [Provider inactivity recovery](recovery.md#provider-inactivity-recovery).
