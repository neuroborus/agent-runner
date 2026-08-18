# Plan Execution Pipeline — Implementation Specification

## 1. Goal

Define the `plan-execution` pipeline that executes a predefined coding plan
autonomously, one planned commit at a time, using local coding agents through
the shared Agent Runner CLI/runtime.

The runner must:

- support both Codex CLI and Claude Code in V1;
- allow Worker, Reviewer, and Arbiter to use different backends;
- complete a bounded clarification phase before implementation begins;
- let the Worker operate unattended during normal execution;
- validate each implementation through the target project's own `finalization` skill;
- independently review each planned commit;
- allow the Worker to fix or dispute review findings;
- advance only when the exact current workspace has passed finalization and review with no unresolved findings;
- pause for the user when a material product decision is genuinely blocking, automated resolution reaches its limits, or execution cannot proceed safely;
- persist enough state to resume after interruption.

Core principle:

> Clarify before work. Stay autonomous afterward except for a genuinely blocking product decision or another explicit escalation.

This is a local orchestration CLI, not a general agent framework.

---

## 2. Technology Baseline

Implement the runner as plain modern JavaScript on Node.js with native ES modules.

Verified baseline as of **2026-08-16**:

- Node.js: **24.x LTS**
- latest npm release: **12.0.2**
- npm: use the version bundled with the selected Node.js 24.x release
- Codex CLI stable release used as the V1 compatibility baseline: **0.147.0**
- Claude Code current release used as the V1 compatibility baseline: **2.1.233**
- Git: required external executable

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

The runner receives:

1. a local Git repository;
2. a task directory.

```bash
agent-run run plan-execution \
  --project /path/to/repository \
  --task /path/to/task
```

Task directory:

```text
task/
├── task.md
├── clarifications.md  # optional plan-authoring transcript
├── plan.md
└── context.md      # optional
```

- `task.md`: task/problem statement.
- `clarifications.md`: optional product decisions captured during plan authoring.
- `plan.md`: ordered commit-by-commit implementation plan.
- `context.md`: optional extra context supplied by the user.

The execution run keeps its own clarification transcript at:

```text
<project>/LOCAL_ARTIFACTS/agent-runner/<run-id>/clarifications.md
```

This local artifact uses the common Markdown transcript format and contains
execution-specific questions and answers. Before creating it, preflight must
use `git check-ignore` to verify that the target
repository ignores the resolved `LOCAL_ARTIFACTS` path. If it does not, pause
with `local_artifacts_not_ignored`; never edit `.gitignore` or
`.git/info/exclude` automatically. The artifact is not runner state and must
never enter a planned commit. The task directory may be located inside or
outside the target repository. Runner state must therefore **never** be stored
inside the task directory or target repository.

---

## 4. Plan Format

The authoritative shared contract lives in
[`@agent-runner/commit-plan`](../../../packages/commit-plan/README.md). Before
bootstrap, this pipeline must parse and validate the plan with that deterministic
contract rather than an LLM.

The Worker must use the validated subject exactly as returned by the parser. The
runner must never ask an agent to generate or rewrite it, and multiple planned
commits must never be merged into one implementation step.

---

## 5. CLI

Required commands:

```bash
agent-run run plan-execution --project <repo> --task <task-dir>
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

Use role-specific model flags when an explicit backend model is required:

```bash
agent-run run plan-execution \
  --project /path/to/repo \
  --task /path/to/task \
  --worker codex \
  --worker-model <codex-model-id> \
  --reviewer claude \
  --reviewer-model <claude-model-id>
```

A new run may seed Worker and Reviewer from one existing session only when both
use its backend:

```bash
agent-run run plan-execution \
  --project /path/to/repo \
  --task /path/to/task \
  --worker codex \
  --reviewer codex \
  --fork-from codex:<session-id>
```

The runner splits only the backend prefix, keeps the session ID opaque, probes
native fork support, and persists the resolved source. Worker and Reviewer fork
it independently; the Arbiter remains independent and `resume` never requires
the flag again.

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

The pipeline descriptor declares the `worker`, `reviewer`, and `arbiter` roles.
Role objects under `pipelines.plan-execution.roles` in the runner's
`.agent-runner.json` may provide an optional `backend` and backend-specific
`model`. Backend precedence is CLI role override, runner pipeline-role value,
runner-wide default, then preflight failure. Model precedence is CLI role
override, runner pipeline-role value, then the selected backend's native
default. Do not hard-code model names into workflow logic.

The descriptor also owns the positive-integer settings and built-in defaults
listed under [Retry Limits and No-Progress Detection](#14-retry-limits-and-no-progress-detection).
Runner overrides live directly under `pipelines.plan-execution`. The root
loader strictly validates the versioned envelope and delegates these values to
the descriptor rather than duplicating pipeline policy.

Codex and Claude do **not** both need to be installed for every run. Preflight validates the Worker and Reviewer selected for the run. The Arbiter backend may be validated lazily when arbitration is first needed.

---

## 6. Persistent State

Runner state must live outside both the task directory and target repository.

Use an OS/user state directory, for example:

```text
$XDG_STATE_HOME/agent-runner/
```

with fallback:

```text
~/.local/state/agent-runner/
```

Assign every run an opaque run ID. Persist the canonical task-directory path in
state, but do not use a mutable filesystem path as the public run identity.

`agent-run status --run <run-id>` must print the resolved state directory.

State layout:

```text
<state-root>/runs/<run-id>/
├── .lease            # present only while a mutating owner is active
├── state.json
├── events.jsonl
├── progress.md
└── context/
    ├── worker.md
    ├── reviewer.md
    └── resolved.md
```

A mutating `run` or `resume` must acquire the atomic per-run execution lease
before recovery or workflow advancement. A competing owner is rejected. Stale
recovery requires both the configured age threshold and proof that the recorded
same-host process is no longer alive; age alone or a foreign host is
insufficient. `status` and public activity reads are lock-free and never acquire
the execution lease.

### `state.json`

Machine-readable current state.

Persist at least:

- run ID;
- pipeline ID and pipeline state-schema version;
- canonical project path;
- canonical task path;
- hashes of `task.md`, `plan.md`, and optional task `clarifications.md` and `context.md`;
- execution clarification path, hash, status, and question-round count;
- suspended workflow state, pending editor action, and pre-editor clarification
  hash while an editor action is pending;
- selected backends;
- detected backend versions;
- current workflow state;
- current plan step;
- expected Git HEAD;
- expected branch/ref context and local-ref fingerprint;
- expected effective remote-configuration fingerprint;
- expected effective Git-identity fingerprint;
- prepared or consumed one-shot commit authorization while `COMMIT` is pending;
- completed commit SHAs;
- current findings;
- fix/dispute counters;
- latest finalized content fingerprint;
- latest reviewed content fingerprint;
- escalation reason when paused.

The common envelope also persists an optional opaque source-session reference,
every direct Worker, Reviewer, or Arbiter child session ID, monotonic revision
and timestamps, and an opaque pipeline-owned state object. Store
correction-round snapshots and arbitration episodes there without asking the
root runtime to interpret them. Native backend session resume is optional; the
persisted task, plan, decisions, summaries, and lineage must be sufficient to
continue with a new native session.

Validate the complete next pipeline state before handing a transition to the
root state service. Write state atomically using temporary-file + rename.

### `events.jsonl`

Append-only machine-readable event history.

Never rewrite previous events.

A partially written final line after a crash may be ignored during recovery; earlier valid lines remain authoritative history.

Every complete event contains the entire next state and its monotonic revision.
For each transition, append and sync that write-ahead event before atomically
replacing `state.json`. Recovery removes only an incomplete final fragment,
rejects malformed durable records, and advances a lagging state file from the
last valid event. Revisions are the stable cursor for resume and activity
consumers.

An event may include a bounded public activity record with `actor`, `phase`,
`kind`, and a concise one-line `message`. The pipeline derives normalized role
summaries, findings, and decisions only from validated structured results. The
state service validates generic shape and size limits without interpreting
roles or outcomes, and cursor readers expose only this safe projection rather
than private pipeline state.

### `progress.md`

Human-readable summary of:

- completed steps;
- important implementation changes;
- clarification questions, answers, and product-decision pauses by reference to the durable artifact;
- finalization results;
- review findings;
- fixes;
- disputes and evidence;
- arbitration outcomes;
- user overrides;
- significant decisions;
- created commit SHAs;
- pause reasons.

Do not store raw model transcripts or agent chain-of-thought.

Regenerate `progress.md` after state recovery when it is missing or stale. Write
pipeline-declared run artifacts such as `context/*.md` atomically beneath the
run directory, rejecting absolute paths, traversal, reserved state filenames,
and symlink escapes. Reject symbolic or hard links for managed state and lease
files.

---

## 7. Agent Adapter Contract

Keep the backend abstraction small and functional.

Conceptually:

```js
const backend = {
  id: "codex",

  async probe() {
    return {
      version: "...",
      structuredOutput: true,
      readOnly: true,
      autonomousWrite: true,
      workspaceWrite: true,
      localCommit: true,
      remoteWriteBlocked: true,
      nativeSessionContinuation: true,
      nativeSessionFork: true
    };
  },

  async run(request) {
    return {
      output: "...",
      structured: {},
      sessionId: "optional"
    };
  }
};
```

A request should contain only runner-level concepts such as:

```js
{
  cwd,
  access: "read-only" | "workspace-write" | "local-commit",
  prompt,
  schema,
  session: { mode: "fork" | "continue", id }, // optional
  authorizationId, // local-commit only
  commit: { expectedHead, message } // local-commit only
}
```

Backend-specific CLI flags belong only inside the adapter.

For non-commit turns, an adapter error may set `recoverable: true` only when
reconstructing and retrying the durable request is safe. Safety, protocol, and
isolation failures are not recoverable; an ambiguous `local-commit` outcome is
never retried and must instead return to Git-state verification.

`local-commit` is a one-turn capability used only after the runner's commit gate
and requires the `commit` constraint. It allows the Worker to stage and create
one ordinary local commit with the exact supplied message while the adapter
continues to block any other history/ref mutation, pushes, hosting-service
writes, and remote configuration changes. Fail preflight if the selected Worker
backend cannot provide that boundary; do not rely on prompt compliance alone.

Native session continuation is optional. Runner correctness must not depend on
it. If a backend session cannot be continued, reconstruct the next prompt from
persisted runner state and the observed workspace. A supplied fork source must
be forked directly; never resume it or silently replace an unavailable source.

Use structured output for all machine-actionable decisions:

- clarification readiness and questions;
- plan-revision requirements;
- blocking product-decision requests;
- review findings;
- Worker FIX/DISPUTE decisions;
- dispute reconsideration;
- arbitration;
- finalization pass/fail result.

Plain Markdown is acceptable for bootstrap/context summaries.

---

## 8. Backend Behavior

### Codex

Use the non-interactive Codex app-server JSONL protocol. Probe the installed
`codex-cli` version and required app-server flags before the first role turn.
Start each process with strict configuration and hosted search, browser,
computer-use, image-generation, artifact, Code Mode, JS REPL, memory,
automatic-goal, guardian-review, multi-agent, external app, plugin,
lifecycle-hook, notification, MCP, shell-environment snapshot, and skill-driven
MCP dependency installation capabilities disabled. Route no native approval to
a subagent or interactive reviewer.
Resolve and disable every configured MCP server individually, then verify the
effective configuration before starting a thread; fail closed when isolation
cannot be proven. The Codex process retains its own provider connectivity, but
command tools receive no network access, workspace-write excludes implicit
temporary-directory roots, Git metadata remains read-only, and reported
activity is rejected if it uses a disabled or unknown tool or attempts a push,
hosting-service mutation, or remote reconfiguration. Strip ambient Git
repository redirection and identity overrides from every Codex process
environment, and expose only Codex's filtered core environment without injected
values or shell-profile loading to agent commands. Remove key-, secret-, and
token-named variables from the isolated local-commit executor while retaining
the ordinary environment needed by Git and hooks.

Worker:

```text
sandbox: workspace-write
approval policy: never
```

Reviewer and Arbiter:

```text
sandbox: read-only
approval policy: never
```

Use Codex structured output / JSON Schema support for machine-actionable responses.

Validate every explicit model with `model/list` and reject any reported model
reroute. Fresh turns use `thread/start`; continuation uses `thread/resume`; and
a supplied source session uses `thread/fork`, with the returned child thread ID
persisted as role lineage. Unavailable continuation may fall back to a fresh
reconstructed turn, while an unavailable fork source is an error.

On native context exhaustion, request thread compaction and retry the turn once.
If the context remains full, start a fresh turn reconstructed from durable
runner input and the current workspace. Never replay an interrupted
`local-commit` turn: return an ambiguous outcome so the runner consumes no
second authorization and verifies Git state before deciding how to proceed.

`local-commit` additionally supplies an opaque authorization ID, expected HEAD,
and exact subject. Its agent turn is read-only and may only confirm readiness
through the adapter's strict schema; it cannot modify files, stage changes, or
write Git metadata itself. After confirmation, the Worker adapter runs the
exact HEAD check, `git add -A`, and ordinary subject-only commit in a dedicated
Codex permission profile. That profile grants write access only to the
workspace and resolved Git directory, denies command network access, preserves
Git hooks and configured Git identity, and receives no ambient Git overrides.

Probe this isolated commit profile by verifying outside-workspace write denial,
Git-metadata writes, and network denial. Report `localCommit: false` and fail
preflight if any boundary cannot be enforced. Any interrupted or failed commit
executor returns an ambiguous outcome for the runner's one-shot authorization
and final Git-state verification; it is never replayed.

### Claude Code

Use non-interactive print mode with JSON output. Start in safe mode, expose only
the built-in repository tools needed by the role, disable Chrome and prompt
suggestions, and load an explicitly empty MCP configuration. Supply
invocation-local settings that
disable bypass mode and commit attribution, disable model fallback, require the
native command sandbox to start successfully, deny its network access, forbid
unsandboxed command retries, and deny writes to the resolved Git metadata
directories. Use native sandbox credential-deny entries so Bash commands cannot
inherit provider credentials without enabling subprocess hardening that
downgrades `auto` to Manual mode, and reject any reported permission-mode
fallback. Fail preflight when the host cannot enforce those settings. Plan-mode
turns do not expose editing tools and also deny command writes to the workspace.

Worker default:

```text
permission mode: auto
```

This is the preferred unattended mode because it removes routine user permission prompts while retaining Claude Code's background safety classifier.

If `auto` mode is unavailable for the installed Claude Code/account/model/provider combination, the adapter must **not silently fall back to Manual mode**.

For V1:

- fail preflight for a Claude Worker when autonomous execution cannot be provided safely;
- do not silently use unrestricted `bypassPermissions` on the host.

Reviewer and Arbiter:

```text
permission mode: plan
```

Do not enable bypass permissions in Reviewer or Arbiter sessions.

Use `--output-format json` and `--json-schema` for machine-actionable output.
Reject permission denials from a non-interactive turn instead of treating a
partial response as success. Pass an explicit model without a fallback chain
and reject a full model ID when the result's model usage reports a different
model.

Fresh turns omit resume flags. Continuation uses `--resume <session-id>`, and a
supplied source session uses `--resume <session-id> --fork-session`; persist the
returned child ID and reject the source ID as invalid fork lineage. An
unavailable continuation may reconstruct a fresh turn, but an unavailable fork
source is an error.

Enable native auto-compaction for every turn. On an explicit context-exhaustion
result, retry the durable request once in the same session with compaction
instructions, then reconstruct it in a fresh session if the context remains
full. Never replay an interrupted `local-commit` turn.

On Linux, the isolated local-commit executor uses a probed `bubblewrap` profile
with a read-only host filesystem, writable workspace and resolved Git
directories, private temporary and runtime directories, and no network. The
agent confirmation turn remains in `plan` mode; after confirmation the executor
checks the expected HEAD, runs `git add -A`, rechecks HEAD, and creates one
subject-only commit with the exact supplied message. It preserves Git hooks and
configured identity, strips ambient Git redirection and sensitive command
environment values, and never adds Claude attribution. Report
`localCommit: false` when this profile or Claude's required Linux sandbox
dependencies cannot be probed.

### Backend-neutral `finalization` skill

`finalization` is a repository-defined instruction/skill, not a Codex-only or Claude-only feature.

During bootstrap, the agent must locate the project's finalization instructions through the repository's agent instructions/skills.

When the selected backend supports the skill natively, it may invoke it natively. Otherwise it must read and follow the skill instructions directly.

The same repository finalization procedure must therefore work with either Worker backend.

---

## 9. Repository Safety Guards

A fresh `run` requires a clean Git working tree, including untracked non-ignored files.

Before any implementation work:

- verify the project is a Git repository;
- record the initial HEAD;
- record the current branch when available;
- record deterministic local-ref, effective remote-configuration, and effective
  Git-identity fingerprints;
- verify an existing Git identity can create local commits without changing
  repository, global, or system configuration;
- verify the working tree is clean;
- verify the execution clarification path is ignored by the target repository;
- hash the task input files, including task-level clarifications when present;
- detect selected agent CLIs and versions.

### Git history/ref and configuration guard

Outside a dedicated, one-shot Worker turn authorized by the runner in `COMMIT`,
**no agent is allowed to change Git history or refs**.

Before and after every agent turn, compare at least:

- `HEAD` commit;
- symbolic branch/detached-HEAD state;
- a deterministic snapshot of local refs (`git for-each-ref` is sufficient);
- a fingerprint of effective remote configuration, including remote names, fetch
  and push URLs, and repository-local `remote.*` / `url.*` configuration;
- a fingerprint of the effective configured Git author/committer identity.

Hash remote configuration and Git identity for comparison without persisting
credential-bearing URLs or personal identity values in runner state or logs.

This catches unexpected commits, branch switches, rebases, resets, stashes,
tag/ref creation, remote renames or URL changes, and similar repository-control
mutations.

If the snapshot changes unexpectedly:

```text
WAITING_FOR_USER
reason: unexpected_git_ref_change
```

Use `unexpected_remote_configuration_change` instead when history/refs are
unchanged but effective remote configuration changed.

Use `unexpected_git_identity_change` when configured author/committer identity
changed.

Do not attempt an automatic destructive recovery.

The authorized `COMMIT` turn has a narrower expected mutation. Accept it only
when the current branch advances by exactly one non-merge commit whose parent is
the expected HEAD, every other ref and the effective remote configuration and
Git identity remain unchanged, and the commit passes the checks in section 13.7.

Staging/index changes by the Worker are allowed because they do not change repository history. Read-only roles are handled more strictly by the mutation guard below.

### Read-only mutation guard

Worker clarification and plan-compatibility turns, both bootstrap turns, and
every Reviewer and Arbiter turn are read-only.

For these turns, capture a repository snapshot before and after execution.

The snapshot must detect:

- HEAD changes;
- tracked content changes;
- untracked content changes;
- index/staging changes;
- effective remote-configuration changes;
- effective Git-identity changes.

If a supposedly read-only turn mutates repository state:

```text
WAITING_FOR_USER
reason: read_only_agent_mutated_repository
```

Do not silently revert it.

The runner may create or update only the resolved execution clarification
artifact while `CLARIFY` is active or while handling a persisted
`product_decision_required` pause. The user edits it through the configured text
editor; agents never write it directly. Hash that ignored artifact separately
before and after every agent turn. Any change outside an authorized editor
window pauses with `clarifications_changed`.

---

## 10. Content Fingerprint

Finalization and review must be tied to the exact content that would be committed.

The fingerprint must represent **repository content**, not whether a change is currently staged or unstaged.

It must include:

- current content of changed tracked files relative to HEAD;
- deletions;
- non-ignored untracked files and their content.

It must ignore staging placement itself.

This is important because `git add` before commit must not invalidate an already finalized/reviewed content fingerprint.

A practical implementation may hash:

1. a deterministic binary diff from `HEAD` to the current working-tree content;
2. sorted untracked non-ignored paths plus their file contents.

Do not modify the Git index to compute the fingerprint.

The ignored `LOCAL_ARTIFACTS` clarification transcript is not commit content and
must not affect this fingerprint. Its independently persisted hash protects it
as a run input.

---

## 11. Workflow

Persisted workflow states:

```text
CLARIFY
BOOTSTRAP
IMPLEMENT
FINALIZE
REVIEW
RESOLVE_FINDINGS
COMMIT
WAITING_FOR_USER
DONE
FAILED
```

`FIX`, `DISPUTE`, `ARBITRATE`, self-review, and per-step context refresh are actions within these states, not separate persisted states.

Only the runner controls transitions.

---

## 12. Clarification And Bootstrap

### Clarification

No implementation or bootstrap work may begin before `CLARIFY` closes. After
the ignore check, the runner ensures the execution clarification artifact exists
without overwriting a resumed transcript. The Worker then studies the task,
validated plan, optional plan-authoring
clarifications, existing execution transcript, repository instructions,
relevant architecture, tests, and Git history in read-only mode.

It returns structured `READY` or all currently actionable questions whose
answers could materially change required behavior, scope, or implementation of
the validated plan. It must use available evidence instead of asking about
ordinary technical choices.

```json
{
  "status": "READY",
  "questions": []
}
```

or:

```json
{
  "status": "QUESTIONS",
  "questions": [
    {
      "question": "Which externally visible behavior is required?",
      "whyItMatters": "The answer changes implementation of the validated step."
    }
  ]
}
```

or, when the clarification input conflicts with the validated plan:

```json
{
  "status": "PLAN_REVISION_REQUIRED",
  "reason": "Existing clarifications conflict with the validated plan.",
  "evidence": ["The requested behavior is outside the validated commit scope."]
}
```

An empty clarification artifact and closing the proactive editor without
changes are valid and do not consume an agent question round. The Worker still
runs and may return `READY`; only unanswered questions appended by the Worker
require user input.

Append each question round to the execution clarification artifact, open the
editor for answers, then let the Worker reread the complete transcript. Default
to at most three agent question rounds. If the editor cannot be opened, the run
is non-interactive, answers remain missing, or the round limit is reached,
persist `WAITING_FOR_USER` instead of advancing.

Before opening the editor or entering `WAITING_FOR_USER`, persist the suspended
state, pending editor action, and last accepted artifact hash. An edit made
through that authorized editor window is accepted as new clarification input
and invalidates dependent work; any edit outside an authorized window pauses
with `clarifications_changed`.

Through MCP, the root runtime never opens an editor. It projects the same
pending authorization with identified questions and accepts an empty response
for optional proactive clarification or one exact answer per Worker question
through `run_respond`. A product decision requires explicit user context; the
controlling agent asks the user when that context is absent. An external edit
followed by `run_resume` remains an equivalent path. Detached continuation does
not change this pipeline's lease, compatibility, Git, or commit gates.

When the Worker returns `READY`, persist and freeze the artifact hash. `READY`
is valid only when the clarification input is compatible with the validated
plan. Both the execution transcript and optional plan-authoring clarifications
become inputs to every later role. After this transition, normal prompts
prohibit questions.

`PLAN_REVISION_REQUIRED` enters `WAITING_FOR_USER` with
`plan_revision_required` before bootstrap. The current run remains paused until
a revised plan is validated and a new execution run starts with the transcript
carried forward; never reinterpret the stale plan.

An agent may instead return structured `PRODUCT_DECISION_REQUIRED` only when
all of these are true:

- the answer changes observable behavior, a business rule, data, security, or material scope;
- multiple incompatible choices are reasonable;
- the task, validated plan, repository, conventions, and prior clarifications do not resolve the choice;
- continuing would invent a requirement or create substantial rework risk.

```json
{
  "status": "PRODUCT_DECISION_REQUIRED",
  "question": "Which behavior should the product expose?",
  "options": ["Option A", "Option B"],
  "whyBlocked": "Both behaviors are valid but incompatible.",
  "evidence": ["The task and plan do not select either behavior."]
}
```

That outcome enters `WAITING_FOR_USER` and appends the question, options, and
evidence to the execution transcript. The user edits the transcript in the
authorized editor window. The runner persists the updated artifact hash, and
the edit invalidates all dependent context, finalization, and review. Before
re-entry, a read-only Worker compatibility check returns `READY` or
`PLAN_REVISION_REQUIRED` without asking questions. Resume at `BOOTSTRAP` if the
question arose there; otherwise resume the current step at `IMPLEMENT`, but only
when the answer leaves completed commits and the validated plan intact. If it
affects completed work, plan scope, or commit boundaries, pause with
`plan_revision_required`; do not reinterpret the plan or rewrite completed
commits. The current run remains paused: create a revised validated plan and
start a new execution run, carrying forward the recorded decision as task
context.

### Bootstrap

No implementation changes may occur before bootstrap completes.

Run Worker bootstrap and Reviewer bootstrap independently and in read-only mode.

Both study:

- repository structure;
- relevant source code and architecture;
- `task.md`;
- the complete `plan.md`;
- plan-authoring and execution clarifications;
- optional `context.md`;
- repository agent instructions;
- relevant repository skills;
- the `finalization` skill;
- relevant tests;
- relevant Git history where useful;
- project conventions related to the task.

They must not receive each other's interpretation until both independent analyses finish.

Persist concise summaries:

```text
context/worker.md
context/reviewer.md
```

Each summary should cover:

- task understanding;
- relevant architecture/files;
- important invariants;
- interpretation of planned commits;
- risks/ambiguities;
- finalization procedure.

The Reviewer summary additionally states what it intends to verify.

### Reconciliation

After both summaries exist, compare material differences.

Resolve differences from task/plan/repository evidence.

Persist the agreed context:

```text
context/resolved.md
```

Do not force agreement.

If a material disagreement remains, use the Arbiter.

If arbitration determines that progress requires an unresolved material product
decision meeting the clarification criteria:

```text
WAITING_FOR_USER
reason: product_decision_required
```

---

## 13. Per-Commit Workflow

For each plan step:

Keep role prompts short. Their mandatory English cores are:

```text
Worker: Implement the changes described in the following planned commit. Keep the implementation idiomatic and minimal, and follow the project's conventions.
Reviewer: Review the changes and verify that they are correct, idiomatic, minimal, and consistent with the project's conventions.
Finding resolution: For each finding below, fix it idiomatically and minimally, following the project's conventions.
```

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

Start or continue the Worker implementation context.

Before editing, the Worker refreshes:

- current commit section;
- relevant resolved context;
- relevant decisions/findings from previous work;
- current affected code.

The Worker then:

1. implements only the current planned commit;
2. performs a concise self-review;
3. returns control to the runner.

The Worker must not create a Git commit during implementation, finalization, or
finding resolution. Commit creation is allowed only in the dedicated,
runner-authorized `COMMIT` turn after the gate passes.

### 13.2 Finalization

Run the project's `finalization` skill in a dedicated Worker turn.

The finalization turn should execute the validation procedure and report its result. It should not perform unrelated discretionary fixes in the same turn.

Before invocation, the Worker reports a missing or invalid resolved skill and
does not execute it. A safe structured result is one of `PASS`, `FAIL`,
`SKILL_MISSING`, `SKILL_INVALID`, `BLOCKED`, or the narrowly permitted
`PRODUCT_DECISION_REQUIRED`. `FAIL` supplies stable `F`-prefixed issue IDs for
the current procedure output; `PASS`, `FAIL`, `SKILL_INVALID`, and `BLOCKED`
identify the resolved repository-relative skill path. Missing, invalid, or
blocked finalization pauses without advancing.

The finalization procedure may legitimately modify files when the project itself requires this, for example formatting or generated output.

Therefore:

1. run finalization;
2. let project-required modifications finish;
3. compute the content fingerprint afterward;
4. associate the finalization result with that fingerprint.

If finalization fails, enter `RESOLVE_FINDINGS` with the reported validation failures.

Any later content change invalidates the previous finalization result.

### 13.3 Review

After finalization passes, use an independent Reviewer context for the current commit.

Prefer one Reviewer session per planned commit, reused for re-review/dispute handling within that commit.

The Reviewer receives:

- task;
- current plan step;
- resolved bootstrap context;
- relevant prior decisions;
- previous findings for this step, if any;
- current repository state/diff;
- finalization result.

It reviews:

- correctness;
- completeness;
- plan compliance;
- regression risk;
- architecture consistency;
- tests;
- edge cases;
- unintended scope expansion;
- project conventions.

The Reviewer must not receive the Worker's private implementation reasoning.

Machine-actionable review output:

```json
{
  "status": "FINDINGS",
  "findings": [
    {
      "id": "R3",
      "file": "src/example.js",
      "problem": "Cache invalidation is missing on one path.",
      "reason": "...",
      "suggestedAction": "..."
    }
  ],
  "question": "",
  "options": [],
  "whyBlocked": "",
  "evidence": []
}
```

All findings are blocking until resolved. Severity is unnecessary for V1 workflow logic.

Finding IDs must remain stable across re-review:

- reuse an existing ID when the same finding remains;
- assign a new ID only to a genuinely new finding.

The runner must not implement fuzzy semantic matching of findings in V1.

When review finishes successfully, persist the reviewed content fingerprint.

### 13.4 Resolve findings

The Worker receives all currently open findings together.

For each finding it returns:

```text
FIX
```

or:

```text
DISPUTE
```

#### FIX

If the Worker agrees:

1. fix all accepted findings in one fix round;
2. return control;
3. run finalization again;
4. run a complete re-review.

When one resolution batch mixes `FIX` and `DISPUTE`, preserve the disputes
through finalization, let the Reviewer reconsider them after finalization
passes, then run the complete re-review.

#### DISPUTE

A dispute must contain concise evidence.

Example:

```text
Finding: R3
Decision: DISPUTE

Reason:
updateMarketConfig() delegates to saveMarket(), which performs invalidation
after persistence succeeds.

Evidence:
- src/market/service.js:142
- src/market/repository.js:88
- existing invalidation test
```

Valid evidence includes:

- source code;
- tests;
- task/plan wording;
- project documentation;
- prior accepted decisions;
- concrete execution paths.

A bare disagreement is invalid.

The Reviewer must reconsider the dispute and return:

```text
WITHDRAW
```

or:

```text
UPHOLD
```

with a concise reason.

### 13.5 Arbiter

Use the Arbiter only when:

- a material bootstrap disagreement remains; or
- a Worker/Reviewer dispute remains unresolved after the configured dispute budget.

Give the Arbiter only:

- relevant task/plan requirement;
- finding;
- Worker evidence;
- Reviewer response;
- relevant code/diff;
- relevant established decisions.

Possible outcomes:

```text
WORKER_CORRECT
REVIEWER_CORRECT
REQUIREMENT_AMBIGUOUS
```

The Arbiter never rewrites requirements.

Per-finding arbitration preserves this mandatory core:

```text
Resolve the disputed finding from the task, plan, repository, diff, and evidence, choosing the correct outcome using the provided schema.
```

Correction-loop stagnation is a separate arbitration episode for correction
churn that has not already reached the stable-finding limit. After the first
`stagnationWindowRounds` consecutive blocked correction rounds, invoke one
fresh read-only Arbiter with compact persisted history and this mandatory core:

```text
Diagnose why the implementation correction loop is not converging and choose the minimal valid next direction using the provided schema.
```

Its structured directions are `CONTINUE_FIXES`, `REWORK_IMPLEMENTATION`,
`RECONSIDER_FINDINGS`, `PLAN_REVISION_REQUIRED`, and
`PRODUCT_DECISION_REQUIRED`. The result cannot approve work, resolve a finding,
reset a budget, or satisfy the commit gate. Content changes remain Worker-only,
and finding reconsideration remains Reviewer-only. If another complete blocked
window accumulates after this arbitration, pause instead of invoking it again.

### 13.6 Commit gate

The runner may authorize the Worker commit turn only when all are true:

```text
finalization == PASS
open findings == 0
unresolved disputes == 0
pending arbitration == false
current content fingerprint == finalized fingerprint
current content fingerprint == reviewed fingerprint
HEAD == expected HEAD
current branch/ref context == expected branch/ref context
```

### 13.7 Commit

Only the Worker creates the planned commit, and only in a dedicated one-shot
turn explicitly authorized by the runner after the commit gate passes. The
runner controls the transition and verifies the result; it does not run
`git commit` itself.

Once the gate passes:

1. use the validated commit subject extracted from the plan heading without
   generating, rewriting, or extending it;
2. reject a message containing a `Co-authored-by` trailer, case-insensitively;
3. record the expected HEAD, branch/ref context, local refs, effective remote
   configuration and Git-identity fingerprints, and finalized/reviewed content
   fingerprint;
4. start or continue the Worker with a narrow instruction to stage the current
   non-ignored workspace (`git add -A`) and create exactly one local commit using
   the exact supplied message;
5. require the Worker to use the repository's existing Git identity and prohibit
   changing `user.name`, `user.email`, author/committer metadata, commit-message
   hooks, remotes, branches, tags, or unrelated Git configuration;
6. verify the new commit is a direct, single-parent child of the expected HEAD
   on the expected branch and no other refs changed;
7. verify the committed tree exactly matches the finalized/reviewed content and
   that staging did not change its fingerprint;
8. verify the effective remote configuration and Git identity are unchanged and
   the commit's author/committer identity matches that baseline;
9. verify the final commit message exactly matches the supplied message with no
   `Co-authored-by` trailer;
10. verify no unexpected non-ignored working-tree or index changes remain;
11. persist the new SHA, mark the step completed, and continue to the next step.

The authorization permits one ordinary local commit only. It does not permit
`commit --amend`, merge commits, rebases, resets, branch switches, tag creation,
or any other history/ref mutation.

If no commit is created, pause with `commit_failed`. If a commit is created but
violates the authorization contract, pause with `commit_contract_violated`.
Never amend, reset, or otherwise rewrite the unexpected commit automatically.

Do not create separate "review fix" commits.

Do not perform a second full review after commit. The exact content was already finalized and reviewed.

Remote mutation is strictly forbidden in V1.

Neither the runner nor any agent may:

- run `git push`;
- run `git push --force` / `--force-with-lease`;
- create, update, delete, or otherwise mutate remote refs;
- push tags;
- create or update pull requests;
- call GitHub/GitLab/Bitbucket APIs or CLIs in a way that writes to the remote repository;
- change remote repository settings;
- add, remove, rename, or change the URL/configuration of `origin` or another
  configured remote;
- perform any other operation that modifies a Git remote.

Remote access, when available, is read-only and may be used only for inspection.
Agent adapters must block remote-write operations at the execution boundary;
prompt instructions alone are not a sufficient safety control. The runner must
also compare the effective remote-configuration fingerprint before and after
every agent turn.

Also never automatically:

- `git reset --hard`;
- discard user work;
- bypass a failing Git hook.

The workflow ends with verified local commits only. Publishing those commits is always a separate explicit user action outside the autonomous V1 workflow.

A commit hook failure or unexpected post-commit repository state must pause the run.

---

## 14. Retry Limits and No-Progress Detection

Defaults:

```text
maxFixRoundsPerStep = 5
maxDisputesPerFinding = 2
maxSameFindingRounds = 3
stagnationWindowRounds = 3
```

A fix round is one Worker fix response followed by the required finalization/review cycle.

Finalization failures that require code changes consume fix rounds too.

A blocked correction round is recorded after a completed fix when finalization
fails, or when finalization passes and the subsequent review returns to finding
resolution. Persist its content fingerprint and exact finalization issue or
Reviewer finding IDs. This diagnostic history is bounded and uses exact IDs;
do not add fuzzy or semantic finding matching. Track consecutive exact-ID
counts separately so the configured stable-finding limit remains enforceable
beyond the retained diagnostic-history window.

No-progress detection in V1 is intentionally simple:

- if the same stable finding ID remains open for `maxSameFindingRounds` consecutive rounds, pause;
- do not implement fuzzy/semantic similarity detection.

Disputes do not consume fix rounds. After `maxDisputesPerFinding` upheld
disputes, invoke one read-only per-finding arbitration. An Arbiter decision in
the Reviewer's favor leaves the finding blocking and requires a fix or explicit
user override; it does not permit another dispute of the same reviewed finding.

Reaching any limit **never** means accept-and-continue.

It always means:

```text
WAITING_FOR_USER
```

---

## 15. User Escalation

Typical reasons:

```text
clarification_answers_required
clarification_limit_reached
clarifications_changed
local_artifacts_not_ignored
product_decision_required
plan_revision_required
fix_limit_reached
dispute_limit_reached
no_progress
finalization_skill_missing
finalization_skill_invalid
finalization_cannot_pass
read_only_agent_mutated_repository
unexpected_git_ref_change
unexpected_remote_configuration_change
unexpected_git_identity_change
unsafe_git_state
backend_unavailable
environment_blocked
arbiter_cannot_resolve
commit_failed
commit_contract_violated
```

When paused:

1. persist state;
2. append an event;
3. print a concise explanation;
4. do not advance.

Example:

```text
Run paused.

Step:
Commit 3: feat(market): add cache

Reason:
Fix limit reached after 5 rounds.

Open finding:
R7 — Cache invalidation may be missing on updateMarketConfig().

Available actions:
- grant additional fix rounds;
- send/re-send to Arbiter;
- re-run review;
- explicitly override/close a finding;
- abort.
```

Support finite additional fix budget:

```bash
agent-run resume \
  --run <run-id> \
  --extra-fix-rounds 3
```

Do not reset previous counters/history.

Also support one explicit override of a currently open finding for the exact
current reviewed fingerprint:

```bash
agent-run resume \
  --run <run-id> \
  --override-finding R7
```

Both resume actions are valid only for an applicable paused run. The override
removes only the named finding, does not approve any other finding, and becomes
stale as soon as the reviewed content fingerprint changes.

A user override must be explicitly recorded in `events.jsonl` and `progress.md`.

---

## 16. Resume

`agent-run resume --run <run-id>` must reconstruct the workflow from persisted
state.

Before continuing:

1. resolve the run ID, load its state, and verify the canonical task path;
2. verify current hashes of `task.md`, `plan.md`, optional task `clarifications.md`, and `context.md`;
3. verify the execution clarification path, hash, and whether its current change was explicitly authorized;
4. verify project path;
5. verify current HEAD;
6. verify current working-tree content/state against persisted expectations.

Reject a persisted resume target unless the exact pause reason permits it and
the suspended pipeline state is valid for that target in the current preflight
phase.

If task inputs changed while paused:

```text
WAITING_FOR_USER
reason: task_input_changed
```

If repository state changed externally and deterministic reconciliation is unsafe:

```text
WAITING_FOR_USER
reason: unsafe_git_state
```

Do not assume a native agent session survived.

Native Codex/Claude resume may be used as an optimization only.

---

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

- current step/state;
- clarification status, round count, and artifact path;
- open findings;
- fix/dispute counters;
- expected/current HEAD;
- last finalized/reviewed fingerprint;
- state directory;
- pause reason when applicable.

---

## 18. Testing

Use built-in `node:test`.

Do not add Jest/Vitest solely for this project.

Most tests must use fake agent adapters and temporary Git repositories. Normal tests must not consume model usage.

At minimum cover:

1. deterministic plan parsing and exact commit-subject extraction;
2. invalid/non-sequential plan numbering and invalid commit-subject rejection;
3. clean-repository preflight;
4. task directory located inside the repository without state pollution;
5. independent read-only bootstrap;
6. bootstrap mutation detection;
7. successful implementation -> finalization -> review -> commit;
8. finalization failure -> fix -> retry;
9. review finding -> fix -> re-finalize -> re-review;
10. dispute -> Reviewer withdraw;
11. dispute -> Reviewer uphold -> Arbiter;
12. fix/dispute/no-progress limits -> `WAITING_FOR_USER`;
13. additional fix budget after resume;
14. content fingerprint is independent of staging state;
15. content changes invalidate previous finalization/review;
16. read-only clarification, plan-compatibility, Reviewer, and Arbiter mutation detection;
17. unexpected Worker Git history/ref change outside the authorized `COMMIT` turn;
18. commit gate rejects unresolved findings;
19. commit staging does not invalidate the reviewed fingerprint;
20. authorized Worker turn creates exactly one direct, non-merge local commit;
21. commit messages containing `Co-authored-by` are rejected;
22. remote configuration changes by any agent are detected;
23. successful one-commit-per-plan-step progression;
24. interrupted run resumes from persisted state;
25. changed task/plan inputs are detected;
26. external repository changes while paused are detected;
27. Codex adapter command/result normalization;
28. Claude adapter command/result normalization;
29. `--clarify` opens the editor before the first Worker clarification turn;
30. `READY` closes clarification without opening the editor when `--clarify` is absent;
31. structured questions append to the transcript and remain read-only to the agent;
32. clarification round exhaustion and missing answers pause before bootstrap;
33. the frozen clarification hash is verified on agent turns and resume;
34. clarification input that conflicts with the validated plan pauses before bootstrap;
35. ordinary questions after `CLARIFY` are rejected;
36. a valid `PRODUCT_DECISION_REQUIRED` pause records the answer and invalidates dependent results;
37. a product answer that changes plan scope pauses with `plan_revision_required`;
38. `LOCAL_ARTIFACTS` remains outside the commit-content fingerprint;
39. preflight rejects a clarification path that the target repository does not ignore.
40. MCP input uses the same one-shot authorization and preserves exact answers;
41. MCP continuation cannot bypass the per-run lease or any local-commit gate.

Real Codex/Claude smoke tests should be opt-in integration tests.

---

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

1. Worker and Reviewer independently study project/task/plan before implementation.
2. Clarification, plan-compatibility, bootstrap, review, and arbitration turns are read-only.
3. The repository's `finalization` skill defines project validation.
4. Finalization is backend-neutral and must work through either Worker adapter.
5. The runner never substitutes generic hard-coded test commands for finalization.
6. The Worker is autonomous during normal implementation.
7. Only the Worker creates planned commits, one at a time, in a dedicated turn
   authorized by the runner after the commit gate passes.
8. Git history/refs must not change outside that authorized `COMMIT` turn.
9. Reviewer and Arbiter never modify repository state.
10. Worker may dispute Reviewer findings with evidence.
11. A finding must be fixed, withdrawn, arbitrated, or explicitly overridden by the user.
12. Any content change invalidates finalization/review for the previous content fingerprint.
13. Staging alone does not invalidate the content fingerprint.
14. Only the runner may advance to the next planned commit.
15. Retry exhaustion always pauses; it never accepts unresolved work.
16. Runner correctness does not depend on native agent-session resume.
17. Codex and Claude Code are both first-class V1 backends.
18. Worker, Reviewer, and Arbiter backend choices are independent.
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

---

## 22. Acceptance Criteria

V1 is complete when:

- it runs as a plain Node.js 24 LTS ESM CLI with no unnecessary runtime dependencies;
- `run`, `resume`, and `status` work;
- Codex and Claude adapters both work;
- Codex-only, Claude-only, and mixed Worker/Reviewer configurations work;
- Worker and Reviewer bootstrap independently;
- a bounded clarification phase with read-only agent turns completes before bootstrap;
- `--clarify` and agent-generated questions use the declared Markdown artifact and configured text editor;
- execution does not start when clarification input conflicts with the validated plan;
- clarification input changes are detected and post-start questions require a blocking product decision;
- preflight refuses to create `LOCAL_ARTIFACTS` when the target repository does not ignore it;
- read-only agent-turn guarantees are actively checked;
- task/plan input changes are detected;
- each plan step is implemented separately;
- project finalization is the validation gate;
- finalization and review are tied to the same staging-independent content fingerprint;
- Worker can fix or dispute findings;
- unresolved disputes can be arbitrated;
- retry/no-progress limits pause for the user;
- only a zero-finding finalized/reviewed workspace can be committed;
- only the Worker creates one local commit per plan step, after explicit runner
  authorization and successful gate verification;
- planned commit messages contain no `Co-authored-by` trailers;
- unexpected agent Git history/ref changes are detected;
- no workflow path can push commits, change remote configuration, or mutate a
  remote repository;
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
