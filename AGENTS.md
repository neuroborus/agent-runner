# AGENTS.md

## Project Goals

- Build a small local CLI that hosts explicit, independently owned agent pipelines.
- Resolve material ambiguity in a bounded clarification phase before work begins.
- Author reviewed commit-by-commit coding plans with the `plan-authoring` pipeline.
- Execute predefined coding plans one verified local commit at a time with the `plan-execution` pipeline.
- Support Codex CLI and Claude Code as independent pipeline role backends.
- Stay autonomous during normal execution and pause only for explicit escalation conditions.
- Make workflow correctness, Git safety, and resumable state more important than convenience.
- Keep the runtime a plain Node.js CLI rather than a general agent framework.
- Expose the same durable runner through a local asynchronous STDIO MCP boundary.

## Source Of Truth

Read `docs/ARCHITECTURE.md` before changing repository boundaries or dependency
direction. Read the affected pipeline specification under `pipelines/*/docs/`
before changing workflow behavior, prompts, review resolution, or pipeline CLI
contracts. `packages/commit-plan/README.md` owns the shared plan contract.

## Working Agreements

- Write source code, comments, logs, tests, and repository documentation in English.
- Target Node.js `>=24 <25` with native ES modules and the standard library.
- Keep internal workspace dependencies explicit; do not add an external runtime dependency until the implementation demonstrates that it is necessary.
- Use `node:test`; keep real Codex and Claude smoke tests opt-in.
- Prefer small functional modules and split them only when they become meaningfully large.
- Keep backend-specific flags and output normalization inside `src/agents/`.
- Keep runner configuration loading and precedence in `src/config.js`; let
  pipeline descriptors own their roles, settings, defaults, and persisted-run
  validation.
- Keep shared plan parsing and structural and subject validation in
  `packages/commit-plan/`. The plan-authoring Planner proposes exact commit
  subjects, deterministic code validates them, and plan execution consumes
  their validated text unchanged.
- Require each plan heading to carry the exact subject-only Conventional Commit message: `type(scope)[!]: imperative summary`.
- Outside an Agent Runner workflow, do not create a Git commit during direct repository maintenance unless the user explicitly asks for one. Finalization stages only the relevant change set and drafts its commit message.
- Never push, mutate a remote ref, change `origin` or another remote's configuration, or write through a hosting-service API or CLI.
- Never add a `Co-authored-by` trailer or change Git author/committer identity on the user's behalf.
- Preserve unrelated user changes in a dirty worktree.
- Fix validation failures that belong to the current change before handoff, then rerun the affected checks.

## Mandatory Safety Boundaries

- Keep project content read-only throughout `plan-authoring` except for the resolved `clarifications.md` and `plan.md` artifact paths, even when the task directory is inside the target repository. Never create a commit.
- Treat pipeline-specific role permissions as part of the owning pipeline's specification, not as global defaults.

All pipelines additionally require:

- Start with a pipeline-owned `CLARIFY` state whose agent turns are read-only.
- Let the primary role return `READY`, structured material questions, or a
  pipeline-owned blocking outcome; do not ask questions that repository
  evidence can answer.
- Accept an empty clarification artifact and an authorized editor close without
  changes; neither requires user text nor consumes an agent question round.
- Freeze and hash `clarifications.md` before leaving `CLARIFY`.
- Prohibit questions after clarification closes unless progress is impossible without an unresolved material product decision.
- Represent that exceptional stop as `PRODUCT_DECISION_REQUIRED`, persist it, and enter `WAITING_FOR_USER` without inventing a requirement.
- Persist the suspended pipeline state and pending editor action before opening
  an editor or waiting for clarification input; consume that one-shot
  authorization when the editor closes or a resumed edit is accepted.
- Treat clarification edits outside a runner-authorized editor window as unexpected input changes.
- Create repository-local clarification artifacts only when `git check-ignore`
  confirms their resolved path is ignored; never alter target ignore rules
  automatically.

`plan-execution` additionally requires:

- Run Worker and Reviewer bootstrap independently and read-only.
- Keep plan-compatibility, Reviewer, and Arbiter turns read-only and verify that
  they did not mutate the repository.
- Allow only the Worker to create the planned local commit, and only in the one-shot `COMMIT` turn explicitly authorized by the runner after the gate passes.
- Reject all other agent history/ref changes and verify that remote configuration remains unchanged across every agent turn.
- Require the exact validated plan subject, reject bodies/footers, and reject `Co-authored-by` trailers.
- Tie finalization and review to the same staging-independent content fingerprint and invalidate both after any content change.
- Resolve every finding by fix, withdrawal, arbitration, or explicit recorded user override.
- Do not leave `CLARIFY` when clarification input conflicts with the validated plan; require a revised plan and new execution run.
- If a product decision invalidates completed commits or the validated plan, require a revised plan and a new execution run; never rewrite completed commits automatically.
- Pause when retry budgets are exhausted or repository reconciliation is unsafe.
- Store state outside both the target repository and task directory, and write state atomically.
- Never make correctness depend on a native Codex or Claude session surviving interruption.
- Persist each run transition as a complete write-ahead event before atomically
  replacing state, and require one recoverable execution lease for mutating run
  or resume operations; keep status reads lock-free.
- Persist MCP idempotency intents before mutation and receipts before returning;
  detached continuations must survive client disconnect without gaining a
  second execution owner.
- Keep MCP on STDIO, reserve stdout for protocol traffic, never open an editor,
  and treat wait cancellation as cancellation of the wait only.

## Repository Map

| Path | Ownership |
| --- | --- |
| `bin/agent-run.js` | Thin executable entry point |
| `src/index.js` | Public root source boundary |
| `src/cli.js` | Argument parsing and terminal-facing command dispatch |
| `src/mcp.js` | STDIO MCP schemas, projections, waits, and detached dispatch |
| `src/config.js` | Runner configuration loading, validation, and role resolution |
| `src/clarifications.js` | Public clarification-service coordination |
| `src/clarification-*.js` | Internal confined-file and editor helpers |
| `src/pipeline-registry.js` | Explicit registry of built-in pipelines |
| `src/runner.js` | High-level run, resume, and status orchestration |
| `src/state.js` | Public run-store coordination and state-directory resolution |
| `src/state-*.js` | Internal state file, journal, action, lease, and validation helpers |
| `src/git.js` | Public Git-safety coordination |
| `src/git-*.js` | Internal Git process, snapshot, and commit-verification helpers |
| `src/agents/index.js` | Public agent-adapter directory boundary |
| `src/agents/` | Codex and Claude adapter implementations |
| `packages/commit-plan/` | Shared deterministic commit-plan contract |
| `pipelines/plan-authoring/` | Plan-authoring workflow, prompts, tests, and specification |
| `pipelines/plan-execution/` | Plan-execution workflow, prompts, tests, and specification |
| `test/` | Root CLI, registry, adapter, and repository-boundary tests |
| `docs/` | Cross-cutting architecture documentation |
| `.agents/skills/` | Shared repository workflow skills |

`.claude/skills` is a symlink to `.agents/skills`. Edit the canonical skill
files under `.agents/skills`; never create a second Claude-specific copy.

## Required Checks

Run after source, test, or documentation changes:

```bash
npm run check
git diff --check
git diff --cached --check
```

The test suite imports every root and workspace source module and validates
project skill frontmatter and interface metadata without depending on one agent
backend's installation path.

Use the `finalization` skill for the complete handoff gate.
