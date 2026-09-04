# AGENTS.md

## Project Goals

- Build a small local CLI that hosts explicit, independently owned agent pipelines.
- Resolve material ambiguity in a bounded clarification phase before work begins.
- Author reviewed commit-by-commit coding plans with the `plan-authoring` pipeline.
- Execute predefined coding plans one verified local commit at a time with the `plan-execution` pipeline.
- Polish, finalize, and apply the selected review gate to existing workspace
  changes without committing them with the `polishing` pipeline.
- Support Codex CLI and Claude Code as independent pipeline role backends.
- Keep `independent` execution the default and recommended mode for genuine
  semantic review despite its higher provider context and token use; expose
  `lazy` only as an explicit lower-consumption choice without independent
  review and never select it automatically.
- Stay autonomous during normal execution and pause only for explicit escalation conditions.
- Make workflow correctness, Git safety, and resumable state more important than convenience.
- Keep the runtime a plain Node.js CLI rather than a general agent framework.
- Expose the same durable runner through a local asynchronous STDIO MCP boundary.

## Source Of Truth

Use `docs/README.md` as the document map and change gate. Read
`docs/CONVENTIONS.md` for the intended architecture and repository-wide code
conventions before changing tracked content. Read `docs/ARCHITECTURE.md` for the
detailed current runtime contract before changing boundaries or dependency
direction, and update it when the implementation changes. Read the affected
pipeline specification under `pipelines/*/docs/` before changing workflow
behavior, prompts, review resolution, or pipeline CLI contracts.
Use the product-document rows in `docs/README.md` for current workflow meaning,
business rules, operator guarantees, and accepted nuances. `RHYTHM.md` records
meaningful implemented decisions and their rationale; it does not replace a
current owning document. `packages/commit-plan/README.md` owns the shared plan
contract.

## Working Agreements

- Write source code, comments, logs, tests, and repository documentation in English.
- Target Node.js `>=24 <25` with native ES modules and the standard library.
- Keep internal workspace dependencies explicit; do not add an external runtime dependency until the implementation demonstrates that it is necessary.
- Use `node:test`; keep real Codex and Claude smoke tests opt-in.
- Prefer small functional modules and split them only when they become meaningfully large.
- Keep backend-specific flags and output normalization inside `src/agents/`.
- Keep runner configuration behind `src/config/index.js`; keep strict parsing,
  confined file loading, trusted profiles, and resolution precedence private
  to that capability. Let pipeline descriptors own their roles, settings,
  defaults, and persisted-run validation.
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

- Own one `mode` setting with exactly `independent` and `lazy`; resolve a
  missing value and every legacy run to `independent`, persist the resolved
  value at creation, and never reload it on resume.
- Validate configured role values deterministically, but in lazy mode resolve,
  probe, persist, source-session-check, invoke, and publicly project only the
  Planner or Worker. Preserve inactive Reviewer and Arbiter configuration for
  a future independent run without exposing provider-private values.
- Fork a deliberately supplied source session independently by primary and
  review checkpoints in independent mode. In lazy mode fork it exactly once
  into the logical primary role for the entire run, then continue the child or
  reconstruct the same role without reforking the source.
- In lazy mode alternate a writable primary-agent `CHECK_AND_FIX` turn with a
  separate read-only `CLEAN_CONFIRM`. Advance only for structured `CLEAN`, no
  read-only mutation, and the unchanged inspected fingerprint; route findings
  back to fixing and keep the loop bounded without invoking Reviewer or
  Arbiter.
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

- In independent mode run Worker and Reviewer bootstrap independently and
  read-only. In lazy mode use the Worker alone to establish the complete
  validation inventory under the same deterministic rules.
- Keep plan-compatibility, Reviewer, and Arbiter turns read-only and verify that
  they did not mutate the repository.
- Allow only the Worker to create the planned local commit, and only in the one-shot `COMMIT` turn explicitly authorized by the runner after the gate passes.
- Reject all other agent history/ref changes and verify that remote configuration remains unchanged across every agent turn.
- Require the exact validated plan subject, reject bodies/footers, and reject `Co-authored-by` trailers.
- Tie finalization and independent review or lazy clean confirmation to the
  same staging-independent content fingerprint and invalidate the evidence
  after any content change. A lazy check/fix change must pass full finalization
  again before confirmation.
- In independent mode resolve every Reviewer finding by fix, withdrawal,
  arbitration, or explicit recorded user override. Route lazy confirmation
  findings directly to fixing; they are never disputed or arbitrated.
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

`polishing` additionally requires:

- In independent mode run Worker and Reviewer bootstrap independently and
  read-only. In lazy mode use the Worker alone to establish the complete
  staging-independent inventory under the same deterministic rules.
- Allow only Worker polishing, finalization, finding-resolution, and lazy
  check/fix turns to change safe workspace content. No agent turn may change
  the index; the runner alone stages the finalized and reviewed polishing
  handoff.
- Keep bootstrap, validation-migration, and finalization required-check
  inventories staging-independent. Translate applicable tracked-content checks
  to `HEAD` or explicit trees; reserve staged and index-relative inspection for
  `HANDOFF`.
- Never request `local-commit`, create a commit, or change `HEAD`, refs, remotes,
  or Git identity.
- Tie successful finalization and independent review or lazy clean confirmation
  to the same staging-independent content fingerprint and invalidate the
  evidence after content changes. A lazy check/fix change must pass full
  finalization again before confirmation.
- Leave the finalized and reviewed workspace changes staged and uncommitted.

## Repository Map

| Path                              | Ownership                                                          |
| --------------------------------- | ------------------------------------------------------------------ |
| `bin/agent-run.js`                | Thin executable entry point                                        |
| `src/index.js`                    | Public root source boundary                                        |
| `src/cli.js`                      | Argument parsing and terminal-facing command dispatch              |
| `src/mcp/index.js`                | Public STDIO MCP protocol capability boundary                      |
| `src/mcp/`                        | Private schemas, projections, waits, detached dispatch, reporting  |
| `src/config/index.js`             | Public runner-configuration capability boundary                    |
| `src/config/`                     | Private parsing, confined loading, profiles, and resolution        |
| `src/clarifications/index.js`     | Public clarification-service boundary                              |
| `src/clarifications/`             | Private coordination, confined transcript, and editor modules      |
| `src/pipeline-registry.js`        | Explicit registry of built-in pipelines                            |
| `src/runner/index.js`             | Public runner-orchestration capability boundary                    |
| `src/runner/`                     | Private input, role/session, migration, and orchestration modules  |
| `src/state/index.js`              | Public run-store capability boundary                               |
| `src/state/`                      | Private service, files, journals, actions, leases, and validation  |
| `src/git/index.js`                | Public Git-safety capability boundary                              |
| `src/git/`                        | Private service, command, content, commit, and handoff modules     |
| `src/trusted-validation/index.js` | Public runner-trusted validation capability boundary               |
| `src/trusted-validation/`         | Private contracts, snapshots, sandboxing, and command execution    |
| `src/agents/index.js`             | Public agent-adapter directory boundary                            |
| `src/agents/`                     | Codex and Claude adapter implementations                           |
| `packages/commit-plan/`           | Shared deterministic commit-plan contract                          |
| `pipelines/plan-authoring/`       | Plan-authoring workflow, prompts, tests, and specification         |
| `pipelines/plan-execution/`       | Plan-execution workflow, prompts, tests, and specification         |
| `pipelines/polishing/`            | Polishing workflow, prompts, tests, and specification              |
| `test/clarifications/`            | Clarification-service behavior tests                               |
| `test/config/`                    | Configuration parsing, loading, and resolution tests               |
| `test/git/`                       | Git-safety behavior tests                                          |
| `test/integration/`               | Cross-capability workflow integration tests                        |
| `test/mcp/`                       | MCP control-plane and issue-reporting behavior tests               |
| `test/state/`                     | State persistence and safety behavior tests                        |
| `test/`                           | Root CLI, registry, adapter, and repository-boundary tests         |
| `docs/`                           | Cross-cutting architecture documentation                           |
| `docs/product/`                   | Current product guarantees, workflow meaning, and accepted nuances |
| `RHYTHM.md`                       | Newest-first record of meaningful implemented repository decisions |
| `.agents/skills/`                 | Shared repository workflow skills                                  |

`.claude/skills` is a symlink to `.agents/skills`. Edit the canonical skill
files under `.agents/skills`; never create a second Claude-specific copy.

## Required Checks

Run after source, test, or documentation changes:

```bash
npm run check
git diff --check HEAD
git diff --cached --check
```

Inside an Agent Runner pipeline, the established inventory ends with the
`HEAD`-relative content check. The runner-owned `COMMIT` or `HANDOFF` boundary
performs the staged check after it alone stages the accepted content.

The test suite imports every root and workspace source module, validates
canonical project skill frontmatter and content without requiring local
provider interface metadata, and checks the central product-document map.

Use the `finalization` skill for the complete handoff gate.
