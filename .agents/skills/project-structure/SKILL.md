---
name: project-structure
description: Agent Runner monorepo structure and ownership guidance. Use when creating, moving, splitting, or reviewing packages, pipelines, source files, tests, documentation, CLI commands, workflow logic, Git helpers, state persistence, prompts, or Codex and Claude adapters.
---

# Project Structure — Agent Runner

Use this map before adding or moving files. Read `docs/ARCHITECTURE.md` for
dependency direction, the affected pipeline specification under
`pipelines/*/docs/`, and `packages/commit-plan/README.md` when a structural
choice affects the shared plan contract.

## Ownership Map

- `bin/agent-run.js`: keep the executable entry point thin.
- `src/index.js`: expose the root source API to the executable and root tests.
- `src/cli.js`: own argument parsing, validation, concise terminal output, and dispatch.
- `src/config.js`: own repository configuration loading, strict validation, and role resolution precedence.
- `src/clarifications.js`: expose and coordinate the clarification boundary.
- `src/clarification-*.js`: keep its confined file and editor helpers internal
  to the root clarification boundary.
- `src/pipeline-registry.js`: own the explicit list of built-in pipelines; do not turn it into a plugin system.
- `src/runner.js`: coordinate `run`, `resume`, and `status` without backend-specific flags.
- `src/state.js`: expose and coordinate the run-store boundary.
- `src/state-*.js`: keep its atomic file, write-ahead journal, execution-lease,
  and persisted-shape helpers internal to the root state boundary.
- `src/git.js`: expose and coordinate the Git safety boundary.
- `src/git-*.js`: keep Git process, snapshot, and commit-verification helpers
  internal to the root Git boundary.
- `src/agents/codex.js`: own Codex CLI probing, command construction, and output normalization.
- `src/agents/claude.js`: own Claude Code probing, command construction, and output normalization.
- `src/agents/index.js`: expose the agent-adapter directory API.
- `packages/commit-plan/`: own deterministic plan parsing, serialization, and validation shared by multiple pipelines.
- `pipelines/<id>/src/`: own that pipeline's states, transitions, prompts, roles, and descriptor.
- `pipelines/<id>/test/`: test that pipeline's behavior with `node:test` and fake adapters.
- `pipelines/<id>/docs/`: keep that pipeline's product and implementation specification.
- `test/`: test root runtime behavior, workspace boundaries, adapters, and temporary Git repositories.
- `docs/`: keep cross-cutting architecture requirements.

## Rules

- Keep plain JavaScript, native ES modules, and Node.js standard-library APIs.
- Do not add TypeScript, a build step, a framework, a database, or a server.
- Keep the dependency direction `root runtime -> pipeline workspaces -> shared contract`.
- Expose a source directory's outward-facing API through its `index.js`; keep imports within the same directory direct instead of routing them back through the index.
- Keep pipelines explicit and independently owned; do not introduce a generic workflow DSL or dynamic plugin loader.
- Do not extract CLI, Git, state, agent adapters, or test helpers into packages until another real consumer needs them.
- Keep the backend contract small and functional; contain CLI-specific details inside adapters.
- Keep the configuration envelope and precedence in the root runtime while
  pipeline descriptors own roles, setting validators, and defaults.
- Keep plan parsing and Conventional Commit subject validation deterministic, shared, and separate from pipeline prompting.
- Keep Git snapshots and fingerprints deterministic and side-effect free.
- Allow a Worker commit only through a one-shot runner authorization after the commit gate; reject co-author trailers and remote-configuration changes.
- Keep persisted runner state outside the repository and task directory.
- Keep `CLARIFY` explicit in every pipeline, freeze its artifact before work, and allow later questions only through `PRODUCT_DECISION_REQUIRED`.
- Require repository-local clarification artifacts to be ignored already; never modify a target repository's ignore rules automatically.
- Keep machine-actionable decisions structured; keep summaries concise Markdown.
- Split a module only after it gains a distinct responsibility or becomes meaningfully large.
- Add no cross-backend abstraction until both adapters demonstrate the shared contract.
- Place tests by behavior, not by implementation detail, and avoid normal-test model usage.

## Review Questions

- Does this file have one clear owner in the map above?
- Is this logic runtime-wide, pipeline-specific, plan-contract-specific, backend-specific, Git-specific, or persistence-specific?
- Does the change preserve the mandatory invariants in `AGENTS.md`, the architecture, and the affected pipeline specification?
- Can the behavior be tested with a fake adapter or temporary repository?
- Is a new module or dependency solving a present problem rather than a hypothetical one?

## Checks

After structural changes, run:

```bash
npm run check
git diff --check
git diff --cached --check
```
