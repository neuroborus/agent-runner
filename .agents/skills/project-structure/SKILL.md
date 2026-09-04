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
- `src/mcp/index.js`: expose the STDIO MCP protocol capability boundary.
- `src/mcp/`: keep schemas, projections, revision waits, detached dispatch,
  and issue reporting private to that boundary without duplicating runner logic.
- `src/config/index.js`: expose the runner-configuration boundary.
- `src/config/`: keep strict parsing, confined file loading, trusted profiles,
  and resolution precedence private to that boundary.
- `src/clarifications/index.js`: expose the clarification boundary.
- `src/clarifications/`: keep coordination, confined transcript files, and
  editor support private to that boundary.
- `src/pipeline-registry.js`: own the explicit list of built-in pipelines; do not turn it into a plugin system.
- `src/runner/index.js`: expose the runner-orchestration boundary.
- `src/runner/`: keep input normalization, role and session setup, pipeline
  migration, and run and resume orchestration private to that boundary.
- `src/state/index.js`: expose and coordinate the run-store boundary.
- `src/state/`: keep service coordination, atomic files, write-ahead journals,
  action intents, execution leases, and persisted-shape validation private to
  that boundary.
- `src/git/index.js`: expose and coordinate the Git safety boundary.
- `src/git/`: keep service coordination, command execution, snapshots and
  fingerprints, commit verification, and handoff support private to that boundary.
- `src/trusted-validation/index.js`: expose the runner-trusted validation boundary.
- `src/trusted-validation/`: keep contract normalization, snapshot handling,
  sandbox construction, and exact-command execution owned by that boundary.
- `src/agents/codex.js`: own Codex adapter coordination, probing, and
  request/result normalization.
- `src/agents/codex-*.js`: keep its app-server transport and constrained commit
  helpers internal to the Codex adapter.
- `src/agents/claude.js`: own Claude Code probing, command construction, and output normalization.
- `src/agents/index.js`: expose the agent-adapter directory API.
- `packages/commit-plan/`: own deterministic plan parsing, serialization, and validation shared by multiple pipelines.
- `pipelines/<id>/src/`: own that pipeline's states, transitions, prompts, roles, and descriptor.
- `pipelines/<id>/test/`: test that pipeline's behavior with `node:test` and fake adapters.
- `pipelines/<id>/docs/`: keep that pipeline's product and implementation specification.
- `test/clarifications/`: test clarification-service behavior.
- `test/config/`: test configuration parsing, loading, profiles, and resolution.
- `test/git/`: test Git-safety behavior.
- `test/integration/`: test cross-capability workflows.
- `test/mcp/`: test MCP control-plane and issue-reporting behavior.
- `test/state/`: test state persistence and safety behavior.
- `test/`: test root runtime behavior, workspace boundaries, adapters, and temporary Git repositories.
- `docs/`: keep cross-cutting architecture requirements.

## Rules

- Keep plain JavaScript, native ES modules, and Node.js standard-library APIs.
- Do not add TypeScript, a build step, a framework, a database, a network
  service, or a daemon.
- Keep the dependency direction `root runtime -> pipeline workspaces -> shared contract`.
- Expose a source directory's outward-facing API through its `index.js`; keep imports within the same directory direct instead of routing them back through the index.
- Keep pipelines explicit and independently owned; do not introduce a generic workflow DSL or dynamic plugin loader.
- Do not extract CLI, Git, state, agent adapters, or test helpers into packages until another real consumer needs them.
- Keep the backend contract small and functional; contain CLI-specific details inside adapters.
- Keep the configuration envelope and precedence in the root runtime while
  pipeline descriptors own roles, settings, defaults, and persisted-run
  validators; load runtime defaults from the runner root, never from a target
  repository.
- Keep plan parsing and Conventional Commit subject validation deterministic, shared, and separate from pipeline prompting.
- Keep Git snapshots and fingerprints deterministic and side-effect free.
- Allow a Worker commit only through a one-shot runner authorization after the commit gate; reject co-author trailers and remote-configuration changes.
- Keep persisted runner state outside the repository and task directory.
- Keep MCP as an asynchronous STDIO projection of the runner; persist an
  idempotency intent before mutation and never tie run lifetime to a tool call.
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
