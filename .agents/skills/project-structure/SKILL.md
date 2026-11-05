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

Read the complete [ownership map](references/ownership-map.md) before selecting
or changing a capability, package, pipeline, source, test, or documentation owner.

## Rules

- Keep plain JavaScript, native ES modules, and Node.js standard-library APIs.
- Do not add TypeScript, a build step, a framework, a database, a network
  service, or a daemon.
- Keep the dependency direction `root runtime -> pipeline workspaces -> shared contract`.
- Expose a source directory's outward-facing API through its `index.js`; keep imports within the same directory direct instead of routing them back through the index.
- Keep pipelines explicit and independently owned; do not introduce a generic workflow DSL or dynamic plugin loader.
- Do not extract CLI, Git, state, agent adapters, or test helpers into packages until another real consumer needs them.
- Keep the backend contract small and functional; contain CLI-specific details inside adapters.
- Add a provider through one complete static descriptor; do not duplicate its
  ID or branch on it in configuration, runner, MCP, or pipeline policy.
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

- Select workspace kind, access, and inspected scope before Git inspection or
  recursive traversal; preserve ordinary-directory consumers of shared capabilities.
- Keep native initialization and incidental bookkeeping within the backend's
  authorized storage; declared read-only tool access alone does not prove an unchanged source tree.
- Align role schemas and instructions with semantic validation and bounded,
  actionable public diagnostics; keep raw provider data private.
- Distinguish a proved concurrent journal extension from corruption at its owning
  boundary; observation and retries must retain the original byte proof and effect authority.

## Review Questions

- Does this file have one clear owner in the map above?
- Is this logic runtime-wide, pipeline-specific, plan-contract-specific, backend-specific, Git-specific, or persistence-specific?
- Does the change preserve the mandatory invariants in `AGENTS.md`, the architecture, and the affected pipeline specification?
- Can the behavior be tested with a fake adapter or temporary repository?
- Does one injected provider descriptor exercise every runtime consumer without
  a provider-specific pipeline branch?
- Is a new module or dependency solving a present problem rather than a hypothetical one?

## Checks

After structural changes, run:

```bash
npm run check
git diff --check
git diff --cached --check
```
