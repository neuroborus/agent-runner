# Ownership Map

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
  sandbox policy, and exact-command execution owned by that boundary.
- `src/platform/index.js`: expose the native-platform boundary with static Linux selection.
- `src/platform/`: keep Linux process facts, owned-process supervision, and
  trusted-command isolation private to that boundary.
- `src/agents/codex/index.js`: expose the Codex provider boundary.
- `src/agents/codex/`: keep Codex processes, App Server transport, flags,
  parsing, sessions, local commits, and workspace storage private to that provider.
- `src/agents/claude/index.js`: expose the Claude provider boundary.
- `src/agents/claude/`: keep Claude Code processes, flags, parsing, sessions,
  local commits, and native sandbox behavior private to that provider.
- `src/agents/index.js`: expose the agent-adapter directory API.
- `src/agents/registry.js`: own the frozen source-controlled provider
  descriptors used by configuration, runner construction, source checks,
  failure normalization, and MCP backend schemas.
- `packages/commit-plan/`: own deterministic plan parsing, serialization, and validation shared by multiple pipelines.
- `pipelines/<id>/src/`: own that pipeline's states, transitions, prompts, roles, and descriptor.
- `pipelines/<id>/test/`: test that pipeline's behavior with `node:test` and fake adapters.
- `pipelines/<id>/docs/`: keep that pipeline's product and implementation specification.
- `test/agents/`: test provider behavior through provider indexes.
- `test/clarifications/`: test clarification-service behavior.
- `test/config/`: test configuration parsing, loading, profiles, and resolution.
- `test/git/`: test Git-safety behavior.
- `test/integration/`: test cross-capability workflows.
- `test/mcp/`: test MCP control-plane and issue-reporting behavior.
- `test/platform/`: test platform process facts and owned-process containment.
- `test/state/`: test state persistence and safety behavior.
- `test/source-boundaries.test.js`: enforce public source indexes and internal
  workspace dependency direction.
- `test/`: test root runtime behavior, workspace boundaries, adapters, and temporary Git repositories.
- `docs/`: keep cross-cutting architecture requirements.
- `src/runtime/`: own immutable startup, admission, and detached execution.
- `src/issues/`: own deliberate issue reports and the global issue store.
- `src/workspace/`: own Git-independent directory inspection, snapshots, and drift guards.
- `src/guidance/`: own bounded operator guidance and durable local updates.
- `packages/custom-plan/`: own criterion-driven custom-plan syntax and validation.
- `test/workspace/`: test directory confinement, controls, snapshots, and drift.
- `test/guidance/`: test operator guidance, local-file safety, and recovery.
