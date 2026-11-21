# Decision History — 2026-08

Read these historical decisions when tracing their rationale; current contracts
remain with the owners in the [document map](README.md).

## 2026-08-27

- **The Git index has one effect owner per content-producing pipeline.**
  [`pipelines/plan-execution/docs/SPEC.md`](../pipelines/plan-execution/docs/SPEC.md)
  assigns staging and commit hygiene to the constrained `COMMIT` effect, while
  [`pipelines/polishing/docs/SPEC.md`](../pipelines/polishing/docs/SPEC.md) assigns
  final staging to the runner-owned `HANDOFF`. Bootstrap, finalization, and
  semantic review remain staging-independent, preventing ordinary agent turns
  from turning index state into evidence they control themselves.

## 2026-08-18

- **Pipeline registration is static and the MCP boundary projects the same
  durable runner.** [`src/pipeline-registry.js`](../src/pipeline-registry.js)
  explicitly registers independently owned pipelines, and
  [`src/mcp/index.js`](../src/mcp/index.js) exposes their control operations over
  STDIO rather than implementing a second workflow engine. Persisted
  idempotency intent, detached continuation, and reconnectable status let long
  runs outlive a client call without introducing dynamic plugins, a network
  service, or a daemon.
