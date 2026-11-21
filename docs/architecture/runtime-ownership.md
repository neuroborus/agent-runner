# Runtime Ownership

Read the affected sections before changing this contract. Use the [topic map](README.md)
for related owners and required reading routes.

## Dependency Direction

```text
root CLI/runtime ──static registry──▶ pipeline workspaces
                                           ┊
                                           └┄ when consumed ┄▶ shared plan contracts
```

The root runner imports registered pipelines. Pipelines do not import the root
application; the runner supplies state, event, agent, and Git services through a
runtime context. The registry stores each descriptor as one frozen composed copy
whose pause projection receives frozen root capabilities, currently only the
Git-owned read-only snapshot-change normalizer; a direct uncomposed projection
has no capability and fails closed. Plan authoring and execution consume
`@agent-runner/commit-plan`; polishing has no shared-package dependency, and
pipelines never depend on each other. Do not declare an internal runtime
dependency before an actual import needs it.

Inside the root, `src/platform/` is the lowest capability: it imports only
Node built-ins and its own siblings, and every other root capability may consume
its index.

## Root Runner Ownership

- CLI parsing, pipeline selection, and concise terminal output.
- Local STDIO MCP tool schemas, projections, and detached-run dispatch.
- Versioned runner configuration loading, validation, and role resolution.
- Run IDs, atomic state, append-only events, resume, and status.
- Clarification files, editor invocation, transcript updates, and input hashes.
- Common operator guidance, complete local additions, and safe durable replacement.
- Frozen provider registration plus adapter execution and access-mode
  enforcement.
- Git snapshots, content fingerprints, read-only guards, remote/identity guards,
  constrained local-commit verification, and verified polishing staging
  handoffs.
- Runner-trusted exact-vector validation outside agent turns, with bounded
  results and repository mutation guards.
- Static pipeline registration.

The root is one application, so these modules are not separate workspace
packages. Extract one only after it gains an independent consumer, release
lifecycle, or dependency boundary.

Each JavaScript source directory exposes outward-facing dependencies through
its `index.js`. Imports between modules in the same directory remain direct to
keep ownership visible and avoid barrel cycles. The source-boundary regression
checks those imports and the root-to-pipeline-to-shared-package dependency
direction from source and workspace manifests.

## Runner Orchestration

The runner capability lives under `src/runner/` behind its public `index.js`.
Private modules keep input normalization, role adapters and source-session
setup, pipeline migration, and run and resume orchestration distinct and
acyclic. Root consumers use the index; orchestration composes the other root
capabilities without exposing their private modules or moving workflow policy
out of pipeline descriptors.

## Native Platform

The root `src/platform/index.js` is the one native-platform boundary. It
statically selects the only implementation, Linux, and exposes three groups:
process facts (`readProcessIdentity`, `readProcessNamespace`), owned processes
(launch, execution, retirement, session inspection and the protected launcher)
and trusted-command isolation (system paths, launcher resolution and
verification, and the fixed bubblewrap profile), plus the process-group
availability fact. Each capability keeps its own host guard, so other hosts fail
closed: process facts are unverifiable, owned launches fail with
`ERR_EXECUTION_PROCESS_UNVERIFIABLE` and isolated commands are rejected before
launch. No other operating system is claimed.
Importing the index has no side effects, and every consumer shares its single
active-process registry. `runtime/bootstrap.js` and `runtime/admission.js`
stay standard-library-only and keep their own checks outside it.
