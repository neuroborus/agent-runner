# Repository Conventions

These conventions define the intended architecture and cross-cutting code,
test, and documentation style for Agent Runner.

`AGENTS.md` owns mandatory workflow and safety policy. This document owns the
architectural principles used to place and design code. `docs/ARCHITECTURE.md`
records the detailed runtime contract and current system design; it is not a
reason to preserve an accidental boundary. When a structural change improves
conformance with these conventions, update the architecture document with the
implementation. Pipeline specifications own pipeline behavior, and
`packages/commit-plan/README.md` owns the shared plan format.

The narrower contract wins when rules overlap, but it may not weaken a safety
invariant from `AGENTS.md`.

## Deliberate adaptations

These conventions adapt an ownership-first TypeScript service guide to a plain
JavaScript CLI. Compile-time-only rules such as type/interface selection,
explicit TypeScript return annotations, and framework enum syntax become strict
runtime validation, closed serialized shapes, named finite constants, and
documentation at non-obvious exported boundaries. Framework dependency
injection becomes explicit construction and capability injection at the root
composition boundary.

Framework, HTTP/OpenAPI, database, finance, queue, and telemetry rules are not
copied because Agent Runner exposes none of those product surfaces. ESLint is
also not implied by the reference baseline: the repository uses runtime
contracts, boundary tests, and root-owned Prettier formatting, and adding a
semantic linter requires its own demonstrated need. The shared commit-plan
contract intentionally omits the otherwise common `style` commit type, so its
closed Conventional Commit allowlist remains authoritative.

## Architecture

### One runtime with explicit features

Agent Runner is a monorepo for one local runtime, independently owned pipeline
workspaces, and narrowly shared contracts. It is not a generic agent framework,
plugin platform, workflow language, or collection of independently deployed
services.

Keep the dependency direction explicit:

```text
bin entry point -> root runtime -> pipeline workspaces -> shared contracts
                         |
                         `-> runtime capabilities and provider adapters
```

- The root runtime composes the application and owns CLI, MCP, configuration,
  persistence, Git safety, clarifications, trusted execution, and providers.
- A pipeline owns its roles, prompts, schemas, state machine, retry policy, and
  completion criteria.
- A shared package owns a deterministic, framework-agnostic contract with more
  than one real consumer.
- Pipelines never import one another or the root runtime. The root supplies
  capabilities through the pipeline context.
- Runtime capabilities and shared packages never import a pipeline.
- Internal workspace dependencies must match actual imports and use declared
  package exports.

The root executable remains a thin entry point. Application assembly belongs at
the root source boundary; business decisions do not belong in `bin/` or in
transport handlers.

### Ownership before reuse

Assign every behavior to one owner before deciding where its file belongs.

| Concern | Owner |
| --- | --- |
| Command parsing and terminal projection | root CLI |
| STDIO protocol and detached control operations | root MCP boundary |
| Configuration loading and precedence | root configuration boundary |
| Run and resume coordination | root runner |
| State, Git, clarification, and trusted-command effects | their root capability |
| Provider protocol, flags, sessions, and output normalization | owning provider adapter |
| Workflow decisions and structured role contracts | owning pipeline |
| Commit-plan parsing and subject validation | `packages/commit-plan` |

- Do not use `shared`, `common`, `utils`, or a workspace package as a dumping
  ground for code that lacks a clear owner.
- Keep source-specific mapping and protocol behavior with the source adapter,
  not in an orchestration layer or shared contract.
- Share a module only after multiple owners need the same stable semantics.
  Similar-looking code with different policy should remain separate.
- If a change crosses a boundary awkwardly, treat that as a design signal.
  Refine the boundary instead of importing a private file for convenience.

### Layers are responsibilities, not mandatory directories

Use these responsibilities when designing a feature:

- **Contract/domain:** values, schemas, deterministic validation, mapping, and
  state-transition rules. This code does not start processes, inspect Git, read
  environment variables, or call providers.
- **Application:** orchestration of a use case through explicitly supplied
  capabilities. It decides sequence and policy without implementing transports.
- **Infrastructure/adapter:** filesystem, process, Git, editor, provider, and
  protocol effects. It validates and normalizes native results before returning
  them across the boundary.
- **Composition root:** configuration and construction of concrete
  implementations. It wires dependencies without acquiring feature policy.

Do not create ceremonial `domain/`, `application/`, or `infrastructure/`
directories for a trivial feature. Start flat inside the owning feature and
introduce a sublayer when it has a distinct responsibility, lifecycle, or
dependency graph. Conversely, do not leave a family of internal modules flat
once the owning boundary is no longer visible.

Create reusable resources at their composition boundary and pass them in.
Avoid constructing provider clients, process transports, stores, or clocks
inside workflow logic. Make resource ownership and teardown explicit; do not
hide mutable singletons in module scope.

### Capability and provider layout

Root capabilities with several implementation files should be directories with
one public `index.js` and private sibling modules. Do not add a directory for a
single file merely for symmetry.

Provider integrations are feature slices under `src/agents/`:

```text
src/agents/
|-- index.js                 # public adapter boundary
|-- adapter-contract.js      # provider-neutral contract
|-- codex/
|   |-- index.js             # Codex feature boundary
|   |-- adapter.js
|   |-- app-server.js
|   |-- local-commit.js
|   `-- workspace-storage.js
`-- claude/
    |-- index.js             # Claude feature boundary
    |-- adapter.js
    |-- local-commit.js
    `-- native-sandbox.js
```

The exact private filenames follow actual responsibilities; the boundary is the
important part. Code outside `src/agents/` imports its public index. The adapter
directory imports each provider through that provider's index. Files inside one
provider import private siblings directly rather than routing through the index.

A provider adapter owns:

- executable discovery and capability probing;
- provider-native profiles, models, context controls, and command arguments;
- child-process transport and session continuation;
- native sandbox and local-commit integration;
- parsing, validation, redaction, and provider-neutral result normalization.

Provider-specific values must not leak into pipeline state machines, the CLI,
or MCP policy. A new provider implements the small public adapter contract and
is registered at the composition boundary. Add a shared abstraction only when
at least two implementations demonstrate the same semantics; do not predict a
future provider with empty interfaces.

### Cross-cutting infrastructure

Keep a cross-cutting effect in the root capability that owns its lifecycle:

- state files, journals, actions, and leases belong to the state boundary;
- snapshots, fingerprints, staging, and commit verification belong to Git;
- confined files and editor invocation belong to clarifications;
- allowlists and host execution belong to trusted validation;
- provider processes and native sandboxes belong to agents.

Pipelines consume these capabilities and must not reproduce their effects.
Transport boundaries such as CLI and MCP project the same runner instead of
implementing parallel workflow logic.

Long-running work must be durable and detached from a single CLI or MCP request.
Persist intent before mutation, expose a status identifier, and let clients wait
or reconnect without becoming execution owners. A client disconnect cancels
only that client's wait unless the owning contract explicitly says otherwise.

### Present needs over speculative architecture

- Prefer the smallest structure that represents the current responsibility
  graph clearly.
- Do not add a framework, daemon, database, dynamic plugin loader, generic DAG,
  or transport layer for a hypothetical future use.
- Preserve an extension seam by keeping boundaries explicit, not by adding fake
  implementations or unused abstractions.
- Promote a flat feature to a directory or stronger module only when its
  internal graph, lifecycle, or number of private files makes that ownership
  useful.
- Extract a workspace package only for a real independent consumer, contract,
  dependency boundary, or release lifecycle.

## Files and directories

- Use lowercase kebab-case for directories and JavaScript filenames.
- Name a file after one concrete responsibility. A role suffix such as
  `schema`, `contract`, `mapper`, `adapter`, `store`, or `test` is useful when
  it clarifies that responsibility; do not force suffixes that add no meaning.
- Distinguish a pure, context-free utility from a context-aware helper. Do not
  mix unrelated functions in a generic utility or helper collection.
- Use directional names for boundary contracts when ambiguity exists, such as
  `request`, `response`, `input`, `result`, or `event`.
- Split a file when responsibilities diverge or its size obstructs
  understanding, not at an arbitrary line count.
- Keep tests next to their owning workspace or in the root `test/` boundary
  according to the behavior under test. Do not create a parallel source tree.

### Directory indexes

- Give every source directory with outward consumers a small, intentional
  `index.js`.
- External consumers import through the nearest owning directory index.
- Files within the same directory import one another directly. They do not
  route private dependencies back through their own index.
- A parent index imports a child directory through the child's index; it does
  not reach into the child's private files.
- Export only the symbols an external consumer needs. Registration does not by
  itself make a symbol public.
- Avoid recursive, generated, or catch-all barrels. An index is an ownership
  boundary, not a shortcut for exporting everything.
- Workspace `package.json` exports resolve to intentional public indexes. Do
  not import another workspace's private source path.

## Modules and imports

- Use native ES modules and explicit `.js` extensions in source imports.
- Order imports as Node.js built-ins, external dependencies, workspace package
  exports, then relative modules. Separate groups when it improves readability.
- Import Node.js built-ins through `node:` specifiers, even when an equivalent
  global exists.
- Keep imports one-directional across ownership boundaries. Avoid cycles and
  callback registration used only to conceal a cycle.
- Prefer named exports for reusable modules. Use a default export only when an
  external protocol or tool requires it.
- Do not create a root barrel that exposes every internal module. `src/index.js`
  is the deliberate runtime API, not a mirror of the filesystem.

## JavaScript and data contracts

- Target the Node.js version declared by the root package. Do not introduce
  TypeScript, transpilation, or a build step.
- Treat filesystem content, configuration, environment-derived input, process
  output, provider responses, persisted state, and MCP input as untrusted until
  validated.
- Use this boundary flow:

  ```text
  unknown native input -> validate -> normalize -> internal contract -> policy
  ```

- Parse before mapping or persistence. Pipeline policy consumes normalized
  contracts, never raw provider or transport output.
- Validate finite values with explicit allowlists and handle every member.
  Reject unknown fields when a public or persisted contract is closed.
- Keep validators with the narrowest owner that understands the contract. Move
  one to a shared package only when its exact semantics are genuinely shared.
- Represent meaningful serialized absence with `null`. Omit a field only when
  omission is part of the validated contract, and do not leak accidental
  `undefined` into persisted or public data.
- Prefer `??` when `0`, an empty string, or `false` is valid.
- Use `const`, frozen literal maps, and defensive copies where values cross an
  ownership boundary. Avoid shared mutable objects.
- Refer to closed values through named constants rather than duplicating raw
  strings across policy, adapters, and tests.
- Keep public and persisted shapes stable. Version a durable shape when an
  incompatible change is unavoidable, and validate legacy input explicitly.

## Configuration

- Load, merge, and validate runner configuration only in the root configuration
  boundary. Other modules receive resolved values.
- Pipeline descriptors own pipeline roles, settings, defaults, and persisted
  validation. The root loader must not duplicate those lists.
- Keep configuration precedence deterministic and test it at every supported
  layer.
- Avoid direct `process.env` reads in pipelines and reusable capabilities.
  Read environment-backed runner settings at the configuration or composition
  boundary. Provider adapters may pass through their native environment but
  must not turn undeclared environment values into runner policy.
- Never commit credentials, machine-local paths, personal profile names, or
  local agent configuration. Tracked examples use neutral placeholders.
- A local configuration changes new runs only unless a persisted-run contract
  explicitly permits re-resolution. Do not silently mutate a run snapshot on
  resume.

## Dependencies and native APIs

The runtime floor is Node.js `>=24 <25`; keep `package.json` engines aligned.

- Prefer Node.js and language APIs before adding a package.
- Use global `fetch`, `crypto.randomUUID`, `process.loadEnvFile`,
  `node:crypto`, `node:perf_hooks`, `structuredClone`, and native collection
  methods when they satisfy the requirement.
- Do not add wrappers such as an HTTP client, UUID package, environment loader,
  request-context library, or utility belt for a practical native capability.
- Keep internal workspace dependencies explicit.
- Add an external runtime dependency only for a demonstrated current need.
  Document a non-obvious exception in the change description, architecture
  record, or nearby rationale comment.
- Keep repository tooling and its configuration at the root unless a workspace
  has a proven independent requirement. Avoid per-workspace version or style
  drift.

## Effects, processes, and resources

- Keep effectful code behind a narrow capability or adapter boundary.
- Invoke child processes with an executable and argument vector; do not build a
  shell command from untrusted strings.
- Make timeouts, cancellation, exit status, signal handling, and ambiguous
  effects explicit. A process ending is not proof that its intended effect did
  or did not occur.
- Bound captured output and redact it before exposing or persisting it.
- Use atomic replacement for authoritative files and an exclusive lease for a
  mutation owner. Durable state must be sufficient to reconstruct the next
  operation without a surviving native provider session.
- Use an injected clock, identifier source, process runner, filesystem, or
  adapter where determinism or tests require control. Do not wrap native APIs
  mechanically when no boundary benefit exists.
- Clean up resources owned by the current scope. Do not terminate or alter a
  process, lock, file, or session whose ownership has not been established.

## Naming

- Use `camelCase` for variables and functions and `PascalCase` for classes and
  constructor-like factories.
- Use `SCREAMING_SNAKE_CASE` only for genuine module-level constants.
- Prefix booleans and boolean-returning functions with `is`, `has`, `can`, or
  `should`; avoid negative boolean names.
- Prefer descriptive names over abbreviations and single-letter identifiers,
  except in narrow loops or mathematical expressions.
- Use `load` or `read` for local retrieval, `fetch` for external retrieval,
  `run` or `execute` for effects, `persist` for durable writes, `map` or
  `normalize` for deterministic transformations, and `assert` for throwing
  validators.
- Do not name an external or effectful operation `get` when a boundary verb
  communicates the behavior more accurately.

## Error handling

- Normalize process, provider, filesystem, Git, and protocol failures inside
  their owning adapter or capability.
- Expose stable error codes and bounded structured details at public
  boundaries. Do not make callers parse human prose to decide policy.
- Keep provider-neutral categories homogeneous across adapters. Provider-native
  codes and messages are evidence used by the adapter, not pipeline policy.
- Distinguish retryable availability, rate limiting, exhausted usage allowance,
  operator action, invalid contract, safety refusal, environment limitation,
  and ambiguous effect.
- Preserve the original error as an internal `cause` when it is safe and useful,
  but do not leak raw standard error, responses, commands, prompts, transcripts,
  credentials, or provider internals into public errors or durable state.
- Retry only conditions classified as transient. Make delay, cap, reset, and
  exhaustion behavior explicit and observable; never retry deterministic
  contract or safety failures as code-fix work.
- Reconcile a potentially completed effect before retrying it. Fail closed when
  validation or effect ownership is uncertain.
- Do not catch an error merely to log and rethrow it at every layer. Add context
  once at the boundary that can classify or handle it.

## Logging and public activity

- Emit concise events at runtime, pipeline, provider, and effect boundaries.
- Include the run, role, state, attempt, outcome, and next-action identifiers
  needed to understand progress. Do not dump internal objects.
- Make waits and retries visible in both CLI and MCP activity, including the
  classified reason and the next retry time.
- Never log credentials, authorization data, cookies, tokens, secrets, raw
  provider payloads, prompts, transcripts, or chain-of-thought.
- Redact new fields containing tokens, keys, signatures, passwords, hashes, or
  secrets in the same change that introduces them.
- Reserve MCP standard output for protocol traffic. Send bounded operational
  diagnostics to standard error.
- Use the injected output or activity boundary in runtime code instead of ad
  hoc `console.log` or `console.error` calls.
- Keep repeated progress useful rather than noisy. Every repeated event states
  what changed or when the next action occurs.

## Formatting

- Prettier is the repository-wide formatting authority. Its dependency,
  configuration, ignore file, and scripts are root-owned; do not add
  per-workspace formatter setup.
- Format JavaScript, JSON, Markdown, and YAML through the root scripts. Do not
  manually preserve style that Prettier normalizes.
- Keep generated output, dependencies, local artifacts, and local agent
  configuration outside formatter scope.
- Prefer formatting a touched file or the accepted change set during
  development. A repository-wide mechanical rewrite belongs in its own commit.
- Finalization runs the writable formatter before the non-mutating repository
  gate and reviews formatter output as part of the current change.

## Comments and documentation

- Explain intent, invariants, tradeoffs, units, effect safety, or external
  quirks rather than restating code.
- Use `TODO(<context>): ...` only for concrete, actionable follow-up work.
- Document an exported helper when its boundary, mutation, persistence, units,
  or failure behavior is not obvious from its name and contract.
- Read the nearest specification, README, and sibling implementation before
  introducing a new pattern.
- Keep examples free of credentials, personal profile names, machine-local
  paths, and local-only artifacts.
- Update `docs/ARCHITECTURE.md` when ownership, dependency direction, lifecycle,
  or a cross-cutting contract changes.
- Update the owning pipeline specification when workflow behavior, prompts,
  roles, settings, state, retries, or completion rules change.
- Update the README when commands, configuration, visible behavior, or the
  repository layout changes.
- Keep tracked descriptive documentation aligned with implemented repository
  state. Normative documents may prescribe an accepted target convention, but
  speculative feature plans and session notes stay in ignored local artifacts.
- Keep source code, comments, logs, tests, and tracked documentation in English.

## Git

- Use subject-only Conventional Commits in the form
  `type(scope)[!]: imperative summary`.
- Use a lowercase established type and required kebab-case scope. Keep the
  subject focused, imperative, without a trailing period, and within the
  repository's validated length limit.
- Never add authorship trailers, change Git identity or remotes, push, or write
  through a hosting service on the user's behalf.
- Preserve unrelated work in a dirty worktree. Stage only the finalized change
  set, and create a commit only at the explicitly authorized boundary.
- Keep generated output, local settings, local agent configuration, and
  repository-local artifacts ignored rather than committing environment state.
- Treat staged content, worktree content, `HEAD`, refs, and remotes as distinct
  state. Verify the exact state relevant to an operation instead of assuming
  one represents another.

## Tests

- Use `node:test` and descriptive behavior names; avoid names such as `works`
  or `test1`.
- Keep arrange, act, and assert phases readable without ceremonial comments.
- Prioritize deterministic contract and pure transformation tests, then runtime
  orchestration and boundary integration tests.
- Test public behavior and safety boundaries rather than private function shape.
- Validate negative paths at every trust boundary: malformed input, unknown
  fields, interrupted effects, partial writes, and unsafe repository state.
- Use fake adapters, clocks, identifiers, and process runners plus temporary Git
  repositories. Normal tests must not consume model turns or depend on mutable
  external services.
- A regression test reproduces the externally visible failure before proving
  the fix. Do not weaken or skip a required check to make a test pass.
- Keep real Codex and Claude smoke tests explicit and opt-in.
- Test public directory indexes and workspace exports so private-path imports do
  not become accidental API.
- Add or update tests in the same change as behavior.
- Before handoff, run the root repository gate and required Git whitespace
  checks from `AGENTS.md` and the finalization skill.

## Development workflow

Before changing code:

1. Identify the owning runtime capability, provider, pipeline, or shared
   contract.
2. Read the nearest specification, public index, tests, and sibling
   implementation.
3. Confirm the required boundary and validation path before adding a module or
   dependency.

While changing code:

1. Keep the structure no larger than the current responsibility graph needs.
2. Reuse the owning public contract instead of duplicating or bypassing it.
3. Keep native inputs at adapter boundaries and normalized values in policy.
4. Update behavior, regression coverage, and affected documentation together.

Before handoff:

1. Check that each changed file has one clear owner and every new export has an
   external consumer.
2. Check that no private import, dependency inversion, provider leak, or
   speculative abstraction was introduced.
3. Run finalization, report the exact commands and results, and identify any
   check that could not run.

When placement remains unclear, classify the behavior instead of choosing the
nearest convenient file: workflow policy belongs to a pipeline; provider
protocol belongs to its adapter; shared deterministic plan semantics belong to
`packages/commit-plan`; runtime-wide effects belong to their root capability.
