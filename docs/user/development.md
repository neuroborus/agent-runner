# Development guide

## Provider Boundary

One provider descriptor binds a backend ID to its adapter factory,
execution-option validation, trusted-profile mapping, source-session support,
and normalized native-failure hooks. Root configuration, orchestration, and MCP
code consume the registry through the public agent boundary; pipelines remain
provider-neutral. Production registration is static and frozen.

## Repository Layout

```text
.
├── bin/
│   └── agent-run.js
├── src/
│   ├── agents/
│   │   ├── adapter-contract.js
│   │   ├── registry.js
│   │   ├── claude/
│   │   │   ├── adapter.js
│   │   │   ├── command-launcher.js
│   │   │   ├── index.js
│   │   │   ├── local-commit.js
│   │   │   └── native-sandbox.js
│   │   ├── codex/
│   │   │   ├── adapter.js
│   │   │   ├── app-server.js
│   │   │   ├── index.js
│   │   │   ├── local-commit.js
│   │   │   └── workspace-storage.js
│   │   └── index.js
│   ├── clarifications/
│   │   ├── files.js
│   │   ├── index.js
│   │   └── service.js
│   ├── cli.js
│   ├── runtime/
│   │   ├── index.js
│   │   ├── bootstrap.js
│   │   ├── admission.js
│   │   ├── archive.js
│   │   ├── candidate.js
│   │   ├── contract.js
│   │   ├── files.js
│   │   ├── payload.js
│   │   └── selection.js
│   ├── config/
│   │   ├── release/
│   │   │   └── index.js
│   │   ├── files.js
│   │   ├── index.js
│   │   ├── parsing.js
│   │   ├── profiles.js
│   │   └── resolution.js
│   ├── editor.js
│   ├── git/
│   │   ├── command.js
│   │   ├── commit.js
│   │   ├── content.js
│   │   ├── handoff.js
│   │   ├── index.js
│   │   ├── preservation.js
│   │   └── service.js
│   ├── guidance/
│   │   ├── content.js
│   │   ├── contract.js
│   │   ├── files.js
│   │   ├── index.js
│   │   └── service.js
│   ├── index.js
│   ├── issues/
│   │   ├── contract.js
│   │   ├── index.js
│   │   ├── location.js
│   │   ├── service.js
│   │   └── store.js
│   ├── mcp/
│   │   ├── index.js
│   │   └── service.js
│   ├── pipeline-registry.js
│   ├── platform/
│   │   ├── index.js
│   │   ├── linux-owned-process.js
│   │   └── linux-process.js
│   ├── runner/
│   │   ├── index.js
│   │   ├── input.js
│   │   ├── migration.js
│   │   ├── roles.js
│   │   ├── session-naming.js
│   │   └── service.js
│   ├── state/
│   │   ├── location/
│   │   │   └── index.js
│   │   ├── actions.js
│   │   ├── files.js
│   │   ├── index.js
│   │   ├── journal.js
│   │   ├── lease.js
│   │   ├── preservation-contract.js
│   │   ├── preservation.js
│   │   ├── runtime-admission.js
│   │   ├── service.js
│   │   └── validation.js
│   ├── trusted-validation/
│   │   ├── execution.js
│   │   ├── index.js
│   │   └── service.js
│   ├── update/
│   │   ├── apply.js
│   │   ├── index.js
│   │   ├── service.js
│   │   ├── activation.js
│   │   ├── candidate.js
│   │   ├── compatibility.js
│   │   ├── registry.js
│   │   ├── preparation.js
│   │   ├── candidate-contract.js
│   │   ├── process.js
│   │   └── storage.js
│   └── workspace/
│       ├── controls.js
│       ├── index.js
│       ├── paths.js
│       ├── service.js
│       └── snapshot.js
├── packages/
│   ├── commit-plan/
│   └── custom-plan/
├── pipelines/
│   ├── audit/                 # read-only audit and reviewed report publication
│   ├── init/                  # reviewed recoverable infrastructure setup
│   ├── plan-authoring/
│   ├── plan-execution/
│   └── polishing/
├── test/
│   ├── agents/
│   │   ├── claude.test.js
│   │   ├── codex.test.js
│   │   └── registry.test.js
│   ├── clarifications/
│   │   └── lifecycle.test.js
│   ├── config/
│   │   ├── documentation.test.js
│   │   ├── loading.test.js
│   │   ├── parsing.test.js
│   │   └── resolution.test.js
│   ├── git/
│   │   ├── local-commit.test.js
│   │   ├── polishing-handoff.test.js
│   │   └── repository-safety.test.js
│   ├── guidance/
│   │   ├── cli.test.js
│   │   ├── content-and-safety.test.js
│   │   ├── documentation.test.js
│   │   ├── editing.test.js
│   │   ├── publication.test.js
│   │   └── support/
│   ├── integration/
│   │   ├── cli-workflows.slow.test.js
│   │   └── mcp-workflows.slow.test.js
│   ├── mcp/
│   │   ├── control-plane.slow.test.js
│   │   ├── control-plane.test.js
│   │   ├── guidance.test.js
│   │   └── issue-reporting.test.js
│   ├── state/
│   │   ├── operator-stops.slow.test.js
│   │   ├── persistence.test.js
│   │   └── safety.test.js
│   ├── workspace/
│   │   └── inspection.test.js
│   └── source-boundaries.test.js
├── docs/
│   ├── architecture/
│   ├── testing/
│   ├── user/
│   ├── product/
│   ├── ARCHITECTURE.md
│   ├── CONVENTIONS.md
│   ├── OPERATOR_GUIDE.md
│   ├── TESTING.md
│   └── README.md
├── .agents/skills/
├── AGENTS.md
├── CLAUDE.md
└── RHYTHM.md
```

`.agents/skills/` is the canonical shared skill directory.
`.claude/skills` points to it so Codex and Claude use the same project
instructions. In the source checkout, use
`.agents/skills/documentation-structure/SKILL.md` for maintained Markdown and
the engineering map at `docs/README.md` for its owners.

## Development

Create the local workspace links from the committed lockfile:

```bash
npm ci
```

Run the fast tests:

```bash
npm test
```

Format every supported tracked or non-ignored repository file:

```bash
npm run format
```

Verify formatting without changing files:

```bash
npm run format:check
```

Run the ordinary repository gate (approximately one minute):

```bash
npm run check
git diff --check HEAD
git diff --cached --check
```

Run the durable cross-service regression tier when its contracts change, and
before release:

```bash
npm run test:slow
```

See Testing (`docs/TESTING.md`) for coverage ownership, temporary storage, and
the distinction between the ordinary and slow gates.

Run the opt-in real-backend smoke turns explicitly:

```bash
AGENT_RUNNER_LIVE_CODEX=1 npm test -- test/agents/codex.test.js
AGENT_RUNNER_LIVE_CLAUDE=1 npm test -- test/agents/claude.test.js
```

Claude keeps tool HOME/config projections and temporary sandbox scaffolding
outside the project and task. Provider authentication and sessions remain
separate. Adapter-owned cleanup must finish before content fingerprints or
trusted checks are accepted; a cleanup reservation is recovered by resuming the
same run, never by asking the agent to remove placeholders or changing ignores.

Claude launcher changes follow the deterministic commit gate and post-install
real acceptance procedure owned by Testing (`docs/TESTING.md`).

Inspect the CLI:

```bash
node bin/agent-run.js --help
```

Use the repository's `finalization` skill before handing off a completed
change. It validates the current change; when explicitly asked to finalize, it
also stages the relevant files and drafts a Conventional Commit message.
Inside the polishing pipeline, that skill remains staging-independent and the
runner stages and inspects the complete finalized and reviewed change set
instead. Its producing roles use `HEAD`-relative or explicit-tree content checks
and never persist a staged/index-relative required check.
Finalization stops at the staged handoff boundary. Commit creation requires a
separate explicit request, and remote state remains read-only in V1.
