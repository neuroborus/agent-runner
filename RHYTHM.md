# RHYTHM.md

Chronological record of meaningful implemented repository decisions. New dated
sections are added immediately below this introduction. Entries describe the
resulting behavior, rationale, and important consequences; current contracts
remain in the owning documentation.

## 2026-09-03

- **Current product meaning and repository decisions have explicit owners.**
  [`docs/README.md`](docs/README.md) is the single document map and change gate,
  while the focused documents under [`docs/product/`](docs/product/) explain
  current guarantees without reproducing pipeline state machines.
  [`docs/CONVENTIONS.md`](docs/CONVENTIONS.md) owns intended engineering rules,
  [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) records the implemented runtime,
  and this file retains the rationale for durable decisions. Reviewers can now
  find business meaning without reconstructing it from code while each exact
  contract keeps one normative owner.
- **Canonical skill instructions are versioned, provider interface metadata is
  local.** [`test/scaffold.test.js`](test/scaffold.test.js) validates each
  canonical `SKILL.md`, and [`.gitignore`](.gitignore) excludes only YAML files
  beneath `.agents/**/agents/`. Codex and Claude continue to share the canonical
  [`.agents/skills/`](.agents/skills/) tree, but an installed agent may create
  its own ignored interface metadata without dirtying the repository or making
  a clean checkout depend on one provider's installation format.
- **Repository placement follows ownership rather than the historical flat
  layout.** [`docs/CONVENTIONS.md`](docs/CONVENTIONS.md) defines capabilities,
  provider slices, intentional public indexes, and present-need promotion as
  the target architecture. [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) remains
  a description of the current implementation and must move with it, so an
  accidental file layout cannot justify new dependency violations.

## 2026-09-02

- **Independent execution remains the default; lazy execution is an explicit
  consumption tradeoff.** The three pipeline descriptors under
  [`pipelines/`](pipelines/) own the same `independent` and `lazy` setting.
  Independent mode retains distinct primary and review contexts for genuine
  semantic review. Lazy mode resolves only the primary role and requires a
  separate read-only clean confirmation, reducing provider use without
  presenting self-review as independent review.
- **Writable provider turns use provider-specific isolation behind one shared
  role contract.** The adapters under [`src/agents/`](src/agents/) block Git
  metadata and remote writes while allowing only phase-authorized content
  changes. Codex receives a runner-owned private temporary root and Claude must
  prove its native sandbox policy before advertising writable capability. This
  keeps provider mechanics private while making the pipeline safety guarantee
  backend-neutral.

## 2026-08-27

- **The Git index has one effect owner per content-producing pipeline.**
  [`pipelines/plan-execution/docs/SPEC.md`](pipelines/plan-execution/docs/SPEC.md)
  assigns staging and commit hygiene to the constrained `COMMIT` effect, while
  [`pipelines/polishing/docs/SPEC.md`](pipelines/polishing/docs/SPEC.md) assigns
  final staging to the runner-owned `HANDOFF`. Bootstrap, finalization, and
  semantic review remain staging-independent, preventing ordinary agent turns
  from turning index state into evidence they control themselves.

## 2026-08-18

- **Pipeline registration is static and the MCP boundary projects the same
  durable runner.** [`src/pipeline-registry.js`](src/pipeline-registry.js)
  explicitly registers independently owned pipelines, and
  [`src/mcp.js`](src/mcp.js) exposes their control operations over STDIO rather
  than implementing a second workflow engine. Persisted idempotency intent,
  detached continuation, and reconnectable status let long runs outlive a
  client call without introducing dynamic plugins, a network service, or a
  daemon.
