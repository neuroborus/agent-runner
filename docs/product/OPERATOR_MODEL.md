# Operator Model

Agent Runner is a local CLI with an asynchronous STDIO MCP boundary over the
same durable runner. Operators start a named pipeline, observe its run ID and
public activity, answer bounded pending input, and resume explicit pauses. The
product does not require a daemon or network service.

## Configuration

Runner-root configuration is the only source of trusted profile
implementations and trusted command vectors. An ignored project configuration
may select safe aliases, role preferences, pipeline settings, and an artifact
root, but it cannot add executables, credentials, environment values, or new
host authority. CLI and MCP overrides have the documented highest precedence.

Resolved active roles, settings, artifact root, trusted commands, and optional
source-session lineage are frozen into a new run. Resume uses that snapshot and
does not silently adopt later configuration changes. `independent` is the
default mode; choosing `lazy` is always an explicit operator decision.

## CLI and MCP control

The CLI provides run, resume, status, pipeline discovery, and MCP server
commands. MCP exposes the same static pipeline registry through STDIO and keeps
standard output exclusively for protocol traffic. It never launches an editor;
pending clarification and product-decision input is represented as a structured
request with a revision and stable request ID.

Mutating MCP calls require idempotency keys. Intent is persisted before
mutation and a receipt before return. Work continues in a detached process, so
a client disconnect or wait cancellation ends only that client's wait and does
not create a second execution owner. A compatibility token prevents an old MCP
process from dispatching a newer or otherwise incompatible workflow.

## Durable state and local artifacts

Run state lives under the user's OS state directory, outside both the target
repository and task directory. Each transition is a complete write-ahead event
followed by atomic current-state replacement. The human-readable progress file
is derived and can be regenerated; the event journal remains authoritative.

Plan authoring writes its declared task artifacts. Plan execution and polishing
may place runner-owned clarification artifacts below the configured repository
artifact root only after Git proves the path is already ignored. The runner
does not edit target ignore rules.

One execution lease protects a mutating run. Plan execution and polishing also
hold a canonical-worktree lease so independently identified runs cannot mutate
the same checkout concurrently. Status and activity reads remain lock-free.

## Pauses, resume, and observability

Normal work is autonomous. The runner pauses for identified clarification or a
material product decision, provider unavailability, an external validation
blocker, exhausted correction budgets, version skew, unsafe Git state, or an
ambiguous effect. Each public pause exposes a finite reason, bounded evidence,
the safe resume checkpoint when one exists, and concrete next actions. It does
not expose prompts, transcripts, credentials, rejected provider output, or raw
diagnostics.

If an unexpected runner-owned invariant rejects a plan-execution finalization
transition, both CLI and MCP status expose the same bounded diagnostic and an
explicit retry from the retained `FINALIZE` checkpoint. Rejected finalization
evidence and native process output do not enter the pause record.

Public activity records the actor, phase, event kind, and concise message. The
active role and phase combine with lease ownership to distinguish running,
interrupted, and idle work without polling a provider or depending on a
heartbeat. An interrupted owner reconstructs work from durable state after
revalidating inputs and the repository.

Unexpected-issue reporting is an optional MCP-only operator action for behavior
that contradicts the documented runner contract. Expected pauses, invalid
input, configured limits, and environmental blockers are not unexpected
issues. Reports contain only caller-supplied bounded Markdown; the runner does
not attach logs or secrets automatically.
