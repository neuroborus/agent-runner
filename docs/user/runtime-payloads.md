# Pinned application payloads

The executable enters a standard-library bootstrap before importing the
application. An assembled installation is verified against its complete release
manifest and materialized into a user-owned read-only payload. Application code,
bundled dependencies, delayed imports and runtime resources then resolve from
that payload, so replacing the outer package cannot change a running process.

Payload storage uses `$XDG_DATA_HOME/agent-runner/runtime` on Linux, falling back
to `$HOME/.local/share/agent-runner/runtime`; macOS uses
`~/Library/Application Support/agent-runner/runtime`, and Windows uses
`%LOCALAPPDATA%\agent-runner\runtime`. These location mappings do not extend
execution-platform acceptance. Settings, credentials and durable run state stay
outside payloads. The legacy configuration fallback retains the original outer
installation path; frozen run configuration is never resolved again.

Preparation publishes only a complete verified tree through an exclusive
reference, preserving any destination that appears concurrently. Processes use
the verified physical tree path. Partial preparations remain separate and are
never selected or reused. Existing damaged payloads fail closed instead of being
overwritten or repaired. MCP detached
continuations verify the same payload and exact Node executable identity before
launch, then verify the binding again before application imports. They retain
the existing compatibility and dispatch-admission gates.

Git checkouts, including `npm link` development, remain development-managed and
create no payload storage. Application startup through the executable owns
pinning; direct source API imports do not bootstrap an installed process.
Payload preparation performs no package installation, controller activation,
run migration or implicit resume. Normal startup reads an already-published
selection before application imports; detached continuations retain their exact
original payload. Linked development bypasses installed-runtime selection.

Pinned CLI/MCP processes register their exact payload and process identity in
user state. New runs, resumes and detached commands pass the same serialized
admission boundary. Activation is deferred while positively associated users
of another payload remain alive; an unverifiable owner remains blocking.
Unrelated host processes are neither enumerated nor signaled. Explicit runtime
activation selects a verified payload or durably queues it for the next safe
admission. A racing obsolete start cannot bypass that selection. Previous
payloads and saved progress remain intact. Resume remains an explicit operation
using supported leased migrations and the run's original frozen configuration;
unknown forward versions fail without modifying progress. The root capability
adds no public update command, automatic update, migration or resume authority.
