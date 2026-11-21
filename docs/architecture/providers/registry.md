# Provider Capability Internals

Read the affected sections before changing this contract. Use the [topic map](README.md)
for related owners and required reading routes.

The Claude provider lives under `src/agents/claude/` behind its provider
`index.js`. The root agent boundary imports only that index; the adapter,
local-commit executor, and isolation-policy selector remain private siblings
that own Claude processes, flags, parsing, sessions, sandbox composition, and
native failure recognition.

The Codex provider lives under `src/agents/codex/` behind its provider
`index.js`. The root agent boundary imports only that index; the adapter, App
Server transport, local-commit executor, and workspace storage remain private
siblings that own Codex processes, protocols, flags, parsing, and sessions.
`directory-policy.js` composes the public workspace inspection/snapshot service
with Codex named permissions; it never duplicates filesystem control discovery.
The private Codex `schema.js` validates the effective response schema before
any provider activity in `run`, including local-commit readiness. Its recursive
keyword allowlist and structural checks supplement the shared JSON,
strict-object, size, and depth checks without imposing Codex restrictions on
other adapters. It traverses schema positions rather than property names or
literal data, permits resolved local recursive references, and rejects
unsupported declarations with terminal `ERR_INVALID_CODEX_SCHEMA` before
probing, spawning, or recovery. This input-contract error is neither backend
unavailability nor malformed-output correction. Pipeline-owned normalizers
remain authoritative for semantic constraints such as terminal finding-ID
uniqueness that the portable response schemas cannot express.

The root `src/agents/index.js` is the only agent API consumed outside the agent
capability. Its private `registry.js` defines one frozen, source-controlled
descriptor per provider. A descriptor binds the backend ID to its adapter
factory, client-attribution support, execution-option validation,
trusted-profile normalization and resolution, source-session fork capability,
and one `failures` hook containing a finite class set and classifier. The
classifier is provider-private; the registry validates its provider-neutral
result before the public agent boundary exposes it. Configuration validation,
runner adapter construction and source checks, normalized failures, and MCP
backend schemas all derive from that registry. Tests may inject another complete
descriptor; production has no dynamic discovery, plugin loading, or
provider-specific pipeline branches.

The public agent boundary owns one strict, frozen client-attribution shape with
exactly `name` and `title`, plus the generic `agent_runner` / `Agent Runner`
default. Both strings are non-empty, trimmed, bounded to 256 characters, and
free of unsafe control, line-separator, and bidirectional formatting
characters. Registry construction passes only a normalized frozen value into
each adapter factory, while the descriptor states whether a provider can
transport a custom value. Codex sends both strings through App Server
`clientInfo` and keeps the package version in that same handshake. Claude's
documented CLI has no client-identity transport: its generic default remains
usable, while a custom value fails its capability probe before provider
activity. Neither adapter maps client attribution into native session names,
commit attribution, or undocumented environment variables, and bounded
failures retain none of its values. Provider-visible origin identity does not
promise a distinct provider dashboard category.
