# Installation

From the Agent Runner repository root, install the pinned dependencies and link
the executable into the active Node.js installation:

```bash
npm ci
npm link
command -v agent-run
agent-run --help
```

`npm link` exposes `agent-run` as a symbolic link to this checkout. Source-only
updates are therefore available to every newly started CLI or MCP process.
Rerun `npm ci` when dependencies change, and rerun `npm link` only after the
link or active Node.js installation changes.

Register the linked executable as a user-level STDIO MCP server in each agent
client you use:

```bash
# Codex
codex mcp add agent_runner -- agent-run mcp
codex mcp get agent_runner

# Claude Code
claude mcp add --transport stdio --scope user agent_runner -- agent-run mcp
claude mcp get agent_runner
```

Restart the agent client after adding the server or updating Agent Runner so it
starts a fresh MCP process. Existing durable runs remain in runner state and can
be resumed after restart. Configure the longer Codex tool timeout shown in
[MCP](mcp.md#mcp) before waiting on long runs.

For repository development without a linked executable, run
`node bin/agent-run.js` directly or use the absolute executable path in the MCP
configuration.
