# Requirements

- Node.js 24 LTS: `>=24 <25`
- Git
- Codex CLI 0.147.0 or newer stable and/or Claude Code 2.1.233 or newer stable,
  depending on the selected role backends
- Linux with usable user and PID namespaces and system-installed `bubblewrap`
  for owned execution and trusted validation, plus `socat` for the Claude backend
  and iproute2 `ss` for Claude versions that pass sandbox descriptors

Claude does not require host `CAP_SYS_ADMIN`. It prefers its full native
sandbox and may automatically use a restricted-host composition only when an
exact probe proves that nested user namespaces are denied and that a private
Runner command launcher validates and strengthens Claude's effective
bubblewrap invocation. The Claude CLI and its provider transport remain on the
host, while each model-issued command crosses one bubblewrap boundary with
private user, PID, mount, network, `/proc`, `/tmp`, and `/run` views. There is
no configuration override. If either composition cannot prove a requested
read-only, workspace-write, or local-commit mode, the run fails early with a
bounded unsupported-backend diagnosis through both CLI and MCP.

The project uses native ES modules. External runtime dependencies comprise the
official Node MCP server SDK and its schema library.
