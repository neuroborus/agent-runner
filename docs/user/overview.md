# Agent Runner

It works as a level 4 software factory on
[Dan Shapiro's five levels of AI-assisted coding](https://simonwillison.net/2026/Jan/28/the-five-levels/):
you own the spec and the plan, but you don't have to write them by hand. Shape
them in a conversation with your coding agent, and the agent drives Agent Runner
over MCP: it starts the pipeline, waits for it, and brings product decisions
back to you. Inside the pipeline, agents implement and review each other's work,
and you review the result. It is not a level 5 "dark factory": a human still
reads what ships.

Agent Runner is a local CLI and STDIO MCP server for durable agent pipelines.

Use the [user map](README.md) for installation, configuration and operation.

Every registered pipeline is runnable through the CLI and local STDIO MCP.
Find the architecture and pipeline specifications in the matching source
checkout through its engineering document map, `docs/README.md`.
