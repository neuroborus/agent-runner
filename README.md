# Agent Runner

Local CLI and STDIO MCP server for durable agent pipelines. Read the [overview](docs/user/overview.md).

## Quickstart

After installing the [requirements](#requirements), link the local CLI:

```bash
npm ci
npm link
```

Register the STDIO MCP server with the client you use, then restart it:

```bash
codex mcp add agent_runner -- agent-run mcp
claude mcp add --transport stdio --scope user agent_runner -- agent-run mcp
```

```text
Using Agent Runner, create a commit-by-commit plan for adding a new adapter
(with a modular, idiomatic design that reuses existing modules). If the plan is
satisfactory, use Agent Runner to execute it.
```

| Mode          | Quality | Speed | Token consumption | Meaning                                                         |
| ------------- | ------- | ----- | ----------------- | --------------------------------------------------------------- |
| `lazy`        | ★★★☆☆   | ★★★★★ | ★★☆☆☆             | Lower-consumption self-review without an independent Reviewer.  |
| `independent` | ★★★★☆   | ★★★☆☆ | ★★★★☆             | Recommended default with genuinely independent semantic review. |
| `combined`    | ★★★★★   | ★★☆☆☆ | ★★★★★             | Primary self-convergence followed by the full independent gate. |

`independent` is the default and recommended mode; resume keeps the saved mode.

Start with the [user map](docs/user/README.md) and the complete
[operator guide](docs/OPERATOR_GUIDE.md). In the matching source checkout,
engineering changes start at `docs/README.md`.

## Core Guarantees

Read [Core Guarantees](docs/user/guarantees.md#core-guarantees).

## Requirements

Read [Requirements](docs/user/requirements.md#requirements).

## Installation

Read [Installation](docs/user/installation.md#installation).

### Local application artifacts

Read [Local application artifacts](docs/user/candidates.md#local-application-artifacts).

### Approved npm releases

Read [Approved npm releases](docs/user/releases.md#approved-npm-releases).

### Operator updates

Read [Operator updates](docs/user/releases.md#operator-updates).

### Isolated candidate installation

Read [Isolated candidate installation](docs/user/candidates.md#isolated-candidate-installation).

### Pinned application payloads

Read [Pinned application payloads](docs/user/runtime-payloads.md#pinned-application-payloads).

## Pipelines

Read [Pipelines](docs/user/pipelines.md#pipelines).

### Plan authoring

Read [Plan authoring](docs/user/pipelines.md#plan-authoring).

### Candidate gates for execution and polishing

Read [Candidate gates for execution and polishing](docs/user/pipelines.md#candidate-gates-for-execution-and-polishing).

### Plan execution

Read [Plan execution](docs/user/pipelines.md#plan-execution).

### Polishing

Read [Polishing](docs/user/pipelines.md#polishing).

### Audit: discovery and finding verification

Read [Audit: discovery and finding verification](docs/user/pipelines.md#audit-discovery-and-finding-verification).

### Init

Read [Init](docs/user/pipelines.md#init).

## Configuration

Read [Configuration](docs/user/configuration.md#configuration).

## Task Inputs

Read [Task Inputs](docs/user/task-inputs.md#task-inputs).

## CLI

Read [CLI](docs/user/cli.md#cli).

## MCP

Read [MCP](docs/user/mcp.md#mcp).

## Provider Boundary

Read [Provider Boundary](docs/user/development.md#provider-boundary).

## Pipeline Boundary

Read [Pipeline Boundary](docs/user/pipelines.md#pipeline-boundary).

## Repository Layout

Read [Repository Layout](docs/user/development.md#repository-layout).

## Development

Read [Development](docs/user/development.md#development).
