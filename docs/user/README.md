# User documentation

Use this map after the [root quickstart](../../README.md#quickstart). Read the
matching topic before preparing an installation, inspecting a candidate,
changing the selected application version, configuring a new run, using or
recovering runs through CLI or MCP, or understanding workflows and development.

The standalone package includes these topics and the
[common operator guide](../OPERATOR_GUIDE.md).
Read source paths and section references in the matching checkout, using
`docs/README.md` as the engineering map.

| Topic                                              | Read when                                                                                                                                       |
| -------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| [Local candidates](candidates.md)                  | Assembling and inspecting an artifact or installing it into an isolated private prefix; owns both client registration examples for that prefix. |
| [CLI recovery](cli-recovery.md)                    | Inspecting state and status or resuming, pausing, cancelling or recovering a run from the command line.                                         |
| [CLI reference](cli.md)                            | Running commands, authoring or executing custom plans, editing guidance, managing issues, selecting preferences or forking a source session.    |
| [Configuration](configuration.md)                  | Creating or migrating user settings, selecting project infrastructure or resolving role preferences and precedence.                             |
| [Development guide](development.md)                | Understanding provider ownership, the repository layout, canonical skills, development commands and opt-in smoke tests.                         |
| [Core guarantees](guarantees.md)                   | Understanding lifecycle, role permissions, modes and safety boundaries.                                                                         |
| [Installation](installation.md)                    | Installing pinned checkout dependencies, linking the CLI, registering a client or restarting after updates.                                     |
| [MCP supervision](mcp-supervision.md)              | Waiting for, responding to, stopping or recovering a run through MCP and inspecting public projections.                                         |
| [MCP reference](mcp.md)                            | Configuring a server, discovering tools, starting runs, updating guidance or managing the issue backlog.                                        |
| [Agent Runner](overview.md)                        | Understanding Agent Runner and its human review model.                                                                                          |
| [Pipeline settings](pipeline-settings.md)          | Selecting modes, defaults, correction limits, commit-size settings or finalization guidance.                                                    |
| [Pipelines](pipelines.md)                          | Selecting a pipeline or understanding workflow gates, mode diagrams, descriptors, init and audit.                                               |
| [Provider recovery](provider-recovery.md)          | Configuring provider inactivity and availability or recovering authentication and disposable sessions.                                          |
| [Releases and updates](releases.md)                | Checking publication approval, inspecting compatibility or deliberately preparing/applying an exact update.                                     |
| [Requirements](requirements.md)                    | Checking Node, Git, provider and Linux isolation prerequisites.                                                                                 |
| [Pinned application payloads](runtime-payloads.md) | Understanding installed resource pinning, storage, detached launch, admission and explicit resume boundaries.                                   |
| [Task inputs](task-inputs.md)                      | Preparing task directories and locating the owning plan contracts.                                                                              |
| [Trusted validation](trusted-validation.md)        | Declaring command vectors, deadlines, isolation, source projection, transient build storage or pinned artifacts.                                |

The [canonical configuration example](configuration.example.json) ships as a regular
resource; the checkout also exposes it through `.agent-runner.example.json`.
