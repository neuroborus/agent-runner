# MCP Architecture Contracts

Read the matching topic before changing its contract. The [document map](../../README.md)
owns the change gate. Read only the affected owners and their required references.

| Topic                                               | Read when                                                                                                                                                            |
| --------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [Bounded Action-Free Continuation](continuation.md) | Revision-bound admission, correlated readiness, exact-key recovery and safe failure diagnostics; read before changing action-free continuation or dispatch recovery. |
| [MCP Control Plane](control-plane.md)               | STDIO tools, strict schemas, shared capability delegation, mode and source-session fields; read before changing transport or tool contracts.                         |
| [MCP Actions and Detached Dispatch](dispatch.md)    | Durable idempotency, start/respond/resume launch, exclusive ownership and stop reconciliation; read before changing mutation or detached execution.                  |
| [MCP Observations and Waits](observations.md)       | Status, activity, wait deadlines, cancellation and public execution projections; read before changing observation behavior.                                          |
