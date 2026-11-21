# Stop and Custody Recovery Contracts

Read the matching topic before changing its contract. The [document map](../../README.md)
owns the change gate. Read only the affected owners and their required references.

| Topic                                                                 | Read when                                                                                                                                                      |
| --------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [Durable authentication-required pauses](authentication.md)           | Operator reauthentication, fork lineage, correction charges and pre-effect proof; read before changing authentication recovery.                                |
| [Durable availability episodes](availability.md)                      | Frozen policy, durable backoff, checkpoint reconciliation and retry continuity; read before changing transient availability recovery.                          |
| [Provider inactivity deadlines](inactivity.md)                        | Validated progress, watchdog expiry, consumed reconstruction and public proof; read before changing timeout recovery.                                          |
| [Interrupted Turns and One-Shot Effects](interrupted-turns.md)        | Durable invocation markers, interrupted reconstruction and consumed-effect verification; read before changing turn recovery or one-shot-effect reconciliation. |
| [Journal replay and recovery](journal.md)                             | Authoritative history, write-ahead publication, certificates, concurrent observation and leased repair; read before changing replay or recovery proof.         |
| [State-owned operator stop protocol](operator-stops.md)               | Revision-bound acceptance, supersession, immutable boundaries, receipts and settlement; read before changing stop accounting or ownership retention.           |
| [Bounded Ownership-Failure Diagnostics](ownership-diagnostics.md)     | Changing bounded ownership-failure diagnostics.                                                                                                                |
| [Process supervision and stop reconciliation](process-supervision.md) | Launch proof, descendant association, bounded retirement and reconciliation-only recovery; read before changing process custody.                               |
