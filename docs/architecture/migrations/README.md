# Supported Migration Contracts

Read the matching topic before changing its contract. The [document map](../../README.md)
owns the change gate. Read only the affected owners and their required references.

| Topic                                                               | Read when                                                                                                                                                      |
| ------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [Common Run-Envelope Migrations](common-envelope.md)                | Versioned shapes, saved-role defaults, lock-free projection and leased atomic migration; read before changing common persistence compatibility.                |
| [Plan-Authoring Migrations](plan-authoring.md)                      | Legacy mode and lazy-checkpoint correction initialization; read before changing authoring migration behavior.                                                  |
| [Plan-Execution Migrations](plan-execution.md)                      | Commit-effect safety, scoped schedules, bounded bootstrap and historical gate/correction migrations; read before changing execution compatibility or recovery. |
| [Polishing Migrations](polishing.md)                                | Validation, correction, candidate/terminal gates and runner-owned handoff migrations; read before changing polishing compatibility or recovery.                |
| [Shared Validation-Inventory Migrations](validation-inventories.md) | Historical execution/polishing inventory, capacity and evidence migration rules; read before changing either pipeline's legacy validation bindings.            |
