# MCP Observations and Waits

Read the affected sections before changing this contract. Use the [topic map](README.md)
for related owners and required reading routes.

`run_wait` is one revision-driven server-side wait that ends at an unresolved
`WAITING_FOR_USER`, `DONE`, `FAILED`, `CANCELED`, an `interrupted` execution
whose lease owner is positively `dead` or `replaced`, or its caller-selected
timeout. Positive owner loss interrupts a checkpoint requiring continuation even
between turns, with no active turn, execution process, preparation record, or
revision change. An owner can exit without changing any file, and Node reports
no exit for a non-child process, so the wait also watches lease files and runs a
read-only lease-owner probe once per second. The probe uses the same
classification as `run_status`, against the classification the caller already
inspected. Only a change to `dead` or `replaced` wakes the wait. The probe
reads no journal, takes no lease, and writes nothing, and a failed probe read
does not end the wait. `live`, `unverifiable`, and `none` (a released or
transferring lease) keep waiting, so recovery stays an explicit `run_resume`.
Optional MCP progress notifications carry only bounded public activity with
role labels; they do not wake a model or alter the run. Cancellation cancels
only that wait. Activity drains retain operation-local journal proof through
bounded concurrent-publication continuations using the [journal certificate rules](../recovery/journal.md). Exhaustion after a proved extension returns
`ERR_RUN_OBSERVATION_BUSY` with `retryable: true` as a structured MCP tool error
for `run_activity` or `run_wait`. It ends only that observation; a later explicit
observation is safe. MCP does not retry it automatically or classify other
errors by matching their code or prose.

An omitted `run_wait.timeoutMs` means 30 seconds and the public maximum is 24
hours; either deadline ends only the client wait. Internal detached-dispatch
and detached reconciliation uses bounded event-driven observation, while the
operator-stop monitor waits for a revision for at most one second at a time.
These are fixed correctness mechanics rather than user-work retry budgets.

MCP status and wait also project one bounded `execution` object. Its finite
`leaseOwner` is `none`, `live`, `dead`, `replaced`, or `unverifiable`, while
`processRecord` is `none` or `persisted`; neither field exposes process
identity. `state` remains the conservative action summary: `running` while the
lease owner is live or unverifiable, `interrupted` when a persisted active turn
or execution process/preparation record has no exclusionary owner, or when a
positively dead or replaced owner leaves a checkpoint requiring continuation,
and `idle` otherwise. Terminal states and unresolved `WAITING_FOR_USER` retain
their existing semantics; owner loss alone does not make them interrupted.
Nullable `role` and `phase` come only from the common run envelope. A read
applies the same exact same-host process-identity classification used for
exclusive acquisition without changing ownership. A timeout therefore
distinguishes live lease ownership, unresolved lease identity, and durable
process ownership without a heartbeat or journal polling.
`pipelines_list` projects descriptor-owned setting values, defaults, and
recommendations. Status, wait, and activity project the persisted resolved mode
without inactive role configuration or provider-private data. `run_activity`
remains an explicit cursor-based history read rather than a polling primitive.
Status and wait additionally expose only the pending stop kind and accepted
revision while reconciliation is incomplete; the request hash, suspended
checkpoint, and internal ownership evidence remain private.
