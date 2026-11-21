# Provider inactivity deadlines

Read the affected sections before changing this contract. Use the [topic map](README.md)
for related owners and required reading routes.

Common run envelope version 17 freezes `providerInactivityTimeoutMs` and
`providerInactivityFingerprint`. The fingerprint is SHA-256 of the canonical
JSON object containing that timeout. Root/project configuration accepts only
integers from 1 through 2147483647 milliseconds, defaults to 1800000, and resolves
project over root. No role, CLI, or MCP override exists. Versions 1–16 normalize
to that default and null recovery; leased migration journals it without loading
configuration or changing pipeline progress. Journal continuity protects both
immutable fields and rejects a fabricated legacy recovery allowance.

`src/runner/inactivity.js` owns one watchdog per adapter invocation inside the
operator-stop monitor. Its injected timer makes policy tests deterministic.
Only the closed validated `onProgress` vocabulary resets the timer. Paired
command events maintain the aggregate count; a positive count suspends the
deadline until all owned commands complete, then starts a full interval.
Keepalives, bytes, liveness, unrelated notifications, and public observation do
not count. Local tool lifecycle events are meaningful progress but do not
suspend the deadline. Settlement drains timer persistence before returning.

Before aborting an inactive provider, the run store durably journals the bounded
`inactivity/expired` activity and `inactivityRecovery`: exactly `role`,
`checkpoint`, `attempt` (1 or 2), `status` (`expired` or `reconstructing`),
`reconstructionRevision` (null before attempt 2), `expiryRevision`, `configurationFingerprint`,
and the observed `contentFingerprint`. The state store records expiry while ownership is still active without advancing
the pipeline or changing other run fields. The marker
is separate from availability episodes and contains no native payloads or tool
content. Failure to persist evidence retires owned work without authorizing a
retry. Process/resource retirement remains mandatory before reconciliation.

Each pipeline reconciles its own read-only or writable checkpoint and any
partial correction before reconstruction. Safe content invalidates stale gates;
the existing charged-correction marker prevents double counting. Reconstruction
uses the complete durable prompt for the same role and never reforks a source.
The transition to attempt 2 is durable before launch. The adapter's optional
awaited `onFreshSession` callback reserves this same allowance before native
fresh fallback; false forbids that fallback. An expired attempt 2 pauses as
resumable `backend_unavailable` rather than entering availability backoff. Owner
loss does not replenish the allowance. Explicit resume after that pause permits
one invocation with attempt 2 still consumed; separate classified availability
failures retain their existing backoff, not another inactivity allowance.
The reconstruction revision consumes that continuation durably: only an
availability failure reconciled at or after the last reservation may authorize
another launch. An older episode cannot authorize replay after owner loss.

Only a returned provider response plus matching repository reconciliation clears
the marker. Pipelines report failed reconciliation at turn settlement; safety
pauses retain the marker without substituting a recovery error for the original
repository failure. Safe content/counter changes and that reset share one durable
transition, before output validation. The adapter's awaited `onCommitExecution`
callback runs after validated readiness and before the constrained executor: it
drains the watchdog and reconciles the readiness response against the existing
baseline. The executor, trusted validation commands, and runner-owned handoff
are outside this watchdog. A readiness expiry may retry only after existing
validated `commitExecutor: "not_started"` evidence and Git verification retire
the consumed authorization. Possible effects, policy failures, usage limits,
authentication requirements, and operator stops retain their precedence.

Common-envelope version 20 adds nullable `expiryRevision`, journaled only by an
actual watchdog expiry. Generic reconstruction consumes `reconstructionRevision`
without proving timeout. Versions 17–19 normalize missing expiry proof to null;
leased migration preserves the consumed allowance without inventing timeout
history. Proven expiry is required for inactivity retry and timeout-specific
correction allowances. An interrupted consumed reconstruction without expiry
proof uses `ERR_PROVIDER_RECONSTRUCTION_EXHAUSTED` and explicit recovery.

CLI status and MCP `inactivityRecovery` expose only role, checkpoint, attempt,
status, and `expiryProven`. Unproven activity and CLI state say reconstruction
rather than inactivity. Bounded `expired`, `reconstructing`, and `recovered` activity uses
the existing journal/projection transport. Client disconnect or canceled waits
change observation only; they cannot cancel or reset the watchdog.
