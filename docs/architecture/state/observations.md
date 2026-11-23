# Durable Observations and Measurements

Read the affected sections before changing this contract. Use the [topic map](README.md)
for related owners and required reading routes.

## Observation Record

Common run-envelope version 18 adds nullable `observations`. Legacy absence
normalizes to `null` on lock-free reads; the existing leased runtime migration
persists that absence without inventing usage or rewriting historical events.
`src/state/observations.js` owns the closed version-1 observation record: the
latest 32 runner attempts and a saturating count of omitted attempts. Each
attempt binds its starting revision as its runner-owned ID to the exact role
and checkpoint, with at most nine sealed native attempt/turn records. Replacement
and recovery retain earlier facts and mark open attempts interrupted. Terminal
attempts and accepted native records are immutable; stale callbacks and duplicate
native ordinals cannot overwrite them. Journal continuity validates these rules.

## Batched Persistence

The runner batches synchronous adapter observations in a bounded map, flushing
before native fresh-session fallback and at invocation termination, including
failure and cancellation. Observation notifications never trigger state writes or
timers. Unchanged batches do not publish revisions. Accepted batches
use the existing leased write-ahead append before atomic snapshot replacement;
recovery repairs interrupted publication and journals incomplete retirement.
Startup observation persistence precedes provider inactivity timing; fallback
flushes neither suspend nor reset the existing deadline. Terminal persistence
runs after the watchdog closes. Inactivity publication also uses the same
serialized write queue so expiry can race a diagnostic batch safely.
It shares the stop monitor's write queue with process and resource callbacks so
diagnostics cannot contend with the owner's stop publication.
Diagnostic writes may finish while process cleanup or a stop is pending, without
changing workflow, correction, retry, process, or effect authority. Interrupted
observation retirement alone qualifies as detached dispatch preparation only
when all other state remains unchanged.

Native `last` and `cumulative` snapshots, their scope and inclusion flags, and
nullable counters remain unchanged; no snapshots or inclusive subsets are added
together. Runner accounting is `reported` only for a completed invocation with
nonempty, entirely reported evidence and no known incomplete facts; otherwise
it is `incomplete`, including unobserved terminal attempts. This describes
observed reporting, not complete historical token consumption. Batches contain
only the normalized payload-free adapter contract. Persistence errors cannot
replace an established provider, safety, ownership, or effect failure.

## Byte Measurements

Common run-envelope version 19 adds an optional closed `measurements` object
on each runner attempt in the version-1 observation record. Version 18 rejects
this field. Its records migrate through the leased runtime migration before
measurement-bearing attempts can begin, changing the detached compatibility
token so mixed-version dispatch rejects before accessing run state.
After migration, leased recovery retires interrupted observations before any
continuation, including verification-only recovery of a consumed commit.
Retirement waits for process-ownership proof and resource cleanup; an unresolved
ownership failure leaves diagnostic state unchanged.
Legacy attempts omit measurements and project `null`;
reads and later attempts preserve the historical shape without backfilling or
rewriting events. New attempts record nullable nonnegative safe integer
`promptBytes`, `recoveryPromptBytes`, `schemaBytes`, `resultBytes`, and
`structuredResultBytes`, plus explicitly unknown `referencedFileCount` and
`referencedFileBytes` (both null). The runner measures UTF-8 strings with
`Buffer.byteLength` and schema/structured JSON with `JSON.stringify`. These are
the supplied request prompt and complete reconstruction prompt, supplied schema,
and returned adapter output and structured object; they exclude native wrappers,
implicit provider schemas, prior session context, and referenced-file contents.
The reconstruction prompt is available context, not proof that fallback sent it.
An absent schema, missing response, or unavailable serialization remains null.
Result measurements settle only on completed invocations; source measurements
and terminal evidence cannot be rewritten. No content or file path is stored.

## Public Projection

`projectObservations` is the state-owned allowlisted projection used by runner
results, CLI status, and MCP status/wait. It preserves attempt correlation,
retention omissions, uncertainty, native scopes, inclusion rules, and bounded
counts. CLI renders the latest attempt; MCP retains the bounded attempt list.
State-owned `observations` activity is journaled at start, changed fallback
batches, and terminal settlement, and the runner publishes the same concise
events live. No native payload or arbitrary failure text enters either surface.
Byte measurements and token snapshots are separate diagnostics, never capacity
controls, consumption totals, progress, or permission to replay an effect.
