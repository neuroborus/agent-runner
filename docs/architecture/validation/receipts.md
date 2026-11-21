# Trusted Validation Receipts and Attribution

Read the affected sections before changing this contract. Use the [topic map](README.md)
for related owners and required reading routes.

## Attempt timing

Completed bounded receipts append a Runner-measured attempt elapsed-time
sentence in milliseconds, rounded to three decimal places. The service's
injectable clock defaults to `process.hrtime.bigint()` and is independent of
executor deadline clocks. Measurement starts after admission and the bound
workspace snapshot, immediately before effectful preparation; it includes
allocation, acquisition, source projection, sandbox preparation, invocation,
verified process retirement, resource cleanup and the final safety check.
Preflight and capability-availability probes produce no check timing evidence.
The sentence distinguishes blockage before executor invocation from an invoked
executor attempt; invocation alone does not prove payload admission or success.
The outcome sentence retains exit, signal, timeout or bounded blockage meaning.
Cancellation, uncertain retirement/cleanup, invalid executor results and safety
failures preserve their errors without publishing completed receipts. No command
streams, provider text or wall-clock subtraction supply this measurement.
Both coding pipelines retain the sentence in their existing evidence lists,
including persistence, reload and the terminal confirmation's validation tuple;
receipt/state shapes and command, content, configuration and infrastructure
bindings are unchanged. Existing receipts without elapsed evidence remain valid
with timing unknown, without migration or invented historical measurements.

## Test attribution producer

The private `trusted-validation/test-attribution.js` producer/codec and
`scripts/test-reporter.js` cooperate with `scripts/test.js` through an optional
canonical request in `.agent-runner-test-attribution` under the existing
`AGENT_RUNNER_SCRATCH` binding. The request carries a fresh nonce and exact
command identity. An exclusive claim binds the original harness PID before test
launch; only its direct reporter children can update the preallocated report.
Both fast batches share that report, and selected slow files use the same
structured event stream. Reporting mode discards native output and performs no
diagnostic reruns; ordinary developer diagnostics retain their existing behavior.
Discovery, batching, order, concurrency, temporary storage, and original
exit/signal handling remain unchanged.

The complete canonical UTF-8 report is at most 4,096 bytes and retains at most
four locations independently of event count. Each location contains only a
canonical repository-relative test-source path of at most 256 UTF-8 bytes,
nullable integer line/column coordinates from 1 through 1,000,000, and a
metadata-derived class: `test-failure`, `subtests`, `timeout`, `cancelled`, or
`uncaught`. Titles, messages, assertion values, stacks, stdout/stderr, external
paths, and provider data are excluded. Invalid requests/reports and unavailable
storage cannot change test outcomes. This is producer-only infrastructure:
the trusted service neither allocates requests nor consumes reports yet, and
pipeline evidence and retry authority remain unchanged.
