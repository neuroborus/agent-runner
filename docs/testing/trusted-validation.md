# Trusted Validation Coverage

Read the affected sections before changing this contract. Use the [topic map](README.md)
for related owners and required reading routes.

## Timing and storage

Fast `test/trusted-timing.test.js` uses an injected monotonic clock and executor
to distinguish outcomes, pre-invocation blockage, preparation-only availability,
rejected admission and incomplete/unsafe attempts without sleeps or wall-clock
assertions. `test/trusted-storage.test.js` binds the interval to real resource
publication, controlled process retirement, cleanup and the final safety check;
uncertain cleanup cannot publish a receipt. The execution pipeline's
`trusted-timing.test.js` carries a real service-generated receipt through saved
state reload and terminal confirmation, rejecting changed tuple evidence without
rerunning the check. Existing unmeasured receipt and legacy fixtures remain
valid. These cases do not attest the orchestration, CLI/MCP workflow/control,
operator-stop, effect-recovery, legacy-compatibility or release-pack slow gates.
Use available Runner measurements for the advisory target and keep unavailable
historical/controller timing unknown; never rerun only for missing telemetry.

## Scratch reporter and harness

Read the [current contract](harness.md#test-harness-and-storage).
