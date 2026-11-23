# Test Harness and Storage

Read the affected sections before changing this contract. Use the [topic map](README.md)
for related owners and required reading routes.

## Storage and execution

The test launcher uses a private temporary directory on executable runtime tmpfs
when available, otherwise the system temporary directory. This removes physical
disk latency from disposable fixtures without mocking filesystem operations or
disabling production synchronization. Set `AGENT_RUNNER_TEST_TMPDIR` to choose
an explicit writable, executable parent; an invalid override fails visibly.
Without an override, the launcher never uses a parent at or under Agent Runner's
fixed trusted mount root `/run/agent-runner`, using the sandbox's private `/tmp`
instead of the scratch mount inside trusted validation.
The parent must remain visible inside process namespaces; `/dev/shm` does not,
because their private device mount hides it. Runtime tmpfs (`XDG_RUNTIME_DIR`
or Linux `/run/user/<uid>`) avoids that conflict.
The launcher reports storage and total elapsed time and removes only its own
directory. Fast runs use the concise dot reporter. Selected and complete slow
runs use the concise spec reporter, which also reports the elapsed time of each
file without enforcing a duration limit. These tests exercise process recovery,
not survival of a machine power loss. Fast files use bounded host-aware
parallelism. The two system-wide process containment suites run in a separate
bounded batch so their process inspection cannot race unrelated file workers.
The durable slow tier retains its proven four-file concurrency bound.

## Scratch-request reporting

The optional scratch-request reporter collects only bounded failure locations
from the original invocation, across both fast batches or selected slow files.
It streams structured events without capturing native output or running
diagnostic retries. An exclusive original-harness claim prevents nested harnesses
from updating its report. Ordinary developer runs retain their diagnostic
behavior, including the original failure outcome if a diagnostic rerun passes.
Request allocation and report consumption by trusted execution are inactive;
focused fixtures exercise the producer without granting check evidence.
`test/trusted-attribution.test.js` owns codec, redaction, bounds, claim and stream
coverage; `test/test-command.test.js` owns actual original-harness invocation,
batch partitioning, selected slow files, nested claims and storage cleanup.
The [validation contract](../product/VALIDATION_AND_REVIEW.md) owns advisory limits.

## Interruption reporting

Follow the interruption-reporting rule in
[test-authoring](../../.agents/skills/test-authoring/SKILL.md).
