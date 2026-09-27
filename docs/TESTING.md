# Testing

The [test-authoring skill](../.agents/skills/test-authoring/SKILL.md) owns test
necessity, minimalism, and determinism. Regressions belong around reproduced
defects and fragile boundaries, not around every edit.

## Ordinary gate

`npm run check` runs formatting verification, the fast test tier, and CLI help.
Its development budget is approximately 60 seconds. The fast tier retains
contract, policy, provider, Git, state, and focused integration checks.
`npm test -- path/to/file.test.js` runs selected coverage.

The test launcher uses a private temporary directory on executable runtime tmpfs
when available, otherwise the system temporary directory. This removes physical
disk latency from disposable fixtures without mocking filesystem operations or
disabling production synchronization. Set `AGENT_RUNNER_TEST_TMPDIR` to choose
an explicit writable, executable parent; an invalid override fails visibly.
The parent must remain visible inside process namespaces; `/dev/shm` does not,
because their private device mount hides it. Runtime tmpfs (`XDG_RUNTIME_DIR`
or Linux `/run/user/<uid>`) avoids that conflict.
The launcher reports storage and elapsed time and removes only its own directory.
These tests exercise process recovery, not survival of a machine power loss.
Fast files use bounded host-aware parallelism. The two system-wide process
containment suites run in a separate bounded batch so their process inspection
cannot race unrelated file workers. The durable slow tier retains its proven
four-file concurrency bound.

## Slow gate

`npm run test:slow` runs every `*.slow.test.js` file. Both tiers together cover
all test files; neither silently excludes a failed test.

| Suite                                                                     | Distinct guarantee                                                      | Run when changing                                                            |
| ------------------------------------------------------------------------- | ----------------------------------------------------------------------- | ---------------------------------------------------------------------------- |
| `test/runner.slow.test.js`                                                | Real-service orchestration, process ownership, durable stops and resume | Runner orchestration, process ownership, state or stop contracts             |
| `test/integration/workflows.slow.test.js`                                 | CLI/MCP workflow composition across real Git and durable storage        | Workflow gates, control-plane mutation, recovery or commit/handoff contracts |
| `test/mcp/control-plane.slow.test.js`                                     | Durable MCP actions, detached ownership, and recovery races             | MCP mutation, detached execution, action recovery, or stop supervision       |
| `test/state/operator-stops.slow.test.js`                                  | Journaled stop settlement, ownership, and concurrency recovery          | State mutation, operator-stop, ownership, or recovery contracts              |
| `pipelines/plan-execution/test/legacy-confirmation-recovery.slow.test.js` | Persisted legacy confirmation recovery with real commits                | Legacy migration, confirmation evidence or commit recovery                   |
| `pipelines/polishing/test/handoff-recovery.slow.test.js`                  | Real Git handoff recovery and legacy effect reconciliation              | Handoff settlement, legacy migration or completion recovery                  |

Run the affected slow coverage once before handing off a change to those
contracts, and the complete slow tier before release. A documentation-only or
unrelated policy edit does not require replaying all durable workflow matrices.
Record exactly which tier/files ran; an unrun slow check is not a pass.
Do not move a test to this tier merely because it fails or has a slow fixture:
first remove redundant setup and use lightweight effects for policy.

Legacy migration interaction coverage lives in
`pipelines/plan-execution/test/legacy-migrations.slow.test.js`; select it when
changing migration composition with confirmation, inventories, or implementation
evidence. Pure migration validation remains in the fast tier.

## Finalization

The canonical finalization skill applies both directly and inside Agent Runner;
there is no second divergent test policy. Establish any affected slow checks in
the run's inventory before work, rather than discovering new commands during
finalization. Keep the ordinary gate as `npm run check`.

Live provider tests remain opt-in as described in the repository README. Normal
tests never consume model turns. Repeated full-suite runs require a specific
unresolved risk, not a ritual.

Claude restricted-host launcher changes use deterministic public-adapter tests
with controlled bubblewrap processes for the commit gate. That coverage must
compare every x64 and arm64 BPF instruction, reject unsupported architectures
and filter tampering or setup failure, prove direct bubblewrap execution with
one user namespace and no fallback Claude helper, and retain provider
connectivity, environment scrubbing, argument rejection before payload
execution, and the complete command-isolation argument contract.
Access-policy coverage also proves that one compound `git log`, `git cat-file`,
`git branch -a`, and `ls` inspection succeeds in the read-only sandbox while
representative workspace, Git, and remote mutations fail, local-commit
readiness uses the same policy, and workspace-write settings stay unchanged.
One bounded capability-gated Linux process regression exercises the installed
bubblewrap direct-filter boundary without a model request, sleep, retry loop,
or slow-tier promotion. It does not replace post-install acceptance: after the
finalized commit is installed, the supervising agent starts a fresh real Claude
lazy plan-authoring run and requires preflight to advertise read-only,
workspace-write, and local-commit access plus a provider response before
dependent provider work continues.
