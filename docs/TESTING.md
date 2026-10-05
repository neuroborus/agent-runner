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
Without an override, the launcher never uses a parent at or under Agent Runner's
fixed trusted mount root `/run/agent-runner`, using the sandbox's private `/tmp`
instead of the scratch mount inside trusted validation.
The parent must remain visible inside process namespaces; `/dev/shm` does not,
because their private device mount hides it. Runtime tmpfs (`XDG_RUNTIME_DIR`
or Linux `/run/user/<uid>`) avoids that conflict.
The launcher reports storage and total elapsed time and removes only its own
directory. Each fast batch uses Node 24's multiple-reporter interface to capture
dot output and private TAP diagnostics from one invocation. Successful output
stays compact; a failed batch additionally forwards its original TAP report,
including native failure types and error codes, opaque thrown values, test
names, assertions, stacks, and Node-provided locations. No test is rerun for
diagnostics, and filenames are never inferred from titles. Private reporter
files stay within the launcher-owned directory and are removed through the
same cleanup boundary on success or failure. Selected and complete slow
runs retain spec output from their one invocation, including the elapsed time of
each file without enforcing a duration limit. These tests exercise process
recovery, not survival of a machine power loss. Fast files use bounded host-aware
parallelism. The two system-wide process containment suites run in a separate
bounded batch so their process inspection cannot race unrelated file workers.
The durable slow tier retains its proven four-file concurrency bound.

Launcher and diagnostic-collector changes use focused fast coverage in
`test/test-command.test.js` and `test/trusted-diagnostics.test.js`; they do not
require unrelated slow workflow matrices. A production process-settlement or
containment repair additionally requires the operator-stop suite listed below,
with focused owned-process regressions for its proved cause. Original failure
output may be inspected transiently; runner-trusted evidence retains only the
bounded normalized diagnostics defined by the architecture contract.
`scripts/index.js` exports the `scripts/test-selection.js` capability shared by
the supported exact trusted repository-check recognizer without changing roots,
tiers, explicit arguments, ordering, batches or concurrency. Trusted failure
evidence can retain only a canonical selected test identity from a failed TAP
diagnostic location, bound to the original inspected content through reload and
CLI/MCP projection.
Runner-measured elapsed milliseconds are separate from launcher/per-file
durations and remain available for successful checks without retaining output.
Use controlled clocks for timing regressions; do not add wall-clock assertions.
When executing against the Runner's own checkout, load changed diagnostic and
timing code through an owner-settled public pause/resume with a fresh process
before first finalization if necessary; preserve frozen inputs and state.

Owned-process fixture repairs use `test/agents/owned-process.test.js`. Keep the
supervisor's real bounded incomplete-inspection retries separate from controlled
parent observations: an uncertain parent must retain registration, so a fixture
expecting durable deregistration supplies an empty parent view and races callback
entry against premature completion. Keep the distinct persistent and transient
parent-uncertainty regressions. Owner-loss fixtures acknowledge entry into the
pending registration callback through IPC, before or after its simulated durable
side effect, and compare recorded process identity before retirement. Await owned
process closure and identity-checked supervisor retirement during teardown.
These test-only synchronization changes do not require the slow operator-stop
suite; production supervision, containment and timeout changes do.

## Native proof harness

The CI-private native harness has its own explicit local invocation:
`node --test ci/native/harness.test.js`. It uses synthetic evidence and injected
effects only, outside the ordinary test discovery roots. Native system and
protected provider cases remain external and must never enter local FINALIZE.
The included `ci/native/composition.test.js` checks version compatibility, protected
source/plan admission, held identity and loader/build/package binding rejection,
reader lifetime, diagnostic failure, incomplete effect ledgers and strict
full-inventory aggregation. Its pure targeted
invocation is `node ci/native/composition.test.js`; synthetic GO fixtures are
evidence-contract tests, never native acceptance. Native readers, audit changes,
helper builds, provider transport and model turns remain external CI setup.

Its [owning document](../ci/native/README.md) defines the proof boundary; passing
this harness establishes reporting/protocol behavior, not native acceptance.

## Slow gate

`npm run test:slow` runs every `*.slow.test.js` file in the ordinary discovery
roots. Both ordinary tiers together cover those test files; neither silently
excludes a failed test. Use
`npm run test:slow -- path/to/file.slow.test.js` to run an affected file, or
pass multiple paths for one affected batch; selected files retain the same
bounded runner and per-file timing output.

| Suite                                                                     | Distinct observable guarantee                                                                                                           | Run when changing                                                                                                                                  |
| ------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| `test/integration/cli-workflows.slow.test.js`                             | Root CLI composition produces one plan artifact, one exact-subject commit, and one uncommitted handoff                                  | CLI projection or root plan-authoring, plan-execution, polishing, real-Git commit, or handoff composition                                          |
| `test/integration/mcp-workflows.slow.test.js`                             | A detached MCP workflow continues through durable runner state after the requesting client is replaced                                  | MCP-to-runner workflow composition, detached continuation, client replacement, or cross-capability durable state                                   |
| `test/mcp/control-plane.slow.test.js`                                     | Detached STDIO dispatch preserves protocol cleanliness and exactly owned durable intents and receipts                                   | MCP STDIO, detached starts or stops, action receipts, disconnects, waits, restart or version skew, or execution-owner contention                   |
| `test/runner-orchestration.slow.test.js`                                  | Root orchestration preserves configuration, sessions, migrations, trusted snapshots, and worktree order                                 | Runner configuration or source sessions, runtime migration, trusted preflight snapshots, worktree serialization, or root service wiring            |
| `test/runner-operator-stops.slow.test.js`                                 | Runner stops settle owned processes and raced commit or handoff effects without losing writable content                                 | Runner operator stops, process settlement or containment, commit or handoff races, execution-storage cleanup, or partial-content resume            |
| `test/runner-effects.slow.test.js`                                        | Commit effects settle exactly once across interruption, verification, and deferred checkpoints                                          | Runner Git/state effect dispatch, commit authorization or verification, deferred settlement, or consumed-effect recovery                           |
| `test/state/operator-stops.slow.test.js`                                  | State journals serialize stop publication, leases, ownership transfer, process identity, and races                                      | State actions or journals, publication boundaries, leases, process identity, worktree ownership transfer, or stop concurrency                      |
| `pipelines/plan-execution/test/legacy-confirmation-recovery.slow.test.js` | Journal-proven confirmation and diagnosed check/fix reconstruction preserve commits, content and accounting across refusals and restart | Plan-execution recovery eligibility or proof, journal publication boundaries, verified commit recovery, partial-content resume or execution leases |
| `pipelines/plan-execution/test/legacy-migrations.slow.test.js`            | Authentic persisted migration history carries legacy confirmation proof into the current contract                                       | Persisted plan-execution migration composition involving confirmation proof, inventories, implementation evidence, or historical events            |
| `pipelines/polishing/test/handoff-recovery.slow.test.js`                  | Legacy handoff recovery distinguishes a completed real-Git effect from a partial effect                                                 | Polishing handoff settlement, legacy handoff migration, completed-effect reconciliation, or partial-effect failure                                 |

The CLI workflow suite also proves that a readiness-wrapped owned command
retains safe failure diagnostics through persistence/reload, finding-resolution
context, and CLI/MCP projection. It reuses separate isolation-policy coverage;
it does not establish native provider support.

Run the affected slow coverage once before handing off a change to the listed
contracts. After the ordinary `npm run check` gate, run the complete
`npm run test:slow` tier as the release gate. A documentation-only or unrelated
policy edit does not require replaying all durable workflow matrices. Record
exactly which tier/files ran; an unrun slow check is not a pass. Do not move a
test to this tier merely because it fails or has a slow fixture: first remove
redundant setup and use lightweight effects for policy. Pure migration
validation remains in the fast tier.

## Finalization

The canonical finalization skill applies both directly and inside Agent Runner;
there is no second divergent test policy. Establish affected slow checks before
work. Plan execution discovers a complete procedure for each canonical plan
step: `npm run check` applies to every step, while a slow check applies only to
steps changing its documented guarantee. Persist those assignments at bootstrap
and retain later checks for their owning steps. Trusted selection alone does
not make a command applicable to every step. Polishing retains its single
workspace inventory.

Run each applicable slow batch for the finalized fingerprint with the existing
concurrency. Reuse accepted evidence on unchanged-fingerprint confirmation
resume; repairs or invalidated evidence require fresh affected validation.
Preparation of the complete trusted catalog is separate from check execution.
Keep the ordinary gate as `npm run check`; never fold slow matrices into it.
The fast execution `validation-schedule.test.js` uses injected effects to cover
two-step selection in all modes, persisted reload, confirmation reuse, and
migration of pending rework and correction accounting.

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
