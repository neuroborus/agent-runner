# Slow and Release Gates

Read the affected sections before changing this contract. Use the [topic map](README.md)
for related owners and required reading routes.

## Exact-artifact package installation

`test/package-install.slow.test.js` owns actual offline installation of the exact
inspected candidate tarball into a new private prefix outside the checkout. It
checks installed bytes/modes, Node metadata, real private workspace imports,
the executable on PATH, CLI help/version, MCP initialize/list-tools/read-only
discovery and transport-EOF shutdown. The installed processes use only bundled
dependencies, with no checkout module resolution, workspace links, inherited
Node overrides, personal settings or live providers. The test consumes the [candidate installation](../user/candidates.md#isolated-candidate-installation)
vector and the server commands from both client-registration examples;
it never invokes clients or writes their registration. Delayed guidance remains
complete after moving only the fixture's outer package, and shutdown retires the
fixture admission without creating a run or project artifacts.
All home, XDG configuration/state/data, npm/Node cache and smoke storage is
private and disposable under the declared scratch/cache capabilities. Every
owned child is awaited before the existing descriptor-bound runtime fixture
cleanup restores only its own directories' write/search access and removes them.
No active controller, existing global/native link or publication is changed. This suite
proves local Linux installation/protocol acceptance, not live-provider or new
native-platform support. Required coverage is never satisfied by an unrun or
failed invocation; complete slow includes it and replaces no separately selected
`npm run test:slow -- test/package-install.slow.test.js` requirement.
Release CI may supply `AGENT_RUNNER_RELEASE_CANDIDATE` pointing to its exact
candidate receipt. That path verifies the archive/manifest, source commit and
lock identity and installs a private copy of the verified byte snapshot, without
repacking or reducing assertions.
Both the separate package-install command and complete slow still run. An unset
variable retains fresh candidate assembly for ordinary local validation.

## Audit recovery

Slow `test/runner-audit-recovery.slow.test.js` owns actual cold journal reloads
across exhaustion retirement, pause clearing before launch and acknowledged-child
response loss. Combined directory coverage imports exercised version-7 evidence
through the store creation boundary and proves migration preserves pending
revisions, rejected/hypothesis dispositions, receipts, correction feedback,
report bytes, original reservations and finite budgets. Missing or incomplete
decisions add no confirmation; only the complete selected gate accepts current
versions. Lazy Git-scope coverage composes availability and controlled inactivity
with repeated exhaustion without another source fork or inactive-role work.
A Git-scope case with more than 10,000 synthetic files beneath the fixture
control directory reproduces the bounded-baseline regression through deferred
capture, provider-policy recording and continuation past the first CLARIFY
transition; snapshots of that tree take seconds each, so it stays in this tier.
Independent coverage retains finding-Reviewer separation and matching redacted
CLI status and MCP status/wait explanations, null-action recovery and inert
completion. Separate failure/cancellation cases retain terminal dispositions
after exhaustion without new provider work or report publication on cold resume.
Provider responses, clocks and interruption boundaries are injected;
these tests use no live provider, sleeps or canonical-journal edits.
Run `npm run test:slow -- test/runner-audit-recovery.slow.test.js` when changing
audit recovery, migration, native selection, persisted audit baselines or their
public projections. The complete slow release gate includes it automatically;
it replaces no existing or separately selected Runner-trusted check.

## Suite inventory

| Suite                                                                     | Distinct observable guarantee                                                                                                           | Run when changing                                                                                                                                                           |
| ------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `test/runtime-pinning.slow.test.js`                                       | Running and detached synthetic applications retain the complete pinned payload after outer replacement; drift blocks another launch     | Startup/bootstrap, runtime manifests or storage, delayed resources, Node identity, detached launch                                                                          |
| `test/release-pack.slow.test.js`                                          | Actual npm tarball matches the complete assembled production application, real dependencies, modes and resources                        | Release assembly, file allowlists, lock closure, package metadata or runtime resources                                                                                      |
| `test/package-install.slow.test.js`                                       | Exact inspected bytes install outside the checkout and expose pinned CLI/MCP behavior with complete teardown                            | Packaging/release gates, candidate installation/activation, installed CLI/MCP update contracts, or final provider/operator installation acceptance                          |
| `test/integration/cli-workflows.slow.test.js`                             | Root CLI composition produces one plan artifact, one exact-subject commit, and one uncommitted handoff                                  | CLI projection or root plan-authoring, plan-execution, polishing, real-Git commit, or handoff composition                                                                   |
| `test/integration/mcp-workflows.slow.test.js`                             | A detached MCP workflow continues through durable runner state after the requesting client is replaced                                  | MCP-to-runner workflow composition, detached continuation, client replacement, or cross-capability durable state                                                            |
| `test/mcp/control-plane.slow.test.js`                                     | Detached STDIO dispatch preserves protocol cleanliness and exactly owned durable intents and receipts                                   | MCP STDIO, detached starts or stops, action receipts, disconnects, waits, restart or version skew, or execution-owner contention                                            |
| `test/runner-orchestration.slow.test.js`                                  | Root orchestration preserves configuration, sessions, migrations, trusted snapshots, and worktree order                                 | Runner configuration or source sessions, runtime migration, trusted preflight snapshots, worktree serialization, or root service wiring                                     |
| `test/runner-operator-stops.slow.test.js`                                 | Runner stops settle owned processes and raced commit or handoff effects, and cold continuation preserves unfinished finding repairs     | Runner operator stops, process settlement or containment, commit or handoff races, execution-storage cleanup, or interrupted finding repair and partial-content resume      |
| `test/runner-effects.slow.test.js`                                        | Commit effects, changed-BLOCKED progress and polishing finding-resolution checkpoints retain once-only accounting across reconstruction | Runner Git/state effect dispatch, commit authorization or verification, deferred settlement, consumed-effect recovery, or blocked/finding-resolution checkpoint publication |
| `test/runner-audit-recovery.slow.test.js`                                 | Cold audit reconstruction preserves pending verification, provenance, budgets and bounded baselines across replacement and migration    | Audit output recovery, persisted migration or baselines, native selection, availability/inactivity composition or public recovery projections                               |
| `test/state/operator-stops.slow.test.js`                                  | State journals preserve bounded replay, stop publication, leases, ownership transfer, process identity, and races                       | State actions or journals, publication boundaries, leases, process identity, worktree ownership transfer, or stop concurrency                                               |
| `pipelines/plan-execution/test/legacy-confirmation-recovery.slow.test.js` | Journal-proven legacy confirmation reconciles one real commit through rejection, crash, and lease cases                                 | Plan-execution legacy confirmation eligibility or proof, journal publication boundaries, verified commit recovery, or execution leases                                      |
| `pipelines/plan-execution/test/legacy-migrations.slow.test.js`            | Authentic persisted migration history carries legacy confirmation proof into the current contract                                       | Persisted plan-execution migration composition involving confirmation proof, inventories, implementation evidence, or historical events                                     |
| `pipelines/polishing/test/handoff-recovery.slow.test.js`                  | Configured-hook legacy recovery verifies complete effects, revalidates untouched effects, and rejects partial effects without repair    | Polishing handoff settlement, hook isolation, legacy handoff migration, completed-effect reconciliation, or partial-effect failure                                          |

## Affected runs and release gate

Run the affected slow coverage once before handing off a change to the listed
contracts. After the ordinary `npm run check` gate, run the complete
`npm run test:slow` tier as the release gate. A documentation-only or unrelated
policy edit does not require replaying all durable workflow matrices. Record
exactly which tier/files ran; an unrun slow check is not a pass. Do not move a
test to this tier merely because it fails or has a slow fixture: first remove
redundant setup and use lightweight effects for policy. Pure migration
validation remains in the fast tier.

## Fixture discipline

MCP control-plane and Runner orchestration fixtures race expected events against
their owning operations so early fulfillment or rejection propagates instead of
leaving an event wait pending. Teardown settles held operations, callbacks and
leases even after an assertion fails. Provider-activity teardown retires its
synthetic process, observation and active turn under the currently held lease,
including after replacement acquisition. Injected failures preserve the original
error and prove fresh lease acquisition. The existing protected-configuration
stop race and stop/recovery assertions remain unchanged; these fixture corrections
change no production lifecycle or inspection diagnosis.

The state operator-stop suite's interrupted checkpoint matrix also verifies
atomic retirement of active observations before publication, alongside the
saved stop outcome and exact receipt replay.

## Runtime pinning

Read the [current contract](runtime.md#runtime-release-and-update-coverage).

## Release packing

Read the [current contract](runtime.md#runtime-release-and-update-coverage).

## MCP control plane

Read the [current contract](runner.md#runner-composition-coverage).

## Custom execution

Read the [current contract](runner.md#runner-composition-coverage).

## Runner effects and operator stops

Read the [current contract](runner.md#runner-composition-coverage).

## Init lifecycle

Read the [current contract](runner.md#runner-composition-coverage).

## Runner orchestration

Read the [current contract](finalization.md#finalization-applicability).
