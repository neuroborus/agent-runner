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

`ci/native/prerequisites.test.js` injects acquisition, sealed custody, native
extractor transport and settlement. It covers fixed bootstrap/package admission,
all three supported preparation profiles, pinned-byte sealing before execution,
bootstrap lifetime, exact protected intents, malformed staged inventory,
non-emergency verification and retained original failures. Its focused invocation
is `node ci/native/prerequisites.test.js`; it performs no retrieval, native build,
elevation, task registration or model turn. Reviewed external assets and fresh
native extraction/materialization proof remain dedicated CI requirements.

The same suite exercises the private prerequisite file owners through an
in-memory filesystem and raw Windows IPC transcripts. It covers immutable exact
intent before writes, exclusive creation, protected ancestors, links/writers,
Darwin rejection despite restrictive modes with foreign inherited/write ACEs,
held-identity substitution, sealed-to-read snapshot changes, bounded reads,
changed bytes, malformed frames, queued recovery request substitution,
creation-time DACL rejection, interruption before acknowledgement, descriptor
closure failure and reconstruction retaining exclusion. The tests run no
PowerShell, compiler, elevation or native file operation. Actual Win32 source
compilation, DACL/sharing behavior, approved stock-host dependency closure and
independent custodian retirement remain dedicated external evidence.
The mode-based Linux filesystem model is explicit even when tests run on another
host; it supplies no Darwin ACL observation or native custody evidence.

The prerequisite suite also evaluates the captured worker graph and fresh
worker imports with IPC edges that reject activation. Filesystem and raw Windows
IPC fixtures exercise protected creation through the repository file owners,
bounded uploads/held reads, frozen admission, expiry and disconnect. Controlled
expiry during intent reads or payload writes and raw stream/output failure or
cancellation verify late-result rejection, original-cause retention and
descriptor cleanup. Source substitution, missing/duplicate citations, commented
dynamic imports, undeclared imports/operations,
escaped paths, nonce changes, malformed UTF-8/JSON and unterminated/oversized
frames are rejected. Pure gateway admission covers missing independent
interpreter/source/privilege pins and altered snapshot/pipe vectors. It runs no
PowerShell or Task Scheduler operation; actual private-DACL creation, native
held identities, System pipe/task admission and independent retirement remain
dedicated external requirements. The existing harness includes this suite.

`ci/native/prerequisite-transport.test.js` executes the explicit repository
worker entry and its real file owners through raw filesystem/process/IPC
transcripts. Its focused invocation is `node ci/native/prerequisite-transport.test.js`.
It covers protected intent/birth before release, separately approved source and
runtime closure, bounded upload/read RPC, lost acknowledgement, partial creation,
late completion, malformed frames, concurrent callers, PID reuse, surviving
children, inaccessible procfs, partial reconstruction and descriptor-close retry.
Controlled timers cover a shared cleanup deadline across parked startup,
operations and publication; recovery pins are captured and bounded before reads.
Native observations are produced by the transport from raw procfs bytes, never
injected retirement callbacks. The native harness registers this suite; it runs
no real host, elevation, task, image compilation, privileged probe or provider
call. Actual full procfs visibility and native stock-host/task settlement remain
external evidence; protocol success supplies no native acceptance.

`ci/native/prerequisite-custody.test.js` invokes the checked-in native entry with
the shared raw filesystem/process/IPC fixture from `prerequisite-fixture.js` and
credential-free HTTP transcripts. Its focused invocation is
`node ci/native/prerequisite-custody.test.js`; the native harness registers it.
It covers complete approved asset acquisition/sealing, immutable distinct
receipts, changed hashes, substituted objects, surviving custodians, interrupted
creation and protected-chain reconstruction after expiry without adoption.
Missing acquisition receipts must preserve failure without skipping independent
stock custody recovery. Exclusive package roots and independent bounded directory
reads are exercised through the same repository file owner. Invalid fixed-catalog
archives cannot start package writes. Pure receipt regressions require the fixed
integrity and full staged entrypoint
consumed by prerequisite admission without supplying native evidence.
Injected bootstrap retirement or replacement factory callbacks cannot admit
inputs. Candidate-entry substitution is rejected before evaluation. These
regressions execute no real compiler, host, task, native probe or provider call.
Full approved package publications and platform prepared-build observations
remain external evidence, alongside native/source acceptance.

Darwin's `preparation-effects.test.js` injects sealed provisioning, compiler
transport, readers and retirement. It covers effect-free construction, fixed
vectors, persisted admission, prepared verification without compilation,
complete recipe wiring, policy barriers, per-effect settlement, retained partial
recovery, bounded compiler-output frames and version-two release observations.
Its focused invocation is
`node ci/native/darwin/preparation-effects.test.js`. It performs no native build,
elevation, installation or system/provider probe. Matched SDK/link builds, real
root audit-domain coverage and fresh native CI remain external proof.

Darwin's `effective.test.js` and `audit.test.js` inject kernel observations and
protected BSM transport. They cover setup intent, unsupported/changed baselines,
retirement-gated restoration, snapshot substitution, bounded capture, matched
SDK mapping, native object attribution and missing controls. Focused invocations
are `node ci/native/darwin/effective.test.js` and
`node ci/native/darwin/audit.test.js`. Neither invokes native effects. Matched SDK
compilation, real PF/Seatbelt installation and complete audit route coverage
remain external CI proof; injected success establishes no native GO.

The included `ci/native/darwin/custody.test.js` injects private root transport and
independent process/file observations. It protects source/intent/setup ordering,
substitution and malformed-frame rejection, held-object lifetime, descriptor
transfer, cancellation during admission, bounded pending completion and independent
closure. Its focused invocation is
`node ci/native/darwin/custody.test.js`; it performs no elevation, native build,
installation or system/provider probe. Darwin SDK compilation and actual native
custody remain dedicated external CI evidence.

The included `ci/native/win32/custody.test.js` injects sealed-byte reads, private
Task Scheduler transport and independent native observations. It protects
effect-free construction, task/provisioning intent, separate System admission,
held identity/volume and PE dependency joins, explicit file/policy handle
transfer, suspended release, cancellation, bounded pipe failure and independent
domain/task retirement. Its focused invocation is
`node ci/native/win32/custody.test.js`; it performs no task registration,
elevation, installation or native build. Matched Windows SDK compilation and
actual LocalSystem/Task Scheduler/NTFS custody remain external CI requirements.
The same suite now executes the repository verifier and prerequisite recovery
using raw framed native replies and filesystem bytes, without supplying verifier
verdict callbacks. It covers original process/token and transferred-object joins,
reused creation identities, missing or empty handle inventories, malformed
responses, concurrent declaration capture, observer nonce collisions, task
substitution, surviving Job members, replaced observers, missing birth records,
worker-writable receipt roots and exact protected intent before task removal.
A fresh verifier rejoins native slots and transferred Jobs retained before disconnect,
rejecting omitted subjects or named Jobs even after its JavaScript maps are lost.
Final task absence cannot settle a surviving retained child or Job; closure rereads absence
and leaves the independent observer with preparation. Controlled clocks cover
expiry before later native commands and after protected receipt completion.
These transcripts supply no native acceptance.

Windows `effective.test.js` and `audit.test.js` inject held native reads and
protected control transport. They cover approved binding joins, actual ACL/MIC
and complete WFP graph comparisons, mandatory independent coverage, late substitutions,
bounded Security XML/version/bookmark decoding, acknowledged intervals,
process/token/Job/object attribution, temporary live-verifier checks, retired
policy/filter-absence snapshots and retirement-gated owned audit restoration.
Their focused commands are `node ci/native/win32/effective.test.js` and
`node ci/native/win32/audit.test.js`. Harness discovery includes both without
removing existing coverage. They perform no native build, audit mutation, task
registration or provider execution. Matched SDK compilation, complete Windows
audit-route controls and fresh native CI proof remain external requirements.

The included `ci/native/linux/preparation-effects.test.js` retains historical
injected Linux bootstrap, command/compiler, custody and retirement coverage. It
covers effect-free construction, prerequisite and policy admission, retained partial recovery,
verification without compilation, data-only ELF parsing and held-file substitution.
New prepared-build and stock-custody regressions use `native-effects.mjs` with
raw held filesystem, process/IPC and procfs edges. The repository bootstrap,
command and fresh verifier owners validate their own observations. They cover
the compiler slice, shortened command deadlines and bounded verification snapshot,
changed helper/source/tool/request bytes, missing command completion, reused or
inaccessible process identities, lost stock completion and surviving session
children. Recovery still observes
namespaces when stock custody is uncertain, and the first failure is retained.
The old stock controller may be absent while a new observer reconstructs it;
historical preparation retains its fixed inventory and three-field settlement.
Its targeted invocation is `node ci/native/linux/preparation-effects.test.js`;
it executes no native build, installation, system case or provider turn.

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
The included `ci/native/system-ci.test.js` uses injected acquisition, filesystem
and native-command effects to check the preparation image/runtime gate,
independent input approval, write-ahead
build intents, nonzero compiler failure, identity/retirement rejection,
controller fencing, partial recovery binding, signer identification and Linux
prepared-build substitution without recompilation. Its targeted invocation is
`node ci/native/system-ci.test.js`.
The included `ci/native/first-failure.test.js` injects receipt publication and
job replacement to cover individual prerequisite diagnoses before acquisition,
interrupted first-cause retention, standalone receipt custody, uniquely bound
aggregation without setup identity, redaction and preparation recovery states.
Its targeted invocation is `node ci/native/first-failure.test.js`.
The harness also checks failed-job diagnostic joins, while acceptance coverage
rejects diagnostic-only selections at system/credential and full-GO boundaries.
Composition coverage also rejects incomplete selected system jobs/artifacts and
checks that the labelled 69-record result cannot replace full acceptance.
The included `ci/native/acceptance.test.js` checks candidate revision binding,
independent PR merge/workflow association, selected-attempt freshness and ordering,
unrelated aggregate-step failures, exact run attempts, environment
protection, stale/duplicate/partial artifact rejection, upload receipts and
credential delivery only to admitted private relay custody. Acquisition uses an
injected public-data fetch, and credential transport uses an in-memory stream.
Its targeted invocation is `node ci/native/acceptance.test.js`. Composition
coverage additionally joins all 87 synthetic records and rejects substituted
reviews, lost recipes, mismatched closure bindings and mixed checkouts. These
checks run no provider, native build, privileged setup or external acceptance.

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
