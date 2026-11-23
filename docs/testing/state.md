# State and Journal Coverage

Read the affected sections before changing this contract. Use the [topic map](README.md)
for related owners and required reading routes.

## Workspace preparation

Fast `test/state/workspace-preparation.test.js` owns bounded pending admission,
frozen declarations/inputs/identities, complete binding publication, interrupted
capture and write-ahead recovery, replacement ownership, stale capture rejection,
and concurrent pause/cancel settlement. Cold recovery rejects discarded
absent-input evidence and missing parent bindings for absent nested inputs;
replacement of a retained input parent blocks recapture. It uses isolated ordinary directories,
controlled callbacks and process identities with real journal/lease publication;
no providers, sleeps or host process census. Legacy version-24 migration retains
completed bindings without manufacturing preparation. Common-envelope changes
also retain state persistence/operator-stop, affected orchestration and legacy
migration slow coverage and release-pack validation; these focused fixtures do
not replace those gates or prove pipeline activation.

The same state suite owns one-time Git membership publication before capture,
malformed-selection rejection, lost publication recovery without reselection and
journal substitution rejection. The optional selection uses common envelope 26;
compatibility changes also require the release-pack slow check.

The state preparation suite also owns leased pipeline-migration rebinding of
the admission state fingerprint across cold reload. It preserves all source,
input, policy, role and accounting declarations and rejects attempted changes,
including workflow advancement or rebinding without increasing the version.
The Runner preparation suite's legacy pending-audit case exercises the actual
audit migrations through version 10, including the nullable recovery defaults,
before capture. These focused cases retain the complete slow release gate for
persisted/lifecycle changes.

## Unfinished-work preservation

The fast state `preservation.test.js` suite owns unfinished-work capture and
checked restoration through the public state/Git boundaries. Isolated
repositories cover binary/link/mode/deletion round trips, mixed-index
preservation, checked file/directory and symlink/directory replacements in both
directions, empty replacement directories, interrupted capture and restoration,
cancellation retention, future work after a child commit,
substitution rejection, destination edits during final blob reads and
version-22 migration without invented authority. Capture-record substitution
during prepared-file publication is rejected before replacement. Recovery cases
include interrupted parent sync after replacement or deletion,
temporary creation before identity publication and interrupted writes after
identity publication, with content and inode substitution rejection. Parent
creation is covered before and after durable identity publication, including a
failed blob read before temporary preparation. The slow
`runner-orchestration.slow.test.js` suite covers public Runner resume with
unsettled and settled version-22 preparation custody before envelope migration
and pending-stop settlement, without new agent or check work.
Preserved replacement execution consumes these primitives only after reviewed
revision acceptance and complete capability discovery. Common envelope/journal
changes also require the affected durable state, effect,
stop, migration and MCP workflow suites in the [slow coverage inventory](slow-gates.md); focused probes do not
replace those gates.

The fast state `journal-checkpoints.test.js` suite owns namespace certification:
real repeated choosing/ready claims during controlled directory observations
must preserve unchanged-prefix reuse, while cold reads validate every event.
It counts durable event decoding rather than timing or optimistic read attempts.
Controlled segment publication during suffix validation proves that recognized
namespace changes require canonical proof or rejection. Existing adjacent cases
retain segmented growth, replacement, restored-mtime tamper, cache eviction,
partial-tail recovery, publication interruption and complete projection coverage.
Journal changes also require the state/operator-stop and legacy-confirmation
slow coverage, plus the affected MCP workflow and control-plane composition
in the [slow coverage inventory](slow-gates.md); focused namespace fixtures do not replace those durable gates.
The same focused suite separates projection decoding from state normalization
and exercises record-count and byte-tail eviction separately and together,
checkpoint entry/combined-byte eviction, oversized unretained checkpoints,
missing evidence before/during/after streaming, and repeated real control claims
during overflow reads. Early-limit pages prove unread ranges; atomic progress,
callback failure, historical tampering with snapshot rollback, partial tails,
and legacy/redaction equivalence retain their original-prefix checks. A controlled
historical edit during lagging-snapshot matching also proves that canonical
validation cannot replace the original publication certificate. A one-shot
file-handle hook awaits a real lease-owner transition after a drain's stream
opens: retained and overflow pages continue with exact cursors. The real MCP
wait and Runner status path also exercises two publications in successive drains
for a new warm wait, a held wait with cold activity proof, and an evicted
checkpoint. These controlled interleavings reproduce the formerly generic
second-drain failure; they do not establish the historical interleaving.
Three raced drains require one more certified extension before returning typed
retryable exhaustion. A same-length restored-mtime prefix edit beside a real
publication still rejects, including during the third drain after a nested
reader caches the edited history. Unavailable proof during that continuation
also rejects. The fast MCP control-plane suite checks the typed structured tool
error for both observation tools, without automatic retries or code-based
classification of an unproved failure. A negative table proves that
runtime version skew, malformed state, a hard-linked state file and injected
`EIO` and `TypeError` failures found by the extension propagate instead of the
original read error, while the overflow hard-link case stays unavailable proof.
The state slow suite's bounded-heap journal case also covers overflowed
projections, complete progress, old cursors and repeated transitions across
segments.

## Journal certification and observation

Full-scan certification cases retain consumed-byte capture evidence when a
lease-owner publication follows the actual read, and when append or a small
legal rotation follows decoding during semantic validation. Cold, evicted and
oversized unretained checkpoints exercise public page/cursor pairing; a cold
full-scan MCP wait reaches the real Runner status and activity consumers.
Both certified and full-scan starts retain the three-drain exhaustion bound.
Additional controlled owner publications during capture, canonical recertification
and extension exercise warm, cold, evicted and overflow pages. A separate stable
consumed-prefix proof binds the raced extension's activities and cursor, even
when canonical state is already later. Repeated raced extensions exhaust the
existing bound only after that proof; observations leave all canonical journal,
state and progress bytes unchanged. Original-prefix and newly consumed extension
edits, file controls, hard links, namespace gaps and a newly sealed incomplete
tail remain strict rejections. The real MCP activity/wait, Runner and cold CLI
status consumers share these fixtures without sleeps, polling or providers.
Custody-inspection hooks publish a complete reservation after a proved extension
capture, comparing initial capture, warm reuse, cold settlement, eviction and an
overflow page that must still drain its unread prefix. Exact pages and cursors
remain paired; canonical journal, state, progress and custody bytes stay unchanged
after owner publication. Repeated reservation/settlement preserves the three-drain
bound, and another reservation at the once-only reload is refused. Distinct
orphan and rolled-back custody survive unrelated advancement; edits to original
or newly consumed bytes, changed controls and an unsafe hard link cannot obtain
a replacement proof.
Shared MCP activity and new/held waits consume the repaired schedule through real
Runner/store calls, with exact progress consumption and a controlled client
deadline rather than a fabricated terminal run.
Activity edits with restored mtime at equal and advanced endpoints,
file/directory replacement, namespace gaps and changed file controls cannot be
certified by a later valid scan. Recovery and append reject a captured endpoint
superseded by publication without changing canonical bytes. These callback-controlled cases establish
the repaired contract, not the unavailable historical stack. The affected
state/operator-stop, Runner operator-stop, legacy confirmation/migration,
MCP control-plane, CLI/MCP workflow, orchestration, effect-recovery and
release-pack slow checks remain required at finalization.

The fast state `recovery-failures.test.js` suite owns the public state boundary
for pre-lease and pre-readiness diagnostic publication, interrupted publication,
exact dispatch/child correlation, immutable retries, absent historical causes and
redaction. It does not establish detached launcher or CLI/MCP projection behavior.
The fast MCP control-plane suite owns exit/signal forwarding and structured,
redacted tool-error projection, including unavailable causes and failed journal
inspection after child exit or control-plane replacement. Retry regressions cover
both resume lease checks and stop status/ownership checks before dispatch,
retaining correlated causes without receipt completion or a replacement child.
The fast state safety suite covers exact context-derived action reads without
mutation or weakened tool/argument matching. The CLI suite
owns safe explanations at execution-lease and state-recovery failures. The slow
MCP control-plane suite composes the real launcher, IPC admission, CLI diagnostic
publication, restart with unknown exit facts, ownership exclusion and identical-key
receipt recovery. It retains the existing STDIO protocol-cleanliness coverage.

## Explicit-model catalog recovery

Fast regressions cover journal recovery between resume acceptance and turn
start. Admission and replay reject a turn that bypasses resume acceptance or
supplies a mismatched checkpoint, phase or reservation, including a replaced
candidate-review step or correction scope, changed candidate-review fix
accounting, COMMIT step or authorization, authoring draft or revision budget,
audit pass or budget, or init revision budget.
The journal rejects a COMMIT catalog pause backed only by a model receipt or
an unproven authorization and preserves verified retirement through
operator-stop settlement. It also rejects an initial IMPLEMENT pause without
verified retirement of its active invocation or with a changed baseline.
Admission and replay also reject changes to frozen input hashes, the
candidate, or spent fix rounds on initial `CHECK_AND_FIX` pause publication.
The journal rejects replacement of the saved candidate-review infrastructure
scope. Admission and replay also reject replacing the saved candidate,
correction or spent fix budget during a `CHECK_AND_FIX` catalog retry in either
coding pipeline or a polishing `POLISH` catalog retry.
State persistence covers rejecting receipts without a completed attempt for the
current invocation at admission and replay. Execution clarification tests
cover recovery of a pending append from versions 43 and 45 and rejection of
invalid original proof or a changed append intent. Journal tests reject a
redirected resume or a changed arbitration checkpoint and preserve a paused
COMMIT reservation through migration.
State tests cover a deferred stop recorded before a plan-execution restatement
starts, for both catalog retry admission and atomic availability scheduling.
In both coding pipelines, atomic backoff admission and replay reject a failed
provider attempt at a different checkpoint, and accept a matching failed
attempt at a retained checkpoint. Watchdog regressions reject a mismatched
provider checkpoint in state admission and replay, cold plan-execution
recovery, and polishing stop settlement. State replay also rejects a writable
reservation substituted before the labeled read-only turn starts.
[Runner coverage](runner.md#explicit-model-catalog-recovery) owns the composed
pipeline and slow-suite regressions.

## Preparation custody

Preparation custody regressions extend `test/state/journal-checkpoints.test.js`'s
real growing/rotating journal fixtures and normalization counters with byte,
hashing and publication work. The monitored service/executor/supervisor path
covers cold, warm, evicted and oversized checkpoints, nullable execution and
polishing targets, delayed stop observation, deadline/cancellation (including
supervisor exit before attachment's first identity check), both admission race
orders, owner replacement, partial-tail replacement/completion during repair and
endpoint-bound interrupted settlement/removal, and orphan custody after cold
canonical rollback. Existing journal tamper/rollback/rotation,
full result and process-custody proofs remain required. Runner orchestration covers both pipelines'
preparation retirement and canonical settlement before pending-stop completion
after owner replacement. This lifecycle affects every slow-suite
row in the [slow coverage inventory](slow-gates.md), plus the complete slow release gate; focused synthetic regressions do
not replace the operator's post-install saved-case acceptance.

## Observation publication

Read the [current contract](#state-and-journal-coverage).

## Recovery diagnostics

Read the [current contract](#state-and-journal-coverage).

## Action-read safety

Read the [current contract](#state-and-journal-coverage).
