# RHYTHM.md

Chronological record of meaningful implemented repository decisions. New dated
sections are added immediately below this introduction. Entries describe the
resulting behavior, rationale, and important consequences; current contracts
remain in the owning documentation.

## 2026-10-13 — Trace the bound Darwin target without grabbing it

The fixed startup trace now supplies the normalized held PID as one positional
macro operand instead of DTrace's process-grab option. Target-only predicates
retain the arming gate, and the target exit record precedes a non-destructive
tracer-only exit. Apple source distinguishes tracing-state draining from target
termination; independent target, sudo and tracer retirement still gate cleanup.
Unavailable or partial observations remain diagnostic, preserve the original
startup failure, and establish neither a repaired SIGABRT nor native acceptance.

## 2026-10-13 — Observe Windows TCP drops without changing network policy

The original held launcher now reads a bounded, AppId/window-scoped WFP snapshot
before TCP failure forwarding and lifecycle retirement. Native socket endpoints,
birth/image and package/user identity gate publication of actual filter/layer
observations. Disabled or incomplete logging remains unproved; checked SDK
closure stays separate from the original Winsock result. This adds diagnostic
visibility without collection/policy changes or relaxing the exact 10013 gate.

## 2026-10-13 — Validate Darwin log completion and retain scoped startup traces

Darwin startup logs now validate the final statistics footer against preceding
events, so empty collection stays empty and malformed records cannot disappear.
One fixed installed target-only DTrace observer binds the parked native child
before release, with bounded capture and independent sudo/tracer retirement.
Unavailable tracing and cleanup uncertainty remain separate from the original
abort; diagnostic observations cannot supply native admission or acceptance.
The sandbox, required controls and unresolved native cause remain unchanged.

## 2026-10-13 — Separate provider image bounds and broker refusal evidence

Windows command hashes now give only the pinned provider image the existing
512 MiB input ceiling, preserving the 128 MiB helper and fixture default and
streaming complete digests. Explicit mixed-reader image kinds keep live helper
verification narrow. Complete bounded broker native stderr reuses the strict
decoder without accepting prefixes, while close facts, first failure and native
cleanup diagnosis remain separate. Raw CI output still streams; neither close
nor diagnostics prove custody or acceptance. Native builds and actual retirement
remain matching hosted Windows evidence, with other blockers unchanged.

## 2026-10-13 — Retain precise Windows command preflight refusal causes

Reached command preflight checks now retain fixed API-specific causes separately
from invariant guards and independently checked cleanup. The closed prerequisite
projection preserves existing unavailable/failure classifications, documented
privilege last-error handling and metadata exhaustion semantics. Standalone
admission follows all guards and cleanup; broker success retains NUL/audit state.
Readiness, rights, audit policy and metadata limits remain fixed. Portable
regressions supply no historical guard diagnosis or native success; matching
hosted evidence and separate Darwin/reviewed-input blockers remain required.

## 2026-10-13 — Bound Windows TCP completion without inventing denial

The shared feasibility TCP transaction now uses nonblocking completion and a
single monotonic five-second budget for connect, partial sends and receives.
Checked socket closure preserves the native primary cause and separate cleanup
failure. A bounded API/phase stderr carrier supplies observation data without
receipt authority; expiry, pending and missing output cannot substitute for the
exact native denial. The outer response guard, nonce/control vector and each
independent Job/map retirement remain fixed. Portable coverage proves neither
the previously stalled API nor native success; matching hosted CI and the
separate Darwin/reviewed-input blockers retain their authority.

## 2026-10-13 — Share held Windows workspace ownership with required bundles

A small private feasibility owner now serves the workspace-rooted diagnostic and
original read/edit bundles, reusing native construction and independent dual
suspended-target assignment. Nonce/role-bound proofs and intents precede effects;
caller-owned operation receipts and full required controls remain separate from
diagnostics. Held original/private PIPE queries preserve meaningful IPC denial
without namespace assumptions or broader grants. Fresh whole-Job retirement
gates resource closure; uncertainty retains holder/profile custody and fences
dependent work. Each bundle supplies its own mapping and cleanup evidence, while
the shared profile keeps its existing end-of-run retirement. Portable coverage
establishes no hosted Windows success or GO; Darwin and reviewed-input blockers
remain unresolved.

## 2026-10-13 — Bind a private Windows cwd diagnostic to both suspended targets

The existing feasibility owners add a separate workspace-rooted hypothesis:
fixed collision-refused `W:` reaches an independently held physical workspace,
and a single holder explicitly assigns the map to the original suspended payload
and Git before their respective releases. Independent payload admission and
receipt persistence precede the holder; possible-effect intents precede map/Git
creation. Partial cancellation keeps acquired resources behind
fresh whole-Job retirement. Physical Git inputs and original diagnostics remain
fixed. Readiness, target SETs, cwd/image observations, actual execution and cleanup
are separate evidence. Portable coverage grants no native success, original-case
repair or GO; matching hosted CI and the independent Darwin/reviewed-input
blockers retain their authority.

## 2026-10-12 — Retain rejected Windows Git image binding as diagnostic data

The existing Git image query and strict equality gate now publish original UTF-16
values, query bounds/flags and failure-only last error through separately bounded
stderr frames. The null-probe artifact preserves capture availability even when
start refuses or rollback is uncertain. Malformed or incomplete image diagnostics
cannot replace the original failure, admit receipts or establish execution,
settlement, compatibility or native acceptance. Existing gates remain unchanged;
portable injected coverage supplies no hosted Windows proof.

## 2026-10-12 — Probe private Windows Git null lookup separately from acceptance

Ordinary Windows feasibility now probes an unproved controller-shadow device map
on fresh admitted, suspended zero-capability Git using the existing invocation,
handles, Job and verifier. An exclusive held zero-byte endpoint and bounded
retirement cover only owned resources; uncertainty excludes reuse. Separate
candidate/run-bound artifacts retain API errors, actual Git execution/capture,
controller/sentinel observations and cleanup. This supplies no original-child
mapping or production proof and leaves existing cases, failures and GO gates
intact. Portable coverage proves only orchestration.

## 2026-10-12 — Publish ordinary native CI diagnostics independently of evidence

Ordinary secret-free Native feasibility and Native PoC CI now publish available
stdout/stderr, exceptions and cause stacks, and process exit/signal facts through
one injectable CI-private writer. Existing process boundaries stream output while
retaining evidence limits and drainage; incomplete captures remain explicit.
Original failures survive separate cleanup failures. Windows confined Git bytes
cross a separate bounded diagnostic carrier, never the strict receipt/refusal
grammar. Darwin publishes already-read selected crash and unified-log contents
before classification can discard the cause. Publication adds no effect replay.

This removes error recognition as a prerequisite for ordinary CI visibility.
Structured evidence, admission, retirement, quarantine, release bindings,
production Runner/MCP and protected provider handling retain their contracts.
Portable regressions supply no native acceptance or repaired-cause claim;
fresh matching hosted workflows must establish those facts.

## 2026-10-12 — Classify remaining pinned Windows Git fatal forms

The local Git for Windows `v2.55.0.windows.5` excerpts, with provenance in
[the native contract](ci/native/README.md), extend the existing private classifier
to worktree/config setup, index corruption and loader threads, stdout/null-device
I/O, random bytes, Winsock and console initialization. Existing owning labels
are reused; four runtime labels remain in the closed nonzero exit catalog.
Plain forms require exact endpoints, errno/strerror forms retain nonempty same-line
tails, and the sole numeric placeholder accepts only source-shaped signed decimals.
The `/dev/null` open form never generalizes paths or modes. Private values are
discarded; capture/drainage bounds, actual exit, first cause and independent cleanup
uncertainty remain unchanged.

Neutral existing source/transport cases cover endpoints, numeric refusals,
malformed captures and closed-domain retention. This diagnostics-only change
identifies no actual hosted cause or errno and supplies no repair or native GO.
Fresh matching same-SHA CI must establish the cause before an actual repair;
runtime/Git bindings, policies, Linux/Darwin routes and protected records remain.

## 2026-10-12 — Classify pinned Windows Git startup diagnostics

Git for Windows `v2.55.0.windows.5`
[`mingw.c`](https://raw.githubusercontent.com/git-for-windows/git/v2.55.0.windows.5/compat/mingw.c),
[`setup.c`](https://raw.githubusercontent.com/git-for-windows/git/v2.55.0.windows.5/setup.c) and
[`read-cache.c`](https://raw.githubusercontent.com/git-for-windows/git/v2.55.0.windows.5/read-cache.c)
provide the bounded long-path, chdir/return and index open/stat/map templates.
Existing path/cwd labels remain; index forms share one exit-only nonzero label.
The long-path quote must end the line; errno forms require exact delimiters and
nonempty tails, with only Windows's empty map suffix. Invalid/NUL/unfinished
captures stay unknown. Capture bounds, drainage, actual exit, first cause and
separate cleanup uncertainty remain; private diagnostic content is never published.

Existing neutral source/transport regressions cover forms, refusals and retention.
This diagnostics-only checkpoint proves no current hosted cause, permission fix
or native acceptance. Fresh same-SHA CI owns attribution; Git bindings, policy,
Linux controls and protected records remain unchanged.

## 2026-10-12 — Retire actual model-free Linux admitting controllers

Model-free receipts named the still-running probe as controller, contradicting
the verifier's required owner absence. A narrow CI-only controller now admits
each command, publishes its protected receipt and waits for the probe's independent
live-binding acknowledgement before release. It forwards actual command streams
and closes before separate fresh verification, including failure cleanup.
Retirement predicates, visibility and bounds remain unchanged; completion supplies
no proof, and missing or unretired ownership retains quarantine and uncertainty.
Injected regressions cover binding, ordering and refusals without native effects.
Fresh complete same-SHA workflows still own native acceptance; existing Windows,
Darwin, reviewed-input and production barriers remain open.

## 2026-10-12 — Attribute model-free Linux completion failures

The command owner previously retained `outside-write-denial` through close,
completion, retirement, trace and joins, conflating post-control failures.
Each existing checkpoint now owns a bounded label; trace read, line decode and
finish are distinct. Four unchanged predicates gain static explanations, and
only these checkpoints retain fixed existing evidence/capture error classes.
Original process and protocol causes still precede later failures; cleanup
remains separate and private values are not projected.

Synthetic regressions protect attribution, ordering, first-cause separation and
redaction. Commands, controls, bounds, joins, custody and retirement stay unchanged.
Fresh matching hosted CI must identify the actual failure; this diagnostic
checkpoint establishes no native acceptance or production GO.

## 2026-10-12 — Select fixed model-free Linux paths during capture

The model-free command owner freezes one Node/inspection/edit/outside vector
for both capture and decoding. Capture validates and retains the four paths
before effects and passes literal strace `-P` pairs. Pinned
[strace 6.8](https://github.com/strace/strace/blob/v6.8/doc/strace.1.in) and
[pathtrace.c](https://github.com/strace/strace/blob/v6.8/src/pathtrace.c) select
accesses including execve/openat/openat2. Shared observer arguments, diagnostic
replay, protected routes, bounds, exact joins, sentinels and independent retirement
remain unchanged. Selection supplies no object authority.

Hosted startup and three controls completed before outside-write-denial SIGXFSZ
at 15,818 ms with uncertain cleanup. Broad unrelated tracing can exhaust the
fixed 8 MiB limit; unavailable raw capture provides no independent size proof.
Injected coverage protects literal arguments, pre-effect refusals and retained
selectors alongside bounds/substitution/retirement guards. Fresh hosted CI still
owns native evidence; Windows, Darwin, reviewed-input acquisition and production
GO remain open.

## 2026-10-12 — Accept timestamped server-notification envelopes

The pinned [ServerNotificationEnvelope](https://github.com/openai/codex/blob/rust-v0.160.0/codex-rs/app-server-protocol/src/protocol/common.rs#L2042)
flattens notifications alongside optional `emittedAtMs: i64` metadata. Its
[publisher and serialization test](https://github.com/openai/codex/blob/rust-v0.160.0/codex-rs/app-server/src/outgoing_message.rs#L898)
populate the timestamp; the [transport owner](https://github.com/openai/codex/blob/rust-v0.160.0/codex-rs/app-server-transport/src/outgoing_message.rs)
sends the envelope. Both known informational validators now share one private
envelope check permitting only optional safe-integer timestamps, with omission
retained for older senders. Metadata is discarded without publication or authority;
payloads, disabled-only status, strict replies and first-error diagnostics remain.

Existing injected regressions cover compatibility, integer boundaries, malformed
timestamps and strict envelopes through all four controls. This repairs the
source-proven rejection, not a proved sole hosted cause or native acceptance.
Fresh same-SHA CI must preserve ten Linux passes and both Windows builds;
Windows Git, Darwin, reviewed-input failures and production GO remain open.

## 2026-10-12 — Distinguish remote-status rejection predicates

The private classifier preserves ordered disabled-status predicates and retains
one of six code-owned subreasons on the first failure. The bounded diagnostic owner
publishes only allowlisted labels at the remote-status envelope reader checkpoint;
peer values and forged or unrelated labels remain private. Existing injected
regressions cover attribution and retention without native effects.
The hosted subcause still requires fresh same-SHA evidence; the coarse reason
proves neither a non-disabled state nor a timeout, native closure or cleanup promotion.

## 2026-10-12 — Localize model-free envelope rejection guards

The bounded client retains finite rejection reasons and necessary envelope/ID-type
shapes on its original failure. The existing diagnostic owner allowlists them;
peer values and forged fields remain private. Acceptance predicates, byte bounds,
RPC/deadline facts and independent cleanup requirements stay unchanged.

Injected regressions localize guards and preserve first causes without native
effects. Fresh same-SHA hosted CI must identify the actual rejection before another
repair is selected; whole-native acceptance and cleanup promotion remain open.

## 2026-10-12 — Accept the pinned disabled model-free startup status

Pinned [0.160.0 initialization](https://github.com/openai/codex/blob/rust-v0.160.0/codex-rs/app-server/src/lib.rs#L1222)
unconditionally sends the [typed remote status](https://github.com/openai/codex/blob/rust-v0.160.0/codex-rs/app-server-protocol/schema/typescript/v2/RemoteControlStatusChangedNotification.ts)
after config warnings, before connection initialization. Account routing requires
`workspace_routing`; thread initialization stores capabilities only. The fresh
empty home needs no account/model notification expansion.

The bounded client validates exact disabled metadata and discards it privately
alongside `configWarning`, independently of pending replies and initialization.
Neither notification consumes a response, publishes identifiers or hashes, issues
an RPC or grants authority, approval, evidence or PASS. Other remote states,
notifications, requests and malformed envelopes remain strict; original errors,
finite reader stages and numeric RPC/deadline facts survive unchanged.

Focused injected regressions cover both environment-ID forms through startup and
all four controls, with strict rejection, first-error preservation and redaction.
These prove the protocol repair, not the sole hosted cause or native acceptance.
Fresh same-SHA CI must preserve ten Linux passes and both Windows builds. Windows
Git fatal128, Darwin failures, reviewed-input acquisition, fd7/live custody,
whole-native closure and production GO remain open.

## 2026-10-12 — Accept the pinned model-free startup warning

The bounded client validates and privately discards only the pinned `configWarning`
notification, independently of pending replies and local initialization. Warnings
confer no authority or evidence; other notifications, requests and malformed
envelopes remain strict. Closed JSON/envelope/stream labels preserve the original
reader cause without exposing peer text or changing numeric RPC/deadline facts.

Injected tests prove the source-backed protocol defect, not the sole hosted cause.
Fresh same-SHA CI must preserve ten Linux passes and both Windows builds. Windows
Git invariant0/fatal128, Darwin attribution, reviewed-input acquisition, fd7/live
custody, whole-native closure and production GO remain open.

## 2026-10-11 — Preserve the first model-free command rejection

The bounded client retains RPC rejection codes and original reader errors before
later deadlines, process failures or cleanup can replace them. Fixed control
labels and finite redacted classifications distinguish rejection from transport;
unknown native facts stay unknown. Only inspected 0.160.0 error forms reach
diagnostic normalization, and proven deadlines retain timeout attribution.

Injected regressions establish no native proof. Fresh matching hosted CI must
preserve ten Linux passes and both Windows builds. The fd7/live-custody route,
Windows fatal128, Darwin attribution, reviewed-input acquisition, whole-native
acceptance and production GO remain open.

## 2026-10-11 — Hold bounded Linux model-free trace output

The model-free observer opens a held private regular file instead of Node's
socket-backed pipe; its descriptor stays with the owner. Existing custody and
protected reads bind fixed prlimit/strace images, bounding native writes before
observation. Independent receipts precede complete reads/removal. Resolved failed
completion and private bounded stderr preserve the original cause through write
errors/EOF, keeping cleanup separate and paths/output private.

Cheap injected regressions supply no native proof. The separate reviewed fd7
streaming route remains deferred; fresh exact-SHA CI must determine remaining
causes and preserve ten Linux passes and both Windows builds. Other platform,
reviewed-input and whole-native/production blockers remain open.

## 2026-10-11 — Initialize the Linux build controller independently

A dependency-free bound owner supplies proof, system and CI preparation imports,
preserving the proof export and exact 70-second expression. This removes direct
proof entry's initialization dependency without changing budgets, entry guards,
source/hash/receipt, ELF or independent-retirement requirements.

Focused effect-free fresh-process coverage protects direct entry and unchanged
bounds alongside index-first imports. It supplies no native proof. The supervisor
owns fresh exact-SHA workflows and preservation of eight Linux passes; Windows,
Darwin, reviewed-input and full Linux/storage or production blockers remain open.

## 2026-10-11 — Attribute Linux helper build rejection boundaries

Existing build diagnostics retain finite source/hash, compiler, controller,
receipt/binding, retirement, image and publication operations without weakening
acceptance. Actual error objects and first causes survive; cleanup stays separate.
Injected regressions prove propagation and redaction only. Fresh exact-SHA native
CI must establish cause and closure, preserving prior Linux passes. Other platform
and reviewed-input failures remain open; the supervisor owns native publication.

## 2026-10-11 — Preserve actual hosted retirement reader context

One owner supplies Linux proof children and helper-build admission with actual
hosted context and fixed PATH/LANG, repairing the verifier's source omission.
Reader authorization, custody, bounds and retirement predicates remain unchanged;
identity is never fabricated and emergency cleanup remains failure.

Injected launch tests prove wiring only; fresh exact-SHA native retirement must
establish CI cause closure. Windows, Darwin and reviewed-input blockers remain
open. The supervisor owns publication and native evaluation.

## 2026-10-11 — Join complete proc-prefixed audit mapping names

The Linux namespace gate compares complete `proc/self` and positive-PID
mapping audit names through its existing canonical syscall join. Strict decoding,
full `/proc/` targets, descriptor bindings and all attribution/policy predicates
remain required; persisted `relative-proc` diagnostics remain unresolved.

Cheap parser and injected regressions supply no native acceptance. Fresh exact-SHA
hosted ordinary and nested after-probes, owned-label verification and cleanup
must establish Linux admission. Other blockers remain open; no native or
production GO is claimed.

## 2026-10-11 — Localize rejected native observations without admission

Existing native owners retain finite Linux proc-prefixed candidate shapes,
Windows capture framing/line classes and distinct image predicates, and Darwin
known-field types and literal held-image relationships. Compact diagnoses remain
bounded and redacted, preserve legacy observations and rejected joins, and keep
first causes separate from observation and cleanup failures.

Cheap injected tests and native source/literal guards supply no runtime proof.
Fresh same-SHA hosted observations must establish any causal repair, cleanup and
both Windows build outcomes. Reviewed-input acquisition and source/release/provider
production admission remain open; no permission or alias acceptance is added.

## 2026-10-11 — Include the Windows RPC link dependency

The shared Windows build recipe and sealed native entry include `rpcrt4.lib`
for custody RPC calls through existing SDK/library bindings. A literal assertion
on emitted custody linker arguments catches the missing dependency; an
actual-source check keeps the native entry's fixed link tail aligned with the recipe.

These cheap portable regressions run in the ordinary fast gate without a native
compiler. Both fresh exact-SHA workflows still need matching hosted Windows
compilation, linking and image inspection of command and custody variants.
Native runtime acceptance, source/release GO and unrelated blockers remain open.

## 2026-10-11 — Align Windows audit builds with the existing ceiling

Command and custody audit compile/link calls reuse `WINDOWS_BUILD_COMMAND_MS`
(60000 ms), while discovery/version queries keep 10000 ms. Signals, capture
bounds, recipes, diagnostics and source/SDK/image inspection remain unchanged.
Injected option and controlled-abort regressions cover both variants in the
ordinary fast gate without a native harness or unrelated slow suite.

The observed custody SIGTERM retains unknown timeout status; C4047/C4024 remain
warnings without established causality. Portable checks prove no build benefit:
fresh exact-SHA hosted Windows compilation, linking and image inspection must
demonstrate it. Complete native PoC closure and source/release GO remain unproved.

## 2026-10-11 — Isolate custody SDK string aliases

The account header confines `ntsecapi.h`'s LSA-to-NT string aliases to private
names, saving and immediately restoring all four caller macro states. This
avoids the collision after `winternl.h` without replacing NT or LSA types,
changing SDK signatures or altering consumers, source inventories or policy.

One cheap actual-source regression protects include order, alias scope and
restoration, and rejects spoofed guards and replacement string declarations.
It proves no SDK compilation or native ABI: fresh exact-SHA Windows evidence
must compile, link and inspect both helper variants. Runtime restoration,
admission and complete native PoC closure remain unproved.

## 2026-10-11 — Keep fixed Windows Git arguments inside the verified cwd

Outside and confined status use the same fixed relative repository recipe while
executable, cwd, metadata and configuration observations remain absolute.
Startup validation derives expected paths from the verified experiment root
and checks the exact recipe and ordered closed environment before hashes and
the unchanged object/verifier joins. Matching recomputed hashes cannot authorize
a substituted cwd, repository recipe or configuration path.

Supplied Git source verifies the cwd-scoped `safe.directory=.` exception and
two fatal forms. Complete LF/CRLF lines with exact delimiters map to
`git-cwd-read` or exit-only `git-path-normalize`; unknown forms retain the original
exit without exposing private stderr or replacing separate cleanup uncertainty.

The supplied base's hosted Windows Git exit 128 remains unclassified beyond
`git-process-exit`, and emergency rollback proves no independent retirement.
This recipe change has no native result until fresh exact-SHA CI; it neither
identifies that fatal cause nor completes native or full PoC acceptance.

## 2026-10-11 — Separate restricted Git observations from canonical reads

The Windows feasibility payload observes only its five fixed Git objects through
the shared checked held-object record writer. Trusted readers retain strict
normalized-path validation; independent canonical reads, exact record joins,
suspended-child verification and fresh unchanged-file checks still precede Git
release. Object observation grants no canonical path authority or new access.

This separates the observed pre-release normalized-name Win32 5 failure from
the evidence required for admission, without an opened-name fallback or generic
bypass. Its deeper local-path cause remains unknown. Portable regressions prove
the contract; fresh same-commit Windows evidence must prove execution and
retirement, and any subsequent failure remains explicit.

## 2026-10-11 — Normalize private Darwin startup records without tolerance

Startup observations distinguish closed log/crash record failures from rejected
identity, image, UUID and capture joins. Timestamp spelling is normalized while
microsecond birth and window equality remain exact; no field aliases or runtime
grants are inferred. SIGABRT, observation failure and independent cleanup stay
separate, and matched native evidence is still required before runtime repair.

The timestamp decoder, finite rejection vocabulary and held-image joins remain
in the existing startup owner so pure decoding and bounded native collection
cannot disagree about precision or redaction. This cohesion, and retaining the
existing publication/closure/control regressions alongside the new precision
cases, justify exceeding the soft line target after canonical formatting.

## 2026-10-11 — Name fixed Windows Git helper failures

The confined fixed Git path separates native API results from payload, I/O,
handle-type and forwarding predicates. Closed operation/domain joins retain only
bounded numeric facts, and independent cleanup diagnostics preserve the original
failure. This diagnoses the remaining helper refusal without changing policy,
handle authority or admission; native causality and retirement remain unproved.

## 2026-10-11 — Diagnose Linux mapping joins without widening admission

Namespace attribution preserves resumed syscall separators and binds annotated
procfs targets to literal or strictly decoded audit names, write masks and the
terminal errno. Per-probe installed-image rechecks retain substitution separately
from cleanup. Unjoined file denials persist finite rejection classes and bounded
refusal counts; private trace, audit paths, PIDs and windows stay transient.
Existing receipts remain recoverable. An unjoined denial still blocks the trial;
diagnostic normalization supplies no native runtime success or permission grant.

## 2026-10-11 — Bind Darwin startup attribution before exec

The minimal Darwin experiment acquires original native helper birth/image
identity and persists exact policy intent before policy application or exec.
Fixture-main readiness, live signed-image/policy reads, fixed controls and
independent cleanup remain required. Native signature verification and unchanged
image UUID/loader/verifier bytes precede build admission. Bounded startup crash
collection now covers every control and joins original process birth and loaded
image UUID rather than PID/path alone. Finite observation classes now distinguish
unavailable sources, failed/unusable reads and watcher failures from successful
empty or unmatched inspection. Malformed denial data cannot become unmatched;
matched crash diagnoses retain separate collection/closure failures. Observation
failure cannot replace the first abort or cleanup cause, and no new sandbox
permission is granted.

The archived abort still lacks a matching native cause. Portable regression
success and this attribution repair do not complete the confined startup repair;
matching macOS CI must supply the missing evidence before a source-supported
runtime or exact policy correction can be selected.

## 2026-10-11 — Prepare ordinary Windows system experiments

Windows ordinary preparation now builds the fixed candidate helper/header
inventory with installed MSVC/SDK tools and reuses System custody, compiler,
held-file and recovery owners. Native build/import and creation/retirement reads
bind expectations without a reviewed delivery or signing approval. Generated
case declarations retain every system recipe and its original policy, audit,
file, Git and ownership controls. Runtime auditing observes actual builds and
loader bindings separately from reviewed source/release closure.

Experimental images retain a PE purpose marker and a distinct custody-plan
header; reviewed publication and native custody reject their promotion. Partial
bootstrap or native startup retains original intent and uncertainty rather than
recompiling or equating exit with retirement. Fresh observers rejoin original
Jobs and owned tasks before load or recovery; only settled owned resources can
be restored. Portable checks and these local observations establish no native CI
acceptance or production GO. Workflow dispatch remains a separate plan step.

## 2026-10-11 — Bind confined Windows Git to its outside control

Windows feasibility Git now uses the same explicit repository/cwd/config and
closed environment for outside status and confined execution. HOME and related
discovery paths stay inside its existing read domain; no ACL or device permission
is widened. The fixed Git child remains suspended until a distinct native verifier
checks its image, token, Job and thread, joined to independent runtime/repository
file reads and native command/environment digests. Its owned startup record
precedes release and required negative controls and independent retirement remain.

Private stderr drains while Git executes instead of waiting with a full pipe;
capture/deadline bounds and finite first causes stay strict. The runtime invocation
and handle correction is implemented, but the historical unclassified exit 128
still supplies no specific cause or native acceptance. Matching Windows CI must
establish both status controls and the unchanged confinement/cleanup cases.

## 2026-10-11 — Bind Linux mapping repair and ordinary preparation

Linux mapping diagnostics now retain exact procfs targets and write-mask classes
and join complete syscall refusals to audit PID/window and installed package.
Source-supported restricted-userns refusals can reach the existing executable-only
policy trial; unrelated denials remain blocking, and both unchanged probes,
owned-label verification and independent cleanup remain mandatory.

The Linux index prepares ordinary experiments with observed GCC-13 toolchain and
dependency bytes through existing compiler ownership and sealed helper builds.
Both fixed recipes reuse every system check and independent settlement. Actual
runtime/build/loader auditing supplies experiment evidence without a review
manifest or publication approval. Recovery requires full-procfs absence of the
original preparer before closing admissions. Missing interrupted birth receipts retain
uncertainty and original failures. Workflow defaults and protected acceptance
remain separate; matching Ubuntu CI must still prove the runtime repair.

## 2026-10-11 — Define ordinary system experiment evidence

The CI-private native index now separates ordinary experiment jobs from reviewed
composition. Fixed platform recipe/build inventories, independent actual bindings,
effective policy and non-emergency effect retirement govern experiment PASS.
Reusable held-image inspection supplies observations without manufacturing approval.
Reports leave source closure, protected acceptance and production GO unestablished;
closed reviewed/protected contracts reject experimental payloads. This foundation
does not claim the pending native runtime repairs or change workflow dispatch.

## 2026-10-10 — Separate audit diagnosis from native policy acceptance

Linux's paired pre-trial probes no longer require duplicated capability audit
messages that AppArmor can suppress. At least one exact relevant attribution,
complete matching outcomes and independent retirement remain prerequisites;
unknown denials block a trial. Both unchanged post-trial probes still must pass.
Windows retains finite Git fatal classes from private stderr, and Darwin reads
PID/window/image-bound related kernel denial classes. Neither diagnostic grants
authority, asserts a guessed crash cause or replaces actual native acceptance.

## 2026-10-10 — Keep fixed Git configuration inside its read domain

Windows experiment Git opens an empty exclusive global configuration in the
synthetic repository rather than a denied null device. Its stdio remains narrow
inherited handles and its AppContainer/Job and negative controls stay unchanged.
Linux capability and Darwin loader diagnoses retain additional closed native
facts without extending policy eligibility or turning a failed probe into PASS.

## 2026-10-10 — Use narrow held controls for native CI prerequisites

Linux CI reads only a permission-protected PID 1 namespace control through its
existing bounded observer privilege; full procfs and same-boot identity checks
remain mandatory. Windows read/edit payloads receive pre-opened null-device
handles through the explicit launch list instead of opening a denied device or
widening its ACL. Fixed Git remains inside the same AppContainer and Job, and
both holder copies close after creation. These repairs confer no native pass.
Darwin diagnostics wait on actual report publication events in a bounded
post-abort window; they neither retry execution nor grant sandbox authority.

## 2026-10-10 — Retain relayed native payload failure before owner loss

The Windows experiment's launcher forwards child stderr through its stdout pipe.
The private decoder now recognizes only the existing closed failure grammar there,
stops the failed session and preserves that original diagnosis when owner-input
loss follows. Malformed output still fails and diagnostic lines supply no receipt
or acceptance. Darwin diagnosis reads both fixed OS crash-report locations under
unchanged exact-image/PID/window bindings; neither change grants native authority.

## 2026-10-10 — Preserve Linux journal failures before namespace admission

The CI-private journal boundary now requires a complete JSON entry and matching
terminal cursor before either unchanged namespace probe. Cursor text stays opaque
and private. Rejected output retains the command's actual status; the documented
GNU timeout exit 124 records a deadline rather than a successful non-timeout.
Finite command/authority/cursor diagnoses survive independent cleanup without
retaining journal prose or changing host policy. The archived cursor-stage exit 1
remains unexplained until matching Ubuntu CI supplies the missing finite fact;
portable observation and cleanup evidence confer no repaired admission.

## 2026-10-10 — Bind native CI input delivery and recovery to original authority

Native system and protected-provider dispatch now receive separately approved
template reviews and prerequisite custody through a closed candidate/platform/run
delivery with an independently supplied byte digest. Before effects, the controller
retains the original delivery and review context in a private immutable receipt.
Live expiry fences new assets, builds and payload admissions; recovery uses the
original protected context and intents even after expiry or delivery loss, without
renewing authority or bypassing independent retirement. The existing short file-worker
lifetime remains separate.

Acquired effects entries bind exact candidate bytes and citations but never execute.
Repository-owned fixed factories replace dynamic evaluation, including the legacy
fallback; historical metadata and reports remain parseable. Publication, provisioning,
separate reviews, approved custody and real native acceptance remain external authority.
Portable tests cannot close the historical system/provider and source findings.

## 2026-10-10 — Gate Linux namespace preparation on attributed policy

Minimal and full native CI now require both original bubblewrap probes and
verified executable policy before admission. An errno alone cannot select a
remedy. Only the inspected Noble package with an attributed restricted-userns
denial and supported installed parser/ABI can receive a temporary application
opt-in attaching exactly to protected `/usr/bin/bwrap`, with the sole `userns`
permission. Global restrictions and production payload confinement remain intact.
Unknown policy stays BLOCKED rather than selecting a broad profile or fallback.

A candidate/run/attempt-bound write-ahead intent owns the exact profile and its
template digest. New work verifies live policy; independent recovery uses the
original intent and settlement, never a fresh admission approval. It removes
only owned policy after native retirement and process-label membership checks;
failed restoration retains a separate quarantine cause. Bounded structured
diagnostics contain no raw trace, kernel prose or private paths. Portable tests
prove wiring and refusal/recovery rules; fresh matching Ubuntu CI still owns
actual policy diagnosis, repaired admission and cleanup evidence.

## 2026-10-10 — Separate Darwin startup diagnosis from native admission

The CI-private Darwin experiment permits only the inspected loader container
query (`Sandbox` MAC syscall 67) beyond its existing runtime mappings. Flushed
finite phases and fixed policy/outside/negative controls isolate startup without
copying broad platform defaults or treating markers as authority. Readiness-bound
identity/image/policy observations and independent retirement remain mandatory;
broken startup retains FAIL, uncertain cleanup and dependent admission blocks.
The archived abort's exact cause and native repair remain matching-CI evidence
requirements, separate from the narrow source-supported experimental correction.

## 2026-10-10 — Verify reviewed native inputs without admitting native effects

The native index now exposes bounded, data-only verification of independently
approved system inputs against a final candidate commit. Private platform profiles
and existing source/release/execution/prerequisite/package validators remain the
authority; no parallel schema or supplied-code loader is introduced. Candidate
blobs join helper/source citations and the schema-2 effects entry, while digest
references stay separate from approval. Metadata validity supplies no native
custody, admission or GO. Publication, immutable pins, independent reviews,
reproducible tool/package/ABI evidence, approved custody delivery and compatible
Linux workers remain operator/CI requirements, documented in the native owner.

## 2026-10-09 — Keep minimal preparation separate from native acceptance

Both minimal workflows now capture installed Darwin SDK/compiler discovery and
noninteractive observer authority alongside existing Linux/Windows preparation.
Unavailable preparation stays BLOCKED without policy mutation or invented native
admission. Run-bound summaries retain original causes, component identities and
independent cleanup witnesses, with native/model-free/protected counts separated.
All capabilities and five protected requirements remain mandatory; source-supported
repairs and portable verification supply no missing reviewed inputs, native
acceptance or source-finding closure.

## 2026-10-09 — Observe finite Windows stock commands without model authority

The Windows minimal experiment now owns concrete native command effects separately
from the schema/RPC client. Explicit unelevated native sandbox selection uses the
release's supported default buffered cap; independent client bounds remain stricter.
Empty credential-free homes and disabled integrations retain the model-free boundary.
Creation-time unnamed Job custody and independent process/image/token observations
precede release. Permitted outside controls distinguish stock denials from admission
policy, while held files/DACLs and Security events join acknowledged windows and
completed-I/O gates. Native privilege, coverage and descriptor-mutation prerequisites
block before every Codex effect, including version/schema probes. Owned inclusion
may supply success auditing when system success is disabled: Microsoft's
Administrators exception concerns exclusion, not inclusion. The
[native owner and primary references](ci/native/README.md) document the distinction.
Independent native queries bind effective policy to the held administrative
broker's actual token and creation identity; a fresh delivered Security 4663 gate
control must also join its principal/logon, read access and original file/ACL.
Unavailable coverage remains BLOCKED without enabling system auditing. Independent
cleanup custody precedes setters and covers partial installation. Refused admission
needs no absent success witness, while admitted capture requirements remain.
Separate observation/cleanup budgets cover partial failure;
held native custody must establish complete retirement before original-handle fixture
removal and restoration of owned audit changes. System policy, unrelated descriptors,
the protected LocalSystem observer and existing source findings retain their contracts.
Portable tests supply no Windows build, live command, token/Job/audit or restoration
acceptance; those require matching external CI evidence.

## 2026-10-09 — Observe finite Darwin stock commands without model authority

The minimal Darwin experiment now supplies concrete native effects to the small
buffered Codex client. Credential-free empty homes, disabled integrations and
explicit network-denying access policies retain the model-free boundary. A cloned
audit pipe, denied session-escape controls and held fresh audit sessions precede
suspended native admission;
acknowledged BSM windows join actual image, task/audit identity, effective policy
and held sentinel observations. A permitted outside write under the enclosing
policy prevents that policy's denial from substituting for the stock sandbox.
Separate observation and settlement bounds require complete all-UID session
retirement, independent observer retirement and identity-bound fixture cleanup.
Unavailable prerequisites block before effects, while lost capture, escapes,
emergency retirement and uncertainty cannot pass. This finite inherited-session
proof supplies no full observer approvals, protected model authority or arbitrary
Darwin descendant-domain recovery. SDK/ABI, builds, live commands, audit capture
and retirement remain externally unverified until matching macOS CI observes them.

## 2026-10-09 — Retain actionable feasibility CI failure causes

Preparation captures retain the reached operation and actual status before shell
failure handling, bound to the exact experiment run. Reporting replaces only
untouched missing-probe placeholders and keeps original probe and cleanup causes
separate. Shared diagnoses bound native output and admit only safe recognized
explanations, with unknown process facts preserved explicitly. Escaped summaries
include the run binding and useful explanations. This enables fresh evidence-based
platform diagnosis without claiming a missing native cause, relaxing isolation
or changing the separate full acceptance gate.

## 2026-10-08 — Isolate three-platform feasibility CI from full acceptance

Dedicated credential-free and manual protected workflows bind observed checkout
and worker metadata to the candidate without adopting the full input-release or
publication framework. A small CI wrapper persists unsettled intent before probes,
reassesses complete reports and retains cleanup uncertainty after interruption.
Only redacted report/summary artifacts leave the worker. The shared read-only
environment guard retains required reviewers and self-review protection; bounded
model authority still cannot attest native custody. The protected CLI therefore
stays BLOCKED with its secret step closed until an independent native owner exists.
Known Darwin/domain and stock-command gaps fail their required checks honestly.
Full acceptance, source findings, production runtime and the step-owned local
validation schedule retain their contracts.

## 2026-10-08 — Separate bounded provider routes from release acceptance

The experiment prepares only fixed Codex/Claude runtime members after integrity
and complete data-only archive preflight. A separate buffered Codex command client
uses installed release schemas; Linux joins fixed native executions and denial
observations to held sentinels and fresh retirement. Direct command evidence cannot
approve model command/file tools. The protected entry reuses existing invocation,
stream and relay owners, requires independent custody and same-SHA model/cost
authority, and rejects missing native/tool/relay joins. Claude's four-tool experiment
subset shares validation with the stream while preserving the seven-tool default.
Missing stock observers, protected native owners and compatible AppContainer
transport remain BLOCKED. Full release review, acceptance and production behavior
remain unchanged; portable regressions establish no native or model success.

## 2026-10-08 — Separate Windows mechanism feasibility from full acceptance

The isolated Windows experiment evaluates a capability-free AppContainer and
creation-time kill-on-close Job under the existing CI identity. Nonce-backed
profile intent and native receipts bind owned-only rollback; fresh suspended
admission precedes literal release. Fixed grants, working outside controls,
independent file/DACL observations and substitution refusal bind bounded probes.
Owner-loss recovery declares its surviving Job holder dependency and uses a fresh
verifier; final-handle retirement instead retains only process observations.
No privileged account setup, network capability, loopback exemption or WFP
composition supplies a pass. Portable regressions prove contracts only; actual
Windows ABI/mechanisms and cleanup require matching external CI. Full acceptance,
the Windows source finding and released provider-support requirements remain.

## 2026-10-08 — Bound Darwin feasibility without a descendant-domain claim

The separate experiment now builds a small native helper and the existing argv
fixture in matching macOS CI, with observed Clang/SDK and binary digests. Narrow
Seatbelt grants, ready outside controls and independent native file/volume reads
bind fixed access bundles and private-storage substitution cleanup. Supported
creation-identity observation and kernel audit-token signalling precede fault
release. A fresh verifier checks acknowledged cancellation and owner loss;
observed survival fails, while individual recorded retirement cannot prove a
complete descendant domain and remains BLOCKED. Intervention preserves the
original failure and cleanup uncertainty. Portable regressions supply no native
success, source-finding closure, saved-factory completion or production support.

## 2026-10-08 — Reuse Linux owners for bounded feasibility probes

The separate experiment now selects three existing ownership cases and two
fixed access bundles in matching hosted Ubuntu CI. Owned synthetic Git metadata,
ready outside TCP/Unix controls and independent snapshots bind denial; fresh
receipt verification binds cancellation and owner-loss retirement. An observed
static-helper build reuses the owned compiler controller without promoting its
inputs into release-review authority. Held private identities bind cleanup, and
an acknowledged substitute must survive refusal before sole-parent restoration.
Outside sentinels and protected artifact evidence remain outside probe cleanup.
Failure or uncertain retirement prevents subsequent admission; emergency cleanup
cannot repair containment evidence. Portable joins and dispatch tests establish
no actual kernel outcome, full acceptance or production native support.

## 2026-10-08 — Separate minimal feasibility from full native acceptance

The CI-private feasibility owner now defines a small fixed experiment inventory
and effect-free report/dispatch contracts without changing the 87-record gate
or four retained source findings. Missing evidence, setup defects, crashes,
deadlines and uncertain cleanup cannot pass. Ready controls, acknowledged
attempts, independent outcomes and unchanged sentinels bind success; cleanup
failures retain the original cause. Model-free command and protected tool records
remain separate, with protected absence expected only in credential-free checks.
The matching-worker entry initially reports every capability unimplemented and
launches no payload. Fixed nonce-backed payloads require acknowledged release.
Portable synthetic coverage demonstrates contract behavior only; actual native
and protected evidence remains external, without production support approval.

## 2026-10-08 — Compose Linux provider cases through native owners

The fixed provider factory now supplies Linux case provisioning, held release
and live-process readers, both parked policy barriers, private relay/bridge
transport, complete case plans and native observation. A from-creation tracer
and separate CLOEXEC probe channels in a nondumpable child retain independent
kernel/event/byte joins;
acknowledged live outside controls distinguish namespace exclusion from fixture
errors. Credentials still reach only the separately admitted root relay after
the selected complete system gate. Protected creation and namespace records
support partial provider/relay/bridge recovery without returned preparation or
final outputs. Payload and helper retirement precede observer drain, outside-control closure,
unchanged owned restoration and custody closure. Missing controls, loss,
substitution or incomplete native retirement retains exclusion. Injected
regressions execute all 60 Linux recipes through the fixed entry and existing
mediation controllers, with transport substitution and interrupted settlement.
Outside-control cleanup joins pending listener startup before accepting closure;
native compilation, privileged/authenticated cases and the unchanged acceptance
gate remain external NOT_RUN evidence.

## 2026-10-08 — Prepare provider helpers through platform owners

The exact checked-in provider entry now supplies protected helper preparation
from reviewed data. Linux compiles the fixed provider gate through confined
compiler custody and fresh independent retirement; Darwin and Windows rejoin
complete prepared helper inventories through native ACL/DACL and held byte
reads without recompilation. Preparation retires file observers before PASS,
and fresh verification checks prior helper domains, complete Windows Job
inventories and owned tasks before any provider case. Pinned root-owned stock
tools retain ordinary owner-write permissions while sources, helpers and receipts
remain sealed. Protected partial records rejoin approved bootstrap assets without
final outputs; missing birth or settlement proof retains exclusion. Construction
remains effect-free and credential-free. Fixed-entry injected regressions prove
composition and rejection behavior. Complete provider cases remain separate work;
native compilation, privileged checks, model calls and acceptance remain external
NOT_RUN evidence.

## 2026-10-08 — Materialize Git through confined Windows extraction

The fixed prerequisite entry now supplies a repository-owned Windows extraction
and publication owner. Independently approved archive, extractor, member,
source/build/license/ABI and containment metadata bind a fixed streaming ABI.
Restricted read-only extraction sends data through two private pipes; System
custody validates complete inventory and member bytes before exclusive publication
writes. Held identities, whole-Job retirement and unchanged owned restoration
precede task/custody closure. Sealed System read/execute objects receive fresh
independent tree/byte/identity verification. Protected partial-effect records
rejoin approved bootstrap readers without final images; missing proof retains
exclusion and the original cause. Injected fixed-entry regressions establish
composition only. Windows compilation, privileged probes and independent
extractor/source/publication acceptance remain external NOT_RUN evidence.

## 2026-10-08 — Recover partial Windows system effects independently

The fixed Windows entry now rejoins protected build, case, helper, policy/audit and
task records through approved bootstrap readers without final outputs. Recovery
fences admissions durably, attempts retained owners before evidence validation,
and independently checks held process/Job, account, peer, object/security and task
retirement. Audit drain and unchanged owned restoration precede account/task and
custody closure. Missing birth or baseline proof retains exclusion and the first
cause; a saved success or an absent pathname grants no cleanup authority. Fresh
observer identities and bounded protected batch reads support repeated recovery
without receipt collisions or enlarged command limits. Fixed private Job names
rejoin possible helper domains and creation-bound compiler Jobs independently;
empty fresh transfer slots cannot replace whole-Job retirement evidence. Complete
raw fixed-entry recipe and interruption regressions exercise the composition; Windows compilation,
privileged verification, source review and native acceptance remain NOT_RUN.

## 2026-10-08 — Compose Windows file, Git and release effects

The fixed Windows entry now supplies file, Git and release owners from approved
data and raw native custody. Held System-only file roots, distinct Git execution
and policy handle lists, exact loader/SDK bindings and both package inventories
replace missing owner implementations. Native file controls and Security events
provide observations independently of helper replies and exit codes. Protected
ACL/audit baselines precede setters; retained Jobs retire partial workers before
unchanged restoration and custody closure. Fresh cleanup signals also rejoin
preparation readers. Unknown final objects keep exclusion, and complete cold
reconstruction remains separate. Injected regressions establish composition and
rejection behavior; Windows compilation, privileged proof, independent source
review and external acceptance remain NOT_RUN.

## 2026-10-07 — Compose Windows access policy and audit controls

All fixed Windows access profiles and owner/helper faults now use repository-owned
policy, native controls, held effective reads and Security/BFE observation. Approved
data supplies source/ABI conclusions and complete graph/observer pins; it supplies
no missing effect implementation. Actual tokens, descriptors, registry, 52 filters,
Jobs, processes and socket identities bind both release barriers. Native drops
and unchanged independent controls prove denials; errors and timeouts do not.
Reduced held directory bindings reach the intended file objects through
root-relative lookup while preserving System-only ancestors and zero privileges.
Protected partial setup retains its cause. Retirement precedes observer drain and
unchanged owned audit/policy restoration and custody closure. Raw fixed-entry
regressions cover the full access inventory and interrupted setup without native
execution. External Windows compilation, source review and acceptance remain
required, and complete cold reconstruction remains a separate owner.

## 2026-10-07 — Execute Windows ownership through native custody

Windows ownership recipes now use repository-owned case effects, independently
approved finite policy, private launcher barriers and a separate System domain
custodian. Fresh witnesses inspect held process/token/Job and filesystem objects;
fixture acknowledgements only synchronize attempts and faults. Outside creator
controls and a protected sentinel remain mandatory. Held admission receipts
reconstruct partial execution without final fixture/build results. Cleanup fences
creation, proves process/Job retirement and compares owned policy before restoring
it; uncertain identity or settlement retains custody and the first cause. Raw
fixed-entry regressions cover all nineteen supported recipes independently.
Other Windows case families, complete cold recovery and native SDK acceptance
remain separate work.

## 2026-10-07 — Bind Windows system provisioning and compiler policy

Windows system composition now owns fresh account/restricting SID setup,
protected private roots and reviewed image copies under System custody. A
separate observer rejoins the exact token, account rights and object identities
before approved template materialization; resource binding repeats those reads.
Build admission independently joins compiler token, creator DACL, inherited
pipes and both Job limits to protected pre-release records and final receipts.
Generated digests identify evidence without granting approval. The launcher
shares its account/token owner with custody and adopts only completed protected
records and unchanged empty Jobs, preserving creation-time restrictions and both
policy barriers. Partial provisioning retires only owned unchanged accounts and
independently closes every involved custodian; missing acknowledgement or
cancelled cleanup retains exclusion. Raw fixed-entry regressions cover these
setup boundaries. Full Windows case execution/reconstruction and matched native
SDK acceptance remain separate work.

## 2026-10-07 — Recover partial Darwin system effects independently

The private Darwin recovery owner now joins bootstrap/compiler, provisioning,
ownership, PF/audit and file/Git/release records without successful preparation or
final helper outputs. Durable recovery intent fences later admission; each owner
uses approved bootstrap assets and fresh readers, so malformed build evidence
cannot suppress case retirement. Native custody owners establish private root
audit sessions, and individual PF enable references are protected before policy
mutation. Access recovery joins sealed audit completion to retained raw frames,
checks named IPC absence independently, then restores only unchanged owned policy
after domain retirement. Unknown identities, lost audit, changed policy and
cancelled cleanup retain exclusion and the first cause. No compiler, payload,
control setup or Git mutation is restarted. Raw fixed-entry regressions cover all
Darwin recipe families and partial recovery; native SDK/source acceptance and
unsupported stock-host custody remain separate gates.

## 2026-10-07 — Compose Darwin file, Git and release custody

Normal Darwin system preparation now supplies every fixed file, Git and release
owner through private family compositions. Independently approved operation
records bind the whole execution context, input and ordered custody inventory;
actual observations cannot manufacture approval. File publication and cleanup
join native object identities, acknowledged publisher/reader barriers and unchanged
foreign controls. Root Git admits each suspended image and full birth identity;
ordinary profiles require native audit returns, independent controls and parsed
Git objects rather than fixture verdicts. Release readers retain signatures,
physical/shared-cache dependencies, actual build/SDK/policy bindings and both
provider packages until independent closure. Fresh interrupted recovery rejoins
protected receipts without setup, compilation or another Git mutation. Missing
acknowledgements, changed foreign objects and uncertain retirement retain custody.
Fixed recipes, subjects and the helper inventory are preserved; native SDK and
protected CI acceptance remain separate from injected composition coverage.

## 2026-10-07 — Compose Darwin access policy and audit controls

The fixed Darwin entry now composes separately approved PF prerequisites, complete
Seatbelt/PF reads, outside positive controls and the three access profiles through
the sealed native custody owner. Held process/object identities and acknowledged
BSM windows accompany every attempt; loopback nonce exchanges additionally join
listener identities and packet counters to pinned kernel rules. Native selectors
and complete coverage remain mandatory: creation handles and fixture output cannot
supply missing audit evidence. Payload and observer retirement precede unchanged
owned-anchor restoration and host-baseline restoration, with exclusion released
last. Interrupted writes or uncertain observation retain custody and the original
failure. Raw filesystem/IPC regressions exercise the composition without native
installation or a GO claim; unfinished system owners remain blocked.

## 2026-10-07 — Execute fixed Darwin ownership cases under native custody

The private Darwin case owner now composes literal/storage and every existing
ownership recipe through the sealed native reader. Actual root launch checks and
two protected launch barriers precede executed-policy admission. Fixed argv and
acknowledged faults join kernel process/session observations, held nonce bytes
and unchanged outside objects. Exclusive root receipts retain admissions,
members and possible signals; interrupted recovery rejoins them without another
setup, compiler or fixture launch. Retirement uses full audit identities and
fresh verifier processes that independently enumerate the domain before held
custody closes. Missing identity/completion and uncertain absence retain
exclusion. Historical fixture semantics stay separate, unfinished inventory
owners remain blocked, and injected regressions establish no native acceptance.

## 2026-10-07 — Bind Darwin setup and compiler policy to native custody

The private Darwin provisioning owner now uses the sealed reader for bounded
case setup and independent compiler-policy evidence. Approved inputs remain
records; observations come from suspended compiler credentials, Seatbelt and
stdio descriptors, held object identities, reserved non-login accounts and
exclusive loopback sockets. A context-derived exclusive root prevents reuse
across candidate, job, run, attempt or execution. Prepared verification and
interrupted setup rejoin protected births and fresh retirement without compiling
or provisioning again. Missing completion, substituted objects and surviving
custody retain exclusion. Complete case effects and native acceptance remain
separate gates, and the new owner stays behind the existing factory boundary.

## 2026-10-06 — Keep Darwin build authority in repository native owners

Darwin build defaults now use the independently admitted reader and fixed
compiler entry. A pinned plan declares the only build directory that can be
created or resealed; native parent handles and extended ACL reads protect the
operation. Unsigned snapshots authorize signing inputs only, while independently
approved final pins remain necessary for image use. Fresh byte, process and audit
session reads rejoin prepared and interrupted builds without compiling again.
The directory receipt precedes tool launch, joins its actual inherited handle and
supports read-only interrupted reconstruction without resealing.
Verifier exit additionally requires an independent kernel absence read. Missing
birth records or surviving effects retain custody. Build lifetimes include a
separate cleanup allowance; system-case defaults and native acceptance remain
separate, fail-closed work.

## 2026-10-06 — Rejoin prepared Linux commands independently

Linux preparation now selects its fixed compiler entries independently of
prerequisite and custody receipts. A bounded input-verification snapshot can
keep bootstrap POSSIBLE until its own independent verification finishes;
completed preparation requires the entire retired inventory. Fresh source,
tool, helper and namespace reads replace reuse of recorded settlement without
recompilation. Interrupted stock custody rejoins the existing transport's
protected intent and creation identities through full procfs observation, even
when final completion or helper output was lost. Uncertainty retains exclusion
and the first failure, while separate bootstrap approval and historical proof
semantics remain unchanged. Local injected coverage supplies no native GO.

## 2026-10-06 — Keep prerequisite implementations in the reviewed repository

Version-2 native inputs now bind acquired entry bytes to the checked-in candidate
entry before evaluation and delegate to indexed repository factories. Operators
supply independently approved data rather than replacement code or callbacks.
Protected acquisition receipts retain exact intent and a bounded manifest-bound
chain; held identities and bytes settle assets and data-only package members.
Exclusive package roots and fresh complete directory observations reject foreign
or undeclared contents. Independent stock custody retirement remains separate
from closed file writers. Interrupted publications retain exclusion after fresh
custody reconstruction, without retry, adoption or deletion. Historical inputs
keep their semantics; incomplete native recipes and external acceptance stay
blocked instead of relying on unimplemented saved-reference methods.

## 2026-10-06 — Rejoin Windows custody through original held kernel objects

The repository verifier now borrows a separately admitted System reader and
persists exact bounded native requests before dispatch. Process/token identities,
transferred objects, Job membership and installed task security are independently
observed. Interrupted prerequisite recovery requires the original observer birth
and held Job slot; reopening a same-named Job cannot substitute for that custody.
Unchanged owned task removal follows fresh domain retirement and precedes fresh
absence reads and protected settlement. Closure repeats the observations and
preserves the first failure when proof is incomplete. Preparation still owns the
live observer, which cannot establish its own retirement. The existing helper
inventory and external native/source acceptance requirements remain unchanged.

## 2026-10-06 — Retire prerequisite transports from fresh kernel observations

Prerequisite transport now separates protected launch/delivery intent, retained
stock source/runtime approval and actual process settlement. A kernel birth
identity precedes worker admission; fresh complete procfs observations, rather
than acknowledgement or exit, retire Linux custody. Lost birth after possible
release, reused identities and surviving children retain exclusion. Recovery
rereads protected records without relaunch or successful final preparation, and
descriptor closure can be retried without replacing the first failure. Darwin
native ACL custody and the Windows native verifier remain explicit release
dependencies, preserving fail-closed intermediate trees and external acceptance.

## 2026-10-06 — Activate prerequisite workers only from the captured source graph

Prerequisite custody now snapshots its complete cited source graph before
activation, including the shared observation dependency. Importing or
evaluating those bytes starts no IPC; only an explicit reviewed entry services
requests. Digest-bound admission, nonces, ordered IDs, canonical scopes,
pre-decoding frame limits and fixed chunk operations keep short-lived workers
within preparation. Writes still require the independently reread immutable
intent and held-file verification rather than a controller success flag.
Interrupted or expired turns retain possible writes and their first cause;
late completion supplies no admission evidence.

Windows snapshot preparation requires independent host/source/privilege pins,
creation-time private DACLs and actual held identities across writer closure.
Its private pipe and short task vector grant no task release or retirement;
those remain separate transport/verifier responsibilities. Reconstruction
retains exclusion without retry or adoption, preserving the distinction between
file/protocol completion and independently proved native settlement.

## 2026-10-06 — Separate prerequisite file closure from custodian retirement

Private prerequisite file owners now require an independently reread immutable
creation request before payload writes, retain ancestor/file identities and
reject substitution, unexpected writers or changed bytes. Windows stock-host
operations use creation-time System DACLs and actual Win32 handles; an
intermediate retains identity while the final read handle denies write/delete
sharing. Activation remains with the separately approved custody transport.

The mode-based Node file owner is restricted to Linux. It rejects Darwin before
filesystem effects because extended ACLs and inheritance require actual native
observation/enforcement; mode bits alone cannot authorize protected custody.

Interrupted creation and reconstruction retain exclusion without adopting or
removing an object based on its name or hash. Descriptor closure reports
`CLOSED`, not process/task retirement: the enclosing custodian still requires
fresh independent settlement. This keeps filesystem observations distinct from
native acceptance while preparation composition remains unchanged.

## 2026-10-06 — Seal approved native prerequisites before bootstrap

CI preparation now admits independently approved metadata before requiring
on-host files. A closed fixed inventory binds reviewed reader/bridge and required
build/launch/retirement images, sources and headers to expected byte counts and
source/build/toolchain/loader hashes. Acquisition and native birth-protected
sealing precede execution; unapproved builds cannot bootstrap their own readers.
Fixed phases persist exact requests before sealing, elevation, tasks or command
release, and held bootstrap custody spans command retirement.

Codex/Claude keep reviewed data-only tar acquisition. Version-2 Windows Git
reviews require a separate reviewed native extractor, approved containment,
explicit Bash and complete immutable member/dependency/license/ABI bindings.
The publication remains data, and no PATH/SFX fallback is selected. Independent
retirement precedes staged-byte verification and sealing; uncertainty preserves
storage custody, exclusion and the original failure. Complete verification and
recovery use protected ledgers and approved bootstrap assets rather than requiring
successful final preparation. Bounds derive from reviewed inventories and the
existing provider image ceiling. Injected supported coverage supplies no native
GO, new probe cases or production dependencies.

## 2026-10-06 — Compose protected provider preparation through native custody

The CI-only provider index now supplies effect-free capability factories for all
three fixed profiles and platforms. Explicit preparation persists protected
intents before sealed helper/native provisioning, rereads independently approved
package/tool bytes and joins fresh custody to existing concrete-policy, relay and
real Codex/Claude mediation owners. Independent template approvals remain separate
from declaration labels; generated launch hashes grant no authority. Fresh native
object identities are retained under the selected system's approved manifest,
without borrowing its observations or bypassing its 69-record gate.
Payload retirement precedes audit drain, unchanged owned restoration and final
held-custody closure. Fresh recovery uses protected partial ledgers and bootstrap
assets even when final helper preparation failed. Credentials stay in the private
relay vault, and all provider cases and eighteen aggregate records remain required.
Injected regressions establish wiring without local model turns; native CI/source
proof remains external and production adapters receive no new grant.

## 2026-10-06 — Compose Windows preparation without implicit native admission

Effect-free indexed factories now join Windows custody and effective/audit readers
with fixed build, launch, policy, ownership/access, file, Git, release and retirement
owners. Protected intents precede provisioning and suspended compiler admission.
Signed helper/tool pins remain independently reviewed; bounded native publication
compares actual compiled bytes to approved signed bytes and rechecks Authenticode,
without inheriting signing credentials. Prepared verification rereads protected
images/receipts and whole Job/task retirement without compiling.
Fresh account identities feed both launch policy barriers. Payload retirement
precedes audit drain/observer closure, owned unchanged restoration and final
custody/task removal. Work cancellation keeps custody available to separate bounded
cleanup while fencing new admissions. Recovery consumes protected partial ledgers
and approved bootstrap assets rather than requiring successful final preparation.
Fixed Windows inventories extend bounds only for the added custody/compiler owners.
Injected regressions establish wiring; fresh matched MSVC/SDK/native proof remains
external and no production provider grant or native GO is established.

## 2026-10-06 — Join Windows policy and audit evidence to retained native objects

Effective Windows reads now compare actual ACL/MIC, token, registry and WFP
objects/conditions and the complete native filter/sublayer graph with approved
bindings while keeping complete host/flow and
creation-authority coverage independent. Owned per-principal audit setup and
SACL changes persist intent; system audit policy remains read-only. Bounded
native XML, SDK mappings, acknowledged capture windows and held identities
prevent expected manifests or PID-only events from supplying observations.
Payload/helper retirement and unchanged installed-state reads precede owned
restoration; temporary verifier checks avoid retaining its live process as a
payload member. Retired policy snapshots rejoin held tokens and freshly proved
domain absence. Raw selectors/XML stay protected; command intents contain digests.
Injected regressions establish wiring, while factory composition and fresh
matched SDK/native evidence remain separate gates.

## 2026-10-06 — Retain Windows custody through a one-shot System task

Windows now has bounded native custody readers behind an effect-free indexed
adapter. Sealed reviewed code and persisted task intent precede native entry;
an administrator token cannot acknowledge LocalSystem/session-0 admission.
Actual process/token, Job, no-follow file/volume, signature and PE/API-set reads
remain held through independent retirement. File and policy helpers start
suspended with creation-time private DACLs, Job membership and explicit inherited
handle lists; a separate native verifier gates release. Owned task removal
requires zero instances and unchanged installed definition/security, then an
independent removal observation. Transport loss or child exit cannot erase
possible effects. Injected regressions establish wiring; matched SDK builds,
reviewed bootstrap capabilities and fresh protected Windows CI proof remain due.

## 2026-10-05 — Compose Darwin preparation through protected native owners

Effect-free indexed factories now join the Darwin custody/policy/audit readers
with fixed preparation recipes and existing native owners. A sealed compiler
entry starts pinned tools suspended and binds their complete fresh root audit
domain to independent retirement; child exit alone cannot release custody.
Reviewed source copies and expected signed tool/helper hashes precede execution.
The sealed entry captures tool output internally as bounded control-frame data,
without requiring extra descriptors to survive noninteractive elevation.
Verified tool retirement and persisted intent precede read-only root publication,
allowing the unprivileged runner to rejoin bytes within private report custody.
Access admission separates native composition and complete-template digests and
rejects substituted parameters or concrete bytes before dependent setup.
Probes rejoin original commands and bytes without compilation. Provisioning
intents and per-effect receipts retain interrupted work; domains retire before
audit/policy restoration and held custody closes last. Bounded cleanup preserves
held observations after cancellation without reopening admission. Case anchors
retire before host PF restoration, and its reservation waits for the independently
rejoined baseline. Original case-reader identities survive partial admission.
Fixed helper/link, custody lifetime and file
case bounds now include the required readers. Injected coverage proves supported
wiring, while sealed provisioning, matched SDK builds and fresh native CI remain
external requirements. Historical source findings and acceptance remain strict.

## 2026-10-05 — Read Darwin effective policy and protected audit evidence

The sealed custody reader now supplies actual Seatbelt, ACL, PF, socket and
descriptor-relative file/Git observations. Separately reviewed empty-baseline PF
preparation owns a fixed quick delegation, approved loopback filtering and any
private enable reference; mutation intent precedes effects and restoration waits
for retirement and unchanged state. Protected libbsm decoding binds acknowledged
windows to held process/vnode identities. Missing coverage and uncertain setup or
restoration remain failures with retained exclusion. Injected regressions prove
wiring; matched SDK builds and fresh native CI remain required.

## 2026-10-05 — Retain Darwin native custody behind verified barriers

Darwin now has a bounded protected native reader and effect-free indexed adapter.
Sealed reviewed code, a cleared noninteractive root entry and persisted intent
precede native effects. Fresh independent helper/image reads acknowledge setup;
held audit/file/volume identities, signatures and Mach-O/shared-cache/SDK reads
stay in private custody. The existing file helper receives only held root/base
descriptors and stays fenced until its image and objects are independently read.
Faults and missing observations retain exclusions; child exit cannot claim
closure. Shared identity routines preserve the existing launcher/file contracts.
Injected coverage proves wiring only; fresh external native proof remains due.

## 2026-10-05 — Supply indexed Linux preparation and candidate readers

Linux factories now reuse the confined compiler/controller, reference engine and
fresh verifier with explicit operations and protected write-ahead receipts.
Separate Linux review and authenticated Noble bootstrap precede admission;
probes reverify prepared bytes without recompilation. Held no-follow readers
resolve actual ELF dependencies, provenance, effective authority and both provider
packages. Approved inventories select inputs rather than creating observations.
Parked reference authority is verified before case release; missing receipts and
uncertain bootstrap or retirement retain custody. Historical source assumptions
and strict native acceptance remain unchanged. Injected regressions establish
wiring only; independent reviews and fresh external CI proof remain required.

## 2026-10-05 — Verify materialized native policy before payload release

Platform admission now joins approved launch/policy templates to trusted held
provisioning and independent complete installed-policy reads. Windows waits at
its setup barrier for the assigned SID, materializes and verifies policy before
suspended creation, then verifies again before release. Its private channel
transfers only a bounded hash; creation-time Job/DACL/handle restrictions remain.
Darwin verifies acknowledged Seatbelt on the parked child, and Linux providers
verify their held namespace authority before release. Provider builders expose
request hashes as evidence, while controllers persist policy proof before
relay/model admission. Injected regressions prove sequencing and rejection only;
concrete reader/factory completion, independent reviews and fresh native CI are
still required for GO.

## 2026-10-05 — Approve immutable native policy templates and identity rules

Independent policy approval now covers immutable templates and explicit bounded
identity bindings, resolving fresh account/session allocation without a per-run
human policy gate. Trusted held provisioning supplies only declared identities;
independent complete installed-policy observations must match the materialized
authority before payload release. Concrete request and observation hashes remain
evidence and cannot become approval pins.

Version-2 release, plan and execution contracts keep those references separate,
require externally supplied template approvals, and retain historical concrete
approval semantics without promoting old evidence. Protected provider receipts
bind the complete independently selected system artifact/job/closure and their
own execution. The fixed 87 records, four findings, authority separation and
independent retirement requirements remain. Local injected tests prove these
contracts only; platform wiring, external approval and fresh native proof remain
required before GO.

## 2026-10-05 — Preserve the first native preparation failure

Closed candidate/platform/tier/run-bound first-failure receipts now identify
individual empty or malformed prerequisites before acquisition. Receipt
publication precedes atomic job replacement, so interrupted reporting and later
stage failures cannot replace the cause. Reports and independently selected
artifacts retain that cause before derivative proof gaps.

Write-ahead preparation admission separates effects never admitted from possible
effects requiring fresh recovery; uncertain retirement remains separate and
successful recovery cannot repair failed proof. Protected failed-job collection
is diagnostics-only, never system admission or full acceptance. The native
owner documents these additive contracts; local injected coverage supplies no GO.

## 2026-10-05 — Require protected acceptance for one reviewed native candidate

The manual three-platform provider workflow now requires matching approved
candidate, dispatch/workflow and checkout revisions, fresh exact system evidence
and independent source/release/execution reviews before effects or credentials.
Protected environment rules and actual native job/upload receipts are verified
through bounded read-only collection. PR synthetic merge ancestry and workflow
blobs are joined independently to the candidate instead of equating their SHAs.

Step-scoped model credentials leave the controller environment and reach only
verified private relay pipes; native preparation and recovery keep separate
write-ahead bindings. Complete system/provider recipe inventories and all 87
records/four findings retain the strict GO predicate. Source implementation and
local commits supply no native GO: operator publication, default-branch hosting,
main/dev full-GO protection, scoped credentials and fresh external proof remain
prerequisites. Repairs require a new candidate and new proof, before production
integration.

## 2026-10-05 — Dispatch the complete system inventory without widening acceptance

The pinned, credential-free and model-free three-platform workflow acquires
independently reviewed candidate inputs, builds fixed helpers in dedicated
indexed phases and runs all 23 system IDs per OS. Native reader bytes and
tool/source/output pins precede effects; uncertain commands and partial builds
retain write-ahead recovery obligations. Inventory-derived deadlines leave
room for separate retirement, cleanup, reporting and artifact upload.

A labelled 69-record system result requires every independently selected job,
record, recipe and settlement. It permits later protected collection of successful
system jobs despite a run failing for absent protected evidence, while leaving
the full 87-record/four-finding acceptance gate unchanged. Input publication,
privileged native custody and fresh external CI proof remain operator prerequisites.

## 2026-10-05 — Bind composed native proof to independent candidate review

CI-private version-6 jobs compose fixed platform and protected provider cases
while retaining the 29 check IDs, four findings and historical Linux contracts.
Separate write-ahead build, helper, policy, observer, transport and provider
ledgers require independent settlement before another execution. Incremental
diagnostics cannot replace receipts or bypass retirement after an output failure.

Indexed release readers bind held native images, loader/ABI and both provider
closures to reviewed manifests. Source findings additionally require reached-code
and API citations under independently admitted candidate-bound review digests.
Aggregation rejects incomplete jobs or missing approvals; flags and successful
probes alone grant no acceptance. Native setup and protected CI collection remain
external responsibilities, with no production runner boundary change.

## 2026-10-05 — Require complete outer proof for opaque Claude tool routes

CI-private Claude mediation now joins real model message/tool IDs, names, input
digests and dispatch order through protected Anthropic relay receipts to native
observations, independent state and retirement.
Nineteen fresh cases retain all command/file routes, read-only denials, prohibited
operations, background cancellation/helper loss and the published terminal route.
Fresh custody preserves existing request/cost bounds. Windows Bash requires the
reviewed immutable Git for Windows closure within the same token/Job; WSL and
fallback cannot prove native Windows behavior. Release-supported controls are
independently verified rather than treated as dispatcher guarantees. The dispatcher
source remains unavailable; only complete reviewed outer composition and actual
protected effects can support acceptance. Pure tests establish no native GO or
source-finding closure.

## 2026-10-05 — Require real Codex turns joined to independent native effects

CI-private Codex mediation now uses the reviewed App Server's ExternalSandbox
turns wholly inside native authority. Source-supported controls and independent
effective registry/package inspection bind real command and apply_patch routes,
execution servers, workers and background children. Fourteen cases per ordinary
profile retain nonce inspection, edit/denial and prohibited operation coverage.
Protected relay completion receipts bind actual model transport to thread/turn
identities without persisting text or credentials. Native observer barriers,
independent state and verified retirement remain necessary: RPCs, refusals,
permission stalls and successful HTTP alone cannot prove mediation. Local pure
coverage adds no catalog PASS, source closure or external native GO.

## 2026-10-05 — Separate native provider transport from tool authority

CI-private provider adapters now select exact reviewed packages and private
stdio through platform indexes. Immutable package/ABI grants and private
home/cache reuse native authority; a provider-specific image bound preserves
the earlier fixture limit. One broker endpoint receives a non-secret capability,
while separately admitted relay custody alone receives scoped real credentials.

Fixed HTTPS routes, reviewed model/cost bounds, in-memory protocol error filtering
and deadlines close failed transport. Linux's bridge joins only the held private
network namespace, outside the payload PID/user namespace. Darwin and Windows
require distinct root/System receiving custody. Native controls precede provider
release; fresh retirement precedes owned restoration and uncertain state retains
exclusion. Source and effect-free tests do not establish real provider proof or
external native acceptance; production boundaries remain unchanged.

## 2026-10-04 — Join native tool events before accepting provider effects

CI-private observers now require successful and failed native controls before
provider release, then join actual kernel events to independently held identities,
nonces, bytes and unchanged sentinels. Shared code owns only the pure evidence
join; each platform owns its tracing/audit mechanism and protected custody.

Private-pipe capture stays bounded and in memory. Missing events, loss, stale
identities and unretired readers fail proof. Verified owned audit restoration
follows independent retirement; uncertainty retains exclusion. Native builds,
privileged setup and real provider proof remain external CI responsibilities.
Caught observation errors cannot retry away missing evidence, and deadline
fences prevent late callbacks from continuing into audit restoration.

## 2026-10-04 — Compose Windows file and synthetic Git proof cases

Six Windows file records now require independent held/named byte observations,
overlapping publication/replacement controls, acknowledged native substitutions
and retirement-bound interrupted cleanup. Unknown objects and unsettled readers
retain custody. Sequential replies and exit codes alone cannot prove these cases.

Synthetic Git has a separate held-object read grant and a literal System executor,
with independent admission before every suspended Git child resumes. Ordinary
profiles deny metadata/pointer mutations; common Git predicates preserve the exact
fixed commit, identity, configuration, remotes and unrelated refs. Native builds,
actual probes and final acceptance remain external CI; no production grant changes.

## 2026-10-04 — Bind Windows file transactions to retained native objects

Windows CI files use an independently admitted System helper with private DACL
parent handles, fixed root-relative native leaves and same-volume file IDs.
Complete exclusive publication records its sole temporary hardlink alias;
POSIX-style native replacement/removal retains old readers. Reparse, stream,
short-name and foreign-link states fail rather than gaining pathname authority.

Persisted intents and independently read identity/byte receipts precede barrier
continuations. Recovery retains object identities across helper retirement and
checks legal interrupted states before fresh state-bound retirement-authorized removal of
owned links and an empty directory. Unsupported semantics and uncertain objects
retain exclusion; monotonic deadlines fence callbacks before invocation.
The helper, pure controller and injected tests establish no
power-loss durability or external Windows acceptance; native Windows 2025
build/admission/sharing proof remains dedicated CI work.

## 2026-10-04 — Gate diagnosed non-commit checkpoint reconstruction

Lazy execution can offer operator continuation after a matched completed turn's
history acquisition or capture/hydration limit rejection. The adapter owns
closed acquisition evidence; normalized failures stay terminal and pipelines
contain no provider class allowlist. Versioned checkpoint metadata is published
only after retirement and safe repository reconciliation. Continuous journal
proof and leased revalidation bind frozen inputs, roles, policy, plan position,
Git controls, content and correction accounting before a write-ahead fresh
Worker request. Restart preserves commits, source-fork consumption, grants and
charged corrections without replaying effects or stale approvals.

Missing or migrated provenance never reopens an opaque failure; legacy terminal
confirmation retains its existing exact eligibility. Unsupported failures use
reconciled polishing and a prepared clean base/revised remaining plan while
preserving useful work. Synthetic regressions protect refusals and durable
restart; fresh convergence and all acceptance gates remain mandatory. These
repairs do not establish native PoC acceptance.

## 2026-10-04 — Bound Codex completed-turn hydration and preserve protocol diagnostics

Codex resume/fork omit bulk history; matching terminal notifications hydrate
summarized or unloaded items through bounded ascending turn-filtered item pages.
The pinned public contract supports both history-listing methods, but a known
completed turn needs no turn enumeration. Acquired items are audited before
further acquisition, and only complete unique bounded traversal becomes full
output. Incremental frame, aggregate capture and retained-notification limits
replace post-allocation framing checks and unbounded history retention.

Finite adapter-owned protocol categories survive completion, compaction,
normalization and public activity without native evidence. Protocol and stronger
safety failures stay terminal rather than becoming context or interruption
retries. Synthetic regressions establish concrete incompatibilities, not the
historical opaque cause, recovery eligibility or native PoC acceptance.

## 2026-10-04 — Preserve Windows private access and loopback policy through retirement

Windows CI profiles now bind native token/access observations to a closed private
DACL and persistent WFP composition. Workspace parent and pointer protection
requires inherited owner-rights denial and independent verification of explicit
creation DACLs; trusted commands require disposable storage. Local ALE principal
checks and reserved endpoint guards protect both
ends of exact IPv4/IPv6 TCP/UDP pairs, including native flow-bound return traffic.

Independent ready controls, protected identity/byte observations and correlated
native permit/drop records replace timeout inference. Owner/helper loss retains
policy, and fresh protected retirement plus exact owned-filter verification
precedes removal. Every reservation remains retained for later owned cleanup.
Pure tests and native source add no Windows acceptance or provider authority;
actual SDK/token/loopback/precedence and complete native observers remain required.

## 2026-10-04 — Recover Windows domains through held authority and independent principal reads

Windows CI recovery carries protected admission and interruption receipts into a
separately receipted custodian. It seals admissions, terminates only the verified
held Job, waits on creation-bound native process handles and requires fresh
principal/membership/holder and helper settlement. Disappeared Jobs retain
account reservations; names, producer counts and PIDs provide no kill authority.

Acknowledged cases exercise inheritance, denied creator capabilities and loss/
publication barriers, while containment requires the independently inspected
restricted-token/object-access and Job-inheritance composition. Unknown views
and exhausted bounds retain every reservation. Pure protocols confer no cleanup
or external Windows acceptance.

## 2026-10-04 — Require creation-time Windows Job admission before payload release

The indexed Windows CI owner uses a separate privileged noninteractive launcher
with fresh private account/token/storage/desktop authority. Both Job membership
and the explicit pipe handle list are installed at suspended process creation;
there is no create-then-assign, UAC or secondary-logon fallback. Three protected
barriers persist helper, setup/policy and payload authority before their effects.
Independent held-object/token/image/creation identities and receipts precede
literal UCRT argument release; privileged helpers retain separate source bindings.

Missing complete policy, reviewed SDK/loader inputs or independent native owners
retain exclusion. Partial effects and all reservations survive failure for fresh
recovery. The inspected Codex attribute source is a precedent only; the release
audit's four findings and all external Windows acceptance remain unresolved.

## 2026-10-04 — Keep native Git proof authority separate from providers

Darwin file cases now compose the held-descriptor helper with independent
native identities, exact bytes, acknowledged faults and receipt-bound recovery.
Concurrent requests share one parent owner; concurrent replacement readers must
report every complete old-or-new read rather than relying on barrier samples.

The disposable Git executor accepts only the fixed fixture edit and subject.
Its native children, objects, refs and metadata are independently inspected;
ordinary and provider profiles never receive its grant. Demonstrated pure commit
predicates moved to the existing native evidence owner with Linux compatibility
exports, while platform effects remain independent. Missing native owners or
bindings retain exclusion and protocol observations close no source finding.

## 2026-10-04 — Account for Darwin file publication aliases during recovery

Darwin file transactions now retain root/parent descriptors and bind native
volume UUID and file identities instead of granting pathname authority.
Exclusive publication records its sole temporary two-link alias before removing
the staging name; replacement uses a same-volume atomic rename. This makes
interruption boundaries explicit without claiming universal power-loss durability.

Protected receipts, fresh payload retirement and exact helper settlement precede
identity-checked cleanup. Unknown objects and unsupported volume/synchronization
contracts retain reservations. Native builds, independent readers and external
proof remain prerequisites; protocol observations close no acceptance finding.

## 2026-10-04 — Preserve Darwin policy until verified owned restoration

Darwin profiles now generate deny-default Seatbelt grants from exact reviewed
images and private paths. No-state PF rules check the sending and receiving UID
on both request and return traffic; endpoint blocks also reject unknown owners.
The private PF bridge admits root helper and worker separately before fixed
anchor-only effects, with independently inspected rules and protected receipts.

Ready outside controls and native events replace absence-of-effect or timeout
claims. Policy restoration requires fresh retirement, no live reserved-UID
process, exact helper settlement and unchanged owned configuration. Uncertainty
retains policy and reservations. Required SDK/reader/tool reviews and external
proof remain explicit inputs; source and pure tests cannot establish acceptance.

## 2026-10-04 — Retain Darwin exclusions through independently verified retirement

Darwin recovery binds protected candidate receipts to immutable UID/audit
credentials and a hard inherited process limit. Separate root audit custody
stays alive while old verified helpers are stopped and bounded complete UID
views drive task-token SIGKILL. Unknown zombies, stale identities, missing rights
or exhausted work retain exclusion rather than substituting a PID or timeout.

A fresh native verifier must establish no live creator and exact helper
settlement before custody acknowledgement. Reservations remain retained for
their later owned release. External fault fixture source and nonce acknowledgements
define fork/recovery cases; pure tests and matching status fields
cannot close source findings or establish macOS acceptance.

## 2026-10-03 — Park Darwin payloads behind complete private authority

The new CI-private Darwin owner pairs a small root launcher with bounded pure
admission contracts and independent verifier joins. Literal exec vectors, fresh
audit identity, explicit saved-ID/group drop and sanitized Mach/descriptor rights
precede a parked release barrier. Root session custody and verifier identities
are tracked separately rather than inferred from ancestry or audit membership.

Inspected XNU requires replacing the group slot left by `setgroups(0)` and
rejecting privileged/unknown host ports or uncleared task-access rights without
weakening SIP. Complete reviewed loader/policy/source inputs and fresh protected
receipt verification remain prerequisites. Missing verifiers or retirement keep
execution disabled; failure retains reservations. This implements admission
source without claiming macOS acceptance or closing the four source findings.

## 2026-10-03 — Provision reviewed Linux inputs before owned compilation

The existing external Linux preparation path now publishes the legacy build
and release inputs from a complete candidate-bound manifest and independent
approval digest. Expected GCC snapshots, helper bytes and runtime ABI inventories
join separate publication/source/build/license bindings; live observations
cannot create them. Exclusive immutable files and a last-published completion
manifest prevent partial or repeated preparation from admitting a build.

Bounded held-file reads and a separate write-ahead preparation report preserve
input substitution, interruption and exact missing prerequisites. Credential-free
PR jobs retain the completed ownership/access foundation while missing review
blocks file/build/release acceptance. Existing native mechanisms, release-v1,
all four source findings and external-only proof responsibilities remain intact.

## 2026-10-03 — Separate provider publication pins from executable authority

The CI-private native owner selects exact three-platform Codex and Claude
publications, retaining Codex's unsigned tag and Claude's opaque dispatcher.
Complete independently approved member/closure reviews precede bounded streamed
acquisition and data-only extraction. Neither observed bytes, wrapper scripts,
moving transport documentation nor a matching package creates native authority.

Large archives use separate limits without weakening the historical prepared
input contract. Exclusive quarantine admits no installer, updater, platform
fallback or unknown member. Windows Bash/7z and release-bound opaque-provider
transport/build/license gaps remain explicit blockers for dependent acceptance;
installed Runner backends and all four source findings retain their semantics.

## 2026-10-03 — Keep reviewed system pins separate from CI observations

The existing CI-private public-input/evidence owners now define bounded system
manifests and API obligations for every declared platform. Complete reachable
dependency closures and separate publication/source/build/license/ABI/privilege/
policy pins prevent observations from creating expected authority. Independent
comparison checks the exact candidate, actual OS/SDK envelope, inventories and
all bindings; missing and unsupported material stays explicit.

The supplied XNU revision is recorded with its macOS 15.6 distribution mapping,
without claiming equivalence to a 15.7.9 kernel or future CI image. Windows
SDK/WDK composition and Linux tracing/toolchain closures remain review inputs.
Even matching data leaves admission and all four source findings blocked:
consistency alone cannot establish reviewed native mechanisms or full acceptance.
Historical catalogs, Linux release-v1 and production boundaries are preserved.

## 2026-10-03 — Separate journal append capacity from readable history

Journal capacity now resolves through root and protected project configuration,
defaulting to 512 MiB with strict byte bounds. Storage policy alone may reload
for subsequent appends; workflow configuration remains frozen. Ordinary Runner
and shared MCP stores use one composition path, while public injected policy
remains authoritative. Safe chunked reads retain a fixed ceiling and raw-byte
offsets, so lower capacity leaves valid history readable and recoverable.

Admission includes the newline and precedes incomplete-tail repair. Trusted
cleanup failures retain their original error and cause across both lease-release
failures, preserving exact same-run responsibility until retirement is journaled.
Supported recovery increases effective root or explicit injected capacity without
editing protected project input or ownership records. Replacement requires exact
owner death or replacement; otherwise ownership stays excluded and durable.

## 2026-10-03 — Compose Linux system proofs with reviewed release bindings

The explicit CI-only system owner now composes ownership/access, independently
retired pinned compiler execution, all six file cases and release audit in a
version-5 job. Group admission is persisted before effects; completed records
survive later failure. Reporting cleanup cannot supply missing retirement.
Missing reviewed build/release inputs leave dependent checks BLOCKED/NOT_RUN.

Release observations recheck used binaries, build snapshots and ABI files while
keeping supplied publication/source/build/license bindings separate from
observed versions, digests, privileges and effective policies. The complete
session inventory derives Linux probe/step/job limits with reporting/upload
reserve. No observed component creates a pin or closes a source assumption.
All 23 system and six provider checks per platform and four unresolved source
findings remain required; real native and protected provider acceptance stays
external and operator-owned. Local effect-free coverage grants no platform GO.

## 2026-10-03 — Bind Linux rejection and cleanup to native guards

The fixed six-ID file suite now covers ancestor/leaf substitution, symlinks,
private-procfs magic links, mount crossings, hard-link aliases and synchronized
identity-matched cleanup. Reached native guards retain operation-specific denial
records and observed normal settlement; generic errors, crashes and timeouts
cannot establish rejection. The denied operation stays failed.

Trusted controls act only at parked barriers under separate identity-bound
ownership. Default helper and ordinary fixture grants remain unchanged; closed
case policies bind the necessary private procfs/read-only sentinel mount to
protected receipts and independent inspection. Fresh non-emergency retirement,
unchanged sentinel observations and protected control restoration precede
recovery or another helper. Unknown objects and uncertain cleanup stay excluded.
The frozen subcase/session inventory owns explicit bounds; existing ownership
proofs retain authority-loss coverage. Complete system/release composition and
fresh external observations remain pending, with all source findings and
platform/provider acceptance requirements intact.

## 2026-10-03 — Prove Linux publication and interrupted replacement

The CI-private file case owner adds privacy, concurrent exclusive publication
and prepared/published replacement interruptions through protected sessions.
Independent fixed-name observations bind identities, private modes/ownership
and complete bytes; serialized parent authority makes one publication winner
stable across losers without exposing descriptors or mutation grants to payloads.

Declared interruption is separate from operation success: original sessions stay
failed and excluded, while fresh non-emergency retirement and identity-bound
recovery/cleanup are required before the proof or a later case can pass.
Admission and immutable evidence precede helper/recovery effects. Injected
coverage retains emergency, uncertainty and unexpected-failure rejection.
This three-case foundation leaves complete-suite dispatch, release integration,
source closure and fresh external native observations pending; it confers no
platform or protected-provider acceptance or universal power-loss guarantee.

## 2026-10-03 — Version Linux file and release evidence by effect group

Explicit version-5 CI-private envelopes now admit the six existing file checks
and release audit while the producer remains on version 4. Historical job
inventories and semantics are preserved; no partial suite or aggregate inventory
change accompanies this contract.

Separate ownership, access, compiler, helper and release-probe ledgers precede
effects. Compiler retirement precedes helper admission; missing possible effects
retain their own obligations without making unreached groups look attempted.
Independent non-emergency settlement remains separate from reporting cleanup.
Incremental check records preserve earlier groups and failures, and bounded
supporting references retain identities/digests rather than raw diagnostics.
Actual file/release policy groups and independently bound same-revision joins
keep runtime, component, phase and provenance conflicts visible. This prepares
complete Linux integration without native acceptance, provider dispatch or
closure of any retained source finding.

## 2026-10-03 — Restore protected Linux file session authority

The CI-private session owner now admits the static helper through the existing
protected launcher and registration barrier, independently checking executable,
namespace and mount identities before commands. Held anchor/parent descriptors,
current named-object checks, serialized operations and the helper lock retain
sole parent authority without payload grants, inherited descriptors or procfs.
Ordinary fixtures and the ownership proof inventory remain unchanged.

Comparable policies retain a stable digest while protected receipts separately
bind each anchor. Recovery consumes protected admission, readiness and native
operation/barrier records rather than accepting caller-supplied object IDs;
fresh independent retirement precedes another helper. Command intents and
immutable barriers precede their effects, and original failure/interruption
evidence survives later recovery. Deadline, owner-settlement and diagnostic
emergencies remain sticky even when a declared interruption exists. The
non-resetting admission budget and separate settlement/verifier bounds remain
explicit. Native effects stay external CI-only; the file suite, job evidence
and release integration remain subsequent work, without three-platform/provider
acceptance.

## 2026-10-03 — Bind safe failing-file identities and Runner timing

The supported exact repository-check launcher now retains canonical selected
failing-file identities from Node TAP diagnostic locations. Its original
Git-inspected inventory, launcher contract and content/command bindings survive
service, persistence/reload and public revalidation without trusting later
worktree discovery. Titles, stacks, arbitrary output and absolute paths remain
excluded. Fast batches retain dot and private TAP reporters from one invocation.

An injectable monotonic Runner clock measures actual exact-command execution.
Bounded timing remains in existing evidence arrays on success and executed
failure, matches generated failure issues, and reaches terminal confirmation or
finding resolution according to the outcome. It is observational, cannot grant
PASS or alter recovery authority, and does not invent historical timing or add a
timing migration. Success discards output diagnostics; blocked outcomes expose
no unbound file identities. Self-hosted changes require freshly loaded Runner
code before finalization through settled public pause/resume when necessary.

## 2026-10-02 — Restore identity-bound Linux file transactions

The CI-private Linux boundary now exposes the preserved file transaction
protocol alongside the helper/build foundation. Closed bounded requests and
immutable acknowledgements bind each operation to its nonce, anchor and native
identities. Ordered prepared/published barriers control continuation, and a
known publication winner cannot be replaced by another publication result.
Captured requests and authority bindings prevent asynchronous callbacks from
redirecting the operation being checked. Initialization requires no held
allocation, leaf or temporary identity.

Protocol success still retains exclusion. Storage release requires fresh
independent non-emergency retirement and successful cleanup; native removal
alone and later cleanup cannot erase an earlier failure. Deterministic injected
regressions cover authority rejection, barrier interruption, substituted
identities, recovery and settlement. Protected session admission, native proofs
and complete-suite dispatch remain pending; external acceptance is unchanged.

## 2026-10-02 — Restore the confined Linux helper/build foundation

The CI-private Linux owner now contains the preserved fixed-command C file
helper and candidate/source-bound compiler boundary. Held descriptors and
current named identities constrain publication, synchronized replacement and
cleanup under sole parent mutation authority. Explicit timeout handling retains
uncertain storage instead of guessing cleanup targets.

Separately reviewed system input pins become verified private snapshots;
the fixed Ubuntu CI compiler sees only those inputs and bounded source/output.
Build records distinguish compiler/input/helper identity and static ELF closure
from publication, licensing and source approval. Missing inputs have no host
toolchain fallback. The public Linux boundary supports effect-free pin/ELF
coverage without activating helper sessions or file-suite dispatch. Native
compilation, system/provider acceptance and all retained source findings remain
external and unproved. The completed diagnostic prerequisite is preserved.

## 2026-10-02 — Retain original test diagnostics and finite failure types

Each fast test batch now captures dot and private spec reporters from the same
Node 24 invocation. Failed batches forward their original spec diagnostics;
successful output stays compact, and slow runs retain their original spec
output. Diagnostic reruns and title-based filename extraction are removed,
preserving invocation counts, concurrency, containment batches, executable
temporary storage, and launcher-owned cleanup.

Trusted-check diagnostics now retain supported finite node:test failure types,
including `testAborted`, instead of reducing them to a generic stage or omission.
Cancellation, timeouts, and unfinished work remain distinguishable from code,
hook, and subtest failures within the existing bounded evidence arrays. Unknown
types and raw titles, locations, assertions, stacks, and environment values
remain excluded; successful output is discarded. These diagnostic labels do
not change validation outcomes, retry authority, or the complete commit gate.

## 2026-10-02 — Provision protected Linux bubblewrap only in native CI

The declared Ubuntu system job now prepares bubblewrap after reporting and
pinned runtime initialization. A private signed Noble package inventory fixes
the exact version and archive integrity before unprivileged acquisition and
bounded installation; unexpected dependency changes and insecure acquisition
are rejected. Canonical executable protection and recorded version/digest bind
the unchanged fixture and namespace probes. Write-ahead preparation receipts
keep failed or interrupted setup from releasing payloads and survive always-run
reports/uploads. Production consumers, configuration and canonical skills remain
unchanged. Installation and injected local regressions supply no native proof:
fresh external same-revision evidence and all retained source/provider closure
remain necessary.

## 2026-10-02 — Separate native non-admission from uncertain process settlement

CI-private version-2 results distinguish producer-known non-admission from
possible process effects. Version-4 jobs persist possible admission before
Linux proof invocation so interruption cannot hide controllers behind absent
receipts or empty results. Only explicit compatible non-admission suppresses
derivative cleanup/retirement findings; setup failures, earlier attempted
observations, emergency cleanup and uncertain retirement retain their meaning.
Legacy reporting inputs stay readable without inheriting native retirement;
fresh cleanup claims use the current evaluator. Conflicting job markers retain
unknown effects, while known unadmitted records claim no effective policy.
Platform-scoped reports cannot yield aggregate GO, and deterministic bounded
annotations expose primary stages and reached prerequisites before proof gaps.
The full three-platform inventory, seven contracts, four source findings and
protected provider gate remain unchanged. No new macOS/Windows probe is
admitted, and local effect-free validation supplies no native acceptance.

## 2026-10-02 — Preserve bounded Linux prerequisite diagnoses through CI evidence

Version-3 native jobs add a closed prerequisite chain while retaining version-1
reporting inputs and version-2 native records. CI distinguishes fixed-system
discovery, executable identity/protection and actual public namespace outcomes
before subsequent fixture requirements. The first failed prerequisite retains
only bounded observed facts; later checks stay NOT_RUN. Candidate, observed
image/build/runtime and provenance accompany the missing-input artifact and
survive reporting and independent joining. This diagnostic cannot attest native
cases or retirement, infer a host-policy cause, or justify installation or policy
changes. Production APIs and strict aggregate/source/provider acceptance remain
unchanged; native proof requires fresh operator-controlled external CI.

## 2026-10-02 — Record source-backed native admission gaps without extending authority

Prepared-source research now distinguishes the released Sandbox Runtime wrapper
routes from a partial pinned Rust candidate with no PE/source binding. The
candidate's outer-Job assignment fallback and process-protection warnings do not
meet fail-closed admission; setup, trust, shared-SID grants and reset-preserved WFP
state also need independent settlement. macOS wrapper IPC/network grants supply
no recovered domain, and each provider separately lacks release-bound enabled-tool
enforcement closure. The native owner records exact citations, missing inputs
and bounded next proof cases. Existing CI/Linux proof code remains the executable
reference; no non-Linux helper, provider execution, production integration or GO
claim is admitted. Final immutable same-SHA system/protected acceptance and any
dependent implementation plan remain external to this continuation.

## 2026-10-01 — Verify prepared public bytes without admitting candidate execution

The CI-private native index now exposes an offline verifier and report consumer
for separately reviewed provenance and immutable prepared bytes. Expected and
observed digests, pinned Git blob identities, prior archive verification, missing
members, licensing and build/ABI/setup assumptions remain distinct. The retained
Sandbox Runtime archive reconciliation is not repeated; partial pinned Rust
source and matching publication/helper bytes cannot establish release equivalence
or close the native findings. Missing Codex, Claude and build-matched macOS
bundles block only their dependent candidates. Retrieval, installation and
downloaded build-script execution remain outside role authority, with exact
dependency/lifecycle and toolchain closure required before any later admission.

## 2026-10-01 — Extend confined Linux proofs with access profiles and fixed Git authority

CI-private synthetic repositories now separate read-only inspection, workspace
edits and disposable trusted-command edits from protected Git metadata.
Ready host TCP and Unix-socket controls distinguish actual denial from absent
setup and private loopback from host loopback. A fixed executor alone receives
synthetic metadata writes for one file and exact subject; independent refs,
configuration, identity, message and sentinel comparisons reject extra effects.
Profiles reuse the existing acknowledged admission and retirement protocol.
Production policies and Runner commit authorization stay unchanged. Local
coverage remains effect-free; kernel/provider acceptance and all file-helper
guarantees remain external and unclaimed.

## 2026-10-01 — Add confined Linux ownership reference cases to system CI

The indexed Linux CI owner reuses the existing public owned-process APIs and
registration barrier while adding a minimal inner filesystem/network fixture.
Protected namespace-init receipts are independently inspected before payload
release. Readiness and fault acknowledgements drive detached/reparented child,
cancellation, owner-loss, supervisor-loss, and launcher-loss cases. Fresh
verifiers require explicit same-boot procfs absence; null, inaccessible,
substituted or mismatched identities retain exclusion without numeric-PID
signals. Emergency cleanup cannot repair a failed case. Only implemented Linux
launch/ownership records enter the exact job envelope; missing prerequisites
and every other native/provider contract remain BLOCKED. Real proofs stay
CI-only, with injected local protocol coverage outside ordinary discovery and
no production integration or native acceptance claim.

## 2026-10-01 — Dispatch declared native CI with independent artifact receipts

The native PoC workflow now resolves one candidate SHA for its three declared
x64 images and records setup, reporting-harness probe, and cleanup separately.
Reporting starts before pinned Node setup; always-run summaries and bounded
artifacts preserve ordinary failures. A read-only controller joins actual
workflow/run/attempt/job metadata to the pinned uploader's API-visible artifact
receipt, rejecting missing or substituted evidence. The pure protocol boundary
remains effect-free, and CI execution stays outside production and ordinary
test discovery. Reporting success leaves every unimplemented system check
BLOCKED; the aggregate gate cannot pass without source closure and complete
same-revision system/protected acceptance. Provider dispatch remains inactive.

## 2026-10-01 — Admit independent native proof evidence and reporting

The separately reviewed continuation introduces a pure, indexed evidence and
reporting owner under `ci/native/`. Its fixed platform/check inventory joins
candidate-bound source and native records with independently supplied CI
artifact/job evidence. Missing source closure, phase failures, cancellation,
inconsistent metadata, or unretired work cannot pass; reporting success does not
establish native acceptance. Synthetic harness tests stay outside ordinary
discovery. The historical audit and seven contracts remain intact, while real
system/protected evidence and all dependent native/provider admission remain
external. Production consumers, configuration, canonical skills, and old run
state retain their existing behavior.

## 2026-10-01 — Reconcile the retained native audit and block dependent work

The [native PoC audit](ci/native/README.md) is reconciled with current
documentation, preserving its seven contracts, complete invariant inventory,
and technical NO_GO findings for macOS ownership, Windows admission/recovery,
provider mediation, and release closure. Historical source observations remain
distinct from authenticated release integrity and native/protected acceptance;
retained bytes confer no fresh validation or inherited approvals. Source/API
closure must justify admission, effective authority, protected receipts,
recovery, and verified retirement before dependent installation or execution.
Further native implementation requires research and an accepted revised plan
with a new run; the historical twelve-step plan grants no continuation.
This reconciliation adds documentation only. Production consumers, canonical
skills, configuration, and ordinary discovery remain unchanged. Native proof
stays external, with publication, credentials, and authorization operator-owned.

## 2026-10-01 — Clarify optional supervision and Runner-owned recovery

The common operator guide recommends following assigned operations through
verified completion, cancellation, or a blocker requiring user input or new
authority, while preserving optional monitoring and detached starts or early
returns. Ongoing launches are reported honestly; later notification requires
an active mechanism. Observation prefers one long event-driven wait, and status
questions do not cancel execution or observation. Recovery diagnoses read-only,
repairs only authorized external prerequisites, and resumes the same run through
its offered actions. This keeps assigned work and settlement inside Runner
workflows without treating a pause or wait ending as authority for manual
completion. Owning summaries link to the common guide; authorized preparation
and genuinely non-resumable recovery retain their existing boundaries.

## 2026-10-01 — Retain safe trusted-check failure diagnostics

Trusted commands continuously drain stdout/stderr through a bounded private
collector, retaining only finite Node/node:test error classes, Prettier stage
labels, and a fixed omission explanation. Successful output is discarded.
Service revalidation keeps raw text out of existing check, issue, and pause
evidence. CLI/MCP expose failed-check diagnostics only with frozen Runner
provenance, content and validation bindings, and matching generated issue IDs;
applicable Runner-blocked pauses preserve their safe evidence directly.
Readiness, isolation, verified retirement, correction budgets, retry eligibility,
and persisted shapes stay unchanged. Historical opaque failures gain detail only
through an authorized normal retry, and the focused owned-process regression
does not establish native provider support.

## 2026-10-01 — Align Codex readiness guidance with its Git audit

Codex commit-readiness instructions now derive the permitted inspection list
from the same private set used by the command audit, so the prompt and audit
describe the same Git policy. Fresh, continued, and reconstructed requests
share the guidance and reserve staging and commit creation for the constrained
executor. The inspection allowlist, authorization, sandbox, rejection classes,
redaction, and recovery rules remain unchanged.

## 2026-10-01 — Preserve bounded commit-readiness rejection categories

Codex readiness policy rejection now distinguishes reported workspace changes,
forbidden Git operations, and invalid readiness objects without retaining native
operations or response data. The validated category survives consumed pre-effect
recovery and produces one fixed CLI/MCP explanation after Git proves no commit
was created. Authorization retirement and fresh-attempt requirements remain
unchanged; legacy records remain valid without inventing missing evidence or
changing state versions. Read-only `git config` remains rejected and `git var`
remains allowed:
adapter-owned instructions now state both explicitly. Recovery explanations
preserve resumable content and direct operators to supported reconciliation and
installed-adapter repair, without treating reported file-change items as proof
of content mutation or inviting edits to frozen inputs. These categories and
inspection restrictions do not establish the cause of historical failures. The
constrained executor and all Git safety boundaries remain intact.

## 2026-09-30

- **Tracked content remains isolated from unrelated project context.** The
  repository-wide working agreement now excludes foreign names, paths,
  identifiers, domain details, and contextual examples from tracked content.
  Test authoring applies the same boundary to assertions, deny lists, and
  fixtures, using minimal synthetic values that exercise only the owned
  contract. Finalization verifies the boundary across the complete tracked
  change before handoff.

- **The local issue index records order and a durable processing cursor.** The
  [operator contract](docs/product/OPERATOR_MODEL.md#local-issue-index) specifies
  the ignored `LOCAL_ARTIFACTS/agent-runner/issues/index.json` artifact while
  keeping issue Markdown authoritative. Maintenance preserves the stored prefix
  and appends unique discoveries in timestamp/path order. Invalid paths and
  stored duplicates are rejected; missing pending reports block advancement,
  while processed missing paths remain only as historical cursor anchors.
  Successful processing precedes atomic replacement and syncing of the complete
  index. This supports deliberate operator bookkeeping without automatic backlog
  loading or new CLI, MCP, prompt, or public run surfaces.

- **Provider inactivity consumes one durable reconstruction allowance.** New
  runs freeze and fingerprint a root/project timeout, defaulting to 30 minutes;
  legacy runs migrate without configuration reload. Both providers reset only
  on validated semantic progress and suspend while owned commands are active.
  Expiry is journaled before termination. Each pipeline reconciles safe partial
  content and corrections before reconstructing the same role without another
  source fork. Native fresh fallback shares the allowance, and restart cannot
  replenish it. Repeated inactivity pauses for explicit resume. Commit readiness
  retains pre-effect proof; constrained effects and trusted commands keep their
  own boundaries. CLI and MCP share bounded activity without native payloads.

- **Provider progress is an internal validated lifecycle.** Both adapters emit
  only closed semantic/tool event kinds and an active-command count, keeping
  overlapping commands independent and native payloads private. Codex correlates
  App Server notifications; Claude consumes bounded stream JSON while retaining
  terminal output, session, and failure contracts. Heartbeats and command output
  are not semantic progress. This preparatory contract changes no public
  activity, deadline, or retry policy.

## 2026-09-29

- **Authentication recovery is one durable operator checkpoint.** Every
  pipeline now consumes only the normalized `authentication_required`
  disposition, reconciles read-only or safe writable state, and persists the
  same fixed redacted pause without availability retry or backoff. When the
  response supersedes an active availability episode, the runner retires that
  episode before persisting the authentication pause. Active-turn retirement,
  the pause, and source-fork recovery are one durable transition. Null resume after
  reauthentication preserves roles, lineage, fingerprints, and correction
  accounting, including completion of an already charged finding-resolution
  round at the fix limit. A source-fork failure retries that fork only with
  no-effect proof; possible-effect evidence persists the logical role/context
  and reconstructs it fresh so an unrecorded native child is never duplicated.
  Local-commit readiness additionally keeps its pre-effect proof and Git
  verification-only boundary before replacing a
  one-shot authorization; CLI and MCP expose no provider-private diagnostics.

- **Authentication-required failures have one redacted disposition.** The
  provider-neutral failure record now distinguishes a terminal authentication
  requirement from availability, authorization, permissions, usage limits,
  malformed requests, and ambiguous effects. Codex emits it only from a
  bounded, structurally valid HTTP 401 authentication envelope in completion
  or App Server request-error paths; conflicting evidence and HTTP 403 remain
  outside the classification, and native messages, identifiers, payloads,
  URLs, and credentials never cross the adapter boundary.

- **Dead lease owners are reclaimed by identity rather than age.** Current
  same-host execution and canonical-worktree leases can be replaced immediately
  only when their boot/PID/start identity proves the exact owner dead or
  replaced. Reclaim markers, mutation-boundary token and identity rechecks,
  atomic replacement, and worktree ownership policy remain intact; legacy,
  identity-free, foreign-host, live, invalid, and unverifiable records continue
  to block competing owners.

- **Client attribution is frozen per run at the root boundary.** Only
  runner-root configuration may select the normalized provider-visible
  identity. Resolution admits a custom value only when every active provider
  descriptor supports it, then persists the value and fingerprint in the
  immutable common envelope. Resume reconstructs adapters from that snapshot;
  legacy runs receive the generic default without configuration reload, and
  prompts, projections, activity, and diagnostics disclose neither string.

- **Provider-visible client identity has one descriptor-owned contract.** The
  public agent boundary now validates and freezes exact `{ name, title }`
  attribution with the generic Agent Runner identity as its default. Codex
  carries either default or custom identity in App Server `clientInfo` beside
  the package version. Claude declares custom identity unsupported and rejects
  it before provider activity because its documented CLI has no transport for
  that value; the generic default remains usable. Attribution is not smuggled
  through sessions, commits, or environment variables, is redacted from
  failures, and makes no promise about provider dashboard bucketing.

- **Polishing owns source-projection discovery and migration independently.**
  Its bootstrap and validation migration now require the same closed boolean
  need without importing plan-execution internals or allowing agent-selected
  paths. Version 17 defaults historical reports to no projection while
  preserving frozen authority, review and correction evidence, workflow
  position, and handoff recovery. Projected results remain fingerprint-bound,
  invalidated by content changes, and accepted only through terminal review
  before runner-owned staging.

- **Plan execution discovers source-projection needs without choosing paths.**
  Bootstrap and validation migration now require a boolean projection need for
  every exact-command capability report. Accepted needs remain additive and
  frozen-authority checked; finalization runs an active projected check only
  against its fingerprint-bound source. The ordered state migration defaults
  historical reports to no projection while preserving workflow position,
  review and correction evidence, immutable snapshots, and consumed-effect
  verification.

- **Writable validation uses exact disposable source, not host authority.**
  Trusted snapshot version 4 adds the closed `sourceProjection: true` command
  capability. The runner journals an owned allocation, reconstructs frozen HEAD
  plus the accepted staging-independent workspace source without the index,
  ignored untracked files, or Git metadata, and mounts only that copy writable in the
  network-isolated check. Original repository, state/task trees, credentials,
  and undeclared host paths stay absent; projected output is discarded after
  verified process retirement. Repository, allocation, source, command,
  authority, configuration, and evidence bindings fail closed on drift or
  incomplete recovery. Legacy snapshots retain their exact earlier authority.

- **Capability reports now represent actual delegated needs.** Plan execution
  and polishing reject zero-need reports and any supplied command identity that
  does not match the frozen trusted-command snapshot, using their existing
  bounded read-only correction path. Correcting to an empty report array keeps
  an ordinary check agent-runnable instead of manufacturing a `not-selected`
  trusted requirement. Genuine blockers and additive multi-role needs remain
  unchanged.

- **Claude scaffolding belongs to the adapter, outside the validation tree.**
  Both sandbox policies project tool HOME/config separately from provider
  authentication and sessions. Read-only mount preparation prevents optional
  project placeholders and provider cleanup bookkeeping; the launcher applies
  the exact authorized workspace access afterward. The adapter journals its
  allocation before launch and cleans only identity-verified storage after
  process retirement, including owner recovery. Preparation/cleanup uncertainty
  preserves the checkpoint; stronger safety and commit-effect checks still win.
  Agents never clean scaffolding or hide it through ignores, and updated immutable
  receipts require fresh policy proofs.

- **Action-free ownership uncertainty keeps its checkpoint.** Process-proof
  failures retain the active turn, including finalization, until exclusive
  retirement and repository reconciliation permit continuation. CLI and MCP
  share that path; reservations are not live-owner evidence. Detached IPC
  admission persists child identity and journals correlated progress, so exact
  retries survive disconnects and receipt interruptions without another owner.
  Action contention and event-driven dispatch are bounded, as are shared-host
  scans across process churn and ancestry. Exhaustion preserves strict exclusion.

- **Safe provider turns now resume through durable availability backoff.** One
  injected runner coordinator serves all pipelines, preserves reconciled partial
  work and correction accounting, and journals public schedule/start events.
  Response resets share the content-reconciliation write so interruption cannot
  separate progress from its charged correction.
  Capped waits continue without a quota, reset only on provider response, and
  remain abortable under the same lease. Source sessions are never reforked.
  Commit-readiness rejection retains bounded pre-executor evidence across restart;
  unchanged Git verification must precede atomic authorization retirement and
  retry scheduling. Potentially executed effects stay verification-only.

## 2026-09-28

- **Availability retry policy and episodes survive restart.** Common envelope
  version 15 freezes a configurable ceiling with a five-second start and a
  30-minute default. Leased scheduling journals exact role/checkpoint, attempt,
  deadline, and reconciled content binding; capped delays repeat without a quota.
  Legacy migration preserves progress and uses the documented default. This
  prerequisite adds no automatic retry dispatch or timer.
- **Explicit provider availability has shared, bounded evidence.** Both adapters
  normalize transport, overload, model-busy, and server failures through the
  registry-validated contract while retaining terminal and uncertain-effect
  precedence. Native diagnostics stay private. Commit readiness requires
  validated proof that its executor did not start; possible workspace changes
  still require reconciliation. Classification adds no retry scheduler.
- **Opaque trusted finalization failures have an operator-bounded retry.** An
  explicit plan-execution resume from an unchanged `environment_blocked`
  finding-resolution pause reruns complete finalization only when persisted
  checks and generated issues prove every blocker came from runner-trusted
  execution. This removes the dead end caused by deliberately discarded native
  diagnostics without retaining output or accepting host attestations. Mixed
  blockers remain in resolution, repeated failures require another explicit
  resume, and all modes preserve candidate acceptance, terminal confirmation,
  frozen validation bindings, and correction accounting.
- **Execution validation follows the planned commit's guarantees.** Bootstrap
  preserves each active role's command-to-step assignments and derives a complete
  ordered inventory for every canonical step. Finalization and terminal
  confirmation bind the active step and exact evidence; later slow checks stay
  available without running early. Trusted preparation still examines the full
  frozen catalog, and accepted inventory amendments cannot alter future steps.
  State version 23 marks version-22 evidence provisional and requires fresh
  mode-required read-only discovery before unfinished work, preserving journal
  history, correction accounting, and verification-only consumed effects. This
  fixes repeated future-contract slow suites without weakening applicable checks
  or changing their concurrency.
- **Shared-host recovery distinguishes unrelated protected processes without
  weakening containment.** Common envelope version 14 records the owned
  supervisor's control-group identity before provider work. When another
  same-user process protects its environment metadata, live cleanup and
  recovery may ignore it only after its lineage reaches no owned evidence and
  its stable control-group identity proves it belongs elsewhere. Matching, missing, malformed, legacy, session, or
  ownership-token evidence remains fail-closed. This prevents unrelated
  desktop sandboxes from blocking provider retirement while preserving the
  existing PID, boot, namespace, ancestry, and descendant guarantees.
- **Eligible provider launch recovery is durable and provider-neutral.** After
  bounded adapter reconstruction, a transient `not_started` or `exited`
  failure with no effect and no commit-executor evidence may persist only its
  normalized class and early launch checkpoint on `backend_unavailable`. CLI
  and MCP project that same redacted value; operator pause preserves it, while
  accepted resume and cancellation clear it. Source-fork requests retain the
  proof only at `spawn` or `initialize`. A lazy early failure with no recorded
  child atomically restores its one-time marker so resume makes exactly one
  successful source fork without recounting corrections or risking duplicate
  effects. Later fork checkpoints fail closed because native child creation is
  uncertain. Pipelines retain independent pause and lineage policy without
  branching on provider identity.

## 2026-09-27

- **Proved read-only isolation, not command text, authorizes Claude
  inspection.** Read-only and local-commit readiness turns now use autonomous
  permission mode with only Bash and repository read/search tools. Their
  access policy omits broad shell and hosting-command denials that rejected
  safe compound inspection, while collaboration, editing, and web restrictions
  remain explicit. The independently proved sandbox continues to preserve the
  content, Git, remote-write, credential, process-escape, network, socket, and
  outside-write boundaries; workspace-write policy is unchanged. Provider
  receipts now bind the complete effective access-specific permission, tool,
  deny, sandbox, isolation, and CLI version contract so resume cannot reuse
  evidence from the prior policy.
- **Claude restricted-host fallback is capability-driven and immutable.** The
  Claude adapter proves read-only, workspace-write, and local-commit isolation
  independently. It prefers the full native sandbox and accepts Claude's weaker
  parent invocation only after the exact probe recognizes
  nested-user-namespace denial. The authenticated provider-private launcher
  validates a closed argument grammar, rejects malformed or weakened input,
  and applies a small architecture-checked Runner seccomp filter directly
  through one pinned real bubblewrap boundary. The same path handles direct
  model-free probes and model commands without invoking Claude's helper.
  The Claude CLI retains its host provider transport and credentials; only
  command children cross the single Runner user, PID, mount, and network
  boundary with private `/proc`, `/tmp`, and `/run`, read-only host and Git
  views, credential scrubbing, and the requested workspace write authority.
  The filter returns `EPERM` for Unix sockets and every io_uring entry point;
  x64 and arm64 audit checks, one bubblewrap user namespace, sealed filter
  bytes, and fail-closed setup avoid the helper's AppArmor-rejected nested user
  namespace while native policy stays strict.
  Common envelope version 13 holds one provider-neutral receipt slot per
  resolved role and persists only a policy fingerprint and supported-access
  list when that role is required; the fingerprint distinguishes the filter
  contract, architecture, and exact bytes, and resume rejects drift before
  provider work. This restores provider connectivity and safe execution
  without host `CAP_SYS_ADMIN`, host-policy changes, provider branches in
  pipelines, or broader authority.
- **Polishing freezes finalization guidance before bootstrap.** State version
  15 persists the configured policy, selected canonical skill or fallback, and
  its fingerprints before provider work. The selected skill remains mandatory
  validation infrastructure, and missing or changed guidance requires a new run
  instead of a late automatic fallback. Legacy active work rediscovers
  validation under the frozen decision, while terminal and completed-handoff
  recovery remains verification-only.
- **Development validation has a measured one-minute budget.** A canonical
  test-authoring skill rejects redundant tests and artificial waiting. Disposable
  test storage prefers executable tmpfs without changing runtime durability.
  Long cross-service recovery matrices remain explicit slow checks, selected by
  the changed contract and run before release; the ordinary finalization gate
  retains focused safety and regression coverage. TESTING.md owns selection.
- **Stop publication cannot race process retirement for its lease.** The stop
  monitor queues its activity and process-ownership writes before delivering
  cancellation. Native-provider cleanup can then persist retirement instead of
  leaving a dead private-namespace owner because a concurrent write was rejected.

## 2026-09-26

- **Shared-host recovery anchors new lineages to frozen launch ancestry.** Before
  supervisor launch, the runner now captures a deterministic baseline of at
  most 4,096 boot/PID/start identities and journals it with process ownership
  before provider work. Live supervision and replacement-owner recovery use
  the identical frozen evidence, walk every observed hop, and accept a new
  unrelated lineage only when it reaches an unchanged anchor after checking
  session and ownership-token evidence. This closes the stable SSH/tmux case
  where a post-launch inaccessible intermediate is rooted at a pre-existing
  SSH process without letting PID reuse, stale anchors, cycles, reparenting
  exhaustion, namespace mismatch, or owned descendants pass. Common envelope
  version 12 adds the nullable baseline; legacy records migrate without a host
  rescan or invented authority and receive a precise compatibility failure when
  same-boot session recovery needs evidence they never stored.

## 2026-09-25

- **Shared-host descendant inspection tolerates bounded process churn.** Both
  the live supervisor and replacement-owner recovery pin each snapshot entry's
  first readable start tick and retry transient exit or reparenting from that
  PID under one three-attempt bound. A fresh absent read discards only the
  exited entry; reuse, malformed or inaccessible evidence, live ownership,
  surviving descendants, and exhausted churn still fail closed. This lets
  action-free pause and cancellation recovery settle after a dead supervisor
  without weakening the persisted launch cutoff.

- **Shared-host process recovery carries its launch boundary durably.** The
  common envelope now journals the supervisor's boot ID and start tick as a
  bounded launch cutoff before provider work. Live teardown and owner-loss
  recovery may disregard inaccessible process metadata only when a same-boot
  start strictly predates that cutoff; equal or newer processes, PID reuse,
  missing or corrupt evidence, and surviving descendants still fail closed.
  Legacy records derive the cutoff from valid supervisor identity, allowing
  action-free recovery to retire the original checkpoint without reacquiring a
  worktree lease it already owns. Owner loss before target launch retires the
  inert supervisor directly, closing the crash window around registration.

- **Execution-owner recovery separates lease, recovery, and process facts.** A
  current owner now performs bounded supervisor teardown through its private
  control boundary, while replacement-lease recovery proves the persisted
  process and descendants absent before clearing the record. Same-run stop
  reconciliation reuses a held worktree lease instead of reacquiring it, so a
  containment failure remains primary and the reservation survives for retry.
  PID replacement, namespace uncertainty, unverifiable owners, and surviving
  descendants still fail closed. MCP status distinguishes lease-owner state
  from a persisted process record without exposing either identity.

## 2026-09-24

- **Ownerless stops are supervised through durable settlement.** Detached stop
  reconciliation is correlated with its checkpoint and child exit; transient
  run-lease ownership no longer counts as success. Plan execution can settle
  only a descriptor-proven untouched initial `CLARIFY` stop under the run lease
  without acquiring an unrelated canonical-worktree lease, while every possible
  repository or effect checkpoint retains worktree exclusion. Action-free CLI
  resume and exact-revision MCP `run_resume` provide recovery when the original
  stop key is unavailable; MCP records the recovery under a new key. Diagnostics
  distinguish the ownerless pending run from a different recorded lease owner,
  and operators never manually delete or bypass lease records.

- **Trusted validation deadlines are explicit per-run configuration.** Root and
  safe project configuration accept bounded millisecond
  `trustedCommandTimeoutMs`, defaulting to one hour with project-over-runner
  precedence. Version-3 snapshots fingerprint and persist the resolved deadline
  without changing command identities; legacy versions deterministically retain
  one hour, and concurrent runs carry independent values. The hidden service
  override is removed while the 10-second preparation cap, no-output-retention
  boundary, isolation, cancellation, cleanup, evidence, and process ownership
  remain unchanged. Longer deadlines neither repair sandbox incompatibility nor
  explain generic isolated exit failures after a host check passes.

## 2026-09-20

- **Explicit Codex overload is transient provider unavailability.** Native
  `serverOverloaded` now joins opaque `turn_other` on the existing single fresh
  reconstruction for eligible ordinary turns, after turn-item auditing preserves
  policy, protocol, and isolation precedence. Repeated overload pauses every
  workflow at its durable `backend_unavailable` checkpoint with native details
  redacted. Source forks retain their supplied context, local-commit readiness
  remains a proven pre-effect rejection without adapter replay, and writable
  reconciliation preserves safe content while invalidating stale fingerprint
  evidence. The exact historical `turn_other` confirmation exception remains
  unchanged, so no migration reopens immutable overload failures.

## 2026-09-17

- **Initial implementation needs an observed content change.** Execution persists
  step-start HEAD/content evidence before writable work and retains it through
  interruption and mutable baseline updates. No-op initial completion requires a
  revised plan before convergence; unchanged corrections remain valid. Version-20
  recovery requires journal proof for legacy evidence and never guesses from the
  current workspace. Verified consumed commits settle before new-work guards.

- **Execution context cannot advance the plan.** Bounded step assessments and a
  separate read-only narrative review reject already-landed claims and directions
  to skip or reorder the selected step. Matching numeric fields are insufficient;
  quoted examples and whole-plan discussion remain valid. Legacy summaries must
  be rediscovered before new writable work, after consumed-effect settlement.

- **Execution rejects stale plans before writable work.** The root Git capability
  supplies HEAD's subject; the validated plan and verified completed commits
  alone select the leading step. Existing subjects and external HEAD movement
  require a new plan/run without adopting commits. Paused step one can remain
  visible before bootstrap completes. Consumed effects settle first, stop
  recovery starts no new effects, and verified settlement retires interrupted
  commit context before selecting the next step.

- **Polishing blocks unsatisfied check capabilities before writable work.** Its
  own bounded reports preserve every active role's exact-command needs without
  granting authority. Availability is rechecked at each writable checkpoint and
  before new handoff staging; environment repair retries the frozen request.
  State version 14 requires read-only legacy discovery while keeping completed
  handoffs verification-only and preserving safety pauses and correction charges.
  Preparation never executes required checks. Discovery, migration, interruption
  recovery, and staging guards form one boundary and must ship together; separate
  pipeline-owned schemas preserve ownership without importing execution internals.

## 2026-09-16

- **Execution checks capability requirements before writable work.** Bootstrap
  and legacy validation migration persist exact-command needs from every active
  role. The root evaluates additive reports against frozen authority and current
  availability at every writable checkpoint, independently of cached preflight.
  Unsatisfied needs pause for environment repair; agents cannot grant authority
  or discard another role's requirements. State version 18 preserves consumed
  commit verification ahead of discovery. Discovery, migration, and writable
  guards form one boundary: shipping a subset could admit work under provisional
  requirements. Availability preparation produces no check evidence; required
  checks still run only during finalization.

- **Capability needs are inspected without running required checks.** The root
  trusted-validation capability matches additive exact-command reports against
  frozen authority and distinguishes malformed contracts from environment blockers.
  Availability preparation reuses durable ownership and runs only a fixed empty
  program in the check sandbox; it never produces check evidence. Dependencies
  are reacquired during finalization. Pipeline discovery and gating remain owned
  by each pipeline, with the runner supplying configuration guards and leases.

- **Verified dependencies share durable execution ownership.** Frozen public HTTPS
  downloads now use journaled allocations before acquisition and a fixed read-only
  digest mount after verification. Checks remain network-isolated; extraction
  belongs to their exact vector and declared scratch. Failures retain bounded
  resumable blockers, and a journaled acquisition owner prevents early cleanup
  after service reconstruction. Common envelope version 10 distinguishes the new
  phase while preserving legacy allocation evidence during migration. Recovery
  cleans old allocations before any fresh download. No partial download is reused.

- **Pinned acquisition separates transport verification from runtime authority.**
  The private primitive shares frozen artifact declaration rules, pins public
  destinations with hostname TLS verification, and bounds transfer and retirement.
  Digest-only publication follows integrity verification and transport closure;
  uncertain ownership preserves files. Production requests remain unavailable
  until durable resource ownership, mounting, and recovery are integrated.

- **Trusted build storage is transient and durably owned.** Scratch/cache mounts
  stay outside repository and control paths. Intent and filesystem identity are
  journaled before launch; cleanup follows verified process retirement. Uncertain
  ownership blocks deletion and interrupted caches are never reused.

- **Trusted execution requests freeze authority before provider work.** Closed
  scratch/cache and pinned-artifact declarations participate in command and
  snapshot fingerprints. Legacy snapshots retain their restricted authority and
  evidence. Unavailable requests pause durably and retry the saved request;
  consumed effects remain verifiable without requiring capabilities for new work.

- **CLI and MCP expose one provider-neutral effort preference.** Run-wide and
  descriptor-derived role overrides share the portable enum and configuration
  precedence. `current` explicitly preserves the provider default. MCP intents
  bind effort before dispatch and detached work reuses the saved selection,
  preventing retries from silently changing execution preferences. Public
  supervision surfaces keep role configuration private.

- **Effort is frozen with active role execution preferences.** Runner and safe
  project configuration share one portable vocabulary and override precedence.
  Inactive roles are validated but never resolved or persisted. Resume reuses
  saved effort, while envelope version 8 migrates legacy missing values to
  `current` under the existing lease without provider activity or rewriting
  journal history. Configuration changes cannot silently alter resumed work.

- **Effort incompatibility is a terminal adapter configuration failure.**
  Provider adapters accept portable effort separately from model identifiers,
  omit native overrides for `current`, and preserve explicit selections across
  session recovery and commit readiness. Native translation and discoverable
  capability checks stay inside the adapters. Unsupported selections return
  one bounded, provider-neutral failure instead of silently downgrading or
  retrying through a fresh session. This keeps recovery from changing the
  requested execution semantics or starting a rejected commit effect.

## 2026-09-15

- **Mode guidance and finalization coverage share canonical owners.** README and
  the operator guide use one identical relative comparison of the three modes;
  token stars indicate consumption, not provider guarantees. Independent stays
  the default recommendation. The canonical finalization skill checks operator,
  transport, example, and owning contract consistency while preserving
  runner-trusted checks and phase-owned staging. Documentation regressions bind
  these surfaces to descriptor defaults and supported commands.

- **Combined polishing completes mode availability.** All three pipelines now
  support primary convergence followed by independent review. Polishing keeps
  self-findings separate, requires both candidate approvals and independent
  terminal confirmation, and limits arbitration to independent findings.
  Existing budgets, isolated sessions, and runner-owned uncommitted handoff
  survive recovery. Independent remains the default and recommendation.

- **Polishing gate evidence has one owner.** Pipeline-private predicates bind
  candidate approval to inspected content and handoff to the separately finalized
  and confirmed content. Routing, validation, migration, and recovery now share
  acceptance and invalidation rules, preserving valid unchanged-resolution reuse
  and completed staging evidence without expanding agent permissions.

- **Polishing mode responsibilities are explicit.** A private policy separates
  role participation, bootstrap, convergence, review, arbitration, and session
  lineage so ordinary and interrupted repair routes agree. Supported modes,
  correction ledgers, and permissions remain unchanged; handoff staging stays
  runner-owned.

- **Combined execution requires both candidate gates.** Worker convergence and
  separate clean confirmation precede independent Reviewer approval of the same
  content. Reviewer terminal confirmation then covers the formatter's result.
  This adds primary repair discipline without replacing independent review or
  broadening commit authority. Only independent finding resolution permits
  arbitration; bootstrap disagreement remains a retryable pause. Saved modes,
  bounded correction accounting, and consumed-effect recovery survive migration.

- **Execution gate evidence composes independently of mode routing.** Shared
  private predicates bind candidate approval to inspected content and terminal
  confirmation to the formatter's result. Repairs and unchanged resolutions use
  explicit invalidation rules across normal execution, migration, and recovery;
  consumed commit effects retain verification-only semantics.

- **Execution mode responsibilities are private pipeline policy.** Active roles,
  bootstrap, convergence, terminal confirmation, arbitration, and session scope
  now have distinct decisions shared by workflow, validation, and recovery.
  The two accepted modes, persisted correction evidence, bounded accounting,
  and repository authorization boundaries retain their existing behavior.

- **Combined authoring converges before independent review.** Authoring alone
  exposes an explicit combined mode, reusing primary check/fix and clean
  confirmation before the complete Reviewer gate. Revisions invalidate both
  approvals, and only independent finding resolution permits arbitration.
  Checkpoint-isolated sessions, read-only turns, durable correction accounting,
  and runner-owned artifact writes retain their existing boundaries. Mode
  availability comes from descriptors; saved modes survive leased migration.

- **Authoring review policy is independent of turn execution.** Private pure
  decisions now separate primary convergence, independent review, session scope,
  correction accounting, and arbitration eligibility. Workflow and state
  validation share those decisions while retaining the two supported modes,
  durable lazy fields, guards, and existing turn implementations.

- **Authorization publication failures preserve durable effect accounting.**
  Deferred-stop fault injection exposed stale workflow failure writes after
  preparation or consumption was already journaled. Execution now propagates
  those failures to existing recovery, preserving prepared authorization and
  verification-only consumed effects. Coverage exercises both stop actions,
  acceptance races, receipt replay, owner loss, and settlement publication.

- **Stop timing is an explicit transport choice.** CLI and MCP expose immediate
  or after-current-commit timing without refreshing inspected revisions.
  Immutable receipts retain acceptance evidence; shared bounded status and
  historical activity summaries retain settlement. Deferred requests use the
  existing quiescent fallback and detached reconciliation, so a disconnected
  caller or canceled wait never grants another owner or asks for extra work.

- **Deferred stops settle at the selected execution boundary.** Execution owns
  target selection; root composition supplies it to state, which serializes
  acceptance and settlement. The monitor permits the target step while still
  observing immediate cancellation. Verification supplies one SHA to the
  existing checkpoint path, including recovery; quiescent fallback preserves
  blockers and consumed-effect evidence without extra work. Final-step pause
  retains `DONE` for an agent-free resume. CLI/MCP status shows timing and target
  while request inputs remain immediate.

- **Deferred stop targets belong to durable state.** A trusted injected resolver
  binds requests to immutable commit-boundary evidence under acceptance
  serialization. Target-step work retains ownership, and crossing requires atomic
  settlement. Timing participates in new identities while historical immediate
  receipts remain replayable. Supersession cannot postpone an earlier stop;
  unsupported capabilities fail closed. Production registration is deferred to
  the runner integration step.

- **Verified commits settle progress and stops together.** Execution owns the
  successful checkpoint construction; state owns its atomic leased publication.
  The runner resolves the latest operator outcome while preserving the verified
  SHA, next checkpoint, and protected-input blockers. Publication failure cannot
  replace journaled progress with stale failure state, and consumed effects
  remain verification-only during recovery.

- **Stop enforcement and ownership accounting have separate policies.** State's
  private stop policy distinguishes pending requests, blocked advancement, and
  retained ownership. Every immediate pending stop still blocks ordinary writes;
  process retirement can complete without releasing unresolved stop accounting.
  Reconciled cancellation remains terminal but does not retain a worktree.
  Mutation serialization, receipt replay, and same-run recovery stay unchanged;
  deferred timing is not yet accepted.

## 2026-09-14

- **Polishing inventories match complete validation ownership.** Polishing now
  accepts 256 entries per bootstrap role and 512 per derived or finalization
  field, with the same responsibility-based infrastructure definition as
  execution. State version 12 preserves saved 64/128 evidence and handoff
  effects under leased migration. Index authority remains runner-owned; byte
  limits and strict Claude preflight and sandbox restrictions remain unchanged.

- **Execution inventories cover complete validation ownership.** Bootstrap roles
  can each report 256 checks and infrastructure files; derived and finalization
  inventories accept 512. Infrastructure is defined by ownership of commands,
  discovery, runners, configuration, or mandatory finalization guidance, not
  by files merely consumed by checks. The shared Git fingerprint input accepts
  512 paths while other path lists and byte limits remain unchanged. State
  version 16 migrates saved evidence without resetting budgets or replaying
  completed effects; polishing retains its existing limits for now.

- **Trusted command catalogs can be project-local.** Safe project configuration
  uses the existing exact-vector validator. Normalized catalogs merge root then
  project, deduplicate identical same-name definitions, and reject conflicts
  even when unselected. The merged catalog retains the 256-definition bound and
  each selection the 32-command bound. Project-only selections use the existing
  immutable snapshot before agent work, with unchanged identities, resume, and
  protected-input guards. Profile implementations and execution sandbox policy
  remain runner-owned; command definitions grant no additional host authority.

- **Commit size is an authoring heuristic.** The persisted
  `preferredCommitLineLimit` defaults to 900 anticipated additions plus deletions,
  including tests and documentation. Planner and review prompts prefer cohesive
  boundaries within that target and require concise explanations for indivisible
  exceptions. Descriptor-driven configuration, CLI discovery, and MCP metadata
  share the default; leased legacy migration supplies it without reloading
  configuration or replaying work. The shared plan format and execution gate
  remain unchanged.

- **Codex shell commands retain the owned-process proof through a narrow
  allowlist.** The provider process keeps its full isolated parent environment,
  while command construction applies Codex's automatic secret exclusions,
  explicit workspace values, and an exact allowlist of standard core names,
  `AGENT_RUNNER_OWNED_PROCESS`, and supplied workspace names. This preserves
  ownership evidence across provider-native PID sessions without exposing
  unrelated parent variables or weakening filesystem, network, MCP, or Git
  isolation.

- **Transient ownership inspection has one bounded recovery window.** A
  completion-time incomplete descendant observation retries against one
  non-resetting descendant-grace deadline before retaining the existing
  fail-closed error and durable exclusion. Once persistent containment failure
  is reported, the parent closes provider protocol resources and unreferences
  the detached supervisor and IPC channel without disconnecting containment,
  signalling unverified work, or clearing ownership, so the run owner can exit
  while deterministic recovery remains possible.

- **Owned-process failure is independent of provider protocol completion.**
  Codex races only owned-completion rejection against the complete App Server
  operation. A supervisor retaining containment and open protocol pipes can no
  longer leave a durable turn falsely running: the original ownership failure
  starts bounded cleanup and remains primary. Successful process completion
  does not substitute for a required protocol result.

- **Owned supervision preserves provider-native sandbox nesting.** Ordinary
  commands retain private PID namespace ownership. Provider adapters explicitly
  identify only executions that create their mandatory native sandbox; after a
  cached full nesting probe fails, those executions alone may use token-backed
  session ownership on the initial host namespace. Live ancestry and a token
  derived from the persisted PID/boot/start proof find provider descendants
  across sessions and nested namespaces, including after owner loss. Complete
  unrelated ancestry remains an independent exclusion proof. A stable
  pre-launch PID/boot/start baseline is the narrower fallback for an unchanged
  inaccessible host process whose ancestry is inconclusive; new, reused,
  changed, owned, and otherwise unproven processes and bounded-cleanup failures
  remain fail closed.

- **Resolved project configuration is protected input.** The same confined
  read that parses a project file now pins its canonical location, content,
  file identity, and real ancestor identities in the durable run envelope.
  Runner-owned checks surround provider turns and guard recovery, trusted
  validation, commit, handoff, and stop reconciliation. Any drift produces one
  bounded non-resumable safety pause without restoring the file or fabricating
  evidence for legacy runs; begun irreversible effects remain
  verification-only.

- **Pause and cancellation are durable controls across CLI and MCP.** CLI
  shorthand captures one inspected revision and fresh idempotency key, while
  repeatable CLI automation and the `run_pause` and `run_cancel` MCP tools bind
  both values explicitly. Exact retries replay state-owned receipts and stale
  requests never refresh silently. A live runner observes the durable stop;
  owner loss starts a detached same-run reconciliation without granting a
  second execution owner. Bounded status and wait projections expose pending
  intent without request identity or checkpoints, wait cancellation remains
  local to the caller, and terminal `CANCELED` work cannot be revived by an
  older continuation.

## 2026-09-13

- **Operator stops reconcile under the execution owner's leases.** The runner
  watches durable stop requests and aborts only its registered provider or
  trusted-command PID namespace. A supervisor waits for registration before
  launching work and starts cleanup when its owner's inherited IPC channel closes.
  System-protected bubblewrap establishes the namespace; its PID 1 lifetime
  contains detached sessions and double forks that process groups cannot retain.
  Envelope version 5 records host PID, boot/start, and namespace identity before
  launch, and retains exclusion until namespace teardown. Live signalling uses
  the original child handle/control channel; recovery never signals recycled
  numeric host PIDs. A nested runner test uses a distinct owned session only
  when the enclosing runner-trusted PID namespace denies another namespace;
  that existing namespace remains the detached-descendant containment boundary
  without added authority. Unsupported isolation otherwise fails closed without
  a group-only fallback. It retains conservative owner-loss recovery. Pipelines reconcile
  frozen inputs and Git permissions without provider work, preserve safe partial
  content, and invalidate affected gates. Consumed commits and begun handoffs are
  verified without replay; observed progress and the requested pause or terminal
  cancellation are recorded together. Null resume restores existing blockers
  before proceeding.

- **Writable turns defer selected trusted checks without deferring repairs.**
  Plan execution and polishing project only persisted exact command text into
  implementation, polishing, lazy check/fix, and finding-resolution requests,
  including continuation, reconstruction, and correction. Established check
  execution and attestation remain exclusive to finalization. Selected-command
  sandbox limitations cannot block applicable repairs or semantic review;
  nondelegated environment blockers preserve the existing safe-content and
  resume paths. No configuration reload, external attestation, or broader
  agent permission is introduced.

- **Legacy confirmation recovery requires journal provenance.** Failed opaque
  terminal confirmations can resume directly after mode-specific candidate
  acceptance, passing finalization, and complete safety revalidation are
  proven under the normal leases. State owns continuous history; the pipeline
  owns proof and shares revision-bound eligibility across CLI and MCP.
  Migration-derived terminal tuples cannot manufacture acceptance. A true
  correction marker survives an already charged fix through unchanged lazy
  checking and finalization, so recovery preserves it when no concrete work
  remains. Durable reconstruction, unchanged evidence, completed commits,
  idempotent receipts, and detached ownership prevent replay or recounting.

- **Structured Codex client errors are terminal even under `other`.** Bounded
  recognition of a native HTTP wrapper and JSON error envelope distinguishes
  non-transient request rejection, including HTTP 400 `invalid_json_schema`,
  from opaque provider failure. Only the fixed `turn_bad_request` diagnostic
  survives; the request is not compacted, retried, or sent to output correction.
  Malformed, ambiguous, oversized, and transient evidence retains existing
  bounded opaque recovery. Item auditing, model selection, source-fork and
  local-commit exclusions, and redaction remain intact without new pipeline
  branches or state migrations.

- **Codex rejects incompatible response schemas before provider activity.**
  A Codex-owned keyword and structural compatibility gate now validates the
  effective schema, including local-commit readiness, before probing or starting
  a turn. Invalid declarations fail terminally without provider recovery or
  output correction. Plan-execution terminal schemas no longer use unsupported
  `uniqueItems`; both runtime normalizers retain deterministic uniqueness,
  bounds, membership, and rejected-result validation. Schema traversal preserves
  literal data and property names, and provider restrictions stay inside Codex.

- **Opaque Codex turn failures use bounded provider recovery.** `turn_other`
  now enters the existing single fresh reconstruction for non-commit requests
  outside source forks. The complete durable request preserves valid workspace
  progress; a repeated failure pauses at the safe checkpoint as
  `backend_unavailable` after repository reconciliation. Only fixed diagnostics
  and safe control fields survive. Local-commit readiness failures retain their
  pre-effect exit, and uncertain commit effects remain verification-only.
  Explicit policy, protocol, and model-selection violations still fail closed
  before recovery.

## 2026-09-12

- **Operator stops have durable state ownership before process control.**
  The common envelope records bounded pause/cancel requests, immutable
  acceptance receipts, and references to exact suspended journal checkpoints.
  A short mutation boundary serializes acceptance with execution-owned writes and
  release without creating another execution owner or locking status reads.
  Cancellation wins competing requests from the same inspected revision, and
  recovery can reconstruct a lost receipt after a later cancellation or
  terminal transition. Pending stops retain held worktree exclusion across
  owner loss until same-run reconciliation. Lease identities now include boot
  and process-start evidence where available; legacy or inaccessible identities
  remain conservative. These state capabilities separate request durability
  from runner-owned signalling and Git reconciliation.

- **Plan execution and polishing repair rejected finalization evidence.**
  Terminal evidence-only findings now return directly to complete finalization,
  preserving candidate acceptance and avoiding unchanged code-fix cycles. Mixed
  findings immediately invalidate evidence and converge content before a fresh
  gate. Two durable semantic retries per execution step or polishing run are
  separate from malformed-output and code-fix budgets; pending attempts survive
  interruption, and exhaustion offers an explicit finalization retry.
  Terminal-fingerprint overrides cannot
  revive an invalidated PASS. Unchanged inventories still require sufficient
  evidence and do not prevent semantic rejection. The new state migration retains
  only bounded validated findings and control metadata while preserving
  commit-effect and runner-owned handoff safety. Polishing retains its existing
  malformed-output correction budget and keeps all agent turns index-read-only.

- **MCP supervision shares guidance and publication with the CLI.** Two thin
  tools read the complete common and local guide or replace the local document
  with an expected hash and idempotency key. The shared capability owns safety,
  concurrency, and interruption recovery, so receipt retries preserve later
  edits from either transport. A single startup reminder applies even when
  issue reporting is disabled; guidance remains supervisor context only.

- **CLI guidance editing shares launch mechanics without sharing exit policy.**
  The CLI reads combined guidance or edits the complete local Markdown through
  a private external copy. Publication retains the original destination,
  configuration, and content hash, so even an unchanged close rejects stale
  edits. Shell-free editor selection and launch now have one root owner;
  guidance requires a successful close while clarification still consumes
  authorization whenever a launched editor closes.

- **Operator guidance has one common owner and a confined local extension.**
  The installed operator guide covers preparation, supervision, recovery,
  validation, and completion across CLI and MCP. The shared root capability
  composes it with the complete optional project-local document, preserving
  common safety precedence and keeping additions outside pipeline roles and
  durable runs. Hash-checked replacement holds canonical-worktree ownership
  and uses atomic publication with durable temporary-file provenance. This
  prevents stale edits, duplicate effects, and incorrect adoption of another
  writer's identical content after interruption.

## 2026-09-05

- **Unchanged terminal repairs retain fingerprint-bound finalization.** Plan
  execution and polishing now clear candidate and confirmation attestations for
  terminal findings while retaining a successful finalization record whose
  content and validation-infrastructure fingerprints remain current. After
  independent or lazy candidate convergence, an exact match retries the distinct
  terminal confirmation directly; actual content or infrastructure changes,
  correction-scope drift, content-changing recovery, and a new commit step still
  force the complete gate to rerun. This removes redundant full-suite work
  without weakening the fresh confirmation required immediately before commit
  or handoff.
- **Compact test output retains complete failure diagnostics.** The normal root
  test command uses Node's built-in `dot` reporter while preserving automatic
  discovery and the bounded concurrency of 4. Passing records no longer flood
  finalization context, while failed-test names, assertion diagnostics, and
  stacks remain available from the same run without a reporting dependency or
  a diagnostic-only rerun.
- **Workflow policy fixtures are lightweight while capability proofs stay
  real.** Plan-execution and polishing state-machine suites inject
  pipeline-owned in-memory effects, split along cohesive behavioral boundaries,
  and expose cross-directory builders only through `test/support/index.js`.
  Focused Git and store integration cases remain serial within their files,
  while root capability and cross-capability suites prove atomic state,
  journals, leases, recovery, filesystem durability, snapshots, commits, and
  handoffs. The root `node:test` command caps file concurrency at 4 to leave
  headroom on the 16-CPU baseline machine after higher bounds exposed
  intermittent contention; isolated suites still overlap without making the
  complete gate depend on maximum host parallelism.
- **Default convergence budgets favor completing difficult corrections.** Plan
  authoring permits 20 revisions, while plan execution and polishing permit 20
  fix rounds, five repeated-finding rounds, and five disputes per finding by
  default. The three-round stagnation window remains unchanged so architectural
  non-convergence is still detected early; every budget remains configurable
  and frozen into each new run.

## 2026-09-04

- **Polishing finalizes only stable semantic candidates.** Independent Reviewer
  convergence, or lazy Worker check/fix plus read-only candidate confirmation,
  now precedes the writable finalization gate. A distinct read-only terminal
  confirmation binds the resulting content and exact validation evidence before
  the runner-owned `HANDOFF`, so formatter changes are reviewed and every repair
  returns through convergence without duplicating staging.
- **Plan execution finalizes only stable semantic candidates.** Independent
  Reviewer convergence, or lazy Worker check/fix plus read-only candidate
  confirmation, now completes before the writable terminal finalization gate.
  One distinct read-only confirmation then binds the resulting content and
  exact validation evidence immediately before `COMMIT`, so intermediate
  candidate corrections do not prematurely run finalization and stale evidence
  cannot authorize a commit.
- **Provider registration is one static, testable composition seam.** A frozen
  descriptor registry under [`src/agents/`](src/agents/) supplies backend IDs,
  adapter factories, native option and profile rules, source-session support,
  and failure classification to root runtime consumers. A fake descriptor and
  source-boundary regression prove that adding a provider does not require
  pipeline branches or private cross-capability imports, while production
  remains source-controlled rather than dynamically extensible.
- **Repository formatting is one root-owned terminal-gate concern.** The exact
  stable Prettier 3 release is pinned once at the root, and the root scripts
  format the Git-visible supported file set while preserving repository and
  local ignore rules. Finalization runs the writable formatter first, then the
  non-mutating repository and whitespace gates, so accepted evidence describes
  the formatted candidate without adding per-workspace tools or configuration.

## 2026-09-03

- **Existing project agent guidance participates in writable turns.** Codex
  protects project-root `.agents` by default, but Agent Runner reopens an
  existing real directory during workspace-write turns so planned guidance
  changes are possible. Complete and recovery role prompts keep that capability
  outside normal maintenance without repeating the rule in compatible
  continuation turns: the task must explicitly request the change, and plan
  execution additionally requires it in the current plan step. A symlinked
  `.agents`, `.git`, and `.codex` retain their provider protection, preserving
  the narrow content-versus-control boundary.
- **Current product meaning and repository decisions have explicit owners.**
  [`docs/README.md`](docs/README.md) is the single document map and change gate,
  while the focused documents under [`docs/product/`](docs/product/) explain
  current guarantees without reproducing pipeline state machines.
  [`docs/CONVENTIONS.md`](docs/CONVENTIONS.md) owns intended engineering rules,
  [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) records the implemented runtime,
  and this file retains the rationale for durable decisions. Reviewers can now
  find business meaning without reconstructing it from code while each exact
  contract keeps one normative owner.
- **Canonical skill instructions are versioned, provider interface metadata is
  local.** [`test/scaffold.test.js`](test/scaffold.test.js) validates each
  canonical `SKILL.md`, and [`.gitignore`](.gitignore) excludes only YAML files
  beneath `.agents/**/agents/`. Codex and Claude continue to share the canonical
  [`.agents/skills/`](.agents/skills/) tree, but an installed agent may create
  its own ignored interface metadata without dirtying the repository or making
  a clean checkout depend on one provider's installation format.
- **Repository placement follows ownership rather than the historical flat
  layout.** [`docs/CONVENTIONS.md`](docs/CONVENTIONS.md) defines capabilities,
  provider slices, intentional public indexes, and present-need promotion as
  the target architecture. [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) remains
  a description of the current implementation and must move with it, so an
  accidental file layout cannot justify new dependency violations.

## 2026-09-02

- **Independent execution remains the default; lazy execution is an explicit
  consumption tradeoff.** The three pipeline descriptors under
  [`pipelines/`](pipelines/) own the same `independent` and `lazy` setting.
  Independent mode retains distinct primary and review contexts for genuine
  semantic review. Lazy mode resolves only the primary role and requires a
  separate read-only clean confirmation, reducing provider use without
  presenting self-review as independent review.
- **Writable provider turns use provider-specific isolation behind one shared
  role contract.** The adapters under [`src/agents/`](src/agents/) block Git
  metadata and remote writes while allowing only phase-authorized content
  changes. Codex receives a runner-owned private temporary root and Claude must
  prove its native sandbox policy before advertising writable capability. This
  keeps provider mechanics private while making the pipeline safety guarantee
  backend-neutral.

## 2026-08-27

- **The Git index has one effect owner per content-producing pipeline.**
  [`pipelines/plan-execution/docs/SPEC.md`](pipelines/plan-execution/docs/SPEC.md)
  assigns staging and commit hygiene to the constrained `COMMIT` effect, while
  [`pipelines/polishing/docs/SPEC.md`](pipelines/polishing/docs/SPEC.md) assigns
  final staging to the runner-owned `HANDOFF`. Bootstrap, finalization, and
  semantic review remain staging-independent, preventing ordinary agent turns
  from turning index state into evidence they control themselves.

## 2026-08-18

- **Pipeline registration is static and the MCP boundary projects the same
  durable runner.** [`src/pipeline-registry.js`](src/pipeline-registry.js)
  explicitly registers independently owned pipelines, and
  [`src/mcp/index.js`](src/mcp/index.js) exposes their control operations over
  STDIO rather than implementing a second workflow engine. Persisted
  idempotency intent, detached continuation, and reconnectable status let long
  runs outlive a client call without introducing dynamic plugins, a network
  service, or a daemon.
