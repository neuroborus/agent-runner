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

## Minimal native feasibility contract

`test/native-windows-toolchain.test.js` exercises the indexed installed-toolchain
selector with injected process and filesystem effects. It protects spaced batch
paths, fixed cmd arguments, setup status retention, bounded discovery/environment
capture, the SDK allowlist, and independent temporary-file cleanup diagnostics.
No Windows process, filesystem or SDK is used locally; actual cmd parsing remains
a matching external worker observation.

`test/native-feasibility-reporting.test.js` belongs to the ordinary fast tier.
Injected reports and native-owner failures cover bounded diagnosis sanitization,
explicit unknown process outcomes, preparation metadata/run binding, skipped
probes, retained first causes and separate escaped cleanup explanations.
On Linux, controlled Bash functions replace package commands while executing
each workflow's actual preparation body, proving update/install status capture
before failure handling. No package command, native probe, compiler or provider
executes. Actual PowerShell/cmd parsing and platform failures require matching
external CI; these regressions add no native or durable slow-gate requirement.

`test/native-feasibility.test.js` belongs to ordinary fast discovery. Its focused
invocation is `node --test test/native-feasibility.test.js`. Pure synthetic
records and injected checkout observations cover SHA/platform mismatch, missing
records, required denial and cleanup evidence, original-cause retention,
protected/model-free separation and confined fixed dispatch. Native operation
injection also proves that revision or observation failure precedes dispatch.
Linux report joins require both distinct access bundles and reject a missing
control, changed sentinel, absent observation or emergency cleanup while
preserving the original failure. Injected receipt reads and verification cover
resolved bindings, same-revision isolation and stability across fresh retirement.
Namespace prerequisite classification distinguishes unsupported probes from
crashes/deadlines; compiler vectors keep the fixed static-helper recipe.
Imports activate no payload, compiler, native observer, Git command or provider.
These regressions establish reporting contracts only, never native success.
Darwin portable coverage protects narrow policy grants and literal quoting,
matching-worker dispatch, missing native records, audit-token argument binding
and the distinction between recorded process retirement and full domain recovery.
Complete native transcripts reject malformed, extra and trailing output; an
unavailable interface retains its diagnosis alongside unsettled cleanup.
It invokes no macOS tool, helper, process fault or socket probe on this host.
`test/native-darwin-build.test.js` reads the actual helper and optional binding
header bytes while injecting compiler and filesystem effects. It protects the
source-supported variadic C-int signature, lookup of both function and const data
exports, dereferencing the flag instead of guessing it, refusal before effects
and the retained live-identity policy checks. Injected builds record both source
digests with unchanged public sandbox linking, diagnostic flags, x64 compilation
and signing. Compiler/declaration/type/link failures retain observed process
outcomes and compiler/SDK identities; absent or unsupported runtime interfaces
remain distinct from failed policy checks. Existing coverage still rejects
malformed x64 headers, missing signatures and substituted loaders. These checks
execute no Darwin tool and compile no macOS code. Fresh matching external macOS
must supply selected SDK/library export and ABI inspection, actual compilation,
signed helper identities and live effective-policy observations. The archived
undeclared-call diagnosis and portable repairs establish no native acceptance.
Windows portable coverage rejects unsafe or incomplete x64 import tables,
confines nonce-backed profile names and distinguishes surviving Job custody from
final-handle retirement. Missing Windows native records fail closed; wrong-worker
dispatch activates no helper. Coverage also checks custody before fault release,
import-name termination bounds and exclusion of ambient Git authority from
fixture tools. These tests exercise pure contracts only.
`test/native-windows-git.test.js` uses neutral PE bytes and injected commands,
reads and exclusive writes to protect uppercase DLL extensions without relaxing
unsafe image/name/range/termination or delay-import refusals. Coverage validates
local discovery and bounded case-folded dependency closure, copied-byte manifests,
copied-runtime version inspection and synthetic repository commands. Discovery,
dependency, copy, version and initialization faults retain their first operation,
actual process facts, validated Win32 errors and already observed components;
changed copies cannot reach repository effects and killed alone proves no deadline.
No Windows process, native filesystem, SDK or installer runs locally. These repairs
do not identify the archived lost exception or prove AppContainer/Git failure;
actual copied-runtime and native behavior require matching external Windows CI.

Provider portable coverage rejects unsafe data-only archive preflight, constrains
the model-free client to buffered command RPCs with explicit sandbox authority,
and prevents provider records from replacing native or protected route evidence.
Unsettled native cleanup prevents later provider admission. Protected readiness
requires private transport, authority, disabled integrations and demonstrated
cleanup; AppContainer loopback cannot satisfy it. Claude's existing default-registry
coverage remains, with focused optional-subset and undeclared-tool regressions in
`ci/native/providers/claude.test.js`. These tests execute no provider binary,
package acquisition, native observer, credentials or model turn. The concrete
Linux, Darwin and Windows command observers and protected entry require external
same-revision CI evidence.

`test/native-windows-command.test.js` uses injected native effects and controlled
signals, with no Windows process or native SDK locally. It protects the allowlisted
credential-free environment, Windows path/request construction, supported default
output cap and independent client bounds. Both explicit access policies require
native process/image/token and creation-time Job joins, Security logon identities/access masks,
acknowledged controls and unchanged original sentinel IDs/bytes. Capture loss,
changed attribution and incomplete Job/observer/audit/fixture settlement cannot
pass. Unavailable prerequisites prevent release; independent observation and
cleanup abort signals protect the separate 120-second and 30-second budgets.
An actual-source regression protects Win32 sharing compatibility between the
held deletion handles and permitted command opens; it does not compile the helper.
Native watcher transport tests retain pipe errors and require a complete retirement
witness. Source checks protect live custody, the held NUL handle, audit-gate DACL
protection against inherited workspace grants and saved ACL protection through restoration.
Bounded native transcripts exercise the finite decoder and broker coverage gate:
system success disabled with effective per-user success and matching delivery,
unavailable queries/coverage, missing or misattributed delivery, and actual
administrative token binding. No version/schema or other Codex probe precedes
coverage. Controlled interruption and partial-setup failures preserve first causes
and separate cleanup uncertainty; restoration follows independent closed custody.
Capture and watcher delivery errors still fail after verified safe restoration;
missing retirement proof refuses restoration.
Narrow source checks protect the native token/API binding and early cleanup
ownership. See the [native owner](../ci/native/README.md) for Microsoft's inclusion
versus Administrators exclusion distinction. These portable regressions establish
no effective native policy or Security delivery.
The concrete owner compiles an opt-in finite variant of the existing helper using
the selected MSVC/SDK. XML-only reuse leaves the full reader's default compilation
and LocalSystem/review contracts intact. Actual native token filtering, Job
attributes, mandatory labels, publisher versions, Security delivery, NUL mutation
denial, original-handle cleanup and audit restoration remain external Windows CI
checks. This adds no durable slow-suite or native-harness selection to local
finalization and supplies no protected or full native acceptance.

`test/native-darwin-command.test.js` uses injected native effects, client responses
and controlled deadlines. It protects the credential-free environment and both
explicit buffered command policies, capture/admission ordering, native process,
image and effective-policy attribution, permitted controls, denied audit records,
completed-I/O gate attribution and unchanged held sentinels. Unavailable admission,
capture, session-escape controls or complete custody prevent provider release;
capture loss, changed sentinels and incomplete retirement cannot pass.
RPC rejection and nonzero buffered replies retain their first cause while native
admission is pending. A missing first-command route is BLOCKED; losing an already
observed route fails. Successful replies still require complete native evidence.
Controlled abort signals prove separate observation and settlement bounds without sleeps or
native processes; elapsed observation excludes the separate cleanup budget.
Injected native-custody operations also protect observer settlement after a failed
independent session check, failed native server exit, first-cause retention and
observed emergency reporting.
Cleanup requests require original file/parent identities and unchanged outside
bytes; replacement fixtures cannot become newly admitted cleanup targets.
The actual finite-operation header digest and opt-in libbsm build vector are
protected by injected compiler/filesystem coverage in the existing Darwin build
test. The concrete matching-worker effects compile finite command
operations into the existing helper, use a cloned LOCAL audit pipe and require
held audit-session custody before suspended release. Actual SDK mapping/ABI,
root privilege, signing, BSM capture, inherited-session closure, stock Codex policy
and independent native retirement remain matching external macOS observations.
The full observer's reviews/custody and Darwin arbitrary-domain findings remain
unchanged. This backend adds no local native harness or slow-suite assignment.

The experiment retains `npm run check` for every step and ends its content
inventory with `git diff --check HEAD`. The explicit native harness below is
additionally selected for changes to the existing Linux proof owner or Claude
invocation/stream tool registry, after the ordinary gate and before that
HEAD-relative check. Unrelated experiment changes do not inherit this harness
merely because its command is in the trusted catalog. The canonical finalization
skill still owns terminal formatting and Runner execution of selected commands.
Matching-OS compilation, effects, model-free provider calls and protected model
acceptance remain external CI; they never enter local FINALIZE inventories.
The bounded Darwin helper and argv fixture compile and execute only in matching
macOS CI. Their native ABI, Seatbelt behavior, file/volume observations and
audit-token signalling remain unproved by portable tests; the Darwin experiment
adds no local native-harness requirement or durable slow-suite assignment.
The bounded Windows helper and UTF-16 argv fixture compile and execute only on
matching Windows x64 CI with the installed native MSVC/SDK environment. Actual
AppContainer tokens, creation-time Job attributes, handle custody, DACL/file IDs,
TCP/named-pipe outcomes and profile cleanup remain external evidence. This step
adds no local native-harness requirement or durable slow-suite assignment.

The dedicated `native-feasibility.yml` checks are `native-feasibility-linux`,
`native-feasibility-darwin` and `native-feasibility-win32`; manual protected checks
use the `native-feasibility-acceptance-` prefix with the same platform suffixes.
They invoke `node ci/native/feasibility/ci.js --stage initialize|probe|cleanup|report`
with `--platform` and `--expected-sha`, plus `prepare-darwin` on Darwin and
`prepare-windows` on Windows;
protected jobs add `--protected` and the
readiness/protected stages. Native compilation, probes, package acquisition and
provider execution belong exclusively to those matching external workers.
Missing native/model-free requirements fail the corresponding check, while
protected-only BLOCKED records are expected in credential-free runs. The current
protected CLI remains BLOCKED without admitted native custody; no policy variable
or successful portable regression supplies that evidence.
Focused portable regressions in `test/native-feasibility.test.js` protect exact
dispatch/workflow/checkout binding, independent environment approval and explicit
bounded model authorization. They perform no API call, native tool or model turn.
Completion-envelope regressions reject inconsistent status, issues and records
while retaining the credential-free-to-protected assessment boundary.
Unavailable protected custody also rejects prior success without erasing failure.
Darwin preparation regressions inject installed-tool discovery and authority
refusal, preserve bounded operation/process outcomes and block without native
effects. Actual workflow bytes protect both preparation/report connections.
Darwin/Windows dispatch regressions retain the complete capability inventory,
all five protected requirements, first causes/components and independent cleanup;
uncertain or emergency native cleanup prevents later provider admission. Summary
coverage distinguishes native/model-free/protected records and preserves observed
component and cleanup witness identities. None executes macOS/Windows tooling,
acquires packages or supplies live command/native acceptance.
Linux injected regressions additionally protect unchanged ordinary/nested
namespace vectors and capture bounds, EXIT_1 versus crashes/deadlines, protection
and receipt-admission attribution, candidate/nonce-bound failure IPC and retained
compiler failures. They distinguish absent, captured-but-unrecognized and
recognized output across both streams, keep rejected bytes private, retain finite
native error classes, and preserve pre-probe resolver failures under ordinary or
nested launcher construction without fabricating process outcomes. String and
Buffer capture tests enforce the byte bound, including multibyte text. The Linux
preparation-effects suite verifies failure delivery
without accepting it as retirement; first and cleanup causes remain separate.
These checks invoke no compiler, bubblewrap or provider. Portable regressions
cover source-form diagnostics for namespace, UID/GID/setgroups, mount
propagation, tmpfs, bind/proc/devpts/device
and executable errors across both bounded streams, including syslog prefixes,
finite errno classes and rejected advice/paths. Injected process effects drive
the actual fixed resolver vector through fixture preparation and admission,
then controller failure IPC and model-free command error wrapping. They protect
FAIL for diagnosed argument/setup defects, distinguish namespace creation EINVAL
from invalid setup arguments, retain the operator's compatible-worker remedy
for unavailable prerequisites and prevent successful probes from masking later
protection failures. These are reporting/classification repairs, not evidence
that any historical namespace rejection was fixed. Fresh hosted Linux still
must observe installed bubblewrap identity/version, the exact probe variant,
actual exit/signal/deadline, sanitized native explanation and originating command
rejection operation. Discarded historical stderr leaves the namespace cause
unresolved; diagnostic capture supplies no native acceptance or repaired cause.
Workflow/report wiring preserves ordinary discovery, fast-gate ownership and all
durable slow-suite assignments. Workflow/report-only changes retain the ordinary
gate and `git diff --check HEAD`; the selected native harness applies only to
changes to the existing Linux proof owner or Claude invocation/stream registry.
See the native owner for exact CI stage commands and
operator-owned protected environment setup; these are external experiment checks,
never additional local FINALIZE commands.

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
Its fixed-entry raw filesystem/IPC coverage also exercises every ownership
recipe, executed-policy admission, acknowledged faults, held nonce/outside reads,
stale signalling, independent retirement census and repeated interrupted receipt
recovery. Missing policy/domain reads, unknown zombies, substituted objects and
unfinished receipt writers retain custody. The same raw filesystem/IPC fixture
now exercises all three access profiles with native-frame BSM windows, outside
controls, complete policy reads, held sentinel/socket observations and four
acknowledged loopback exchanges. Interrupted bootstrap/anchor installation,
missing controls or native IPC IDs, audit loss, stale identities, missing counter
legs, changed outside state and surviving observers withhold admission or retain
custody. Repeated observation preserves the first failure. The same fixed-entry
fixture exercises all six file recipes, both Git recipes and release closure
through filesystem bytes and raw IPC frames. It covers private UID denial,
overlapping publisher/reader barriers, parent/leaf/link/volume substitutions and
aliases, every suspended Git child, all three ordinary profiles with native BSM
returns, physical/shared-cache dependencies, signatures and both package readers.
SDK build identifiers rejoin the original fixed query and fresh retirement reads;
substituted query output cannot satisfy the independently approved release binding.
Changed outside objects, substituted mountpoints, lost events, substituted
images/packages, unresolved receipt writes and incomplete closure retain custody or fail admission. Fresh
recovery rejoins partial admissions and completed mutations without setup,
compilation or another Git operation; file cleanup uses recorded identities and
its separate signal lifetime. Missing independent approvals remain blocked.
Fresh recovery coverage also removes preparation results and final images, rejects
malformed or undeclared inventory slots without suppressing case retirement, and
fences later admissions. A request for a substituted job is rejected before any
recovery effect, even when its request digest matches that job. Interrupted PF
bootstrap rejoins the original protected enable reference; missing references,
substituted root policy and cleanup cancellation retain exclusion. Lost native
acknowledgements and receipt writers cannot substitute later process absence for a
sealed operation birth. Recorded root births require a fresh domain census even
when the original domain acknowledgement was lost. Lost cleanup results can recover
only after sealed audit replay, independent named IPC absence and fresh domain
retirement. Missing audit frames or completion, surviving IPC and undrained
observation cannot authorize policy restoration or lease release. These regressions
inject filesystem bytes and raw native frames; no retirement verdict or recovery
callback substitutes for the repository owner.
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
Interrupted audit setup retains its first cause and permits recovery only after
independent payload retirement, observer drain and retirement, and fresh reads
of unchanged baseline or exactly owned per-user policy and SACL changes.
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

`ci/native/darwin/preparation-effects.test.js` retains historical injected
composition coverage and exercises build defaults through `native-effects.mjs`
with raw held filesystem, private IPC and kernel zero-signal read transcripts.
The actual repository owners verify and persist all 22 fixed Clang/SDK/signing
commands, snapshot unsigned inputs and rejoin final pins and original receipts
without recompilation. Regressions cover missing source approvals, intermediate
substitution, native directory identity substitution, foreign receipt ACLs, the
pending prerequisite snapshot, the held compiler-directory release barrier,
original failure despite an uncertainty-write error, bounded build/helper
lifetimes, missing acknowledgements,
reused verifier PIDs and independently retained compiler effects. Partial
recovery needs no successful final outputs. Fixed-entry case coverage additionally
exercises independent parked-compiler policy reads and the mandatory build gate,
context-bound directory/image/policy custody, exclusive approved endpoints,
account observations, shared primary groups, UID/GID aliases and partial
provisioning recovery. Missing reads, extra authority, undeclared identities,
substituted contexts/objects and interrupted
writers withhold admission or retain custody. Only raw filesystem and native IPC
are injected for these defaults. Its targeted invocation is
`node ci/native/darwin/preparation-effects.test.js`; the existing harness includes
it. The suite performs no SDK compilation, elevation, native probe, installation
or provider call and supplies no native acceptance.

`ci/native/win32/preparation-effects.test.js` retains historical injected
composition coverage and exercises the checked-in `native-effects.mjs` entry
with raw filesystem/IPC transcripts. Repository defaults provision protected
build/receipt custody, observe parked workers, run the two version queries and
thirteen compiles, and rejoin prepared bytes and settle the build case without
another compiler or bootstrap.
Signal handoff coverage ends preparation before verification and preserves the
original observer deadline, cancellation checks and first transport failure.
Distinct regressions reject unsigned/source/output substitution, publication changes
outside allowed PE fields, missing approvals/completion/intent/birth records,
misbound worker receipts, interrupted writers, journal gaps, surviving workers
and incomplete observer retirement.
The fixed build case also verifies an independently approved compiler-policy
binding against actual pre-release raw token/Job/DACL/handle reads and held output.
Case setup through normal defaults reaches acknowledged fresh account/restricting
SIDs, held private objects and repeated independent resource binding before the
unfinished execution-owner gate. Distinct cases reject missing compiler policy,
extra authority/principals/endpoints, undeclared SIDs, substituted objects and
wrong job/attempt contexts. Interrupted account or observer reads and cleanup
cancellation retain possible custody; completed pre-execution setup retires only
with independent account/rights/Job and custodian closure.
Controlled clocks cover the whole command-plus-cleanup lifetime. Partial recovery
needs no final prepared images. Its focused invocation is
`node ci/native/win32/preparation-effects.test.js`; the existing native harness
already includes it. These tests do not compile with MSVC/SDK, register tasks,
elevate or establish native acceptance.

The same raw fixed-entry suite covers all nine access profile/fault variants,
38 complete denied routes and four private TCP/UDP pairs per case. It requires
repository-owned policy/audit/control operations and checks retirement before
observer drain and unchanged restoration. Distinct injected failures cover
interrupted policy/audit setup, missing controls, unjoined DROP events, unrelated
file-denial rights, Security clear, incomplete filter inventories and surviving
custodian flows. Reduced held directory bindings are required before file
attempts; changed identities, excess rights and lost transfer acknowledgements
retain exclusion and independently retire the possible handles. Multiple
runtime images exercise the complete held inventory; duplicate/missing destinations,
noninteger source slots and an immutable declaration for the mutable owned file
must fail before private case writes.
`node ci/native/win32/access-transport.test.js`
checks held sender/receiver and tuple attribution and separate UDP return
authorizations. These injected regressions supply no Windows SDK or privileged
evidence; native checks remain dedicated matching-OS CI requirements.

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

`node ci/native/linux/provider-effects.test.js` exercises the indexed Linux
provider defaults with raw filesystem, procfs, process, IPC and credential-free
HTTP transcripts. It covers effect-free fixed-entry construction, all 60 recipe
executions through `provider-effects.mjs` and the existing Codex/Claude mediation
controllers, full mandatory case-plan construction and both effective-policy
barriers for Codex/Claude in all three ordinary profiles. Repository owners
perform the private relay/bridge handshake, held-image and namespace joins,
live device/inode closure inspection, native trace/control/byte observation,
receipt synchronization, ordered
retirement, all ten transport controls and partial reconstruction. TCP/Unix
outside controls and credential-free helper loss use the repository owners.
Promise-controlled regressions suspend creation/release receipts during recovery
and outside-listener setup during retirement, rejecting late effects while
permitting supervisor deregistration. A delayed listening event verifies that
cleanup waits for startup and closes the listener before returning. Complete
fixed-entry cases also reject bridge-source substitution after relay admission
and independently settle interrupted provider work without accepting mediation.
Descriptor cleanup retains an unverified close acknowledgement and repeats the
independent closure read on subsequent attempts before releasing custody.
Socket substitution during a nonce exchange
also retains exclusion. Raw receiver environment omission, creation replacement
during receiver or live-image inspection, executable changes without a new
creation identity, and a mapped device substitution are
rejected. The live observer regression requires relay/bridge retirement before
the audit settlement record.
Replacing the relay receipt pipe during a model receipt read blocks receipt
and transport acceptance, and remains blocked after the descriptor is restored.
Transport controls also reject a successful captured syscall paired with a
denial acknowledgement; valid controls join the held probe identity and exact
native result/errno between independent trace watermarks.
Missing controls, changed assets, extra
descriptors, malformed or lost frames and unavailable audit-drain evidence
retain exclusion. A parked native pidfd receiver retires only recorded creation
identities; receiver completion alone cannot settle missing audit evidence.
The harness explicitly imports this suite. These injected regressions invoke no
native compiler, privileged operation, real socket or authenticated provider;
native compilation, source/ABI review and complete external acceptance remain
separate evidence.

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
