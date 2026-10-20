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
supervisor's bounded incomplete-inspection retries separate from controlled
parent observations: an uncertain parent must retain registration, so a fixture
expecting durable deregistration supplies an empty parent view and races callback
entry against premature completion. Keep the distinct persistent and transient
parent-uncertainty regressions. The transient case forces a failed termination
message callback, making its additional fallback inspection deterministic.
The persistent retry assertion advances its injected supervisor clock only
after another inspection, so scheduler stalls and termination-message delivery
cannot bypass its retry proof. Other live supervisor retry windows retain real
time.
Owner-loss fixtures acknowledge entry into the pending registration callback
through IPC, before or after its simulated durable side effect, and compare
recorded process identity before retirement. Await owned process closure and
identity-checked supervisor retirement during teardown.
Synthetic procfs classification fixtures control inspection clocks in test
parents, generated owners and embedded supervisors so scheduler pauses cannot
exhaust an unrelated test's budget; explicit elapsed-budget regressions and real
supervisor retry windows retain their own clocks.
These test-only synchronization changes do not require the slow operator-stop
suite; production supervision, containment and timeout changes do.

## Minimal native feasibility contract

Ordinary version-7 preparation explicitly trusts the declared disposable hosted
image and installed toolchain. Portable coverage retains exact candidate/source/
runtime/job bindings and actual tool/SDK/output version/hash observations; the
assumption supplies no reviewed or production approval. Linux ordinary package
setup uses the fixed hosted recipe once, without archive-keyring permission
mutations or a reviewed package receipt. Existing installed-Bubblewrap checks,
namespace policy/probes and independent restoration remain required. Reviewed
installation, strict receipt validators and launcher safety retain their coverage.

`test/native-module-loading.test.js` belongs to ordinary fast discovery. Fresh
Node processes protect index-first catalog initialization and the checked-in
Linux `proof.js` direct entry with no arguments and hosted context unset. A
separate proof-first process checks exact build, system, preparation and workflow
bounds. The regressions require silent initialization, start no native tools or
providers and supply no native CI proof.

`ci/native/experiment.test.js` is registered by the explicit native harness
(`node --test ci/native/harness.test.js`). Pure synthetic reads protect complete
ordinary system recipe coverage, candidate/run/source/tool/SDK/image/loader
substitution rejection, missing inventory, effective-policy and sentinel mismatch,
uncertain/emergency settlement, canonical key-order-independent binding, intent and
original-observation preservation during recovery, and rejection of
experiment-to-reviewed/protected promotion. It performs no native compilation,
platform effects or provider request and supplies no native CI proof. This CI-private
contract adds no durable slow-tier assignment. Runner-selected commands execute only
through FINALIZE; ordinary validation and content hygiene remain as documented above.

Retained Darwin custody, launch, policy and preparation suites additionally inject
explicit experiment bindings. They reject mixed-purpose declarations, legacy
approval callbacks, protected-provider promotion, substituted signatures,
incomplete fresh installed-policy reads and surviving compiler descendants.
Build admissions retain their purpose and pinned inputs despite caller mutation;
image refusals retain segment and purpose diagnostics in build failures.
Default-reader build-entry regressions inject raw filesystem and bootstrap
effects without replacing the preparation reader. Protected installed Clang,
SDK-query and signer hardlinks reach the command boundary; matching pins cannot
admit unclassified tools, hardlinked sources/helpers, unsafe ancestry or changed
held bytes. Reviewed and experiment reads retain their distinct purpose. The
existing direct-reader suite owns the detailed installed-input refusal matrix.
Synthetic signed Mach-O bytes protect the durable read-only purpose section and
reviewed inspection refusal. These tests use no Darwin tool or compiler and add
no slow-suite assignment; the explicit native harness registers them.

Darwin's ordinary preparation coverage injects installed Clang/SDK discovery,
exact Git-blob and checkout bytes, one compile per helper, ad-hoc signing and
root publication. It verifies actual command diagnostics, cancellation, missing
output and changed candidate/source/tool/output observations. Version-3 records
reject legacy, mixed and incomplete command/environment inventories; cold loading
compares binding values independently of key order and cannot acquire or recompile.
Ordinary preparation and repeated cold/runtime reads require no cache discovery
or enumeration. The helper-only inventory retains all ten images, held identities,
signatures and native ABI, plus the separately held dyld input. Existing regressions
reject old or mixed private records, incomplete builds and substituted helpers;
recovery preserves uncertainty and the original failure without rebuilding.
A deterministic process-group fixture verifies cancellation, stream-read failure,
reaped closure and unsuccessful completion when descendants remain. Injected streams
retain successful diagnostics above 64 KiB, including split multibyte chunks, and
cover the combined 256 KiB boundary and overflow. Long diagnostics survive receipt
persistence and cold loading under the existing receipt-size limits; persisted
validation also rejects combined-output overflow. Interrupted builds
cannot reconstruct missing compiler receipts or erase the original failure.
The indexed preparation fixture retains the complete inventory and independently
read build policy, then exercises interrupted case custody and lost native-reader
closure. A completed build cannot retire admitted cases. Compiler-only bootstrap,
SDK reconstruction and acquisition-observer matrices have been removed with their
obsolete owners. Fixed native launch guards and distinct reviewed compiler,
source, signature and recovery coverage remain strict. Native file/Git/access,
PF/audit exclusion, original-owner retirement and all 23 checks remain required.
These portable injected tests run no Darwin tool and supply no hosted acceptance.

Installed-tool acquisition and cold-load regressions cover thin and universal Git
through the existing case generator, private copying and native Git consumers.
They retain whole-file pins, held identities and native CDHash verification,
reject substitutions and changed recorded Mach-O observations, and keep helper
and dyld observations mandatory. Incompatible images use injected native-loader
refusal. Held dyld fixtures execute the native container-selection and Mach-O
parser bodies for thin and 32/64-bit universal images in both byte orders.
Acquisition, cold loading and the runtime release consumer's native `macho`
read retain identical selected metadata with exact whole-file pins. Refusals
cover truncated/oversized tables, missing or duplicate x86_64 slices, invalid,
overlapping or misaligned ranges, short headers/load commands, architecture
and subtype mismatch, and private/reviewed admission. Synthetic bytes establish
no native x64 loading success. These cases remain in the existing explicit
native harness, with no test-tier reassignment.

One compact actual-body census fixture injects all four BSD/audit sampling
points. It proves whole-view discard, fresh complete enumeration/storage,
zombie visibility, success on the third attempt and deterministic exhaustion
with the original sampling-stage errno diagnosis.
Permission, malformed-result, list/PID/duplicate, birth/credential/session and
live-inspection failures refuse immediately. Neutral records use no native tools,
delays or new harness. This protects the source-supported lifetime-race handling;
it proves neither an observed failed-PID history, exact hosted-build approval nor
independent original-owner/domain retirement.
The same fast build-source suite executes the original SDK admission predicate
with injected realpath/lstat and sampled metadata. It covers each short-circuit
stop, unknown later terms, single native-call evaluation, successful unchanged
admission and failed diagnostic writes without changing the guard errno.
One compact signature fixture translates the complete original admission, bounded
CFError helpers, hex encoder, refusal and downstream guard/cleanup bodies.
Neutral injections cover URL and each API failure, exact call order/flags/counts
and later-call suppression,
signed-status boundaries distinct from uncalled states, control/non-UTF-8 path
bytes, truncation bounds and long-path success without new admission. The single
WithErrors call covers NULL/malformed error, domain and description objects,
empty/oversized UTF-8 details, signed code limits, conversion/write/flush failures
and independent owned-description/error release, including non-NULL success
errors. Success remains silent; diagnostic and release work preserves original
refusal and errno, including zero. The full-report tradeoff supplies no native
work equivalence. The composite source line and errno identify no failed API.
These portable observations establish neither native validity nor a unique remedy;
they add no native invocation, harness, dependency or tier assignment.
The same suite executes the complete protected-file reader body, including its
original hex encoder and refusal path, with injected native calls. It protects
initial admission order/counts, nested installed-input branches, inaccessible
metadata on open/stat failure, explicit unsampled states and errno-zero refusal.
Special path bytes and near-`PATH_MAX` lengths retain complete hex encoding;
BigInt metadata and format-aware output assertions preserve signed and full-width
values. Failed diagnostic writes/flushes retain refusal, successful reads stay
silent, later denials remain unchanged, and output stays within existing bounds.
These fixtures add no harness or slow-tier assignment and establish no native
filename, failed predicate, selected-SDK success, retirement or acceptance proof.
The same actual-body fixture executes helper admission before those predicates,
joining fresh audit-session creation, birth announcement and the original `P`
barrier before protected tool checks. The raw build transport injects the
original SDK refusal for reviewed and experiment purposes, preserving the exact
first cause without a worker or publication. It requires original command-domain
proof before observer finish and full independent revalidation afterward.
Missing/replaced births, surviving descendants, incomplete census and cancelled
cleanup retain exclusion; existing lost-finish coverage prohibits replay.
No fixture supplies a safe replacement SDK, native build or retirement proof.
Retained shared native compiler/source fixtures still protect exact SDK/toolchain
identities, installed-input size ceilings, signatures, protected publication and
original-owner retirement for their protected consumers. Ordinary experiment
preparation uses the hosted toolchain assumption and its completed-build record;
these protected compiler matrices do not supply ordinary compiler receipts.
Native case reader, file identity and custody guards remain independently tested.
Successful selected-SDK metadata and real native compilation, TASK_ACCESS_PORT,
model-free routes and independent case retirement require matching hosted Darwin.
Portable tests cannot establish production or reviewed readiness.

Darwin preparation regressions also execute the fixed ownership/access inventory
with explicit experiment bindings through the retained injected native transports.
They preserve literal/storage barriers, every ownership fault and helper-loss path,
all three access profiles, outside controls, 33 acknowledged denials and four private
loopback pairs. Missing native reads, mixed bindings, surviving or unavailable fresh
domains and TCP deadlines remain unsuccessful. Policy tests retain purpose-bound
PF journals and forbid restoration before independent retirement; retirement tests
reject a surviving descendant or unavailable fresh census. Caller mutation cannot
change admitted PF purpose or case recipes, and fenced direct provisioning starts
no fresh build read. Promise-synchronized overlapping preparation must also reject
the second build observation. These tests add no
native effect or slow-tier assignment; reviewed and protected rejection coverage
remains retained in the explicit harness.

The same Darwin preparation fixtures acquire a compact real XNU event declaration
excerpt without `BSLOOKUP` and an `audit_record.h` named-version/alias excerpt.
The latter reproduces the producer-selected OpenBSM version without a synthetic
generic declaration. Acquisition cases preserve held header pins, SDK/ABI joins
and mapping digests, accept observed numeric or single version-named aliases,
and reject missing, duplicate, conditional, unsupported or contradictory
declarations before PF/volume setup. Quoted string and character comment markers
cannot hide duplicate declarations. Existing decoder cases reject Solaris and
other mismatched captured versions. These public excerpts explain the contract;
they are not an exact hosted-header match or native acceptance evidence.
The same installed-input acquisition fixture requires one interface snapshot for
both address families and retains successful thin/universal acquisition. Missing
IPv4, missing IPv6 and internal/scoped-only IPv6 inventories must refuse before
PF/volume setup while reporting the failed family and all named candidates with
addresses, internal flags, scope IDs and exclusions. Scoped cases include
link-local addresses across `fe80::/10`, nonzero scope IDs and zone-qualified
literals. A throwing diagnostic sink cannot replace the original refusal.
The existing case consumer additionally asserts all 39 attempts, distinct
family-bound host-network and loopback targets, 33 denials and four echoes.
These synthetic reads and injected commands run through the existing native
harness without a slow-tier addition or host networking changes. Missing-family
diagnostics supply neither a hosted acquisition repair nor native acceptance.
The fixtures produce versioned experiment Mach records and carry
the installed log source/tool into the retained access observation and retirement
route. The existing portable BSM transcript model and all-profile coverage remain
separate from native acceptance. Compact binder refusals cover missing/redacted or
ambiguous logs, wrong PID/service/nonce/birth/source, exact microsecond boundaries,
unsupported or contradictory lookup/send results and invalid control audit
trailers. Cold loading refuses legacy/mixed source records while recovery still
attempts independent original-owner cleanup; a surviving named service prevents
fresh retirement. These tests execute no Darwin commands, change no test tier,
and establish no hosted unified-log availability or native PASS.

`darwin/effective.test.js` additionally injects complete experiment PF graphs and
counter records. It rejects missing children/rulesets, stale generations, altered
owned semantics, incomplete state/interface evidence and unrelated counter records;
authority equality cannot substitute for generation equality. The retained native
source regression checks counter normalization against the adapter. No test builds
a Darwin helper or supplies matching-host PF acceptance.
Injected root action and match substitutions must reject setup even when its root
digest comes from readback, retaining uncertain setup and its reservation.
The route regression preserves authority and expiry metrics while normalizing only
documented usage counters, so control traffic cannot invalidate route equality.
Return-response regressions reject altered ICMP codes and unsupported queue
selectors without inferring expected policy from installed bytes.
PF lifecycle fixtures retain disabled stock-style attachments and foreign child
rules across installation, normal restoration and cold rejoin. Injected interruption
points cover enablement, attachment, installation replies and restoration replies;
recovery cannot replay installation or accept missing original-operation evidence.
Foreign rule-byte/identity, generation, route/interface and state substitutions
retain exclusion. Root relocation permits only derived ordinals/skip destinations
while preserving authority and order. Native source predicates protect conditional
insertion/removal, durable intent ordering and refusal of impossible phase states;
they supply no compilation or running-kernel proof. Composition coverage drains
capture before restoring owned PF effects and closing custody over the stock graph.
Audit-domain regressions bind explicit all-UID session scope, changed-credential
members, known births/zombies and fresh independent custody. Missing controls,
substituted session/holder births, escaping known members and unsettled custodians
reject retirement. Injected ownership/access recovery covers transfer before old
holder retirement, lost replies, interrupted custody publication, repeated closed
rejoin and missing/substituted original custodians without relaunch. Transport
regressions enforce lease/file prerequisites, custody transfer before old-reader
retirement, retention of undrained capture consumers and original identities
despite a matching live substitute. Ordinary Git fixtures model the payload's
post-exec token epoch and reject stale epochs or changed births, sessions and
credentials before starting a worker. Source regressions bind stable post-hello Git
launcher births, the actual native negative controls and shared census, protected
intent-before-acquisition, reference retention and fixed close ordering. The existing
fast source suite and explicit native harness retain ownership; no slow-tier or
future-step assignment changes. Actual negative controls, fork races, session
lifetimes and helper-loss containment remain matching macOS CI requirements.
The feasibility fault owner separately injects both original cancellation and
owner-loss recipes with complete protected session evidence, an additional detached
member, lost custody, stale intent, unavailable/truncated census and emergency
cleanup. Its private transport fixture joins original A/C/L framing and stdio to
the independent custody channel, native empty-domain verifier and later custodian
settlement. The per-birth fallback remains covered and cannot pass. Build coverage
binds the shared custody and fixed feasibility-domain header bytes, including the
helper's required libbsm linkage without enabling model-free command observation.
Native predicates reject changed zombie credentials and sealed-file metadata;
channel failures retain bounded native diagnostics independently of payload errors.
Retirement rejects changed admission bindings, trailing custody output and a close
reply without bounded custodian exit.
These deterministic fast regressions run no macOS helper; the existing native
harness and all future check assignments remain unchanged.
Fault transition regressions execute the original writable-journal handoff and
audit-session creation bodies with injected native calls, covering descriptor
substitution, read-only access, exact errors and preserved reexec effects.

Task-access regressions execute the actual complete sanitation body through
the original child launch branch, using only injected Mach and process calls.
Null and dead sentinels need no namespace release; allocated dead names require
a successful type query and checked release. Live, mixed, unknown and empty
types, failed getters/queries, refused deallocation and retained foreign rights
cannot reach the payload exec. Unexpected types without a send, send-once or
dead-name reference stop before deallocation can raise an invalid-right guard
exception; the original authority refusal survives. Combined authority/release
failures preserve
the primary refusal and independent cleanup error. The same execution retains
ordinary-host checks, descriptor closure, bootstrap/registered/exception clearing
and foreign-name destruction. Existing cancel/owner-loss caller and independent
domain-retirement cases remain required; bounded task-access metadata alone
supplies no success or retirement evidence. Custodian lifecycle fixtures execute
the actual observation body with failed getters, absent/dead values, live send
references, unavailable type queries and refused releases. They verify one checked
release per valid getter copy, no endpoint contact and unchanged errno. The
same matrix includes the forked child's observation after its alarm and before
audit-session or credential transitions. The original child fixture executes
that observation and its separate payload read, retaining live-authority refusal.
Unavailable child getter/type facts stay distinct from the authoritative payload
check; a failed child copied-reference release stops before the audit transition
and retains its cleanup cause. The custody caller fixture forwards fragmented
raw lifecycle and malformed metadata while preserving the original authority failure and separate
release cause, including when the raw diagnostic sink throws. These portable
fixtures run no native compiler or macOS tool and add no slow-tier assignment.

`test/native-darwin-command.test.js` additionally executes the actual finite
command guard, failure and cleanup bodies with injected native calls. Audit-pipe
open/query/selection failures retain exact caller/guard, return value and saved
errno, including when diagnostics or cleanup change errno. Initial guards retain
their entry order; session-escape and membership refusals stop before previously
short-circuited operations. A later retirement refusal cannot replace the first
error and keeps a separate cleanup cause. These fast fixtures preserve exit
semantics and never classify exit 78 alone as an environmental explanation.
Both task-access confinement and model-free command feasibility remain open
until fresh matching native evidence establishes their functional causes.

The original fault transport matrix also injects pre-exec live-authority refusal
for both fault roles. An original exit delivered alongside admission must retain
its diagnostic and reach separate recovery without payload release, fault
replay or finish replay. Independent held/closed proof permits cleanup only;
the scenario remains failed. Changed original births, incomplete census and
missing custodian retirement retain uncertainty. Actual-body fixtures execute
partial pipe/direct-child settlement and the original domain retirement loop:
unreleased EOF, release uncertainty, failed close/reap, bounded cancellation,
unknown zombies, replaced owners and alarm exit cannot establish retirement.
These tests retain the existing fast and native-harness assignments and all
future check assignments. They establish no supported confinement of the live
inherited slot and no native cleanup result.
Matching macOS CI must resolve the observed live send right (`type=0x10000/query=0`)
without weakening admission and verify functional
recovery and complete independent retirement.

Held-initialization regressions execute the actual creation helper with synthetic
inherited metadata, failed setters and substituted identities. They retain the
strict root/journal modes, ACL refusal and creation-only normalization boundary;
portable injections establish no native ownership or filesystem acceptance.
Fault-start regressions also execute the actual lease acquisition branch with
injected filesystem and lock effects: exclusive creation with inherited metadata,
strict existing-file reuse, refused objects, contention, setter failures and
held/name substitution. Reuse and contention permit no metadata repair or lease
replacement; failed acquisition cannot reach payload creation. These cases retain
the original cancel/owner-loss controls and independent recovery requirements,
without running macOS tools or adding slow-tier checks.
The same source-execution suite drives the shared custody ACL inspector through
one case table: inspected absence, present empty or nonempty ACLs, malformed or
failed reads, held metadata changes and independent resource-release failures.
Admission and effective serialization use the same strict inspection. Absence
hashes zero bytes only after a successful presence query; present empty ACLs use
native text. Failed inspection/release cannot publish a hash, and cleanup cannot
erase the primary error. These cases run no SDK or filesystem ACL operations.
Both original fault channels reject pre-ready native failures, incomplete output
and unclosed custody; late stderr/status cannot erase the first channel cause.
Fixed diagnostic parsing retains bounded errno, Mach and operation-specific
status facts. These cases add no native execution or slow-tier requirement and
do not prove that the hosted cancel failure is repaired.
Token regressions reject timestamp/process-name substitution alongside value/PID
changes. Restored authority must match the original root positions even when
generation tickets have advanced.

The same preparation/proof suites now exercise experimental file/Git purposes
through every retained recipe and fresh interrupted file/Git/PF recovery. They
reject missing complete declarations, substituted loader/ABI observations and
promotion into reviewed release acceptance. Public prepare/load coverage joins
all fixed declarations, original build receipts and complete version-7 preparation,
checks repeated cold loading and subsequent build verification without
compilation, and verifies effect-free indexed factory construction. Installed audit
mapping coverage retains Git open variants within the original class mask. Missing
case selectors keep recovery retained despite retired build receipts.
Interrupted cold reads exercise uncertain recovery after preparation retirement,
a fresh independent retry, preservation of the original receipt/failure, and
refusal of a substituted preparation-close receipt.
Experimental access coverage also observes installed PF/ACL pins instead
of supplying approval hashes. `test/native-module-loading.test.js` checks the four
complete Darwin preparation exports. These are pure or injected portable
regressions, add no slow-tier assignment and establish no native PASS. Matching
hosted CI still owns actual file aliases, Git commands, native runtime reads,
process retirement and policy restoration.

The explicit harness also registers `ci/native/system-experiment.test.js`.
Pure injected Darwin/Windows entry coverage checks declared recipe order, the
build recipe without check IDs, all 23 checks, write-ahead admission, purpose-bound
policy verification and fresh runtime inventory. Missing/substituted observations,
native failure and uncertain/emergency retirement stop later cases. Controlled
deadline acknowledgements fence late completion; retirement-only recovery preserves
FAIL and cannot restart the loop. Delayed policy publication cannot overwrite the
terminal failure after cleanup. Retained platform proof/preparation suites own
the actual assertion coverage; Darwin's indexed build recipe independently reads
published output and its completed hosted-build observation, without compiler
policy receipts. These regressions establish no
native PASS and add no durable slow-tier assignment. Version-6 composition
coverage remains retained.

The experiment reporting regressions also join complete same-candidate synthetic
inventories across all three platforms. They reject wrong producing jobs, mixed
purpose/revision/run context, incomplete recipes, missing experimental steps,
expired artifacts and invalid upload receipts, while preserving original failure
and separate cleanup uncertainty. Existing harness artifact-selection and
acceptance regressions retain reviewed behavior and reject experimental promotion.
These pure joins add no native evidence or durable slow-tier requirement.

The retained `system-experiment.test.js` also injects the private CI stage owner:
explicit purpose selection, hosted identity refusal before effects, ordinary
preparation without review/delivery inputs, complete probing, cleanup, reporting,
first/cleanup cause separation, deadline fencing and refusal of admission after
cleanup starts. Linux recovery fixtures join the original reference writer and
native receipts, reject missing/substituted or
live/emergency observations, and preserve failed probes while allowing independent
namespace release. `test/native-linux-namespace.test.js` retains minimal/reviewed
coverage and adds version-7 context, preparation retirement and emergency refusal.
These tests execute no native platform tools and add no slow-tier assignment.
Windows cleanup injections keep final outputs unavailable, rejoin protected
selectors, reject selector substitution and preserve the original failed case.
The retained harness's Linux reference injections also abort after ownership,
file work and the runtime-audit barrier, preserving the original cancellation and
refusing later groups. Promise-controlled stage tests fence late Linux prerequisite
receipts and policy installation after a deadline. Reviewed bounds remain unchanged.
The same injected stage coverage compares the Linux bootstrap vector with Native
feasibility's actual fixed update/install recipe and bounded command vectors,
checks hosted/context admission and write-ahead intent, and retains actual package
failure status. It fences effects after failed intent persistence or cancellation,
rejects late package completion and prevents namespace admission after failure.
Failure-receipt persistence cannot replace the original command exception. Ordinary
initialization creates no reviewed package receipt or trust-hardening journal.
The same coverage verifies controller-token exclusion from native owners and retains
external namespace cleanup failure separately from an earlier cause. Namespace
observations and independent restoration remain covered by their existing owner;
portable success never substitutes for fresh hosted native acceptance.

`test/native-poc-workflow.test.js` is a pure fast-tier workflow regression. It
requires explicit experiment purpose at every ordinary stage, one candidate,
pinned images/Node/actions, read-only permissions, independent platform execution,
no review/provider prerequisites and always-run cleanup/report/upload. It checks
artifact-root receipt selection and digest-bound aggregation. The existing
namespace workflow regression also checks receipt retention through the ordinary
JSON glob while keeping explicit minimal/protected receipt paths. These tests
perform no network, package installation, native effect or model turn; actual
same-SHA Native PoC and Native feasibility results require operator-inspected
hosted runs after Runner completion and portable gates. They are not prerequisites
for intermediate local finalization and cannot be inferred from injected success.

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
Summary regressions separate evidence-backed dependent admission blocks from
primary failures and independent cleanup, and retain deduplicated inspected
component digests with every capability and checkout binding. Tool/source-only
records establish no successful helper build or admission; these pure reports
exercise no native compiler or provider. A reported provider attempt cannot be
presented as an unstarted dependent block merely because native cleanup failed.
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
Injected build regressions retain actual read errors, closed request bindings,
retirement refusals and first causes through redacted reports. Fresh native CI
must establish underlying cause and closure; no new slow-tier guarantee applies.
Imports activate no payload, compiler, native observer, Git command or provider.
These regressions establish reporting contracts only, never native success.
Windows socket regressions execute the actual source transfer, destination
input/import and destination-binding bodies with injected OS calls. The production
operation loop uses the guarded helper session for both original read/edit roles
and persists the target/provider record before `D`. Original `10022` reaches
bounded prerequisite collection, checked source closure and the unchanged
failure transport without importing the original socket, connecting or admitting
it. Query-only destination
access failures, failed/short token reads, failed restriction queries,
diagnostic-output failure and separate diagnostic/source closure failures
preserve the original cause. The same caller coverage samples the effective
thread-token type/impersonation level and the original socket's query-only QoS
status, including unsupported/short replies. Malformed new metadata stays
incomplete without replacing `10022`; failed-query byte counts remain unknown.
Both fresh unbound duplication refusals
can remain `10022` with imports unattempted and independent source closure.
Coverage runs every source/destination failure for both read/edit roles and
protects destination drift, lost `D/T/U` acknowledgments and failed import;
malformed/PID-only carriers, partial writes and original pipe bounds retain their
existing regressions. No changed transfer boundary is replaced by an idealized
success callback.

The same actual-source/caller fixture exercises two separate fresh unbound
controls after the original refusal, with the original identity, provider,
zero flags and nonblocking/exclusive options. Self and destination duplication
and import refusals remain distinct, including unsupported self sharing. It
protects one-use destination carriers, birth/token drift, replay and short
carriers, lost control acknowledgment, independently attempted source/import
closure and shared-budget exhaustion, including delayed carrier arrival or
identity reads before destination import. The original error is latched before
control failures; successful controls never advance original `D/T/U`, observer
state, connect or receipts. Invalid, repeated, oversized and mismatched control
observations remain incomplete diagnostic data. Import and closure uncertainty
remain separate from the original refusal and require independent retirement.

The optional prerequisite record retains exact public provider bytes and
negotiated Winsock versions within the unchanged 2 KiB TCP budget; missing or
malformed observations supply no proof. Actual application socket copying through
`DuplicateHandle` is not an admitted route, and injected API success cannot prove
native reference accounting. Failed persistence withholds the next `D/T/U`
acknowledgment without replay. Flags remain zero; strict actual `10013` denial,
outside nonce, closed-port `10061`, full-PoC DROP semantics and independent
retirement remain mandatory. Portable coverage establishes neither native
transfer compatibility nor a cause for `10022` and adds no slow-tier assignment.
Darwin portable coverage protects narrow policy grants and literal quoting,
matching-worker dispatch, missing native records, audit-token argument binding
and the distinction between recorded process retirement and full domain recovery.
Complete native transcripts reject malformed, extra and trailing output; an
unavailable interface retains its diagnosis alongside unsettled cleanup.
It invokes no macOS tool, helper, process fault or socket probe on this host.
Injected Darwin preparation regressions cover inherited-group normalization,
allocation before canonicalization, fixed independent removals, replaced parents,
explicit no-admission/child settlement, child backstop retirement, unknown exit-78
retirement and original native/cleanup cause propagation into provider admission
blocks. The existing fast Darwin build tests also protect the fragile Apple ACL
presence and return conventions, volume packing, task-name audit query and
direct-errno signal forms from actual source. Held ACL absence requires successful
`fstatx_np` and `filesec_query_property` calls; source guards refuse an ENOENT
bypass and protect the zero/nonzero property branch. The actual C integer
predicate is exercised for absence (`0`) and Apple's present ACL bit (`32`)
without duplicating the ACL implementation or executing a native API. Guards
require valid empty ACLs when present and bind descriptor identity and
owner/group/mode/link checks across inspection. They also protect independent
ACL/filesec release and the void filesec cleanup signature. Injected ordinary
and command builds retain the actual helper source digest. Preparation regressions
reject query/read failures, extended entries and
changed identity; first inspection failures survive separate ACL-release failures
even when every owned temporary file is removed. These fixtures exercise driver
refusal and cleanup joins, retaining historical presence diagnoses without
reenacting their old Boolean assumption. They establish neither libc ACL behavior
nor native compilation or the cause of the separate first-launch SIGABRT.
These source assertions are not native compilation; both helper variants and live
controls still require fresh matching external macOS CI. No slow tier is added.
Fast source and injected-stream regressions in `test/native-feasibility.test.js`
protect parked Git admission through the outside observers: original parent and
child birth/credential joins, immutable helper images, applied policy and policy
file stability must precede the separate release. Substituted locators, parents,
identities, images or policies refuse admission. Partial/malformed framing
(including an incomplete UTF-8 prefix), native refusal and input/output-stream
loss or early EOF/closure close release paths. Coverage retains acquired births
and the first failure when a later observation fails, keeps native reaping
uncertainty separate, and
fences parent retirement when child settlement is unproved. Actual-source
gate branches verify EOF/refusal exits without Git exec, original-child custody,
checked reaping and unchanged literal Git arguments. These controlled effects
establish no hosted Mach policy attribution or native success; the profile and
the slow-tier inventory remain unchanged.
The same fast suite injects the confined cancellation and owner-loss fault seam:
bounded locators, retained births before binding queries, credential/binding/intent
drift, EOF, partial framing and native refusal. It protects original verdicts,
missing evidence, both-original observation before intervention, partial custody,
parent fencing and separate reaping uncertainty. Actual-source gate and failure-hook
execution checks unreleased-child reaping and preserves the unconfined control.
No native API or compiler runs; no slow-tier assignment is added.
`test/native-darwin-startup.test.js` injects stream events and every startup-control
effect. It protects fragmented phase/receipt interleaving, ordered finite markers,
malformed/oversized output, complete stdout counts, self-exec fault phases/signals,
documented sandbox status -1, fixed-operation attribution through pre-readiness
and session failures, operation-valid phase prefixes, bounded loader abort
classes and path-free causes. Injected controls protect image substitution refusal
before release, exact negative outcomes, stopping admission on the first failure,
the distinct confined positive operation and independent retirement/closure
failures without replacing the first cause. Reporting regressions preserve the
original crash across separate cleanup outcomes and retain its actionable native
blocker after normalization and serialization.
The startup gate coverage records the original native birth/image and policy
intent before exec release, keeps fixture-main readiness mandatory, and refuses
birth substitution without signalling the replacement. Every fixed control and
confined startup retains its own bound crash/denial observation; failed diagnostic
reads remain separate from the original abort and cleanup. Crash parsing rejects
matching PIDs with different birth times, image paths or loaded-image UUIDs.
Indexed reader regressions inject image/filesystem/log effects and controlled
expiry to distinguish missing sources, enumeration/watch/open/stat/read failures,
unstable/non-regular files, malformed UTF-8/NDJSON/reports, successful empty and
valid unmatched inspection. Publication, watcher errors and expiry exercise the
actual wait loop and watcher/timer teardown. Matched diagnoses retain separate
report-closure failures, image changes refuse attribution, and finite redacted
outcomes preserve the original operation, SIGABRT, phase and abort classification.
These regressions execute no macOS or Windows tool and add no slow-tier check.
Actual-source guards protect flushed helper/fixture phases and the fixed sibling
outside control; policy guards allow only the exact additional `Sandbox` syscall
67 query. No process, socket, macOS tool or API runs in these regressions. Matching
macOS CI alone establishes policy-only application, inspected outside startup,
invalid-policy/withheld-exec failures, actual confined startup, unchanged
negative controls and independent cleanup. The archived SIGABRT cause remains
unresolved: observe the failing fixed operation and recognized abort cause for the
bound signed image before claiming a correction. These guarantees require only the
ordinary fast gate locally and add no durable slow-suite assignment.
Pure crash-report coverage binds only the matching fixture PID, image and window,
rejects malformed or oversized reports and prevents private report contents from
entering first causes. Only faulting-thread frame classes can supplement an abort;
these injected reports neither execute macOS nor establish a repaired startup.
The same pure abort coverage rejects tails appended to exact public dyld halt
literals; closed shared-cache/ignition classes never alter admission.
Kernel-log diagnosis coverage rejects other PIDs, times, senders and malformed
data; finite related denial classes neither retain private tails nor establish
the cause of a crash. Matching native CI alone supplies actual log observations.
Startup regressions normalize numeric-offset/fractional timestamps, CRLF and
pretty modern IPS bodies; exact microsecond birth/window mismatches, invalid
dates/encoding and sibling image joins exercise the shared decoder. Timestamp
cases distinguish missing/type, format/timezone, precision and calendar failures;
held-image mismatch pairs and substitution refuse abort attribution. Finite record
and binding rejection reasons remain redacted and separate from SIGABRT and
cleanup. These cases use only injected observations and add no check assignment.
`test/native-darwin-build.test.js` reads the actual helper and optional binding
header bytes while injecting compiler and filesystem effects. It protects the
source-supported variadic C-int signature, lookup of both function and const data
exports, dereferencing the flag instead of guessing it, refusal before effects
and the retained live-identity policy checks. Injected builds record both source
digests with unchanged public sandbox linking, diagnostic flags, x64 compilation
and signing. Compiler/declaration/type/link failures retain observed process
outcomes and compiler/SDK identities; absent or unsupported runtime interfaces
remain distinct from failed policy checks. Existing coverage still rejects
malformed x64 headers, missing signatures and substituted loaders. Injected builds
also reject native signature-verification failure, changed verified bytes and
missing image UUIDs before admitting a helper. Successful records bind the exact
UUID/image digest and installed loader/signature-verifier bytes.
These checks execute no Darwin tool and compile no macOS code. Fresh matching
external macOS
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
variable declared optional-header directories, import extents beyond 4 KiB with
independently bounded descriptor walking, non-file-backed sections and distinct
overlap, overflow and name-byte boundaries. Closed rule/numeric diagnostics and
the inspected launcher digest survive rejection before executable invocation.
Unknown or tainted diagnostic fields are discarded rather than reported.
These fixtures reproduce PE parser defects under the documented Microsoft
format; they neither inspect the archived executable nor prove native loading.
No additional slow tier is selected for these portable boundaries.
Coverage also validates
local discovery and bounded case-folded dependency closure, copied-byte manifests,
copied-runtime version inspection and synthetic repository commands. Discovery,
dependency, copy, version and initialization faults retain their first operation,
actual process facts, validated Win32 errors and already observed components;
changed copies cannot reach repository effects and killed alone proves no deadline.
No Windows process, native filesystem, SDK or installer runs locally. These repairs
do not identify the archived lost exception or prove AppContainer/Git failure;
actual copied-runtime and native behavior require matching external Windows CI.
The synthetic Git preparation regression also requires an empty confined global
config and a successful outside status control with the confined command's exact
relative recipe, absolute cwd and closed environment. It compares the outside
argument vector with the actual C payload literals while protecting absolute
root-derived image/workspace/metadata/config observation paths. Source agreement
supplies no native execution proof. Pure suspended-start regressions
reject substituted image/dependency/config/command/environment bindings, missing
files and reused or uncertain native admission. Recomputed command and ordered
Unicode environment hashes cannot authorize substituted cwd, image, root,
safe-directory, metadata/worktree arguments, discovery, extra settings or
absolute config/profile/temp/PATH bindings. A combined repository-rebinding case
rejects internally consistent path, environment and hash changes. The existing
rejection matrix also covers omissions and uncovered field substitutions for all five restricted
records: image, cwd, metadata, empty global config and repository config.
Missing `identity`, `private` or `sha256` fails even when both trusted and
restricted records omit it. Reordered fields or added canonical-path claims
cannot replace the exact serialized joins.

Actual-source guards confine the private observation wrapper to those five
`bundle()` calls. They preserve unchanged opening rights, sharing and flags,
checked non-reparse inspection, and strict normalized-path validation for trusted
`file()`/`emitfile()` callers, including the independent verifier. The shared
held-object emitter retains ACL, nonzero volume/file identity, shape, link-count
and delete-pending checks, bounded digest, complete ordered fields and checked
closure.
Opened-name fallback and general bypass paths remain prohibited. Existing
Job/token verification before release, verified-root delivery to the startup
validator, unchanged-file comparison before persistence and `G`, narrow inherited
stdio, stderr draining before exit waits and capture/deadline guards remain
required. These regressions
use neutral deterministic bytes and injected effects; they neither compile nor
execute the Windows helper. The outer helper's child-environment guard remains
distinct from Git's explicit absolute config/HOME block.

The observed pre-release `file-path` Win32 5 identifies the restricted
`GetFinalPathNameByHandleW(FILE_NAME_NORMALIZED | VOLUME_NAME_DOS)` failure,
not its deeper cause. The
[normalized/opened-name API distinction and separate SMB note](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfinalpathnamebyhandlew)
do not establish why this hosted local-path query failed. The supplied base
`a9c2d7a03e23097c3d85ed9f5590b41dcc1a9bd1` subsequently reached actual Git exit
128 in hosted Windows Native feasibility run `38141988448`; its fatal cause was
unobserved, and emergency rollback did not prove independent retirement. The
relative-recipe candidate has no native result before fresh exact-SHA CI.
Portable regressions establish the trusted-reader/restricted-observation contract, not native
acceptance. Existing fast discovery covers the repair; no slow-tier or
native-harness addition is required. Selected trusted checks retain their exact
Runner FINALIZE ownership. Fresh same-commit Windows x64 evidence from Native
feasibility and Native PoC must establish actual compilation, both permitted
status bundles, required negative scenarios, independent admission and retirement.
Subsequent failures remain explicit; this repair completes neither the full PoC
nor the separate Linux/Darwin repairs.

Closed diagnostics retain status, config and suspended-binding rejection codes
without adopting unknown codes or arbitrary error text.
Relayed failure coverage retains specific Git fatal-prefix operations through
owner loss with unchanged actual exit and separate cleanup facts.
The actual C diagnostic table and guarded complete-line scan cover LF/CRLF,
preceding warnings, the supplied `abspath.c` cwd/invalid-path delimiters,
missing quotes or error tails, cross-line delimiters and unterminated capture.
Unknown forms additionally cover captured-byte framing, embedded NUL, empty and
unterminated stderr, and finite fatal/error/warning/other classes. Source guards
separate original/launch/verifier/Git image APIs, bounds and equality without
changing their predicates or order. Legacy `git-process-exit` stays readable;
unknown operations, wrong domains and zero exits are rejected. Closed-protocol cases
propagate `git-cwd-read` and exit-only `git-path-normalize` through pending reads,
completion and separate cleanup; other domains and zero exits are rejected.
These deterministic source guards supply no native execution proof or attribution
of the base's unknown exit 128. Supplied `setup.c` verifies the special `.`
safe-directory contract, without broadening the command or filesystem grants.

Fast model-free command regressions inject held-file launches: private regular
output, unchanged stdio/observer flags, pre-write kernel-limit wiring, saturation
and substitution. Resolved nonzero completion and coded startup failures retain
redacted first causes across write errors/EOF and separate cleanup. They execute
no native tool/provider and supply no native evidence; matching CI owns closure.

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
Actual-source coverage-control and driver regressions use controlled clocks and
native calls to distinguish a bounded no-event receipt from rejected logon/time/
object attribution. Refusal diagnostics retain bounded typed facts and predicate
counts without raw XML or paths. The actual broker reader preserves admitted
terminal capture after a primary failure. Rejected-coverage cleanup exercises
original domain retirement, capture closure, watcher barriers, independent exact
restoration and fixture removal; the original refusal survives both successful
settlement and separate cleanup failures. These tests add no native support claim
or slow-tier assignment.
The same controlled capture fixture drives case-variant original names through
the source subscription contract, native control predicate and real decoder/join.
Missing delivery and mismatched attribution still refuse all probes and attempt
independent restoration; restoration failure remains separate. Source execution
also checks the diagnostic query's original FILETIME interval, shared capture
limits and independent query/event/render-context closure. Only that failure-only
query drops the subscription's SID/type filter. Actual predicate bodies count
original actor, held-name and successful read matches and SID/type intersections,
with loss and unavailable observations separate. Fixtures cover zero results,
filter exclusion, malformed or missing fields, original native render failures,
strict scalar/identity/interval/access carriers, and separate closure failures.
All examined records and XML/value render reservations consume the shared
4096-record/8-MiB budget and combined 64-KiB record ceiling; subsequent capture
cannot reuse that budget. Historical matches and incomplete diagnostics still
refuse probes and preserve independent restoration and separate cleanup failure.
These focused portable fixtures add no slow-tier requirement and establish no
Windows event generation, native XPath/SDK acceptance or hosted audit delivery.
The same actual-body fixtures cover original setter start/completion binding and
immediate-error preservation, File System snapshot projection, and a separate
installation-to-control 4912 query. They exercise principal/logon/target/GUID
matches and unknown fields, original query preservation, shared record/render
charges through later capture, and independent query/event/context closure.
Fixed-buffer channel fixtures cover Boolean values, unavailable reads, malformed
types/sizes and separate closure failures, including zero-error failed reads
and consumed-slot closure failures that must still refuse capture retirement.
Strict caller fixtures bind the installation and original control intervals,
reject inconsistent scalar authority, and retain the original missing-delivery
refusal. All APIs and clocks are injected; these additions perform no native
tool, policy or channel change and add no slow-tier assignment or native
acceptance claim.
The production coverage sequence also drives the actual policy/SACL installer,
gate open/read, bounded delivery loop and capture/bookmark bodies together.
Injected APIs verify the fresh `CreateFileW` pathname open under the held broker
token independently of whether the fixture delivers an event. A completed
32-byte read with zero delivered records still blocks. Changed token, object,
event time or logon and a substituted file ID cannot admit probes. Installed
policy/SACL readback precedes the new open, and file identity precedes I/O.
Rejected-coverage retirement additionally attempts every independent reader and
restoration barrier after capture, writer or abandon failure, retaining separate
first and cleanup causes. These fast regressions add no slow-tier requirement;
matching Windows CI must establish actual generation and subscription delivery.
Custody/channel source execution covers original overlapped completion before
event release, cancellation settlement within the original operation deadline,
process failure without releasing unsettled I/O storage, distinct bridge
wait/exit-query/exit-code refusals, and relay retirement with late input-thread
completion refused under a controlled clock. Injected EOF with a live
owner and fragmented reader diagnostics cannot supply a receipt or settle
custody. Lost finish responses, changed held identity and failed durable
acknowledgement withhold task removal; independent
removal verification remains required. Experiment startup regressions preserve the
original owner and failure after a later open response is lost, separately from
cleanup refusal. These cases execute no Windows tools or native probes.
Compiler-open regressions execute the production open, pin, PE/experiment,
verification and failure-emission bodies with injected SDK/kernel reads, then
use the actual fragmented failure parser and experiment preparation owner.
The same fixture executes the actual shared reader startup and environment
constructor, plus helper startup and both production creation-call fragments,
with injected native directory and environment operations. It checks
the exact four-entry, double-NUL UTF-16 block before trust despite absent or
conflicting ambient values, including a nondefault path with spaces and Unicode
and the supported buffer boundary. Failed/truncated results, missing or premature
termination, unsupported paths and installation failure reach neither VERIFY nor
CLOSE. Both helper APIs receive the exact block with unchanged creation flags;
repeated launches construct fresh blocks, reread the OS directory and exclude
ambient values without reinstalling the reader environment. Custody regressions
refuse invalid OS directories before file sharing or the launch-setup boundary.
Existing paired-call, pin-substitution and separate failed-owner retirement
regressions remain required. The helper's former omission is source-proven; its
unique connection to `0x8` remains unproven. Fresh matching native CI and
independent original-effect retirement remain required. These injected cases
establish neither native trust success nor retirement.
They retain the original nonzero LONG separately from closure failures, reject
positive and signed-negative nonzero results and substituted content/signature
pins, and exercise original owner settlement without repeating verification.
Malformed status, identity, slot and pin carriers remain failures without
diagnostic authority.
Custody regressions execute the actual runtime type-anchor helper and both creator
census paths with injected native reads. Varying Job/Thread indices select only
proved relevant types before duplication; unrelated unsupported objects receive
no duplication, while a required object's refusal remains fatal. Missing,
ambiguous, invalid or contradictory anchors, actual-type disagreement and anchor
cleanup are covered. Unique child membership, compiler limits, DACL proofs and
both complete inherited-object censuses remain mandatory, including unknown or
inaccessible inherited objects and incorrect pipe counts.
The same custody suite checks actual build-only creation flags, disjoint controller
and compiler admission, exact `0x2808/32/255` and `0x2008/31/255` policies, rejected
compiler breakaway/silent-breakaway and closed policy shapes. Retirement checks
the original worker and named compiler Job independently of the held controller
Job, including surviving descendants, changed births and missing observations.
Existing preparation coverage models separate original Job ownership and joins
protected pre-release worker records to settled results and approved policy;
normal, partial and owner-loss recovery remain covered by the existing native
harness. No slow-tier assignment or native acceptance follows from these portable
fixtures; fresh matching native CI and separate original-effect retirement remain
mandatory.
The actual guard, failure emitter and both creator-census duplication fragments
also run through the real fragmented channel parser.
They retain the saved error despite diagnostic I/O changing LastError, require
one duplication per attempted entry, clear successful context before an unrelated
refusal and keep refusal fail-closed. The carrier matrix covers maximum native
metadata, missing/malformed/unknown fields, conflicting trust context, legacy
frames and complete or unfinished diagnostics exceeding 1 KiB. Existing trust
and separate original-owner retirement coverage remains intact. These injected
checks prove the evidence path, not a native cause, cure, acceptance or retirement;
fresh matching original CI remains separately required.
The injected WinVerifyTrust boundary requires `INVALID_HANDLE_VALUE` for both
VERIFY and CLOSE, the original full path and readable held handle, unchanged
UI/revocation/cache policy, a single VERIFY per held file and closure of that
same verification state. A simultaneous negative VERIFY and failed CLOSE keeps
both original statuses. These checks extend the existing caller matrix and
preserve the original LONG 8/CLOSE 0 settlement regressions.
The actual trust-input snapshot and authenticated failure carrier retain the
original result 8/CLOSE 0 alongside unchanged call inputs, held handle flags,
size and current position, including failed optional queries. Per-handle positions
model EOF after byte reads. Embedded verification requires checked `FILE_BEGIN`
initialization of the original held handle before observation and VERIFY; seek
failure invokes neither VERIFY nor CLOSE. Unavailable optional queries do not
prevent initialization, and every attempted VERIFY starts at zero while retaining
the separate same-state CLOSE. Position observation remains passive zero
`FILE_CURRENT`. Microsoft's contract documents a readable open handle, not an
EOF-specific diagnosis; deterministic initialization proves neither the cause of
`0x8` nor native trust success. Malformed input arrays cannot become trusted
failure context or retirement receipts.
These cases run in the existing selected native harness, add no slow-tier
requirement and establish no Windows trust cause or native acceptance.
The same compiler-trust fixture executes the production failure-only provider
observer and bounded memory-read body before original CLOSE. Injected cases cover
missing module/API/state/data, short or unreadable structures, undersized metadata,
count/pointer mismatch, unreadable steps, empty and truncated arrays, and first
nonzero-step summaries. Native error state, one VERIFY and the same-state CLOSE
remain required; successful VERIFY needs no observation, including CLOSE failure.
The existing strict carrier matrix rejects malformed provider summaries. Caller
coverage retains original LONG 8/CLOSE 0 and separate CLOSE failure, along with
nested original cleanup refusal and independent original-owner recovery. Provider
data proves neither a trust remedy nor original native retirement.
Preparation receipt regressions drain aggregate batch deferrals without
individual reopen amplification, retain oversized-record reads, and preserve
the complete original access-profile/fault cold-recovery matrix and observer
command bounds.
Post-ready fragmented broker refusals survive later watcher and cleanup failures
through command results and the final report. Invalid, incomplete or oversized
carriers supply no native evidence; earlier transport failures keep precedence.
Actual spawn/admission/census bodies retain ownership before launch cleanup and
require birth, termination, signaling and zero exit status before releasing the
original process/thread slots and querying the Job. The caller retains the child
identity and rejects absent or inconsistent ready metadata. Source-executed
retirement checks release only exited children, clear server aliases and prevent
duplicate closure during later settlement. Live originals and unregistered Job
members (including nested descendants) remain blocking within the original bound.
Returned assignment/list completeness, query/closure failures and surviving
members still refuse; one process signal or released handle never establishes
whole-Job retirement. Fragmented observation
metadata preserves the original broker refusal and separate cleanup cause;
repeated or malformed records provide no proof. Existing capture/coverage fixtures
also check the cached notification, drain, reset, bookmark and control counters
without adding gate I/O or policy changes. Missing delivery carries the counters
through its existing diagnostic query even without a native fatal error; malformed
counters are rejected and valid counters cannot satisfy subscription delivery.
Source-executed gate/retirement regressions protect immediate error capture,
independent closure and impersonation reversal within the existing deadlines.
Controlled capture APIs execute the actual notification, enumeration, rendering,
bookmark and closure flow with XML projection isolated. They cover no enumeration
before readiness, ordered multiple batches, exhaustion/checked reset, later
notifications and arrivals during draining, exhaustion/reset and post-reset
rechecking. Fatal wait, enumeration (including 4317), render, bookmark, reset and
close failures retain immediate first causes and independently retire partial
batch/subscription/bookmark/notification resources, including inactive preflight.
These regressions replace superseded capture text assertions while retaining
distinct admission and retirement coverage. They execute no Windows/macOS tool
or compiler. Hosted Windows CI must establish whether 4317 is closed and broker
coverage succeeds; Windows TCP denial, observed Darwin cancellation/owner-loss
escapes with uncertain cleanup and absent full-system reviewed inputs/source
closure remain unresolved.
These portable checks add no slow-tier requirement or native success claim.
Narrow source checks protect the native token/API binding and early cleanup
ownership. See the [native owner](../ci/native/README.md) for Microsoft's inclusion
versus Administrators exclusion distinction. These portable regressions establish
no effective native policy or Security delivery.
The concrete owner compiles an opt-in finite variant of the existing helper using
the selected MSVC/SDK. Injected installed discovery and source reads exercise the
actual builder's separate compile/link vectors and inspected-image boundary,
including separately queried tool versions, retained input digests after a query
failure and the first operation on each failure. Linker discovery regressions
bind an encoded file-version query to the exact selected path and reject invalid
versions, nonzero statuses, fatal or incomplete output, truncation, missing tools,
cancellation, deadlines and changed linker bytes before compilation or helper
publication. No PowerShell, LINK or Windows file-resource query executes locally;
actual installed querying and native builds remain matching Windows CI requirements.
Both audit variants' injected options protect the reused 60000-ms compile/link
ceiling, unchanged 10000-ms discovery/version budget, original signals and capture
limits (4096 bytes for linker-version queries). Controlled aborts before compile
and between compile/link prevent subsequent build commands. These regressions run
in the ordinary fast gate; no additional slow suite or native harness applies.
Portable success supplies no hosted build benefit; fresh exact-SHA Windows
compilation, linking and image inspection remain required.
The custody build regression independently requires literal `rpcrt4.lib` in emitted
linker arguments, matching Microsoft's
[`RpcBindingFree` requirements](https://learn.microsoft.com/en-us/windows/win32/api/rpcdce/nf-rpcdce-rpcbindingfree).
An actual-source check compares the native build entry's fixed link tail with the
shared recipe. Both run in the ordinary fast gate without a native compiler;
no full native harness or slow suite applies to this dependency repair. Portable
success proves only link inventory consistency. Both fresh exact-SHA workflows
must compile, link and inspect command and custody images on matching hosted
Windows; native runtime and source/release GO remain unproved.
Copied-environment coverage reproduces uppercase `SYSTEMROOT` losing its native
case-insensitive lookup. Canonicalization preserves the exact installed query;
conflicting aliases refuse construction without adding environment authority.
Portable MSVC transcripts protect bounded code/symbol redaction from both streams, error
priority over warnings and linker summaries, and rejection of contaminated output.
Injected acquisition/identity/removal effects and child-close events exercise the
real preparation ledger before canonicalization, directory identity or building
fails, original-root cleanup after canonical identity rejection, independent
resource retirement, substituted-root refusal and uncertain
emergency retirement. Failed preparation releases zero provider effects and
retains cleanup separately. A narrow actual-source check protects the XmlLite
enumeration and SDK C vtable forms; it is not native compilation/linking.
XML-only reuse leaves the full reader's default compilation
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
test. Source guards require the SDK's `AUDIT_HEADER_VERSION_OPENBSM` declaration,
compile-time refusal without it, prerequisite reporting and native captured-version
comparison. Both recipes retain strict diagnostics, source identities and their
existing link flags; command-only file/FIFO ACL calls pass held stat snapshots.
Injected command captures retain an independent prerequisite version and reject
Solaris or incompatible OpenBSM records while preserving distinct cleanup outcomes.
Compiler declaration/argument failures remain setup failures rather than unavailable
interfaces or retirement proof. These fixtures execute no Darwin tools.
The concrete matching-worker effects compile finite command
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
Caller-prerequisite regressions also protect unchanged spaced and Unicode
`LOCALAPPDATA` values, path-free missing/malformed diagnoses and refusal before
helper dispatch. Source guards require the explicit AppContainer child block
to contain only the four fixed Git controls, `LOCALAPPDATA` and caller
`SystemRoot` independently matched to the native Windows directory, in sorted
order with capacity checks and double-NUL
termination. Native prerequisite validation precedes image/Job/pipe/launch-intent
effects; immediate Win32 error capture and the suspended admission/cleanup
contracts remain covered separately. These portable checks execute no Windows
tool or SDK and do not prove Win32 203 repaired. Fresh Server 2025 x64 CI must
establish real suspended launch, image/token/Job joins, positive controls,
required denials and independent retirement.

`test/native-windows-audit-builds.test.js` protects both retirement-gated cleanup
call sites, SID-scoped auditpol image/ancestor custody, closed transport,
bounded output/deadlines and independent settlement. Injected builds attempt
both variants after either failure and reject stale, missing or unbound reports.
Command build tests protect default custody compile/link recipes and shared-header
substitution; custody/preparation tests bind the six-source seal and complete
inventory. Matching Windows CI records both SDK builds through `build-windows`,
independently of launch and approved-input admission. Portable checks execute no
Windows tool and establish no native restoration. Effective-policy/audit suites
remain in the explicit native harness, reserved for Runner FINALIZE.

One cheap actual-source regression in that audit-build owner protects custody's
NT-before-account include order, the four temporary `ntsecapi.h` string aliases,
saved macro states and immediate restoration before account code. It rejects
spoofed `_NTDEF_` definitions and replacement string declarations and fails
against the unisolated include. This is source/include isolation coverage only;
portable success proves neither SDK compilation nor native ABI compatibility.
This include-only change needs the ordinary `npm run check` gate followed by
`git diff --check HEAD`, with no additional slow suite or native harness.
Both matching exact-SHA Windows builds still require compilation, linking and
image inspection; runtime restoration, admission and full native PoC closure
remain unproved.

The dedicated `native-feasibility.yml` checks are `native-feasibility-linux`,
`native-feasibility-darwin` and `native-feasibility-win32`; manual protected checks
use the `native-feasibility-acceptance-` prefix with the same platform suffixes.
They invoke `node ci/native/feasibility/ci.js --stage initialize|probe|cleanup|report`
with `--platform` and `--expected-sha`, plus `prepare-darwin` on Darwin and
`prepare-windows` and build-only `build-windows` on Windows;
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
Windows injected helper streams cover receipt-only stdout and incremental bounded
stderr, failure before the first record, split diagnostics, Win32 versus invariant
and returned HRESULT/NTSTATUS errors, stale 203, malformed/oversized diagnostics,
strict stdout and separate cleanup failure. Fragmented refusal after partial JSON
latches before owner-input teardown; fragmented cleanup remains observable after
rejection. Queued or pending receipts, valid trailing output and exit zero cannot
make a known refusal succeed. Payload/launcher failure and cleanup sequences have
explicit line-count and aggregate 4096-byte bounds, including incomplete tails.
Fragmented encoding/framing/JSON/bound failures and fixed Git receipt rejection
retain their first closed class across teardown owner-read 109; native-first
ordering and EOF without acknowledgement still fail. Reporting round trips keep
these facts and Darwin timestamp/image distinctions separate from cleanup.
Fixed Git regressions additionally reject cross-domain diagnoses, contradictory
or out-of-bound count/type facts and stale CRT/Win32 errors. Relayed predicate
failures retain their facts separately from failed owned-handle closure.
Narrow native source guards protect returned-status APIs, attribute sizing,
held executable checks, first-cause capture before cleanup, distinct stdio handles,
child-required inheritance and serialized stderr forwarding with owned joins.
These fast cases
invoke no Windows process or compiler and add no slow or native-harness check.
Actual compilation, diagnostic delivery, confined Git behavior, token/image
admission and independent cleanup remain pending fresh matching Windows
observations from both workflows. Portable passing results are not native
acceptance and do not identify the hidden API failure or complete the PoC.
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
protection failures. Mapping EACCES regressions retain the installed executable's
version/digest without changing prerequisite shape or populating unreached
checks. Injected reports preserve the original preparation cause, derivative
admission blocks and independently observed model-free preparation cleanup;
cleanup PASS never promotes blocked admission. These are reporting/classification
repairs, not evidence that any historical namespace rejection was fixed.
Fresh hosted Linux still must observe installed bubblewrap identity/version,
the exact probe variant, actual exit/signal/deadline, sanitized native explanation
and originating command rejection operation. Discarded historical stderr leaves
the namespace cause unresolved; diagnostic capture supplies no native acceptance
or repaired cause.
The fresh Ubuntu `bubblewrap 0.9.0-1ubuntu0.3` mapping refusal requires an
established remedy or independently demonstrated compatible Ubuntu 24.04 x64
GitHub-hosted worker before a rerun is useful acceptance evidence. Both fixed
probes, UID/GID mapping and required namespace/proc visibility remain mandatory.
Version-specific source/patch inspection establishes no probe or environment
correction. The shared CI-private namespace gate now requires bounded installed
identity, sysctl and effective-label facts plus PID-attributed AppArmor denials
before selecting an executable-scoped application opt-in. Historical policy and
fresh native compatibility remain unproved.
See the [native blocker procedure](../ci/native/README.md#linux-mapping-admission-blocker).
Workflow/report wiring preserves ordinary discovery, fast-gate ownership and all
durable slow-suite assignments. Diagnostic/workflow/report-only changes retain
the ordinary gate and `git diff --check HEAD`; the selected native harness
applies to changes to the existing Linux proof/preparation contracts or Claude
invocation/stream registry. Namespace preparation changes require
`node --test ci/native/harness.test.js`; the affected shared first-failure contract
also requires `node ci/native/first-failure.test.js`. Selected trusted commands
execute only through Runner FINALIZE, with their ordinary fast discovery intact.
`test/native-linux-namespace.test.js` adds fast injected success, refusal and
restoration coverage: unattributed EACCES and unknown policy cause zero loads;
the supported remedy persists intent before effects and needs both probes plus
the effective owned label; stale image/policy facts reject new admission; partial
load failures and unsettled native work preserve separate cleanup causes; and
original-context recovery removes only owned policy. Bounded trace/audit parsing
rejects malformed/oversized data and unrelated PIDs without retaining private
paths. Mapping regressions join complete resumed opens/writes to exact procfs
targets, audit PID/window, masks and errno, and reject unrelated opens, unexpected
profiles/capabilities, capability errno mismatches, incomplete calls and replay disagreement.
Pure normalization cases preserve resumed argument separators and annotated
descriptor-relative targets, distinguish quoted names from strict unquoted hex
bytes, join procfs self/PID absolute/rooted/mount-relative and complete proc-prefixed names,
reject BOM-prefixed names and quoted-field suffixes, and prevent
write-buffer text from supplying errno. Unjoined records
round-trip finite rejection classes, bounded refusal counts, closed audit-name
forms and refused-target lists through reports and summaries while remaining
BLOCKED; invalid counts, unknown/private fields and contradictory matched diagnostics
are rejected. Image substitution retains its finite first cause independently
of cleanup. No additional native effects or slow-tier guarantees are involved.
Complete proc-prefixed self/PID mapping names join only identical canonical
syscall targets; legacy `relative-proc` diagnostics still round-trip as BLOCKED.
Malformed names, absent procfd bindings and target mismatches remain rejected.
Darwin injected observations cover missing-timestamp known-field types, literal
image path relationships, legacy facts, closed-vocabulary refusals and escaped
bounded summaries with separate first, observation and cleanup failures.
These attribution additions require only the ordinary fast gate and HEAD-relative
content check, with no native harness or unrelated slow tier.
Linux-only plain Node child fixtures exercise the private regular-file
transport, fixed 6.8 `-f -o`/kernel-limit command contract, held identity,
substitution refusal, bounds, deadlines and independent retirement. Portable
coverage protects successful/resumed exec attribution, required terminal exit
records, payload exclusion and
redacted first-cause persistence before complete observations, independently of
cleanup outcomes. Missing probes are never synthesized; legacy receipts remain
recoverable. These fixtures run neither strace, prlimit nor bubblewrap.
Workflow/report regressions protect the admission gate, unknown process
facts and always-run policy recovery. No test invokes native probes, parser,
sudo or kernel policy, and no unrelated durable slow suite is affected.
Injected journal commands exercise the actual protected sudo/timeout/journalctl
boundary, complete matching JSON/terminal cursor acquisition, opaque cursor
handoff and empty successful kernel reads. Refusals before either probe retain
real exit/signal/deadline facts, including wrapper exit 124. Exit 137 alone retains
an unknown deadline rather than guessing its signal source. Missing, mismatched,
incomplete, malformed UTF-8 or excessive output cannot supply a cursor; rejected
output retains successful exit 0 rather than inventing unavailable process facts.
First-cause and partial-probe evidence survive separate policy cleanup failures
without publishing command output, journal prose or cursor values. These tests
bind the corrected `--dmesg` vector. Local installed journalctl reproduced the
unsupported `--kernel` spelling and accepted the corrected command; native CI
still owns the namespace and policy proof.
Injected procfs controls reproduce protected PID 1 link refusal and admit the
same full same-boot control through a supplied reader; hidden procfs and a
different init namespace still refuse retirement. Actual Ubuntu CI owns the
fixed privileged link read, unchanged namespace probes and independent cleanup.
Injected verifier/build-child launches cover the hosted tuple, absent/nonmatching
context, fixed PATH/LANG, secret/provider exclusion and unchanged bounds.
These effect-free tests prove wiring only. The source omission is repaired;
fresh exact-SHA native retirement must establish CI cause closure. Windows,
Darwin and reviewed-input blockers remain open. This proof-owner repair retains
the ordinary gate, selected full native harness and HEAD-relative check in order.
Matching Ubuntu 24.04 CI with installed strace 6.8 must exercise actual policy attribution, installed
parser/ABI preparation, unchanged ordinary/nested success, payload denials and
independent native/profile cleanup. Injected cleanup never supplies a native
retirement witness or a GO decision.
See the native owner for exact CI stage commands and
operator-owned protected environment setup; these are external experiment checks,
never additional local FINALIZE commands.

## Native proof harness

Windows experiment regressions prove that helper admission and cold verification
bind thirteen images without traversing their installed-system imports. Dependency
coverage is scoped to private payload and Git copies, preserving held source/copy
identities, delay edges and substitution refusal. Payload and Git fixtures expose
unresolvable ordinary and delay imports on held stock targets and assert that
neither discovery path resolves them. Direct access copies survive, and nested
private Git copies retain their source slots and delay edges in operation
declarations. Cold loading rejoins both inventories without acquisition or
compilation; missing private dependencies, changed held bytes/identities and
changed delay evidence fail. Operation-reader coverage joins native observations
of the private graph, omits stock edges and rejects missing/substituted private
modules or extra stock-import evidence. Explicit null helper/system
import inventories cannot be promoted to empty observed graphs or used for reviewed
admission. Live loader coverage accepts hosted System32 module observations while
rejecting undeclared private modules and incomplete private dependency evidence.
Version-4 preparation and version-2 operation records reject legacy, mixed or
missing evidence without recompilation. Custody recovery retains original
process-hold failure even after a later observer completes. These neutral
injections use existing fast discovery and the selected native harness; they invoke
no Windows tool, add no slow tier and establish no native acceptance or original-owner
retirement. Windows `verify-retain` 87, observer-transfer 10022, missing 4663 audit
and Darwin inherited `TASK_ACCESS_PORT`/model-free prerequisite 78 remain required
external concerns. The retained `ole32.dll` delay-import failure is not an
optional-contract exception; fresh matching original CI on the final SHA must
establish native outcomes independently of these portable checks.

The existing Windows preparation-to-operation and cold-load cases cover both
installed UCRT and MinGW Git layouts. They exercise shared discovery, persisted
runtime selection and whole-file pins, copied/private import inventories and
their actual operation consumers. Missing or substituted selectors/images,
discovery disagreement and changed private or delay dependencies fail without
cold rediscovery. The native reader's shared installed-path predicate is exercised
with injected string operations, including out-of-root and nested-path refusals.
These cases change no test assignment and establish no native Windows loading or
retirement success.

Darwin injected/source regressions protect shared sandbox function/data bindings,
unavailable exports, all custody query consumers, path-filter results and PF
counter normalization without losing experiment rule authority/order. Existing
acquisition, build, custody and cold-recovery regressions also reject missing,
substituted or shadowed binding-header dependencies. These portable tests compile
no native helper. Matching macOS must compile/inspect all ten helpers and exercise
positive/negative SPI controls; compilation supplies no PF runtime evidence.

Darwin cache regressions execute the repository loader-query body with injected
task and memory reads. They reject failed queries, incomplete counts, unknown
formats, short/wrapped records or reads, old versions and substituted UUID/base
observations. Source-derived predicates reject slid-address and mapped-range
overflow; retained shared custody fixtures protect cache/image UUID requirements
in both purposes and experiment mapped-text hashes. Ordinary helper preparation
does not invoke those cache readers. SDK layouts remain
symbolic in these portable tests: actual SDK compilation/linking and loaded-cache
joins require matching macOS CI. Retained reviewed preparation coverage freezes both
loader SDK headers in the compiler dependency inventory and rejects substitution
on cold load. These cases use existing fast discovery and the selected native
harness, adding no slow-tier requirement.

The same Darwin build-source suite executes the shared native ancestor predicate
for both compile purposes. Synthetic installed-cache paths accept hosted parent
ownership/modes only in experiment builds; private helper/case roots, tools,
near-miss names, non-directories and reviewed inputs retain their refusals.
Shared custody regressions exercise held cache reads under hosted ancestry,
rejecting canonical-path, parent/leaf identity, ownership and content substitution.
Ordinary preparation and cold loading instead bind existing helper bytes without
cache selection, acquisition or recompilation. These cases add no native
tool, framework, slow-tier assignment or native acceptance claim.

Linux interpreter regressions inject source/running-inode and byte-window
substitution, sealed-image/loader replacement, missing or mismatched original
owner/intent evidence, interrupted publication and lost replies. Cold rejoin
performs no copy, rejects a substituted running interpreter, and uses the original
sealed image for fresh verification.
Independent preparation recovery distinguishes validated unstarted compiler work
from missing acquisition evidence. These effect-free regressions use the existing
native harness; actual helper builds, all 23 Linux checks and independent normal
and interrupted namespace restoration remain matching Ubuntu CI requirements.

Linux system-experiment regressions inject preflight rejection, interrupted
reference publication, admission and native lost replies, and zero-case cleanup
dispatch. Controlled clocks retain startup time in the first recipe deadline;
diagnostic write failures preserve the original cause. Namespace checks require
the original stage journal, independently retired preparation and independent
proof closure. Preparation regressions rejoin the complete original command
inventory after prior retirement and reject unavailable fresh retirement. These
cases retain original failures, use controlled clocks and injected effects, and
are covered by the existing fast gate and native harness. They add no durable
slow-tier requirement or native acceptance evidence.

Synthetic experiment and acceptance metadata regressions bound artifact creation
by upload start and producing-job completion. The successful literal-ID receipt
binds the producing job, independently of API creation time. Controlled clocks
admit creation after receipt completion within the job, including both envelope
endpoints, and reject creation outside that envelope or jobs completing after now.
Malformed or unordered intervals, duplicate or missing steps, failed receipts,
substitutions, freshness and expiry retain rejection.

Zero/one/multiple selection cases protect the pinned downloader's layout: one
artifact requests the validated name directory, while multiple artifacts request
the common root so the action creates name directories. Simultaneous system and
provider selections remain disjoint and exact selected IDs are retained. Workflow
coverage requires nonempty ID guards and the matching emitted destinations for
every affected download. Strict loaders and working version-7 parsers are unchanged.
These neutral, synthetic, wait-free checks establish metadata and layout consistency,
not native success, external approval or full PoC completion.

Fixed build-loop regressions inject multiple compiler failures, later independent
attempts and first-cause retention. Bootstrap fixtures require the complete fixed
inventory before sealing; protected preparation fixtures require settled native
receipts for continuation and reject partial publication. Controlled clocks,
cancellation, changed-input and uncertain-completion cases identify unattempted
recipes without starting native tools. Selected-SDK PF capability fixtures retain
absent headers, failed dependency queries and unattempted observations separately;
Windows audit capture retains the underlying first exception through its existing
diagnostic sink. These cases use the ordinary gate and selected full native
harness, add no durable slow-tier assignment and establish no native acceptance.

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

`test/native-windows-experiment.test.js` belongs to ordinary fast discovery.
Pure/injected cases protect the complete helper/header/case inventory, disjoint
experiment custody, exact checkout/Git-blob bytes, one hosted compilation per
helper, explicit environments, actual command diagnostics and immutable PE purpose.
Version-2 records reject changed candidate/output, legacy and incomplete evidence;
cold loading cannot discover or compile. Injected process-tree cancellation and
uncertain cleanup preserve the original cause. Interrupted System publication
retains possible ownership without retry or fabricated retirement. The build
policy reads fresh held output, without System compiler domains or nested Jobs.
Cold-load failure coverage preserves both verification and cleanup causes.
Superseded compiler dependency and bootstrap-journal fixtures are removed. The
retained raw preparation suite still verifies observer coalescing, lost finish
without replay, original birth/Job/task retirement, cleanup/persistence failures,
and every distinct native file, Git, access, audit, policy and ownership guard.
Its real JS protocol regression requires the recorded helper SHA-256 in
`prepare-read`, rejects changed hashes, unlisted paths and helper/installed-image
substitutions, and retains the distinct installed-input request.
Generated cases preserve native copy kinds, complete copied Git loader graphs
and valid Git index padding/checksums. The preparation suite keeps immutable Git
copying in the case custodian without requesting bootstrap read authority.
The native custody suite also exercises experiment-purpose Job/handle protection
through raw frames. These checks perform no Windows build, elevation, policy or
Task Scheduler effect and provide no native CI proof. The existing Windows
preparation, launch, effective-policy and audit suites remain required for their
owned contracts; matching Windows CI supplies actual PE/SDK, System DACL/held
handle, ordinary compiler completion, policy/audit, file and fixed-Git execution
evidence. Reviewed compiler/signature/publication guards retain their distinct
coverage; portable tests cannot establish native acceptance or production readiness.
Runner-selected commands execute only in the dedicated FINALIZE gate.

The included `ci/native/win32/custody.test.js` injects sealed-byte reads, private
Task Scheduler transport and independent native observations. It protects
effect-free construction, task/provisioning intent, separate System admission,
held identity/volume and PE dependency joins, explicit file/policy handle
transfer, suspended release, cancellation, bounded pipe failure and independent
domain/task retirement. A portable source-driven principal regression covers
SID/name routing, conversion failure and invalid/non-System rejection without
invoking a Windows tool. Its focused invocation is
`node ci/native/win32/custody.test.js`; it performs no task registration,
elevation, installation or native build. Matched Windows SDK compilation and
actual LocalSystem/Task Scheduler/NTFS custody remain external CI requirements.
It also covers hidden-task GUID/state/engine and birth joins, matching-digest
zero-instance rejection, durable pre-setup abort receipts and fresh verification
without clearing admission failure. Lost replies, live Jobs and exit 124 retain
separate causes; independent task settlement precedes outer observer release.
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
Experiment input-journal coverage uses the real custody reader with fake
transport, holds its acknowledgement to prove that acquisition cannot advance,
and rejects inadmissible receipt names. Normal and fresh recovery selectors
exclude only the numbered preparation journal family from retirement evidence;
malformed names and experiment journals in reviewed inventories remain failures.
Indexed preparation and cold/recovery coverage also retains the actual producer
names, first-cause preservation and independent non-emergency retirement.
For reviewed preparation, the repository owners verify and persist all 22 fixed
Clang/SDK/signing commands, snapshot unsigned inputs and rejoin final pins and original receipts
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
The existing ordinary preparation-to-cold-consumer fixture also calls the real
`createWindowsExperimentSystemEffects` factory through its preparation-options
proxy. It successfully verifies the build and independently reads its policy,
aborts that work signal, then supplies a distinct live cleanup signal only to
system settlement. It never calls `beginCleanup` itself or replaces the file
owner. Assertions require independent build/policy settlement, the original file
observer's process and task retirement, admission fencing, registry removal and
one cached finish without recompilation. The same fixture retains its original
closed-receipt and failed-recovery refusals; reviewed build, deadline, latched
failure, cleanup cancellation and live-reader coverage remain in this suite.
This regression belongs to the existing explicit native harness, adds no slow
tier and establishes no matching Windows CI or native acceptance.
The real experiment open/close and preparation catch also use that raw fixture.
The fast experiment suite exercises the actual preparation registry rather than
extracting the changing close method from source. Parked-admission closure is
covered through the real experiment owner; raw observer finish rejects a live
held subject, and EOF exit 126 still requires complete independent recovery proof.
Each injected observer owns its file/read/upload slots and directory snapshot;
an independently retired fresh observer cannot consume or settle an original
observer's pending read.

The existing experiment producer-to-cold-consumer fixture now removes exited
original observer actors from its process table. Loading and original-owner
recovery select cold verification from matching protected intent, close, birth
and result records rather than attempting a live retain. The mixed-inventory
regression combines completed observers that have disappeared with interrupted
observers whose process handles remain readable. Either subset failing retains
the interrupted owner's task; successful recovery preserves the first failure.
Custody regressions cover complete proof, signaled readable originals, PID reuse
and complete identity changes, nonce/task/receipt mismatches, incomplete or failed
process/Job/task reads, live recovery/compiler/controlling Job members, and surviving hidden task
instances. Reordered census identities remain equivalent, and cancellation of
pending cold-observer IPC closes that channel without clearing the failure or
renewing the original deadline. Native-source execution exercises bounded complete
process enumeration and the hidden-instance query even when the registered task
is missing. Failed fresh-observer retirement withholds success; later observers
cannot settle earlier uncertainty. The failed-live-hold and dependent-reader
retention regressions remain.
These injected cases add no Windows execution or native-acceptance claim and
remain owned by the existing native harness.

The same producer-to-cold-consumer fixture uses the real system recovery owner
and its original inventory, including `windows-experiment-selector.json`.
Protected metadata reads exclude that selector from effect intents and reject
unknown names, malformed shapes and candidate/bootstrap contradictions. Missing
selectors and final preparation outputs do not replace original journals as
recovery inputs. Failed fresh proof retains dependent readers and the first
cause; a later observer's successful finish cannot clear that uncertainty.
Inventory admission is distinct from preparation retirement and cleanup PASS;
these portable cases establish no native acceptance.

Partial package recovery models the failed cold observer's eventual EOF exit 126
when its channel closes. The former no-op close left that observer permanently
live after per-observer custody stopped a fresh finish from discarding its held
subjects. The regression retains every original live owner after the rejected
cold pass, leaves observer tasks for independent removal, and requires fresh
complete recovery to retire all actors and tasks without admitting publication.
The access matrix's cold recovery first settles the actual preparation owner.
The public factory deliberately reuses a live observer; leaving that owner open
incorrectly spent its shared 32,768-command budget on reconstruction and retained
`access.workspace-write.none`. The regression now proves that original preparation
owners retired and their tasks were removed before constructing fresh recovery,
preserving all nine profile/fault variants, native command bounds and independent
recovery assertions.
The cancellation fixture keeps EOF exit status separate from the closed process
observations, matching native `process_read` and `verify-process-exit`; embedding
`exitCode` in those observations incorrectly blocked complete recovery. Its
channel close is idempotent, matching `windowsCustodyChannel`: a late cleanup
callback previously reread an already removed task and raised an asynchronous
`TypeError` after the test passed. Controlled recovery cancellation now exercises
that callback immediately after complete retirement, without waiting for a timer.
Normal observer disposal also preserves the distinction between successful
verification and explicit cleanup/recovery fencing. Setting that fence during
ordinary `settleFiles` made `verifyBuild` reject its own verified settlement. Reader
registration still rejects admission once observer settlement starts or completes.
Regressions cover post-startup open rejection, retained/thrown reader settlement,
receipt failure, concurrent/repeated close, interrupted explicit recovery and
cleanup IPC cancellation. The actual preparation-files registry preserves reader
dependencies until fresh original process/Job/task proof permits observer closure.
Cancellation covers queued reader work, consumed receipt acknowledgements, task
acknowledgement and bridge completion while preserving dependent observer custody.
A wrong original birth cannot release registration, and recovery holds the old
observer births before closing them without treating that custody as retirement.
A later observer's success, missing task or watchdog exit cannot retire an old
owner. Original preparation and cleanup/persistence causes remain separate.
Raw transport regressions distinguish terminal failure from bridge exit while
rejecting outstanding sends, receives and dependent waits. Actual reader commands
also reject when their journal is still pending, without sending late work.
The compiler-trust and preparation callers retain the original nonzero trust
refusal and separate CLOSE result while delaying bridge exit. Recovery must wait
for that exit, then independently prove the original births, whole Jobs and tasks;
a surviving compiler Job or an expired cleanup signal retains registration and
the dependent observer. A consumed observer finish with a lost acknowledgement
is cached once; fresh recovery must retain the old observer before waiting for
its bridge exit and independently proving original observer retirement. These
portable fixtures exercise ordering, not native trust success or retirement.
The preparation fixture also enforces the native task-removal guard over every
retained process and previously observed whole Job. An actual-source custody
regression executes the original process/Job guard loops without a Windows tool.
The original LONG 8/CLOSE 0 caller now proves reader task removal before live
observer retention, two exact-birth reads before registration release, then
separate observer retirement. Missing/replaced readers or observers, a changed
second birth read, task substitution, surviving Jobs and cancellation cannot
release unproved dependencies or establish complete retirement. Registry checks
reject missing no-live-member proof and absent or incomplete custody of its own
original observer pair. Existing
lost-finish, bridge-exit, emergency-retirement and bounded-cancellation coverage
remains active; no command or trust verification is replayed. These portable
cases retain the selected native harness and add no slow-tier assignment or
native acceptance claim.
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
Its Linux preparation suite injects one hosted GCC compilation and verifies actual
host paths, fixed static options, command diagnostics and cold loading without
execution. Legacy/mixed or incomplete records and changed candidate/source/tool/
output/ABI observations are rejected. Compilation, missing output, cancellation
and interrupted publication retain the original failure; recovery requires a
completed build record, the original preparer's absence and its sealed interpreter.
A rejoined interpreter alone cannot settle a missing command completion. Existing
held-image, file/Git/access and ownership regressions remain distinct. The system
composition fixture exercises all 23 checks with an explicit experiment reference
and build observation, without compiler admission or a review manifest. Reviewed
consumers reject that private reference; reviewed compiler receipts, audit
missing-input refusal and independent payload retirement remain strict.
Direct production receipt-admission coverage injects protected reads and fresh
verifiers for the complete ownership/access and 21-file-session inventory, with
both compiler receipts required only for reviewed compilation. Missing, duplicate,
unexpected, substituted and unretired receipts are rejected.
These injected regressions invoke no GCC, bubblewrap or privileged native effect;
they add no durable slow-tier guarantee. Existing harness and first-failure
requirements remain unchanged and run only through Runner FINALIZE when selected.
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
The included `ci/native/review-inputs.test.js` checks data-only candidate/platform
and byte bindings, independent system/Linux/template approval requirements,
Linux normalization/build/ABI agreement and declared package/tool/helper closure.
Metadata capture rejects hidden fields, custom prototypes and executable accessors
without weakening the existing accepted source-data shapes.
Its injected Git inspection also rejects missing local objects without lazy acquisition.
Its injected entry bytes throw if evaluated; metadata-valid fixtures retain
unobserved native custody/admission and distinguish manifest schema 2 from execution
schema 2. Its focused invocation is `node ci/native/review-inputs.test.js`. It runs
no native tools, acquisition, helper build or installed-input inspection. The
harness remains required for changes to this verifier and its shared validators;
matching-OS native acceptance is separate.

`test/native-ci-inputs.test.js` belongs to the ordinary fast tier. Injected delivery,
acquisition and protected-receipt edges check independent digest and run binding,
closed data, zero writes after refusal, unique controller-source citations, original
review/custody reuse and live-expiry fencing for provisioning and nested payload
admission with independent settlement/recovery still available after delivery loss.
Bounded real-file reads cover missing/non-regular files, symbolic links, hard-link aliases
and oversized delivery.
Source snapshot/custody validators use captured repository bytes; separate metadata
validation remains owned by `ci/native/review-inputs.test.js`. None of these tests runs
a native tool or establishes native custody, admission or GO. Shared system/review,
acquisition, factory-loading and recovery changes also require
`node --test ci/native/harness.test.js` and `node ci/native/first-failure.test.js`.
Selected trusted checks execute exclusively in Runner FINALIZE. Fresh matching
Windows/macOS/Linux CI still owns actual builds, approved inputs, startup, controls,
Linux policy and independent cleanup; full/protected acceptance needs genuine
source/release/provider closure.
The included `ci/native/first-failure.test.js` injects receipt publication and
job replacement to cover individual prerequisite diagnoses before acquisition,
interrupted first-cause retention, standalone receipt custody, uniquely bound
aggregation without setup identity, redaction and preparation recovery states.
Rendering coverage keeps missing reviewed inputs as unsuccessful prerequisites
with independently supported non-admission, separates mixed native/recovery
failures, and refuses to infer no effects from a prerequisite label alone.
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
