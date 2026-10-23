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
parent-uncertainty regressions. The transient case fails the termination write
without delivering its command, then reports the asynchronous callback error;
its additional fallback inspection is independent of native IPC delivery.
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
The existing preparation/custody fixtures distinguish completed-build file
revalidation from retained ABI/read/retirement observations. Repeated cold loads
and per-case verification check current source/tool/SDK/helper bytes without new
build effects, recovery replay or original-domain census. They reject substituted,
oversized, missing or unsettled inputs and file-read digests presented as fresh
native events. The required runtime input observer supplies fresh held helper
observations; native build policy and actual case admission retain independent
identity, signature, installed-policy and retirement checks. Malformed original
journals remain recovery refusals rather than triggers for normal cold loading.
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
IPv4, missing IPv6 and internal-only or malformed IPv6 inventories must refuse before
PF/volume setup while reporting the failed family and all named candidates with
addresses, internal flags, scope IDs and exclusions. Scoped acquisition accepts
observed link-local addresses across `fe80::/10` with matching named or numeric
zones, preserves unscoped preference, and rejects missing, malformed or conflicting
interface/scope evidence. A throwing diagnostic sink cannot replace the original refusal.
The existing case consumer additionally asserts all 39 attempts, distinct
family-bound host-network and loopback targets, pinned numeric zones, 33 denials
and four echoes. Scoped transcripts retain all access profiles and independent
retirement; cold reads reject malformed scopes and disagreeing TCP/UDP targets.
The custody suite executes both native sockaddr constructors and control/payload
argument expressions with injected operations, covering exact scope IDs, source
binding and reviewed-scope refusal without compiling or running Darwin code.
These synthetic reads and injected commands run through the existing native
harness without a slow-tier addition or host networking changes. Missing-family
diagnostics and portable regressions supply no native acceptance.
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
Route regressions execute the native acquisition and normalization bodies with
synthetic storage. They distinguish syscall failure (including errno 0), empty or
oversized dumps, truncated headers, invalid message extents/version/type and hash
failure. Only documented usage counters are normalized; other observed bytes
remain in the digest. Ordinary route variation is accepted across preparation,
case snapshots, counter windows, normal restoration and interrupted recovery;
reviewed route pins remain strict. The native journal retains its bounded original
route hash without requiring host routing to rewind. These tests infer no failed
predicate from the original combined guard's errno 0 and run no native API.
Return-response regressions reject altered ICMP codes and unsupported queue
selectors without inferring expected policy from installed bytes.
PF lifecycle fixtures retain disabled stock-style attachments and foreign child
rules across installation, normal restoration and cold rejoin. Injected interruption
points cover enablement, attachment, installation replies and restoration replies;
recovery cannot replay installation or accept missing original-operation evidence.
Foreign rule-byte/identity, generation, interface and state substitutions and
malformed route observations retain exclusion. Root relocation permits only derived
ordinals/skip destinations while preserving authority and order. Native source predicates protect conditional
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

Task-access regressions execute the actual sanitation, checked-release and
original child launch bodies using injected Mach and process calls. They accept
absent/dead values and the specific task-access slot's exact SEND service with
`IKOT_NONE`, including different local names across lifecycle observations.
Task/thread/kernel substitutions, mixed/unknown types and failed type or kobject
queries refuse exec. A getter-copy release cannot clear the slot. The accepted
service survives the full bounded census and is released only afterward, alongside
the checked ordinary-host and thread copies. Unknown live census rights refuse
without destruction; unowned dead names remain untouched. Missing/changed census
entries, list/count failures and array/reference release failures also refuse.
Unsupported types without an owned reference are never deallocated; combined
query/authority and release failures preserve the first refusal and independent
cleanup cause. Descriptor closure and explicit bootstrap/debug/registered/exception
sanitation remain covered.

The same actual-body fixture begins reference ownership at child entry, before
the first observation, and rejects copied parent bookkeeping as cleanup authority.
Its actual allocator callback records bounded ordinary reply returns before the
child launch body runs; the existing sanitation fixture separately models the
ordinary MIG and special reply caches. It covers child PID rebinding, fresh
reexec bookkeeping, null/dead allocator results, racing initializers, unfinished
parent initialization, interleaved allocations, overflow,
duplicate/incompatible provenance and an ordinary cache sharing a producer name.
Getter/local send copies may alias borrowed ordinary or special replies without
consuming the runtime's references. Missing/dead or aliased caches, replacement
before/during census or release, new producer events during census/release,
changed exact types and missing census entries refuse exec. An unobserved ordinary
receive and an additional receive-only `IKOT_NONE` right both remain unknown:
the census cannot supply their provenance. Environment setup precedes the final
census, which refuses an unknown right introduced by that setup before exec.
Partial cache/thread/host acquisition, failed access type queries and simultaneous
array/getter release failures retain
their distinct original and cleanup outcomes. These deterministic cases add no
native execution, validation command or slow-tier assignment. They identify no
historical unknown right and establish no native dyld interception or closure.

That existing fixture also reads the owned interposition declaration, requires
the retained `__DATA,__interpose` entry and its ordered, typed replacement/replacee
pair, and rejects the unavailable `mach-o/dyld-interposing.h` include. It models
outside-image allocation dispatch through the actual declared pair. The original
allocator stub remains distinct from that dispatch, and each intercepted call
must return exactly one original allocation without recursion. The existing
PID/fork, concurrency, cache, overflow, missed-producer, census and cleanup cases
all retain their original assertions through this entry. These portable
observations protect declaration and ownership wiring only; they do not execute
dyld, compile an SDK shim or prove installed header/export availability. Both
ordinary and command-enabled helper builds remain matching hosted CI obligations.
No validation command or slow-tier assignment is added.

That fixture also requires the exact owned `mach_port_name_t mach_reply_port(void)`
prototype before both the allocator callback and interposition entry. It checks
the common domain include alongside the optional command include and rejects
broad `PRIVATE` enablement across the complete helper's transitive source owners
and build arguments. The same actual allocator and interposition bodies still
exercise the original ownership matrix; no replacement fixture or SDK shim is
introduced. The existing ordinary/command build fixtures retain their source
pins and link flags. These source guards do not compile either variant or prove
the installed allocator export; matching hosted compilation, linking and runtime
verification remain required.

The same fixture executes the cached special-reply loader body with injected
`dlsym` and `dlerror`. It protects the pinned zero-argument `mach_port_t` call
type without the unavailable private SDK header, clears a stale loader error,
and refuses missing exports or a nonnull result accompanied by a lookup error
before either cache borrow or native observation. A copied parent pointer cannot
bypass the child's lookup. Refusal still releases its owned bootstrap reference;
a release failure remains separate from the original binding failure. Existing
cache, producer, census and retirement matrices remain intact. The public failure
decoder retains the bounded binding operation without raw loader output. These
portable regressions establish no installed macOS export availability and add no
native execution, validation command or slow-tier assignment.

Custodian lifecycle fixtures retain one checked release per valid getter copy,
no endpoint contact and unchanged errno, including unavailable type queries. The
child's observation remains after its alarm and before credential/session changes;
its optional getter/query cannot replace the authoritative payload sanitation, and
failed copied-reference release stops before that transition. The custody caller
still forwards fragmented raw lifecycle and malformed metadata without replacing
the original refusal or separate release cause when diagnostics throw. Bounded
classification covers service-query, census-authority, special-cache and runtime
provenance failures through the existing owner. Cancellation/owner-loss and
independent retirement matrices remain required: primitive cleanup success cannot
pass cancellation.
These portable fixtures run no native compiler or macOS tool, supply no native
acceptance and add no slow-tier assignment.

`test/native-darwin-command.test.js` additionally executes the actual finite
command guard, failure and cleanup bodies with injected native calls. Capture
fixtures forward exact child stderr bytes, including split binary chunks,
through the existing broker diagnostics before V/G exit and schema refusal.
Read and diagnostic-write failures preserve the original outcome. Unexpected
task-access authority refusals, owner-loss fences and independent cleanup coverage
remain required. Audit-pipe open/query/selection failures retain exact caller/guard,
return value and saved errno, including when diagnostics or cleanup change errno.
Checked `FIONBIO` success and failure protect the audit driver's explicit nonblocking initialization
before its selection queries. Actual drain bodies cover empty nonblocking drains
returning to command input, EINTR before and after expiry, native read/EOF failures
and sustained separate/coalesced records reaching expiry. Split headers and records
survive empty drains without dropped tails; malformed headers/lengths, 64-KiB
record overflow, eight-MiB total overflow and 4096-record exhaustion refuse
admission through the existing owner. Barriers cannot acknowledge an unfinished
tail; explicit terminal capture cannot close or emit completion for one. The
per-record libbsm decoder remains independently required, and these fixtures
supply no native token or matching-host acceptance.
Initial guards retain their entry order; session-escape and membership refusals
stop before previously short-circuited operations. A later retirement refusal
cannot replace the first error and keeps a separate cleanup cause. These fast
fixtures preserve exit semantics and never classify exit 78 alone as an
environmental explanation.
The same suite executes the actual command-image identity body with injected
metadata, 8-KiB reads and SHA-256 calls. It streams the observed 260,633,072-byte
provider length as counts without allocating or hashing a large fixture. Only
the configured path/digest pair receives 512 MiB; helper overflow, provider
overflow, wrong bindings, short/growing streams, digest mismatch, kernel-path
substitution and held/named identity substitution remain refusals. Existing
metadata and retirement coverage retains its separate guarantees. These
portable cases add no native execution or slow-tier requirement.
Both task-access confinement and model-free command feasibility remain open
until fresh matching native evidence establishes their functional causes.
Event-driven in-memory broker streams now cover ready followed by an unanswered
V, cancellation during an acquired launch, late custody after cancellation,
closure without retirement evidence, and separate cleanup deadline/observer
failures. They exercise the existing effects owner and controller with unchanged
120/30-second signals, independent settlement readers and the original failure
preserved. An actual-body native failure fixture closes the unreleased P gate and
reaps only its original fork. These portable tests add no native invocation or
slow-tier assignment and establish no native acceptance of the V/G stall.

Cold trace fixtures additionally execute the replacement-epoch binding and the
native T/E handoff. A controlled binding promise keeps E fenced until the real
exec row arrives; changed PID/birth/credentials/session, unchanged generation,
duplicate binding, early tracer closure and cancellation refuse release. The
trace's failure callback interrupts an active cold request after E while leaving
later independent settlement consumable; callback exceptions cannot replace the
original trace refusal or prevent observer retirement. The
native exec body retains its original image and policy descriptions through E
and checks them again before resume. A separate actual-body capture case rejects
remaining domain members after wrapper exit while retaining the child's original
stderr. Controlled process-exit and stream-close events deliver the final
syscall/numeric return and exit in fragments, proving that process completion
cannot discard buffered observations or retire the observer chain before drain.
Exec-only output, missing returns and failed independent retirement retain their
existing refusals. These in-memory regressions use the existing startup and
command suites, add no command or slow-tier requirement, and establish no native
probe rebinding, trace delivery or closure. Fresh original macOS CI owns that proof.

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
compilation, and verifies effect-free indexed factory construction.
Default installed-file build regressions also revalidate unchanged canonical tools
through cold loading, without a `readInstalled` override. They preserve existing
512 MiB tool, one MiB SDK and 128 MiB private-helper bounds, exact byte and
identity refusal, bounded
ordinary-sink predicate/error diagnostics, recorded expected-hash labeling, and
separate primary/descriptor-close failures despite sink exceptions. They retain
captured stability snapshots and distinguish held and named recheck API failures.
Refused reads permit descriptor closure but no subsequent file reads or native
effects. The same fixture injects the former-bound-plus-one, observed Clang size
and exact native-budget boundary without allocating large tool images; it checks
the installed-reader ceiling and unchanged private/source ceilings. Tiny buffer
cases cover the shared acquisition/observation guard's exact ceiling and refusal
of oversized, empty or non-buffer results. The default held reader still rejects
native-budget-plus-one metadata before reading and retains independent SDK-limit,
substitution, unsafe-metadata, stability and closure-failure coverage. These
portable checks establish neither a complete large native read nor hosted
acceptance. They remain in the existing explicit native harness and add no durable
slow-tier requirement.
Installed audit mapping coverage retains Git open variants within the original
class mask. Missing case selectors keep recovery retained despite retired build
receipts.
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
policy verification and fresh runtime inventory. Noncanonical Windows parameter
order crosses the normalizing policy producer; wrong templates, context and unknown
binding fields still refuse. Missing/substituted observations,
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
Windows socket regressions execute the actual source DACL producer/readback,
primary-token creation, self-transfer, observer admission and partial-close
bodies with injected OS calls. The held child source receives only an exact
`PROCESS_DUP_HANDLE` AppContainer ACE beside the retained full user ACE; the
independent suspended-child verifier requires the same protected DACL. Readback
rejects a changed owner/SID/mask, inheritance, extra ACEs and query failures.
Setter/descriptor failures refuse release and free the temporary descriptor.
Only the original read/edit source selects this contract; Git children and other
launches retain private DACLs. The effective-token preflight opens only the
source's current PID and checks closure. Neither destination denial nor `10022`
authorizes an observer grant.

Creation must use the child's exact primary AppContainer token with no thread
token. Failed or short token reads, zero-error query failures, wrong package,
user or capabilities, token drift and uncertain closure refuse admission.
The production operation loop persists the exact child/provider record before
`D`. Actual self-duplication/import bodies rejoin birth/token/local endpoint
and provider/catalog/chain; PID-only carriers, injected tickets, partial input,
changed providers, connected peers and lost `D/T/U` acknowledgments refuse
success. Every acquired socket retains checked closure. The self-import is a
separate control, closed before observer readiness; it cannot replace the
original socket used by connect and held through `U`. Control close failures
retain the first protocol failure. A second identity check after `T` fences
token drift at connect. The child parks its held socket until independent
observation completes; the observer receives no socket or duplication grant.

Bundle lifetime fixtures execute the actual principal acquisition and completion
bodies across Git into TCP and named-pipe consumers, then check one release per
owned allocation, including the Git-only probe. The bundle's protocol input
loses inheritance before Git; only the separate NUL/diagnostic handles are
inherited by Git. The actual connect/completion/partial send/receive bodies cover
allowed and denied attempts, pending completion, native API refusal and loss of
the final acknowledgment before checked socket closure.
Launcher command and acknowledgment bodies join `O/D/T/U` through one private
input reader, with distinct observer/settlement readiness, token drift, expiry,
owner loss, short packets and failed writes. Session regressions reject early,
unconsumed or replayed frames and retain both synchronous and asynchronous write
failures without redelivery. Persistence remains a prerequisite for release.
Settlement permits the original completion after an unproved observation;
existing receipt, escape and independent-retirement assertions still apply.

Native WFP fixtures resolve the actual filter provider and terminating callout,
including different filter/callout providers, exact key/layer joins, partial
lookup failures and one release per acquired SDK allocation. A lookup finishing
at or beyond the original observation deadline cannot admit the final match.
The actual WFP enumeration/drain and cleanup bodies cover initially empty and
unrelated snapshots followed by final delivery, permanently absent events, the
shared 256-record scan limit, API/lookup/deadline failures and intermediate/final
snapshot, engine and token closure failures. Injected clocks drive delivery
without real sleeps. Snapshot refresh preserves the exact query and existing
five-second bound while the original socket and token remain held.
Receipt consumers join both actual `WSAENOTCONN` and exact requested-peer reads;
missing, mismatched or fabricated peers refuse success. The real operation-loop
fixture carries both peer forms through `O/D/T/U`, completion and independent
retirement, rejecting successful, pending, refused or timed-out connects and
wrong endpoints. Empty or mismatched events, wrong filter/layer/direction/window
and unsupported actions also refuse success. Only native `10013`
completion plus matching attribution and complete independent retirement can
pass. Pending operations and deadlines supply no denial receipt.
The diagnostic reader retains both native block and terminating-callout DROP
actions without confusing a supported action with unobserved cleanup; its
snapshot still supplies no denial authority or provider/callout join.
The actual TCP wait body retains readiness counts and timeout/error facts before
diagnostic collection; exceptional readiness still requires checked `SO_ERROR`,
and inconsistent ready sets refuse a receipt. These fixtures keep the original
remaining transaction budget and verify closure after both native and observer
failures.

The refused-call fixture preserves the saved `10022` through query-only source,
destination, effective-token, QoS and exclusive-option observations. Failed or
short reads remain unavailable; diagnostic errors and separate closure failures
cannot replace the original cause. The bounded self control after an original
self-export refusal cannot authorize import or use of the original socket.
Existing distinct-destination control fixtures retain their separate failure/cleanup
contract, covering one-use carriers, birth/token drift, replay, partial input,
lost acknowledgment and independently attempted source/import closure. Successful
controls never advance original `D/T/U`, observer state or receipts.

The optional prerequisite/control records retain exact public provider bytes
and negotiated Winsock versions within the unchanged 2 KiB TCP budget; malformed,
repeated, oversized or missing observations supply no proof. Actual application
socket copying through `DuplicateHandle` remains excluded. Failed persistence
withholds the next acknowledgment without replay. Creation/import flags remain
zero; outside nonce, closed-port `10061`, full-PoC DROP semantics and independent
retirement remain mandatory. Portable coverage establishes neither native
transfer compatibility nor WFP enforcement and adds no slow-tier assignment.

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
`test/native-darwin-command.test.js` executes the command signal, full token/birth
liveness and shared prerequisite-settlement bodies with injected native APIs.
Positive-signal controls require exact SIGKILL termination and an empty session;
launcher SIGCONT permission checks retain the private provider-release barrier.
Coverage rejects birth/pidversion/credential/session drift and direct API refusals,
including EINVAL, while retaining independent close/wait failures and the original
refusal. Child reaping alone cannot report possible command effects settled.
The existing fault-sanitation fixture also distinguishes earlier null/dead
observations from a later live task-access slot, preserving the authority refusal
and separate getter-reference release failures. These portable tests establish no
native signal delivery or safe inherited-authority correction.
The same fast command suite projects the production `admission.sb` write into an
in-memory file and executes the native cold-launch policy-consumer body with
injected effects. It captures the bytes selected by the broker and requires the
exact `hw.pagesize` and numeric-consumer `hw.pagesize_compat` read grants plus the
complete retained policy, including default denial, bounded fixture writes and
absence of network or broader sysctl grants. Actual-body release tests require
a genuine private pre-exec byte gate, trace acknowledgement, held executable and
policy bindings, then the suspended replacement image and native identity
transition before resume. The injected broker fixture joins each V/G helper to
one target with unchanged birth/session/credentials and changed pidversion;
missing exec despite exit zero, duplicate transitions and substituted identities
refuse admission. Capture continues while arming and across exec observation;
controller or launcher loss, capture refusal, EOF, bad acknowledgement,
interrupted release, expiration or closed admission after the image/policy
recheck, and changed authority cannot resume the target. Unused pipe-end close
failures must stop either launch owner before it advances. Refusal cleanup closes
acquired gates/descriptors and retains session-release failures separately.
Startup trace fixtures in
`test/native-darwin-startup.test.js` exercise bounded numeric page-size and
libpthread stack observations, all six `mmap` inputs and its result separately
from `mprotect`, thread pairing, unknown missing values, malformed bounds and
foreign PID rejection. Cold trace attachment retains explicit process tracking
across exec; its probes gate syscall/argument/numeric rows on actual exec-success,
and its consumer rejects helper observations as target coverage. Missing exec
or exit still refuses complete capture while independent tracer retirement runs.
These regressions compile/run no Darwin binaries and
establish no hosted values, Rust crash causality or installed-build equivalence.
Existing hosted cold version/schema probes, model-free commands, positive
controls and independent cleanup remain required; no slow-tier assignment changes.
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
The existing actual-body protection fixture checks the emitted process descriptor's
Builtin Administrators grant separately from its owner, with the original-user
grant retained for Jobs and both events. Generic and exactly mapped masks pass;
original-user process grants, substituted grantees, foreign object masks and extra
rights refuse admission. Owner, protected-DACL and high NWNR checks remain distinct.
Injected protection conversion, owner/control/ACL queries, security reads, setters
and event creation cover the existing 50/120/1314 unsupported policy and ordinary
Win32 failures. Descriptor and event cleanup remain checked, including a primary
unsupported setter refusal followed by a separate failed descriptor release.
Actual command-case bodies still perform both broker authority attempts before
target I/O. Unexpected duplicate or terminate handles remain invariant failures,
with separately checked handle closure; unexpected failed opens retain their
immediate Win32 cause. Successful inspect/edit/outside controls and event joins
retain their existing coverage. Finite diagnostic tests reject unrelated domains
and malformed values without weakening independent inspection or restoration.
These portable cases run no Windows tool and add no slow-tier requirement.
The same actual command body now checks marker nonce bytes and closes the marker
after read, size or nonce refusal, including a second close failure. No failed
marker may write the finishing nonce. Actual effects reject reversed `N/F`
completion state before the event barrier or child release. Controlled native
barriers retain output pumping and held-process checks through delayed delivery,
completed I/O with no events, target-only or mismatched-marker events, early
child exit and the existing `D` stop or owner loss. Queued ordinary protocol
input stays unconsumed during the barrier. The exact original Security
query, service notification/reset flow and 10-second bound remain exercised.
The actual child-exit collector drains both pipes to EOF before publishing the
real exit; reader fixtures retain fragmented child diagnostics and output after
an earlier broker refusal, with separate cleanup uncertainty. Event delivery
alone leaves process completion unset. Release rejects missing, repeated or
conflicting exit frames. Existing restoration-failure and separate
terminal-witness tests remain required; these fixtures supply no native events.
The actual SACL builder places the owned explicit audit ACE before baseline
labels and inherited entries. Controlled native ACL calls protect the exact
read/write success/failure mask, byte-preserving baseline copies and partial
insertion/read/copy refusal; baseline restoration remains unchanged.
Bounded native transcripts distinguish verified setup from real command delivery.
System-success-disabled cases still require both effective per-user outcomes and
all original token/object/SACL joins. Setup admits only schema/version probes,
suspended-server admission and the real permitted outside control. The native and
JavaScript guards reject release or forwarding before that control has fresh
4663 target evidence, its later audited marker, independent process/token/image
joins, held-file observations and successful target restoration.
The actual setup owner checks stale baselines before setters and all cleanup,
restoration and watcher acknowledgements before installation. Controlled failures
preserve the original setup cause separately from settlement uncertainty. Native
subscription/projection and decoder fixtures retain case-variant names and reject
wrong subjects/objects/logons, stale or historical records, missing target/marker
evidence, loss and failed controls. Every restricted command keeps its own
4656 denial or 4663 permitted I/O, completed-I/O marker and sentinel checks.

The actual query producer is checked as an Event-node selection with one outer
predicate, retaining both loss IDs, failed 4656, successful 4663, exact
provider/SID/type filters and both bounded interval branches. A rejected
root-level Boolean example protects the producer/consumer result contract
without pretending to emulate Event Log.
Actual-body command readback uses the operating thread token and the original
held target/marker, with policy-query errors, missing outcomes, identity/SACL
mismatch and checked token release. The actual effects sequence withholds T or U
on failed before/after joins to installed SACL bytes; broker setup success cannot
supply this different token observation. Existing decoded missing-target/marker,
wrong-principal/logon/PID/mask, loss, window and cleanup regressions remain the
delivery and retirement proof. Zero records still fail. Portable coverage proves
no native delivery or hosted failure causality and adds no slow-tier assignment.

The actual future-only subscription startup creates a nonsignaled manual-reset
event and waits for service readiness. The capture fixture distinguishes idle,
notified, enumerating and exhausted subscription states; a forced initial signal
does not authorize enumeration in that model. An arrival between subscription
creation and the first pump follows decoder initialization. Idle startup performs
no enumeration and still cannot acknowledge a marker. Failed event, bookmark or
subscription creation and failed readiness output retain partial ownership and
separate cleanup errors. A failed notified enumeration preserves its original
error, including unexpected 4317, and separately failed subscription closure.
Actual native target/marker predicates
cover inspection, permitted and denied edits, denied outside access and the
permitted outside control, joining the operating logon, subject, mask, release
window and live held birth.
Wrong outcomes, missing fields, expired/replaced processes, failed native waits
and earlier/equal marker records cannot release a command. The effects fixture
requires B before U. All six action/profile combinations carry the exact expected
outcome through private selection, and U requires both delivered observations;
partial-policy installation and independent restoration coverage remain unchanged.

Terminal regressions require a separate broker 4663 gate read after complete domain
retirement, bound to D's native domain-empty FILETIME and the last command window.
The last child marker, absent/stale events and an unclosed decoder cannot replace
it. Actual-source UTC parsing and native projection reject queued older broker
records, equal timestamps and malformed dates while retaining supported fractional
precision. The actual failed broker reader keeps terminal capture through cleanup;
independent domain/watcher retirement, exact restoration/readback, fixture removal
and separate cleanup failures remain covered. The retained gate-read fixtures
execute installed SACL/ACE/thread-token query and failure output bodies, including
short reads, unsupported layouts, truncation, original-error preservation and
independent token/handle closure. Only obsolete P/M-specific delivery/query tests
are removed. These portable cases introduce no validation command, slow-tier
assignment, provider service, system-policy change or native acceptance claim.
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
Actual command-child bodies exercise API-specific errors, named nonce/count/content,
denial and acknowledgement guards, successful inspection/edit/denial controls and
partial closure without replacing the first refusal. Controlled original-reader
transcripts cover fragmented child stderr, malformed framing/carriers, bounds,
premature stream closure, validated child/broker arrival precedence and separate
cleanup causes. They preserve `permitted-control` through later phases and both
proved and uncertain retirement within the unchanged deadlines. These portable
cases neither identify the original control refusal nor supply native acceptance;
they add no slow-tier assignment.
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
The existing capture/control fixtures execute the actual 10-second barrier with
a controlled clock: empty delivery and delivered but unselected target rows
refuse as `command-marker-barrier`, while the genuine target/marker pair retains
its barrier reply. Original failure output includes the installed query/channel/
flags, immediate wait/enumeration outcomes and expected PID/action/held IDs and
marker state. Diagnostic writes preserve the original API error; optional raw
metadata cannot supply a cause or proof or change the 4-KiB carrier bound.
Source-executed gate/retirement regressions protect immediate error capture,
independent closure and impersonation reversal within the existing deadlines.
Controlled capture APIs execute the actual notification, enumeration, rendering,
bookmark and closure flow with XML projection isolated. They cover ordered
multiple batches, checked reset before each query and renewed service readiness
after exhaustion. Controlled arrivals before and after reset, during draining,
at exhaustion and after the readiness recheck retain delivery without querying
an exhausted subscription. Rechecks use zero-time waits within the original
pump budget. Fatal wait, first or later notified enumeration (including 4317),
render, bookmark, first or later reset and close failures retain immediate first
causes and independently retire partial batch/subscription/bookmark/notification
resources, including inactive preflight.
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
The Windows custody suite executes the account readback and both native guard
bodies with injected NetAPI calls for ordinary and reviewed builds. Ordinary
metadata-label variation succeeds silently; reviewed privilege mismatch, API
failure, a missing success buffer, wrong flags and failed buffer release still
refuse admission. Mixed label/release failures preserve the correct first
refusal alongside cleanup status, and keep diagnostic write failures independent.
Failed queries never expose unsampled fields; only the two numeric fields are read
before each returned buffer's single release. Valid admission remains silent.
Account-only native guard fixtures reject wrong SIDs, nonempty groups and missing,
duplicate or unexpected rights without a child/token API. Effective-policy
regressions separately reject wrong token principals, enabled groups, remaining
privileges, missing restricting SIDs, elevated integrity and malformed token data;
existing actual-access and interrupted-cleanup refusals remain in force.
Existing interrupted-provisioning coverage retains possible account effects until
independent original-domain cleanup is proved. These cases infer no native account
value or flag repair and never log credentials or whole account structures.
These portable cases invoke no Windows process or compiler and leave the required
check inventory and slow-tier assignments unchanged.
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

The existing Windows custody fixture executes the complete cold census/acquisition
owner with injected native calls. It covers present exited originals, allowed and
watchdog/out-of-range exits, live originals, disappearance during acquisition,
newer replacement births, changed/older births, inaccessible handles and incomplete
or duplicate inventories. Every failed predicate retains its immediate native
error; separately failed closes cannot replace it. The actual bounded diagnostic
producer passes through fragmented authenticated transport and remains failure
evidence only. Repeated original Job/task checks and normal/recovery refusal
matrices remain required. The preparation fixture holds actual bridge exit after
its retirement frame and requires closure before publication. A controlled clock
exhausts the original deadline during that wait and retains the first refusal
without replaying finish; cancellation and dependent-reader ordering remain
unchanged. These portable cases add no native execution or slow-tier assignment,
and cleanup cannot attest the 23 unrun system
cases. Both original hosted workflows must still prove native acceptance on the
same final SHA.

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
The actual ancestry body also distinguishes original `lstat` failure, unavailable
API errno and sampled metadata refusal, retaining both input and parent paths.
Injected diagnostic writes cannot replace the primary error; the installed-input
classifier and held-image/root checks remain unchanged.
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
closure. A source-driven custody fixture executes the actual build-directory
producer, read-only root join, complete-plan admission and open/read/stability
guards with injected filesystem calls. Its private user-owned report parent
reproduces the generic ancestry refusal before the bound join succeeds. Root/file
replacement, birth changes, ACLs, wrong pins/bindings and unrelated ancestry still
refuse, and consuming reads cannot chown or reseal the root.

That same fixture executes the actual ordinary case-parent predicate and ancestry,
admission, open/read and held-file stability bodies against the observed root-owned
GID 1 mode-0775 run directory. It admits only fixed, canonical case roots with a
64-character lowercase hexadecimal context, and rejects writable arbitrary
parents, unsafe generated descendants, malformed/near-miss roots and host-parent
owner/kind/mode changes. Reviewed reads retain refusal, while canonical aliases,
no-follow symlinks and post-open substitution remain unsuccessful. The original
build/root birth, ACL, pin and binding matrices remain intact. These portable
observations establish no native admission or retirement result.

The same small filesystem projection follows the actual experiment lease
publication and case declaration into native plan admission, descriptor-relative
open, stability and PF reservation guards. For the lease path, a successful
`lstat` of the observed root-owned gid-1 mode-0775 run directory still refuses
through generic ancestry;
only the exact experiment lease joins its strict producer-created private base.
The producer models Darwin directory-GID inheritance and normalizes only after
exclusive creation. Read-only consumers retain root:wheel ownership, exact
modes/bytes/pin, no-follow canonical paths and ACL refusal without resealing.
Parent/base/lease replacement refuses after admission, open and reservation;
birth, kind, content, ownership/mode/link, ACL, symlink, lock and near-miss-path
substitutions retain exclusion. Reviewed and non-case reads cannot acquire the
experiment exception. Source-derived normal and interrupted reservation paths
retain fresh absence and PF-restoration checks before closure; the existing
independent settlement matrices remain their separate owner. No Darwin binary
is compiled or executed by this fixture.
The existing raw-IPC preparation fixture also retains the declared root across
pinned generated-source reads and private case copies, alongside original-failure and independent
retirement coverage. These portable regressions run no Darwin binary and add no
validation command or durable slow-tier requirement. Its focused invocation is
`node ci/native/darwin/custody.test.js`; it performs no elevation, native build,
installation or system/provider probe. Darwin SDK compilation and actual native
custody remain dedicated external CI evidence.

The existing native file-body fixture in `ci/native/darwin/files.test.js` also
executes the actual held-tree traversal and stat-comparison bodies. Its injected
directory descriptions model shared `dup` offsets and independent `openat`
offsets. It reproduces three files followed by an empty traversal before the
repair, then protects repeated complete snapshots, a retained nonzero cursor,
fresh-root identity refusal, changes during traversal, read errors and checked
closure. File-barrier observations are injected at their existing boundary;
the fixture supplies no native filesystem or independent recovery proof.
The selected native harness retains this coverage without a new command or
slow-tier assignment; matching macOS verification remains required.

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
The raw-IPC preparation fixture gives each reader a distinct process identity
and enforces its native self-retain refusal. Through the actual launch guard,
custody reader and bound admission verifier, it reproduces the original
case-reader self-retain failure and proves independent primary-helper observation
while payload and other-helper slots remain with the case reader. Duplicate full
identities consume one slot per owner; each inspection still reads fresh process
and current-token evidence. Reused births, changed session/SID, substituted slots
and a failed fresh read refuse after an earlier success. The custody suite also
rejects wrong candidate/context, plan, admission and verifier bindings before
native reads. Original admission failure and separate independent-observer
retirement failure coverage remain intact. These portable regressions execute no
Windows binary and add no validation command or slow-tier requirement.
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
Ordinary experiment cold recovery distinguishes the ordered normal finish chain
from the bound pre-setup abort/helper-retirement chain. Injected records reject
missing, duplicated or reordered acknowledgements, mixed setup/abort lifecycles,
substituted helper/bridge births, task hashes, instances and verifiers. Fresh
process/Job censuses and task removal remain required after either chain; error
87 and a failed live retention call cannot authorize a different recovery lane.
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

The same custody suite executes the loaded-module name producer, identity-bound
canonicalization and exact file guard with injected native reads. Synthetic
load-time spelling differences pass only through held identity, original
no-reparse ancestors and the retained NT mapped-image join. Query/bounds/prefix,
exact-path, file-ID/replacement, reparse, mapping, noninheritance and close failures
refuse admission, including fresh failures after an earlier successful read.
The existing open-refusal fixture carries each final-path predicate through the
bounded authenticated channel and preserves immediate API errors separately
from invariant refusals with last-error zero. Existing release/verifier fixtures
retain independent slots, fresh runtime reads and negative path/identity joins.
These portable regressions add no slow-tier assignment and establish no native
compilation, observed path alias or cause of the archived compound refusal.

Windows `effective.test.js` and `audit.test.js` inject held native reads and
protected control transport. They cover approved binding joins, actual ACL/MIC
and complete WFP graph comparisons, mandatory independent coverage, late substitutions,
bounded Security XML/version/bookmark decoding, acknowledged intervals,
process/token/Job/object attribution, temporary live-verifier checks, retired
policy/filter-absence snapshots and retirement-gated owned audit restoration.
Interrupted audit setup retains its first cause and permits recovery only after
independent payload retirement, observer drain and retirement, and fresh reads
of unchanged baseline or exactly owned per-user policy and SACL changes.
The effective suite also executes the actual native security-reader/writer and
custody failure bodies with injected APIs and live handle grants. It proves that
a complete query on a sufficiently granted original succeeds without reopening
even when a fresh reopen would fail. Only file-query `ERROR_ACCESS_DENIED` permits
the strict fallback; partial descriptors must be released first, and failed
cleanup or unexpected direct-query errors stop without reopening. It retains
identity-query reopen rights, compatible read/write/delete sharing with a live
DELETE-granted open on the same object, unchanged observer desired access without
DELETE, and temporary-only closure while source and control handles remain live.
Injected reopening refuses incompatible sharing, so reverting either temporary
sharing mask makes the existing success regression fail. This models sharing
compatibility without changing original protective handles, the setter or
control-handle access and sharing.
Existing cases retain complete security selectors, borrowed registry handles,
separate native/status and invariant refusals, volume/file-ID substitution,
descriptor bounds and partial handle/descriptor release. Close, free and
diagnostic failures cannot replace the
original error; no failed close or partial-descriptor free is retried. These
fixtures run no Windows API or compiler and add no slow-tier requirement. The
direct query is a supported equivalent operation, not an explanation of the
kernel condition behind the observed Windows system `ReOpenFile` error5. The
injected sharing refusal neither identifies the historical compound error5 cause
nor establishes an observed native error32. Portable success confers no Windows
acceptance. Fresh original Windows CI remains necessary.
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
PF acquisition coverage sends the real installed-input producer's two reads
through the custody command journal and into build cold loading. It preserves
separate native command and contiguous journal sequences, rejects malformed
request shapes, sequence bounds, unrelated PF phases and reviewed build use,
and exercises a lost second reply. Fresh recovery independently checks original
processes and domains without repeating acquisition or inventing completed
preparation. Existing substitution and unavailable/live-retirement cases retain
their separate guarantees. These injected regressions add no native execution
or durable slow-tier requirement.
The complete aggregate fixture retains all 109 uploads and 78 hosted command
observations, neutral CI-shaped paths and compiler diagnostics. Its serialization
exceeds one MiB and must pass the actual aggregate writer, normal loader and
interrupted cold recovery without losing inventory or rebuilding. Exact-boundary
and one-byte-overflow cases exercise the production writer and held reader:
only `darwin-experiment-preparation.json` admits four MiB; close, selector and
similarly prefixed receipts remain limited to one MiB. Held metadata, substitution
and growth failures still close their descriptors. Source-driven native receipt
guards exercise the same limits and preserve declared-input admission, private
ownership/mode/link checks and the separate provider-receipt lane. These portable
regressions also pad otherwise unchanged JSON with whitespace to prove normal
loading and recovery reject overflow at the size predicate, rather than at JSON
parsing or binding comparison. They add no native acceptance or durable slow-tier
requirement.
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
Queued native replies cross an event-loop turn in the raw pipe fixture, matching
native IPC delivery and allowing retired abort-signal compositions and their
retained command transcripts to be collected during the complete file run.
The same suite covers ownership refusal before setup/policy/payload admission,
lost launch and policy replies, and recovery through the retained original reader
observer until policy/account/task settlement precedes that observer's retirement.
The failure fixture refuses first-time acquisition of an exited primary token;
only the original transferred process/token pairs can be imported after a lost
reply. It requires unchanged pre-policy baselines, restoration before account
deletion, exact retained births and
preservation of the first launcher failure. Substituted births and failed
restoration retain reservations. Existing complete ownership cases continue to
cover cancellation, owner/helper loss, final handle close and literal/storage
behavior. `ci/native/win32/launch.test.js` executes the actual shared Job query
body with independent query failures, creation errors retained across descriptor
release, and nonzero assignment history despite empty membership.
`ci/native/win32/custody.test.js` executes the actual acquired-creator failure fence,
process/token transfer before birth publication, observer/birth/token-bound import
and untouched versus installed policy restoration branch,
scopes shared prelaunch witness claims to
captured ownership baselines, and retains original stderr transport coverage and
Job identity through an unlaunched fence. These portable regressions remain in
the existing native harness, add no check or slow tier, and establish no Windows
API, native cleanup or hosted PASS.
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
The binding regression carries an actual raw Windows builder template through
`createWindowsExperimentSystemEffects` and the shared experiment controller.
It checks the independently produced canonical template digest and policy receipt,
then deliberately refuses before native case assertions and verifies real independent
settlement. It neither echoes the consumer's digest nor supplies native PASS.
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
Each injected observer retains its original helper at task registration, before
independent recovery can remove the task. The fixture invokes every pending close
callback twice after complete retirement, preserving observed exit codes and
requiring no timer delay or surviving task lookup.
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
The preparation fixture also fails ordinary case preparation before it returns,
both before setup and after account acquisition. Settlement must reach the exact
retained recipe/execution owner, reject substituted completed objects, and acquire
independent original-process custody before exit. It preserves all thirteen
successful helper builds and separately injects case-observer retirement failure:
closed reader custody cannot erase the original preparation cause or prove the
observer retired. These cases use the existing portable suites and introduce no
additional validation command or native acceptance claim.

The Windows launch fixture executes the actual native trust decision for both
experiment and reviewed builds, including unsigned held bytes, malformed
certificate-directory state, digest refusal, verification failure and independently
failed trust closure. The native producer body carries the real literal request
and existing finite mode vectors without executing Windows tools. Existing raw
ownership fixtures require helper/P/setup/policy-C/ready/R ordering, reject a
changed setup account or premature payload, and rejoin the original custodian
birth during reconstruction. All literal/storage, cancellation, owner/helper-loss,
creation-time Job and non-emergency retirement cases remain active.
The actual native error-drain body preserves bounded original launcher bytes
through fragmented failure frames and later EOF; partial reads, failed inspection,
overflow, idle and post-release paths cannot become delivery evidence. Custody
recovery covers a lost final append after a complete finish acknowledgement,
retaining fresh census/Job/task requirements and refusing live originals, missing
finish proof and raw error 87. Combined original-owner, proof and observer cleanup
failures retain the first cause and separate uncertainty. These portable suites
add no slow-tier assignment; both fresh original hosted workflows on the final
candidate, all three platforms, all 69 records and exact provenance remain the
supervisor's external acceptance requirement.
The same custody fixture proves that a rejected reader command does not replace
the bridge's actual exit event. The existing raw preparation fixture loses the
setup acknowledgement and a provisioning read separately, requires the failed
reader's cleanup/retirement commands to remain unused, and rejoins its protected
intent and held original process/token custody through independent recovery.
Account/Job/task proof and preparation-file retirement remain separate, including
observer-close failure. Missing authority for two acquired owners retains both
causes without suppressing an independently recoverable case. Existing transferred
creator-handle, PID-reuse, missing receipt, policy/SACL and outside-sentinel
refusals remain active. Closed-owner fixtures also cover an observer that already
holds matching originals and reject unrelated retained subjects. These cases use
the existing explicit native harness, add no check or version, and prove no
Windows API behavior or native acceptance.
The existing raw experiment preparation fixture also reaches the actual
`experiment-runtime.js` consumer through the normal system factory and independent
admission verifier. Repeated observations retain the same owner slots while
reading changed native module metadata and a newly loaded hosted System32 module.
The case reader never retains itself or consumes the verifier's slots, and the
successful case independently retires the original readers, tasks and accounts.
After an initial success, raw frames substitute helper PID/birth/session/SID,
verifier identity, owner process/file slots, image pins and module path/identity/
hash/signature/DACL/link evidence; missing or undeclared private modules, wrong
import scope and failed fresh process/runtime reads also refuse. The existing
custody binding regression now obtains a successful helper observation before
substituting candidate/context, plan, admission, helper or verifier bindings.
That shared admission guard precedes both token-only and runtime observations.
The operation fixture uses the actual marked experiment-image parser for unsigned
helper signature observations while retaining reviewed signature parsing.
Existing private-import, reviewed release, launch, payload and helper ownership
coverage remains active. These regressions use the existing selected native
harness, add no validation command or slow tier, and execute no Windows binary.
Matching Windows CI must establish real image/module reads and original-owner
retirement; portable success supplies no native acceptance or complete PoC claim.

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

Darwin's existing custody and preparation-effects fixtures carry the native
case producer's directory frames through normal completion and fresh recovery.
The actual-body native guard distinguishes the prepared UID/GID mode-0700
workspace from the root-owned mode-0555 build root without metadata repair.
Independent probes reject missing, duplicate, swapped, aliased or changed
descriptors and device/inode/metadata substitutions. Recovery must rejoin the
original sealed role bindings even when fresh owner and probe observations
agree with a replacement. A live original reader still retains custody despite
an empty reserved-UID census. Existing cancellation, owner-loss, policy
restoration and independent retirement cases remain required. This coverage
uses the existing fast/native harness assignments and establishes no native
acceptance.

The same Darwin preparation fixture interrupts the actual custody producer both
before `probe-created` and after creation but before completion. Fresh recovery
keeps a missing birth refused, while an acquired subset with recorded identities
retains independent observation of each original owner. Altered phase/PID joins
publish precise bounded `probeJoin` diagnostics through the original exception
owner, preserving the separate acquisition cause and original ledger bytes.
Recovery performs no setup or compilation, and diagnostics expose no full
requests. This portable coverage adds no command or slow-tier assignment and
does not attribute or repair the hosted recovery failure by itself.

Experiment case recovery regressions reuse the original protected ledger and
closed-custody observations. They cover acknowledged disappeared readers and
children, mixed closed observers and live custody, damaged births/task bindings,
missing acknowledgements, surviving Jobs, incomplete censuses, error 87 and
account, rights, policy, audit and reader closure requirements. Production
preparation and case owners complete a literal fixture before fresh recovery,
then prove no rebuild, payload replay or final-image opening. Cancellation and separate proof
and observer-retirement failures preserve exclusion and the primary cause.
Existing build/cold-load and reviewed recovery coverage remains required; these
injections add no check, tier, native invocation or native acceptance claim.
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
Its existing Windows actual-body baseline fixture executes the original baseline
and `file_sd`/security-failure bodies together. It requires saved held identity
before a complete owner/group/DACL/label/SACL read, direct success when reopening
would fail, strict denied-query fallback and refusal of unexpected query errors
or substituted fallback identities. Borrowed originals remain open; primary
errors survive independent temporary-handle and descriptor cleanup failures
without retrying failed cleanup. Existing finite diagnostic-frame and
compiler-trust attribution coverage remains required. The fixture supplies no
Windows SDK/runtime evidence or kernel explanation for the observed error5.
The ordinary fast fixtures in `test/native-feasibility.test.js` cover 32/64-bit
WFP keyword values and exact DROP rejection predicates. Those in
`test/native-windows-command.test.js`
preserve successful operating-token/policy/SACL observations
and exercise bounded post-refusal query selection, empty/error/saturated batches,
typed and textual PID/logon/time projection, case-insensitive held-name joins,
foreign/stale event exclusion and independent event/query/context closure.
Inspection never drains the live subscription or supplies native acceptance.
Existing notification/drain ordering, missing-event
and uncertain-retirement refusals remain required. These tiny injected cases add
no validation tier and execute no Windows tool on a foreign host.
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
