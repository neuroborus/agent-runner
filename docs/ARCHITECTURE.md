# Architecture

Agent Runner is an npm-workspaces monorepo with one root CLI/runtime, one shared
commit-plan contract, and independently owned pipeline workspaces.

## Dependency Direction

```text
root CLI/runtime ──static registry──▶ pipeline workspaces
                                           ┊
                                           └┄ when consumed ┄▶ @agent-runner/commit-plan
```

The root runner imports registered pipelines. Pipelines do not import the root
application; the runner supplies state, event, agent, and Git services through a
runtime context. Plan authoring and execution consume
`@agent-runner/commit-plan`; polishing has no shared-package dependency, and
pipelines never depend on each other. Do not declare an internal runtime
dependency before an actual import needs it.

The CI-private native proof owner lives under `ci/native/`, outside runtime
and workspace dependencies. Its intentional `index.js` exposes pure evidence
normalization, fixed contract catalogs, deterministic aggregation, and bounded
report rendering. It has no import-time effects or production consumers.
Its separate `ci/native/feasibility/` index exposes a fixed, version-1 minimal
experiment report and portable dispatch/assessment contracts. Expected revision
and platform remain separate from observed checkout, OS/build and architecture.
Capability records retain tool/helper identity/digests, bounded first causes,
elapsed time, independent observations and separate cleanup failures. Success
requires ready positive controls, acknowledged matching attempts, unchanged
outside sentinels and independently witnessed non-emergency cleanup. Missing
records fail closed; unavailable owners explicitly remain BLOCKED. Protected
absence is expected only in credential-free experiment checks, while actual
failures always fail that check. Model-free command and protected tool evidence
have separate capability IDs. This contract neither changes full acceptance
nor closes retained source findings.
The explicit `feasibility/run.js` entry confines native dispatch to matching
x64 GitHub-hosted CI before observing Git/OS metadata and fences native effects
on the exact observed revision. The Linux index selects three existing ownership
cases and two access bundles under Ubuntu 24.04 CI, with the existing controller
and fresh receipt-bound retirement verifier. The separate Linux observer joins
held sentinel identities, independent Git snapshots, acknowledged outside-control
denials and non-emergency cleanup. Its observed static-helper build reuses the
owned compiler controller without supplying full release-review authority.
Substituted storage survives refused cleanup before sole-parent restoration;
the outside sentinel remains outside cleanup ownership. Artifact intent and
evidence remain in exclusive CI storage, and unsettled ownership prevents further
admission. The Darwin index adds a separate bounded helper/driver using observed
native Clang/SDK inputs and deny-default Seatbelt launches. The helper uses
a private optional sandbox-check binding with a source-supported variadic
C-int ABI and a separately resolved const data export. Missing exports block
before prerequisite effects; the loaded flag value is never guessed. Existing
public sandbox linking, signed x64 inspection and live-identity-bound policy
checks remain required. Build evidence retains both helper and binding-header
digests; observed export presence supplies no SDK/runtime or policy acceptance.
Fixed access bundles join ready TCP/Unix controls and independent held
file/volume/permission reads;
identity-matched allocation cleanup preserves acknowledged substitutions. Fresh
audit-token observations and safe signalling precede detached fault release.
Individual fixture cleanup never establishes a complete descendant domain:
survival fails, and unsupported domain recovery remains BLOCKED. No saved
preparation factory or full acceptance owner is completed by this experiment.
The Windows index adds an isolated current-identity AppContainer/Job experiment,
without completing privileged preparation factories. Its private synthetic-Git
owner validates local executable/exec paths, retains strict x64 PE/import checks
with case-insensitive DLL extensions, and bounds private dependency copying.
Copied bytes bind the manifest and copied-runtime version/repository commands;
finite operation-specific causes retain observed tool/helper identities without
inferring a deadline from a killed flag. This supplies neither release closure nor
native acceptance. Owned nonce/SID receipts
precede profile use and bind rollback/deletion. Creation-time Job and handle
attributes precede suspended admission by a fresh native verifier. Fixed access
bundles join exact fixture grants, ready TCP/named-pipe controls and independent
file IDs/DACLs/bytes; sole-parent storage cleanup preserves substitutions.
Cancellation verifies the exact Job; owner-loss recovery explicitly depends on
a surviving holder and a fresh receipt/handle join. Final-handle retirement uses
only held process observations, with no surviving Job handle. Missing prerequisites
remain BLOCKED and unsettled cleanup cannot pass. Existing Windows source findings,
full acceptance and provider factories retain their requirements. The provider
experiment prepares only fixed runtime bytes after archive integrity and full
data-only preflight; it supplies no release-review bindings. Its separate buffered
Codex command client validates the installed generated schema and has no model,
thread or filesystem RPC surface. Linux stock sandbox controls join actual fixed
executions, syscall observations, held sentinels and fresh namespace retirement.
Darwin adds a private finite command controller and native effects owner around
the existing signed helper, cloned audit pipe, compatible BSM decoder and native
identity/file observations. A root prerequisite control precedes Codex effects;
held fresh audit sessions and denied session-escape controls precede suspended
native admission and release. Version/schema probes use a separate home so the
app-server home remains empty at admission. A
permitted outside write under the enclosing policy distinguishes stock Codex
denials from outer policy denials. Both explicit access policies join fixed
nonce-backed commands to acknowledged capture windows, live image/policy and held
sentinels, including an audited held gate acknowledging completed I/O before the
final file snapshot. Separate 120-second observation and 30-second settlement bounds cover
partial failures. Closed admission, fresh independent all-UID session inventories
while rights remain held, native observer retirement and identity-bound fixture
cleanup are required; PID/group exit alone cannot pass. Missing privileges or
interfaces remain BLOCKED before effects, and emergency or uncertain settlement
prevents further provider admission. This supplies no full observer approvals or
arbitrary Darwin domain recovery; native behavior remains externally unverified.
Windows adds a separate finite command controller and effects owner, using the
shared installed-schema client with the release-supported default buffered cap
and independent client bounds. A fresh empty home, filtered environment and
explicit unelevated native sandbox selection precede six fixed commands under
both network-denying policies. A suspended, filtered medium-integrity app-server
enters an unnamed Job through creation-time attributes; independent native reads
join its image, process/token identities and Job membership before release.
An outside-write control verifies that admission permits the operation and
that the high-integrity observer cannot be acquired by the command. Held file
IDs/DACLs and native Security success/failure records join acknowledged command
windows and an audited completed-I/O gate whose protected DACL remains unchanged
by inherited workspace grants. The bounded native publisher mapping
and reused XmlLite/record decoder supply observations, never review approvals.
Per-user audit inclusion and owned fixture SACL changes preserve system policy.
After owned per-user inclusion, independent native reads bind
AuditComputeEffectivePolicyByToken to the held administrative broker's actual
primary token, principal/logon and creation identity. A matching delivered Security
4663 gate-read success in a fresh bounded capture window must precede every Codex
launch, including version/schema probes. System bits remain preservation evidence;
unavailable coverage blocks with zero Codex effects. Inclusion can add auditing;
the Administrators exception applies to exclusion, as documented by the
[primary Microsoft references](../ci/native/README.md#separate-minimal-feasibility-experiment).
The release's attempted NUL descriptor updates require an independently observed
denial of that mutation and an unchanged held descriptor. Missing privileges,
coverage or custody block before Codex effects. Observation and independent
settlement retain separate 120-second and 30-second bounds. Held Job/process
watchers and an independent finish owner acquire original custody before audit
setters. They prove complete empty custody and observer retirement before restoring
verified unchanged owned changes, including partial installation. Refused admission
needs no missing success witness; admitted capture/terminal requirements remain.
Safe restoration is attempted even after capture failure, with first cause and
settlement uncertainty retained separately. Capture loss, escape, emergency or
unsettled retirement cannot pass. The full Windows observer's LocalSystem, review and protected custody
requirements remain unchanged; native behavior still requires external CI.
A separate protected entry
uses sibling invocation builders, existing stream clients and relay custody,
requiring independent native admission and explicit same-SHA model/cost authority
before model input. It joins real tool events and relay receipts to native and
filesystem observations under both access bundles. Claude's validated optional
four-tool subset leaves its seven-tool full-acceptance default intact. Unused
integrations and effective routes must be independently inspected. Incompatible
AppContainer loopback transport remains BLOCKED; no saved provider factory or
production readiness contract is completed. The fixed
`payload.cjs` protocol requires an owned nonce fixture and acknowledged release;
payload receipts supply no independent proof. Injected portable coverage and
CI marker checks authenticate neither native outcomes nor worker provenance.
Production CLI/MCP, provider registration and Linux runtime behavior retain
their existing owners and contracts.
The isolated `native-feasibility.yml` matrix runs credential-free native and
model-free observations on matching ephemeral x64 workers. Its separate manual
`native-feasibility-acceptance.yml` action binds dispatch/workflow/checkout to one
reviewed SHA and uses per-platform protected environments. The indexed pure
environment approval guard is shared with full acceptance without changing its
reviewer/self-review requirements. `feasibility/ci.js` owns confined, atomically
replaced redacted reports and run-bound intent; probe publishes unsettled effects
before executing the existing owners. Always-run cleanup audits their independent
settlement and preserves uncertainty after interruption instead of guessing safe
deletion. Reporting rechecks current checkout and worker metadata and rejects
missing or malformed evidence. Only redacted reports/summaries are uploaded.
Explicit preparation/probe IDs supply bounded operation/status captures and step
conclusions, joined to the existing candidate/platform/run/attempt intent.
Preparation replaces only untouched initialization placeholders; existing probe
and independent cleanup causes survive derivative step failures. Shared diagnosis
formatting retains observed process facts, leaves unavailable facts unknown and
never infers a deadline from `killed`. Bounded native output yields only recognized
explanations or narrowly sanitized compiler diagnostics. The unchanged report
shape carries `output=absent|unrecognized|recognized` and only allowlisted native
error classes within bounded failure details; the diagnostic sanitizer still
returns a string or null. Linux fixture preparation retains pre-probe resolver
errors as ordinary or nested launcher-construction failures with unknown process
outcomes, independently of actual namespace exit/signal/deadline evidence.
Source-backed Bubblewrap explanations distinguish namespace creation/joining,
UID/GID maps, mount propagation, tmpfs, bind/remount, procfs, devpts/device,
executable launch and argument rejection. Only finite errno suffix classes and
fixed explanations survive bounded capture from either stream; paths and native
policy advice do not. The CI diagnostic probe uses a fixed PATH and C locale,
leaving public launch vectors and their deadline intact. Observed exit-1 argument
rejection or non-namespace EINVAL/ENOTDIR/ENOEXEC setup remains FAIL rather than
an unavailable prerequisite. Namespace creation EINVAL remains distinct from an
argument defect. Other refused prerequisites remain BLOCKED with the requirement
for a compatible isolated worker. Successful probes carry no failure diagnosis
into later protection failures. Preparation, controller IPC and model-free
command wrappers preserve the first cause independently of cleanup;
historical discarded output supplies no kernel or AppArmor diagnosis.
Escaped summaries retain
the validated run binding and render first and cleanup causes separately.
Windows preparation delegates to one experiment-owned installed-toolchain selector;
its private batch wrapper retains setup status, exports only SDK/compiler variables
and reports temporary-file cleanup separately from native settlement.
Darwin preparation checks installed SDK/compiler discovery and noninteractive
observer authority with bounded, operation-specific captures. It supplies no
audit/custody admission and mutates no system policy. Both minimal workflows
join those outcomes to exact candidate/run/attempt intent. Windows keeps the
installed MSVC/SDK selection; its observer requires native privileges and
established effective broker audit coverage without changing system auditing.
Summaries retain all native, model-free and five protected requirements, component identities and independent
cleanup witnesses; a derivative cleanup-step failure invents no native violation.
The historical full aggregate independently lacked the three system input/review
variables and Linux's reviewed manifest digest: admission never started, 0/69
system and 0/18 provider records were accepted, and four source findings remain
open. The native owner documents the exact missing inputs and unverified native
outcomes; minimal evidence supplies none of those approvals.
Environment-owned model/cost bounds and approval precede the conditional secret
step. Default protected native custody remains unavailable, so readiness blocks
without model use; operator variables cannot attest private transport or unlock
missing factories. These workflows require no external input-release service and
do not change full acceptance, production behavior or local finalization commands.
Its offline public-input verifier consumes immutable prepared byte snapshots
against a separately reviewed frozen provenance catalog. Exact public URLs,
revisions, archive/member/binary digests, licensing, build/ABI/setup assumptions
and missing material remain structured. Standard-library hashing performs no
retrieval, extraction, installation or candidate execution. Prior archive
verification is retained separately; matching members and pinned source cannot
close release bindings or authorize native admission. `renderPublicInputReport`
joins this evidence through the existing pure report owner with no native proof
records; its findings remain BLOCKED and missing bundles remain independent.
The same public-input/evidence owners expose bounded version-1 reviewed system
manifests and independent observations for all declared x64 CI images.
Publication, source, build, dependencies, licensing, ABI, privileges and policy
references remain separate expected pins; observations cannot fill null pins.
Required component roots admit only complete acyclic reachable dependency
closures, and mandatory interface inventories include independently bound SDK
contracts and actual availability. Exact candidate, OS/SDK, inventory and all
binding comparisons produce MISSING, MISMATCH or MATCHED consistency, never
native admission or source closure. Matching records remain BLOCKED, all four
source findings stay open, and historical public-input/Linux release contracts
retain their semantics. A pinned XNU source/distribution reference maps to macOS
15.6 without identifying the described 15.7.9 binary or a future job's ABI.
The native owner documents the one-MiB/128-component manifest limits and exact
Windows SDK/WDK and Linux tracing/toolchain prerequisites. These contracts have
no filesystem, network, build or process effects and no production consumer.
Separate CI-private package catalogs pin the selected Codex 0.160.0 and Claude
2.1.285 native publications without changing installed backend selection or
historical public inputs. Candidate-bound complete member reviews and independent
approval digests precede explicit external acquisition. `package-inputs.js`
owns bounded review/integrity contracts; `package-archive.js` owns data-only
streamed POSIX/PAX tar validation; `package-acquisition.js` owns credential-free
bounded downloads and exclusive quarantine materialization. They share the
existing native index, never execute installers/build scripts, and keep package
bytes distinct from accepted native custody/loader/API proof. Immutable modes
cannot establish Windows DACL protection or untrusted admission. Missing
dependency/license/build/ABI/transport inputs retain exclusion; the Git for
Windows self-extractor remains data. Legacy/incomplete reviews stay blocked;
version-2 reviews can supply a separately approved native data-only extractor,
explicit Bash entrypoint, containment template and complete immutable closure.
`package-extraction.js` persists its exact request before release, independently
verifies installed policy twice, then requires non-emergency domain retirement,
complete staged inventory and protected held-byte reads before sealing. Missing
controls, escaping paths, links, streams and undeclared members retain exclusion.
Uncertain settlement retains archive/storage custody and the original failure. The
indexed Windows package owner composes the approved streaming data-only extractor
through prerequisite custody, restricted launch, held policy barriers and whole
Job retirement. System custody owns exclusive publication writes, hashes complete
members before creation, retains their identities, and seals only unchanged owned
objects to System read/execute access. A separate native observer verifies the
entire sealed tree and retires independently. The package custody/loader/setup
metadata and protected possible-effect records permit reconstruction through
bootstrap readers without successful final outputs. No SFX, unconfined fallback,
operator extraction callback, observed approval pin or added system recipe is
admitted. The native owner records reached release-bound Codex tool,
executor, hook, sandbox and custom-provider source, and the unavailable opaque
Claude dispatcher and unbound moving gateway/tool documentation.
Inspected source, unresolved hypotheses, missing inputs, and native observations
are separate evidence; incomplete source or system/provider records retain
BLOCKED. The controller must supply independently inspected CI artifact/job
bindings; the pure join cannot authenticate metadata or establish native truth.
The owning [native document](../ci/native/README.md) defines acceptance, retained
audit findings, and external proof boundaries. Its local synthetic harness is
explicitly invoked outside ordinary test discovery. Pure dispatch/stage and
artifact-join contracts share that index. `ci/native/run.js` owns explicit CI
report I/O, read-only GitHub metadata collection, and the effect-free harness
child. Its explicit Linux system probe calls the indexed `ci/native/linux/`
owner, which reuses public agent ownership/identity APIs with an inner confined
fixture. Protected admission precedes release; acknowledged cancellation and
owner/supervisor/launcher loss are followed by a fresh read-only verifier of
persisted namespace-init retirement. Null identity reads never establish death.
The indexed Linux build/system factories are effect-free until explicit
operations rejoin the separate Linux review and authenticated Noble bootstrap.
They reuse confined compiler/controller receipts and fresh retirement readers;
prepared-build verification rereads bytes without compiling. Fixed write-ahead
intents survive partial preparation, and recovery retains uncertain custody.
Linux candidate readers retain no-follow file identities, parse actual ELF load
commands/cache dependencies, read reviewed provenance artifacts and independently
verify both provider packages. Expected inventories select permitted files;
they cannot manufacture observed authority, dependencies or approval pins.
The reference engine verifies parked namespace authority before case release
while retaining its historical unresolved-source semantics.
Darwin's indexed custody adapter constructs without effects and enters a
short-lived, sealed reviewed native reader through noninteractive elevation and
cleared private pipes. Shared native routines read actual audit-token/BSD and
held file/volume identities, signatures, Mach-O/shared-cache commands and SDK/build
bindings. Independent process/image admission precedes the setup barrier; the
existing file helper receives held root/base descriptors only after exclusive
custody admission, and its signed image and inherited objects are freshly read
before operation release. Intent and uncertainty survive transport faults;
independent closure, never child exit alone, supplies retirement. Complete policy
and dependency composition remain distinct owners and external native proof is
still required.
The same sealed Darwin reader now owns effective Seatbelt/ACL and held filesystem
observations, actual PF graph/interfaces/state/routes and socket ownership.
`pf-preparation.js` owns separately approved empty-baseline setup and persists
intent before its fixed quick delegation and approved loopback change. Private enable references are
released individually. Case changes remain anchor-only. Restoration requires
retirement and unchanged installed state; uncertainty retains the host-wide lease.
That lease uses one reusable pinned inode, rejoined to its protected pathname at
every observation and mutation. Seatbelt evidence binds the exact acknowledged
launch request and arguments to the candidate, closure and nonce.
Protected libbsm decoding joins acknowledged audit windows to held process/vnode
identities, while descriptor-relative file/Git snapshots supply independent state.
Incomplete native coverage, unsupported baselines and ambiguous joins remain
failures. These CI-only owners preserve the historical evidence/source findings
and have no production consumers or import-time effects.
Darwin's indexed build/system factories now compose those readers with the fixed
native owners. Construction has no effects; explicit operations verify sealed
reviewed inputs and persist provisioning/build intent. A short-lived sealed
compiler entry starts fixed tools suspended under a fresh root audit session;
independent image/signature and complete domain reads fence release and custody
retirement. Clang reads reviewed sealed source copies, never a mutable privileged
checkout. Signed helper/toolchain pins precede execution. Prepared verification
rereads the complete original command/byte inventory without recompilation.
Historical case capabilities supply sealed provisioning/private control
primitives; the repository fixes recipes, composition and retirement assertions.
Build provisioning and protected snapshots now have repository defaults through
the established native custody reader and compiler entry. Only a build directory
declared in the independently pinned plan can be created or resealed; held native
parent identities and extended ACL reads protect creation and publication.
Exclusive immutable receipts receive native held-byte and ACL verification before
dependent effects, and the original build-directory identity survives resealing.
Its receipt precedes compiler launch; the independent process reader rejoins the
compiler entry's actual held directory before release. Recovery reads that same
identity through native handles without resealing, including incomplete builds.
Unsigned intermediates are bounded signing inputs, while separately approved
final pins govern image use. Version-two preparation selects the 22 native build
commands separately from prerequisite/custody receipts. Its shortened verification
snapshot keeps outer requests pending for the prerequisite owner. Fresh
verification reads original source/tool/helper bytes and rejoins worker, bootstrap,
verifier and empty audit-session custody, including intermediate verifier
children from their protected creation records. Every verifier records its exact
intent and birth, then requires a kernel absence observation after exit. Build-only
recovery consumes partial protected records without successful helper outputs or
recompilation; missing identities and surviving domains retain custody. Its reader
lifetime covers the fixed inventory and a separate cleanup allowance. The private `darwin/case-provisioning.js` owner now supplies compiler-policy and
case-setup defaults. Each suspended compiler receives an independent native
credential, Seatbelt and complete descriptor read before release. Prepared policy
verification rejoins those protected observations, exact commands, fresh output
identity and retirement against an independently approved build template.
Case setup binds its exclusively created root and nonce to the entire execution
context. Native reads verify separately reserved non-login UID/GID accounts,
private directory ownership, copied immutable policy/image bytes and exclusive
loopback sockets while retaining the same sealed reader and host-wide lease.
Partial setup can retire without a payload or policy change. Interrupted recovery
requires recorded reader/verifier births and fresh object/UID joins; missing
writer completion or surviving custody remains retained. The private
`darwin/case-effects.js` owner now supplies literal/storage and every fixed
ownership recipe through that same sealed custody transport. The native root
launcher retains its privilege checks, parks behind protected admission receipts
and installs the complete independently approved fixture policy. Separate native
reads join executed image, credentials, audit session, cwd and actual Seatbelt
decisions before admission. Acknowledged fault barriers, held nonce files and
unchanged outside objects accompany complete domain observations; fixture output
cannot supply those proofs. Retirement uses full native identities, separate
audit custody and fresh verifier processes that independently enumerate the
domain. Interrupted admissions rejoin exclusive root receipts and member ledgers
without setup, compilation or another fixture launch. A root-only receipt also
requires independent UID absence; missing completion or identity retains custody.
The private `darwin/access-effects.js` composition adds the three fixed access
profiles behind that same factory boundary. A separately protected access record
pins the PF bootstrap approval, private tool/configuration copies, SDK audit
mapping, object query inventory and fixed attempt bank to the full case context.
The owner retains the host PF lease and its individual enable reference. Only
case-anchor writes follow bootstrap; parked tool helpers, worker identities and
kernel ruleset tickets are joined before each write. Actual Seatbelt queries,
complete PF graph/route/interface reads and exclusive endpoint reads precede
admission. Root outside controls run before anchor installation and supply their
own acknowledged BSM windows and held-object reads. Payload attempts join native
denial/permit events to before/after full identities and protected sentinels.
Four nonce exchanges join actual listener identities and held sockets to all
four packet-counter legs of each separately pinned PF rule set. A numeric
process ID, fixture result or creation handle cannot substitute for a native
audit selector; unavailable routes and incomplete coverage remain non-PASS.
Payload retirement and drained observer retirement precede unchanged owned-anchor
restoration, then PF baseline restoration. Custody closes and releases the lease
last. Interrupted installation, event loss and uncertain retirement preserve the
first cause and retain custody rather than authorize speculative restoration.
The private `darwin/case-operations.js` composition supplies every remaining
file, ordinary/fixed Git and release recipe through the same factory. Separately
approved operation records bind the exact context, input digest and ordered
custody assets; observations never mint those pins. File probes drop inherited
root descriptors before using the reserved UID. Parked publishers/readers,
controlled substitutions and native alias reads join actual full object/process
identities to immutable receipt barriers and unchanged outside snapshots.
Only the signed file helper owns publication; recovery cleanup receives only
recorded original objects and fixed cleanup commands. Root Git execution admits
each suspended child image and uses identity-safe release, while all three
ordinary profiles join actual Git exits, native audit denials and independent
positive controls to held metadata/workspace snapshots and parsed loose objects.
Release readers retain component, build/SDK/policy binding and both package files;
actual signatures and physical/shared-cache load commands must match the separate
approved closure. The captured fixed SDK query supplies its build identifier,
with protected receipt and fresh retirement joins; Mach-O SDK/minimum versions
remain separate observations. Full process/domain absence and independent held-reader closure
precede case retirement. Interrupted operations rejoin protected receipts without
setup, compilation or another Git mutation; missing acknowledgements or changed
foreign objects retain custody. These family helpers stay private. Provider
composition and native acceptance remain separate work.
The private `darwin/case-recovery.js` owner now reconstructs the complete protected
build, provisioning, ownership, access, file/Git and release inventory. Durable
context-bound recovery intents fence subsequent admission, including in a fresh
factory. Separately approved bootstrap assets and fresh case readers replace
successful preparation and final helper results. Stock custody, build and case
settlement are attempted independently; malformed or undeclared records retain
failure without suppressing another owner's retirement. Root custodians have
private audit sessions, so missing helper acknowledgements cannot hide surviving
descendants. Recovery rejoins native root receipts, immutable outside objects and
reserved UID domains before closure. Access recovery replays captured BSM bytes
against the root-sealed observer completion digest, independently checks named IPC
absence, and restores only the unchanged owned anchor and approved PF baseline.
The native owner records its individual PF enable reference before root-policy
mutation; recovery never acquires a replacement reference or globally disables PF.
Undrained observers, missing identities, changed policy and cleanup cancellation
retain exclusion and the first cause. No compiler, payload, Git mutation or private
control setup is restarted. Unsupported stock custody remains retained; injected
recipe coverage supplies neither native acceptance nor external source proof.
Concrete policy verification precedes dispatch or the parked payload's launch
barriers. Domains retire before audit release or owned policy restoration, and
held reader custody closes last. Persisted bounded cleanup keeps new admissions
fenced after work cancellation. Case anchors retire before host PF setup is
restored, and exclusion releases only after independent baseline verification.
Case reader intents and admitted identities share the recovery ledger; the fixed
reader lifetime covers the longest recipe and its separate cleanup allowance.
Per-effect receipts match the admitted ledger;
partial recovery retains uncertain roots and consumes protected immutable intents.
Helper/link and file-case bounds derive from the fixed supported inventory.
Version-two Darwin release observations retain independent template pins.
Injected composition proves wiring only; matched SDK builds and fresh native CI
remain external requirements.
The indexed Windows custody adapter is effect-free until persisted admission
starts its sealed native Task Scheduler bridge. The one-shot task has no triggers
and runs only the reviewed reader as LocalSystem in session 0. Private IPC joins
both process creation identities; separate native verification precedes setup.
The bounded reader retains process/token and Job handles, no-follow files and
volume handles, DACLs and signed loader inputs through retirement. PE imports,
delay imports and actual API-set mappings resolve against observed loaded modules;
SDK/build observations remain separate from reviewed pins. Existing file/policy
helpers receive explicit creation-time handle lists and private control pipes,
start suspended in a private restricted Job, and require independent transfer
verification before release. Domain retirement precedes held-resource closure;
the bridge checks zero task instances and unchanged task definition/security
before owned removal, followed by independent removal verification. Missing
observations retain possible effects. Injected tests prove protocol wiring;
Windows SDK compilation and fresh protected native proof remain external.
The indexed `createWindowsCustodyVerifier` reuses a separately approved, admitted
repository reader through its private bounded verification lane. It holds the
target's process/token, transferred Job and immutable source/image identities;
native Task Scheduler reads independently join the exact task definition and
security digest. Each native request is persisted with its exact arguments
before dispatch. Worker/task retirement leaves the independent reader live and
owned by preparation; an observer cannot prove its own retirement.
Windows indexed build/system factories compose that custody with existing launch,
policy, ownership/access, file, fixed Git, release, audit and retirement owners.
Construction has no effects; protected intent precedes explicit bootstrap,
compiler entry, publication and case provisioning. Sealed MSVC/SDK inputs and
independently approved helper/tool pins precede execution. The one-shot compiler
entry creates private outputs and pipe lists, starts a suspended System worker
inside bounded private Jobs, and admits it only after held image/creation reads.
Build and fixed Git grants use a separate System primary token with a System-only
creator default DACL, independently verified before helper release.
Native publication joins compiled unsigned bytes to a reviewed signed image,
allowing only checksum/security-directory and certificate differences; no signing
credential is inherited. Independent closed-writer verification gates receipts.
Prepared verification rejoins actual tool-version output, the complete
image/command inventory and fresh whole-domain retirement without recompilation.
Fresh provisioning supplies
literal account SIDs at both existing policy release barriers; nonliteral
installed-policy observations precede dispatch. Payload retirement precedes audit
stop/drain and observer EOF, owned unchanged policy restoration, custody closure
and independently verified task removal. Fixed Git/policy helpers use the same
private pipes and distinct held-handle lists; actual Git status must match stable
held filesystem snapshots. File transfer reopens only the private `base\files`
root with delete sharing for owned substitution controls, continuously retaining
the same identity and System-only DACL. Protected parents retain their sharing;
independent transfer verification gates helper release.
Security capture has a separate bounded helper slot
and pipe pair through finite file/policy work, with both Jobs retired before
restoration or task removal. A bounded cleanup signal fences new process/Job and
payload/helper admissions after work cancellation. Only owned removal helpers
may start after explicit retirement authorization and fresh unchanged-installed
state verification. Partial recovery uses
approved bootstrap assets and protected ledgers, without requiring successful
preparation or surviving prepared images, and retains every uncertain effect.
Windows-only helper/command bounds derive from the extended fixed inventory;
file recipe deadlines include their existing session limits, and the native
Task Scheduler/transport lifetime covers the longest case and its settlement.
Other platform preparation contracts retain their limits. Injected composition
proves wiring, while matched SDK compilation and fresh native proof remain external.
Version-6 CI jobs compose fixed platform cases and protected provider sessions.
`composition.js` owns the pure versioned job/ledger contract;
`composition-execution.js` bounds write-ahead execution and separate build, helper,
policy, observer, transport and provider ledgers. Each possible effect needs an
independent retirement receipt before another execution; native owners retain
complete protected recovery receipts while reports expose only bounded references.
`composition-plan.js` binds the complete fixed inventory and effective policy to
candidate-bound protected review and reduces only complete settled native cases.
The indexed provider dispatcher uses all three authority profiles and all required
Codex/Claude routes; selecting a CLI tier grants no operator authority.

`providers/effects.js`, exposed through the CI provider index, composes sealed
helper preparation, fresh platform custody/release readers, existing launch and
concrete-policy owners, protected relay/native transports and real mediation
owners. Schema-2 provider input declares every fixed case and its native selectors;
independent template approvals are supplied separately. The checked-in
`provider-effects.mjs` entry must match the published candidate bytes and its
unique reached-source citation. It exports the repository factory; publications
supply approved data rather than capability implementations. Construction is
effect-free; explicit bootstrap/build operations persist protected intents first.
Expected source, toolchain and executable pins confer authority; observed hashes
never replace them. `providers/preparation-effects.js` and `preparation-files.js`
supply protected
held directories, immutable receipts and helper preparation defaults. Linux
compiles the fixed provider gate through the existing confined compiler owner;
Darwin/Windows rejoin the complete prepared platform helper inventory through
native ACL/DACL and byte reads without compiling. Pinned root-owned stock tools
retain ordinary owner-write permissions; sources, helpers and receipts stay
sealed, and group/world writes or set-id bits block file admission. `settleBuild`
closes file observers before preparation PASS. `verifyBuild` rereads protected
receipts/images and freshly checks every previous custody/file observer and task retirement,
including complete Windows helper and compiler Job inventories, without
compiling. Helper-only reconstruction uses approved bootstrap assets
without final output files; missing birth or retirement proof retains exclusion.
The indexed `linux/provider-effects.js` now supplies provider-case provisioning,
held release and live-process readers, parked launch/policy barriers, private
relay/bridge transport, complete case materialization, retirement and Linux
partial-case reconstruction. Its private kernel, channel, observer, transport
and outside-control modules own raw filesystem/process/IPC/HTTP effects.
The provider gate retains a separate CLOEXEC probe pair in a nondumpable child;
a tracer starts with
the parked launch, follows fork/clone/exec and writes only to a protected pipe.
Neither probe nor trace descriptors reach the provider executable. Complete
kernel credentials, namespace mappings, mounts and descriptor inventories are
read before both release barriers. Independent object/byte readers join native
tool events; hidden objects/endpoints require an acknowledged outside control
and a complete matching namespace inventory, never an error code alone.
Payload and relay/bridge retirement precede trace drain, outside-control closure
and unchanged owned restoration. Control closure fences listener creation and
joins any pending listen attempt before accepting retirement.
A shared transport owner persists and reuses
helper retirement proof. Live image inspection joins mapped devices/inodes to
approved objects and rechecks complete namespace membership after its reads.
Protected records retain supervisor creation identities and
private namespace init identities for provider, relay, bridge and sacrificial
workers; reconstruction fences admissions, revokes private release/control
pipes and uses creation-checked pidfds,
including setup that never returned its prepared object. Missing birth, loss,
changed inputs or incomplete retirement retains exclusion. Darwin/Windows
provider-case composition and shared recovery remain separate plan work.
Fresh package reads retain new object/observation identities
under the selected system's approved manifest, while the dispatcher preserves
that exact selected system gate before credential delivery. Invocation/configuration
and actual installed-policy barriers precede relay/provider admission. Payload
retirement precedes audit release, unchanged owned restoration and final custody
closure. Recovery uses protected partial ledgers and approved bootstrap assets,
without successful preparation, and retains uncertain effects. Receipt bodies stay
private; aggregation remains eighteen provider records and all 87 total records.
Injected preparation tests establish wiring only; native/model proof stays in
approved external CI. Production adapters are unchanged.

`system-ci.js` separates approved metadata admission from on-host input reads.
Version-2 manifests add the fixed `prerequisites.js` bootstrap/package inventory:
reviewed reader/bridge, required launch/retirement/build images and all fixed
sources/headers and bootstrap/case custody plans have explicit byte/hash and
source/build/toolchain/loader bindings. Windows includes every reviewed signed
helper image needed for native build publication.
No reader executes before acquisition, native birth protection and independent
sealed-byte verification. Expected images never come from an unapproved build.
The checked-in, effect-free `native-effects.mjs` entry delegates through the native
index to repository factories. Version-2 loading compares acquired bytes with
the cited candidate entry before evaluating a captured copy whose only relative
import is bound to the repository index. Historical version-1 entries keep their
original semantics. Repository owners enforce review, bootstrap assets, explicit bootstrap, toolchain,
helper build, packages and complete verification phases. Protected exact requests
precede sealing, elevation, tasks and commands. Held bootstrap signals span command
retirement, and complete independent verification retires their outer receipts.
Recovery consumes approved metadata/bootstrap assets and protected ledgers without
requiring final package materialization or successful prepared images. Per-asset,
package and aggregate bounds derive from the fixed inventories and existing
512-MiB provider image limit. Missing prerequisites or uncertain retirement retain
exclusion and the first failure. This adds no production dependency, probe case,
provider credential delivery or synthetic native proof.

`prerequisite-custody.js` composes the reviewed transport through private
`capability-files.js`. Approved context supplies admission, stock runtime,
privilege, scope and manifest/source pins as data; no factory callback or
replacement module is consumed. Exclusive controller receipts form a bounded
candidate/manifest-bound chain. Asset creation independently rejoins immutable
bytes and birth identities. Data-only package acquisition admits the complete
fixed-catalog archive before creating an exclusive package root, then seals each
reviewed member only after its byte/hash check. Held directory observations
reject undeclared members; complete verification rereads every archive, member,
asset, tool and input and calls the indexed platform prepared-build verifier.
Custodian closure independently proves process/task retirement after descriptor
work drains. Interrupted acquisition reconstructs the protected chain and fresh
stock custody observations while retaining partial publications without adoption
or deletion. An incomplete acquisition chain preserves its first failure while
still attempting independent stock custody settlement. Generic Darwin/Windows
file release, incomplete platform build/case defaults and native Git extraction
remain fail-closed at their existing owners.

Private prerequisite file owners now implement exclusive creation behind a
separately persisted, independently reread immutable request. Linux operations
retain no-follow ancestor and file descriptors, bound reads to 512 MiB, and
compare native identities, permissions, metadata and bytes across creation and
read-only transfer. Failed writes retain handles and exclusion; reconstruction
does not infer birth ownership from a matching name or digest. The mode-based
owner rejects Darwin before filesystem effects because Node cannot independently
observe extended ACLs or creation inheritance; actual native ACL custody is
required before enabling Darwin prerequisite files. Windows defines
a fixed, explicitly invoked PowerShell 7 Core interop entry with actual Win32
creation-time System DACLs, retained file IDs/security descriptors, no-reparse
parents and a final read handle denying write/delete sharing. The JavaScript
adapter bounds raw operations to 32-KiB chunks within 64-KiB frames and rejects
mismatched or malformed responses. Host/source/runtime approval and process/task
custody remain owned by the separately admitted transport; missing transport
enables no operation.
Neither file owner launches processes or changes preparation composition.
`CLOSED` means descriptor closure only, never custodian retirement or native
acceptance. The enclosing owner must independently settle every possible effect.

Private prerequisite source custody now captures the complete fixed worker
graph against unique reached-code citations, including its observation
dependency. Snapshot evaluation and worker imports start no IPC; a generated
explicit entry is the only activation boundary. Requests bind the complete
admission digest, nonce, ordered IDs, canonical scope and bounded expiry. Frames
are bounded before decoding, and fixed chunked reads/uploads cannot select
arbitrary filesystem methods, compilers or verifier children. Creation still
passes through the immutable-intent and independently held-file owners above.
Expiry and stream interruption reach active file operations; late results and
blocked or failed output cannot acknowledge success. Partial gateway custody
retains exact intent/task selectors before effects. Failed admission preserves
possible effects; descriptor closure never supplies process retirement.

The Windows stock-host gateway defines protected snapshot/pipe preparation and
the short fixed Task Scheduler action. Independent source, interpreter and
System-privilege pins precede exclusive private-DACL creation; actual native
identities span writer closure and held read-only verification. Preparation
registers/starts no task. Reconstruction retains intent and exclusion without
retry or file adoption; later transport/verifier owners must independently
admit, release and retire every possible process/task. No preparation factory
or production adapter is rewired by this slice, and native acceptance remains
external.

The private prerequisite transport now supplies repository-owned Linux worker
launch, bounded serialized file RPC and interrupted-custody reconstruction.
Independent source/runtime/manifest/scope/privilege approvals precede effects;
held source/tool bytes, protected exclusive records and kernel creation identities
remain retained. Launch intent is synchronized before process creation and birth
identity before worker admission. Each command has a protected delivery intent.
Two fresh complete procfs observations must prove absence of the exact worker
and every possible session/descendant member; exit, EOF, PID reuse or an old
completion cannot retire custody. Missing birth after possible admission retains
exclusion. One cleanup deadline covers pending startup, raw operations, recovery
and publication; unresolved filesystem work retains its descriptors across
timeout and retry. Cleanup preserves the first failure and retries failed descriptor
closure without signalling by PID or adopting uncertain files. Recovery needs
only approved stock inputs and protected records, not successful final images.
Darwin exposes its fixed sudo/env vector but still requires native ACL custody.
Windows reconstruction rereads protected intent/birth records through the
approved native verifier. The original observer creation identity and retained
Job slot must survive; reopening a named Job cannot establish retirement.
Fresh held process/token and whole-Job observations precede removal of only the
unchanged nonce-owned task, followed by two fresh absence reads and protected
settlement. Closure repeats those observations within the same cleanup budget.
Missing handles, records, inaccessible reads or surviving members retain the
first failure. Windows worker release still requires protected preparation
composition; these recovery defaults change no production adapter or build factory.

`policy-template.js` owns the pure approved-template contract behind the native
index. Version-2 release and plan shapes separate independently reviewed immutable
templates and narrowly declared runtime identity rules from concrete policy,
request and observation hashes. Trusted held provisioning supplies only declared
UID/GID, SID, session, custody and owned loopback identities; commands, grants,
peers/routes, tool/package hashes and privilege limits remain fixed. Materialization
derives expected policy data, and independent complete installed-policy reads
must match it before payload release. Version-2 execution receipts bind the exact
candidate/platform/tier/run/attempt, complete job provenance, execution and closure;
write-ahead policy evidence precedes provider transport/model effects. Historical concrete-policy
inputs remain readable under their original guarantees without promotion.
Provider evidence retains the complete independently selected system job digest,
artifact binding and closure. Aggregation rejoins that selection and independently
supplied template approvals, preserving all 87 records and four source findings.
The pure binding contract fixes normalized launch arguments and platform policy
parameters while excluding derived policy pins from independent approval.
Indexed platform launch/policy owners consume that binding and trusted provisioning;
complete independent installed-policy reads precede payload release. Windows
launch versions 3/4 defer policy bytes until the acknowledged held SID/object
setup barrier, send only a bounded concrete hash over the private control pipe,
and verify before suspended creation and again before release. Darwin verifies
acknowledged Seatbelt on its parked child. Provider controllers persist concrete
policy evidence before relay/model admission. Credential-bearing relay admission
runs within parked-domain preparation; earlier endpoint reservation stays
credential-free. Generated request digests confer no approval. All native
installation, readers and execution remain dedicated external CI, and missing
observation withholds release without relaxing retirement.

`closure.js` shares only pure reviewed-manifest comparison. Platform indexes own
held-image/identity, actual loader/ABI, build, privilege, effective-policy and
provider-package reads. Both packages enter system release evidence and are
reverified live in protected records. The historical Linux reference release
contract is unchanged; its candidate closure is separate. Version-3 result
references bind release/source/package/effect evidence to version-6 jobs.
Aggregation additionally requires independently supplied release and execution
review approvals and the complete matching jobs; mixed older records cannot
complete a new proof. Source evidence version 2 requires reached-code/API citations
and protected candidate-bound manifest approval, beyond status fields or probes.
The fixed API probe name matches `Probe complete system inventory`, retaining
legacy reporting-harness records and rejecting duplicate stage aliases.
These CI-private capabilities add no production consumer or import-time effects.

The manual `native-poc-acceptance.yml` workflow binds dispatch/workflow/checkout to
one approved published candidate before effects or secrets. Protected provider
jobs reuse indexed preparation and actual mediation owners; only verified private
relay pipes receive step-scoped credentials, with provider inheritance excluded.
Fresh recovery separately binds provider/preparation ledgers and keeps uncertain
proof non-PASS. The read-only acceptance collector verifies repository/workflow
identity, exact system/provider run attempts, protected environment rules, actual
native job conclusions and upload receipts, digests and lifetimes. PR merge SHAs
are independently joined to candidate parents and matching workflow blobs, never
used as checkout identities. Independently approved source/release/execution
manifests join all 87 records and four findings through the strict existing
predicate. A successful system inventory cannot replace `native-full-go`.
Default-branch workflow hosting, publication, protected environments/main/dev
rulesets, credentials and fresh native proof remain external operator actions.

The CI-private first-failure owner adds bounded version-1 receipts to new
version-6 jobs without promoting historical evidence. Individual prerequisite
diagnoses precede acquisition; the first receipt is published before atomic job
replacement and retained through subsequent stage failures and artifact joins.
Write-ahead preparation admission distinguishes unstarted effects from POSSIBLE
effects requiring fresh recovery. Uncertain retirement is reported separately;
recovery cannot repair the original failure. Protected failed-job collection is
diagnostics-only and is rejected by system admission and full acceptance.
The native owner specifies the closed fields, custody and external proof boundary.

The three-platform system workflow now dispatches preparation and probes through
those indexes. Fixed public input members at an independently approved revision
are acquired without credentials or redirects; complete candidate-bound source,
tool, build, dependency and reader digests precede native effects. A fixed reviewed
single-file native reader is loaded from verified bytes in memory, with no CLI
module selector or mutable relative dependencies. Dedicated private build phases
persist command intents before independently observed retirement; probes only
verify prepared images. Fresh recovery binds partial preparation and execution
ledgers without repairing failed proof. Inventory-derived deadlines preserve
case/settlement budgets and reserve cleanup/report/upload. A separately labelled
69-record system result preserves independent job/artifact selection while full
acceptance still requires all provider records and source findings. Actual
privileged readers, reviewed publication and external observations remain operator
CI responsibilities, detailed by the native owner.
Windows build defaults use the already independently admitted reader/bridge
seed through a separate System file/verification lane that admits no work
helpers. Native exact-request and creation-identity records precede task/work
acknowledgement; directory discovery, exclusive receipt sealing and unsigned
snapshots stay under protected native custody. A fixed 16-minute lifetime covers
two version queries, thirteen compiler commands and separate cleanup. Parked
compiler image/token/Job observations precede release, and fresh retirement
precedes publication of separately approved signed bytes. Only PE checksum,
security-directory and aligned certificate data may differ from the reproduced
unsigned image; no signing credentials are inherited. Prepared verification
rereads source/tool/image/receipt pins without compiling. Partial recovery keeps
the original observer handles in an index-owned preparation registry and rejects
missing intent/birth/journal evidence, misbound worker receipts or
surviving effects; observer/task closure remains independently observed. This
adds build defaults, not complete system cases or native acceptance, and does
not change the thirteen-helper inventory or historical injected semantics.
Windows system defaults now add private case provisioning and mandatory build
policy observation. A protected worker record joins independently read token,
inner/outer Job limits, creator DACL and inherited pipes to the final compiler
receipt. The approved template describes that actual authority and held output;
materialized expectations cannot provide observations. Case roots derive from the
complete candidate/job/run/attempt/execution context. Native System custody
creates private roots, copies reviewed images, allocates fresh accounts and
restricting SIDs, and retains restricted tokens, empty Jobs and approved loopback
endpoints. A separate context-bound observer rejoins the exact token handle,
account rights and held file identities/DACLs before resource binding. The shared
private account header is a fifth sealed custody source; the thirteen helper
images and creation-time launcher restrictions remain unchanged. Partial setup
retirement requires unchanged owned accounts, no payload creation, independent
account/rights/Job absence and closure of both custodians. Lost acknowledgement or
cancelled cleanup retains possible reservations. Private Windows case effects
now compose all fixed ownership recipes using the same sealed launcher and
restricted account/token owner. A separate System domain custodian, protected
admission receipts and fresh finite native witnesses join actual process/token,
Job, cwd/image and object identities to an independently approved ownership
policy. Its writes affect only the six case-private objects and four owned WFP
deny filters. Protected policy receipts at setup and the parked payload
independently precede R; its creator default DACL and inherited pipes remain
System-only. Outside controls and a held sentinel are required; fixture bytes
alone grant no evidence.
Faults distinguish domain-owner loss from launcher loss, retain children before
reparenting, reject stale birth signalling and prove all holders before the last
Job handle closes. Held admissions reconstruct without final fixture/build
results. Creator fencing and fresh whole-domain absence precede unchanged owned
policy restoration. A fresh descriptor/WFP-absence witness precedes independently
observed account/custodian closure.
Fixed Windows access recipes now compose repository-owned policy, coverage,
control, observation and retirement operations behind the same platform index.
Separately approved data binds the source/ABI obligations, complete competing
WFP graph and observer pins. Independent held reads cover token, file/ancestor,
registry, all 52 persistent filters, account/Job census and socket identities;
both policy barriers precede release. Private native controls and separately
parked peers replace missing high-level owner callbacks. Security/BFE events must
join held actors, objects and full socket tuples; fixture status and timeouts
cannot prove denial. Two independently verified directory handles with only
traversal/attribute/synchronization rights bind root-relative file probes after
admission; System-only ancestors and the privilege-free token stay protected.
Protected partial-setup records retain the original cause.
Payload/peer/helper retirement precedes observer drain, unchanged per-user audit
and owned policy restoration, then account/custodian/task closure. Uncertain
native transport or proof retains exclusion.
Private Windows operation owners now complete default composition of six file
recipes, two Git recipes and release inspection. Approved data selects sealed
assets, held resource slots, loader edges and build/package bindings; it cannot
replace effect implementations. The custody reader owns finite native controls,
worker Jobs, actual PE/API-set reads, private file observations and Git Security
events. File execution transfers exactly two System-only directory handles; Git
execution and policy-writing inventories remain distinct. Protected receipts
and native ACL/audit baselines precede possible effects. Independent snapshots
join fixed Git objects and metadata; release inspection joins held signed bytes,
SDK/build authority and both provider package inventories before closing readers.
Fencing and held-Job retirement precede unchanged restoration and account/task
closure, including partial workers and failed readers. Fresh cleanup signals
rejoin preparation custodians before writes and closure. Unknown final objects or
lost native proof retain exclusion and the first failure. Complete cold
reconstruction remains separate; these defaults establish no native Windows
acceptance or provider dispatch.
Darwin's final compiler barrier publishes root-owned read-only outputs only after
verified tool-domain retirement and persisted intent, so the unprivileged runner
can rejoin actual bytes under private report custody. Access preparation joins
approved parameters and concrete bytes before policy setup, keeping the native
Seatbelt/PF composition digest separate from the complete template digest.
The sealed compiler captures bounded tool output internally and returns it as
data over standard control pipes, preserving default sudo descriptor closure.

Independent tool observation shares only the pure `ci/native/observation.js`
join. Platform indexes own fixture-started Linux syscall tracing, private Darwin
UID/session-selected BSM audit pipes, and Windows object-access/WFP subscriptions.
Protected external readers join native events to held identities, acknowledged
windows, independent nonce/state reads and fresh domain/observer retirement.
Permit/deny controls precede provider release; text, missing events and capture
loss fail proof. Native readers/setup remain external CI; bounded raw data stays
in private pipes/memory while persisted diagnostics contain only synthetic hashes.
Owned audit restoration follows independent retirement and verified unchanged
settings. Observation failures remain terminal when caught by a caller; callback
deadlines fence effects and restoration also requires settled controller work.
No production owner, historical evidence, source finding or acceptance
gate gains authority from this source implementation.
Receipts, control code and the checkout remain outside payload writable grants.
The Linux index also owns CI-only package preparation between reporting
initialization/pinned runtime setup and native probes. A private authenticated
Ubuntu Noble APT inventory resolves an exact amd64 bubblewrap version and
archive digest. A private bootstrap configuration prevents image-wide APT hooks
from loading and is explicitly preserved through sudo. Unprivileged acquisition
and integrity checks precede a bounded noninteractive installation with downloads
disabled and no additional dependency changes. It preserves host security policy
and requires canonical executable
protection through the existing public agent API. A separate candidate-bound
preparation receipt is atomically persisted before each phase and uploaded;
failed, absent or interrupted preparation makes setup fail and blocks probes.
Successful preparation records the installed version/digest in job component
evidence, which the existing fixture checks before payload admission while
retaining both unchanged namespace probes and fallback rejection. This receipt
supplies neither native acceptance nor retirement. Acquisition, installation and
system probes remain external CI effects; local coverage injects all effects.
CI-private access profiles extend that fixture with separate synthetic Git
repositories, read-only ordinary metadata, disposable trusted-command content,
ready host network/socket controls, and a fixed protected commit executor.
`linux/profiles.js` owns pure authority/effect predicates; `linux/access.js`
owns explicit system preparation and independent sentinel/Git observation.
These cases reuse admission and fresh retirement rather than duplicating loss
scenarios. Only the fixed executor receives synthetic metadata write authority;
its operation, subject, helpers and existing identity are constrained. Provider
checks remain BLOCKED; file checks have their separate complete proof owner.
Production profile and workflow authorizations remain unchanged.
The Linux index also exposes the restored file helper/build foundation through
the complete CI-only system composition. `file-helper.c` owns bounded fixed descriptor-relative
operations, current named-object identity checks, exclusive publication,
synchronized replacement and identity-bound cleanup under sole parent authority.
Its explicit alarm exits without cleanup; the admitting owner must keep parent
authority and channels outside payload access. The complete fixed file cases
below add independent file observations within that complete suite.
`file-build.js` accepts separately reviewed candidate/source-bound system input
pins and compiles only in Ubuntu 24.04 x64 CI. Verified private snapshots and
fixed arguments exclude host toolchain fallback. Bounded source/input/output and
compiler invocations produce a compiler/input/helper record with static ELF
closure. The index exposes pure pin and ELF validation for effect-free coverage;
imports have no build effects. Missing pins prevent compilation, and build
observations establish no publication, licensing or native acceptance.
The indexed `files-protocol.js` owner adds fixed closed requests, bounded
contents and immutable replies/continuations through injected callbacks.
Expected nonce, anchor and operation identities remain fixed across awaits;
allocation/recovery reject an already-held allocation before sending commands.
Prepared/published barriers precede their continuations. Publication preserves
the known winner, and recovery matches recorded object identities in a fresh
confined mount. Transaction success retains exclusion. Only fresh independent
non-emergency retirement and successful cleanup can release a successful
operation's storage; earlier failures remain failed.
The indexed `files.js` owner now supplies protected CI-only sessions with held
anchor/parent descriptors, named-object checks and serialized commands. The
existing launcher and registration barrier precede independent executable,
namespace and mount inspection. Helper mounts exclude payloads and procfs while
ordinary fixture requirements and ownership cases stay unchanged. Immutable
possible-admission, readiness, command, operation, barrier and interruption
records precede dependent effects; a separate terminal record cannot erase
them. Comparable policies exclude anchor names, which remain bound separately
in protected session receipt digests. Recovery validates the old protected
candidate, policy, readiness and recorded native identities and requires fresh
independent retirement before another helper. Failed operations, emergencies
and uncertain storage remain failed/excluded. One non-resetting 30-second
admission/probe budget and separate five-second owner/verifier bounds apply.
File sessions alone do not activate system-suite dispatch.
The indexed `files-cases.js` owner supplies all six explicit CI-only file cases
plus effect-free injected orchestration and a frozen subcase inventory.
Fixed-name host reads bind native device/inode/birth identities, private ownership,
modes and exact bytes under retained parent authority. Concurrent publication
requests share that serialized authority and must yield one unchanged winner.
Replacement interrupts owned live handles at acknowledged prepared/published
barriers, verifies complete old/new bytes after fresh non-emergency retirement,
then recovers and cleans only protected recorded identities in a separate session.
Interrupted and denied operations stay failed. Substitution, symlink/magic-link,
mount and hard-link cases require operation-specific native guard evidence,
permitted controls and unchanged independent sentinel/identity observations.
Cleanup observes identities before synchronized removal and rejects a substituted
leaf at its parked removal barrier. Closed case policies admit only private
procfs or one read-only sentinel mount when needed; default helper grants and
ordinary fixture requirements remain unchanged. The separate control owner
retains parent descriptors, removes only its own recorded objects and restores
original identities after fresh non-emergency retirement. Protected denial and
restoration records precede recovery; unknown objects cannot be adopted or
recursively removed. Case admission precedes every helper; emergency,
uncertainty, unexpected failure and failed control cleanup/recovery cannot pass.
The 1/1/4/4/8/3-session inventory derives 45/45/190/210/420/150-second envelopes,
retaining existing session/retirement bounds and separate five-second control
cleanup. CI-private documentation owns the subcase/budget table. No universal power-loss durability,
partial system dispatch, source closure or platform/provider acceptance is claimed.
The workflow emits fixed fallback summaries when checkout is unavailable.
The declared-platform workflow pins one candidate SHA and released Node
and actions, retains phase failures and bounded artifacts, and binds upload
receipts to API-reported jobs. Its pure indexed `isWindows2025Image` predicate
recognizes exactly `win25` and the reviewed `win25-vs2026` as `windows-2025`,
requiring build `10.0.26100` with at most one numeric revision and a bounded
1–128-character hosted image version. CI inspection preserves the observed
build/image version and the separate checkout, x64, pinned Node version/digest
and independent job/artifact gates. Recognition is not native proof; the
[native owner](../ci/native/README.md#implemented-reporting-workflow) defines
the exact image-version character contract and remaining acceptance boundaries.
Version-4 job envelopes admit only implemented
same-revision Linux launch/ownership/access records and nullable closed prerequisite
diagnoses. Their closed `unrecordedAdmission` marker starts as `not-started` and
is atomically persisted as `possible` before Linux proof invocation, retaining
interrupted-controller obligations without a receipt or result. Version-2
native records carry explicit `admission` evidence. Only compatible producer
`not-started` records suppress derivative phase/settlement findings; known
pre-admission setup FAIL remains FAIL with probe/cleanup NOT_RUN and retained
exclusion, never successful native retirement. Legacy records normalize to
possible effects, and conflicting policy, phase status/reason, observation or
settlement evidence cannot erase attempted-process obligations. Earlier attempted cases
retain their observations and settlement after a later fixture failure.
Conflicting job markers cannot hide absent implemented records or uncertain
non-Linux effects. Absent policies assert no different effective policy;
recorded policies still compare within their real groups, with Linux
generic ownership and access grouped separately.
New reporting cleanup and job validation share the same effect/retirement
predicate; historical job versions 1–3 remain readable under their original
cleanup validation without attesting native cleanup. Every version uses the
current evaluator before recording a fresh cleanup PASS.
Explicit version-5 job envelopes add the six fixed file checks and release
audit. The complete indexed Linux system owner now composes their dispatch. Their five-key effect ledger separates
ownership, access, compiler, file-helper and release-probe admission; producer
write-ahead records and independent non-emergency settlement remain distinct
from reporting cleanup. Compiler retirement precedes helper admission, and
missing possible effects stay conservative within their actual groups.
Incremental results cannot replace earlier records. Bounded supporting
identity/digest references retain no raw output and cannot supply observations
or source closure. File/release policy groups, candidate/runtime/components and
independently read job/artifact bindings remain strict. Per-job and joined
reports preserve ledgers/references as `nativeEffects`. Versions 1–4 keep their
original inventories and semantics; the current CI producer explicitly uses
version 5. The default historical constructor option remains version 4.
The CI-only `linux/system.js` owner writes group admission before effects and
completed group results/settlement before advancing ownership, access, pinned
build, complete file suite and read-only release audit. A separate compiler
controller writes protected command receipts and exits before fresh independent
retirement; only then can file-helper admission occur. Missing reviewed inputs
leave dependent checks BLOCKED/NOT_RUN; later failure cannot erase earlier
completed groups or immutable failed/interrupted session records.
Prepared Linux verification selects only the fixed compiler slice of the
preparation ledger, separating asset/bootstrap/package/verification receipts.
The explicitly requested verification snapshot keeps exactly one bootstrap
entry POSSIBLE and precedes its own receipt; completed preparation requires the
full retired inventory. Repository factories reread source/tool snapshots,
protected version requests/completions and helper images, then independently
reobserve the original namespace receipts without recompilation. Original result digests
join protected command completions with their original bounded deadlines while
raw version output stays transient.
The native index exposes the stock transport recovery owner to Linux. Recovery
requires separately approved same-job/manifest custody data and rejoins nonce
intent, birth identities and fresh full-procfs census even without final helper
bytes or completion. Unknown or reused processes retain exclusion, namespace
observation proceeds despite stock uncertainty, and verification retains its
first failure. Separate Linux bootstrap approval and historical reference-proof
semantics remain unchanged; these operations supply no native acceptance.
The shared CI loader forwards supplied approved stock-custody data only to
version-2 repository factories. Linux recovery uses bootstrap assets and skips
final helper-image reads, while normal prepared admission still requires them.
`linux/release.js` consumes explicitly supplied canonical, private, immutable
candidate-bound side inputs, with no automatic pin discovery. Release evidence
keeps publication/source/build/license bindings separate from measured
versions/digests, copied build inputs, ABI, observer privileges, effective policy
and the four open source assumptions. Every used executable/build input/ABI
component must match the reviewed inventory; fresh receipt verification precedes
the audit result. Matching observations cannot create pins or close findings.
The indexed `linux/reviewed-inputs.js` owner now provisions those existing
version-1 build/release inputs during explicit external Linux preparation.
A candidate-bound manifest joins every copied GCC-13 input, executable and
declared runtime ABI component to separately reviewed publication/source/build/
license bindings; a trusted independently approved normalized digest precedes
exclusive private publication. Held, bounded reads recheck file/parent identities
and immutable modes. The completion manifest is published last and rejoined to
the approval and both exact inputs before compiler admission. A separate
write-ahead preparation report preserves missing inputs, failure and interruption.
Only its exact candidate-bound NOT_RUN receipt permits the first attempt; a later
attempt cannot overwrite a failed or interrupted report by selecting another
input or directory. Its status alone supplies no expected pins. Ordinary PR jobs reserve an output
path but provide no approval or source manifest, retaining the earlier Linux
ownership/access foundation while dependent build/file/release checks block.
The ten-second input budget fits the existing preparation reserve; no compiler,
file, release-v1, source-finding, inventory or production behavior is replaced.
The frozen five ownership/four access/21 file sessions and compiler/retirement
budgets derive a 2,025-second Linux probe, 35-minute step and 53-minute job,
including bounded always-run reporting/upload reserve. Other platforms retain
their existing limits. The native owner documents the exact input and budget
contracts; imports, ordinary discovery and local validation have no native
compilation, system or authenticated provider effects.
The Linux prerequisite owner distinguishes fixed candidate discovery, executable
identity/protection, ordinary and nested public namespace probes, procfs,
private storage, executable ABI/runtime binding and bubblewrap version. Only
reached checks are recorded, with later prerequisites NOT_RUN after the first
failure. Bounded errno, exit, signal and explicit timeout facts survive the
versioned missing-input artifact, job report and independent artifact join under
the containing revision, observed image/build/runtime and provenance. Unknown
failures remain unverifiable; no host-policy cause or preparation is inferred.
Diagnoses cannot attest native cases, policy or retirement: dependent cases stay
BLOCKED/missing-input. Production launcher/protection behavior is unchanged.
The minimal Linux experiment separately captures bounded namespace diagnostics
through the public injected probe without changing those prerequisite shapes or
fixed isolation vectors. CI admission shares that capture, and candidate/nonce-bound
closed failure IPC preserves first causes and independent cleanup explanations.
Compiler observations precede successful-build assertions; failure diagnostics
confer neither admission nor retirement. Matching hosted CI must still establish
the missing historical namespace and command rejection causes.
The Darwin experiment likewise retains discovered tool identities and bounded
build diagnostics, including the rejected Mach-O inspection condition. Its x64
and signing checks and private sandbox bindings remain unchanged pending matching
SDK/library evidence; diagnostic capture establishes no historical build repair.
Per-job reports project only their platform and applicable source/prerequisite
findings and cannot yield aggregate GO. The aggregate inventory remains all
three platforms, 23 system cases and six provider checks each, with the four
retained source findings. CI stage health, system case acceptance, source
closure and protected provider absence are reported separately. Deterministic
annotations prioritize primary stages and reached Linux prerequisites before
derivative/missing-proof findings, retaining the 32-annotation bound and every
structured finding. Artifact guidance applies only to actual selection,
download or payload defects; stage failures survive even without a payload and
cannot hide missing artifacts. Failed-job provenance keeps its strict gate
with stage guidance even when independent artifact selection succeeds.
The indexed CI-private `ci/native/darwin/` owner adds native admission without
changing dispatch or production adapters. Its root launcher creates a fresh
audit session for an externally reserved non-login UID/GID, drops real/effective/
saved credentials, installs a reviewed Seatbelt profile and sanitizes inherited
descriptors and Mach rights. An ordinary host port is required because SIP
prevents clearing that special slot; privileged/unknown host or uncleared
task-access authority blocks launch. Root custody acquires the new session's
send right only after fork, and is tracked separately by stable native identity.
Thin x64 Mach-O structure, root-owned immutable bytes, native signature/CDHash,
permitted entitlements and independently reviewed loader closure precede literal
`execve`. A parked pipe barrier joins separately inspected task audit tokens,
BSD saved IDs/start identities, current-directory objects, private storage,
complete policy and protected receipts before release. Missing verification/
retirement owners retain BLOCKED;
failure closes the parked channel while retaining UID/storage exclusion. Root
session custody retains its reference after direct-child exit until a recovered
custodian is admitted and the old helper is stopped by verified native identity.
Account/setup/build, actual private API availability, policy source
arguments and native cases remain dedicated external prerequisites; pure tests
establish no native admission or source closure.
Darwin recovery reads candidate/digest-bound protected admission and optional
retirement receipts. Separate root audit custody survives old-launcher retirement;
private libproc task-token signalling replaces numeric-PID authority. A hard
inherited 32-process limit bounds complete UID enumeration. Bounded repeated
retirement requires a fresh independent zero-live-member view and exact helper
settlement before custody acknowledgement; UID/policy/storage reservations stay
retained. Unknown zombies, stale identities, partial views or exhausted budgets
cannot establish retirement. Indexed acknowledged native ownership fixtures
remain external; their pure OBSERVED protocol result cannot replace accepted
native inventory or independently reviewed source closure.
Darwin's indexed policy owner renders deny-default Seatbelt profiles with exact
immutable image and filesystem grants, plus no-state PF loopback rules checking
both sending and receiving UIDs for request and return traffic. Unconditional
endpoint blocks reject unknown owners. Protected external readers bind active
PF, root/anchor ordering, state/NAT/skip exclusions and exclusive reservations
before admission. A fixed native PF bridge separately admits and settles its
root helper and worker; writes affect only the owned anchor. Acknowledged access
fixtures join actual native attempts, ready outside controls and nonce bytes.
Recovery preserves policy; restoration requires fresh independent retirement,
no live reserved-UID process, helper/control settlement and unchanged owned
configuration. Missing native readers, SDK semantics or reviewed tool/runtime
closures keep execution blocked; pure tests establish no effective policy proof.
Darwin's confined file owner supplies a CI-only trusted helper with held root
and parent descriptors, native file/volume identities and fixed no-follow leaf
operations. Exclusive link publication explicitly accounts for its temporary
two-link alias; same-volume rename replaces complete bytes. Protected barriers
bind independent bytes and identities before continuation. Recovery reads
immutable receipts, requires fresh payload retirement and exact old-helper
settlement, and removes only revalidated owned objects. Unsupported volume
aliases, synchronization, substituted objects and unknown interruption state
retain reservations. New cleanup helpers settle independently; no universal
power-loss durability or native file acceptance follows from pure protocol tests.
Darwin's six external file cases join those sessions to protected native readers,
concurrent queued publication and complete old-or-new reader observations,
acknowledged substitution/alias controls and interruption/recovery receipts.
Private file and fixed-Git channels bound pending completion independently of
process-close events; native settlement remains a separate protected proof.
The separate disposable Git owner denies ordinary staging/commit attempts and
admits only a parked protected executor for the fixed synthetic edit and subject.
Independent object/ref/metadata comparisons retain identity, configuration,
remotes, witness refs and outside sentinels. Native Git children have separately
verified stable identities. Common pure commit predicates live in the native
evidence owner with Linux compatibility exports; platform effects remain private.
No provider receives this grant, and OBSERVED cases confer no native acceptance.
The indexed CI-private `ci/native/win32/` owner adds a separate LocalSystem/
session-0 launcher with a fresh batch-only non-login account, stripped low-integrity
restricted token, dedicated restricting SID and private DACL storage/desktop.
A protected no-breakaway Job receives the suspended payload through creation-time
attributes with an explicit two-pipe handle list and application path. Root
setup, complete external authority policy and suspended payload admission each
have a parked acknowledgement barrier; protected receipts and independent native
token, Job-object, creation-time, image/parser, policy and storage reads precede
release. Account/setup APIs belong to that launcher; WFP and verifier helpers have
separately bound stable identities and source pins. Literal UCRT fixture output
joins actual UTF-16 arguments to the private native image/current directory.
Missing SDK/loader/policy/observer/retirement inputs retain BLOCKED; faults retain
all reservations and never infer retirement from exit or Job-handle closure.
The inspected Codex creation-time attribute precedent confers no approval of its
complete released helper composition. No production adapter or dispatch grant
changes, and pure/injected tests establish no Windows acceptance/source closure.
Windows recovery joins protected admission and previous retirement receipts to
native account, Job and process creation identities. A separately admitted root
custodian seals old admissions, uses only verified held-Job termination, waits on
held processes and requires fresh independent principal/membership/holder reads
and exact helper settlement. Job disappearance authorizes no guessed-name or PID
killing: account reservations, complete native principal enumeration and verified
process waits remain mandatory. The bounded recovery owner retains all account,
ACL, filter, transport and storage reservations. Acknowledged native ownership
cases corroborate the separately reviewed restricted-token/object-access and
Job-inheritance composition; finite fixtures and producer counts prove neither
containment nor retirement. Unknown identities, incomplete views and deadlines
retain exclusion, including interruption before receipt publication.
The fixed Windows system entry now reconstructs partial build and case effects
from bounded protected ledgers and independently approved bootstrap assets,
without successful preparation or final helper outputs. Durable recovery intent
fences fresh admissions. Retained case owners attempt retirement before evidence
validation; case and build cleanup remain independently attempted, and the first
failure survives. Fresh observers rejoin native receipt parts, creator/worker
births, original object/security baselines and exact task registrations. Held
process/Job reads, complete principal/peer census and fresh account/rights,
registry/WFP and task observations establish settlement; old receipts supply
bindings, never fresh retirement. A fixed private nonce-bound inventory covers
all possible helper, custodian, witness and peer Jobs. These and compiler Job names
bind the held creator's PID and creation time, allowing successive bootstrap owners
to share the approved nonce without name collisions. Cold recovery reads the
complete inventory twice and rejects live members or missing proof even when every
recorded worker exited and fresh transfer slots are empty. The finite native
command grammar covers subsequent recovery and task removal as well as setup.
Explicit audit drain precedes unchanged owned restoration. Missing births,
baselines or drain proof retain exclusion. Only a
verified unchanged task with zero instances and retired held owners may be
removed. Component receipts precede outer-observer closure and cannot claim
whole-run retirement. Native Windows proof and independent source acceptance
remain external.
The Windows policy owner binds three restricted-token profiles to a closed
private DACL manifest. Workspace roots grant creation without delete-child or
root deletion. Admission requires independent source/native evidence that both
inherited and explicit creation DACLs preserve private access; the inherited
owner-rights template alone cannot establish that guarantee. Pointer, metadata,
custody, checkout, configuration, registry and synthetic credentials remain
protected. Trusted commands require
independently verified disposable storage; loader exceptions remain individually
reviewed and confer no host creation or service grant.
Persistent System-custodied WFP provider/sublayer filters check local principals
at IPv4/IPv6 connect and receive/accept layers. Exact reversed TCP/UDP endpoint
pairs and foreign reserved-port guards cover both ends. Independent effective
BFE/token/AccessCheck reads must establish complete precedence, loopback and
return-flow semantics without exemptions, unknown identity or an unfiltered
route. Fixture actors bind held creation identities and restricted tokens to the
exact admitted Job; retirement accounts for the complete recorded membership.
Ready controls, unchanged protected native identities/bytes and
socket-correlated permit/drop evidence corroborate access denial; TCP return
bytes bind the original authorized flow, and a pending connect or missing UDP
echo proves nothing. Acknowledged owner/helper loss retains the exact filters,
held file/registry identities, DACLs and private endpoint leases through
retirement and filter removal.
Only fresh receipt-bound principal retirement, settled helpers and absent
principal flows authorize exact owned-filter removal. Retirement accounts for
every privileged helper identity in the protected admission receipt. ACL,
account, registry, transport, storage and provider/sublayer reservations remain
retained. Missing native bridges/SDK/observer review, creation-DACL protection
evidence and external Windows acceptance remain explicit exclusions.
Windows files add a separate indexed System/session-0 helper and protected
controller. Inherited private DACL base/root handles anchor fixed-leaf
`NtCreateFile` operations; volume/file IDs, streams, canonical spelling, link
counts and reparse rejection exclude foreign aliases. Exclusive complete link
publication admits only its recorded temporary two-link state. Same-volume
POSIX-style native rename/disposition preserves held readers without a legacy
fallback. Supported file flushing claims no power-loss durability.
Write-ahead intents, independent identity/byte receipts and acknowledged barriers
precede effects and continuations. Protected recovery joins retained objects to
fresh current-state-bound prior-principal/helper retirement before revalidating
legal interrupted states and removing only owned links and an empty directory.
No uncertain path is recursively deleted. External held-image/loader admission and exact inherited
handles remain required; bounded pure sessions and injected tests confer neither
Windows 2025 sharing proof nor release/source closure.
Reviewed Windows 2025 envelope verification precedes helper creation. Monotonic
session deadlines fence callbacks before invocation even when timer delivery is delayed.
The indexed Windows file cases compose all six records using independent native
identities/bytes, overlapping caller/reader controls, acknowledged substitutions
and interrupted owned recovery. Separate CI-only Git fixtures add exact literal
arguments, immutable package/loader admission and complete protected snapshots.
The read-grant helper touches only held synthetic metadata/hooks/content objects;
ordinary profiles gain no metadata or pointer mutation. The System fixed grant
parks each Job-born Git child for independent admission before resume. Common
pure Git predicates preserve exact subject/content/parent, identity/configuration,
remotes, unrelated refs and the bounded metadata effects. Failed or ambiguous
controls retain all possible effects and reservations for independent retirement.
All native effects remain behind the Windows index and protected external bridges.

Windows effective readers extend the sealed custody reader with actual ACL/MIC,
restricted-token, change-notified registry and persistent WFP object/condition
reads. Approved template/provisioning bindings select permitted objects; observed
identities, native AccessCheck/mandatory-label decisions and repeated installed
graph reads establish concrete policy. Global reads preserve native filter values
and sublayer precedence; independent coverage must bind that actual graph digest.
Paired AccessCheck controls verify restricted read enforcement. Temporary native
verifier reads preserve its live identity without retaining it as a payload
member. Explicit retired snapshots require fresh whole-domain proof and use the
held token to verify installed state or owned-filter absence after removal.
Complete host/creation/handle/endpoint and
global flow/precedence coverage still requires separate independent native proof.
Explicitly reviewed mutable leaves permit shared writes; all held leaves and
ancestors exclude shared deletion, and executable/toolchain inputs stay immutable.
Held byte/ancestor/tree barriers join protected sentinels and Git snapshots.

The indexed Windows audit owner snapshots system policy without modifying it,
persists intent and changes only a new per-principal entry and owned label-only
SACLs. Native setup checks all approved descriptor and system-audit digests before its
first write. Independent exclusive-writer/closed-admission proofs gate setup and
restoration; pending restoration fences new custody and settled setup is one-shot.
The private observer pipe has acknowledged subscription and sequenced time
barriers; bounded XmlLite decoding joins actual Security event fields to
held process/token/Job/object observations and reviewed SDK versions. The query
selects failed handle-open and successful access events; event-specific network
PID fields, parsed addresses and joined ABI pins prevent schema substitution.
Raw XML and
selectors stay in protected memory/transport; persisted command intents contain
digests. Loss/clear, malformed records, missing coverage or uncertain retirement
remain failures. Payload retirement and independent observer retirement/EOF
precede restoration, which rechecks the complete installed snapshot and native
security descriptors, then independently verifies only its owned restoration.
These effect-free adapters add no production dispatch, factory preparation,
global audit change or native acceptance claim.
Version-6 composition dispatches the indexed macOS/Windows owners only after
protected source, release and fixed execution-plan admission. Missing preparation,
readers, policy or retirement capabilities preserve BLOCKED. Protected provider
dispatch requires separately approved operator authority and settled same-candidate
system evidence. Native cases execute only in external CI, never ordinary
discovery or local finalization; no native acceptance is established locally.

The CI-private `providers/` index owns private Codex/Claude invocation adapters,
a bounded standard-library relay and a credential-free broker, using platform
indexes for actual package/ABI launch. Linux reuses owned-process admission with
a parked native exec and immutable bubblewrap bindings; its bridge joins only the
private network namespace through a held descriptor and never the payload PID/user
namespace. Darwin/Windows version-2 launch/policy contracts add reviewed image
lengths, separate private stdio, writable private home/cache and one exclusive
broker endpoint with independently verified root/System receiving custody. Earlier
fixture semantics remain intact. Real credentials reach only the separately
admitted relay through a protected pipe; providers receive a non-secret token.
Fixed upstream/method/path/model grants, reviewed inclusive cost bounds,
JSON/SSE error redaction and non-resetting deadlines close failed capabilities.
Native controls and independent observations precede transport results; verified
retirement and owned-only restoration follow, retaining uncertain exclusion.
These short-lived external CI fixtures have no production consumer and supply no
model-tool mediation, catalog PASS, source closure or native GO by themselves.

The private Codex mediation owner adds bounded App Server model turns after
transport admission and native observer controls. Source-supported never-ask
ExternalSandbox turns use the fixed broker, with effective registry/configuration
and live package/dependency/ABI/policy inspection after thread creation, before
tool turns, and after execution. Protected receipts additionally bind the actual
model-facing tool array to its reviewed registry digest.
Fourteen fixed cases per ordinary platform/profile require actual command and
apply_patch events, nonce-backed inspection, intended bytes or denial, prohibited
Git/outside/credential/network/IPC dispatch and background confinement. A separate
protected relay receipt pipe binds upstream completion to each thread/turn; only
hashes and synthetic metadata survive. Native events, independent state and complete
observer/transport retirement join before MEDIATION_OBSERVED, retaining exclusion
on failure. The native documentation owns exact controls/source contracts. This
CI-private owner has no production consumer and does not close catalog/source
acceptance; external protected aggregation remains separate.

The private Claude mediation owner runs the exact opaque native package with
private home/configuration, non-secret relay transport and release-supported bare,
settings/tool and unattended controls inside the same outer authority. Nineteen
fresh cases per platform/profile require Bash, Read/Glob/Grep/Edit/Write effects
or OS denials, prohibited Git/outside/credential/network/IPC dispatch, background
cancellation/helper-loss settlement and EndConversation dispatch. The published
terminal route is covered explicitly; no internal dispatcher guarantee is inferred.
Protected Anthropic receipts bind actual assistant message/tool IDs, tool names,
normalized input digests and dispatch order, rendered registry, model and complete
response to native observer events, independent state
and settled custody. Windows additionally binds reviewed native Git for Windows
Bash to immutable private images, loader grants and the same restricted token/Job;
WSL and fallback are rejected. Fault effects remain platform-owned and run after
independent event/byte reads. Bounded metadata-only receipts retain exclusion on
missing proof or uncertain retirement. CASE_MEDIATION_OBSERVED covers one case;
all cases still require protected aggregation. Claude's dispatcher remains
UNAVAILABLE, and moving wrapper/CLI documentation supplies no source closure.
Local effect-free coverage supplies no catalog PASS or external native GO.

## Root Runner Ownership

- CLI parsing, pipeline selection, and concise terminal output.
- Local STDIO MCP tool schemas, projections, and detached-run dispatch.
- Versioned runner configuration loading, validation, and role resolution.
- Run IDs, atomic state, append-only events, resume, and status.
- Clarification files, editor invocation, transcript updates, and input hashes.
- Common operator guidance, complete local additions, and safe durable replacement.
- Frozen provider registration plus adapter execution and access-mode
  enforcement.
- Git snapshots, content fingerprints, read-only guards, remote/identity guards,
  constrained local-commit verification, and verified polishing staging
  handoffs.
- Runner-trusted exact-vector validation outside agent turns, with bounded
  results and repository mutation guards.
- Static pipeline registration.

The root is one application, so these modules are not separate workspace
packages. Extract one only after it gains an independent consumer, release
lifecycle, or dependency boundary.

Each JavaScript source directory exposes outward-facing dependencies through
its `index.js`. Imports between modules in the same directory remain direct to
keep ownership visible and avoid barrel cycles. The source-boundary regression
checks those imports and the root-to-pipeline-to-shared-package dependency
direction from source and workspace manifests.

The state capability lives under `src/state/` behind its public `index.js`.
The index exposes only the run-store and runtime contracts used outside the
capability; its private service composes confined file operations, the
write-ahead journal, durable actions, execution leases, and state validation.

The Git capability lives under `src/git/` behind its public `index.js`. The
small index exposes only the service factory and shared safety error; its
private service composes command execution, content and snapshot inspection,
exact source materialization, commit verification, and polishing handoff
modules without exposing their implementation contracts to root consumers.

`inspectHead` reads the current commit object ID and that immutable object's
subject, including unborn HEAD as `{head: null, subject: null}`. Plan execution
uses this observation before writable entry and ahead of generic resume or
interruption drift handling. An exact leading-plan subject already at HEAD, or
external HEAD movement from the saved baseline, requires plan revision without
adopting the commit. Consumed runner-authorized commits settle verification-only
first; only that verified settlement changes plan progress.

Plan execution owns bounded step assessments and semantic context validation in
its private `plan-position.js` contract. Every context-producing phase receives
the runner-selected subject and verified completion evidence. A separate
read-only review checks narrative directions before acceptance; matching fields
cannot override contradictory prose. Its `plan-context` interruption marker
requires read-only reconciliation before replaying the producing checkpoint.
Version-19 migration invalidates legacy context before writable work while
preserving verification-only settlement of consumed commits. Root Git remains
the observation authority; agents and summaries never select the next step.

Plan execution also owns durable initial-implementation evidence. Its
`implementation-evidence.js` contract separates the original step/HEAD/content
baseline from mutable repository snapshots and reconstructs legacy evidence only
from the state-owned validated journal. State version 20 persists that evidence
before writable implementation and rejects unchanged initial results before
candidate convergence. Corrections retain their existing unchanged-result semantics;
verified commit settlement alone resets the record for the next step. Consumed
effects and stop recovery remain ahead of preparation for new writable work.

The trusted-validation capability lives under `src/trusted-validation/` behind
its public `index.js`. The index exposes only the contracts consumed by the
root runtime and capability tests; private service and execution modules keep
snapshot validation, exact command vectors, sandboxing, bounded evidence, and
repository mutation guards within the capability.

The configuration capability lives under `src/config/` behind its public
`index.js`. Strict runner and project parsing, confined file loading, trusted
profile interpretation, and precedence-based resolution remain private,
acyclic modules. Root consumers use only the index, while pipeline descriptors
continue to own role lists, settings, defaults, and persisted-run validation.

The runner capability lives under `src/runner/` behind its public `index.js`.
Private modules keep input normalization, role adapters and source-session
setup, pipeline migration, and run and resume orchestration distinct and
acyclic. Root consumers use the index; orchestration composes the other root
capabilities without exposing their private modules or moving workflow policy
out of pipeline descriptors.

The MCP capability lives under `src/mcp/` behind its public `index.js`. The
index exposes only the control-plane and STDIO server contracts consumed by
the root runtime and capability tests; private service and reporting modules
keep protocol schemas, projections, revision waits, detached dispatch, and
local issue publication within the capability.

The Claude provider lives under `src/agents/claude/` behind its provider
`index.js`. The root agent boundary imports only that index; the adapter,
local-commit executor, and isolation-policy selector remain private siblings
that own Claude processes, flags, parsing, sessions, sandbox composition, and
native failure recognition.

The Codex provider lives under `src/agents/codex/` behind its provider
`index.js`. The root agent boundary imports only that index; the adapter, App
Server transport, local-commit executor, and workspace storage remain private
siblings that own Codex processes, protocols, flags, parsing, and sessions.
The private Codex `schema.js` validates the effective response schema before
any provider activity in `run`, including local-commit readiness. Its recursive
keyword allowlist and structural checks supplement the shared JSON,
strict-object, size, and depth checks without imposing Codex restrictions on
other adapters. It traverses schema positions rather than property names or
literal data, permits resolved local recursive references, and rejects
unsupported declarations with terminal `ERR_INVALID_CODEX_SCHEMA` before
probing, spawning, or recovery. This input-contract error is neither backend
unavailability nor malformed-output correction. Pipeline-owned normalizers
remain authoritative for semantic constraints such as terminal finding-ID
uniqueness that the portable response schemas cannot express.

The root `src/agents/index.js` is the only agent API consumed outside the agent
capability. Its private `registry.js` defines one frozen, source-controlled
descriptor per provider. A descriptor binds the backend ID to its adapter
factory, client-attribution support, execution-option validation,
trusted-profile normalization and resolution, source-session fork capability,
and one `failures` hook containing a finite class set and classifier. The
classifier is provider-private; the registry validates its provider-neutral
result before the public agent boundary exposes it. Configuration validation,
runner adapter construction and source checks, normalized failures, and MCP
backend schemas all derive from that registry. Tests may inject another complete
descriptor; production has no dynamic discovery, plugin loading, or
provider-specific pipeline branches.

The public agent boundary owns one strict, frozen client-attribution shape with
exactly `name` and `title`, plus the generic `agent_runner` / `Agent Runner`
default. Both strings are non-empty, trimmed, bounded to 256 characters, and
free of unsafe control, line-separator, and bidirectional formatting
characters. Registry construction passes only a normalized frozen value into
each adapter factory, while the descriptor states whether a provider can
transport a custom value. Codex sends both strings through App Server
`clientInfo` and keeps the package version in that same handshake. Claude's
documented CLI has no client-identity transport: its generic default remains
usable, while a custom value fails its capability probe before provider
activity. Neither adapter maps client attribution into native session names,
commit attribution, or undocumented environment variables, and bounded
failures retain none of its values. Provider-visible origin identity does not
promise a distinct provider dashboard category.

## Pipeline Ownership

Each pipeline owns its input interpretation, roles, configuration settings and
defaults, accepted `run` options, prompts, structured-output schemas, explicit
JavaScript state machine, retry policy, and completion criteria. Roles, settings,
accepted and required options, task-input definitions, clarification and status
projections, resume-action validation, and persisted-run validation are exposed
through its static descriptor. The descriptor also selects the active roles
from its resolved settings, including all mode semantics; pipeline states remain
workspace-owned rather than becoming root runtime policy.

Execution's private `mode-policy.js` separates active roles, independent
bootstrap, primary convergence, independent review, terminal confirmer,
arbitration, and primary session scope. The workflow, persisted-state validator,
resume-action checks, migrations, and journal-proven confirmation recovery use
those decisions. Ordinary and stop-reconciled content repairs rejoin the same
candidate checkpoint. Session selection preserves one run-wide Worker source
fork in lazy mode, checkpoint forks in independent and combined modes, and fresh arbitration
and output-correction contexts. Permissions, one-shot commit verification, and bounded
correction accounting remain with their existing workflow operations; policy
selection grants no additional repository authority.

Combined execution runs Worker check/fix and a separate read-only clean
confirmation before the complete independent candidate Reviewer gate. Both
candidate approvals bind the same content fingerprint. Finalization may format
that content; a distinct Reviewer terminal confirmation approves its resulting
fingerprint and validation evidence before one-shot commit authorization.
Content repairs restart primary convergence. Self-findings go directly to fixing;
independent findings retain disputes, withdrawals, exact recorded overrides, and
fresh on-demand arbitration. Unresolved bootstrap disagreements and primary
exhaustion pause without arbitration. Corrections remain bounded and interrupted
work is charged once; resume preserves the saved mode and consumed commits remain
verification-only.

Execution's private `gate-evidence.js` composes primary clean evidence,
independent candidate approval, passing finalization, and terminal confirmation.
Persisted validation, normal routing, migration invalidation, journal-proven
recovery, stop reconciliation, and new commit authorization share these predicates
and resets. Candidate approval stays bound to the inspected content; finalization
may format it, so its resulting fingerprint requires distinct terminal approval.
Content repairs clear dependent evidence. Unchanged resolutions reconverge the
candidate and retain passing finalization only subject to fresh content and
infrastructure checks. Correction ledgers keep their existing bounded accounting.
Execution state version 17 adds bounded `primaryFindings` without renaming the
persisted lazy correction ledger. Leased version-16 migration adds an empty list
and preserves saved mode, counters, gate evidence, and pending effects. Combined
primary proof and independent approval remain distinct, including journal-proven
confirmation recovery.
Consumed effects still bypass new authorization and use verification-only recovery;
the shared predicates neither replace journal provenance nor grant Git authority.

The root CLI owns `--clarify` as a common run-lifecycle option. Role and
pipeline-specific options remain in pipeline descriptors.

V1 registers:

- `plan-authoring`: produces a validated `plan.md` without changing target Git
  history.
- `plan-execution`: consumes `plan.md` and implements one reviewed local commit
  per step.
- `polishing`: polishes, finalizes, and reviews an existing dirty worktree, then
  stages the complete result while leaving it uncommitted.

Polishing's private `mode-policy.js` separates active roles, bootstrap
independence, primary convergence, independent review, terminal confirmer,
arbitration eligibility, and primary session scope. Its workflow, persisted
validator, resume checks, and legacy migrations share those decisions. Ordinary
and interrupted repairs return through the same candidate checkpoint. Lazy keeps
one run-wide Worker source fork; independent checkpoints remain isolated and
Arbiter and correction contexts remain fresh. Persisted correction shapes and
budgets do not change. No policy grants index authority: staging remains the
runner-owned handoff effect. Polishing accepts independent, lazy, and combined.

Polishing's private `gate-evidence.js` composes primary clean, independent
candidate, finalization, terminal-confirmation, and handoff predicates. Routing,
persisted validation, legacy migration, and handoff authorization share these
checks. Candidate approval binds its inspected fingerprint; finalization can
format it into a different fingerprint that needs distinct terminal approval.
Content repair clears dependent evidence. Unchanged resolution retains only
fingerprint-bound passing finalization, subject to live content and infrastructure
rechecks after reconvergence. Legacy active evidence reconverges under the lease;
accepted handoff evidence survives migration and completed effects remain
verification-only. No persisted shape, mode, correction budget, or index permission
changes.

The pipeline registry is static. V1 has no dynamic plugins, workflow DSL, or
generic DAG executor.

## Runner Configuration

Root and safe project configuration accept `maxEventLogBytes`, a numeric integer
from `1` through `2147483647` bytes, defaulting to `536870912` (512 MiB).
Configuration validates it through the public state storage-policy contract;
project capacity overrides root capacity. `src/runner/store.js` supplies one
configuration-to-store composition path for ordinary Runner and shared MCP
construction, including detached continuations and direct state mutations.
State receives the resolved policy through `createRunStore` and never loads
configuration. Explicitly injected stores retain their policy.

Capacity is an explicit storage-only exception to workflow configuration
freezing. Each append loads current root policy and identity-verifies only the
originally protected project overlay before reading its capacity, without
re-resolving roles, settings, commands, or inputs. Legacy runs without protection
never discover an overlay. Protected project configuration cannot change during
recovery; public consumers may construct a store with a larger explicit capacity.
`createRunStore.maxEventLogBytes` accepts either a validated integer or a callback
receiving immutable run state, resolved and validated before each append,
permitting same-Runner injected-policy retry. There are no provider branches,
environment policy, CLI flags, or MCP schemas for capacity.

The root runtime reads an optional `.agent-runner.json` from the Agent Runner
repository root, beside its tracked `.agent-runner.example.json`. That file is
the only source of trusted profile implementations. It may also supply runner
defaults for backends, execution preferences, pipeline limits, and the
repository-relative artifact root. The loader never rewrites it, and the local
runtime file remains ignored and untracked.

For a new run, the root also discovers an optional ignored and untracked
`<project>/LOCAL_ARTIFACTS/agent-runner.json`, or uses an explicitly selected
confined project path from CLI/MCP. Both files require `schemaVersion: 1`;
unknown versions, pipelines, roles, settings, and fields are errors. Project
configuration may define exact trusted commands, select trusted aliases,
override execution defaults, pipeline roles and settings, and select a normalized
repository-relative artifact root. It cannot define profiles, credentials,
provider binaries, or arbitrary environment values. Tracked, non-ignored,
missing explicit, traversing, and symbolic-link paths are rejected without
creating a file or changing ignore rules.

The confined read that supplies parsed project values also produces a
versioned protection record. It pins the canonical project and file paths,
repository-relative location, SHA-256 content hash, device/inode and bounded
file metadata, plus device/inode evidence for every real directory from the
project root to the file's parent. The initial read and every later inspection
use a bounded no-follow descriptor and compare path, descriptor, and ancestor
identity before and after reading. A project configuration must have one hard
link.

The V1 shape is:

```json
{
  "schemaVersion": 1,
  "artifactRoot": "LOCAL_ARTIFACTS",
  "maxEventLogBytes": 536870912,
  "issueReporting": true,
  "clientAttribution": {
    "name": "agent_runner",
    "title": "Agent Runner"
  },
  "defaultBackend": "codex",
  "defaultProfile": "current",
  "defaultModel": "current",
  "defaultEffort": "current",
  "defaultContextSize": "current",
  "trustedCommandTimeoutMs": 3600000,
  "availabilityRetryMaxDelayMs": 1800000,
  "providerInactivityTimeoutMs": 1800000,
  "profiles": {
    "codex-work": {
      "backend": "codex",
      "profile": "work"
    },
    "claude-primary": {
      "backend": "claude",
      "configDirectory": "/profiles/claude-primary"
    }
  },
  "trustedCommands": {
    "service-tests": {
      "command": "npm run test:service",
      "executable": "npm",
      "arguments": ["run", "test:service"]
    }
  },
  "pipelines": {
    "plan-execution": {
      "mode": "independent",
      "finalization": "auto",
      "trustedChecks": ["service-tests"],
      "maxFixRoundsPerStep": 20,
      "roles": {
        "worker": {
          "backend": "claude",
          "profile": "claude-primary",
          "model": "sonnet",
          "contextSize": "200000"
        }
      }
    }
  }
}
```

`issueReporting` is runner-local, defaults to `true`, and is not accepted in a
project configuration. The MCP process loads it once at startup; applying a
change requires a restart. A disabled server omits the reporting tool, schema,
and related instructions from discovery. Other runner settings are reloaded
for each fresh report and persisted through its resolved reservation.

`clientAttribution` is also runner-root-only and defaults to the generic
`agent_runner` / `Agent Runner` identity. Configuration uses the public agent
contract to normalize the exact `{ name, title }` object, then rejects a custom
value when any active role's provider descriptor does not support it. There is
no project, CLI, MCP, pipeline, prompt, or repository-content override. The
normalized value and its SHA-256 fingerprint are immutable common run-envelope
fields. Production adapter sets are constructed through provider descriptors
from the resolved frozen value during creation and from the saved value on
resume; current configuration cannot replace it. Prompts, activity, public
status, and diagnostics omit both fields.

`trustedCommandTimeoutMs` is accepted by root and safe project configuration as
a strict integer from `1` through `2147483647` milliseconds and defaults to
`3600000` (60 minutes). The project value overrides the root value. It has no
CLI or MCP override because configuration resolution, not a transport-specific
surface, owns the deadline.

`availabilityRetryMaxDelayMs` is a common root/project setting, a strict integer
from `5000` through `2147483647` milliseconds, defaulting to `1800000` (30
minutes). Project configuration overrides root configuration; CLI, MCP, roles,
and pipelines do not introduce separate ceilings. Resolution freezes
`availabilityPolicy: { initialDelayMs: 5000, maxDelayMs }` when creating the run.
The state boundary owns the validated policy and deterministic schedule;
configuration consumes it through the public state index.

`defaultBackend` is optional. A role's `profile`, `model`, `contextSize`, and
`effort` resolve from its role-specific override, the run-wide override, its
project-role value, the corresponding project-wide default, its pipeline-role
runner value, the corresponding runner-wide default, then the built-in string
`current`; a role-specific CLI override has highest precedence. CLI/MCP expose
profile, model, context size, and effort through the same runner input contract.
CLI uses `--effort` and descriptor-derived `--<role>-effort`; MCP uses `effort`
and `roleOverrides.<role>.effort`. Both validate the portable enum before
dispatch. MCP action identities include both selections before mutation;
detached continuations resume the saved run without re-resolving them. Explicit
CLI/MCP pipeline-setting overrides take precedence over project pipeline
settings, which take precedence over runner settings and descriptor defaults.
A profile alias is trusted runner configuration, pins one backend, and maps
only to a native Codex profile name or an isolated Claude configuration
directory. A conflicting explicit backend is invalid; profile configuration
cannot inject credentials, binaries, or arbitrary environment variables.
Without a selected profile, the backend resolves from the role override,
pipeline-role value, then `defaultBackend`; absence is a preflight error.

`current` omits that native override. For models this means both Codex and
Claude use the model selected by their effective native profile, process, or
backend native default; Agent Runner does not hard-code a backend model ID. An
explicit context size is a decimal token string validated by the selected
adapter and mapped to Codex's context-window setting or Claude's
auto-compaction token window. These controls are not treated as otherwise
equivalent.

Both configuration layers accept `defaultEffort` and role `effort` using only
`current|low|medium|high|xhigh`. Vocabulary validation includes inactive roles;
provider capability validation applies only to resolved active roles. Effort
remains separate from model IDs, and native translation belongs to adapters.
An explicit `current` at any precedence level retains the effective provider
default instead of inheriting a lower-precedence effort selection.

Pipeline descriptors validate their own settings and supply built-in defaults.
The root loader owns only the versioned envelope, strict field validation, and
resolution precedence; it does not duplicate pipeline-specific role or setting
lists.

Plan authoring additionally owns the positive-safe-integer
`preferredCommitLineLimit`, default 900. Root configuration and a safe project
overlay resolve it through existing precedence before creation. It is a prompt
heuristic for anticipated additions plus deletions, including tests and
documentation: prefer cohesive commits within the target and explain genuinely
indivisible exceptions. It changes neither the shared plan contract nor execution
validation. Authoring state version 4 persists the value; the ordered version-3
migration supplies 900 to non-null legacy settings without configuration reload,
progress changes, or effect replay. The existing lease governs persistence of
that migration. Authoring planning, review, self-review, and recovery prompts
use the saved value. CLI `pipelines` displays descriptor-owned setting defaults;
MCP `pipelines_list` projects the same metadata.

Every built-in descriptor owns one string `mode` setting supporting
`independent`, `lazy`, and `combined`. A missing value resolves to
`independent`, which is the default and recommended option because its distinct primary and review
roles provide genuinely independent semantic review. That independence uses
more provider context and tokens. `lazy` is an explicit lower-consumption
choice that uses only the Planner for plan authoring or the Worker for execution
and polishing and does not provide independent review. Neither the root runner
nor a pipeline may select it automatically.

Runner and project configuration are deterministically validated for every
declared role. After settings resolve, the descriptor selects active roles.
Only those roles are resolved to a backend, profile, model, context size, and
effort; only they are probed, persisted in the run, checked against a source session,
and invoked. Public projections may identify an active role for bounded
activity, but expose neither provider-private values nor inactive role
configuration. Inactive Reviewer and Arbiter values remain untouched in the
configuration source for a later independent run. The resolved mode is
persisted when the run is created and is never reloaded on resume.

Plan execution and polishing own a string `finalization` setting. `auto`, the
default, discovers a conventional confined repository skill and otherwise
falls back to repository instructions and project-defined checks. `none`
selects that fallback directly. Any other accepted value is a normalized
repository-relative `SKILL.md` path; a missing or unsafe explicit path blocks
the run. Runner configuration supplies the base value and a safe project
overlay may replace it. The configured policy is persisted with the other
pipeline settings; each owning workflow separately freezes the effective
guidance decision and does not reload it on resume.

Plan execution resolves its effective guidance through the root Git inspection
and validation-infrastructure fingerprint capabilities after Git preflight and
before bootstrap. Its pipeline state separately freezes the configured policy,
selected canonical regular repository-relative skill or fallback decision,
selected-file fingerprint when applicable, and complete decision fingerprint.
Bootstrap and validation migration receive only that path or fallback, never
copied skill content, and no additional provider checkpoint is introduced. The
selected skill is part of established validation infrastructure. Execution
rechecks its exact path and fingerprint before guidance-consuming, correction,
and resumed work. Missing, invalid, or changed frozen guidance requires a fresh
run; automatic selection never switches late. This decision does not replace
the frozen trusted-validation snapshot, exact inventory matching, capability
reports, environment blockers, or requirement inspection.

Polishing owns the same behavior through its separate workflow, schemas,
prompts, state validation, migration, and public pause projection; it does not
import plan-execution internals. It freezes guidance after dirty-worktree Git
preflight and before backend probing or bootstrap, includes any selected skill
in established validation infrastructure, and rechecks the exact path and
fingerprint before guidance-consuming, correction, and resumed work. Missing,
invalid, or changed guidance requires a fresh run while environment blockers
retain their existing resumable checkpoints. Completed `HANDOFF` recovery stays
verification-only, index mutation remains runner-owned, and no extra provider
turn is added.

`trustedCommands` is accepted in root and safe project configuration through
the same exact-vector validator. Each lowercase alias binds one exact inventory
command to one executable and argument vector. Definitions reject shell-string
substitutes and environment, credential, or host-authority fields.
Configuration privately merges normalized root then project catalogs in stable
order, deduplicates identical same-name definitions, and rejects conflicts even
when unselected. The merged catalog accepts at most 256 definitions, while each
immutable run snapshot remains limited to 32 selected commands. Direct argument
strings may contain line feeds for exact multiline scripts; other control
characters remain invalid. Plan execution and polishing each own a
`trustedChecks` setting; an ignored project configuration may replace that
pipeline's selection with root or project aliases. The default selection is
empty, and selected order determines snapshot order. Profile implementations
and trusted execution policy remain runner-owned. Before agent work, the root
resolves it into an immutable snapshot containing every selected vector,
deterministic command identities, an ordered command fingerprint, and a
trusted-configuration fingerprint. Resume uses that durable snapshot without
reloading either configuration source. Later project configuration changes
remain subject to the protected-input guard.

## Run Lifecycle

The root runner resolves the canonical Git root, safely loads runner and
project configuration, applies run-wide, role-specific, and accepted
pipeline-setting overrides, asks the descriptor for the active roles, and
persists those resolved roles, the resolved settings, artifact root, and
optional source-session reference and profile before pipeline work begins.
Common run-envelope version 8 persists effort for every active role and retains
the optional project-configuration protection record. Older runs normalize the
absent protection record to `null`; migration
never fabricates evidence by inspecting a current file.
Common run-envelope version 13 adds a provider-neutral policy-receipt slot for
every resolved role. A receipt contains only schema version `1`, a SHA-256 policy
fingerprint, and ordered supported access modes; it contains no provider flags,
payloads, prompts, credentials, stderr, or session storage. New runs persist
required-role receipts at capability preflight. Version-12 and older runs
migrate under the execution lease with null receipts before provider work and
then pin each required role's first valid receipt. Resume and reconstruction
reproduce the receipt before provider invocation; later policy drift fails
closed. The on-demand Arbiter receipt is pinned when first used. Pipeline
descriptors own role access requirements, so CLI and MCP receive the same
bounded `ERR_UNSUPPORTED_BACKEND` diagnosis without provider branches.
`run` then holds the new run's per-run lease while invoking its statically
registered workflow. Plan execution and polishing additionally hold one external lease
keyed by the canonical Git worktree before any workflow-owned mutation. The
runner always acquires the per-run lease first and releases the worktree lease
first. The narrow exception is plan execution's descriptor-proven initial
`CLARIFY` stop checkpoint: the runner retains the per-run lease but settles the
stop through the state-owned atomic checkpoint without acquiring an unrelated
canonical-worktree lease. Every checkpoint that may require repository
reconciliation or effect verification still requires the worktree lease.
`resume` recovers the durable event history and reconstructs the same
runtime from persisted state without reloading either configuration source or
requiring a live native session. `status` remains lock-free.

The root runner, rather than a pipeline or provider, checks a non-null
protection record before recovery and stop reconciliation, immediately before
and after every provider turn, and before trusted execution, commit
authorization/consumption, and handoff. Removal, content drift, same-content
replacement, hard or symbolic links, changed ignored/tracked status, or
ancestor substitution produces only `ERR_PROJECT_CONFIGURATION_CHANGED` and
the bounded non-resumable `project_configuration_changed` pause. It does not
restore or replace the file. If an irreversible commit or handoff effect has
already begun, its existing verification-only accounting remains authoritative
before further execution is blocked.

`artifactRoot` defaults to `LOCAL_ARTIFACTS`. Plan execution and polishing use
it only for runner-owned repository-local artifacts beneath
`<artifactRoot>/agent-runner/<run-id>/`; ignored-path, traversal, symlink,
overlap, and fingerprint guards apply to the resolved path. Legacy runs with no
persisted selection retain `LOCAL_ARTIFACTS`. Plan authoring continues to keep
its task-owned `clarifications.md` and `plan.md` beside `task.md`.

`--fork-from <backend>:<session-id>` is accepted only on a new run. The session
ID remains opaque after the first separator; `--fork-profile <alias>` supplies
its optional trusted profile without changing that syntax. Every participating
primary or review role must use the source backend and support native forking.
When the source profile is known, its `current` selections inherit that profile
and every explicit participating-role selection must match. When it is unknown,
participating roles must remain `current`, no native profile override is
supplied, and unavailable native forking fails closed. In independent mode,
each primary and review checkpoint's first eligible turn forks the source
directly and independently, while the Arbiter remains unconstrained. In lazy
mode, the source is forked exactly once into the
logical primary role for the entire run. Later checkpoints continue the
compatible child or reconstruct the same logical role in a disposable session;
they never fork the source again. Resume uses the persisted source, profile,
child lineage, and one-time lazy-fork marker and never asks for the flags again.

The CLI renders only persisted public activity and a concise current-state
projection. A user-action pause has a distinct exit status from an internal
failure; neither status output nor activity rendering exposes raw prompts or
model transcripts.

Each descriptor also owns a bounded public pause projection. CLI status, MCP
status, and MCP wait render that same projection as `null` or an object with
the finite public `reason`, an optional validated bounded diagnostic `code`, a
concise `explanation`, bounded `evidence`, the validated `resumeState` when one
exists, and `nextActions`. No other persisted pause field crosses this boundary:
in particular prompts, transcripts, credentials, native responses, raw
standard error, rejected values, internal diagnostics, and counters remain private.
Unknown pause reasons fail closed to `unknown_pause` without their persisted
text. A pipeline descriptor may derive bounded evidence from already validated
pipeline state when the derivation exposes only finite public identifiers;
`authentication_required` always projects the fixed
`ERR_AUTHENTICATION_REQUIRED` code, a fixed reauthentication explanation, the
saved logical checkpoint, and one null resume action. Provider-native
diagnostics never participate in that projection.
plan-execution finalization-backed `no_progress` exposes only the active
finalization issue IDs and never their commands, problems, evidence, or paths.
Plan execution also projects `finalization_transition_invalid` as a resumable
`FINALIZE` checkpoint with a fixed bounded diagnostic when an unexpected
runner-owned finalization invariant rejects advancement. The retained state
contains neither the rejected evidence record nor provider, prompt,
transcript, trusted-process-output, or detached-log data.

Public next actions are concrete descriptor-owned operations. `respond`
identifies the exact pending request; `resume` carries either the validated
null retry or one valid extra-round or finding-override payload; and
`start-new-run` identifies a `revised-plan`, `uncontaminated-worktree`, or
`resolved-finalization-blockers` requirement. The last applies when correction
has stopped with unresolved finalization failures and no validated retry
applies; it requires resolving the reported blockers, restoring a clean
baseline, and preparing a plan for the remaining work before starting a fresh
execution run. A submitted input awaiting detached continuation exposes no
second action. Plan revision never projects resume of the stale run, and a
read-only repository mutation never projects acceptance of contaminated or
hybrid changes. This is a read-only projection of existing durable state and
does not change the root or pipeline state versions.

## Operator Guidance

The installed [operator guide](OPERATOR_GUIDE.md) owns the canonical CLI/MCP
procedure for optional supervision, reporting ongoing launches, and recovery
within Runner workflows. It distinguishes expected pauses, genuine unexpected
defects, and stable project lessons. Valid dirty work from a genuinely
non-resumable run may enter polishing after ownership ends and inputs are
reconciled, preserving contamination safeguards and the uncommitted outcome.

The guidance capability lives under `src/guidance/` behind its public `index.js`.
Private content, contract, file, and service modules own composition, configuration
selection, confined access, and durable replacement. Its factory is deliberately
exported from `src/index.js`; transports consume the same capability rather
than duplicating policy. No pipeline depends on it.

`createGuidanceService().read({ projectPath, projectConfigurationPath? })` loads
the common guide from the installed runner and uses public configuration and
Git services to resolve `<artifactRoot>/agent-runner/rules.md`. Its result
contains canonical project/local/configuration paths, complete `commonContent`
and `localContent`, `combinedContent`, and `localHash`. Rendering separates the
documents and states that local additions cannot weaken common safety or
product contracts. Missing local content is an empty string with a null hash;
an existing document, including an empty one, has a SHA-256 hash. Reading
creates neither local artifacts nor external state.

Both documents have a 64 KiB UTF-8 byte limit. Reads and replacements reject
invalid encoding, unsafe control characters, and recognizable credential or
provider-transcript formats without echoing or partially redacting content.
Operators remain responsible for excluding sensitive material that cannot be
recognized deterministically. Local paths must be ignored, untracked, confined,
and disjoint from project configuration and protected control paths. Missing
destinations receive the same safety inspection. Symlinks, hard links,
non-regular files, and unsafe ancestors fail closed.

The public `update` method accepts the same selectors plus complete
`localContent`, nullable `expectedHash`, and `idempotencyKey`. It validates the
external-state boundary before intent or lease writes, rejecting state and
project trees that contain one another. It binds the key to
canonical arguments and a content hash, and reserves the destination and a hash
of resolved configuration. The existing action store accepts the narrow
`guidance_update` kind. Context and receipts contain paths, hashes, publication
phases, and filesystem identity, never document bodies. The state service's
`withGuidanceLease` holds the canonical-worktree lease with an opaque operation
owner, excluding mutating execution and other guidance writers across processes.
A contender receives a conflict and may retry its same incomplete intent after
ownership is released.

Filesystem access is relative to pinned directory descriptors using
`/proc/self/fd` or `/dev/fd`; unavailable descriptor access fails closed.
Directory identities and lexical confinement are rechecked around effects so
ancestor replacement cannot redirect reads, writes, publication, or cleanup.
Atomic rename publishes an owner-only, synchronized temporary file in the
destination directory; that temporary path must also be ignored. Publication
rechecks configuration, path safety, execution ownership, the expected hash,
and inspected file identities.

An intent records reserved, writing, prepared, and published phases. Temporary
inode provenance is persisted before writing, and complete file identity before
rename. Recovery removes a proven partial temporary write or recognizes its
own renamed inode. It never adopts another writer's identical bytes or
overwrites an intervening edit. An unproven temporary file left before
provenance was recorded is neither adopted nor deleted; retry reserves a fresh
name. Changed configuration cannot redirect incomplete publication. A durable
published record completes its receipt without replaying the effect. Completed
retries return the recorded bounded receipt (`projectPath`, `localPath`,
`localHash`, `updated`) without reapplying the old hash comparison or reloading
configuration. Receipts describe their operation, not the current document.

The CLI dispatches `guidance` and `guidance edit` directly to this capability
with project/configuration selectors; it never constructs a pipeline runner.
The capability's `edit` method reads and pins the complete original selection,
opens an owner-only temporary document outside the project, and validates the
entire result after the editor closes. It uses the same confined file access
and shared writer, retaining the original destination and configuration hash
through the publication boundary. Even unchanged content must pass current
path, hash, configuration, and execution-ownership checks. A missing document
left unchanged remains absent, with a null-hash no-op receipt; explicit empty
replacement still creates an empty document. Temporary copies are removed
through their pinned parent directory, without following substituted links.

`src/editor.js` owns shared shell-free command parsing, `$VISUAL`/`$EDITOR`
selection, launch fallback, and exit/signal outcomes. Only an unavailable or
unparseable editor command permits fallback. Guidance rejects a nonzero or
signalled close and never publishes that edit. Clarification retains its
existing policy: any launched editor close consumes its one-shot authorization,
even after a nonzero exit or signal. Authorization, document safety, and
publication remain in their owning capabilities. MCP never opens an editor.

Local guidance is supervisor context only: it is absent from role prompts, run
state, and resume configuration. Guidance never constructs a pipeline run,
changes ignore rules, replaces the common guide, mutates Git control state,
or performs finalization or commit work.

## MCP Control Plane

`agent-run mcp` exposes the same static pipeline registry and runner through the
official Node MCP SDK over STDIO only. The private `src/mcp/service.js` module
owns the nine pipeline-control tools: `pipelines_list`, `run_start`, `run_status`,
`run_activity`, `run_wait`, `run_respond`, `run_resume`, `run_pause`, and
`run_cancel`; it also owns the shared-capability tools `guidance_read` and
`guidance_update`, and the
conditionally registered MCP-only `unexpected_issue_report`. It contains
transport schemas and concise projections, not a second workflow
implementation. The private `src/mcp/reporting.js` module owns the narrow local
publication service. Standard output belongs exclusively to MCP; bounded
protocol diagnostics go to standard error without prompts or model transcripts.

One compact startup instruction asks the supervisor to call `guidance_read`
once before first managing a run for each project. It remains present when
issue reporting is disabled; tool descriptions do not repeat the guide.
Both strict guidance schemas accept `projectPath` and optional
`projectConfigurationPath`. Reading returns complete common and local content,
combined rendering, resolved paths, and the nullable local hash. Replacement
also requires complete `localContent`, nullable `expectedHash`, and an
`idempotencyKey`, returning only the bounded publication receipt. An empty
document removes local additions. Reading is annotated read-only; replacement
is destructive, idempotent, and local.

MCP delegates both calls directly to `src/guidance/index.js`, sharing the
control plane's run store and current configuration loader. That capability
owns file safety, byte and content validation, composition, worktree exclusion,
action intents, interrupted-publication recovery, and receipts. MCP neither
opens an editor nor adds another action wrapper. Completed retries replay the
recorded receipt without overwriting later CLI or MCP edits; stale edits require
a fresh read, reconciliation, and a new mutation key. Guidance remains outside
role prompts, run state, and resume configuration.

Unexpected-issue reporting remains deliberate and caller-initiated. Its tool
description and server instructions limit it to a supervising client agent
that has explicitly concluded Agent Runner behaved genuinely unexpectedly or
contrary to its documented contract. Expected completion, exhausted configured
budgets, usage limits, expected user pauses, documented environment blockers,
and invalid user or configuration input are not reportable. Runner error paths
never invoke it, and backend role sessions are not exposed to the MCP server.

The caller supplies bounded English Markdown for every diagnostic section and
optional bounded details, run ID, and error code. The service never gathers or
attaches logs, transcripts, prompts, environment values, credentials, secrets,
or other diagnostic data automatically. It canonicalizes the Git project,
validates the external-state boundary before action persistence, loads the same
current runner and optional confined project configuration used for a new run,
and resolves `<artifactRoot>/agent-runner/issues/`. Git and filesystem guards
require that destination to be ignored, untracked, confined, and free of
symbolic- or hard-link escapes. Publication uses a sortable colon-free UTC name,
an exclusive atomic link, and collision retries without changing ignore rules
or overwriting an existing path.

Mutating MCP calls require an opaque idempotency key. The state layer hashes the
key, binds it to the tool and canonical arguments, and durably records an action
intent before mutation and a receipt before returning. An exact retry returns
the receipt; reuse with different arguments fails. An incomplete run intent is
reconciled against the reserved run ID, current revision, submitted transcript
hash, and execution lease before work is launched again.

`run_start` persists the run before spawning `agent-run resume` as a detached
child with no inherited standard streams. `run_respond` atomically writes the
identified answers, records their transcript hash in run state, then launches
the same detached continuation. `run_resume` normally accepts only an action
applicable to the persisted pause. Two exact-revision, action-free recovery
paths are additional: a nonterminal checkpoint with no pause or live owner, and
an ownerless applicable stop. Stop recovery persists its own idempotency intent
and private stop-checkpoint revision, so it uses a new key and does not require
the original stop key. A non-null action, stale revision, live owner, or
duplicate ownership race is rejected without weakening ordinary pause-action
validation.

An ordinary continuation child owns the existing per-run execution lease and,
for plan execution or polishing, the canonical-worktree lease. Before ordinary
detached dispatch, MCP rejects an already-owned worktree without completing the
idempotency intent, leaving the reserved durable run available for an exact
retry. After spawning an ordinary mutating continuation, MCP withholds the
receipt until journaled readiness correlates that dispatch with process retirement
and checkpoint continuation under the required leases. A child that loses a
concurrent ownership race leaves the intent incomplete and exactly retryable.
Child-exit and ownership notifications wake bounded inspection; unrelated
revision changes and transient lease ownership cannot acknowledge a launch.

Detached stop reconciliation has the stronger completion condition. MCP binds
the launched child to the exact stop checkpoint and follows it until that stop
is durably settled or that child exits; transient acquisition of the run lease
is not progress. Exit before settlement leaves the recovery intent retryable
and reports detached-start failure or the distinct runtime-version-skew error.
A delayed child carries the checkpoint revision and becomes a no-op after that
stop settles, so it cannot resume a reconciled pause or revive cancellation.
An MCP disconnect, tool timeout, worktree conflict, or duplicate recovery
launch cannot create a second workflow owner.

`run_pause` and `run_cancel` delegate directly to the state-owned stop action,
so the acceptance event and receipt are durable before either tool returns.
Both require the caller's exact inspected revision and idempotency key. An
exact retry replays the receipt; a stale or conflicting request never refreshes
itself. A live execution owner observes the durable request through the runner
monitor. If ownership was already lost, MCP launches a detached action-free
resume to perform the same-run reconciliation. If the child exits first, the
diagnostic identifies a conflicting canonical lease by its recorded owner run
ID, distinct from the ownerless run whose stop remains applicable. Execution
and worktree leases still exclude a second owner. Client cancellation stops
only the tool's wait and does not retract the request or terminate the detached
child.

MCP start fields remain additive. `run_start.mode` exposes the union of
descriptor modes (`independent`, `lazy`, `combined`); the selected pipeline
validates availability. It has the same highest precedence as CLI `--mode`.
MCP guidance states that `independent` is the default and recommended choice for genuinely
independent semantic review despite its higher context and token cost, and that
`lazy` is an opt-in lower-consumption tradeoff without independent review that
must never be selected automatically. `combined` adds primary
convergence before independent review. `sourceSession` defaults to unset. When
a compatible current native session is available, the controlling agent offers
a fresh start and a deliberate fork choice, including its trusted source
profile when known. An unknown profile permits only `current` inheritance; the
agent never guesses an alias, inspects provider-private storage, or interprets
the opaque native ID. The field is passed only after the user selects the fork.
Independent and combined modes fork the complete source context into primary
and review roles; lazy mode forks it once into the primary role. A fresh start is
recommended for a long, multi-topic, or uncertain source session to avoid
unnecessary provider context and quota use.

The role-backend and source-session backend enums are projections of the
provider registry. A descriptor that does not advertise source-session forks
does not appear in the latter enum; the selected installed adapter must still
prove native fork support at its capability probe.

`run_wait` is one revision-driven server-side wait that ends at an unresolved
`WAITING_FOR_USER`, `DONE`, `FAILED`, `CANCELED`, or its caller-selected
timeout. Optional MCP progress notifications carry only bounded public activity
with role labels; they do not wake a model or alter the run. Cancellation
cancels only that wait.

An omitted `run_wait.timeoutMs` means 30 seconds and the public maximum is 24
hours; either deadline ends only the client wait. Internal detached-dispatch
and detached reconciliation uses bounded event-driven observation, while the
operator-stop monitor waits for a revision for at most one second at a time.
These are fixed correctness mechanics rather than user-work retry budgets.

MCP status and wait also project one bounded `execution` object. Its finite
`leaseOwner` is `none`, `live`, `dead`, `replaced`, or `unverifiable`, while
`processRecord` is `none` or `persisted`; neither field exposes process
identity. `state` remains the conservative action summary: `running` while the
lease owner is live or unverifiable, `interrupted` when a persisted active turn
or process record has no exclusionary owner, and `idle` otherwise. Nullable
`role` and `phase` come only from the common run envelope. A read applies the
same exact same-host process-identity classification used for exclusive
acquisition without changing ownership. A timeout therefore distinguishes live
lease ownership, unresolved lease identity, and durable process ownership
without polling or a heartbeat.
`pipelines_list` projects descriptor-owned setting values, defaults, and
recommendations. Status, wait, and activity project the persisted resolved mode
without inactive role configuration or provider-private data. `run_activity`
remains an explicit cursor-based history read rather than a polling primitive.
Status and wait additionally expose only the pending stop kind and accepted
revision while reconciliation is incomplete; the request hash, suspended
checkpoint, and internal ownership evidence remain private.

V1 does not require the MCP Tasks extension, a network transport,
authentication, or a daemon.

### Bounded action-free continuation

CLI resume accepts an optional `--expected-revision`; MCP resume always binds
its inspected revision. Both enter the same runner resume path. Admission
checks the revision under the execution lease before recovery. An ownerless
nonterminal checkpoint with no pause also accepts action-free continuation,
including a crash between admission and the first provider turn. Retained
process/resource reservations are exclusion evidence, not proof of a live
runner: only same-host owner inspection decides whether to dispatch a replacement.
Same-run worktree reclamation retains exact process identity, mutation, and
reclaim-marker checks, and recovery reuses an already-held worktree handle.

MCP action-lease contention returns `ERR_MCP_ACTION_IN_PROGRESS` immediately.
Detached dispatch uses revision/lease notifications and the correlated child's
exit, with at most 64 inspections within 30 seconds. Exhaustion returns
`ERR_DETACHED_OWNERSHIP_PENDING`; it does not clear ownership or cancel the child.
The client can retry the identical key. Client cancellation and disconnect affect
only observation; reconciliation and receipt publication keep their action lease.

Before IPC admission, the action intent saves a dispatch UUID, exact revision,
and the child's hostname/boot/PID/start identity. The inert child waits up to ten
seconds for admission and cannot execute after a pre-admission disconnect.
Under the execution lease it journals a correlated `dispatch-started` event
before potentially long recovery. After process/resource retirement and acquiring
the required worktree lease, `dispatch-ready` marks checkpoint continuation;
short input/configuration paths can acknowledge their durable return; stop
recovery uses its existing checkpoint-bound settlement without appending another
acknowledgement revision.
These events do not approve content or attest workflow completion. Public activity
and progress output omit the private correlation UUID. Legacy confirmation
proof accepts these events only when the complete state is unchanged apart
from revision and timestamp; it is rebuilt for the acknowledged snapshot. The detached compatibility token versions
this admission protocol independently of the run envelope.

A restarted control plane adopts only matching journal evidence, never arbitrary
revision movement or transient lease ownership. A live or unverifiable recorded
child prevents redispatch. A dead/replaced child without a ready event permits
same-key recovery only at its unchanged revision or while its admission is
followed exclusively by root reconciliation. Another admission or workflow turn
makes that request stale. A durable ready event permits receipt repair even after
later pauses or input changes. Stop receipts additionally require settlement of
the specific saved stop checkpoint. A different worktree owner remains identified
in the retryable diagnostic.

Action-free provider process-proof failures leave the active turn and exact
pipeline checkpoint durable, including a finalization failure after command
execution. They do not become terminal `internal_failure` or accept output,
fingerprints, or checks while ownership is uncertain. Resume retires retained
processes first, then performs the pipeline's ordinary interrupted-turn Git/input
reconciliation. Consumed effects retain verification-only recovery.

## External Run State

Journal append capacity is separate from the fixed `2147483647`-byte read
ceiling. The safe-file boundary reads 64 KiB chunks from a no-follow isolated
regular-file descriptor, bounded to its initially inspected size. Complete-record
offsets count raw bytes; decoding occurs only after assembling a record, so
split UTF-8 and incomplete tails cannot corrupt offsets. Existing continuity and
state/event consistency checks still apply. Lower append policy does not make
valid history malformed or prevent lock-free reads and leased recovery.

An append charges the entire encoded complete-state event and its newline,
accepting exact capacity. Insufficient capacity raises `ERR_EVENT_LOG_LIMIT`
before changing the journal, snapshot, progress, or incomplete tail. Only leased
recovery or an admitted append removes an incomplete final fragment. Valid
history remains append-only, with no rotation, compression, compaction, or
durable format change; synchronization still precedes atomic state replacement.

Runner classifies `ERR_TRUSTED_VALIDATION_RESOURCE_UNVERIFIABLE` as retained
resource ownership. The original cleanup error and internal cause, including a
journal-capacity failure, survive both worktree and execution lease-release
failures. Private exact same-run handles remain available for verified retry;
other owners remain excluded until existing trusted cleanup, including verified
absent-child recovery, is successfully journaled. Public errors stay finite and
redacted. Increase effective root policy and resume the same run, or use a larger
explicit public store policy while preserving protected project configuration.
A replacement Runner must first prove the exact former owner dead or replaced;
it cannot take over a live owner. Without a permitted increase, retain all
history and ownership records and remain blocked.

The state service's internal `loadRunHistory` operation returns the run and
complete validated events from one authoritative snapshot. It shares journal
continuity, size, migration-envelope, and snapshot-consistency checks with
ordinary reads and preserves lock-free, non-repairing status semantics.
Recovery still repairs incomplete tails and lagging snapshots only under the
run lease. Optional expected-revision transitions reject stale evidence before
appending anything.

The runner supplies this private history to a pipeline's optional
`prepareRecovery` descriptor operation. Plan execution binds legacy terminal
confirmation eligibility to the inspected run object and revision; no history
or recovery authorization is serialized into public run data. Status may
project supported migrations in memory, while execution first persists the
existing migration chain and obtains fresh history under both execution
leases. Plan-execution resume revalidates canonical project and task boundaries
inside the worktree lease, including restart after a durable recovery transition.
Pipeline policy validates actual candidate/finalization transitions and their
intervening fingerprint lineage. A migrated terminal snapshot alone
cannot establish acceptance. The exact legacy opaque failure can then enter
`CONFIRM` through a revision-checked write-ahead transition carrying the
read-only active request. Existing interrupted-turn reconstruction handles a
crash at any persistence boundary without repeating a source fork or earlier
work. Non-actionable `pendingCorrection` accounting is retained with its
counters; concrete pending work and effects remain disqualifying.

The descriptor shares that eligibility with CLI/MCP projections and resume
action validation. MCP's detached launcher admits the proven failed state
without changing stale-revision, ownership, compatibility, or receipt rules.
The owning [execution specification](../pipelines/plan-execution/docs/SPEC.md)
defines eligibility and revalidation; the state layer owns all journal I/O.

The same descriptor also prepares diagnosed lazy Worker `CHECK_AND_FIX`
reconstruction. `diagnosed-checkpoint-recovery.js` consumes backend-neutral,
closed acquisition evidence and binds a continuous turn, reconciliation,
retirement and failure chain to the current revision. No provider code/class
allowlist lives in the pipeline. State version 27 adds nullable, versioned
`diagnosedCheckpoint` metadata; the version-26 migration supplies null rather
than fabricating provenance. A snapshot or diagnostic alone cannot reopen a
failure. Proof verifies saved inputs, roles, configuration and provider policy,
step and completed commits, Git controls, content and correction accounting.
Execution repeats safety revalidation under both leases, then writes the
reconstruction intent before fresh provider work. The retained marker makes an
interrupted publication reconstructible without reforking the source. Fresh
check/fix consumes it, preserves charged rounds, clears stale approvals and
requires the ordinary candidate, finalization and terminal-confirmation gates.
Legacy terminal-confirmation eligibility remains unchanged.

The root runtime persists runs under `$XDG_STATE_HOME/agent-runner/`, falling
back to `~/.local/state/agent-runner/`. A run is addressed by an opaque ID and
stored beneath `runs/<run-id>/`. Preflight requires the canonical state tree
to be disjoint from both the project and task trees: neither may contain the
other.

MCP action intents and receipts live under `actions/<hashed-key>/` in the same
external root. The opaque key itself is not persisted. Action records are
atomically replaced and protected by a same-host process lease; they never live
inside the target or task directory.

An unexpected-issue action persists its intent and reserved report path before
publication. It records a published phase while the temporary hard link still
proves ownership, then removes that link and persists the path receipt before
returning. Recovery adopts a report-only path only with that durable ownership
proof; otherwise a matching file is a collision. An exact retry returns the
same path, while key reuse with different arguments fails.

Canonical-worktree leases live under
`worktrees/<sha256(canonical-worktree-path)>/` in that external root. The hash
keeps filesystem-safe bounded keys while the owner record contains only the
run ID, an opaque token, process ID, hostname, acquisition time, and nullable
process identity. Version-2 lease records pin Linux boot identity and process
start ticks when available. A live reused PID is a replaced owner, not proof
that the recorded execution survives. Foreign-host, legacy, identity-free, and
otherwise unverifiable owners remain conservative exclusion barriers. Legacy
records are read without rewriting them; new acquisitions publish the current
lease format. Empty key directories may remain after release. Ownership uses
`.lease`; a pending stop also retains an interrupted `.lease-reclaiming`
reservation until reconciliation permits its release.

Run, canonical-worktree, reclaiming, and MCP action leases share one durable
no-replace publication primitive. It writes and syncs the complete JSON record
to an isolated in-directory temporary file, atomically links that inode at the
lease path only when the path is absent, removes the temporary link, and syncs
the directory before acquisition returns. A lock-free reader therefore treats
an unpublished lease as absent and parses only a complete record. If it meets
the bounded internal link between publication and cleanup, including after an
interrupted publisher, it removes only the matching same-directory temporary
link to restore the isolated final file. Bounded retries cover replacement
publication between inspection and opening; each read still requires an
isolated regular file, and unrecognized or persistent hard links remain unsafe.
Exclusive contention, dead-owner recovery, and release all use the published
record and continue to verify its opaque owner token. A current same-host run
or worktree lease with a complete boot/PID/start identity is reclaimable
immediately only when that exact owner is dead or replaced. Acquisition time is
neither a delay nor ownership proof. Legacy, identity-free, foreign-host, live,
invalid, and otherwise unverifiable records remain exclusion barriers.

These state retry counts are fixed correctness guards rather than workflow
budgets. Managed-state reads make at most five attempts across an atomic
replacement; lease acquisition, including reclaim-marker and owner
reconciliation, makes at most five passes. Runner release of either an
execution or canonical-worktree lease makes at most five stop-aware attempts;
exhaustion leaves stop reconciliation pending. Generated run IDs try at most
ten candidates. Unexpected-issue publication tries at most 1,010
collision-safe names, ending with random-token candidates. None of these loops
waits for user work or makes an external service more available, so exposing
their counts as configuration would weaken the persistence proof without
creating a useful operator control.

### Provider inactivity deadlines

Common run envelope version 17 freezes `providerInactivityTimeoutMs` and
`providerInactivityFingerprint`. The fingerprint is SHA-256 of the canonical
JSON object containing that timeout. Root/project configuration accepts only
integers from 1 through 2147483647 milliseconds, defaults to 1800000, and resolves
project over root. No role, CLI, or MCP override exists. Versions 1–16 normalize
to that default and null recovery; leased migration journals it without loading
configuration or changing pipeline progress. Journal continuity protects both
immutable fields and rejects a fabricated legacy recovery allowance.

`src/runner/inactivity.js` owns one watchdog per adapter invocation inside the
operator-stop monitor. Its injected timer makes policy tests deterministic.
Only the closed validated `onProgress` vocabulary resets the timer. Paired
command events maintain the aggregate count; a positive count suspends the
deadline until all owned commands complete, then starts a full interval.
Keepalives, bytes, liveness, unrelated notifications, and public observation do
not count. Local tool lifecycle events are meaningful progress but do not
suspend the deadline. Settlement drains timer persistence before returning.

Before aborting an inactive provider, the run store durably journals the bounded
`inactivity/expired` activity and `inactivityRecovery`: exactly `role`,
`checkpoint`, `attempt` (1 or 2), `status` (`expired` or `reconstructing`),
`reconstructionRevision` (null before attempt 2), `configurationFingerprint`,
and the observed `contentFingerprint`. The state store records expiry while ownership is still active without advancing
the pipeline or changing other run fields. The marker
is separate from availability episodes and contains no native payloads or tool
content. Failure to persist evidence retires owned work without authorizing a
retry. Process/resource retirement remains mandatory before reconciliation.

Each pipeline reconciles its own read-only or writable checkpoint and any
partial correction before reconstruction. Safe content invalidates stale gates;
the existing charged-correction marker prevents double counting. Reconstruction
uses the complete durable prompt for the same role and never reforks a source.
The transition to attempt 2 is durable before launch. The adapter's optional
awaited `onFreshSession` callback reserves this same allowance before native
fresh fallback; false forbids that fallback. An expired attempt 2 pauses as
resumable `backend_unavailable` rather than entering availability backoff. Owner
loss does not replenish the allowance. Explicit resume after that pause permits
one invocation with attempt 2 still consumed; separate classified availability
failures retain their existing backoff, not another inactivity allowance.
The reconstruction revision consumes that continuation durably: only an
availability failure reconciled at or after the last reservation may authorize
another launch. An older episode cannot authorize replay after owner loss.

Only a returned provider response plus matching repository reconciliation clears
the marker. Pipelines report failed reconciliation at turn settlement; safety
pauses retain the marker without substituting a recovery error for the original
repository failure. Safe content/counter changes and that reset share one durable
transition, before output validation. The adapter's awaited `onCommitExecution`
callback runs after validated readiness and before the constrained executor: it
drains the watchdog and reconciles the readiness response against the existing
baseline. The executor, trusted validation commands, and runner-owned handoff
are outside this watchdog. A readiness expiry may retry only after existing
validated `commitExecutor: "not_started"` evidence and Git verification retire
the consumed authorization. Possible effects, policy failures, usage limits,
authentication requirements, and operator stops retain their precedence.

CLI status and MCP `inactivityRecovery` expose only role, checkpoint, attempt,
and status. Bounded `expired`, `reconstructing`, and `recovered` activity uses
the existing journal/projection transport. Client disconnect or canceled waits
change observation only; they cannot cancel or reset the watchdog.

### Durable availability episodes

Common envelope version 16 adds the immutable normalized client attribution and
its matching fingerprint. Version 1 through version 15 runs normalize only to
the generic default; a leased runtime migration journals that value without
loading current configuration. Legacy state cannot claim a custom identity.

Common envelope version 15 adds immutable `availabilityPolicy` and nullable
`availabilityRetry`. Runtime compatibility includes this envelope version.
Legacy versions project the documented default policy and no pending episode;
the leased runtime migration journals those values without replacing saved
roles, checkpoints, modes, corrections, session lineage, or provider receipts.
Current configuration never replaces a frozen policy on resume. Legacy records
cannot claim a custom policy or pending episode.

The state service's `scheduleAvailabilityRetry` accepts an inspected revision,
active role, bounded logical checkpoint, finite provider-neutral reason, and
reconciled content fingerprint. It requires retired turn/process/resource
ownership and the existing exclusive mutation lease, then appends the complete
event before replacing state and returning. The episode stores a UUID, role,
checkpoint, reason, attempt, delay, scheduling time, retry deadline, content
fingerprint, and reconciled revision. The caller owns repository reconciliation;
a hash-shaped value alone does not prove Git safety.

Delays are `min(maxDelayMs, 5000 * 2^(attempt - 1))`: at the default ceiling,
5, 10, 20, 40, 80, 160, 320, 640, 1280, 1800 seconds, then 1800 repeatedly.
The attempt has no policy quota; its numeric representation saturates at the
largest safe integer without stopping capped retries. Journal validation rejects
policy drift, changed episode identity/role/checkpoint, skipped attempts,
inconsistent deadlines, and progression before the prior deadline. Deadlines
are calculated from the current scheduling time, so overdue recovery cannot
produce a catch-up schedule. Unrelated transitions and restart retain the episode;
clearing it is reserved for the successful-provider-turn coordinator path.

The runner injects one availability coordinator into all three pipelines.
Logical checkpoints bind the original access mode as well as role and phase;
read-only dispute recovery cannot regain write access through an availability
episode when its correction budget is exhausted.
Each pipeline first reconciles repository controls, safe partial content, and
turn/process retirement, then requests scheduling. Correction accounting and
pending correction diagnostics remain bound to the same logical turn; partial
writes invalidate dependent approvals without charging that correction twice.
After restart the pipeline reconstructs the same role/checkpoint from durable
state, preserving lineage without reforking the source. Deadline waits retain
the execution/worktree leases and are abortable by immediate or deferred stops.
An overdue deadline permits one attempt, never a catch-up burst.

Scheduling and retry start are journaled before waiting or dispatch and immediately
published to CLI/MCP activity with bounded role, checkpoint, normalized reason,
attempt, delay, and deadline. Status projects the same fields in `availabilityRetry`.
A successfully returned provider response clears the episode at repository
reconciliation, before deterministic output validation; rejected output can
therefore still mark provider progress. A normalized authentication-required
response instead retires the superseded episode before persisting its distinct
operator pause. Reconciled content and correction accounting are persisted
atomically with either transition. Check/fix mutation claims are compared against
the attempt's starting fingerprint, including any safe content retained from
earlier failed attempts. Other availability errors, tool activity, partial output,
session replacement, operator resume, and restart do not reset it. Persistence or
wait failures retain the checkpoint and propagate without inventing a terminal
pipeline failure.

Plan-execution state version 24 permits a bounded availability reason and
`commitExecutor: "not_started"` in a persisted pre-effect rejection. Version 23
migrates without inventing that proof. Version 25 makes the plan-execution
source-projection need explicit and defaults version-24 reports to false without
changing frozen authority, workflow evidence, correction accounting, or effects.
Consumed authorization remains verification-only until Git proves no commit and
unchanged state; only then can one atomic journal transition retire it and
schedule a fresh authorization.
Potentially executed commit/handoff effects never enter availability replay.
Polishing state version 16 preserves charged partial resolutions at their original
checkpoint. Both writable pipelines persist whether the current provider-recovery
continuation has charged a check/fix round; authentication recovery also retains
the charge for a partially completed finding-resolution round. An earlier
pending correction does not exempt a new round, and availability reset or
authentication pause cannot erase an unfinished charge.
Legacy pipeline migration initializes that marker to false. Both retain unresolved blockers and historical
negative validation evidence during recovery; no stale passing evidence or
approval can authorize the changed content.
Polishing state version 17 makes its independently owned source-projection need
explicit and defaults version-16 reports to false without changing frozen
authority, workflow position, review or correction evidence, or handoff state.
Null provisional reports retain the existing read-only discovery barrier.
Foreground CLI owner loss requires resume; detached MCP ownership outlives a
client timeout or disconnect.

### Durable authentication-required pauses

The runner injects one provider-neutral authentication policy into all three
pipelines. It accepts only a strict normalized adapter failure carrying
`disposition: "authentication_required"`; raw messages, diagnostic classes,
HTTP evidence, and provider-specific codes cannot activate the policy.
Authentication is an operator action, not availability: the runner schedules
no retry or backoff and persists no availability episode. When it supersedes an
active availability retry, that episode is retired before the authentication
pause is persisted.

After provider execution retires, each pipeline applies its ordinary repository
guard. Writable execution and polishing turns reconcile safe partial content,
invalidate stale fingerprint-bound approvals, and preserve correction charging.
One durable transition retires the active turn, saves any source-fork recovery
marker, and enters `WAITING_FOR_USER`; interrupted publication cannot leave a
finished turn without its authentication checkpoint. The pause contains exactly
`authentication_required`, `ERR_AUTHENTICATION_REQUIRED`, and the current
logical resume state. Role configuration, source and child session lineage,
content fingerprints, findings, and counters stay in their existing durable
fields. After the operator reauthenticates, a null resume reconstructs that
same checkpoint without requiring the failed native session. A partially
completed finding-resolution turn retains its writable access even when its
already charged round reached the fix budget; completing that round does not
consume another round or authorize a new one.

Authentication during an initial source-session fork additionally preserves a
nullable provider-neutral recovery marker containing only the logical role and
context key. Proof that the rejected request had no effect permits the source
fork to be retried. Possible-effect evidence instead persists the marker and
reconstructs the same role in a fresh session, never reforking a source whose
native child may already exist. The marker survives repeated authentication or
interruption and clears only after a child session is durably recorded.
If interruption precedes pause publication, authentication during fresh
recovery retains the earlier unrecorded fork's possible effect even when the
new request proves no effect.

Local-commit readiness remains effect-safe. The disposition qualifies only
when the normalized record also proves `commitExecutor: "not_started"`.
Plan execution persists that bounded proof with the consumed authorization,
performs the existing Git verification-only path, and retires the authorization
only after Git proves no commit. It then pauses at `COMMIT`; uncertain or
started effects never become authentication retries. Polishing handoff remains
runner-owned and uses its existing staged-effect verification path.

Plan-authoring state version 6, plan-execution version 26, and polishing
version 18 introduced these pause, proof, and source-fork recovery variants.
Their immediately prior migrations initialize the nullable recovery marker to
`null` while preserving workflow position, existing session lineage, evidence,
and correction accounting. They do not reload configuration or infer a native
child. The version bump makes older readers reject rather than misread the new
durable checkpoint.

### State-owned operator stop protocol

The common envelope version 7 extends the nullable bounded `stopRequest` with
requested and effective timing, immutable target evidence, and settlement
accounting. The state service's `requestOperatorStop` accepts a run ID,
`pause_requested` or `cancel_requested`, an inspected `expectedRevision`, an
`idempotencyKey`, and optional `timing` (`immediate` by default).
It persists a version-3 action intent, appends the complete acceptance event,
and publishes an acceptance receipt before returning. This capability does not
signal processes, reconcile Git, or expose CLI/MCP commands; those operations
belong to runner and transport integration.

Short, recoverable `.mutation-<uuid>` claims serialize requests with
execution-owned journal writes and lease release. Each contender durably
publishes a choosing claim before selecting its ordered ticket; it waits for
choosing peers and lower ticket/identity pairs. Dead claims have unique paths,
so recovery cannot unlink a newer owner at a reused lock pathname. Claims and
contention are observed at most 500 times with 10 milliseconds between blocked
observations, about five seconds plus filesystem work. Exhaustion returns the
retryable mutation-busy outcome, and unverifiable owners continue to exclude
mutation. Action-lease reclamation uses the same boundary, which does not grant
another execution lease. Worktree owners without a pipeline run, such as
guidance publishers, use claims in the worktree lease directory. Status and
activity reads remain lock-free.
The acceptance record contains the hashed request identity, request kind,
inspected and accepted revisions, request time, nullable reconciled revision,
and a suspended checkpoint. That checkpoint records the workflow state, active
turn, null resume action, and the exact earlier journal revision. Reading that
revision recovers the complete frozen state, including existing pause blockers
and pending input, without duplicating a potentially large pipeline payload.

Only nonterminal runs accept fresh requests. A cancellation may supersede a
pending pause using either its original inspected revision or the current
revision; it retains the original checkpoint. Other stale requests fail, as do
new competing requests that cannot supersede the pending stop. Exact retries
return their original receipt. If receipt publication was interrupted, the
acceptance event reconstructs it even after cancellation superseded a pause or
the run terminated. Receipt replay neither advances the run nor executes work.
Version-1 and version-2 action records remain readable; incomplete actions
upgrade when written, and completed receipts replay without migration writes.

Execution propagates commit-authorization preparation and consumption publication
failures without overwriting the journal with a stale local checkpoint. Deferred
stop recovery preserves the durable authorization, never invokes a prepared
effect to obtain a commit, and only verifies a consumed effect. Fault-injection
coverage includes acceptance versus advancement/completion, lost receipts,
lease transfer, and verified settlement publication for both stop actions.

New stop argument identities include timing and canonicalize omitted and explicit
`immediate`. Legacy timing-less identities accept those same immediate arguments
and retain their original receipt shape; a timing change conflicts. Legacy stop
records normalize to immediate timing without read-side writes. New receipts
include requested/effective timing and bounded target evidence. CLI `--timing`
and MCP's optional `timing` field expose the same two values; omission stays
immediate. Transport validation never refreshes an inspected revision or changes
retry arguments. MCP keeps `pendingStop` for pending requests and adds the
state-owned bounded `projectOperatorStop` summary as `stop` for current and settled
requests. CLI status uses the same summary; public activity derives it from each
event's state, and waits reuse status. It excludes identities and private
checkpoints, exposing kind, accepted revision, requested/effective timing,
target step, state, and nullable settlement. `applicable` denotes immediate
requests or suspended/failed checkpoints awaiting reconciliation; other pending
requests remain `pending`, including interrupted owners awaiting recovery.
`settled` denotes completed accounting, with `quiescent` or a verified commit
SHA when available. These projections do not decide ownership or enforcement.

Plan execution's descriptor classifies one stop checkpoint as `pre-work` only
when the applicable request is immediate, its saved journal revision matches
the unchanged current pipeline state, and both snapshots remain at initial
`CLARIFY` with incomplete preflight, empty input hashes, no repository baseline,
backend versions, clarification path, frozen artifact, pending edit, canonical
plan, selected step, pending commit, or completed commit, and no pause, active
turn, execution process, or execution resource. The runner holds the run lease and
uses the existing atomic stop settlement without acquiring a canonical lease
recorded for another run. Cancellation becomes terminal; pause preserves that
same resumable `CLARIFY` checkpoint. Any failed predicate retains the ordinary
worktree-lease requirement and full repository/effect reconciliation. Plan
execution state version 21 is an identity migration that rotates detached
runtime compatibility for this settlement-aware contract. Plan execution state
version 22 adds its frozen finalization-guidance decision. Terminal states and
consumed commits retain verification-only recovery. Other unfinished legacy
states establish the decision before more provider work and use the existing
read-only validation migration before writable work when their prior inventory
cannot prove the new contract.

The private `src/state/stop-policy.js` owns three distinct decisions: whether a
request awaits reconciliation, whether that request blocks execution, and
whether unresolved stop accounting or a recorded execution process retains
ownership. Immediate requests block execution. Deferred requests retain ownership
while allowing progress within their immutable target. The runner monitor keeps
watching for immediate cancellation supersession without aborting deferred work.
Envelope validation owns
shape; the stop service owns acceptance, supersession, and receipt accounting.

State accepts `after-current-commit` only with a trusted synchronous
`resolveStopBoundary` capability supplied to `createRunStore` by composition.
It resolves a frozen authoritative snapshot inside acceptance serialization.
The bounded `verified-commit-v1` evidence contains the positive step number,
completed-commit count, and baseline SHA; no provider data or free text is stored.
Ordinary writes cannot change that boundary; only leased atomic settlement can
record progress together with the stop outcome. Unsupported resolver results or
persisted capabilities fail closed, including during history reads. The root
pipeline registry supplies execution's boundary resolver to the runner
and MCP stores. Execution accepts a selected step, including suspended
checkpoints; clarification, bootstrap, absent steps, and the other pipelines
reject deferred requests. Direct state stores without that capability still
fail closed. Deferred CLI/MCP request inputs remain unavailable.

Cancellation supersession retains the original suspended checkpoint and cannot
delay an earlier immediate stop. Requested timing remains visible when effective
timing is immediate; a still-deferred cancellation retains the earlier target.
Settlement records either a verified commit SHA or a quiescent fallback, and
becomes immutable with the reconciliation revision. Workflow meaning and commit
verification remain the pipeline/runner's responsibility. Execution supplies the
verified SHA to both ordinary checkpoint settlement and verification-only recovery.
The state mutation records progress and the latest requested outcome together.
If the target pauses, fails, or loses its owner before verification, recovery
reconciles effects and applies the request at the quiescent checkpoint without
invoking another role. Underlying failures, blockers, and consumed authorization
evidence remain in the operator checkpoint. A final-commit pause suspends `DONE`;
resume reaches `DONE` without agent work. Final-commit cancellation retains all
completed commits in `CANCELED`.

The common advancement guard applies inside the mutation boundary to workflow
transitions, provider-turn records, session/artifact writes, and execution
registration. Pending stop enforcement takes precedence over process accounting,
then terminal cancellation blocks any further advancement. Retiring a recorded
process remains allowed while a stop is pending so reconciliation can finish.

Lease release, worktree reclamation, and durable `runIsLeased` exclusion consult
the separate ownership-retention policy. A reconciled cancellation remains
terminal without retaining ownership; a reconciled pause permits ordinary
resumption once other blockers are resolved. A pending stop prevents release
of held run/worktree ownership even after its process record has been retired.
A dead owner's existing worktree lease remains excluded from other runs while
the request is pending; only recovery of the same run can reclaim it.
Reclamation, including reclaim-marker recovery, rechecks the stop under the
original run's mutation boundary before replacing ownership. A crash leaving
only a reclaiming record retains that reservation until a replacement lease
exists, restricted to the same run while a stop is pending; failed
replacement publication restores the previous lease when possible.
The recorded lease owner and the run currently requesting reconciliation are
separate identities: diagnostics name both when they differ. Operators never
manually delete, rewrite, or bypass a lease record to make progress; recovery
uses the state-owned settlement and normal lease acquisition/reclamation rules.
`inspectRunLeaseOwner` exposes private identity and finite
live/dead/replaced/unverifiable classification for runner use; unverifiable
owners are not eligible signalling targets.

The runner separately tracks an in-process canonical-worktree lease handle,
durable same-run recovery responsibility, and the persisted execution-process
record. Stop reconciliation reuses a handle it already owns and releases it
only after durable settlement. If process retirement cannot be proved, the
same-run reservation remains for retry and the containment error escapes
unchanged; release recovery never reacquires that handle and cannot replace the
failure with a self-conflict. After owner loss, normal age, process-identity,
and competing-owner checks govern same-run stale reclamation before the same
retirement and settlement path runs.

Only the execution lease holder can call `completeOperatorStop`, after the
runner has reconciled the interrupted access contract and any begun effects.
That operation atomically records `WAITING_FOR_USER`/`operator_paused` or
`CANCELED`, clears active-turn activity, and marks reconciliation complete.
It does no repository work. The journal retains the suspended checkpoint and
prohibits cancellation downgrade or revival. Identical completion retries do
not add another transition. Lease release becomes possible only after this
durable accounting. Version-1 through version-3 run envelopes project a null
request without read-side writes; stop acceptance can upgrade only the common
envelope in its acceptance event while preserving pipeline state and history.

Verified commit settlement uses the leased `settleCheckpoint` state operation.
Its synchronous resolver reads the latest authoritative snapshot inside the
mutation boundary; the runner supplies workflow patches and the pipeline
validator checks the fully normalized result before journal publication. A
recorded execution process prevents settlement. A pending stop must settle to
its requested outcome, including a cancellation that superseded a pause during
verification. No provider, Git, or artifact effects run inside the resolver.

Execution's private `commit-checkpoint.js` constructs the verified SHA, clean
repository baseline, completed-commit list, next step or `DONE`, evidence resets,
and counters. Normal execution and verification-only stop recovery use that same
construction. The runner wraps the checkpoint in an operator pause or cancellation
when applicable and retains protected-configuration blockers beneath the stop.
Successful settlement clears the active commit turn and consumed authorization
in the same event as progress. Publication errors escape without writing failure
state from an older local snapshot; journal recovery preserves an already
published checkpoint without replaying the commit. Deferred requests use the
same settlement path and retain explicit commit or quiescent accounting.

### Common envelope and pipeline migrations

Common envelope version 5 adds nullable `executionProcess` ownership. Version
11 adds the supervisor's bounded boot/start launch cutoff and changes the
runtime compatibility token. Version 12 adds a nullable, ordered launch-time
ancestry baseline bounded to 4,096 entries, each containing the boot ID, PID,
and start tick observed immediately before supervisor launch. Version 14 adds
the nullable SHA-256 identity of the supervisor's exact Linux control-group
membership. Versions 5 through 10 derive the cutoff from a valid recorded
supervisor identity during normalization. Versions 5 through 11 normalize the
baseline to null; versions 5 through 13 normalize the control-group identity to
null. Neither migration rescans the host or synthesizes recovery authority.
The ordinary leased runtime migration persists that conservative shape, while
malformed, unsorted, oversized, mixed-boot, or mismatched current evidence is
rejected. Before a provider or trusted command can execute, a private
supervisor waits on a separate inherited Node IPC channel while the runner
journals its host PID, hostname, boot/start identity, launch cutoff, frozen
ancestry baseline, control-group identity, and PID namespace identity. The
shared agents boundary owns the
closed `ordinary` and `native-sandbox-provider` supervision modes. Ordinary
processes launch this supervisor as PID 1 in a private Linux namespace using
system-protected bubblewrap. Provider launches use that mode only when a cached,
namespace-local probe proves the complete outer-plus-inner user, PID, mount,
device, and network namespace shape. When nesting is unavailable on the initial
host PID namespace, only a declared provider may use a distinct owned session
before its mandatory native sandbox starts. When repository validation is
already inside the runner-trusted private PID namespace and that policy denies
another namespace, the existing owned-session mode remains available without
widening the enclosing sandbox. The private launcher preserves inherited filesystem/network
restrictions while replacing `/dev` with bubblewrap's minimal synthetic device
filesystem. Enclosing-session reuse retains the enclosing namespace's mounts
and restrictions. Provider and trusted-executor sandboxes still enforce their
narrower access contracts. The launcher's private status channel supplies the
host PID, verified against its parent and namespace before registration. No
provider work starts without that proof.

Launcher verification resolves the fixed system executable to a regular,
single-linked canonical file and checks that file plus every relevant ancestor
against the effective Linux mount table. A read-only mount is a protected
substitution anchor even when a namespace-root permission probe would otherwise
report writable. Paths without that anchor must deny runner-identity writes
through the root. Missing mount evidence, links, or a writable substitution
path fails closed.

Disconnecting IPC on runner loss starts bounded cleanup; bubblewrap also binds
the namespace lifetime to the runner. Exiting namespace PID 1 makes the kernel
retire all descendants, including detached sessions, double forks, and nested
namespaces. Normal completion reports surviving descendants before retiring
them, so trusted checks cannot pass with leaked work. Recovery inspects only the
recorded owner and waits for namespace-init death before clearing ownership;
the outer launcher's exit alone is insufficient. Live shutdown uses the original
child handle and control channel. The session token is derived from the already
persisted PID, boot, and process-start proof, so recovery can reject clearing a
dead session supervisor while matching descendants remain without signalling a
numeric host PID. Unverifiable ownership retains exclusion.
Former group-only records remain conservative until a verified reboot; they
cannot prove that detached descendants stopped. Unavailable ordinary namespace
support fails before execution. Session-mode discovery combines session
membership and verified live ancestry with a per-launch inherited ownership
token, including same-user descendants that create another session or PID
namespace. Complete ancestry that reaches an unrelated host process remains an
independent reason to disregard a candidate only when every observed hop
reaches an unchanged frozen baseline identity. Parent loss before target launch
retires the inert supervisor without scanning the shared namespace; no provider
descendants can yet exist. Once launch is accepted, live and replacement-owner
inspection use the identical frozen baseline. The scanner reads and stabilizes
each hop before accepting an exact boot/PID/start anchor. It checks observed
session and token evidence first, so an anchor cannot skip known ownership. A
stable inaccessible intermediate environment may be crossed only if the
lineage subsequently reaches an unchanged anchor; inaccessible current-process
environment is excluded only when its lineage reaches no owned evidence and its
stable control-group identity differs from the recorded owner. A missing or matching control-group identity, a stale
or reused anchor, a missing baseline, a boot mismatch, a cycle, malformed
identity evidence, and otherwise unproven candidates remain unverifiable
during both live execution and recovery. Recovery also rejects a
recorded PID namespace that differs from its own because the envelope does not
grant authority to infer that the old namespace was private. Legacy state with
a null baseline reports that it predates frozen ancestry recovery evidence
instead of falling back to its launch cutoff. The independently proven
previous-boot owner case is handled below. Other incomplete process evidence is
unverifiable, and surviving descendants after bounded TERM/KILL retirement fail
closed. Reusing the enclosing trusted namespace neither retries without
containment nor widens its policy; its namespace init remains responsible for
otherwise detached descendants.
Ordinary processes never receive the initial-host session fallback.

Live and recovery shared-host scans additionally share a 65,536-operation and
250-millisecond inspection budget. Reads, snapshot entries, baseline indexing,
and ancestry traversal consume bounded work; a final read that exceeds the time
budget also fails closed. Each inspection builds its validated baseline index
once. Baseline capture uses the same work/time limits and retains its 4,096-entry
cap. These limits cannot reset per PID or during process churn, and exhaustion
never proves process absence.

Runner construction supplies the same session inspector to ordinary recovery
and operator-stop reconciliation. Production uses the shared strict inspector;
synthetic-process orchestration tests inject their process-table view instead of
sampling unrelated host workers. Identity rechecks, namespace checks, and lease
ownership remain in the real retirement path.

Both shared-host scanners classify each PID under a fixed three-attempt bound.
The first readable stat pins that entry's start tick. An `ENOENT`/`ESRCH` from a
later UID, environment, or ancestry read, or an observed parent/session change,
restarts only that PID from a fresh stat and new ancestry. An entry absent on
that fresh read is ignored as exited; a changed start tick is PID reuse and
remains unverifiable. Malformed metadata, unapproved permission denial, live
session/token evidence, a surviving descendant, and exhausted churn keep the
existing fail-closed result. This per-entry retry applies identically inside the
live supervisor and during replacement-owner recovery; it does not extend the
completion grace below.

Completion-time descendant inspection retries transiently incomplete evidence
against one non-resetting one-second descendant-grace deadline. Complete
evidence resumes the ordinary success or bounded TERM/KILL path; uncertainty at
the deadline retains the existing fail-closed error. While the current owner
still holds the private child handle and control channel, it makes one bounded
teardown attempt through that boundary and rechecks the owned session. An empty
retained supervisor is retired and its durable process record is cleared before
the original containment error is returned. If owned descendants survive or
inspection remains incomplete, the process record and exclusion remain; the
parent never signals a host PID from persisted identity alone.

The runner service accepts revision-bound `requestOperatorStop` requests and
monitors durable revisions while executing. An accepted request aborts only
the owned provider or trusted execution and publishes stopping activity.
Provider recovery attempts and the constrained commit executor check the same
abort signal before starting. The run/worktree leases remain held through
process shutdown, read-only reconciliation, and the final stop event. The monitor
serializes process registration/retirement and stop-activity writes under that
lease, so abort-triggered cleanup cannot race publication of the stopping event.
Persisted
process ownership also prevents a different run from reclaiming the worktree
after owner loss, and prevents checkpoint advancement before process cleanup.
CLI/MCP command registration remains transport-owned.

After owner loss, the replacement execution lease inspects the recorded
PID/boot/start, frozen ancestry baseline, control-group identity, and namespace
evidence. A PID that
vanishes between liveness and identity reads is checked again and classified
dead only when that second read proves absence. Same-boot PID replacement, a
live or unverifiable owner, an initial-host namespace hidden from the recovery
process, missing or incompatible frozen ancestry, incomplete descendant
inspection, or surviving descendants all retain the record. A previous boot or
a dead same-namespace session with a complete empty descendant scan permits
journaled clearing under the replacement lease. Current-boot namespace
mismatch remains unverifiable even when the recorded owner PID is dead.
Crashes before clearing repeat retirement proof; crashes after clearing repeat
resource and checkpoint settlement without signalling the former PID.

Each pipeline has a reconciliation-only entry path with provider invocation,
trusted commands, and artifact writes disabled. It rechecks frozen inputs and
the interrupted access contract, preserves safe partial content, rejects index
or Git-control drift, and retains safety blockers. Content-changing partial
work invalidates dependent gates and charges correction work once; the exact
suspended journal checkpoint remains inspectable. Consumed commits are verified
without reinvoking their executor. Handoff reconciliation only inspects whether
the existing index is complete or untouched; it never stages. Verified effects
and step advancement are included atomically in the final stop event.
When the runner proves that an operator stop prevented commit invocation,
verification of unchanged Git state retires the unused authorization. Resume
can obtain a new authorization; uncertain or begun effects remain verification-only.
Provider error redaction retains that runner-owned pre-effect stop proof while
discarding native error wrappers; unrelated rejections remain blockers.

Reconciliation produces `WAITING_FOR_USER` with `operator_paused` and an
explicit null resume action, or terminal `CANCELED`. A bounded private
`operatorResume` record retains the reconciled workflow position, active-turn
reconstruction marker, and any preceding pause. Null resume restores an existing
pause without consuming its editor authorization or bypassing its blockers.
Otherwise it reconstructs the preserved logical role from frozen configuration
and session lineage only after reacquiring any required worktree lease.
Invalidated content returns through the pipeline's
candidate gate before further finalization. Cancellation cannot resume.
Cancellation superseding a pause during reconciliation changes only the final
outcome; verification never replays an effect or counts its progress twice.
Authorized clarification edits remain pending; stop reconciliation checks Git
safety without consuming them or classifying them as frozen-input drift. Input
drift outside that window cannot skip repository reconciliation.

`state.json` contains the common versioned envelope: monotonic revision,
pipeline ID and state version, an explicit runtime-compatibility tuple,
canonical paths, resolved roles, counters, hashes, pause state, session
lineage, nullable bounded active provider role/phase, timestamps, and opaque
pipeline-owned state, including its resolved settings from the initial
revision. The compatibility generation is maintained independently from the
package version, which is not a persistence contract.
The root validates JSON shape, size, and the common terminal/stop lifecycle;
pipeline-specific roles and outcomes remain opaque to the state capability.
Session lineage records an optional source-session reference, its resolved
trusted profile when known, and every direct child role/session ID with its
accepted-input and pipeline-checkpoint context key. Legacy role records missing
`profile` or `contextSize`, and missing or nullable `model`, normalize to
`current` in memory without rewriting state or event history. Envelope versions
1–7 also normalize absent active-role `effort` to `current`; version 8 requires
a portable effort value on every saved role. The leased runtime migration
persists those defaults without provider activity or configuration reload,
preserving prior journal records, progress, leases, and session evidence.
Changing runner configuration never re-resolves saved effort; changing protected
project configuration retains the safety pause without changing saved roles.
Native session resume remains an optimization rather than a correctness dependency.

Lock-free readers reject unsupported envelope, runtime, or pipeline versions
with an actionable version-skew error and never rewrite durable state. A
supported legacy envelope may be projected through the pipeline's explicit,
ordered migrations for status. Before workflow execution, the runner evaluates
the complete migration chain, validates the current pipeline shape, and appends
one complete migration event while holding the per-run execution lease. The
event upgrades the envelope and pipeline state atomically without rewriting
earlier history. Missing, failing, or forward-version migrations fail closed.

Plan execution persists each prepared or consumed one-shot commit authorization
and every verified commit SHA. After an ambiguous commit turn, resume verifies
the recorded authorization against Git state and never replays the effect.
An adapter may record `commitExecutor: "not_started"` only at the `commit`
checkpoint, with `none` or `possible` effect evidence, when it proves that its
isolated commit executor was never invoked. The boundary derives
`effectStarted: false` from that validated record. The pipeline durably records
that bounded proof on the consumed authorization before Git verification.
For a classified readiness policy rejection, the consumed `preEffectRejection`
also retains optional `diagnosticClass` derived from the validated failure record.
Only the three finite readiness categories are accepted there; terminal
readiness metadata cannot coexist with availability or authentication proof.
Interrupted verification retains that metadata. After Git independently
confirms that no commit was created, the pipeline retires the
authorization before a later resume can issue a fresh ID. An absent marker or
executor failure keeps the consumed authorization on the verification-only
path, while interrupted verification retains any recorded proof for resume.
Polishing has no commit authorization and preserves the initial `HEAD`, refs,
remotes, and Git identity through completion.

Plan authoring state version 2 adds the resolved mode, the fingerprint accepted
by lazy clean confirmation, and the one-time lazy source-fork marker. Its
version-1 migration selects `independent` and initializes the new checkpoint
fields without moving the workflow, replaying a role turn, rewriting a draft or
artifact, or reviving a terminal run.

Plan authoring state version 3 adds a pipeline-owned lazy-checkpoint correction
ledger and nullable pending marker scoped to `CHECK_AND_FIX` or
`CLEAN_CONFIRM` and the exact draft fingerprint. Each record retains only
attempt `1` and bounded Planner field-and-constraint diagnostics. Its ordered
version-2 migration initializes both fields empty without moving active or
terminal workflow positions, reviving terminal work, replaying an accepted
checkpoint, consuming revision or correction budgets, or writing `plan.md`.

Plan execution state version 23 scopes validation to canonical plan steps. Its
private `validation-schedule.js` derives per-step inventories from immutable
Worker-first accepted role assignments, unioning applicability of identical
commands. Independent and combined retain both roles; lazy retains Worker only.
Each role must cover every step with its complete applicable procedure. Shared
infrastructure stays globally fingerprinted. The persisted schedule must match
its role evidence; only a confirmed current-step amendment may overlay the
active inventory. Verified advancement clears that amendment and prior gates
and selects the next schedule entry.

Finalization records its active step and exact ordered checks; terminal
confirmation hashes the complete canonical evidence tuple. Resume validates
both bindings before reuse. Confirmation also sees future requirements when
assessing shared infrastructure changes. Trusted capability inspection uses the
complete catalog and both roles' additive reports; finalization reserves and
executes only active selected commands. The frozen snapshot, vectors, identities,
and command/configuration fingerprints stay intact.

The explicit version-22 migration retains historical unscoped evidence under a
provisional legacy marker. It never infers applicability. Before unfinished
work advances, a read-only barrier invalidates active gates and requires scoped
discovery by every mode-required role. Accepted partial discovery survives
restart. Completed effects, pauses, configuration, and correction accounting
are preserved; terminal history remains readable. Consumed stagnation arbitration
and pending rework survive discovery; incompatible pending correction markers
retire without resetting their ledgers or fix accounting. Consumed commit
verification precedes discovery and capability preparation, with any subsequent
unfinished step subject to the same barrier. Older historical inventory contracts below
remain relevant to their migration chain.

Plan execution and polishing state version 2 persist the mode-specific
bootstrapped required-check inventory, the repository-relative files that own
validation infrastructure, and a runner-computed fingerprint of those files.
Plan execution and polishing each own a 256-item limit for each bootstrap role
inventory field and a separate 512-item limit for each derived, persisted,
finalization, and fingerprint-input field. A role exceeding its pipeline's limit
reports strict `CAPACITY_EXHAUSTED` with that `capacityField`
and per-role `capacityLimit`; required-check overflow takes priority. The
pipeline pauses without consuming a correction or accepting truncated evidence.
Validation infrastructure includes files owning commands, discovery, runners,
configuration, or mandatory finalization guidance, excluding ordinary source,
individual tests, fixtures, and generated output merely consumed by checks.
Classification uses responsibility rather than filename heuristics.
The Git validation-infrastructure fingerprint API accepts 512 paths; other Git
path lists retain their 256-path bounds. Execution state version 16 and polishing
state version 12 expand capacity with leased migrations preserving legacy 64/128
evidence, budgets, completed commits and handoffs, and one-shot effects. Item,
structured-output, and durable byte limits do not change. Expanded schemas
retain strict Claude preflight and native sandbox restrictions. Only Claude's
independently proved command-boundary policy sets `allowAllUnixSockets: true`
so the authenticated launcher, rather than Claude's automatic command path,
orders the pinned seccomp helper before its single bubblewrap boundary. Neither
process encloses or weakens provider transport.
In independent mode, the runner establishes that inventory from accepted Worker
evidence followed by accepted Reviewer evidence; in lazy mode, accepted Worker
evidence is complete. It deduplicates exact commands and paths in stable
first-seen order and assigns contiguous `C1`-through-`Cn` IDs; independent-mode
reconciliation and arbitration resolve only summaries and material
disagreements and cannot add commands or paths. Validation-migration discovery
uses the same mode-specific derivation.
The version-1 migration preserves safe workspace content while invalidating
active aggregate finalization and review evidence. Paused legacy evidence is
explicitly provisional: before a retry, override, finalization, or review can
advance, fresh independent Worker and Reviewer checkpoints re-establish the
inventory and the runner fingerprints it again. A consumed plan-execution
commit authorization remains on the verification path until Git resolves its
effect; migration never converts it into a replayable authorization. Immutable
terminal history is shape-upgraded without replaying an effect.

Plan execution state version 3 adds the nullable bounded pre-effect rejection
record to each pending commit. Its version-2 migration sets that record to
`null`; it never infers proof for a legacy consumed authorization.

Plan execution state version 4 adds a bounded bootstrap-correction ledger. Its
version-3 migration initializes an empty ledger without changing accepted
bootstrap context, validation evidence, workspace content, commit authority, or
workflow position. Each producing role, phase, and contract may consume at most
one read-only correction attempt. The durable entry contains only attempt `1`
and the existing bounded role, phase, contract, field, and constraint
diagnostic; rejected values and provider output are never persisted. A bounded
pending copy distinguishes a correction that still must run from consumed
history and is cleared as soon as a valid replacement is accepted. Each adapter
maps its native structured-output failure to the shared bounded
`structured-output` failure class. Pipelines consume only that backend-neutral
class, and plan execution turns it into the bounded semantic diagnostic only
after read-only mutation checks complete.

Plan execution state version 5 adds the resolved trusted-validation snapshot
and executor provenance to every accepted per-check result. Its version-4
migration selects empty legacy trust and invalidates active finalization and
review gates through the existing independent validation-migration checkpoint.
Immutable terminal evidence is shape-upgraded, and a consumed one-shot commit
authorization remains on its verification-only path; migration never makes it
replayable.

Plan execution state version 6 makes validation inventories staging-independent
and assigns the Git index exclusively to `COMMIT`. Its version-5 migration
shape-upgrades clarification, preflight, and immutable terminal states without
rediscovery; clears partial bootstrap evidence at an unfinished bootstrap; and
routes every other prepared nonterminal run through fresh independent summaries,
resolved context, and validation before advancement. A consumed commit
authorization and its gate evidence stay on the verification-only path. Git
verification runs before reconciliation, migration discovery, or another role
turn, and any still-pending migration resumes only after that effect is resolved.

Plan execution state version 7 adds one finalization-correction record and a
matching pending marker scoped to the current commit step. Its version-6
migration initializes both to `null` without changing workflow position or
evidence. The first invalid Worker finalization result records only attempt `1`,
the step, bounded guidance and content-fingerprint scope, and the role, phase,
contract, field, and constraint diagnostic. The runner then reconstructs the
complete finalization request from durable state and uses the same schema for
one fresh-session, read-only correction turn. A valid replacement clears the
pending marker and rejoins the existing gate; a second invalid result fails
closed. Rejected values, commands, paths, provider text, and transcripts never
enter state or public activity. Interrupted correction recovery remains
read-only and does not require a native session.

Plan execution state version 8 replaces that single record with a two-entry
finalization-correction ledger and one pending attempt. Its version-7 migration
preserves a consumed or pending attempt as the first one-entry diagnostic batch
without changing workflow position, evidence, or correction scope.
Deterministic finalization validation batches independently detectable
violations where practical and always includes every staging-dependent required
command. The first batch may authorize attempt `1`; one wholly new batch may
authorize attempt `2`. Any repeated diagnostic, mixed repeated/new batch, or
invalid result after attempt `2` fails closed. Guidance identifies how to
reconstruct a pending request and never creates another budget. The ledger is
scoped to the current step and request content fingerprint and is cleared when
that content scope changes. Rejected commands, paths, values, provider text,
and transcripts remain outside state and public activity, while interruption
preserves the pending attempt without replaying or recounting it.

Plan execution state version 9 makes user finding overrides unique by exact
finding ID and reviewed content fingerprint and requires every finalization
validation-infrastructure candidate to pass the same existing canonical-file
inspection as bootstrap evidence before fingerprinting or review. Its version-8
migration deduplicates legacy override audit entries, preserves completed
commits, safe current-step content, counters, Git controls, and one-shot commit
effect safety, and marks active validation evidence provisional. Before
advancement, the existing validation-migration checkpoint independently
rediscovers the complete stable inventory and invalidates provisional
finalization and review evidence. Immutable terminal history is shape-upgraded
without replaying work.

Plan execution state version 10 replaces each consumed or pending bootstrap
correction's single field diagnostic with one bounded, deduplicated diagnostic
batch. Its version-9 migration losslessly wraps every existing diagnostic in a
one-entry batch without changing workflow position, accepted context, safe
content, gates, counters, or commit authority. Deterministic bootstrap and
validation-migration validation collects all independently detectable
violations from one candidate where practical, including every
staging-dependent required command and every lexically valid
validation-infrastructure path that canonical-file inspection rejects. The
producing role still receives exactly one correction attempt for its phase and
contract; a pending batch survives interruption and is cleared only after a
valid complete replacement is accepted. Repeated or still-invalid output fails
closed. Durable state and public activity contain only bounded diagnostic
identities, never rejected values, commands, paths, provider output, or
transcripts.

Plan execution state version 11 adds one final-Reviewer correction record and
a pending marker scoped to the current step, finalized content fingerprint,
and validation-infrastructure fingerprint. Its version-10 migration initializes
both to `null` without moving the workflow, altering accepted finalization or
review evidence, reviving terminal runs, or inferring rejected output that was
never retained. The first provider structured-output, normalization, or
validation-change consistency failure records attempt `1` and only bounded
Reviewer/review field-and-constraint diagnostics, then reconstructs the full
unchanged review request for a fresh-session, read-only correction with the
same schema. Interruption and backend unavailability preserve that pending
attempt without replay or recounting. A still-invalid replacement pauses at
the deliberately retryable `review_output_invalid` REVIEW checkpoint; an
explicit retry reruns the pending correction without approving content or
bypassing finalization, findings, fingerprints, Git guards, or commit
authorization. Rejected values, findings, commands, paths, provider output,
prompts, and transcripts never enter durable state or public activity.

Plan execution state version 12 adds the resolved mode, the fingerprint
accepted by lazy clean confirmation, and the one-time lazy source-fork marker.
Its version-11 migration selects `independent` without moving active or terminal
workflow positions, changing completed commits, or replaying a pending or
consumed one-shot commit effect.

Plan execution state version 13 adds a pipeline-owned lazy-checkpoint
correction ledger and pending marker. Each record is scoped to the current
step, `CHECK_AND_FIX` or `CLEAN_CONFIRM` phase, finalized content fingerprint,
and validation-infrastructure fingerprint and retains only attempt `1`, whether
actual fix work was already charged, and bounded Worker field-and-constraint
diagnostics. The version-12 migration
initializes both fields empty without moving active or terminal workflow
positions, changing accepted gates or completed commits, reviving terminal
runs, or replaying agent or commit effects.

Plan execution state version 14 separates semantic candidate convergence from
the terminal gate. Independent `REVIEW`, or lazy `CHECK_AND_FIX` plus candidate
`CLEAN_CONFIRM`, now precedes `FINALIZE`; passing finalization enters the new
read-only `CONFIRM` checkpoint before `COMMIT`. Candidate and terminal results,
fingerprints, correction diagnostics, and public activity are distinct. The
version-13 migration preserves terminal runs and consumed commit authorization
on verification-only paths and retains an unfinished `IMPLEMENT` checkpoint.
Evidence at every later active checkpoint that cannot prove the new ordering is
invalidated and routed to safe mode-specific candidate convergence. Retained
legacy terminal-Reviewer correction diagnostics are translated into the new
terminal-confirmation namespace on immutable paths.

Plan execution state version 15 adds bounded semantic finalization recovery.
Terminal roles share rejection routing: after the exact whole-result override
gate, `REJECTED` invalidates finalization immediately. The structured
`finalizationFindingIds` subset separates evidence-only findings from content
repairs. Pure rejection preserves candidate approval and re-enters `FINALIZE`
without code-fix accounting; mixed rejection resolves content first and still
requires replacement finalization. The complete deterministic gate preserves
established check IDs/commands and infrastructure entries, and fresh confirmation
binds the resulting fingerprint. Ordinary non-rejection reuse is unchanged.
Evidence rejection remains valid when inventories are unchanged; equality of
the inventory cannot substitute for sufficient check evidence.

The version-14 migration initializes metadata without interpreting missing
provider output or replaying workflow/effect history. Two semantic retries per
step are reserved durably before invocation. Pending attempts survive
interruption and unavailable providers without recounting; fingerprint drift
clears feedback without restoring allowance. Exhaustion exposes
`finalization_evidence_rejected` at `FINALIZE` with one explicit additional
attempt per null retry. Independent overrides use the saved terminal content
fingerprint; closing recovery feedback still requires replacement finalization
and fresh confirmation. Only bounded validated findings and control metadata
are retained. Each pipeline owns its recovery policy independently; polishing
adopts the same contract with a per-run allowance in state version 11.

Polishing state version 3 adopts the same resolved trusted-validation snapshot,
per-check executor provenance, and fingerprint-bound evidence tuple. Its
version-2 migration selects empty legacy trust, preserves safe workspace
content, and invalidates active finalization and review evidence through the
existing independent validation-migration checkpoint before advancement.
Retained `BLOCKED` and `NOT_RUN` entries in paused or immutable failed evidence
become `FAIL` without losing their bounded diagnostics. Immutable terminal
evidence is shape-upgraded without replaying work.

Polishing state version 4 adds its bounded bootstrap-correction ledger and
pending one-shot diagnostic. Its version-3 migration initializes both without
changing accepted bootstrap context, validation evidence, workspace content,
or workflow position. Each producing role, bootstrap or validation-migration
phase, and contract may consume one read-only correction;
only attempt `1` and the bounded role, phase, contract, field, and constraint
are durable. A valid replacement clears the pending copy, an interrupted turn
reconstructs it from state, and a second invalid result fails closed without
retaining rejected values or provider output. Validation migration also
persists its accepted bounded disagreement before arbitration, resumes that
checkpoint directly, and clears it when the migration completes.

Polishing state version 5 adds the durable runner-owned `HANDOFF` boundary.
Its version-4 migration preserves immutable terminal history and untouched
preflight state, clears partial bootstrap evidence, and routes applicable
prepared nonterminal runs through fresh independent staging-free validation
before they can advance. Legacy paused evidence remains provisional until
resume invalidates it through that checkpoint.

Polishing state version 6 makes bootstrap, validation-migration, and
finalization inventories staging-independent. Its version-5 migration preserves
immutable terminal history, frozen inputs, safe content, counters, Git controls,
and trusted-validation state; clears incompatible partial bootstrap evidence;
invalidates stale active finalization and review gates; and routes prepared
nonterminal work through fresh independent inventory discovery. A legacy
`HANDOFF` is reconciled first: a complete verified effect becomes immutable
completion, an untouched pre-effect state enters discovery without staging, and
an incomplete or contaminated index fails closed.

Polishing state version 7 adds one finalization-correction record and a
matching pending marker scoped to the current content fingerprint. Its
version-6 migration initializes both to `null` without changing workflow
position or evidence. The first invalid Worker finalization result records only
attempt `1`, bounded resolved-or-fallback guidance and content-fingerprint
scope, and the role, phase, contract, field, and constraint diagnostic. The
runner reconstructs the complete finalization request from durable state and
uses the same schema for one fresh-session, read-only correction turn. A valid
replacement clears the pending marker and rejoins the existing gate; a second
invalid result for the same content fails closed. Content changes clear stale
correction scope. Rejected values, commands, paths, provider text, and
transcripts never enter state or public activity. Interrupted correction
recovery remains read-only and does not require a native session. `HANDOFF`
remains the sole Git-index owner for both Codex and Claude turns.

Polishing state version 8 adds the resolved mode, the fingerprint accepted by
lazy clean confirmation, and the one-time lazy source-fork marker. Its
version-7 migration selects `independent` without moving active or terminal
workflow positions, changing safe workspace content, or replaying a pending or
completed `HANDOFF` effect.

Polishing state version 9 adds a pipeline-owned lazy-checkpoint correction
ledger and pending marker scoped to the checkpoint phase, finalized content
fingerprint, and validation-infrastructure fingerprint. Its version-8
migration initializes both fields empty without moving active or terminal
workflow positions, changing safe workspace content, or replaying a pending or
completed `HANDOFF` effect.

Polishing state version 10 separates semantic candidate convergence from the
terminal gate. Independent `REVIEW`, or lazy `CHECK_AND_FIX` plus candidate
`CLEAN_CONFIRM`, precedes `FINALIZE`; passing finalization enters the new
read-only `CONFIRM` checkpoint before `HANDOFF`. Candidate and terminal results,
fingerprints, and bounded correction diagnostics are distinct. The version-9
migration invalidates unprovable active gate evidence and routes it through safe
mode-specific candidate convergence, defers the same repair for paused runs,
and preserves `HANDOFF`, `DONE`, and `FAILED` without replaying staging.

Polishing state version 13 enables combined review with independent roles,
bootstrap, and isolated checkpoint sessions. Worker check/fix and separate
read-only clean confirmation precede independent candidate review of the same
fingerprint; independent terminal confirmation covers finalized content before
runner-only handoff. Durable `primaryFindings` keep self-findings separate from
independent findings. Content repairs clear both gates; unchanged resolutions
retain only current finalization. Only independent finding resolution permits
fresh arbitration; unresolved bootstrap and primary exhaustion pause. Version-12
migration adds an empty primary-findings record without changing saved mode,
correction budgets, or consumed handoff evidence.

Polishing state version 11 adds the same bounded semantic finalization recovery
as plan execution, with two automatic attempts per polishing run. Both terminal
roles share deterministic pure/mixed rejection routing within polishing. Exact
terminal-fingerprint overrides are checked first; otherwise rejected evidence is
invalidated immediately and replacement finalization plus fresh confirmation
must pass before runner-owned `HANDOFF`. Pending attempts survive interruption
and environment/provider blockage without recounting. Scope drift clears feedback
without restoring allowance; explicit retry after exhaustion grants one additional
attempt. The version-10 migration initializes metadata without moving checkpoints,
inferring old rejection output, or replaying pending or completed staging effects.
The existing polishing malformed-output correction budget and index restrictions
remain unchanged.

Common run-envelope version 3 adds `activeTurn`, either `null` or the current
bounded `{ role, phase }`. Version-1 and version-2 runs project it as `null`
without rewriting state or history; the next mutating continuation persists the
explicit ordered runtime migration under the execution lease.

## Agent Context Recovery

Backend sessions are disposable execution context, not durable workflow state.
Adapter capability probes inspect the installed CLI and enforceable local
isolation only. They do not apply a selected native profile and do not claim
that its authentication or provider is usable; that is established by the
first real turn under the effective profile.

Turn requests accept an optional synchronous `onProgress` observer. The shared
internal contract emits frozen `{ kind, activeCommands }` records only. Its
closed kinds are `semantic`, `local-command-started`,
`local-command-completed`, `local-tool-started`, and `local-tool-completed`.
The nonnegative command count covers overlapping commands independently of
other local tools. Provider-private identities correlate starts and completions;
duplicate starts/completions and unmatched completions cannot change the count.
Each attempt bounds its retained tool identities to 16,384 and retires remaining
activity only after process retirement. Progress carries no native identifiers,
payloads, commands, output, diagnostics, or timestamps. It is not public CLI/MCP
activity; the shared inactivity watchdog consumes it without changing availability
backoff or emitting native events publicly.
Observer failures are redacted; retirement reporting cannot replace an already
established provider failure.

Codex derives progress from validated, matching thread/turn notifications for
turn and item lifecycle events and nonempty text/reasoning/plan deltas. Up to
1,024 payload-free facts can precede the `turn/start` reply; only facts matching
the returned turn are delivered. Command-output deltas, unrelated turns,
keepalives, and unknown traffic provide no semantic progress. Final turn-item
auditing and failure classification remain authoritative.

Codex App Server capture bounds each UTF-8 JSONL frame incrementally to 16 MiB,
including frames without a terminating newline, and bounds aggregate stdout and
stderr to 64 MiB per attempt. Fragmented multibyte text and CRLF remain supported;
invalid UTF-8, JSON or response envelopes fail closed. Retained completion and
model-reroute notifications allow at most 128 records and 16 MiB in total.
Delivered responses and completions cannot hide an already observed protocol
rejection; acquired items retain audit precedence. These limits do not change
owned-process retirement or the three one-second shutdown phases.
Process exit preserves bounded matching completion evidence for normal auditing;
protocol rejection invalidates retained notifications.

Resume and fork request `excludeTurns: true` while preserving thread, model and
lineage checks. The matching terminal notification selects the turn. Full items
are audited directly; `summary` and `notLoaded` views require ascending
`thread/items/list` pages filtered by that turn ID. The Codex 0.160.0 public
contract supports this full-item listing and `thread/turns/list`, whose default
item view is summarized. A known completed turn needs no turn enumeration or
whole-thread `thread/read` hydration. Unsupported listing fails closed.
Hydration requests at most 32 pages of 128 items, retains at most 4,096 unique
item IDs and 16 MiB of serialized page data, and validates page envelopes,
turn membership, timing fields and bounded advancing cursors. Every acquired
item receives the existing policy/isolation audit before another acquisition or
cursor/limit rejection. Only complete traversal becomes a full audited turn;
summaries and partial collections cannot authorize output or effects.

Claude consumes UTF-8 JSONL using `--output-format stream-json --verbose
--include-partial-messages`. The private parser bounds each line to 16 MiB and
the complete stdout stream to 64 MiB, validates message/block/session envelopes,
and retains one terminal result for the existing structured-output, permission,
failure, model, and session-lineage checks. Partial tool-input generation is
semantic progress; a complete Bash tool-use starts command activity, and its
matching tool-result completes it. Recognized background Bash tasks have their
own correlated lifetimes. File tools report separate start/completion events.
Token accounting, tool-progress heartbeats, and irrelevant records do not emit
progress. Malformed, duplicate, or missing results cannot become success;
permission failures and uncertain killed-process outcomes retain precedence.
Owned process capture delivers bounded stdout chunks without bypassing durable
registration, containment, cancellation, retirement, or storage cleanup.

Every model-free subprocess used for version/help, Claude `socat` and isolation
policy checks, the local-commit executor proof, or owned-process namespace
proof has a 10-second deadline. Within that outer bound, a local-commit probe
has a one-second network-denial observation deadline; silence cannot prove
isolation, so exhaustion fails the capability closed. Claude's per-turn Git
metadata preparation and both providers' pre-effect local-commit Git metadata
lookups use the 10-second bound. These preparation deadlines do not cap the
authorized commit effect after it begins. Codex MCP configuration discovery is
the deliberate exception: it makes at most two `mcp list` attempts with a
30-second subprocess deadline apiece and no added retry delay, then reports
recoverable provider unavailability. Codex model-catalog discovery issues at
most 32 page requests with a requested limit of 100 entries per page, and
rejects a repeated cursor. The 256-name MCP configuration capacity and
catalog-page cap are schema and protocol defenses, not operator-configurable
work budgets.

The shared adapter contract accepts optional `effort` in execution options and
turn requests, validated by each registered provider through that contract.
Its closed vocabulary is `current|low|medium|high|xhigh`; omission and `current`
normalize to no override. Model identifiers cannot contain whitespace, so a
combined model-and-effort string is rejected before provider activity.
Native translation stays within the providers: Codex supplies
`model_reasoning_effort` at process launch and `effort` on every `turn/start`;
Claude supplies `--effort`, translating portable `xhigh` to native `max`.
The supported Codex App Server baseline includes effort control. Claude's
model-free help probe must advertise the requested native tier. These checks
apply only to explicit selections and do not add requirements to `current`.
Codex uses `model/list` reasoning-tier metadata when present. An explicit model
is checked before thread selection; an inherited model uses the selected
thread's effective model, falling back to effective configuration or the
catalog default when unavailable. Missing tier metadata or an unlisted
inherited model defers support to the provider instead of guessing a model
capability. Every continued, forked, compacted, reconstructed, and
commit-readiness turn retains the same effort.
Both adapters normalize an unsupported explicit selection or bounded native
effort/model rejection to non-recoverable `ERR_UNSUPPORTED_EFFORT` and
`effort_unsupported`. Codex classifies relevant RPC errors before discarding
their payloads and preserves that classification through thread recovery.
Structured authentication, usage, and transient failures retain their existing
semantics. A specific Claude effort rejection takes precedence over a generic
turn-setup failure. Native rejection text is not retained, and commit-readiness
failure cannot start or replay the constrained executor.

On Linux, Claude selects an isolation policy independently for read-only,
workspace-write, and local-commit access. The selector first uses the fixed,
model-free provider/child probe around Claude's embedded `apply-seccomp` helper
for the full native sandbox. Only a positively recognized
nested-user-namespace denial may try the fallback. A bounded model-free version
invocation first proves that Claude accepts the spawning-parent policy option.
The isolation proofs invoke no model or provider transport. The native proof
invokes Claude's local embedded seccomp helper. The fallback proof supplies
representative effective arguments without that automatic dispatch through
the same provider-private command launcher, validation grammar, and
access-aware topology installed for model commands.
Fallback turns launch the Claude CLI directly so authentication and provider
transport retain the host environment and network path. The invocation-local
spawning-parent policy selects the short-lived launcher only when Claude starts
a sandboxed command without changing the provider's `PATH`. The launcher pins
the canonical host `bwrap` executable before the turn instead of resolving it
through a potentially workspace-writable path. The launcher file is non-writable.
Its owner-only allocation is outside the project, task, and state trees, and
command namespaces cannot write the allocation. The adapter retains directory
authority for teardown.
The authenticated launcher accepts one closed Claude bubblewrap grammar: the
session and parent-lifetime flags; unique environment removals or non-protected
assignments; network unsharing; a read-only root followed by supported bind,
read-only-bind, or private-runtime tmpfs operations; the synthetic device
mount; PID and required user unsharing; Claude's weaker host `/proc` bind; and
exactly one absolute shell, `-c`, and opaque command payload after `--`. The
launcher translates the required user-unshare argument into exactly one
bubblewrap user namespace. Claude's fixed
incidental write binds for its temporary, npm-log, and debug paths are
recognized exactly but discarded rather than exposing their host paths. All
other writable binds must resolve inside the canonical workspace, must not
resolve inside Git metadata, and are accepted only for workspace-write access.
Read-only binds must preserve their source path except for Claude's `/dev/null`
or verified owner-only empty-directory masks beneath the canonical runtime
temporary root, both limited to strict workspace descendants. Empty-directory
masks are replaced by private read-only tmpfs mounts rather than exposing their
host temporary sources.
The exact expected workspace and Git mounts, including redundant Git
descendants, are replaced by Runner-owned mounts. Other same-path read-only
workspace descendants preserve Claude's command-protection policy; every
remaining read-only bind must not overlap the writable workspace or any part of
the Runner-private device, process, runtime, or launcher trees. Only `/tmp` and
`/run` may be supplied as tmpfs destinations; the launcher replaces them with
its own private mounts. A later writable bind may not overlap an established
read-only workspace restriction, and no later mount may re-expose a path hidden
by a private workspace mask.
Duplicate environment operations, assignments to `ARGV0`, credentials, or the
launcher token, writable roots, unsupported options, malformed namespace
arguments, malformed option arity or ordering, and extra payload arguments exit
before any child starts.

After validation the launcher drops Claude's host `/proc` bind and strengthens
the same invocation with PID-1 behavior, an empty capability set, private
procfs, private `/tmp` and `/run`, a private `/tmp/claude`, a hidden launcher
path, the exact workspace authority, read-only resolved Git metadata, missing
protected-environment removals, and the requested working directory. A private
Claude module serializes a classic seccomp BPF for little-endian x64 or arm64.
The program validates `seccomp_data.arch`, kills an architecture mismatch,
returns `EPERM` for `socket(AF_UNIX, ...)`, `io_uring_setup`,
`io_uring_enter`, and `io_uring_register`, and allows other syscalls. X64
covers both native and x32 syscall numbers. Unsupported architectures and
malformed programs fail before launch.

On every invocation the authenticated launcher decodes and hashes the exact
filter bytes, writes and syncs an owner-only no-follow file, reopens it
read-only, and unlinks it before verifying the link-free descriptor's owner,
mode, size, identity, and complete contents with positioned reads that leave
its offset at zero. It then removes its authorization token, `ARGV0`, and
provider credentials and invokes the pinned real `bwrap` directly once,
passing that sealed resource as inherited child descriptor `3` with
`--seccomp 3`. Filter creation, tampering, descriptor inheritance, bubblewrap
setup or execution, close, and resource cleanup errors all fail closed. The
fallback's `allowAllUnixSockets: true` setting suppresses Claude's automatic
helper dispatch so the Runner-owned filter is the only fallback socket policy.
The command crosses one user, PID, mount, and network namespace boundary; the
fallback never invokes Claude's seccomp helper or creates a nested user
namespace.

The direct fallback probe supplies representative effective Claude arguments
to that same validator and execution path. Native and fallback child probes use
a disposable committed repository to require compound repository inspection
and, for read-only access, reject workspace, Git, and local remote-ref
mutations. They also check access-specific workspace writes, outside-write
denial, private temporary storage, IP isolation, inability to reach live host
abstract and pathname Unix sockets, credential and `ARGV0` removal, and host
provider-proc secrecy. The selected fallback sets
Claude's required weaker-nesting option and `allowAllUnixSockets: true`, so no
second automatic helper is added to the opaque command payload. Native policy
retains `allowAllUnixSockets: false` and its existing stricter topology.
Arbitrary native failures, launcher construction or execution failure,
incomplete proof, or cleanup failure do not enable the fallback.
Both policies keep model-command network, host Unix sockets, credentials, Git
metadata, remotes, and outside writes denied. Probes use fixed representative
arguments and a fixed validated shell payload, the credential-filtered command
environment, and bounded time and output; they retain no host diagnostic and
never apply a profile, authenticate, or invoke a model.
The local-commit executor proof remains independent and `localCommit` requires
both the local-commit turn policy and executor proof.
Both policies now install an authenticated adapter-owned projection launcher.
The native launcher preserves the native namespace/seccomp invocation; only the
restricted-host launcher replaces its known weaker topology. Both preserve
existing descendant masks. Claude prepares its filesystem arguments with an
explicit read-only project reservation and no extra configured write paths;
this prevents it from registering absent project targets for creation or later
cleanup. The authenticated launcher replaces only that exact reservation with
the runner-authorized workspace access. Writable access requires both the
original workspace bind and the preparation reservation. All project bind,
directory, tmpfs, device, and proc targets must resolve before bubblewrap starts.
Missing `.bashrc`, `.gitconfig`, `.mcp.json`, editor directories, and `.claude`
tooling paths must never be materialized inside a writable project bind. No project file is
ignored, filtered from a fingerprint, or cleaned by an agent.

Commands receive an empty, read-only HOME/config projection with private
namespace-local temporary, cache, and runtime directories. The real provider
HOME, authentication environment, selected config directory, and session store
remain separate and unchanged. Provider temporary scaffolding and the fallback
filter's temporary files belong to the same allocation. Probes exercise the
projection launcher too; the contract revisions are `claude-isolation-v2` and
`claude-command-boundary-v8`. Old receipts cannot authorize the new policy.

Before a turn launches, the adapter journals allocation intent and then the
private directory's device/inode identity through the optional `onResource`
request callback. The stop monitor serializes that callback with process and
stop-activity writes; cancellation does not cancel cleanup persistence.
`storageForbiddenPaths` supplies the task/state exclusions in
addition to cwd. The existing execution-resource slot holds the frozen adapter
preparation identity in `commandIdentity`; this identity never selects or
attests a trusted validation command. A provider descriptor may register one
unique resource identity and recovery hook. The runner dispatches retirement
cleanup through this hook without provider branches or changes to Codex.

Cleanup verifies the host, canonical private root, owner, permissions, and child
identity, pins the root descriptor, removes only the recorded child, syncs the
parent, and journals removal. Missing children permit interrupted-removal
recovery; replaced or unverifiable storage remains blocking. Cleanup occurs
only after process and descendant retirement, before a response, fingerprint,
trusted validation, or commit executor can be accepted. Owner-loss resume and
operator stops use the same adapter cleanup under exclusive leases. A still-live
runner retains its private run/worktree lease handles after resource cleanup
failure; a sequential retry revalidates the run token through the state mutation
boundary before reuse, retaining the handle if inspection itself fails.
Concurrent resumes and other owners remain excluded, and stale revisions remain
errors. Restart uses normal identity-based owner reclamation.
`ERR_EXECUTION_RESOURCE_UNVERIFIABLE` preserves the active checkpoint for
repository/effect reconciliation on resume. A fully cleaned pre-launch failure
uses `ERR_AGENT_ENVIRONMENT_PREPARATION` and the existing safe provider pause,
including proven not-started source-fork recovery. Errors retain only finite
`environment_preparation` or `environment_cleanup` class/checkpoint evidence.
A journaled `environment/cleanup-pending` activity distinguishes unfinished
adapter cleanup from a repository check without retaining raw diagnostics.
A stronger provider or containment failure is preserved; the root marks retained
resource ownership so pipelines cannot accept content or finish the turn over
it. Terminal provider failures are persisted as failed checkpoints while their
cleanup reservations remain owned; subsequent cleanup cannot replay the turn.
Process-proof uncertainty stays resumable. Consumed commit effects remain
verification-only.

The provider-private policy identity binds the installed CLI version, selected
isolation policy, complete effective permission, tool, deny, and sandbox policy,
and, for fallback access, the direct-filter contract, architecture, and exact
byte hash. A receipt created for the superseded helper-based fallback, another
architecture, or a prior permission policy cannot authorize later provider
work.
Claude derives its advertised read-only capability and turn arguments from one
autonomous access envelope shared by read-only and local-commit readiness
turns. It exposes only repository-inspection tools and omits broad shell-command
denials that would reject compound inspection, while retaining collaboration,
editing, and web restrictions. Autonomous Bash is available only inside the
proved sandbox, which denies workspace and Git-metadata writes, closes command
network and Unix-socket access, and forbids unsandboxed fallback.
Workspace-write turns retain their separate `auto` permission policy,
background classifier, broader content tools, and existing command denials
while denying Git-directory writes and `git add`. Codex workspace-write
isolation likewise exposes safe content
writes without Git-metadata writes. Codex protects project-root `.agents` as
provider metadata by default, so a workspace-write turn adds it as an explicit
writable root only when it exists as a real directory. A missing or symlinked
`.agents` stays protected, as do `.git` and `.codex`. For each Codex app-server
attempt, the runner creates one canonical owner-only private root beneath the
fixed platform temporary location without consulting ambient temporary
variables. The effective writable set is the repository content, including an
eligible `.agents`, and that private root. `TMPDIR`, `XDG_CACHE_HOME`, and
`XDG_RUNTIME_DIR` project validated children of the root into command tooling
through the effective shell policy. The policy starts from the full provider
process environment, applies Codex's automatic secret-name exclusions and an
empty custom exclusion list, overlays those explicit workspace values, and then
keeps exactly Codex's standard core names (`HOME`, `LOGNAME`, `PATH`, `SHELL`,
and `USER`), `AGENT_RUNNER_OWNED_PROCESS`, and the three workspace names. This
preserves the dynamic ownership proof without exposing unrelated parent
variables. The provider process environment remains unchanged, ambient
`TMPDIR` and host `/tmp` remain excluded, shell profiles stay disabled, and
command network access remains denied. In-session compaction retains the
attempt's root. Every successful, failed, or freshly recovered attempt validates
and removes its root before returning or retrying, and unsafe preparation or
cleanup fails closed.
Codex observes owned-process completion as soon as the App Server starts and
races only its rejection against the complete protocol operation. An ownership
failure therefore starts bounded client and workspace cleanup promptly and
retains precedence over client-cleanup failures, even when containment
deliberately keeps protocol pipes open. Successful owned completion does not
satisfy a protocol request; the adapter still requires the complete App Server
result. App Server shutdown has up to three fixed one-second observation
windows: natural protocol close, TERM, then KILL. These post-turn cleanup phases
are containment invariants, not configurable provider-work deadlines.
Read-only and local-commit storage remain independently isolated. Both adapters
advertise `gitMetadataWriteBlocked`; the runner, not an agent turn, owns effects
that require the index.
Each pipeline's complete and recovery role-prompt envelope provides the
semantic boundary for eligible project `.agents` content: plan authoring
requires an explicit user task, polishing requires the same, and plan execution
additionally requires the current planned commit to authorize the guidance
change. The responsible roles must not propose, make, or approve a change
outside that scope. A compatible continuation inherits the boundary from its
native session, while every fresh or reconstructed context receives it again.
Violations use the owning pipeline's ordinary finding-and-fix route and do not
open a user question.
Every retryable request carries a turn prompt and a complete recovery prompt
reconstructed from validated run state, durable artifacts, and the observed
workspace. A role session is continued only when its persisted key matches the
accepted inputs, role, and pipeline-owned checkpoint. Clarification and normal
work use distinct checkpoints. In independent mode, plan execution also
isolates Worker and Reviewer by planned commit, while polishing isolates
bootstrap from Worker and Reviewer work. Compatible continuations receive only
the current instruction and state delta; first, forked, fresh, and
context-invalidated turns receive the complete prompt. Arbiters remain fresh.

A checkpoint's complete prompt is reconstructed from validated inputs, durable
resolved summaries, its current plan step or change-set fingerprint, active
blockers, and the pipeline's bounded decision history. These inputs remain
durable even when the native session is gone.
Every pipeline role turn also states that the authorized role must produce the
result itself without delegation, subagents, or multi-agent collaboration.
Prompt compliance supplements rather than replaces the adapters' fail-closed
collaboration audit.

Independent mode retains the original role topology: primary and review roles
have separate contexts and any required Arbiter starts fresh. Lazy mode has one
logical primary role and never resolves, probes, forks, invokes, or charges a
Reviewer or Arbiter. Plan authoring uses the Planner; plan execution and
polishing use the Worker. A reconstructed native session is still that same
logical role, and all clarification, no-delegation, provider recovery,
redaction, product-decision, durable-state, lease, and repository guards remain
unchanged.

Lazy convergence is a bounded pipeline-owned loop. A writable
`CHECK_AND_FIX` turn reviews the complete current result with the established
pipeline review criteria and fixes any problem immediately. An unchanged
result enters a separate read-only `CLEAN_CONFIRM` turn with the same criteria,
an explicit edit prohibition, and a strict `CLEAN` or concrete-findings result.
Advancement requires `CLEAN`, no repository mutation, and the exact inspected
content fingerprint. In plan execution and polishing this first converges the
candidate; `FINALIZE` follows, then a distinct read-only `CONFIRM` applies the
validation-change decision to the finalized evidence.
Content findings return directly to `CHECK_AND_FIX`, never to dispute or arbitration.
Ordinary terminal findings clear candidate and confirmation attestations but retain a
successful finalization record while its content and validation-infrastructure
fingerprints remain current. After candidate convergence, the runner recomputes
both fingerprints and retries `CONFIRM` directly on an exact match; otherwise it
invalidates the record and returns to `FINALIZE`. Declared fixes do not stand in
for observed repository mutation. Every actual content or validation-
infrastructure change, provider correction-scope drift, content-changing
interruption reconciliation, and plan-execution commit-step advancement
invalidates finalization evidence. Plan-authoring drafts stay
in external state and are deterministically validated only after confirmation.
Plan execution and polishing route pure validation-evidence rejection directly
to bounded replacement finalization; mixed rejection returns through candidate
convergence before fresh finalization. Both require a fresh terminal confirmation.
Existing fix/revision, stable-finding, stagnation, and additional-round budgets
bound the loop and never silently accept an unconfirmed result.

Plan authoring separates primary convergence, independent review, session scope,
correction accounting, and arbitration eligibility in its private
`review-policy.js`. The workflow and persisted-state contract share these pure
decisions. Turn implementations, effect guards, persistence, and plan writing
remain in the workflow. Combined mode enables both primary convergence and
independent review, retaining checkpoint-isolated sessions and the existing
durable lazy-checkpoint field names. Draft review invalidation
retains correction scopes so returning to an earlier fingerprint cannot reset
an automatic correction allowance.

Combined authoring records primary confirmation separately from Reviewer
approval. A revised draft clears both and restarts primary convergence; Reviewer
reconsideration of an unchanged draft can retain primary confirmation. Self
findings and structural failures return to check/fix, without arbitration on
exhaustion. Only independent finding resolution may request the fresh Arbiter.
Each accepted check/fix or revision consumes one bounded revision round; invalid
output and recovery cannot duplicate accepted work. Version 5 adds combined
mode while migrating saved version-4 independent/lazy state unchanged under
the lease; missing mode remains independent and unsupported old values reject.

Plan authoring owns primary-convergence structured-output recovery at both checkpoints.
Provider and deterministic contract failures become bounded diagnostics, then
one fresh repository-read-only Planner session receives the complete durable
draft-bound request and original schema. Only a valid replacement under the
unchanged draft fingerprint rejoins the ordinary route. Repeated invalid output
pauses at the exact checkpoint with a redacted explicit null retry; interruption
and resume preserve the pending marker without retaining rejected output,
replaying accepted progress, consuming revision or correction budgets, or
writing `plan.md` early.

Plan execution also owns lazy structured-output recovery. Provider and
deterministic checkpoint failures are reduced to bounded diagnostics, then one
fresh Worker session receives the complete durable checkpoint request with its
original schema. A writable check/fix correction may reconcile safe content
exactly once, invalidates dependent evidence, charges actual fix work once,
and must pass complete finalization before the pending checkpoint resumes. A
clean-confirmation correction is read-only and requires unchanged content and
validation-infrastructure fingerprints. Repeated invalid output pauses at the
exact checkpoint with a redacted explicit null retry; retry reconstructs the
pending attempt without recounting its automatic attempt or fix budget. No
correction result can act as early finalization, confirmation, review, or
commit evidence.

Polishing owns the corresponding lazy structured-output recovery before its
runner-owned handoff. A writable check/fix correction reconciles safe content
and charges actual fix work once, invalidates stale gate evidence, and returns
through candidate convergence. A candidate clean-confirmation correction
remains read-only and retains the index, content, and
validation-infrastructure guards. Terminal Reviewer and Worker corrections are
separately scoped to finalized evidence; scope drift invalidates that evidence
and returns through finalization. Repeated
invalid output pauses with bounded redacted diagnostics and an explicit null
retry; neither a correction nor its recovery can stage, approve, or enter
`HANDOFF` early.

When a native context is full, an adapter may compact it and retry the complete
recovery prompt once. If continuation still fails, writable and read-only work
can resume in a fresh session with the same complete prompt and a concise
recovery preface.

Claude turn failures use a finite adapter-owned diagnostic allowlist. Structured
`permission_denials`, `api_error_status`, result subtype, and `terminal_reason`
take precedence over bounded message matching. The adapter discards denied tool
input, native result text, raw standard error, and process causes; only its
fixed code, fixed message, allowlisted class, and safety fields cross the
boundary. Authentication remains terminal. A denial that identifies an
unexposed tool or a Bash command outside the narrow positive repository-
inspection allowlist is also terminal. Only an expected non-Bash tool or a
positively recognized safe Bash inspection may be a recoverable capability or
configuration failure. Structured provider recovery accepts only explicit
transient HTTP statuses; non-transient client statuses and an `api_error`
without a transient status fail closed with a fixed request-rejected error.

The shared failure record optionally carries `availabilityReason`, restricted to
`transport_unavailable`, `temporarily_overloaded`, `model_busy`, and
`server_unavailable`. The adapter contract and registry accept this evidence only
with transient retry eligibility, a `not_started`, `rejected`, or `exited`
outcome, and no started effects. A commit checkpoint additionally requires
validated `commitExecutor: "not_started"` proof. Possible workspace changes still
require repository reconciliation; ambiguous outcomes cannot carry this evidence.

The same exact record may instead carry the finite optional
`disposition: "authentication_required"`. The contract accepts it only for a
terminal rejected response without started effect, process outcome, or
availability evidence. It is not an availability reason and does not collapse
authorization, permission, usage-limit, malformed-request, or ambiguous-effect
failures into authentication.

Provider-private availability recognition maps explicit offline, DNS, refused or
reset connections, timeouts, overload, and model-busy errors. Both adapters map
statuses 408, 425, 500, 502, 503, 504, and 529 to the same finite reasons. Codex
also recognizes native connection/stream and internal-server variants through
closed variant payloads. Its private HTTP-wrapper parser requires bounded,
duplicate-free envelopes; matching transient native statuses may be corroborated
by closed server-error wrappers. Conflicting or malformed evidence cannot qualify.
Only native server-error RPC codes can establish availability at `turn/start`;
protocol/request codes retain precedence. Native text is bounded to 16 KiB for
Codex and below Claude's 4 KiB diagnostic truncation bound. Terminal evidence
excludes an availability reason, and existing structured classifications retain
precedence over text. A Claude budget-exhaustion terminal reason precedes transient
statuses but cannot replace a structured authentication, request, or output
rejection. Killed processes cannot use even parseable diagnostics to hide
uncertain effects.
Unknown errors receive no availability reason. Explicit eligible evidence enters
the runner's durable availability coordinator after repository reconciliation;
other failures retain their bounded recovery, pause, or terminal outcomes.

Codex App Server `usageLimitExceeded` and explicit Claude rate, quota, credit,
or spend-limit rejections bypass context recovery and provider fallback. Their
adapters own native recognition and expose only bounded normalized diagnostics;
pipelines consume the backend-neutral recoverable failure. Other allowlisted
backend, capability, configuration, usage, and provider failures use the same
durable pause path.

Codex App Server `other` failures use bounded native HTTP error recognition
before opaque recovery. A complete `unexpected status` wrapper with an
allowlisted non-transient client status and a parsed JSON `error` envelope
becomes terminal `ERR_CODEX_TURN_FAILED` / `turn_bad_request`, with the fixed
message `Codex turn failed.` and `recoverable: false`. This includes HTTP 400
`invalid_request_error` / `invalid_json_schema`; it starts no compaction, fresh
retry, backend-availability pause, or output correction.
Recognition is limited to 16 KiB, statuses 400, 401, 403, 404, 405, 413, 415, and
422, and a shallow envelope with scalar `message`, `type`, `param`, and `code`
fields. The type must identify an invalid request, or authentication/permission
failure at status 401/403 respectively. Optional non-null codes must be in the
adapter's finite client-error allowlist. Optional native URL, CF ray, and request
ID suffixes are discarded. Unknown codes, malformed JSON, duplicate fields or
metadata, inconsistent status text, oversized evidence, transient statuses,
and prose lookalikes remain opaque; additional details and variant payloads
are never alternative sources for this client-envelope refinement.
Within that parser, only status 401 with `authentication_error`, an absent or
null parameter, and an absent, null, or `invalid_api_key` code establishes the
shared `authentication_required` disposition. Completion evidence must agree
with any native HTTP status. App Server request errors additionally require a
native server-error RPC code and the standard exact `code`, `message`, and
optional opaque `data` shape. HTTP 403, permission/authorization evidence,
conflicting status or client codes, non-null parameters, unknown request-error
fields, and protocol/request RPC codes remain outside the authentication path.
The resulting fixed failure retains none of the native message, URL, request
ID, payload, or credential material. Claude and future providers remain
unchanged until their descriptors own an equivalent bounded classifier.
Opaque failures retain `turn_other`; the native `serverOverloaded` variant maps
to `turn_server_overloaded`. Both classes are recoverable after the turn-item
audit unless a validated client envelope rejects the request. Explicit native
transport/server availability is recoverable after the same audit. Neither
path retains native messages, variant payloads, additional details, or causes.
Completion notifications and hydrated turns accept only `completed`, `failed`,
and `interrupted` statuses before failure classification. For these failures,
the existing item audit and explicit-model reroute guard still reject policy,
protocol, and isolation violations before classification or recovery. For
recoverable non-commit failures without availability evidence outside a source fork, the existing recovery
path attempts one fresh session with the complete `recoveryPrompt` and observed
workspace. The failure itself does not request compaction, and the second
attempt's failure propagates unchanged without another reconstruction. Source
forks remain ineligible for adapter fallback; the runner reconstructs an eligible
availability failure without reforking its source. Local-commit readiness failures
record that the commit executor did not start; the boundary-derived
`effectStarted: false` projection therefore keeps an overload rejected before
the isolated executor as a proven pre-effect rejection.
Executor outcomes remain on their verification-only path and are never
replayed.

An otherwise unclassified valid read-only result or process failure is
recoverable only because the enforced read-only envelope and the pipeline's
post-turn repository guard prove that it could not mutate the repository.
Unknown writable process outcomes remain terminal after reconciliation;
classified usage and provider failures may pause only after safe workspace
changes and control state have been reconciled. After the adapter's applicable
retry policy is exhausted for failures without availability evidence, the owning
pipeline persists `backend_unavailable`,
the exact resumable workflow checkpoint, reconciled one-shot authorization
state, and any safe workspace changes before entering `WAITING_FOR_USER`. An
eligible normalized transient launch failure also persists only
`launchRecovery: { failureClass, checkpoint }`. Eligibility requires `none`
effect evidence, a `not_started` or `exited` outcome, one of `spawn`,
`initialize`, `session`, or `turn_start`, and no commit-executor evidence.
Deterministic incompatibilities, ambiguous effects, turn and commit failures,
and provider-native details remain ineligible. Resume clears the pause and
reconstructs the same durable request after availability returns. The optional
pause field requires no state-version migration.

A Worker returns a bounded structured blocker when sandbox, IPC, loopback,
process-isolation, missing-service, permission, or comparable external
constraints prevent work not delegated to an exact selected runner-trusted
command. A selected command's agent-sandbox limitation alone cannot block
applicable content repairs or semantic review; another command's selection
does not suppress a genuine blocker. Plan execution and polishing
persist `environment_blocked` rather than treating that condition as a code
failure, preserve safe workspace content, and invalidate any stale
fingerprint-bound candidate, finalization, and confirmation evidence. A
content-changing finding resolution resumes at `REVIEW` in independent mode or
`CHECK_AND_FIX` in lazy and combined modes; an unchanged turn resumes at its original
checkpoint. Finalization always resumes at `FINALIZE`. The workflow does not
weaken isolation or grant network or host temporary-directory access to bypass
the unavailable validation.

Finalization is fail closed. A `PASS` contains exactly one ordered result with
bounded direct evidence for every persisted required check; omitted, skipped,
substituted, replaced, or weakened checks are invalid output. The runner hashes
the identified package scripts, test-discovery and runner files, skill guidance,
and validation configuration rather than trusting an agent-supplied hash.
Changing that inventory, its file set, or its fingerprint is provisional until
the read-only terminal Reviewer in independent and combined modes, or the lazy
read-only terminal clean confirmation, accepts that the task or current plan
step authorizes the complete change for
the same content fingerprint. The confirming turn receives both the established
and candidate tuples, so acceptance cannot depend on a prior native session.
Both pipelines invalidate rejected evidence and use their independently owned
bounded semantic recovery routes. Commands and repository-relative infrastructure
paths are validated and compared without rewriting interior whitespace.
Host-reported results and user attestations are outside this trust boundary.
Plan execution builds both passing and failing persisted finalization evidence
through one deterministic pipeline contract before attempting advancement.
That contract normalizes the Worker and runner portions together, derives the
aggregate status, validates ordered executor provenance, and binds the result
to the content, validation-infrastructure, ordered-command, and trusted-
configuration fingerprints. An unexpected persisted-state invariant therefore
leaves the prior valid `FINALIZE` checkpoint available for the bounded public
retry instead of turning the run into an opaque terminal failure.

Plan execution gives each preparation phase one owner. Independent semantic
review, or lazy check/fix and candidate clean confirmation, converges first.
Implementation, finding-resolution, and lazy check/fix turns do not invoke project finalization
or perform generic commit preparation. The dedicated finalization turn follows
every substantive instruction in the pre-bootstrap frozen guidance. A selected
skill remains in the established validation-infrastructure inventory and must
match its frozen path and fingerprint through finalization and terminal
confirmation. Guidance repair or drift starts a new run rather than consuming
correction or review budgets. The finalization turn runs the writable
repository formatter first, treats its output as the content under finalization, then runs
generation, the non-mutating repository gate, Git whitespace checks, and
staging-independent content review. Bootstrap,
validation-migration, and finalization inventories deterministically reject
index mutation, staged or index-relative inspection, implicit
worktree-versus-index assertions, alternate-index workarounds, and commit
preparation; applicable content checks use `HEAD` or explicit trees.
Established checks are input only to `FINALIZE`.
After finalization and the distinct mode-specific terminal confirmation bind
the same content and validation-infrastructure fingerprints, the constrained local-commit executor
alone runs `git add -A`, fixed unstaged-clean, staged-diff whitespace, and
nonempty-diff hygiene, and the subject-only commit with the validated plan
subject. The contract is
identical for Codex and Claude and does not broaden ordinary Worker access to
Git metadata.

Polishing uses the same ownership rule without requesting `local-commit`.
Worker polishing, finalization, finding-resolution, and lazy or combined check/fix turns
are content-only, including when selected finalization guidance normally
requests staging. Its independently persisted pre-bootstrap decision supplies
only the frozen skill path or fallback to bootstrap and validation migration.
Any selected skill remains in established infrastructure and must retain its
path and fingerprint through correction, finalization, confirmation, and
resume; repair or drift requires a new run without consuming fix or review
rounds. Bootstrap, validation-migration, and finalization inventories
use the same deterministic staging-independence policy as plan execution;
applicable tracked content checks use `HEAD` or explicit trees, and established
checks are input only to `FINALIZE`. Once candidate convergence has completed
and finalization plus the distinct mode-specific terminal confirmation bind the
same staging-independent content and validation-infrastructure fingerprints,
the pipeline persists `HANDOFF`.
The root Git boundary then accepts either an unchanged pre-effect state or an
already-complete recovered effect, runs `git add -A` only for the former, and
verifies unchanged content and Git controls, a nonempty complete staged set,
no unstaged or non-ignored untracked remnants, and staged whitespace hygiene
before the pipeline can enter `DONE`.

Both pipelines project only exact command text from persisted
`trustedValidation.commands` into implementation or polishing, lazy or combined
`CHECK_AND_FIX`, and finding-resolution prompts. The existing snapshot bounds
limit the projection; an empty selection produces an empty array. Complete,
continued, reconstructed, and correction requests all carry it without
configuration reloads, provider settings, executable vectors, or a repeated
validation inventory. Established required-check execution and attestation
remain exclusive to `FINALIZE`. Selected trusted commands never execute inside
agent turns, and their agent-sandbox limitations do not prevent applicable
repairs and semantic review. Bootstrap inventory-reporting and finalization
`NOT_RUN` instructions stay in their existing contexts.

A selected runner-trusted command is the only exception to agent-side check
execution during finalization. The runner-derived bootstrap inventory must
contain its exact configured command.

The public trusted-validation service also provides `inspectRequirements` for
pipeline-owned requirement discovery and writable-entry decisions. This is an
explicit preparation effect, never a required-check execution or attestation.
Construction, status reads, and ordinary preflight do not call it. Pipelines
retain their own reporting schemas, saved requests, migration, and pause policy;
the capability owns normalization, frozen authority matching, and availability.
Plan execution and polishing independently own reports in each active role's
bootstrap or validation-migration inventory and inspect their union at every
writable entry. Cached declaration preflight cannot bypass this gate. Execution
also checks unconsumed COMMIT; polishing inspects completed HANDOFF settlement
before discovery or preparation and checks availability before new staging.
Polishing state version 14 preserves historical handoff evidence while requiring
read-only capability discovery before further content work. State version 15
adds frozen finalization guidance, including a partial-preflight state that
durably retains the decision across backend-probe pauses. Terminal and
completed-handoff recovery stay verification-only; other unfinished legacy work
resolves the decision before provider work and repeats read-only validation
migration when prior evidence cannot prove the selected skill is part of the
established inventory. Neither pipeline imports the other's report schemas or
workflow internals.

Plan execution and polishing each require a boolean `sourceProjection` field in
their own report schema and map only `true` into the shared capability request.
Their ordered migrations add `false` to historical concrete reports without
reloading configuration or changing immutable trusted snapshots, and preserve
null provisional reports for read-only rediscovery.

Inspection accepts `inventory` (up to 512 unique, trimmed, single-line exact
command strings, each at most 4,000 characters) and `requirements` (up to 1,024
reports, accommodating two role inventories with 256 needs and 256 blockers each).
Every selected frozen command must appear in the inventory. Each
report names an inventory `command` and may supply `commandIdentity` (null or a
lowercase SHA-256 identity), `capabilities` (the closed scratch, cache,
source-projection, and exact artifact declaration shape), and `unsupported` (up
to 16 unique lowercase capability labels of at most 64 characters). Unknown
fields, malformed parameters, or commands outside the inventory raise
`ERR_INVALID_TRUSTED_REQUIREMENTS` before effects. Unsupported labels describe
needs, never executable requests, paths, environment values, or authority. The
capability copies and freezes the accepted request before asynchronous work.

All reports for a command are additive; one role's smaller report cannot remove
another's requirement. A valid report without trusted selection, with unsupported
needs, or exceeding the saved command identity or capabilities returns `BLOCKED`
with bounded `not-selected`, `unsupported`, or `insufficient-authority` reasons.
Artifact authority matches both canonical URL and digest. Selected declarations
are always runner-known requirements even without reports. Authority for the
entire request is checked before any preparation; the snapshot is never changed.

For authorized requests, inspection prepares each selected command sequentially
under the existing durable storage, transport, and process lifecycle. It acquires
and verifies dependencies, constructs the same network-isolated mounts, checks
the declared executable's availability, and runs only a runner-defined empty Node
program in that sandbox, with a maximum ten-second process deadline. The check's
argument vector is never invoked. Preparation failures return bounded
`unavailable` blockers without native diagnostics, URLs, or process output.
Uncertain resource ownership, cancellation, and repository mutation preserve
their existing safety error contracts and recovery evidence. Successful
retirement journaling is required before inspecting another command; an
uncertain process registration stops preparation with its ownership intact.
Successful inspection returns only `READY` and an empty blocker list; it grants no check
pass or finalization evidence. Owned resources are retired and cleaned, and
finalization later acquires dependencies afresh and reverifies them.

The runner's private inspection adapter pins repository scope and snapshot to
the saved run, guards project configuration before and after the effect, and
uses the stop monitor's signal and leased process/resource callbacks. Outstanding
ownership must be recovered first. Stop reconciliation rejects inspection just
as it rejects new command execution. This adds no eager capability work ahead
of consumed-commit or completed-handoff verification; pipelines must keep that
verification-only recovery ahead of any new preparation.

Trusted declarations optionally carry `capabilities`, a closed object with
`scratch: true`, `cache: true`, `sourceProjection: true`, and
`artifacts: [{ url, sha256 }]`. Omit a capability to leave it disabled. Scratch
and cache request isolated per-execution storage with runner-defined paths and
environment bindings; declarations cannot choose host paths, mount points, or
environment names. Source projection requests an isolated writable copy of the
accepted staging-independent source rather than a host path. Artifacts request
pinned acquisition outside the check sandbox, never network permission for the
command.
The artifact list contains 1–32 unique canonical HTTPS URLs and lowercase
SHA-256 digests. URLs cannot carry credentials, fragments, nondefault ports,
IP literals, or local/reserved hostnames. Public DNS, connection pinning,
integrity, and resource limits must be enforced by the acquisition implementation.
Scratch and cache provide isolated transient storage. Artifact acquisition uses
the same durable allocation lifecycle and exposes verified files read-only.

The private `acquisition.js` primitive shares artifact declaration normalization
with the snapshot contract. The trusted executor invokes it privately after
journaling verified allocation ownership. The caller supplies an exclusively
owned mode-0700 directory handle, never a destination filename. Descriptor-relative
exclusive partials are hashed while streaming, synchronized, and published without replacing
existing entries under their lowercase SHA-256 names with mode 0444. Identical
digests share one published file, but every declared URL is acquired and verified.
Cleanup rechecks entries against the open file's identity and preserves substitutes.
Earlier verified files can remain after a later failure; callers must not expose
an incomplete acquisition and remain responsible for the owned directory.
The service exposes the dependency directory only after the complete request
succeeds, all transports retire, and allocation and subdirectory identities are
rechecked. Every execution acquires fresh files from its frozen declarations;
resume cleans previous allocations before downloading again.

Acquisition performs one DNS phase with one A and one AAAA lookup, one resolver
try each, and at most 64 combined answers. It rejects the entire answer set if
any address is not public unicast and pins one numeric destination.
The conservative address policy excludes IPv4 special-use ranges and IPv6 outside
2000::/3, plus special-use, documentation and transition ranges within it. The
declared hostname remains the HTTP Host and TLS verification name; the actual
peer must match the pinned address. Each request uses a fresh connection, explicit
Node built-in trust roots, TLS 1.2 or newer, no proxy environment, and a 16 KiB
header limit. Only HTTP 200 and identity content encoding are accepted; redirects,
ambiguous framing, incomplete bodies, and integrity mismatches fail closed.

Limits are 64 MiB per file and 256 MiB across a sequential acquisition, including
repeated digests. DNS has a 5-second deadline, connection establishment 10 seconds,
body/header inactivity 15 seconds, and the whole acquisition 5 minutes. Cancellation
and deadlines prevent subsequent publication. Requests, responses, and sockets
must close before publication or partial cleanup; retirement has a separate
1-second bound. Unverified retirement retains the partial for owned recovery.
The live service retains the resource while transport closure is uncertain and
rejects concurrent recovery; closure permits cleanup retry. Recovery also checks
the journaled acquisition owner, even after lease release and service
reconstruction.
A live or unverifiable owner blocks cleanup unless that same service observed
transport retirement. A dead or replaced owner permits confined cleanup. Late
callbacks cannot publish files. Errors expose finite acquisition categories,
not URLs, response bodies, or native transport diagnostics. Tests inject DNS,
HTTPS and deadline scheduling without network access.

Root and safe project catalogs share strict normalization, including capability
parameters. Capability changes participate in catalog conflict detection and
command identities. New snapshots use schema version 4 with an explicit
`capabilities` object on every command and the resolved `timeoutMs`.
Configuration fingerprints bind the version, complete normalized request, and
timeout, while command identities and ordered-command fingerprints remain
independent of the deadline. Version-1 and version-2 snapshots retain their
original identities and fingerprints on migration/resume and deterministically
use the 60-minute fallback. Version 3 retains its frozen timeout and closed
pre-projection capability set. Legacy validation never grants source projection,
so already accepted evidence remains bound to its original policy. Each run
carries its own immutable snapshot; resume does not reload configuration, and
concurrent projects do not share deadline state.

Creation checks the frozen request before provider probes. A valid unavailable
request creates a durable `environment_blocked` run with incomplete preflight,
no repository baseline, backend versions, input hashes, or agent activity.
Malformed declarations remain configuration errors. Resume retries the saved
request under the execution/worktree leases before new provider work; successful
retry resumes ordinary preflight without reloading configuration. Later failures
retain the applicable pipeline checkpoint. Capability inspection does not execute
or attest checks. Consumed commits and completed handoffs are verified before
capability checks needed for new work; status and immutable terminal reads do no
capability work. Launcher discovery is lazy for the same reason.

Scratch and cache mount only at `/run/agent-runner/scratch` and
`/run/agent-runner/cache`. They provide `AGENT_RUNNER_SCRATCH`/`TMPDIR` and
`AGENT_RUNNER_CACHE`/`XDG_CACHE_HOME`/`npm_config_cache` respectively (npm uses
`/run/agent-runner/cache/npm`). These bindings are runner-defined; project
configuration chooses only the capability booleans. Without source projection,
build output must explicitly target scratch. Dependencies mount only at the read-only
`/run/agent-runner/dependencies`, with `AGENT_RUNNER_DEPENDENCIES` bound to that
path. Files use their declared lowercase SHA-256 digest as their name. No partial
file is exposed. Artifact-only requests allocate storage even without scratch or
cache. Extraction or setup must be part of the exact declared command and target
declared scratch; the runner does not extract archives or install host tools.
Without source projection the repository mount remains read-only; system mounts
are always read-only and networking remains private.
These capabilities do not change the agent sandbox.

`sourceProjection: true` makes the Git boundary materialize the immutable HEAD
selected by the pre-execution repository snapshot plus the exact current
tracked and non-ignored untracked content represented by its staging-independent
content fingerprint. It neither materializes staged blob content from the
mutable index nor carries ignored untracked files, and it never copies `.git`.
The owned allocation is journaled before its destination exists, and the source
directory must match its allocated device/inode before any source write.
Descriptor-anchored writes and a final kind, mode, size, and content-hash
comparison verify the complete owned tree before execution. Its root and
source-directory identities are also verified before and after materialization.
The executor rechecks the original repository snapshot before launch, mounts
only that source directory writable at the canonical project path inside the
namespace, and uses it as the command's working directory. Original worktree,
index, Git metadata, state, task paths, credentials, and undeclared host storage
are absent. The check may create or rewrite projected files, but those effects
are discarded with the owned allocation after the complete process tree
retires. A final repository guard rejects external or original-repository drift,
and accepted evidence retains the source content, HEAD, command-identity,
ordered-command, trusted-configuration, and validation-infrastructure bindings.
Stale content or HEAD, substituted directory identities, incomplete
materialization, projected entries overlapping protected control paths, runtime
mounts that would expose an external protected path, and uncertain cleanup fail
closed without reusable output.
Preflight checks storage-root writability and rejects fixed mount targets that
overlap protected paths before provider work; allocation rechecks that policy.
Private storage also cannot overlap system, executable, or PATH exposures;
the sandbox rechecks this before mounting. Protected Git paths include canonical
directory-symlink targets and shared metadata reached through Git directory
pointers or `commondir` files.

Common run-envelope version 9 adds private `executionResource` ownership next to
`executionProcess`. Legacy envelopes normalize it to null and migrate through the
existing leased journal transition without filesystem allocation, provider work,
or changes to session/progress evidence. Status reads never allocate or clean
resources. The resource record carries a random execution ID, host, command
identity, private root device/inode, and allocation phase; the allocated phase
also records the execution directory device/inode. Common run-envelope version
10 adds the `acquiring` phase, which journals the runner PID and boot/start
identity before transport activity. Version-9 state and journal records retain
their original closed allocation contract and load without writes; leased
migration preserves ownership, command identities, and progress without new
resource effects. The runtime compatibility token changes with this version.
Verified retirement restores `allocated` before launch or cleanup; only those
exact identity-preserving transitions are accepted. Acquisition journal failures
retain ownership and report the bounded resumable ownership blocker. Resource ownership is never publicly projected.

The trusted executor creates a runner-owned mode-0700 parent under the runner's
temporary directory, disjoint from project, task, Git metadata, and runner state.
A journaled allocation intent precedes exclusive per-execution directory creation;
verified identity is journaled before downloading, materializing source,
exposing mounts, or launching a process. The execution directory owns its
dependency and optional source subdirectories as well as scratch/cache; the
acquisition phase records transport ownership separately from command process
registration.
Directory creation is synchronized before publishing allocation identity, and
declared storage entries are synchronized before acquisition or launch. Cleanup
synchronizes removal before clearing journaled ownership, including retries
after removal.
Descriptor-anchored directory operations and identity checks reject symlink
substitution. Only declared scratch/cache subdirectories and the exact declared
source projection are mounted writable.
No mutable cache is reused across executions, including after interruption.

Each runner-trusted validation command derives its deadline from the validated
run snapshot. The public `trustedCommandTimeoutMs` default is 60 minutes, and
capability preparation uses `Math.min(timeoutMs, 10_000)`. The service has no
construction-time timeout override, so no second deadline of this operational
class can bypass the per-run configuration contract.

Command completion, failure, timeout, and cancellation retire descendants before
confined cleanup and repository mutation checks. Resume and operator-stop recovery
retire any recorded process before cleaning saved resources, even when interruption
preceded process registration. Cleanup uses the recorded root, not a newly selected
temporary directory. A missing child can be cleared idempotently. An existing child
without a journaled verified identity, a replaced directory/root, or uncertain
process ownership retains evidence and ownership for explicit recovery; the runner
never guesses which directory to remove. Checkpoint settlement and releasing
ownership remain closed until cleanup succeeds. After an operator restores the
recorded directory or removes an independently verified orphan, resume retries
cleanup before any new work. Acquisition failures return bounded, redacted
`BLOCKED` check evidence without launching the command. They and resource cleanup
uncertainty preserve an `environment_blocked` FINALIZE checkpoint and never attest the check. Cancellation
preserves the abort outcome after safe cleanup; uncertain retirement retains
ownership and blocks settlement.

The finalization agent returns `NOT_RUN` only for those selected entries; after
the agent turn reconciles, the root executor replaces each placeholder by
running the exact persisted executable/argument vector directly without a
shell. On Linux it requires bubblewrap and runs with a private network
namespace. The trusted sandbox selects `native-sandbox-provider` ownership;
the service and exact-command executor forward that mode to the owned-process
launcher so it probes the complete nested isolation shape. The trusted sandbox
explicitly creates its own user namespace, matching the nested probe rather than
relying on Bubblewrap's host-dependent implicit user-namespace selection. Executions whose
sandbox does not select a mode retain ordinary ownership. The trusted command's
isolation profile and process-containment requirements remain unchanged.
Before agent work, the root resolves bubblewrap only from fixed
system locations to a canonical absolute executable whose file and ancestor
directories are not writable by the runner identity. Project-relative or
project-writable `PATH` entries never participate, and resume and execution
reverify the pinned path. The namespace contains minimal read-only system mounts
and either the read-only repository view or the declared writable source
projection, private temporary storage, a hidden ambient home, private runtime
storage, and a finite non-credential environment. Isolated loopback
listeners remain available inside the command namespace, but raw host Unix
daemon and control sockets are masked.
A Docker daemon must be rootless, and every service must be command-owned inside
the same mount, network, and PID namespaces, so it cannot gain host mounts or
networking and is retired with the complete process tree. Remote network and
filesystem writes, hosting credentials, Git credential helpers, and ambient
authentication variables are unavailable. A private PID namespace and an outer
process group give every completed, readiness-confirmed command one fixed
one-second grace period for remaining descendants to retire naturally
regardless of exit code, then provide bounded TERM/KILL retirement when the
group remains active.
Timeout cleanup begins immediately. A one-byte readiness signal emitted inside
the completed isolation profile
distinguishes setup denial from an executed check failure without exposing
native output. The runner discards raw stdout/stderr and records bounded
status, exit/signal/timeout data, command identity, and normalized evidence. A full
Git snapshot before and after each command rejects workspace, index,
history/ref, remote-configuration, or identity mutation, and the complete
validation-infrastructure fingerprint is recomputed after trusted execution.
Missing isolation, an unterminated process tree, skipped, changed,
non-allowlisted, substituted, unmatched, or fingerprint-drifting checks fail
closed. The final evidence tuple binds agent and runner results to the same
content, validation-infrastructure, ordered-command, and trusted-configuration
fingerprints. This service does not broaden any agent turn's sandbox and
introduces no daemon or shell DSL.

The private trusted-validation diagnostic collector continuously drains both
streams forwarded by the readiness wrapper, independently of its readiness
channel and verified retirement. Command exit is observed separately from pipe
closure so inherited output pipes cannot defer descendant cleanup to the command
deadline; exited commands require bounded closure verification before evidence
is finalized. Only readiness-confirmed failures receive diagnostics.
It decodes at most 1,024 bytes at a time,
retains at most 2,048 bytes per line on each of two streams, and keeps up to
eight recent distinct candidates within 1,024 bytes of diagnostic evidence.
Supported Node/node:test and Prettier failure formats yield finite
normalized error classes, check-stage labels, or node:test failure-type labels.
Anchored dot/spec failed-test headers (`Failed tests:` and `✖ failing tests:`)
and positive TAP/spec failure summaries (`# fail N` and `ℹ fail N`) identify
the `tests` stage even without an
allowlisted error class. Bounded indented error headers and quoted `code`/`name`
fields, including reporter trailing commas, retain only allowlisted classes.
Bounded indented quoted `failureType` fields from Node 24 TAP/spec output,
including reporter trailing commas, retain a closed allowlist as
`Trusted check test failure type: <type>.` evidence strings. `testAborted`,
`testTimeoutFailure`, `cancelledByParent`, and `parentAlreadyFinished` distinguish
cancelled or incomplete work from `testCodeFailure`, `subtestsFailed`, and
`hookFailed`. The supported set also includes `callbackAndPromisePresent`,
`multipleCallbackInvocations`, `expectedFailure`, `uncaughtException`, and
`unhandledRejection`. Unknown types are omitted rather than copied or inferred.
These labels use the existing evidence arrays and undergo the same finite
revalidation, byte/candidate bounds, and public check/issue binding as classes
and stages; they do not change check outcomes or grant retry authority.
Banners, stage starts and zero-failure summaries are not failure evidence.
Titles, arbitrary paths, assertion values, messages, stacks, provider output and
ambient context are never evidence. The narrow repository-check exception below
retains only verified canonical failing-file identities.
Unsupported, unsafe, malformed or oversized data yields a fixed omission
explanation while drainage and collection of other supported evidence continue;
successful checks discard all candidates.
For the frozen exact `agent-runner-check` vector (`npm`, `run`, `check`), the
capability additionally verifies package scripts and canonical formatter/test
launcher files against the installed contract frozen when this Runner loaded.
`scripts/index.js` exposes only the selection capability implemented by
`scripts/test-selection.js`, sharing the launcher's existing roots, tier
selection, explicit arguments and ordering. The installed source binding covers
both files alongside the formatter, test launcher and storage implementation;
batching and concurrency remain launcher-owned.
Before execution, Git path inspection verifies the selected fast inventory and
launcher files as canonical regular content files, rejecting symlink aliases and
ignored untracked inputs. Unsupported contracts retain finite-label fallback.
Inventories are bounded to 1,024 files and identities to 256 bytes.

Only a Node TAP `location` field at the diagnostic indentation of a failed
`not ok` block can produce `Trusted check failed test file: <relative-path>.`.
The location must exactly name a verified inventory member, optionally under the
execution root; there is no URI decoding, path rewriting or title/stack inference.
Locations are validated without removing color codes; an outdented reporter
line ends location collection for an unterminated diagnostic block.
Traversal, aliases, foreign files, controls, malformed encodings and oversized
values are omitted. Identities share the existing candidate/byte bounds. Failed
check records carrying identities preserve an optional `diagnosticInventory`
with the original file list and content, command and launcher bindings plus its
digest. Service, root persistence/reload and public projection revalidate that
contract against the recorded content, never discovery from a later worktree.
Pipelines preserve this opaque capability-owned binding without duplicating its
policy. Success discards the inventory with output diagnostics. Blocked outcomes
retain finite labels rather than unbound file identities.

The service's injectable monotonic clock brackets only actual exact-command
execution, excluding preparation and acquisition. Readiness-confirmed outcomes
retain `Runner-trusted check elapsed: <milliseconds> ms.` in existing evidence
arrays: one rounded integer from zero through 2,147,483,647. Launcher durations
and agent claims are ignored. Successful checks keep timing without diagnostics;
failed checks and matching generated issues carry identical evidence to finding
resolution, while passing evidence reaches distinct terminal confirmation.
Executed timeout/retirement blockers can retain timing in the existing bounded
pause, revalidated against the Runner-owned FINALIZE blocker and frozen alias.
Preflight and unstarted checks retain no timing. Malformed, duplicate or
non-Runner observations fail closed at service, persistence and projection
boundaries. Historical absence remains valid without migration or invented
values. These observations are included in the existing evidence tuple and
cannot grant PASS, revive confirmation or change retry authority.
The service validates these observations again before adding them to existing
evidence fields. Existing pipeline evidence carries them into findings and
durable reload. The shared trusted-validation projection used by CLI and MCP
exposes only recognized fragments tied to a frozen failed runner check and its
matching generated issue, identified by check and issue IDs. It neither exposes
general issue prose or commands nor changes pause actions or retry authority.
Runner-generated `BLOCKED` pauses at `FINALIZE` preserve revalidated diagnostic
fragments through their existing bounded pause evidence; they have no generated
failure issue IDs. Signal termination remains distinct from a nonzero exit.

The deadline changes only timeout behavior. It cannot make an incompatible
sandbox succeed or restore historical discarded output. A full repository check
may pass on the host yet fail closed in trusted isolation; unsupported failures
retain the generic outcome and bounded omission explanation. Increasing
`trustedCommandTimeoutMs` neither explains nor fixes that difference.

Plan execution can retry eligible runner-trusted failures through an explicit
null-action resume from an `environment_blocked` finding-resolution pause.
Pipeline policy recognizes only a complete persisted match between failed runner
checks and their generated issues, with no agent failure or other unresolved work.
After input, repository, and failure-fingerprint revalidation, one write-ahead transition clears terminal
evidence and enters complete `FINALIZE`, repeating Worker finalization and all
applicable runner-trusted checks to generate fresh diagnostics while retaining
candidate acceptance and correction accounting. A repeated failure rejoins
resolution and does not retry automatically. The trusted executor's authority,
output-retention policy, and mode-specific confirmation gates remain unchanged.
Normalized diagnostics do not change eligibility, budgets or bindings.
Historical records remain unchanged;
an authorized normal retry produces fresh evidence but cannot recover discarded
historical output. The [execution specification](../pipelines/plan-execution/docs/SPEC.md)
owns eligibility.

Before plan execution or polishing accepts a producing role's bootstrap or
legacy validation-migration inventory, and before either pipeline fingerprints
finalization evidence, the root Git boundary verifies every
validation-infrastructure entry is an existing regular file whose canonical
repository-relative path exactly matches the proposed path. Missing files,
directories, symlinks, and paths traversing a symlink are field-specific
violations; the runner does not follow or silently canonicalize them. Plan
execution collects every inspectable violation from the candidate into the
owning bounded bootstrap or finalization diagnostic batch, and a repeated
invalid result fails closed. The deterministic aggregate is therefore derived
only from independently accepted canonical role evidence.
Plan execution and polishing additionally reject each staging-dependent
required command with bounded field-specific diagnostics before accepting that
producing result; plan execution batches all such independently detectable
violations, and the same policy rejects a finalization candidate inventory
without delegating index ownership to an ordinary Worker turn.

An explicitly supplied source session is different. In independent and combined
modes, the
first eligible turn of each new primary or review checkpoint creates a direct
child and returns its ID without resuming or mutating the source. In lazy mode,
only the first eligible primary turn may create that child, and the durable
one-time marker forbids later source forks even when a native session must be
reconstructed. For failures without availability evidence, if an eligible `spawn` or `initialize` launch failure occurs
before a lazy fork can create a child, the same atomic availability-pause
transition restores the one-time marker. Resume then makes the run's single
fork for the same logical role. Recovery at `session` or `turn_start` is removed
from a fork request and the request becomes non-resumable because a native child
may already exist without durable lineage; recorded children are continued or
reconstructed and never reforked.
If the source cannot otherwise be forked, the turn fails before agent work
rather than silently losing lineage.

Adapter failures retain only bounded diagnostics. Every adapter classification
produces the same closed record: `failureClass`, `checkpoint`, `outcome`,
`effect`, and `retry`, with optional commit-executor proof, finite availability
reason, and an optional sanitized process outcome containing only an exit code
or signal.
An optional version-1 `reconstruction` record has the sole kind
`completed_turn_acquisition`. Provider-owned class admission and the shared
contract require a rejected, possible-effect, terminal turn failure with no
commit, availability, authentication or process-outcome evidence. Codex adds it
only after a matched completed notification and recognized history/capture or
hydration acquisition rejection, with verified retirement and cleanup. The
normalized boundary and registry preserve it without raw evidence; automatic
retry policy remains terminal.
Codex protocol rejections retain finite adapter-owned `protocol_*` classes for
framing, frame/capture/notification limits, envelopes, identity, item view,
terminal status, unsupported or unavailable history acquisition, hydration
limits, cursor progress, duplicate IDs, invalid/unfinished/unsupported items,
and progress rejection. Completion and compaction wrappers preserve these
terminal classes and stronger audit failures. The registry validates the class
before normalizing or persisting it; existing CLI/MCP pause and public activity
projections expose it without native responses, parsing causes or history.
Protocol rejection never becomes interruption, availability or context retry.
A diagnostic alone establishes neither historical cause nor recovery authority.
`commitExecutor: "not_started"` is valid only at the `commit` checkpoint with
`none` or `possible` effect evidence; it is invalid with `started` evidence or
at any other checkpoint. Checkpoints are `probe`, `spawn`, `initialize`,
`session`, `turn_start`, `turn`, or `commit`; outcomes, effect evidence, and
retry eligibility are likewise finite shared vocabularies. The shared launch
classes cover process exit and version, argument, protocol, and configuration
incompatibility. Deterministic incompatibilities are terminal; process-exit
eligibility remains explicit in the record. The contract rejects unknown
fields, unbounded values, and contradictory combinations. Capability probes
produce a proof containing the version, required capabilities, and the existing
`adapter-capabilities-v1` policy receipt.

The root boundary derives launch recovery only from that validated record and
never from raw provider causes. The frozen projection contains exactly the
normalized failure class and checkpoint. Without availability evidence, fork
requests retain it only at
`spawn` and `initialize`; a later eligible checkpoint keeps its normalized
failure record but cannot enter pipeline retry policy. All other requests may
retain any eligible launch checkpoint. CLI and MCP status read the same
persisted projection, including through an operator pause. Accepted resume
removes it with the pause, while terminal cancellation removes it from the
retained private checkpoint.

Codex capability, isolation, prohibited-operation, and recognized App Server
failures and Claude session, profile, authentication, backend, capability,
configuration, usage, provider, permission, and process failures remain native
recognition owned by their provider directories. The root agent boundary
validates the descriptor classification once, derives pipeline control
properties only from the shared record, and maps an unclassified cause to a
terminal rejected outcome with possible effects. When an ambiguous provider
turn precedes a local commit, the record retains its possible provider effects
and may separately prove that the isolated commit executor never started. The
boundary derives `effectStarted` solely from that validated record; raw cause
fields cannot override it. It does not duplicate backend class lists or
traverse native cause chains. Every pipeline may persist the normalized class
for a terminal failure and projects it only through a deterministic CLI/MCP
explanation. Native messages, additional details, denied input, provider
responses, prompts, commands, credentials, transcripts, and process causes
never cross that boundary or enter durable state.

Codex `subAgentActivity` or another collaboration audit signal remains a
terminal `operation_multi_agent` isolation failure even though collaboration is
disabled at launch. A backend that ignores that disabled capability cannot be
accepted, reclassified as an environment blocker, or transparently retried.
Context exhaustion and interruption retain their dedicated recovery paths.

Interrupted one-shot effects are also different. In particular, a
`local-commit` turn is never replayed; control returns to the runner for pending
authorization and Git-state verification. Backend policy, profile, provider,
or turn rejection before the isolated executor may record
`commitExecutor: "not_started"`; the derived `effectStarted: false` proof
permits authorization renewal only after Git verifies that the effect did not
occur. It never makes the consumed authorization replayable.

Each state transition is a small write-ahead transaction:

1. append and sync a complete `events.jsonl` record containing the next state;
2. atomically replace `state.json` using a temporary file and rename;
3. atomically regenerate the derived `progress.md` projection.

Revisions start at `1` and remain contiguous. Recovery ignores and removes only
an incomplete final event fragment, rejects malformed durable records, advances
a lagging `state.json` from the last complete event, and regenerates stale or
missing progress. Valid event history is never discarded.

Events may carry an optional bounded public activity record containing only
`actor`, `phase`, `kind`, and a concise one-line `message`. Pipelines derive
these messages from validated structured results; the state service validates
only their generic form. Cursor-based readers expose this projection without
returning private pipeline state, model output, credentials, or unhashed remote
and identity values. Persist concise structured decisions and summaries, never
raw model transcripts or chain-of-thought.

Immediately before every provider invocation, the runner appends and syncs a
complete `turn-started` transition whose next state contains the bounded active
role and pipeline phase. The active turn remains durable while the provider is
blocked and through repository or one-shot-effect reconciliation, then a
second write-ahead transition clears it. If the process stops first, the stale
activity remains without a live execution owner, even while its lease record
awaits stale recovery. A resumed owner
reconstructs the request from durable pipeline state, replaces ordinary stale
activity when it starts the reconstructed turn, and clears a one-shot commit
activity only after Git verification deterministically resolves the consumed
authorization. Native sessions, polling, model-token heartbeats, and daemons
are not part of this correctness path.

Before an ordinary interrupted turn is reconstructed, the runner revalidates
the canonical project and task directories and the owning pipeline revalidates
every durable task, context, plan, and accepted clarification input. The root
Git boundary then compares the persisted snapshot with the current repository.
Read-only turns still require an unchanged workspace and index. An interrupted
polishing Worker may retain content drift only for a phase that originally had
workspace-write authority; any index drift is rejected. Plan execution retains
its owning pipeline's one-shot commit reconciliation rules. `HEAD`, branch and
detached state, local refs, remotes, Git identity, canonical root, and allowed
runner paths must remain unchanged. The pipeline advances its baseline only
after those checks, invalidates its fingerprint-bound gate evidence when
content changed, and charges interrupted correction work once.
The reconstructed request uses the complete recovery prompt in a fresh native
session, and its `turn-started` event replaces the stale marker before normal
post-turn reconciliation clears it. If a correction transition was already
persisted before process loss, recovery clears its retained marker after the
same input and Git checks and continues from the advanced checkpoint without
replaying or recounting the correction. Consumed one-shot commit turns remain
on their verification-only path and are never reconstructed or replayed.

Every mutating run or resume holds one atomic per-run execution lease. Plan
execution and polishing also hold one atomic lease for the canonical Git
worktree throughout workflow execution and runner-authorized clarification
writes, preventing independently identified runs from mutating the same
worktree concurrently. Status and public activity reads acquire neither lease.
A competing owner is rejected. A current same-host lease is recoverable
immediately only when its complete boot/PID/start identity proves the exact
owner dead or replaced; the reclaim marker and mutation boundary recheck that
identity and the opaque token before atomic replacement. Acquisition age does
not delay recovery and never proves that ownership ended. Legacy,
identity-free, foreign-host, live, invalid, and unverifiable records remain
non-reclaimable. Release verifies the opaque owner token before removing a
lease. Pipeline-declared run artifacts are
atomically replaced beneath the run directory, with absolute paths, traversal,
reserved state files, and symlink escapes rejected. Managed state and lease
paths must be isolated regular files rather than symbolic or hard links.

At MCP startup, the root freezes one bounded detached-compatibility token
derived canonically from the detached protocol version, root run-envelope
compatibility tuple, and the sorted ID/state-version pairs of every loaded pipeline descriptor. Detached
launch passes that token in an internal environment field. After loading its
own registry, the child independently recomputes and compares the token before
acquiring a run lease, recovering state, or evaluating a migration. A mismatch
uses a distinct exit status that the parent converts to an actionable
version-skew error; `state.json`, the journal, leases, the durable run, and the
incomplete idempotency intent remain exactly at their pre-dispatch state for an
exact-key retry after the MCP process is restarted. Client disconnect and wait
cancellation still affect only the client-side operation.

## Clarification Lifecycle

Every pipeline starts with an explicit, pipeline-owned `CLARIFY` state. Its
primary agent studies the task and repository read-only, then returns `READY`,
structured questions whose answers could materially change the required
behavior, scope, or planned work, or a pipeline-owned blocking outcome.
`--clarify` opens the text editor before that turn so the user can add context
proactively; otherwise the editor opens only when the agent asks a question.

The fixed protocol limit is three agent question rounds for every pipeline.
Empty artifacts and authorized editor closes without changes consume no round.
Exhaustion pauses instead of extending the dialogue indefinitely; this is an
ambiguity-resolution bound, not a configurable duration or workflow budget.

The root runtime owns the common mechanics under `src/clarifications/` behind
its public `index.js`: creating the `clarifications.md` artifact, invoking
`$VISUAL` or `$EDITOR`, appending question rounds, and hashing the result.
Pipelines own the artifact location, prompt, round limit, transition out of
`CLARIFY`, and safe re-entry after an exceptional product decision. This is a
bounded preparation protocol, not a general chat or dialogue engine.

Before the first clarification turn, the runner creates the Markdown artifact
when missing and otherwise preserves its existing transcript. Keep the format
intentionally simple: the runner appends questions without rewriting prior
content. An existing empty clarification artifact is valid and must not be
replaced with a template. Closing an authorized editor without changes is also
valid. Both cases require no user text and do not consume an agent question
round. Unanswered questions already appended by an agent still require a
response.

During an authorized editor window, the resulting user edit is accepted as new
clarification input and invalidates every dependent result. Changes outside an
authorized editor window remain unexpected input changes.

MCP never launches `$VISUAL` or `$EDITOR`. It projects a pending edit as a
structured request with a stable ID, kind, identified questions and options,
rationale, artifact path, and run revision. An empty answer set is valid only
for optional proactive clarification. `run_respond` requires exactly one
non-empty answer for every identified question, preserves the supplied text,
and rejects stale or already answered requests. Editing the artifact externally
and calling `run_resume` remains available. A controlling agent answers from
explicit user context or asks the user; it must not invent a material product
decision.

```markdown
# Clarifications

## Context

<!-- Optional user context. -->

## Round 1

### Q1

Question text.

Why it matters: concise impact on scope, behavior, or planned work.

### A1

<!-- Write the answer here. -->
```

Product-decision pauses append a separate `## Product Decision N` section with
the question, concrete options when available, blocking evidence, and a user
decision field. After the authorized editor closes, the runner persists the new
artifact hash before re-entry. Store no model chain-of-thought or full agent
transcript.

Before opening the editor or pausing for an answer, persist the suspended
pipeline state, pending editor action, and last accepted artifact hash. Resume
accepts an edit only for that pending action and returns to the pipeline-owned
safe re-entry state. The authorization is one-shot and is consumed when the
editor closes or a resumed edit is accepted.

Repository-local clarification artifacts may be created only after
`git check-ignore` confirms the target repository ignores their resolved paths.
The runner never edits target ignore rules automatically.

When clarification closes, the runner freezes the artifact hash. Normal work
prompts prohibit further questions. An agent may return the structured
`PRODUCT_DECISION_REQUIRED` outcome only when progress is impossible without a
material product decision that existing task, plan, repository, conventions,
and clarification evidence cannot resolve. The runner pauses for the user and
invalidates dependent work after the answer; it never invents the requirement.
If the decision invalidates completed commits or the validated plan, the runner
requires a revised plan and a new execution run instead of rewriting history.

## Shared Commit-Plan Contract

`@agent-runner/commit-plan` is the only extracted shared domain package. It owns
the deterministic `plan.md` representation and validation rules needed by both
authoring and execution. It does not own prompts, agent roles, review behavior,
or workflow transitions.

## Global Safety Policy

Every pipeline inherits non-negotiable runner controls:

- no remote writes, pushes, or hosting-service mutations;
- no remote configuration or Git identity changes;
- no `Co-authored-by` trailers;
- active mutation checks around read-only turns;
- no repository-local clarification artifact outside an already ignored path;
- state outside target and task repositories;
- explicit pause on unsafe or unrecoverable state.
