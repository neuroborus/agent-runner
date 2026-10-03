# Native platform proof contracts and release audit

This owns the contracts and retained release audit for an isolated proof of
concept (PoC), plus its newly authorized evidence/reporting and CI boundary.
It adds no native runtime support and changes no production consumer. Dedicated
Linux system CI now provisions the protected bubblewrap prerequisite.
The existing Linux runner, provider registry, pipelines, state, configuration,
and canonical skills retain their current contracts.

**Historical audit disposition: technical NO_GO for dependent implementation.** The
released interfaces inspected below do not establish a recoverable macOS
descendant domain, Windows helper admission/recovery, or complete native
provider mediation. No missing mechanism is approved by this document. Retain
the findings and require reviewed source closure before dependent work;
do not replace a required contract with a weaker approximation.

No native system or authenticated provider acceptance was run. Those results
remain **UNPROVED**, independently of the source findings. Local version/help
inspection and protocol schema generation establish callable surfaces only.
They are neither sandbox acceptance nor successful provider tool dispatch.

The 2026-10-01 reconciliation retains the 2026-09-30 audit against current
committed documentation. Retained bytes confer no fresh validation or inherited
approvals. The current Linux Codex 0.159.3 installation does not replace the
historical 0.159.2 observations below or establish native acceptance.

## Authorized continuation: evidence, reporting, and declared CI

The audit-only stop was honored. A separately reviewed six-commit continuation
now admits independent reporting, Linux reference-proof engineering, and source
investigation without weakening the retained contracts. The pure reporting
owner, effect-free protocol tests, declared-platform workflow, Linux
owned-process, access-profile and fixed Git reference cases, offline public
input verification, and the prepared-source mechanism research below are
implemented. The accepted scoped continuation also implements protected file
sessions, the complete six-ID file suite, version-5 system composition and
reviewed-input release audit. Actual CI observations, complete release source closure, and
provider integrations remain pending; their missing evidence remains BLOCKED.
The historical audit below retains its original inspection scope and conclusions.

`ci/native/index.js` intentionally exports the fixed platform/check/finding
catalogs, `normalizeNativeResult`, `normalizeSourceEvidence`,
`aggregateNativeEvidence`, `renderNativeReport`, `PUBLIC_INPUT_REQUIREMENTS`,
`verifyPreparedPublicInputs`, `renderPublicInputReport`, and their bounded contract
error. All imports, validation, aggregation, and rendering are effect-free;
there is no filesystem, process, environment, provider, or network access.
The index also exposes the pure system dispatch, CI stage-record, and independent
artifact-join contracts. Explicit report I/O, CI metadata retrieval, and the
harness child process belong to `run.js`; Linux system effects belong to the
indexed `linux/` owner invoked explicitly by that entry point. The workflow emits fixed fallback
summaries when checkout is unavailable. Importing the entry point does not
execute it.

The aggregate evidence request has these separate inputs:

- `candidateSha`: the exact 40-character candidate object ID, checked against
  each result's independently observed `checkoutSha` and CI binding.
- `source`: candidate-bound `inspected` facts, unresolved `hypotheses`, concrete
  `missingInputs`, and the four retained audit `findings`. Facts record a public
  HTTPS URL, revision or explicit null, SHA-256, publication/implementation kind,
  release binding, completeness, and a bounded statement. Publication bytes,
  revision text, or partial/unbound implementation cannot close a finding.
- `results`: complete check/profile records naming declared and observed image,
  OS/build/architecture, public workflow/run/attempt/job provenance, component
  versions/digests, effective policy identity/digest, implementation state, and
  native/model-free/protected dispatch. Setup/probe/cleanup each carry status,
  elapsed time, deadline, and a closed failure reason. Observations require a
  ready permitted positive control, an attempted operation, a matching result,
  and unchanged sentinels. Settlement records independent retirement, retained
  exclusion, or unverifiability, separately from emergency cleanup.
  Each `profile.*` check names its matching profile; `git.fixed-commit` names
  the `commit` profile. Other check profiles identify their owned case group.
  Unavailable provenance is explicit null in failed/BLOCKED records so setup
  failures remain reportable; PASS and independent bindings require complete
  workflow/run/attempt/job identities.
  Build and version identifiers are bounded public metadata that must survive
  unchanged; identifiers requiring redaction or truncation are rejected so
  sanitization cannot hide inconsistent job evidence.
  Version-2 native records add closed `admission: "not-started" | "possible"`
  producer evidence. Version-1 records remain readable and normalize to
  `possible`; labels, absent receipts and empty observations do not prove that
  a controller or helper never started. `not-started` excludes derivative
  phase/retirement findings only for unimplemented/missing-input BLOCKED records
  or setup-failed/deadline FAIL records, with compatible evidence: null policy,
  no observations, setup NOT_RUN with null elapsed time or recorded matching FAIL,
  probe/cleanup NOT_RUN with null elapsed times, and retained non-independent
  exclusion without emergency cleanup. BLOCKED phase reasons must match the
  result reason; unreached probe/cleanup after a setup FAIL retain `missing-input`.
  Conflicting evidence, including phase reasons, remains possibly attempted
  and gets an inconsistency finding. A known pre-admission fixture
  failure keeps setup FAIL and its result FAIL; it never invents successful
  native cleanup or retirement. Earlier attempted-case observations, cleanup
  and settlement remain when a later profile fixture fails.
  Absent policy records do not assert a different effective policy or create
  policy-comparison findings beside attempted cases. Recorded policies still
  require consistent policies within each actual profile/case group; Linux
  generic ownership and access groups are distinct.
- `bindings`: artifact IDs and candidate/platform/tier/job identities read
  independently by the CI controller, including actual job conclusion. A
  payload's repeated provenance is not an independent binding. The pure join
  checks consistency; it cannot authenticate an API or attest the truth of
  supplied observations or source review.
  Provider bindings additionally require `operator-protected` authority derived
  from the operator's immutable trusted candidate and approved environment,
  publication, credentials, and acceptance authorization. An ordinary PR job or
  a payload-supplied tier cannot supply that authority; the field records an
  independently established prerequisite and grants no permission by itself.
- Optional `providerModes`: a complete reviewed assignment for every provider
  check, with protected dispatch the default. Model-free dispatch requires
  source-backed support and real enabled-tool observations; a schema, mock,
  standalone sandbox, or transport result cannot justify this assignment.

The required inventory cannot be narrowed by submitted records. GO requires all
checks on all three declared x64 platforms, matching candidate and job evidence,
successful phases within their deadlines, independent non-emergency retirement,
closed release-bound source findings, and the required actual provider dispatch.
Missing, duplicate, skipped, cancelled, mismatched, inconsistent, unimplemented,
or unretired evidence cannot pass. Explicit native failure, including a failed
phase mislabeled as BLOCKED, yields NO_GO; incomplete or invalid evidence retains
BLOCKED. Invalid outer envelopes throw
`ERR_INVALID_NATIVE_EVIDENCE`; invalid individual records are quarantined as
fixed actionable findings without retaining their raw input.

The renderer recomputes the gate instead of trusting a supplied decision. It
returns a structured report, a bounded Markdown summary, and at most 32 failure
annotations, retaining all findings in the structured report. Per-job rendering
projects only that platform, its applicable source findings and prerequisites;
it cannot establish aggregate GO. Aggregate acceptance still requires all
three platforms, 23 system cases and six provider checks per platform, and all
four retained source findings. Reports distinguish CI harness health, accepted
system cases, source closure and absent protected provider records. Primary CI
stages and the first failed Linux prerequisite precede derivative/missing-proof
annotations in deterministic order. Setup/probe guidance concerns those actual
stages; artifact-repair guidance is reserved for selection, download and payload
defects. Diagnostic prose
is limited to 512 characters and redacts credential assignments, authorization,
URLs, local paths, workflow commands, and unsafe controls. Summaries and
annotations contain only fixed messages and closed IDs. Do not supply raw
process/provider output, environments, credentials, sessions, or transcripts.
Successful rendering never turns a BLOCKED proof into GO.

## Offline prepared public inputs

`public-input-catalog.js` owns reviewed public provenance separately from the
supplied bytes. `public-inputs.js` verifies it without filesystem or network
access. The public `verifyPreparedPublicInputs` accepts an exact candidate SHA,
a `bytes` Map keyed by `bundle-id/member`, and optionally a separately reviewed
`reviewed` catalog. The default is the frozen `PUBLIC_INPUT_REQUIREMENTS`.
Payload-supplied manifests are bytes to check, never authority to replace the
reviewed catalog. A supervisor prepares separate immutable bundles; the caller
supplies byte snapshots through this explicit boundary. The verifier never opens
member names as paths, extracts archives, imports candidate modules, invokes an
installer, or runs build scripts. Report/artifact I/O remains explicit in the
CI entry point or supervising collector; ordinary jobs do not acquire these
unprepared inputs or activate protected provider execution.

Each bundle records its exact version, pinned revision or explicit null, public
locator URLs, dependent audit findings, licensing scope, build inputs, ABI
assumptions, setup privileges, and missing material. Each member records its
name, kind, exact URL or unresolved null, reviewed SHA-256 and byte count, any
archive digest, and any Git blob ID. The verifier compares supplied SHA-256,
length and, when available, the Git `blob <length>\0` SHA-1 identity.
Entries without resolved URLs/digests identify missing material and do not claim
resolved archive members or usable implementation bytes.
Source files and members carrying a Git blob identity require a declared exact
revision and a URL carrying that revision, including manifests and licenses.
A moving URL with a revision field is rejected. Unresolved artifact URLs or
digests cannot be filled by hashing newly supplied bytes. Unknown or duplicate
members, unsafe names, extra manifest fields, and inconsistent prior-archive
references are rejected.
Inputs are bounded to eight bundles, 128 members, 64 MiB per member and 256 MiB
total. These names are byte-map identifiers and confer no filesystem authority.

Member results distinguish `PASS` byte matches, `FAIL` altered bytes, and
`BLOCKED` missing bytes/provenance. Expected and observed digests and sizes
remain separate; raw candidate contents and diagnostics never enter a report.
Missing material blocks its own bundle while independently matching members
remain inspectable. A successful byte check proves only a match to reviewed
provenance. Every new inspected fact remains incomplete and release-unbound;
findings remain BLOCKED even when all supplied members match and a binary and
source revision are both present. The verifier neither attests an audited build
nor accepts source/binary equivalence, callable authority, installation, or
native/provider proof.

`renderPublicInputReport` consumes that verification through the existing
evidence/reporting owner. Its structured `report.publicInputs` retains exact
public metadata and missing material. Its bounded summary and annotations use
only fixed messages, validated bundle IDs and counts. Its native aggregate has
no system or protected provider records, and therefore cannot produce GO.

### Retained and missing bundles

- **Sandbox Runtime 0.0.78 publication:** retain the already reconciled archive
  SHA-256, SHA-512 SRI and npm key identity against the exact
  [metadata](https://registry.npmjs.org/@anthropic-ai/sandbox-runtime/0.0.78),
  [archive](https://registry.npmjs.org/@anthropic-ai/sandbox-runtime/-/sandbox-runtime-0.0.78.tgz)
  and [key](https://registry.npmjs.org/-/npm/v1/keys) URLs. `PRIOR_VERIFIED`
  denotes historical publication verification, which is not repeated or
  silently promoted to source closure. The eight prepared release-member
  hashes are recorded separately. Full released `package.json`, `LICENSE`,
  `dist/` closure, `vendor/build-common.js`, and
  `vendor/srt-win/x64/srt-win.exe` bytes are still missing. The absent published
  `gitHead` and absence of Rust archive members remain unresolved.
- **Sandbox Runtime candidate source:** tag `v0.0.78` resolves to
  `6f0ce155ccb136bda33a8a72201fe7f54fe47d9b` in the prepared provenance. Ten
  pinned files include Cargo manifests/lockfile, `launch.rs`, `runner.rs`,
  selected Job/account/self-protection/CLI code, upstream `package.json`, and
  `LICENSE`. Reviewed SHA-256 and Git blob IDs accompany each. Seventeen
  additional known Rust members, including entry points, token, WFP, ACL,
  registry/state and recovery dependencies, have pinned URLs/blob IDs but no
  prepared bytes or reviewed SHA-256. Full reached-source review and
  release/tag/tree/build provenance linking the packaged PE to that exact Rust
  tree are still missing. Upstream Apache-2.0 declarations do not establish
  complete packaged or transitive licensing.
- **Codex 0.159.2:** the
  [exact publication](https://registry.npmjs.org/@openai/codex/0.159.2) and
  [repository](https://github.com/openai/codex) are retrieval locators. Platform
  manifest/archive URLs must come from that publication, not a derived guess
  or the local 0.159.3 installation. Publication/platform bytes,
  release/checksum/build provenance, pinned Cargo manifests/lockfile,
  sandbox/setup implementations, tool registry/specification and reached
  handlers, and version-matched App Server dispatch/schemas remain missing.
- **Claude 2.1.285:**
  [setup documentation](https://code.claude.com/docs/en/setup),
  [installer](https://claude.ai/install.sh), and
  [publication](https://registry.npmjs.org/@anthropic-ai/claude-code/2.1.285)
  are retrieval inputs only. Actual version publication/platform URLs,
  artifact bytes, checksums, licensing and any release-bound tool/enforcement
  implementation remain missing. No installer is executed. Native binaries
  and npm contents have no presumed equivalence; Sandbox Runtime licensing
  and platform support do not transfer to Claude.
- **macOS mechanisms:**
  [XNU](https://github.com/apple-oss-distributions/xnu) is a source locator,
  with no guessed revision or member URL. Build-matched SDK declarations and
  exact-tree process identity, coalition/domain privilege, membership and
  lifecycle implementations under `bsd/sys`, `bsd/kern`, `osfmk/kern` and
  `libsyscall/wrappers/libproc` are missing. Documented launchd/XPC lifecycle
  interfaces and relevant implementation evidence are also missing. Older or
  unpinned source cannot establish current callable authority.

### Installation and build exclusion

No candidate installation is admitted by this verifier. Before any separately
authorized installation, the supervisor must prepare and reviewers must inspect
a CI-private lock proposal covering every exact transitive/platform dependency,
its registry metadata and tarball URLs, integrity, licensing, lifecycle/build
scripts and toolchains. Source or Cargo lock files alone do not supply that
closure. Missing derived URLs/revision pins are resolved before their bytes can
be relied on; packages are never installed just to discover their dependencies.
The root dependency graph and lockfile are unchanged.

The current Windows hypothesis includes Rust edition 2024, locked Windows
bindings and bundled SQLite, plus Bun/TypeScript helper/release build inputs.
Actual x64 Windows Rust/MSVC/SDK versions, dependency/build-script closure, PE
ABI imports and privileged account/WFP/ACL/registry setup still require review.
Non-Windows host shims and stubbed C compiler/archive tools cannot demonstrate
helper reproducibility. If binary equivalence needs reproduction, separately
authorized CI must use the complete reviewed tree, exact dependency bytes,
licenses and lifecycle scripts, pinned real target toolchains and build inputs,
and independently compare resulting binary digests/build provenance. Roles do
not run downloaded build scripts. Non-Linux provider ABI and setup privileges
remain explicit unknowns in their own bundles. Pinned but unbound source stays
hypothesis evidence and authorizes no dependent installation or admission.

## Seven required contracts

1. **Exact launch.** Execute a selected executable with literal argv, including
   spaces, empty strings, Unicode, quotes, and shell metacharacters. Launch a
   real executable from the allocated storage. A Node process reading a script
   there does not prove executable storage. Intentionally requested shell
   scripts are explicit restricted payloads.
2. **Access profiles.** Read-only permits inspection, including ordinary Git
   inspection, but denies content and Git-control mutation. Workspace-write
   permits intended content edits while denying Git/control, outside writes,
   and synthetic credentials. Trusted commands receive disposable writable
   storage without authority over the original checkout. The separate commit
   profile exposes only the fixed executor's synthetic metadata authority.
3. **Confined files.** Allocate private storage, retain parent authority, reject
   ancestor/leaf substitution and unsupported aliases, and delete only the
   recorded identity. Exclusive publication has one winner and exposes complete
   bytes; replacement is atomic across process interruption. State the measured
   crash guarantee without claiming universal power-loss durability.
4. **Network and IPC.** Deny prohibited host endpoints, sockets, credentials,
   and control channels. Prove permitted isolated loopback where the profile
   declares it. Host loopback, proxy access, account separation, and a status
   flag cannot stand in for isolated loopback or effective enforcement.
5. **Durable ownership.** Admit every payload and helper into an owned domain
   before releasing execution. Persist complete, protected native identities,
   policy, and admission evidence. Detached/reparented descendants remain owned
   across cancellation and owner/helper loss. A fresh independent verifier must
   establish retirement from persisted evidence before exclusion is cleared.
6. **Constrained Git authority.** Ordinary profiles cannot stage or commit.
   The fixed executor can create only the expected synthetic HEAD/current-branch
   effect using the exact subject-only message and existing identity, without
   bodies, footers, authorship trailers, extra refs, remote/configuration/identity
   changes, or outside effects. Workflow one-shot authorization stays
   runner-owned; it is not a claimed kernel property.
7. **Provider mediation.** Real command and enabled file-tool paths use the
   proved effective authority, operate unattended, and cannot escape through
   alternate tools, hooks, background execution, or permission fallback.
   Provider transport/authentication remains separate from payload authority.
   A standalone sandbox, mocked tool, version, or help response is insufficient.

## Shared invariant inventory

The IDs below are the proposed native evidence contract, separate from local
pipeline finalization check IDs. Keep them stable when the harness is admitted.
Use one implementation of each invariant and add platform cases only for a
distinct native mechanism. Do not multiply equivalent kernel proofs across
providers, pipelines, modes, or transports.

Evidence routes: **L** = local released-source/API inspection; **S** = real
native system CI; **P** = explicitly authorized protected provider acceptance
when real tool dispatch cannot be exercised model-free. An L observation never
substitutes for S or P. All required native observations are currently unproved.

| Check ID                  | Required observation                                                                                                       | Route                     |
| ------------------------- | -------------------------------------------------------------------------------------------------------------------------- | ------------------------- |
| `audit.release`           | Versions, bytes, licensing, ABI, privileges, effective policy, and unresolved source assumptions are recorded.             | L + S                     |
| `launch.argv`             | The exact executable and shared literal argument corpus reach the payload without shell reinterpretation.                  | L + S                     |
| `launch.storage`          | A real executable starts from the private allocation under the selected profile.                                           | S                         |
| `profile.read-only`       | Inspection succeeds; content, index, refs, control storage, outside writes, and credential access are denied.              | L + S                     |
| `profile.workspace-write` | Intended edits succeed; Git/control, outside writes, and credential access are denied.                                     | L + S                     |
| `profile.trusted-command` | Disposable edits succeed; the original checkout and host authority are unavailable.                                        | L + S                     |
| `files.private`           | Allocation privacy and held-parent authority are independently observed.                                                   | L + S                     |
| `files.publish`           | Concurrent exclusive publication has one winner with complete bytes.                                                       | S                         |
| `files.replace`           | Acknowledged interruption barriers leave complete old or new content.                                                      | S                         |
| `files.substitution`      | Ancestor/leaf substitution fails and cleanup preserves the substitute.                                                     | S                         |
| `files.aliases`           | Native aliases and unsupported representations cannot broaden authority.                                                   | L + S                     |
| `files.cleanup`           | Removal matches the held/recorded identity and synchronizes the declared durable boundary.                                 | L + S                     |
| `network.deny`            | A ready positive-control endpoint is reachable outside the profile; the actual prohibited operation is denied inside it.   | L + S                     |
| `network.loopback`        | Declared isolated loopback works while prohibited host endpoints remain unreachable.                                       | L + S                     |
| `ipc.deny`                | Host sockets, unsafe service paths, and receipt/control channels remain unavailable to the payload.                        | L + S                     |
| `ownership.admission`     | Complete protected receipts and native domain membership precede payload release.                                          | L + S                     |
| `ownership.descendants`   | Detached/reparented descendants retain the same owned domain.                                                              | L + S                     |
| `ownership.cancel`        | Cancellation retires the owned domain within its explicit bound.                                                           | S                         |
| `ownership.owner-loss`    | A fresh verifier establishes retirement after acknowledged owner loss.                                                     | L + S                     |
| `ownership.helper-loss`   | Helper loss settles managers, trampolines, proxies, descendants, and storage, or retains exclusion.                        | L + S                     |
| `ownership.receipts`      | Live, substituted, mismatched, or unverifiable evidence excludes another launch without signalling unrelated processes.    | L + S                     |
| `git.ordinary-denial`     | Ordinary staging and commit attempts are denied with unchanged external state.                                             | S                         |
| `git.fixed-commit`        | Only the expected HEAD/current branch and exact subject change; all other authorities remain unchanged.                    | L + S                     |
| `provider.transport`      | Provider connectivity is distinct from command authority and does not disclose authentication to payloads.                 | L + S; P if indispensable |
| `codex.command-tools`     | The actual native command/tool route enforces the bound policy and unattended approvals.                                   | L + S; P if indispensable |
| `codex.file-tools`        | Every enabled model file tool shares enforced authority or is disabled with complete inspection/editing preserved.         | L + S; P if indispensable |
| `claude.command-tools`    | Real Bash and alternate command/background routes cannot bypass confinement.                                               | L + S; P if indispensable |
| `claude.file-tools`       | Every enabled file tool is enforced or demonstrably disabled without losing required inspection/editing.                   | L + S; P if indispensable |
| `provider.no-fallback`    | Unsandboxed fallback, alternate tools/hooks, and native permission prompting cannot bypass or stall the required behavior. | L + S; P if indispensable |

Every denial requires valid setup, a permitted positive control, observation of
the attempted operation and its denial, and unchanged external sentinels.
Missing binaries, invalid arguments, crashes, and connection timeouts fail the
case. Setup, case, and teardown have separate explicit deadlines. Controller
emergency cleanup cannot turn a case into a pass.

The controller provisions owned fixtures; the restricted payload attempts the
effects; the verifier independently inspects identities and sentinels. Use
readiness messages and acknowledged fault barriers. Payloads cannot write
receipt/control storage. Cleanup uses owned handles or revalidated stable native
identities, never an unrelated host process or an unvalidated numeric PID.

### Necessary platform cases

- **Linux:** reuse the existing protected bubblewrap and owned-process exports
  through `src/agents/index.js`. Preserve their registration barrier and PID
  namespace retirement. Inspect actual namespace identities and detached
  descendants; do not relocate the production supervisor. Source references
  are `src/agents/owned-process.js` and `process-containment.js`, with current
  contract details in [Architecture](../../docs/ARCHITECTURE.md).
- **macOS:** held descriptors and file/volume identities must cover symlinks,
  case/volume aliases, and interrupted publication/replacement. Seatbelt policy
  needs explicit review of Mach services, Apple Events/Launch Services, host
  sockets, and loopback. Recoverable ownership needs its own accepted native
  descendant domain and stable identity, not ancestry or process groups.
- **Windows:** held handles, private DACLs, volume/file IDs, reparse points,
  junctions, hard links, drive/UNC paths, alternate streams, device paths, and
  ambiguous names need faithful support or explicit rejection. Observe actual
  restricted identity, Job admission/no-breakaway, nested/alternate-identity
  launches, WFP probe ownership, proxy exceptions, and ACL settlement.

The initial declared native images are `ubuntu-24.04`, `macos-15-intel`, and
`windows-2025`, all x64. These are plan targets, not observed hosts or confirmed
ABI compatibility. Package arm64 coverage does not establish arm64 PoC proof;
Windows Server evidence does not establish Windows desktop compatibility.
Missing declared checks remain BLOCKED, with no capability skips or narrowed
coverage adopted automatically.
Unknown platform branches remain BLOCKED.

## Candidate releases and inspected evidence

Inspection date: 2026-09-30. No release is adopted as a production dependency.
Only the evidence explicitly described here was inspected. Upstream repository
and documentation links are source locators, not claims that their contents or
release signatures were retrieved and verified.

### Sandbox Runtime 0.0.78

Inspected the locally available npm archive for
`@anthropic-ai/sandbox-runtime@0.0.78`: `package.json`, `LICENSE`, `README.md`,
`dist/index.js`/`.d.ts`, and the released manager, macOS, and Windows JavaScript
and declarations. The manifest and license identify Apache-2.0, Node.js
`>=20.11.0`, and the [upstream repository](https://github.com/anthropics/sandbox-runtime).
The [version metadata](https://registry.npmjs.org/@anthropic-ai/sandbox-runtime/0.0.78)
and [release archive](https://registry.npmjs.org/@anthropic-ai/sandbox-runtime/-/sandbox-runtime-0.0.78.tgz)
are the publication verification targets; their authenticated integrity and
source-revision binding have not been obtained in this audit.

Public exports include `SandboxManager`, configuration schemas,
`resolveSrtWin`, installation/status functions, `verifyWindowsWfpEgress`,
`stampWindowsAcl`/`restoreWindowsAcl`, and `grantWindowsAcl`/`revokeWindowsAcl`.
`SandboxManager` is one module-global object, not an independently constructible
manager. Its `initialize`, `updateConfig`, `wrapWithSandbox`,
`wrapWithSandboxArgv`, `cleanupAfterCommand`, and `reset` share state.
Separate future policy allocations need separate short-lived manager processes;
resetting one singleton is not proof of independent overlapping profiles.

Both wrap methods take **command text**. `wrapWithSandboxArgv(command, ...)`
returns `{argv, env}`; it does not accept a payload executable/argv tuple.
The macOS implementation builds an `env`/`sandbox-exec`/shell `-c` invocation.
The Windows implementation returns `srt-win exec ... -- <shell> ... <command>`.
A future protected fixed trampoline must receive executable/literal argv via
private IPC; payload arguments must never be interpolated into wrapper text.
The returned broker environment and sandbox-user environment are distinct.

The macOS implementation uses `/usr/bin/sandbox-exec`; its policy permits fork
and exec but supplies no durable ownership, recovered retirement, or native
process-handle API. Its log monitor is diagnostic evidence only. The release
documents `allowAppleEvents` and `enableWeakerNetworkIsolation` as unsafe
expansions; do not enable them. `allowLocalBinding` opens host loopback access,
not a private network domain. The base Mach/IPC allowances require review as
well as any configured additions. macOS setup lists ripgrep; private file-helper
compilation requires a native SDK/toolchain in CI. No consumer compiler or
privileged ownership installation has been approved.

Windows is explicitly alpha. The archive contains x64 and arm64 PE helpers
(observed machine values `0x8664` and `0xaa64`). Its JS/README describe a dedicated
account, account-SID WFP filters, and broker → `CreateProcessWithLogonW` runner →
restricted-token child in a Job. This description does not prove Job membership
of both hops or out-of-band creation containment. `vendor/srt-win/build.ts`
references a locked Cargo build of `srt-win-src`; that Rust source and its
`launch.rs` are absent from the inspected npm archive.

The released `resolveSrtWin({path})` requires an explicit existing path and
returns `{exe, prependArgs: ['--srt-win']}`. There is no automatic packaged-helper
fallback, despite the README's omission guidance. `VENDORED_SRT_WIN_EXE` is an
exported locator, not an integrity/protection check. The PoC must pin and protect
the selected binary before using the descriptor. Metadata surfaces include
`checkWindowsSandboxStatusAsync`, `getWindowsWfpStatusAsync`, and
`getWindowsSandboxUserStatusAsync`; elevated setup uses
`installWindowsSandboxAsync`. Behavioral verification is a separate operation.

Elevated installation provisions the account, local group, registry credential
storage, and machine-wide WFP policy. Test payloads must use the restricted
identity; the CI administrator is setup authority only. Status enumeration can
be admin-gated. `SandboxManager.initialize()` invokes behavioral
`verifyWindowsWfpEgress`, which launches a sandbox-user probe. Thus initialization
is execution requiring prior owned admission, not harmless metadata setup.

Successful WFP verification is cached once per manager process; `reset()` does
not clear it. With TLS termination and implicit CA storage, initialization also
calls `ensurePersistentWindowsCa`, which writes CA files and may invoke
`windowsTrustCaAsync` to launch a sandbox-user trust helper. Certificate trust
persists beyond manager reset. That optional path needs the same owned admission
and explicit accounting for storage/trust effects and cleanup. Neither cache
reuse nor manager reset proves current enforcement or complete settlement.

Filesystem grants are session-scoped. Per-command `allowRead`/`allowWrite`
overrides throw; denies and glob expansion do not provide held-parent file
authority. ACL grants share the sandbox SID, so concurrent policy allocations
cannot be assumed independent. A future harness must serialize that shared
resource or establish an audited alternative. `reset()` logs ACL anomalies
instead of rejecting them; restore/revoke can return incomplete outcomes.
Independent native verification must retain exclusion until cleanup is proved.
WFP allows the configured host proxy port range; that exception is not isolated
loopback or proof that other host services are unavailable. Per-user executable
installs may be inaccessible to the sandbox account.

The npm manifest uses dependency ranges. A private CI lock must pin and inspect
transitive bytes/licenses before installation; no dependency was installed here.
Neither PE architecture nor wrapper source establishes the minimum supported
Windows/macOS build, native setup success, or consumer distribution feasibility.

### Codex 0.159.2

Inspected `@openai/codex` and its installed Linux x64 platform manifest, Node
launcher, executable version/help, and generated public App Server JSON schemas.
The manifests declare Apache-2.0 and Node.js `>=16`. The launcher maps Linux
musl, macOS, and Windows MSVC packages for x64/arm64. Only the Linux x64 executable
was inspected; its ELF header identifies static PIE. Other OS binaries, minimum
OS builds, native privilege/setup requirements, and complete Rust source are
unverified. Source locators are the [repository](https://github.com/openai/codex)
and [version metadata](https://registry.npmjs.org/@openai/codex/0.159.2).

Observed CLI version: `codex-cli 0.159.2`. Linux `codex sandbox --help` exposes one
unified command taking command argv, plus permission-profile and sandbox-state
options. It does not expose OS subcommands; do not invent `sandbox linux`,
`sandbox macos`, or `sandbox windows`, or assume the same native interface.
No sandboxed payload was run. Model-free version/help inspection reported an
unavailable PATH-alias write, which does not attest execution confinement.

`codex app-server --help` advertises STDIO and schema generation. Running
`codex app-server generate-json-schema --out <private-audit-directory>` produced
the version's public schemas without a thread, turn, or model request:

- `command/exec` accepts a command argv vector, cwd, environment overrides,
  timeout/output bounds, and `sandboxPolicy`; its description specifies the
  server sandbox. This is a concrete model-free command probe surface.
- `thread/start`, `turn/start`, and their schemas expose sandbox and approval
  settings. Their actual model-issued command/file implementations still need
  source review and native/protected proof.
- `fs/readFile` and `fs/writeFile` describe **host filesystem** operations with
  an absolute path and no thread-bound sandbox parameter. They are separate
  control RPCs, not proof of model file-tool confinement or an observed escape.
  Unused host/configuration RPCs must not become payload authority.
- A schema description mentions `permissionProfile`, but the generated public
  `CommandExecParams` properties omit it. Do not infer a callable field from
  that description or silently adopt experimental interfaces.
- Windows setup/readiness RPCs are present, but were not executed. Schema
  presence cannot establish effective native setup, policy, or ownership.

The official [App Server documentation](https://developers.openai.com/codex/app-server)
could not be fetched because DNS was unavailable. No current documentation or
published release checksum is asserted from that failed retrieval. Command
dispatch success would still not establish an App Server model file-tool path.

### Claude 2.1.285

Inspected the installed Linux x64 native executable's header/digest and
`claude --version`/`--help`; observed version `2.1.285 (Claude Code)`. Its ELF
header identifies a dynamically linked x86-64 executable. No complete release
source, authenticated manifest/checksum, other OS binary, minimum OS/ABI, or
redistribution license was inspected. Do not inherit Sandbox Runtime's
Apache-2.0 license or Windows support for Claude. Publication/setup/licensing
locators are [Claude Code setup](https://code.claude.com/docs/en/setup),
[sandboxing](https://code.claude.com/docs/en/sandboxing), and
[Anthropic terms](https://www.anthropic.com/legal/consumer-terms); they were not
retrieved as release-specific evidence here.

The real help advertises `--tools`, `--allowedTools`, `--disallowedTools`,
`--settings`, `--setting-sources`, `--strict-mcp-config`, and `--bare`.
It also advertises `--permission-mode dontAsk` and `--permission-prompts none`:
the latter denies anything that would prompt, while the permission mode still
decides the operation. These are candidate unattended controls, not proof that
required inspection/editing succeeds.

`--restricted` advertises working-directory confinement for file tools and
removes command/code tools unless `--tools` names them. Re-enabling Bash is not
an advertised binding to an external Windows sandbox. `--bare` skips hooks and
several integrations but is not a complete tool or filesystem security policy.
Background, PowerShell/code-running tools, plugins, MCP, and fallback paths need
explicit coverage or disabling. No authenticated turn or real tool dispatch was
run, and no released mechanism for complete native Windows mediation has been
accepted. Existing Linux adapter policy remains unchanged.

### Observed integrity, not authenticated release pins

These SHA-256 values identify only the bytes inspected. They are not committed
CI successes, published checksums, signature verification, or authorization to
install/distribute the candidates. Native composition must obtain trustworthy
publication/source bindings and record each actually installed binary digest.

| Inspected artifact                     | SHA-256                                                            |
| -------------------------------------- | ------------------------------------------------------------------ |
| Sandbox Runtime 0.0.78 npm archive     | `a9cf9e35068a4c71d2d94de8b0abe8de51c7d44daef537cc92906848ccc67240` |
| Its `vendor/srt-win/x64/srt-win.exe`   | `b1927893da83a1cb28054f63c8b2bc61ac4303cf63dd92c0182f79c5c414d26d` |
| Its `vendor/srt-win/arm64/srt-win.exe` | `72a289b76db3de6b94bb7ae7821870dcbf7b950a4de98c8b5e92619060a5b44d` |
| Codex 0.159.2 Linux x64 executable     | `1748767b230ebfc3d4ab7e4e254920d0c0ad9691fd8c11f190e7d44511a4a92e` |
| Claude 2.1.285 Linux x64 executable    | `33dad1ec615a2e08cc78b494f05c110e49916de2c79d78ec8799ebf46b233d29` |

## Mechanism decisions and helper gaps

| Responsibility             | Inspected mechanism or necessary gap                                                                                                                                                                                                                                          | Audit disposition                                             |
| -------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------- |
| Linux ownership            | Existing indexed owned-process registration, protected bubblewrap, native identities, and namespace retirement. Reuse without changing production.                                                                                                                            | Concrete reference; native CI UNPROVED.                       |
| macOS/Windows exact launch | Released wrappers take command text; a protected fixed argv trampoline with private IPC is necessary.                                                                                                                                                                         | Gap identified; implementation and native proof pending.      |
| macOS files                | Node lacks the required held-parent operations; a narrow native helper needs `openat`, `fstatat`, `linkat`, `renameat`, `unlinkat`, stable file/volume identities, and synchronization.                                                                                       | Gap identified; native SDK/ABI and crash proofs pending.      |
| Windows files              | A narrow handle-relative helper needs private DACLs, reparse-aware traversal, volume/file IDs, and handle-based publication/removal. Audit `NtCreateFile` root handles and native rename/sharing semantics.                                                                   | Gap identified; native implementation and ABI proofs pending. |
| macOS ownership            | Seatbelt, process groups, ancestry, and a live monitor do not supply a recovered descendant domain. No accepted domain/identity/retirement API was found.                                                                                                                     | `A-MAC-OWNERSHIP`: technical NO_GO.                           |
| Windows ownership          | Job/process handles, suspended launch/assignment, no-breakaway, queries, and creation identities are the candidate native primitives. Exact two-hop, initialization subprocesses, out-of-band, and last-handle-loss composition is unverified; helper Rust source is missing. | `A-WIN-ADMISSION`: technical NO_GO.                           |
| Provider mediation         | Codex command RPC is concrete, but model file-tool authority is unverified. Claude help supplies controls, not a verified native Windows Bash/file-tool binding.                                                                                                              | `A-PROVIDER-MEDIATION`: technical NO_GO.                      |
| Adoption/distribution      | Publication integrity, complete helper source binding, transitive licensing, Claude licensing, non-Linux ABI, and setup privileges need release-specific closure.                                                                                                             | `A-RELEASE-CLOSURE`: technical NO_GO for adoption.            |

The candidate Windows kernel API surface is `CreateJobObjectW`,
`SetInformationJobObject`, suspended process creation,
`AssignProcessToJobObject`, `QueryInformationJobObject`, `OpenJobObjectW`,
`TerminateJobObject`, process handles, `GetProcessTimes`, and exit waits.
The [Job Object reference](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects)
is a research locator. These names do not establish released helper support:
the audit must bind their actual use to both launch hops, controlling handles,
creation identities, protected receipts, and fresh-verifier retirement before
accepting a native gap implementation.

The ownership gap is not permission to invent helper flags, use numeric PIDs as
authority, or choose an event monitor/process group as recovered proof. Native
file APIs alone cannot close it. Job membership alone cannot exclude host
service creation. Keep account, proxy, ACL, helper, and storage uncertainty in
the exclusion record. Source/API closure must precede an accepted implementation
sequence; native behavior alone awaiting CI stays explicitly unproved.

## Source/API closure and continuation gate

Before dependent installation, helper execution, or payload admission, inspect
released implementations and callable APIs that justify the complete admission,
effective authority, protected receipts, recovery, and independently verified
retirement sequence. Candidate primitives, wrapper descriptions, and behavioral
status flags cannot substitute for that source closure. Do not select guessed
mechanisms or helper flags.

The technical findings require the following closure evidence:

- **`A-MAC-OWNERSHIP`:** an accepted recoverable descendant domain with stable
  native identities and independent recovered retirement. Seatbelt, ancestry,
  process groups, and monitoring remain insufficient.
- **`A-WIN-ADMISSION`:** released helper-source/binary binding, admission of both
  launch hops and initialization/WFP subprocesses, no-breakaway, containment of
  out-of-band creation, and controlling-handle/helper-loss recovery. Account,
  proxy, ACL, trust, and storage settlement must all be established.
- **`A-PROVIDER-MEDIATION`:** inspected enforcement for actual commands and every
  enabled file-tool route, unattended operation, authentication separation,
  alternate/background tools, hooks, and permission fallback. Schemas, help,
  standalone sandboxes, and mocks cannot establish complete mediation.
- **`A-RELEASE-CLOSURE`:** trustworthy publication/source/binary binding,
  transitive integrity and licensing, non-Linux ABI, and required setup
  privileges. Observed digests and research locators remain insufficient.

The historical reconciliation stopped at **BLOCKED: technical NO_GO** for
dependent native implementation. The old twelve-step plan remains historical
reference. The new reviewed continuation admits the independent evidence owner
above; it does not close these findings or admit dependent native helpers.
Source/API closure and a separately reviewed implementation sequence remain
required for those dependent mechanisms.

## Prepared-source mechanism research: 2026-10-02

This continuation inspected prepared files as data, without retrieving,
installing, importing, executing, or building candidate bytes. It preserves the
historical audit's narrower scope. The partial Rust tree now makes specific
admission and recovery hypotheses inspectable; it does not resolve the absent
release binding. Missing Windows material does not suspend the independent
macOS, Codex, or Claude investigations. Each dependent candidate remains
BLOCKED for the reasons below, rather than receiving acceptance from another
candidate's evidence.

### Citation and binding scope

**MAC**, **WIN**, and **MGR** below identify these members of the exact
[Sandbox Runtime 0.0.78 archive](https://registry.npmjs.org/@anthropic-ai/sandbox-runtime/-/sandbox-runtime-0.0.78.tgz).
Line references count the prepared released JavaScript, including comments.
There is no published `gitHead` binding for these members. Their reviewed
digests and the historical archive integrity evidence remain in
[the public-input catalog](public-input-catalog.js); this inspection does not
repeat or upgrade that reconciliation.

| Citation | Archive member                                  | Reviewed SHA-256                                                   |
| -------- | ----------------------------------------------- | ------------------------------------------------------------------ |
| MAC      | `package/dist/sandbox/macos-sandbox-utils.js`   | `acb89435d05939bacc93fce50755e8199739de41ca1ea7a00b5599eef0d5f43a` |
| WIN      | `package/dist/sandbox/windows-sandbox-utils.js` | `2a651f7e337c508ff8c299f86c15772f245fa064bb4c1d8976b4955e2484575d` |
| MGR      | `package/dist/sandbox/sandbox-manager.js`       | `d3ebcfe582a1ed2b5178cd2a6bda296e97175aa39de824ece5a61fb28d01edac` |

Every Rust link below names revision
`6f0ce155ccb136bda33a8a72201fe7f54fe47d9b` in
`anthropics/sandbox-runtime`, prepared as the `v0.0.78` candidate. The ten
prepared files have reviewed SHA-256 and Git blob identities in the catalog.
The same version/tag is insufficient to bind the packaged PE to this tree.
All Rust conclusions below are **unbound source findings**; none asserts the
released helper executes this implementation. Missing reached modules prevent
even complete source-level composition review.

The prepared provenance supplies no build-matched XNU/SDK/launchd implementation
and no release-bound Codex or Claude tool implementation. Their exact missing
inputs are identified below without guessing revisions, artifact URLs, symbols,
or an enabled tool set. Moving documentation and historical help/schema
observations remain surface evidence only.

### macOS: effective policy is separate from recovered ownership

MAC `generateSandboxProfile`, lines 674–687, starts with deny-default but grants
`process-exec` and `process-fork` without a target predicate, plus
`process-info*`, `signal`, and `mach-priv-task-port` with `same-sandbox` targets.
These grants permit process operations; the wrapper supplies no protected
allocation, durable
membership receipt, native birth identity, admission acknowledgement, or
recovered retirement operation. A policy predicate cannot demonstrate that a
fresh verifier can retire detached or reparented members after the owner dies.
No such native behavior was observed in this continuation.

The base policy also supplies authority that needs independent review:

- MAC lines 693–707 allow named Mach lookups for audio, distributed
  notifications, fonts, logging, power, directory/membership, security, and
  `com.apple.coreservices.launchservicesd`, among others. Availability of a
  service is not evidence that its server-side work joins the client's owned
  domain. Service-mediated creation and delegated effects need their actual
  handler and privilege checks, or an effective denial with a positive control.
- Lines 709–728 add `com.apple.trustd.agent` for weaker network isolation and
  Apple Events/`lsopen`/related lookups for Apple Events. Both options default
  false and remain disabled. That does not remove the base Launch Services
  lookup. Lines 730–736 permit configured exact Mach names or prefixes for a
  trailing `*`; each addition expands the service audit, rather than inheriting
  a blanket ownership guarantee.
- Lines 738–742 grant POSIX shared-memory and semaphore operations without a
  fixture-private naming rule here. Job/domain membership, host object access,
  and private protocol channels are separate questions. The specific IOKit
  allowances and AF_SYSTEM socket rule that follow also need build-matched
  enforcement review; upstream comments calling them safe are not proof.
- Lines 847–876 allow `network*` when restrictions are unnecessary.
  `allowLocalBinding` otherwise grants wildcard bind/inbound access and
  `localhost:*` outbound access. This is host loopback authority, not isolated
  loopback. Lines 886–913 add broad or selected Unix-socket paths and proxy
  loopback ports. Removing broad Unix-socket grants does not remove the Mach
  and POSIX IPC grants above.

MAC lines 564–621 start file reads with `allow file-read*`, add configured
denies/re-allows, then movement restrictions. Write rules at lines 626–668 allow
configured roots, apply mandatory/configured denies and movement restrictions;
without write configuration they allow `file-write*`. The visible mandatory
Git entries at lines 20–43 cover hooks and conditionally configuration, while
other dangerous-path lists come from an unprepared import. This is not a
recovered complete Git-control exclusion or held-parent file boundary. Fixture
profiles still need explicit index/ref/control protection and real effective
denials, independently of wrapper read/write settings.

MAC `wrapCommandWithSandboxMacOS`, lines 966–1110, degrades requested masks to
read-deny rules and returns the original command if network/read/write
restrictions, environment overlays and Git safe-directory entries are absent.
Otherwise it resolves a shell and assembles quoted environment text plus
`/usr/bin/sandbox-exec -p <profile> <shell> -c <command>`. MGR lines 1421–1540
expose the macOS result through another shell `-c` argv. This is not the exact
executable/literal argv boundary required by `launch.argv`. A protected
trampoline would need private authenticated input and its own admission and
retirement sequence; no supplied implementation provides that sequence.

The MAC log monitor, lines 1116–1193, starts `log stream`, filters diagnostic
messages, and returns a function that signals that monitor. It does not recover
the payload domain. MGR's imported proxy, parent-proxy, address-guard,
credential/Java-agent and environment implementations are not prepared. MGR
lines 1290–1304 grant reads for selected CA/trust-bundle/agent files; lines
1315–1368 join network initialization to wrapping. These resources need separate
protected identities and cleanup observations. Closing listeners or seeing a
log message cannot attest the retirement of proxy workers, trampoline code,
manager processes, or service-created work.

Coalitions/domains and launchd/XPC remain distinct, unaccepted hypotheses. The
failed hypothesis is that names, ancestry, `same-sandbox`, or diagnostic
monitoring alone provide recovered exclusion. No conclusion that macOS is
impossible follows. No callable coalition/domain or service-lifecycle API has
been recovered from the supplied material, so dependent macOS admission stops
before execution. The next source closure is specifically:

| Hypothesis                       | Required prepared input and decision                                                                                                                                                                                                                                                                                                                                                                                                                   |
| -------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Kernel-owned descendant domain   | Match the actual `macos-15-intel` image/build to SDK declarations and an exact XNU tree. Locate the reached `bsd/sys`, `bsd/kern`, `osfmk/kern` declarations/implementations for creation, membership, lifecycle and privilege. Establish whether ordinary CI authority can allocate and protect the domain, whether members can escape, and whether a fresh owner can retire it. Root/entitlement requirements are unresolved, not assumed available. |
| Stable process/domain identity   | Match `libsyscall/wrappers/libproc` and reached kernel interfaces to that build. Establish identity lifetime, replacement detection, inspection permissions and reliable absence evidence. Numeric PIDs or a failed identity read cannot clear exclusion.                                                                                                                                                                                              |
| launchd/XPC-mediated ownership   | Supply documented lifecycle interfaces and version/build-matched server implementation for the proposed creation/control route, including entitlement, endpoint authentication, membership and owner/service-loss behavior. A service name or client connection is not a protected controlling handle.                                                                                                                                                 |
| Seatbelt and delegated resources | Supply the reached policy/IPC/proxy/trampoline implementation and SDK/ABI assumptions. Establish the exact service operations allowed, who owns delegated processes and sockets, and how credential, manager and storage authority settles independently.                                                                                                                                                                                              |

The next macOS system proof, once a source-backed sequence is reviewed, must
first acknowledge protected allocation and membership before release. A permitted
read/exec/private-IPC positive control precedes denied host operations. Create
real detached/reparented children, acknowledge their readiness, and inject
cancellation, owner loss, and each controlling helper's loss only at an
acknowledged barrier. A fresh verifier must observe the original domain's
retirement, or retain exclusion for live, inaccessible, replaced or substituted
receipts. A proxy/service-created positive control must either remain in the
proved domain or be denied by the inspected service boundary.

Network/IPC cases must use reachable host IPv4/IPv6 listeners, Unix sockets,
POSIX objects and relevant allowed Mach services outside the payload, plus a
separate positive control for any declared private loopback. Observe the actual
prohibited attempt and unchanged credential/control/outside sentinels. A
connection timeout, missing service, malformed request, crash, or absent log is
a failure, not denial. Keep Apple Events and weaker network isolation disabled
in both policy and recorded observations. Host proxy access cannot pass
`network.loopback`. The source-backed mechanism for that contract is still
missing.

### Windows: all helper routes need admission, including setup

WIN `resolveSrtWin`, lines 191–201, checks existence of an explicitly selected
path and produces `exe` plus `--srt-win`. Existence is not a protected binary
identity. `getSrtWinPath` has development locations; those are not an approved
fallback. WIN lines 202–277 implement the only two direct process primitives
in this prepared wrapper: synchronous `spawnSync` and asynchronous `spawn`.
The async timeout calls `child.kill()`; neither primitive registers an owned
domain, acknowledges admission, persists native identity, or independently
settles descendants. JSON adapters at lines 278–312 do not add those properties.
The default spawn budget is 15 seconds, with these overrides and routes:

| Released route and WIN lines                       | Actual operation                                                                                                         | Effect/admission consequence                                                                                                                                               |
| -------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Combined, WFP and account status, 355–396, 497–505 | `status`, `wfp status`, `user status`, sync/async JSON adapters                                                          | Read-oriented queries still execute the helper and need its protected launch/settlement boundary. Status cannot attest behavioral enforcement.                             |
| Behavioral WFP check, 421–486                      | `wfp verify --target <host:port>`, 30-second spawn budget                                                                | Creates a logon runner and may create its persistent profile. It is not effect-free readiness and cannot precede admission closure.                                        |
| Installation, 791–917                              | `install` with only the implemented sublayer/port-range/user/force options, sync/async, default 120 seconds, then status | Account, WFP, registry and ACL changes plus elevation require independent setup authority and settlement. UAC cancellation/timeout is not a complete rollback observation. |
| Uninstallation, 922–940                            | `uninstall`, optional sublayer and keep-user flags, installation budget                                                  | Removes persistent state through an elevated route. It cannot be ordinary payload authority or be assumed to clean every partial installation.                             |
| CA readback, 522–526                               | Uses supplied account status or falls back to `user status`                                                              | Supplying observed status avoids another launch; omitting it invokes the same status helper boundary.                                                                      |
| CA provisioning, 544–560, 636–775                  | `user trust-ca <certificate-path>`, sync/async, 60 seconds; persistent-CA preparation invokes it                         | Account-profile trust writes and broker certificate/key/state writes need separate protected authority and identity.                                                       |
| Deny ACLs, 1050–1111                               | `acl stamp` receives path lists on stdin; `acl restore` uses holder PID/SID and `--json`, 60 seconds                     | Partial effects can precede an error. Restore preserves per-path JSON even on failure and may return no result after a spawn/parse error.                                  |
| Allow ACLs, 1124–1169                              | `acl grant` and `acl revoke`, holder PID and SID, 60 seconds                                                             | Grants are additive shared-account authority; best-effort revocation is not independent effective-DACL or storage verification.                                            |
| Wrapped command, 1190–1285                         | Descriptor for `exec`, deny flags and environment overlays, then selected shell and command text                         | Caller launches the broker. Returned argv does not supply controller admission of either subsequent hop or exact payload argv.                                             |
| Dependency checks, 1383–1417                       | Status helpers through the same sync/async primitives                                                                    | They acquire no special exemption from helper ownership merely because called before initialization.                                                                       |

This covers each `runSrtWin`/`runSrtWinAsync` route in the prepared WIN member,
including the JSON wrappers and all returned command descriptors. It does not
claim closure of unprepared imports or the packaged helper's entry points.
The actual `--srt-win`, `exec`, `runner` and setup commands are source surfaces;
there is no recovered suspended-launch, acknowledgement, receipt, or Job-control
helper flag to invoke. No invented flags or ordinary subprocess wrapper can
repair the internal release window.

### Windows: the two Job hops are not interchangeable

The pinned
[Job wrapper, lines 36–122](https://github.com/anthropics/sandbox-runtime/blob/6f0ce155ccb136bda33a8a72201fe7f54fe47d9b/vendor/srt-win-src/src/job.rs#L36-L122)
creates an **unnamed** Job, sets kill-on-last-handle-close and explicit UI
restrictions before assignment, assigns via a held process handle, and closes
the Job handle on drop. The broker's Job allows breakaway; the runner's child
Job does not. UI limits cover specific clipboard, atoms, USER/GDI and desktop
operations, not every service/RPC effect. `is_process_in_job` returns true on
API error to choose creation flags; that conservative choice is not an
independent membership observation. `CreateJobObjectW(None, None)` supplies
neither an explicit protected Job DACL nor a persistent object binding here.
Effective DACLs, handle custody and denied payload access to controlling handles
remain proof obligations; default security attributes are not such evidence.

The candidate launch sequence is:

1. [Broker/logon creation, lines 232–278](https://github.com/anthropics/sandbox-runtime/blob/6f0ce155ccb136bda33a8a72201fe7f54fe47d9b/vendor/srt-win-src/src/logon.rs#L232-L278)
   creates the outer Job and calls `CreateProcessWithLogonW` with
   `LOGON_WITH_PROFILE` and `CREATE_SUSPENDED`, using its own executable and
   runner dispatch. Secondary Logon service execution and alternate-account
   identity are part of this hop; parentage alone is insufficient.
2. [Logon lines 315–368](https://github.com/anthropics/sandbox-runtime/blob/6f0ce155ccb136bda33a8a72201fe7f54fe47d9b/vendor/srt-win-src/src/logon.rs#L315-L368)
   retain an armed terminate-on-drop process guard, grant the account access to
   WinSta0/session named objects, attempt outer Job assignment, then resume.
   **`ERROR_NOT_SUPPORTED` logs and continues after assignment failure.** The
   source explicitly says the guard cannot cover external broker death. This
   disproves fail-closed admission for that candidate branch; an in-process
   guard cannot replace missing broker-loss containment. Upstream comments
   about earlier live probes are not evidence on `windows-2025`.
3. [Runner dispatch, lines 109–175](https://github.com/anthropics/sandbox-runtime/blob/6f0ce155ccb136bda33a8a72201fe7f54fe47d9b/vendor/srt-win-src/src/runner.rs#L109-L175)
   sends only `Exec` through `run_lockdown`. `InstallCa` writes through the
   missing certificate implementation; `ProbeEgress` connects as the bare
   account runner. Neither uses the restricted-child token/inner-Job path.
   They therefore require separate authority and settlement review rather than
   inheriting the `Exec` child's restrictions.
4. [Restricted creation, lines 128–173](https://github.com/anthropics/sandbox-runtime/blob/6f0ce155ccb136bda33a8a72201fe7f54fe47d9b/vendor/srt-win-src/src/launch.rs#L128-L173)
   attempts runner process protection, constructs a restricted primary token
   through missing `token.rs`, and creates the non-breakaway inner Job. It
   deliberately requests `CREATE_BREAKAWAY_FROM_JOB` when in a containing Job
   to escape the outer/Secondary Logon stack before inner assignment. This
   migration is not a no-breakaway guarantee for the whole two-hop sequence.
5. [Child assignment, lines 223–346](https://github.com/anthropics/sandbox-runtime/blob/6f0ce155ccb136bda33a8a72201fe7f54fe47d9b/vendor/srt-win-src/src/launch.rs#L223-L346)
   supplies mitigations and an explicit stdio handle list, creates the child
   suspended with `CreateProcessAsUserW`, retains a held-handle guard, aborts on
   inner assignment failure, checks resume, then disarms the guard. It waits
   for the primary child and closes the inner Job. This is a concrete inner
   admission pattern worth investigating, but there is no external controller
   acknowledgement or protected receipt before resume, and no independent
   retirement observation for every member after Job close.

The candidate runner command is length-prefixed JSON with a 4 MiB cap
([`runner.rs`, lines 71–104](https://github.com/anthropics/sandbox-runtime/blob/6f0ce155ccb136bda33a8a72201fe7f54fe47d9b/vendor/srt-win-src/src/runner.rs#L71-L104)).
Framing prevents ambiguous input length; it is not a domain admission receipt.
Literal argv storage in `RunnerSpec` and quoting functions in `launch.rs`
cannot prove the released JS shell-text path meets `launch.argv`.

Both [runner protection, `launch.rs` lines 133–146](https://github.com/anthropics/sandbox-runtime/blob/6f0ce155ccb136bda33a8a72201fe7f54fe47d9b/vendor/srt-win-src/src/launch.rs#L133-L146)
and [broker protection, `cli.rs` lines 1490–1493](https://github.com/anthropics/sandbox-runtime/blob/6f0ce155ccb136bda33a8a72201fe7f54fe47d9b/vendor/srt-win-src/src/cli.rs#L1490-L1493)
warn and continue on process-DACL failure. The runner source identifies
same-account parent-process creation as a reason for this protection. The
[`self_protect.rs` implementation](https://github.com/anthropics/sandbox-runtime/blob/6f0ce155ccb136bda33a8a72201fe7f54fe47d9b/vendor/srt-win-src/src/self_protect.rs)
constructs SYSTEM/Administrators/OWNER_RIGHTS ACLs and an optional broker-user
ACE, and protects the executable through a sharing lock. The broker also treats
failure to acquire that executable lock as best effort
([`cli.rs`, lines 1402–1421](https://github.com/anthropics/sandbox-runtime/blob/6f0ce155ccb136bda33a8a72201fe7f54fe47d9b/vendor/srt-win-src/src/cli.rs#L1402-L1421)).
These branches cannot establish mandatory protection of controlling processes,
handles, or code before payload release. Restricted-token SID/privilege shape
and effective handle inheritance still require the missing token/SID/util code.
An approved fresh verifier must have sufficient inspection rights; denial of
those rights retains exclusion rather than proving that a process disappeared.

Named Jobs are an alternative hypothesis, not an implemented recovery API in
this tree. A named object alone would not bind a protected receipt to the
original object or prevent name replacement. Reopening or retaining a Job
handle also changes when the **last** handle closes. A recovery design must
explicitly resolve that lifetime tradeoff, DACL/name protection, holder loss,
member identity, authoritative termination and independent completion under
nested Jobs and alternate logons. The prepared `Job` module exposes no named
reopen, enumeration or recovered termination protocol. Microsoft Job-object
documentation is a research input, not proof that those properties compose on
the declared image. No broad taskkill/account filter or unvalidated PID signal
is accepted as cleanup.

### Windows: persistent and delegated authority remains unsettled

The pinned
[`cli.rs` elevation path, lines 1632–1720](https://github.com/anthropics/sandbox-runtime/blob/6f0ce155ccb136bda33a8a72201fe7f54fe47d9b/vendor/srt-win-src/src/cli.rs#L1632-L1720)
uses `ShellExecuteExW` with `runas`, obtains an elevated process handle, then
waits indefinitely. It supplies no suspended Job admission at that call site.
The released WIN installation timeout explicitly warns that elevation is not
retracted when the parent dies (lines 779–814). Consequently, killing the
original helper on timeout cannot independently settle an outstanding UAC
request or elevated child. Account/group, machine registry, WFP and ambient ACL
installation/removal implementations reached by CLI setup are missing. Setup
privileges must be separately operator-approved and their persistent effects
reconciled; ordinary PR authority is not presumed sufficient.

MGR lines 538–571 perform provisioning status and WFP behavioral verification
during initialization. `windowsWfpVerified` is process-global (lines 67–72),
and reset at lines 1716–1748 deliberately preserves it. A prior successful
probe therefore does not establish filters for a later configuration, account,
helper identity, or policy. The future proof must bind each observation to the
effective configuration and native admission evidence, and inspect reset and
overlapping allocations. It must not inherit this cache as a proof receipt.

WIN WFP verification selects a host listener outside the proxy permit range,
then runs the account probe (lines 421–486). The candidate
[`runner.rs` probe](https://github.com/anthropics/sandbox-runtime/blob/6f0ce155ccb136bda33a8a72201fe7f54fe47d9b/vendor/srt-win-src/src/runner.rs#L133-L175)
returns success only for Winsock `WSAEACCES` (10013), connected as code 3 and
other failures as code 2; malformed input is an error. Its two-second connect
timeout is not successful denial. That error alone does not identify the
effective denying filter or bind it to the selected WFP configuration.
The wrapper opens a listener but does not
demonstrate an acknowledged permitted connection to that listener. Future CI
needs that reachable positive control, observed prohibited attempts, and
independent listener/runner cleanup. The unprepared WFP implementation must
establish address-family/filter/lifetime behavior; this one host-loopback check
cannot prove isolated loopback or all network paths.

WIN lines 1190–1285 forward selected PATH/PATHEXT/proxy/mask/Git environment
values to the fresh account while the broker descriptor inherits its host
environment. The source explains that proxied traffic goes through a broker-SID
connection outside the account-SID WFP block. That proxy is delegated authority,
not a Job member or an equivalent user-token connection by assumption. Its
endpoint authentication, target filtering, child creation, credential handling
and cleanup need the missing proxy implementations. Inspect service/RPC-created
processes and persistent work separately from ordinary Job inheritance; the
Job's UI restrictions do not answer that question.

Privilege assumptions must remain visible. WIN lines 373–381 describe WFP
enumeration as administrator-gated and permit a `cannot-read` result; the
behavioral probe and CA trust surfaces describe non-elevated alternate-account
execution. These descriptions do not establish actual permissions on
`windows-2025`. Account/WFP/ambient setup requests elevation; process-DACL
rewrites, token conversion, desktop/named-object grants and cross-account
inspection depend on the reached security implementations and actual identities.
Record each required grant and its owner. Do not silently give the payload
administrative/debug authority so a fresh verifier can inspect or clean up.

MGR lines 614–690 record the SID before granting allows and stamping denies.
On failure, cleanup attempts revocation/restoration; partial operations may
already have changed authority. WIN restore/revoke can report per-path failures
or no usable result. Reset logs unacceptable outcomes, clears module tracking,
and accepts `stillHeld` for overlapping holders. Clearing tracking does not
establish restored external state. Shared account-SID grants affect other
matching tokens and need concurrency/union-of-authority review. The numeric
holder PID is wrapped as `HolderPid` in
[`cli.rs` ACL operations, lines 1110–1349](https://github.com/anthropics/sandbox-runtime/blob/6f0ce155ccb136bda33a8a72201fe7f54fe47d9b/vendor/srt-win-src/src/cli.rs#L1110-L1349);
without `state_db.rs`, PID reuse, holder birth identity, locking, recovery and
partial rollback cannot be assessed.

Optional CA preparation (WIN lines 636–775; MGR lines 576–611) writes broker
certificate/key/state files using path-based temporary publication and invokes
account-profile trust installation. Previous trusted roots can persist across
rotation. Logon WinSta0/BaseNamedObjects grants are intentionally persistent
across concurrent executions (`logon.rs`, lines 328–337). Account profile,
credential, registry, trust, shared grants and storage therefore need recorded
resource identities and independent settlement beyond process retirement. Node
path/rename rechecks attest none of `files.*`.

The exact next input is the packaged x64 PE/build provenance bound to the
candidate tree, then its reached entry points and missing `token`, `sid`,
`winsta`, `util`, `user`, `sam`, `dpapi`, `install`, `ambient`, `wfp`, `acl`,
`path_id`, `reg`, `state_db` and `cert_store` modules, with dependency/build and
licensing closure. These names have resolved candidate-tree provenance in the
catalog, but their bytes are absent. Real Windows/MSVC/SDK ABI and setup
privileges remain unproved. Complete source may change the mechanism decision;
the visible continue-on-failure branches already prevent accepting this partial
candidate as the required fail-closed sequence.

**All dependent Windows helper execution remains stopped**, including status,
initialization, behavioral readiness, CA creation, ACL operations and elevation,
until complete admission and independent settlement have a source-backed
sequence. Wrapping `initialize` in a parent process alone does not compose
internal suspended admission or out-of-band creation. The next reviewed plan
must decide whether an actually available interface can meet the contract or a
different implementation is required; it cannot assume undocumented flags.

### Providers: enabled-tool closure is still missing independently

No prepared release-bound registry, specification or reached tool handler exists
for Codex 0.159.2 or Claude 2.1.285. The number and identities of actually enabled
tools are therefore **unknown**, not an empty or approved list. The following
are route-audit obligations derived from historical surfaces, not a claim that
every named route is enabled in either release. Each provider needs its own
publication/platform/build binding and implementation; Sandbox Runtime source
cannot supply it. The current local Codex installation cannot fill the 0.159.2
gap, and public source absence is not successful model-free proof.

For each exact provider configuration and platform, recover the registry and
dispatch construction, feature/permission gating, dynamic registration, and all
reached handlers. Record each enabled entry, its release/revision/file and
enforcing boundary, or implementation evidence that it is disabled. Include
per-session/tool-list changes, approvals, settings precedence, external tools,
hooks, MCP and plugins. An unmapped enabled entry or unresolved fallback blocks
that provider even if every known shell path is restricted. Disabled routes
must leave complete ordinary inspection and editing available under the proved
profile; disabling all useful file operations cannot pass mediation.

| Codex route                                             | Evidence and required enforcement trace                                                                                                                                                                                                                                                                                            |
| ------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| App Server `command/exec`                               | Historical 0.159.2 schema describes server-sandbox argv execution. Recover the exact dispatch and sandbox/setup implementation, timeout/cancellation, policy/approval resolution and errors. A successful direct RPC can prove this controller command only, not model dispatch.                                                   |
| Host-control `fs/readFile` / `fs/writeFile`             | Historical schemas specify absolute host paths without thread sandbox parameters. Keep these controller RPCs outside payload/model authority; trace authentication/dispatch reachability rather than treating them as model file tools or as an observed escape.                                                                   |
| `thread/shellCommand` and experimental process spawning | Supervisor-prepared moving documentation distinguishes these from sandboxed `command/exec` and describes host-side execution. No version-matched handler was supplied. Resolve the 0.159.2 implementation/feature gates and disable or constrain any reachable route; do not infer release behavior from that current description. |
| Model shell / unified-exec / background execution       | Recover actual registry entries, handlers, session/process reuse and asynchronous continuation. Trace policy at every creation and retry, ownership, permission escalation, cancellation and output collection, including failed native setup and fallback. Controller execution or a standalone sandbox is not this path.         |
| Patch, file inspection/editing and search               | Recover each enabled patch/read/write/search handler and its path resolution, Git/control/credential restrictions and executing identity. Trace in-process filesystem effects as well as subprocess tools. Complete inspection/editing must survive any tool disabling.                                                            |
| Hooks, external tools, MCP/plugins and approvals        | Recover dispatch and configuration precedence, startup and tool-time hooks, arbitrary external process creation, authorization boundaries and every error/fallback branch. Unattended configuration must reject escalation rather than prompt, stall, or reroute outside the policy.                                               |

The prepared moving App Server documentation summary is a retrieval lead, not
release-bound source. The earlier `CommandExecParams` description/property
discrepancy for `permissionProfile` remains unresolved; no new field is invented.
Version-matched App Server schemas alone would still lack model-tool enforcement.
The exact next Codex input is the 0.159.2 manifest and its named platform
artifacts, corresponding release/build/checksum provenance, pinned Cargo
manifests/lockfile, sandbox/setup code, registry/specification, reached handlers
and App Server dispatch. Until supplied, `codex.command-tools`,
`codex.file-tools` and its dependent no-fallback/transport composition remain
BLOCKED independently of Claude or Windows.

| Claude route/control                    | Evidence and required enforcement trace                                                                                                                                                                                                                                                                                                         |
| --------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Bash and alternate command/code tools   | Historical help names tool selectors, not their implementation. Recover enabled registry entries and Bash, PowerShell/alternate-shell, code and background handlers where present, including native sandbox invocation, process reuse, asynchronous continuation and cancellation. Re-enabling a tool is not binding it to an external sandbox. |
| Read / Glob / Grep / Edit / Write       | These are the required inspection/editing audit targets, not a recovered enabled set. Recover handlers for every actual enabled file route and any additional tools; trace host filesystem calls, cwd/path authority, aliases, Git/control and credential exclusions. Subprocess confinement cannot attest an in-process file operation.        |
| Restriction and tool disabling          | Resolve implementation and settings precedence for `--restricted`, `--tools`, allowed/disallowed tools and per-tool permission rules. Help's cwd confinement claim and removal of command tools do not prove native enforcement or that required inspection/editing remains usable.                                                             |
| Unattended permissions                  | Recover `dontAsk` / permission-prompt suppression behavior at each handler, denied-operation error and fallback branch. No prompt, interactive escape, silent retry with wider authority, or permission-mode override is acceptable.                                                                                                            |
| Hooks / MCP / plugins / external tools  | Recover enabled integration construction and every reached dispatcher. Verify disabling from implementation, including inherited/project settings and startup hooks; `--bare` and `--strict-mcp-config` help text do not prove complete closure.                                                                                                |
| Authentication and native/package paths | Bind the actual 2.1.285 publication/platform bytes and enforcement implementation. Keep transport credentials outside tools, inherited payload environment and report output. Native and npm installations do not inherit each other's tool boundary, licensing or Sandbox Runtime support.                                                     |

The exact next Claude input is the actual 2.1.285 publication manifest and
resolved platform artifact/checksum/licensing provenance, then any release-bound
registry/enforcement implementation exposed by that publication. Installer and
setup URLs are inputs to resolve, never scripts to run in a role. If the
required implementation is unavailable, record that specific missing source and
the unresolved tool/permission boundary; do not substitute help, a mock, an
older distribution or another provider. `claude.command-tools`,
`claude.file-tools` and its dependent no-fallback/transport composition remain
BLOCKED independently.

**Model-free model-tool dispatch is not established for either provider.** An
accepted direct test seam would have to be demonstrated in that exact released
implementation, invoking the same real enabled handler, tool context,
permission logic, native policy and ownership as a model-issued call. An App
Server transport response, generated schema, standalone sandbox, mocked handler
or injected local effect does not establish that seam. If no such seam exists,
real protected tool dispatch is indispensable; source closure remains required
before granting that execution authority.

Protected acceptance requires an operator-published immutable trusted candidate,
approved environment and credentials, and the **same candidate SHA** as system
evidence. Ordinary PR jobs receive none of that authority. The current CI entry
point rejects provider tier execution. This research adds no provider integration,
permission mode, model turn, credential request, or production policy change.

### Next proof cases and independent settlement

The following are specifications for a separate reviewed implementation after
source/binding closure, not implemented checks or PASS records. They reuse the
stable inventory above and its Linux reference protocol rather than multiply
equivalent ownership cases across tools. For each proposed case, record actual
image/build/ABI, executable digest, policy, privilege/entitlement and permitted
operation before the prohibited attempt. Do not substitute images or treat
unavailable privileges as a pass.

For both Windows creation hops, a future fault barrier must distinguish
successful suspended assignment from the release of that exact thread. Owner
loss at either pre-release barrier must leave no executed payload and recoverable
settlement evidence. For Job recovery, test loss of the last controlling holder
separately from fresh-verifier handle acquisition, and observe whether retaining
that handle defers kill-on-close. A retained handle is no evidence that members
have exited. Inspect terminal member completion after the intended
holder/termination sequence. Helper stdout, the primary process's exit code,
disappearance of a Job name, or an inaccessible process handle cannot
clear exclusion.

Proposed non-Linux case budgets are 30 seconds for allocation/admission or each
acknowledged fault barrier, 30 seconds for each probe, and a separate 30 seconds
for independent retirement/cleanup. These are proposed bounds, not measured
outcomes or changes to current CI budgets. Explicitly privileged installation
needs its own reviewed bounded setup sequence, not an unbounded UAC wait inside
a payload case. A protected tool turn needs a separately approved transport/turn
deadline and the same bounded ownership settlement. Timeout or emergency cleanup
preserves failure; there are no retries until green.

| Case group / stable checks                                                                                                                                           | Positive controls, barriers and independent observation                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| -------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Native launch, `launch.argv`, `launch.storage`                                                                                                                       | Readiness from a real private executable with the full literal argument corpus, including empty arguments/metacharacters, through a protected trampoline if needed. Persist original native identity and effective policy before release; malformed command text or shell reinterpretation fails.                                                                                                                                                                                                                                                                                                                                          |
| macOS domain, `ownership.*`                                                                                                                                          | Acknowledge admitted parent and detached/reparented children, then fault owner, helper, manager, proxy and trampoline separately. Fresh verifier uses the source-backed native object/identity and observes retirement. Substitute receipts and native objects; live, inaccessible or mismatched identities retain exclusion without signalling unrelated processes.                                                                                                                                                                                                                                                                       |
| Windows two-hop ownership, `ownership.admission`, `ownership.descendants`, `ownership.cancel`, `ownership.owner-loss`, `ownership.helper-loss`, `ownership.receipts` | Admit the protected broker, then acknowledge the suspended runner's admission and protected process/Job handles before resuming that hop. Only the admitted trusted runner may create the restricted child; acknowledge that child's admission before its own resume. Inspect actual restricted token, both memberships, denied child breakaway, nested Jobs and alternate identities. Fault each owner/controlling holder at acknowledged barriers and verify every member's completion independently. The source's unsupported-assignment and DACL-warning branches must be rejected before any payload runs.                            |
| Windows setup/delegation, `audit.release`, `ownership.*`, `ipc.deny`                                                                                                 | Separate owned fixtures and ready controls for elevation, status, WFP probe, CA trust, ACL operations and service/RPC creation. Record account/profile/filter/DACL/registry/trust/storage identities before effects and partial-failure barriers. Verify shared-holder/PID-reuse behavior, surviving holders, proxy exceptions and independently restored sentinels; module reset or best-effort JSON is insufficient.                                                                                                                                                                                                                     |
| Access, network and IPC, `profile.*`, `network.*`, `ipc.deny`, `git.ordinary-denial`                                                                                 | Ready permitted inspection/editing/disposable controls plus externally reachable host endpoints/sockets/services and separate private-loopback control. Acknowledge each actual denied attempt; independently compare original checkout, Git/config/identity, credentials, receipts and outside sentinels. Service-side work must be owned or effectively denied.                                                                                                                                                                                                                                                                          |
| Constrained Git, `git.fixed-commit`                                                                                                                                  | Reuse the fixed synthetic-operation contract with protected executor authority, disabled hooks/configuration helpers, existing synthetic identity and exact subject. Independently compare refs, message, configuration, identity and outside state. Runner one-shot authorization is a workflow prerequisite, not a Job/domain claim.                                                                                                                                                                                                                                                                                                     |
| Provider tools, `codex.*`, `claude.*`, `provider.*`                                                                                                                  | From the recovered enabled registry, invoke every actual inspection/edit/command/background boundary or prove implementation disabling with complete useful operations retained. Ready permitted tools precede denied mutations/host/credential/control attempts. Observe unattended failures and no fallback at acknowledged dispatch barriers; cancellation/helper loss must settle tool workers independently. Check authentication separation without retaining secrets or transcripts. Direct real-handler testing is valid only with the demonstrated model-free seam; otherwise use indispensable operator-protected tool dispatch. |

All seven contracts remain required. No macOS/Windows file helper is admitted
by this research: native held-parent/handle identity, alias rejection,
publication, replacement and interrupted cleanup still need their own reviewed
implementation and real `files.*` proof. Point-in-time Node path checks, wrapper
masking and CA temporary renames do not close any of them.

The concrete decision is to retain the executable independent reporting and
Linux ownership/access/Git proof code already implemented, while rejecting
dependent non-Linux/provider admission on the identified source gaps. macOS
needs a callable build-matched recovered domain and network/IPC composition;
the Windows candidate needs complete release binding plus a fail-closed two-hop
and setup/recovery sequence; each provider needs its own enabled-tool enforcement
closure. These bounded technical findings do not halt independent source
inspection or assert platform impossibility.

This ends the PoC continuation without production integration or a GO claim.
Real system and indispensable protected evidence must cover the final
operator-published immutable candidate. Any repair invalidates dependent proof;
collect fresh evidence for that new SHA. Do not commit successful reports and
then change the tested SHA. Dependent macOS/Windows file helpers,
confinement/admission composition and provider integrations require a separate
reviewed plan once mechanisms and release bindings are known. Local engineering
completion, byte verification and documentation review never attest native
behavior or authorize remote publication/protected execution.

## Validation and external acceptance boundary

Follow the canonical [finalization skill](../../.agents/skills/finalization/SKILL.md)
and [testing policy](../../docs/TESTING.md) for each admitted implementation step.
Formatting, the ordinary fast gate, and `git diff --check HEAD` remain local
finalization requirements. Format first with `npm run format`, then run the
ordinary `npm run check` gate, necessary effect-free harness coverage with
`node --test ci/native/harness.test.js`, and `git diff --check HEAD`. Documentation-only
changes need no wording-only tests or unrelated slow coverage. Selected exact trusted commands remain
Runner-owned: agent turns report `NOT_RUN` with their frozen Runner identities,
and the Runner executes the persisted exact vectors during FINALIZE.
Only the Runner-authorized COMMIT boundary stages, checks staged whitespace,
and creates the exact subject-only local commit using existing identity,
without authorship trailers or remote writes. Native system/protected
acceptance never enters a local FINALIZE inventory.

The implemented local, effect-free protocol tests use
`node --test ci/native/harness.test.js`, outside ordinary discovery. The specialized
CI-only entry point is `node ci/native/run.js --tier system`. The workflow invokes
its explicit `--stage initialize`, Linux-only `prepare-linux`, `setup`, `probe`,
`cleanup`, and `report` stages, and its controller invokes `collect` and
`aggregate`. The default system invocation runs the job stages together,
including Linux-only `prepare-linux`
before setup. Provider dispatch is deliberately
rejected; it requires a separately reviewed implementation after prerequisites
close. Ordinary test discovery must not
start native helpers, restricted payloads, or provider turns, including through
new source imports. CI-only packages must be injected at composition, with no
production import dependency or startup effect.

The implemented [native workflow](../../.github/workflows/native-poc.yml) targets
PRs to **both `main` and `dev`**, plus explicit dispatch. Pin the
candidate releases and checkout SHA, an exact Node.js 24 release, actions,
images, and adopted helpers; record actual checkout, OS/build/architecture,
versions/digests, effective
policy, contract/check/profile, phase, expected/observed behavior, elapsed time,
deadline/failure reason, and cleanup outcome. Run all OS jobs without matrix
fail-fast. Use read-only permissions, no persisted checkout credentials,
no provider secrets/models in PR jobs, and no `pull_request_target`.

Named setup/probe/cleanup stages, actionable annotations, per-OS and aggregate
summaries, and accessible bounded sanitized artifacts must survive setup,
probe, or cleanup failure. Never retain environments, credentials, raw provider
responses, session data, or unrelated project context. Missing, skipped,
cancelled, inconsistent, incomplete, or unretired evidence fails acceptance;
reporting success does not mean proof success. Do not use `continue-on-error`
or retries until green. Partial CI evidence cannot yield GO.

### Implemented reporting workflow

The candidate job resolves the PR head (or dispatch revision) once and verifies
its checkout. Every matrix and aggregate job checks out that exact SHA. The
matrix declares `ubuntu-24.04`, `macos-15-intel`, and `windows-2025`, with x64
Node and fail-fast disabled. Setup independently reads HEAD, kernel/build
information, Ubuntu release or macOS product/build version where applicable,
hosted image identifiers, actual architecture, and the Node executable digest.
Missing image identifiers, incompatible OS/version/architecture, or substitutions
remain BLOCKED. The hosted labels' real availability and behavior require CI;
local code review cannot attest them.

The pure `isWindows2025Image` predicate in `dispatch.js`, exported through the
native index and consumed by CI image inspection, recognizes exactly the hosted
`ImageOS` values `win25` and the reviewed `win25-vs2026` as `windows-2025`.
Both require the observed Windows build `10.0.26100`, optionally followed by
one numeric revision, and an `ImageVersion` of 1–128 ASCII letters, digits,
dots, underscores or hyphens. Other images and arbitrary suffixes are rejected.
The observed build and image version remain recorded unchanged. Recognition
does not waive exact candidate/checkout, x64, Node 24.21.0 version/digest or
independent job/artifact provenance checks, and supplies no native proof.
Effect-free injected regressions establish this recognition/reporting contract;
all Windows native cases and protected provider evidence remain unproved.

Reporting is initialized using the image's preinstalled Node before pinned Node
setup. Historical CI-private version-4 `native-job.json` envelopes record CI
stages separately from native check phases and admit only the implemented Linux check records,
with nullable `linuxPrerequisites` diagnostic evidence and closed
`unrecordedAdmission: "not-started" | "possible"`. Initialization knows that no
native controller has started. Before invoking Linux proofs, the producer
atomically persists `possible`; interruption without a receipt or result then
retains settlement obligations for the implemented Linux cases. Completed proof
output explicitly records cases never admitted, including prerequisite-blocked
and later unreached cases. macOS/Windows placeholders are producer-known
unimplemented dispatch routes, not inferred from their labels. A conflicting
possible-admission marker on a non-Linux job remains uncertain; a recorded Linux
attempt also prevents `not-started` from hiding absent implemented-case records.
Version-1 reporting inputs remain readable with no native results; version-2
inputs retain their implemented records without a prerequisite diagnosis;
version-3 inputs retain diagnostics without the new job admission marker.
Legacy native evidence and missing admission evidence stay conservative;
historical reporting cleanup remains readable under its original validation
without supplying native retirement. New reporting cleanup and job validation
reject possibly attempted or interrupted cases lacking independent retirement
or successful case cleanup. Fresh cleanup PASS recording uses that same evaluator
for every job version; completed legacy cleanup is read as reporting history.
An independently selected artifact from a failed producing job retains the
failed-job gate and stage guidance, without inventing an artifact-selection
defect. Stage findings cannot suppress actual missing artifacts. Native
records must match the containing job's exact revision, platform, image,
provenance, and observed runtime; duplicate or unauthorized IDs are rejected.
Linux preparation has a 150-second internal budget and a three-minute workflow
step. Setup has a 120-second internal budget and reporting cleanup has 30 seconds.
Linux probe/step/job bounds are derived below; other platforms retain the
450-second probe, eight-minute step and twenty-minute job. CI runs the single effect-free
test file in the awaited child with `--test-isolation=none`, preventing a file
worker from outliving deadline termination. Captured output is bounded and
discarded rather than published. This CI process choice does not change the
exact local finalization command or ordinary test discovery.
Linux probes then execute the reference cases described below. Each case owns
its bounded retirement and cleanup; a later reporting cleanup cannot attest an
interrupted probe. Unimplemented system checks retain exclusion and NOT_RUN
native phases; provider records remain absent. CI stage
outcomes have a separate `ciStatus` and stage records, including failures even
when no native case ran. Per-OS job success means its CI stages succeeded;
missing Linux prerequisites still leave dependent native records BLOCKED. The aggregate acceptance command exits unsuccessfully
while source, system, or indispensable provider evidence remains incomplete,
or the independent CI status is not PASS. The metadata token stays in the
controller and is removed from subprocess environments.

Dispatch composes all 23 Linux system checks; file and release checks require
separately supplied reviewed build/release inputs and stay BLOCKED without them.
All 23 macOS and 23 Windows system cases remain explicitly BLOCKED. Their
guidance retains the audit's build-matched recovered macOS domain,
fail-closed suspended Windows two-hop admission and setup/holder-loss recovery,
native held-parent/handle file-helper proof, and exact release/build bindings.
Image recognition, diagnostic/report repairs and local effect-free regressions
close none of the four source findings and
supply no protected provider acceptance. All seven contracts remain required;
fresh native evidence belongs to external operator-controlled CI on the final
immutable candidate.

### Version-5 file and release evidence

The CI-private producer initializes version 5 through the explicit
`initializeNativeJob(context, { schemaVersion: 5 })` option and composes the
complete Linux suite. Versions 1–4 keep their original admitted IDs,
missing-effect assumptions and historical cleanup semantics. The aggregate
inventory remains 23 system and six provider checks per declared platform.

Version 5 admits the six existing `files.*` IDs and `audit.release` alongside
ownership/access results. The catalog owns their actual groups and policies:
`linux-file-authority-v1` for files and `linux-release-audit-v1` for release,
separate from existing ownership/access policies. File/release profile names
are fixed, and their policies compare within actual groups rather than
caller-selected labels. Every record still binds the exact candidate, checkout,
observed runtime, job provenance and containing component versions. Conflicting
component versions or group policy digests remain inconsistency findings.

The closed `admissions` ledger has exactly five effect keys: `ownership`,
`access`, `file-build`, `file-helper` and `release-probe`. Each contains
`admission: "not-started" | "possible"` and the ordinary independent-retirement
settlement shape. `recordNativeAdmission(job, effectId)` must be atomically
persisted before that effect. Compiler admission is distinct from helper
admission; build effects alone create no phantom file-case attempts. Independent
non-emergency compiler retirement precedes helper admission. Missing records
after possible helper/probe admission remain conservative within that group;
explicitly unreached groups stay not-started. Non-Linux jobs cannot admit these
Linux effects.

`recordNativeSettlement` records independently supplied effect retirement;
reporting cleanup never creates it. Unverifiable or emergency settlement cannot
be overwritten through this API. Version-5 cleanup requires non-emergency
independent retirement of every possible effect and all possibly attempted
cases, plus successful case cleanup. Case failures remain failed even when
retirement and later reporting cleanup succeed. Incremental
`recordNativeResults` appends distinct check IDs, preserving completed earlier
groups after a later failure; it cannot replace an earlier failure or record.

`recordNativeSupportingEvidence` appends at most 32 closed references containing
`checkId`, `kind`, a 1–128-character alphanumeric/dot/underscore/hyphen `id`,
starting with an alphanumeric character, and a SHA-256. File kinds are `build`,
`receipt`, `operation`, `interruption` and `recovery`; release uses `release`,
and ownership/access allow `receipt`.
References require matching effect admission. Duplicate keys, conflicting
digests for one group/kind/identity, paths, unknown fields and oversized lists
are rejected. File PASS requires a receipt reference; release PASS requires a
release reference. References retain no raw output, environments or credentials
and supply neither native observations nor release/source closure on their own.

Per-job reports and independently bound artifact joins retain these candidate/job
ledgers and references as `nativeEffects`. The join still requires exact
revision, producing-job identity and phase consistency, including failed-job
conclusions and upload receipts. Local injected regressions establish only this
contract. Real file cases and release observations remain external-CI work;
all four source findings remain unresolved.

### Complete Linux system composition and release audit

The indexed `linux/system.js` owner composes ownership, access, the pinned
compiler build, all six file cases, and `audit.release` through
`node ci/native/run.js --tier system`. It persists each group's possible
admission before its effects and its terminal results/settlement before the
next group. An interrupted producer retains its admission and immutable case
evidence, including interrupted or denied operations. Incomplete check/session
inventories cannot pass. A failed prerequisite leaves dependent checks BLOCKED
with NOT_RUN phases; completed earlier groups survive later failure. Reporting
cleanup only evaluates retained evidence. Fixed `native-linux <group/check> <phase>`
diagnostics contain no child output, environments or credentials.

`NATIVE_REVIEWED_INPUT_DIRECTORY` optionally names an explicitly supplied,
canonical CI-private directory owned by the controller with mode 0700. The
single-link regular `linux-file-build.json` and `linux-release.json` inputs
must be owned by that identity, mode 0400, and at most one MiB each. No input
is downloaded, inferred from the host, or generated from observations. The
ordinary credential-free/model-free PR workflow supplies no reviewed inputs;
its dependent checks remain BLOCKED. Supplying reviewed inputs is separate
operator work in the approved CI environment, not a provider authorization or
an installation/publishing route.

The build input is the existing closed candidate/source/GCC/input-pin contract.
Two bounded compiler commands run through the protected ownership launcher in
a separate controller, with immutable literal-argv admission receipts written
before execution. Compiler code sees only its pinned snapshots and private
output/scratch. The controller exits before fresh verifiers establish retirement
of both admitted namespaces and controlling processes. Timeout, emergency,
missing receipt or unverifiable settlement cannot admit file helpers. The
candidate-bound build record is retained by digest before file-helper admission
and uploaded as bounded `linux/evidence/helper-build.json`.
Each file result retains a bounded digest of its complete session bundle;
original failure, denial, interruption and recovery records stay intact.

The version-1 release input contains `candidateSha`, `buildPinsSha256`,
`components`, and `unresolvedAssumptions`, besides `schemaVersion`. The build
pin digest is SHA-256 of the normalized build JSON, without a newline. Each
component has `name`, `version`, `sha256` and separate `publication`, `source`,
`build`, and `license` bindings; each binding contains a bounded neutral `id`
and SHA-256. The closed inventory (at most 600 components) must exactly match
the components used: Node, bubblewrap, Git, compiler, static helper, every
copied build input, and Node/Git ABI libraries. Build-input and ABI identities
use `build-input-` or `abi-` followed by the first 32 hexadecimal characters of
SHA-256 of the native target path. Unversioned inputs use `unversioned`; the
helper uses version `1`. Main executable versions come from the earlier
setup/access/build observations, not caller claims.

`linux/release.js` separately records reviewed bindings and read-only observed
versions/digests, static ELF/syscall ABI, executable ownership/modes, observer privileges and effective
policy digests. It rechecks actually used immutable binaries, snapshots and
libraries, and the system owner freshly verifies every protected session and
build receipt against its admission-bound digest and identity. Its bounded `release.json` supports the candidate/job audit
record. Both input and observation retain all four fixed source assumptions.
Runtime rereads are bounded to 256 MiB for Node, 64 MiB per other host executable
or ABI file, and four MiB for the helper. Compiler snapshots retain their
separate 64-MiB aggregate build-input budget and 64-KiB source bound.
A matching audit establishes only supplied release binding consistency:
observations cannot create pins, verify licensing independently, or close
`A-MAC-OWNERSHIP`, `A-WIN-ADMISSION`, `A-PROVIDER-MEDIATION`, or
`A-RELEASE-CLOSURE`.

`LINUX_SYSTEM_BOUNDS` charges 30 seconds for the effect-free harness,
345 for ownership (120 preparation plus five 45-second sessions), 300 for
access (four 30-second setups plus four 45-second sessions), 70 for the two
20-second compiler commands plus independent settlement/verifier and storage
allowances, 1,060 for the frozen 21-helper file inventory, and 220 for release
reads plus 32 five-second fresh verifiers. The total internal probe bound is
2,025 seconds. The workflow rounds up and reserves one minute: a 35-minute
probe step. The 53-minute Linux job adds 18 minutes for checkout, initialization,
runtime/preparation/setup, cleanup, always-run reporting, two-minute artifact
upload and independent upload binding. Ordinary production deadlines and
session bounds are unchanged. Upload receipts and same-revision aggregation
remain strict; no local harness result grants platform GO or provider support.

### Protected Linux package preparation

After reporting initialization and pinned Node setup, `prepare-linux` invokes
`linux/preparation.js` through the Linux index. Preparation requires the actual
Ubuntu 24.04 x64 image and a matching checkout before installation. A private
APT source names only the official HTTPS Ubuntu archive's `noble` main/universe
components and the protected system Ubuntu archive keyring. `APT_CONFIG` loads
a private bootstrap configuration before any image-wide configuration,
suppressing its hooks; installation explicitly preserves that configuration
through sudo.
Separate lists and disabled shared binary caches and preferences prevent other
repositories or image package pins from selecting the package. APT must
authenticate the release and package indexes; insecure repositories,
unauthenticated packages and retries are disabled. No target repository, global
APT source or host security policy is edited.

The signed metadata resolves one exact amd64 bubblewrap version, archive member,
size and SHA-256 before installation. A simulated transaction must contain only
bubblewrap, without removal or additional dependency changes. Acquisition runs
without sudo into private storage; regular-file/single-link identity, bounded
size and SHA-256 are checked before the fixed version is installed with downloads
disabled. Only installation uses noninteractive sudo. Existing configuration is
preserved on package conflicts. Each command uses a protected timeout executable
with a process-group deadline and five-second termination escalation, inside the
overall preparation budget; expiry or interruption cannot publish success.

The version-1 `linux-preparation.json` starts NOT_RUN and atomically records
RUNNING before metadata, acquisition, installation and verification effects.
PASS requires the exact installed package version, canonical protected
`/usr/bin/bwrap`, its reported version and executable SHA-256. Failed preparation
retains FAIL and its reached phase; interruption retains NOT_RUN/RUNNING or an
absent receipt. Setup requires both the matching complete receipt and a successful
workflow preparation outcome. Otherwise setup fails and dependent probes remain
NOT_RUN. Always-run reports and bounded uploads retain stage failures and the
receipt; acquisition files and raw package output are not uploaded.

The verified version/digest enter job component evidence. `prepareLinuxFixture`
binds subsequent launcher bytes/version to that evidence and still exercises the
unchanged ordinary and nested namespace probes, rejecting host-session fallback.
Installation and these prerequisite checks supply no native acceptance, source
closure or provider evidence. All retained source findings and fixed cases remain
mandatory. Local injected coverage verifies ordering, failures and receipt gates;
actual provisioning and namespace observations require fresh dedicated external CI.

### Confined Linux file helper and build foundation

`linux/index.js` exposes `buildLinuxFileHelper`, `normalizeLinuxFileBuildPins`
and `verifyLinuxFileElf`. Imports do not compile or launch anything. The
source-owned `file-helper.c` accepts only fixed allocation, publication,
replacement, inspection, recovery, cleanup and finish commands, with fixed
names, at most 32 operations and 4 KiB contents. An explicit 25-second alarm
handler exits without cleanup, including when the helper is namespace PID 1.

The helper holds anchor, allocation and leaf descriptors and compares them
with the current named objects before mutation. `openat2` confines traversal
beneath its parent, rejecting symlinks, magic links and mount crossings;
`statx` checks device/inode, mount and birth identity, private modes/ownership
and single-link regular files. An anchor lock excludes concurrent helpers.
The admitting owner must keep all parent mutation authority, descriptors,
procfs and command channels outside payload grants and serialize permitted
mutations. Identity-check-then-removal relies on that sole parent authority.

Exclusive publication uses complete synchronized `.pending` bytes and
`renameat2(RENAME_NOREPLACE)`. Replacement uses a checked old leaf and atomic
rename, with parked `prepared` and `published` barriers before the remaining
directory synchronization. These primitives preserve complete old or new named
bytes across process interruption; universal power-loss durability is not
claimed. Recovery compares recorded device/inode/birth identity while confining
objects to the fresh anchor mount. Unknown or substituted objects cannot be
adopted or recursively removed. Cleanup verifies identities and synchronizes
removal; failure or timeout retains uncertain storage.

`file-build.js` compiles only in Ubuntu 24.04 x64 system CI. A separately
reviewed candidate-bound declaration supplies the helper source SHA-256,
exact GCC 13 version and every canonical protected compiler/tool/header/library
input with its SHA-256. Observed hashes cannot create pins. The source is
bounded to 64 KiB and the input inventory to 512 files and 64 MiB. Verified
inputs are copied into private read-only snapshots before the fixed compiler
invocation. Only those snapshots, source, private output and scratch are
exposed; incomplete inputs cannot fall back to the host toolchain or root.
Version inspection and compilation each have a 20-second bound. The build
record retains candidate/source binding, compiler identity, exact arguments,
input vector, helper digest and static x86-64 ELF closure. Dynamic dependencies,
an executable stack and writable executable load segments are rejected. The
compiler's own loader/libraries also require explicit pins.

This foundation alone is not a `files.*` result. The six file cases below
add independent observations under the complete system composition. Historical
job inventories remain unchanged.
Local coverage is effect-free pin/ELF and protocol validation; native compilation
and system/provider acceptance remain external. Build observations supply no publication or
licensing binding and close none of the four retained source findings.

### Linux file transaction protocol

The Linux index exposes `encodeLinuxFileRequest`, `normalizeLinuxFileMessage`,
`runLinuxFileTransaction` and `retireLinuxFileStorage` through the CI-private
`files-protocol.js` owner. These functions have no filesystem or process effects
of their own; transactions use explicitly supplied send, receive, barrier,
verification and cleanup callbacks. The protected session owner below supplies
the explicit CI effects.

Requests have only fixed commands, allocation/leaf/temporary identities and
at most 4 KiB of hex-encoded contents. Closed data-property shapes reject paths,
argv, modes, unknown fields and malformed bytes or native identities before
commands. Replies require the expected nonce, anchor and mount identities,
phase-specific fields and checked old/new leaves. Requests, replies and
continuation acknowledgements are immutable snapshots; the expected authority
bindings stay fixed across asynchronous callbacks.
Allocation and recovery require an empty held-object state before any command;
they cannot replace the caller's existing allocation or leaf authority.

Publication and replacement park at validated `prepared` and `published`
barriers. Each barrier callback must succeed before its fixed continuation is
sent, and completion must identify the prepared temporary as the new leaf.
A later publication can acknowledge only the already known winner; it cannot
replace that winner with another successful publication. Recovery compares
recorded device/inode/birth identities while requiring every returned object
to belong to the fresh anchor mount. Malformed, substituted, redirected or
interrupted evidence fails the operation and retains exclusion.

Operation success and native removal never prove independent retirement or
release storage. The admitting owner must supply a fresh independent verifier;
only non-emergency retirement of a successful operation followed by successful
cleanup releases exclusion. Failed operations, uncertain verification and
cleanup failures remain failed and retain storage/exclusion, including after
a later retirement or cleanup attempt. Local regressions inject every effect
and establish protocol behavior only; native proofs and acceptance remain
external.

### Protected Linux file sessions

`runLinuxFileSession` admits the pinned static helper only in Ubuntu 24.04 x64
system CI, through the existing protected launcher and registration barrier.
Independent process identities, namespace membership, executable bytes and
mount sources are checked before file commands. The helper has only its
read-only executable and writable anchor: no payload, procfs, host checkout or
inherited parent descriptors. Ordinary fixtures still require private procfs.
Helper receipts reuse the existing fresh retirement verifier without extending
the ownership case inventory or activating system-suite dispatch.

The session holds anchor and fixture-parent descriptors and compares their
current host names, identities, private ownership and modes before commands.
The helper retains allocation/leaf descriptors and its exclusive anchor lock.
Only the trusted owner serializes identity-sensitive operations and acknowledged
barrier controls; payloads receive neither the parent authority nor its command
channel. Cleanup preserves substituted objects and uncertain storage.

An immutable possible-admission record precedes controller creation. Readiness,
command intents, successful operation acknowledgements, prepared/published
barriers and declared interruptions are written exclusively as private evidence
before dependent commands or signals. The original record remains alongside a
separate terminal result. Timeouts, malformed evidence and uncertain settlement
remain failures; a declared interruption cannot clear an actual emergency.
The admission/probe deadline is one non-resetting 30-second budget. Owner
settlement and fresh verification each have a separate five-second bound.
Failed or late owner settlement remains emergency evidence even after a
declared interruption.

`linuxFileSessionPolicy` supplies the comparable helper policy; its digest stays
stable across session-specific anchor names. The protected
receipt separately binds the stable policy digest and anchor name through
`sessionPolicyDigest`, alongside its candidate, nonce and executable binding.
Recovery also reads the old protected possible-admission, readiness and named
operation/barrier records. `normalizeLinuxFileRecovery` rejects caller-supplied
identities that differ from those records, redirected record names and changed
policies. Fresh independent non-emergency retirement precedes a recovery helper;
the helper then checks recorded anchor/allocation/leaf/temporary identities in
its fresh confined mount. Unknown objects cannot be adopted or recursively
removed. Recovery links to the original session and cannot erase its immutable
failure or interruption evidence.

These sessions alone supply no native file-check result or acceptance claim.
Local mount, receipt, policy and recovery regressions inject effects or validate
synthetic records. Actual admission, process interruption and file observations
remain external CI work; the complete version-5 suite awaits real CI observations. The diagnostic
prerequisite, fixed three-platform/provider inventories and all four source
findings remain intact.

### Linux file cases

The CI-private Linux index exposes `runLinuxFileCase` for injected orchestration,
`assertLinuxFileObservation` for strict observation binding, and the explicit
system-CI effect owner `runLinuxFileProofs`. Its fixed six-ID inventory uses
version-5 job inputs. `LINUX_FILE_SUBCASES` owns the complete required subcases;
missing subcases or sessions cannot yield success. `linuxFileProofPolicy` binds
the default and closed case-specific effective session policies as one group.
Imports neither compile nor launch anything. Only the complete indexed system
composition dispatches the suite; no partial suite grants acceptance.

Host observers open only fixed anchor/allocation/value/temporary names without
following symlinks, compare held and current objects around reads, and retain no
parent descriptors in payloads. Device/inode/birth identities, private owner,
0700 directory and 0600 single-link file modes, complete binary bytes and absent
temporary names are checked independently of helper replies. Namespace mount
identity remains the protected session owner's responsibility. These observations
do not broaden helper grants or change ordinary fixture procfs requirements.

`files.private` observes an allocation and published private file under retained
sole parent authority. `files.publish` submits three distinct requests together
through that serialized authority for one logical target. Exactly one complete
publication wins; every loser identifies the same winner, and independent barrier
and final observations require its unchanged identity and complete winner bytes.

`files.replace` uses two distinct fault sessions, at acknowledged `prepared` and
`published` barriers. The owned live controller handle applies the interruption;
its observed SIGKILL settlement and recorded phase must agree. Independent reads
after fresh retirement require the complete old leaf plus recorded temporary at
the prepared barrier, or the complete new leaf and absent temporary at published.
Each interrupted session remains immutable FAIL with retained storage/exclusion.
A separate recovery session binds its protected receipt/readiness/barrier records,
rechecks identities in the fresh mount, removes only recorded objects and retires
independently. The proof passes only for its declared, independently observed fault
with non-emergency retirement and successful identity-bound recovery/cleanup.
Unexpected failure, missing fault evidence, emergency cleanup or uncertainty fails.
These are process-interruption/synchronization guarantees, not universal power-loss
durability.

`files.substitution` replaces an allocation ancestor and a leaf only at an
acknowledged prepared barrier. The fault owner holds the originals separately
and introduces its own private sentinel objects. `files.aliases` rejects a
symlink leaf, a direct private-procfs magic link, a read-only mount crossing and
a hard-link alias. Each has a permitted control and independent identity/byte
observations. The magic-link control opens the same held private leaf through
private procfs before its confined open rejects it. The mount control opens
the same separately bound private sentinel before `RESOLVE_NO_XDEV` rejects
the crossing. Neither setup failure nor inaccessible controls establish denial.

`files.cleanup` first proves identity-matched synchronized removal, then replaces
the leaf at an acknowledged `removing` barrier. The helper rechecks the current
named identity before unlinking; the substitute must survive. A fixed `denied`
reply binds the reached operation, native identities, guard reason and permitted
control. The protected controller must observe its exact normal exit 39 without
a signal; a generic nonzero exit, crash, alarm or timeout cannot pass. Denied
operations remain immutable FAIL with retained storage/exclusion even when the
expected-denial proof succeeds.

Controls have no caller-supplied paths, argv, mounts or descriptors. Default helper
authority and ordinary fixture procfs requirements stay unchanged. Only the
closed magic-link policy adds private procfs; only the closed mount policy adds
one read-only private sentinel mount. Both are protected-receipt-bound and
independently inspected before commands. Fault mutation is serialized with the
parked helper, outside payload grants and helper mutation authority. Intent and
applied control records precede continuation. Independent observations must
match the recorded originals, substitutes and sentinel bytes after fresh
non-emergency retirement. The separate control owner removes only its recorded
objects, restores held originals, synchronizes affected parents and persists
restoration before a separately admitted recovery helper. Unknown or changed
objects and partial control cleanup retain exclusion; no recursive removal or
adoption is permitted. Protected rejection/restoration records bind recovery.

Case admission records precede each helper or recovery effect. Protected session
and case records retain earlier failures before another effect. Host observations
are immutable before barrier acknowledgement, interruption or dependent cleanup;
incomplete evidence cannot manufacture retirement. Unstarted admission failures
retain setup failure without claiming a process effect.

| ID                   | Required subcases                              | Maximum helper sessions |  Case bound |
| -------------------- | ---------------------------------------------- | ----------------------: | ----------: |
| `files.private`      | private allocation/file                        |                       1 |  45 seconds |
| `files.publish`      | concurrent exclusive publication               |                       1 |  45 seconds |
| `files.replace`      | prepared, published interruption               |                       4 | 190 seconds |
| `files.substitution` | ancestor, leaf                                 |                       4 | 210 seconds |
| `files.aliases`      | symlink, magic link, mount crossing, hard link |                       8 | 420 seconds |
| `files.cleanup`      | matching removal, substituted leaf             |                       3 | 150 seconds |

Each session retains its non-resetting 30-second admission/probe, five-second
owner and five-second verifier bounds. A fresh case verifier has five seconds;
each recovery additionally verifies the prior session for five seconds. Each
denial also has a fresh five-second control verifier and a separate five-second
identity-bound control cleanup budget. `linuxFileCaseBound` derives the fixed
envelopes from this inventory (21 sessions, 1,060 seconds across all cases).
Existing ownership-loss proofs continue to own process-authority loss coverage.
Later dependent cases remain
not-started after failure. No fixture removal or later case can precede fresh
independent retirement. Local harness coverage supplies injected contract evidence
only; real cases, compilation and all external acceptance remain external CI.

### Linux owned-process reference proof

`linux/index.js` exposes the pure receipt/retirement, bounded message queue and injected case protocol,
plus `runLinuxOwnershipProofs`, whose effects require Linux GitHub system CI.
`confinement.js` exposes injected fixture preparation, the pure native
`linux-prerequisites.js` owner validates its diagnostic envelope, `controller.js` owns live launches and
fresh verifier processes, `inspect.js` inspects native identities/mounts,
`proof.js` coordinates barriers and evidence, and the fixed `payload.cjs` and
`fault.cjs` run only in those CI cases. Imports do not execute these entry points.
No native process, procfs read, allocation, or kernel case runs in local harness
tests or ordinary discovery.

The proof reuses `resolveOwnedProcessLauncher`,
`assertOwnedProcessLauncherProtected`, `spawnOwnedProcess`,
`terminateOwnedProcess`, and `readProcessIdentity` through `src/agents/index.js`.
It preserves the existing supervisor and registration barrier in
`src/agents/owned-process.js`. A protected canonical bubblewrap executable and
an actual new PID namespace are prerequisites. The public launcher capability
probe also checks nested user/PID/network creation; it admits no provider.
A host-session fallback is rejected. Full procfs retirement visibility is also
checked before any payload is admitted. Missing prerequisites produce a bounded
version-1 `linux-missing-inputs.json` with the containing candidate/checkout,
platform, declared/observed image and build, runtime digests and job provenance,
plus a closed `diagnosis`. The same evidence survives normalized job reporting
and independently bound artifact joining. It cannot attest a case: all sixteen
dependent implemented records remain `BLOCKED/missing-input`, with NOT_RUN
native phases, no policy or case observations, and no retirement claim.

The diagnostic chain is ordered: `bubblewrap-discovery`, `bubblewrap-identity`,
`bubblewrap-protection`, `ordinary-namespace`, `procfs-retirement`,
`nested-namespaces`, `private-fixture-storage`, `protected-executable-abi`,
and `bubblewrap-version`. Discovery examines only the public launcher's four
fixed system candidates, not PATH. Canonical regular-file/single-link identity,
executability and public protection checks precede the unchanged public namespace
probes; alternative missing candidates do not hide a reached identity or
protection failure. CI observes the public probe callback with a fresh cache,
without copying its arguments or changing production policy. An ordinary probe
exit of 1 is distinct from a returned non-isolated/host-session fallback, which
the fixture rejects; nested capability is separately reached after procfs.

Only reached checks can be PASS. The first unavailable check is BLOCKED, and
every dependent check is NOT_RUN with empty observation fields. Closed diagnoses
distinguish absence, invalid identity, non-executability, unavailable protection,
probe failure, rejected fallback, copied-runtime mismatch and invalid version.
Other failures stay `unverifiable` at their observed stage. Evidence retains
only allowlisted errno/signal values, integer process exits from 0–255, and
explicitly observed timeouts; a killed process alone does not establish timeout.
Process facts come from probe results or command rejection boundaries, never
arbitrary fixture exception properties.
Raw output, paths, environments, exception details and host-policy explanations
never enter the diagnosis. Procfs, private-storage, ABI and version requirements
remain mandatory; later prerequisites need not succeed to diagnose an earlier
failure. Prerequisite probes supply no system-case or provider acceptance.

Fresh operator-controlled external CI on the immutable candidate must identify
the first failed prerequisite, distinguishing discovery/identity/protection from
ordinary and nested namespace outcomes. The retained opaque launcher error does
not establish an AppArmor, privilege or namespace-policy cause. The CI-only package
preparation above resolves installation explicitly; namespace/protection changes,
host-session substitutions and unreviewed bytes remain excluded.

Before payload execution, an inner bubblewrap domain supplies fresh PID, user,
network, IPC, mount, and UTS namespaces with dropped capabilities and a cleared
environment. Its root is private tmpfs. The only host file grants are the copied
private Node executable, fixed read-only payload, protected ELF loader/libraries,
and this case's owned output directory. Standard private devices and private
procfs supply runtime necessities. Protected `ldd` resolves the declared Node
runtime's existing ABI closure in CI; no candidate package or downloaded build
script is installed or executed. The policy records executable/input/library
digests. Independent mount inspection checks the observed grants, read-only
input mounts, private root, and output identity. The checkout, receipts, control
files, and fault executor are outside payload grants. A second PID namespace
also prevents payload procfs from exposing the outer supervisor's host
filesystem authority. These are fixture ownership prerequisites; complete
access-profile cases are described below.

The trusted controller persists a protected, bounded receipt containing the
candidate, case, nonce, policy and executable digests, namespace-init, launcher
and controller boot/start identities, PID namespace and nested PID-1 membership,
launch cutoff, complete ancestry baseline, and control-group hash. The independent
parent verifies those bytes, their digest, and live native identities before
acknowledging admission. Only then may the public registration callback return
and release the confined payload. Readiness and acknowledged reparent/fault
barriers replace timing-based fault ordering. The registration callback alone
consumes admission acknowledgements; a failed or expired channel rejects
buffered messages. Admission and probe share one
30-second controller deadline; phase records also enforce 30-second bounds.
The injected protocol checks the shared deadline before release and faults;
owner-loss settlement cannot treat deadline termination as a successful fault.
Fresh verification has a five-second child deadline, including at most three
seconds of retirement observation.

The literal corpus includes an empty argument, whitespace, Unicode, quotes,
wildcard, semicolon and command-substitution text. The payload reports exact argv and
writes a permitted nonce. A worker launches a detached leaf and exits only
after its ready message; independent procfs inspection proves its session,
stable identity, namespace membership, and reparenting to the inner PID 1.
Fault cases exercise indexed live cancellation, loss of the trusted owner,
loss of the actual supervisor via an acknowledged CI-only self-exit preload,
and loss of the launcher via its live child handle. Production supervisor code
and registry behavior are unchanged. Fault controllers use indexed termination,
live child handles, or self-exit, never independent numeric-PID signals or
unvalidated process groups.
Cancellation rejects an already-settled handle and requires the observed
completion to carry the requested SIGKILL. Protected observation JSON retains
the inspected root, worker and leaf identities and reparenting alongside the
policy digest and exact argv.

Fresh verifier processes read the original persisted namespace-init receipt;
they never signal. The inspected repository recovery API cannot reconcile a
dead owner from another PID namespace. Its indexed identity reader also maps
both absence and denied reads to null. Consequently null is insufficient:
this proof requires two explicit proc-directory ENOENT/ESRCH observations for
the namespace init and both controlling helpers,
matching self/PID-1 procfs views before and after, a full procfs mount without PID
hiding or per-PID substitutions, the same boot and observer namespace, and
unchanged protected receipt bytes. Live, replaced, mismatched, inaccessible,
or substituted identities retain exclusion. The inspected Linux
`pid_namespaces(7)` contract states that namespace-init termination kills all
members, including the owned nested descendants; this is the retirement
contract under test. Zombies are not absence. CI negative controls exercise
live, substituted, mismatched and unverifiable receipts; a failed control
prevents a successful case or further release when retirement is uncertain.

Only independent retirement permits output cleanup or the next case. Emergency
termination preserves FAIL even when a fresh verifier subsequently observes
retirement; cleanup errors remain failed even after independent retirement.
Uncertain output and protected evidence remain retained. Uploads
include bounded policy, admission, negative-control and case-result JSON from
`linux/evidence/`, never raw process output or environments. Missing later
cases cannot become successful records.

The ownership suite reports only `launch.argv`, `launch.storage`,
`ownership.admission`, `ownership.descendants`, `ownership.cancel`,
`ownership.owner-loss`, `ownership.helper-loss` (both supervisor and launcher
cases), and `ownership.receipts`. Local injected protocol tests cover admission
order, the shared deadline, fault acknowledgement, terminal channel failures, retained exclusion,
cleanup failures, and same-revision joining.
These ownership cases confer no access-profile or provider evidence. They have not
been run locally; actual observations require system CI on the final published
candidate. Implementation or local protocol coverage cannot establish GO or
native support.

### Linux access profiles and fixed Git executor

After successful ownership cases, `linux/access.js` prepares separate owned
synthetic repositories for `read-only`, `workspace-write`, `trusted-command`
and `commit`. A failed or uncertain ownership result blocks this dependent
suite. `profiles.js` owns pure grants, denial completeness, fixed request and
commit-effect predicates; `access-payload.cjs` supplies fixed ordinary probes,
and `fixed-executor.cjs` accepts only `commit` and the exact fixture subject
`test(fixture): record owned edit`. These are explicit system-CI effects,
never ordinary discovery or local finalization cases.

The fixture follows the inspected invocation contracts in
`src/agents/claude/native-sandbox.js` (read-only content with separately protected
Git metadata; workspace writes retain metadata protection) and
`src/trusted-validation/execution.js` (an owned writable source projection with
read-only runtime exposures). It imports neither implementation. Fixture
construction does not modify, replace or attest production/provider policy.
The protected system Git executable is copied into private executable storage;
its version, digest and protected ELF closure are recorded without installation.
Git and Node receive only the required ABI files. The private tmpfs root and
independently inspected mount list expose no original checkout or host home.

Ordinary profiles mount synthetic metadata and the Git pointer read-only.
Read-only content permits Git log, status and object inspection plus content
reads; its content mutation must fail. Workspace and trusted-command profiles
permit the fixed content edit. The latter receives its own disposable copy,
with the original checkout hidden; its edit never reaches that checkout.
All three attempt real staging and commit commands and direct writes to index,
refs, configuration and the Git pointer. They also attempt outside/control and
receipt writes, and reads of a synthetic credential, original checkout and
receipt. Valid Git inspection and an existing identity precede these attempts.
Only effective permission/authority errors count as denials: missing Git, invalid
arguments, crashes, signals and deadlines fail the case. Protected metadata,
inputs, credentials and outside sentinels are independently compared before and
after. Every required attempt must be present once with an effective denial
and its bounded observed errno or nonzero Git exit code;
a missing attempt or positive control fails the whole profile.
Missing protected Git/ABI prerequisites remain BLOCKED. After those inputs are
available, synthetic repository or host-control setup errors are explicit FAIL
records with an unrun probe and retained exclusion, never a successful denial.

Owned host TCP, filesystem Unix and Linux abstract Unix endpoints are ready and
independently reachable before payload release and remain ready after probes.
Host loopback and a real host interface are tested separately inside the new
network namespace. Each must be unreachable there; timeout is failure rather
than denial. The same payload independently creates and reaches its own private
loopback listener. Successful isolated loopback never attests host loopback.
Both host socket forms and protected receipt/control storage are unavailable
inside the private filesystem/network/IPC domain. No Internet endpoint, secret,
provider or model is needed for these controls.

The commit profile gives read-only worktree content and writable metadata only
to the fixed executor. Its code, protocol input and empty hooks directory are
read-only, outside every ordinary writable grant. Setup supplies one known edit
to the synthetic file. The executor stages precisely that file and commits the
exact subject; it accepts no shell, alternate operation, path, flags or identity.
Git receives a cleared environment with system/global configuration disabled,
an empty protected hooks path, disabled fsmonitor, signing, auto-GC and
maintenance, and no external attributes. A configured executable pre-commit
failure hook is deliberately bypassed by the empty hooks policy. The fixture's
existing author/committer identity is retained. Independent protected Git reads
require one new parented commit, the exact subject with no body/footer/trailer,
only the expected file/tree change, a clean workspace, and the current branch
update. A witness branch/tag, configuration, identity, protected metadata outside
the declared commit effects, and outside sentinels must remain unchanged.
This fixture mechanism does not implement Runner one-shot authorization; that
remains the existing workflow property.

Each profile reuses protected admission, readiness/release, acknowledged
probe/finish, independent fresh retirement and bounded cleanup. After probe
completion, the payload stays parked while the controller independently inspects
membership and mounts, avoiding races with short-lived Git children. Loss scenarios
remain in the ownership suite rather than repeating across profiles. Protected
per-profile policy/attempt/result JSON and independent commit comparisons join
the same candidate/job envelope. Network, IPC and ordinary Git records require
all three ordinary profiles; a partial suite cannot become a pass. Their bounds
are included in the complete Linux probe/step/job derivation above.

These cases implement only `profile.read-only`, `profile.workspace-write`,
`profile.trusted-command`, `network.deny`, `network.loopback`, `ipc.deny`,
`git.ordinary-denial` and `git.fixed-commit`. Necessary local tests cover pure
grant/request, denial completeness and independent commit-effect predicates.
File and release checks have their separate proof owners; provider checks remain BLOCKED. Mount/path inspection
does not establish confined publication, replacement, alias or durable file
guarantees. Actual kernel cases remain unrun here and require CI evidence at the
final operator-published candidate; no native acceptance or GO is claimed.

### Retained CI failure artifacts and runtime pins

Ordinary setup, probe, and cleanup failures are persisted with distinct phase
reasons. Always-run report and two-minute upload steps retain bounded JSON and
Markdown artifacts for seven days. Initialization, checkout, runner loss, and
cancellation may prevent later work or upload; the controller reports missing
artifacts and actual job/step conclusions rather than manufacturing success.
Linux package preparation is the only added installation path; no provider or
model is installed or invoked. Its separate bounded receipt survives alongside
the native-job and prerequisite artifacts, without establishing acceptance.

The aggregate controller reads the GitHub REST run, attempt-scoped jobs, and
artifacts with `actions: read`. Collection is limited to four pages per list,
100 entries per page, two MiB per response, and ten seconds per request. It
checks repository, workflow, revision, run/attempt, unique declared job and
artifact names, artifact creation within the job lifetime, size, expiry, and
SHA-256 metadata. The pinned uploader's returned artifact ID is recorded in an
API-visible `Bind native artifact <ID>` step name. A unique successful receipt
in the producing job is required; artifact naming or payload provenance alone
cannot bind a job. Only independently selected IDs are downloaded, into their
separate runner-private directories, with digest mismatch treated as an error.
Missing downloads, unsafe/oversized files, mismatched payload identities or
candidate checkouts, failed/skipped/cancelled phases, and absent receipts retain
exclusion. Read-only metadata failure remains explicit and cannot yield GO.

The supervisor prepared these official stable release pins before workflow
authoring. All eight manifest/license JSON source representations were decoded
and matched against their original byte lengths and SHA-256; readable copies
may normalize line endings. This verifies the prepared inputs, not full action
implementation or native behavior.

| Action                      | Stable release | Exact revision                             |
| --------------------------- | -------------- | ------------------------------------------ |
| `actions/checkout`          | `v7.0.1`       | `3d3c42e5aac5ba805825da76410c181273ba90b1` |
| `actions/setup-node`        | `v7.0.0`       | `820762786026740c76f36085b0efc47a31fe5020` |
| `actions/upload-artifact`   | `v7.0.1`       | `043fb46d1a93c77aae656e7c1c64a875d1fc6a0a` |
| `actions/download-artifact` | `v8.0.1`       | `3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c` |

Node **24.21.0** is the exact prepared release (2026-09-07) from
[`dist/index.json`](https://nodejs.org/dist/index.json). Its published
[`SHASUMS256.txt`](https://nodejs.org/dist/v24.21.0/SHASUMS256.txt) has prepared
SHA-256 `f410428039e2c922a14058df067a4482691c9304a5c01a75847f9f3f2d3307f6`.
The reviewed x64 archive checksums are:

| Official distribution member      | SHA-256                                                            |
| --------------------------------- | ------------------------------------------------------------------ |
| `node-v24.21.0-linux-x64.tar.xz`  | `fd8e59d5a511510f6a298afb548f18c7d2b1be404d8b4a27d94fbe49f56cb2d6` |
| `node-v24.21.0-darwin-x64.tar.gz` | `1462cb3b3046b815cf8ea436d3da450ec1a9f11dac7e5a46b0ada5305d7e8097` |
| `node-v24.21.0-win-x64.zip`       | `158f7685b44de51f6c0df1d153526cbcd3e1bc739a8dfc607721cef75de9e541` |

These declared distribution checksums and the actually observed executable
digest have different byte scopes; neither closes native source/binary findings.

Protected acceptance requires explicit operator authorization and a reviewed
immutable candidate published through a trusted ref, never arbitrary PR code
with credentials. GO requires complete successful same-revision declared native
evidence, indispensable protected evidence, and closed source/API findings.
The operator owns publication, protection/rulesets, environments, credentials,
and authorization. Do not commit successful results and change the tested SHA;
repairs need fresh evidence. Stop after PoC and do not advertise production
native support or prepare production integration before GO.
