# Native platform proof contracts and release audit

This owns the contracts and retained release audit for an isolated proof of
concept (PoC), plus its newly authorized evidence/reporting and CI boundary.
It adds no native runtime support, installs no dependency, and changes no
production consumer.
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
owner, effect-free protocol tests, declared-platform workflow, and Linux
owned-process reference cases are implemented. Actual CI observations, source
verification, and provider integrations remain pending; their missing evidence
remains BLOCKED. The historical audit below
retains its original inspection scope and conclusions.

`ci/native/index.js` intentionally exports the fixed platform/check/finding
catalogs, `normalizeNativeResult`, `normalizeSourceEvidence`,
`aggregateNativeEvidence`, `renderNativeReport`, and their bounded contract
error. All imports, validation, aggregation, and rendering are effect-free;
there is no filesystem, process, environment, provider, or network access.
The index also exposes the pure system dispatch, CI stage-record, and independent
artifact-join contracts. Explicit report I/O, CI metadata retrieval, and the
harness child process belong to `run.js`; Linux system effects belong to the
indexed `linux/` owner invoked explicitly by that entry point. The workflow emits fixed fallback
summaries when checkout is unavailable. Importing the entry point does not
execute it.

The version-1 evidence contract has these separate inputs:

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
annotations, retaining all findings in the structured report. Diagnostic prose
is limited to 512 characters and redacts credential assignments, authorization,
URLs, local paths, workflow commands, and unsafe controls. Summaries and
annotations contain only fixed messages and closed IDs. Do not supply raw
process/provider output, environments, credentials, sessions, or transcripts.
Successful rendering never turns a BLOCKED proof into GO.

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

## Validation and external acceptance boundary

Follow the canonical [finalization skill](../../.agents/skills/finalization/SKILL.md)
and [testing policy](../../docs/TESTING.md) for each admitted implementation step.
Formatting, the ordinary fast gate, and `git diff --check HEAD` remain local
finalization requirements. Format first with `npm run format`, then run necessary
effect-free harness coverage with `node --test ci/native/harness.test.js`, the
ordinary `npm run check` gate, and `git diff --check HEAD`. Documentation-only
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
its explicit `--stage initialize`, `setup`, `probe`, `cleanup`, and `report`
stages, and its controller invokes `collect` and `aggregate`. The default system
invocation runs the job stages together. Provider dispatch is deliberately
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

Reporting is initialized using the image's preinstalled Node before pinned Node
setup. A runner-private version-2 `native-job.json` records CI stages separately
from native check phases and admits only the implemented Linux check records.
Version-1 reporting inputs remain readable with no native results. Native
records must match the containing job's exact revision, platform, image,
provenance, and observed runtime; duplicate or unauthorized IDs are rejected.
Setup has a 120-second internal budget; probe has 220 seconds and reporting
cleanup has 30 seconds. CI runs the single effect-free
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

### Linux owned-process reference proof

`linux/index.js` exposes the pure receipt/retirement, bounded message queue and injected case protocol,
plus `runLinuxOwnershipProofs`, whose effects require Linux GitHub system CI.
`confinement.js` prepares the fixture, `controller.js` owns live launches and
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
`linux-missing-inputs.json` naming the failed inspection stage and error code;
there is no substitution, installation, or retry to obtain a pass.

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
access-profile cases belong to the next commit.

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

The Linux owner may report only `launch.argv`, `launch.storage`,
`ownership.admission`, `ownership.descendants`, `ownership.cancel`,
`ownership.owner-loss`, `ownership.helper-loss` (both supervisor and launcher
cases), and `ownership.receipts`. Local injected protocol tests cover admission
order, the shared deadline, fault acknowledgement, terminal channel failures, retained exclusion,
cleanup failures, and same-revision joining.
All other system and provider contracts remain BLOCKED. These cases have not
been run locally; actual observations require system CI on the final published
candidate. Implementation or local protocol coverage cannot establish GO or
native support.

### Retained CI failure artifacts and runtime pins

Ordinary setup, probe, and cleanup failures are persisted with distinct phase
reasons. Always-run report and two-minute upload steps retain bounded JSON and
Markdown artifacts for seven days. Initialization, checkout, runner loss, and
cancellation may prevent later work or upload; the controller reports missing
artifacts and actual job/step conclusions rather than manufacturing success.
Only existing protected Linux reference executables run; no provider, model,
or new package is installed or executed.

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
