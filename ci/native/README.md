# Native platform proof contracts and release audit

This is the first gate of an isolated proof of concept (PoC). It adds no native
runtime support, installs no dependency, and changes no production consumer.
The existing Linux runner, provider registry, pipelines, state, configuration,
and canonical skills retain their current contracts.

**Audit disposition: technical NO_GO for dependent implementation.** The
released interfaces inspected below do not establish a recoverable macOS
descendant domain, Windows helper admission/recovery, or complete native
provider mediation. No missing mechanism is approved by this document. Retain
the findings and revise the PoC plan and execution run before dependent work;
do not replace a required contract with a weaker approximation.

No native system or authenticated provider acceptance was run. Those results
remain **UNPROVED**, independently of the source findings. Local version/help
inspection and protocol schema generation establish callable surfaces only.
They are neither sandbox acceptance nor successful provider tool dispatch.

The 2026-10-01 reconciliation retains the 2026-09-30 audit against current
committed documentation. Retained bytes confer no fresh validation or inherited
approvals. The current Linux Codex 0.159.3 installation does not replace the
historical 0.159.2 observations below or establish native acceptance.

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

Dependent native implementation remains **BLOCKED: technical NO_GO**. The old
twelve-step plan is historical reference, not an executable continuation. Stop
after the verified audit reconciliation commit. Source/API research and an
accepted revised plan with a new execution run are required before further
implementation; this commit grants no automatic continuation.

## Validation and external acceptance boundary

Follow the canonical [finalization skill](../../.agents/skills/finalization/SKILL.md)
and [testing policy](../../docs/TESTING.md) for each admitted implementation step.
Formatting, the ordinary fast gate, and `git diff --check HEAD` remain local
finalization requirements. For this documentation-only reconciliation, run
`npm run format`, then `npm run check` and `git diff --check HEAD`; no new tests
or affected slow coverage are required. Selected exact trusted commands remain
Runner-owned: agent turns report `NOT_RUN` with their frozen Runner identities,
and the Runner executes the persisted exact vectors during FINALIZE.
Only the Runner-authorized COMMIT boundary stages, checks staged whitespace,
and creates the exact subject-only local commit using existing identity,
without authorship trailers or remote writes. Native system/protected
acceptance never enters a local FINALIZE inventory.

The later harness proposal has separate invocations: local, effect-free protocol
tests use `node --test ci/native/harness.test.js`; native CI alone uses
`node ci/native/run.js --tier system`; protected provider acceptance, if
indispensable, uses `node ci/native/run.js --tier provider`. These files and
workflows are not implemented by this audit. Ordinary test discovery must not
start native helpers, restricted payloads, or provider turns, including through
new source imports. CI-only packages must be injected at composition, with no
production import dependency or startup effect.

Native PR CI targets **both `main` and `dev`**, plus explicit dispatch. Pin the
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

Protected acceptance requires explicit operator authorization and a reviewed
immutable candidate published through a trusted ref, never arbitrary PR code
with credentials. GO requires complete successful same-revision declared native
evidence, indispensable protected evidence, and closed source/API findings.
The operator owns publication, protection/rulesets, environments, credentials,
and authorization. Do not commit successful results and change the tested SHA;
repairs need fresh evidence. Stop after PoC and do not advertise production
native support or prepare production integration before GO.
