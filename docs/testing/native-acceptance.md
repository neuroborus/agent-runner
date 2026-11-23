# Native and Live-Provider Acceptance

Read the affected sections before changing this contract. Use the [topic map](README.md)
for related owners and required reading routes.

## Operator-owned Codex file-output acceptance

Existing-file output readiness regressions live in `test/agents/codex.test.js`,
`test/agents/registry.test.js` and `test/runner-directory.test.js`. Injected native
effects prove regular/dotfile refusal before work, mixed declarations without
preparation, read-only preservation, descriptor validation and shape substitution
after cached approval or pause. They establish no actual native enforcement.

Operator-owned model-free native acceptance is deliberately outside ordinary
fast/slow coverage and live-provider smoke. After pipeline gates, explicitly run:

```bash
node scripts/accept-codex-file-outputs.js --enable --candidate=/absolute/private/package --codex=/absolute/configured/cli
```

The candidate must be a separately installed package. The script uses owned
temporary ordinary directories and synthetic native settings without credentials
or model requests. It records named-profile configuration acceptance separately
from enforcement, requires the expected file-grant setup failure before its
command marker, verifies directory-write/read-only and protected-metadata/sibling
controls, and proves source/candidate adapter refusal before any injected native
inspection, allocation or launch. Missing interfaces, timeouts and failed controls
are failures, not acceptance; an unrun script remains NOT_RUN. Report failures,
skips and limits before installation/activation. This negative native witness
must never become a PASS-required agent check. Neither mocked tests nor CLI
version/help success grants native acceptance credit.

## Ownership diagnostic acceptance

Focused deterministic development coverage lives in
`test/platform/ownership-diagnostic.test.js`, the injected supervisor/parent
cases in `test/platform/owned-process.test.js`,
`test/runner-observations.test.js`, `test/state/observations.test.js` and
`test/state/recovery-failures.test.js`. It owns closed shape/site/branch rejection,
measured overruns and unavailable facts without additional inspection work,
adapter parity, unchanged failure policy, retained samples across cleanup,
terminal write-ahead reconstruction, immutable legacy records and correlated
recovery publication. CLI and MCP fixtures retain projection parity and redaction.
The parent/supervisor fixture also covers valid post-request pre-spawn expiry,
with no target spawn, no added inspection and close before deregistration.
Injected `test/trusted-timing.test.js` regressions cover synchronous and
asynchronous no-launch refusals, plus preparation refusals through receipts and
capability blockers; `test/agents/codex.test.js` covers storage allocation/cleanup
cause propagation. Both adapter suites cover launcher-failure mappings with
validated, unavailable and malformed diagnostics while preserving failure policy.
Both coding pipelines' `capability-requirements.test.js` fixtures cover retained
blocker evidence and caught inspection, preflight and cleanup diagnostics in
persisted pauses, with unchanged stopping behavior and redacted native errors.
Both retain malformed-evidence rejection and unchanged failure policy without
executing selected trusted commands or consuming native acceptance.
Existing state custody, stop, journal, migration, orchestration, CLI/MCP and release
slow suites remain required through the complete `npm run test:slow` gate; do not
repeat those selected files as additional equivalent slow commands. Release
assembly/archive verification and the separate exact-artifact
`npm run test:slow -- test/package-install.slow.test.js` gate remain additive.
Focused development results give none of those later gates acceptance credit.

After reviewed polishing HANDOFF, the separate authorized operator commit,
whole-result review and inactive candidate installation, the supervising operator
runs the smallest model-free native acceptance against exact committed Source and
a separately installed candidate:

```bash
node scripts/accept-ownership-diagnostics.js --enable --candidate=/absolute/private/package --commit=<source-commit>
```

The script verifies clean committed Source and identical platform bytes in the
separate installation. Both executions use the real supervisor/IPC with an owned
synthetic Node target: one controlled inspection refusal, a post-request pre-spawn
preparation expiry and a clean-retirement control. The expiry uses the existing
parent preparation-clock/deadline injection and a supervisor clock preload to
reach the absolute deadline when handling start, without sleeps or target effects.
It requires an actual parent request, recorded expiry, no target effect marker
and positive retirement/deregistration. The refusal injects a procfs read denial
and labels that condition separately from actual native launch, IPC and verified
retirement. Injected preparation clocks are likewise labeled separately from
native execution. It changes no supervision mode, sandbox, native inspection
limits or provider settings. It retains fixture storage if retirement is
uncertain. An unsupported environment,
missing evidence or failed control is a failure, never a skip credited as native
acceptance. Unrun acceptance stays NOT_RUN; injected tests and retained evidence
cannot substitute for Source/Installed execution. Historical cause and
Source-contract violation remain UNKNOWN. Live-model smoke remains opt-in.
Activation and default concurrent MCP acceptance remain separate operator
delivery work after these gates.

## Live providers

Live provider tests remain opt-in as described in the repository README. Normal
tests never consume model turns. Repeated full-suite runs require a specific
unresolved risk, not a ritual.

## Native Claude permission policy

The slow `test/agents/claude-native-policy.slow.test.js` suite owns the
model-free reproduction of the Claude native permission policy and workspace
staging through the installed CLI. Enable it explicitly on the host with
`AGENT_RUNNER_NATIVE_CLAUDE=1 npm run test:slow -- test/agents/claude-native-policy.slow.test.js`.
It is operator-owned native-platform acceptance: the Runner-trusted executor's
outer isolation does not provide the nested Claude sandbox required by this test.
The ordinary slow gate skips it, so passing that gate never establishes native
acceptance. When enabled, it skips only on non-Linux hosts or when `claude` or
`bwrap` is absent from `PATH`; unavailable workspace-write isolation and any
other preflight or protocol failure still fail. Every turn runs through the real
adapter probe, generated settings, authenticated launcher, and stream
normalization against an owned Git repository or ordinary directory,
configuration directory, synthetic key, and loopback Messages stub that scripts
tool calls and refuses every other request. Adapter environment/settings enforce
foreground execution for permission and cwd scripts, and each turn is awaited
before snapshots.
Owned-process supervision bounds each turn with a deadline and test
cancellation; interruption fails independently of any later adapter error.
Fixture cleanup requires verified retirement of every registered process;
otherwise it retains the fixture and fails. Claude receives only a
fixture-owned environment; seeded conflicting host provider routing,
authentication, header and proxy settings must never reach a Claude invocation.
Only baseline turns replace the generated
settings with the superseded workspace policy: a subcommand-rule refusal of
ordinary inspection must end as terminal unclassified Bash, script-driven
content work outside Claude's accept-edits fast path must receive a terminal
classifier refusal, and a workspace Git-metadata `Write` must miss the
root-relative rule and reach a classifier decision. Corrected turns must admit
Git inspection, fast-path filesystem work and script-driven content work without
a permission denial, deny an absolute Git-metadata `Write` without a classifier
decision, and admit direct Bash writes to Git `HEAD` and `config` without a
native denial so each returns a command-sandbox permission error. Neither
corrected multi-command Git turn may create `.claude` in the workspace.
A further Git workspace-write Bash command uses a descriptor witness that
reports sockets in both the executed Node command and its parent shell. A
test-only metadata tap in the generated launcher records the authenticated
producer socket identities and original stdio before projection returns,
without changing arguments, forwarding, or isolation. The command must hold no
nonstandard socket. No producer socket may reach the shell; any remaining
shell socket must match captured launcher stdio, accounting for saved stdio
without attributing its origin to IPC. The exact encoded native tool result
is retained and decoded for assertions. A separate model-free child with a
deliberately inherited socket at descriptor 9 must trip the same witness;
this diagnostic negative control grants no native-policy acceptance credit.
Claude 2.1.326 or newer must actually exercise a producer pair in that turn;
legacy producers without IPC options remain supported by the tap.
Read-only ordinary-directory sources initially lack staging and have either
synthetic instructions with `.claude/skills` linked to a canonical skill tree,
or a sparse `.claude` control holding one ordinary file. The directory
differential removes only `CLAUDE_BASH_MAINTAIN_PROJECT_WORKING_DIR` from both
launch environments. Without retention, a lone `pwd` leaves the source
unchanged, but `pwd`, source `Read`, then another `pwd` must successfully
complete all tools and the native turn before the adapter rejects source drift.
Both control shapes must acquire an empty mode-0700 `.claude/.cc-writes` and
a changed source/control snapshot. With retention, both control shapes must
complete unchanged: both Bash commands still execute in the workspace, source
`Read` succeeds, and source/control snapshots
and root and `.claude` directory metadata remain unchanged, with no denial or
unscripted request. Ordinary slow runs skip this differential; only an enabled
host run proves the mechanism and its prevention for the candidate.
A retained-cwd workspace-write turn over a sparse control with one existing
declared `out` output root must advertise `workspaceWrite` and admit a scripted
Bash write of `out/result.md` without a denial or unscripted request, while
Bash writes to `source.txt` and `.claude/notes.md` each return a command-sandbox
permission error. A sibling write under namespace-private `/tmp` may succeed
inside scratch or return a permission error; the host sibling must remain
absent in either case. Its snapshot must be unchanged
outside declared outputs, root and `.claude` directory metadata unchanged, and
no `.claude/.cc-writes` created. This proves the launcher's output-only
directory write authority through the installed CLI. It is operator-only
acceptance: run it against the candidate, and as a read-only differential
against the previous implementation. Accept that differential only when the
previous implementation fails specifically at the declared-directory writer
and the repaired implementation passes; an earlier policy or IPC failure does
not establish the directory repair. Claude may
still require separate native approval for sensitive Git commands, so the suite
does not claim that every Git mutation reaches the sandbox; the effective access
proof exercises those mutations directly. Every case leaves HEAD, refs, index,
configuration, and remotes unchanged, owned decoys for the stripped ambient Git
routing stay untouched, and public errors, records, and diagnostics carry no
command, path, free-text reason, provider payload, or key. A loopback endpoint
leaves auto mode without its server-side check, so test-local native records
distinguish rule decisions from classifier decisions. Changes to Claude
permission settings, effective access proofs, or policy identity require a
separate enabled host run before installation in addition to the complete slow
gate. Record both results and report any skip explicitly. No live model is used.

The suite also keeps a separate native foreground/background differential.
Conflicting caller and fixture user settings set
`CLAUDE_CODE_DISABLE_BACKGROUND_TASKS=0`; only the baseline removes the adapter's
forced value from both launch surfaces. All other policy settings, including
private cwd retention and permissions, remain identical. The strict Messages
stub captures the offered Bash schema and refuses and counts requests beyond
its bounded script without retaining their payloads. The baseline Bash command
blocks on an owned FIFO. At the first result the stdout tap must observe no
effect before releasing the FIFO; the baseline then requires the completed
effect and actual rejected post-result model traffic or a duplicate result.
Repaired turns require no background schema option, a successful effect before
the sole result, and no task-start/progress/notification records. An unsupported
background request may fail as a tool request or complete synchronously, but
cannot produce a late effect. A timed-out blocked command must prove it started,
return a tool error and never complete its effect. No sleep supplies causal
ordering; deadlines only bound hangs.

Both native fixtures use public owned-process supervision with forwarded
cancellation and ownership proofs. Pending turns are aborted and awaited, and
every registered process must report `onProcess(null)` before FIFO or fixture
removal. Their separate host temporary roots survive the test launcher's scratch
cleanup on uncertain retirement; uncertainty fails and retains storage. Native
records remain test-local and public diagnostics stay redacted. These lifecycle
cases supplement the newer source-shaped cwd and permission differential above;
they do not replace it or establish the cause of historical protocol failures.
The enabled suite remains supervisor-owned post-completion acceptance after
reviewed HANDOFF and the separate operator commit, against exact committed main
and the installed-package adapter, before global installation and activation.
It is not a pipeline required check, and ordinary slow skips establish no native
acceptance. Applicable post-install provider acceptance remains separately
operator-owned.

## Post-install Claude acceptance

Read the [current contract](providers.md#provider-coverage).
