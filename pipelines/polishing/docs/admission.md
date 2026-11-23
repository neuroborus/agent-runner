# Polishing Admission

Read the affected sections before changing this contract. Use the [topic map](README.md)
for related owners and required reading routes.

## Inputs And Change Set

The task directory contains:

```text
task/
├── task.md
├── clarifications.md  # optional task-level transcript
└── context.md         # optional
```

`task.md` is required and non-empty. `clarifications.md` and `context.md` are
optional immutable inputs. The pipeline does not accept or parse `plan.md`.

The initial change set is all repository content represented by:

- staged, unstaged, or deleted tracked paths relative to `HEAD`;
- non-ignored untracked paths and their content.

Staging placement does not define content membership. Ignored untracked files
are outside the change set. Preflight requires at least one change.

Task inputs may be outside the repository or may be ignored untracked files
inside it. A repository-local task input is rejected when it is a dirty tracked
path regardless of ignore rules, or a non-ignored untracked path. This prevents
immutable hashed input from overlapping the writable change set. A clean
tracked input is allowed and remains protected by input-drift checks.

## Roles And Configuration

The descriptor declares independently configurable `worker`, `reviewer`, and
on-demand `arbiter` roles and owns active-role selection. Independent and
combined modes activate all three, with Arbiter still resolved on demand; lazy mode activates
only Worker. CLI and runner configuration use the common backend
and execution-preference precedence rules. Each role accepts string trusted
`profile`, backend-native `model`, decimal `contextSize`, and portable `effort` selections;
role-specific CLI/MCP values win over run-wide and runner values, with
`current` omitting the native override. Worker and Reviewer may use any
Codex/Claude combination; Arbiter supports either backend.

Effort accepts only `current|low|medium|high|xhigh|max`, independently of model IDs.
The shared root resolver applies role override → run override → project role →
project `defaultEffort` → runner role → runner `defaultEffort` → `current`.
CLI `--effort` and descriptor-derived `--<role>-effort` map to MCP
`run_start.effort` and `roleOverrides.<role>.effort` through the same runner
contract. Both reject values outside the portable enum before dispatch; MCP
intents bind the selections and detached continuations reuse saved effort.
Validate all configured vocabulary, but resolve and persist only active roles;
native translation stays in provider adapters. Every role turn carries saved explicit
effort, including recovery; `current` omits the request override.
Common envelope version 8 requires saved active-role effort. Legacy missing
values migrate to `current` under the run lease without provider activity,
configuration reload, or changes to progress and session evidence. Public
status and activity omit these provider-private values.

Worker capability preflight requires structured output, read-only inspection,
autonomous safe content writes, remote-write blocking, and the explicit
`gitMetadataWriteBlocked` guarantee. Codex satisfies it through workspace-write
isolation; Claude satisfies it through its proved sandbox's Git-directory write
and `git add` denials and absolute file-tool Git-metadata denials. On Linux,
Claude proves read-only and workspace-write policies separately. It prefers
full native isolation and may use the weaker parent invocation only after a
recognized nested-user-namespace denial and a complete proof through the
authenticated provider-private launcher. The launcher validates and
strengthens Claude's parent bubblewrap invocation, then executes
the pinned real binary once so each command crosses one effective boundary
while provider transport stays outside. That proof follows the identical
launcher path and covers the exact workspace authority plus Git, outside-write,
network, Unix-socket, and credential restrictions with bounded model-free
execution and no retained native diagnostic. A generic failure leaves the
affected mode unavailable.
The provider-neutral receipt is pinned before that role's work and must match
before later provider work.
The local-commit executor proof remains irrelevant to polishing, and neither
backend receives broader `.git` access.
Each Codex workspace-write app-server attempt receives one canonical owner-only
runner-created root beneath the fixed platform temporary location. Exactly the
repository and that private root are writable; host `/tmp`, ambient temporary
paths, Git metadata, and command network access remain excluded. The effective
shell policy projects validated `TMPDIR`, `XDG_CACHE_HOME`, and
`XDG_RUNTIME_DIR` children without changing the provider process environment.
In-session compaction retains the root, while every success, failure, or fresh
recovery validates and removes it before another attempt. Unsafe preparation or
cleanup fails closed. Read-only and local-commit isolation remain unchanged.

The pipeline owns these settings and defaults:

```text
mode = independent
maxFixRounds = 20
maxDisputesPerFinding = 5
maxSameFindingRounds = 5
stagnationWindowRounds = 3
```

`mode` accepts exactly `independent`, `lazy`, and `combined`. Missing values resolve to
`independent`, which is the default and recommended mode because its separate
Reviewer provides genuinely independent semantic review, at the cost of more
provider context and tokens. `lazy` is an explicit lower-consumption choice
that uses only Worker and does not provide independent review. It is never
selected automatically. CLI `--mode` and MCP `run_start.mode` provide the
explicit per-run override.

It also owns `finalization`, a string setting whose default `auto` discovers a
conventional confined repository `finalization` skill and otherwise falls back
to repository instructions and project-defined checks. `none` selects that
fallback directly. Any other valid value is a normalized infrastructure-relative
Markdown path and requires that exact procedure (including an adjacent `RUNNER.md`). After Git preflight and
before backend probing or bootstrap, the workflow durably persists the
configured policy, selected canonical regular path or fallback, selected-file
fingerprint when applicable, and a fingerprint of the complete decision. A
backend pause retains that partial-preflight decision; resume verifies it before
retrying probes and never reloads or switches it. Explicit paths resolve from the
frozen selected infrastructure root, while `auto` retains conventional discovery
inside the target. A bound external `finalization/SKILL.md` requires only that
exact file read; neither the original skill nor any parent is changed or granted
additional access. New `file` decisions fingerprint bytes, file identity, real
ancestors, target and root without retaining procedure text. The existing
`skillPath` field supplies its inventory label: an integrated repository-relative
path or `finalization://<infrastructure-relative-path>` for external guidance.
The latter never replaces repository-relative validation entries, including
same-relative-path files. Prompts also declare the exact absolute read. Only this selected label may name external
validation infrastructure. Replacement (even identical bytes), links, missing
files and drift block without switching guidance or consuming repair budgets.

State version 19 preserves version-18 decisions and all accounting and effect
evidence unchanged through its leased migration. Legacy `skill` decisions retain
their original repository path and fingerprint algorithm; no identity proof is
inferred and no frozen selection is rediscovered. Consumed commits and completed
handoffs remain verification-only. New selection adds no model checkpoint.

Bootstrap, migration and finalization instructions require reading the exact
selected entry and its mandatory repository references under existing read
authority. References controlling validation commands or gate behavior belong
in ordinary validation infrastructure under existing inventory, migration and
drift rules; other documents are classified by responsibility. Selection and
the request envelope grant no parent-directory or external sibling access,
recursive retrieval, substitution or late fallback.

`trustedChecks` is an array of unique runner-trusted command aliases and
defaults to empty. Root and safe project `trustedCommands` catalogs use the same
exact-vector validator for each alias's inventory command, executable, and
arguments. Normalized catalogs merge root then project in stable order;
identical same-name definitions deduplicate and conflicts reject even when
unselected. The merged catalog permits at most 256 definitions and a selection
at most 32 aliases. Project settings may replace the selection with root or
project aliases in the selected order. Definitions reject shell-string
substitutes and environment, credential, or host-authority fields. The root resolves
the complete selection and fingerprints it before agent work; resume uses the
persisted snapshot without reloading configuration. Later project configuration
edits trigger the existing protected-input guard.
The top-level `trustedCommandTimeoutMs` supplies the per-command deadline in
milliseconds. It accepts only integers from `1` through `2147483647`, defaults
to `3600000` (60 minutes), and resolves project over runner configuration with
no CLI or MCP override. Creation fingerprints and persists it once; resume and
concurrent runs retain their own values. For example,
`"trustedCommandTimeoutMs": 7200000` selects two hours.

Trusted declarations also accept the architecture's closed `capabilities`
object: `scratch: true`, `cache: true`, `sourceProjection: true`, and bounded
pinned HTTPS `artifacts`. Root and project normalization are identical.
Version-4 snapshots include normalized capabilities in command identities and
`timeoutMs` in the trusted-configuration fingerprint without changing command
identities. Version 3 retains its saved timeout without gaining source-
projection authority. Legacy version-1 and version-2 snapshots retain their
policy, exact fingerprints, and evidence bindings with the deterministic one-
hour fallback, without configuration reload or authority upgrades. Capability
preparation uses the smaller of the snapshot deadline and 10 seconds.
This is one absolute monotonic launch-to-close deadline including durable
registration, checked again by the supervisor at payload admission. Expiry or
cancellation permanently closes release; pending registration and verified
retirement must drain, with uncertain ownership retained. Reconciliation never
turns an expired preparation into availability or required-check evidence.
Common envelope version 22 routes only preparation through canonical reservation,
bounded attachment/admission, and endpoint-bound canonical settlement. The root's
custody gate preserves accepted immediate stops even with delayed observation;
matching deferred targets retain current-step permission, while an explicit null
target supports ordinary preparation. No restart releases an old attempt, and
custody settles before cleanup, availability or further work. Existing consumed-
effect verification remains first; see [preparation custody](../../../docs/ARCHITECTURE.md#preparation-custody).

Unavailable frozen requests create a durable `environment_blocked` pause before
provider work. Early pauses retain `preflightComplete: false`, null baseline,
backend versions and clarification path, empty hashes, and no `resumeState`.
Null-action resume retries the saved request before ordinary `CLARIFY` preflight;
later pauses retain their applicable checkpoint, including an untouched HANDOFF.
Completed handoffs are verified before checking capabilities needed for new
work. Status and immutable terminal reads perform no capability work. Inspection
does not execute or attest required checks. Scratch/cache requests use isolated
transient storage; artifact requests use bounded runner-owned acquisition and
read-only mounts. Declaration preflight inspects storage and isolation without
downloading dependencies. Requirement inspection before writable work prepares
dependencies; finalization execution reacquires and reverifies them. Environment
repair permits retry; changing declarations requires a new run and never permits
weakened validation.

Settings are stored in pipeline state at run creation and are not reloaded on
resume. The root may load safe project overrides from an ignored
`LOCAL_ARTIFACTS/agent-runner.json` or an explicitly selected integrated ignored
path or target-bound external configuration under the root configuration
contract. CLI/MCP execution selections win over project values, which win over
runner-root values. Alongside trusted command catalogs, a project file may select
runner-trusted profile aliases and safe role, setting, and repository-relative
artifact-root values; it cannot define profile implementations, credentials,
provider binaries, or environment values. Explicit CLI/MCP pipeline-setting
overrides win over project values, runner values, and descriptor defaults.
All configured roles are validated,
but only active roles are resolved, probed, persisted, source-session checked,
or invoked. Inactive values stay in the configuration source for a later
independent run and are not exposed through lazy state. The resolved active
roles, settings, and artifact root are persisted. In independent and combined modes the
Arbiter backend is probed when first needed; lazy mode never probes Reviewer or
Arbiter.
When a project configuration supplied those values, the root runner persists
its protection record and checks it before recovery, around every provider
turn, and before trusted execution, handoff, or stop reconciliation. Drift
produces the non-resumable `project_configuration_changed` safety pause;
already begun handoff effects remain verification-only. Complete and recovery
role envelopes explicitly prohibit modifying the resolved project
configuration.
