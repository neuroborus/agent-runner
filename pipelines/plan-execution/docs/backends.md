# Execution Backend Behavior

Read the affected sections before changing this contract. Use the [topic map](README.md)
for related owners and required reading routes.

## Codex

Use the non-interactive Codex app-server JSONL protocol. Probe the installed
`codex-cli` version and required app-server flags before the first role turn.
Start each process with strict configuration and hosted search, browser,
computer-use, image-generation, artifact, Code Mode, JS REPL, memory,
automatic-goal, guardian-review, multi-agent, external app, plugin,
lifecycle-hook, notification, MCP, shell-environment snapshot, and skill-driven
MCP dependency installation capabilities disabled. Route no native approval to
a subagent or interactive reviewer.
Resolve and disable every configured MCP server individually, then verify the
effective configuration before starting a thread; fail closed when isolation
cannot be proven. The Codex process retains its own provider connectivity, but
command tools receive no network access, workspace-write excludes implicit
temporary-directory roots, Git metadata remains read-only, and reported
activity is rejected if it uses a disabled or unknown tool or attempts a push,
hosting-service mutation, or remote reconfiguration. Each workspace-write
app-server attempt receives one runner-created canonical owner-only private
root beneath the fixed platform temporary location. Add exactly the repository
and that root to native writable roots, keep host `/tmp` excluded, and project
only its validated temporary, cache, and runtime children as `TMPDIR`,
`XDG_CACHE_HOME`, and `XDG_RUNTIME_DIR` through the effective command shell
policy. Build that policy from the full provider process environment, retain
Codex's automatic secret-name exclusions and an empty custom exclusion list,
then apply the explicit workspace values and an exact allowlist containing
Codex's standard core names (`HOME`, `LOGNAME`, `PATH`, `SHELL`, and `USER`),
`AGENT_RUNNER_OWNED_PROCESS`, and those three workspace names. The allowlist
keeps the dynamic owned-process proof available to model-issued commands
without exposing unrelated parent variables. Do not change the provider process
environment. Retain the root across in-session compaction, but validate and
remove it after every success, failure, or fresh recovery before starting
another attempt with a distinct root. Unsafe preparation or cleanup fails
closed and never reports success. Read-only and local-commit storage remain
unchanged. Strip ambient Git repository redirection and identity overrides from
every Codex process environment, and disable shell-profile loading for agent
commands. Remove key-, secret-, and token-named variables from the isolated
local-commit executor while retaining the ordinary environment needed by Git
and hooks.
Capability, isolation, and prohibited-operation failures expose only one
bounded allowlisted diagnostic class identifying the rejected capability or
operation class. Do not retain the reported command, native error response,
credentials, or transcript as diagnostic evidence.
Reported `subAgentActivity` or any other collaboration use remains a terminal
`operation_multi_agent` isolation failure. Disabled multi-agent launch
configuration does not authorize accepting or transparently retrying a backend
that ignores the restriction.
For `ERR_CODEX_TURN_FAILED`, map only recognized App Server
`codexErrorInfo` variants to finite allowlisted terminal classes. Persist the
validated class in plan-execution failure state, but discard the native error
message, HTTP status and other variant data, additional details, provider
response, prompt, and transcript. Unknown variants add no diagnostic class.
Keep context-exhaustion compaction and interruption handling on their existing
dedicated paths.
For valid terminal `other` errors, audit items and reject explicit model reroutes
before refining their classification. Bounded recognition of a non-transient
HTTP client status plus a structured error envelope, including HTTP 400
`invalid_request_error` / `invalid_json_schema`, produces terminal
`ERR_CODEX_TURN_FAILED` with `turn_bad_request`, the fixed message
`Codex turn failed.`, and `recoverable: false`. In both modes this bypasses
compaction, fresh retry, `backend_unavailable`, and output-correction recovery.
Malformed, oversized, ambiguous, and transient-status evidence remains opaque
`turn_other`: eligible non-commit turns outside source forks reconstruct once
from the complete durable request, then propagate the next failure unchanged.
The explicit `turn_server_overloaded` class enters shared durable backoff after
item auditing, without passing through native HTTP-message refinement.
Local-commit readiness failures remain pre-effect rejections and never replay
the executor. Recognition and redaction belong to the adapter as specified in
[`docs/ARCHITECTURE.md`](../../../docs/ARCHITECTURE.md); no pipeline branch or
state migration is needed.
Recognized native output exhaustion remains a terminal failure with the shared
`output_exhausted` disposition and bypasses automatic replay, compaction, availability,
quota, and output-correction recovery. The
[provider model](../../../docs/product/PROVIDER_MODEL.md#normalized-failures-and-recovery)
owns its recognition and evidence limits.

Worker:

```text
sandbox: workspace-write
approval policy: never
```

Reviewer and Arbiter:

```text
sandbox: read-only
approval policy: never
```

Use Codex structured output / JSON Schema support for machine-actionable responses.
Before any provider activity in an adapter `run`, validate the effective output
schema, including the adapter-owned local-commit readiness schema. Keep the
Codex keyword allowlist and structural compatibility checks inside that adapter;
retain shared strict-object, JSON-value, size, and depth validation. Inspect only
schema positions, including nested properties, array items, `anyOf` branches,
and `$defs`; property names and `enum`/`const` data are not schema keywords.
Reject unsupported keywords such as `uniqueItems`, boolean or tuple schemas,
root `anyOf`, malformed patterns, regex lookaround or backreferences, and
invalid or external references locally with terminal
`ERR_INVALID_CODEX_SCHEMA`. Such rejection starts no provider turn or recovery
attempt and is not a structured-output correction or backend availability
failure. Supported local references may be recursive.
Resolve URI-fragment and JSON Pointer escapes before requiring a schema target;
malformed escapes are rejected without retaining native parsing errors.

Validate every explicit model with `model/list` and reject any reported model
reroute. Fresh turns use `thread/start`; continuation uses `thread/resume`; and
a supplied source session uses `thread/fork`, with the returned child thread ID
persisted as role lineage. Unavailable continuation may fall back to a fresh
reconstructed turn, while an unavailable fork source is an error.

Map a trusted Codex alias only to its configured native profile name and pass
it with `--profile`. Map an explicit decimal context size to
`model_context_window`. Omit both controls for `current`; do not derive them
from native session storage.

On native context exhaustion, request thread compaction and retry the turn once.
If the context remains full, start a fresh turn reconstructed from durable
runner input and the current workspace. Never replay an interrupted
`local-commit` turn: return an ambiguous outcome so the runner consumes no
second authorization and verifies Git state before deciding how to proceed.

`local-commit` additionally supplies an opaque authorization ID, expected HEAD,
and exact subject. Its agent turn is read-only and may only confirm readiness
through the adapter's strict schema; it cannot modify files, stage changes, or
write Git metadata itself. After confirmation, the Worker adapter runs the
exact HEAD check, `git add -A`, fixed unstaged-clean, staged-diff whitespace,
and nonempty-diff hygiene, and the ordinary subject-only commit in a dedicated
Codex permission profile. That profile grants write access only to the
workspace and resolved Git directory, denies command network access, preserves
Git hooks and configured Git identity, and receives no ambient Git overrides.

Probe this isolated commit profile by verifying outside-workspace write denial,
Git-metadata writes, and network denial. Report `localCommit: false` and fail
preflight if any boundary cannot be enforced. Any interrupted or failed commit
executor returns an ambiguous outcome for the runner's one-shot authorization
and final Git-state verification; it is never replayed. Policy, capability,
provider, or confirmation-turn rejection before executor invocation carries
`effectStarted: false`, including `ERR_CODEX_LOCAL_COMMIT_POLICY`. The adapter
preserves the original bounded error code and recoverable classification.
`ERR_CODEX_LOCAL_COMMIT_POLICY` carries one diagnostic class per refusing rule:
`operation_local_commit_file_change` for a reported file change,
`operation_local_commit_git_operation` for a Git subcommand outside the
readiness inspection allowlist, and
`operation_local_commit_confirmation` for a missing or invalid `{ ready: true }`
confirmation. The readiness prompt discloses that inspection allowlist,
derived from the enforced set rather than a second list, and names the
`git var GIT_AUTHOR_IDENT` and `git var GIT_COMMITTER_IDENT` identity queries,
so the git-operation class means a disclosed-policy refusal before executor
invocation; it establishes neither a classifier defect nor an attempted
mutation. These classes never expose commands, paths, output, or native
messages. The retired single class `operation_local_commit` remains valid in
historical failure records but is no longer emitted.

## Claude Code

Use non-interactive print mode with bounded stream JSON output. Start in safe mode, expose only
the built-in repository tools needed by the role, disable Chrome and prompt
suggestions, and load an explicitly empty MCP configuration. Supply
invocation-local settings that
disable bypass mode and commit attribution, disable model fallback, require the
native command sandbox to start successfully, deny its network access, forbid
unsandboxed command retries, and deny writes to the resolved Git metadata
directories. Use native sandbox credential-deny entries so Bash commands cannot
inherit provider credentials without enabling subprocess hardening that
downgrades `auto` to Manual mode, and reject any reported permission-mode
fallback. Fail preflight when the host cannot enforce those settings. Plan-mode
turns derive their advertised read-only capability and invocation arguments
from the same access envelope. They do not expose editing tools, deny command
writes to the workspace and Git metadata, and set
`sandbox.autoAllowBashIfSandboxed: true` so repository inspection proceeds
without a prompt only inside the required native sandbox. Git workspace-write
turns share that envelope with the added Edit and Write tools and the
launcher-granted workspace write; the proved sandbox denies Git index, ref,
tag, remote, configuration and identity changes, outside writes, network and
Unix sockets under every access policy. File-tool Git-metadata denials bind
each resolved absolute protected directory, a protected path with rule, glob or
control characters fails before launch, and declared-directory turns keep
their Git-subcommand denials. Unsandboxed fallback and command network access
remain disabled. On Linux, prove read-only,
workspace-write, and local-commit turn policies independently with fixed,
model-free effective invocations. Prefer Claude's full native sandbox. Only a
recognized nested-user-namespace denial may select Claude's weaker parent
invocation through a Runner-private authenticated launcher. Keep the Claude CLI
outside the command boundary so provider credentials and transport remain
available, and install the launcher only for model-issued commands. It accepts
only the supported Claude bubblewrap grammar, rejects malformed, conflicting,
weakened, or unsupported arguments before spawning, adds the missing
Runner-owned restrictions, scrubs its token and credential environment, and
executes the pinned real bubblewrap binary once with the validated payload. The
fallback proof uses representative effective arguments through that identical
launcher validation, strengthening, and execution path. Each proof checks
workspace write authority, compound Git inspection, Git mutation and
outside-write denial, network and
Unix-socket denial, and credential removal, including denial of the provider
process's proc environment. Generic failures cannot enable the fallback, no
diagnostic is retained, and no proof selects a profile, authenticates, or
invokes a model. The separate local-commit executor proof remains required.
Each resolved role has a provider-neutral receipt slot; its receipt is pinned
when the role is first required and must match before later provider work. The
deterministic adapter gate uses controlled launcher coverage. After the
finalized commit is installed, a fresh real Claude lazy plan-authoring
acceptance must report successful preflight and a provider response before
dependent provider work continues.

Worker default:

```text
permission mode: auto
```

This is the preferred unattended mode because it removes routine user permission prompts while retaining Claude Code's background safety classifier.

If `auto` mode is unavailable for the installed Claude Code/account/model/provider combination, the adapter must **not silently fall back to Manual mode**.

For V1:

- fail preflight for a Claude Worker when autonomous execution cannot be provided safely;
- do not silently use unrestricted `bypassPermissions` on the host.

Reviewer and Arbiter:

```text
permission mode: plan
```

Do not enable bypass permissions in Reviewer or Arbiter sessions.

Use `--output-format stream-json --verbose --include-partial-messages` and
`--json-schema` for machine-actionable output. Validate bounded UTF-8 records,
derive progress only from recognized correlated lifecycle events, and retain
one terminal result for the existing output and failure checks.
Reject permission denials from a non-interactive turn instead of treating a
partial response as success. Pass an explicit model without a fallback chain
and reject a full model ID when the result's model usage reports a different
model.

Classify `permission_denials`, `api_error_status`, result subtype, and
`terminal_reason` before consulting at most one bounded native-text slice.
Expose only fixed error codes and messages plus a finite non-sensitive
diagnostic class. Never attach denied `tool_input`, provider result text, raw
standard error, or the native process error. A denial of an unexposed tool or a
Bash command outside the positive repository-inspection allowlist is terminal and
classified only by that fact, with an unknown refusal cause; see the
[provider permission classes](../../../docs/product/PROVIDER_MODEL.md#normalized-failures-and-recovery).
Role requests carry the established persisted required-check commands for that
diagnosis only, so a denial exactly equal to one is terminal
`permission_bash_required_check` rather than unclassified Bash. A closed native
refusal reason uniquely matched to every non-safe Bash denial in the batch
yields the terminal `permission_reason_<code>` class instead, without naming the
operation.
An exposed non-Bash tool or a positively recognized safe Bash inspection may be
a recoverable capability/configuration failure. For structured
API errors, treat only explicit transient HTTP statuses as provider unavailability;
fail closed on non-transient client statuses and `api_error` without such a status. Unknown
valid read-only result failures and unclassified read-only process exits are
recoverable; the same unknown outcomes during workspace-write or one-shot
commit work are not.
Explicit native transport, overload, model-busy, and server availability use the
injected runner coordinator after repository reconciliation. The exact role and
logical checkpoint survive five-second exponential backoff capped by the frozen
policy, with indefinite repeats at the ceiling. Scheduling and start are durable
and immediately visible; overdue recovery dispatches once. A successful provider
response resets the episode before output validation. A normalized authentication-
required response instead retires the superseded episode before its distinct
operator pause. Partial output, partial writes, session changes, resume, and
restart do not reset it. Safe partial
content and pending corrections survive; stale approvals are invalidated and the
same correction is not charged again. Check/fix mutation claims use the successful
attempt's starting fingerprint, after retained partial content is reconciled.
Source forks are never replayed. An
abortable wait retains exclusive ownership and honors immediate/deferred stops.
See the common [availability contract](../../../docs/ARCHITECTURE.md#durable-availability-episodes).

Map a trusted Claude alias only to its configured absolute isolated
configuration directory through `CLAUDE_CONFIG_DIR`. Map an explicit decimal
context size to the native `--autocompact` token window. Omit both controls for
`current`, and never accept profile-provided arbitrary environment or
credential material.

Fresh turns omit resume flags. Continuation uses `--resume <session-id>`, and a
supplied source session uses `--resume <session-id> --fork-session`; persist the
returned child ID and reject the source ID as invalid fork lineage. An
original fresh or forked Claude launch also receives the supported `--name`
flag from Runner context; continuation and compaction omit it. A verified child
is retained before a bounded metadata failure is returned, without a replacement
launch or replayed turn/commit. The [provider contract](../../../docs/product/PROVIDER_MODEL.md#sessions-and-context)
owns naming support, title bounds and acknowledgement timing. An
unavailable continuation may reconstruct a fresh turn, but an unavailable fork
source is an error. Classify source-session and continuation-session failures
from the attempted session mode. On a fresh turn, distinguish effective-profile,
authentication, and provider failures instead of reporting a generic missing
session, and retain no native error text.

Enable native auto-compaction for every turn. On an explicit context-exhaustion
result, retry the durable request once in the same session with compaction
instructions, then reconstruct it in a fresh session if the context remains
full. Never replay an interrupted `local-commit` turn.

On Linux, the isolated local-commit executor uses a probed `bubblewrap` profile
with a read-only host filesystem, writable workspace and resolved Git
directories, private temporary and runtime directories, and no network. The
Runner-owned executor proof is independent from the native Claude turn proof,
and `localCommit` requires both while native session and structured-output
capabilities remain CLI-derived. The agent confirmation turn retains the
read-only inspection policy; after confirmation the executor checks the expected HEAD, runs
`git add -A`, rechecks HEAD, applies fixed
unstaged-clean, staged-diff whitespace, and nonempty-diff hygiene, and creates
one subject-only commit with the exact supplied message. It preserves Git hooks and configured
identity, strips ambient Git redirection and sensitive command environment
values, and never adds Claude attribution. Report
`localCommit: false` when either applicable proof or Claude's required Linux
sandbox dependencies fail. Policy, capability, provider, or confirmation-
turn rejection before executor invocation carries `effectStarted: false`,
including `ERR_CLAUDE_LOCAL_COMMIT_POLICY`, while preserving the classified
profile, authentication, provider, continuation, or process error and its
recoverability; an executor failure does not carry the marker.

## Backend-neutral finalization guidance

Finalization is a dedicated pipeline gate, not a Codex-only or Claude-only
feature. A repository-defined skill may guide it, but the gate does not depend
on optional guidance being present.

Before bootstrap, the runner resolves the persisted policy with the root
configuration capability's confined, identity-bound Markdown inspection.
Legacy `skill` decisions keep their original Git inspection and fingerprinting.
For `auto`, it freezes the first safely inspectable canonical regular
conventional skill or a fallback decision when none qualifies. `none` freezes
the fallback directly. An explicit path must already identify a safely confined
canonical regular file. Missing or deterministically invalid explicit guidance
pauses before provider probing and requires a new run after repair.

Bootstrap and validation migration receive the frozen inventory label or fallback
decision. New `file` selections also supply the exact absolute read declaration.
They never receive copied procedure content or add a guidance-specific provider
turn. A selected skill is included in the
established validation-infrastructure inventory. Its exact path and
selected-file fingerprint are verified before bootstrap, validation migration,
finalization, bounded correction, and resumed work. Drift or later
unavailability requires a fresh run without consuming a fix or review round;
`auto` does not rediscover or switch to fallback during the run.

Bootstrap, migration and finalization instructions require reading the exact
selected entry and its mandatory repository references under existing read
authority. References controlling validation commands or gate behavior belong
in ordinary validation infrastructure, with its existing inventory, migration
and drift rules. Other documents are classified by responsibility. Neither
the request envelope nor selection grants parent-directory or external sibling
access, recursive retrieval, substitution or late fallback.

When the selected backend supports a resolved skill natively, it may invoke it
natively. Otherwise it reads and follows the instructions directly. Exact
runner-trusted authority and availability remain owned by the frozen trusted
snapshot, capability requirements, environment blockers, inventory matching,
and requirement inspection; the guidance decision grants no additional
authority.

The same repository finalization procedure must therefore work with either
Worker backend and without skill-specific guidance.

Phase ownership is also backend-neutral. Implementation and finding-resolution
turns reserve project finalization and generic commit preparation for their
dedicated phases. The finalization turn follows all substantive guidance but
keeps its inventory staging-independent. Staging, staged/index-relative
inspection, alternate-index workarounds, staged handoff, and commit-message
drafting belong to the constrained `COMMIT` executor. Applicable content checks
use `HEAD` or explicit trees. This deferral is not a validation blocker or a
skipped required check.

---
