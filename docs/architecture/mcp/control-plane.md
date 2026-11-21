# MCP Control Plane

Read the affected sections before changing this contract. Use the [topic map](README.md)
for related owners and required reading routes.

The MCP capability lives under `src/mcp/` behind its public `index.js`. The
index exposes only the control-plane and STDIO server contracts consumed by
the root runtime and capability tests; private service and detached modules
keep protocol schemas, projections, revision waits, and detached dispatch
within the capability.

## Shared capability tools

`update_check` and `update_apply` delegate to the single root update service with
the control plane's store. Both have strict schemas and no project/configuration,
source, role or run selectors. Apply requires `operatorInitiated: true` plus an
idempotency key; that acknowledgement is not authority inferred from task content.
Existing provider isolation keeps MCP disabled in pipeline sessions. Check is
read-only and on demand; apply is destructive and idempotent. Both declare their
fixed official registry interaction as open-world. Wait cancellation detaches only
the observer: receipt publication continues, and server loss recovers from the
persisted intent on the identical request. Neither restarts an MCP client or resumes
a run. CLI `update --check` and `update` use the same capability directly, without
constructing a pipeline or resolving project configuration; stdout contains one
bounded JSON result. Before effects, apply prints an automatically generated retry
key on stderr so an interrupted invocation remains retryable. Diagnostics stay on stderr.

## STDIO and tool surface

`agent-run mcp` exposes the same static pipeline registry and runner through the
official Node MCP SDK over STDIO only. The private `src/mcp/service.js` module
owns the nine pipeline-control tools: `pipelines_list`, `run_start`, `run_status`,
`run_activity`, `run_wait`, `run_respond`, `run_resume`, `run_pause`, and
`run_cancel`; it also owns the shared-capability tools `guidance_read` and
`guidance_update`, `update_check`, `update_apply`, the issue-management tools
`issues_list`, `issues_read`, and `issues_update`, and the
conditionally registered MCP-only `unexpected_issue_report`. It contains
transport schemas and concise projections, not a second workflow
implementation. The issue tools delegate directly to `src/issues/index.js`,
sharing the control plane's run store. Management tools stay registered when
issue reporting is disabled.
Standard output belongs exclusively to MCP; bounded
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
or other diagnostic data automatically. The shared capability validates the
same field bounds as the MCP schema. It first replays a completed receipt for
the lexically resolved request, then resolves the origin through the workspace
and external-state boundaries before action persistence. An enclosing Git
marker requires successful Git resolution to the canonical worktree root;
failed Git inspection never falls back to a directory. Without a marker,
controls-only workspace inspection rejects unsafe controls and bare metadata,
and the canonical selected directory is the origin. Source files are not read
or snapshotted. The origin grants no storage or Git-effect authority; no
configuration is loaded and `projectConfigurationPath` only remains part of
the request identity.

Issues live in one private per-user store selected from environment, home, and
platform inputs injected at composition: `$XDG_DATA_HOME/agent-runner/issues`
on Linux, with unset or relative XDG values falling back to `~/.local/share`,
user Application Support on macOS, and `%LOCALAPPDATA%` on Windows. Mapping
requires bounded safe absolute paths and grants no execution-platform support.
The store must neither contain nor lie inside the origin project, the state
root, the user settings file, the installation, or the installed runtime
payload root; ordinary shared parents such as `agent-runner/` are allowed.
Every path component is opened without following links; missing components
are created with mode `0700`, and the final directory must belong to the
current user without group or other access. Operations use the
descriptor-bound directory and reverify each component identity and the
store's private ownership, so link, permission, or replacement attacks fail. Publication never touches the project or its ignore
rules.

Each issue is `<issueId>.json`, a canonical, bounded, schema-versioned JSON
document whose random UUID v4 ID is bound to its filename. It holds the
immutable rendered Markdown with its SHA-256 hash and one authoritative
tracking record: revision, a finite status (`open`, `queued`, `in_progress`,
`resolved`, or `dismissed`), origin name and canonical path, creation and
update times, optional run ID and error code, bounded plan and resolving commit
references, and an optional note. Creation writes revision `1`, status `open`,
and empty tracking metadata. Strict parsing rejects unknown or duplicate
fields, non-canonical bytes, and invalid IDs, statuses, hashes, or bounds.

Management opens the store without creating it; a missing store is an empty
backlog. It loads no configuration, inspects no origin, constructs no pipeline,
and takes no worktree lease. Listing reads every published `<issueId>.json`
through the descriptor-bound directory (at most 10,000 entries), skipping
hidden reservation files, foreign names, and a document still hard-linked to
its bound creation file. Exact filters compare the recorded origin path and
status; results sort by `createdAt`, then ID, with pages of 1 to 100 (default
50). The opaque base64url cursor holds the last key and a hash of the store
path, directory identity, and canonical filters; any other binding fails with
`ERR_INVALID_ISSUE_CURSOR`. Read returns Markdown, tracking, `documentHash`
(SHA-256 of the document bytes), and the path; absent and unfinished issues
fail with `ERR_ISSUE_NOT_FOUND`.

`issues_update` sets only `status`, `planReferences`, `commitReferences`, and
`note`; omitted fields are unchanged, `[]` and `null` clear, and at least one
field is required. It requires `expectedRevision`, `expectedHash`, and an
idempotency key. A mismatch fails with `ERR_ISSUE_REVISION_CONFLICT` without
mutation. Success increments the revision, advances `updatedAt` monotonically,
and returns `{ issueId, revision, documentHash }`.

`agent-run issues list`, `issues read`, and `issues update` call the same
service methods directly from `src/cli.js` with the CLI environment, without
constructing a runner, loading configuration, or consulting `issueReporting`.
They map `--origin`, repeatable `--status`, `--limit`, `--cursor`, `--issue`,
`--expected-revision`, `--expected-hash`, repeatable references, and `--note`
onto the shared inputs; `--clear-*` flags supply `[]` or `null`, and combining
a value with its clear flag fails before dispatch. Admission receives no origin
path, so the list filter remains uninspected. Stdout carries one JSON result;
an update without `--idempotency-key` first prints its generated key on stderr
and adds it to the receipt, under the same `issues_update` action identity as
MCP. Errors print their message on stderr with exit code `1`. Creation remains
MCP-only.

## Run-start schemas

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

V1 does not require the MCP Tasks extension, a network transport,
authentication, or a daemon.
