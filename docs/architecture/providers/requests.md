# Provider Requests

Read the affected sections before changing this contract. Use the [topic map](README.md)
for related owners and required reading routes.

## Model-Free Deadlines and Discovery Bounds

Every model-free subprocess used for version/help, Claude `socat` and isolation
policy checks, the local-commit executor proof, or owned-process namespace
proof has a 10-second deadline. Within that outer bound, a local-commit probe
has a one-second network-denial observation deadline; silence cannot prove
isolation, so exhaustion fails the capability closed. Claude's per-turn Git
metadata preparation uses the 10-second bound. Codex's pre-effect local-commit
Git metadata lookup uses a 60-second bound; Claude's pre-effect local-commit
Git metadata lookup retains the 10-second bound. These preparation deadlines
do not cap the authorized commit effect after it begins. Codex MCP configuration
discovery is the deliberate exception: it makes at most two `mcp list` attempts
with a 30-second subprocess deadline apiece and no added retry delay, then reports
recoverable provider unavailability. Codex model-catalog discovery issues at
most 32 page requests with a requested limit of 100 entries per page, and
rejects a repeated cursor. The 256-name MCP configuration capacity and
catalog-page cap are schema and protocol defenses, not operator-configurable
work budgets.

## Portable Effort

The shared adapter contract accepts optional `effort` in execution options and
turn requests, validated by each registered provider through that contract.
Its closed vocabulary is `current|low|medium|high|xhigh|max`; omission and `current`
normalize to no override. Model identifiers cannot contain whitespace, so a
combined model-and-effort string is rejected before provider activity.
Native translation stays within the providers: Codex supplies
`model_reasoning_effort` at process launch and `effort` on every `turn/start`;
Claude supplies `--effort`, passing explicit `max` unchanged and retaining the
legacy translation of portable `xhigh` to native `max`.
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

## Required-Check Diagnostic Attribution

The shared request contract accepts an optional diagnostic-only
`requiredCheckCommands` array of at most 512 non-empty commands of at most
4,000 characters without NUL, matching the pipelines' aggregate validation
capacity, and stores a frozen copy. Polishing and plan-execution role requests
pass the established persisted inventory commands unchanged; it never enters
prompts, native arguments, settings, storage, events or failure records, and
Codex ignores it. Claude labels a denied non-safe Bash command
`permission_bash_required_check` only on exact string equality with one of
them; that terminal class ranks below unexposed, unclassified Bash and malformed
entries and above the capability fallback.
