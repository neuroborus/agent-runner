# Provider recovery

Read this topic when configuring provider inactivity or availability limits,
or recovering authentication and disposable sessions. [Configuration](configuration.md)
owns role preferences; [trusted validation](trusted-validation.md) owns command
deadlines and isolation. Use the [user documentation map](README.md) for other topics.

## Inactivity

`providerInactivityTimeoutMs` limits provider inactivity, with a conservative
`1800000` (30-minute) default. Root and project configuration accept integers
from `1` through `2147483647`; project configuration takes precedence. There is
no CLI or MCP override. Each run freezes and fingerprints the setting; resume
and legacy migration never reload it. Only validated semantic progress resets
the deadline. Owned local commands suspend it until every overlapping command
completes; keepalives, process liveness, and command output do not reset it.

Expiry records bounded recovery evidence before stopping the invocation. After
safe repository reconciliation, the same role can use its single fresh-session
reconstruction allowance without reforking the source. Native fresh fallback
uses that same durable allowance. A repeated expiry pauses as
`backend_unavailable` with `ERR_PROVIDER_INACTIVE`; an offered explicit resume
tries once without replenishing automatic recovery. Safe partial work and
correction accounting survive. CLI and MCP expose only the role, checkpoint,
attempt, and recovery status. Trusted commands, constrained commit execution,
runner-owned handoff, usage limits, operator stops, and availability backoff
retain their separate policies. See the provider contract (`docs/product/PROVIDER_MODEL.md#provider-inactivity`).

## Model catalog misses

A complete Codex catalog miss can pause an exercised explicit model for resume at
the same checkpoint. The Runner requires prior completion on the frozen role
and no effect from the failing invocation. The pause carries
`ERR_MODEL_CATALOG_RETRY` with reason `backend_unavailable`, or
`provider_interrupted` for init. The Runner keeps the exact role and checkpoint
internally; status shows the saved resume state and any offered action. Once
the model is available to the selected provider again, resume the same run
only when status offers the null action; it uses the same model, profile and
effort after
repository and input checks. Catalog recovery adds no automatic retry,
backoff, fallback model or source refork, and keeps reservations, counters,
and spent provider allowances. A first use, a source fork, a miss during
native recovery, an invalid or incomplete catalog (`model_catalog_invalid`)
and unsupported effort (`effort_unsupported`) authorize no retry.
A consumed commit authorization requires separate durable proof and Git
verification before it can be renewed. Invalid or incomplete catalogs and
unsupported effort grant no COMMIT retry. See the provider model
(`docs/product/PROVIDER_MODEL.md#normalized-failures-and-recovery`).

## Availability and authentication

`availabilityRetryMaxDelayMs` sets the frozen common availability-policy ceiling
for new runs. It accepts integers from `5000` through `2147483647` milliseconds,
defaults to `1800000` (30 minutes), and resolves project over runner configuration.
The initial delay is fixed at five seconds. Resume preserves the saved policy;
legacy runs use the default. Explicit transient availability failures in all registered
pipelines retry automatically after Git reconciliation. Delays double from five
seconds to the saved ceiling, then repeat there without a retry quota. A successful
provider response resets the episode; a normalized authentication-required response
retires it before entering the separate operator pause. Restart and partial work do
not reset it.
CLI activity and MCP status expose the role, checkpoint, reason, attempt, delay,
and deadline. A foreground CLI must be resumed after owner loss; detached MCP
work continues independently of client wait cancellation or disconnect.

Provider authentication is a distinct operator recovery. A normalized
authentication failure pauses any pipeline immediately after safe repository
reconciliation as `authentication_required`, with no availability retry or
backoff; any superseded availability episode is retired first. CLI and MCP show
the fixed `ERR_AUTHENTICATION_REQUIRED` code, the saved checkpoint, and one null
resume action without native provider details.
Reauthenticate the selected provider, then resume the same run; its roles,
session lineage, content fingerprints, and correction accounting remain
frozen. A failed source-session fork is retried only with no-effect proof;
possible-effect evidence resumes the same logical role fresh without reforking
the source. Commit readiness still verifies the existing pre-effect proof and
Git state before replacing a one-shot authorization.

## Session naming and reconstruction

Runner supplies active adapters with the full run UUID and bounded project,
pipeline and role descriptions, separately from client attribution. A verified
new child is durably acknowledged before its naming diagnosis is returned;
bounded naming diagnoses never authorize another turn or source fork. Both
providers use `[<full run UUID>] <description>` for new children, including
reconstruction. Codex names after acknowledgement and before its first model
turn. Claude passes the documented `--name` at fresh or forked launch, checks
installed flag support first, and retains a verified child before reporting a
metadata failure. Ordinary continuation preserves user-edited names. A rejected
Codex metadata RPC can continue the original turn; a rejected Claude launch or
unusable Codex naming transport pauses without replay or fallback launch.
See the session contract (`docs/product/PROVIDER_MODEL.md#sessions-and-context`).

Backend sessions are disposable. When a native context is full, the adapter
compacts it and retries once; persistent pressure moves ordinary turns to a
fresh session reconstructed from durable run state, artifacts, and the current
workspace. Explicit source sessions retain strict identity and lineage.
Interrupted ordinary turns revalidate canonical paths, durable task inputs, and
Git controls before restarting from the complete request in a fresh native
session. Read-only turns still require an unchanged repository. Polishing
Worker turns may preserve partial content, but index drift is rejected; the
runner owns the later staging handoff. Plan-execution recovery retains its
pipeline-specific one-shot commit reconciliation.
Interrupted local-commit turns are reconciled from Git state and never replayed.
For a Codex App Server `usageLimitExceeded` rejection or an explicit Claude
rate, quota, credit, or spend-limit rejection, the rejected native turn is
invoked once and the pipeline pauses as `backend_unavailable`. Durable workflow
state and safe workspace changes are preserved, and resume reconstructs the
pending request from runner state.

## Failure classification

Codex rejects incompatible response schemas locally with
`ERR_INVALID_CODEX_SCHEMA` before provider activity. This terminal input error
does not trigger provider retries or output correction. Pipeline validation
still enforces constraints such as unique finalization finding IDs when the
provider-compatible schema cannot express them.

Codex recognizes bounded structured non-transient HTTP client errors even when
the native failure is marked `other`. HTTP 400 `invalid_request_error` /
`invalid_json_schema` is terminal `ERR_CODEX_TURN_FAILED` with
`turn_bad_request`; it does not trigger provider retries, output correction,
or `backend_unavailable`. Native error details are discarded.

A structurally valid Codex HTTP 401 authentication envelope becomes the shared
`authentication_required` disposition. HTTP 403, authorization or permission
failures, conflicting or malformed payloads, and other providers without an
equivalent descriptor contract remain outside it. The runner persists only the
fixed redacted pause and resumes the same logical checkpoint after the operator
reauthenticates; it never exposes the native message, URL, request identifier,
payload, or credential material.

Explicit Codex overload and both providers' normalized availability failures use
the shared durable backoff without immediate adapter retries. Opaque Codex
`turn_other` retains its bounded fresh reconstruction and pause path. Policy,
protocol, isolation, usage-limit, and ambiguous-effect outcomes retain precedence.
A failed source fork is reconstructed as the same logical role without forking
the source again. Commit-readiness availability rejection requires persisted
proof that the executor never started and unchanged Git verification before
retiring the consumed authorization and scheduling a fresh one. Potentially
executed effects remain verification-only; native error details are discarded.

For failures without explicit availability evidence, when bounded adapter
recovery ends in an eligible transient pre-effect launch
failure, the availability pause retains only `failureClass` and the `spawn`,
`initialize`, `session`, or `turn_start` checkpoint. CLI status renders
`Launch recovery: <checkpoint> (<failureClass>)`; MCP status returns the same
two-field `launchRecovery` value. Source-fork requests retain it only before
native forking can begin (`spawn` or `initialize`). In lazy mode that early
failure restores the unconsumed one-time fork marker when no child exists, so
resume performs the source fork once. A failure at `session` or `turn_start`
fails the run instead of offering a resume that could create a second child.
Resume clears the projection; an operator pause preserves it, and cancellation
clears it.
