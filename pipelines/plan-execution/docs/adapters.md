# Execution Agent Adapter Contract

Read the affected sections before changing this contract. Use the [topic map](README.md)
for related owners and required reading routes.

## Agent Adapter Contract

Keep the backend abstraction small and functional.

Conceptually:

```js
const backend = {
  id: "codex",

  async probe() {
    return {
      version: "...",
      structuredOutput: true,
      readOnly: true,
      autonomousWrite: true,
      gitMetadataWriteBlocked: true,
      workspaceWrite: true,
      localCommit: true,
      remoteWriteBlocked: true,
      nativeSessionContinuation: true,
      nativeSessionFork: true,
    };
  },

  async run(request) {
    return {
      output: "...",
      structured: {},
      sessionId: "optional",
    };
  },
};
```

A request should contain only runner-level concepts such as:

```js
{
  cwd,
  access: "read-only" | "workspace-write" | "local-commit",
  prompt,
  recoveryPrompt, // optional; defaults to prompt
  onProgress, // optional synchronous observer of internal normalized progress
  onFreshSession, // optional awaited reservation of the single fresh allowance
  onCommitExecution, // optional awaited boundary after readiness, before effects
  effort: "current" | "low" | "medium" | "high" | "xhigh" | "max", // optional
  schema,
  session: { mode: "fork" | "continue", id }, // optional
  sessionNaming: { runId, project, pipeline, role }, // Runner-owned display data
  onSessionCreated, // awaited durable acknowledgement of a verified new child
  onSessionNaming, // awaited bounded metadata diagnosis; no execution authority
  authorizationId, // local-commit only
  commit: { expectedHead, message } // local-commit only
}
```

Active role turns carry the Runner-owned [session naming context](../../../docs/product/PROVIDER_MODEL.md#sessions-and-context).
The creation acknowledgement records a verified new child at this pipeline's
existing logical context key before a naming diagnosis or metadata failure is
returned; the eventual response does not record it twice. Naming diagnoses grant
no retry, source fork, replacement,
owner cycle or workflow/effect authority. Continuation preserves historical sessions.
Fresh commit-readiness children have their own context key and remain excluded
from ordinary Worker continuation; acknowledging them grants no full-role context.

Backend-specific CLI flags belong only inside the adapter.

The optional internal progress observer receives frozen `{ kind,
activeCommands }` records with the closed `semantic`, `local-command-started`,
`local-command-completed`, `local-tool-started`, and `local-tool-completed`
kinds. Only validated provider protocol events qualify; raw payloads,
identifiers, commands, output, and heartbeats never cross this boundary. The
count preserves overlapping command lifetimes, and remaining activity retires
with its owned process. The shared inactivity watchdog consumes this private
progress without changing availability backoff or exposing native events publicly.

Adapter effort is independent of the model identifier. Missing effort or
`current` omits the native override. Codex uses its reasoning-effort control;
Claude passes explicit `max` unchanged and maps legacy `xhigh` to its
advertised native `max` tier through `--effort`.
Explicit selections require native support, preserve every session/recovery
and commit-readiness path, and use discoverable model capabilities before a
turn. Unsupported selections and provider-only effort/model rejections return
non-recoverable `ERR_UNSUPPORTED_EFFORT` / `effort_unsupported` without native
diagnostics, downgrade, or availability retry. A rejected readiness turn keeps
the commit executor unstarted. See the provider model for the shared contract.

`probe()` validates installed CLI features and enforceable local isolation.
Codex also validates a selected named profile model-free on the App Server
startup path; a profile that does not apply there fails before any launch with
`ERR_UNSUPPORTED_CODEX_CAPABILITY` / `capability_native_profile` and is never
ignored or substituted. `probe()` does not attest that the profile's
authentication and provider are usable. The first real `run()` request uses the
effective profile and reports a bounded classified failure when it cannot be
used.

For non-commit turns, an adapter error may set `recoverable: true` only when
reconstructing and retrying the durable request is safe. Safety, protocol, and
isolation failures are not recoverable; an ambiguous `local-commit` outcome is
never retried and must instead return to Git-state verification.

The common Runner attempt/recovery surfaces retain nullable platform-validated
`ownershipDiagnostic` evidence independently of native sessions. The shared
[ownership diagnostic contract](../../../docs/ARCHITECTURE.md#bounded-ownership-failure-diagnostics)
owns its vocabulary, persistence compatibility and CLI/MCP projections. This
pipeline adds no diagnostic policy, retry, checkpoint or effect authority.
Capability pauses retain the trusted service's bounded blocker evidence. Caught
preflight, inspection and cleanup refusals use its pure `failureEvidence`
projection without changing pause codes or resume checkpoints.

The root agent boundary normalizes thrown failures through the selected
adapter's own finite diagnostic-class validator. It exposes only a fixed
message, bounded code, safe effect/recovery flags, the shared structured-output
class, and the validated adapter diagnostic class. Pipelines never duplicate
backend allowlists or receive native messages, denied inputs, prompts,
commands, responses, transcripts, credentials, or process causes.

When a requested structured result cannot be produced, each adapter retains
its backend-specific bounded error code and additionally exposes only the
shared `failureClass: "structured-output"` classification. Pipeline workflow
logic consumes that class rather than backend IDs or native error codes.

A `local-commit` adapter error may additionally set `effectStarted: false`
only when the adapter proves that its isolated commit executor was never
invoked. This marker is independent of `recoverable`: policy rejection may be
non-recoverable while provider unavailability is recoverable. The absent
marker is the safe default for executor failures and every other outcome that
could have started the effect. The runner never renews an authorization from
the marker alone. It first persists the bounded code and recoverable
classification on the consumed authorization, then Git must verify that no
commit was created. An interrupted verification retains that durable proof for
resume.

Claude recoverability is derived from a finite adapter-owned diagnostic-class
allowlist. Structured permission denials, HTTP status, result subtype, and
terminal reason take precedence over bounded message matching. Backend,
capability, configuration, usage, provider, and expected-tool permission
failures may be recoverable, but Bash permission recovery requires a positively
recognized safe repository inspection: an exact single-space command form,
including the `HEAD`-relative `git diff --check HEAD`. The normalized
`authentication_required` disposition enters the fixed durable
reauthentication pause; other authentication evidence, unexposed-tool and
unclassified-Bash denials whose refusal cause is unknown, and legacy
`permission_forbidden_operation` records remain terminal (see the
[provider permission classes](../../../docs/product/PROVIDER_MODEL.md#normalized-failures-and-recovery)).
Provider recovery requires an explicit transient HTTP status; non-transient
client statuses and an unqualified structured `api_error` fail closed. An
otherwise unclassified valid result or process failure is recoverable only for
a read-only turn. Denied tool input,
native result text, raw standard error, and process causes are discarded.

A Codex App Server `usageLimitExceeded` rejection or an explicit Claude rate,
quota, credit, or spend-limit rejection is recoverable backend unavailability,
but the rejected turn itself is never retried through compaction, a fresh
session, or provider fallback. Provider adapters own native recognition and
bounded diagnostic normalization; the pipeline consumes only the
backend-neutral recoverable failure. Persist
`backend_unavailable` with the resumable pipeline state, reconcile any prepared
one-shot commit authorization, preserve safe workspace changes, and enter
`WAITING_FOR_USER` after the single rejected invocation. Classified usage and
provider failures from non-commit writable turns use the same path only after
workspace and repository-control reconciliation. Unknown writable process
outcomes remain terminal. Resume reconstructs the complete request from durable
state rather than requiring the failed native session. These rules add no new
pipeline-state field, provider branch, or migration.

Every non-commit role routes that disposition only after repository-control and
safe workspace reconciliation. The pause contains exactly
`authentication_required`, `ERR_AUTHENTICATION_REQUIRED`, and the current
logical state, with no retry delay. A null resume preserves roles, session
lineage, fingerprints, findings, and correction accounting while rebuilding
the same request from durable state. Provider-native diagnostics are neither
persisted in the pause nor publicly projected. For a failed source-session fork,
normalized no-effect evidence permits the fork to be retried. Possible-effect
evidence instead persists only the role and logical context key, resumes the
same role in a fresh session without reforking, and clears that marker only
after a child session is durably recorded.
The pause and source-fork state are persisted atomically with active-turn
retirement. An interrupted write preserves recovery instead of converting the
run into a terminal failure. A partially completed finding-resolution round
retains its charged writable continuation even at the fix limit; it neither
consumes another round nor permits a new round beyond that limit.
If publication was interrupted before the pause was saved, authentication
during fresh recovery still preserves the earlier unrecorded source fork.

When a failure without availability evidence proves an eligible transient
pre-effect launch failure, the same pause also persists only
`launchRecovery: { failureClass, checkpoint }`. In lazy mode, a failed source
fork at `spawn` or `initialize` with no recorded child restores
`lazySourceForkConsumed: false` in that atomic pause transition. Resume rebuilds
the same request and performs the run's one successful fork without charging a
correction round, consuming commit authorization, or replaying work. Recovery
at later fork checkpoints is stripped because an unrecorded native child may
already exist; the failure is terminal for that request rather than exposing a
resume that could refork the source. Operator pause, resume, and cancellation
use the common state semantics.

Codex App Server `serverOverloaded` is a distinct recoverable provider
diagnostic. After turn-item policy, protocol, and isolation auditing, it uses the
shared durable availability coordinator, with no immediate adapter retry. An overload that
rejects local-commit readiness retains `effectStarted: false`; only Git proof of
no effect may retire and reauthorize the one-shot request.

When sandbox, IPC, loopback, process-isolation, missing-service, permission,
or comparable external constraints prevent nondelegated work, a writable
Worker turn returns structured `BLOCKED` with bounded reason and evidence.
A selected runner-trusted command's agent-sandbox limitation alone does not
block content repairs or semantic review; its execution belongs to `FINALIZE`. The pipeline persists `environment_blocked`; it does not
turn the external constraint into a code finding or weaken the sandbox,
network, process, or host temporary-directory boundary. Safe content remains in
the workspace. A content-changing finding-resolution turn invalidates stale
fingerprint-bound evidence and resumes at `REVIEW` in independent mode or
`CHECK_AND_FIX` in lazy mode; an unchanged turn resumes at `RESOLVE_FINDINGS`.
Initial implementation and finalization resume at their
original `IMPLEMENT` and `FINALIZE` checkpoints respectively.

`local-commit` is a one-turn capability used only after the runner's commit gate
and requires the `commit` constraint. It allows the Worker to stage and create
one ordinary local commit with the exact supplied message while the adapter
continues to block any other history/ref mutation, pushes, hosting-service
writes, and remote configuration changes. Fail preflight if the selected Worker
backend cannot provide that boundary; do not rely on prompt compliance alone.

Native session continuation is optional. Runner correctness must not depend on
it. `prompt` is the compact instruction and state delta for a compatible
continuation. `recoveryPrompt` is the complete durable request used for first,
forked, fresh, context-invalidated, compacted, or reconstructed turns. Continue
a persisted child only when its context key matches the accepted inputs, role,
and pipeline-owned checkpoint. The first eligible turn of each new primary or
review checkpoint forks a supplied source directly; never resume it or silently
replace an unavailable source.

Use structured output for all machine-actionable decisions:

- clarification readiness and questions;
- plan-revision requirements;
- blocking product-decision requests;
- review findings;
- Worker FIX/DISPUTE decisions;
- dispute reconsideration;
- arbitration;
- finalization pass/fail result.

Plain Markdown is acceptable for bootstrap/context summaries.

---
