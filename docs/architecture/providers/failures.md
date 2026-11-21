# Normalized Provider Failures and Recovery

Read the affected sections before changing this contract. Use the [topic map](README.md)
for related owners and required reading routes.

## Claude Failure Precedence

Claude turn failures use a finite adapter-owned diagnostic allowlist. Structured
`permission_denials`, `api_error_status`, result subtype, and `terminal_reason`
take precedence over bounded message matching. The adapter discards denied tool
input, native result text, raw standard error, and process causes; only its
fixed code, fixed message, allowlisted class, and safety fields cross the
boundary. Authentication remains terminal. A denial of an unexposed tool or of a
Bash command outside the narrow positive repository-inspection allowlist is
terminal and classified only as an unexposed tool or unclassified Bash whose
refusal cause is unknown. The allowlist matches whole single commands whose
tokens are separated by exactly one space, including the `HEAD`-relative
`git diff --check HEAD` content check; see the [provider permission classes](../../product/PROVIDER_MODEL.md#normalized-failures-and-recovery).
On both completed and failed exits, the permission path passes the stream and
the result session to classification. When every denial in the batch carries a
valid, unique `tool_use_id` and every non-safe Bash denial has the same code
from the bound stream lookup, the batch is the terminal
`permission_reason_<code>` class, which replaces unclassified Bash and outranks
the required-check label but never an unexposed or malformed entry. A missing,
invalid or repeated id, or any missing, unknown, conflicting, mixed or unbound
reason, keeps the operation classes.
Only an expected non-Bash tool or a positively recognized safe Bash inspection
may be a recoverable capability or configuration failure. Structured provider
recovery accepts only explicit transient HTTP statuses; non-transient client
statuses and an `api_error` without a transient status fail closed with a fixed
request-rejected error.

The shared failure record optionally carries `availabilityReason`, restricted to
`transport_unavailable`, `temporarily_overloaded`, `model_busy`, and
`server_unavailable`. The adapter contract and registry accept this evidence only
with transient retry eligibility, a `not_started`, `rejected`, or `exited`
outcome, and no started effects. A commit checkpoint additionally requires
validated `commitExecutor: "not_started"` proof. Possible workspace changes still
require repository reconciliation; ambiguous outcomes cannot carry this evidence.

The same exact record may instead carry the finite optional `disposition`,
either `authentication_required` or `output_exhausted`. The contract accepts it
only for a terminal rejected response without started-effect evidence, process
outcome, or availability evidence. These dispositions remain separate from
availability, authorization, permission, usage-limit, malformed-request, and
ambiguous-effect classifications.

## Availability Recognition

Provider-private availability recognition maps explicit offline, DNS, refused or
reset connections, timeouts, overload, and model-busy errors. Both adapters map
statuses 408, 425, 500, 502, 503, 504, and 529 to the same finite reasons. Codex
also recognizes native connection/stream and internal-server variants through
closed variant payloads. Its private HTTP-wrapper parser requires bounded,
duplicate-free envelopes; matching transient native statuses may be corroborated
by closed server-error wrappers. Conflicting or malformed evidence cannot qualify.
Only native server-error RPC codes can establish availability at `turn/start`;
protocol/request codes retain precedence. Native text is bounded to 16 KiB for
Codex and below Claude's 4 KiB diagnostic truncation bound. Terminal evidence
excludes an availability reason, and existing structured classifications retain
precedence over text. A Claude budget-exhaustion terminal reason precedes transient
statuses but cannot replace a structured authentication, request, or output
rejection. Killed processes cannot use even parseable diagnostics to hide
uncertain effects.
Unknown errors receive no availability reason. Explicit eligible evidence enters
the runner's durable availability coordinator after repository reconciliation;
other failures retain their bounded recovery, pause, or terminal outcomes.

## Usage Rejections

Codex App Server `usageLimitExceeded` and explicit Claude rate, quota, credit,
or spend-limit rejections bypass context recovery and provider fallback. Their
adapters own native recognition and expose only bounded normalized diagnostics;
pipelines consume the backend-neutral recoverable failure. Other allowlisted
backend, capability, configuration, usage, and provider failures use the same
durable pause path.

## Output Exhaustion

Codex recognizes output exhaustion only from the exact native message
`Incomplete response returned, reason: max_output_tokens` in a failed
completion whose `codexErrorInfo` is the unit `other` variant. App Server
`turn/start` request errors qualify with the same exact message, a server-error
RPC code (`-32603` or `-32000`), and the standard exact `code`, `message`, and
optional opaque `data` shape. Other variants, variant payloads, additional
details, RPC data, tool output, malformed or oversized messages, and prose
lookalikes cannot establish exhaustion. Protocol validation and reported-item
auditing precede completion classification. The adapter emits only fixed
`ERR_CODEX_OUTPUT_EXHAUSTED`, `turn_output_exhausted`,
`disposition: "output_exhausted"`, and `Codex response output was exhausted.`
diagnostics with terminal retry eligibility. This bypasses automatic fresh
replay, availability and quota recovery, structured-output correction, and
compaction; only explicit native context-window exhaustion invokes compaction.
Source forks remain isolated and rejected local-commit readiness retains
`commitExecutor: "not_started"`. Native evidence is discarded. The incomplete
reason establishes neither a numeric output ceiling nor context utilization,
and does not complete missing or incomplete usage accounting.

Each pipeline consumes normalized output exhaustion through its own durable
`output_exhausted` pause after process/resource retirement and repository safety
checks. Its closed pause retains only the fixed `ERR_OUTPUT_EXHAUSTED` code,
resume state, role, and complete logical checkpoint. CLI/MCP project bounded
checkpoint evidence and explicit retry or new-run guidance. Exhaustion supersedes
availability backoff without authorizing replay, compaction, or output correction.
Execution and polishing preserve safe partial writes, invalidate affected gates,
and persist charged correction work atomically with the pause. Explicit retry
reconstructs the saved request without reforking a possibly created source child
or replenishing recovery allowances. Compatibility-named authentication source-
fork markers also protect this rejected disposition. Consumed commits remain
verification-only; only validated not-started proof plus unchanged Git
verification can retire an unused authorization. Pipeline specifications own the
exact recovery and gate policies.

## Codex Failure Precedence and Retry

Other Codex App Server `other` failures use bounded native HTTP error recognition
before opaque recovery. A complete `unexpected status` wrapper with an
allowlisted non-transient client status and a parsed JSON `error` envelope
becomes terminal `ERR_CODEX_TURN_FAILED` / `turn_bad_request`, with the fixed
message `Codex turn failed.` and `recoverable: false`. This includes HTTP 400
`invalid_request_error` / `invalid_json_schema`; it starts no compaction, fresh
retry, backend-availability pause, or output correction.
Recognition is limited to 16 KiB, statuses 400, 401, 403, 404, 405, 413, 415, and
422, and a shallow envelope with scalar `message`, `type`, `param`, and `code`
fields. The type must identify an invalid request, or authentication/permission
failure at status 401/403 respectively. Optional non-null codes must be in the
adapter's finite client-error allowlist. Optional native URL, CF ray, and request
ID suffixes are discarded. Unknown codes, malformed JSON, duplicate fields or
metadata, inconsistent status text, oversized evidence, transient statuses,
and prose lookalikes remain opaque; additional details and variant payloads
are never alternative sources for this client-envelope refinement.
Within that parser, only status 401 with `authentication_error`, an absent or
null parameter, and an absent, null, or `invalid_api_key` code establishes the
shared `authentication_required` disposition. Completion evidence must agree
with any native HTTP status. App Server request errors additionally require a
native server-error RPC code and the standard exact `code`, `message`, and
optional opaque `data` shape. HTTP 403, permission/authorization evidence,
conflicting status or client codes, non-null parameters, unknown request-error
fields, and protocol/request RPC codes remain outside the authentication path.
The resulting fixed failure retains none of the native message, URL, request
ID, payload, or credential material. Claude and future providers remain
unchanged until their descriptors own an equivalent bounded classifier.
Opaque failures retain `turn_other`; the native `serverOverloaded` variant maps
to `turn_server_overloaded`. Both classes are recoverable after the turn-item
audit unless output exhaustion is recognized or a validated client envelope
rejects the request. Explicit native transport/server availability is
recoverable after the same audit. Neither path retains native messages,
variant payloads, additional details, or causes.
Completion notifications and hydrated turns accept only `completed`, `failed`,
and `interrupted` statuses before failure classification. For these failures,
the existing item audit and explicit-model reroute guard still reject policy,
protocol, and isolation violations before classification or recovery. For
recoverable non-commit failures without availability evidence outside a source fork, the existing recovery
path attempts one fresh session with the complete `recoveryPrompt` and observed
workspace. The failure itself does not request compaction, and the second
attempt's failure propagates unchanged without another reconstruction. Source
forks remain ineligible for adapter fallback; the runner reconstructs an eligible
availability failure without reforking its source. Local-commit readiness failures
record that the commit executor did not start; the boundary-derived
`effectStarted: false` projection therefore keeps an overload rejected before
the isolated executor as a proven pre-effect rejection.
Executor outcomes remain on their verification-only path and are never
replayed.

## Backend-Unavailable Pauses

An otherwise unclassified valid read-only result or process failure is
recoverable only because the enforced read-only envelope and the pipeline's
post-turn repository guard prove that it could not mutate the repository.
Unknown writable process outcomes remain terminal after reconciliation;
classified usage and provider failures may pause only after safe workspace
changes and control state have been reconciled. After the adapter's applicable
retry policy is exhausted for failures without availability evidence, the owning
pipeline persists `backend_unavailable`,
the exact resumable workflow checkpoint, reconciled one-shot authorization
state, and any safe workspace changes before entering `WAITING_FOR_USER`. An
eligible normalized transient launch failure also persists only
`launchRecovery: { failureClass, checkpoint }`. Eligibility requires `none`
effect evidence, a `not_started` or `exited` outcome, one of `spawn`,
`initialize`, `session`, or `turn_start`, and no commit-executor evidence.
Deterministic incompatibilities, ambiguous effects, turn and commit failures,
and provider-native details remain ineligible. Resume clears the pause and
reconstructs the same durable request after availability returns. The optional
pause field requires no state-version migration.

## External Environment Blockers

A Worker returns a bounded structured blocker when sandbox, IPC, loopback,
process-isolation, missing-service, permission, or comparable external
constraints prevent work not delegated to an exact selected runner-trusted
command. A selected command's agent-sandbox limitation alone cannot block
applicable content repairs or semantic review; another command's selection
does not suppress a genuine blocker. Plan execution and polishing
persist `environment_blocked` rather than treating that condition as a code
failure, preserve safe workspace content, and invalidate any stale
fingerprint-bound candidate, finalization, and confirmation evidence. A
content-changing finding resolution resumes at `REVIEW` in independent mode or
`CHECK_AND_FIX` in lazy and combined modes; an unchanged turn resumes at its original
checkpoint. Finalization always resumes at `FINALIZE`. The workflow does not
weaken isolation or grant network or host temporary-directory access to bypass
the unavailable validation.

## Closed Failure Record

Adapter failures retain only bounded diagnostics. Every adapter classification
produces the same closed record: `failureClass`, `checkpoint`, `outcome`,
`effect`, and `retry`, with optional commit-executor proof, finite availability
reason, and an optional sanitized process outcome containing only an exit code
or signal.
`commitExecutor: "not_started"` is valid only at the `commit` checkpoint with
`none` or `possible` effect evidence; it is invalid with `started` evidence or
at any other checkpoint. Checkpoints are `probe`, `spawn`, `initialize`,
`session`, `turn_start`, `turn`, or `commit`; outcomes, effect evidence, and
retry eligibility are likewise finite shared vocabularies. The shared launch
classes cover process exit and version, argument, protocol, and configuration
incompatibility. Deterministic incompatibilities are terminal; process-exit
eligibility remains explicit in the record. The contract rejects unknown
fields, unbounded values, and contradictory combinations. Capability probes
produce a proof containing the version, required capabilities, and the existing
`adapter-capabilities-v1` policy receipt.

## Launch Recovery Projection

The root boundary derives launch recovery only from that validated record and
never from raw provider causes. The frozen projection contains exactly the
normalized failure class and checkpoint. Without availability evidence, fork
requests retain it only at
`spawn` and `initialize`; a later eligible checkpoint keeps its normalized
failure record but cannot enter pipeline retry policy. All other requests may
retain any eligible launch checkpoint. CLI and MCP status read the same
persisted projection, including through an operator pause. Accepted resume
removes it with the pause, while terminal cancellation removes it from the
retained private checkpoint.

## Boundary Projection and Effect Proof

Codex capability, isolation, prohibited-operation, and recognized App Server
failures and Claude session, profile, authentication, backend, capability,
configuration, usage, provider, permission, and process failures remain native
recognition owned by their provider directories. The root agent boundary
validates the descriptor classification once, derives pipeline control
properties only from the shared record, and maps an unclassified cause to a
terminal rejected outcome with possible effects. Its error message is composed
only of fixed text, the pattern-validated code, and the registry-validated
non-generic class: `Agent backend turn failed: CODE (class).`, `Agent backend
turn failed: CODE.`, or `Agent backend turn failed.`; direct CLI failures print
that line. When an ambiguous provider turn precedes a local commit, the record
retains its possible provider effects and may separately prove that the
isolated commit executor never started. The
boundary derives `effectStarted` solely from that validated record; raw cause
fields cannot override it. It does not duplicate backend class lists or
traverse native cause chains. Every pipeline may persist the normalized class
for a terminal failure and projects it only through a deterministic CLI/MCP
explanation. Native messages, additional details, denied input, provider
responses, prompts, commands, credentials, transcripts, and process causes
never cross that boundary or enter durable state.

Codex `subAgentActivity` or another collaboration audit signal remains a
terminal `operation_multi_agent` isolation failure even though collaboration is
disabled at launch. A backend that ignores that disabled capability cannot be
accepted, reclassified as an environment blocker, or transparently retried.
Context exhaustion and interruption retain their dedicated recovery paths.
