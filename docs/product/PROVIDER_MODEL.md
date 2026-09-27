# Provider Model

Agent Runner supports Codex CLI and Claude Code as independent role backends.
The pipelines consume one small normalized turn contract; provider-native
processes, flags, profiles, protocols, sandbox behavior, sessions, and parsing
remain adapter concerns.

## Selection and capabilities

Each active role resolves a backend plus optional trusted profile, native model,
and context-size selection. `current` means the provider's effective native
selection rather than a model ID chosen by Agent Runner. A trusted profile is
defined only in runner-local configuration and pins one backend. Project
configuration may select its alias but cannot define credentials, binaries, or
arbitrary environment values.

Configured inactive roles are validated, but lazy mode neither resolves nor
probes them and does not persist or publicly expose their provider-private
values. Combined pipelines resolve their primary role, Reviewer, and on-demand
Arbiter like independent mode. Its added primary turns do not share the
Reviewer session; the Arbiter always starts fresh.

Before work, an adapter proves the capabilities required by the role: structured
output, read-only inspection, safe workspace writes when applicable, remote
write blocking, native session behavior, and constrained local commit when the
pipeline needs it. A capability probe does not prove authentication or provider
availability; the first real turn under the selected profile establishes that.

Adapter execution options and turn requests also accept the portable effort
values `current`, `low`, `medium`, `high`, and `xhigh`. Effort is separate from
the model identifier; identifiers containing whitespace, including combined
model-and-effort strings, are invalid. Missing effort and `current` omit the
native override and preserve the provider's effective default.

Codex maps explicit effort to its reasoning-effort configuration and turn
control. Claude uses `--effort`, mapping `xhigh` to native `max` only when the
installed CLI advertises that tier. Explicit selections require native support;
`current` adds no capability requirement. Codex checks discoverable model
reasoning tiers before starting a turn, including the effective model of a
continued or forked session. Model-specific support that cannot be discovered
locally remains subject to provider rejection. Effort survives continuation,
forking, compaction, fresh reconstruction, and local-commit readiness.

Unsupported explicit selections and provider-reported effort/model
incompatibilities produce terminal `ERR_UNSUPPORTED_EFFORT` with the bounded
`effort_unsupported` diagnostic. They never silently downgrade, enter
availability retry, or expose native error text. Rejected commit readiness
retains `effectStarted: false`; the commit executor does not run.

## Registration

Providers are registered through one frozen, source-controlled descriptor list.
Each descriptor binds a backend ID to its adapter factory, execution-option
validation, trusted-profile rules, source-session capability, and native
failure classifier. Configuration, runner construction and source checks,
failure normalization, and MCP backend discovery all consume that list. Adding
a backend is one explicit repository change rather than a plugin installation
or a set of provider branches in pipeline policy.

Tests may inject a complete fake descriptor to prove the seam. Production
registration is fixed at process startup and does not load descriptors from
configuration, target repositories, provider storage, or the network.

## Sessions and context

Native sessions are disposable execution context, never durable workflow
state. Every turn has a complete recovery prompt reconstructed from persisted
inputs, summaries, decisions, fingerprints, and repository evidence. A
compatible session may be continued as an optimization, but interruption and
context exhaustion can recover in a fresh session without changing correctness.

An operator may deliberately provide a source session. Independent mode and
combined mode fork it separately into primary and review checkpoints so the Reviewer does not
inherit the primary agent's reasoning. Lazy mode forks it exactly once into the
logical primary role for the entire run. The source ID remains opaque, profile
compatibility is checked before work, and a failed fork never silently becomes
an unrelated fresh context.

## Isolation and effects

Read-only turns cannot change repository content or Git control state.
Workspace-write turns may change safe content but cannot write Git metadata.
Codex uses a runner-owned private temporary root for writable attempts; Claude
advertises each access mode only after its effective isolation policy is proven.
Remote writes remain blocked in every access mode.

Claude prefers its full native sandbox. If and only if the exact effective
probe recognizes nested-user-namespace denial, it may use weaker native nesting
inside a Runner-owned command boundary with private user, PID, mount, and
network isolation plus private `/proc`, `/tmp`, and `/run`. The Claude CLI stays
outside that boundary so its authentication environment and provider transport
remain usable. A short-lived provider-private launcher applies the boundary
only when Claude starts a model-issued command. The direct model-free fallback
probe invokes that same launcher, outer arguments, and access-specific
topology. It keeps the host root read-only, makes only workspace content
writable for workspace-write access, re-binds all Git metadata read-only, and
proves IP and host Unix-socket isolation, credential removal and provider-proc
secrecy, workspace authority, and outside-write denial. The proved fallback
skips only the redundant inner Unix-socket seccomp layer; native policy remains
stricter. It does not require host `CAP_SYS_ADMIN`, change host policy, or
expose host procfs. A generic sandbox failure, incomplete proof, launcher
failure, or cleanup failure leaves the affected access mode unavailable. There
is no configuration switch that forces or weakens this selection.

The runner holds one provider-neutral receipt slot per resolved role and
persists only a fingerprint and supported-access list when that role is first
required. Resume and reconstruction must reproduce the receipt before later
provider work, so a host or CLI policy change cannot silently widen authority.
Pipeline descriptors declare their role access needs; unsupported access uses
the same early bounded diagnosis through CLI and MCP for every provider.

Codex model-issued commands derive from the provider process environment only
through a strict shell policy. Automatic secret-name exclusions run before
explicit workspace values, and an exact allowlist retains Codex's standard core
names, the dynamic `AGENT_RUNNER_OWNED_PROCESS` proof, and the supplied workspace
environment names. Unrelated parent variables remain unavailable, while the
provider process keeps its existing environment for authentication and provider
connectivity.

Plan execution's local commit is a separate constrained adapter capability. It
is available only for the Worker's one-shot authorized `COMMIT` turn and does
not widen ordinary workspace-write access. Codex readiness may use the
read-only `git var` subcommand to inspect the repository's existing author and
committer identities; staging, commit, configuration, history, ref, and remote
mutations remain outside that turn. Polishing never requests local commit.

Model-free capability subprocesses for CLI, sandbox, commit-executor, and
process-containment proofs each have a fixed 10-second deadline. Within that
bound, a local-commit probe has a one-second network-denial observation
deadline and fails closed when a silent socket cannot prove isolation. Both
providers' pre-effect local-commit Git metadata lookups also use the 10-second
bound; this preparation deadline does not cap the authorized commit effect
after it begins. Codex MCP configuration discovery needed to construct
isolation gets at most two attempts with a 30-second subprocess deadline apiece
and no added retry delay; exhaustion reports provider unavailability before a
model turn. Codex model-catalog discovery makes at most 32 page requests, each
asking for 100 entries, so a malformed or cyclic provider response cannot make
discovery unbounded. These are protocol and safety bounds rather than user-work
budgets, so they are intentionally not configuration settings.

## Normalized failures and recovery

Provider requests may carry runner-owned abort and process-registration
callbacks. The adapter keeps these out of prompts and provider configuration.
Owned supervisors wait for durable registration, including their bounded
launch-time boot/PID/start ancestry baseline, before launching work. Live
supervision and owner-loss recovery receive the same frozen evidence and may
exclude a new unrelated process only after its stabilized lineage reaches an
unchanged baseline identity. A baseline anchor never bypasses observed session
or ownership-token evidence; missing legacy evidence remains conservative. A
provider adapter declares `native-sandbox-provider` only for an
execution that requires a native sandbox. That mode uses a private PID
namespace only after the complete nested namespace shape is proven; when
nesting is unavailable on the initial host namespace, it may instead use the
narrow session/token ownership mode while its mandatory provider sandbox still
enforces command isolation. Ordinary owned processes cannot use
that host fallback. A runner exercised inside the already-private
trusted-validation namespace retains the distinct owned-session path when
that sandbox denies nested namespace creation; the enclosing namespace still
contains otherwise detached descendants. Cancellation or runner loss
retires the owned containment before reconciliation can release ownership.
Completion retries incomplete descendant evidence only within one fixed
one-second descendant-grace deadline. Persistent uncertainty retains
the original ownership failure. Before returning it, the current owner uses the
private child handle and control channel for one bounded teardown and clears
the durable registration only after proving the owned session empty. Otherwise
registration remains for later replacement-lease recovery; no adapter signals
a host PID from persisted identity.
Codex races App Server work against owned-completion rejection so an ownership
failure cannot remain hidden behind an open protocol request. It preserves the
original ownership failure through bounded cleanup; successful ownership
completion still requires the protocol operation to produce its result. App
Server shutdown allows up to one second each for natural close, TERM, and KILL.
Those post-turn phases and the descendant grace are fixed containment
invariants rather than configurable provider-work timeouts.
Unavailable containment fails before provider execution. Every fresh
or recovery attempt checks the abort signal. A constrained commit that may already have begun stays
on the verification-only path; a proven pre-effect interruption retains that
bounded proof for safe recovery.

Adapters classify native failures into a finite provider-neutral control
surface. Authentication, unsafe permissions, forbidden collaboration,
isolation failure, invalid contracts, and ambiguous writable outcomes fail
closed. Allowlisted backend, capability, configuration, usage, provider, and
source-session availability failures may enter a durable pause only after the
runner proves the repository is safe.

An ordinary non-commit turn with native context exhaustion may receive at most
one in-session compaction retry of the complete request when it has a usable
native session. Persistent pressure outside a source fork can then enter the
single fresh reconstruction path; neither recovery mechanism loops or falls
back to a different provider.

Codex validates response-schema compatibility locally before provider activity,
including its own local-commit readiness schema. Unsupported declarations such
as `uniqueItems` fail with terminal `ERR_INVALID_CODEX_SCHEMA`, without a
provider turn, retry, or output-correction attempt. Provider-compatible schema
declarations do not replace deterministic pipeline validation: both
plan-execution terminal roles still reject duplicate finalization finding IDs,
out-of-bounds or non-member IDs, and IDs outside rejected terminal results.

Codex refines native `other` failures only when bounded, validated HTTP status
and structured error-envelope evidence identify a non-transient client error.
For example, HTTP 400 `invalid_request_error` / `invalid_json_schema` becomes
terminal `ERR_CODEX_TURN_FAILED` with `turn_bad_request`, a fixed message, and
no provider retry, availability pause, or output correction. Raw error text,
payloads, and additional details are discarded after classification. Malformed,
oversized, ambiguous, or transient-status evidence does not become a bad request.

The remaining Codex `turn_other` and the explicit native `serverOverloaded`
variant, normalized as `turn_server_overloaded`, are recoverable provider
failures. The adapter audits reported turn items first so policy, protocol, and
isolation violations retain precedence. An ordinary non-commit request uses the
existing single fresh reconstruction from its complete persisted recovery
context and the observed workspace. A second failure returns to the pipeline
without another adapter retry and pauses as `backend_unavailable` at the safe
checkpoint when it remains recoverable. Writable workflows first reconcile safe
workspace changes and invalidate stale fingerprint-bound evidence. A source
fork is never replaced by fresh context. Local-commit turns bypass this retry:
a rejected readiness turn, including overload, reports that the executor never
started, and any uncertain commit effect remains subject to verification
without replay. Native error details are discarded.

Explicit rate, quota, credit, or spend-limit failures are not hidden behind
context compaction or provider fallback. A resumable failure records only its
bounded normalized class and checkpoint. Resume reconstructs the same logical
request after the operator restores availability; it does not depend on raw
native output or a surviving provider session.

Provider messages, responses, prompts, denied tool input, standard error,
credentials, and process causes do not enter public activity or durable state.
Adding another backend is a source-controlled runtime decision, not dynamic
plugin loading, and must preserve these shared semantics without adding
provider branches to pipeline policy.
