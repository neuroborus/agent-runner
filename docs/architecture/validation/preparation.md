# Trusted Validation Preparation

Read the affected sections before changing this contract. Use the [topic map](README.md)
for related owners and required reading routes.

## Availability inspection

For authorized requests, inspection prepares each selected command sequentially
under the existing durable storage, transport, and process lifecycle. It acquires
and verifies dependencies, constructs the same network-isolated mounts, checks
the declared executable's availability, and runs only a runner-defined empty Node
program in that sandbox, with a maximum ten-second process deadline. The check's
argument vector is never invoked. Preparation failures return bounded
`unavailable` blockers without native diagnostics, URLs, or process output.
Uncertain resource ownership, cancellation, and repository mutation preserve
their existing safety error contracts and recovery evidence. Successful
retirement journaling is required before inspecting another command; an
uncertain process registration stops preparation with its ownership intact.
Successful inspection returns only `READY` and an empty blocker list; it grants no check
pass or finalization evidence. Owned resources are retired and cleaned, and
finalization later acquires dependencies afresh and reverifies them.

The runner's private inspection adapter pins repository scope and snapshot to
the saved run, guards project configuration before and after the effect, and
uses the stop monitor's signal and leased process/resource callbacks. Outstanding
ownership must be recovered first. Stop reconciliation rejects inspection just
as it rejects new command execution. This adds no eager capability work ahead
of consumed-commit or completed-handoff verification; pipelines must keep that
verification-only recovery ahead of any new preparation.

### Preparation custody

Common envelope version 22 adds nullable `preparation` authority; older runtimes
reject it and legacy migration grants no process proof. Before the inert
supervisor launches, the state capability fully publishes a canonical reservation
and initializes its confined custody log. The reservation binds the attempt,
execution lease and owner, original certified journal prefix/revision, frozen
input/content and trusted command/configuration fingerprints, allocated resource
identity, initial stop state, and descriptor-proven commit target. An explicit
null target supports ordinary execution and polishing preparation; unsupported
deferred stops still reject. The reservation authorizes future work only.

Launch starts the unchanged absolute preparation deadline. Attachment and
one-shot admission use fresh stable custody/lease reads, directory identity and
process-identity rechecks. The log identifies the issued reservation by revision
and digest without copying or hashing its history certificate. It preserves the
complete process record within 16 records and 2 MiB; no historical field is
truncated. Attachment requires supervisor identity and namespace. Historical
ancestry and control-group proofs remain strictly validated when present, while
new launches attach null values for both obsolete fields. Cancellation during
attachment retains the captured proof with denied admission even if the
supervisor has exited; settlement still requires verified retirement. These compact operations
bypass canonical mutation queues, history loading/normalization and progress
generation.
The short state-owned custody gate serializes them with stop revocation. Stop
acceptance retains canonical mutation serialization and publishes its bounded
request/revision/timing/target disposition under that gate before canonical
acceptance. Immediate or mismatched stops deny admission independently of monitor
observation; matching deferred stops retain current-target permission. Interrupted
acceptance cannot reopen a denied reservation. Monitor abort precedes stop-activity
publication; all gate waits and attachment work consume the original deadline.

After verified close and descendant retirement, canonical settlement verifies the
original certificate and records the complete custody log with its exact endpoint.
Journal append/sync, state replacement and progress publication finish before log
removal and canonical clearing. Retries reuse settlement rather than duplicate
facts. Storage cleanup, further preparation, availability, checkpoint advancement
and ownership release wait for that lifecycle. A reservation remains visible to
lock-free ownership projections and blocks worktree reclamation. Recovery never
releases an old attempt: it reconciles attachment, applies the shared retirement
policy, and settles the same endpoint. An incomplete final record
can be removed only after original-prefix verification and phase-specific
no-launch or retirement proof. Truncation binds the inspected file's identity,
observations and exact prefix length, then rechecks the synced prefix and
handle/path evidence; changed or completed tails retain ownership.
Missing or conflicting authority stays reserved.
An orphan custody log also rejects state and ownership reads after cold canonical
rollback. State-owned authorization permits one caller-bounded reload to recognize
concurrent reservation publication or settlement. Activity continuation anchors
that reload to its already proved extended snapshot through `extendSnapshot`,
retaining the original operation's consumed-prefix proof transitively. Unavailable
advancement or proof retains the custody refusal; file presence or an unrelated
append cannot establish authority. Observation never repairs or removes custody.
Neither attachment nor admission proves that the probe ran, exited, or passed.
Canonical replay enforces reservation, immutable authority, settlement and clearing
in order; custody transitions cannot change workflow state or validation evidence.
Live custody-prefix evidence survives history-checkpoint eviction, and repeated
recovery reuses irreversible revocation without exhausting the bounded log.
Ordinary trusted-command execution retains its existing canonical process path.

## Preparation deadlines

Each runner-trusted validation command derives its deadline from the validated
run snapshot. The public `trustedCommandTimeoutMs` default is 60 minutes, and
capability preparation uses `Math.min(timeoutMs, 10_000)`. The service has no
construction-time timeout override, so no second deadline of this operational
class can bypass the per-run configuration contract.
Preparation starts one absolute `process.hrtime.bigint()` deadline before
launch, including durable registration through observed close. The runner and
supervisor compare that same monotonic deadline after registration and at
payload admission; queued IPC never starts a new relative allowance. Expiry or
cancellation permanently closes release authority. Pending registration, IPC
callbacks, and verified retirement drain before completion, even after expiry;
uncertain publication or retirement retains ownership. A registration deadline
failure is distinguished from observed isolation failure, and an unobserved
payload exit or signal remains null rather than copying launcher status or a
requested termination signal. Preparation still runs only the empty sandbox
probe and grants no required-check evidence.
