# Process supervision and stop reconciliation

Read the affected sections before changing this contract. Use the [topic map](README.md)
for related owners and required reading routes.

Before a provider or trusted command can execute, a private supervisor waits on
a separate inherited Node IPC channel while the runner journals its host PID,
hostname, boot/start identity, matching launch cutoff and PID namespace identity.
The platform boundary owns the
closed `ordinary` and `native-sandbox-provider` supervision modes. Ordinary
processes launch this supervisor as PID 1 in a private Linux namespace using
system-protected bubblewrap. Provider launches use that mode only when a cached,
namespace-local probe proves the complete outer-plus-inner user, PID, mount,
device, and network namespace shape. When nesting is unavailable on the initial
host PID namespace, only a declared provider may use a distinct owned session
before its mandatory native sandbox starts. When repository validation is
already inside the runner-trusted private PID namespace and that policy denies
another namespace, the existing owned-session mode remains available without
widening the enclosing sandbox. The private launcher preserves inherited filesystem/network
restrictions while replacing `/dev` with bubblewrap's minimal synthetic device
filesystem. Enclosing-session reuse retains the enclosing namespace's mounts
and restrictions. Provider and trusted-executor sandboxes still enforce their
narrower access contracts. The launcher's private status channel supplies the
host PID, verified against its parent and namespace before registration. No
provider work starts without that proof.

Launcher verification resolves the fixed system executable to a regular,
single-linked canonical file and checks that file plus every relevant ancestor
against the effective Linux mount table. A read-only mount is a protected
substitution anchor even when a namespace-root permission probe would otherwise
report writable. Paths without that anchor must deny runner-identity writes
through the root. Missing mount evidence, links, or a writable substitution
path fails closed.

Disconnecting IPC on runner loss starts bounded cleanup; bubblewrap also binds
the namespace lifetime to the runner. Exiting namespace PID 1 makes the kernel
retire all descendants, including detached sessions, double forks, and nested
namespaces. Normal completion reports surviving descendants before retiring
them, so trusted checks cannot pass with leaked work. Recovery inspects only the
recorded owner and waits for namespace-init death before clearing ownership;
the outer launcher's exit alone is insufficient. Live shutdown uses the original
child handle and control channel. The session token is derived from the already
persisted PID, boot, and process-start proof, so recovery can reject clearing a
dead session supervisor while matching descendants remain without signalling a
numeric host PID. Unverifiable ownership retains exclusion.
Identity-free records remain conservative until a verified reboot. Unavailable
ordinary namespace support fails before execution. Ordinary processes never
receive the initial-host session fallback.

Shared-host supervision and replacement-owner recovery use the same positive
association scanner. Owned-session membership, a matching per-launch inherited
token, or observed owned ancestry associates a process. Available parent links
are followed through inaccessible environments; a historical baseline never
short-circuits the search. Every snapshot descendant is inspected independently.
An unassociated process does not block progress or receive signals because its
metadata is unreadable, its session began later, or its cgroup is shared. There
is no unrelated-process custody, exited-candidate or control-group exclusion
proof. Shared-host discovery cannot prove absence against arbitrary same-user
processes hiding all ancestry and token evidence; private PID containment
remains the stronger kernel-enforced boundary.

Positive association is retained across retries and live scans until a fresh
stat proves the PID absent. Loss of a token, session change or reparenting cannot
discard that association. An associated identity that is replaced, unreadable,
malformed or unstable remains unverifiable rather than authorizing a signal or
an empty scan. Previously observed members are rechecked even when omitted from
a later directory listing. Session termination and containment failure freeze
supervisor discovery and pass its retained associations to parent-side cleanup.
Parent-side absence can clear registration only after that handoff is received;
a watchdog killing the supervisor before transfer retains the ownership blocker.
If IPC disconnects after handoff, the supervisor resumes discovery using its
retained associations and signals verified owned members. Any pending termination
check is upgraded to verified absence at its original deadline; surviving or
uncertain descendants keep the supervisor live as an ownership blocker.
Recovery remains inspection-only for persisted host PIDs. Recorded supervisor
identity and namespace validation, live-owner exclusion and journaled retirement
remain mandatory. Recovery rejects a current-boot
namespace mismatch; a previous boot independently proves the old work absent.
Parent loss before payload release retires the inert supervisor directly because
no provider descendants can yet exist.

Live and recovery scans share a 65,536-operation and 250-millisecond inspection
budget covering reads, snapshot entries, retained associations and ancestry
traversal. A final read exceeding the time budget fails closed. These limits do
not reset per PID or during churn, and exhaustion never proves process absence.

Runner construction supplies the same session inspector to ordinary recovery
and operator-stop reconciliation. Production uses the shared strict inspector;
synthetic-process orchestration tests inject their process-table view instead of
sampling unrelated host workers. Identity rechecks, namespace checks, and lease
ownership remain in the real retirement path.

Both scanners allow at most three attempts per snapshot entry. Transient
`ENOENT`/`ESRCH` or parent/session change restarts that entry's classification.
Unassociated churn supplies no ownership authority. Once ownership is observed,
identity replacement or exhausted retries retains the process record; only an
observed absent PID can retire that association. This retry policy does not
extend the completion grace below.

Completion-time descendant inspection retries transiently incomplete evidence
against one non-resetting one-second descendant-grace deadline. Complete
evidence resumes the ordinary success or bounded TERM/KILL path; uncertainty at
the deadline retains the existing fail-closed error. While the current owner
still holds the private child handle and control channel, it makes one bounded
teardown attempt through that boundary and rechecks the owned session. An empty
retained supervisor is retired and its durable process record is cleared before
the original containment error is returned. If owned descendants survive or
inspection remains incomplete, the process record and exclusion remain; the
parent never signals a host PID from persisted identity alone.

The runner service accepts revision-bound `requestOperatorStop` requests and
monitors durable revisions while executing. An accepted request aborts only
the owned provider or trusted execution and publishes stopping activity.
Provider recovery attempts and the constrained commit executor check the same
abort signal before starting. The run/worktree leases remain held through
process shutdown, read-only reconciliation, and the final stop event. The monitor
serializes process registration/retirement and stop-activity writes under that
lease, so abort-triggered cleanup cannot race publication of the stopping event.
Persisted
process ownership also prevents a different run from reclaiming the worktree
after owner loss, and prevents checkpoint advancement before process cleanup.
The only live-process registration is the active turn role acknowledging its new
child session; it changes lineage alone, and other roles, an absent turn,
preparation custody, pending stops and cancellation remain blocked.
`RunStore.recordSessionNaming` applies the same role rule to journal one finite
naming status for that recorded child under the lease, changing only the
revision and its bounded activity; generic transitions, including activity-only
ones, still reject live custody.
CLI/MCP command registration remains transport-owned.

After owner loss, the replacement execution lease inspects the recorded
PID/boot/start and namespace evidence. A PID that vanishes between liveness and
identity reads is checked again and classified dead only when that second read
proves absence. Same-boot PID replacement, a
live or unverifiable owner, an initial-host namespace hidden from the recovery
process, missing required owner identity, incomplete bounded inspection, or
surviving positively associated descendants all retain the record. A previous
boot or a dead same-namespace session with a complete empty descendant scan
permits journaled clearing under the replacement lease. Current-boot namespace
mismatch remains unverifiable even when the recorded owner PID is dead.
Crashes before clearing repeat retirement proof; crashes after clearing repeat
resource and checkpoint settlement without signalling the former PID.

Each pipeline has a reconciliation-only entry path with provider invocation,
trusted commands, and artifact writes disabled. It rechecks frozen inputs and
the interrupted access contract, preserves safe partial content, rejects index
or Git-control drift, and retains safety blockers. Content-changing partial
work invalidates dependent gates and charges correction work once; the exact
suspended journal checkpoint remains inspectable. Consumed commits are verified
without reinvoking their executor. Handoff reconciliation only inspects whether
the existing index is complete or untouched; it never stages. Verified effects
and step advancement are included atomically in the final stop event.
When the runner proves that an operator stop prevented commit invocation,
verification of unchanged Git state retires the unused authorization. Resume
can obtain a new authorization; uncertain or begun effects remain verification-only.
Provider error redaction retains that runner-owned pre-effect stop proof while
discarding native error wrappers; unrelated rejections remain blockers.

Reconciliation produces `WAITING_FOR_USER` with `operator_paused` and an
explicit null resume action, or terminal `CANCELED`. A bounded private
`operatorResume` record retains the reconciled workflow position, active-turn
reconstruction marker, and any preceding pause. Null resume restores an existing
pause without consuming its editor authorization or bypassing its blockers.
Otherwise it reconstructs the preserved logical role from frozen configuration
and session lineage only after reacquiring any required worktree lease.
Invalidated content returns through the pipeline's
candidate gate before further finalization. Cancellation cannot resume.
A settled pause rejects further pauses but accepts a fresh cancellation at its
current revision; the old pause's inspected revision grants no authority, and
deferred timing keeps its existing eligibility. Until reconciliation the pending
cancellation coexists with the preserved `operator_paused` checkpoint; the
plan-authoring, plan-execution, polishing, and init validators accept exactly
that combination. Reconciliation unwraps the checkpoint, retires owned work, and
wraps the underlying state once as `operator_canceled` without provider probes.
Cancellation superseding a pause during reconciliation changes only the final
outcome; verification never replays an effect or counts its progress twice.
Authorized clarification edits remain pending; stop reconciliation checks Git
safety without consuming them or classifying them as frozen-input drift. Input
drift outside that window cannot skip repository reconciliation.
