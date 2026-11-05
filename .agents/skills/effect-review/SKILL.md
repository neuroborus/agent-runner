---
name: effect-review
description: Review an operation's actual effects and ownership across preparation, invocation, observation, interruption, recovery, and cleanup. Use when these boundaries change or an effect/ownership defect is investigated, not for every source edit.
---

# Effect Review — Agent Runner

Follow one operation and its actual effects, including effects outside an agent
turn. Use the existing task role and gate. This procedure does not authorize
additional reviewers or pipeline roles, filesystem, Git, provider, or stop actions.

## Establish owners and boundaries

- Identify the operation, owning capability/pipeline, selected mode and workspace
  kind, callers, declared access, and the outcome being changed or investigated.
- Read the owning specification and trace the actual entry points, native adapter,
  preparation, publication, observation, recovery, and cleanup paths that matter.
- Make one compact owner/effect trace: who may read, create, replace, execute,
  acknowledge, stop, preserve, or delete each affected resource, and on what proof.
  Include workspace content, controls, Git state, durable records, and provider storage.

## Walk the lifecycle

1. **Admission and scope.** Establish workspace kind, confined sources, exclusions,
   protected declarations, and frozen bindings before expensive traversal. Retain
   ordinary-directory consumers when Git is optional. Check that excluded trees
   are actually outside the traversal, not merely hidden in the final report.
2. **Preparation and native startup.** Compare declared permissions with actual
   initialization and first-turn effects, including empty directories, temporary
   files, and provider bookkeeping. Identify the authorized storage for each.
   Do not precreate source content or hide control drift to make a read-only turn pass.
3. **Costly setup.** Identify the durable owner/status identifier, cancellation path,
   and recoverable checkpoint for long preparation. Distinguish cheap rejection
   before admission from work already needing supervision. Do not claim that an
   unreturned identifier or client lifetime makes setup controllable or durable.
4. **Invocation and publication.** Locate intent before mutation, exclusive execution
   ownership for the canonical scope, verified effect settlement, and receipt before
   acknowledgement. Check retries and reconnects against the same logical action;
   neither client disconnect nor reconstruction grants a second owner or replay.
5. **Observation.** Trace status, activity, and waits separately from execution.
   Reads must not acquire execution authority, replay effects, or repair canonical
   history. For concurrent progress, require the original certified prefix and a
   proven valid extension before a bounded classified reread. Changed bytes,
   missing proof, or uncertain ownership must not become a retry by error-name matching.
6. **Interruption and recovery.** Distinguish wait cancellation from run stop.
   Establish quiescence of the recorded owner and owned descendants before release;
   reconcile possibly consumed effects before retry. Missing process records alone
   do not prove that an effect never started or that recovery authority is available.
7. **Cleanup and preservation.** Require verified ownership and unchanged identities
   for the exact resources being retired, with recorded intent where required.
   Keep unfinished work in verified external preservation; cancellation does not
   dispose of it. Do not sweep unrelated processes, paths, workspaces, or leases.

## Choose necessary proof

- Compare before/after state at the changed boundary rather than relying solely on
  access labels or a successful tool response. Retain meaningful source/control
  drift detection and exact frozen bindings when isolating incidental effects.
- Use injected effects, finite recorded identities, events, or controlled clocks to
  expose relevant interleavings and interruption points. Exercise the distinct
  uncertainty/corruption case without multiplying equivalent scenarios.
- Separate source inspection, model-free fixtures/probes, and actual-provider
  acceptance. A public CLI implementation or simulated first turn is not proof
  that a historical provider caused a change. Real provider smoke remains opt-in.
- Reproduce only authorized effects in isolated artifacts. Preserve foreign work
  and private provider storage; do not repeat a real mutation to obtain a second review.

## Evidence and handoff

- Report each material mismatch with its lifecycle point, declared owner, observed
  effect, owning rule, evidence, and necessary correction. Mark unproven attribution
  or unavailable proof explicitly rather than inferring a cause.
- Explain which stop/retry/cleanup behavior was actually checked and what remains
  unknown. Return through the existing role's protocol without changing its
  permissions, correction budget, verification inventory, or acceptance gate.
