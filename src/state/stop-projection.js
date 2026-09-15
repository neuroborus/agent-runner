// Public stop evidence excludes request identities and private checkpoints.
export function projectOperatorStop(run) {
  const stop = run.stopRequest;
  if (stop == null) return null;
  const pending = stop.reconciledRevision === null;
  const effectiveTiming = stop.effectiveTiming ?? "immediate";
  const applicable =
    pending &&
    (effectiveTiming === "immediate" ||
      ["WAITING_FOR_USER", "FAILED"].includes(run.pipelineState.workflowState));
  return {
    kind: stop.kind,
    revision: stop.acceptedRevision,
    timing: stop.timing ?? "immediate",
    effectiveTiming,
    targetStep: stop.targetBoundary?.step ?? null,
    state: pending ? (applicable ? "applicable" : "pending") : "settled",
    settlement:
      stop.settlement == null
        ? null
        : { kind: stop.settlement.kind, commit: stop.settlement.commit },
  };
}
