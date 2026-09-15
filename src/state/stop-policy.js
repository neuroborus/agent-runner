import { RunStoreError } from "./validation.js";

export function stopIsPending(state) {
  return (
    state.stopRequest != null && state.stopRequest.reconciledRevision === null
  );
}

// Requests are immediate today. Enforcement is a separate policy from pending
// accounting so execution eligibility never determines ownership retention.
export function stopBlocksExecution(state) {
  return stopIsPending(state);
}

export function runRetainsOwnership(state) {
  return stopIsPending(state) || state.executionProcess != null;
}

export function assertRunCanAdvance(state) {
  if (stopBlocksExecution(state)) {
    throw new RunStoreError(
      "Operator stop must be reconciled before further work.",
      { code: "ERR_STOP_RECONCILIATION_REQUIRED" },
    );
  }
  if (state.executionProcess != null) {
    throw new RunStoreError(
      "Owned execution must stop before advancing its checkpoint.",
      {
        code: "ERR_EXECUTION_PROCESS_ACTIVE",
      },
    );
  }
  if (
    state.pipelineState.workflowState === "CANCELED" ||
    state.stopRequest?.kind === "cancel_requested"
  ) {
    throw new RunStoreError("A canceled run cannot advance.", {
      code: "ERR_RUN_CANCELED",
    });
  }
}

export function assertRunCanReleaseOwnership(state) {
  if (!runRetainsOwnership(state)) return;
  if (stopIsPending(state)) {
    throw new RunStoreError(
      "Stop reconciliation must finish before releasing ownership.",
      { code: "ERR_STOP_RECONCILIATION_REQUIRED" },
    );
  }
  throw new RunStoreError(
    "Owned execution must stop before releasing ownership.",
    { code: "ERR_EXECUTION_PROCESS_ACTIVE" },
  );
}
