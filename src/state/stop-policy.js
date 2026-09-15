import { isDeepStrictEqual } from "node:util";
import { validStopBoundary } from "./stop-contract.js";
import { deepFreeze, RunStoreError } from "./validation.js";

export function stopIsPending(state) {
  return (
    state.stopRequest != null && state.stopRequest.reconciledRevision === null
  );
}

export function resolveCommitBoundary(state, resolver) {
  const boundary =
    typeof resolver === "function"
      ? resolver(deepFreeze(structuredClone(state)))
      : null;
  if (!validStopBoundary(boundary)) {
    throw new RunStoreError(
      "Commit-boundary stops are unsupported at this checkpoint.",
      {
        code: "ERR_STOP_BOUNDARY_UNSUPPORTED",
      },
    );
  }
  return structuredClone(boundary);
}

export function stopBlocksExecution(state, resolver) {
  if (!stopIsPending(state)) return false;
  if (state.stopRequest.effectiveTiming !== "after-current-commit") return true;
  return !isDeepStrictEqual(
    resolveCommitBoundary(state, resolver),
    state.stopRequest.targetBoundary,
  );
}

export function assertStopProgress(previous, next, resolver) {
  if (
    stopIsPending(previous) &&
    previous.stopRequest.effectiveTiming === "after-current-commit" &&
    !isDeepStrictEqual(
      resolveCommitBoundary(next, resolver),
      previous.stopRequest.targetBoundary,
    )
  ) {
    throw new RunStoreError(
      "Commit-boundary progress requires atomic settlement.",
      {
        code: "ERR_STOP_BOUNDARY_SETTLEMENT_REQUIRED",
      },
    );
  }
}

export function runRetainsOwnership(state) {
  return stopIsPending(state) || state.executionProcess != null;
}

export function assertRunCanAdvance(state, resolver) {
  if (stopBlocksExecution(state, resolver)) {
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
    (state.stopRequest?.kind === "cancel_requested" && !stopIsPending(state))
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
