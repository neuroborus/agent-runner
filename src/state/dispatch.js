import { isDeepStrictEqual } from "node:util";

import { assertRunId, RunStoreError } from "./validation.js";

const PREPARATION_FIELDS = new Map([
  [
    "runtime/migrated",
    [
      "schemaVersion",
      "runtimeCompatibility",
      "pipelineStateVersion",
      "pipelineState",
    ],
  ],
  ["runtime/provider-policy-recorded", ["providerPolicies"]],
  ["execution/stopped", ["executionProcess"]],
  ["execution/resource-recorded", ["executionResource"]],
  ["execution/resource-cleaned", ["executionResource"]],
  ["stop/resumed", ["pause", "activeTurn", "pipelineState"]],
]);

// Only pre-continuation reconciliation may inherit an incomplete dispatch.
// A different admission, CLI turn, or checkpoint advance consumes that authority.
export function isRecoveryPreparation(previous, event) {
  if (event.activity?.actor !== "runner") return false;
  const fields = PREPARATION_FIELDS.get(
    `${event.activity.phase}/${event.activity.kind}`,
  );
  if (fields === undefined) return false;
  if (
    event.activity.kind === "resource-recorded" &&
    !(
      previous.executionResource?.phase === "acquiring" &&
      event.state.executionResource?.phase === "allocated"
    )
  )
    return false;
  const omit = (state) =>
    Object.fromEntries(
      Object.entries(state).filter(
        ([field]) => !["revision", "updatedAt", ...fields].includes(field),
      ),
    );
  return isDeepStrictEqual(omit(previous), omit(event.state));
}

export function normalizeRecoveryDispatch(value) {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.keys(value).length !== 2 ||
    !Object.hasOwn(value, "id") ||
    !Object.hasOwn(value, "expectedRevision") ||
    !Number.isSafeInteger(value.expectedRevision) ||
    value.expectedRevision < 1
  )
    throw new RunStoreError("Detached dispatch is invalid.", {
      code: "ERR_INVALID_MCP_ACTION",
    });
  assertRunId(value.id);
  return Object.freeze({
    id: value.id,
    expectedRevision: value.expectedRevision,
  });
}

// Correlation evidence lives in the private journal; public activity omits IDs.
export function dispatchActivity(dispatch, ready = false) {
  return {
    actor: "runner",
    phase: "recovery",
    kind: ready ? "dispatch-ready" : "dispatch-started",
    message: `Detached recovery ${dispatch.id} ${ready ? "ready" : "started"}.`,
  };
}

export function publicDispatchActivity(activity) {
  if (
    activity?.actor !== "runner" ||
    activity.phase !== "recovery" ||
    !["dispatch-started", "dispatch-ready"].includes(activity.kind)
  )
    return activity;
  return {
    ...activity,
    message:
      activity.kind === "dispatch-ready"
        ? "Detached recovery reached checkpoint continuation."
        : "Detached recovery acquired execution ownership.",
  };
}
