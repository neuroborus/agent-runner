import { CORRECTION_STATES } from "./correction-feedback.js";
import { recheckRole } from "./cycles.js";
import { assertAudit, exact, sessionContextKey } from "./discovery-contract.js";

export function auditCheckpoint(run, phase) {
  const state = run.pipelineState;
  assertAudit(
    Object.hasOwn(CORRECTION_STATES, phase),
    "Audit recovery phase is invalid.",
  );
  const number =
    phase === "clarify"
      ? state.clarificationRounds
      : phase === "discovery"
        ? state.history.length
        : state.recheckHistory.length;
  return {
    phase,
    number,
    contextKey: sessionContextKey(run, phase, number),
  };
}

/** Retire a prefix of common lineage, never duplicate native identities. */
export function createOutputRecovery(run, phase) {
  return {
    ...auditCheckpoint(run, phase),
    retiredChildren: run.sessionLineage.children.length,
  };
}

export function reserveOutputRecovery(run, pipelineState) {
  const recovery = pipelineState.outputRecovery;
  return recovery === null
    ? pipelineState
    : {
        ...pipelineState,
        outputRecovery: {
          ...recovery,
          ...auditCheckpoint({ ...run, pipelineState }, recovery.phase),
        },
      };
}

export function assertOutputRecovery(run) {
  const state = run.pipelineState;
  const recovery = state.outputRecovery;
  if (recovery === null) {
    assertAudit(
      state.workflowState !== "WAITING_FOR_USER" ||
        run.pause?.reason !== "output_exhausted",
      "Audit output exhaustion requires retirement intent.",
    );
    return;
  }
  exact(recovery, ["phase", "number", "contextKey", "retiredChildren"]);
  const expected = auditCheckpoint(run, recovery.phase);
  const suspended = CORRECTION_STATES[recovery.phase];
  const role = recovery.phase === "recheck" ? recheckRole(state) : "auditor";
  assertAudit(
    recovery.number === expected.number &&
      recovery.contextKey === expected.contextKey &&
      Number.isSafeInteger(recovery.retiredChildren) &&
      recovery.retiredChildren >= 0 &&
      recovery.retiredChildren <= run.sessionLineage.children.length &&
      run.sessionLineage.children
        .slice(recovery.retiredChildren)
        .every(
          (child) =>
            child.role === role && child.contextKey === recovery.contextKey,
        ) &&
      [suspended, "WAITING_FOR_USER", "FAILED", "CANCELED"].includes(
        state.workflowState,
      ) &&
      state.pendingEdit === null &&
      state.repositoryBaseline !== null,
    "Audit output recovery checkpoint is invalid.",
  );
  if (recovery.phase === "clarify") {
    assertAudit(
      state.inputs === null,
      "Audit clarification recovery is stale.",
    );
  } else {
    const pass =
      recovery.phase === "discovery"
        ? state.history.at(-1)
        : state.recheckHistory.at(-1);
    assertAudit(
      ["running", "invalid"].includes(pass?.outcome) &&
        pass.contextKey === recovery.contextKey &&
        (recovery.phase !== "recheck" || state.pendingBatch !== null),
      "Audit output recovery requires its original reservation.",
    );
  }
  if (run.pause?.reason === "output_exhausted") {
    assertAudit(
      state.workflowState === "WAITING_FOR_USER" &&
        run.activeTurn === null &&
        run.pause.code === "ERR_OUTPUT_EXHAUSTED" &&
        run.pause.resumeState === suspended &&
        run.pause.role === role &&
        run.pause.checkpoint ===
          `audit:${recovery.phase}:read-only:${recovery.number}` &&
        recovery.retiredChildren === run.sessionLineage.children.length,
      "Audit output-exhaustion pause differs from its retirement intent.",
    );
    if (recovery.phase !== "clarify") {
      assertAudit(
        (recovery.phase === "discovery"
          ? state.history
          : state.recheckHistory
        ).at(-1)?.outcome === "running",
        "Audit exhaustion requires an unsettled reservation.",
      );
    }
  }
}

/** Only an authentic suspended legacy checkpoint can gain recovery intent. */
export function migrateOutputRecovery(run) {
  assertAudit(
    !Object.hasOwn(run.pipelineState, "outputRecovery"),
    "Legacy audit already contains output recovery.",
  );
  const exhausted =
    run.pipelineState.workflowState === "WAITING_FOR_USER" &&
    run.pause?.reason === "output_exhausted";
  const phase = exhausted
    ? Object.keys(CORRECTION_STATES).find(
        (key) => CORRECTION_STATES[key] === run.pause.resumeState,
      )
    : null;
  const pipelineState = {
    ...run.pipelineState,
    outputRecovery: exhausted ? createOutputRecovery(run, phase) : null,
  };
  assertOutputRecovery({ ...run, pipelineState });
  return pipelineState;
}
