import {
  assertAudit,
  exact,
  fingerprint,
  isHash,
  same,
  sessionContextKey,
} from "./discovery-contract.js";
import { auditDiagnostic, MAX_AUDIT_DIAGNOSTICS } from "./diagnostics.js";

export const CORRECTION_STATES = Object.freeze({
  clarify: "CLARIFY",
  discovery: "DISCOVER",
  recheck: "VERIFY_FINDINGS",
});

/** Retain constraints and checkpoint bindings, never rejected output or causes. */
export function createCorrectionFeedback(run, phase, diagnostics) {
  const state = run.pipelineState;
  const number =
    phase === "clarify"
      ? state.clarificationRounds
      : phase === "discovery"
        ? state.history.length
        : state.recheckHistory.length;
  const recognized = Array.isArray(diagnostics)
    ? diagnostics.slice(0, MAX_AUDIT_DIAGNOSTICS)
    : [];
  return {
    phase,
    number,
    contextKey: sessionContextKey(run, phase, number),
    snapshotFingerprint: state.repositoryBaseline.contentFingerprint,
    reportFingerprint: state.reportFingerprint,
    batchFingerprint:
      phase === "recheck" ? fingerprint(state.pendingBatch) : null,
    diagnostics:
      recognized.length === 0
        ? [auditDiagnostic("result", "invalid-result")]
        : recognized.map((entry) => auditDiagnostic(entry?.field, entry?.code)),
  };
}

/** Feedback cannot authorize a pass or survive acceptance of different evidence. */
export function assertCorrectionFeedback(run) {
  const state = run.pipelineState;
  const feedback = state.correctionFeedback;
  if (feedback === null) return;
  exact(feedback, [
    "phase",
    "number",
    "contextKey",
    "snapshotFingerprint",
    "reportFingerprint",
    "batchFingerprint",
    "diagnostics",
  ]);
  assertAudit(
    Object.hasOwn(CORRECTION_STATES, feedback.phase) &&
      Number.isSafeInteger(feedback.number) &&
      feedback.number >= 0 &&
      state.repositoryBaseline !== null &&
      isHash(feedback.snapshotFingerprint) &&
      (feedback.phase === "clarify"
        ? feedback.number === state.clarificationRounds
        : feedback.number > 0 &&
          feedback.number <=
            (feedback.phase === "discovery"
              ? state.history.length
              : state.recheckHistory.length)) &&
      feedback.snapshotFingerprint ===
        state.repositoryBaseline?.contentFingerprint &&
      feedback.reportFingerprint === state.reportFingerprint &&
      Array.isArray(feedback.diagnostics) &&
      feedback.diagnostics.length > 0 &&
      feedback.diagnostics.length <= MAX_AUDIT_DIAGNOSTICS,
    "Audit correction feedback is invalid.",
  );
  for (const diagnostic of feedback.diagnostics) {
    exact(diagnostic, ["field", "code"]);
    assertAudit(
      same(diagnostic, auditDiagnostic(diagnostic.field, diagnostic.code)),
      "Audit correction diagnostic is invalid.",
    );
  }
  assertAudit(
    feedback.contextKey ===
      sessionContextKey(run, feedback.phase, feedback.number) &&
      [
        CORRECTION_STATES[feedback.phase],
        "WAITING_FOR_USER",
        "FAILED",
        "CANCELED",
      ].includes(state.workflowState),
    "Audit correction checkpoint is invalid.",
  );
  if (feedback.phase === "clarify") {
    assertAudit(
      state.inputs === null &&
        state.pendingEdit === null &&
        feedback.batchFingerprint === null,
      "Audit clarification feedback is stale.",
    );
    return;
  }
  const history =
    feedback.phase === "discovery" ? state.history : state.recheckHistory;
  assertAudit(
    history[feedback.number - 1]?.outcome === "invalid" &&
      history[feedback.number - 1].contextKey === feedback.contextKey &&
      history
        .slice(feedback.number)
        .every(({ outcome }) => ["running", "interrupted"].includes(outcome)) &&
      (feedback.phase === "recheck"
        ? state.pendingBatch !== null &&
          feedback.batchFingerprint === fingerprint(state.pendingBatch)
        : feedback.batchFingerprint === null && state.pendingBatch === null),
    "Audit correction feedback lacks its rejected checkpoint.",
  );
}
