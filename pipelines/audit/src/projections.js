import { join } from "node:path";

import { CORRECTION_STATES } from "./correction-feedback.js";
import {
  auditDiagnostic,
  diagnosticIssues,
  MAX_AUDIT_DIAGNOSTICS,
} from "./diagnostics.js";
import { projectAuditReport, REPORT_FILENAME } from "./publication-contract.js";

const RESUMABLE = Object.freeze([
  "audit_scope_blocked",
  "discovery_interrupted",
  "invalid_discovery",
  "discovery_incomplete",
  "invalid_recheck",
  "recheck_incomplete",
  "authentication_required",
  "output_exhausted",
  "backend_unavailable",
]);
const EXPLANATIONS = Object.freeze({
  audit_scope_blocked: "Audit scope cannot yet be resolved.",
  discovery_interrupted:
    "Discovery was interrupted; resume preserves its charged pass.",
  invalid_discovery: "Discovery returned invalid structured content.",
  discovery_incomplete: "Discovery is incomplete.",
  invalid_recheck: "Finding verification returned invalid structured content.",
  recheck_incomplete: "Finding verification is incomplete.",
  authentication_required: "Authenticate the selected provider, then resume.",
  output_exhausted:
    "The provider exhausted its response output; resume the saved checkpoint.",
  backend_unavailable: "The selected provider is temporarily unavailable.",
  clarification_answers_required:
    "Material clarification answers are required.",
  proactive_clarification:
    "Optional clarification input may be supplied before agent work begins.",
  clarification_limit_reached:
    "The bounded clarification question limit was reached.",
  discovery_limit_reached: "The run-wide discovery pass limit was reached.",
  finding_recheck_limit_reached:
    "The run-wide finding recheck limit was reached.",
  audit_reviewer_required:
    "This legacy run has no frozen finding Reviewer; start a new independent audit.",
  audit_report_changed:
    "The published audit report changed; preserve it and start a new audit.",
  audit_report_binding_required:
    "This legacy run has no frozen report artifact bindings; start a new audit.",
  input_changed:
    "Frozen task or clarification content changed; start a new audit.",
  workspace_changed:
    "Frozen workspace content or controls changed; start a new audit.",
  project_configuration_changed:
    "Frozen project configuration changed; start a new audit.",
  operator_paused: "The operator paused this audit.",
  operator_canceled: "The operator canceled this audit.",
  internal_failure: "Audit failed.",
});

export function validateResumeAction(run, action) {
  if (
    [
      "input_changed",
      "workspace_changed",
      "project_configuration_changed",
      "audit_report_changed",
      "audit_report_binding_required",
    ].includes(run.pause?.reason)
  )
    throw new Error("Changed frozen audit inputs cannot resume.");
  if (
    action !== null ||
    run.pipelineState.workflowState !== "WAITING_FOR_USER" ||
    (!run.pipelineState.pendingEdit &&
      !RESUMABLE.includes(run.pause?.reason) &&
      run.pause?.reason !== "operator_paused")
  )
    throw new Error("Resume action is not valid for this paused audit.");
}

export const auditProjections = Object.freeze({
  clarification: (run) =>
    Object.freeze({
      path: join(run.taskPath, "clarifications.md"),
      hash: run.hashes?.clarifications ?? null,
    }),
  pause(run) {
    if (!run.pause) return null;
    const known = Object.hasOwn(EXPLANATIONS, run.pause.reason);
    let resumable = false;
    try {
      validateResumeAction(run, null);
      resumable = true;
    } catch {}
    const pendingRequest =
      run.pipelineState.workflowState === "WAITING_FOR_USER" &&
      run.pause.inputRequest !== undefined &&
      run.pause.inputResponse === undefined;
    const feedback = run.pipelineState.correctionFeedback;
    const correcting =
      ["invalid_discovery", "invalid_recheck"].includes(run.pause.reason) &&
      feedback != null &&
      CORRECTION_STATES[feedback.phase] === run.pause.resumeState;
    const diagnosticClass =
      run.pipelineState.workflowState === "FAILED" &&
      run.pause.reason === "internal_failure" &&
      typeof run.pause.diagnosticClass === "string" &&
      /^[a-z][a-z0-9_]{0,63}$/u.test(run.pause.diagnosticClass)
        ? run.pause.diagnosticClass
        : null;
    return Object.freeze({
      reason: known ? run.pause.reason : "unknown_pause",
      code:
        known && /^[A-Z0-9_]{1,64}$/u.test(run.pause.code ?? "")
          ? run.pause.code
          : null,
      explanation: correcting
        ? "Audit structured content was rejected. Resume requests a complete corrected result within the remaining pass budget."
        : diagnosticClass === "isolation_workspace_policy"
          ? "The provider could not enforce the declared workspace policy. Preserve this failed audit and resolve provider/workspace compatibility before a separately authorized new audit."
          : (EXPLANATIONS[run.pause.reason] ??
            "No public diagnostic is available."),
      evidence: Object.freeze(
        correcting
          ? feedback.diagnostics
              .slice(0, MAX_AUDIT_DIAGNOSTICS)
              .map((entry) => {
                const diagnostic = auditDiagnostic(entry.field, entry.code);
                return `${CORRECTION_STATES[feedback.phase]}: [${diagnostic.code}] ${diagnosticIssues(diagnostic)[0]}`;
              })
          : diagnosticClass === null
            ? []
            : [`Adapter diagnostic: ${diagnosticClass}.`],
      ),
      resumeState: resumable ? (run.pause.resumeState ?? null) : null,
      nextActions: Object.freeze(
        pendingRequest
          ? [
              Object.freeze({
                type: "respond",
                requestId: run.pause.inputRequest.id,
              }),
            ]
          : resumable && run.pause.inputResponse === undefined
            ? [Object.freeze({ type: "resume", action: null })]
            : [],
      ),
    });
  },
  status(run) {
    const state = run.pipelineState;
    const projected = state.report === null ? null : projectAuditReport(state);
    return Object.freeze({
      currentStep: null,
      planPath: null,
      findings: Object.freeze([]),
      completedCommits: Object.freeze([]),
      stagnationDirection: null,
      finalizedFingerprint: null,
      reviewedFingerprint: null,
      auditSource: Object.freeze({
        sourceScope: state.settings.sourceScope ?? "directory",
        excludePaths: Object.freeze([...(state.settings.excludePaths ?? [])]),
        selectionFingerprint:
          (run.workspacePreparation ?? run.workspace)?.sourceSelection
            ?.fingerprint ?? null,
      }),
      auditReport: Object.freeze({
        path: join(run.taskPath, REPORT_FILENAME),
        status:
          state.publication.published === null
            ? "unpublished"
            : state.workflowState === "DONE"
              ? "complete"
              : "in-progress",
        contentHash: state.publication.published?.contentHash ?? null,
        confirmedFindings: projected?.report.findings.length ?? 0,
        pendingCandidates: projected?.pending.length ?? 0,
        discoveryPasses: state.history.length,
        findingRecheckPasses: state.recheckHistory.length,
      }),
    });
  },
});
