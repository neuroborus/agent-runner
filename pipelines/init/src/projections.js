import { join } from "node:path";
import { initCorrectiveFeedback } from "./rejection.js";
import {
  assertInspectionFailure,
  inspectionFailureExplanation,
} from "./inspection-failure.js";

const RESUMABLE = [
  "operator_paused",
  "provider_interrupted",
  "invalid_result",
  "authentication_required",
  "output_exhausted",
  "init_inspection_failed",
];
const INPUT_CHECKPOINTS = [
  "clarification_required",
  "placement_conflict",
  "product_decision_required",
];
const EXPLANATIONS = Object.freeze({
  setup_blocked: "Setup cannot proceed with the inspected requirements.",
  revision_limit:
    "The setup revision budget is exhausted; unresolved findings remain.",
  clarification_limit: "The bounded setup clarification limit was reached.",
  clarification_required: "Material setup clarification answers are required.",
  placement_conflict:
    "Competing setups require an explicit placement or configuration selector.",
  product_decision_required:
    "An unresolved material product decision prevents setup from continuing.",
  proactive_clarification:
    "Optional setup context may be supplied before work begins.",
  provider_interrupted:
    "The provider was interrupted; resume the saved setup checkpoint.",
  invalid_result: "The provider returned invalid structured setup content.",
  authentication_required: "Authenticate the selected provider, then resume.",
  output_exhausted:
    "The provider exhausted its response output; resume the saved checkpoint.",
  operator_paused: "The operator paused setup at its saved checkpoint.",
  operator_canceled:
    "The operator canceled setup; prepared resources are preserved.",
  workspace_changed:
    "Frozen setup inputs or workspace controls changed; preserve the setup and start a new run.",
  project_configuration_changed:
    "The active run configuration changed; preserve the setup and start a new run.",
  internal_failure:
    "The provider turn failed. Preserve this failed init and any prepared resources; review the supported diagnosis and resolve established prerequisites before a separately authorized new init run. Missing failure classification remains unknown.",
});
export function validateResumeAction(run, action) {
  if (
    run.pause?.reason === "init_inspection_failed" &&
    assertInspectionFailure(run.pause, run.pipelineState).constraint !==
      "inspection_unavailable"
  )
    throw new Error(
      "Preserve existing work, correct the prerequisite outside this run, then start a fresh init run.",
    );
  if (
    ["workspace_changed", "project_configuration_changed"].includes(
      run.pause?.reason,
    ) ||
    action !== null ||
    run.pipelineState.workflowState !== "WAITING_FOR_USER" ||
    (!run.pipelineState.pendingEdit &&
      !INPUT_CHECKPOINTS.includes(run.pipelineState.pauseReason) &&
      !RESUMABLE.includes(run.pause?.reason))
  )
    throw new Error(
      "This init checkpoint cannot resume; preserve the setup and inspect its blocker.",
    );
}
const findings = (state) =>
  state.findings.slice(0, 256).map((summary, index) => ({
    id: `init-${index + 1}`,
    summary: summary.slice(0, 4_000),
  }));
export const initProjections = Object.freeze({
  clarification: (run) => ({
    path: join(run.taskPath, "clarifications.md"),
    hash: run.pipelineState.transcriptHash,
  }),
  pause(run) {
    if (!run.pause) return null;
    let resumable = false;
    try {
      validateResumeAction(run, null);
      resumable = true;
    } catch {}
    const state = run.pipelineState;
    const feedback =
      run.pause.reason === "invalid_result"
        ? initCorrectiveFeedback(state)
        : null;
    return {
      reason: run.pause.reason,
      code:
        feedback?.code ??
        (/^[A-Z0-9_]{1,64}$/u.test(run.pause.code ?? "")
          ? run.pause.code
          : null),
      ...(feedback === null ? {} : { correctiveFeedback: feedback }),
      ...(run.pause.reason === "init_inspection_failed"
        ? { inspectionFailure: { ...assertInspectionFailure(run.pause) } }
        : {}),
      explanation:
        feedback?.explanation ??
        (run.pause.reason === "init_inspection_failed"
          ? inspectionFailureExplanation(run.pause)
          : EXPLANATIONS[run.pause.reason]) ??
        "Init is paused at its saved setup checkpoint.",
      evidence:
        run.pause.reason === "internal_failure"
          ? run.pause.diagnosticClass === undefined
            ? []
            : [`Adapter diagnostic: ${run.pause.diagnosticClass}.`]
          : run.pause.reason === "init_inspection_failed"
            ? []
            : (state.productDecision?.evidence ??
              findings(state).map(({ summary }) => summary)),
      resumeState: resumable ? (run.pause.resumeState ?? null) : null,
      nextActions:
        run.pause.inputResponse !== undefined || !resumable
          ? []
          : run.pause.reason === "init_inspection_failed"
            ? [{ type: "resume", action: null }]
            : state.pendingEdit
              ? [{ type: "respond", requestId: state.pendingEdit.id }]
              : [{ type: "resume", action: null }],
    };
  },
  status(run) {
    return {
      currentStep: null,
      planPath: null,
      findings: findings(run.pipelineState),
      completedCommits: [],
      stagnationDirection: null,
      finalizedFingerprint: null,
      reviewedFingerprint: null,
      setup: run.pipelineState.completion,
    };
  },
});
