// Only trusted inspection boundaries may turn these constraints into a pause.
// Native messages and rejected paths/values never belong in durable diagnoses.
const CONSTRAINTS = Object.freeze({
  evidence_capacity: "Complete setup evidence exceeds the supported capacity.",
  destination_unavailable:
    "The selected setup destination is unavailable or conflicts with its binding.",
  configuration_invalid:
    "An inspected setup configuration is invalid or unsupported.",
  workspace_changed:
    "Previously inspected sources, inputs, destinations or controls changed.",
  unsafe_path:
    "Inspection could not establish safe path and control confinement.",
  inspection_unavailable: "Complete inspection is temporarily unavailable.",
});
const PHASES = [
  "discovery",
  "inspection",
  "reinspection",
  "preparation",
  "post-turn",
  "publication-preparation",
  "recovery",
];
const CHECKPOINTS = [
  "CLARIFY",
  "PROPOSE",
  "CHECK_AND_FIX",
  "CLEAN_CONFIRM",
  "REVIEW",
  "PROPOSAL_ACCEPTED",
  "DONE",
];
const RETRYABLE_IO = ["EACCES", "EPERM", "EMFILE", "ENFILE", "ENOMEM"];
const BLOCKING_PAUSES = [
  "setup_blocked",
  "revision_limit",
  "clarification_limit",
];

export class InitInspectionError extends Error {
  constructor(constraint, phase = null, message = CONSTRAINTS[constraint]) {
    super(message);
    this.code = "ERR_INIT_INSPECTION";
    this.constraint = constraint;
    this.phase = phase;
  }
}
export function assertInitInspection(condition, constraint, message) {
  if (!condition) throw new InitInspectionError(constraint, null, message);
}

function constraintFor(cause) {
  if (!(cause instanceof Error)) return null;
  if (
    cause instanceof InitInspectionError &&
    Object.hasOwn(CONSTRAINTS, cause.constraint)
  )
    return cause.constraint;
  if (
    [
      "ERR_UNSAFE_GUIDANCE_PATH",
      "ERR_GUIDANCE_STORAGE",
      "ERR_PROJECT_CONFIGURATION_READ",
    ].includes(cause?.code) &&
    [
      "inspection_unavailable",
      "workspace_changed",
      "unsafe_path",
      "evidence_capacity",
    ].includes(cause.readFailure)
  )
    return cause.readFailure;
  if (
    ["ERR_INVALID_CLARIFICATION", "ERR_PROJECT_CONFIGURATION_READ"].includes(
      cause?.code,
    )
  ) {
    if (cause.constraint === "file_size") return "evidence_capacity";
    if (cause.constraint === "isolated_regular_file") return "unsafe_path";
    if (
      cause.code === "ERR_PROJECT_CONFIGURATION_READ" &&
      cause.constraint === "missing_file"
    )
      return "workspace_changed";
  }
  switch (cause?.code) {
    case "ERR_WORKSPACE_PROOF_CAPACITY":
      return "evidence_capacity";
    case "ERR_CLARIFICATIONS_CHANGED":
    case "ERR_CLARIFICATION_NOT_FOUND":
    case "ERR_WORKSPACE_DRIFT":
    case "ERR_WORKSPACE_SNAPSHOT_RACE":
      return "workspace_changed";
    case "ERR_UNSAFE_CLARIFICATION_PATH":
    case "ERR_WORKSPACE_PATH":
    case "ERR_PROJECT_CONFIGURATION_NOT_IGNORED":
      return "unsafe_path";
    case "ERR_PROJECT_CONFIGURATION_BINDING":
    case "ERR_INVALID_CONFIGURATION":
    case "ERR_UNSUPPORTED_CONFIGURATION_VERSION":
      return "configuration_invalid";
    case "ERR_CLARIFICATION_READ":
    case "ERR_PROJECT_CONFIGURATION_READ":
    case "ERR_WORKSPACE_INSPECTION":
      if (cause.cause?.code === "ENOENT") return "workspace_changed";
      if (RETRYABLE_IO.includes(cause.cause?.code))
        return "inspection_unavailable";
  }
  return null;
}

export async function inspectInitOperation(phase, operation) {
  try {
    return await operation();
  } catch (cause) {
    if (cause?.executionResourceRetained) throw cause;
    const constraint = constraintFor(cause);
    if (constraint === null) throw cause;
    throw new InitInspectionError(
      constraint,
      cause instanceof InitInspectionError ? (cause.phase ?? phase) : phase,
    );
  }
}

export function assertInspectionFailure(pause, state = null) {
  const failure = pause?.inspectionFailure;
  if (
    pause?.reason !== "init_inspection_failed" ||
    pause.code !== "ERR_INIT_INSPECTION" ||
    failure === null ||
    typeof failure !== "object" ||
    Array.isArray(failure) ||
    ![Object.prototype, null].includes(Object.getPrototypeOf(failure)) ||
    Object.keys(failure).length !== 2 ||
    !Object.hasOwn(failure, "phase") ||
    !Object.hasOwn(failure, "constraint") ||
    !PHASES.includes(failure.phase) ||
    typeof failure.constraint !== "string" ||
    !Object.hasOwn(CONSTRAINTS, failure.constraint) ||
    !CHECKPOINTS.includes(pause.resumeState) ||
    BLOCKING_PAUSES.includes(state?.pauseReason)
  )
    throw new Error("Init inspection diagnosis is invalid.");
  return failure;
}

export function inspectionFailureExplanation(pause) {
  const { phase, constraint } = assertInspectionFailure(pause);
  const next =
    constraint === "inspection_unavailable"
      ? "Restore inspection access or resources without changing frozen inputs, then resume."
      : "Preserve existing work, correct the prerequisite outside this run, then start a fresh init run.";
  return `Init ${phase}: ${CONSTRAINTS[constraint]} ${next}`;
}

// Root recovery uses the same owner before lifecycle dispatch. Null phase admits
// only tagged lifecycle rejections, never arbitrary invocation/effect errors.
export function initInspectionFailure(run, cause, phase = "recovery") {
  if (
    phase === null &&
    !(cause instanceof InitInspectionError && PHASES.includes(cause.phase))
  )
    return null;
  const constraint = constraintFor(cause);
  const resumeState = run.pause?.resumeState ?? run.pipelineState.workflowState;
  if (
    constraint === null ||
    !CHECKPOINTS.includes(resumeState) ||
    BLOCKING_PAUSES.includes(run.pipelineState.pauseReason) ||
    cause.executionResourceRetained ||
    run.preparation != null ||
    run.executionProcess != null ||
    run.executionResource != null ||
    run.pipelineState.publication?.pending != null ||
    (run.pipelineState.guidanceIntent !== null &&
      run.pipelineState.guidanceReceipt === null)
  )
    return null;
  const pause = {
    reason: "init_inspection_failed",
    code: "ERR_INIT_INSPECTION",
    resumeState,
    inspectionFailure: {
      phase:
        cause instanceof InitInspectionError ? (cause.phase ?? phase) : phase,
      constraint,
    },
  };
  assertInspectionFailure(pause);
  return {
    pipelineState: {
      ...run.pipelineState,
      workflowState: "WAITING_FOR_USER",
      pendingTurn: null,
    },
    pause,
    activeTurn: null,
  };
}
