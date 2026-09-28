import {
  ADAPTER_FAILURE_CLASS,
  isAdapterDiagnosticClass,
  LAUNCH_RECOVERY_CHECKPOINTS,
} from "../agents/index.js";

const LAUNCH_RECOVERY_FIELDS = Object.freeze(["failureClass", "checkpoint"]);

export function normalizeLaunchRecovery(value) {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    ![Object.prototype, null].includes(Object.getPrototypeOf(value)) ||
    Reflect.ownKeys(value).length !== LAUNCH_RECOVERY_FIELDS.length ||
    LAUNCH_RECOVERY_FIELDS.some((field) => !Object.hasOwn(value, field)) ||
    !LAUNCH_RECOVERY_CHECKPOINTS.includes(value.checkpoint) ||
    (value.failureClass !== ADAPTER_FAILURE_CLASS &&
      !isAdapterDiagnosticClass(value.failureClass))
  ) {
    throw new TypeError("Launch recovery is invalid.");
  }
  return Object.freeze({
    failureClass: value.failureClass,
    checkpoint: value.checkpoint,
  });
}

export function projectLaunchRecovery(run) {
  if (run.pause?.reason === "backend_unavailable") {
    return run.pause.launchRecovery ?? null;
  }
  if (run.pause?.reason === "operator_paused") {
    const retained = run.pause.operatorResume.pause;
    if (retained?.reason === "backend_unavailable") {
      return retained.launchRecovery ?? null;
    }
  }
  return null;
}
