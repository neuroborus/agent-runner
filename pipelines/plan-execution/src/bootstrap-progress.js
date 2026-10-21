import { isDeepStrictEqual } from "node:util";
import {
  createBootstrapScope,
  createBootstrapWork,
  normalizeBootstrapWork,
} from "./bootstrap-units.js";
import { selectedPlanPosition } from "./plan-position.js";
import { validationEvidenceFingerprint as fingerprint } from "./validation-schedule.js";
import {
  workflowError,
  assertRun,
  normalizePipelineState,
} from "./workflow-contract.js";

export const BOOTSTRAP_LIMITS = Object.freeze({
  maxSteps: 4,
  maxBytes: 256 * 1024,
});
export const MAX_BOOTSTRAP_SUBDIVISIONS = 16;
const exact = (value, keys) =>
  value !== null &&
  typeof value === "object" &&
  Object.keys(value).length === keys.length &&
  keys.every((key) => Object.hasOwn(value, key));

export function clearedBootstrapWork(progress) {
  return Object.fromEntries(
    Object.entries(progress).map(([role, value]) => [
      role,
      { ...value, work: null },
    ]),
  );
}

export function bootstrapScopeFor(
  state,
  role,
  inputFingerprint,
  infrastructureFingerprint,
) {
  return createBootstrapScope({
    canonicalPlan: state.canonicalPlan,
    role,
    inputFingerprint,
    repositoryFingerprint: fingerprint(state.repositoryBaseline),
    infrastructureFingerprint,
    position: selectedPlanPosition(state),
    trustedCommands: state.trustedValidation.commands,
  });
}

// Saved proof is checked structurally on every load; live input and file bindings
// are checked again before reuse. Historical complete inventories need no fake units.
export function validateBootstrapProgress(state) {
  const progress = state.bootstrapProgress;
  if (!exact(progress, ["worker", "reviewer"]))
    throw workflowError("Invalid bootstrap progress.");
  for (const [role, value] of Object.entries(progress)) {
    if (
      !exact(value, ["work", "subdivisions"]) ||
      !Number.isSafeInteger(value.subdivisions) ||
      value.subdivisions < 0 ||
      value.subdivisions > MAX_BOOTSTRAP_SUBDIVISIONS ||
      (role === "reviewer" &&
        state.settings?.mode === "lazy" &&
        (value.work !== null || value.subdivisions !== 0))
    )
      throw workflowError("Invalid bootstrap progress allowance.");
    if (value.work === null) continue;
    try {
      const binding = value.work.binding;
      const scope = bootstrapScopeFor(
        state,
        role,
        binding.inputFingerprint,
        binding.infrastructureFingerprint,
      );
      const phase = state.validationMigrationPending
        ? "validation-migration"
        : "bootstrap";
      const consumed = state.bootstrapCorrections.some(
        ({ diagnostics }) =>
          diagnostics[0].role === role &&
          diagnostics[0].phase === phase &&
          diagnostics[0].contract === "bootstrap",
      );
      normalizeBootstrapWork(value.work, scope, consumed ? 1 : 0);
      const original = createBootstrapWork(
        scope,
        value.work.discovery,
        BOOTSTRAP_LIMITS,
        consumed ? 1 : 0,
      );
      if (
        value.work.correctionAttempt !== (consumed ? 1 : 0) ||
        value.work.units.length - original.units.length > value.subdivisions
      )
        throw workflowError("Bootstrap allowance is inconsistent.");
      if (!isDeepStrictEqual(value.work.limits, BOOTSTRAP_LIMITS))
        throw workflowError("Invalid bootstrap limits.");
    } catch {
      throw workflowError("Invalid persisted bootstrap evidence.");
    }
  }
}

// Compose full persisted validation above the inventory primitives. The general
// workflow contract stays independent of bootstrap units and their validators.
export function normalizeExecutionState(value) {
  const state = normalizePipelineState(value);
  validateBootstrapProgress(state);
  return state;
}

export function assertExecutionRun(run) {
  assertRun(run);
  validateBootstrapProgress(run.pipelineState);
}
