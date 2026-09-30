import { createHash } from "node:crypto";

// Role assignments remain immutable. An accepted amendment overlays only the
// selected step; advancement always selects the next original inventory.
export function deriveValidationSchedule(validations, stepCount) {
  const commands = new Map();
  for (const validation of validations.filter(Boolean)) {
    for (const { command, steps } of validation.requiredChecks) {
      if (!commands.has(command)) commands.set(command, new Set());
      for (const step of steps) commands.get(command).add(step);
    }
  }
  return Array.from({ length: stepCount }, (_, index) => ({
    step: index + 1,
    requiredChecks: [...commands]
      .filter(([, steps]) => steps.has(index + 1))
      .map(([command], checkIndex) => ({ id: `C${checkIndex + 1}`, command })),
  }));
}

export function scheduledChecks(state, step = state.currentStep) {
  return (
    state.validationSchedule?.find((entry) => entry.step === step)
      ?.requiredChecks ?? null
  );
}

export function validationCatalog(state) {
  const commands = new Set();
  for (const validation of [state.workerValidation, state.reviewerValidation]) {
    for (const check of validation?.requiredChecks ?? [])
      commands.add(check.command);
  }
  for (const entry of state.validationSchedule ?? []) {
    for (const check of entry.requiredChecks) commands.add(check.command);
  }
  for (const check of state.requiredChecks ?? []) commands.add(check.command);
  return [...commands];
}

export function activeTrustedCommands(state) {
  const active = new Set(state.requiredChecks?.map(({ command }) => command));
  return state.trustedValidation.commands.filter(({ command }) =>
    active.has(command),
  );
}

export function validationEvidenceFingerprint(evidence) {
  const canonical = (value) =>
    Array.isArray(value)
      ? value.map(canonical)
      : value !== null && typeof value === "object"
        ? Object.fromEntries(
            Object.keys(value)
              .sort()
              .map((key) => [key, canonical(value[key])]),
          )
        : value;
  return createHash("sha256")
    .update(JSON.stringify(canonical(evidence)))
    .digest("hex");
}

export function acceptedValidationAmendment(state) {
  const evidence = state.finalizationResult;
  return {
    requiredChecks: evidence.requiredChecks,
    validationAmendment: {
      step: state.currentStep,
      requiredChecks: evidence.requiredChecks,
      confirmationFingerprint: validationEvidenceFingerprint(evidence),
    },
    validationInfrastructure: evidence.validationInfrastructure,
    validationInfrastructureFingerprint:
      evidence.validationInfrastructureFingerprint,
  };
}
