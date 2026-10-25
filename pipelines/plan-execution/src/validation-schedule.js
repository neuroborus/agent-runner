import { createHash } from "node:crypto";
import { isDeepStrictEqual } from "node:util";
import { effectivePlanAuthority } from "./plan-position.js";

// Role assignments remain immutable. An accepted amendment overlays only the
// selected step; revision schedules retain their accepted authority.
export function deriveValidationSchedule(
  validations,
  stepCount,
  planBinding = null,
) {
  const commands = new Map();
  for (const validation of validations.filter(Boolean)) {
    for (const { command, steps } of validation.requiredChecks) {
      if (!commands.has(command)) commands.set(command, new Set());
      for (const step of steps) commands.get(command).add(step);
    }
  }
  return {
    ...(planBinding === null ? {} : { effectivePlan: planBinding }),
    commands: [...commands.keys()],
    steps: Array.from({ length: stepCount }, (_, index) => ({
      step: index + 1,
      commandIndexes: [...commands.values()].flatMap((steps, commandIndex) =>
        steps.has(index + 1) ? [commandIndex] : [],
      ),
    })),
  };
}

export function scheduledChecks(state, step = state.currentStep) {
  const schedule = state.validationSchedule;
  if (
    !schedule?.effectivePlan &&
    state.effectivePlanRevisions?.revisions.some(
      (revision) => revision.accepted,
    )
  )
    return null;
  if (
    schedule?.effectivePlan &&
    !isDeepStrictEqual(
      schedule.effectivePlan,
      effectivePlanAuthority(state).binding,
    )
  )
    return null;
  const entry = schedule?.steps.find((entry) => entry.step === step);
  return entry
    ? entry.commandIndexes.map((commandIndex, checkIndex) => ({
        id: `C${checkIndex + 1}`,
        command: schedule.commands[commandIndex],
      }))
    : null;
}

export function validationCatalog(state) {
  const commands = new Set();
  for (const validation of [state.workerValidation, state.reviewerValidation]) {
    for (const check of validation?.requiredChecks ?? [])
      commands.add(check.command);
  }
  for (const command of state.validationSchedule?.commands ?? [])
    commands.add(command);
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

// Frozen role inventories remain historical; capability checks use the current
// accepted revision receipts once their complete schedule is selected.
export function validationReports(state) {
  const record = state.effectiveValidation?.find(
    (entry) =>
      entry.revision === state.validationSchedule?.effectivePlan?.revision,
  );
  return record?.schedule
    ? [record.worker.inventory, record.reviewer?.inventory ?? null]
    : [state.workerValidation, state.reviewerValidation];
}
