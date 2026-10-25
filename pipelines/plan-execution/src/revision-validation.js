import { isDeepStrictEqual } from "node:util";

import {
  assembleBootstrapInventory,
  createBootstrapScope,
} from "./bootstrap-units.js";
import {
  effectivePlanAuthority,
  effectiveStepCorrespondence,
  effectiveStepPosition,
} from "./plan-position.js";
import { executionPolicy } from "./mode-policy.js";
import {
  deriveValidationSchedule,
  scheduledChecks,
  validationEvidenceFingerprint as fingerprint,
} from "./validation-schedule.js";
import { freezeReport } from "./capability-requirements.js";
import {
  MAX_VALIDATION_ITEMS,
  normalizeBootstrapResult,
  normalizePhaseSafeRequiredChecks,
  normalizeValidationInfrastructure,
  workflowError,
} from "./workflow-contract.js";

const exact = (value, keys) =>
  value !== null &&
  typeof value === "object" &&
  !Array.isArray(value) &&
  Object.keys(value).length === keys.length &&
  keys.every((key) => Object.hasOwn(value, key));
const fail = () => {
  throw workflowError("Invalid effective revision validation.");
};
const rejectApplicability = () => {
  throw workflowError(
    "Revision applicability dropped an existing requirement.",
    "ERR_INVALID_PLAN_EXECUTION_OUTPUT",
    {
      field: "assignments",
      constraint: "preserve-prior-revision-applicability",
    },
  );
};
const fields = [
  "requiredChecks",
  "validationInfrastructure",
  "capabilityRequirements",
  "environmentBlockers",
];
const inventoryOf = (result) =>
  Object.fromEntries(fields.map((field) => [field, result[field]]));
const rolesFor = (state) =>
  executionPolicy(state.settings).independentBootstrap
    ? ["worker", "reviewer"]
    : ["worker"];
const amendmentOf = (state) =>
  state.validationAmendment === null
    ? null
    : {
        ...state.validationAmendment,
        validationInfrastructure: state.validationInfrastructure,
      };

function validationRecords(state) {
  return [
    ...(state.replacementExecution?.inputChanges ?? []).flatMap(
      ({ validation }) => (validation === null ? [] : [validation]),
    ),
    ...state.effectiveValidation,
  ].sort((left, right) => left.revision - right.revision);
}

function previousReceipt(state, revision, role, inputFingerprint) {
  return validationRecords(state).findLast(
    (record) =>
      record[role] !== null &&
      (record.revision < revision ||
        (record.revision === revision &&
          record[role].binding.inputFingerprint !== inputFingerprint)),
  );
}

export function revisionBootstrapScope(
  state,
  role,
  {
    inputFingerprint,
    repositoryFingerprint = fingerprint(state.repositoryBaseline),
    infrastructureFingerprint,
    revision,
    step = state.completedCommits.length + 1,
    amendment = amendmentOf(state),
  },
) {
  const authority = effectivePlanAuthority(state, revision);
  const previous = previousReceipt(
    state,
    authority.binding.revision,
    role,
    inputFingerprint,
  );
  const previousValidation =
    previous === undefined
      ? state[`${role}Validation`]
      : (previous[role]?.inventory ?? null);
  const correspondence = effectiveStepCorrespondence(
    state,
    previous?.revision ?? 0,
    authority.binding.revision,
  );
  const inheritedAssignments = (
    previousValidation?.requiredChecks ?? []
  ).flatMap(({ command, steps }) =>
    (steps ?? []).map((step) => ({
      command,
      steps: correspondence[step - 1].steps,
    })),
  );
  if (
    authority.binding.revision !== 0 &&
    role === "worker" &&
    amendment !== null
  ) {
    const targets = amendmentTargets(
      state,
      authority.binding.revision,
      amendment,
      { inputFingerprint, step },
    );
    inheritedAssignments.push(
      ...amendment.requiredChecks.map(({ command }) => ({
        command,
        steps: targets,
      })),
    );
  }
  const position = { step, subject: authority.steps[step - 1]?.subject };
  return createBootstrapScope({
    canonicalPlan: authority.plan,
    role,
    inputFingerprint,
    repositoryFingerprint,
    infrastructureFingerprint,
    position,
    trustedCommands: state.trustedValidation.commands,
    ...(authority.binding.revision === 0
      ? {}
      : {
          planBinding: effectiveStepPosition(
            state,
            step,
            authority.binding.revision,
          ),
          stepMapping: authority.mapping,
          validationAmendment: amendment,
          previousValidation,
          inheritedAssignments,
        }),
  });
}

// Reports and the catalog are additive. An unchanged assignment follows its
// validated splice correspondence; a split assignment must survive on at least
// one descendant, whose exact applicability is independently rediscovered.
function assertPreserved(state, previous, inventory, from, to, output = false) {
  const reject = () => {
    if (output) rejectApplicability();
    fail();
  };
  if (
    previous === null ||
    previous.capabilityRequirements === null ||
    previous.environmentBlockers === null
  )
    reject();
  const rows = effectiveStepCorrespondence(state, from, to);
  for (const [index, check] of previous.requiredChecks.entries()) {
    if (
      !Array.isArray(check.steps) ||
      inventory.requiredChecks[index]?.command !== check.command
    )
      reject();
    const next = inventory.requiredChecks.find(
      ({ command }) => command === check.command,
    );
    if (
      !next ||
      check.steps.some((step) => {
        const row = rows[step - 1];
        return !row || !row.steps.some((target) => next.steps.includes(target));
      })
    )
      reject();
  }
  for (const field of fields.slice(1))
    if (
      !previous[field].every((item) =>
        inventory[field].some((next) => isDeepStrictEqual(item, next)),
      )
    )
      reject();
}

function amendmentTargets(state, number, amendment, binding) {
  const revision = state.effectivePlanRevisions.revisions.find(
    (entry) => entry.number === number && entry.accepted,
  );
  if (
    !exact(amendment, [
      "step",
      "requiredChecks",
      "confirmationFingerprint",
      "validationInfrastructure",
    ]) ||
    !revision ||
    typeof amendment.confirmationFingerprint !== "string" ||
    !/^[a-f0-9]{64}$/u.test(amendment.confirmationFingerprint)
  )
    fail();
  normalizePhaseSafeRequiredChecks(amendment.requiredChecks);
  normalizeValidationInfrastructure(amendment.validationInfrastructure);
  // A receipt can be archived by a compatible clarification while its parent
  // amendment is still active. Keep that original mapping; a newly confirmed
  // amendment after revision preparation belongs to the current replacement.
  const prior = validationRecords(state).filter(
    (record) =>
      record.worker !== null &&
      (record.revision < number ||
        (record.revision === number &&
          record.worker.binding.inputFingerprint !== binding.inputFingerprint)),
  );
  let index = prior.length - 1;
  while (
    prior[index]?.revision === number &&
    isDeepStrictEqual(prior[index].amendment, amendment)
  )
    index--;
  if (prior[index]?.revision === number) {
    if (
      amendment.step !== binding.step ||
      amendment.step < revision.step ||
      amendment.step > effectivePlanAuthority(state, number).steps.length
    )
      fail();
    return [amendment.step];
  }
  if (amendment.step !== revision.step) fail();
  return effectiveStepCorrespondence(state, revision.parent, revision.number)[
    amendment.step - 1
  ].steps;
}

function assertAmendment(state, record, output = false) {
  const amendment = record.amendment;
  if (amendment === null) return;
  const targets = amendmentTargets(
    state,
    record.revision,
    amendment,
    (record.worker ?? record.reviewer).binding,
  );
  if (record.worker === null) return;
  const inventory = record.worker.inventory;
  if (
    amendment.requiredChecks.some(
      ({ command }) =>
        !inventory.requiredChecks.some(
          (check) =>
            check.command === command &&
            targets.some((step) => check.steps.includes(step)),
        ),
    ) ||
    amendment.validationInfrastructure.some(
      (path) => !inventory.validationInfrastructure.includes(path),
    )
  ) {
    if (output) rejectApplicability();
    fail();
  }
}

function expectedSchedule(state, record) {
  if (rolesFor(state).some((role) => record[role] === null)) return null;
  const authority = effectivePlanAuthority(state, record.revision);
  const schedule = deriveValidationSchedule(
    rolesFor(state).map((role) => record[role].inventory),
    authority.steps.length,
    authority.binding,
  );
  if (
    schedule.commands.length > MAX_VALIDATION_ITEMS ||
    schedule.steps.some(
      ({ commandIndexes }) =>
        commandIndexes.length === 0 ||
        commandIndexes.length > MAX_VALIDATION_ITEMS,
    )
  )
    fail();
  const infrastructure = new Set(
    rolesFor(state).flatMap(
      (role) => record[role].inventory.validationInfrastructure,
    ),
  );
  if (infrastructure.size > MAX_VALIDATION_ITEMS) fail();
  return schedule;
}

export function assertRevisionValidation(state) {
  if (!Array.isArray(state.effectiveValidation)) fail();
  if (
    state.effectiveValidation.some(
      (record, index) =>
        record.revision <=
        (state.effectiveValidation[index - 1]?.revision ?? 0),
    )
  )
    fail();
  let previous = null;
  const records = validationRecords(state);
  for (const [index, record] of records.entries()) {
    if (
      !exact(record, [
        "revision",
        "amendment",
        "worker",
        "reviewer",
        "schedule",
      ]) ||
      !Number.isSafeInteger(record.revision) ||
      record.revision < (previous?.revision ?? 1) ||
      (record.worker === null && record.reviewer === null)
    )
      fail();
    const authority = effectivePlanAuthority(state, record.revision);
    const historical = {
      ...state,
      replacementExecution: {
        ...state.replacementExecution,
        inputChanges: [],
      },
      effectiveValidation: records.slice(0, index),
    };
    for (const role of ["worker", "reviewer"]) {
      const receipt = record[role];
      if (receipt === null) continue;
      if (
        !rolesFor(state).includes(role) ||
        !exact(receipt, ["binding", "inventory"])
      )
        fail();
      const binding = receipt.binding;
      const revisionStep = state.effectivePlanRevisions.revisions.find(
        (revision) => revision.number === record.revision,
      ).step;
      const rebound = state.replacementExecution?.inputChanges.some(
        (change) =>
          change.revision === record.revision &&
          change.after === binding?.inputFingerprint,
      );
      if (
        (!rebound && binding?.step !== revisionStep) ||
        binding?.step < revisionStep ||
        binding?.step > state.completedCommits.length + 1 ||
        binding?.step > authority.steps.length
      )
        fail();
      const scope = revisionBootstrapScope(historical, role, {
        ...binding,
        revision: record.revision,
        amendment: record.amendment,
      });
      if (
        !isDeepStrictEqual(binding, scope.binding) ||
        !exact(receipt.inventory, fields)
      )
        fail();
      const normalized = normalizeBootstrapResult(
        {
          ...receipt.inventory,
          status: "READY",
          summary: "Accepted revision applicability.",
          stepAssessment: {
            step: binding.step,
            subject: binding.subject,
            disposition: "CURRENT",
            evidence: [],
          },
          capacityField: "",
          capacityLimit: 0,
          reason: "",
          question: "",
          options: [],
          whyBlocked: "",
          evidence: [],
        },
        role,
        authority.steps.length,
        { trustedCommands: state.trustedValidation.commands },
      );
      if (!isDeepStrictEqual(receipt.inventory, inventoryOf(normalized)))
        fail();
      const prior = previousReceipt(
        historical,
        record.revision,
        role,
        binding.inputFingerprint,
      );
      assertPreserved(
        state,
        prior === undefined
          ? state[`${role}Validation`]
          : prior[role].inventory,
        receipt.inventory,
        prior?.revision ?? 0,
        record.revision,
      );
    }
    assertAmendment(historical, record);
    if (
      record.worker !== null &&
      record.reviewer !== null &&
      ["inputFingerprint", "repositoryFingerprint", "step", "subject"].some(
        (field) =>
          record.worker.binding[field] !== record.reviewer.binding[field],
      )
    )
      fail();
    if (
      !isDeepStrictEqual(record.schedule, expectedSchedule(state, record)) ||
      (previous !== null &&
        previous.revision !== record.revision &&
        previous.schedule === null)
    )
      fail();
    previous = record;
  }
}

// The caller journals the returned state. A complete bounded work record is
// required; assessment, plan approval, or an unbound inventory cannot substitute.
export function acceptRevisionValidation(state, role, scope, work) {
  assertRevisionValidation(state);
  const authority = effectivePlanAuthority(state);
  if (
    authority.binding.revision === 0 ||
    state.pendingCommit !== null ||
    state.workflowState === "COMMIT" ||
    !rolesFor(state).includes(role) ||
    !isDeepStrictEqual(
      scope.binding,
      revisionBootstrapScope(state, role, {
        inputFingerprint: scope.binding.inputFingerprint,
        infrastructureFingerprint: scope.binding.infrastructureFingerprint,
      }).binding,
    )
  )
    fail();
  const inventory = inventoryOf(assembleBootstrapInventory(scope, work));
  const previous = previousReceipt(
    state,
    authority.binding.revision,
    role,
    scope.binding.inputFingerprint,
  );
  assertPreserved(
    state,
    previous === undefined
      ? state[`${role}Validation`]
      : (previous[role]?.inventory ?? null),
    inventory,
    previous?.revision ?? 0,
    authority.binding.revision,
    true,
  );
  const records = structuredClone(state.effectiveValidation);
  let record = records.at(-1);
  if (record?.revision !== authority.binding.revision) {
    record = {
      revision: authority.binding.revision,
      amendment: structuredClone(scope.validationAmendment),
      worker: null,
      reviewer: null,
      schedule: null,
    };
    records.push(record);
  }
  if (!isDeepStrictEqual(record.amendment, scope.validationAmendment)) fail();
  const receipt = { binding: scope.binding, inventory };
  if (record[role] !== null && !isDeepStrictEqual(record[role], receipt))
    fail();
  record[role] = receipt;
  assertAmendment(state, record, true);
  record.schedule = expectedSchedule(state, record);
  const next = { ...state, effectiveValidation: records };
  assertRevisionValidation(next);
  return { ...next, effectiveValidation: freezeReport(records) };
}

export function effectiveValidationInventory(state) {
  assertRevisionValidation(state);
  const record = state.effectiveValidation.at(-1);
  if (
    !record?.schedule ||
    record.revision !== effectivePlanAuthority(state).binding.revision
  )
    return null;
  return {
    workerValidation: record.worker.inventory,
    reviewerValidation: record.reviewer?.inventory ?? null,
    validationSchedule: record.schedule,
    requiredChecks: scheduledChecks(
      { ...state, validationSchedule: record.schedule },
      state.completedCommits.length + 1,
    ),
  };
}
