import { isDeepStrictEqual } from "node:util";
import {
  parseCommitPlan,
  serializeCommitPlan,
} from "@agent-runner/commit-plan";
import { matchesPlanPosition, validStepAssessment } from "./plan-position.js";
import {
  freezeReport,
  validCapabilityReports,
} from "./capability-requirements.js";
import { validationEvidenceFingerprint as fingerprint } from "./validation-schedule.js";
import {
  MAX_BOOTSTRAP_ITEMS,
  MAX_PLAN_LENGTH,
  assertStructuredResultSize,
  isRecord,
  normalizeBootstrapResult,
  normalizePhaseSafeRequiredChecks,
  normalizeRequiredChecks,
  stagingDependentCheckDiagnostics,
  normalizeSummary,
  normalizeValidationInfrastructure,
  sha256,
  workflowError,
} from "./workflow-contract.js";

const VERSION = 1;
const INVALID = "ERR_INVALID_PLAN_EXECUTION_OUTPUT";
const exact = (value, keys) =>
  isRecord(value) &&
  Object.keys(value).length === keys.length &&
  keys.every((key) => Object.hasOwn(value, key));
const fail = (field, constraint) => {
  throw workflowError("Invalid bounded bootstrap evidence.", INVALID, {
    field,
    constraint,
  });
};
const assert = (valid, field, constraint) => {
  if (!valid) fail(field, constraint);
};
const finish = (value) => freezeReport(structuredClone(value));
const DISCOVERY_FIELDS = [
  "stepAssessment",
  "summary",
  "requiredChecks",
  "validationInfrastructure",
  "capabilityRequirements",
  "environmentBlockers",
];

// The caller supplies frozen root-owned fingerprints and the existing role
// correction attempt. Neither provider output nor a reconstructed session owns
// these values. Scope contains plan text for requests; work records contain hashes.
export function createBootstrapScope({
  canonicalPlan,
  role,
  inputFingerprint,
  repositoryFingerprint,
  infrastructureFingerprint,
  position,
  trustedCommands = [],
}) {
  assert(
    typeof canonicalPlan === "string" &&
      canonicalPlan.length <= MAX_PLAN_LENGTH,
    "canonicalPlan",
    "bounded-canonical-plan",
  );
  const plan = parseCommitPlan(canonicalPlan);
  assert(
    serializeCommitPlan(plan) === canonicalPlan,
    "canonicalPlan",
    "canonical-plan",
  );
  assert(["worker", "reviewer"].includes(role), "role", "producing-role");
  for (const value of [
    inputFingerprint,
    repositoryFingerprint,
    infrastructureFingerprint,
  ])
    assert(
      typeof value === "string" && /^[a-f0-9]{64}$/u.test(value),
      "binding",
      "sha256-fingerprints",
    );
  assert(
    Number.isSafeInteger(position?.step) &&
      position.step > 0 &&
      position.step <= plan.steps.length &&
      plan.steps[position.step - 1]?.subject === position.subject,
    "stepAssessment",
    "runner-selected-position",
  );
  return finish({
    binding: {
      version: VERSION,
      role,
      inputFingerprint,
      planFingerprint: sha256(canonicalPlan),
      repositoryFingerprint,
      infrastructureFingerprint,
      trustedFingerprint: fingerprint(trustedCommands),
      step: position.step,
      subject: position.subject,
    },
    steps: plan.steps,
    trustedCommands,
  });
}

export function normalizeRepositoryDiscovery(
  payload,
  scope,
  { deferredDiagnostics = false } = {},
) {
  assertStructuredResultSize(payload);
  assert(exact(payload, DISCOVERY_FIELDS), "discovery", "exact-field-set");
  assert(
    validStepAssessment(payload.stepAssessment) &&
      matchesPlanPosition(payload.stepAssessment, scope.binding),
    "stepAssessment",
    "runner-selected-position",
  );
  const requiredChecks = (
    deferredDiagnostics
      ? normalizeRequiredChecks
      : normalizePhaseSafeRequiredChecks
  )(payload.requiredChecks, INVALID, {
    maxItems: MAX_BOOTSTRAP_ITEMS,
  });
  assert(
    validCapabilityReports(payload, requiredChecks, scope.trustedCommands),
    "capabilityRequirements",
    "exact-command-capability-reports",
  );
  assert(
    deferredDiagnostics ||
      scope.trustedCommands.every(({ command }) =>
        requiredChecks.some((check) => check.command === command),
      ),
    "requiredChecks",
    "includes-runner-trusted-commands",
  );
  const result = finish({
    ...payload,
    summary: normalizeSummary(
      payload.summary,
      "repository discovery",
      INVALID,
      {
        field: "summary",
        constraint: "concise-markdown-up-to-20000-characters",
      },
    ),
    requiredChecks,
    validationInfrastructure: normalizeValidationInfrastructure(
      payload.validationInfrastructure,
      INVALID,
      { maxItems: MAX_BOOTSTRAP_ITEMS },
    ),
  });
  return deferredDiagnostics
    ? { result, diagnostics: stagingDependentCheckDiagnostics(requiredChecks) }
    : result;
}

// This exact request is the measured supplied JSON. Referenced file contents and
// provider framing are not measured here and must not be reported as included.
export function applicabilityRequest(scope, discovery, start, end) {
  assert(
    Number.isSafeInteger(start) &&
      Number.isSafeInteger(end) &&
      start >= 1 &&
      end >= start &&
      end <= scope.steps.length,
    "range",
    "contiguous-canonical-range",
  );
  const catalogFingerprint = fingerprint(discovery);
  return {
    unitId: fingerprint({
      binding: scope.binding,
      catalogFingerprint,
      start,
      end,
    }),
    binding: scope.binding,
    catalogFingerprint,
    discovery,
    steps: scope.steps.slice(start - 1, end),
  };
}

function unitFor(scope, discovery, start, end) {
  const request = applicabilityRequest(scope, discovery, start, end);
  return {
    id: request.unitId,
    start,
    end,
    suppliedBytes: Buffer.byteLength(JSON.stringify(request)),
  };
}

function capacity() {
  throw workflowError(
    "Bootstrap applicability cannot subdivide beyond one canonical step.",
    "ERR_BOOTSTRAP_UNIT_CAPACITY_EXHAUSTED",
  );
}

function children(scope, discovery, unit) {
  if (unit.start === unit.end) capacity();
  const middle = Math.floor((unit.start + unit.end) / 2);
  return [
    unitFor(scope, discovery, unit.start, middle),
    unitFor(scope, discovery, middle + 1, unit.end),
  ];
}

function boundedUnits(scope, discovery, limits) {
  assert(
    exact(limits, ["maxSteps", "maxBytes"]) &&
      [limits.maxSteps, limits.maxBytes].every(
        (value) => Number.isSafeInteger(value) && value > 0,
      ),
    "limits",
    "positive-finite-unit-bounds",
  );
  const fit = (unit) => {
    if (unit.suppliedBytes <= limits.maxBytes) return [unit];
    return children(scope, discovery, unit).flatMap(fit);
  };
  const units = [];
  for (let start = 1; start <= scope.steps.length; start += limits.maxSteps) {
    units.push(
      ...fit(
        unitFor(
          scope,
          discovery,
          start,
          Math.min(scope.steps.length, start + limits.maxSteps - 1),
        ),
      ),
    );
  }
  return units;
}

export function createBootstrapWork(scope, payload, limits, correctionAttempt) {
  assert(
    [0, 1].includes(correctionAttempt),
    "correctionAttempt",
    "existing-role-allowance",
  );
  const discovery = normalizeRepositoryDiscovery(payload, scope);
  return finish({
    binding: scope.binding,
    discovery,
    catalogFingerprint: fingerprint(discovery),
    limits,
    correctionAttempt,
    pendingCorrection: null,
    units: boundedUnits(scope, discovery, limits),
    accepted: [],
    catalogCorrection: null,
  });
}

function normalizeBatch(payload, scope, work, unit) {
  assertStructuredResultSize(payload);
  assert(
    exact(payload, [
      "status",
      "unitId",
      "assignments",
      "missingCommands",
      "missingInfrastructure",
      "capabilityRequirements",
      "environmentBlockers",
    ]) &&
      payload.unitId === unit.id &&
      Array.isArray(payload.assignments),
    "batch",
    "exact-bound-unit-result",
  );
  const correction = payload.status === "CATALOG_CORRECTION_REQUIRED";
  assert(
    correction || payload.status === "READY",
    "status",
    "supported-status",
  );
  assert(
    Array.isArray(payload.missingCommands),
    "missingCommands",
    "exact-command-list",
  );
  const missingChecks = payload.missingCommands.map((command, index) => ({
    id: `C${index + 1}`,
    command,
  }));
  normalizePhaseSafeRequiredChecks(missingChecks, INVALID, {
    allowEmpty: true,
    maxItems: MAX_BOOTSTRAP_ITEMS,
  });
  normalizeValidationInfrastructure(payload.missingInfrastructure, INVALID, {
    maxItems: MAX_BOOTSTRAP_ITEMS,
  });
  const reportFields = ["capabilityRequirements", "environmentBlockers"];
  assert(
    validCapabilityReports(
      payload,
      [...work.discovery.requiredChecks, ...missingChecks],
      scope.trustedCommands,
    ),
    "capabilityRequirements",
    "exact-command-capability-reports",
  );
  assert(
    reportFields.every((field) =>
      payload[field].every(
        (report) =>
          !work.discovery[field].some((existing) =>
            isDeepStrictEqual(existing, report),
          ),
      ),
    ),
    "catalogCorrection",
    "new-capability-evidence",
  );
  assert(
    payload.missingCommands.every(
      (command) =>
        !work.discovery.requiredChecks.some(
          (check) => check.command === command,
        ),
    ) &&
      payload.missingInfrastructure.every(
        (path) => !work.discovery.validationInfrastructure.includes(path),
      ),
    "catalogCorrection",
    "missing-catalog-requirements",
  );
  if (correction) {
    assert(
      payload.assignments.length === 0 &&
        payload.missingCommands.length +
          payload.missingInfrastructure.length +
          payload.capabilityRequirements.length +
          payload.environmentBlockers.length >
          0,
      "catalogCorrection",
      "nonempty-correction-without-coverage",
    );
  } else {
    assert(
      payload.missingCommands.length === 0 &&
        payload.missingInfrastructure.length === 0 &&
        reportFields.every((field) => payload[field].length === 0),
      "batch",
      "ready-without-correction",
    );
    const checks = work.discovery.requiredChecks;
    let previous = -1;
    const coverage = new Set();
    for (const assignment of payload.assignments) {
      assert(
        exact(assignment, ["checkId", "steps"]),
        "assignments",
        "exact-field-set",
      );
      const index = checks.findIndex(({ id }) => id === assignment.checkId);
      assert(index > previous, "assignments", "unique-catalog-order");
      previous = index;
      assert(
        Array.isArray(assignment.steps) &&
          assignment.steps.length > 0 &&
          assignment.steps.every(
            (step, offset, steps) =>
              Number.isSafeInteger(step) &&
              step >= unit.start &&
              step <= unit.end &&
              (offset === 0 || step > steps[offset - 1]),
          ),
        "assignments",
        "ascending-unit-steps",
      );
      for (const step of assignment.steps) coverage.add(step);
    }
    assert(
      coverage.size === unit.end - unit.start + 1,
      "assignments",
      "complete-unit-coverage",
    );
  }
  return finish(payload);
}

// Reload validates saved acceptance against current frozen inputs and the saved
// role allowance. A session reset or a smaller batch cannot mint another attempt.
export function normalizeBootstrapWork(value, scope, correctionAttempt) {
  assert(
    exact(value, [
      "binding",
      "discovery",
      "catalogFingerprint",
      "limits",
      "correctionAttempt",
      "pendingCorrection",
      "units",
      "accepted",
      "catalogCorrection",
    ]) && isDeepStrictEqual(value.binding, scope.binding),
    "binding",
    "matching-frozen-context",
  );
  const initial = createBootstrapWork(
    scope,
    value.discovery,
    value.limits,
    value.correctionAttempt,
  );
  assert(
    [0, 1].includes(correctionAttempt) &&
      value.correctionAttempt >= correctionAttempt,
    "correctionAttempt",
    "conserved-role-allowance",
  );
  assert(
    value.catalogFingerprint === initial.catalogFingerprint &&
      isDeepStrictEqual(value.discovery, initial.discovery),
    "catalogFingerprint",
    "accepted-discovery",
  );
  assert(
    Array.isArray(value.units) &&
      value.units.length > 0 &&
      value.units.length <= scope.steps.length,
    "units",
    "bounded-complete-partition",
  );
  let leaf = 0;
  const inspectSubdivision = (unit) => {
    if (isDeepStrictEqual(unit, value.units[leaf])) {
      leaf++;
      return;
    }
    assert(unit.start < unit.end, "units", "deterministic-subdivision");
    for (const child of children(scope, initial.discovery, unit))
      inspectSubdivision(child);
  };
  for (const unit of initial.units) inspectSubdivision(unit);
  assert(leaf === value.units.length, "units", "deterministic-subdivision");
  assert(
    Array.isArray(value.accepted) &&
      value.accepted.length <= value.units.length,
    "accepted",
    "ordered-unit-evidence",
  );
  for (const [index, accepted] of value.accepted.entries()) {
    const normalized = normalizeBatch(
      accepted,
      scope,
      value,
      value.units[index],
    );
    assert(normalized.status === "READY", "accepted", "ready-coverage-only");
  }
  if (value.catalogCorrection !== null) {
    assert(
      value.accepted.length < value.units.length,
      "catalogCorrection",
      "pending-unit",
    );
    const correction = normalizeBatch(
      value.catalogCorrection,
      scope,
      value,
      value.units[value.accepted.length],
    );
    assert(
      correction.status === "CATALOG_CORRECTION_REQUIRED",
      "catalogCorrection",
      "correction-only",
    );
  }
  assert(
    value.pendingCorrection === null ||
      (value.correctionAttempt === 1 &&
        value.accepted.length < value.units.length &&
        ((value.pendingCorrection === "catalog" &&
          value.catalogCorrection !== null) ||
          (value.pendingCorrection === "unit" &&
            value.catalogCorrection === null))),
    "pendingCorrection",
    "consumed-role-authorization",
  );
  return finish(value);
}

export function acceptBootstrapBatch(scope, value, payload) {
  const work = normalizeBootstrapWork(value, scope, value.correctionAttempt);
  assert(
    work.catalogCorrection === null && work.accepted.length < work.units.length,
    "batch",
    "next-unaccepted-unit",
  );
  const result = normalizeBatch(
    payload,
    scope,
    work,
    work.units[work.accepted.length],
  );
  const next =
    result.status === "READY"
      ? {
          ...work,
          accepted: [...work.accepted, result],
          pendingCorrection: null,
        }
      : { ...work, catalogCorrection: result, pendingCorrection: null };
  if (next.accepted.length === next.units.length)
    assembleBootstrapInventory(scope, next);
  return finish(next);
}

export function subdivideBootstrapWork(scope, value) {
  const work = normalizeBootstrapWork(value, scope, value.correctionAttempt);
  assert(
    work.catalogCorrection === null && work.accepted.length < work.units.length,
    "units",
    "next-unaccepted-unit",
  );
  const index = work.accepted.length;
  return finish({
    ...work,
    units: [
      ...work.units.slice(0, index),
      ...children(scope, work.discovery, work.units[index]),
      ...work.units.slice(index + 1),
    ],
  });
}

export function consumeBootstrapCorrection(scope, value) {
  const work = normalizeBootstrapWork(value, scope, value.correctionAttempt);
  assert(
    work.correctionAttempt === 0,
    "correctionAttempt",
    "role-correction-exhausted",
  );
  assert(
    work.accepted.length < work.units.length,
    "correctionAttempt",
    "pending-unit",
  );
  return finish({
    ...work,
    correctionAttempt: 1,
    pendingCorrection: work.catalogCorrection === null ? "unit" : "catalog",
  });
}

export function correctBootstrapCatalog(scope, value, payload) {
  const work = normalizeBootstrapWork(value, scope, value.correctionAttempt);
  const missing = work.catalogCorrection;
  assert(
    missing !== null && work.pendingCorrection === "catalog",
    "catalogCorrection",
    "consumed-catalog-authorization",
  );
  const replacement = createBootstrapWork(
    scope,
    payload,
    work.limits,
    work.correctionAttempt,
  );
  const discovery = replacement.discovery;
  assert(
    work.discovery.requiredChecks.every((check, index) =>
      isDeepStrictEqual(check, discovery.requiredChecks[index]),
    ) &&
      [
        ...work.discovery.validationInfrastructure,
        ...missing.missingInfrastructure,
      ].every((path) => discovery.validationInfrastructure.includes(path)) &&
      missing.missingCommands.every((command) =>
        discovery.requiredChecks.some((check) => check.command === command),
      ) &&
      ["capabilityRequirements", "environmentBlockers"].every((field) =>
        [...work.discovery[field], ...missing[field]].every((report) =>
          discovery[field].some((candidate) =>
            isDeepStrictEqual(report, candidate),
          ),
        ),
      ),
    "catalogCorrection",
    "preserve-and-complete-catalog",
  );
  return replacement;
}

export function assembleBootstrapInventory(scope, value) {
  const work = normalizeBootstrapWork(value, scope, value.correctionAttempt);
  assert(
    work.catalogCorrection === null &&
      work.accepted.length === work.units.length,
    "accepted",
    "complete-plan-coverage",
  );
  const checks = work.discovery.requiredChecks.map((check) => ({
    ...check,
    steps: work.accepted.flatMap(
      (batch) =>
        batch.assignments.find(({ checkId }) => checkId === check.id)?.steps ??
        [],
    ),
  }));
  return normalizeBootstrapResult(
    {
      ...work.discovery,
      status: "READY",
      requiredChecks: checks,
      capacityField: "",
      capacityLimit: 0,
      reason: "",
      question: "",
      options: [],
      whyBlocked: "",
      evidence: [],
    },
    scope.binding.role,
    scope.steps.length,
    { trustedCommands: scope.trustedCommands },
  );
}
