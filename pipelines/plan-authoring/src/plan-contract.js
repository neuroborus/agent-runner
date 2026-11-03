import { join, resolve } from "node:path";
import { isDeepStrictEqual } from "node:util";

import {
  parseCommitPlan,
  serializeCommitPlan,
} from "@agent-runner/commit-plan";
import {
  CustomPlanValidationError,
  normalizeCustomCriteria,
  parseCustomPlan,
  serializeCustomPlan,
} from "@agent-runner/custom-plan";

export const MAX_PLAN_LENGTH = 100_000;
const DRAFT_STEP_HEADROOM = 4_000;

const pathReference = (value) =>
  typeof value === "string" &&
  value.length > 0 &&
  value.length <= 4096 &&
  value === value.trim() &&
  !/[\0\p{Cc}\p{Zl}\p{Zp}]/u.test(value);
const references = (value) =>
  Array.isArray(value) &&
  value.length <= 256 &&
  value.every(pathReference) &&
  new Set(value).size === value.length;
const remoteReference = (value) => /^[a-z][a-z0-9+.-]*:/iu.test(value);

export const PLAN_SETTINGS = Object.freeze({
  planKind: Object.freeze({
    defaultValue: "commit",
    values: Object.freeze(["commit", "custom"]),
    option: "plan-kind",
    errorMessage: "must be commit or custom",
    validate: (value) => ["commit", "custom"].includes(value),
  }),
  criteriaPath: Object.freeze({
    defaultValue: null,
    option: "criteria",
    errorMessage: "must be a local criteria path or null",
    validate: (value) =>
      value === null || (pathReference(value) && !remoteReference(value)),
  }),
  sourceReferences: Object.freeze({
    defaultValue: Object.freeze([]),
    option: "source",
    multiple: true,
    errorMessage: "must contain distinct source references",
    validate: references,
  }),
  outputPaths: Object.freeze({
    defaultValue: Object.freeze([]),
    option: "output",
    multiple: true,
    errorMessage: "must contain distinct local output paths",
    validate: (value) =>
      references(value) && value.every((path) => !remoteReference(path)),
  }),
});

export const LEGACY_PLAN_SETTINGS = Object.freeze(
  Object.fromEntries(
    Object.entries(PLAN_SETTINGS).map(([name, definition]) => [
      name,
      definition.defaultValue,
    ]),
  ),
);

export function resolveAuthoringWorkspace({
  settingOverrides: settings = {},
  projectPath,
  taskPath,
}) {
  const kind = settings.planKind ?? "commit";
  if (!PLAN_SETTINGS.planKind.validate(kind))
    throw new Error("Unknown authoring plan kind.");
  for (const [name, definition] of Object.entries(PLAN_SETTINGS)) {
    if (settings[name] !== undefined && !definition.validate(settings[name]))
      throw new Error(`Authoring ${name} ${definition.errorMessage}.`);
  }
  const inputPaths = settings.criteriaPath
    ? [resolve(projectPath, settings.criteriaPath)]
    : [];
  const sourcePaths = (settings.sourceReferences ?? [])
    .filter((source) => !remoteReference(source))
    .map((source) => resolve(projectPath, source));
  const artifactPaths = [
    join(taskPath, "clarifications.md"),
    join(taskPath, "plan.md"),
  ];
  return Object.freeze({
    kind: kind === "custom" ? "directory" : "git",
    lease: kind === "custom" ? "exclusive" : "none",
    inputPaths,
    sourcePaths,
    // Planned outputs are declarations, never writable authoring roots.
    artifactPaths,
  });
}

export function resolveAuthoringTaskInputs({ settings, projectPath }) {
  return settings?.criteriaPath
    ? {
        criteria: {
          path: resolve(projectPath, settings.criteriaPath),
          optional: false,
        },
      }
    : {};
}

export function normalizeAgreedCriteria(value, { allowEmpty = false } = {}) {
  if (allowEmpty && Array.isArray(value) && value.length === 0)
    return Object.freeze([]);
  const criteria = normalizeCustomCriteria(value);
  if (
    criteria.length > 256 ||
    criteria.some(
      ({ id, condition }) => id.length > 64 || condition.length > 4000,
    )
  )
    throw new CustomPlanValidationError([
      "Agreed criteria exceed the bounded authoring catalog.",
    ]);
  return criteria;
}

export function assertCustomAuthoringBudget(criteria, settings) {
  const minimumPlan = serializeCustomPlan({
    kind: "custom",
    criteria,
    inputs: settings.sourceReferences,
    outputs: settings.outputPaths,
    steps: [
      {
        number: 1,
        title: "Result",
        work: "Work",
        expectedResults: "Result",
        criterionRefs: criteria.map(({ id }) => id),
      },
    ],
  });
  if (minimumPlan.length + DRAFT_STEP_HEADROOM > MAX_PLAN_LENGTH)
    throw new CustomPlanValidationError([
      "Custom declarations exceed the authoring draft budget, including required step content headroom.",
    ]);
}

export function canonicalAuthoringPlan(source, settings, agreedCriteria) {
  if ((settings?.planKind ?? "commit") === "commit")
    return serializeCommitPlan(parseCommitPlan(source));
  const plan = parseCustomPlan(source);
  const expectedInputs = settings.sourceReferences;
  if (
    !isDeepStrictEqual(plan.criteria, agreedCriteria) ||
    !isDeepStrictEqual(plan.inputs, expectedInputs) ||
    !isDeepStrictEqual(plan.outputs, settings.outputPaths)
  ) {
    throw new CustomPlanValidationError([
      "Custom plan declarations must match the frozen criteria, sources and outputs exactly.",
    ]);
  }
  const canonicalPlan = serializeCustomPlan(plan);
  if (canonicalPlan.length > MAX_PLAN_LENGTH)
    throw new CustomPlanValidationError([
      "Canonical custom plan exceeds the authoring draft limit.",
    ]);
  return canonicalPlan;
}
