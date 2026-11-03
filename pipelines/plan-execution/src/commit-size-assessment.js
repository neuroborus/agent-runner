import { createHash } from "node:crypto";
import { isDeepStrictEqual } from "node:util";

import { parseCommitPlan } from "@agent-runner/commit-plan";

import { executionPolicy } from "./mode-policy.js";

export const COMMIT_SIZE_DEFAULTS = Object.freeze({
  preferredCommitLineLimit: 900,
  commitSizeAssessmentMultiplier: 3,
});
// Shared by an original step and all of its eventual replacements. A proposal
// consumes an assessment too; neither reconstruction nor refinement renews it.
export const MAX_SIZE_ASSESSMENTS = 3;
const HASH = /^[a-f0-9]{64}$/u;
const HEAD = /^(?:[a-f0-9]{40}|[a-f0-9]{64})$/u;
const BINDING_FIELDS = [
  "originalStep",
  "planFingerprint",
  "inputFingerprint",
  "scopeFingerprint",
  "dependenciesFingerprint",
  "baseHead",
  "contentFingerprint",
  "changedLines",
  "binaryFiles",
  "gitlinks",
  "preferredCommitLineLimit",
  "threshold",
];
const exact = (value, fields) =>
  value !== null &&
  typeof value === "object" &&
  !Array.isArray(value) &&
  Object.keys(value).length === fields.length &&
  fields.every((field) => Object.hasOwn(value, field));
const count = (value) => Number.isSafeInteger(value) && value >= 0;
const text = (value, limit) =>
  typeof value === "string" &&
  value.trim().length > 0 &&
  value.length <= limit &&
  !/[\0\u2028\u2029]/u.test(value);
const fingerprint = (binding) =>
  createHash("sha256")
    .update(JSON.stringify(BINDING_FIELDS.map((field) => binding[field])))
    .digest("hex");

export function commitSizeThreshold(settings) {
  const target = settings.preferredCommitLineLimit;
  const multiplier = settings.commitSizeAssessmentMultiplier;
  if (
    ![target, multiplier].every(
      (value) => Number.isSafeInteger(value) && value > 0,
    ) ||
    !Number.isSafeInteger(target * multiplier)
  ) {
    throw new Error(
      "preferredCommitLineLimit and commitSizeAssessmentMultiplier must produce a positive safe-integer threshold.",
    );
  }
  return target * multiplier;
}

export function createCommitSizeAssessment({ eligible = false } = {}) {
  return { eligible, lineages: [] };
}

export function createCommitSizeBinding({ measurement, ...scope }, settings) {
  const binding = {
    ...scope,
    baseHead: measurement.baseHead,
    contentFingerprint: measurement.contentFingerprint,
    changedLines: measurement.changedLines,
    binaryFiles: measurement.binaryPaths.length,
    gitlinks: measurement.gitlinkPaths.length,
    preferredCommitLineLimit: settings.preferredCommitLineLimit,
    threshold: commitSizeThreshold(settings),
  };
  assertBinding(binding);
  return Object.freeze(binding);
}

function assertBinding(binding) {
  if (
    !exact(binding, BINDING_FIELDS) ||
    !count(binding.originalStep) ||
    binding.originalStep < 1 ||
    ![
      "planFingerprint",
      "inputFingerprint",
      "scopeFingerprint",
      "dependenciesFingerprint",
      "contentFingerprint",
    ].every(
      (field) =>
        typeof binding[field] === "string" && HASH.test(binding[field]),
    ) ||
    !(
      binding.baseHead === null ||
      (typeof binding.baseHead === "string" && HEAD.test(binding.baseHead))
    ) ||
    ![
      "changedLines",
      "binaryFiles",
      "gitlinks",
      "preferredCommitLineLimit",
      "threshold",
    ].every((field) => count(binding[field])) ||
    binding.preferredCommitLineLimit < 1 ||
    binding.threshold < binding.preferredCommitLineLimit ||
    binding.threshold % binding.preferredCommitLineLimit !== 0
  ) {
    throw new Error("Invalid commit-size assessment binding.");
  }
}

export const COMMIT_SIZE_ASSESSMENT_SCHEMA = {
  type: "object",
  properties: {
    bindingFingerprint: { type: "string", pattern: "^[a-f0-9]{64}$" },
    decision: { type: "string", enum: ["ATOMIC", "SPLIT"] },
    reason: { type: "string", minLength: 1, maxLength: 4000 },
    replacementPlan: { type: "string", maxLength: 100000 },
  },
  required: ["bindingFingerprint", "decision", "reason", "replacementPlan"],
  additionalProperties: false,
};

export function normalizeCommitSizeDecision(value, binding) {
  assertBinding(binding);
  if (
    !exact(value, COMMIT_SIZE_ASSESSMENT_SCHEMA.required) ||
    binding.changedLines <= binding.threshold ||
    value.bindingFingerprint !== fingerprint(binding) ||
    !["ATOMIC", "SPLIT"].includes(value.decision) ||
    !text(value.reason, 4000) ||
    typeof value.replacementPlan !== "string" ||
    value.replacementPlan.length > 100000 ||
    (value.decision === "ATOMIC" && value.replacementPlan !== "")
  ) {
    throw new Error("Invalid commit-size assessment decision.");
  }
  if (value.decision === "SPLIT") {
    const plan = parseCommitPlan(value.replacementPlan);
    if (
      plan.steps.length < 2 ||
      plan.steps.length > 16 ||
      plan.steps.some(({ body }) => !text(body, 100000))
    ) {
      throw new Error(
        "A size proposal requires two to sixteen scoped replacement commits.",
      );
    }
  }
  return Object.freeze({ ...value });
}

function inputBindingMatches(before, after, inputChanges) {
  let current = before;
  if (current === after) return true;
  for (const change of inputChanges) {
    if (change.before === current && change.after !== null)
      current = change.after;
    if (current === after) return true;
  }
  return false;
}

export function assertCommitSizeAssessment(value, settings, inputChanges = []) {
  if (
    !exact(value, ["eligible", "lineages"]) ||
    typeof value.eligible !== "boolean" ||
    !Array.isArray(value.lineages) ||
    (value.lineages.length > 0 && settings === null) ||
    (!value.eligible && value.lineages.length !== 0) ||
    new Set(value.lineages.map((lineage) => lineage?.originalStep)).size !==
      value.lineages.length
  ) {
    throw new Error("Invalid commit-size assessment ledger.");
  }
  for (const lineage of value.lineages) {
    if (
      !exact(lineage, ["originalStep", "attempts"]) ||
      !Array.isArray(lineage.attempts) ||
      lineage.attempts.length < 1 ||
      lineage.attempts.length > MAX_SIZE_ASSESSMENTS
    ) {
      throw new Error("Invalid original-step assessment allowance.");
    }
    for (const [index, attempt] of lineage.attempts.entries()) {
      if (!exact(attempt, ["binding", "result"]))
        throw new Error("Invalid size assessment attempt.");
      assertBinding(attempt.binding);
      if (
        attempt.binding.originalStep !== lineage.originalStep ||
        attempt.binding.changedLines <= attempt.binding.threshold ||
        attempt.binding.preferredCommitLineLimit !==
          settings.preferredCommitLineLimit ||
        attempt.binding.threshold !== commitSizeThreshold(settings) ||
        attempt.binding.planFingerprint !==
          lineage.attempts[0].binding.planFingerprint ||
        !inputBindingMatches(
          lineage.attempts[Math.max(0, index - 1)].binding.inputFingerprint,
          attempt.binding.inputFingerprint,
          inputChanges,
        ) ||
        (attempt.result === null && index !== lineage.attempts.length - 1)
      ) {
        throw new Error("Inconsistent size assessment lineage.");
      }
      if (attempt.result !== null)
        normalizeCommitSizeDecision(attempt.result, attempt.binding);
    }
  }
}

// Called only at a reconciled boundary before another convergence/review loop.
// The caller must publish the returned ledger before invoking the checkpoint.
// Production callers reconcile effects and preserve work before separation.
export function reserveCommitSizeAssessment(
  ledger,
  binding,
  settings,
  {
    planKind = "commit",
    reconciled = false,
    commitPending = true,
    inputChanges = [],
  } = {},
) {
  assertCommitSizeAssessment(ledger, settings, inputChanges);
  if (
    !ledger.eligible ||
    planKind !== "commit" ||
    reconciled !== true ||
    commitPending !== false
  )
    return null;
  assertBinding(binding);
  const lineage = ledger.lineages.find(
    ({ originalStep }) => originalStep === binding.originalStep,
  );
  const previous = lineage?.attempts.at(-1);
  if (
    previous &&
    (previous.binding.planFingerprint !== binding.planFingerprint ||
      !inputBindingMatches(
        previous.binding.inputFingerprint,
        binding.inputFingerprint,
        inputChanges,
      ))
  ) {
    throw new Error("Frozen assessment inputs changed.");
  }
  if (previous?.result === null) {
    if (!isDeepStrictEqual(previous.binding, binding))
      throw new Error(
        "Reconcile the pending size assessment before replacing it.",
      );
    return assessmentRequest(
      ledger,
      binding,
      settings,
      lineage.attempts.length,
    );
  }
  if (binding.changedLines <= commitSizeThreshold(settings)) return null;
  if (
    previous &&
    previous.binding.inputFingerprint === binding.inputFingerprint &&
    previous.binding.scopeFingerprint === binding.scopeFingerprint &&
    previous.binding.dependenciesFingerprint ===
      binding.dependenciesFingerprint &&
    binding.changedLines - previous.binding.changedLines <=
      settings.preferredCommitLineLimit
  )
    return null;
  if (lineage?.attempts.length === MAX_SIZE_ASSESSMENTS) return null;
  const updated = {
    originalStep: binding.originalStep,
    attempts: [
      ...(lineage?.attempts ?? []),
      { binding: { ...binding }, result: null },
    ],
  };
  const next = {
    ...ledger,
    lineages: [...ledger.lineages.filter((item) => item !== lineage), updated],
  };
  assertCommitSizeAssessment(next, settings, inputChanges);
  return assessmentRequest(next, binding, settings, updated.attempts.length);
}

function assessmentRequest(ledger, binding, settings, attempt) {
  return {
    ledger,
    role: executionPolicy(settings).independentReview ? "reviewer" : "worker",
    access: "read-only",
    checkpoint: `commit-size:${binding.originalStep}:${attempt}`,
    bindingFingerprint: fingerprint(binding),
  };
}

export function recordCommitSizeDecision(
  ledger,
  binding,
  result,
  settings,
  inputChanges = [],
) {
  assertCommitSizeAssessment(ledger, settings, inputChanges);
  const normalized = normalizeCommitSizeDecision(result, binding);
  const lineage = ledger.lineages.find(
    ({ originalStep }) => originalStep === binding.originalStep,
  );
  const pending = lineage?.attempts.at(-1);
  if (
    !pending ||
    !isDeepStrictEqual(pending.binding, binding) ||
    (pending.result !== null && !isDeepStrictEqual(pending.result, normalized))
  ) {
    throw new Error("Size assessment has no matching reservation.");
  }
  return {
    ...ledger,
    lineages: ledger.lineages.map((item) =>
      item !== lineage
        ? item
        : {
            ...item,
            attempts: item.attempts.map((attempt) =>
              attempt !== pending
                ? attempt
                : { ...attempt, result: normalized },
            ),
          },
    ),
  };
}

export const COMMIT_SIZE_ASSESSMENT_INSTRUCTIONS = `Assess only the current unfinished commit against the supplied frozen scope, requirements, dependencies, measured text changes, separate binary/gitlink counts and repository evidence. This is a distinct read-only size assessment, before further convergence or review, including in combined mode. Do not edit, stage, run checks, commit, ask questions or approve implementation. Return ATOMIC with a concrete indivisibility reason and empty replacementPlan, or SPLIT with a cohesive ordered commit plan preserving all requirements, dependencies, checks, findings and later-step meaning. Use exact Conventional Commit subjects and independently valid intermediate states, never arbitrary file groups or fixed-size patch chunks. Echo the supplied bindingFingerprint. This proposal grants no revision, preservation, materialization or commit authority. Size alone is neither a failure nor a reason to demand an override.`;
