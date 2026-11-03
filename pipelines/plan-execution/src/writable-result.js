import { createHash } from "node:crypto";
import { isDeepStrictEqual } from "node:util";

import { executionContentFingerprint } from "./custom-results.js";
import { PlanExecutionWorkflowError } from "./errors.js";

const hash = (value) =>
  createHash("sha256").update(JSON.stringify(value)).digest("hex");
const fingerprint = (value) =>
  typeof value === "string" && /^[a-f0-9]{64}$/u.test(value);
const exact = (value, fields) =>
  value !== null &&
  typeof value === "object" &&
  !Array.isArray(value) &&
  Object.keys(value).length === fields.length &&
  fields.every((field) => Object.hasOwn(value, field));
const count = (value) => Number.isSafeInteger(value) && value >= 0;
const FIELDS = [
  "schemaVersion",
  "phase",
  "step",
  "stage",
  "beforeFingerprint",
  "originalContentFingerprint",
  "factsFingerprint",
  "blockers",
  "restrictedIds",
  "budgetExhausted",
  "rework",
  "fixRoundsBefore",
  "fixCharged",
  "pendingCorrectionBefore",
  "candidateFingerprint",
  "attempts",
  "additionalAttempts",
  "diagnostic",
  "productDecision",
];
const CONSTRAINTS = new Set([
  "object",
  "single-object-wrapper",
  "semantic-contract",
  "provider-structured-output",
  "exact-field-set",
  "maximum-2-mebibytes",
  "serializable-json",
  "empty-string",
  "empty-array",
  "implementation-status",
  "resolution-status",
  "nonempty-plain-text-up-to-4000-characters",
  "concise-markdown-up-to-20000-characters",
  "array-up-to-32-items",
  "array-up-to-16-items",
  "nonempty-array-up-to-32-items",
  "current-blocker-id",
  "fix-or-dispute",
  "disputable-blocker-only",
  "every-current-blocker-exactly-once",
  "bounded-current-criterion-evidence-and-authorized-outputs",
  "null-for-inactive-status",
]);

function phaseContract(phase) {
  return phase === "IMPLEMENT" ? "implementation" : "finding-resolution";
}

// New durable diagnostics admit identities only. Historical diagnostics keep
// their existing validator; rejected values and arbitrary exception text never
// enter this checkpoint, even when an adapter supplies diagnostic-like fields.
export function writableResultDiagnostic(cause, phase) {
  const contract = phaseContract(phase);
  const candidate = cause?.diagnostic;
  const field = candidate?.field;
  const decisionField =
    /^decisions\[(?:[0-9]|[12][0-9]|3[01])\](?:\.(?:id|decision|reason|evidence(?:\[(?:[0-9]|[12][0-9]|3[01])\])?))?$/u;
  const listField =
    /^(?:evidence\[(?:[0-9]|[12][0-9]|3[01])\]|options\[(?:[0-9]|1[0-5])\])$/u;
  const allowedField =
    [
      "result",
      "status",
      "reason",
      "question",
      "options",
      "whyBlocked",
      "evidence",
      "customResult",
    ].includes(field) ||
    (phase === "IMPLEMENT" && field === "summary") ||
    (phase === "RESOLVE_FINDINGS" &&
      (field === "decisions" ||
        (typeof field === "string" && decisionField.test(field)))) ||
    (typeof field === "string" && listField.test(field));
  return {
    role: "worker",
    phase: contract,
    contract,
    field:
      allowedField && CONSTRAINTS.has(candidate?.constraint) ? field : "result",
    constraint:
      allowedField && CONSTRAINTS.has(candidate?.constraint)
        ? candidate.constraint
        : "semantic-contract",
  };
}

// Blockers are validated owning-pipeline data, not a rejected response. Keep
// their ownership when content changes invalidate the gates that produced them.
function writableResultFacts(state, checkpoint) {
  return hash({
    phase: checkpoint.phase,
    step: state.currentStep,
    settings: state.settings,
    plan: state.canonicalPlan,
    revisions: state.effectivePlanRevisions,
    implementation: state.stepImplementation,
    direction: state.implementationDirection,
    findings: state.findings,
    previousFindings: state.previousFindings,
    pendingDisputes: state.pendingDisputes,
    disputeCounts: state.disputeCounts,
    arbitrations: state.findingArbitrations,
    stagnation: state.stagnationDirection,
    correctionHistory: state.correctionHistory,
    sameFindingRounds: state.sameFindingRounds,
    disputeHistory: state.disputeHistory,
    blockedSinceStagnation: state.blockedSinceStagnation,
    additionalFixRounds: state.additionalFixRounds,
    pendingCorrectionBefore: checkpoint.pendingCorrectionBefore,
    fixRoundsBefore: checkpoint.fixRoundsBefore,
    completedCommits: state.completedCommits,
    customResults: state.customResults,
    validationSchedule: state.validationSchedule,
    requiredChecks: state.requiredChecks,
    overrides: state.findingOverrides,
    blockers: checkpoint.blockers,
    restrictedIds: checkpoint.restrictedIds,
    budgetExhausted: checkpoint.budgetExhausted,
    rework: checkpoint.rework,
    customCandidate: state.customCandidate,
    customWritePolicy: state.customWritePolicy,
  });
}

export function createWritableResult(
  state,
  counters,
  {
    beforeFingerprint,
    blockers = [],
    restrictedIds = [],
    budgetExhausted = false,
  },
) {
  const checkpoint = {
    schemaVersion: 1,
    phase: state.workflowState,
    step: state.currentStep,
    stage: "prepared",
    beforeFingerprint,
    originalContentFingerprint: state.repositoryBaseline.contentFingerprint,
    factsFingerprint: null,
    blockers: structuredClone(blockers),
    restrictedIds,
    budgetExhausted,
    rework: state.implementationDirection !== null,
    fixRoundsBefore: counters.fixRounds,
    fixCharged: false,
    pendingCorrectionBefore: state.pendingCorrection,
    candidateFingerprint: null,
    attempts: 0,
    additionalAttempts: 0,
    diagnostic: null,
    productDecision: null,
  };
  checkpoint.factsFingerprint = writableResultFacts(state, checkpoint);
  return checkpoint;
}

export function assertWritableResult(
  state,
  { validateBlockers, validateProductDecision } = {},
) {
  const value = state.writableResult;
  if (value === null) return;
  const invalid = () => {
    throw new PlanExecutionWorkflowError(
      "Invalid writable result checkpoint.",
      {
        code: "ERR_INVALID_PLAN_EXECUTION_STATE",
      },
    );
  };
  if (
    !exact(value, FIELDS) ||
    value.schemaVersion !== 1 ||
    !["IMPLEMENT", "RESOLVE_FINDINGS"].includes(value.phase) ||
    ![value.phase, "WAITING_FOR_USER", "FAILED", "CANCELED"].includes(
      state.workflowState,
    ) ||
    value.step !== state.currentStep ||
    !Number.isSafeInteger(value.step) ||
    value.step < 1 ||
    ![
      "prepared",
      "invoking",
      "ready",
      "correcting",
      "exhausted",
      "blocked",
    ].includes(value.stage) ||
    ![
      value.beforeFingerprint,
      value.originalContentFingerprint,
      value.factsFingerprint,
    ].every(fingerprint) ||
    !Array.isArray(value.blockers) ||
    value.blockers.length > 32 ||
    value.blockers.some(
      (blocker) =>
        blocker === null ||
        typeof blocker !== "object" ||
        typeof blocker.id !== "string" ||
        !/^[RF][1-9][0-9]{0,8}$/u.test(blocker.id),
    ) ||
    !Array.isArray(value.restrictedIds) ||
    value.restrictedIds.length > 32 ||
    new Set(value.restrictedIds).size !== value.restrictedIds.length ||
    value.restrictedIds.some(
      (id) => !value.blockers.some((blocker) => blocker.id === id),
    ) ||
    typeof value.budgetExhausted !== "boolean" ||
    typeof value.rework !== "boolean" ||
    value.rework !== (state.implementationDirection !== null) ||
    !count(value.fixRoundsBefore) ||
    typeof value.fixCharged !== "boolean" ||
    typeof value.pendingCorrectionBefore !== "boolean" ||
    (["prepared", "invoking"].includes(value.stage) &&
      (value.pendingCorrectionBefore !== state.pendingCorrection ||
        value.beforeFingerprint !== executionContentFingerprint(state))) ||
    (!["prepared", "invoking"].includes(value.stage) &&
      (value.fixCharged !==
        (value.originalContentFingerprint !==
          state.repositoryBaseline?.contentFingerprint &&
          (value.rework ||
            (value.phase === "RESOLVE_FINDINGS" &&
              !value.pendingCorrectionBefore))) ||
        state.pendingCorrection !==
          (value.pendingCorrectionBefore ||
            (value.fixCharged && value.phase === "RESOLVE_FINDINGS")))) ||
    !count(value.attempts) ||
    !count(value.additionalAttempts) ||
    !Number.isSafeInteger(value.additionalAttempts + 1) ||
    value.attempts > value.additionalAttempts + 1 ||
    (value.stage === "invoking" && value.diagnostic !== null) ||
    (!["prepared", "invoking"].includes(value.stage) &&
      value.candidateFingerprint !== executionContentFingerprint(state)) ||
    (["prepared", "invoking"].includes(value.stage) &&
      value.originalContentFingerprint !==
        state.repositoryBaseline?.contentFingerprint) ||
    value.attempts < value.additionalAttempts ||
    (value.stage === "correcting" &&
      value.attempts !== value.additionalAttempts + 1) ||
    (value.stage === "exhausted" &&
      value.attempts !== value.additionalAttempts + 1) ||
    (value.stage === "ready" && value.attempts !== value.additionalAttempts) ||
    (["prepared", "invoking"].includes(value.stage) &&
      (value.candidateFingerprint !== null ||
        value.attempts !== 0 ||
        value.fixCharged)) ||
    (!["prepared", "invoking"].includes(value.stage) &&
      !fingerprint(value.candidateFingerprint)) ||
    (value.phase === "IMPLEMENT" &&
      (value.blockers.length ||
        value.restrictedIds.length ||
        value.budgetExhausted)) ||
    (value.phase === "RESOLVE_FINDINGS" && !value.blockers.length) ||
    (value.fixCharged && value.phase === "IMPLEMENT" && !value.rework) ||
    (value.diagnostic !== null &&
      !isDeepStrictEqual(
        value.diagnostic,
        writableResultDiagnostic({ diagnostic: value.diagnostic }, value.phase),
      )) ||
    (value.diagnostic !== null &&
      !exact(value.diagnostic, [
        "role",
        "phase",
        "contract",
        "field",
        "constraint",
      ])) ||
    (value.productDecision !== null &&
      (!exact(value.productDecision, [
        "decision",
        "number",
        "expectedHash",
        "resultHash",
      ]) ||
        !["ready", "correcting"].includes(value.stage) ||
        !exact(value.productDecision.decision, [
          "question",
          "options",
          "whyBlocked",
          "evidence",
        ]) ||
        !Number.isSafeInteger(value.productDecision.number) ||
        value.productDecision.number < 1 ||
        !fingerprint(value.productDecision.expectedHash) ||
        (value.productDecision.resultHash !== null &&
          (!fingerprint(value.productDecision.resultHash) ||
            value.productDecision.resultHash ===
              value.productDecision.expectedHash)))) ||
    value.factsFingerprint !== writableResultFacts(state, value) ||
    state.pendingCommit !== null
  )
    invalid();
  const blockers =
    value.phase === "IMPLEMENT"
      ? []
      : state.finalizationResult?.status === "FAIL"
        ? state.finalizationResult.issues.map((issue) => ({
            ...issue,
            source: "finalization",
          }))
        : state.findings.map((finding) => ({ ...finding, source: "review" }));
  const restrictedIds = blockers
    .filter(
      ({ id }) =>
        state.findingArbitrations.some(
          (entry) =>
            entry.findingId === id && entry.direction === "REVIEWER_CORRECT",
        ) ||
        (state.disputeCounts[id] ?? 0) >= state.settings.maxDisputesPerFinding,
    )
    .map(({ id }) => id);
  if (
    !isDeepStrictEqual(value.blockers, blockers) ||
    !isDeepStrictEqual(value.restrictedIds, restrictedIds)
  )
    invalid();
  validateBlockers?.(value.blockers);
  if (value.productDecision !== null)
    validateProductDecision?.(value.productDecision.decision);
}
