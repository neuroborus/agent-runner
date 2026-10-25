import { isDeepStrictEqual } from "node:util";

import {
  assertEffectivePlanReport,
  effectivePlanReviewPhases,
} from "./effective-plan.js";
import { validationEvidenceFingerprint as fingerprint } from "./validation-schedule.js";

const HASH = /^[a-f0-9]{64}$/u;

// Retain the binding from before the question was appended. Only the authorized
// editor's consumption can complete this transition; old receipts stay intact.
export function suspendReplacementInputs(state, before) {
  if (
    !state.commitSizeAssessment.eligible ||
    !state.commitSizeAssessment.lineages.length
  )
    return state.replacementExecution;
  return {
    ...state.replacementExecution,
    inputChanges: [
      ...state.replacementExecution.inputChanges,
      {
        before,
        after: null,
        checkpoint: state.workflowState,
        revision:
          state.effectivePlanRevisions.revisions.findLast(
            (entry) => entry.accepted,
          )?.number ?? 0,
        validation: null,
        reports: [],
      },
    ],
  };
}

export function acceptReplacementInputs(state, after) {
  const changes = state.replacementExecution.inputChanges;
  const change = changes.at(-1);
  if (!change || change.after !== null) return state;
  const validation =
    state.effectiveValidation.find(
      (entry) => entry.revision === change.revision,
    ) ?? null;
  return {
    ...state,
    bootstrapProgress: Object.fromEntries(
      Object.entries(state.bootstrapProgress).map(([role, progress]) => [
        role,
        { ...progress, work: null },
      ]),
    ),
    effectiveValidation: state.effectiveValidation.filter(
      (entry) => entry !== validation,
    ),
    replacementExecution: {
      ...state.replacementExecution,
      inputChanges: [...changes.slice(0, -1), { ...change, after, validation }],
    },
  };
}

export function replacementInputReview(state) {
  const changes = state.replacementExecution.inputChanges;
  const change = changes.at(-1);
  if (!change?.after || change.revision === 0) return null;
  if (change.reports.some(({ status }) => status !== "CLEAN")) return null;
  const phase = effectivePlanReviewPhases(state.settings.mode)[
    change.reports.length
  ];
  if (!phase) return null;
  const revision = state.effectivePlanRevisions.revisions.find(
    (entry) => entry.number === change.revision,
  );
  return {
    role: phase === "REVIEW" ? "reviewer" : "worker",
    phase,
    checkpoint: `effective-plan:${change.revision}:input:${changes.length}:${phase}`,
    fingerprint: fingerprint([revision.fingerprint, change.after]),
  };
}

export function recordReplacementInputReview(state, report) {
  const request = replacementInputReview(state);
  if (!request) throw new Error("No pending replacement input review.");
  assertEffectivePlanReport(report, request.fingerprint);
  const changes = state.replacementExecution.inputChanges;
  const change = changes.at(-1);
  return {
    ...state,
    replacementExecution: {
      ...state.replacementExecution,
      inputChanges: [
        ...changes.slice(0, -1),
        { ...change, reports: [...change.reports, report] },
      ],
    },
  };
}

export function assertReplacementInputs(state) {
  const changes = state.replacementExecution.inputChanges;
  if (
    !Array.isArray(changes) ||
    (!state.commitSizeAssessment.eligible && changes.length)
  )
    throw new Error("Invalid replacement input changes.");
  for (const [index, change] of changes.entries()) {
    const revision = state.effectivePlanRevisions.revisions.find(
      (entry) => entry.number === change.revision && entry.accepted,
    );
    const phases = effectivePlanReviewPhases(state.settings.mode);
    if (
      !isDeepStrictEqual(Object.keys(change).sort(), [
        "after",
        "before",
        "checkpoint",
        "reports",
        "revision",
        "validation",
      ]) ||
      !HASH.test(change.before) ||
      ![
        "IMPLEMENT",
        "CHECK_AND_FIX",
        "CLEAN_CONFIRM",
        "REVIEW",
        "CONFIRM",
        "FINALIZE",
        "RESOLVE_FINDINGS",
      ].includes(change.checkpoint) ||
      !(change.after === null || HASH.test(change.after)) ||
      (index > 0 && changes[index - 1].after !== change.before) ||
      (!revision && change.revision !== 0) ||
      (change.validation !== null &&
        change.validation.revision !== change.revision) ||
      (change.validation !== null &&
        ["worker", "reviewer"].some(
          (role) =>
            change.validation[role] !== null &&
            change.validation[role]?.binding.inputFingerprint !== change.before,
        )) ||
      !Array.isArray(change.reports) ||
      change.reports.length > (revision ? phases.length : 0) ||
      (index < changes.length - 1 &&
        (change.after === null ||
          (revision &&
            (change.reports.length !== phases.length ||
              change.reports.some(({ status }) => status !== "CLEAN"))))) ||
      (change.after === null &&
        (index !== changes.length - 1 ||
          change.reports.length ||
          change.validation !== null))
    )
      throw new Error("Invalid replacement input binding.");
    for (const [position, report] of change.reports.entries()) {
      assertEffectivePlanReport(
        report,
        fingerprint([revision.fingerprint, change.after]),
      );
      if (position > 0 && change.reports[position - 1].status !== "CLEAN")
        throw new Error(
          "Replacement input review followed unresolved findings.",
        );
    }
  }
}
