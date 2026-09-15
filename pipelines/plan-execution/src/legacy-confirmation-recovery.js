import { isDeepStrictEqual } from "node:util";

import {
  candidateGatePassed,
  finalizationGatePassed,
} from "./gate-evidence.js";
import { executionPolicy } from "./mode-policy.js";
import { assertRun } from "./workflow-contract.js";

// This evidence is deliberately neither persisted on the run nor projected.
// A restart must obtain proof again from the state-owned validated journal.
const provenRuns = new WeakMap();
const ROOT_BINDINGS = [
  "runId",
  "pipelineId",
  "projectPath",
  "taskPath",
  "roles",
  "hashes",
];
const STEP_BINDINGS = [
  "currentStep",
  "settings",
  "artifactRoot",
  "clarificationPath",
  "clarificationFrozen",
  "canonicalPlan",
  "completedCommits",
  "trustedValidation",
  "requiredChecks",
  "validationInfrastructure",
  "validationInfrastructureFingerprint",
  "workerSummary",
  "reviewerSummary",
  "resolvedSummary",
  "workerValidation",
  "reviewerValidation",
];
const GIT_BINDINGS = [
  "projectPath",
  "allowedPaths",
  "head",
  "branch",
  "detached",
  "refsFingerprint",
  "indexFingerprint",
  "remoteConfigurationFingerprint",
  "identityFingerprint",
  "identityAvailable",
];

function sameFields(left, right, fields) {
  return fields.every((field) =>
    isDeepStrictEqual(left?.[field], right?.[field]),
  );
}

function isFailure(run) {
  return (
    run.pipelineState.workflowState === "FAILED" &&
    run.pause?.reason === "internal_failure" &&
    run.pause.code === "ERR_CODEX_TURN_FAILED" &&
    run.pause.diagnosticClass === "turn_other" &&
    Object.keys(run.pause).every((key) =>
      ["reason", "code", "diagnosticClass"].includes(key),
    )
  );
}

function hasNoPendingWork(state) {
  return (
    state.preflightComplete &&
    state.clarificationFrozen &&
    !state.compatibilityCheckRequired &&
    !state.validationMigrationPending &&
    !state.candidateMigrationPending &&
    [
      "pendingEdit",
      "pendingCommit",
      "pendingBootstrapCorrection",
      "pendingFinalizationCorrection",
      "pendingReviewCorrection",
      "pendingConfirmationCorrection",
      "pendingLazyCorrection",
      "reviewCorrection",
      "confirmationCorrection",
      "implementationDirection",
      "stagnationDirection",
      "bootstrapDisagreement",
    ].every((key) => state[key] === null) &&
    ["findings", "pendingDisputes", "reviewReconsideration"].every(
      (key) => state[key].length === 0,
    ) &&
    !state.finalizationRecovery.required &&
    !state.finalizationRecovery.pending &&
    state.finalizationRecovery.feedback === null
  );
}

function candidateTuple(state) {
  return [
    state.candidateReviewResult,
    state.candidateReviewedFingerprint,
    state.candidateConfirmationFingerprint,
  ];
}

function isActivity(event, actor, phase, kinds) {
  return (
    event.activity?.actor === actor &&
    event.activity.phase === phase &&
    kinds.includes(event.activity.kind)
  );
}

function unchangedExcept(left, right, fields) {
  const omit = (value) =>
    Object.fromEntries(
      Object.entries(value).filter(([key]) => !fields.includes(key)),
    );
  return isDeepStrictEqual(omit(left), omit(right));
}

function proveHistory(run, history, migrate) {
  if (
    !isFailure(run) ||
    run.activeTurn !== null ||
    !hasNoPendingWork(run.pipelineState)
  )
    return false;
  // Exercise the complete current gate, including inventory/trust provenance,
  // override rules, counters, and every required CONFIRM invariant.
  assertRun({
    ...run,
    pause: null,
    pipelineState: { ...run.pipelineState, workflowState: "CONFIRM" },
  });
  if (
    !Array.isArray(history.events) ||
    history.events.length === 0 ||
    history.run.revision !== run.revision ||
    !isDeepStrictEqual(history.events.at(-1).state, history.run) ||
    !isDeepStrictEqual(migrate(history.run), run)
  )
    return false;

  let previous = null;
  let previousRaw = null;
  let candidate = null;
  let finalization = null;
  let unchangedCheck = null;
  let completedTurn = null;
  let activeRequest = null;
  let failed = false;
  for (const [index, event] of history.events.entries()) {
    if (
      event.revision !== index + 1 ||
      event.state.revision !== event.revision ||
      event.runId !== run.runId
    )
      return false;
    const current = migrate(event.state);
    assertRun(current);
    const state = current.pipelineState;
    if (previous === null) {
      if (
        state.workflowState !== "CLARIFY" ||
        state.preflightComplete ||
        current.activeTurn !== null ||
        current.sessionLineage.children.length !== 0
      )
        return false;
      previous = current;
      previousRaw = event.state;
      continue;
    }
    const before = previous.pipelineState;
    const migration = !sameFields(event.state, previousRaw, [
      "schemaVersion",
      "pipelineStateVersion",
      "runtimeCompatibility",
    ]);
    if (migration) {
      // The explicit migration functions may preserve old proof, never invent
      // a candidate transition. Reject any extra change hidden in a migration.
      if (
        !isActivity(event, "runner", "runtime", ["migrated"]) ||
        !unchangedExcept(previous, current, [
          "revision",
          "updatedAt",
          "schemaVersion",
          "runtimeCompatibility",
        ])
      )
        return false;
      previous = current;
      previousRaw = event.state;
      continue;
    }
    if (isActivity(event, "runner", "runtime", ["migrated"])) return false;
    if (failed) return false;
    const bound =
      sameFields(previous, current, ROOT_BINDINGS) &&
      sameFields(before, state, STEP_BINDINGS) &&
      sameFields(
        before.repositoryBaseline,
        state.repositoryBaseline,
        GIT_BINDINGS,
      );
    const contentChanged =
      before.repositoryBaseline?.contentFingerprint !==
      state.repositoryBaseline?.contentFingerprint;
    const formatting =
      bound &&
      before.workflowState === "FINALIZE" &&
      previous.activeTurn?.role === "worker" &&
      previous.activeTurn.phase === "finalize" &&
      isDeepStrictEqual(previous.activeTurn, current.activeTurn);
    if (
      state.currentStep === run.pipelineState.currentStep &&
      state.pendingCorrection &&
      !before.pendingCorrection &&
      !(
        contentChanged &&
        previous.activeTurn?.role === "worker" &&
        ["check-and-fix", "resolve-findings"].includes(
          previous.activeTurn.phase,
        )
      ) &&
      !(
        before.workflowState === "CHECK_AND_FIX" &&
        before.findings.length > 0 &&
        state.workflowState === "CLEAN_CONFIRM" &&
        !contentChanged
      ) &&
      !(
        before.workflowState === "IMPLEMENT" &&
        before.implementationDirection !== null
      )
    )
      return false;
    if (!bound || (contentChanged && !formatting)) {
      candidate = null;
      finalization = null;
      unchangedCheck = null;
      completedTurn = null;
    }
    if (
      candidate !== null &&
      (!isDeepStrictEqual(candidate, candidateTuple(state)) ||
        before.pendingCorrection !== state.pendingCorrection ||
        !isDeepStrictEqual(previous.counters, current.counters))
    )
      candidate = null;
    const checkpoint =
      state.workflowState === "WAITING_FOR_USER"
        ? current.pause?.resumeState
        : state.workflowState;
    if (!["FINALIZE", "CONFIRM", "FAILED"].includes(checkpoint))
      candidate = null;
    if (
      state.pendingCommit !== null ||
      ["IMPLEMENT", "COMMIT", "DONE"].includes(checkpoint)
    ) {
      candidate = null;
      finalization = null;
    }
    if (
      finalization !== null &&
      (!isDeepStrictEqual(finalization, state.finalizationResult) ||
        finalization.fingerprint !==
          state.repositoryBaseline?.contentFingerprint)
    )
      finalization = null;
    if (current.activeTurn !== null) {
      completedTurn = null;
      if (
        previous.activeTurn !== null &&
        !isDeepStrictEqual(previous.activeTurn, current.activeTurn)
      )
        return false;
      if (
        isActivity(event, current.activeTurn.role, current.activeTurn.phase, [
          "turn-started",
        ])
      ) {
        if (
          current.activeTurn.phase !==
          event.state.pipelineState.workflowState
            .toLowerCase()
            .replaceAll("_", "-")
        )
          return false;
        activeRequest = current.activeTurn;
      } else if (!isDeepStrictEqual(activeRequest, current.activeTurn))
        return false;
    }
    if (
      bound &&
      !contentChanged &&
      previous.activeTurn !== null &&
      current.activeTurn === null &&
      before.workflowState === state.workflowState
    ) {
      if (!isDeepStrictEqual(activeRequest, previous.activeTurn)) return false;
      completedTurn = activeRequest;
      activeRequest = null;
    }
    if (current.activeTurn === null && previous.activeTurn !== null)
      activeRequest = null;

    const lazyCheckFingerprint = unchangedCheck;
    if (
      bound &&
      !contentChanged &&
      before.workflowState === "CHECK_AND_FIX" &&
      state.workflowState === "CLEAN_CONFIRM" &&
      completedTurn?.role === "worker" &&
      completedTurn.phase === "check-and-fix" &&
      isActivity(event, "worker", "check-and-fix", ["unchanged"])
    ) {
      unchangedCheck = state.repositoryBaseline.contentFingerprint;
    } else if (state.workflowState !== "CLEAN_CONFIRM") {
      unchangedCheck = null;
    }

    const policy = executionPolicy(state.settings);
    const candidateTransition =
      bound &&
      !contentChanged &&
      event.state.pipelineStateVersion >= 14 &&
      ["FINALIZE", "CONFIRM"].includes(state.workflowState) &&
      candidateGatePassed(state, state.repositoryBaseline.contentFingerprint) &&
      (policy.primaryConvergence
        ? before.workflowState === "CLEAN_CONFIRM" &&
          completedTurn?.role === "worker" &&
          completedTurn.phase === "clean-confirm" &&
          isActivity(event, "worker", "clean-confirm", ["clean"])
        : before.workflowState === "REVIEW" &&
          completedTurn?.role === "reviewer" &&
          completedTurn.phase === "review" &&
          isActivity(event, "reviewer", "review", [
            "approved",
            "overrides-applied",
          ]));
    // The unchanged-check proof must survive the CLEAN_CONFIRM -> gate edge.
    if (
      candidateTransition &&
      (!policy.primaryConvergence ||
        before.repositoryBaseline.contentFingerprint === lazyCheckFingerprint)
    ) {
      candidate = candidateTuple(state);
    }

    if (
      bound &&
      candidate !== null &&
      before.workflowState === "FINALIZE" &&
      state.workflowState === "CONFIRM" &&
      completedTurn?.role === "worker" &&
      completedTurn.phase === "finalize" &&
      isActivity(event, "worker", "finalization", ["passed"]) &&
      finalizationGatePassed(state, state.repositoryBaseline.contentFingerprint)
    ) {
      finalization = state.finalizationResult;
    }
    if (state.workflowState === "FAILED") {
      failed =
        isFailure(current) &&
        before.workflowState === "CONFIRM" &&
        bound &&
        !contentChanged &&
        completedTurn?.role === policy.terminalConfirmer &&
        completedTurn.phase === "confirm" &&
        current.activeTurn === null &&
        previous.pause === null &&
        unchangedExcept(before, state, ["workflowState"]) &&
        isDeepStrictEqual(previous.counters, current.counters) &&
        candidate !== null &&
        finalization !== null &&
        hasNoPendingWork(state) &&
        isActivity(event, "runner", "plan-execution", ["failed"]);
      if (!failed) {
        candidate = null;
        finalization = null;
      }
    }
    previous = current;
    previousRaw = event.state;
  }
  return failed && candidate !== null && finalization !== null;
}

export function prepareLegacyConfirmationRecovery(run, history, migrate) {
  provenRuns.delete(run);
  try {
    if (proveHistory(run, history, migrate))
      provenRuns.set(run, structuredClone(run));
  } catch {
    // Invalid or unprovable pipeline history grants no recovery authority.
  }
}

export function canRecoverLegacyConfirmation(run) {
  return provenRuns.has(run) && isDeepStrictEqual(provenRuns.get(run), run);
}
