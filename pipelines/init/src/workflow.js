import { join } from "node:path";
import { isDeepStrictEqual } from "node:util";

import { selectInitPlacement } from "./inspection.js";
import {
  integratedFinalizationContent,
  integratedFinalizationPath,
} from "./integrated-policy.js";
import {
  externalFinalizationContent,
  externalFinalizationPath,
} from "./external-policy.js";
import {
  assertInit,
  assertInspection,
  assertInspectionExtension,
  assertProductDecision,
  assertResultSize,
  digest,
  exact,
  hashText,
  isHash,
  isPath,
  normalizeProposal,
  normalizeInitRoleResult,
  questions,
  text,
  texts,
} from "./proposal.js";
import { INIT_INSTRUCTIONS, PHASE_INSTRUCTIONS } from "./prompts.js";
import { initGuidanceContent } from "./guidance.js";
import { initCorrectiveFeedback, isInitRejection } from "./rejection.js";
import {
  assertInitInspection,
  assertInspectionFailure,
} from "./inspection-failure.js";
import {
  CLARIFICATION_SCHEMA,
  PROPOSAL_SCHEMA,
  REVIEW_SCHEMA,
} from "./schemas.js";

export const INIT_MODES = Object.freeze(["independent", "lazy", "combined"]);
const STAGES = [
  "CLARIFY",
  "PROPOSE",
  "CHECK_AND_FIX",
  "CLEAN_CONFIRM",
  "REVIEW",
  "PROPOSAL_ACCEPTED",
  "DONE",
  "CANCELED",
  "FAILED",
  "WAITING_FOR_USER",
];
const primaryConvergence = (state) => state.settings.mode !== "independent";

export function createInitState({
  settings = {},
  configurationPath = null,
  artifactRoot = "LOCAL_ARTIFACTS",
  proactiveClarification = false,
  providerAuthority = {},
} = {}) {
  const resolved = {
    mode: "independent",
    placement: null,
    maxRevisionRounds: 20,
    ...settings,
  };
  exact(resolved, ["mode", "placement", "maxRevisionRounds"]);
  assertInit(
    INIT_MODES.includes(resolved.mode) &&
      [null, "integrated", "external"].includes(resolved.placement) &&
      Number.isSafeInteger(resolved.maxRevisionRounds) &&
      resolved.maxRevisionRounds > 0 &&
      resolved.maxRevisionRounds <= 20,
    "Init settings are invalid.",
  );
  assertInit(
    configurationPath === null || isPath(configurationPath),
    "Init explicit configuration path is invalid.",
  );
  return {
    workflowState: "CLARIFY",
    artifactRoot,
    proactiveClarification,
    proactiveClarificationComplete: !proactiveClarification,
    publication: null,
    guidanceIntent: null,
    guidanceReceipt: null,
    terminal: null,
    completion: null,
    setupBaseline: null,
    createdFinalizationPath: null,
    sourceForks: [],
    providerAuthority,
    settings: resolved,
    requestedConfigurationPath: configurationPath,
    clarificationReady: false,
    clarificationSelection: {
      placement: resolved.placement,
      configurationPath,
    },
    inspection: null,
    reinspectionRequired: false,
    selection: null,
    clarificationHash: null,
    transcriptHash: null,
    pendingEdit: null,
    questionAppendPending: false,
    transcriptAppendHash: null,
    productDecision: null,
    productDecisionAppended: false,
    productDecisions: 0,
    clarificationRounds: 0,
    revisionRounds: 0,
    proposal: null,
    proposalHash: null,
    primaryApproval: null,
    reviewApproval: null,
    findings: [],
    questions: [],
    pendingTurn: null,
    correctiveFeedback: null,
    sequence: 0,
    pauseReason: null,
  };
}

export function assertInitState(state) {
  exact(state, Object.keys(createInitState()));
  exact(state.settings, ["mode", "placement", "maxRevisionRounds"]);
  createInitState({
    settings: state.settings,
    configurationPath: state.requestedConfigurationPath,
  });
  assertInit(
    STAGES.includes(state.workflowState) &&
      Number.isSafeInteger(state.clarificationRounds) &&
      state.clarificationRounds >= 0 &&
      state.clarificationRounds <= 3 &&
      Number.isSafeInteger(state.revisionRounds) &&
      state.revisionRounds >= 0 &&
      state.revisionRounds <= state.settings.maxRevisionRounds &&
      Number.isSafeInteger(state.sequence) &&
      state.sequence >= 0 &&
      typeof state.clarificationReady === "boolean" &&
      typeof state.questionAppendPending === "boolean" &&
      typeof state.productDecisionAppended === "boolean" &&
      Number.isSafeInteger(state.productDecisions) &&
      state.productDecisions >= 0 &&
      typeof state.reinspectionRequired === "boolean",
    "Init state or accounting is invalid.",
  );
  texts(state.findings);
  assertInit(
    state.createdFinalizationPath === null ||
      (isPath(state.createdFinalizationPath) &&
        Array.isArray(state.setupBaseline?.snapshot?.entries) &&
        state.setupBaseline.snapshot.entries.some(
          (entry) =>
            entry.path === state.createdFinalizationPath &&
            entry.kind === "file" &&
            isHash(entry.hash),
        )),
    "Init procedure repair requires a verified prepared baseline.",
  );
  assertInit(
    state.providerAuthority !== null &&
      typeof state.providerAuthority === "object" &&
      !Array.isArray(state.providerAuthority) &&
      Object.values(state.providerAuthority).every(isHash),
    "Init provider authority proof is invalid.",
  );
  assertInit(
    typeof state.artifactRoot === "string" &&
      typeof state.proactiveClarification === "boolean" &&
      typeof state.proactiveClarificationComplete === "boolean" &&
      Array.isArray(state.sourceForks) &&
      state.sourceForks.every((key) => typeof key === "string"),
    "Init runtime bindings are invalid.",
  );
  questions(state.questions);
  exact(state.clarificationSelection, ["placement", "configurationPath"]);
  assertInit(
    [null, "integrated", "external"].includes(
      state.clarificationSelection.placement,
    ) &&
      (state.clarificationSelection.configurationPath === null ||
        isPath(state.clarificationSelection.configurationPath)) &&
      (state.settings.placement === null ||
        state.clarificationSelection.placement === state.settings.placement) &&
      (state.requestedConfigurationPath === null ||
        state.clarificationSelection.configurationPath ===
          state.requestedConfigurationPath),
    "Init clarification selection conflicts with explicit input.",
  );
  assertInit(
    state.transcriptHash === null || isHash(state.transcriptHash),
    "Init transcript hash is invalid.",
  );
  if (state.productDecision !== null) {
    assertProductDecision(state.productDecision);
    assertInit(
      state.workflowState === "WAITING_FOR_USER" &&
        state.pauseReason === "product_decision_required" &&
        state.selection !== null &&
        state.productDecisions > 0 &&
        state.proposal === null &&
        state.pendingTurn === null,
      "Init product decision requires a suspended proposal and frozen selection.",
    );
  }
  assertInit(
    !state.productDecisionAppended || state.productDecision !== null,
    "Init decision append lacks its request.",
  );
  assertInit(
    state.transcriptAppendHash === null ||
      (isHash(state.transcriptAppendHash) &&
        state.pendingEdit === null &&
        (state.questionAppendPending || state.productDecision !== null)),
    "Init transcript append requires a journaled unanswered request.",
  );
  if (state.pauseReason === "clarification_required")
    assertInit(
      state.workflowState === "WAITING_FOR_USER" &&
        state.selection === null &&
        state.inspection !== null &&
        isHash(state.transcriptHash) &&
        state.questions.length > 0 &&
        state.clarificationRounds > 0 &&
        !state.clarificationReady,
      "Init answer request requires an unanswered clarification round.",
    );
  if (state.questionAppendPending)
    assertInit(
      state.pauseReason === "clarification_required" &&
        state.pendingEdit === null &&
        state.pendingTurn === null,
      "Init question append requires an unanswered clarification round.",
    );
  if (state.pendingEdit !== null) {
    const edit = state.pendingEdit;
    exact(edit, [
      "schemaVersion",
      "id",
      "artifactRoot",
      "transcriptPath",
      "suspendedState",
      "action",
      "preEditorHash",
    ]);
    assertInit(
      state.workflowState === "WAITING_FOR_USER" &&
        (edit.action === "product-decision"
          ? state.productDecision !== null && state.productDecisionAppended
          : state.selection === null) &&
        state.inspection !== null &&
        edit.schemaVersion === 1 &&
        typeof edit.id === "string" &&
        edit.id.length > 0 &&
        edit.id.length <= 256 &&
        edit.artifactRoot === state.inspection.taskPath &&
        edit.transcriptPath === join(edit.artifactRoot, "clarifications.md") &&
        edit.suspendedState ===
          (edit.action === "product-decision" ? "PROPOSE" : "CLARIFY") &&
        ((edit.action === "clarification-answers" &&
          ["clarification_required", "placement_conflict"].includes(
            state.pauseReason,
          )) ||
          (edit.action === "proactive-clarification" &&
            state.pauseReason !== "clarification_required") ||
          (edit.action === "product-decision" &&
            state.pauseReason === "product_decision_required")) &&
        edit.preEditorHash === state.transcriptHash,
      "Init pending editor authorization is invalid.",
    );
  }
  assertInit(
    state.pauseReason === null ||
      [
        "placement_conflict",
        "clarification_required",
        "clarification_limit",
        "revision_limit",
        "setup_blocked",
        "product_decision_required",
      ].includes(state.pauseReason),
    "Init pause reason is invalid.",
  );
  if (state.inspection !== null) assertInspection(state.inspection);
  if (state.reinspectionRequired)
    assertInit(
      state.selection === null &&
        state.inspection !== null &&
        !state.clarificationReady &&
        state.pendingTurn === null &&
        ["CLARIFY", "WAITING_FOR_USER"].includes(state.workflowState),
      "Init selection changes require additive reinspection before work.",
    );
  assertInit(
    (state.selection === null) === (state.clarificationHash === null),
    "Init selection must freeze with clarification.",
  );
  if (state.selection !== null) {
    assertInit(
      state.inspection !== null &&
        isHash(state.clarificationHash) &&
        isDeepStrictEqual(
          state.selection,
          selectInitPlacement(state.inspection, state.clarificationSelection),
        ) &&
        (state.settings.placement === null ||
          state.settings.placement === state.selection.placement),
      "Frozen init selection is invalid.",
    );
    assertInit(
      state.requestedConfigurationPath === null ||
        state.requestedConfigurationPath === state.selection.configurationPath,
      "Init changed its explicitly selected configuration.",
    );
    assertInit(
      state.clarificationHash === state.transcriptHash,
      "Init frozen clarifications changed.",
    );
  }
  if (
    !["CLARIFY", "WAITING_FOR_USER", "CANCELED", "FAILED"].includes(
      state.workflowState,
    )
  )
    assertInit(
      state.selection !== null && state.clarificationReady,
      "Init work requires closed clarification.",
    );
  if (
    ["CHECK_AND_FIX", "CLEAN_CONFIRM", "REVIEW"].includes(state.workflowState)
  )
    assertInit(
      state.proposal !== null,
      "Init review requires a durable proposal.",
    );
  if (state.workflowState === "CLEAN_CONFIRM")
    assertInit(
      primaryConvergence(state),
      "Independent init does not self-confirm.",
    );
  if (state.workflowState === "REVIEW")
    assertInit(
      state.settings.mode !== "lazy" &&
        (state.settings.mode !== "combined" ||
          state.primaryApproval === approvalHash(state)),
      "Init independent review requires the selected primary gate.",
    );
  if (state.proposal !== null) {
    assertInit(
      state.selection !== null &&
        digest(normalizeProposal(state.proposal, state)) === state.proposalHash,
      "Init proposal fingerprint changed.",
    );
  } else
    assertInit(
      state.proposalHash === null,
      "Init proposal fingerprint lacks content.",
    );
  for (const approval of [state.primaryApproval, state.reviewApproval]) {
    if (approval !== null)
      assertInit(
        state.proposalHash !== null && approval === approvalHash(state),
        "Init approval belongs to another proposal or input binding.",
      );
  }
  assertInit(
    state.reviewApproval === null || state.settings.mode !== "lazy",
    "Lazy init cannot acquire independent approval.",
  );
  if (["PROPOSAL_ACCEPTED", "DONE"].includes(state.workflowState)) {
    assertInit(
      state.pendingTurn === null &&
        state.selection !== null &&
        state.proposal !== null &&
        (!primaryConvergence(state) ||
          state.primaryApproval === approvalHash(state)) &&
        (state.settings.mode === "lazy" ||
          state.reviewApproval === approvalHash(state)),
      "Init proposal has not passed its selected gates.",
    );
  }
  if (state.workflowState === "DONE")
    assertInit(
      state.completion !== null &&
        state.terminal?.status === "CLEAN" &&
        state.guidanceReceipt !== null &&
        state.publication?.prepared,
      "Init completion requires verified publication and distinct terminal confirmation.",
    );
  if (state.publication !== null)
    assertInit(
      state.proposal !== null &&
        (!primaryConvergence(state) ||
          state.primaryApproval === approvalHash(state)) &&
        (state.settings.mode === "lazy" ||
          state.reviewApproval === approvalHash(state)),
      "Publication requires unchanged proposal approvals.",
    );
  if (state.guidanceIntent !== null) {
    const intent = state.guidanceIntent;
    exact(intent, [
      "projectPath",
      "projectConfigurationPath",
      "path",
      "beforeIdentity",
      "idempotencyKey",
      "expectedHash",
      "localContentHash",
      "localContent",
    ]);
    const guide = state.proposal?.resources.find(
      ({ kind }) => kind === "guidance",
    );
    assertInit(
      state.publication?.prepared &&
        intent.projectPath === state.inspection.projectPath &&
        intent.projectConfigurationPath === state.selection.configurationPath &&
        intent.path === guide?.path &&
        (intent.beforeIdentity === null
          ? guide.beforeHash === null
          : guide.beforeHash !== null &&
            typeof intent.beforeIdentity === "object" &&
            !Array.isArray(intent.beforeIdentity)) &&
        intent.expectedHash === guide.beforeHash &&
        intent.localContent === initGuidanceContent(state) &&
        intent.localContentHash === hashText(intent.localContent) &&
        typeof intent.idempotencyKey === "string",
      "Init guidance intent changed its approved selection or content.",
    );
  }
  if (state.guidanceReceipt !== null) {
    exact(state.guidanceReceipt, ["receipt", "observed"]);
    assertInit(
      state.guidanceIntent !== null &&
        state.guidanceReceipt.receipt.localPath === state.guidanceIntent.path &&
        state.guidanceReceipt.receipt.localHash ===
          state.guidanceIntent.localContentHash &&
        state.guidanceReceipt.observed.binding.path ===
          state.guidanceIntent.path &&
        state.guidanceReceipt.observed.file?.contentHash ===
          state.guidanceIntent.localContentHash,
      "Init guidance receipt differs from its intent.",
    );
  }
  if (state.terminal !== null) {
    exact(state.terminal, ["fingerprint", "status"]);
    assertInit(
      state.guidanceReceipt !== null &&
        isHash(state.terminal.fingerprint) &&
        ["PENDING", "CLEAN"].includes(state.terminal.status),
      "Init terminal confirmation lacks complete prepared evidence.",
    );
  }
  if (state.completion !== null)
    assertInit(
      ["DONE", "WAITING_FOR_USER", "CANCELED"].includes(state.workflowState) &&
        state.completion.fingerprint === state.terminal.fingerprint &&
        state.completion.configurationPath ===
          state.selection.configurationPath &&
        state.completion.placement === state.selection.placement,
      "Init completion belongs to another setup.",
    );
  if (state.pendingTurn !== null) {
    exact(state.pendingTurn, ["id", "phase", "role", "binding"]);
    assertInit(
      state.pendingTurn.id === state.sequence &&
        state.pendingTurn.phase === state.workflowState &&
        state.pendingTurn.role ===
          (state.workflowState === "REVIEW" ? "reviewer" : "planner") &&
        state.pendingTurn.binding === turnBinding(state),
      "Init pending turn binding changed.",
    );
  }
  if (state.correctiveFeedback !== null) {
    const feedback = state.correctiveFeedback;
    exact(feedback, ["code", "constraint", "reservation", "settingsHash"]);
    const reservation = feedback.reservation;
    exact(reservation, ["id", "phase", "role", "binding"]);
    assertInit(
      isInitRejection(feedback) &&
        feedback.settingsHash === digest(state.settings) &&
        [
          "CLARIFY",
          "PROPOSE",
          "CHECK_AND_FIX",
          "CLEAN_CONFIRM",
          "REVIEW",
          "CONFIRM",
        ].includes(reservation.phase) &&
        Number.isSafeInteger(reservation.id) &&
        reservation.id > 0 &&
        reservation.id <= state.sequence &&
        reservation.role ===
          (reservation.phase === "CONFIRM"
            ? state.settings.mode === "lazy"
              ? "planner"
              : "reviewer"
            : reservation.phase === "REVIEW"
              ? "reviewer"
              : "planner") &&
        reservation.binding === turnBinding(state, reservation.phase) &&
        (state.workflowState === "WAITING_FOR_USER" ||
          state.workflowState ===
            (reservation.phase === "CONFIRM"
              ? "PROPOSAL_ACCEPTED"
              : reservation.phase)) &&
        (reservation.phase !== "CONFIRM" ||
          state.terminal?.status === "PENDING") &&
        state.pauseReason === null &&
        state.pendingEdit === null &&
        state.productDecision === null,
      "Init corrective feedback belongs to another checkpoint or input binding.",
    );
  }
}

const approvalHash = (state) =>
  digest({
    inspection: state.inspection,
    selection: state.selection,
    clarificationHash: state.clarificationHash,
    proposalHash: state.proposalHash,
  });
const turnBinding = (state, phase = state.workflowState) =>
  digest({
    binding: approvalHash(state),
    phase,
    findings: state.findings,
    revisions: state.revisionRounds,
    questions: state.clarificationRounds,
    transcriptHash: state.transcriptHash,
    ...(phase === "CONFIRM"
      ? { fingerprint: state.terminal?.fingerprint }
      : {}),
  });

export function initConfirmationReservation(state) {
  return {
    id: state.sequence,
    phase: "CONFIRM",
    role: state.settings.mode === "lazy" ? "planner" : "reviewer",
    binding: turnBinding(state, "CONFIRM"),
  };
}

// Retire only this logical result; retain prior proposal/approvals and all
// consumed accounting. The lifecycle persists this with its invalid-result pause.
export function rejectInitResult(state, request, rejection) {
  assertInitState(state);
  const reservation =
    request.phase === "CONFIRM"
      ? initConfirmationReservation(state)
      : state.pendingTurn;
  assertInit(
    reservation !== null &&
      isDeepStrictEqual(reservation, {
        id: request.id,
        phase: request.phase,
        role: request.role,
        binding: request.binding,
      }) &&
      isInitRejection(rejection) &&
      state.publication?.pending == null &&
      (state.guidanceIntent === null || state.guidanceReceipt !== null),
    "Init rejection does not own the reserved checkpoint.",
  );
  const next = {
    ...state,
    workflowState: "WAITING_FOR_USER",
    pendingTurn: null,
    correctiveFeedback: {
      ...rejection,
      reservation: structuredClone(reservation),
      settingsHash: digest(state.settings),
    },
  };
  assertInitState(next);
  return next;
}

// The caller persists the returned reservation before invoking its adapter.
export function prepareInitTurn(state, inspection, transcriptHash) {
  assertInitState(state);
  assertInspection(inspection);
  assertInitInspection(
    isHash(transcriptHash) &&
      (state.transcriptHash === null ||
        state.transcriptHash === transcriptHash),
    "workspace_changed",
    "Init clarifications changed outside an authorized editor window.",
  );
  assertInit(
    !["PROPOSAL_ACCEPTED", "WAITING_FOR_USER"].includes(state.workflowState),
    "Init is not at an agent checkpoint.",
  );
  if (state.reinspectionRequired)
    assertInspectionExtension(state.inspection, inspection);
  else
    assertInitInspection(
      state.inspection === null ||
        isDeepStrictEqual(state.inspection, inspection),
      "workspace_changed",
    );
  selectInitPlacement(inspection, state.clarificationSelection);
  const next = structuredClone({
    ...state,
    inspection,
    transcriptHash,
    reinspectionRequired: false,
  });
  if (next.pendingTurn === null) {
    next.sequence += 1;
    next.pendingTurn = {
      id: next.sequence,
      phase: next.workflowState,
      role: next.workflowState === "REVIEW" ? "reviewer" : "planner",
      binding: turnBinding(next),
    };
  }
  return {
    state: next,
    request: {
      ...next.pendingTurn,
      correctiveFeedback: initCorrectiveFeedback(next),
      access: "read-only",
      schema:
        next.workflowState === "CLARIFY"
          ? CLARIFICATION_SCHEMA
          : ["PROPOSE", "CHECK_AND_FIX"].includes(next.workflowState)
            ? PROPOSAL_SCHEMA
            : REVIEW_SCHEMA,
      prompt: `${INIT_INSTRUCTIONS}\n\n${PHASE_INSTRUCTIONS[next.workflowState]}\n\n${JSON.stringify(
        {
          inspection,
          correctiveFeedback: initCorrectiveFeedback(next),
          mode: next.settings.mode,
          selectionInput: next.clarificationSelection,
          selection: next.selection,
          proposal: next.proposal,
          proposalHash: next.proposalHash,
          createdFinalizationPath: next.createdFinalizationPath,
          mergedGuidance:
            next.proposal === null ? null : initGuidanceContent(next),
          findings: next.findings,
          integratedFinalization:
            next.selection?.placement === "integrated"
              ? {
                  path: integratedFinalizationPath(
                    next,
                    next.proposal?.checks ?? ["<actual ordered project check>"],
                  ),
                  template: integratedFinalizationContent(
                    next,
                    next.proposal?.checks ?? ["<actual ordered project check>"],
                  ),
                }
              : null,
          externalFinalization:
            next.selection?.placement === "external"
              ? {
                  path: externalFinalizationPath(next),
                  template: externalFinalizationContent(
                    next,
                    next.proposal?.checks ?? ["<actual ordered project check>"],
                  ),
                }
              : null,
        },
      )}`,
    },
  };
}

function pause(state, reason) {
  return { ...state, workflowState: "WAITING_FOR_USER", pauseReason: reason };
}

// READY is not closure: the clarification service must first freeze the artifact.
export function closeInitClarification(
  state,
  { inspection, clarificationHash },
) {
  assertInitState(state);
  assertInit(
    state.workflowState === "CLARIFY" &&
      state.pendingTurn === null &&
      state.clarificationReady &&
      isHash(clarificationHash) &&
      clarificationHash === state.transcriptHash,
    "Init clarification cannot close at this checkpoint.",
  );
  assertInspection(inspection);
  assertInitInspection(
    state.inspection === null ||
      isDeepStrictEqual(state.inspection, inspection),
    "workspace_changed",
  );
  const selected = selectInitPlacement(
    inspection,
    state.clarificationSelection,
  );
  assertInit(
    selected !== null,
    "Competing init placements require explicit clarification.",
  );
  return {
    ...state,
    inspection: structuredClone(inspection),
    selection: selected,
    clarificationHash,
    workflowState: "PROPOSE",
    findings: [],
  };
}

// Pass these transitions to the clarification service's persistence/consume
// callbacks. An editor is never opened by the proposal contract itself.
export function acceptInitQuestionAppend(
  state,
  { round, expectedHash, transcript },
) {
  assertInitState(state);
  assertInit(
    state.questionAppendPending &&
      round === state.clarificationRounds &&
      expectedHash === state.transcriptHash &&
      transcript?.artifactRoot === state.inspection.taskPath &&
      transcript.transcriptPath ===
        join(state.inspection.taskPath, "clarifications.md") &&
      isHash(transcript.hash) &&
      (state.transcriptAppendHash === null ||
        transcript.hash === state.transcriptAppendHash) &&
      transcript.hash !== expectedHash,
    "Init question append does not match the pending round.",
  );
  const next = {
    ...state,
    questionAppendPending: false,
    transcriptAppendHash: null,
    transcriptHash: transcript.hash,
  };
  assertInitState(next);
  return next;
}

export function authorizeInitEdit(state, authorization) {
  assertInitState(state);
  assertInit(
    (authorization.action === "product-decision"
      ? state.productDecision !== null && state.productDecisionAppended
      : state.selection === null) &&
      state.pendingTurn === null &&
      state.pendingEdit === null &&
      !state.questionAppendPending &&
      state.transcriptAppendHash === null &&
      ["CLARIFY", "WAITING_FOR_USER"].includes(state.workflowState) &&
      !["clarification_limit", "setup_blocked"].includes(state.pauseReason),
    "Init cannot authorize this edit.",
  );
  const next = {
    ...state,
    workflowState: "WAITING_FOR_USER",
    pendingEdit: structuredClone(authorization),
    proactiveClarificationComplete:
      state.proactiveClarificationComplete ||
      authorization.action === "proactive-clarification",
  };
  assertInitState(next);
  return next;
}

export function acceptInitEdit(
  state,
  result,
  selection = state.clarificationSelection,
) {
  assertInitState(state);
  const edit = state.pendingEdit;
  const decision = edit?.action === "product-decision";
  assertInit(
    edit !== null &&
      result.authorizationId === edit.id &&
      result.preEditorHash === edit.preEditorHash &&
      result.transcriptPath === edit.transcriptPath &&
      result.action === edit.action &&
      result.suspendedState === (decision ? "PROPOSE" : "CLARIFY") &&
      isHash(result.hash) &&
      result.changed === (result.hash !== edit.preEditorHash),
    "Init editor authorization does not match.",
  );
  if (
    ["clarification-answers", "product-decision"].includes(edit.action) &&
    !result.changed
  )
    return { ...state, pendingEdit: null };
  const next = {
    ...state,
    pendingEdit: null,
    workflowState: decision ? "PROPOSE" : "CLARIFY",
    pauseReason: null,
    transcriptHash: result.hash,
    clarificationReady: decision,
    ...(decision
      ? {
          clarificationHash: result.hash,
          productDecision: null,
          productDecisionAppended: false,
        }
      : {}),
    questions: [],
    clarificationSelection: structuredClone(
      decision ? state.clarificationSelection : selection,
    ),
    reinspectionRequired:
      state.reinspectionRequired ||
      (!decision &&
        !isDeepStrictEqual(selection, state.clarificationSelection)),
  };
  assertInitState(next);
  return next;
}

export function acceptInitResult(
  state,
  { turnId, inspection, transcriptHash, result },
) {
  assertInitState(state);
  assertInitInspection(
    transcriptHash === state.transcriptHash &&
      isDeepStrictEqual(state.inspection, inspection),
    "workspace_changed",
  );
  assertInit(
    state.pendingTurn !== null && state.pendingTurn.id === turnId,
    "Init turn is stale or changed read-only inputs.",
  );
  assertResultSize(result);
  let next = structuredClone({
    ...state,
    pendingTurn: null,
    correctiveFeedback: null,
  });
  if (state.workflowState === "CLARIFY") {
    exact(result, ["status", "questions", "reason"]);
    questions(result.questions);
    assertInit(
      ["READY", "QUESTIONS", "BLOCKED"].includes(result.status) &&
        typeof result.reason === "string" &&
        (result.status === "QUESTIONS"
          ? result.questions.length > 0
          : result.questions.length === 0),
      "Init clarification result is invalid.",
    );
    if (result.status === "BLOCKED") {
      assertInit(
        text(result.reason),
        "Init blocking outcome needs a bounded reason.",
      );
      return pause({ ...next, findings: [result.reason] }, "setup_blocked");
    }
    if (result.status === "QUESTIONS") {
      if (next.clarificationRounds === 3)
        return pause(next, "clarification_limit");
      next.clarificationRounds += 1;
      return pause(
        {
          ...next,
          clarificationReady: false,
          questionAppendPending: true,
          questions: structuredClone(result.questions),
        },
        "clarification_required",
      );
    }
    next.clarificationReady = true;
    if (selectInitPlacement(inspection, state.clarificationSelection) === null)
      return pause(next, "placement_conflict");
    return next;
  }
  result = normalizeInitRoleResult(
    result,
    ["PROPOSE", "CHECK_AND_FIX"].includes(state.workflowState),
  );
  if (result.status === "PRODUCT_DECISION_REQUIRED")
    return requestInitDecision(next, result.decision);
  if (["PROPOSE", "CHECK_AND_FIX"].includes(state.workflowState)) {
    next.proposal = normalizeProposal(result, next);
    // Reject unrenderable guidance while the prior valid proposal remains
    // retryable, before it becomes durable input to the next agent request.
    initGuidanceContent(next);
    next.proposalHash = digest(next.proposal);
    next.primaryApproval = null;
    next.reviewApproval = null;
    next.findings = [];
    next.workflowState = primaryConvergence(next)
      ? state.workflowState === "PROPOSE"
        ? "CHECK_AND_FIX"
        : "CLEAN_CONFIRM"
      : "REVIEW";
  } else {
    exact(result, ["status", "proposalHash", "findings"]);
    texts(result.findings);
    assertInit(
      ["CLEAN", "FINDINGS"].includes(result.status) &&
        result.proposalHash === state.proposalHash &&
        (result.status === "CLEAN"
          ? result.findings.length === 0
          : result.findings.length > 0),
      "Init confirmation must inspect the exact current proposal.",
    );
    if (result.status === "FINDINGS") {
      next.primaryApproval = null;
      next.reviewApproval = null;
      next.findings = structuredClone(result.findings);
      if (next.revisionRounds === next.settings.maxRevisionRounds)
        return pause(next, "revision_limit");
      next.revisionRounds += 1;
      next.workflowState = primaryConvergence(next)
        ? "CHECK_AND_FIX"
        : "PROPOSE";
    } else if (state.workflowState === "CLEAN_CONFIRM") {
      next.primaryApproval = approvalHash(next);
      next.workflowState =
        next.settings.mode === "lazy" ? "PROPOSAL_ACCEPTED" : "REVIEW";
    } else {
      next.reviewApproval = approvalHash(next);
      next.workflowState = "PROPOSAL_ACCEPTED";
    }
  }
  assertInitState(next);
  return next;
}

export function requestInitDecision(state, decision) {
  assertProductDecision(decision);
  const next = {
    ...state,
    workflowState: "WAITING_FOR_USER",
    pauseReason: "product_decision_required",
    pendingTurn: null,
    correctiveFeedback: null,
    proposal: null,
    proposalHash: null,
    primaryApproval: null,
    reviewApproval: null,
    productDecision: structuredClone(decision),
    productDecisions: state.productDecisions + 1,
    productDecisionAppended: false,
    transcriptAppendHash: null,
    findings: [],
  };
  assertInitState(next);
  return next;
}

export function assertInitRun(run) {
  assertInit(
    run.pipelineId === "init",
    "Init state belongs to another pipeline.",
  );
  if (["operator_paused", "operator_canceled"].includes(run.pause?.reason)) {
    const checkpoint = run.pause.operatorResume;
    exact(checkpoint, ["workflowState", "pause", "activeTurn"]);
    const canceled = run.pause.reason === "operator_canceled";
    assertInit(
      STAGES.includes(checkpoint.workflowState) &&
        checkpoint.workflowState !== "CANCELED" &&
        !["operator_paused", "operator_canceled"].includes(
          checkpoint.pause?.reason,
        ) &&
        run.pipelineState.workflowState ===
          (canceled ? "CANCELED" : "WAITING_FOR_USER") &&
        run.activeTurn === null &&
        run.pause.resumeAction === null &&
        run.stopRequest?.reconciledRevision != null &&
        run.stopRequest.kind ===
          (canceled ? "cancel_requested" : "pause_requested"),
      "Init operator stop requires a reconciled suspended checkpoint.",
    );
    run = {
      ...run,
      pipelineState: {
        ...run.pipelineState,
        workflowState: checkpoint.workflowState,
      },
      pause: checkpoint.pause,
    };
  } else {
    assertInit(
      run.pipelineState.workflowState !== "CANCELED",
      "Init cancellation requires a reconciled operator request.",
    );
  }
  if (
    run.pause?.reason === "internal_failure" ||
    Object.hasOwn(run.pause ?? {}, "diagnosticClass")
  ) {
    const diagnostic = Object.hasOwn(run.pause, "diagnosticClass");
    // Registry membership is validated by the common run envelope.
    exact(run.pause, [
      "reason",
      "code",
      ...(diagnostic ? ["diagnosticClass"] : []),
    ]);
    assertInit(
      run.pipelineState.workflowState === "FAILED" &&
        run.pause.reason === "internal_failure" &&
        typeof run.pause.code === "string" &&
        /^[A-Z0-9_]{1,64}$/u.test(run.pause.code) &&
        (!diagnostic ||
          (typeof run.pause.diagnosticClass === "string" &&
            /^[a-z][a-z0-9_]{0,63}$/u.test(run.pause.diagnosticClass))) &&
        run.pipelineState.pendingTurn === null &&
        run.pipelineState.pendingEdit === null &&
        run.pipelineState.completion === null &&
        run.pipelineState.terminal?.status !== "CLEAN" &&
        run.activeTurn === null &&
        run.preparation == null &&
        run.executionProcess == null &&
        run.executionResource == null &&
        run.pipelineState.publication?.pending == null &&
        (run.pipelineState.guidanceIntent === null ||
          run.pipelineState.guidanceReceipt !== null),
      "Init terminal provider failure requires settled read-only work.",
    );
  }
  if (run.pause?.reason === "init_inspection_failed") {
    assertInspectionFailure(run.pause, run.pipelineState);
    assertInit(
      run.pipelineState.workflowState === "WAITING_FOR_USER" &&
        run.pipelineState.pendingTurn === null &&
        run.activeTurn === null &&
        run.preparation == null &&
        run.executionProcess == null &&
        run.executionResource == null &&
        run.pipelineState.publication?.pending == null &&
        (run.pipelineState.guidanceIntent === null ||
          run.pipelineState.guidanceReceipt !== null),
      "Init inspection rejection requires a settled pause.",
    );
    if (
      run.pipelineState.pendingEdit === null &&
      run.pipelineState.productDecision === null &&
      run.pipelineState.pauseReason !== "clarification_required"
    )
      assertInitState({
        ...run.pipelineState,
        workflowState: run.pause.resumeState,
      });
  }
  // Root safety blockers may suspend a still-reserved read-only turn. Validate
  // its original binding without granting a continuation through that blocker.
  const state = run.pipelineState;
  if (
    state.correctiveFeedback !== null &&
    state.workflowState === "WAITING_FOR_USER" &&
    !["workspace_changed", "project_configuration_changed"].includes(
      run.pause?.reason,
    )
  )
    assertInit(
      run.pause?.resumeState ===
        (state.correctiveFeedback.reservation.phase === "CONFIRM"
          ? "PROPOSAL_ACCEPTED"
          : state.correctiveFeedback.reservation.phase),
      "Init rejection resume checkpoint changed.",
    );
  const phase =
    state.workflowState === "WAITING_FOR_USER" &&
    state.pendingTurn !== null &&
    ["workspace_changed", "project_configuration_changed"].includes(
      run.pause?.reason,
    )
      ? state.pendingTurn.phase
      : state.workflowState;
  assertInitState({ ...state, workflowState: phase });
}

export function failInitTurn(state, request) {
  assertInitState(state);
  assertInit(
    request.phase === "CONFIRM"
      ? state.workflowState === "PROPOSAL_ACCEPTED" &&
          state.pendingTurn === null &&
          state.terminal?.status === "PENDING" &&
          request.role ===
            (state.settings.mode === "lazy" ? "planner" : "reviewer")
      : state.pendingTurn !== null &&
          state.pendingTurn.id === request.id &&
          state.pendingTurn.phase === request.phase &&
          state.pendingTurn.role === request.role &&
          state.pendingTurn.binding === request.binding,
    "Init failure does not own the reserved turn.",
  );
  return {
    ...state,
    workflowState: "FAILED",
    pendingTurn: null,
    correctiveFeedback: null,
  };
}
