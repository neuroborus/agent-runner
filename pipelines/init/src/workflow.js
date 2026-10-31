import { join } from "node:path";
import { isDeepStrictEqual } from "node:util";

import { selectInitPlacement } from "./inspection.js";
import {
  assertInit,
  assertInspection,
  assertInspectionExtension,
  assertResultSize,
  digest,
  exact,
  isHash,
  isPath,
  normalizeProposal,
  questions,
  text,
  texts,
} from "./proposal.js";
import { INIT_INSTRUCTIONS, PHASE_INSTRUCTIONS } from "./prompts.js";
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
  "WAITING_FOR_USER",
];
const primaryConvergence = (state) => state.settings.mode !== "independent";

export function createInitState({
  settings = {},
  configurationPath = null,
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
    clarificationRounds: 0,
    revisionRounds: 0,
    proposal: null,
    proposalHash: null,
    primaryApproval: null,
    reviewApproval: null,
    findings: [],
    questions: [],
    pendingTurn: null,
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
      typeof state.reinspectionRequired === "boolean",
    "Init state or accounting is invalid.",
  );
  texts(state.findings);
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
        state.selection === null &&
        state.inspection !== null &&
        edit.schemaVersion === 1 &&
        typeof edit.id === "string" &&
        edit.id.length > 0 &&
        edit.id.length <= 256 &&
        edit.artifactRoot === state.inspection.taskPath &&
        edit.transcriptPath === join(edit.artifactRoot, "clarifications.md") &&
        edit.suspendedState === "CLARIFY" &&
        edit.action ===
          (state.pauseReason === "clarification_required"
            ? "clarification-answers"
            : "proactive-clarification") &&
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
  if (!["CLARIFY", "WAITING_FOR_USER"].includes(state.workflowState))
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
  if (state.workflowState === "PROPOSAL_ACCEPTED") {
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
}

const approvalHash = (state) =>
  digest({
    inspection: state.inspection,
    selection: state.selection,
    clarificationHash: state.clarificationHash,
    proposalHash: state.proposalHash,
  });
const turnBinding = (state) =>
  digest({
    binding: approvalHash(state),
    phase: state.workflowState,
    findings: state.findings,
    revisions: state.revisionRounds,
    questions: state.clarificationRounds,
    transcriptHash: state.transcriptHash,
  });

// The caller persists the returned reservation before invoking its adapter.
export function prepareInitTurn(state, inspection, transcriptHash) {
  assertInitState(state);
  assertInspection(inspection);
  assertInit(
    isHash(transcriptHash) &&
      (state.transcriptHash === null ||
        state.transcriptHash === transcriptHash),
    "Init clarifications changed outside an authorized editor window.",
  );
  assertInit(
    !["PROPOSAL_ACCEPTED", "WAITING_FOR_USER"].includes(state.workflowState),
    "Init is not at an agent checkpoint.",
  );
  if (state.reinspectionRequired)
    assertInspectionExtension(state.inspection, inspection);
  else
    assertInit(
      state.inspection === null ||
        isDeepStrictEqual(state.inspection, inspection),
      "Inspected init inputs or destinations changed.",
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
          mode: next.settings.mode,
          selectionInput: next.clarificationSelection,
          selection: next.selection,
          proposal: next.proposal,
          proposalHash: next.proposalHash,
          findings: next.findings,
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
  assertInit(
    state.inspection === null ||
      isDeepStrictEqual(state.inspection, inspection),
    "Init setup changed during clarification.",
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
      transcript.hash !== expectedHash,
    "Init question append does not match the pending round.",
  );
  const next = {
    ...state,
    questionAppendPending: false,
    transcriptHash: transcript.hash,
  };
  assertInitState(next);
  return next;
}

export function authorizeInitEdit(state, authorization) {
  assertInitState(state);
  assertInit(
    state.selection === null &&
      state.pendingTurn === null &&
      state.pendingEdit === null &&
      !state.questionAppendPending &&
      ["CLARIFY", "WAITING_FOR_USER"].includes(state.workflowState) &&
      !["clarification_limit", "setup_blocked"].includes(state.pauseReason),
    "Init cannot authorize this edit.",
  );
  const next = {
    ...state,
    workflowState: "WAITING_FOR_USER",
    pendingEdit: structuredClone(authorization),
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
  assertInit(
    edit !== null &&
      result.authorizationId === edit.id &&
      result.preEditorHash === edit.preEditorHash &&
      result.transcriptPath === edit.transcriptPath &&
      result.action === edit.action &&
      result.suspendedState === "CLARIFY" &&
      isHash(result.hash) &&
      result.changed === (result.hash !== edit.preEditorHash),
    "Init editor authorization does not match.",
  );
  if (edit.action === "clarification-answers" && !result.changed)
    return { ...state, pendingEdit: null };
  const next = {
    ...state,
    pendingEdit: null,
    workflowState: "CLARIFY",
    pauseReason: null,
    transcriptHash: result.hash,
    clarificationReady: false,
    questions: [],
    clarificationSelection: structuredClone(selection),
    reinspectionRequired:
      state.reinspectionRequired ||
      !isDeepStrictEqual(selection, state.clarificationSelection),
  };
  assertInitState(next);
  return next;
}

export function acceptInitResult(
  state,
  { turnId, inspection, transcriptHash, result },
) {
  assertInitState(state);
  assertInit(
    state.pendingTurn !== null &&
      state.pendingTurn.id === turnId &&
      transcriptHash === state.transcriptHash &&
      isDeepStrictEqual(state.inspection, inspection),
    "Init turn is stale or changed read-only inputs.",
  );
  assertResultSize(result);
  let next = structuredClone({ ...state, pendingTurn: null });
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
  if (["PROPOSE", "CHECK_AND_FIX"].includes(state.workflowState)) {
    next.proposal = normalizeProposal(result, next);
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
