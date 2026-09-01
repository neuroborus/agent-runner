import { createHash } from "node:crypto";
import { isAbsolute, join, relative, resolve, sep } from "node:path";

import {
  parseCommitPlan,
  serializeCommitPlan,
} from "@agent-runner/commit-plan";

export const MAX_CLARIFICATION_ROUNDS = 3;

export const WORKFLOW_STATES = Object.freeze([
  "CLARIFY",
  "ANALYZE",
  "DRAFT",
  "REVIEW",
  "REVISE",
  "VALIDATE",
  "WRITE_PLAN",
  "WAITING_FOR_USER",
  "DONE",
  "FAILED",
]);

const PIPELINE_STATE_FIELDS = new Set([
  "workflowState",
  "preflightComplete",
  "settings",
  "repositoryBaseline",
  "proactiveClarification",
  "proactiveClarificationComplete",
  "clarificationFrozen",
  "pendingEdit",
  "draft",
  "draftFingerprint",
  "findings",
  "validationIssues",
  "blockerKind",
  "reviewApproved",
  "lastCountedRevision",
  "blockedSinceArbitration",
  "arbitrationUsed",
  "arbiterDirection",
  "correctionHistory",
  "canonicalPlan",
  "planPath",
]);
const COUNTER_FIELDS = Object.freeze([
  "clarificationRounds",
  "productDecisions",
  "revisionRounds",
  "correctionRounds",
]);
const PENDING_EDIT_FIELDS = new Set([
  "schemaVersion",
  "id",
  "artifactRoot",
  "transcriptPath",
  "suspendedState",
  "action",
  "preEditorHash",
]);
const FINDING_ID_PATTERN = /^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$/u;
const HASH_PATTERN = /^[a-f0-9]{64}$/u;
const MAX_TEXT_LENGTH = 4_000;
const MAX_PLAN_LENGTH = 100_000;
const MAX_ITEMS = 32;
const MAX_PRODUCT_DECISION_OPTIONS = 16;
const MAX_STRUCTURED_RESULT_BYTES = 256 * 1024;
const INVALID_OUTPUT_CODE = "ERR_INVALID_PLAN_AUTHORING_OUTPUT";
const FAILURE_FIELDS = Object.freeze(["reason", "code"]);
const ADAPTER_FAILURE_FIELDS = Object.freeze([
  ...FAILURE_FIELDS,
  "diagnosticClass",
]);
const ADAPTER_DIAGNOSTIC_CLASS_PATTERN = /^[a-z][a-z0-9_]{0,63}$/u;
const BACKEND_RESUME_STATES = Object.freeze([
  "CLARIFY",
  "DRAFT",
  "REVIEW",
  "REVISE",
]);
const ROLES = Object.freeze(["planner", "reviewer", "arbiter"]);

export const MAX_DIAGNOSTIC_ITEMS = MAX_ITEMS;

export function resolveActiveRoles() {
  return ROLES;
}

export class PlanAuthoringWorkflowError extends Error {
  constructor(message, { cause, code = "ERR_PLAN_AUTHORING_WORKFLOW" } = {}) {
    super(message, { cause });
    this.name = "PlanAuthoringWorkflowError";
    this.code = code;
  }
}

export function isRecord(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function hasExactFields(value, fields) {
  return (
    Object.keys(value).length === fields.length &&
    fields.every((field) => Object.hasOwn(value, field))
  );
}

export function workflowError(
  message,
  code = "ERR_INVALID_PLAN_AUTHORING_STATE",
) {
  return new PlanAuthoringWorkflowError(message, { code });
}

export function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function repositoryRelativePath(projectPath, path) {
  const relativePath = relative(projectPath, path);
  if (
    relativePath === "" ||
    relativePath === ".." ||
    relativePath.startsWith(`..${sep}`) ||
    isAbsolute(relativePath)
  ) {
    return null;
  }
  return relativePath.split(sep).join("/");
}

function outputError(message) {
  return workflowError(message, INVALID_OUTPUT_CODE);
}

function isFindingId(value) {
  return (
    typeof value === "string" &&
    value.length <= 64 &&
    FINDING_ID_PATTERN.test(value)
  );
}

function emptyDecision(payload) {
  return (
    payload.question === "" &&
    payload.whyBlocked === "" &&
    Array.isArray(payload.options) &&
    payload.options.length === 0 &&
    Array.isArray(payload.evidence) &&
    payload.evidence.length === 0
  );
}

function assertStructuredResultSize(payload) {
  let serialized;
  try {
    serialized = JSON.stringify(payload);
  } catch (cause) {
    throw new PlanAuthoringWorkflowError(
      "Structured role result must be serializable.",
      { cause, code: INVALID_OUTPUT_CODE },
    );
  }
  if (
    typeof serialized !== "string" ||
    Buffer.byteLength(serialized) > MAX_STRUCTURED_RESULT_BYTES
  ) {
    throw workflowError(
      "Structured role result is too large.",
      INVALID_OUTPUT_CODE,
    );
  }
}

function normalizeText(
  value,
  name,
  maximumLength = MAX_TEXT_LENGTH,
  code = "ERR_INVALID_PLAN_AUTHORING_STATE",
) {
  if (
    typeof value !== "string" ||
    value.trim().length === 0 ||
    value.length > maximumLength ||
    /[\0\p{Cc}\p{Zl}\p{Zp}]/u.test(value)
  ) {
    throw workflowError(`${name} must be concise plain text.`, code);
  }
  return value.trim().replace(/\s+/gu, " ");
}

function normalizeTextList(
  value,
  name,
  {
    allowEmpty = false,
    code = "ERR_INVALID_PLAN_AUTHORING_STATE",
    maximum = MAX_ITEMS,
  } = {},
) {
  if (
    !Array.isArray(value) ||
    (!allowEmpty && value.length === 0) ||
    value.length > maximum
  ) {
    throw workflowError(`${name} has an invalid number of items.`, code);
  }
  return Object.freeze(
    value.map((item, index) =>
      normalizeText(item, `${name}[${index}]`, MAX_TEXT_LENGTH, code),
    ),
  );
}

function assertInputPause(run, pipelineState) {
  const request = run.pause?.inputRequest;
  if (
    pipelineState.workflowState !== "WAITING_FOR_USER" ||
    pipelineState.pendingEdit === null
  ) {
    if (request !== undefined || run.pause?.inputResponse !== undefined) {
      throw workflowError("Plan-authoring input pause is invalid.");
    }
    return;
  }
  if (request === undefined) {
    return;
  }
  if (!isRecord(request) || !Array.isArray(request.questions)) {
    throw workflowError("Plan-authoring input request is invalid.");
  }

  const action = pipelineState.pendingEdit.action;
  const productDecision = action === "product-decision";
  const invalidQuestions =
    action === "proactive-clarification"
      ? request.questions.length !== 0
      : productDecision
        ? request.questions.length !== 1 ||
          !isRecord(request.questions[0]) ||
          !Array.isArray(request.questions[0].options) ||
          request.questions[0].id !== "decision" ||
          request.questions[0].rationale !== undefined
        : request.questions.length === 0 ||
          request.questions.some(
            (question, index) =>
              !isRecord(question) ||
              !Array.isArray(question.options) ||
              question.id !== `q${index + 1}` ||
              question.options.length !== 0 ||
              question.rationale === undefined,
          );
  if (
    request.id !== pipelineState.pendingEdit.id ||
    request.kind !== (productDecision ? "product-decision" : "clarification") ||
    request.artifactPath !== pipelineState.pendingEdit.transcriptPath ||
    invalidQuestions
  ) {
    throw workflowError("Plan-authoring input request is invalid.");
  }
}

function normalizeProductDecision(payload) {
  return Object.freeze({
    question: normalizeText(
      payload.question,
      "product decision question",
      MAX_TEXT_LENGTH,
      INVALID_OUTPUT_CODE,
    ),
    options: normalizeTextList(payload.options, "product decision options", {
      allowEmpty: true,
      code: INVALID_OUTPUT_CODE,
      maximum: MAX_PRODUCT_DECISION_OPTIONS,
    }),
    whyBlocked: normalizeText(
      payload.whyBlocked,
      "product decision rationale",
      MAX_TEXT_LENGTH,
      INVALID_OUTPUT_CODE,
    ),
    evidence: normalizeTextList(
      payload.evidence,
      "product decision evidence",
      { code: INVALID_OUTPUT_CODE },
    ),
  });
}

export function normalizeQuestions(payload) {
  if (!isRecord(payload) || !["READY", "QUESTIONS"].includes(payload.status)) {
    throw outputError("Planner returned an invalid clarification result.");
  }
  assertStructuredResultSize(payload);
  if (
    !Array.isArray(payload.questions) ||
    payload.questions.length > MAX_ITEMS
  ) {
    throw outputError("Planner returned invalid clarification questions.");
  }
  const questions = Object.freeze(
    payload.questions.map((question, index) => {
      if (!isRecord(question)) {
        throw outputError(`clarification question ${index + 1} is invalid.`);
      }
      return Object.freeze({
        question: normalizeText(
          question.question,
          `clarification question ${index + 1}`,
          MAX_TEXT_LENGTH,
          INVALID_OUTPUT_CODE,
        ),
        whyItMatters: normalizeText(
          question.whyItMatters,
          `clarification rationale ${index + 1}`,
          MAX_TEXT_LENGTH,
          INVALID_OUTPUT_CODE,
        ),
      });
    }),
  );
  if (
    (payload.status === "READY" && questions.length !== 0) ||
    (payload.status === "QUESTIONS" && questions.length === 0)
  ) {
    throw outputError("Clarification status does not match its questions.");
  }
  return Object.freeze({ status: payload.status, questions });
}

export function normalizePlannerResult(payload) {
  if (
    !isRecord(payload) ||
    !["DRAFT", "PRODUCT_DECISION_REQUIRED"].includes(payload.status)
  ) {
    throw outputError("Planner returned an invalid draft result.");
  }
  assertStructuredResultSize(payload);
  if (payload.status === "PRODUCT_DECISION_REQUIRED") {
    if (payload.plan !== "") {
      throw outputError("A product-decision result must not include a plan.");
    }
    return Object.freeze({
      status: payload.status,
      decision: normalizeProductDecision(payload),
    });
  }
  if (
    typeof payload.plan !== "string" ||
    payload.plan.trim().length === 0 ||
    payload.plan.length > MAX_PLAN_LENGTH ||
    !emptyDecision(payload)
  ) {
    throw outputError("Planner returned an invalid commit plan draft.");
  }
  return Object.freeze({ status: payload.status, plan: payload.plan });
}

function normalizeFindings(value, code = INVALID_OUTPUT_CODE) {
  if (!Array.isArray(value) || value.length === 0 || value.length > MAX_ITEMS) {
    throw workflowError(
      "Reviewer findings have an invalid number of items.",
      code,
    );
  }
  const findings = value.map((finding, index) => {
    if (!isRecord(finding) || !isFindingId(finding.id)) {
      throw workflowError(
        `Reviewer finding ${index + 1} has an invalid ID.`,
        code,
      );
    }
    return Object.freeze({
      id: finding.id,
      description: normalizeText(
        finding.description,
        `Reviewer finding ${finding.id}`,
        MAX_TEXT_LENGTH,
        code,
      ),
      evidence: normalizeTextList(
        finding.evidence,
        `Reviewer finding ${finding.id} evidence`,
        { code },
      ),
    });
  });
  if (new Set(findings.map(({ id }) => id)).size !== findings.length) {
    throw workflowError("Reviewer finding IDs must be unique.", code);
  }
  return Object.freeze(findings);
}

export function normalizeReviewResult(payload) {
  const statuses = ["APPROVED", "FINDINGS", "PRODUCT_DECISION_REQUIRED"];
  if (!isRecord(payload) || !statuses.includes(payload.status)) {
    throw outputError("Reviewer returned an invalid review result.");
  }
  assertStructuredResultSize(payload);
  if (payload.status === "PRODUCT_DECISION_REQUIRED") {
    if (!Array.isArray(payload.findings) || payload.findings.length !== 0) {
      throw outputError("A product decision must not include findings.");
    }
    return Object.freeze({
      status: payload.status,
      decision: normalizeProductDecision(payload),
    });
  }
  if (!emptyDecision(payload)) {
    throw outputError("Review result contains inapplicable decision fields.");
  }
  if (payload.status === "APPROVED") {
    if (!Array.isArray(payload.findings) || payload.findings.length !== 0) {
      throw outputError("An approved review must not include findings.");
    }
    return Object.freeze({
      status: payload.status,
      findings: Object.freeze([]),
    });
  }
  return Object.freeze({
    status: payload.status,
    findings: normalizeFindings(payload.findings),
  });
}

export function normalizeArbiterResult(payload, pipelineState) {
  const directions = [
    "CONTINUE_REVISION",
    "RESTRUCTURE_PLAN",
    "RECONSIDER_FINDINGS",
    "PRODUCT_DECISION_REQUIRED",
  ];
  if (!isRecord(payload) || !directions.includes(payload.direction)) {
    throw outputError("Arbiter returned an invalid direction.");
  }
  assertStructuredResultSize(payload);
  const rationale = normalizeText(
    payload.rationale,
    "Arbiter rationale",
    MAX_TEXT_LENGTH,
    INVALID_OUTPUT_CODE,
  );
  if (payload.direction === "PRODUCT_DECISION_REQUIRED") {
    if (!Array.isArray(payload.findingIds) || payload.findingIds.length !== 0) {
      throw outputError("Product-decision arbitration cannot name findings.");
    }
    return Object.freeze({
      direction: payload.direction,
      rationale,
      decision: normalizeProductDecision(payload),
    });
  }
  if (!emptyDecision(payload)) {
    throw outputError("Arbiter result contains inapplicable decision fields.");
  }
  const findingIds = normalizeTextList(
    payload.findingIds,
    "Arbiter finding IDs",
    {
      allowEmpty: true,
      code: INVALID_OUTPUT_CODE,
    },
  );
  if (
    findingIds.some((id) => !isFindingId(id)) ||
    new Set(findingIds).size !== findingIds.length
  ) {
    throw outputError("Arbiter returned an invalid finding ID.");
  }
  if (payload.direction === "RECONSIDER_FINDINGS") {
    const currentIds = pipelineState.findings.map(({ id }) => id).sort();
    const requestedIds = [...new Set(findingIds)].sort();
    if (
      pipelineState.blockerKind !== "findings" ||
      currentIds.length !== requestedIds.length ||
      currentIds.some((id, index) => id !== requestedIds[index])
    ) {
      throw outputError("Finding reconsideration is not applicable.");
    }
  } else if (findingIds.length !== 0) {
    throw outputError("This Arbiter direction cannot name findings.");
  }
  return Object.freeze({
    direction: payload.direction,
    rationale,
    findingIds,
  });
}

export function normalizePipelineState(value) {
  if (!isRecord(value)) {
    throw workflowError("Plan-authoring state must be an object.");
  }
  const unknown = Object.keys(value).find(
    (field) => !PIPELINE_STATE_FIELDS.has(field),
  );
  if (
    unknown !== undefined ||
    Object.keys(value).length !== PIPELINE_STATE_FIELDS.size ||
    !WORKFLOW_STATES.includes(value.workflowState)
  ) {
    throw workflowError("Plan-authoring state is invalid.");
  }
  for (const field of [
    "preflightComplete",
    "proactiveClarification",
    "proactiveClarificationComplete",
    "clarificationFrozen",
    "reviewApproved",
    "arbitrationUsed",
  ]) {
    if (typeof value[field] !== "boolean") {
      throw workflowError(`Plan-authoring state field ${field} is invalid.`);
    }
  }
  if (value.settings !== null) {
    assertSettings(value.settings);
  }
  if (
    (value.preflightComplete && value.settings === null) ||
    (value.repositoryBaseline !== null &&
      !isRecord(value.repositoryBaseline)) ||
    value.preflightComplete !== (value.repositoryBaseline !== null)
  ) {
    throw workflowError("Plan-authoring preflight state is invalid.");
  }
  for (const field of ["lastCountedRevision", "blockedSinceArbitration"]) {
    if (!Number.isSafeInteger(value[field]) || value[field] < 0) {
      throw workflowError(`Plan-authoring state field ${field} is invalid.`);
    }
  }
  for (const field of ["findings", "validationIssues", "correctionHistory"]) {
    if (!Array.isArray(value[field])) {
      throw workflowError(`Plan-authoring state field ${field} is invalid.`);
    }
  }
  if (value.pendingEdit !== null) {
    const pendingEdit = value.pendingEdit;
    if (!isRecord(pendingEdit)) {
      throw workflowError("Plan-authoring pending edit is invalid.");
    }
    const expectedState = {
      "clarification-answers": "CLARIFY",
      "product-decision": "ANALYZE",
      "proactive-clarification": "CLARIFY",
    }[pendingEdit.action];
    if (
      Object.keys(pendingEdit).length !== PENDING_EDIT_FIELDS.size ||
      Object.keys(pendingEdit).some(
        (field) => !PENDING_EDIT_FIELDS.has(field),
      ) ||
      pendingEdit.schemaVersion !== 1 ||
      typeof pendingEdit.id !== "string" ||
      pendingEdit.id.trim().length === 0 ||
      pendingEdit.id !== pendingEdit.id.trim() ||
      pendingEdit.id.length > 256 ||
      /[\0\p{Cc}\p{Zl}\p{Zp}]/u.test(pendingEdit.id) ||
      typeof pendingEdit.artifactRoot !== "string" ||
      !isAbsolute(pendingEdit.artifactRoot) ||
      typeof pendingEdit.transcriptPath !== "string" ||
      !isAbsolute(pendingEdit.transcriptPath) ||
      expectedState === undefined ||
      pendingEdit.suspendedState !== expectedState ||
      typeof pendingEdit.preEditorHash !== "string" ||
      !HASH_PATTERN.test(pendingEdit.preEditorHash)
    ) {
      throw workflowError("Plan-authoring pending edit is invalid.");
    }
  }
  if (
    value.pendingEdit !== null &&
    !["WAITING_FOR_USER", "FAILED"].includes(value.workflowState)
  ) {
    throw workflowError("Plan-authoring pending edit is not applicable.");
  }
  if (
    (!value.proactiveClarification &&
      !value.proactiveClarificationComplete) ||
    (!value.proactiveClarificationComplete &&
      !["CLARIFY", "WAITING_FOR_USER", "FAILED"].includes(
        value.workflowState,
      )) ||
    (value.pendingEdit !== null &&
      (value.pendingEdit.action === "proactive-clarification") !==
        (value.proactiveClarification &&
          !value.proactiveClarificationComplete))
  ) {
    throw workflowError(
      "Plan-authoring proactive clarification state is invalid.",
    );
  }
  for (const field of ["draft", "canonicalPlan"]) {
    if (
      value[field] !== null &&
      (typeof value[field] !== "string" ||
        value[field].length === 0 ||
        value[field].length > MAX_PLAN_LENGTH)
    ) {
      throw workflowError(`Plan-authoring state field ${field} is invalid.`);
    }
  }
  if (
    value.draftFingerprint !== null &&
    (typeof value.draftFingerprint !== "string" ||
      !HASH_PATTERN.test(value.draftFingerprint))
  ) {
    throw workflowError("Plan-authoring draft fingerprint is invalid.");
  }
  if (
    (value.draft === null) !== (value.draftFingerprint === null) ||
    (value.draft !== null && value.draftFingerprint !== sha256(value.draft))
  ) {
    throw workflowError("Plan-authoring draft fingerprint does not match.");
  }
  if (value.canonicalPlan !== null) {
    let expectedCanonicalPlan;
    try {
      expectedCanonicalPlan = serializeCommitPlan(parseCommitPlan(value.draft));
    } catch {
      throw workflowError("Canonical plan does not match the reviewed draft.");
    }
    if (value.canonicalPlan !== expectedCanonicalPlan) {
      throw workflowError("Canonical plan does not match the reviewed draft.");
    }
  }
  if (![null, "findings", "validation"].includes(value.blockerKind)) {
    throw workflowError("Plan-authoring blocker kind is invalid.");
  }
  if (value.blockerKind === "findings") {
    normalizeFindings(value.findings, "ERR_INVALID_PLAN_AUTHORING_STATE");
  } else if (value.findings.length !== 0) {
    throw workflowError("Plan-authoring findings do not match the blocker kind.");
  }
  const validationIssues = normalizeTextList(
    value.validationIssues,
    "Plan-authoring validation issues",
    { allowEmpty: value.blockerKind !== "validation" },
  );
  if (
    value.blockerKind !== "validation" &&
    validationIssues.length !== 0
  ) {
    throw workflowError(
      "Plan-authoring validation issues do not match the blocker kind.",
    );
  }
  if (value.arbiterDirection !== null) {
    if (
      !isRecord(value.arbiterDirection) ||
      Object.keys(value.arbiterDirection).length !== 2 ||
      !["direction", "rationale"].every((field) =>
        Object.hasOwn(value.arbiterDirection, field),
      ) ||
      ![
        "CONTINUE_REVISION",
        "RESTRUCTURE_PLAN",
        "RECONSIDER_FINDINGS",
      ].includes(value.arbiterDirection.direction)
    ) {
      throw workflowError("Plan-authoring Arbiter direction is invalid.");
    }
    normalizeText(value.arbiterDirection.rationale, "Arbiter rationale");
  }
  if (
    value.correctionHistory.length > MAX_DIAGNOSTIC_ITEMS ||
    value.correctionHistory.some((entry) => !isRecord(entry))
  ) {
    throw workflowError("Plan-authoring correction history is invalid.");
  }
  let previousRound = 0;
  for (const entry of value.correctionHistory) {
    if (
      Object.keys(entry).length !== 4 ||
      !["round", "draftFingerprint", "findingIds", "validationIssues"].every(
        (field) => Object.hasOwn(entry, field),
      ) ||
      !Number.isSafeInteger(entry.round) ||
      entry.round < 1 ||
      typeof entry.draftFingerprint !== "string" ||
      !HASH_PATTERN.test(entry.draftFingerprint)
    ) {
      throw workflowError("Plan-authoring correction history is invalid.");
    }
    if (entry.round <= previousRound) {
      throw workflowError("Plan-authoring correction history is not ordered.");
    }
    previousRound = entry.round;
    const findingIds = normalizeTextList(
      entry.findingIds,
      "Plan-authoring correction finding IDs",
      { allowEmpty: true },
    );
    if (
      findingIds.some((id) => !isFindingId(id)) ||
      new Set(findingIds).size !== findingIds.length
    ) {
      throw workflowError("Plan-authoring correction finding IDs are invalid.");
    }
    const validationIssues = normalizeTextList(
      entry.validationIssues,
      "Plan-authoring correction validation issues",
      { allowEmpty: true },
    );
    if ((findingIds.length === 0) === (validationIssues.length === 0)) {
      throw workflowError("Plan-authoring correction evidence is invalid.");
    }
  }
  if (
    value.planPath !== null &&
    (typeof value.planPath !== "string" || !isAbsolute(value.planPath))
  ) {
    throw workflowError("Plan-authoring plan path is invalid.");
  }
  if (value.planPath !== null && value.workflowState !== "DONE") {
    throw workflowError("Plan-authoring plan path is not applicable.");
  }
  if (value.arbiterDirection !== null && !value.arbitrationUsed) {
    throw workflowError("Plan-authoring Arbiter direction is not applicable.");
  }
  if (
    value.arbiterDirection?.direction === "RECONSIDER_FINDINGS" &&
    value.blockerKind !== "findings"
  ) {
    throw workflowError("Plan-authoring finding reconsideration is invalid.");
  }

  const emptyPlanState =
    value.draft === null &&
    value.blockerKind === null &&
    !value.reviewApproved &&
    value.canonicalPlan === null &&
    value.planPath === null;
  if (
    ["CLARIFY", "ANALYZE", "DRAFT"].includes(value.workflowState) &&
    !emptyPlanState
  ) {
    throw workflowError("Plan-authoring planning state is inconsistent.");
  }
  if (
    value.workflowState === "REVIEW" &&
    (value.draft === null ||
      value.reviewApproved ||
      value.canonicalPlan !== null ||
      (value.blockerKind !== null &&
        value.arbiterDirection?.direction !== "RECONSIDER_FINDINGS"))
  ) {
    throw workflowError("Plan-authoring review state is inconsistent.");
  }
  if (
    value.workflowState === "REVISE" &&
    (value.draft === null ||
      value.blockerKind === null ||
      value.reviewApproved ||
      value.canonicalPlan !== null)
  ) {
    throw workflowError("Plan-authoring revision state is inconsistent.");
  }
  if (
    value.workflowState === "VALIDATE" &&
    (value.draft === null ||
      value.blockerKind !== null ||
      !value.reviewApproved ||
      value.canonicalPlan !== null)
  ) {
    throw workflowError("Plan-authoring validation state is inconsistent.");
  }
  if (
    ["WRITE_PLAN", "DONE"].includes(value.workflowState) &&
    (value.draft === null ||
      value.blockerKind !== null ||
      !value.reviewApproved ||
      value.canonicalPlan === null ||
      (value.workflowState === "DONE") !== (value.planPath !== null))
  ) {
    throw workflowError("Plan-authoring completion state is inconsistent.");
  }
  if (
    !["CLARIFY", "WAITING_FOR_USER", "FAILED"].includes(
      value.workflowState,
    ) &&
    !value.preflightComplete
  ) {
    throw workflowError("Plan-authoring state has not completed preflight.");
  }
  if (
    (value.workflowState === "CLARIFY" && value.clarificationFrozen) ||
    (["DRAFT", "REVIEW", "REVISE", "VALIDATE", "WRITE_PLAN", "DONE"].includes(
      value.workflowState,
    ) &&
      !value.clarificationFrozen)
  ) {
    throw workflowError("Plan-authoring clarification state is inconsistent.");
  }
  if (
    value.arbiterDirection !== null &&
    !["WAITING_FOR_USER", "FAILED"].includes(value.workflowState)
  ) {
    const expectedState =
      value.arbiterDirection.direction === "RECONSIDER_FINDINGS"
        ? "REVIEW"
        : "REVISE";
    if (value.workflowState !== expectedState) {
      throw workflowError("Plan-authoring Arbiter state is inconsistent.");
    }
  }
  return value;
}

export function createPlanAuthoringState({
  proactiveClarification = false,
  settings = null,
} = {}) {
  if (typeof proactiveClarification !== "boolean") {
    throw workflowError("proactiveClarification must be a boolean.");
  }
  if (settings !== null) {
    assertSettings(settings);
  }
  return Object.freeze({
    workflowState: "CLARIFY",
    preflightComplete: false,
    settings: settings === null ? null : Object.freeze({ ...settings }),
    repositoryBaseline: null,
    proactiveClarification,
    proactiveClarificationComplete: !proactiveClarification,
    clarificationFrozen: false,
    pendingEdit: null,
    draft: null,
    draftFingerprint: null,
    findings: Object.freeze([]),
    validationIssues: Object.freeze([]),
    blockerKind: null,
    reviewApproved: false,
    lastCountedRevision: 0,
    blockedSinceArbitration: 0,
    arbitrationUsed: false,
    arbiterDirection: null,
    correctionHistory: Object.freeze([]),
    canonicalPlan: null,
    planPath: null,
  });
}

function assertCounterRecord(counters) {
  if (
    !isRecord(counters) ||
    Object.keys(counters).some((field) => !COUNTER_FIELDS.includes(field))
  ) {
    throw workflowError("Plan-authoring counters are invalid.");
  }
  for (const field of COUNTER_FIELDS) {
    const value = Object.hasOwn(counters, field) ? counters[field] : 0;
    if (!Number.isSafeInteger(value) || value < 0) {
      throw workflowError(`Plan-authoring counter ${field} is invalid.`);
    }
  }
}

export function normalizedCounters(counters) {
  return Object.freeze(
    Object.fromEntries(
      COUNTER_FIELDS.map((field) => [
        field,
        Object.hasOwn(counters, field) ? counters[field] : 0,
      ]),
    ),
  );
}

export function assertRun(run) {
  if (
    !isRecord(run) ||
    run.pipelineId !== "plan-authoring" ||
    run.pipelineStateVersion !== 1 ||
    typeof run.projectPath !== "string" ||
    !isAbsolute(run.projectPath) ||
    resolve(run.projectPath) !== run.projectPath ||
    typeof run.taskPath !== "string" ||
    !isAbsolute(run.taskPath) ||
    resolve(run.taskPath) !== run.taskPath ||
    !isRecord(run.roles) ||
    !isRecord(run.hashes) ||
    !isRecord(run.sessionLineage) ||
    !Array.isArray(run.sessionLineage.children)
  ) {
    throw workflowError("Plan-authoring run envelope is invalid.");
  }
  const pipelineState = normalizePipelineState(run.pipelineState);
  const activeRoles = resolveActiveRoles(pipelineState.settings);
  if (
    Object.keys(run.roles).length !== activeRoles.length ||
    activeRoles.some((role) => !Object.hasOwn(run.roles, role))
  ) {
    throw workflowError("Plan-authoring roles are invalid.");
  }
  for (const role of activeRoles) {
    if (
      !isRecord(run.roles[role]) ||
      Object.keys(run.roles[role]).some(
        (field) =>
          !["backend", "profile", "model", "contextSize"].includes(field),
      ) ||
      typeof run.roles[role].backend !== "string" ||
      run.roles[role].backend.length === 0 ||
      (run.roles[role].model !== undefined &&
        run.roles[role].model !== null &&
        (typeof run.roles[role].model !== "string" ||
          run.roles[role].model.length === 0)) ||
      ["profile", "contextSize"].some(
        (field) =>
          run.roles[role][field] !== undefined &&
          (typeof run.roles[role][field] !== "string" ||
            run.roles[role][field].length === 0),
      )
    ) {
      throw workflowError(`Plan-authoring role ${role} is invalid.`);
    }
  }
  if (
    run.sessionLineage.source !== null &&
    (typeof run.sessionLineage.source !== "string" ||
      run.sessionLineage.source.length === 0)
  ) {
    throw workflowError("Plan-authoring source session is invalid.");
  }
  if (
    run.sessionLineage.sourceProfile !== undefined &&
    run.sessionLineage.sourceProfile !== null &&
    (run.sessionLineage.source === null ||
      typeof run.sessionLineage.sourceProfile !== "string" ||
      run.sessionLineage.sourceProfile.length === 0)
  ) {
    throw workflowError("Plan-authoring source profile is invalid.");
  }
  for (const child of run.sessionLineage.children) {
    if (
      !isRecord(child) ||
      !activeRoles.includes(child.role) ||
      typeof child.sessionId !== "string" ||
      child.sessionId.length === 0 ||
      child.sessionId === run.sessionLineage.source ||
      (Object.hasOwn(child, "contextKey") &&
        (typeof child.contextKey !== "string" ||
          !/^[a-f0-9]{64}$/u.test(child.contextKey)))
    ) {
      throw workflowError("Plan-authoring child session is invalid.");
    }
  }
  const childSessionIds = run.sessionLineage.children.map(
    (child) => child.sessionId,
  );
  if (new Set(childSessionIds).size !== childSessionIds.length) {
    throw workflowError("Plan-authoring child sessions must be unique.");
  }
  if (pipelineState.repositoryBaseline !== null) {
    const baselineProjectPath = pipelineState.repositoryBaseline.projectPath;
    if (
      pipelineState.repositoryBaseline.schemaVersion !== 1 ||
      typeof baselineProjectPath !== "string" ||
      !isAbsolute(baselineProjectPath) ||
      resolve(baselineProjectPath) !== baselineProjectPath ||
      (baselineProjectPath !== run.projectPath &&
        repositoryRelativePath(baselineProjectPath, run.projectPath) === null)
    ) {
      throw workflowError("Plan-authoring repository baseline is invalid.");
    }
    const expectedAllowedPaths = [
      join(run.taskPath, "clarifications.md"),
      join(run.taskPath, "plan.md"),
    ]
      .map((path) => repositoryRelativePath(baselineProjectPath, path))
      .filter((path) => path !== null)
      .sort();
    if (
      !Array.isArray(pipelineState.repositoryBaseline.allowedPaths) ||
      pipelineState.repositoryBaseline.allowedPaths.length !==
        expectedAllowedPaths.length ||
      pipelineState.repositoryBaseline.allowedPaths.some(
        (path, index) => path !== expectedAllowedPaths[index],
      )
    ) {
      throw workflowError("Plan-authoring repository baseline is invalid.");
    }
  }
  if (
    pipelineState.pendingEdit !== null &&
    (pipelineState.pendingEdit.artifactRoot !== run.taskPath ||
      pipelineState.pendingEdit.transcriptPath !==
        join(run.taskPath, "clarifications.md"))
  ) {
    throw workflowError("Plan-authoring pending edit path is invalid.");
  }
  if (
    pipelineState.pendingEdit !== null &&
    pipelineState.pendingEdit.preEditorHash !== run.hashes.clarifications
  ) {
    throw workflowError("Plan-authoring pending edit hash is invalid.");
  }
  const pauseExpected = ["WAITING_FOR_USER", "FAILED"].includes(
    pipelineState.workflowState,
  );
  if (
    pauseExpected !== (run.pause !== null) ||
    (run.pause !== null &&
      (!isRecord(run.pause) ||
        typeof run.pause.reason !== "string" ||
        run.pause.reason.length === 0))
  ) {
    throw workflowError("Plan-authoring pause state is invalid.");
  }
  if (pipelineState.workflowState === "FAILED") {
    const hasAdapterDiagnostic = Object.hasOwn(
      run.pause,
      "diagnosticClass",
    );
    const fields = hasAdapterDiagnostic
      ? ADAPTER_FAILURE_FIELDS
      : FAILURE_FIELDS;
    if (
      run.pause.reason !== "internal_failure" ||
      !hasExactFields(run.pause, fields) ||
      typeof run.pause.code !== "string" ||
      !/^[A-Z0-9_]{1,64}$/u.test(run.pause.code) ||
      (hasAdapterDiagnostic &&
        (typeof run.pause.diagnosticClass !== "string" ||
          !ADAPTER_DIAGNOSTIC_CLASS_PATTERN.test(
            run.pause.diagnosticClass,
          )))
    ) {
      throw workflowError("Plan-authoring adapter diagnostic is invalid.");
    }
  }
  assertInputPause(run, pipelineState);
  if (pipelineState.workflowState === "WAITING_FOR_USER") {
    const expectedReason = {
      "clarification-answers": "clarification_answers_required",
      "product-decision": "product_decision_required",
      "proactive-clarification": "proactive_clarification",
    }[pipelineState.pendingEdit?.action];
    const hasAuthorizationId = Object.hasOwn(run.pause, "authorizationId");
    if (
      (pipelineState.pendingEdit === null && hasAuthorizationId) ||
      (pipelineState.pendingEdit !== null &&
        (run.pause.authorizationId !== pipelineState.pendingEdit.id ||
          run.pause.reason !== expectedReason))
    ) {
      throw workflowError("Plan-authoring pending edit pause is invalid.");
    }
    const hasResumeState = Object.hasOwn(run.pause, "resumeState");
    if (
      (run.pause.reason === "backend_unavailable") !== hasResumeState ||
      (hasResumeState &&
        (!pipelineState.preflightComplete ||
          !BACKEND_RESUME_STATES.includes(run.pause.resumeState)))
    ) {
      throw workflowError("Plan-authoring pause resume state is invalid.");
    }
  }
  const hashFields = ["task", "context", "clarifications"];
  const hashKeys = Object.keys(run.hashes);
  if (
    (!pipelineState.preflightComplete && hashKeys.length !== 0) ||
    (pipelineState.preflightComplete &&
      (hashKeys.length !== hashFields.length ||
        hashFields.some((field) => !Object.hasOwn(run.hashes, field)) ||
        !HASH_PATTERN.test(run.hashes.task) ||
        (run.hashes.context !== null &&
          !HASH_PATTERN.test(run.hashes.context)) ||
        !HASH_PATTERN.test(run.hashes.clarifications)))
  ) {
    throw workflowError("Plan-authoring input hashes are invalid.");
  }
  assertCounterRecord(run.counters);
  const counters = normalizedCounters(run.counters);
  if (
    counters.clarificationRounds > MAX_CLARIFICATION_ROUNDS ||
    counters.correctionRounds > counters.revisionRounds ||
    counters.correctionRounds > pipelineState.lastCountedRevision ||
    pipelineState.lastCountedRevision > counters.revisionRounds ||
    pipelineState.blockedSinceArbitration > counters.correctionRounds ||
    (pipelineState.correctionHistory.length > 0 &&
      pipelineState.correctionHistory.at(-1).round !==
        counters.correctionRounds) ||
    (pipelineState.settings !== null &&
      (counters.revisionRounds > pipelineState.settings.maxRevisionRounds ||
        pipelineState.blockedSinceArbitration >
          pipelineState.settings.stagnationWindowRounds ||
        (pipelineState.arbitrationUsed &&
          counters.correctionRounds <
            pipelineState.settings.stagnationWindowRounds))) ||
    (pipelineState.planPath !== null &&
      pipelineState.planPath !== join(run.taskPath, "plan.md"))
  ) {
    throw workflowError("Plan-authoring persisted progress is invalid.");
  }
}

export function assertSettings(settings) {
  const fields = ["maxRevisionRounds", "stagnationWindowRounds"];
  if (
    !isRecord(settings) ||
    Object.keys(settings).length !== fields.length ||
    fields.some((field) => !Object.hasOwn(settings, field))
  ) {
    throw workflowError("Plan-authoring settings are invalid.");
  }
  for (const field of fields) {
    if (!Number.isSafeInteger(settings[field]) || settings[field] < 1) {
      throw workflowError(`Plan-authoring setting ${field} is invalid.`);
    }
  }
}

export function assertRuntime(runtime, activeRoles = ROLES) {
  if (
    !isRecord(runtime) ||
    !isRecord(runtime.adapters) ||
    !isRecord(runtime.clarifications) ||
    !isRecord(runtime.git)
  ) {
    throw workflowError("Plan-authoring runtime is invalid.");
  }
  for (const role of activeRoles) {
    if (typeof runtime.adapters[role]?.run !== "function") {
      throw workflowError(`Plan-authoring ${role} adapter is invalid.`);
    }
  }
  for (const name of [
    "finishAgentTurn",
    "readInputs",
    "recordChildSession",
    "startAgentTurn",
    "transition",
    "writePlan",
  ]) {
    if (typeof runtime[name] !== "function") {
      throw workflowError(`Plan-authoring runtime.${name} is invalid.`);
    }
  }
  for (const name of ["assertUnchanged", "preflight", "snapshot"]) {
    if (typeof runtime.git[name] !== "function") {
      throw workflowError(`Plan-authoring Git service.${name} is invalid.`);
    }
  }
  for (const name of [
    "acceptEdit",
    "appendProductDecision",
    "appendQuestionRound",
    "ensureTranscript",
    "freezeTranscript",
    "inspectTranscript",
    "openEditor",
    "prepareEdit",
  ]) {
    if (typeof runtime.clarifications[name] !== "function") {
      throw workflowError(
        `Plan-authoring clarification service.${name} is invalid.`,
      );
    }
  }
}

function assertInputFile(value, expectedPath, name, { optional = false } = {}) {
  if (value === null && optional) {
    return null;
  }
  if (
    !isRecord(value) ||
    value.path !== expectedPath ||
    typeof value.content !== "string" ||
    (!optional && value.content.trim().length === 0) ||
    typeof value.hash !== "string" ||
    !HASH_PATTERN.test(value.hash) ||
    value.hash !== sha256(value.content)
  ) {
    throw workflowError(`${name} input snapshot is invalid.`);
  }
  return value;
}

export function normalizeInputSnapshot(value, taskPath) {
  if (!isRecord(value)) {
    throw workflowError("Plan-authoring input snapshot is invalid.");
  }
  return Object.freeze({
    task: assertInputFile(value.task, join(taskPath, "task.md"), "task.md"),
    context: assertInputFile(
      value.context,
      join(taskPath, "context.md"),
      "context.md",
      { optional: true },
    ),
  });
}
