import { createHash } from "node:crypto";
import { isAbsolute, join, relative, resolve, sep } from "node:path";

import {
  parseCommitPlan,
  serializeCommitPlan,
} from "@agent-runner/commit-plan";

export const MAX_CLARIFICATION_ROUNDS = 3;

export const WORKFLOW_STATES = Object.freeze([
  "CLARIFY",
  "BOOTSTRAP",
  "IMPLEMENT",
  "FINALIZE",
  "REVIEW",
  "RESOLVE_FINDINGS",
  "COMMIT",
  "WAITING_FOR_USER",
  "DONE",
  "FAILED",
]);

const PIPELINE_STATE_FIELDS = new Set([
  "workflowState",
  "preflightComplete",
  "settings",
  "repositoryBaseline",
  "backendVersions",
  "proactiveClarification",
  "proactiveClarificationComplete",
  "clarificationPath",
  "clarificationFrozen",
  "pendingEdit",
  "canonicalPlan",
  "workerSummary",
  "reviewerSummary",
  "resolvedSummary",
  "bootstrapDisagreement",
  "bootstrapArbitrationUsed",
  "compatibilityCheckRequired",
  "currentStep",
]);
const COUNTER_FIELDS = Object.freeze([
  "clarificationRounds",
  "productDecisions",
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
const HASH_PATTERN = /^[a-f0-9]{64}$/u;
const RUN_ID_PATTERN = /^[a-zA-Z0-9][a-zA-Z0-9_-]{0,127}$/u;
const MAX_TEXT_LENGTH = 4_000;
const MAX_SUMMARY_LENGTH = 20_000;
export const MAX_PLAN_LENGTH = 100_000;
const MAX_ITEMS = 32;
const MAX_OPTIONS = 16;
const MAX_STRUCTURED_RESULT_BYTES = 256 * 1024;
const INVALID_OUTPUT_CODE = "ERR_INVALID_PLAN_EXECUTION_OUTPUT";
export const INVALID_EXECUTION_INPUT_CODE = "ERR_INVALID_EXECUTION_INPUT";
const SETTINGS_FIELDS = Object.freeze([
  "maxFixRoundsPerStep",
  "maxDisputesPerFinding",
  "maxSameFindingRounds",
  "stagnationWindowRounds",
]);
const EDIT_PAUSE_REASONS = Object.freeze({
  "clarification-answers": "clarification_answers_required",
  "product-decision": "product_decision_required",
  "proactive-clarification": "proactive_clarification",
});

export class PlanExecutionWorkflowError extends Error {
  constructor(message, { cause, code = "ERR_PLAN_EXECUTION_WORKFLOW" } = {}) {
    super(message, { cause });
    this.name = "PlanExecutionWorkflowError";
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

export function workflowError(
  message,
  code = "ERR_INVALID_PLAN_EXECUTION_STATE",
) {
  return new PlanExecutionWorkflowError(message, { code });
}

export function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function outputError(message) {
  return workflowError(message, INVALID_OUTPUT_CODE);
}

function assertStructuredResultSize(payload) {
  let serialized;
  try {
    serialized = JSON.stringify(payload);
  } catch (cause) {
    throw new PlanExecutionWorkflowError(
      "Structured role result must be serializable.",
      { cause, code: INVALID_OUTPUT_CODE },
    );
  }
  if (
    typeof serialized !== "string" ||
    Buffer.byteLength(serialized) > MAX_STRUCTURED_RESULT_BYTES
  ) {
    throw outputError("Structured role result is too large.");
  }
}

function normalizeText(
  value,
  name,
  maximumLength = MAX_TEXT_LENGTH,
  code = "ERR_INVALID_PLAN_EXECUTION_STATE",
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

function normalizeSummary(
  value,
  name,
  code = "ERR_INVALID_PLAN_EXECUTION_STATE",
) {
  if (
    typeof value !== "string" ||
    value.trim().length === 0 ||
    value.length > MAX_SUMMARY_LENGTH ||
    /\0|\p{Zl}|\p{Zp}/u.test(value)
  ) {
    throw workflowError(`${name} must be concise Markdown.`, code);
  }
  return value.trim();
}

function normalizeTextList(
  value,
  name,
  {
    allowEmpty = false,
    code = "ERR_INVALID_PLAN_EXECUTION_STATE",
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

function emptyArray(value) {
  return Array.isArray(value) && value.length === 0;
}

function emptyDecision(payload, { ignoreEvidence = false } = {}) {
  return (
    payload.question === "" &&
    payload.whyBlocked === "" &&
    emptyArray(payload.options) &&
    (ignoreEvidence || emptyArray(payload.evidence))
  );
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
      maximum: MAX_OPTIONS,
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

function normalizePlanRevision(payload) {
  if (!emptyDecision(payload, { ignoreEvidence: true })) {
    throw outputError("Plan-revision result contains inapplicable fields.");
  }
  return Object.freeze({
    status: "PLAN_REVISION_REQUIRED",
    reason: normalizeText(
      payload.reason,
      "plan-revision reason",
      MAX_TEXT_LENGTH,
      INVALID_OUTPUT_CODE,
    ),
    evidence: normalizeTextList(payload.evidence, "plan-revision evidence", {
      code: INVALID_OUTPUT_CODE,
    }),
  });
}

export function normalizeClarificationResult(payload) {
  const statuses = [
    "READY",
    "QUESTIONS",
    "PLAN_REVISION_REQUIRED",
    "PRODUCT_DECISION_REQUIRED",
  ];
  if (!isRecord(payload) || !statuses.includes(payload.status)) {
    throw outputError("Worker returned an invalid clarification result.");
  }
  assertStructuredResultSize(payload);
  if (payload.status === "PRODUCT_DECISION_REQUIRED") {
    if (!emptyArray(payload.questions) || payload.reason !== "") {
      throw outputError("Product decision contains inapplicable fields.");
    }
    return Object.freeze({
      status: payload.status,
      decision: normalizeProductDecision(payload),
    });
  }
  if (payload.status === "PLAN_REVISION_REQUIRED") {
    if (!emptyArray(payload.questions)) {
      throw outputError("Plan revision must not contain questions.");
    }
    return normalizePlanRevision(payload);
  }
  if (payload.reason !== "" || !emptyDecision(payload)) {
    throw outputError("Clarification result contains inapplicable fields.");
  }
  if (!Array.isArray(payload.questions) || payload.questions.length > MAX_ITEMS) {
    throw outputError("Worker returned invalid clarification questions.");
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

export function normalizeCompatibilityResult(payload) {
  if (
    !isRecord(payload) ||
    !["READY", "PLAN_REVISION_REQUIRED"].includes(payload.status)
  ) {
    throw outputError("Worker returned an invalid compatibility result.");
  }
  assertStructuredResultSize(payload);
  if (payload.status === "PLAN_REVISION_REQUIRED") {
    return Object.freeze({
      status: payload.status,
      reason: normalizeText(
        payload.reason,
        "plan-revision reason",
        MAX_TEXT_LENGTH,
        INVALID_OUTPUT_CODE,
      ),
      evidence: normalizeTextList(
        payload.evidence,
        "plan-revision evidence",
        { code: INVALID_OUTPUT_CODE },
      ),
    });
  }
  if (payload.reason !== "" || !emptyArray(payload.evidence)) {
    throw outputError("Compatible result contains inapplicable fields.");
  }
  return Object.freeze({ status: payload.status });
}

export function normalizeBootstrapResult(payload, role) {
  const statuses = [
    "READY",
    "PLAN_REVISION_REQUIRED",
    "PRODUCT_DECISION_REQUIRED",
  ];
  if (!isRecord(payload) || !statuses.includes(payload.status)) {
    throw outputError(`${role} returned an invalid bootstrap result.`);
  }
  assertStructuredResultSize(payload);
  if (payload.status === "PRODUCT_DECISION_REQUIRED") {
    if (payload.summary !== "" || payload.reason !== "") {
      throw outputError("Product decision contains inapplicable fields.");
    }
    return Object.freeze({
      status: payload.status,
      decision: normalizeProductDecision(payload),
    });
  }
  if (payload.status === "PLAN_REVISION_REQUIRED") {
    if (payload.summary !== "") {
      throw outputError("Plan revision must not contain a summary.");
    }
    return normalizePlanRevision(payload);
  }
  if (payload.reason !== "" || !emptyDecision(payload)) {
    throw outputError("Bootstrap result contains inapplicable fields.");
  }
  return Object.freeze({
    status: payload.status,
    summary: normalizeSummary(
      payload.summary,
      `${role} bootstrap summary`,
      INVALID_OUTPUT_CODE,
    ),
  });
}

export function normalizeReconciliationResult(payload) {
  const statuses = [
    "RESOLVED",
    "DISAGREEMENT",
    "PLAN_REVISION_REQUIRED",
    "PRODUCT_DECISION_REQUIRED",
  ];
  if (!isRecord(payload) || !statuses.includes(payload.status)) {
    throw outputError("Worker returned an invalid reconciliation result.");
  }
  assertStructuredResultSize(payload);
  if (payload.status === "PRODUCT_DECISION_REQUIRED") {
    if (
      payload.summary !== "" ||
      payload.disagreement !== "" ||
      payload.reason !== ""
    ) {
      throw outputError("Product decision contains inapplicable fields.");
    }
    return Object.freeze({
      status: payload.status,
      decision: normalizeProductDecision(payload),
    });
  }
  if (payload.status === "PLAN_REVISION_REQUIRED") {
    if (payload.summary !== "" || payload.disagreement !== "") {
      throw outputError("Plan revision contains inapplicable fields.");
    }
    return normalizePlanRevision(payload);
  }
  if (payload.status === "RESOLVED") {
    if (
      payload.disagreement !== "" ||
      payload.reason !== "" ||
      !emptyDecision(payload)
    ) {
      throw outputError("Resolved reconciliation must not contain a disagreement.");
    }
    return Object.freeze({
      status: payload.status,
      summary: normalizeSummary(
        payload.summary,
        "resolved bootstrap summary",
        INVALID_OUTPUT_CODE,
      ),
    });
  }
  if (
    payload.summary !== "" ||
    payload.reason !== "" ||
    payload.question !== "" ||
    payload.whyBlocked !== "" ||
    !emptyArray(payload.options)
  ) {
    throw outputError("Bootstrap disagreement must not contain a summary.");
  }
  return Object.freeze({
    status: payload.status,
    disagreement: Object.freeze({
      description: normalizeText(
        payload.disagreement,
        "bootstrap disagreement",
        MAX_TEXT_LENGTH,
        INVALID_OUTPUT_CODE,
      ),
      evidence: normalizeTextList(
        payload.evidence,
        "bootstrap disagreement evidence",
        { code: INVALID_OUTPUT_CODE },
      ),
    }),
  });
}

export function normalizeBootstrapArbitration(payload) {
  const directions = [
    "USE_WORKER",
    "USE_REVIEWER",
    "SYNTHESIZE",
    "PLAN_REVISION_REQUIRED",
    "PRODUCT_DECISION_REQUIRED",
  ];
  if (!isRecord(payload) || !directions.includes(payload.direction)) {
    throw outputError("Arbiter returned an invalid bootstrap direction.");
  }
  assertStructuredResultSize(payload);
  const rationale = normalizeText(
    payload.rationale,
    "bootstrap arbitration rationale",
    MAX_TEXT_LENGTH,
    INVALID_OUTPUT_CODE,
  );
  if (payload.direction === "PRODUCT_DECISION_REQUIRED") {
    if (payload.summary !== "" || payload.reason !== "") {
      throw outputError("Product decision contains inapplicable fields.");
    }
    return Object.freeze({
      direction: payload.direction,
      rationale,
      decision: normalizeProductDecision(payload),
    });
  }
  if (payload.direction === "PLAN_REVISION_REQUIRED") {
    if (payload.summary !== "") {
      throw outputError("Plan revision must not contain a summary.");
    }
    const revision = normalizePlanRevision(payload);
    return Object.freeze({
      direction: payload.direction,
      rationale,
      reason: revision.reason,
      evidence: revision.evidence,
    });
  }
  if (payload.reason !== "" || !emptyDecision(payload)) {
    throw outputError("Bootstrap arbitration contains inapplicable fields.");
  }
  return Object.freeze({
    direction: payload.direction,
    rationale,
    summary: normalizeSummary(
      payload.summary,
      "arbitrated bootstrap summary",
      INVALID_OUTPUT_CODE,
    ),
  });
}

function normalizePendingEdit(value) {
  if (value === null) {
    return null;
  }
  if (
    !isRecord(value) ||
    Object.keys(value).length !== PENDING_EDIT_FIELDS.size ||
    Object.keys(value).some((field) => !PENDING_EDIT_FIELDS.has(field)) ||
    value.schemaVersion !== 1 ||
    typeof value.id !== "string" ||
    value.id.trim().length === 0 ||
    value.id !== value.id.trim() ||
    value.id.length > 256 ||
    /[\0\p{Cc}\p{Zl}\p{Zp}]/u.test(value.id) ||
    typeof value.artifactRoot !== "string" ||
    !isAbsolute(value.artifactRoot) ||
    typeof value.transcriptPath !== "string" ||
    !isAbsolute(value.transcriptPath) ||
    !HASH_PATTERN.test(value.preEditorHash)
  ) {
    throw workflowError("Plan-execution pending edit is invalid.");
  }
  const expectedStates = {
    "clarification-answers": ["CLARIFY"],
    "product-decision": ["CLARIFY", "BOOTSTRAP"],
    "proactive-clarification": ["CLARIFY"],
  }[value.action];
  if (!expectedStates?.includes(value.suspendedState)) {
    throw workflowError("Plan-execution pending edit is invalid.");
  }
  return value;
}

function normalizeDisagreement(value) {
  if (value === null) {
    return null;
  }
  if (
    !isRecord(value) ||
    Object.keys(value).length !== 2 ||
    !Object.hasOwn(value, "description") ||
    !Object.hasOwn(value, "evidence")
  ) {
    throw workflowError("Plan-execution bootstrap disagreement is invalid.");
  }
  return Object.freeze({
    description: normalizeText(value.description, "bootstrap disagreement"),
    evidence: normalizeTextList(value.evidence, "bootstrap disagreement evidence"),
  });
}

function normalizedSummary(value, name) {
  return value === null ? null : normalizeSummary(value, name);
}

export function normalizePipelineState(value) {
  if (!isRecord(value)) {
    throw workflowError("Plan-execution state must be an object.");
  }
  if (
    Object.keys(value).length !== PIPELINE_STATE_FIELDS.size ||
    Object.keys(value).some((field) => !PIPELINE_STATE_FIELDS.has(field)) ||
    !WORKFLOW_STATES.includes(value.workflowState)
  ) {
    throw workflowError("Plan-execution state is invalid.");
  }
  for (const field of [
    "preflightComplete",
    "proactiveClarification",
    "proactiveClarificationComplete",
    "clarificationFrozen",
    "bootstrapArbitrationUsed",
    "compatibilityCheckRequired",
  ]) {
    if (typeof value[field] !== "boolean") {
      throw workflowError(`Plan-execution state field ${field} is invalid.`);
    }
  }
  if (value.settings !== null) {
    assertSettings(value.settings);
  }
  if (
    value.preflightComplete !== (value.repositoryBaseline !== null) ||
    value.preflightComplete !== (value.backendVersions !== null) ||
    value.preflightComplete !== (value.clarificationPath !== null) ||
    value.preflightComplete !== (value.canonicalPlan !== null) ||
    (value.preflightComplete && value.settings === null)
  ) {
    throw workflowError("Plan-execution preflight state is invalid.");
  }
  if (value.repositoryBaseline !== null && !isRecord(value.repositoryBaseline)) {
    throw workflowError("Plan-execution repository baseline is invalid.");
  }
  if (value.backendVersions !== null) {
    if (
      !isRecord(value.backendVersions) ||
      Object.keys(value.backendVersions).length !== 3 ||
      !["worker", "reviewer", "arbiter"].every((role) =>
        Object.hasOwn(value.backendVersions, role),
      )
    ) {
      throw workflowError("Plan-execution backend versions are invalid.");
    }
    for (const [role, version] of Object.entries(value.backendVersions)) {
      if (
        (role !== "arbiter" && typeof version !== "string") ||
        (version !== null &&
          (typeof version !== "string" || version.trim().length === 0))
      ) {
        throw workflowError(`Plan-execution ${role} version is invalid.`);
      }
    }
  }
  if (
    value.clarificationPath !== null &&
    (typeof value.clarificationPath !== "string" ||
      !isAbsolute(value.clarificationPath))
  ) {
    throw workflowError("Plan-execution clarification path is invalid.");
  }
  const pendingEdit = normalizePendingEdit(value.pendingEdit);
  if (
    pendingEdit !== null &&
    !["WAITING_FOR_USER", "FAILED"].includes(value.workflowState)
  ) {
    throw workflowError("Plan-execution pending edit is not applicable.");
  }
  if (
    (!value.proactiveClarification && !value.proactiveClarificationComplete) ||
    (!value.proactiveClarificationComplete &&
      !["CLARIFY", "WAITING_FOR_USER", "FAILED"].includes(
        value.workflowState,
      )) ||
    (pendingEdit !== null &&
      (pendingEdit.action === "proactive-clarification") !==
        (value.proactiveClarification &&
          !value.proactiveClarificationComplete))
  ) {
    throw workflowError("Plan-execution proactive clarification state is invalid.");
  }
  if (
    value.canonicalPlan !== null &&
    (typeof value.canonicalPlan !== "string" ||
      value.canonicalPlan.length === 0 ||
      value.canonicalPlan.length > MAX_PLAN_LENGTH)
  ) {
    throw workflowError("Plan-execution canonical plan is invalid.");
  }
  if (value.canonicalPlan !== null) {
    let canonical;
    try {
      canonical = serializeCommitPlan(parseCommitPlan(value.canonicalPlan));
    } catch {
      throw workflowError("Plan-execution canonical plan is invalid.");
    }
    if (canonical !== value.canonicalPlan) {
      throw workflowError("Plan-execution canonical plan is not normalized.");
    }
  }
  const workerSummary = normalizedSummary(value.workerSummary, "Worker summary");
  const reviewerSummary = normalizedSummary(
    value.reviewerSummary,
    "Reviewer summary",
  );
  const resolvedSummary = normalizedSummary(
    value.resolvedSummary,
    "resolved summary",
  );
  const disagreement = normalizeDisagreement(value.bootstrapDisagreement);
  if (
    (reviewerSummary !== null && workerSummary === null) ||
    ((resolvedSummary !== null || disagreement !== null) &&
      (workerSummary === null || reviewerSummary === null)) ||
    (resolvedSummary !== null && disagreement !== null)
  ) {
    throw workflowError("Plan-execution bootstrap context is inconsistent.");
  }
  if (
    value.bootstrapArbitrationUsed &&
    (disagreement !== null ||
      resolvedSummary === null ||
      typeof value.backendVersions?.arbiter !== "string")
  ) {
    throw workflowError("Plan-execution bootstrap arbitration is inconsistent.");
  }
  if (
    value.compatibilityCheckRequired &&
    (!["BOOTSTRAP", "WAITING_FOR_USER", "FAILED"].includes(
      value.workflowState,
    ) ||
      value.clarificationFrozen ||
      workerSummary !== null ||
      reviewerSummary !== null ||
      resolvedSummary !== null ||
      disagreement !== null ||
      value.currentStep !== null)
  ) {
    throw workflowError("Plan-execution compatibility state is invalid.");
  }
  if (
    value.currentStep !== null &&
    (!Number.isSafeInteger(value.currentStep) || value.currentStep < 1)
  ) {
    throw workflowError("Plan-execution current step is invalid.");
  }
  if (
    !value.preflightComplete &&
    (value.clarificationFrozen ||
      pendingEdit !== null ||
      workerSummary !== null ||
      reviewerSummary !== null ||
      resolvedSummary !== null ||
      disagreement !== null ||
      value.bootstrapArbitrationUsed ||
      value.compatibilityCheckRequired ||
      value.currentStep !== null)
  ) {
    throw workflowError("Plan-execution preflight state is inconsistent.");
  }
  if (
    ["CLARIFY", "BOOTSTRAP"].includes(value.workflowState) &&
    value.currentStep !== null
  ) {
    throw workflowError("Plan-execution current step is not applicable.");
  }
  if (
    value.workflowState === "CLARIFY" &&
    (value.clarificationFrozen ||
      workerSummary !== null ||
      reviewerSummary !== null ||
      resolvedSummary !== null ||
      disagreement !== null)
  ) {
    throw workflowError("Plan-execution clarification state is inconsistent.");
  }
  if (
    value.workflowState === "BOOTSTRAP" &&
    !value.clarificationFrozen &&
    !value.compatibilityCheckRequired
  ) {
    throw workflowError("Plan-execution bootstrap clarification is not frozen.");
  }
  if (
    value.workflowState === "IMPLEMENT" &&
    (!value.clarificationFrozen || resolvedSummary === null || value.currentStep !== 1)
  ) {
    throw workflowError("Plan-execution implementation state is inconsistent.");
  }
  if (
    !["CLARIFY", "WAITING_FOR_USER", "FAILED"].includes(value.workflowState) &&
    !value.preflightComplete
  ) {
    throw workflowError("Plan-execution state has not completed preflight.");
  }
  return value;
}

export function createPlanExecutionState({ proactiveClarification = false } = {}) {
  if (typeof proactiveClarification !== "boolean") {
    throw workflowError("proactiveClarification must be a boolean.");
  }
  return Object.freeze({
    workflowState: "CLARIFY",
    preflightComplete: false,
    settings: null,
    repositoryBaseline: null,
    backendVersions: null,
    proactiveClarification,
    proactiveClarificationComplete: !proactiveClarification,
    clarificationPath: null,
    clarificationFrozen: false,
    pendingEdit: null,
    canonicalPlan: null,
    workerSummary: null,
    reviewerSummary: null,
    resolvedSummary: null,
    bootstrapDisagreement: null,
    bootstrapArbitrationUsed: false,
    compatibilityCheckRequired: false,
    currentStep: null,
  });
}

function assertCounterRecord(counters) {
  if (
    !isRecord(counters) ||
    Object.keys(counters).some((field) => !COUNTER_FIELDS.includes(field))
  ) {
    throw workflowError("Plan-execution counters are invalid.");
  }
  for (const field of COUNTER_FIELDS) {
    const value = Object.hasOwn(counters, field) ? counters[field] : 0;
    if (!Number.isSafeInteger(value) || value < 0) {
      throw workflowError(`Plan-execution counter ${field} is invalid.`);
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

function repositoryRelativePath(projectPath, path) {
  const pathFromProject = relative(projectPath, path);
  if (
    pathFromProject === "" ||
    pathFromProject === ".." ||
    pathFromProject.startsWith(`..${sep}`) ||
    isAbsolute(pathFromProject)
  ) {
    return null;
  }
  return pathFromProject.split(sep).join("/");
}

export function assertRun(run) {
  if (
    !isRecord(run) ||
    typeof run.runId !== "string" ||
    !RUN_ID_PATTERN.test(run.runId) ||
    run.pipelineId !== "plan-execution" ||
    run.pipelineStateVersion !== 1 ||
    typeof run.projectPath !== "string" ||
    !isAbsolute(run.projectPath) ||
    resolve(run.projectPath) !== run.projectPath ||
    typeof run.taskPath !== "string" ||
    !isAbsolute(run.taskPath) ||
    resolve(run.taskPath) !== run.taskPath ||
    !isRecord(run.roles) ||
    Object.keys(run.roles).length !== 3 ||
    !isRecord(run.hashes) ||
    !isRecord(run.sessionLineage) ||
    !Array.isArray(run.sessionLineage.children)
  ) {
    throw workflowError("Plan-execution run envelope is invalid.");
  }
  for (const role of ["worker", "reviewer", "arbiter"]) {
    if (
      !isRecord(run.roles[role]) ||
      typeof run.roles[role].backend !== "string" ||
      run.roles[role].backend.length === 0 ||
      (run.roles[role].model !== null &&
        (typeof run.roles[role].model !== "string" ||
          run.roles[role].model.length === 0))
    ) {
      throw workflowError(`Plan-execution role ${role} is invalid.`);
    }
  }
  if (
    run.sessionLineage.source !== null &&
    (typeof run.sessionLineage.source !== "string" ||
      run.sessionLineage.source.length === 0)
  ) {
    throw workflowError("Plan-execution source session is invalid.");
  }
  for (const child of run.sessionLineage.children) {
    if (
      !isRecord(child) ||
      !["worker", "reviewer", "arbiter"].includes(child.role) ||
      typeof child.sessionId !== "string" ||
      child.sessionId.length === 0 ||
      child.sessionId === run.sessionLineage.source
    ) {
      throw workflowError("Plan-execution child session is invalid.");
    }
  }
  const childSessionIds = run.sessionLineage.children.map(
    (child) => child.sessionId,
  );
  if (new Set(childSessionIds).size !== childSessionIds.length) {
    throw workflowError("Plan-execution child sessions must be unique.");
  }
  const state = normalizePipelineState(run.pipelineState);
  if (state.repositoryBaseline !== null) {
    const repositoryPath = state.repositoryBaseline.projectPath;
    if (
      state.repositoryBaseline.schemaVersion !== 1 ||
      typeof repositoryPath !== "string" ||
      !isAbsolute(repositoryPath) ||
      resolve(repositoryPath) !== repositoryPath ||
      (repositoryPath !== run.projectPath &&
        repositoryRelativePath(repositoryPath, run.projectPath) === null)
    ) {
      throw workflowError("Plan-execution repository baseline is invalid.");
    }
    const expectedClarificationPath = join(
      repositoryPath,
      "LOCAL_ARTIFACTS",
      "agent-runner",
      run.runId,
      "clarifications.md",
    );
    const expectedAllowedPath = repositoryRelativePath(
      repositoryPath,
      expectedClarificationPath,
    );
    if (
      state.clarificationPath !== expectedClarificationPath ||
      !Array.isArray(state.repositoryBaseline.allowedPaths) ||
      state.repositoryBaseline.allowedPaths.length !== 1 ||
      state.repositoryBaseline.allowedPaths[0] !== expectedAllowedPath
    ) {
      throw workflowError("Plan-execution repository baseline is invalid.");
    }
  }
  if (
    state.pendingEdit !== null &&
    (state.pendingEdit.artifactRoot !== state.repositoryBaseline?.projectPath ||
      state.pendingEdit.transcriptPath !== state.clarificationPath ||
      state.pendingEdit.preEditorHash !== run.hashes.executionClarifications)
  ) {
    throw workflowError("Plan-execution pending edit boundary is invalid.");
  }
  const pauseExpected = ["WAITING_FOR_USER", "FAILED"].includes(
    state.workflowState,
  );
  if (
    pauseExpected !== (run.pause !== null) ||
    (run.pause !== null &&
      (!isRecord(run.pause) ||
        typeof run.pause.reason !== "string" ||
        run.pause.reason.length === 0))
  ) {
    throw workflowError("Plan-execution pause state is invalid.");
  }
  if (state.workflowState === "WAITING_FOR_USER") {
    const expectedReason = EDIT_PAUSE_REASONS[state.pendingEdit?.action];
    const hasAuthorizationId = Object.hasOwn(run.pause, "authorizationId");
    if (
      (state.pendingEdit === null &&
        (hasAuthorizationId ||
          Object.values(EDIT_PAUSE_REASONS).includes(run.pause.reason))) ||
      (state.pendingEdit !== null &&
        (run.pause.authorizationId !== state.pendingEdit.id ||
          run.pause.reason !== expectedReason))
    ) {
      throw workflowError("Plan-execution pending edit pause is invalid.");
    }
  }
  const hashFields = [
    "task",
    "plan",
    "taskClarifications",
    "context",
    "executionClarifications",
  ];
  const hashKeys = Object.keys(run.hashes);
  if (
    (!state.preflightComplete && hashKeys.length !== 0) ||
    (state.preflightComplete &&
      (hashKeys.length !== hashFields.length ||
        hashFields.some((field) => !Object.hasOwn(run.hashes, field)) ||
        !HASH_PATTERN.test(run.hashes.task) ||
        !HASH_PATTERN.test(run.hashes.plan) ||
        (run.hashes.taskClarifications !== null &&
          !HASH_PATTERN.test(run.hashes.taskClarifications)) ||
        (run.hashes.context !== null && !HASH_PATTERN.test(run.hashes.context)) ||
        !HASH_PATTERN.test(run.hashes.executionClarifications)))
  ) {
    throw workflowError("Plan-execution input hashes are invalid.");
  }
  assertCounterRecord(run.counters);
  const counters = normalizedCounters(run.counters);
  if (counters.clarificationRounds > MAX_CLARIFICATION_ROUNDS) {
    throw workflowError("Plan-execution persisted progress is invalid.");
  }
  if (state.canonicalPlan !== null) {
    const stepCount = parseCommitPlan(state.canonicalPlan).steps.length;
    if (state.currentStep !== null && state.currentStep > stepCount) {
      throw workflowError("Plan-execution current step is outside the plan.");
    }
  }
}

export function assertSettings(settings) {
  if (
    !isRecord(settings) ||
    Object.keys(settings).length !== SETTINGS_FIELDS.length ||
    SETTINGS_FIELDS.some((field) => !Object.hasOwn(settings, field))
  ) {
    throw workflowError("Plan-execution settings are invalid.");
  }
  for (const field of SETTINGS_FIELDS) {
    if (!Number.isSafeInteger(settings[field]) || settings[field] < 1) {
      throw workflowError(`Plan-execution setting ${field} is invalid.`);
    }
  }
}

export function assertRuntime(runtime) {
  if (
    !isRecord(runtime) ||
    !isRecord(runtime.adapters) ||
    !isRecord(runtime.clarifications) ||
    !isRecord(runtime.git)
  ) {
    throw workflowError("Plan-execution runtime is invalid.");
  }
  for (const role of ["worker", "reviewer", "arbiter"]) {
    if (
      typeof runtime.adapters[role]?.probe !== "function" ||
      typeof runtime.adapters[role]?.run !== "function"
    ) {
      throw workflowError(`Plan-execution ${role} adapter is invalid.`);
    }
  }
  for (const name of [
    "readInputs",
    "recordChildSession",
    "transition",
    "writeRunArtifact",
  ]) {
    if (typeof runtime[name] !== "function") {
      throw workflowError(`Plan-execution runtime.${name} is invalid.`);
    }
  }
  for (const name of ["assertUnchanged", "preflight", "snapshot"]) {
    if (typeof runtime.git[name] !== "function") {
      throw workflowError(`Plan-execution Git service.${name} is invalid.`);
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
        `Plan-execution clarification service.${name} is invalid.`,
      );
    }
  }
}

export function normalizeAdapterCapabilities(value, role, sourceSession) {
  if (!isRecord(value) || typeof value.version !== "string" || value.version.length === 0) {
    throw workflowError(
      `${role} backend returned invalid capabilities.`,
      "ERR_UNSUPPORTED_PLAN_EXECUTION_BACKEND",
    );
  }
  const required =
    role === "worker"
      ? [
          "structuredOutput",
          "readOnly",
          "autonomousWrite",
          "workspaceWrite",
          "localCommit",
          "remoteWriteBlocked",
        ]
      : ["structuredOutput", "readOnly", "remoteWriteBlocked"];
  if (sourceSession !== null && role !== "arbiter") {
    required.push("nativeSessionFork");
  }
  if (required.some((field) => value[field] !== true)) {
    throw workflowError(
      `${role} backend cannot enforce the required capabilities.`,
      "ERR_UNSUPPORTED_PLAN_EXECUTION_BACKEND",
    );
  }
  return Object.freeze({ version: value.version });
}

function assertInputFile(value, expectedPath, name, { optional = false } = {}) {
  if (value === null && optional) {
    return null;
  }
  if (
    !isRecord(value) ||
    value.path !== expectedPath ||
    typeof value.content !== "string" ||
    typeof value.hash !== "string" ||
    !HASH_PATTERN.test(value.hash) ||
    value.hash !== sha256(value.content)
  ) {
    throw workflowError(`${name} input snapshot is invalid.`);
  }
  if (!optional && value.content.trim().length === 0) {
    throw workflowError(`${name} must not be empty.`, INVALID_EXECUTION_INPUT_CODE);
  }
  return value;
}

export function normalizeInputSnapshot(value, taskPath) {
  if (!isRecord(value)) {
    throw workflowError("Plan-execution input snapshot is invalid.");
  }
  return Object.freeze({
    task: assertInputFile(value.task, join(taskPath, "task.md"), "task.md"),
    plan: assertInputFile(value.plan, join(taskPath, "plan.md"), "plan.md"),
    taskClarifications: assertInputFile(
      value.taskClarifications,
      join(taskPath, "clarifications.md"),
      "clarifications.md",
      { optional: true },
    ),
    context: assertInputFile(
      value.context,
      join(taskPath, "context.md"),
      "context.md",
      { optional: true },
    ),
  });
}
