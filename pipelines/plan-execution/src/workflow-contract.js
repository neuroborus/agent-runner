import { createHash } from "node:crypto";
import { isAbsolute, join, posix, relative, resolve, sep } from "node:path";

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
  "artifactRoot",
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
  "reviewerStep",
  "implementationDirection",
  "finalizationResult",
  "finalizedFingerprint",
  "reviewedFingerprint",
  "findings",
  "previousFindings",
  "pendingDisputes",
  "disputeCounts",
  "disputeHistory",
  "findingArbitrations",
  "correctionHistory",
  "sameFindingRounds",
  "pendingCorrection",
  "blockedSinceStagnation",
  "stagnationArbitrationUsed",
  "stagnationDirection",
  "reviewReconsideration",
  "additionalFixRounds",
  "findingOverrides",
  "pendingCommit",
  "completedCommits",
]);
const COUNTER_FIELDS = Object.freeze([
  "clarificationRounds",
  "productDecisions",
  "fixRounds",
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
const HASH_PATTERN = /^[a-f0-9]{64}$/u;
const OBJECT_ID_PATTERN = /^(?:[a-f0-9]{40}|[a-f0-9]{64})$/u;
const RUN_ID_PATTERN = /^[a-zA-Z0-9][a-zA-Z0-9_-]{0,127}$/u;
const REVIEW_FINDING_ID_PATTERN = /^R[1-9][0-9]{0,8}$/u;
const FINALIZATION_ISSUE_ID_PATTERN = /^F[1-9][0-9]{0,8}$/u;
const MAX_TEXT_LENGTH = 4_000;
const MAX_SUMMARY_LENGTH = 20_000;
export const MAX_PLAN_LENGTH = 100_000;
const MAX_ITEMS = 32;
const MAX_OPTIONS = 16;
export const MAX_DIAGNOSTIC_ITEMS = 32;
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
const PAUSE_RESUME_STATES = Object.freeze({
  backend_unavailable: Object.freeze([
    "CLARIFY",
    "BOOTSTRAP",
    "IMPLEMENT",
    "FINALIZE",
    "REVIEW",
    "RESOLVE_FINDINGS",
    "COMMIT",
  ]),
  environment_blocked: Object.freeze(["IMPLEMENT"]),
  finalization_cannot_pass: Object.freeze(["FINALIZE"]),
  fix_limit_reached: Object.freeze(["IMPLEMENT", "RESOLVE_FINDINGS"]),
  no_progress: Object.freeze(["RESOLVE_FINDINGS"]),
});
const COMMIT_AUTHORIZATION_FIELDS = Object.freeze([
  "schemaVersion",
  "id",
  "projectPath",
  "expectedHead",
  "expectedBranch",
  "expectedRefsFingerprint",
  "expectedOtherRefsFingerprint",
  "expectedContentFingerprint",
  "expectedIndexFingerprint",
  "expectedRemoteConfigurationFingerprint",
  "expectedIdentityFingerprint",
  "expectedAuthorIdentityFingerprint",
  "expectedCommitterIdentityFingerprint",
  "subject",
]);

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

function assertInputPause(run, state) {
  const request = run.pause?.inputRequest;
  if (
    state.workflowState !== "WAITING_FOR_USER" ||
    state.pendingEdit === null
  ) {
    if (request !== undefined || run.pause?.inputResponse !== undefined) {
      throw workflowError("Plan-execution input pause is invalid.");
    }
    return;
  }
  if (request === undefined) {
    return;
  }
  if (!isRecord(request) || !Array.isArray(request.questions)) {
    throw workflowError("Plan-execution input request is invalid.");
  }

  const action = state.pendingEdit.action;
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
    request.id !== state.pendingEdit.id ||
    request.kind !== (productDecision ? "product-decision" : "clarification") ||
    request.artifactPath !== state.pendingEdit.transcriptPath ||
    invalidQuestions
  ) {
    throw workflowError("Plan-execution input request is invalid.");
  }
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

function normalizeOptionalEvidence(value, name, code = INVALID_OUTPUT_CODE) {
  return normalizeTextList(value, name, {
    allowEmpty: true,
    code,
  });
}

function normalizeRelativePath(value, name, code = INVALID_OUTPUT_CODE) {
  const path = normalizeText(value, name, MAX_TEXT_LENGTH, code);
  if (
    isAbsolute(path) ||
    path === "." ||
    path.split(/[\\/]/u).some((part) => part === "..")
  ) {
    throw workflowError(`${name} must be repository-relative.`, code);
  }
  return path;
}

function normalizeReviewFinding(value, code = INVALID_OUTPUT_CODE) {
  if (!isRecord(value) || !REVIEW_FINDING_ID_PATTERN.test(value.id)) {
    throw workflowError("Reviewer finding has an invalid ID.", code);
  }
  return Object.freeze({
    id: value.id,
    file: normalizeRelativePath(value.file, `finding ${value.id} file`, code),
    problem: normalizeText(
      value.problem,
      `finding ${value.id} problem`,
      MAX_TEXT_LENGTH,
      code,
    ),
    reason: normalizeText(
      value.reason,
      `finding ${value.id} reason`,
      MAX_TEXT_LENGTH,
      code,
    ),
    suggestedAction: normalizeText(
      value.suggestedAction,
      `finding ${value.id} suggested action`,
      MAX_TEXT_LENGTH,
      code,
    ),
  });
}

function normalizeReviewFindings(value, code = INVALID_OUTPUT_CODE) {
  if (!Array.isArray(value) || value.length > MAX_ITEMS) {
    throw workflowError("Reviewer findings have an invalid number of items.", code);
  }
  const findings = Object.freeze(
    value.map((finding) => normalizeReviewFinding(finding, code)),
  );
  if (new Set(findings.map(({ id }) => id)).size !== findings.length) {
    throw workflowError("Reviewer finding IDs must be unique.", code);
  }
  return findings;
}

function normalizeFinalizationIssues(value, code = INVALID_OUTPUT_CODE) {
  if (!Array.isArray(value) || value.length > MAX_ITEMS) {
    throw workflowError(
      "Finalization issues have an invalid number of items.",
      code,
    );
  }
  const issues = Object.freeze(
    value.map((issue) => {
      if (!isRecord(issue) || !FINALIZATION_ISSUE_ID_PATTERN.test(issue.id)) {
        throw workflowError("Finalization issue has an invalid ID.", code);
      }
      return Object.freeze({
        id: issue.id,
        command: normalizeText(
          issue.command,
          `finalization issue ${issue.id} command`,
          MAX_TEXT_LENGTH,
          code,
        ),
        problem: normalizeText(
          issue.problem,
          `finalization issue ${issue.id} problem`,
          MAX_TEXT_LENGTH,
          code,
        ),
        evidence: normalizeTextList(
          issue.evidence,
          `finalization issue ${issue.id} evidence`,
          { code },
        ),
      });
    }),
  );
  if (new Set(issues.map(({ id }) => id)).size !== issues.length) {
    throw workflowError("Finalization issue IDs must be unique.", code);
  }
  return issues;
}

export function normalizeImplementationResult(payload) {
  if (
    !isRecord(payload) ||
    !["COMPLETED", "BLOCKED", "PRODUCT_DECISION_REQUIRED"].includes(
      payload.status,
    )
  ) {
    throw outputError("Worker returned an invalid implementation result.");
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
  if (payload.status === "BLOCKED") {
    if (
      payload.summary !== "" ||
      payload.question !== "" ||
      payload.whyBlocked !== "" ||
      !emptyArray(payload.options)
    ) {
      throw outputError("Blocked implementation contains inapplicable fields.");
    }
    return Object.freeze({
      status: payload.status,
      reason: normalizeText(
        payload.reason,
        "implementation blocker",
        MAX_TEXT_LENGTH,
        INVALID_OUTPUT_CODE,
      ),
      evidence: normalizeTextList(payload.evidence, "implementation evidence", {
        code: INVALID_OUTPUT_CODE,
      }),
    });
  }
  if (payload.reason !== "" || !emptyDecision(payload)) {
    throw outputError("Completed implementation contains inapplicable fields.");
  }
  return Object.freeze({
    status: payload.status,
    summary: normalizeSummary(
      payload.summary,
      "implementation summary",
      INVALID_OUTPUT_CODE,
    ),
  });
}

export function normalizeFinalizationResult(payload) {
  const statuses = [
    "PASS",
    "FAIL",
    "SKILL_MISSING",
    "SKILL_INVALID",
    "BLOCKED",
    "PRODUCT_DECISION_REQUIRED",
  ];
  if (!isRecord(payload) || !statuses.includes(payload.status)) {
    throw outputError("Worker returned an invalid finalization result.");
  }
  assertStructuredResultSize(payload);
  if (payload.status === "PRODUCT_DECISION_REQUIRED") {
    if (
      payload.skillPath !== "" ||
      payload.summary !== "" ||
      !emptyArray(payload.issues) ||
      payload.reason !== ""
    ) {
      throw outputError("Product decision contains inapplicable fields.");
    }
    return Object.freeze({
      status: payload.status,
      decision: normalizeProductDecision(payload),
    });
  }
  if (["SKILL_MISSING", "SKILL_INVALID", "BLOCKED"].includes(payload.status)) {
    if (
      payload.summary !== "" ||
      !emptyArray(payload.issues) ||
      payload.question !== "" ||
      payload.whyBlocked !== "" ||
      !emptyArray(payload.options)
    ) {
      throw outputError("Unavailable finalization contains inapplicable fields.");
    }
    if (
      (payload.status === "SKILL_MISSING" && payload.skillPath !== "") ||
      (payload.status !== "SKILL_MISSING" && payload.skillPath === "")
    ) {
      throw outputError("Finalization skill path is inapplicable.");
    }
    return Object.freeze({
      status: payload.status,
      skillPath:
        payload.skillPath === ""
          ? null
          : normalizeRelativePath(
              payload.skillPath,
              "finalization skill path",
              INVALID_OUTPUT_CODE,
            ),
      reason: normalizeText(
        payload.reason,
        "finalization blocker",
        MAX_TEXT_LENGTH,
        INVALID_OUTPUT_CODE,
      ),
      evidence: normalizeOptionalEvidence(
        payload.evidence,
        "finalization blocker evidence",
      ),
    });
  }
  if (payload.reason !== "" || !emptyDecision(payload)) {
    throw outputError("Finalization result contains inapplicable fields.");
  }
  const issues = normalizeFinalizationIssues(payload.issues);
  if (
    (payload.status === "PASS" && issues.length !== 0) ||
    (payload.status === "FAIL" && issues.length === 0)
  ) {
    throw outputError("Finalization status does not match its issues.");
  }
  return Object.freeze({
    status: payload.status,
    skillPath: normalizeRelativePath(
      payload.skillPath,
      "finalization skill path",
      INVALID_OUTPUT_CODE,
    ),
    summary: normalizeSummary(
      payload.summary,
      "finalization summary",
      INVALID_OUTPUT_CODE,
    ),
    issues,
  });
}

export function normalizeReviewResult(payload, previousFindings = []) {
  if (
    !isRecord(payload) ||
    !["APPROVED", "FINDINGS", "PRODUCT_DECISION_REQUIRED"].includes(
      payload.status,
    )
  ) {
    throw outputError("Reviewer returned an invalid review result.");
  }
  assertStructuredResultSize(payload);
  if (payload.status === "PRODUCT_DECISION_REQUIRED") {
    if (!emptyArray(payload.findings)) {
      throw outputError("Product decision must not include findings.");
    }
    return Object.freeze({
      status: payload.status,
      decision: normalizeProductDecision(payload),
    });
  }
  if (!emptyDecision(payload)) {
    throw outputError("Review result contains inapplicable fields.");
  }
  const findings = normalizeReviewFindings(payload.findings);
  if (
    (payload.status === "APPROVED" && findings.length !== 0) ||
    (payload.status === "FINDINGS" && findings.length === 0)
  ) {
    throw outputError("Review status does not match its findings.");
  }
  for (const finding of findings) {
    const previous = previousFindings.find(
      (candidate) =>
        candidate.file === finding.file && candidate.problem === finding.problem,
    );
    if (previous !== undefined && previous.id !== finding.id) {
      throw outputError("Reviewer changed the ID of an unchanged finding.");
    }
  }
  return Object.freeze({ status: payload.status, findings });
}

export function normalizeResolutionResult(payload, blockers, arbitratedIds) {
  if (
    !isRecord(payload) ||
    !["RESOLVED", "PRODUCT_DECISION_REQUIRED"].includes(payload.status)
  ) {
    throw outputError("Worker returned an invalid finding resolution.");
  }
  assertStructuredResultSize(payload);
  if (payload.status === "PRODUCT_DECISION_REQUIRED") {
    if (!emptyArray(payload.decisions)) {
      throw outputError("Product decision must not include finding decisions.");
    }
    return Object.freeze({
      status: payload.status,
      decision: normalizeProductDecision(payload),
    });
  }
  if (!emptyDecision(payload) || !Array.isArray(payload.decisions)) {
    throw outputError("Finding resolution contains inapplicable fields.");
  }
  const expectedIds = blockers.map(({ id }) => id).sort();
  const decisions = Object.freeze(
    payload.decisions.map((decision) => {
      if (
        !isRecord(decision) ||
        !["FIX", "DISPUTE"].includes(decision.decision) ||
        !expectedIds.includes(decision.id)
      ) {
        throw outputError("Worker returned an invalid finding decision.");
      }
      if (
        decision.decision === "DISPUTE" &&
        (decision.id.startsWith("F") || arbitratedIds.has(decision.id))
      ) {
        throw outputError("This blocker cannot be disputed.");
      }
      return Object.freeze({
        id: decision.id,
        decision: decision.decision,
        reason: normalizeText(
          decision.reason,
          `resolution ${decision.id} reason`,
          MAX_TEXT_LENGTH,
          INVALID_OUTPUT_CODE,
        ),
        evidence:
          decision.decision === "DISPUTE"
            ? normalizeTextList(
                decision.evidence,
                `dispute ${decision.id} evidence`,
                { code: INVALID_OUTPUT_CODE },
              )
            : normalizeOptionalEvidence(
                decision.evidence,
                `fix ${decision.id} evidence`,
              ),
      });
    }),
  );
  const actualIds = decisions.map(({ id }) => id).sort();
  if (
    decisions.length !== blockers.length ||
    new Set(actualIds).size !== actualIds.length ||
    actualIds.some((id, index) => id !== expectedIds[index])
  ) {
    throw outputError("Worker must resolve every current blocker exactly once.");
  }
  return Object.freeze({ status: payload.status, decisions });
}

export function normalizeReconsiderationResult(payload, disputes) {
  if (
    !isRecord(payload) ||
    !["RESOLVED", "PRODUCT_DECISION_REQUIRED"].includes(payload.status)
  ) {
    throw outputError("Reviewer returned an invalid dispute reconsideration.");
  }
  assertStructuredResultSize(payload);
  if (payload.status === "PRODUCT_DECISION_REQUIRED") {
    if (!emptyArray(payload.decisions)) {
      throw outputError("Product decision must not include dispute decisions.");
    }
    return Object.freeze({
      status: payload.status,
      decision: normalizeProductDecision(payload),
    });
  }
  if (!emptyDecision(payload) || !Array.isArray(payload.decisions)) {
    throw outputError("Dispute reconsideration contains inapplicable fields.");
  }
  const expectedIds = disputes.map(({ findingId }) => findingId).sort();
  const decisions = Object.freeze(
    payload.decisions.map((decision) => {
      if (
        !isRecord(decision) ||
        !["WITHDRAW", "UPHOLD"].includes(decision.direction) ||
        !expectedIds.includes(decision.id)
      ) {
        throw outputError("Reviewer returned an invalid dispute decision.");
      }
      return Object.freeze({
        findingId: decision.id,
        direction: decision.direction,
        reason: normalizeText(
          decision.reason,
          `dispute ${decision.id} reconsideration`,
          MAX_TEXT_LENGTH,
          INVALID_OUTPUT_CODE,
        ),
        evidence: normalizeOptionalEvidence(
          decision.evidence,
          `dispute ${decision.id} reconsideration evidence`,
        ),
      });
    }),
  );
  const actualIds = decisions.map(({ findingId }) => findingId).sort();
  if (
    decisions.length !== disputes.length ||
    new Set(actualIds).size !== actualIds.length ||
    actualIds.some((id, index) => id !== expectedIds[index])
  ) {
    throw outputError("Reviewer must reconsider every dispute exactly once.");
  }
  return Object.freeze({ status: payload.status, decisions });
}

export function normalizeFindingArbitration(payload) {
  const directions = [
    "WORKER_CORRECT",
    "REVIEWER_CORRECT",
    "REQUIREMENT_AMBIGUOUS",
  ];
  if (!isRecord(payload) || !directions.includes(payload.direction)) {
    throw outputError("Arbiter returned an invalid finding direction.");
  }
  assertStructuredResultSize(payload);
  const rationale = normalizeText(
    payload.rationale,
    "finding arbitration rationale",
    MAX_TEXT_LENGTH,
    INVALID_OUTPUT_CODE,
  );
  if (payload.direction === "REQUIREMENT_AMBIGUOUS") {
    return Object.freeze({
      direction: payload.direction,
      rationale,
      decision: normalizeProductDecision(payload),
    });
  }
  if (!emptyDecision(payload)) {
    throw outputError("Finding arbitration contains inapplicable fields.");
  }
  return Object.freeze({ direction: payload.direction, rationale });
}

export function normalizeStagnationResult(payload, pipelineState) {
  const directions = [
    "CONTINUE_FIXES",
    "REWORK_IMPLEMENTATION",
    "RECONSIDER_FINDINGS",
    "PLAN_REVISION_REQUIRED",
    "PRODUCT_DECISION_REQUIRED",
  ];
  if (!isRecord(payload) || !directions.includes(payload.direction)) {
    throw outputError("Arbiter returned an invalid stagnation direction.");
  }
  assertStructuredResultSize(payload);
  const rationale = normalizeText(
    payload.rationale,
    "stagnation rationale",
    MAX_TEXT_LENGTH,
    INVALID_OUTPUT_CODE,
  );
  if (payload.direction === "PRODUCT_DECISION_REQUIRED") {
    if (!emptyArray(payload.findingIds) || payload.reason !== "") {
      throw outputError("Product decision contains inapplicable fields.");
    }
    return Object.freeze({
      direction: payload.direction,
      rationale,
      decision: normalizeProductDecision(payload),
    });
  }
  if (payload.direction === "PLAN_REVISION_REQUIRED") {
    if (!emptyArray(payload.findingIds) || !emptyDecision(payload, { ignoreEvidence: true })) {
      throw outputError("Plan revision contains inapplicable fields.");
    }
    return Object.freeze({
      direction: payload.direction,
      rationale,
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
  if (payload.reason !== "" || !emptyDecision(payload)) {
    throw outputError("Stagnation result contains inapplicable fields.");
  }
  if (!Array.isArray(payload.findingIds)) {
    throw outputError("Stagnation finding IDs are invalid.");
  }
  const findingIds = payload.findingIds.map((id) => {
    if (!REVIEW_FINDING_ID_PATTERN.test(id)) {
      throw outputError("Stagnation finding ID is invalid.");
    }
    return id;
  });
  const currentFindingIds = new Set(pipelineState.findings.map(({ id }) => id));
  if (
    (payload.direction === "RECONSIDER_FINDINGS" &&
      (findingIds.length === 0 ||
        new Set(findingIds).size !== findingIds.length ||
        findingIds.some((id) => !currentFindingIds.has(id)))) ||
    (payload.direction !== "RECONSIDER_FINDINGS" && findingIds.length !== 0)
  ) {
    throw outputError("Stagnation direction names inapplicable findings.");
  }
  return Object.freeze({
    direction: payload.direction,
    rationale,
    findingIds: Object.freeze(findingIds),
  });
}

export function normalizeResumeAction(value) {
  if (value === undefined || value === null) {
    return null;
  }
  if (!isRecord(value) || !["extra-fix-rounds", "override-finding"].includes(value.type)) {
    throw workflowError("Plan-execution resume action is invalid.");
  }
  if (
    value.type === "extra-fix-rounds" &&
    Object.keys(value).length === 2 &&
    Number.isSafeInteger(value.amount) &&
    value.amount > 0
  ) {
    return Object.freeze({ type: value.type, amount: value.amount });
  }
  if (
    value.type === "override-finding" &&
    Object.keys(value).length === 2 &&
    REVIEW_FINDING_ID_PATTERN.test(value.findingId)
  ) {
    return Object.freeze({ type: value.type, findingId: value.findingId });
  }
  throw workflowError("Plan-execution resume action is invalid.");
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
    "product-decision": ["CLARIFY", "BOOTSTRAP", "IMPLEMENT"],
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

function assertExactFields(value, fields, name) {
  if (
    !isRecord(value) ||
    Object.keys(value).length !== fields.length ||
    fields.some((field) => !Object.hasOwn(value, field))
  ) {
    throw workflowError(`${name} is invalid.`);
  }
}

function normalizePersistedFindings(value, name = "Plan-execution findings") {
  try {
    return normalizeReviewFindings(value, "ERR_INVALID_PLAN_EXECUTION_STATE");
  } catch (cause) {
    throw new PlanExecutionWorkflowError(`${name} are invalid.`, {
      cause,
      code: "ERR_INVALID_PLAN_EXECUTION_STATE",
    });
  }
}

function normalizePersistedFinalization(value) {
  if (value === null) {
    return null;
  }
  assertExactFields(
    value,
    ["status", "skillPath", "summary", "issues", "fingerprint"],
    "Plan-execution finalization result",
  );
  if (
    !["PASS", "FAIL"].includes(value.status) ||
    !HASH_PATTERN.test(value.fingerprint)
  ) {
    throw workflowError("Plan-execution finalization result is invalid.");
  }
  normalizeRelativePath(
    value.skillPath,
    "finalization skill path",
    "ERR_INVALID_PLAN_EXECUTION_STATE",
  );
  normalizeSummary(value.summary, "finalization summary");
  const issues = normalizeFinalizationIssues(
    value.issues,
    "ERR_INVALID_PLAN_EXECUTION_STATE",
  );
  if (
    (value.status === "PASS" && issues.length !== 0) ||
    (value.status === "FAIL" && issues.length === 0)
  ) {
    throw workflowError("Plan-execution finalization result is inconsistent.");
  }
  return value;
}

function normalizeStringCountRecord(value, name) {
  if (!isRecord(value) || Object.keys(value).length > MAX_DIAGNOSTIC_ITEMS) {
    throw workflowError(`${name} is invalid.`);
  }
  for (const [id, count] of Object.entries(value)) {
    if (
      !REVIEW_FINDING_ID_PATTERN.test(id) ||
      !Number.isSafeInteger(count) ||
      count < 1
    ) {
      throw workflowError(`${name} is invalid.`);
    }
  }
  return value;
}

function normalizePendingDisputes(value) {
  if (!Array.isArray(value) || value.length > MAX_ITEMS) {
    throw workflowError("Plan-execution pending disputes are invalid.");
  }
  const disputes = value.map((dispute) => {
    assertExactFields(
      dispute,
      ["findingId", "reason", "evidence"],
      "Plan-execution pending dispute",
    );
    if (!REVIEW_FINDING_ID_PATTERN.test(dispute.findingId)) {
      throw workflowError("Plan-execution pending dispute is invalid.");
    }
    normalizeText(dispute.reason, `dispute ${dispute.findingId} reason`);
    normalizeTextList(dispute.evidence, `dispute ${dispute.findingId} evidence`);
    return dispute;
  });
  if (new Set(disputes.map(({ findingId }) => findingId)).size !== disputes.length) {
    throw workflowError("Plan-execution pending disputes must be unique.");
  }
  return value;
}

function normalizeDisputeHistory(value) {
  if (!Array.isArray(value) || value.length > MAX_DIAGNOSTIC_ITEMS) {
    throw workflowError("Plan-execution dispute history is invalid.");
  }
  for (const entry of value) {
    assertExactFields(
      entry,
      [
        "findingId",
        "attempt",
        "direction",
        "workerReason",
        "workerEvidence",
        "reviewerReason",
        "reviewerEvidence",
      ],
      "Plan-execution dispute history entry",
    );
    if (
      !REVIEW_FINDING_ID_PATTERN.test(entry.findingId) ||
      !Number.isSafeInteger(entry.attempt) ||
      entry.attempt < 1 ||
      !["WITHDRAW", "UPHOLD"].includes(entry.direction)
    ) {
      throw workflowError("Plan-execution dispute history entry is invalid.");
    }
    normalizeText(entry.workerReason, "dispute Worker reason");
    normalizeTextList(entry.workerEvidence, "dispute Worker evidence");
    normalizeText(entry.reviewerReason, "dispute Reviewer reason");
    normalizeTextList(entry.reviewerEvidence, "dispute Reviewer evidence", {
      allowEmpty: true,
    });
  }
  return value;
}

function normalizeFindingArbitrations(value) {
  if (!Array.isArray(value) || value.length > MAX_DIAGNOSTIC_ITEMS) {
    throw workflowError("Plan-execution finding arbitrations are invalid.");
  }
  for (const entry of value) {
    assertExactFields(
      entry,
      ["findingId", "direction", "rationale"],
      "Plan-execution finding arbitration",
    );
    if (
      !REVIEW_FINDING_ID_PATTERN.test(entry.findingId) ||
      !["WORKER_CORRECT", "REVIEWER_CORRECT"].includes(entry.direction)
    ) {
      throw workflowError("Plan-execution finding arbitration is invalid.");
    }
    normalizeText(entry.rationale, "finding arbitration rationale");
  }
  if (new Set(value.map(({ findingId }) => findingId)).size !== value.length) {
    throw workflowError("Plan-execution finding arbitrations must be unique.");
  }
  return value;
}

function normalizeCorrectionHistory(value) {
  if (!Array.isArray(value) || value.length > MAX_DIAGNOSTIC_ITEMS) {
    throw workflowError("Plan-execution correction history is invalid.");
  }
  for (const entry of value) {
    assertExactFields(
      entry,
      ["round", "fingerprint", "finalizationIssueIds", "findingIds"],
      "Plan-execution correction history entry",
    );
    if (
      !Number.isSafeInteger(entry.round) ||
      entry.round < 1 ||
      !HASH_PATTERN.test(entry.fingerprint) ||
      !Array.isArray(entry.finalizationIssueIds) ||
      !Array.isArray(entry.findingIds) ||
      entry.finalizationIssueIds.some(
        (id) => !FINALIZATION_ISSUE_ID_PATTERN.test(id),
      ) ||
      entry.findingIds.some((id) => !REVIEW_FINDING_ID_PATTERN.test(id)) ||
      new Set(entry.finalizationIssueIds).size !==
        entry.finalizationIssueIds.length ||
      new Set(entry.findingIds).size !== entry.findingIds.length ||
      (entry.finalizationIssueIds.length === 0) ===
        (entry.findingIds.length === 0)
    ) {
      throw workflowError("Plan-execution correction history entry is invalid.");
    }
  }
  return value;
}

function normalizeDirection(value, name, directions) {
  if (value === null) {
    return null;
  }
  assertExactFields(value, ["direction", "rationale"], name);
  if (!directions.includes(value.direction)) {
    throw workflowError(`${name} is invalid.`);
  }
  normalizeText(value.rationale, `${name} rationale`);
  return value;
}

function normalizeFindingOverrides(value) {
  if (!Array.isArray(value) || value.length > MAX_DIAGNOSTIC_ITEMS) {
    throw workflowError("Plan-execution finding overrides are invalid.");
  }
  for (const entry of value) {
    assertExactFields(
      entry,
      ["findingId", "fingerprint"],
      "Plan-execution finding override",
    );
    if (
      !REVIEW_FINDING_ID_PATTERN.test(entry.findingId) ||
      !HASH_PATTERN.test(entry.fingerprint)
    ) {
      throw workflowError("Plan-execution finding override is invalid.");
    }
  }
  return value;
}

function normalizePendingCommit(value) {
  if (value === null) {
    return null;
  }
  assertExactFields(
    value,
    ["status", "authorization"],
    "Plan-execution pending commit",
  );
  if (!["prepared", "consumed"].includes(value.status)) {
    throw workflowError("Plan-execution pending commit is invalid.");
  }
  const authorization = value.authorization;
  assertExactFields(
    authorization,
    COMMIT_AUTHORIZATION_FIELDS,
    "Plan-execution commit authorization",
  );
  if (
    authorization.schemaVersion !== 1 ||
    typeof authorization.id !== "string" ||
    authorization.id.length === 0 ||
    typeof authorization.projectPath !== "string" ||
    !isAbsolute(authorization.projectPath) ||
    resolve(authorization.projectPath) !== authorization.projectPath ||
    !OBJECT_ID_PATTERN.test(authorization.expectedHead) ||
    (authorization.expectedBranch !== null &&
      (typeof authorization.expectedBranch !== "string" ||
        authorization.expectedBranch.length === 0)) ||
    [
      "expectedRefsFingerprint",
      "expectedOtherRefsFingerprint",
      "expectedContentFingerprint",
      "expectedIndexFingerprint",
      "expectedRemoteConfigurationFingerprint",
      "expectedIdentityFingerprint",
      "expectedAuthorIdentityFingerprint",
      "expectedCommitterIdentityFingerprint",
    ].some((field) => !HASH_PATTERN.test(authorization[field])) ||
    typeof authorization.subject !== "string" ||
    authorization.subject.length === 0 ||
    authorization.subject.trim() !== authorization.subject ||
    /[\0\r\n]/u.test(authorization.subject) ||
    [...authorization.subject].length > 72
  ) {
    throw workflowError("Plan-execution commit authorization is invalid.");
  }
  return value;
}

function normalizeCompletedCommits(value) {
  if (
    !Array.isArray(value) ||
    value.some((commit) => !OBJECT_ID_PATTERN.test(commit)) ||
    new Set(value).size !== value.length
  ) {
    throw workflowError("Plan-execution completed commits are invalid.");
  }
  return value;
}

export function normalizePipelineState(value) {
  if (!isRecord(value)) {
    throw workflowError("Plan-execution state must be an object.");
  }
  if (!Object.hasOwn(value, "artifactRoot")) {
    value = { ...value, artifactRoot: "LOCAL_ARTIFACTS" };
  }
  if (
    Object.keys(value).length !== PIPELINE_STATE_FIELDS.size ||
    Object.keys(value).some((field) => !PIPELINE_STATE_FIELDS.has(field)) ||
    !WORKFLOW_STATES.includes(value.workflowState)
  ) {
    throw workflowError("Plan-execution state is invalid.");
  }
  if (
    typeof value.artifactRoot !== "string" ||
    value.artifactRoot.includes("\\") ||
    /^[a-zA-Z]:\//u.test(value.artifactRoot) ||
    posix.isAbsolute(value.artifactRoot) ||
    posix.normalize(value.artifactRoot) !== value.artifactRoot ||
    value.artifactRoot === "." ||
    value.artifactRoot === ".." ||
    value.artifactRoot.startsWith("../") ||
    value.artifactRoot === ".git" ||
    value.artifactRoot.startsWith(".git/") ||
    /[\0\p{Cc}\p{Zl}\p{Zp}]/u.test(value.artifactRoot)
  ) {
    throw workflowError("Plan-execution artifact root is invalid.");
  }
  for (const field of [
    "preflightComplete",
    "proactiveClarification",
    "proactiveClarificationComplete",
    "clarificationFrozen",
    "bootstrapArbitrationUsed",
    "compatibilityCheckRequired",
    "pendingCorrection",
    "stagnationArbitrationUsed",
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
  let planSteps = null;
  if (value.canonicalPlan !== null) {
    let canonical;
    try {
      const plan = parseCommitPlan(value.canonicalPlan);
      canonical = serializeCommitPlan(plan);
      planSteps = plan.steps;
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
    (!["BOOTSTRAP", "IMPLEMENT", "WAITING_FOR_USER", "FAILED"].includes(
      value.workflowState,
    ) ||
      value.clarificationFrozen ||
      disagreement !== null ||
      (value.currentStep === null
        ? workerSummary !== null ||
          reviewerSummary !== null ||
          resolvedSummary !== null
        : resolvedSummary === null))
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
    value.reviewerStep !== null &&
    (!Number.isSafeInteger(value.reviewerStep) ||
      value.reviewerStep < 1 ||
      value.currentStep === null ||
      value.reviewerStep > value.currentStep)
  ) {
    throw workflowError("Plan-execution Reviewer step is invalid.");
  }
  const implementationDirection = normalizeDirection(
    value.implementationDirection,
    "Plan-execution implementation direction",
    ["REWORK_IMPLEMENTATION"],
  );
  const finalizationResult = normalizePersistedFinalization(
    value.finalizationResult,
  );
  const findings = normalizePersistedFindings(value.findings);
  const previousFindings = normalizePersistedFindings(
    value.previousFindings,
    "Plan-execution previous findings",
  );
  const pendingDisputes = normalizePendingDisputes(value.pendingDisputes);
  const disputeCounts = normalizeStringCountRecord(
    value.disputeCounts,
    "Plan-execution dispute counts",
  );
  normalizeDisputeHistory(value.disputeHistory);
  const findingArbitrations = normalizeFindingArbitrations(
    value.findingArbitrations,
  );
  normalizeCorrectionHistory(value.correctionHistory);
  const sameFindingRounds = normalizeStringCountRecord(
    value.sameFindingRounds,
    "Plan-execution same-finding rounds",
  );
  const stagnationDirection = normalizeDirection(
    value.stagnationDirection,
    "Plan-execution stagnation direction",
    ["CONTINUE_FIXES", "REWORK_IMPLEMENTATION", "RECONSIDER_FINDINGS"],
  );
  if (value.stagnationArbitrationUsed !== (stagnationDirection !== null)) {
    throw workflowError("Plan-execution stagnation arbitration is inconsistent.");
  }
  if (
    !Number.isSafeInteger(value.blockedSinceStagnation) ||
    value.blockedSinceStagnation < 0 ||
    !Number.isSafeInteger(value.additionalFixRounds) ||
    value.additionalFixRounds < 0 ||
    (value.settings !== null &&
      !Number.isSafeInteger(
        value.settings.maxFixRoundsPerStep + value.additionalFixRounds,
      ))
  ) {
    throw workflowError("Plan-execution correction progress is invalid.");
  }
  if (
    value.finalizedFingerprint !== null &&
    !HASH_PATTERN.test(value.finalizedFingerprint)
  ) {
    throw workflowError("Plan-execution finalized fingerprint is invalid.");
  }
  if (
    value.reviewedFingerprint !== null &&
    !HASH_PATTERN.test(value.reviewedFingerprint)
  ) {
    throw workflowError("Plan-execution reviewed fingerprint is invalid.");
  }
  if (
    !Array.isArray(value.reviewReconsideration) ||
    value.reviewReconsideration.length > MAX_ITEMS ||
    value.reviewReconsideration.some(
      (id) => !REVIEW_FINDING_ID_PATTERN.test(id),
    ) ||
    new Set(value.reviewReconsideration).size !==
      value.reviewReconsideration.length
  ) {
    throw workflowError("Plan-execution review reconsideration is invalid.");
  }
  normalizeFindingOverrides(value.findingOverrides);
  const pendingCommit = normalizePendingCommit(value.pendingCommit);
  const completedCommits = normalizeCompletedCommits(value.completedCommits);
  if (
    completedCommits.length > (planSteps?.length ?? 0) ||
    (value.currentStep !== null &&
      completedCommits.length !== value.currentStep - 1) ||
    (value.workflowState === "DONE" &&
      completedCommits.length !== planSteps?.length) ||
    (!value.preflightComplete && completedCommits.length !== 0) ||
    (completedCommits.length > 0 &&
      value.repositoryBaseline?.head !== completedCommits.at(-1))
  ) {
    throw workflowError("Plan-execution completed-commit progress is invalid.");
  }
  if (
    pendingCommit !== null &&
    (!["COMMIT", "WAITING_FOR_USER", "FAILED"].includes(value.workflowState) ||
      value.currentStep === null ||
      pendingCommit.authorization.projectPath !==
        value.repositoryBaseline?.projectPath ||
      pendingCommit.authorization.expectedHead !==
        value.repositoryBaseline?.head ||
      pendingCommit.authorization.expectedBranch !==
        value.repositoryBaseline?.branch ||
      pendingCommit.authorization.expectedRefsFingerprint !==
        value.repositoryBaseline?.refsFingerprint ||
      pendingCommit.authorization.expectedContentFingerprint !==
        value.reviewedFingerprint ||
      pendingCommit.authorization.expectedIndexFingerprint !==
        value.repositoryBaseline?.indexFingerprint ||
      pendingCommit.authorization.expectedRemoteConfigurationFingerprint !==
        value.repositoryBaseline?.remoteConfigurationFingerprint ||
      pendingCommit.authorization.expectedIdentityFingerprint !==
        value.repositoryBaseline?.identityFingerprint ||
      pendingCommit.authorization.subject !==
        planSteps?.[value.currentStep - 1]?.subject)
  ) {
    throw workflowError("Plan-execution pending commit is inconsistent.");
  }
  const currentFindingIds = new Set(findings.map(({ id }) => id));
  const previousFindingIds = new Set(previousFindings.map(({ id }) => id));
  const deferredDisputes =
    pendingDisputes.length > 0 &&
    findings.length === 0 &&
    pendingDisputes.every(({ findingId }) =>
      previousFindingIds.has(findingId),
    ) &&
    ([
      "IMPLEMENT",
      "FINALIZE",
      "REVIEW",
      "WAITING_FOR_USER",
      "FAILED",
    ].includes(value.workflowState) ||
      (value.workflowState === "RESOLVE_FINDINGS" &&
        finalizationResult?.status === "FAIL"));
  if (
    (pendingDisputes.some(
      ({ findingId }) => !currentFindingIds.has(findingId),
    ) &&
      !deferredDisputes) ||
    (["FINALIZE", "REVIEW"].includes(value.workflowState) &&
      pendingDisputes.length > 0 &&
      !deferredDisputes) ||
    value.reviewReconsideration.some((id) => !currentFindingIds.has(id)) ||
    Object.keys(disputeCounts).some(
      (id) =>
        !currentFindingIds.has(id) &&
        !pendingDisputes.some(({ findingId }) => findingId === id) &&
        !value.disputeHistory.some((entry) => entry.findingId === id) &&
        !value.findingOverrides.some((entry) => entry.findingId === id),
    )
  ) {
    throw workflowError("Plan-execution finding progress is inconsistent.");
  }
  if (
    finalizationResult === null &&
    (value.finalizedFingerprint !== null ||
      value.reviewedFingerprint !== null ||
      findings.length !== 0 ||
      (pendingDisputes.length !== 0 && !deferredDisputes))
  ) {
    throw workflowError("Plan-execution validation progress is inconsistent.");
  }
  if (
    finalizationResult !== null &&
    ((finalizationResult.status === "PASS") !==
      (value.finalizedFingerprint === finalizationResult.fingerprint) ||
      (value.reviewedFingerprint !== null &&
        value.reviewedFingerprint !== value.finalizedFingerprint) ||
      (finalizationResult.status === "FAIL" &&
        (value.reviewedFingerprint !== null || findings.length !== 0)))
  ) {
    throw workflowError("Plan-execution finalization progress is inconsistent.");
  }
  if (
    (findings.length > 0 || pendingDisputes.length > 0) &&
    value.reviewedFingerprint === null &&
    !deferredDisputes
  ) {
    throw workflowError("Plan-execution review progress is inconsistent.");
  }
  if (
    implementationDirection !== null &&
    (!["IMPLEMENT", "WAITING_FOR_USER", "FAILED"].includes(
      value.workflowState,
    ) ||
      stagnationDirection?.direction !== "REWORK_IMPLEMENTATION")
  ) {
    throw workflowError("Plan-execution implementation direction is inapplicable.");
  }
  if (
    value.pendingCorrection &&
    !["FINALIZE", "REVIEW", "WAITING_FOR_USER", "FAILED"].includes(
      value.workflowState,
    )
  ) {
    throw workflowError("Plan-execution pending correction is inapplicable.");
  }
  if (
    stagnationDirection !== null &&
    ![
      "IMPLEMENT",
      "FINALIZE",
      "REVIEW",
      "RESOLVE_FINDINGS",
      "COMMIT",
      "DONE",
      "WAITING_FOR_USER",
      "FAILED",
    ].includes(value.workflowState)
  ) {
    throw workflowError("Plan-execution stagnation direction is inapplicable.");
  }
  if (
    value.reviewReconsideration.length > 0 &&
    !["REVIEW", "WAITING_FOR_USER", "FAILED"].includes(value.workflowState)
  ) {
    throw workflowError("Plan-execution review reconsideration is inapplicable.");
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
      value.currentStep !== null ||
      value.reviewerStep !== null ||
      implementationDirection !== null ||
      finalizationResult !== null ||
      previousFindings.length !== 0 ||
      Object.keys(disputeCounts).length !== 0 ||
      value.disputeHistory.length !== 0 ||
      findingArbitrations.length !== 0 ||
      value.correctionHistory.length !== 0 ||
      Object.keys(sameFindingRounds).length !== 0 ||
      value.pendingCorrection ||
      value.blockedSinceStagnation !== 0 ||
      value.stagnationArbitrationUsed ||
      stagnationDirection !== null ||
      value.reviewReconsideration.length !== 0 ||
      value.additionalFixRounds !== 0 ||
      value.findingOverrides.length !== 0 ||
      pendingCommit !== null ||
      completedCommits.length !== 0)
  ) {
    throw workflowError("Plan-execution preflight state is inconsistent.");
  }
  if (
    ["CLARIFY", "BOOTSTRAP"].includes(value.workflowState) &&
    (value.currentStep !== null ||
      value.reviewerStep !== null ||
      implementationDirection !== null ||
      finalizationResult !== null ||
      previousFindings.length !== 0 ||
      Object.keys(disputeCounts).length !== 0 ||
      value.disputeHistory.length !== 0 ||
      findingArbitrations.length !== 0 ||
      value.correctionHistory.length !== 0 ||
      Object.keys(sameFindingRounds).length !== 0 ||
      value.pendingCorrection ||
      value.blockedSinceStagnation !== 0 ||
      value.stagnationArbitrationUsed ||
      stagnationDirection !== null ||
      value.reviewReconsideration.length !== 0 ||
      value.additionalFixRounds !== 0 ||
      value.findingOverrides.length !== 0 ||
      pendingCommit !== null ||
      completedCommits.length !== 0)
  ) {
    throw workflowError("Plan-execution work progress is not applicable.");
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
    ((!value.clarificationFrozen && !value.compatibilityCheckRequired) ||
      resolvedSummary === null ||
      value.currentStep === null ||
      finalizationResult !== null ||
      findings.length !== 0 ||
      (pendingDisputes.length !== 0 && !deferredDisputes) ||
      value.reviewReconsideration.length !== 0)
  ) {
    throw workflowError("Plan-execution implementation state is inconsistent.");
  }
  if (
    ["FINALIZE", "REVIEW", "RESOLVE_FINDINGS", "COMMIT"].includes(
      value.workflowState,
    ) &&
    (!value.clarificationFrozen ||
      resolvedSummary === null ||
      value.currentStep === null ||
      value.compatibilityCheckRequired)
  ) {
    throw workflowError("Plan-execution active step state is inconsistent.");
  }
  if (
    value.workflowState === "FINALIZE" &&
    (finalizationResult !== null ||
      findings.length !== 0 ||
      value.reviewReconsideration.length !== 0)
  ) {
    throw workflowError("Plan-execution finalization state is inconsistent.");
  }
  if (
    value.workflowState === "REVIEW" &&
    (finalizationResult?.status !== "PASS" ||
      value.finalizedFingerprint === null)
  ) {
    throw workflowError("Plan-execution review state is inconsistent.");
  }
  const finalizationBlocked =
    finalizationResult?.status === "FAIL" &&
    finalizationResult.issues.length > 0;
  if (
    value.workflowState === "RESOLVE_FINDINGS" &&
    !finalizationBlocked &&
    findings.length === 0 &&
    pendingDisputes.length === 0
  ) {
    throw workflowError("Plan-execution finding resolution has no blockers.");
  }
  if (
    value.workflowState === "COMMIT" &&
    (finalizationResult?.status !== "PASS" ||
      value.finalizedFingerprint === null ||
      value.reviewedFingerprint !== value.finalizedFingerprint ||
      findings.length !== 0 ||
      pendingDisputes.length !== 0 ||
      value.reviewReconsideration.length !== 0)
  ) {
    throw workflowError("Plan-execution commit gate is inconsistent.");
  }
  if (
    value.workflowState === "DONE" &&
    (value.currentStep !== null ||
      pendingCommit !== null ||
      finalizationResult?.status !== "PASS" ||
      value.finalizedFingerprint === null ||
      value.reviewedFingerprint !== value.finalizedFingerprint ||
      findings.length !== 0 ||
      pendingDisputes.length !== 0 ||
      value.reviewReconsideration.length !== 0)
  ) {
    throw workflowError("Plan-execution completion state is inconsistent.");
  }
  if (
    !["CLARIFY", "WAITING_FOR_USER", "FAILED"].includes(value.workflowState) &&
    !value.preflightComplete
  ) {
    throw workflowError("Plan-execution state has not completed preflight.");
  }
  return value;
}

export function createPlanExecutionState({
  artifactRoot = "LOCAL_ARTIFACTS",
  proactiveClarification = false,
  settings = null,
} = {}) {
  if (typeof proactiveClarification !== "boolean") {
    throw workflowError("proactiveClarification must be a boolean.");
  }
  if (settings !== null) {
    assertSettings(settings);
  }
  return Object.freeze(normalizePipelineState({
    workflowState: "CLARIFY",
    artifactRoot,
    preflightComplete: false,
    settings: settings === null ? null : Object.freeze({ ...settings }),
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
    reviewerStep: null,
    implementationDirection: null,
    finalizationResult: null,
    finalizedFingerprint: null,
    reviewedFingerprint: null,
    findings: Object.freeze([]),
    previousFindings: Object.freeze([]),
    pendingDisputes: Object.freeze([]),
    disputeCounts: Object.freeze({}),
    disputeHistory: Object.freeze([]),
    findingArbitrations: Object.freeze([]),
    correctionHistory: Object.freeze([]),
    sameFindingRounds: Object.freeze({}),
    pendingCorrection: false,
    blockedSinceStagnation: 0,
    stagnationArbitrationUsed: false,
    stagnationDirection: null,
    reviewReconsideration: Object.freeze([]),
    additionalFixRounds: 0,
    findingOverrides: Object.freeze([]),
    pendingCommit: null,
    completedCommits: Object.freeze([]),
  }));
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
  if (
    run.sessionLineage.sourceProfile !== undefined &&
    run.sessionLineage.sourceProfile !== null &&
    (run.sessionLineage.source === null ||
      typeof run.sessionLineage.sourceProfile !== "string" ||
      run.sessionLineage.sourceProfile.length === 0)
  ) {
    throw workflowError("Plan-execution source profile is invalid.");
  }
  for (const child of run.sessionLineage.children) {
    if (
      !isRecord(child) ||
      !["worker", "reviewer", "arbiter"].includes(child.role) ||
      typeof child.sessionId !== "string" ||
      child.sessionId.length === 0 ||
      child.sessionId === run.sessionLineage.source ||
      (Object.hasOwn(child, "contextKey") &&
        (typeof child.contextKey !== "string" ||
          !/^[a-f0-9]{64}$/u.test(child.contextKey)))
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
      state.artifactRoot,
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
  assertInputPause(run, state);
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
    const hasResumeState = Object.hasOwn(run.pause, "resumeState");
    const allowedResumeStates = Object.hasOwn(
      PAUSE_RESUME_STATES,
      run.pause.reason,
    )
      ? PAUSE_RESUME_STATES[run.pause.reason]
      : undefined;
    const requiresResumeState =
      ["fix_limit_reached", "no_progress"].includes(run.pause.reason) ||
      (state.preflightComplete &&
        ["backend_unavailable", "environment_blocked"].includes(
          run.pause.reason,
        )) ||
      (run.pause.reason === "finalization_cannot_pass" &&
        run.pause.code !== "ERR_FINALIZATION_MODIFIED_BEFORE_VALIDATION");
    if (
      (hasResumeState &&
        (!allowedResumeStates?.includes(run.pause.resumeState) ||
          !state.preflightComplete)) ||
      (requiresResumeState && !hasResumeState)
    ) {
      throw workflowError("Plan-execution pause resume state is invalid.");
    }
    if (hasResumeState) {
      normalizePipelineState({
        ...state,
        workflowState: run.pause.resumeState,
      });
    }
    if (
      (state.pendingCommit !== null) !==
        ["commit_failed", "commit_contract_violated"].includes(
          run.pause.reason,
        ) ||
      (state.pendingCommit !== null &&
        state.pendingCommit.status !== "consumed")
    ) {
      throw workflowError("Plan-execution pending commit pause is invalid.");
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
  const correctionHistory = state.correctionHistory;
  const lastCorrection = correctionHistory.at(-1)?.round ?? 0;
  const lastCorrectionFindingIds = new Set(
    correctionHistory.at(-1)?.findingIds ?? [],
  );
  if (
    counters.clarificationRounds > MAX_CLARIFICATION_ROUNDS ||
    counters.correctionRounds > counters.fixRounds ||
    counters.fixRounds >
      (state.settings?.maxFixRoundsPerStep ?? 0) + state.additionalFixRounds ||
    lastCorrection !== counters.correctionRounds ||
    correctionHistory.some(
      (entry, index) =>
        index > 0 &&
        entry.round !== correctionHistory[index - 1].round + 1,
    ) ||
    state.blockedSinceStagnation > counters.correctionRounds ||
    Object.keys(state.sameFindingRounds).some(
      (id) => !lastCorrectionFindingIds.has(id),
    ) ||
    Object.values(state.sameFindingRounds).some(
      (count) => count > counters.correctionRounds,
    )
  ) {
    throw workflowError("Plan-execution persisted progress is invalid.");
  }
  for (const [findingId, count] of Object.entries(state.disputeCounts)) {
    const recorded = state.disputeHistory.filter(
      (entry) => entry.findingId === findingId,
    );
    if (
      count > state.settings.maxDisputesPerFinding ||
      recorded.some(
        (entry, index) =>
          entry.attempt > count ||
          (index > 0 && entry.attempt <= recorded[index - 1].attempt),
      )
    ) {
      throw workflowError("Plan-execution dispute progress is invalid.");
    }
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
  for (const name of [
    "assertUnchanged",
    "consumeCommit",
    "contentFingerprint",
    "preflight",
    "prepareCommit",
    "snapshot",
    "verifyCommit",
  ]) {
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
