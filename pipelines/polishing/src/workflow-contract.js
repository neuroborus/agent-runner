import { createHash } from "node:crypto";
import { isAbsolute, join, relative, resolve, sep } from "node:path";

export const MAX_CLARIFICATION_ROUNDS = 3;
export const WORKFLOW_STATES = Object.freeze([
  "CLARIFY",
  "BOOTSTRAP",
  "POLISH",
  "WAITING_FOR_USER",
  "FAILED",
]);

const ROLES = Object.freeze(["worker", "reviewer", "arbiter"]);
const SETTINGS_FIELDS = Object.freeze([
  "maxFixRounds",
  "maxDisputesPerFinding",
  "maxSameFindingRounds",
  "stagnationWindowRounds",
]);
const COUNTER_FIELDS = Object.freeze([
  "clarificationRounds",
  "productDecisions",
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
  "refreezeRequired",
  "workerSummary",
  "reviewerSummary",
  "resolvedSummary",
  "bootstrapDisagreement",
  "bootstrapArbitrationUsed",
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
const SNAPSHOT_FIELDS = new Set([
  "schemaVersion",
  "projectPath",
  "allowedPaths",
  "head",
  "branch",
  "detached",
  "clean",
  "refsFingerprint",
  "trackedContentFingerprint",
  "untrackedContentFingerprint",
  "contentFingerprint",
  "indexFingerprint",
  "remoteConfigurationFingerprint",
  "identityAvailable",
  "identityFingerprint",
]);
const HASH_PATTERN = /^[a-f0-9]{64}$/u;
const RUN_ID_PATTERN = /^[a-zA-Z0-9][a-zA-Z0-9_-]{0,127}$/u;
const MAX_TEXT_LENGTH = 4_000;
const MAX_SUMMARY_LENGTH = 20_000;
const MAX_ITEMS = 32;
const MAX_OPTIONS = 16;
const MAX_STRUCTURED_RESULT_BYTES = 256 * 1024;
const INVALID_OUTPUT_CODE = "ERR_INVALID_POLISHING_OUTPUT";
export const INVALID_POLISHING_INPUT_CODE = "ERR_INVALID_POLISHING_INPUT";
const EDIT_PAUSE_REASONS = Object.freeze({
  "clarification-answers": "clarification_answers_required",
  "product-decision": "product_decision_required",
  "proactive-clarification": "proactive_clarification",
});

export class PolishingWorkflowError extends Error {
  constructor(message, { cause, code = "ERR_POLISHING_WORKFLOW" } = {}) {
    super(message, { cause });
    this.name = "PolishingWorkflowError";
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
  code = "ERR_INVALID_POLISHING_STATE",
) {
  return new PolishingWorkflowError(message, { code });
}

export function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function outputError(message) {
  return workflowError(message, INVALID_OUTPUT_CODE);
}

function assertExactFields(value, fields, name, code) {
  if (
    !isRecord(value) ||
    Object.keys(value).length !== fields.length ||
    Object.keys(value).some((field) => !fields.includes(field))
  ) {
    throw workflowError(`${name} has invalid fields.`, code);
  }
}

function assertStructuredResult(payload) {
  let serialized;
  try {
    serialized = JSON.stringify(payload);
  } catch (cause) {
    throw new PolishingWorkflowError(
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

function normalizeText(value, name, code = "ERR_INVALID_POLISHING_STATE") {
  if (
    typeof value !== "string" ||
    value.trim().length === 0 ||
    value.length > MAX_TEXT_LENGTH ||
    /[\0\p{Cc}\p{Zl}\p{Zp}]/u.test(value)
  ) {
    throw workflowError(`${name} must be concise plain text.`, code);
  }
  return value.trim().replace(/\s+/gu, " ");
}

function normalizeSummary(value, name, code = "ERR_INVALID_POLISHING_STATE") {
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
  { allowEmpty = false, maximum = MAX_ITEMS, code = INVALID_OUTPUT_CODE } = {},
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
      normalizeText(item, `${name}[${index}]`, code),
    ),
  );
}

function emptyArray(value) {
  return Array.isArray(value) && value.length === 0;
}

function emptyDecision(payload) {
  return (
    payload.question === "" &&
    payload.whyBlocked === "" &&
    emptyArray(payload.options) &&
    emptyArray(payload.evidence)
  );
}

function normalizeProductDecision(payload) {
  return Object.freeze({
    question: normalizeText(
      payload.question,
      "product decision question",
      INVALID_OUTPUT_CODE,
    ),
    options: normalizeTextList(payload.options, "product decision options", {
      allowEmpty: true,
      maximum: MAX_OPTIONS,
    }),
    whyBlocked: normalizeText(
      payload.whyBlocked,
      "product decision rationale",
      INVALID_OUTPUT_CODE,
    ),
    evidence: normalizeTextList(
      payload.evidence,
      "product decision evidence",
    ),
  });
}

export function normalizeClarificationResult(payload) {
  const fields = [
    "status",
    "questions",
    "reason",
    "question",
    "options",
    "whyBlocked",
    "evidence",
  ];
  assertExactFields(payload, fields, "Clarification result", INVALID_OUTPUT_CODE);
  assertStructuredResult(payload);
  if (
    !["READY", "QUESTIONS", "PRODUCT_DECISION_REQUIRED"].includes(
      payload.status,
    )
  ) {
    throw outputError("Worker returned an invalid clarification status.");
  }
  if (payload.status === "PRODUCT_DECISION_REQUIRED") {
    if (!emptyArray(payload.questions) || payload.reason !== "") {
      throw outputError("Product decision contains inapplicable fields.");
    }
    return Object.freeze({
      status: payload.status,
      decision: normalizeProductDecision(payload),
    });
  }
  if (payload.reason !== "" || !emptyDecision(payload)) {
    throw outputError("Clarification result contains inapplicable fields.");
  }
  if (!Array.isArray(payload.questions) || payload.questions.length > MAX_ITEMS) {
    throw outputError("Worker returned invalid clarification questions.");
  }
  const questions = Object.freeze(
    payload.questions.map((question, index) => {
      assertExactFields(
        question,
        ["question", "whyItMatters"],
        `Clarification question ${index + 1}`,
        INVALID_OUTPUT_CODE,
      );
      return Object.freeze({
        question: normalizeText(
          question.question,
          `clarification question ${index + 1}`,
          INVALID_OUTPUT_CODE,
        ),
        whyItMatters: normalizeText(
          question.whyItMatters,
          `clarification rationale ${index + 1}`,
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

export function normalizeBootstrapResult(payload, role) {
  const fields = [
    "status",
    "summary",
    "reason",
    "question",
    "options",
    "whyBlocked",
    "evidence",
  ];
  assertExactFields(payload, fields, `${role} bootstrap result`, INVALID_OUTPUT_CODE);
  assertStructuredResult(payload);
  if (!["READY", "PRODUCT_DECISION_REQUIRED"].includes(payload.status)) {
    throw outputError(`${role} returned an invalid bootstrap status.`);
  }
  if (payload.status === "PRODUCT_DECISION_REQUIRED") {
    if (payload.summary !== "" || payload.reason !== "") {
      throw outputError("Product decision contains inapplicable fields.");
    }
    return Object.freeze({
      status: payload.status,
      decision: normalizeProductDecision(payload),
    });
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
  const fields = [
    "status",
    "summary",
    "disagreement",
    "reason",
    "question",
    "options",
    "whyBlocked",
    "evidence",
  ];
  assertExactFields(payload, fields, "Bootstrap reconciliation", INVALID_OUTPUT_CODE);
  assertStructuredResult(payload);
  if (
    !["RESOLVED", "DISAGREEMENT", "PRODUCT_DECISION_REQUIRED"].includes(
      payload.status,
    )
  ) {
    throw outputError("Worker returned an invalid reconciliation status.");
  }
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
  if (payload.status === "RESOLVED") {
    if (
      payload.disagreement !== "" ||
      payload.reason !== "" ||
      !emptyDecision(payload)
    ) {
      throw outputError("Resolved reconciliation contains inapplicable fields.");
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
    throw outputError("Bootstrap disagreement contains inapplicable fields.");
  }
  return Object.freeze({
    status: payload.status,
    disagreement: Object.freeze({
      description: normalizeText(
        payload.disagreement,
        "bootstrap disagreement",
        INVALID_OUTPUT_CODE,
      ),
      evidence: normalizeTextList(
        payload.evidence,
        "bootstrap disagreement evidence",
      ),
    }),
  });
}

export function normalizeBootstrapArbitration(payload) {
  const fields = [
    "direction",
    "summary",
    "rationale",
    "reason",
    "question",
    "options",
    "whyBlocked",
    "evidence",
  ];
  assertExactFields(payload, fields, "Bootstrap arbitration", INVALID_OUTPUT_CODE);
  assertStructuredResult(payload);
  if (
    ![
      "USE_WORKER",
      "USE_REVIEWER",
      "SYNTHESIZE",
      "PRODUCT_DECISION_REQUIRED",
    ].includes(payload.direction)
  ) {
    throw outputError("Arbiter returned an invalid bootstrap direction.");
  }
  const rationale = normalizeText(
    payload.rationale,
    "bootstrap arbitration rationale",
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

export function assertSettings(settings) {
  assertExactFields(settings, SETTINGS_FIELDS, "Polishing settings");
  for (const field of SETTINGS_FIELDS) {
    if (!Number.isSafeInteger(settings[field]) || settings[field] < 1) {
      throw workflowError(`Polishing setting ${field} is invalid.`);
    }
  }
}

function normalizeOptionalSummary(value, name) {
  return value === null ? null : normalizeSummary(value, name);
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
    value.id.length === 0 ||
    !isAbsolute(value.artifactRoot) ||
    !isAbsolute(value.transcriptPath) ||
    !["CLARIFY", "BOOTSTRAP"].includes(value.suspendedState) ||
    !Object.hasOwn(EDIT_PAUSE_REASONS, value.action) ||
    !HASH_PATTERN.test(value.preEditorHash)
  ) {
    throw workflowError("Polishing pending edit is invalid.");
  }
  return value;
}

function normalizeDisagreement(value) {
  if (value === null) {
    return null;
  }
  assertExactFields(
    value,
    ["description", "evidence"],
    "Polishing bootstrap disagreement",
  );
  return Object.freeze({
    description: normalizeText(value.description, "bootstrap disagreement"),
    evidence: normalizeTextList(value.evidence, "bootstrap evidence", {
      code: "ERR_INVALID_POLISHING_STATE",
    }),
  });
}

function assertSnapshot(value) {
  if (
    !isRecord(value) ||
    Object.keys(value).length !== SNAPSHOT_FIELDS.size ||
    Object.keys(value).some((field) => !SNAPSHOT_FIELDS.has(field)) ||
    value.schemaVersion !== 1 ||
    typeof value.projectPath !== "string" ||
    !isAbsolute(value.projectPath) ||
    resolve(value.projectPath) !== value.projectPath ||
    !Array.isArray(value.allowedPaths) ||
    value.allowedPaths.some(
      (path) => typeof path !== "string" || path.length === 0 || isAbsolute(path),
    ) ||
    (value.head !== null && typeof value.head !== "string") ||
    (value.branch !== null && typeof value.branch !== "string") ||
    typeof value.detached !== "boolean" ||
    typeof value.clean !== "boolean" ||
    typeof value.identityAvailable !== "boolean" ||
    [
      "refsFingerprint",
      "trackedContentFingerprint",
      "untrackedContentFingerprint",
      "contentFingerprint",
      "indexFingerprint",
      "remoteConfigurationFingerprint",
      "identityFingerprint",
    ].some((field) => !HASH_PATTERN.test(value[field]))
  ) {
    throw workflowError("Polishing repository baseline is invalid.");
  }
  return value;
}

export function normalizePipelineState(value) {
  if (
    !isRecord(value) ||
    Object.keys(value).length !== PIPELINE_STATE_FIELDS.size ||
    Object.keys(value).some((field) => !PIPELINE_STATE_FIELDS.has(field)) ||
    !WORKFLOW_STATES.includes(value.workflowState)
  ) {
    throw workflowError("Polishing state is invalid.");
  }
  for (const field of [
    "preflightComplete",
    "proactiveClarification",
    "proactiveClarificationComplete",
    "clarificationFrozen",
    "refreezeRequired",
    "bootstrapArbitrationUsed",
  ]) {
    if (typeof value[field] !== "boolean") {
      throw workflowError(`Polishing state field ${field} is invalid.`);
    }
  }
  if (value.settings !== null) {
    assertSettings(value.settings);
  }
  if (
    value.preflightComplete !== (value.repositoryBaseline !== null) ||
    value.preflightComplete !== (value.backendVersions !== null) ||
    value.preflightComplete !== (value.clarificationPath !== null) ||
    (value.preflightComplete && value.settings === null)
  ) {
    throw workflowError("Polishing preflight state is invalid.");
  }
  if (value.repositoryBaseline !== null) {
    assertSnapshot(value.repositoryBaseline);
  }
  if (value.backendVersions !== null) {
    assertExactFields(
      value.backendVersions,
      ROLES,
      "Polishing backend versions",
    );
    if (
      typeof value.backendVersions.worker !== "string" ||
      typeof value.backendVersions.reviewer !== "string" ||
      (value.backendVersions.arbiter !== null &&
        typeof value.backendVersions.arbiter !== "string")
    ) {
      throw workflowError("Polishing backend versions are invalid.");
    }
  }
  if (
    value.clarificationPath !== null &&
    (typeof value.clarificationPath !== "string" ||
      !isAbsolute(value.clarificationPath))
  ) {
    throw workflowError("Polishing clarification path is invalid.");
  }
  const pendingEdit = normalizePendingEdit(value.pendingEdit);
  if (
    pendingEdit !== null &&
    !["WAITING_FOR_USER", "FAILED"].includes(value.workflowState)
  ) {
    throw workflowError("Polishing pending edit is inapplicable.");
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
    throw workflowError("Polishing proactive clarification state is invalid.");
  }
  const workerSummary = normalizeOptionalSummary(
    value.workerSummary,
    "Worker summary",
  );
  const reviewerSummary = normalizeOptionalSummary(
    value.reviewerSummary,
    "Reviewer summary",
  );
  const resolvedSummary = normalizeOptionalSummary(
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
    throw workflowError("Polishing bootstrap context is inconsistent.");
  }
  if (
    value.bootstrapArbitrationUsed &&
    (disagreement !== null ||
      resolvedSummary === null ||
      typeof value.backendVersions?.arbiter !== "string")
  ) {
    throw workflowError("Polishing bootstrap arbitration is inconsistent.");
  }
  if (
    !value.preflightComplete &&
    (value.clarificationFrozen ||
      pendingEdit !== null ||
      value.refreezeRequired ||
      workerSummary !== null ||
      reviewerSummary !== null ||
      resolvedSummary !== null ||
      disagreement !== null ||
      value.bootstrapArbitrationUsed)
  ) {
    throw workflowError("Polishing preflight state is inconsistent.");
  }
  if (
    value.workflowState === "CLARIFY" &&
    (value.clarificationFrozen ||
      value.refreezeRequired ||
      workerSummary !== null ||
      reviewerSummary !== null ||
      resolvedSummary !== null ||
      disagreement !== null)
  ) {
    throw workflowError("Polishing clarification state is inconsistent.");
  }
  if (
    value.workflowState === "BOOTSTRAP" &&
    ((!value.clarificationFrozen && !value.refreezeRequired) ||
      resolvedSummary !== null)
  ) {
    throw workflowError("Polishing bootstrap state is inconsistent.");
  }
  if (
    value.workflowState === "POLISH" &&
    (!value.clarificationFrozen ||
      value.refreezeRequired ||
      resolvedSummary === null ||
      disagreement !== null)
  ) {
    throw workflowError("Polishing prepared state is inconsistent.");
  }
  if (
    !["CLARIFY", "WAITING_FOR_USER", "FAILED"].includes(
      value.workflowState,
    ) &&
    !value.preflightComplete
  ) {
    throw workflowError("Polishing state has not completed preflight.");
  }
  return value;
}

export function createPolishingState({
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
    backendVersions: null,
    proactiveClarification,
    proactiveClarificationComplete: !proactiveClarification,
    clarificationPath: null,
    clarificationFrozen: false,
    pendingEdit: null,
    refreezeRequired: false,
    workerSummary: null,
    reviewerSummary: null,
    resolvedSummary: null,
    bootstrapDisagreement: null,
    bootstrapArbitrationUsed: false,
  });
}

export function normalizedCounters(counters) {
  if (
    !isRecord(counters) ||
    Object.keys(counters).some((field) => !COUNTER_FIELDS.includes(field))
  ) {
    throw workflowError("Polishing counters are invalid.");
  }
  const normalized = Object.fromEntries(
    COUNTER_FIELDS.map((field) => {
      const value = Object.hasOwn(counters, field) ? counters[field] : 0;
      if (!Number.isSafeInteger(value) || value < 0) {
        throw workflowError(`Polishing counter ${field} is invalid.`);
      }
      return [field, value];
    }),
  );
  return Object.freeze(normalized);
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

function assertInputRequest(run, state) {
  const request = run.pause?.inputRequest;
  if (state.pendingEdit === null) {
    if (request !== undefined || run.pause?.inputResponse !== undefined) {
      throw workflowError("Polishing input pause is invalid.");
    }
    return;
  }
  if (request === undefined) {
    return;
  }
  if (
    !isRecord(request) ||
    request.id !== state.pendingEdit.id ||
    request.artifactPath !== state.pendingEdit.transcriptPath ||
    !["clarification", "product-decision"].includes(request.kind) ||
    !Array.isArray(request.questions)
  ) {
    throw workflowError("Polishing input request is invalid.");
  }
}

export function assertRun(run) {
  if (
    !isRecord(run) ||
    typeof run.runId !== "string" ||
    !RUN_ID_PATTERN.test(run.runId) ||
    run.pipelineId !== "polishing" ||
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
    throw workflowError("Polishing run envelope is invalid.");
  }
  assertExactFields(run.roles, ROLES, "Polishing roles");
  for (const role of ROLES) {
    assertExactFields(
      run.roles[role],
      ["backend", "model"],
      `Polishing role ${role}`,
    );
    if (
      typeof run.roles[role].backend !== "string" ||
      run.roles[role].backend.length === 0 ||
      (run.roles[role].model !== null &&
        (typeof run.roles[role].model !== "string" ||
          run.roles[role].model.length === 0))
    ) {
      throw workflowError(`Polishing role ${role} is invalid.`);
    }
  }
  if (
    run.sessionLineage.source !== null &&
    (typeof run.sessionLineage.source !== "string" ||
      run.sessionLineage.source.length === 0)
  ) {
    throw workflowError("Polishing source session is invalid.");
  }
  const sessionIds = [];
  for (const child of run.sessionLineage.children) {
    if (
      !isRecord(child) ||
      !ROLES.includes(child.role) ||
      typeof child.sessionId !== "string" ||
      child.sessionId.length === 0 ||
      child.sessionId === run.sessionLineage.source
    ) {
      throw workflowError("Polishing child session is invalid.");
    }
    sessionIds.push(child.sessionId);
  }
  if (new Set(sessionIds).size !== sessionIds.length) {
    throw workflowError("Polishing child sessions must be unique.");
  }
  const state = normalizePipelineState(run.pipelineState);
  if (state.repositoryBaseline !== null) {
    const repositoryPath = state.repositoryBaseline.projectPath;
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
      (repositoryPath !== run.projectPath &&
        repositoryRelativePath(repositoryPath, run.projectPath) === null) ||
      state.clarificationPath !== expectedClarificationPath ||
      state.repositoryBaseline.allowedPaths.length !== 1 ||
      state.repositoryBaseline.allowedPaths[0] !== expectedAllowedPath
    ) {
      throw workflowError("Polishing repository baseline is invalid.");
    }
  }
  if (
    state.pendingEdit !== null &&
    (state.pendingEdit.artifactRoot !== state.repositoryBaseline?.projectPath ||
      state.pendingEdit.transcriptPath !== state.clarificationPath ||
      state.pendingEdit.preEditorHash !== run.hashes.executionClarifications)
  ) {
    throw workflowError("Polishing pending edit boundary is invalid.");
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
    throw workflowError("Polishing pause state is invalid.");
  }
  if (state.workflowState === "WAITING_FOR_USER") {
    const expectedReason = EDIT_PAUSE_REASONS[state.pendingEdit?.action];
    if (
      (state.pendingEdit === null &&
        Object.values(EDIT_PAUSE_REASONS).includes(run.pause.reason)) ||
      (state.pendingEdit !== null &&
        (run.pause.authorizationId !== state.pendingEdit.id ||
          run.pause.reason !== expectedReason))
    ) {
      throw workflowError("Polishing pending edit pause is invalid.");
    }
  }
  assertInputRequest(run, state);
  const hashFields = [
    "task",
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
        (run.hashes.taskClarifications !== null &&
          !HASH_PATTERN.test(run.hashes.taskClarifications)) ||
        (run.hashes.context !== null &&
          !HASH_PATTERN.test(run.hashes.context)) ||
        !HASH_PATTERN.test(run.hashes.executionClarifications)))
  ) {
    throw workflowError("Polishing input hashes are invalid.");
  }
  const counters = normalizedCounters(run.counters);
  if (counters.clarificationRounds > MAX_CLARIFICATION_ROUNDS) {
    throw workflowError("Polishing clarification progress is invalid.");
  }
}

export function assertRuntime(runtime) {
  if (
    !isRecord(runtime) ||
    !isRecord(runtime.adapters) ||
    !isRecord(runtime.clarifications) ||
    !isRecord(runtime.git)
  ) {
    throw workflowError("Polishing runtime is invalid.");
  }
  for (const role of ROLES) {
    if (
      typeof runtime.adapters[role]?.probe !== "function" ||
      typeof runtime.adapters[role]?.run !== "function"
    ) {
      throw workflowError(`Polishing ${role} adapter is invalid.`);
    }
  }
  for (const name of [
    "readInputs",
    "recordChildSession",
    "transition",
    "writeRunArtifact",
  ]) {
    if (typeof runtime[name] !== "function") {
      throw workflowError(`Polishing runtime.${name} is invalid.`);
    }
  }
  for (const name of [
    "assertUnchanged",
    "inspectPath",
    "preflight",
    "snapshot",
  ]) {
    if (typeof runtime.git[name] !== "function") {
      throw workflowError(`Polishing Git service.${name} is invalid.`);
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
      throw workflowError(`Polishing clarification service.${name} is invalid.`);
    }
  }
}

export function normalizeAdapterCapabilities(value, role, sourceSession) {
  if (
    !isRecord(value) ||
    typeof value.version !== "string" ||
    value.version.length === 0
  ) {
    throw workflowError(
      `${role} backend returned invalid capabilities.`,
      "ERR_UNSUPPORTED_POLISHING_BACKEND",
    );
  }
  const required =
    role === "worker"
      ? [
          "structuredOutput",
          "readOnly",
          "autonomousWrite",
          "workspaceWrite",
          "remoteWriteBlocked",
        ]
      : ["structuredOutput", "readOnly", "remoteWriteBlocked"];
  if (sourceSession !== null && role !== "arbiter") {
    required.push("nativeSessionFork");
  }
  if (required.some((field) => value[field] !== true)) {
    throw workflowError(
      `${role} backend cannot enforce the required capabilities.`,
      "ERR_UNSUPPORTED_POLISHING_BACKEND",
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
    !HASH_PATTERN.test(value.hash) ||
    value.hash !== sha256(value.content)
  ) {
    throw workflowError(`${name} input snapshot is invalid.`);
  }
  if (!optional && value.content.trim().length === 0) {
    throw workflowError(`${name} must not be empty.`, INVALID_POLISHING_INPUT_CODE);
  }
  return value;
}

export function normalizeInputSnapshot(value, taskPath) {
  assertExactFields(
    value,
    ["task", "taskClarifications", "context"],
    "Polishing input snapshot",
  );
  return Object.freeze({
    task: assertInputFile(value.task, join(taskPath, "task.md"), "task.md"),
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

export function activity(actor, phase, kind, message) {
  return Object.freeze({ actor, phase, kind, message });
}

export function diagnosticCode(cause, fallback) {
  return typeof cause?.code === "string" && cause.code.length > 0
    ? cause.code
    : fallback;
}
