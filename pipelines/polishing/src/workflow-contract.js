import { createHash } from "node:crypto";
import { isAbsolute, join, posix, relative, resolve, sep } from "node:path";
import { isDeepStrictEqual } from "node:util";

export const MAX_CLARIFICATION_ROUNDS = 3;
export const DEFAULT_FINALIZATION_POLICY = "auto";
export const CONVENTIONAL_FINALIZATION_SKILL_PATHS = Object.freeze([
  ".agents/skills/finalization/SKILL.md",
  ".claude/skills/finalization/SKILL.md",
]);
export const WORKFLOW_STATES = Object.freeze([
  "CLARIFY",
  "BOOTSTRAP",
  "POLISH",
  "FINALIZE",
  "REVIEW",
  "RESOLVE_FINDINGS",
  "HANDOFF",
  "WAITING_FOR_USER",
  "DONE",
  "FAILED",
]);

const ROLES = Object.freeze(["worker", "reviewer", "arbiter"]);
const SETTINGS_FIELDS = Object.freeze([
  "finalization",
  "maxFixRounds",
  "maxDisputesPerFinding",
  "maxSameFindingRounds",
  "stagnationWindowRounds",
  "trustedChecks",
]);
const NUMERIC_SETTINGS_FIELDS = SETTINGS_FIELDS.filter(
  (field) => !["finalization", "trustedChecks"].includes(field),
);
const COUNTER_FIELDS = Object.freeze([
  "clarificationRounds",
  "productDecisions",
  "fixRounds",
  "correctionRounds",
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
  "refreezeRequired",
  "workerSummary",
  "reviewerSummary",
  "workerValidation",
  "reviewerValidation",
  "resolvedSummary",
  "bootstrapDisagreement",
  "bootstrapArbitrationUsed",
  "bootstrapCorrections",
  "pendingBootstrapCorrection",
  "polishSummary",
  "finalizationResult",
  "finalizedFingerprint",
  "requiredChecks",
  "validationInfrastructure",
  "validationInfrastructureFingerprint",
  "trustedValidation",
  "validationMigrationPending",
  "validationMigrationDisagreement",
  "reviewResult",
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
const REVIEW_FINDING_ID_PATTERN = /^R[1-9][0-9]{0,8}$/u;
const FINALIZATION_ISSUE_ID_PATTERN = /^F[1-9][0-9]{0,8}$/u;
const REQUIRED_CHECK_ID_PATTERN = /^C[1-9][0-9]{0,8}$/u;
const PERSISTED_CHECK_RESULT_FIELDS = Object.freeze([
  "checkId",
  "command",
  "status",
  "evidence",
  "executor",
  "commandIdentity",
  "exitCode",
  "signal",
  "timedOut",
]);
const REQUIRED_CHECK_FIELDS = Object.freeze(["id", "command"]);
const INDEX_WRITING_GIT_COMMANDS = new Set([
  "add",
  "am",
  "checkout",
  "checkout-index",
  "cherry-pick",
  "clean",
  "commit",
  "commit-tree",
  "merge",
  "merge-index",
  "read-tree",
  "rebase",
  "reset",
  "restore",
  "revert",
  "rm",
  "stash",
  "switch",
  "update-index",
  "write-tree",
]);
const INDEX_INSPECTING_GIT_COMMANDS = new Set([
  "diff-files",
  "diff-index",
  "ls-files",
  "status",
]);
const SHELL_SEPARATOR_PATTERN = /^[;&|()<>]$/u;
const EXPLICIT_TREE_PATTERN =
  /^(?:HEAD(?:[~^][0-9]*)*|[a-f0-9]{7,64}|refs\/(?:heads|remotes|tags)\/[^\s]+)$/iu;
const TRUSTED_COMMAND_FIELDS = Object.freeze([
  "alias",
  "command",
  "executable",
  "arguments",
  "identity",
]);
const TRUSTED_VALIDATION_FIELDS = Object.freeze([
  "schemaVersion",
  "commands",
  "commandFingerprint",
  "configurationFingerprint",
]);
const TRUSTED_ALIAS_PATTERN = /^[a-z][a-z0-9-]{0,63}$/u;
const ADAPTER_DIAGNOSTIC_CLASS_PATTERN = /^[a-z][a-z0-9_]{0,63}$/u;
const FAILURE_FIELDS = Object.freeze(["reason", "code"]);
const ADAPTER_FAILURE_FIELDS = Object.freeze([
  ...FAILURE_FIELDS,
  "diagnosticClass",
]);
export const MAX_TEXT_LENGTH = 4_000;
export const MAX_SUMMARY_LENGTH = 20_000;
export const MAX_ITEMS = 32;
export const MAX_BOOTSTRAP_ITEMS = MAX_ITEMS * 2;
export const MAX_VALIDATION_ITEMS = MAX_BOOTSTRAP_ITEMS * 2;
export const MAX_OPTIONS = 16;
const MAX_STRUCTURED_RESULT_BYTES = 256 * 1024;
export const MAX_DURABLE_RUN_BYTES = 960 * 1024;
export const MAX_DIAGNOSTIC_ITEMS = 32;
export const MAX_DISPUTE_HISTORY_BYTES = 64 * 1024;
export const MAX_DISPUTES_PER_FINDING = 2;
const INVALID_OUTPUT_CODE = "ERR_INVALID_POLISHING_OUTPUT";
export const INVALID_POLISHING_INPUT_CODE = "ERR_INVALID_POLISHING_INPUT";
const OUTPUT_DIAGNOSTIC_FIELDS = Object.freeze([
  "role",
  "phase",
  "contract",
  "field",
  "constraint",
]);
const LEGACY_OUTPUT_FAILURE_FIELDS = Object.freeze(["reason", "code"]);
const OUTPUT_FAILURE_FIELDS = Object.freeze([
  ...LEGACY_OUTPUT_FAILURE_FIELDS,
  "diagnostic",
]);
const OUTPUT_DIAGNOSTIC_VALUE_PATTERN = /^[a-zA-Z0-9_.[\]-]{1,128}$/u;
const BOOTSTRAP_CORRECTION_FIELDS = Object.freeze([
  "attempt",
  ...OUTPUT_DIAGNOSTIC_FIELDS,
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
    "POLISH",
    "FINALIZE",
    "REVIEW",
    "RESOLVE_FINDINGS",
  ]),
  environment_blocked: Object.freeze([
    "POLISH",
    "FINALIZE",
    "RESOLVE_FINDINGS",
  ]),
  finalization_cannot_pass: Object.freeze(["FINALIZE"]),
  finalization_skill_invalid: Object.freeze(["FINALIZE"]),
  finalization_skill_missing: Object.freeze(["FINALIZE"]),
  fix_limit_reached: Object.freeze(["POLISH", "RESOLVE_FINDINGS"]),
  no_progress: Object.freeze(["RESOLVE_FINDINGS"]),
});

export class PolishingWorkflowError extends Error {
  constructor(
    message,
    { cause, code = "ERR_POLISHING_WORKFLOW", diagnostic } = {},
  ) {
    super(message, cause === undefined ? undefined : { cause });
    this.name = "PolishingWorkflowError";
    this.code = code;
    if (diagnostic !== undefined) {
      this.diagnostic = Object.freeze({ ...diagnostic });
    }
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
  diagnostic,
) {
  return new PolishingWorkflowError(message, { code, diagnostic });
}

export function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function trustedCommandIdentity(command) {
  return sha256(
    JSON.stringify({
      alias: command.alias,
      command: command.command,
      executable: command.executable,
      arguments: command.arguments,
    }),
  );
}

function trustedValidationFingerprints(commands) {
  return Object.freeze({
    commandFingerprint: sha256(
      JSON.stringify(commands.map(({ identity }) => identity)),
    ),
    configurationFingerprint: sha256(
      JSON.stringify({
        schemaVersion: 1,
        commands: commands.map(
          ({ alias, command, executable, arguments: argumentsList }) => ({
            alias,
            command,
            executable,
            arguments: argumentsList,
          }),
        ),
      }),
    ),
  });
}

function normalizeExactVectorText(
  value,
  name,
  { allowEmpty = false, requireTrimmed = false } = {},
) {
  if (
    typeof value !== "string" ||
    (!allowEmpty && value.length === 0) ||
    [...value].length > MAX_TEXT_LENGTH ||
    /[\0\p{Cc}\p{Zl}\p{Zp}]/u.test(value) ||
    (requireTrimmed && value.trim() !== value)
  ) {
    throw workflowError(`${name} is invalid.`);
  }
  return value;
}

function normalizeTrustedValidation(value) {
  if (
    !isRecord(value) ||
    Object.keys(value).length !== TRUSTED_VALIDATION_FIELDS.length ||
    TRUSTED_VALIDATION_FIELDS.some((field) => !Object.hasOwn(value, field)) ||
    value.schemaVersion !== 1 ||
    !Array.isArray(value.commands) ||
    value.commands.length > MAX_ITEMS ||
    !HASH_PATTERN.test(value.commandFingerprint) ||
    !HASH_PATTERN.test(value.configurationFingerprint)
  ) {
    throw workflowError("Polishing trusted validation is invalid.");
  }
  const commands = Object.freeze(
    value.commands.map((command, index) => {
      if (
        !isRecord(command) ||
        Object.keys(command).length !== TRUSTED_COMMAND_FIELDS.length ||
        TRUSTED_COMMAND_FIELDS.some((field) =>
          !Object.hasOwn(command, field)
        ) ||
        !TRUSTED_ALIAS_PATTERN.test(command.alias) ||
        !Array.isArray(command.arguments) ||
        command.arguments.length > 64 ||
        !HASH_PATTERN.test(command.identity)
      ) {
        throw workflowError(
          `Polishing trusted command ${index + 1} is invalid.`,
        );
      }
      const normalized = Object.freeze({
        alias: command.alias,
        command: normalizeExactVectorText(
          command.command,
          `trusted command ${command.alias} command`,
          { requireTrimmed: true },
        ),
        executable: normalizeExactVectorText(
          command.executable,
          `trusted command ${command.alias} executable`,
          { requireTrimmed: true },
        ),
        arguments: Object.freeze(
          command.arguments.map((argument) =>
            normalizeExactVectorText(
              argument,
              `trusted command ${command.alias} argument`,
              { allowEmpty: true },
            ),
          ),
        ),
        identity: command.identity,
      });
      if (trustedCommandIdentity(normalized) !== command.identity) {
        throw workflowError(
          `Polishing trusted command ${command.alias} identity is invalid.`,
        );
      }
      return normalized;
    }),
  );
  if (
    new Set(commands.map(({ alias }) => alias)).size !== commands.length ||
    new Set(commands.map(({ command }) => command)).size !== commands.length ||
    new Set(commands.map(({ identity }) => identity)).size !== commands.length
  ) {
    throw workflowError("Polishing trusted commands must be unique.");
  }
  const fingerprints = trustedValidationFingerprints(commands);
  if (
    value.commandFingerprint !== fingerprints.commandFingerprint ||
    value.configurationFingerprint !== fingerprints.configurationFingerprint
  ) {
    throw workflowError("Polishing trusted validation fingerprint is invalid.");
  }
  return Object.freeze({ schemaVersion: 1, commands, ...fingerprints });
}

export const EMPTY_TRUSTED_VALIDATION = Object.freeze(
  normalizeTrustedValidation({
    schemaVersion: 1,
    commands: Object.freeze([]),
    ...trustedValidationFingerprints([]),
  }),
);

function serializedBytes(value) {
  try {
    const serialized = JSON.stringify(value);
    return typeof serialized === "string"
      ? Buffer.byteLength(serialized)
      : Number.POSITIVE_INFINITY;
  } catch {
    return Number.POSITIVE_INFINITY;
  }
}

export function disputeHistoryFits(value) {
  return serializedBytes(value) <= MAX_DISPUTE_HISTORY_BYTES;
}

export function assertDisputeHistoryFits(
  value,
  code = "ERR_INVALID_POLISHING_STATE",
) {
  if (!disputeHistoryFits(value)) {
    throw workflowError(
      "Polishing dispute evidence exceeds its durable history limit.",
      code,
    );
  }
}

function outputConstraint(field, constraint) {
  return Object.freeze({ field, constraint });
}

function outputError(message, diagnostic) {
  return workflowError(message, INVALID_OUTPUT_CODE, diagnostic);
}

export function isOutputDiagnostic(value) {
  return (
    isRecord(value) &&
    Object.keys(value).length === OUTPUT_DIAGNOSTIC_FIELDS.length &&
    OUTPUT_DIAGNOSTIC_FIELDS.every(
      (field) =>
        typeof value[field] === "string" &&
        OUTPUT_DIAGNOSTIC_VALUE_PATTERN.test(value[field]),
    )
  );
}

function hasExactFields(value, fields) {
  return (
    isRecord(value) &&
    Object.keys(value).length === fields.length &&
    fields.every((field) => Object.hasOwn(value, field))
  );
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

function assertExactOutputFields(value, fields, field = "result") {
  if (!hasExactFields(value, fields)) {
    throw outputError(
      "Structured role result has an invalid field set.",
      outputConstraint(field, "exact-field-set"),
    );
  }
}

function assertStructuredResult(payload, diagnostic) {
  let serialized;
  try {
    serialized = JSON.stringify(payload);
  } catch {
    throw outputError(
      "Structured role result must be serializable.",
      outputConstraint("result", "serializable-json"),
    );
  }
  if (
    typeof serialized !== "string" ||
    Buffer.byteLength(serialized) > MAX_STRUCTURED_RESULT_BYTES
  ) {
    throw outputError("Structured role result is too large.", diagnostic);
  }
}

function normalizeText(
  value,
  name,
  code = "ERR_INVALID_POLISHING_STATE",
  diagnostic,
) {
  if (
    typeof value !== "string" ||
    value.trim().length === 0 ||
    value.length > MAX_TEXT_LENGTH ||
    /[\0\p{Cc}\p{Zl}\p{Zp}]/u.test(value)
  ) {
    throw workflowError(`${name} must be concise plain text.`, code, diagnostic);
  }
  return value.trim().replace(/\s+/gu, " ");
}

function normalizeSummary(
  value,
  name,
  code = "ERR_INVALID_POLISHING_STATE",
  diagnostic,
) {
  if (
    typeof value !== "string" ||
    value.trim().length === 0 ||
    value.length > MAX_SUMMARY_LENGTH ||
    /\0|\p{Zl}|\p{Zp}/u.test(value)
  ) {
    throw workflowError(`${name} must be concise Markdown.`, code, diagnostic);
  }
  return value.trim();
}

function normalizeTextList(
  value,
  name,
  {
    allowEmpty = false,
    maximum = MAX_ITEMS,
    code = INVALID_OUTPUT_CODE,
    diagnosticField,
  } = {},
) {
  if (
    !Array.isArray(value) ||
    (!allowEmpty && value.length === 0) ||
    value.length > maximum
  ) {
    throw workflowError(
      `${name} has an invalid number of items.`,
      code,
      diagnosticField === undefined
        ? undefined
        : outputConstraint(
            diagnosticField,
            `${allowEmpty ? "array" : "nonempty-array"}-up-to-${maximum}-items`,
          ),
    );
  }
  return Object.freeze(
    value.map((item, index) =>
      normalizeText(
        item,
        `${name}[${index}]`,
        code,
        diagnosticField === undefined
          ? undefined
          : outputConstraint(
              `${diagnosticField}[${index}]`,
              "nonempty-plain-text-up-to-4000-characters",
            ),
      ),
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
    "requiredChecks",
    "validationInfrastructure",
    "capacityField",
    "capacityLimit",
    "reason",
    "question",
    "options",
    "whyBlocked",
    "evidence",
  ];
  if (
    !isRecord(payload) ||
    !["READY", "CAPACITY_EXHAUSTED", "PRODUCT_DECISION_REQUIRED"].includes(
      payload.status,
    )
  ) {
    throw outputError(
      `${role} returned an invalid bootstrap status.`,
      outputConstraint("status", "supported-status"),
    );
  }
  assertStructuredResult(
    payload,
    outputConstraint("result", "maximum-256-kibibytes"),
  );
  assertExactOutputFields(payload, fields);
  if (payload.status === "CAPACITY_EXHAUSTED") {
    if (
      payload.summary !== "" ||
      !emptyArray(payload.requiredChecks) ||
      !emptyArray(payload.validationInfrastructure) ||
      payload.reason !== "" ||
      !emptyDecision(payload) ||
      !["requiredChecks", "validationInfrastructure"].includes(
        payload.capacityField,
      ) ||
      payload.capacityLimit !== MAX_BOOTSTRAP_ITEMS
    ) {
      throw outputError(
        "Bootstrap capacity result contains inapplicable fields.",
        outputConstraint("status", "status-field-consistency"),
      );
    }
    return Object.freeze({
      status: payload.status,
      capacityField: payload.capacityField,
      capacityLimit: payload.capacityLimit,
    });
  }
  if (payload.capacityField !== "" || payload.capacityLimit !== 0) {
    throw outputError(
      "Bootstrap result contains inapplicable capacity fields.",
      outputConstraint("status", "status-field-consistency"),
    );
  }
  if (payload.status === "PRODUCT_DECISION_REQUIRED") {
    if (
      payload.summary !== "" ||
      payload.reason !== "" ||
      !emptyArray(payload.requiredChecks) ||
      !emptyArray(payload.validationInfrastructure)
    ) {
      throw outputError(
        "Product decision contains inapplicable fields.",
        outputConstraint("status", "status-field-consistency"),
      );
    }
    return Object.freeze({
      status: payload.status,
      decision: normalizeProductDecision(payload),
    });
  }
  if (payload.reason !== "" || !emptyDecision(payload)) {
    throw outputError(
      "Bootstrap result contains inapplicable fields.",
      outputConstraint("status", "status-field-consistency"),
    );
  }
  return Object.freeze({
    status: payload.status,
    summary: normalizeSummary(
      payload.summary,
      `${role} bootstrap summary`,
      INVALID_OUTPUT_CODE,
      outputConstraint("summary", "concise-markdown-up-to-20000-characters"),
    ),
    requiredChecks: normalizePhaseSafeRequiredChecks(
      payload.requiredChecks,
      INVALID_OUTPUT_CODE,
      { maxItems: MAX_BOOTSTRAP_ITEMS },
    ),
    validationInfrastructure: normalizeValidationInfrastructure(
      payload.validationInfrastructure,
      INVALID_OUTPUT_CODE,
      { maxItems: MAX_BOOTSTRAP_ITEMS },
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
  if (
    !isRecord(payload) ||
    !["RESOLVED", "DISAGREEMENT", "PRODUCT_DECISION_REQUIRED"].includes(
      payload.status,
    )
  ) {
    throw outputError(
      "Worker returned an invalid reconciliation status.",
      outputConstraint("status", "supported-status"),
    );
  }
  assertStructuredResult(
    payload,
    outputConstraint("result", "maximum-256-kibibytes"),
  );
  assertExactOutputFields(payload, fields);
  if (payload.status === "PRODUCT_DECISION_REQUIRED") {
    if (
      payload.summary !== "" ||
      payload.disagreement !== "" ||
      payload.reason !== ""
    ) {
      throw outputError(
        "Product decision contains inapplicable fields.",
        outputConstraint("status", "status-field-consistency"),
      );
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
      throw outputError(
        "Resolved reconciliation contains inapplicable fields.",
        outputConstraint("status", "status-field-consistency"),
      );
    }
    return Object.freeze({
      status: payload.status,
      summary: normalizeSummary(
        payload.summary,
        "resolved bootstrap summary",
        INVALID_OUTPUT_CODE,
        outputConstraint("summary", "concise-markdown-up-to-20000-characters"),
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
    throw outputError(
      "Bootstrap disagreement contains inapplicable fields.",
      outputConstraint("status", "status-field-consistency"),
    );
  }
  return Object.freeze({
    status: payload.status,
    disagreement: Object.freeze({
      description: normalizeText(
        payload.disagreement,
        "bootstrap disagreement",
        INVALID_OUTPUT_CODE,
        outputConstraint(
          "disagreement",
          "nonempty-plain-text-up-to-4000-characters",
        ),
      ),
      evidence: normalizeTextList(
        payload.evidence,
        "bootstrap disagreement evidence",
        { code: INVALID_OUTPUT_CODE, diagnosticField: "evidence" },
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
  if (
    !isRecord(payload) ||
    ![
      "USE_WORKER",
      "USE_REVIEWER",
      "SYNTHESIZE",
      "PRODUCT_DECISION_REQUIRED",
    ].includes(payload.direction)
  ) {
    throw outputError(
      "Arbiter returned an invalid bootstrap direction.",
      outputConstraint("direction", "supported-direction"),
    );
  }
  assertStructuredResult(
    payload,
    outputConstraint("result", "maximum-256-kibibytes"),
  );
  assertExactOutputFields(payload, fields);
  const rationale = normalizeText(
    payload.rationale,
    "bootstrap arbitration rationale",
    INVALID_OUTPUT_CODE,
    outputConstraint(
      "rationale",
      "nonempty-plain-text-up-to-4000-characters",
    ),
  );
  if (payload.direction === "PRODUCT_DECISION_REQUIRED") {
    if (
      payload.summary !== "" ||
      payload.reason !== ""
    ) {
      throw outputError(
        "Product decision contains inapplicable fields.",
        outputConstraint("direction", "direction-field-consistency"),
      );
    }
    return Object.freeze({
      direction: payload.direction,
      rationale,
      decision: normalizeProductDecision(payload),
    });
  }
  if (payload.reason !== "" || !emptyDecision(payload)) {
    throw outputError(
      "Bootstrap arbitration contains inapplicable fields.",
      outputConstraint("direction", "direction-field-consistency"),
    );
  }
  return Object.freeze({
    direction: payload.direction,
    rationale,
    summary: normalizeSummary(
      payload.summary,
      "arbitrated bootstrap summary",
      INVALID_OUTPUT_CODE,
      outputConstraint("summary", "concise-markdown-up-to-20000-characters"),
    ),
  });
}

function normalizeOptionalEvidence(value, name, code = INVALID_OUTPUT_CODE) {
  return normalizeTextList(value, name, { allowEmpty: true, code });
}

function normalizeRelativePath(value, name, code = INVALID_OUTPUT_CODE) {
  const path = normalizeText(value, name, code);
  if (
    isAbsolute(path) ||
    path === "." ||
    path.split(/[\\/]/u).some((part) => part === "..")
  ) {
    throw workflowError(`${name} must be repository-relative.`, code);
  }
  return path;
}

function normalizeExactCommand(value, name, code, diagnostic) {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > MAX_TEXT_LENGTH ||
    value.trim() !== value ||
    /[\0\p{Cc}\p{Zl}\p{Zp}]/u.test(value)
  ) {
    throw workflowError(
      `${name} must be an exact single-line command.`,
      code,
      diagnostic,
    );
  }
  return value;
}

function shellWords(command) {
  const words = [];
  let word = "";
  let quote = null;
  let escaped = false;
  function finishWord() {
    if (word.length > 0) {
      words.push(word);
      word = "";
    }
  }
  for (const character of command) {
    if (escaped) {
      word += character;
      escaped = false;
    } else if (character === "\\" && quote !== "'") {
      escaped = true;
    } else if (quote !== null) {
      if (character === quote) {
        quote = null;
      } else {
        word += character;
      }
    } else if (character === "'" || character === '"') {
      quote = character;
    } else if (/\s/u.test(character)) {
      finishWord();
    } else if (SHELL_SEPARATOR_PATTERN.test(character)) {
      finishWord();
      words.push(character);
    } else {
      word += character;
    }
  }
  finishWord();
  return words.flatMap((candidate) =>
    /\s/u.test(candidate) ? shellWords(candidate) : candidate,
  );
}

function gitSubcommand(words, gitIndex) {
  let index = gitIndex + 1;
  while (index < words.length && !SHELL_SEPARATOR_PATTERN.test(words[index])) {
    const word = words[index];
    if (
      [
        "-C",
        "-c",
        "--config-env",
        "--git-dir",
        "--namespace",
        "--work-tree",
      ].includes(word)
    ) {
      index += 2;
    } else if (word.startsWith("-")) {
      index += 1;
    } else {
      return Object.freeze({ command: word.toLowerCase(), index });
    }
  }
  return null;
}

function diffUsesExplicitTrees(words, commandIndex) {
  for (let index = commandIndex + 1; index < words.length; index += 1) {
    const word = words[index];
    if (SHELL_SEPARATOR_PATTERN.test(word)) {
      break;
    }
    if (word === "--no-index" || EXPLICIT_TREE_PATTERN.test(word)) {
      return true;
    }
  }
  return false;
}

function gitArgumentsUseIndex(words, commandIndex) {
  const argumentsList = [];
  for (let index = commandIndex + 1; index < words.length; index += 1) {
    if (SHELL_SEPARATOR_PATTERN.test(words[index])) {
      break;
    }
    argumentsList.push(words[index]);
  }
  return (
    argumentsList.some(
      (word) =>
        /^:(?:[0-3]:)?[^/]/u.test(word) ||
        [
          "--3way",
          "--index",
          "--intent-to-add",
          "--ita-invisible-in-index",
          "--ita-visible-in-index",
        ].includes(word),
    ) ||
    argumentsList.some(
      (word, index) =>
        word === "--git-path" && argumentsList[index + 1] === "index",
    )
  );
}

function isStagingIndependentCommand(command) {
  if (
    /(?:^|[^a-zA-Z0-9_])GIT_INDEX_FILE\s*=/u.test(command) ||
    /(?:^|[\s'"(])(?:\.git|\$GIT_DIR)\/index(?:$|[\s'"),;&|])/u.test(
      command,
    ) ||
    /(?:^|[\s'"=])--(?:cached|staged)(?:$|[\s'",);&|])/iu.test(command) ||
    /(?:draft|prepare)[-_:]?commit(?:[-_:]?(?:msg|message))?/iu.test(command)
  ) {
    return false;
  }
  const words = shellWords(command);
  for (const [index, word] of words.entries()) {
    if (!/(?:^|\/)git$/iu.test(word)) {
      continue;
    }
    const subcommand = gitSubcommand(words, index);
    if (subcommand === null) {
      continue;
    }
    if (
      INDEX_WRITING_GIT_COMMANDS.has(subcommand.command) ||
      INDEX_INSPECTING_GIT_COMMANDS.has(subcommand.command) ||
      gitArgumentsUseIndex(words, subcommand.index) ||
      (subcommand.command === "diff" &&
        !diffUsesExplicitTrees(words, subcommand.index))
    ) {
      return false;
    }
  }
  return true;
}

function normalizePhaseSafeRequiredChecks(value, code, options) {
  const checks = normalizeRequiredChecks(value, code, options);
  for (const [index, check] of checks.entries()) {
    if (!isStagingIndependentCommand(check.command)) {
      throw workflowError(
        "Required check must be staging-independent.",
        code,
        outputConstraint(
          `requiredChecks[${index}].command`,
          "staging-independent-validation-command",
        ),
      );
    }
  }
  return checks;
}

function normalizeValidationInfrastructurePath(value, name, code, diagnostic) {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > MAX_TEXT_LENGTH ||
    value.trim() !== value ||
    value.includes("\\") ||
    value.endsWith("/") ||
    /^[a-zA-Z]:\//u.test(value) ||
    /[\0\p{Cc}\p{Zl}\p{Zp}]/u.test(value) ||
    posix.isAbsolute(value) ||
    posix.normalize(value) !== value ||
    value === "." ||
    value === ".git" ||
    value.startsWith(".git/") ||
    value.split("/").some((part) => part === "..")
  ) {
    throw workflowError(
      `${name} must be an exact repository-relative path.`,
      code,
      diagnostic,
    );
  }
  return value;
}

function normalizeRequiredChecks(
  value,
  code,
  { allowEmpty = false, maxItems = MAX_VALIDATION_ITEMS } = {},
) {
  if (
    !Array.isArray(value) ||
    (!allowEmpty && value.length === 0) ||
    value.length > maxItems
  ) {
    throw workflowError(
      "Required-check inventory is invalid.",
      code,
      outputConstraint(
        "requiredChecks",
        allowEmpty
          ? `array-up-to-${maxItems}-items`
          : `nonempty-array-up-to-${maxItems}-items`,
      ),
    );
  }
  const checks = Object.freeze(
    value.map((check, index) => {
      if (!hasExactFields(check, REQUIRED_CHECK_FIELDS)) {
        throw workflowError(
          "Required check has an invalid field set.",
          code,
          outputConstraint(`requiredChecks[${index}]`, "exact-field-set"),
        );
      }
      if (!REQUIRED_CHECK_ID_PATTERN.test(check.id)) {
        throw workflowError(
          "Required check has an invalid ID.",
          code,
          outputConstraint(`requiredChecks[${index}].id`, "required-check-id"),
        );
      }
      return Object.freeze({
        id: check.id,
        command: normalizeExactCommand(
          check.command,
          `required check ${check.id} command`,
          code,
          outputConstraint(
            `requiredChecks[${index}].command`,
            "exact-single-line-command-up-to-4000-characters",
          ),
        ),
      });
    }),
  );
  if (
    new Set(checks.map(({ id }) => id)).size !== checks.length ||
    new Set(checks.map(({ command }) => command)).size !== checks.length
  ) {
    throw workflowError(
      "Required checks must have unique IDs and commands.",
      code,
      outputConstraint("requiredChecks", "unique-ids-and-commands"),
    );
  }
  return checks;
}

function normalizeValidationInfrastructure(
  value,
  code,
  { maxItems = MAX_VALIDATION_ITEMS } = {},
) {
  if (!Array.isArray(value) || value.length > maxItems) {
    throw workflowError(
      "Validation infrastructure is invalid.",
      code,
      outputConstraint(
        "validationInfrastructure",
        `array-up-to-${maxItems}-items`,
      ),
    );
  }
  const paths = Object.freeze(
    value.map((path, index) =>
      normalizeValidationInfrastructurePath(
        path,
        `validation infrastructure[${index}]`,
        code,
        outputConstraint(
          `validationInfrastructure[${index}]`,
          "exact-repository-relative-path-up-to-4000-characters",
        ),
      ),
    ),
  );
  if (new Set(paths).size !== paths.length) {
    throw workflowError(
      "Validation infrastructure paths must be unique.",
      code,
      outputConstraint("validationInfrastructure", "unique-paths"),
    );
  }
  return paths;
}

function normalizeCheckResults(
  value,
  requiredChecks,
  code,
  { trustedCommands = new Set() } = {},
) {
  if (!Array.isArray(value) || value.length !== requiredChecks.length) {
    throw workflowError("Finalization check evidence is incomplete.", code);
  }
  return Object.freeze(
    value.map((result, index) => {
      const required = requiredChecks[index];
      if (
        !isRecord(result) ||
        result.checkId !== required.id ||
        !["PASS", "FAIL", "BLOCKED", "NOT_RUN"].includes(result.status) ||
        (trustedCommands.has(required.command)
          ? result.status !== "NOT_RUN"
          : result.status === "NOT_RUN")
      ) {
        throw workflowError("Finalization check evidence was substituted.", code);
      }
      const command = normalizeExactCommand(
        result.command,
        `finalization check ${result.checkId} command`,
        code,
      );
      if (command !== required.command) {
        throw workflowError("Finalization check evidence was substituted.", code);
      }
      return Object.freeze({
        checkId: result.checkId,
        command,
        status: result.status,
        evidence: normalizeTextList(
          result.evidence,
          `finalization check ${result.checkId} evidence`,
          { code },
        ),
      });
    }),
  );
}

function normalizeReviewFinding(value, code = INVALID_OUTPUT_CODE) {
  if (!isRecord(value) || !REVIEW_FINDING_ID_PATTERN.test(value.id)) {
    throw workflowError("Reviewer finding has an invalid ID.", code);
  }
  assertExactFields(
    value,
    ["id", "file", "problem", "reason", "suggestedAction"],
    `finding ${value.id}`,
    code,
  );
  return Object.freeze({
    id: value.id,
    file: normalizeRelativePath(value.file, `finding ${value.id} file`, code),
    problem: normalizeText(value.problem, `finding ${value.id} problem`, code),
    reason: normalizeText(value.reason, `finding ${value.id} reason`, code),
    suggestedAction: normalizeText(
      value.suggestedAction,
      `finding ${value.id} suggested action`,
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
    throw workflowError("Finalization issues have an invalid number of items.", code);
  }
  const issues = Object.freeze(
    value.map((issue) => {
      if (!isRecord(issue) || !FINALIZATION_ISSUE_ID_PATTERN.test(issue.id)) {
        throw workflowError("Finalization issue has an invalid ID.", code);
      }
      assertExactFields(
        issue,
        ["id", "command", "problem", "evidence"],
        `finalization issue ${issue.id}`,
        code,
      );
      return Object.freeze({
        id: issue.id,
        command: normalizeText(
          issue.command,
          `finalization issue ${issue.id} command`,
          code,
        ),
        problem: normalizeText(
          issue.problem,
          `finalization issue ${issue.id} problem`,
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

export function normalizePolishResult(payload) {
  const fields = [
    "status",
    "summary",
    "reason",
    "question",
    "options",
    "whyBlocked",
    "evidence",
  ];
  assertExactFields(payload, fields, "Polishing result", INVALID_OUTPUT_CODE);
  assertStructuredResult(payload);
  if (
    !["COMPLETED", "BLOCKED", "PRODUCT_DECISION_REQUIRED"].includes(
      payload.status,
    )
  ) {
    throw outputError("Worker returned an invalid polishing result.");
  }
  if (payload.status === "PRODUCT_DECISION_REQUIRED") {
    if (payload.summary !== "" || payload.reason !== "") {
      throw outputError("Product decision contains inapplicable fields.");
    }
    return Object.freeze({ status: payload.status, decision: normalizeProductDecision(payload) });
  }
  if (payload.status === "BLOCKED") {
    if (
      payload.summary !== "" ||
      payload.question !== "" ||
      payload.whyBlocked !== "" ||
      !emptyArray(payload.options)
    ) {
      throw outputError("Blocked polishing result contains inapplicable fields.");
    }
    return Object.freeze({
      status: payload.status,
      reason: normalizeText(payload.reason, "polishing blocker", INVALID_OUTPUT_CODE),
      evidence: normalizeTextList(payload.evidence, "polishing blocker evidence"),
    });
  }
  if (payload.reason !== "" || !emptyDecision(payload)) {
    throw outputError("Completed polishing result contains inapplicable fields.");
  }
  return Object.freeze({
    status: payload.status,
    summary: normalizeSummary(payload.summary, "polishing summary", INVALID_OUTPUT_CODE),
  });
}

export function normalizeFinalizationResult(
  payload,
  { trustedCommands = [] } = {},
) {
  const fields = [
    "status",
    "skillPath",
    "summary",
    "issues",
    "requiredChecks",
    "validationInfrastructure",
    "checks",
    "reason",
    "question",
    "options",
    "whyBlocked",
    "evidence",
  ];
  assertExactFields(payload, fields, "Finalization result", INVALID_OUTPUT_CODE);
  assertStructuredResult(payload);
  const statuses = [
    "PASS",
    "FAIL",
    "SKILL_MISSING",
    "SKILL_INVALID",
    "BLOCKED",
    "PRODUCT_DECISION_REQUIRED",
  ];
  if (!statuses.includes(payload.status)) {
    throw outputError("Worker returned an invalid finalization result.");
  }
  const trustedCommandSet = new Set(trustedCommands);
  if (
    trustedCommandSet.size !== trustedCommands.length ||
    trustedCommands.some((command) => typeof command !== "string")
  ) {
    throw workflowError("Trusted finalization commands are invalid.");
  }
  if (payload.status === "PRODUCT_DECISION_REQUIRED") {
    if (
      payload.skillPath !== "" ||
      payload.summary !== "" ||
      !emptyArray(payload.issues) ||
      !emptyArray(payload.requiredChecks) ||
      !emptyArray(payload.validationInfrastructure) ||
      !emptyArray(payload.checks) ||
      payload.reason !== ""
    ) {
      throw outputError("Product decision contains inapplicable fields.");
    }
    return Object.freeze({ status: payload.status, decision: normalizeProductDecision(payload) });
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
    if (payload.status === "SKILL_INVALID" && payload.skillPath === "") {
      throw outputError("Finalization skill path is inapplicable.");
    }
    const requiredChecks = normalizePhaseSafeRequiredChecks(
      payload.requiredChecks,
      INVALID_OUTPUT_CODE,
      { allowEmpty: payload.status !== "BLOCKED" },
    );
    const validationInfrastructure = normalizeValidationInfrastructure(
      payload.validationInfrastructure,
      INVALID_OUTPUT_CODE,
    );
    const checks =
      payload.status === "BLOCKED"
        ? normalizeCheckResults(
            payload.checks,
            requiredChecks,
            INVALID_OUTPUT_CODE,
            { trustedCommands: trustedCommandSet },
          )
        : Object.freeze([]);
    if (
      payload.status !== "BLOCKED" &&
      (requiredChecks.length !== 0 ||
        validationInfrastructure.length !== 0 ||
        !emptyArray(payload.checks))
    ) {
      throw outputError("Unavailable finalization contains validation evidence.");
    }
    if (
      payload.status === "BLOCKED" &&
      (!checks.some(({ status }) => status === "BLOCKED") ||
        checks.some(({ status }) => status === "FAIL"))
    ) {
      throw outputError("Blocked finalization has invalid check evidence.");
    }
    const evidence =
      payload.status === "BLOCKED"
        ? normalizeTextList(payload.evidence, "finalization blocker evidence")
        : normalizeOptionalEvidence(payload.evidence, "finalization evidence");
    return Object.freeze({
      status: payload.status,
      skillPath:
        payload.skillPath === ""
          ? null
          : normalizeRelativePath(payload.skillPath, "finalization skill path"),
      reason: normalizeText(payload.reason, "finalization blocker", INVALID_OUTPUT_CODE),
      evidence,
      requiredChecks,
      validationInfrastructure,
      checks,
    });
  }
  if (payload.reason !== "" || !emptyDecision(payload)) {
    throw outputError("Finalization result contains inapplicable fields.");
  }
  const issues = normalizeFinalizationIssues(payload.issues);
  const requiredChecks = normalizePhaseSafeRequiredChecks(
    payload.requiredChecks,
    INVALID_OUTPUT_CODE,
  );
  const validationInfrastructure = normalizeValidationInfrastructure(
    payload.validationInfrastructure,
    INVALID_OUTPUT_CODE,
  );
  const checks = normalizeCheckResults(
    payload.checks,
    requiredChecks,
    INVALID_OUTPUT_CODE,
    { trustedCommands: trustedCommandSet },
  );
  if (
    (payload.status === "PASS" && issues.length !== 0) ||
    (payload.status === "FAIL" && issues.length === 0) ||
    (payload.status === "PASS" &&
      checks.some(
        ({ command, status }) =>
          status !== "PASS" &&
          !(trustedCommandSet.has(command) && status === "NOT_RUN"),
      )) ||
    (payload.status === "FAIL" &&
      (!checks.some(({ status }) => status === "FAIL") ||
        checks.some(({ status }) => status === "BLOCKED")))
  ) {
    throw outputError("Finalization status does not match its issues.");
  }
  return Object.freeze({
    status: payload.status,
    skillPath:
      payload.skillPath === ""
        ? null
        : normalizeRelativePath(payload.skillPath, "finalization skill path"),
    summary: normalizeSummary(payload.summary, "finalization summary", INVALID_OUTPUT_CODE),
    issues,
    requiredChecks,
    validationInfrastructure,
    checks,
  });
}

export function normalizeReviewResult(payload, previousFindings = []) {
  const fields = [
    "status",
    "findings",
    "validationChange",
    "validationEvidence",
    "question",
    "options",
    "whyBlocked",
    "evidence",
  ];
  assertExactFields(payload, fields, "Review result", INVALID_OUTPUT_CODE);
  assertStructuredResult(payload);
  if (!["APPROVED", "FINDINGS", "PRODUCT_DECISION_REQUIRED"].includes(payload.status)) {
    throw outputError("Reviewer returned an invalid review result.");
  }
  if (payload.status === "PRODUCT_DECISION_REQUIRED") {
    if (
      !emptyArray(payload.findings) ||
      payload.validationChange !== "UNCHANGED" ||
      !emptyArray(payload.validationEvidence)
    ) {
      throw outputError("Product decision must not include findings.");
    }
    return Object.freeze({ status: payload.status, decision: normalizeProductDecision(payload) });
  }
  if (!emptyDecision(payload)) {
    throw outputError("Review result contains inapplicable fields.");
  }
  const findings = normalizeReviewFindings(payload.findings);
  if (
    !["UNCHANGED", "ACCEPTED", "REJECTED"].includes(
      payload.validationChange,
    )
  ) {
    throw outputError("Review validation-change decision is invalid.");
  }
  const validationEvidence = normalizeTextList(
    payload.validationEvidence,
    "review validation evidence",
    {
      allowEmpty: payload.validationChange === "UNCHANGED",
      code: INVALID_OUTPUT_CODE,
    },
  );
  if (
    (payload.status === "APPROVED" && findings.length !== 0) ||
    (payload.status === "FINDINGS" && findings.length === 0) ||
    (payload.status === "APPROVED" && payload.validationChange === "REJECTED")
  ) {
    throw outputError("Review status does not match its findings.");
  }
  for (const finding of findings) {
    const previous = previousFindings.find(
      (candidate) => candidate.file === finding.file && candidate.problem === finding.problem,
    );
    if (previous !== undefined && previous.id !== finding.id) {
      throw outputError("Reviewer changed the ID of an unchanged finding.");
    }
  }
  return Object.freeze({
    status: payload.status,
    findings,
    validationChange: payload.validationChange,
    validationEvidence,
  });
}

export function normalizeResolutionResult(
  payload,
  blockers,
  nonDisputableIds,
) {
  assertExactFields(
    payload,
    [
      "status",
      "decisions",
      "reason",
      "question",
      "options",
      "whyBlocked",
      "evidence",
    ],
    "Finding resolution",
    INVALID_OUTPUT_CODE,
  );
  assertStructuredResult(payload);
  if (
    !isRecord(payload) ||
    !["RESOLVED", "BLOCKED", "PRODUCT_DECISION_REQUIRED"].includes(
      payload.status,
    )
  ) {
    throw outputError("Worker returned an invalid finding resolution.");
  }
  if (payload.status === "PRODUCT_DECISION_REQUIRED") {
    if (!emptyArray(payload.decisions) || payload.reason !== "") {
      throw outputError("Product decision must not include finding decisions.");
    }
    return Object.freeze({ status: payload.status, decision: normalizeProductDecision(payload) });
  }
  if (payload.status === "BLOCKED") {
    if (
      !emptyArray(payload.decisions) ||
      payload.question !== "" ||
      payload.whyBlocked !== "" ||
      !emptyArray(payload.options)
    ) {
      throw outputError("Blocked finding resolution contains inapplicable fields.");
    }
    return Object.freeze({
      status: payload.status,
      reason: normalizeText(
        payload.reason,
        "finding-resolution blocker",
        INVALID_OUTPUT_CODE,
      ),
      evidence: normalizeTextList(
        payload.evidence,
        "finding-resolution blocker evidence",
      ),
    });
  }
  if (
    payload.reason !== "" ||
    !emptyDecision(payload) ||
    !Array.isArray(payload.decisions)
  ) {
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
      assertExactFields(
        decision,
        ["id", "decision", "reason", "evidence"],
        `finding decision ${decision.id}`,
        INVALID_OUTPUT_CODE,
      );
      if (
        decision.decision === "DISPUTE" &&
        (decision.id.startsWith("F") || nonDisputableIds.has(decision.id))
      ) {
        throw outputError("This blocker cannot be disputed.");
      }
      return Object.freeze({
        id: decision.id,
        decision: decision.decision,
        reason: normalizeText(
          decision.reason,
          `resolution ${decision.id} reason`,
          INVALID_OUTPUT_CODE,
        ),
        evidence:
          decision.decision === "DISPUTE"
            ? normalizeTextList(decision.evidence, `dispute ${decision.id} evidence`)
            : normalizeOptionalEvidence(decision.evidence, `fix ${decision.id} evidence`),
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
  assertExactFields(
    payload,
    ["status", "decisions", "question", "options", "whyBlocked", "evidence"],
    "Dispute reconsideration",
    INVALID_OUTPUT_CODE,
  );
  assertStructuredResult(payload);
  if (!isRecord(payload) || !["RESOLVED", "PRODUCT_DECISION_REQUIRED"].includes(payload.status)) {
    throw outputError("Reviewer returned an invalid dispute reconsideration.");
  }
  if (payload.status === "PRODUCT_DECISION_REQUIRED") {
    if (!emptyArray(payload.decisions)) {
      throw outputError("Product decision must not include dispute decisions.");
    }
    return Object.freeze({ status: payload.status, decision: normalizeProductDecision(payload) });
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
      assertExactFields(
        decision,
        ["id", "direction", "reason", "evidence"],
        `dispute decision ${decision.id}`,
        INVALID_OUTPUT_CODE,
      );
      return Object.freeze({
        findingId: decision.id,
        direction: decision.direction,
        reason: normalizeText(
          decision.reason,
          `dispute ${decision.id} reconsideration`,
          INVALID_OUTPUT_CODE,
        ),
        evidence: normalizeOptionalEvidence(decision.evidence, `dispute ${decision.id} evidence`),
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
  assertExactFields(
    payload,
    ["direction", "rationale", "question", "options", "whyBlocked", "evidence"],
    "Finding arbitration",
    INVALID_OUTPUT_CODE,
  );
  assertStructuredResult(payload);
  if (
    !isRecord(payload) ||
    !["WORKER_CORRECT", "REVIEWER_CORRECT", "REQUIREMENT_AMBIGUOUS"].includes(payload.direction)
  ) {
    throw outputError("Arbiter returned an invalid finding direction.");
  }
  const rationale = normalizeText(
    payload.rationale,
    "finding arbitration rationale",
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
  assertExactFields(
    payload,
    [
      "direction",
      "rationale",
      "findingIds",
      "question",
      "options",
      "whyBlocked",
      "evidence",
    ],
    "Stagnation arbitration",
    INVALID_OUTPUT_CODE,
  );
  assertStructuredResult(payload);
  if (
    !isRecord(payload) ||
    ![
      "CONTINUE_FIXES",
      "REWORK_IMPLEMENTATION",
      "RECONSIDER_FINDINGS",
      "PRODUCT_DECISION_REQUIRED",
    ].includes(payload.direction)
  ) {
    throw outputError("Arbiter returned an invalid stagnation direction.");
  }
  const rationale = normalizeText(payload.rationale, "stagnation rationale", INVALID_OUTPUT_CODE);
  if (payload.direction === "PRODUCT_DECISION_REQUIRED") {
    if (!emptyArray(payload.findingIds)) {
      throw outputError("Product decision contains inapplicable fields.");
    }
    return Object.freeze({
      direction: payload.direction,
      rationale,
      decision: normalizeProductDecision(payload),
    });
  }
  if (!emptyDecision(payload) || !Array.isArray(payload.findingIds)) {
    throw outputError("Stagnation result contains inapplicable fields.");
  }
  const findingIds = payload.findingIds.map((id) => {
    if (!REVIEW_FINDING_ID_PATTERN.test(id)) {
      throw outputError("Stagnation finding ID is invalid.");
    }
    return id;
  });
  const currentIds = new Set(pipelineState.findings.map(({ id }) => id));
  if (
    (payload.direction === "RECONSIDER_FINDINGS" &&
      (findingIds.length === 0 ||
        new Set(findingIds).size !== findingIds.length ||
        findingIds.some((id) => !currentIds.has(id)))) ||
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
    throw workflowError("Polishing resume action is invalid.");
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
  throw workflowError("Polishing resume action is invalid.");
}

export function assertSettings(settings) {
  settings = normalizeSettings(settings);
  assertExactFields(settings, SETTINGS_FIELDS, "Polishing settings");
  if (!isFinalizationPolicy(settings.finalization)) {
    throw workflowError("Polishing setting finalization is invalid.");
  }
  if (!isTrustedCheckSelection(settings.trustedChecks)) {
    throw workflowError("Polishing setting trustedChecks is invalid.");
  }
  for (const field of NUMERIC_SETTINGS_FIELDS) {
    if (!Number.isSafeInteger(settings[field]) || settings[field] < 1) {
      throw workflowError(`Polishing setting ${field} is invalid.`);
    }
  }
  if (settings.maxDisputesPerFinding > MAX_DISPUTES_PER_FINDING) {
    throw workflowError(
      `Polishing setting maxDisputesPerFinding must not exceed ${MAX_DISPUTES_PER_FINDING}.`,
    );
  }
  disputeHistoryCapacity(settings);
}

export function isTrustedCheckSelection(value) {
  return (
    Array.isArray(value) &&
    value.length <= MAX_ITEMS &&
    new Set(value).size === value.length &&
    value.every(
      (alias) => typeof alias === "string" && TRUSTED_ALIAS_PATTERN.test(alias),
    )
  );
}

export function isFinalizationPolicy(value) {
  if (value === "auto" || value === "none") {
    return true;
  }
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= 1_024 &&
    !value.includes("\\") &&
    !/^[a-zA-Z]:\//u.test(value) &&
    !posix.isAbsolute(value) &&
    posix.normalize(value) === value &&
    value !== "." &&
    value !== ".." &&
    !value.startsWith("../") &&
    value !== ".git" &&
    !value.startsWith(".git/") &&
    (value === "SKILL.md" || value.endsWith("/SKILL.md")) &&
    !/[\0\p{Cc}\p{Zl}\p{Zp}]/u.test(value)
  );
}

function normalizeSettings(settings) {
  let normalized = settings;
  if (
    isRecord(normalized) &&
    !Object.hasOwn(normalized, "finalization") &&
    ((Object.keys(normalized).length === NUMERIC_SETTINGS_FIELDS.length &&
      NUMERIC_SETTINGS_FIELDS.every((field) =>
        Object.hasOwn(normalized, field)
      )) ||
      (Object.keys(normalized).length === SETTINGS_FIELDS.length - 1 &&
        SETTINGS_FIELDS.filter((field) => field !== "finalization").every(
          (field) => Object.hasOwn(normalized, field),
        )))
  ) {
    normalized = Object.freeze({
      finalization: DEFAULT_FINALIZATION_POLICY,
      ...normalized,
    });
  }
  if (
    isRecord(normalized) &&
    !Object.hasOwn(normalized, "trustedChecks") &&
    Object.keys(normalized).length === SETTINGS_FIELDS.length - 1 &&
    SETTINGS_FIELDS.filter((field) => field !== "trustedChecks").every(
      (field) => Object.hasOwn(normalized, field),
    )
  ) {
    normalized = Object.freeze({
      ...normalized,
      trustedChecks: Object.freeze([]),
    });
  }
  return normalized;
}

export function disputeHistoryCapacity(settings) {
  const capacity =
    MAX_DIAGNOSTIC_ITEMS * settings?.maxDisputesPerFinding;
  if (
    !Number.isSafeInteger(capacity) ||
    capacity < 1 ||
    settings.maxDisputesPerFinding > MAX_DISPUTES_PER_FINDING
  ) {
    throw workflowError(
      "Polishing setting maxDisputesPerFinding is too large.",
    );
  }
  return capacity;
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

function normalizeBootstrapCorrection(correction) {
  if (
    !hasExactFields(correction, BOOTSTRAP_CORRECTION_FIELDS) ||
    correction.attempt !== 1
  ) {
    throw workflowError("Polishing bootstrap correction is invalid.");
  }
  const diagnostic = Object.fromEntries(
    OUTPUT_DIAGNOSTIC_FIELDS.map((field) => [field, correction[field]]),
  );
  const validContext =
    (correction.contract === "bootstrap" &&
      ["worker", "reviewer"].includes(correction.role)) ||
    (correction.contract === "bootstrap-reconciliation" &&
      correction.role === "worker") ||
    (correction.contract === "bootstrap-arbitration" &&
      correction.role === "arbiter");
  if (
    !isOutputDiagnostic(diagnostic) ||
    !["bootstrap", "validation-migration"].includes(correction.phase) ||
    !validContext
  ) {
    throw workflowError("Polishing bootstrap correction is invalid.");
  }
  return correction;
}

function normalizeBootstrapCorrections(value) {
  if (!Array.isArray(value) || value.length > MAX_ITEMS) {
    throw workflowError("Polishing bootstrap corrections are invalid.");
  }
  const contexts = new Set();
  for (const correction of value) {
    normalizeBootstrapCorrection(correction);
    const context = `${correction.role}\0${correction.phase}\0${correction.contract}`;
    if (contexts.has(context)) {
      throw workflowError("Polishing bootstrap corrections must be unique.");
    }
    contexts.add(context);
  }
  return value;
}

function normalizePersistedFindings(value, name = "Polishing findings") {
  try {
    return normalizeReviewFindings(value, "ERR_INVALID_POLISHING_STATE");
  } catch (cause) {
    throw new PolishingWorkflowError(`${name} are invalid.`, {
      cause,
      code: "ERR_INVALID_POLISHING_STATE",
    });
  }
}

function normalizePersistedFinalization(value) {
  if (value === null) {
    return null;
  }
  assertExactFields(
    value,
    [
      "status",
      "skillPath",
      "summary",
      "issues",
      "requiredChecks",
      "validationInfrastructure",
      "validationInfrastructureFingerprint",
      "checks",
      "trustedCommandFingerprint",
      "trustedConfigurationFingerprint",
      "validationChanged",
      "fingerprint",
    ],
    "Polishing finalization result",
  );
  if (!["PASS", "FAIL"].includes(value.status) || !HASH_PATTERN.test(value.fingerprint)) {
    throw workflowError("Polishing finalization result is invalid.");
  }
  if (value.skillPath !== null) {
    normalizeRelativePath(
      value.skillPath,
      "finalization skill path",
      "ERR_INVALID_POLISHING_STATE",
    );
  }
  normalizeSummary(value.summary, "finalization summary");
  const issues = normalizeFinalizationIssues(value.issues, "ERR_INVALID_POLISHING_STATE");
  const requiredChecks = normalizeRequiredChecks(
    value.requiredChecks,
    "ERR_INVALID_POLISHING_STATE",
  );
  normalizeValidationInfrastructure(
    value.validationInfrastructure,
    "ERR_INVALID_POLISHING_STATE",
  );
  if (
    !Array.isArray(value.checks) ||
    value.checks.length !== requiredChecks.length
  ) {
    throw workflowError("Polishing check evidence is incomplete.");
  }
  const checks = value.checks.map((check, index) => {
    if (
      !isRecord(check) ||
      Object.keys(check).length !== PERSISTED_CHECK_RESULT_FIELDS.length ||
      PERSISTED_CHECK_RESULT_FIELDS.some((field) =>
        !Object.hasOwn(check, field)
      )
    ) {
      throw workflowError("Polishing check evidence is invalid.");
    }
    const [normalized] = normalizeCheckResults(
      [
        {
          checkId: check.checkId,
          command: check.command,
          status: check.status,
          evidence: check.evidence,
        },
      ],
      [requiredChecks[index]],
      "ERR_INVALID_POLISHING_STATE",
    );
    const runnerResult = check.executor === "runner";
    const validRunnerResult =
      runnerResult &&
      !check.timedOut &&
      ((check.status === "PASS" &&
        check.exitCode === 0 &&
        check.signal === null) ||
        (check.status === "FAIL" &&
          (check.exitCode === null || check.exitCode !== 0) &&
          (check.exitCode !== null || check.signal !== null)));
    if (
      !["agent", "runner"].includes(check.executor) ||
      !["PASS", "FAIL"].includes(check.status) ||
      typeof check.timedOut !== "boolean" ||
      (runnerResult
        ? !HASH_PATTERN.test(check.commandIdentity) ||
          (check.exitCode !== null && !Number.isSafeInteger(check.exitCode)) ||
          (check.signal !== null &&
            (typeof check.signal !== "string" || check.signal.length > 32)) ||
          !validRunnerResult
        : check.commandIdentity !== null ||
          check.exitCode !== null ||
          check.signal !== null ||
          check.timedOut)
    ) {
      throw workflowError("Polishing check executor evidence is invalid.");
    }
    return Object.freeze({ ...normalized, ...check });
  });
  if (
    (value.status === "PASS" && issues.length !== 0) ||
    (value.status === "FAIL" && issues.length === 0) ||
    typeof value.validationChanged !== "boolean" ||
    !HASH_PATTERN.test(value.validationInfrastructureFingerprint) ||
    !HASH_PATTERN.test(value.trustedCommandFingerprint) ||
    !HASH_PATTERN.test(value.trustedConfigurationFingerprint) ||
    (value.status === "PASS" &&
      checks.some(({ status }) => status !== "PASS")) ||
    (value.status === "FAIL" &&
      !checks.some(({ status }) => status === "FAIL"))
  ) {
    throw workflowError("Polishing finalization result is inconsistent.");
  }
  return value;
}

function normalizePersistedValidation(value, name) {
  if (value === null) {
    return null;
  }
  assertExactFields(
    value,
    ["requiredChecks", "validationInfrastructure"],
    name,
  );
  normalizeRequiredChecks(value.requiredChecks, "ERR_INVALID_POLISHING_STATE", {
    maxItems: MAX_BOOTSTRAP_ITEMS,
  });
  normalizeValidationInfrastructure(
    value.validationInfrastructure,
    "ERR_INVALID_POLISHING_STATE",
    { maxItems: MAX_BOOTSTRAP_ITEMS },
  );
  return value;
}

function normalizePersistedReview(value) {
  if (value === null) {
    return null;
  }
  assertExactFields(
    value,
    ["status", "validationChange", "validationEvidence", "fingerprint"],
    "Polishing review result",
  );
  if (
    !["APPROVED", "FINDINGS"].includes(value.status) ||
    !["UNCHANGED", "ACCEPTED", "REJECTED"].includes(
      value.validationChange,
    ) ||
    !HASH_PATTERN.test(value.fingerprint)
  ) {
    throw workflowError("Polishing review result is invalid.");
  }
  normalizeTextList(value.validationEvidence, "review validation evidence", {
    allowEmpty: value.validationChange === "UNCHANGED",
    code: "ERR_INVALID_POLISHING_STATE",
  });
  if (value.status === "APPROVED" && value.validationChange === "REJECTED") {
    throw workflowError("Polishing review result is inconsistent.");
  }
  return value;
}

function normalizeCountRecord(value, name) {
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
    throw workflowError("Polishing pending disputes are invalid.");
  }
  for (const dispute of value) {
    assertExactFields(dispute, ["findingId", "reason", "evidence"], "Polishing pending dispute");
    if (!REVIEW_FINDING_ID_PATTERN.test(dispute.findingId)) {
      throw workflowError("Polishing pending dispute is invalid.");
    }
    normalizeText(dispute.reason, `dispute ${dispute.findingId} reason`);
    normalizeTextList(dispute.evidence, `dispute ${dispute.findingId} evidence`);
  }
  if (new Set(value.map(({ findingId }) => findingId)).size !== value.length) {
    throw workflowError("Polishing pending disputes must be unique.");
  }
  return value;
}

function normalizeDisputeHistory(value, capacity) {
  if (
    !Array.isArray(value) ||
    value.length > capacity
  ) {
    throw workflowError("Polishing dispute history is invalid.");
  }
  assertDisputeHistoryFits(value);
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
      "Polishing dispute history entry",
    );
    if (
      !REVIEW_FINDING_ID_PATTERN.test(entry.findingId) ||
      !Number.isSafeInteger(entry.attempt) ||
      entry.attempt < 1 ||
      !["WITHDRAW", "UPHOLD"].includes(entry.direction)
    ) {
      throw workflowError("Polishing dispute history entry is invalid.");
    }
    normalizeText(entry.workerReason, "dispute Worker reason");
    normalizeTextList(entry.workerEvidence, "dispute Worker evidence");
    normalizeText(entry.reviewerReason, "dispute Reviewer reason");
    normalizeTextList(entry.reviewerEvidence, "dispute Reviewer evidence", { allowEmpty: true });
  }
  return value;
}

function normalizeFindingArbitrations(value) {
  if (!Array.isArray(value) || value.length > MAX_DIAGNOSTIC_ITEMS) {
    throw workflowError("Polishing finding arbitrations are invalid.");
  }
  for (const entry of value) {
    assertExactFields(
      entry,
      ["findingId", "direction", "rationale"],
      "Polishing finding arbitration",
    );
    if (
      !REVIEW_FINDING_ID_PATTERN.test(entry.findingId) ||
      !["WORKER_CORRECT", "REVIEWER_CORRECT"].includes(entry.direction)
    ) {
      throw workflowError("Polishing finding arbitration is invalid.");
    }
    normalizeText(entry.rationale, "finding arbitration rationale");
  }
  if (new Set(value.map(({ findingId }) => findingId)).size !== value.length) {
    throw workflowError("Polishing finding arbitrations must be unique.");
  }
  return value;
}

function normalizeCorrectionHistory(value) {
  if (!Array.isArray(value) || value.length > MAX_DIAGNOSTIC_ITEMS) {
    throw workflowError("Polishing correction history is invalid.");
  }
  for (const entry of value) {
    assertExactFields(
      entry,
      ["round", "fingerprint", "finalizationIssueIds", "findingIds"],
      "Polishing correction history entry",
    );
    if (
      !Number.isSafeInteger(entry.round) ||
      entry.round < 1 ||
      !HASH_PATTERN.test(entry.fingerprint) ||
      !Array.isArray(entry.finalizationIssueIds) ||
      !Array.isArray(entry.findingIds) ||
      entry.finalizationIssueIds.some((id) => !FINALIZATION_ISSUE_ID_PATTERN.test(id)) ||
      entry.findingIds.some((id) => !REVIEW_FINDING_ID_PATTERN.test(id)) ||
      new Set(entry.finalizationIssueIds).size !==
        entry.finalizationIssueIds.length ||
      new Set(entry.findingIds).size !== entry.findingIds.length ||
      (entry.finalizationIssueIds.length === 0) ===
        (entry.findingIds.length === 0)
    ) {
      throw workflowError("Polishing correction history entry is invalid.");
    }
  }
  return value;
}

function normalizeStagnationDirection(value) {
  if (value === null) {
    return null;
  }
  assertExactFields(
    value,
    ["direction", "rationale"],
    "Polishing stagnation direction",
  );
  if (![
    "CONTINUE_FIXES",
    "REWORK_IMPLEMENTATION",
    "RECONSIDER_FINDINGS",
  ].includes(value.direction)) {
    throw workflowError("Polishing stagnation direction is invalid.");
  }
  normalizeText(value.rationale, "stagnation direction rationale");
  return value;
}

function normalizeFindingOverrides(value) {
  if (!Array.isArray(value) || value.length > MAX_DIAGNOSTIC_ITEMS) {
    throw workflowError("Polishing finding overrides are invalid.");
  }
  for (const entry of value) {
    assertExactFields(
      entry,
      ["findingId", "fingerprint"],
      "Polishing finding override",
    );
    if (
      !REVIEW_FINDING_ID_PATTERN.test(entry.findingId) ||
      !HASH_PATTERN.test(entry.fingerprint)
    ) {
      throw workflowError("Polishing finding override is invalid.");
    }
  }
  if (
    new Set(
      value.map(
        ({ findingId, fingerprint }) => `${findingId}:${fingerprint}`,
      ),
    ).size !== value.length
  ) {
    throw workflowError("Polishing finding overrides must be unique.");
  }
  return value;
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
  if (isRecord(value) && !Object.hasOwn(value, "artifactRoot")) {
    value = { ...value, artifactRoot: "LOCAL_ARTIFACTS" };
  }
  if (
    !isRecord(value) ||
    Object.keys(value).length !== PIPELINE_STATE_FIELDS.size ||
    Object.keys(value).some((field) => !PIPELINE_STATE_FIELDS.has(field)) ||
    !WORKFLOW_STATES.includes(value.workflowState)
  ) {
    throw workflowError("Polishing state is invalid.");
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
    throw workflowError("Polishing artifact root is invalid.");
  }
  for (const field of [
    "preflightComplete",
    "proactiveClarification",
    "proactiveClarificationComplete",
    "clarificationFrozen",
    "refreezeRequired",
    "bootstrapArbitrationUsed",
    "validationMigrationPending",
    "pendingCorrection",
    "stagnationArbitrationUsed",
  ]) {
    if (typeof value[field] !== "boolean") {
      throw workflowError(`Polishing state field ${field} is invalid.`);
    }
  }
  if (value.settings !== null) {
    const settings = normalizeSettings(value.settings);
    assertSettings(settings);
    if (settings !== value.settings) {
      value = { ...value, settings };
    }
  }
  const trustedValidation = normalizeTrustedValidation(value.trustedValidation);
  if (trustedValidation !== value.trustedValidation) {
    value = { ...value, trustedValidation };
  }
  if (
    value.settings !== null &&
    !isDeepStrictEqual(
      value.settings.trustedChecks,
      trustedValidation.commands.map(({ alias }) => alias),
    )
  ) {
    throw workflowError(
      "Polishing trusted validation selection is inconsistent.",
    );
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
  const workerValidation = normalizePersistedValidation(
    value.workerValidation,
    "Worker validation evidence",
  );
  const reviewerValidation = normalizePersistedValidation(
    value.reviewerValidation,
    "Reviewer validation evidence",
  );
  const resolvedSummary = normalizeOptionalSummary(
    value.resolvedSummary,
    "resolved summary",
  );
  const disagreement = normalizeDisagreement(value.bootstrapDisagreement);
  const validationMigrationDisagreement = normalizeDisagreement(
    value.validationMigrationDisagreement,
  );
  const bootstrapCorrections = normalizeBootstrapCorrections(
    value.bootstrapCorrections,
  );
  const pendingBootstrapCorrection =
    value.pendingBootstrapCorrection === null
      ? null
      : normalizeBootstrapCorrection(value.pendingBootstrapCorrection);
  if (
    pendingBootstrapCorrection !== null &&
    !bootstrapCorrections.some((correction) =>
      isDeepStrictEqual(correction, pendingBootstrapCorrection),
    )
  ) {
    throw workflowError(
      "Polishing pending bootstrap correction is inconsistent.",
    );
  }
  const polishSummary = normalizeOptionalSummary(
    value.polishSummary,
    "polishing summary",
  );
  const finalizationResult = normalizePersistedFinalization(
    value.finalizationResult,
  );
  const requiredChecks =
    value.requiredChecks === null
      ? null
      : normalizeRequiredChecks(
          value.requiredChecks,
          "ERR_INVALID_POLISHING_STATE",
        );
  const validationInfrastructure =
    value.validationInfrastructure === null
      ? null
      : normalizeValidationInfrastructure(
          value.validationInfrastructure,
          "ERR_INVALID_POLISHING_STATE",
        );
  const reviewResult = normalizePersistedReview(value.reviewResult);
  if (
    (requiredChecks === null) !== (resolvedSummary === null) ||
    (validationInfrastructure === null) !== (resolvedSummary === null) ||
    (value.validationInfrastructureFingerprint === null) !==
      (resolvedSummary === null) ||
    (value.validationInfrastructureFingerprint !== null &&
      !HASH_PATTERN.test(value.validationInfrastructureFingerprint))
  ) {
    throw workflowError("Polishing validation inventory is inconsistent.");
  }
  if (
    requiredChecks !== null &&
    trustedValidation.commands.some(
      ({ command }) =>
        !requiredChecks.some((required) => required.command === command),
    )
  ) {
    throw workflowError(
      "Polishing validation inventory omits a trusted command.",
    );
  }
  if (finalizationResult !== null) {
    const trustedCommands = new Map(
      trustedValidation.commands.map((command) => [command.command, command]),
    );
    const matchesEstablishedValidation =
      isDeepStrictEqual(finalizationResult.requiredChecks, requiredChecks) &&
      isDeepStrictEqual(
        finalizationResult.validationInfrastructure,
        validationInfrastructure,
      ) &&
      finalizationResult.validationInfrastructureFingerprint ===
        value.validationInfrastructureFingerprint;
    if (
      finalizationResult.trustedCommandFingerprint !==
        trustedValidation.commandFingerprint ||
      finalizationResult.trustedConfigurationFingerprint !==
        trustedValidation.configurationFingerprint ||
      finalizationResult.checks.some((check) => {
        const trusted = trustedCommands.get(check.command);
        return trusted === undefined
          ? check.executor !== "agent" || check.commandIdentity !== null
          : check.executor !== "runner" ||
              check.commandIdentity !== trusted.identity;
      })
    ) {
      throw workflowError(
        "Polishing trusted finalization evidence is inconsistent.",
      );
    }
    const reviewedChange = reviewResult?.validationChange;
    if (
      (!finalizationResult.validationChanged &&
        !matchesEstablishedValidation) ||
      (finalizationResult.validationChanged &&
        reviewedChange !== "ACCEPTED" &&
        matchesEstablishedValidation) ||
      (reviewedChange === "UNCHANGED" &&
        finalizationResult.validationChanged) ||
      (["ACCEPTED", "REJECTED"].includes(reviewedChange) &&
        !finalizationResult.validationChanged) ||
      (reviewedChange === "ACCEPTED" && !matchesEstablishedValidation) ||
      (reviewedChange === "REJECTED" && matchesEstablishedValidation)
    ) {
      throw workflowError("Polishing validation-change evidence is inconsistent.");
    }
  }
  const findings = normalizePersistedFindings(value.findings);
  const previousFindings = normalizePersistedFindings(
    value.previousFindings,
    "Polishing previous findings",
  );
  const pendingDisputes = normalizePendingDisputes(value.pendingDisputes);
  const disputeCounts = normalizeCountRecord(
    value.disputeCounts,
    "Polishing dispute counts",
  );
  const sameFindingRounds = normalizeCountRecord(
    value.sameFindingRounds,
    "Polishing same-finding rounds",
  );
  normalizeDisputeHistory(
    value.disputeHistory,
    value.settings === null ? 0 : disputeHistoryCapacity(value.settings),
  );
  const findingArbitrations = normalizeFindingArbitrations(
    value.findingArbitrations,
  );
  normalizeCorrectionHistory(value.correctionHistory);
  const stagnationDirection = normalizeStagnationDirection(
    value.stagnationDirection,
  );
  normalizeFindingOverrides(value.findingOverrides);
  if (
    (value.finalizedFingerprint !== null &&
      !HASH_PATTERN.test(value.finalizedFingerprint)) ||
    (value.reviewedFingerprint !== null &&
      !HASH_PATTERN.test(value.reviewedFingerprint)) ||
    !Number.isSafeInteger(value.blockedSinceStagnation) ||
    value.blockedSinceStagnation < 0 ||
    !Number.isSafeInteger(value.additionalFixRounds) ||
    value.additionalFixRounds < 0 ||
    (value.settings !== null &&
      !Number.isSafeInteger(
        value.settings.maxFixRounds + value.additionalFixRounds,
      )) ||
    !Array.isArray(value.reviewReconsideration) ||
    value.reviewReconsideration.length > MAX_ITEMS ||
    value.reviewReconsideration.some(
      (id) => !REVIEW_FINDING_ID_PATTERN.test(id),
    ) ||
    new Set(value.reviewReconsideration).size !==
      value.reviewReconsideration.length
  ) {
    throw workflowError("Polishing correction state is invalid.");
  }
  if (value.stagnationArbitrationUsed !== (stagnationDirection !== null)) {
    throw workflowError("Polishing stagnation arbitration is inconsistent.");
  }
  if (
    (reviewerSummary !== null && workerSummary === null) ||
    (!value.validationMigrationPending &&
      (workerValidation !== null) !== (workerSummary !== null)) ||
    (!value.validationMigrationPending &&
      (reviewerValidation !== null) !== (reviewerSummary !== null)) ||
    (value.validationMigrationPending &&
      reviewerValidation !== null &&
      workerValidation === null) ||
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
    value.validationMigrationPending &&
    (!value.preflightComplete ||
      resolvedSummary === null ||
      ["CLARIFY", "BOOTSTRAP", "DONE"].includes(value.workflowState))
  ) {
    throw workflowError("Polishing validation migration is inapplicable.");
  }
  if (
    (validationMigrationDisagreement !== null &&
      (!value.validationMigrationPending ||
        workerValidation === null ||
        reviewerValidation === null)) ||
    (pendingBootstrapCorrection?.phase === "validation-migration" &&
      pendingBootstrapCorrection.contract === "bootstrap-arbitration" &&
      validationMigrationDisagreement === null)
  ) {
    throw workflowError("Polishing validation migration checkpoint is invalid.");
  }
  const currentFindingIds = new Set(findings.map(({ id }) => id));
  const previousFindingIds = new Set(previousFindings.map(({ id }) => id));
  const deferredDisputes =
    pendingDisputes.length > 0 &&
    findings.length === 0 &&
    pendingDisputes.every(({ findingId }) =>
      previousFindingIds.has(findingId),
    ) &&
    (["POLISH", "FINALIZE", "REVIEW", "WAITING_FOR_USER", "FAILED"].includes(
      value.workflowState,
    ) ||
      (value.workflowState === "RESOLVE_FINDINGS" &&
        finalizationResult?.status === "FAIL"));
  if (
    (pendingDisputes.some(
      ({ findingId }) => !currentFindingIds.has(findingId),
    ) &&
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
    throw workflowError("Polishing finding progress is inconsistent.");
  }
  if (
    finalizationResult === null &&
    (value.finalizedFingerprint !== null ||
      reviewResult !== null ||
      value.reviewedFingerprint !== null ||
      findings.length !== 0 ||
      (pendingDisputes.length !== 0 && !deferredDisputes))
  ) {
    throw workflowError("Polishing validation progress is inconsistent.");
  }
  if (
    finalizationResult !== null &&
    ((finalizationResult.status === "PASS") !==
      (value.finalizedFingerprint === finalizationResult.fingerprint) ||
      (value.reviewedFingerprint !== null &&
        value.reviewedFingerprint !== value.finalizedFingerprint) ||
      (finalizationResult.status === "FAIL" &&
        (reviewResult !== null ||
          value.reviewedFingerprint !== null ||
          findings.length !== 0)))
  ) {
    throw workflowError("Polishing finalization progress is inconsistent.");
  }
  if (
    (reviewResult === null) !== (value.reviewedFingerprint === null) ||
    (reviewResult !== null &&
      reviewResult.fingerprint !== value.reviewedFingerprint) ||
    (reviewResult?.status === "APPROVED" && findings.length !== 0)
  ) {
    throw workflowError("Polishing review evidence is inconsistent.");
  }
  if (
    value.repositoryBaseline !== null &&
    ((finalizationResult !== null &&
      finalizationResult.fingerprint !==
        value.repositoryBaseline.contentFingerprint) ||
      (value.finalizedFingerprint !== null &&
        value.finalizedFingerprint !==
          value.repositoryBaseline.contentFingerprint) ||
      (value.reviewedFingerprint !== null &&
        value.reviewedFingerprint !==
          value.repositoryBaseline.contentFingerprint))
  ) {
    throw workflowError("Polishing content fingerprints are inconsistent.");
  }
  if (
    (findings.length > 0 || pendingDisputes.length > 0) &&
    value.reviewedFingerprint === null &&
    !deferredDisputes
  ) {
    throw workflowError("Polishing review progress is inconsistent.");
  }
  if (
    value.pendingCorrection &&
    !["POLISH", "FINALIZE", "REVIEW", "WAITING_FOR_USER", "FAILED"].includes(
      value.workflowState,
    )
  ) {
    throw workflowError("Polishing pending correction is inapplicable.");
  }
  if (
    stagnationDirection !== null &&
    ![
      "POLISH",
      "FINALIZE",
      "REVIEW",
      "RESOLVE_FINDINGS",
      "HANDOFF",
      "DONE",
      "WAITING_FOR_USER",
      "FAILED",
    ].includes(value.workflowState)
  ) {
    throw workflowError("Polishing stagnation direction is inapplicable.");
  }
  if (
    value.reviewReconsideration.length > 0 &&
    !["REVIEW", "WAITING_FOR_USER", "FAILED"].includes(value.workflowState)
  ) {
    throw workflowError("Polishing review reconsideration is inapplicable.");
  }
  const hasCorrectionProgress =
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
    value.findingOverrides.length !== 0;
  const hasWorkProgress =
    polishSummary !== null ||
    finalizationResult !== null ||
    value.finalizedFingerprint !== null ||
    value.reviewedFingerprint !== null ||
    findings.length !== 0 ||
    previousFindings.length !== 0 ||
    pendingDisputes.length !== 0 ||
    hasCorrectionProgress;
  if (
    !value.preflightComplete &&
    (value.clarificationFrozen ||
      pendingEdit !== null ||
      value.refreezeRequired ||
      workerSummary !== null ||
      reviewerSummary !== null ||
      workerValidation !== null ||
      reviewerValidation !== null ||
      resolvedSummary !== null ||
      disagreement !== null ||
      value.bootstrapArbitrationUsed ||
      bootstrapCorrections.length !== 0 ||
      pendingBootstrapCorrection !== null ||
      validationMigrationDisagreement !== null ||
      hasWorkProgress)
  ) {
    throw workflowError("Polishing preflight state is inconsistent.");
  }
  if (
    ["CLARIFY", "BOOTSTRAP"].includes(value.workflowState) &&
    hasWorkProgress
  ) {
    throw workflowError("Polishing work progress is not applicable.");
  }
  if (
    value.workflowState === "CLARIFY" &&
    (value.clarificationFrozen ||
      value.refreezeRequired ||
      workerSummary !== null ||
      reviewerSummary !== null ||
      workerValidation !== null ||
      reviewerValidation !== null ||
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
    [
      "POLISH",
      "FINALIZE",
      "REVIEW",
      "RESOLVE_FINDINGS",
      "HANDOFF",
      "DONE",
    ].includes(value.workflowState) &&
    (!value.clarificationFrozen ||
      value.refreezeRequired ||
      resolvedSummary === null ||
      disagreement !== null)
  ) {
    throw workflowError("Polishing prepared state is inconsistent.");
  }
  if (
    (["FINALIZE", "REVIEW", "RESOLVE_FINDINGS", "HANDOFF", "DONE"].includes(
      value.workflowState,
    ) &&
      polishSummary === null)
  ) {
    throw workflowError("Polishing result state is inconsistent.");
  }
  if (
    value.workflowState === "FINALIZE" &&
    (finalizationResult !== null ||
      findings.length !== 0 ||
      value.reviewReconsideration.length !== 0)
  ) {
    throw workflowError("Polishing finalization state is inconsistent.");
  }
  if (
    value.workflowState === "REVIEW" &&
    (finalizationResult?.status !== "PASS" ||
      value.finalizedFingerprint === null)
  ) {
    throw workflowError("Polishing review state is inconsistent.");
  }
  const completionReady =
    finalizationResult?.status === "PASS" &&
    value.finalizedFingerprint !== null &&
    value.reviewedFingerprint === value.finalizedFingerprint &&
    ["UNCHANGED", "ACCEPTED"].includes(reviewResult.validationChange) &&
    findings.length === 0 &&
    pendingDisputes.length === 0;
  const finalizationBlocked =
    finalizationResult?.status === "FAIL" &&
    finalizationResult.issues.length > 0;
  if (
    value.workflowState === "RESOLVE_FINDINGS" &&
    !completionReady &&
    !finalizationBlocked &&
    findings.length === 0 &&
    pendingDisputes.length === 0
  ) {
    throw workflowError("Polishing finding resolution has no blockers.");
  }
  if (
    ["HANDOFF", "DONE"].includes(value.workflowState) &&
    (!completionReady || value.reviewReconsideration.length !== 0)
  ) {
    throw workflowError("Completed polishing state is inconsistent.");
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
  artifactRoot = "LOCAL_ARTIFACTS",
  proactiveClarification = false,
  settings = null,
  trustedValidation = EMPTY_TRUSTED_VALIDATION,
} = {}) {
  if (typeof proactiveClarification !== "boolean") {
    throw workflowError("proactiveClarification must be a boolean.");
  }
  if (settings !== null) {
    assertSettings(settings);
  }
  const normalizedTrustedValidation =
    normalizeTrustedValidation(trustedValidation);
  return Object.freeze(normalizePipelineState({
    workflowState: "CLARIFY",
    artifactRoot,
    preflightComplete: false,
    settings:
      settings === null
        ? null
        : Object.freeze({
            ...settings,
            trustedChecks: Object.freeze([...settings.trustedChecks]),
          }),
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
    workerValidation: null,
    reviewerValidation: null,
    resolvedSummary: null,
    bootstrapDisagreement: null,
    bootstrapArbitrationUsed: false,
    bootstrapCorrections: Object.freeze([]),
    pendingBootstrapCorrection: null,
    polishSummary: null,
    finalizationResult: null,
    finalizedFingerprint: null,
    requiredChecks: null,
    validationInfrastructure: null,
    validationInfrastructureFingerprint: null,
    trustedValidation: normalizedTrustedValidation,
    validationMigrationPending: false,
    validationMigrationDisagreement: null,
    reviewResult: null,
    reviewedFingerprint: null,
    findings: [],
    previousFindings: [],
    pendingDisputes: [],
    disputeCounts: {},
    disputeHistory: [],
    findingArbitrations: [],
    correctionHistory: [],
    sameFindingRounds: {},
    pendingCorrection: false,
    blockedSinceStagnation: 0,
    stagnationArbitrationUsed: false,
    stagnationDirection: null,
    reviewReconsideration: [],
    additionalFixRounds: 0,
    findingOverrides: [],
  }));
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
    run.pipelineStateVersion !== 6 ||
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
    const roleFields = Object.keys(run.roles[role]);
    if (
      roleFields.some(
        (field) =>
          !["backend", "profile", "model", "contextSize"].includes(field),
      ) ||
      !Object.hasOwn(run.roles[role], "backend")
    ) {
      throw workflowError(`Polishing role ${role} is invalid.`);
    }
    if (
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
  if (
    run.sessionLineage.sourceProfile !== undefined &&
    run.sessionLineage.sourceProfile !== null &&
    (run.sessionLineage.source === null ||
      typeof run.sessionLineage.sourceProfile !== "string" ||
      run.sessionLineage.sourceProfile.length === 0)
  ) {
    throw workflowError("Polishing source profile is invalid.");
  }
  const sessionIds = [];
  for (const child of run.sessionLineage.children) {
    if (
      !isRecord(child) ||
      !ROLES.includes(child.role) ||
      typeof child.sessionId !== "string" ||
      child.sessionId.length === 0 ||
      child.sessionId === run.sessionLineage.source ||
      (Object.hasOwn(child, "contextKey") &&
        (typeof child.contextKey !== "string" ||
          !/^[a-f0-9]{64}$/u.test(child.contextKey)))
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
  const outputFailure =
    state.workflowState === "FAILED" &&
    run.pause?.reason === "internal_failure" &&
    run.pause.code === INVALID_OUTPUT_CODE;
  const hasOutputDiagnostic = Object.hasOwn(run.pause ?? {}, "diagnostic");
  if (
    (hasOutputDiagnostic &&
      (!outputFailure ||
        !hasExactFields(run.pause, OUTPUT_FAILURE_FIELDS) ||
        !isOutputDiagnostic(run.pause.diagnostic))) ||
    (outputFailure &&
      !hasExactFields(
        run.pause,
        hasOutputDiagnostic
          ? OUTPUT_FAILURE_FIELDS
          : LEGACY_OUTPUT_FAILURE_FIELDS,
      ))
  ) {
    throw workflowError("Polishing output diagnostic is invalid.");
  }
  const adapterFailure =
    state.workflowState === "FAILED" &&
    run.pause?.reason === "internal_failure" &&
    !outputFailure;
  const hasAdapterDiagnostic = Object.hasOwn(
    run.pause ?? {},
    "diagnosticClass",
  );
  if (
    (hasAdapterDiagnostic &&
      (!adapterFailure ||
        !hasExactFields(run.pause, ADAPTER_FAILURE_FIELDS) ||
        typeof run.pause.diagnosticClass !== "string" ||
        !ADAPTER_DIAGNOSTIC_CLASS_PATTERN.test(
          run.pause.diagnosticClass,
        ))) ||
    (adapterFailure &&
      !hasExactFields(
        run.pause,
        hasAdapterDiagnostic ? ADAPTER_FAILURE_FIELDS : FAILURE_FIELDS,
      ))
  ) {
    throw workflowError("Polishing adapter diagnostic is invalid.");
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
      throw workflowError("Polishing pending edit pause is invalid.");
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
        [
          "backend_unavailable",
          "environment_blocked",
          "finalization_skill_invalid",
          "finalization_skill_missing",
        ].includes(run.pause.reason)) ||
      (run.pause.reason === "finalization_cannot_pass" &&
        run.pause.code !== "ERR_FINALIZATION_MODIFIED_BEFORE_VALIDATION");
    if (
      (hasResumeState &&
        (!allowedResumeStates?.includes(run.pause.resumeState) ||
          !state.preflightComplete)) ||
      (requiresResumeState && !hasResumeState)
    ) {
      throw workflowError("Polishing pause resume state is invalid.");
    }
    if (hasResumeState) {
      normalizePipelineState({
        ...state,
        workflowState: run.pause.resumeState,
      });
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
  const fixBudget =
    (state.settings?.maxFixRounds ?? 0) + state.additionalFixRounds;
  const correctionHistory = state.correctionHistory;
  const lastCorrection = correctionHistory.at(-1)?.round ?? 0;
  const lastCorrectionFindingIds = new Set(
    correctionHistory.at(-1)?.findingIds ?? [],
  );
  if (
    counters.clarificationRounds > MAX_CLARIFICATION_ROUNDS ||
    counters.correctionRounds > counters.fixRounds ||
    counters.fixRounds > fixBudget ||
    (run.pause?.reason === "fix_limit_reached" &&
      (counters.fixRounds !== fixBudget ||
        run.pause.fixRounds !== counters.fixRounds)) ||
    lastCorrection !== counters.correctionRounds ||
    correctionHistory.some(
      (entry, index) =>
        index > 0 &&
        entry.round !== correctionHistory[index - 1].round + 1,
    ) ||
    state.blockedSinceStagnation > counters.correctionRounds ||
    (state.stagnationArbitrationUsed && counters.correctionRounds === 0) ||
    Object.keys(state.sameFindingRounds).some(
      (id) => !lastCorrectionFindingIds.has(id),
    ) ||
    Object.values(state.sameFindingRounds).some(
      (count) => count > counters.correctionRounds,
    )
  ) {
    throw workflowError("Polishing persisted progress is invalid.");
  }
  if (
    state.pendingDisputes.some(
      ({ findingId }) => !Object.hasOwn(state.disputeCounts, findingId),
    ) ||
    state.disputeHistory.some(
      ({ findingId }) => !Object.hasOwn(state.disputeCounts, findingId),
    ) ||
    state.findingArbitrations.some(
      ({ findingId }) =>
        !state.disputeHistory.some((entry) => entry.findingId === findingId),
    )
  ) {
    throw workflowError("Polishing dispute progress is invalid.");
  }
  for (const [findingId, count] of Object.entries(state.disputeCounts)) {
    const recorded = state.disputeHistory.filter(
      (entry) => entry.findingId === findingId,
    );
    const pending = state.pendingDisputes.find(
      (entry) => entry.findingId === findingId,
    );
    const arbitration = state.findingArbitrations.find(
      (entry) => entry.findingId === findingId,
    );
    const latest = recorded.at(-1);
    const exhaustedUpheld =
      count === state.settings.maxDisputesPerFinding &&
      recorded.length === count &&
      latest?.direction === "UPHOLD";
    if (
      count > state.settings.maxDisputesPerFinding ||
      recorded.some((entry, index) => entry.attempt !== index + 1) ||
      (!pending && recorded.length !== count) ||
      (pending &&
        recorded.length !== count - 1 &&
        !(
          recorded.length === count &&
          count === state.settings.maxDisputesPerFinding &&
          latest.direction === "UPHOLD"
        )) ||
      (pending !== undefined &&
        recorded.length === count &&
        (pending.reason !== latest.workerReason ||
          pending.evidence.length !== latest.workerEvidence.length ||
          pending.evidence.some(
            (evidence, index) => evidence !== latest.workerEvidence[index],
          ))) ||
      (state.findings.some(({ id }) => id === findingId) &&
        exhaustedUpheld &&
        pending === undefined &&
        arbitration === undefined)
    ) {
      throw workflowError("Polishing dispute progress is invalid.");
    }
  }
  for (const arbitration of state.findingArbitrations) {
    const count = state.disputeCounts[arbitration.findingId];
    const recorded = state.disputeHistory.filter(
      (entry) => entry.findingId === arbitration.findingId,
    );
    if (
      count !== state.settings.maxDisputesPerFinding ||
      recorded.length !== count ||
      recorded.at(-1)?.direction !== "UPHOLD" ||
      state.pendingDisputes.some(
        (entry) => entry.findingId === arbitration.findingId,
      )
    ) {
      throw workflowError("Polishing arbitration history is incomplete.");
    }
  }
  if (serializedBytes(run) > MAX_DURABLE_RUN_BYTES) {
    throw workflowError("Polishing run exceeds its durable size budget.");
  }
}

export function assertRuntime(runtime) {
  if (
    !isRecord(runtime) ||
    !isRecord(runtime.adapters) ||
    !isRecord(runtime.clarifications) ||
    !isRecord(runtime.git) ||
    !isRecord(runtime.trustedValidation) ||
    typeof runtime.trustedValidation.execute !== "function"
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
    "finishAgentTurn",
    "readInputs",
    "recordChildSession",
    "startAgentTurn",
    "transition",
    "writeRunArtifact",
  ]) {
    if (typeof runtime[name] !== "function") {
      throw workflowError(`Polishing runtime.${name} is invalid.`);
    }
  }
  for (const name of [
    "assertUnchanged",
    "contentFingerprint",
    "inspectPath",
    "preflight",
    "snapshot",
    "stagePolishingHandoff",
    "validationInfrastructureFingerprint",
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
          "gitMetadataWriteBlocked",
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

export function activeTurn(role, workflowState) {
  return Object.freeze({
    role,
    phase: workflowState.toLowerCase().replaceAll("_", "-"),
  });
}

export function diagnosticCode(cause, fallback) {
  return typeof cause?.code === "string" && cause.code.length > 0
    ? cause.code
    : fallback;
}
