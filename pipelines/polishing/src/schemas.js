import {
  MAX_ITEMS,
  MAX_OPTIONS,
  MAX_SUMMARY_LENGTH,
  MAX_TEXT_LENGTH,
  MAX_VALIDATION_ITEMS,
} from "./workflow-contract.js";

function deepFreeze(value) {
  if (value === null || typeof value !== "object" || Object.isFrozen(value)) {
    return value;
  }
  Object.freeze(value);
  for (const child of Object.values(value)) {
    deepFreeze(child);
  }
  return value;
}

const TEXT = { type: "string", maxLength: MAX_TEXT_LENGTH };
const SUMMARY = { type: "string", maxLength: MAX_SUMMARY_LENGTH };
const TEXT_LIST = { type: "array", maxItems: MAX_ITEMS, items: TEXT };
const REQUIRED_CHECK = {
  type: "object",
  properties: {
    id: { type: "string", pattern: "^C[1-9][0-9]{0,8}$" },
    command: TEXT,
  },
  required: ["id", "command"],
  additionalProperties: false,
};
const REQUIRED_CHECKS = {
  type: "array",
  maxItems: MAX_VALIDATION_ITEMS,
  items: REQUIRED_CHECK,
};
const BOOTSTRAP_REQUIRED_CHECKS = { ...REQUIRED_CHECKS, maxItems: MAX_ITEMS };
const VALIDATION_INFRASTRUCTURE = {
  type: "array",
  maxItems: MAX_VALIDATION_ITEMS,
  items: TEXT,
};
const BOOTSTRAP_VALIDATION_INFRASTRUCTURE = {
  ...VALIDATION_INFRASTRUCTURE,
  maxItems: MAX_ITEMS,
};
const CHECK_RESULT = {
  type: "object",
  properties: {
    checkId: { type: "string", pattern: "^C[1-9][0-9]{0,8}$" },
    command: TEXT,
    status: { type: "string", enum: ["PASS", "FAIL", "BLOCKED", "NOT_RUN"] },
    evidence: TEXT_LIST,
  },
  required: ["checkId", "command", "status", "evidence"],
  additionalProperties: false,
};
const OPTION_LIST = { type: "array", maxItems: MAX_OPTIONS, items: TEXT };
const QUESTION = {
  type: "object",
  properties: {
    question: TEXT,
    whyItMatters: TEXT,
  },
  required: ["question", "whyItMatters"],
  additionalProperties: false,
};
const DECISION_PROPERTIES = {
  question: TEXT,
  options: OPTION_LIST,
  whyBlocked: TEXT,
  evidence: TEXT_LIST,
};
const FINALIZATION_ISSUE = {
  type: "object",
  properties: {
    id: { type: "string", pattern: "^F[1-9][0-9]{0,8}$" },
    command: TEXT,
    problem: TEXT,
    evidence: TEXT_LIST,
  },
  required: ["id", "command", "problem", "evidence"],
  additionalProperties: false,
};
const REVIEW_FINDING = {
  type: "object",
  properties: {
    id: { type: "string", pattern: "^R[1-9][0-9]{0,8}$" },
    file: TEXT,
    problem: TEXT,
    reason: TEXT,
    suggestedAction: TEXT,
  },
  required: ["id", "file", "problem", "reason", "suggestedAction"],
  additionalProperties: false,
};

export const CLARIFICATION_SCHEMA = deepFreeze({
  type: "object",
  properties: {
    status: {
      type: "string",
      enum: ["READY", "QUESTIONS", "PRODUCT_DECISION_REQUIRED"],
    },
    questions: { type: "array", maxItems: MAX_ITEMS, items: QUESTION },
    reason: TEXT,
    ...DECISION_PROPERTIES,
  },
  required: [
    "status",
    "questions",
    "reason",
    "question",
    "options",
    "whyBlocked",
    "evidence",
  ],
  additionalProperties: false,
});

export const BOOTSTRAP_SCHEMA = deepFreeze({
  type: "object",
  properties: {
    status: {
      type: "string",
      enum: ["READY", "PRODUCT_DECISION_REQUIRED"],
    },
    summary: SUMMARY,
    requiredChecks: BOOTSTRAP_REQUIRED_CHECKS,
    validationInfrastructure: BOOTSTRAP_VALIDATION_INFRASTRUCTURE,
    reason: TEXT,
    ...DECISION_PROPERTIES,
  },
  required: [
    "status",
    "summary",
    "requiredChecks",
    "validationInfrastructure",
    "reason",
    "question",
    "options",
    "whyBlocked",
    "evidence",
  ],
  additionalProperties: false,
});

export const BOOTSTRAP_RECONCILIATION_SCHEMA = deepFreeze({
  type: "object",
  properties: {
    status: {
      type: "string",
      enum: ["RESOLVED", "DISAGREEMENT", "PRODUCT_DECISION_REQUIRED"],
    },
    summary: SUMMARY,
    disagreement: TEXT,
    reason: TEXT,
    ...DECISION_PROPERTIES,
  },
  required: [
    "status",
    "summary",
    "disagreement",
    "reason",
    "question",
    "options",
    "whyBlocked",
    "evidence",
  ],
  additionalProperties: false,
});

export const BOOTSTRAP_ARBITRATION_SCHEMA = deepFreeze({
  type: "object",
  properties: {
    direction: {
      type: "string",
      enum: [
        "USE_WORKER",
        "USE_REVIEWER",
        "SYNTHESIZE",
        "PRODUCT_DECISION_REQUIRED",
      ],
    },
    summary: SUMMARY,
    rationale: TEXT,
    reason: TEXT,
    ...DECISION_PROPERTIES,
  },
  required: [
    "direction",
    "summary",
    "rationale",
    "reason",
    "question",
    "options",
    "whyBlocked",
    "evidence",
  ],
  additionalProperties: false,
});

export const POLISH_SCHEMA = deepFreeze({
  type: "object",
  properties: {
    status: {
      type: "string",
      enum: ["COMPLETED", "BLOCKED", "PRODUCT_DECISION_REQUIRED"],
    },
    summary: SUMMARY,
    reason: TEXT,
    ...DECISION_PROPERTIES,
  },
  required: [
    "status",
    "summary",
    "reason",
    "question",
    "options",
    "whyBlocked",
    "evidence",
  ],
  additionalProperties: false,
});

export const FINALIZATION_SCHEMA = deepFreeze({
  type: "object",
  properties: {
    status: {
      type: "string",
      enum: [
        "PASS",
        "FAIL",
        "SKILL_MISSING",
        "SKILL_INVALID",
        "BLOCKED",
        "PRODUCT_DECISION_REQUIRED",
      ],
    },
    skillPath: TEXT,
    summary: SUMMARY,
    issues: { type: "array", maxItems: MAX_ITEMS, items: FINALIZATION_ISSUE },
    requiredChecks: REQUIRED_CHECKS,
    validationInfrastructure: VALIDATION_INFRASTRUCTURE,
    checks: {
      type: "array",
      maxItems: MAX_VALIDATION_ITEMS,
      items: CHECK_RESULT,
    },
    reason: TEXT,
    ...DECISION_PROPERTIES,
  },
  required: [
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
  ],
  additionalProperties: false,
});

export const REVIEW_SCHEMA = deepFreeze({
  type: "object",
  properties: {
    status: {
      type: "string",
      enum: ["APPROVED", "FINDINGS", "PRODUCT_DECISION_REQUIRED"],
    },
    findings: { type: "array", maxItems: MAX_ITEMS, items: REVIEW_FINDING },
    validationChange: {
      type: "string",
      enum: ["UNCHANGED", "ACCEPTED", "REJECTED"],
    },
    validationEvidence: TEXT_LIST,
    ...DECISION_PROPERTIES,
  },
  required: [
    "status",
    "findings",
    "validationChange",
    "validationEvidence",
    "question",
    "options",
    "whyBlocked",
    "evidence",
  ],
  additionalProperties: false,
});

export const FINDING_RESOLUTION_SCHEMA = deepFreeze({
  type: "object",
  properties: {
    status: {
      type: "string",
      enum: ["RESOLVED", "BLOCKED", "PRODUCT_DECISION_REQUIRED"],
    },
    decisions: {
      type: "array",
      maxItems: MAX_ITEMS,
      items: {
        type: "object",
        properties: {
          id: { type: "string", pattern: "^[FR][1-9][0-9]{0,8}$" },
          decision: { type: "string", enum: ["FIX", "DISPUTE"] },
          reason: TEXT,
          evidence: TEXT_LIST,
        },
        required: ["id", "decision", "reason", "evidence"],
        additionalProperties: false,
      },
    },
    reason: TEXT,
    ...DECISION_PROPERTIES,
  },
  required: [
    "status",
    "decisions",
    "reason",
    "question",
    "options",
    "whyBlocked",
    "evidence",
  ],
  additionalProperties: false,
});

export const DISPUTE_RECONSIDERATION_SCHEMA = deepFreeze({
  type: "object",
  properties: {
    status: {
      type: "string",
      enum: ["RESOLVED", "PRODUCT_DECISION_REQUIRED"],
    },
    decisions: {
      type: "array",
      maxItems: MAX_ITEMS,
      items: {
        type: "object",
        properties: {
          id: { type: "string", pattern: "^R[1-9][0-9]{0,8}$" },
          direction: { type: "string", enum: ["WITHDRAW", "UPHOLD"] },
          reason: TEXT,
          evidence: TEXT_LIST,
        },
        required: ["id", "direction", "reason", "evidence"],
        additionalProperties: false,
      },
    },
    ...DECISION_PROPERTIES,
  },
  required: [
    "status",
    "decisions",
    "question",
    "options",
    "whyBlocked",
    "evidence",
  ],
  additionalProperties: false,
});

export const FINDING_ARBITRATION_SCHEMA = deepFreeze({
  type: "object",
  properties: {
    direction: {
      type: "string",
      enum: ["WORKER_CORRECT", "REVIEWER_CORRECT", "REQUIREMENT_AMBIGUOUS"],
    },
    rationale: TEXT,
    ...DECISION_PROPERTIES,
  },
  required: [
    "direction",
    "rationale",
    "question",
    "options",
    "whyBlocked",
    "evidence",
  ],
  additionalProperties: false,
});

export const STAGNATION_SCHEMA = deepFreeze({
  type: "object",
  properties: {
    direction: {
      type: "string",
      enum: [
        "CONTINUE_FIXES",
        "REWORK_IMPLEMENTATION",
        "RECONSIDER_FINDINGS",
        "PRODUCT_DECISION_REQUIRED",
      ],
    },
    rationale: TEXT,
    findingIds: {
      type: "array",
      maxItems: MAX_ITEMS,
      items: { type: "string", pattern: "^R[1-9][0-9]{0,8}$" },
    },
    ...DECISION_PROPERTIES,
  },
  required: [
    "direction",
    "rationale",
    "findingIds",
    "question",
    "options",
    "whyBlocked",
    "evidence",
  ],
  additionalProperties: false,
});
