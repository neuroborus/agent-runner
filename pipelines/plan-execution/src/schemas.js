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

const TEXT = { type: "string" };
const TEXT_LIST = { type: "array", items: TEXT };
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
  options: TEXT_LIST,
  whyBlocked: TEXT,
  evidence: TEXT_LIST,
};
const REVIEW_FINDING_ID = {
  type: "string",
  maxLength: 10,
  pattern: "^R[1-9][0-9]{0,8}$",
};
const BLOCKER_ID = {
  type: "string",
  maxLength: 10,
  pattern: "^(?:R|F)[1-9][0-9]{0,8}$",
};
const FINALIZATION_ISSUE = {
  type: "object",
  properties: {
    id: {
      type: "string",
      maxLength: 10,
      pattern: "^F[1-9][0-9]{0,8}$",
    },
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
    id: REVIEW_FINDING_ID,
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
      enum: [
        "READY",
        "QUESTIONS",
        "PLAN_REVISION_REQUIRED",
        "PRODUCT_DECISION_REQUIRED",
      ],
    },
    questions: { type: "array", items: QUESTION },
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

export const PLAN_COMPATIBILITY_SCHEMA = deepFreeze({
  type: "object",
  properties: {
    status: { type: "string", enum: ["READY", "PLAN_REVISION_REQUIRED"] },
    reason: TEXT,
    evidence: TEXT_LIST,
  },
  required: ["status", "reason", "evidence"],
  additionalProperties: false,
});

export const BOOTSTRAP_SCHEMA = deepFreeze({
  type: "object",
  properties: {
    status: {
      type: "string",
      enum: [
        "READY",
        "PLAN_REVISION_REQUIRED",
        "PRODUCT_DECISION_REQUIRED",
      ],
    },
    summary: TEXT,
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

export const BOOTSTRAP_RECONCILIATION_SCHEMA = deepFreeze({
  type: "object",
  properties: {
    status: {
      type: "string",
      enum: [
        "RESOLVED",
        "DISAGREEMENT",
        "PLAN_REVISION_REQUIRED",
        "PRODUCT_DECISION_REQUIRED",
      ],
    },
    summary: TEXT,
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
        "PLAN_REVISION_REQUIRED",
        "PRODUCT_DECISION_REQUIRED",
      ],
    },
    summary: TEXT,
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

export const IMPLEMENTATION_SCHEMA = deepFreeze({
  type: "object",
  properties: {
    status: {
      type: "string",
      enum: ["COMPLETED", "BLOCKED", "PRODUCT_DECISION_REQUIRED"],
    },
    summary: TEXT,
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
    summary: TEXT,
    issues: { type: "array", items: FINALIZATION_ISSUE },
    reason: TEXT,
    ...DECISION_PROPERTIES,
  },
  required: [
    "status",
    "skillPath",
    "summary",
    "issues",
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
    findings: { type: "array", items: REVIEW_FINDING },
    ...DECISION_PROPERTIES,
  },
  required: [
    "status",
    "findings",
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
      enum: ["RESOLVED", "PRODUCT_DECISION_REQUIRED"],
    },
    decisions: {
      type: "array",
      items: {
        type: "object",
        properties: {
          id: BLOCKER_ID,
          decision: { type: "string", enum: ["FIX", "DISPUTE"] },
          reason: TEXT,
          evidence: TEXT_LIST,
        },
        required: ["id", "decision", "reason", "evidence"],
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

export const DISPUTE_RECONSIDERATION_SCHEMA = deepFreeze({
  type: "object",
  properties: {
    status: {
      type: "string",
      enum: ["RESOLVED", "PRODUCT_DECISION_REQUIRED"],
    },
    decisions: {
      type: "array",
      items: {
        type: "object",
        properties: {
          id: REVIEW_FINDING_ID,
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
        "PLAN_REVISION_REQUIRED",
        "PRODUCT_DECISION_REQUIRED",
      ],
    },
    rationale: TEXT,
    findingIds: { type: "array", items: REVIEW_FINDING_ID },
    reason: TEXT,
    ...DECISION_PROPERTIES,
  },
  required: [
    "direction",
    "rationale",
    "findingIds",
    "reason",
    "question",
    "options",
    "whyBlocked",
    "evidence",
  ],
  additionalProperties: false,
});
