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
const FINDING_ID = {
  type: "string",
  maxLength: 64,
  pattern: "^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$",
};
const QUESTION = {
  type: "object",
  properties: {
    question: TEXT,
    whyItMatters: TEXT,
  },
  required: ["question", "whyItMatters"],
  additionalProperties: false,
};
const FINDING = {
  type: "object",
  properties: {
    id: FINDING_ID,
    description: TEXT,
    evidence: TEXT_LIST,
  },
  required: ["id", "description", "evidence"],
  additionalProperties: false,
};

export const CLARIFICATION_SCHEMA = deepFreeze({
  type: "object",
  properties: {
    status: { type: "string", enum: ["READY", "QUESTIONS"] },
    questions: { type: "array", items: QUESTION },
  },
  required: ["status", "questions"],
  additionalProperties: false,
});

export const PLANNER_SCHEMA = deepFreeze({
  type: "object",
  properties: {
    status: {
      type: "string",
      enum: ["DRAFT", "PRODUCT_DECISION_REQUIRED"],
    },
    plan: TEXT,
    question: TEXT,
    options: TEXT_LIST,
    whyBlocked: TEXT,
    evidence: TEXT_LIST,
  },
  required: ["status", "plan", "question", "options", "whyBlocked", "evidence"],
  additionalProperties: false,
});

export const REVIEW_SCHEMA = deepFreeze({
  type: "object",
  properties: {
    status: {
      type: "string",
      enum: ["APPROVED", "FINDINGS", "PRODUCT_DECISION_REQUIRED"],
    },
    findings: { type: "array", items: FINDING },
    question: TEXT,
    options: TEXT_LIST,
    whyBlocked: TEXT,
    evidence: TEXT_LIST,
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

export const CHECK_AND_FIX_SCHEMA = deepFreeze({
  type: "object",
  properties: {
    status: {
      type: "string",
      enum: ["CHANGED", "UNCHANGED", "PRODUCT_DECISION_REQUIRED"],
    },
    plan: TEXT,
    question: TEXT,
    options: TEXT_LIST,
    whyBlocked: TEXT,
    evidence: TEXT_LIST,
  },
  required: ["status", "plan", "question", "options", "whyBlocked", "evidence"],
  additionalProperties: false,
});

export const CLEAN_CONFIRM_SCHEMA = deepFreeze({
  type: "object",
  properties: {
    status: {
      type: "string",
      enum: ["CLEAN", "FINDINGS", "PRODUCT_DECISION_REQUIRED"],
    },
    findings: { type: "array", items: FINDING },
    question: TEXT,
    options: TEXT_LIST,
    whyBlocked: TEXT,
    evidence: TEXT_LIST,
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

export const STAGNATION_SCHEMA = deepFreeze({
  type: "object",
  properties: {
    direction: {
      type: "string",
      enum: [
        "CONTINUE_REVISION",
        "RESTRUCTURE_PLAN",
        "RECONSIDER_FINDINGS",
        "PRODUCT_DECISION_REQUIRED",
      ],
    },
    rationale: TEXT,
    findingIds: { type: "array", items: FINDING_ID },
    question: TEXT,
    options: TEXT_LIST,
    whyBlocked: TEXT,
    evidence: TEXT_LIST,
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
