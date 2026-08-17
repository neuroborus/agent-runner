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
