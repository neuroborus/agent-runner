import {
  MAX_BOOTSTRAP_ITEMS,
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

const PORTABLE_PLAIN_TEXT_PATTERN =
  "^[^\\u0000-\\u001f\\u007f-\\u009f\\u2028\\u2029]+$";
const PORTABLE_REPOSITORY_PATH_PATTERN =
  "^[^\\\\/\\u0000-\\u001f\\u007f-\\u009f\\u2028\\u2029]+(?:/[^\\\\/\\u0000-\\u001f\\u007f-\\u009f\\u2028\\u2029]+)*$";
const PORTABLE_NONEMPTY_SUMMARY_PATTERN =
  "^[^\\u0000\\u2028\\u2029]+$";
const TEXT = { type: "string", maxLength: MAX_TEXT_LENGTH };
const SUMMARY = { type: "string", maxLength: MAX_SUMMARY_LENGTH };
const TEXT_LIST = { type: "array", items: TEXT, maxItems: MAX_ITEMS };
const OPTIONS = { type: "array", items: TEXT, maxItems: MAX_OPTIONS };
const EMPTY_TEXT = { type: "string", maxLength: 0 };
const EMPTY_TEXT_LIST = { ...TEXT_LIST, maxItems: 0 };
const EMPTY_OPTIONS = { ...OPTIONS, maxItems: 0 };
const NONEMPTY_TEXT = {
  ...TEXT,
  minLength: 1,
  pattern: PORTABLE_PLAIN_TEXT_PATTERN,
};
const NONEMPTY_SUMMARY = {
  ...SUMMARY,
  minLength: 1,
  pattern: PORTABLE_NONEMPTY_SUMMARY_PATTERN,
};
const NONEMPTY_TEXT_LIST = {
  ...TEXT_LIST,
  items: NONEMPTY_TEXT,
  minItems: 1,
};
const TEXT_OPTIONS = { ...OPTIONS, items: NONEMPTY_TEXT };
const EXACT_COMMAND = {
  type: "string",
  minLength: 1,
  maxLength: MAX_TEXT_LENGTH,
  pattern: PORTABLE_PLAIN_TEXT_PATTERN,
};
const VALIDATION_PATH = {
  type: "string",
  minLength: 1,
  maxLength: MAX_TEXT_LENGTH,
  pattern: PORTABLE_REPOSITORY_PATH_PATTERN,
};
const REQUIRED_CHECK = {
  type: "object",
  properties: {
    id: { type: "string", maxLength: 10, pattern: "^C[1-9][0-9]{0,8}$" },
    command: EXACT_COMMAND,
  },
  required: ["id", "command"],
  additionalProperties: false,
};
const REQUIRED_CHECKS = {
  type: "array",
  items: REQUIRED_CHECK,
  maxItems: MAX_VALIDATION_ITEMS,
};
const BOOTSTRAP_REQUIRED_CHECKS = {
  ...REQUIRED_CHECKS,
  maxItems: MAX_BOOTSTRAP_ITEMS,
};
const EMPTY_REQUIRED_CHECKS = { ...BOOTSTRAP_REQUIRED_CHECKS, maxItems: 0 };
const NONEMPTY_REQUIRED_CHECKS = {
  ...BOOTSTRAP_REQUIRED_CHECKS,
  minItems: 1,
};
const VALIDATION_INFRASTRUCTURE = {
  type: "array",
  items: VALIDATION_PATH,
  maxItems: MAX_VALIDATION_ITEMS,
};
const BOOTSTRAP_VALIDATION_INFRASTRUCTURE = {
  ...VALIDATION_INFRASTRUCTURE,
  maxItems: MAX_BOOTSTRAP_ITEMS,
};
const EMPTY_VALIDATION_INFRASTRUCTURE = {
  ...BOOTSTRAP_VALIDATION_INFRASTRUCTURE,
  maxItems: 0,
};
const CHECK_RESULT = {
  type: "object",
  properties: {
    checkId: { type: "string", maxLength: 10, pattern: "^C[1-9][0-9]{0,8}$" },
    command: EXACT_COMMAND,
    status: { type: "string", enum: ["PASS", "FAIL", "BLOCKED", "NOT_RUN"] },
    evidence: TEXT_LIST,
  },
  required: ["checkId", "command", "status", "evidence"],
  additionalProperties: false,
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
const DECISION_PROPERTIES = {
  question: TEXT,
  options: OPTIONS,
  whyBlocked: TEXT,
  evidence: TEXT_LIST,
};
const EMPTY_DECISION_PROPERTIES = {
  question: EMPTY_TEXT,
  options: EMPTY_OPTIONS,
  whyBlocked: EMPTY_TEXT,
  evidence: EMPTY_TEXT_LIST,
};
const PRODUCT_DECISION_PROPERTIES = {
  question: NONEMPTY_TEXT,
  options: TEXT_OPTIONS,
  whyBlocked: NONEMPTY_TEXT,
  evidence: NONEMPTY_TEXT_LIST,
};
const BOOTSTRAP_PROPERTIES = {
  status: {
    type: "string",
    enum: [
      "READY",
      "CAPACITY_EXHAUSTED",
      "PLAN_REVISION_REQUIRED",
      "PRODUCT_DECISION_REQUIRED",
    ],
  },
  summary: SUMMARY,
  requiredChecks: BOOTSTRAP_REQUIRED_CHECKS,
  validationInfrastructure: BOOTSTRAP_VALIDATION_INFRASTRUCTURE,
  capacityField: {
    type: "string",
    enum: ["", "requiredChecks", "validationInfrastructure"],
  },
  capacityLimit: {
    type: "integer",
    enum: [0, MAX_BOOTSTRAP_ITEMS],
  },
  reason: TEXT,
  ...DECISION_PROPERTIES,
};
const RECONCILIATION_PROPERTIES = {
  status: {
    type: "string",
    enum: [
      "RESOLVED",
      "DISAGREEMENT",
      "PLAN_REVISION_REQUIRED",
      "PRODUCT_DECISION_REQUIRED",
    ],
  },
  summary: SUMMARY,
  disagreement: TEXT,
  reason: TEXT,
  ...DECISION_PROPERTIES,
};
const ARBITRATION_PROPERTIES = {
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
  summary: SUMMARY,
  rationale: NONEMPTY_TEXT,
  reason: TEXT,
  ...DECISION_PROPERTIES,
};

function strictObject(properties) {
  return {
    type: "object",
    properties,
    required: Object.keys(properties),
    additionalProperties: false,
  };
}

function variant(discriminator, values, properties, constraints) {
  return strictObject({
    ...properties,
    [discriminator]: { ...properties[discriminator], enum: values },
    ...constraints,
  });
}

function resultUnion(variants) {
  return strictObject({ result: { anyOf: variants } });
}

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

export const BOOTSTRAP_SCHEMA = deepFreeze(
  resultUnion([
    variant("status", ["READY"], BOOTSTRAP_PROPERTIES, {
      summary: NONEMPTY_SUMMARY,
      requiredChecks: NONEMPTY_REQUIRED_CHECKS,
      capacityField: { type: "string", enum: [""] },
      capacityLimit: { type: "integer", enum: [0] },
      reason: EMPTY_TEXT,
      ...EMPTY_DECISION_PROPERTIES,
    }),
    variant("status", ["CAPACITY_EXHAUSTED"], BOOTSTRAP_PROPERTIES, {
      summary: EMPTY_TEXT,
      requiredChecks: EMPTY_REQUIRED_CHECKS,
      validationInfrastructure: EMPTY_VALIDATION_INFRASTRUCTURE,
      capacityField: {
        type: "string",
        enum: ["requiredChecks", "validationInfrastructure"],
      },
      capacityLimit: { type: "integer", enum: [MAX_BOOTSTRAP_ITEMS] },
      reason: EMPTY_TEXT,
      ...EMPTY_DECISION_PROPERTIES,
    }),
    variant("status", ["PLAN_REVISION_REQUIRED"], BOOTSTRAP_PROPERTIES, {
      summary: EMPTY_TEXT,
      requiredChecks: EMPTY_REQUIRED_CHECKS,
      validationInfrastructure: EMPTY_VALIDATION_INFRASTRUCTURE,
      capacityField: { type: "string", enum: [""] },
      capacityLimit: { type: "integer", enum: [0] },
      reason: NONEMPTY_TEXT,
      question: EMPTY_TEXT,
      options: EMPTY_OPTIONS,
      whyBlocked: EMPTY_TEXT,
      evidence: NONEMPTY_TEXT_LIST,
    }),
    variant("status", ["PRODUCT_DECISION_REQUIRED"], BOOTSTRAP_PROPERTIES, {
      summary: EMPTY_TEXT,
      requiredChecks: EMPTY_REQUIRED_CHECKS,
      validationInfrastructure: EMPTY_VALIDATION_INFRASTRUCTURE,
      capacityField: { type: "string", enum: [""] },
      capacityLimit: { type: "integer", enum: [0] },
      reason: EMPTY_TEXT,
      ...PRODUCT_DECISION_PROPERTIES,
    }),
  ]),
);

export const BOOTSTRAP_RECONCILIATION_SCHEMA = deepFreeze(
  resultUnion([
    variant("status", ["RESOLVED"], RECONCILIATION_PROPERTIES, {
      summary: NONEMPTY_SUMMARY,
      disagreement: EMPTY_TEXT,
      reason: EMPTY_TEXT,
      ...EMPTY_DECISION_PROPERTIES,
    }),
    variant("status", ["DISAGREEMENT"], RECONCILIATION_PROPERTIES, {
      summary: EMPTY_TEXT,
      disagreement: NONEMPTY_TEXT,
      reason: EMPTY_TEXT,
      question: EMPTY_TEXT,
      options: EMPTY_OPTIONS,
      whyBlocked: EMPTY_TEXT,
      evidence: NONEMPTY_TEXT_LIST,
    }),
    variant(
      "status",
      ["PLAN_REVISION_REQUIRED"],
      RECONCILIATION_PROPERTIES,
      {
        summary: EMPTY_TEXT,
        disagreement: EMPTY_TEXT,
        reason: NONEMPTY_TEXT,
        question: EMPTY_TEXT,
        options: EMPTY_OPTIONS,
        whyBlocked: EMPTY_TEXT,
        evidence: NONEMPTY_TEXT_LIST,
      },
    ),
    variant(
      "status",
      ["PRODUCT_DECISION_REQUIRED"],
      RECONCILIATION_PROPERTIES,
      {
        summary: EMPTY_TEXT,
        disagreement: EMPTY_TEXT,
        reason: EMPTY_TEXT,
        ...PRODUCT_DECISION_PROPERTIES,
      },
    ),
  ]),
);

export const BOOTSTRAP_ARBITRATION_SCHEMA = deepFreeze(
  resultUnion([
    variant(
      "direction",
      ["USE_WORKER", "USE_REVIEWER", "SYNTHESIZE"],
      ARBITRATION_PROPERTIES,
      {
        summary: NONEMPTY_SUMMARY,
        reason: EMPTY_TEXT,
        ...EMPTY_DECISION_PROPERTIES,
      },
    ),
    variant(
      "direction",
      ["PLAN_REVISION_REQUIRED"],
      ARBITRATION_PROPERTIES,
      {
        summary: EMPTY_TEXT,
        reason: NONEMPTY_TEXT,
        question: EMPTY_TEXT,
        options: EMPTY_OPTIONS,
        whyBlocked: EMPTY_TEXT,
        evidence: NONEMPTY_TEXT_LIST,
      },
    ),
    variant(
      "direction",
      ["PRODUCT_DECISION_REQUIRED"],
      ARBITRATION_PROPERTIES,
      {
        summary: EMPTY_TEXT,
        reason: EMPTY_TEXT,
        ...PRODUCT_DECISION_PROPERTIES,
      },
    ),
  ]),
);

export const IMPLEMENTATION_SCHEMA = deepFreeze({
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
    issues: { type: "array", items: FINALIZATION_ISSUE },
    requiredChecks: REQUIRED_CHECKS,
    validationInfrastructure: VALIDATION_INFRASTRUCTURE,
    checks: {
      type: "array",
      items: CHECK_RESULT,
      maxItems: MAX_VALIDATION_ITEMS,
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
    findings: { type: "array", items: REVIEW_FINDING },
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
