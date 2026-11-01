const TEXT = { type: "string" };
const object = (properties) => ({
  type: "object",
  properties,
  required: Object.keys(properties),
  additionalProperties: false,
});
const TEXTS = { type: "array", items: TEXT };
const DECISION_FIELDS = {
  question: TEXT,
  options: TEXTS,
  whyBlocked: TEXT,
  evidence: TEXTS,
};
export const CLARIFICATION_SCHEMA = object({
  status: { type: "string", enum: ["READY", "QUESTIONS", "BLOCKED"] },
  questions: {
    type: "array",
    items: object({ question: TEXT, whyItMatters: TEXT }),
  },
  reason: TEXT,
});
export const PROPOSAL_SCHEMA = object({
  status: { type: "string", enum: ["PROPOSAL", "PRODUCT_DECISION_REQUIRED"] },
  ...DECISION_FIELDS,
  summary: TEXT,
  checks: TEXTS,
  resources: {
    type: "array",
    items: object({
      path: TEXT,
      kind: {
        type: "string",
        enum: [
          "configuration",
          "artifacts",
          "finalization",
          "guidance",
          "ignore",
        ],
      },
      action: { type: "string", enum: ["create", "replace", "reuse"] },
      beforeHash: { type: ["string", "null"] },
      content: TEXT,
    }),
  },
});
export const REVIEW_SCHEMA = object({
  status: {
    type: "string",
    enum: ["CLEAN", "FINDINGS", "PRODUCT_DECISION_REQUIRED"],
  },
  ...DECISION_FIELDS,
  proposalHash: TEXT,
  findings: TEXTS,
});
