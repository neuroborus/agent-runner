import { AUDIT_CATALOG } from "./catalog.js";

const TEXT = { type: "string" };
const TEXTS = { type: "array", items: TEXT };
const object = (properties) => ({
  type: "object",
  properties,
  required: Object.keys(properties),
  additionalProperties: false,
});
const INPUTS = object({
  scope: TEXTS,
  references: TEXTS,
  exclusions: TEXTS,
  criteria: TEXTS,
});
const example = (kind, fields) =>
  object({
    kind: { type: "string", enum: [kind] },
    basis: { type: "string", enum: ["observed", "code-derived"] },
    ...Object.fromEntries(fields.map((key) => [key, TEXT])),
  });
const finding = {
  id: TEXT,
  causeId: TEXT,
  title: TEXT,
  severity: {
    type: "string",
    enum: AUDIT_CATALOG.severities.map(({ name }) => name),
  },
  category: {
    type: "string",
    enum: AUDIT_CATALOG.categories.map(({ name }) => name),
  },
  locations: TEXTS,
  evidence: TEXTS,
  impact: TEXT,
  severityRationale: TEXT,
  examples: {
    type: "array",
    items: {
      anyOf: [
        example("behavioral", ["conditions", "action", "expected", "actual"]),
        example("non-behavioral", ["material", "rule", "violation"]),
      ],
    },
  },
};
const FINDING = {
  anyOf: [object(finding), object({ ...finding, recommendation: TEXT })],
};
const HYPOTHESIS = object({
  id: TEXT,
  title: TEXT,
  evidence: TEXTS,
  uncertainty: TEXT,
});

export const CLARIFICATION_SCHEMA = object({
  status: { type: "string", enum: ["READY", "QUESTIONS", "BLOCKED"] },
  inputs: { anyOf: [INPUTS, { type: "null" }] },
  questions: {
    type: "array",
    items: object({ question: TEXT, whyItMatters: TEXT }),
  },
  reason: TEXT,
});

export const DISCOVERY_SCHEMA = object({
  status: { type: "string", enum: ["COMPLETE", "INCOMPLETE"] },
  snapshotFingerprint: TEXT,
  candidates: {
    type: "array",
    items: FINDING,
  },
  limitations: TEXTS,
  hypotheses: {
    type: "array",
    items: HYPOTHESIS,
  },
  reportCorrections: TEXTS,
});

export const RECHECK_SCHEMA = object({
  status: { type: "string", enum: ["COMPLETE", "INCOMPLETE"] },
  snapshotFingerprint: TEXT,
  reportFingerprint: TEXT,
  batchFingerprint: TEXT,
  decisions: {
    type: "array",
    items: object({
      id: TEXT,
      kind: {
        type: "string",
        enum: ["confirm", "correct", "reject", "merge", "hypothesis"],
      },
      rationale: TEXT,
      finding: { anyOf: [FINDING, { type: "null" }] },
      targetId: { type: ["string", "null"] },
      hypothesis: { anyOf: [HYPOTHESIS, { type: "null" }] },
    }),
  },
  additions: { type: "array", items: FINDING },
});
