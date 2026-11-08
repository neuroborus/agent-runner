import { AUDIT_CATALOG } from "./catalog.js";
import {
  HASH_PATTERN,
  ID_PATTERN,
  MAX_COLLECTION_LENGTH,
  MAX_ID_LENGTH,
  MAX_QUESTION_LENGTH,
  MAX_QUESTIONS,
  MAX_STRING_LENGTH,
} from "./constraints.js";

const TEXT = { type: "string", maxLength: MAX_STRING_LENGTH };
const NONEMPTY_TEXT = { ...TEXT, minLength: 1, pattern: "\\S" };
const SINGLE_LINE_TEXT = {
  ...NONEMPTY_TEXT,
  description: "Nonempty single-line text without control characters.",
};
const ID = {
  type: "string",
  minLength: 1,
  maxLength: MAX_ID_LENGTH,
  pattern: ID_PATTERN,
};
const HASH = {
  type: "string",
  minLength: 64,
  maxLength: 64,
  pattern: HASH_PATTERN,
  description: "Copy the supplied fingerprint exactly; never recompute it.",
};
const list = (items, minItems = 0, maxItems = MAX_COLLECTION_LENGTH) => ({
  type: "array",
  items,
  minItems,
  maxItems,
});
const TEXTS = list(NONEMPTY_TEXT);
const object = (properties) => ({
  type: "object",
  properties,
  required: Object.keys(properties),
  additionalProperties: false,
});
const INPUTS = object({
  scope: list(NONEMPTY_TEXT, 1),
  references: TEXTS,
  exclusions: TEXTS,
  criteria: list(NONEMPTY_TEXT, 1),
});
const example = (kind, fields) =>
  object({
    kind: { type: "string", enum: [kind] },
    basis: { type: "string", enum: ["observed", "code-derived"] },
    ...Object.fromEntries(fields.map((key) => [key, NONEMPTY_TEXT])),
  });
const finding = {
  id: ID,
  causeId: ID,
  title: SINGLE_LINE_TEXT,
  severity: {
    type: "string",
    enum: AUDIT_CATALOG.severities.map(({ name }) => name),
  },
  category: {
    type: "string",
    enum: AUDIT_CATALOG.categories.map(({ name }) => name),
  },
  locations: list(SINGLE_LINE_TEXT, 1),
  evidence: list(NONEMPTY_TEXT, 1),
  impact: NONEMPTY_TEXT,
  severityRationale: NONEMPTY_TEXT,
  examples: list(
    {
      anyOf: [
        example("behavioral", ["conditions", "action", "expected", "actual"]),
        example("non-behavioral", ["material", "rule", "violation"]),
      ],
    },
    1,
  ),
};
const FINDING = {
  anyOf: [
    object(finding),
    object({ ...finding, recommendation: NONEMPTY_TEXT }),
  ],
};
const HYPOTHESIS = object({
  id: ID,
  title: SINGLE_LINE_TEXT,
  evidence: TEXTS,
  uncertainty: NONEMPTY_TEXT,
});

// Also owns diagnostic locations for the public normalized report contract.
export const REPORT_SCHEMA = object({
  scope: list(NONEMPTY_TEXT, 1),
  snapshot: object({ fingerprint: HASH, description: NONEMPTY_TEXT }),
  criteria: list(NONEMPTY_TEXT, 1),
  findings: list(FINDING),
  limitations: TEXTS,
  hypotheses: list(HYPOTHESIS),
});

export const CLARIFICATION_SCHEMA = object({
  status: { type: "string", enum: ["READY", "QUESTIONS", "BLOCKED"] },
  inputs: { anyOf: [INPUTS, { type: "null" }] },
  questions: list(
    object({
      question: { ...SINGLE_LINE_TEXT, maxLength: MAX_QUESTION_LENGTH },
      whyItMatters: { ...SINGLE_LINE_TEXT, maxLength: MAX_QUESTION_LENGTH },
    }),
    0,
    MAX_QUESTIONS,
  ),
  reason: { ...TEXT, maxLength: MAX_QUESTION_LENGTH },
});

export const DISCOVERY_SCHEMA = object({
  status: { type: "string", enum: ["COMPLETE", "INCOMPLETE"] },
  snapshotFingerprint: HASH,
  candidates: list(FINDING),
  limitations: TEXTS,
  hypotheses: list(HYPOTHESIS),
  reportCorrections: TEXTS,
});

export const RECHECK_SCHEMA = object({
  status: { type: "string", enum: ["COMPLETE", "INCOMPLETE"] },
  snapshotFingerprint: HASH,
  reportFingerprint: HASH,
  batchFingerprint: HASH,
  decisions: list(
    object({
      id: ID,
      kind: {
        type: "string",
        enum: ["confirm", "correct", "reject", "merge", "hypothesis"],
      },
      rationale: NONEMPTY_TEXT,
      finding: { anyOf: [FINDING, { type: "null" }] },
      targetId: { anyOf: [ID, { type: "null" }] },
      hypothesis: { anyOf: [HYPOTHESIS, { type: "null" }] },
    }),
    1,
  ),
  additions: list(FINDING),
});
