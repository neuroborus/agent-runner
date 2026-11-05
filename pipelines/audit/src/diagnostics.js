import { MAX_COLLECTION_LENGTH } from "./constraints.js";
import {
  CLARIFICATION_SCHEMA,
  DISCOVERY_SCHEMA,
  RECHECK_SCHEMA,
  REPORT_SCHEMA,
} from "./schemas.js";

// Validation is fail-fast: one recognized constraint per rejected result.
export const MAX_AUDIT_DIAGNOSTICS = 1;
export const AUDIT_DIAGNOSTIC_MESSAGES = Object.freeze({
  "invalid-result": "must satisfy the audit result contract.",
  "invalid-record": "must be an object.",
  "unsupported-fields": "contains unsupported fields.",
  "required-fields": "is missing required fields.",
  "invalid-text":
    "must be nonempty text without control characters or unsupported line breaks.",
  "invalid-id": "must be a lowercase kebab-case ID of at most 64 characters.",
  "unsupported-value": "must be a supported value.",
  "required-items": "must be an array with the required minimum entries.",
  "duplicate-items": "must not contain duplicates after text normalization.",
  "duplicate-ids": "must have unique report-local IDs.",
  "shared-cause":
    "must consolidate each shared cause into one finding retaining all locations.",
  "invalid-fingerprint": "must be a SHA-256 content fingerprint.",
  "binding-mismatch": "must copy the supplied fingerprint exactly.",
  "invalid-outcome": "must satisfy the selected status requirements.",
  "invalid-payload": "must carry only the payload allowed by its disposition.",
  "candidate-mismatch": "must decide each supplied candidate exactly once.",
  "identity-mismatch": "must preserve the established finding and cause IDs.",
  "invalid-merge":
    "must name a distinct confirmed or corrected retained target.",
  "collection-limit": "exceeds the 10,000-item collection limit.",
  "field-limit": "exceeds the 100,000-character field limit.",
  "nesting-limit": "exceeds the persistent nesting limit.",
  "result-size": "exceeds the two-MiB serialized result limit.",
  unserializable: "must be JSON serializable.",
});

const SCHEMAS = {
  clarification: CLARIFICATION_SCHEMA,
  discovery: DISCOVERY_SCHEMA,
  recheck: RECHECK_SCHEMA,
  report: REPORT_SCHEMA,
};
const variants = (schema) => schema.anyOf?.flatMap(variants) ?? [schema];

// Resolve only schema-owned names and bounded indices, never rejected keys.
function safeField(field) {
  if (field === "result") return field;
  if (typeof field !== "string" || field.length > 256) return "result";
  const tokens = field.match(/[A-Za-z][A-Za-z0-9]*|\[[0-9]+\]/gu) ?? [];
  if (tokens.join(".").replaceAll(".[", "[") !== field) return "result";
  const root = tokens.shift();
  if (!Object.hasOwn(SCHEMAS, root)) return "result";
  let schemas = variants(SCHEMAS[root]);
  for (const token of tokens) {
    const index = token.startsWith("[") ? Number(token.slice(1, -1)) : null;
    if (
      index !== null &&
      (!Number.isSafeInteger(index) ||
        index < 0 ||
        index >= MAX_COLLECTION_LENGTH ||
        token !== `[${index}]`)
    )
      return "result";
    schemas = schemas.flatMap((schema) => {
      const child =
        index === null
          ? schema.properties && Object.hasOwn(schema.properties, token)
            ? schema.properties[token]
            : undefined
          : index < (schema.maxItems ?? MAX_COLLECTION_LENGTH)
            ? schema.items
            : undefined;
      return child ? variants(child) : [];
    });
    if (schemas.length === 0) return "result";
  }
  return field;
}

export function auditDiagnostic(field, code) {
  return Object.freeze({
    field: safeField(field),
    code:
      typeof code === "string" && Object.hasOwn(AUDIT_DIAGNOSTIC_MESSAGES, code)
        ? code
        : "invalid-result",
  });
}

export function diagnosticIssues(diagnostic) {
  return Object.freeze([
    `${diagnostic.field} ${AUDIT_DIAGNOSTIC_MESSAGES[diagnostic.code]}`,
  ]);
}
