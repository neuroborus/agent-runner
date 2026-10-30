import {
  MAX_BOOTSTRAP_ITEMS,
  MAX_TEXT_LENGTH,
  MAX_VALIDATION_ITEMS,
} from "./workflow-contract.js";

// Keep reusable fragments separate from the complete response-schema exports.
export const PORTABLE_PLAIN_TEXT_PATTERN =
  "^[^\\u0000-\\u001f\\u007f-\\u009f\\u2028\\u2029]+$";
const PORTABLE_VALIDATION_PATH_PATTERN =
  "^(?:finalization://)?[^\\\\/\\u0000-\\u001f\\u007f-\\u009f\\u2028\\u2029]+(?:/[^\\\\/\\u0000-\\u001f\\u007f-\\u009f\\u2028\\u2029]+)*$";

export const EXACT_COMMAND = {
  type: "string",
  minLength: 1,
  maxLength: MAX_TEXT_LENGTH,
  pattern: PORTABLE_PLAIN_TEXT_PATTERN,
};
const VALIDATION_PATH = {
  type: "string",
  minLength: 1,
  maxLength: MAX_TEXT_LENGTH,
  pattern: PORTABLE_VALIDATION_PATH_PATTERN,
};
export const REQUIRED_CHECK = {
  type: "object",
  properties: {
    id: { type: "string", maxLength: 10, pattern: "^C[1-9][0-9]{0,8}$" },
    command: EXACT_COMMAND,
  },
  required: ["id", "command"],
  additionalProperties: false,
};
export const VALIDATION_INFRASTRUCTURE = {
  type: "array",
  items: VALIDATION_PATH,
  maxItems: MAX_VALIDATION_ITEMS,
};
export const BOOTSTRAP_VALIDATION_INFRASTRUCTURE = {
  ...VALIDATION_INFRASTRUCTURE,
  maxItems: MAX_BOOTSTRAP_ITEMS,
};
