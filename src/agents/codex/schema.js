import { isRecord } from "../adapter-contract.js";

const KEYWORDS = new Set([
  "$defs",
  "$ref",
  "type",
  "title",
  "description",
  "enum",
  "const",
  "properties",
  "required",
  "additionalProperties",
  "items",
  "anyOf",
  "minLength",
  "maxLength",
  "pattern",
  "format",
  "minimum",
  "maximum",
  "exclusiveMinimum",
  "exclusiveMaximum",
  "multipleOf",
  "minItems",
  "maxItems",
]);
const TYPES = new Set([
  "object",
  "array",
  "string",
  "number",
  "integer",
  "boolean",
  "null",
]);
const FORMATS = new Set([
  "date-time",
  "time",
  "date",
  "duration",
  "email",
  "hostname",
  "ipv4",
  "ipv6",
  "uuid",
]);

function isSupportedPattern(pattern) {
  if (typeof pattern !== "string") {
    return false;
  }
  try {
    new RegExp(pattern, "u");
  } catch {
    return false;
  }
  let characterClass = false;
  for (let index = 0; index < pattern.length; index += 1) {
    const character = pattern[index];
    if (character === "\\") {
      index += 1;
      if (!characterClass && /[1-9k]/u.test(pattern[index])) {
        return false;
      }
    } else if (character === "[") {
      characterClass = true;
    } else if (character === "]") {
      characterClass = false;
    } else if (
      !characterClass &&
      /^\(\?(?:[=!]|<[=!])/u.test(pattern.slice(index, index + 4))
    ) {
      return false;
    }
  }
  return true;
}

// The shared contract has already bounded and normalized JSON and strict
// objects. Walk schema positions only: property names and enum/const data are
// not keywords. Provider-specific restrictions must not affect Claude.
export function assertCodexSchema(schema, AdapterError) {
  if (schema === undefined) {
    return;
  }
  function reject() {
    throw new AdapterError("Codex output schema is not supported.", {
      code: "ERR_INVALID_CODEX_SCHEMA",
    });
  }
  if (schema.type !== "object" || Object.hasOwn(schema, "anyOf")) {
    reject();
  }
  const pending = [schema];
  const schemas = new Set();
  const references = [];
  while (pending.length > 0) {
    const entry = pending.pop();
    if (
      !isRecord(entry) ||
      Object.keys(entry).some((keyword) => !KEYWORDS.has(keyword)) ||
      !["type", "anyOf", "enum", "const", "$ref"].some((keyword) =>
        Object.hasOwn(entry, keyword),
      )
    ) {
      reject();
    }
    schemas.add(entry);
    if (entry.type !== undefined) {
      const types = Array.isArray(entry.type) ? entry.type : [entry.type];
      if (
        types.length === 0 ||
        new Set(types).size !== types.length ||
        types.some((type) => !TYPES.has(type)) ||
        (types.includes("array") && !isRecord(entry.items))
      ) {
        reject();
      }
    }
    for (const [keyword, value] of Object.entries(entry)) {
      switch (keyword) {
        case "$defs":
        case "properties":
          if (!isRecord(value)) {
            reject();
          }
          for (const child of Object.values(value)) {
            pending.push(child);
          }
          break;
        case "items":
          if (!isRecord(value)) {
            reject();
          }
          pending.push(value);
          break;
        case "anyOf":
          if (!Array.isArray(value) || value.length === 0) {
            reject();
          }
          for (const child of value) {
            pending.push(child);
          }
          break;
        case "$ref":
          if (typeof value !== "string") {
            reject();
          }
          references.push(value);
          break;
        case "additionalProperties":
          if (value !== false) {
            reject();
          }
          break;
        case "required":
          if (
            !Array.isArray(value) ||
            value.some((name) => typeof name !== "string")
          ) {
            reject();
          }
          break;
        case "enum":
          if (!Array.isArray(value) || value.length === 0) {
            reject();
          }
          break;
        case "minItems":
        case "maxItems":
        case "minLength":
        case "maxLength":
          if (!Number.isSafeInteger(value) || value < 0) {
            reject();
          }
          break;
        case "minimum":
        case "maximum":
        case "exclusiveMinimum":
        case "exclusiveMaximum":
        case "multipleOf":
          if (
            typeof value !== "number" ||
            !Number.isFinite(value) ||
            (keyword === "multipleOf" && value <= 0)
          ) {
            reject();
          }
          break;
        case "format":
          if (!FORMATS.has(value)) {
            reject();
          }
          break;
        case "pattern":
          if (!isSupportedPattern(value)) {
            reject();
          }
          break;
        case "title":
        case "description":
          if (typeof value !== "string") {
            reject();
          }
          break;
      }
    }
  }
  // Resolve local JSON Pointers only after collecting schema positions. This
  // permits recursive definitions without traversing references indefinitely.
  for (const reference of references) {
    if (!reference.startsWith("#")) {
      reject();
    }
    let pointer;
    try {
      pointer = decodeURIComponent(reference.slice(1));
    } catch {
      reject();
    }
    if (pointer === "") {
      continue;
    }
    if (!pointer.startsWith("/")) {
      reject();
    }
    let target = schema;
    for (const token of pointer.slice(1).split("/")) {
      if (/~(?:[^01]|$)/u.test(token)) {
        reject();
      }
      const key = token.replaceAll("~1", "/").replaceAll("~0", "~");
      if (
        target === null ||
        typeof target !== "object" ||
        !Object.hasOwn(target, key)
      ) {
        reject();
      }
      target = target[key];
    }
    if (!schemas.has(target)) {
      reject();
    }
  }
}
