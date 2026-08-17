import { dirname, isAbsolute, resolve } from "node:path";

const ACCESS_MODES = new Set([
  "read-only",
  "workspace-write",
  "local-commit",
]);
const REQUEST_FIELDS = Object.freeze([
  "access",
  "authorizationId",
  "commit",
  "cwd",
  "model",
  "prompt",
  "schema",
  "session",
]);
const SESSION_FIELDS = Object.freeze(["id", "mode"]);
const COMMIT_FIELDS = Object.freeze(["expectedHead", "message"]);
const OBJECT_ID_PATTERN = /^(?:[a-f0-9]{40}|[a-f0-9]{64})$/u;
const MAX_PROMPT_BYTES = 1024 * 1024;
const MAX_SCHEMA_BYTES = 1024 * 1024;
const MAX_SCHEMA_DEPTH = 128;
const SCHEMA_CHILD_KEYWORDS = Object.freeze([
  "additionalItems",
  "additionalProperties",
  "allOf",
  "anyOf",
  "contains",
  "contentSchema",
  "else",
  "if",
  "items",
  "not",
  "oneOf",
  "prefixItems",
  "propertyNames",
  "then",
  "unevaluatedItems",
  "unevaluatedProperties",
]);
const SCHEMA_MAP_KEYWORDS = Object.freeze([
  "$defs",
  "definitions",
  "dependencies",
  "dependentSchemas",
  "patternProperties",
  "properties",
]);

export function isRecord(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

export function isEnvironment(value) {
  return (
    Object.prototype.toString.call(value) === "[object Object]" &&
    Object.values(value).every(
      (entry) => typeof entry === "string" || entry === undefined,
    )
  );
}

function isFilesystemRoot(value) {
  const normalized = resolve(value);
  return dirname(normalized) === normalized;
}

export function isolateGitEnvironment(value) {
  const environment = { ...value };
  for (const name of Object.keys(environment)) {
    const normalizedName = name.toUpperCase();
    if (normalizedName === "EMAIL" || normalizedName.startsWith("GIT_")) {
      delete environment[name];
    }
  }
  environment.GIT_TERMINAL_PROMPT = "0";
  return Object.freeze(environment);
}

export function deepFreeze(value) {
  const pending = [value];
  while (pending.length > 0) {
    const entry = pending.pop();
    if (
      entry !== null &&
      typeof entry === "object" &&
      !Object.isFrozen(entry)
    ) {
      Object.freeze(entry);
      for (const child of Object.values(entry)) {
        pending.push(child);
      }
    }
  }
  return value;
}

export function createAdapterContract({ AdapterError, backendName }) {
  const errorPrefix = backendName.toUpperCase();

  function optionsError(message) {
    return new AdapterError(message, {
      code: `ERR_INVALID_${errorPrefix}_OPTIONS`,
    });
  }

  function schemaError(message) {
    return new AdapterError(message, {
      code: `ERR_INVALID_${errorPrefix}_SCHEMA`,
    });
  }

  function assertFields(value, fields, name) {
    if (!isRecord(value)) {
      throw optionsError(`${name} must be an object.`);
    }
    const unknown = Object.keys(value).find((field) => !fields.includes(field));
    if (unknown !== undefined) {
      throw optionsError(`${name} field is not supported: ${unknown}.`);
    }
    return value;
  }

  function assertString(value, name, maximumLength = 4096) {
    if (
      typeof value !== "string" ||
      value.length === 0 ||
      value.length > maximumLength ||
      /[\0\r\n]/u.test(value)
    ) {
      throw optionsError(`${name} is invalid.`);
    }
    return value;
  }

  function assertJsonValue(value) {
    const ancestors = new Set();
    const pending = [{ depth: 0, value }];
    while (pending.length > 0) {
      const entry = pending.pop();
      if (entry.exit === true) {
        ancestors.delete(entry.value);
        continue;
      }
      if (
        entry.value === null ||
        typeof entry.value === "string" ||
        typeof entry.value === "boolean" ||
        (typeof entry.value === "number" && Number.isFinite(entry.value))
      ) {
        continue;
      }
      if (typeof entry.value !== "object" || ancestors.has(entry.value)) {
        throw schemaError("JSON Schema must contain only JSON values.");
      }
      if (entry.depth > MAX_SCHEMA_DEPTH) {
        throw schemaError("JSON Schema is too deeply nested.");
      }
      let children;
      if (Array.isArray(entry.value)) {
        children = entry.value;
      } else if (isRecord(entry.value)) {
        children = Object.values(entry.value);
      } else {
        throw schemaError("JSON Schema must be a plain JSON object.");
      }
      ancestors.add(entry.value);
      pending.push({ exit: true, value: entry.value });
      for (let index = children.length - 1; index >= 0; index -= 1) {
        pending.push({ depth: entry.depth + 1, value: children[index] });
      }
    }
  }

  function assertStrictObjectSchemas(schema) {
    const pending = [schema];
    while (pending.length > 0) {
      const entry = pending.pop();
      if (Array.isArray(entry)) {
        for (const child of entry) {
          pending.push(child);
        }
        continue;
      }
      if (!isRecord(entry)) {
        continue;
      }
      const describesObject =
        entry.type === "object" ||
        (Array.isArray(entry.type) && entry.type.includes("object")) ||
        entry.properties !== undefined;
      if (describesObject) {
        const properties = isRecord(entry.properties)
          ? Object.keys(entry.properties)
          : [];
        if (
          !isRecord(entry.properties) ||
          entry.additionalProperties !== false ||
          !Array.isArray(entry.required) ||
          entry.required.length !== properties.length ||
          new Set(entry.required).size !== properties.length ||
          properties.some((property) => !entry.required.includes(property))
        ) {
          throw schemaError(
            "Object schemas must declare properties, every required field, " +
              "and additionalProperties: false.",
          );
        }
      }
      for (const keyword of SCHEMA_CHILD_KEYWORDS) {
        if (entry[keyword] !== undefined) {
          pending.push(entry[keyword]);
        }
      }
      for (const keyword of SCHEMA_MAP_KEYWORDS) {
        if (isRecord(entry[keyword])) {
          for (const child of Object.values(entry[keyword])) {
            pending.push(child);
          }
        }
      }
    }
  }

  function normalizeSchema(value) {
    if (value === undefined) {
      return undefined;
    }
    assertJsonValue(value);
    if (!isRecord(value) || value.type !== "object") {
      throw schemaError(`${backendName} output schema must describe an object.`);
    }
    assertStrictObjectSchemas(value);
    const source = JSON.stringify(value);
    if (Buffer.byteLength(source) > MAX_SCHEMA_BYTES) {
      throw schemaError(`${backendName} output schema is too large.`);
    }
    return deepFreeze(JSON.parse(source));
  }

  function normalizeSession(value) {
    if (value === undefined) {
      return undefined;
    }
    assertFields(value, SESSION_FIELDS, `${backendName} session`);
    if (!["continue", "fork"].includes(value.mode)) {
      throw optionsError(`${backendName} session mode is invalid.`);
    }
    return Object.freeze({
      id: assertString(value.id, `${backendName} session ID`),
      mode: value.mode,
    });
  }

  function normalizeCommit(value) {
    assertFields(value, COMMIT_FIELDS, `${backendName} commit constraint`);
    if (
      typeof value.expectedHead !== "string" ||
      !OBJECT_ID_PATTERN.test(value.expectedHead) ||
      typeof value.message !== "string" ||
      value.message.length === 0 ||
      value.message.trim() !== value.message ||
      /[\0\r\n]/u.test(value.message) ||
      [...value.message].length > 72
    ) {
      throw optionsError(`${backendName} commit constraint is invalid.`);
    }
    return Object.freeze({
      expectedHead: value.expectedHead,
      message: value.message,
    });
  }

  function normalizeRequest(value) {
    assertFields(value, REQUEST_FIELDS, `${backendName} request`);
    if (
      typeof value.cwd !== "string" ||
      !isAbsolute(value.cwd) ||
      isFilesystemRoot(value.cwd) ||
      /[\0\r\n]/u.test(value.cwd) ||
      !ACCESS_MODES.has(value.access) ||
      typeof value.prompt !== "string" ||
      value.prompt.trim().length === 0 ||
      /\0/u.test(value.prompt) ||
      Buffer.byteLength(value.prompt) > MAX_PROMPT_BYTES
    ) {
      throw optionsError(`${backendName} request is invalid.`);
    }
    const normalized = {
      access: value.access,
      cwd: value.cwd,
      model:
        value.model === undefined
          ? undefined
          : assertString(value.model, `${backendName} model`, 256),
      prompt: value.prompt,
      schema: normalizeSchema(value.schema),
      session: normalizeSession(value.session),
    };
    if (value.access === "local-commit") {
      if (normalized.schema !== undefined) {
        throw optionsError(
          "Local-commit requests use the adapter confirmation schema.",
        );
      }
      normalized.authorizationId = assertString(
        value.authorizationId,
        "Commit authorization ID",
      );
      normalized.commit = normalizeCommit(value.commit);
    } else if (
      value.authorizationId !== undefined ||
      value.commit !== undefined
    ) {
      throw optionsError("Commit constraints require local-commit access.");
    }
    return Object.freeze(normalized);
  }

  return Object.freeze({ assertFields, normalizeRequest });
}
