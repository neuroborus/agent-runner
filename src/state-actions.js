import { createHash, randomUUID } from "node:crypto";
import { lstat, mkdir, realpath } from "node:fs/promises";
import { hostname } from "node:os";
import { join } from "node:path";

import {
  atomicWriteFile,
  publishExclusiveFile,
  readOptionalPublishedText,
  readOptionalText,
  removeFile,
} from "./state-files.js";
import { RunStoreError } from "./state-validation.js";

const ACTION_SCHEMA_VERSION = 1;
const ACTIONS_DIRECTORY = "actions";
const ACTION_FILENAME = "action.json";
const LEASE_FILENAME = ".lease";
const MAX_KEY_LENGTH = 1_024;
const MAX_ACTION_BYTES = 256 * 1_024;
const TOOLS = new Set([
  "run_start",
  "run_respond",
  "run_resume",
  "unexpected_issue_report",
]);
const LEASE_FIELDS = new Set(["token", "pid", "hostname", "acquiredAt"]);
const ACTION_FIELDS = new Set([
  "schemaVersion",
  "keyHash",
  "tool",
  "argumentsHash",
  "status",
  "context",
  "result",
  "createdAt",
  "updatedAt",
]);

function hash(value) {
  return createHash("sha256").update(value).digest("hex");
}

function canonicalJson(value) {
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJson).join(",")}]`;
  }
  if (value !== null && typeof value === "object") {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function isRecord(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function actionError(message, code = "ERR_INVALID_MCP_ACTION") {
  return new RunStoreError(message, { code });
}

function actionIdentity(key, tool, actionArguments) {
  if (
    typeof key !== "string" ||
    key.trim().length === 0 ||
    key.length > MAX_KEY_LENGTH ||
    /[\0\p{Cc}\p{Zl}\p{Zp}]/u.test(key) ||
    !TOOLS.has(tool)
  ) {
    throw actionError("MCP action input is invalid.");
  }
  return Object.freeze({
    keyHash: hash(key),
    argumentsHash: hash(canonicalJson(actionArguments)),
  });
}

function parseRecord(source, keyHash) {
  let value;
  try {
    value = JSON.parse(source);
  } catch (cause) {
    throw new RunStoreError("MCP action record contains invalid JSON.", {
      cause,
      code: "ERR_INVALID_MCP_ACTION",
    });
  }
  const createdAt = new Date(value?.createdAt);
  const updatedAt = new Date(value?.updatedAt);
  if (
    !isRecord(value) ||
    Object.keys(value).some((field) => !ACTION_FIELDS.has(field)) ||
    value.schemaVersion !== ACTION_SCHEMA_VERSION ||
    value.keyHash !== keyHash ||
    !TOOLS.has(value.tool) ||
    !/^[a-f0-9]{64}$/u.test(value.argumentsHash) ||
    !["intent", "completed"].includes(value.status) ||
    !isRecord(value.context) ||
    (value.status === "intent" && value.result !== null) ||
    (value.status === "completed" &&
      !isRecord(value.result)) ||
    Number.isNaN(createdAt.valueOf()) ||
    createdAt.toISOString() !== value.createdAt ||
    Number.isNaN(updatedAt.valueOf()) ||
    updatedAt.toISOString() !== value.updatedAt ||
    updatedAt < createdAt
  ) {
    throw actionError("MCP action record is invalid.");
  }
  return value;
}

function processIsAlive(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch (cause) {
    if (cause?.code === "ESRCH") {
      return false;
    }
    if (cause?.code === "EPERM") {
      return true;
    }
    throw cause;
  }
}

function parseLease(source) {
  let value;
  try {
    value = JSON.parse(source);
  } catch (cause) {
    throw new RunStoreError("MCP action lease contains invalid JSON.", {
      cause,
      code: "ERR_INVALID_MCP_ACTION_LEASE",
    });
  }
  const acquiredAt = new Date(value?.acquiredAt);
  if (
    !isRecord(value) ||
    Object.keys(value).some((field) => !LEASE_FIELDS.has(field)) ||
    typeof value.token !== "string" ||
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(
      value.token,
    ) ||
    !Number.isSafeInteger(value.pid) ||
    value.pid < 1 ||
    typeof value.hostname !== "string" ||
    value.hostname.length === 0 ||
    value.hostname.length > 255 ||
    /[\p{Cc}\p{Zl}\p{Zp}]/u.test(value.hostname) ||
    Number.isNaN(acquiredAt.valueOf()) ||
    acquiredAt.toISOString() !== value.acquiredAt
  ) {
    throw actionError(
      "MCP action lease is invalid.",
      "ERR_INVALID_MCP_ACTION_LEASE",
    );
  }
  return value;
}

async function ensureDirectory(path) {
  await mkdir(path, { recursive: true, mode: 0o700 });
  const metadata = await lstat(path);
  if (metadata.isSymbolicLink() || !metadata.isDirectory()) {
    throw actionError("MCP action path must be a real directory.");
  }
  return realpath(path);
}

export function createActionStore({
  stateRoot,
  clock = () => new Date(),
  hostName = hostname(),
  processId = process.pid,
  processIsAlive: checkProcess = processIsAlive,
  onPublicationBoundary,
  tokenFactory = randomUUID,
}) {
  function timestamp(notBefore) {
    const value = new Date(clock());
    if (Number.isNaN(value.valueOf())) {
      throw actionError("MCP action clock returned an invalid date.");
    }
    const current = value.toISOString();
    return notBefore !== undefined && current < notBefore
      ? notBefore
      : current;
  }

  async function acquireLease(actionDirectory) {
    const leasePath = join(actionDirectory, LEASE_FILENAME);
    for (let attempt = 0; attempt < 5; attempt += 1) {
      const lease = {
        token: tokenFactory(),
        pid: processId,
        hostname: hostName,
        acquiredAt: timestamp(),
      };
      const serializedLease = `${JSON.stringify(lease)}\n`;
      parseLease(serializedLease);
      try {
        await publishExclusiveFile(leasePath, serializedLease, {
          onPublicationBoundary,
        });
        return async () => {
          const current = await readOptionalPublishedText(leasePath);
          if (current !== null && parseLease(current).token === lease.token) {
            await removeFile(leasePath);
          }
        };
      } catch (cause) {
        if (cause?.code !== "EEXIST") {
          throw cause;
        }
      }
      const source = await readOptionalPublishedText(leasePath);
      if (source === null) {
        continue;
      }
      const existing = parseLease(source);
      if (existing.hostname !== hostName) {
        throw actionError(
          "An identical MCP action is already in progress.",
          "ERR_MCP_ACTION_IN_PROGRESS",
        );
      }
      const processAlive = await checkProcess(existing.pid);
      if (typeof processAlive !== "boolean") {
        throw actionError("MCP action liveness check is invalid.");
      }
      if (processAlive) {
        throw actionError(
          "An identical MCP action is already in progress.",
          "ERR_MCP_ACTION_IN_PROGRESS",
        );
      }
      const current = await readOptionalPublishedText(leasePath);
      if (current !== null && parseLease(current).token === existing.token) {
        await removeFile(leasePath);
      }
    }
    throw actionError(
      "MCP action lease could not be acquired.",
      "ERR_MCP_ACTION_IN_PROGRESS",
    );
  }

  async function begin({ key, tool, arguments: actionArguments, context }) {
    if (!isRecord(context)) {
      throw actionError("MCP action input is invalid.");
    }

    const { keyHash, argumentsHash } = actionIdentity(
      key,
      tool,
      actionArguments,
    );
    const actionsPath = await ensureDirectory(join(stateRoot, ACTIONS_DIRECTORY));
    const actionDirectory = join(actionsPath, keyHash);
    try {
      await mkdir(actionDirectory, { mode: 0o700 });
    } catch (cause) {
      if (cause?.code !== "EEXIST") {
        throw cause;
      }
    }
    await ensureDirectory(actionDirectory);
    const release = await acquireLease(actionDirectory);
    const recordPath = join(actionDirectory, ACTION_FILENAME);

    try {
      const source = await readOptionalText(recordPath);
      const created = source === null;
      let record;
      if (source === null) {
        const createdAt = timestamp();
        record = {
          schemaVersion: ACTION_SCHEMA_VERSION,
          keyHash,
          tool,
          argumentsHash,
          status: "intent",
          context,
          result: null,
          createdAt,
          updatedAt: createdAt,
        };
        const serialized = `${JSON.stringify(record)}\n`;
        if (Buffer.byteLength(serialized) > MAX_ACTION_BYTES) {
          throw actionError("MCP action record is too large.");
        }
        await atomicWriteFile(recordPath, serialized);
      } else {
        record = parseRecord(source, keyHash);
        if (record.tool !== tool || record.argumentsHash !== argumentsHash) {
          throw actionError(
            "Idempotency key was already used with different arguments.",
            "ERR_MCP_IDEMPOTENCY_CONFLICT",
          );
        }
      }

      let released = false;
      return Object.freeze({
        created,
        get record() {
          return Object.freeze(record);
        },
        async updateContext(nextContext) {
          if (
            released ||
            record.status !== "intent" ||
            !isRecord(nextContext)
          ) {
            throw actionError("MCP action context cannot be updated.");
          }
          const updated = {
            ...record,
            context: nextContext,
            updatedAt: timestamp(record.updatedAt),
          };
          const serialized = `${JSON.stringify(updated)}\n`;
          if (Buffer.byteLength(serialized) > MAX_ACTION_BYTES) {
            throw actionError("MCP action record is too large.");
          }
          await atomicWriteFile(recordPath, serialized);
          record = updated;
          return Object.freeze(updated);
        },
        async complete(result) {
          if (released || record.status !== "intent" || !isRecord(result)) {
            throw actionError("MCP action cannot be completed.");
          }
          const completed = {
            ...record,
            status: "completed",
            result,
            updatedAt: timestamp(record.updatedAt),
          };
          const serialized = `${JSON.stringify(completed)}\n`;
          if (Buffer.byteLength(serialized) > MAX_ACTION_BYTES) {
            throw actionError("MCP action receipt is too large.");
          }
          await atomicWriteFile(recordPath, serialized);
          record = completed;
          return Object.freeze(completed);
        },
        async release() {
          if (!released) {
            await release();
            released = true;
          }
        },
      });
    } catch (cause) {
      await release();
      throw cause;
    }
  }

  async function read({ key, tool, arguments: actionArguments }) {
    const { keyHash, argumentsHash } = actionIdentity(
      key,
      tool,
      actionArguments,
    );
    let canonicalRoot;
    try {
      canonicalRoot = await realpath(stateRoot);
    } catch (cause) {
      if (cause?.code === "ENOENT") {
        return null;
      }
      throw cause;
    }
    const actionsPath = join(canonicalRoot, ACTIONS_DIRECTORY);
    const actionDirectory = join(actionsPath, keyHash);
    for (const directoryPath of [actionsPath, actionDirectory]) {
      try {
        const metadata = await lstat(directoryPath);
        if (metadata.isSymbolicLink() || !metadata.isDirectory()) {
          throw actionError("MCP action path must be a real directory.");
        }
      } catch (cause) {
        if (cause?.code === "ENOENT") {
          return null;
        }
        throw cause;
      }
    }
    const source = await readOptionalText(join(actionDirectory, ACTION_FILENAME));
    if (source === null) {
      return null;
    }
    const record = parseRecord(source, keyHash);
    if (record.tool !== tool || record.argumentsHash !== argumentsHash) {
      throw actionError(
        "Idempotency key was already used with different arguments.",
        "ERR_MCP_IDEMPOTENCY_CONFLICT",
      );
    }
    return Object.freeze(record);
  }

  return Object.freeze({ begin, read });
}
