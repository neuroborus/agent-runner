import { createHash, randomUUID } from "node:crypto";
import { lstat, mkdir, realpath } from "node:fs/promises";
import { hostname } from "node:os";
import { join } from "node:path";

import { STOP_TIMINGS, validStopTiming } from "./stop-contract.js";
import { atomicWriteFile, readOptionalText } from "./files.js";
import { createLeaseManager } from "./lease.js";
import { createMutationBoundary } from "./mutation.js";
import { readProcessIdentity } from "./process-owner.js";
import { assertRunId, deepFreeze, RunStoreError } from "./validation.js";

const ACTION_SCHEMA_VERSION = 3;
const ACTIONS_DIRECTORY = "actions";
const ACTION_FILENAME = "action.json";
const MAX_KEY_LENGTH = 1_024;
const MAX_ACTION_BYTES = 256 * 1_024;
const TOOLS = new Set([
  "run_start",
  "run_respond",
  "run_resume",
  "run_pause",
  "run_cancel",
  "unexpected_issue_report",
  "guidance_update",
]);
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
  let legacyArgumentsHash = null;
  if (["run_pause", "run_cancel"].includes(tool)) {
    if (
      !isRecord(actionArguments) ||
      Object.keys(actionArguments).some(
        (field) => !["runId", "expectedRevision", "timing"].includes(field),
      )
    )
      throw actionError("Stop action arguments are invalid.");
    const timing = actionArguments.timing ?? "immediate";
    if (
      !STOP_TIMINGS.has(timing) ||
      (Object.hasOwn(actionArguments, "timing") &&
        actionArguments.timing !== timing)
    )
      throw actionError("Stop action timing is invalid.");
    if (timing === "immediate") {
      legacyArgumentsHash = hash(
        canonicalJson({
          runId: actionArguments.runId,
          expectedRevision: actionArguments.expectedRevision,
        }),
      );
    }
    actionArguments = { ...actionArguments, timing };
  }
  return Object.freeze({
    keyHash: hash(key),
    argumentsHash: hash(canonicalJson(actionArguments)),
    legacyArgumentsHash,
  });
}

function parseRecord(source, keyHash) {
  if (Buffer.byteLength(source) > MAX_ACTION_BYTES)
    throw actionError("MCP action record is too large.");
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
    ![1, 2, ACTION_SCHEMA_VERSION].includes(value.schemaVersion) ||
    (value.schemaVersion === 1 &&
      ["run_pause", "run_cancel"].includes(value.tool)) ||
    value.keyHash !== keyHash ||
    !TOOLS.has(value.tool) ||
    !/^[a-f0-9]{64}$/u.test(value.argumentsHash) ||
    !["intent", "completed"].includes(value.status) ||
    !isRecord(value.context) ||
    (value.status === "intent" && value.result !== null) ||
    (value.status === "completed" && !isRecord(value.result)) ||
    Number.isNaN(createdAt.valueOf()) ||
    createdAt.toISOString() !== value.createdAt ||
    Number.isNaN(updatedAt.valueOf()) ||
    updatedAt.toISOString() !== value.updatedAt ||
    updatedAt < createdAt
  ) {
    throw actionError("MCP action record is invalid.");
  }
  if (["run_pause", "run_cancel"].includes(value.tool)) {
    assertRunId(value.context.runId);
    if (Object.keys(value.context).length !== 1)
      throw actionError("Stop action context is invalid.");
    if (value.status === "completed") {
      const result = value.result;
      const modern = Object.hasOwn(result, "timing");
      if (
        Object.keys(result).length !== (modern ? 8 : 5) ||
        (modern && (value.schemaVersion < 3 || !validStopTiming(result))) ||
        result.runId !== value.context.runId ||
        result.requestId !== keyHash ||
        result.kind !==
          (value.tool === "run_pause"
            ? "pause_requested"
            : "cancel_requested") ||
        !Number.isSafeInteger(result.expectedRevision) ||
        result.expectedRevision < 1 ||
        !Number.isSafeInteger(result.revision) ||
        result.revision <= result.expectedRevision ||
        hash(
          canonicalJson({
            runId: result.runId,
            expectedRevision: result.expectedRevision,
            ...(modern ? { timing: result.timing } : {}),
          }),
        ) !== value.argumentsHash
      ) {
        throw actionError("Stop action receipt is invalid.");
      }
    }
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
  processIdentity = readProcessIdentity,
  onPublicationBoundary,
  tokenFactory = randomUUID,
}) {
  function timestamp(notBefore) {
    const value = new Date(clock());
    if (Number.isNaN(value.valueOf())) {
      throw actionError("MCP action clock returned an invalid date.");
    }
    const current = value.toISOString();
    return notBefore !== undefined && current < notBefore ? notBefore : current;
  }

  const mutate = createMutationBoundary({
    hostName,
    processId,
    processIsAlive: checkProcess,
    processIdentity,
    onPublicationBoundary,
  });
  const leases = createLeaseManager({
    withMutation: (_record, operation, directory) =>
      mutate(directory, operation),
    activeLeaseDescription: "MCP action lease",
    conflictCode: "ERR_MCP_ACTION_IN_PROGRESS",
    invalidLeaseCode: "ERR_INVALID_MCP_ACTION_LEASE",
    leaseDescription: "MCP action lease",
    reclaimingLeaseDescription: "Reclaiming MCP action lease",
    leaseSubject: () => "MCP action",
    includeRunId: false,
    requireMatchingRunId: false,
    currentDate: () => new Date(timestamp()),
    timestamp,
    hostName,
    processId,
    processIsAlive: checkProcess,
    processIdentity,
    onPublicationBoundary,
    staleMs: 0,
    tokenFactory,
  });

  async function begin({ key, tool, arguments: actionArguments, context }) {
    if (!isRecord(context)) {
      throw actionError("MCP action input is invalid.");
    }

    const { keyHash, argumentsHash, legacyArgumentsHash } = actionIdentity(
      key,
      tool,
      actionArguments,
    );
    const actionsPath = await ensureDirectory(
      join(stateRoot, ACTIONS_DIRECTORY),
    );
    const actionDirectory = join(actionsPath, keyHash);
    try {
      await mkdir(actionDirectory, { mode: 0o700 });
    } catch (cause) {
      if (cause?.code !== "EEXIST") {
        throw cause;
      }
    }
    await ensureDirectory(actionDirectory);
    const lease = await leases.acquire(actionDirectory, null);
    const release = () => lease.release();
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
        parseRecord(serialized, keyHash);
        await atomicWriteFile(recordPath, serialized);
      } else {
        record = parseRecord(source, keyHash);
        if (
          record.tool !== tool ||
          (record.argumentsHash !== argumentsHash &&
            record.argumentsHash !== legacyArgumentsHash)
        ) {
          throw actionError(
            "Idempotency key was already used with different arguments.",
            "ERR_MCP_IDEMPOTENCY_CONFLICT",
          );
        }
      }

      let released = false;
      return Object.freeze({
        created,
        get legacyIdentity() {
          return record.argumentsHash === legacyArgumentsHash;
        },
        get record() {
          return deepFreeze(structuredClone(record));
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
            schemaVersion: ACTION_SCHEMA_VERSION,
            context: nextContext,
            updatedAt: timestamp(record.updatedAt),
          };
          const serialized = `${JSON.stringify(updated)}\n`;
          if (Buffer.byteLength(serialized) > MAX_ACTION_BYTES) {
            throw actionError("MCP action record is too large.");
          }
          parseRecord(serialized, keyHash);
          await atomicWriteFile(recordPath, serialized);
          record = updated;
          return deepFreeze(structuredClone(updated));
        },
        async complete(result) {
          if (released || record.status !== "intent" || !isRecord(result)) {
            throw actionError("MCP action cannot be completed.");
          }
          const completed = {
            ...record,
            schemaVersion: ACTION_SCHEMA_VERSION,
            status: "completed",
            result,
            updatedAt: timestamp(record.updatedAt),
          };
          const serialized = `${JSON.stringify(completed)}\n`;
          if (Buffer.byteLength(serialized) > MAX_ACTION_BYTES) {
            throw actionError("MCP action receipt is too large.");
          }
          parseRecord(serialized, keyHash);
          await atomicWriteFile(recordPath, serialized);
          record = completed;
          return deepFreeze(structuredClone(completed));
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
    const { keyHash, argumentsHash, legacyArgumentsHash } = actionIdentity(
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
    const source = await readOptionalText(
      join(actionDirectory, ACTION_FILENAME),
    );
    if (source === null) {
      return null;
    }
    const record = parseRecord(source, keyHash);
    if (
      record.tool !== tool ||
      (record.argumentsHash !== argumentsHash &&
        record.argumentsHash !== legacyArgumentsHash)
    ) {
      throw actionError(
        "Idempotency key was already used with different arguments.",
        "ERR_MCP_IDEMPOTENCY_CONFLICT",
      );
    }
    return deepFreeze(structuredClone(record));
  }

  return Object.freeze({ begin, read });
}
