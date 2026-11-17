import { randomUUID } from "node:crypto";
import { join, isAbsolute, resolve } from "node:path";
import { isDeepStrictEqual } from "node:util";
import { lstat } from "node:fs/promises";

import { readProcessNamespace } from "../platform/index.js";

import { atomicWriteFile, readOptionalText } from "./files.js";
import { createMutationBoundary } from "./mutation.js";
import { inspectProcessOwner } from "./process-owner.js";
import {
  assertRunId,
  deepFreeze,
  RunStoreError,
  validateProcessIdentity,
} from "./validation.js";

const MAX_BYTES = 256 * 1024;
const MAX_USERS = 256;
const KINDS = new Set(["cli", "mcp", "run", "resume"]);
const RUNTIME_FIELDS = [
  "payloadId",
  "rootPath",
  "executablePath",
  "nodePath",
  "nodeVersion",
  "nodeIdentity",
];
const exact = (value, fields) =>
  value !== null &&
  typeof value === "object" &&
  !Array.isArray(value) &&
  Object.keys(value).length === fields.length &&
  fields.every((key) => Object.hasOwn(value, key));
const failure = (message, code = "ERR_RUNTIME_ADMISSION") =>
  new RunStoreError(message, { code });

function runtimeIdentity(value) {
  if (
    !exact(value, RUNTIME_FIELDS) ||
    !/^[a-f0-9]{64}$/u.test(value.payloadId) ||
    typeof value.nodeVersion !== "string" ||
    !/^v24\.\d+\.\d+$/u.test(value.nodeVersion) ||
    !exact(value.nodeIdentity, ["dev", "ino", "size", "mtimeNs", "ctimeNs"]) ||
    Object.values(value.nodeIdentity).some(
      (part) => typeof part !== "string" || !/^\d{1,30}$/u.test(part),
    )
  )
    throw failure("Runtime identity is invalid.");
  for (const key of ["rootPath", "executablePath", "nodePath"])
    if (
      typeof value[key] !== "string" ||
      value[key].length > 4096 ||
      !isAbsolute(value[key]) ||
      resolve(value[key]) !== value[key] ||
      /[\p{Cc}\p{Zl}\p{Zp}]/u.test(value[key])
    )
      throw failure("Runtime location is invalid.");
  if (value.executablePath !== join(value.rootPath, "bin/agent-run.js"))
    throw failure("Runtime executable is outside its payload.");
  return structuredClone(value);
}

function ownerIdentity(value) {
  if (
    !exact(value, ["pid", "hostname", "processIdentity", "namespace"]) ||
    typeof value.namespace !== "string" ||
    !/^pid:\[\d+\]$/u.test(value.namespace) ||
    !Number.isSafeInteger(value.pid) ||
    value.pid < 1 ||
    typeof value.hostname !== "string" ||
    !value.hostname ||
    value.hostname.length > 255 ||
    /[\p{Cc}\p{Zl}\p{Zp}]/u.test(value.hostname) ||
    validateProcessIdentity(value.processIdentity) === null
  )
    throw failure(
      "Runtime owner cannot be verified.",
      "ERR_RUNTIME_OWNER_UNVERIFIABLE",
    );
  return structuredClone(value);
}

function parse(source) {
  if (source === null)
    return {
      schemaVersion: 2,
      revision: 0,
      lastOperation: null,
      active: null,
      activeOperation: null,
      pending: null,
      pendingOperation: null,
      users: [],
    };
  let value;
  try {
    value = JSON.parse(source);
  } catch {
    throw failure("Runtime admission record is invalid.");
  }
  if (
    !exact(value, [
      "schemaVersion",
      "revision",
      "lastOperation",
      "active",
      "pending",
      "users",
      ...(value?.schemaVersion === 2
        ? ["activeOperation", "pendingOperation"]
        : []),
    ]) ||
    ![1, 2].includes(value.schemaVersion) ||
    !Number.isSafeInteger(value.revision) ||
    value.revision < 1 ||
    typeof value.lastOperation !== "string" ||
    !/^(?:admit|activate|release):[a-f0-9-]{36}$/u.test(value.lastOperation) ||
    !Array.isArray(value.users) ||
    value.users.length > MAX_USERS
  )
    throw failure("Runtime admission record is invalid.");
  if (value.schemaVersion === 1) {
    value = {
      ...value,
      schemaVersion: 2,
      activeOperation: null,
      pendingOperation: null,
    };
  }
  if (value.activeOperation !== null) {
    assertRunId(value.activeOperation);
    if (value.active === null)
      throw failure("Active runtime proof is invalid.");
  }
  if (value.pendingOperation !== null) {
    assertRunId(value.pendingOperation);
    if (value.pending === null)
      throw failure("Pending runtime proof is invalid.");
  }
  if (value.active !== null) runtimeIdentity(value.active);
  if (value.pending !== null) runtimeIdentity(value.pending);
  const ids = new Set();
  for (const user of value.users) {
    if (
      !exact(user, ["id", "runtime", "kind", "owner"]) ||
      !KINDS.has(user.kind) ||
      ids.has(user.id)
    )
      throw failure("Runtime user record is invalid.");
    assertRunId(user.id);
    ids.add(user.id);
    runtimeIdentity(user.runtime);
    ownerIdentity(user.owner);
    if (!isDeepStrictEqual(user.runtime, value.active))
      throw failure("Runtime user disagrees with the active payload.");
  }
  return value;
}

function validateCheckpoint(record, operation, id) {
  const context = record.context;
  const planned = Object.hasOwn(context, "fromRevision");
  if (
    !exact(context, planned ? ["owner", "fromRevision", "result"] : ["owner"])
  )
    throw failure("Runtime action context is invalid.");
  ownerIdentity(context.owner);
  if (!planned) {
    if (record.status !== "intent")
      throw failure("Runtime action has no write-ahead proof.");
    return;
  }
  const result = context.result;
  if (
    !Number.isSafeInteger(context.fromRevision) ||
    context.fromRevision < 0 ||
    !result ||
    result.id !== id ||
    !(
      operation === "release"
        ? ["released"]
        : [operation === "admit" ? "admitted" : "active", "deferred"]
    ).includes(result.status)
  )
    throw failure("Runtime write-ahead proof is invalid.");
  if (result.status === "released") {
    if (!exact(result, ["id", "status"]))
      throw failure("Runtime receipt is invalid.");
  } else {
    if (
      !exact(result, ["id", "status", "runtime", "restartRequired"]) ||
      result.restartRequired !== (result.status === "deferred")
    )
      throw failure("Runtime receipt is invalid.");
    runtimeIdentity(result.runtime);
  }
  if (
    record.status === "completed" &&
    !isDeepStrictEqual(result, record.result)
  )
    throw failure("Runtime receipt disagrees with its intent.");
}

// This focused state projection uses the existing action intents, leases and
// mutation boundary. It grants no run migration, process custody or Git effects.
export function createRuntimeAdmissionStore({
  rootPath,
  openStorage,
  ensureRoot,
  ensureDirectory,
  actions,
  hostName,
  processId,
  processIdentity,
  processIsAlive,
  processNamespace = readProcessNamespace,
  onPublicationBoundary,
  onBoundary = async () => {},
}) {
  const ownerOptions = { hostName, processIdentity, processIsAlive };
  const mutate = createMutationBoundary({
    hostName,
    processId,
    processIdentity,
    processIsAlive,
    processNamespace,
    onPublicationBoundary,
    prefix: ".runtime-mutation-",
  });

  async function inspectOwner(record, observer) {
    if (
      record.hostname === hostName &&
      record.processIdentity.bootId !== observer.processIdentity.bootId
    )
      return "dead";
    if (record.namespace !== observer.namespace) return "unverifiable";
    return inspectProcessOwner(record, ownerOptions);
  }

  async function owner() {
    return ownerIdentity({
      pid: processId,
      hostname: hostName,
      processIdentity: await processIdentity(processId),
      namespace: await processNamespace(processId),
    });
  }

  async function transaction(operation, input) {
    const allowed =
      operation === "release"
        ? ["id"]
        : operation === "admit"
          ? ["id", "runtime", "kind"]
          : ["id", "runtime"];
    if (
      !input ||
      typeof input !== "object" ||
      Array.isArray(input) ||
      Object.keys(input).some((key) => !allowed.includes(key))
    )
      throw failure("Runtime operation input is invalid.");
    const id =
      input.id === undefined && operation !== "release"
        ? randomUUID()
        : input.id;
    assertRunId(id);
    const identity = await owner();
    const runtime =
      operation === "release" ? null : runtimeIdentity(input.runtime);
    if (operation === "admit" && !KINDS.has(input.kind))
      throw failure("Runtime user kind is invalid.");
    const { rootPath } = await ensureRoot();
    const directory = await ensureDirectory(
      join(rootPath, "runtime-admission"),
      "Runtime admission path",
    );
    const metadata = await lstat(directory);
    if (
      typeof process.getuid !== "function" ||
      metadata.uid !== process.getuid() ||
      (metadata.mode & 0o7777) !== 0o700
    )
      throw failure("Runtime admission storage must be private and owned.");
    return mutate(directory, async () => {
      const path = join(directory, "runtime.json");
      const state = parse(
        await readOptionalText(path, { maxBytes: MAX_BYTES }),
      );
      async function validateActor(record) {
        validateCheckpoint(record, operation, id);
        if (
          !isDeepStrictEqual(record.context.owner, identity) &&
          (operation === "admit" ||
            !["dead", "replaced"].includes(
              await inspectOwner(record.context.owner, identity),
            ))
        )
          throw failure(
            "Runtime action belongs to another process.",
            "ERR_RUNTIME_OWNER_UNVERIFIABLE",
          );
      }
      const request = {
        key: `runtime-${operation}:${id}`,
        tool: `runtime_${operation}`,
        arguments: { id, runtime, kind: input.kind ?? null },
      };
      const prior = await actions.read(request);
      if (prior !== null) await validateActor(prior);
      const live = [];
      for (const user of state.users) {
        const status = await inspectOwner(user.owner, identity);
        if (status === "unverifiable")
          throw failure(
            "An associated runtime user cannot be verified.",
            "ERR_RUNTIME_OWNER_UNVERIFIABLE",
          );
        if (status === "live") live.push(user);
      }
      if (
        operation === "admit" &&
        live.length === 0 &&
        state.pendingOperation !== null &&
        isDeepStrictEqual(state.pending, runtime)
      ) {
        const pendingId = state.pendingOperation;
        const pendingRequest = {
          key: `runtime-activate:${pendingId}`,
          tool: "runtime_activate",
          arguments: { id: pendingId, runtime: state.pending, kind: null },
        };
        const pending = await actions.read(pendingRequest);
        if (!pending) throw failure("Pending activation proof is missing.");
        validateCheckpoint(pending, "activate", pendingId);
        if (
          pending.context.result?.status !== "deferred" ||
          pending.context.fromRevision >= state.revision
        )
          throw failure("Pending activation proof is invalid.");
        if (pending.status === "intent") {
          if (
            !isDeepStrictEqual(pending.context.owner, identity) &&
            !["dead", "replaced"].includes(
              await inspectOwner(pending.context.owner, identity),
            )
          )
            throw failure(
              "Pending activation owner cannot be verified.",
              "ERR_RUNTIME_OWNER_UNVERIFIABLE",
            );
          const recovery = await actions.begin({
            ...pendingRequest,
            context: pending.context,
          });
          try {
            validateCheckpoint(recovery.record, "activate", pendingId);
            if (recovery.record.status !== "completed")
              await recovery.complete(recovery.record.context.result);
          } finally {
            await recovery.release();
          }
        }
      }
      const action = await actions.begin({
        ...request,
        context: { owner: identity },
      });
      try {
        await validateActor(action.record);
        const planned = action.record.context;
        if (
          action.record.status === "intent" &&
          planned.fromRevision !== undefined
        ) {
          if (
            (state.revision === planned.fromRevision + 1 &&
              state.lastOperation === `${operation}:${id}`) ||
            (operation === "activate" &&
              state.revision > planned.fromRevision &&
              ((planned.result.status === "active" &&
                state.activeOperation === id &&
                isDeepStrictEqual(state.active, runtime)) ||
                (planned.result.status === "deferred" &&
                  state.pendingOperation === id &&
                  isDeepStrictEqual(state.pending, runtime))))
          ) {
            await action.complete(planned.result);
            return action.record.result;
          }
          if (state.revision !== planned.fromRevision)
            throw failure(
              "Runtime operation requires reconciliation.",
              "ERR_RUNTIME_RECONCILIATION_REQUIRED",
            );
        }
        state.users = live;
        if (action.record.status === "completed") {
          if (
            operation === "admit" &&
            action.record.result.status === "admitted" &&
            !live.some(
              (user) =>
                user.id === id &&
                isDeepStrictEqual(user.owner, identity) &&
                isDeepStrictEqual(user.runtime, runtime),
            )
          )
            throw failure("Completed runtime admission is no longer held.");
          return action.record.result;
        }
        let result;
        if (operation === "release") {
          const user = live.find((user) => user.id === id);
          if (user && !isDeepStrictEqual(user.owner, identity))
            throw failure(
              "Runtime admission belongs to another process.",
              "ERR_RUNTIME_OWNER_UNVERIFIABLE",
            );
          state.users = live.filter((user) => user.id !== id);
          result = { status: "released", id };
        } else {
          const boundarySelection =
            operation === "admit" && live.length === 0
              ? ((state.pendingOperation !== null ? state.pending : null) ??
                state.active)
              : state.active;
          const conflict =
            live.some((user) => !isDeepStrictEqual(user.runtime, runtime)) ||
            (operation === "admit" &&
              boundarySelection !== null &&
              !isDeepStrictEqual(boundarySelection, runtime));
          if (conflict) {
            if (operation === "activate") {
              state.pending = runtime;
              state.pendingOperation = id;
            }
            result = {
              status: "deferred",
              id,
              runtime: state.active,
              restartRequired: true,
            };
          } else {
            state.active = runtime;
            if (operation === "activate") state.activeOperation = id;
            else if (isDeepStrictEqual(state.pending, runtime))
              state.activeOperation = state.pendingOperation;
            if (
              operation === "activate" ||
              isDeepStrictEqual(state.pending, runtime)
            ) {
              state.pending = null;
              state.pendingOperation = null;
            }
            if (operation === "admit") {
              const prior = live.find((user) => user.id === id);
              if (
                prior &&
                (!isDeepStrictEqual(prior.runtime, runtime) ||
                  prior.kind !== input.kind ||
                  !isDeepStrictEqual(prior.owner, identity))
              )
                throw failure("Runtime admission identity changed.");
              if (!prior)
                state.users.push({
                  id,
                  runtime,
                  kind: input.kind,
                  owner: identity,
                });
            }
            result = {
              status: operation === "admit" ? "admitted" : "active",
              id,
              runtime,
              restartRequired: false,
            };
          }
        }
        await action.updateContext({
          owner: identity,
          fromRevision: state.revision,
          result,
        });
        state.revision += 1;
        state.lastOperation = `${operation}:${id}`;
        const bytes = `${JSON.stringify(state)}\n`;
        if (
          Buffer.byteLength(bytes) > MAX_BYTES ||
          state.users.length > MAX_USERS
        )
          throw failure("Runtime admission capacity is exhausted.");
        parse(bytes);
        await atomicWriteFile(path, bytes);
        await onBoundary({ operation, id });
        await action.complete(result);
        return deepFreeze(structuredClone(result));
      } finally {
        await action.release();
      }
    });
  }

  return Object.freeze({
    async read() {
      let binding;
      try {
        binding = await openStorage(join(rootPath, "runtime-admission"));
        const state = parse(
          await readOptionalText(join(binding.anchor, "runtime.json"), {
            maxBytes: MAX_BYTES,
          }),
        );
        await binding.verify();
        return deepFreeze({
          revision: state.revision,
          active: state.active,
          pending: state.pending,
        });
      } catch (error) {
        if (error.code === "ENOENT")
          return deepFreeze({ revision: 0, active: null, pending: null });
        throw error;
      } finally {
        await binding?.close();
      }
    },
    admit: (input) => transaction("admit", input),
    activate: (input) => transaction("activate", input),
    release: (id) => transaction("release", { id }),
  });
}
