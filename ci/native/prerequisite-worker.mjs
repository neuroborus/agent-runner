// Importing this module defines capabilities only. The reviewed snapshot must
// explicitly call runPrerequisiteWorker after its transport persists admission.
import * as filesystem from "node:fs/promises";
import { connect } from "node:net";
import { posix, win32 } from "node:path";

import {
  observationDigest,
  observationObject,
  requireObservation,
} from "./observation.js";
import {
  createPosixPrerequisiteFiles,
  prerequisiteCreationRequest,
  PREREQUISITE_FILE_LIMITS,
} from "./prerequisite-files.js";
import { createWindowsPrerequisiteFiles } from "./prerequisite-windows.js";

export const PREREQUISITE_WORKER_LIMITS = Object.freeze({
  frameBytes: 1048576,
  chunkBytes: 32768,
  roots: 256,
  reads: 32,
  heldBytes: 536870912,
  lifetimeMs: 120000,
});

export function prerequisitePath(platform, file) {
  const paths = platform === "win32" ? win32 : posix;
  return (
    typeof file === "string" &&
    file.length <= 4096 &&
    paths.isAbsolute(file) &&
    paths.normalize(file) === file &&
    !/[\u0000-\u001f\u007f]/u.test(file) &&
    (platform !== "win32" ||
      (/^[A-Za-z]:\\[^:]+$/u.test(file) &&
        file
          .slice(3)
          .split("\\")
          .every(
            (part) =>
              part &&
              !/[<>"|?*]|[. ]$/u.test(part) &&
              !/^(?:con|prn|aux|nul|com[0-9]|lpt[0-9])(?:\.|$)/iu.test(part),
          )))
  );
}

export function normalizePrerequisiteAdmission(input, now = Date.now()) {
  observationObject(input, [
    "schemaVersion",
    "platform",
    "root",
    "readRoots",
    "writeRoots",
    "controllerUid",
    "controllerSid",
    "nonce",
    "expires",
  ]);
  const plan = structuredClone(input),
    paths = plan.platform === "win32" ? win32 : posix;
  requireObservation(
    plan.schemaVersion === 1 &&
      ["linux", "darwin", "win32"].includes(plan.platform) &&
      prerequisitePath(plan.platform, plan.root) &&
      paths.dirname(plan.root) !== plan.root &&
      typeof plan.nonce === "string" &&
      /^[a-f0-9]{32}$/u.test(plan.nonce) &&
      Number.isSafeInteger(plan.expires) &&
      plan.expires > now &&
      plan.expires - now <= PREREQUISITE_WORKER_LIMITS.lifetimeMs,
  );
  for (const key of ["readRoots", "writeRoots"]) {
    requireObservation(
      Array.isArray(plan[key]) &&
        plan[key].length > 0 &&
        plan[key].length <= PREREQUISITE_WORKER_LIMITS.roots &&
        plan[key].every((file) => prerequisitePath(plan.platform, file)) &&
        new Set(plan[key]).size === plan[key].length,
    );
  }
  const lower = (file) =>
    plan.platform === "win32" ? file.toLowerCase() : file;
  requireObservation(
    plan.writeRoots.every((file) =>
      lower(file).startsWith(lower(plan.root) + paths.sep),
    ) &&
      plan.writeRoots.every((file) =>
        plan.readRoots.some(
          (root) =>
            lower(file) === lower(root) ||
            lower(file).startsWith(lower(root) + paths.sep),
        ),
      ),
  );
  requireObservation(
    plan.platform === "win32"
      ? plan.controllerUid === null &&
          typeof plan.controllerSid === "string" &&
          plan.controllerSid.length <= 184 &&
          /^S-1-[0-9]+(?:-[0-9]+){1,15}$/u.test(plan.controllerSid)
      : plan.controllerSid === null &&
          Number.isSafeInteger(plan.controllerUid) &&
          plan.controllerUid >= 0,
  );
  return plan;
}

/** Only supported file operations reach the retained file owners. No package,
 * compiler, verifier child, arbitrary filesystem method or process is admitted. */
export function createPrerequisiteWorker(
  { nonce, admissionSha256 },
  {
    fs = filesystem,
    exchange,
    signal,
    clock = Date.now,
    platform = process.platform,
    uid = process.getuid?.(),
    pid = process.pid,
  } = {},
) {
  requireObservation(
    typeof nonce === "string" &&
      /^[a-f0-9]{32}$/u.test(nonce) &&
      typeof admissionSha256 === "string" &&
      /^[a-f0-9]{64}$/u.test(admissionSha256),
  );
  let owner,
    plan,
    upload,
    lastId = 0,
    nextRead = 0,
    heldBytes = 0,
    fenced = false,
    pending = Promise.resolve();
  const reads = new Map();
  // File owners check this at their asynchronous effect/observation boundaries,
  // including expiry which occurs after a request has begun.
  const effectSignal = {
    get aborted() {
      return Boolean(signal?.aborted || (plan && clock() >= plan.expires));
    },
  };
  const allowed = (file, write = false) => {
    requireObservation(prerequisitePath(platform, file));
    const lower = (value) =>
      platform === "win32" ? value.toLowerCase() : value;
    requireObservation(
      plan[write ? "writeRoots" : "readRoots"].some(
        (root) =>
          lower(file) === lower(root) ||
          lower(file).startsWith(
            lower(root) + (platform === "win32" ? "\\" : "/"),
          ),
      ),
    );
  };
  const options = (value, creation = false) => {
    observationObject(
      value,
      creation ? ["executable", "intent"] : ["maximum", "sealed"],
    );
    if (!creation) {
      requireObservation(
        Number.isSafeInteger(value.maximum) &&
          value.maximum > 0 &&
          value.maximum <= PREREQUISITE_FILE_LIMITS.bytes &&
          typeof value.sealed === "boolean",
      );
      return;
    }
    requireObservation(typeof value.executable === "boolean");
    observationObject(value.intent, ["file", "bytes", "sha256"]);
    allowed(value.intent.file);
    requireObservation(
      Number.isSafeInteger(value.intent.bytes) &&
        value.intent.bytes > 0 &&
        value.intent.bytes <= PREREQUISITE_FILE_LIMITS.intentBytes &&
        typeof value.intent.sha256 === "string" &&
        /^[a-f0-9]{64}$/u.test(value.intent.sha256),
    );
  };
  const close = async () => {
    fenced = true;
    reads.clear();
    upload = undefined;
    heldBytes = 0;
    return owner
      ? owner.close()
      : { status: "CLOSED", closedHandles: 0, custodianRetired: false };
  };
  const invoke = async (frame) => {
    observationObject(frame, ["id", "nonce", "operation", "args"]);
    requireObservation(
      !fenced &&
        (frame.operation === "close" || !effectSignal.aborted) &&
        frame.id === lastId + 1 &&
        Number.isSafeInteger(frame.id) &&
        frame.nonce === nonce &&
        typeof frame.operation === "string" &&
        Array.isArray(frame.args),
    );
    lastId = frame.id;
    const { operation, args } = frame;
    if (operation === "init") {
      requireObservation(
        !plan &&
          args.length === 1 &&
          observationDigest(args[0]) === admissionSha256,
      );
      const admitted = normalizePrerequisiteAdmission(args[0], clock());
      requireObservation(
        admitted.platform === platform && admitted.nonce === nonce,
      );
      // Windows requires the separately admitted stock-host IPC edge. It may
      // not silently replace held native reads with Node filesystem operations.
      requireObservation(
        platform !== "win32" || typeof exchange === "function",
      );
      owner =
        platform === "win32"
          ? createWindowsPrerequisiteFiles(admitted, { exchange })
          : createPosixPrerequisiteFiles({
              root: admitted.root,
              controllerUid: admitted.controllerUid,
              ownerUid: uid,
              fs,
              platform,
            });
      plan = admitted;
      return { pid, platform };
    }
    requireObservation(plan);
    if (operation === "close") {
      requireObservation(args.length === 0);
      return close();
    }
    requireObservation(clock() < plan.expires);
    if (operation === "hold") {
      requireObservation(
        args.length === 2 && reads.size < PREREQUISITE_WORKER_LIMITS.reads,
      );
      allowed(args[0]);
      options(args[1]);
      requireObservation(
        heldBytes + (upload?.bytes.length ?? 0) + args[1].maximum <=
          PREREQUISITE_WORKER_LIMITS.heldBytes,
      );
      const { bytes, ...proof } = await owner.hold(args[0], {
          ...args[1],
          signal: effectSignal,
        }),
        readId = ++nextRead;
      reads.set(readId, bytes);
      heldBytes += bytes.length;
      return { ...proof, readId, bytesLength: bytes.length };
    }
    if (operation === "read-held") {
      requireObservation(args.length === 3);
      const bytes = reads.get(args[0]),
        [, offset, count] = args;
      requireObservation(
        bytes &&
          Number.isSafeInteger(offset) &&
          offset >= 0 &&
          Number.isSafeInteger(count) &&
          count > 0 &&
          count <= PREREQUISITE_WORKER_LIMITS.chunkBytes &&
          offset + count <= bytes.length,
      );
      return {
        nativeBytes: bytes.subarray(offset, offset + count).toString("base64"),
      };
    }
    if (operation === "release-read") {
      requireObservation(args.length === 1 && reads.has(args[0]));
      heldBytes -= reads.get(args[0]).length;
      reads.delete(args[0]);
      return null;
    }
    if (operation === "create") {
      requireObservation(args.length === 3 && !upload);
      allowed(args[0], true);
      options(args[2], true);
      observationObject(args[1], ["nativeBytes"]);
      const data = args[1].nativeBytes;
      requireObservation(
        typeof data === "string" &&
          data.length <= PREREQUISITE_WORKER_LIMITS.frameBytes,
      );
      const bytes = Buffer.from(data, "base64");
      requireObservation(
        bytes.toString("base64") === data &&
          bytes.length + heldBytes <= PREREQUISITE_WORKER_LIMITS.heldBytes,
      );
      const { bytes: observed, ...proof } = await owner.create(args[0], bytes, {
        ...args[2],
        signal: effectSignal,
      });
      return { ...proof, bytesLength: observed.length };
    }
    if (operation === "create-begin") {
      requireObservation(args.length === 2 && !upload);
      const request = args[0];
      observationObject(request, [
        "schemaVersion",
        "operation",
        "root",
        "file",
        "bytes",
        "sha256",
        "executable",
      ]);
      allowed(request.file, true);
      options(args[1], true);
      requireObservation(
        request.schemaVersion === 1 &&
          request.operation === "create" &&
          request.root === plan.root &&
          Number.isSafeInteger(request.bytes) &&
          request.bytes >= 0 &&
          request.bytes + heldBytes <= PREREQUISITE_WORKER_LIMITS.heldBytes &&
          typeof request.sha256 === "string" &&
          /^[a-f0-9]{64}$/u.test(request.sha256) &&
          request.executable === args[1].executable,
      );
      upload = {
        request,
        options: args[1],
        bytes: Buffer.alloc(request.bytes),
        offset: 0,
      };
      return { offset: 0 };
    }
    if (operation === "create-chunk") {
      requireObservation(
        upload && args.length === 2 && args[0] === upload.offset,
      );
      observationObject(args[1], ["nativeBytes"]);
      const data = args[1].nativeBytes;
      requireObservation(
        typeof data === "string" && data.length > 0 && data.length <= 43692,
      );
      const bytes = Buffer.from(data, "base64");
      requireObservation(
        bytes.toString("base64") === data &&
          bytes.length <= PREREQUISITE_WORKER_LIMITS.chunkBytes &&
          upload.offset + bytes.length <= upload.bytes.length,
      );
      bytes.copy(upload.bytes, upload.offset);
      upload.offset += bytes.length;
      return { offset: upload.offset };
    }
    if (operation === "create-finish") {
      requireObservation(
        upload &&
          args.length === 0 &&
          upload.offset === upload.bytes.length &&
          observationDigest(
            prerequisiteCreationRequest(
              plan.root,
              upload.request.file,
              upload.bytes,
              upload.options.executable,
            ),
          ) === observationDigest(upload.request),
      );
      const { bytes, ...proof } = await owner.create(
        upload.request.file,
        upload.bytes,
        { ...upload.options, signal: effectSignal },
      );
      upload = undefined;
      return { ...proof, bytesLength: bytes.length };
    }
    if (operation === "recover") {
      requireObservation(args.length === 2);
      allowed(args[0]?.file, true);
      observationObject(args[1], ["intent"]);
      options({ executable: args[0].executable, intent: args[1].intent }, true);
      return owner.recover(args[0], { ...args[1], signal: effectSignal });
    }
    throw new Error("Undeclared prerequisite operation");
  };
  return {
    invoke(frame) {
      requireObservation(!fenced);
      frame = structuredClone(frame);
      requireObservation(
        Buffer.byteLength(JSON.stringify(frame)) <=
          PREREQUISITE_WORKER_LIMITS.frameBytes,
      );
      const result = pending.then(async () => {
        const value = await invoke(frame);
        requireObservation(
          frame.operation === "close" || !effectSignal.aborted,
        );
        return value;
      });
      pending = result.catch(() => {
        fenced = true;
      });
      return result;
    },
    async close() {
      fenced = true;
      await pending;
      return close();
    },
  };
}

/** Bound bytes before decoding or JSON parsing; readline's post-line limit
 * cannot bound a peer which never sends a delimiter. */
export async function* prerequisiteFrames(input) {
  const buffer = Buffer.alloc(PREREQUISITE_WORKER_LIMITS.frameBytes);
  let length = 0;
  for await (const value of input) {
    const chunk = Buffer.isBuffer(value) ? value : Buffer.from(value);
    let start = 0;
    while (start < chunk.length) {
      const newline = chunk.indexOf(10, start),
        end = newline === -1 ? chunk.length : newline,
        size = end - start;
      requireObservation(
        length + size <= PREREQUISITE_WORKER_LIMITS.frameBytes,
      );
      chunk.copy(buffer, length, start, end);
      length += size;
      if (newline === -1) break;
      requireObservation(length > 0);
      yield JSON.parse(
        new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(
          buffer.subarray(0, length),
        ),
      );
      length = 0;
      start = end + 1;
    }
  }
  requireObservation(length === 0);
}

export async function runPrerequisiteWorker(
  { nonce, admissionSha256, expires, pipe = null },
  edges = {},
) {
  // No inherited startup/module configuration reaches a subsequent operation.
  const environment = edges.env ?? process.env;
  for (const key of Object.keys(environment)) delete environment[key];
  let wire;
  const controller = new AbortController(),
    signal = edges.signal
      ? AbortSignal.any([controller.signal, edges.signal])
      : controller.signal,
    worker = createPrerequisiteWorker(
      { nonce, admissionSha256 },
      { ...edges, signal },
    );
  const remaining = expires - (edges.clock ?? Date.now)();
  requireObservation(
    Number.isSafeInteger(expires) &&
      remaining > 0 &&
      remaining <= PREREQUISITE_WORKER_LIMITS.lifetimeMs,
  );
  requireObservation(
    pipe === null ||
      ((edges.platform ?? process.platform) === "win32" &&
        pipe === "\\\\.\\pipe\\AgentRunnerPrerequisites-" + nonce),
  );
  let input = edges.input ?? process.stdin,
    output = edges.output ?? process.stdout,
    timer,
    primary,
    failed = false,
    clean = false;
  const fail = (error) => {
    if (!failed) {
      primary = error;
      failed = true;
    }
    controller.abort(error);
  };
  const interrupted = () => {
    fail(signal.reason);
    input.destroy(signal.reason);
  };
  signal.addEventListener("abort", interrupted, { once: true });
  const write = async (value) => {
    const bytes = Buffer.from(JSON.stringify(value) + "\n");
    requireObservation(bytes.length <= PREREQUISITE_WORKER_LIMITS.frameBytes);
    let onAbort;
    try {
      await new Promise((resolve, reject) => {
        onAbort = () => reject(signal.reason);
        signal.addEventListener("abort", onAbort, { once: true });
        if (signal.aborted) {
          onAbort();
          return;
        }
        output.write(bytes, (error) => (error ? reject(error) : resolve()));
      });
    } finally {
      signal.removeEventListener("abort", onAbort);
    }
  };
  try {
    input.on("error", fail);
    if (output !== input) output.on("error", fail);
    if (signal.aborted) throw signal.reason;
    timer = setTimeout(() => {
      const error = new Error("Expired prerequisite worker");
      fail(error);
    }, remaining);
    if (pipe !== null) {
      wire = (edges.connect ?? connect)(pipe);
      input.removeListener("error", fail);
      if (output !== input) output.removeListener("error", fail);
      input = output = wire;
      input.on("error", fail);
      // Install the failure listener before awaiting connection or writing the
      // hello frame; a failed socket must become the owned result, not an
      // unhandled EventEmitter error. Later errors also reach stream reads.
      await new Promise((resolve, reject) => {
        wire.once("error", reject);
        wire.once("connect", resolve);
      });
    }
    if (wire)
      await write({
        pid: edges.pid ?? process.pid,
        platform: edges.platform ?? process.platform,
        nonce,
      });
    for await (const frame of prerequisiteFrames(input)) {
      const result = await worker.invoke(frame);
      await write({ id: frame.id, nonce, result });
      if (frame.operation === "close") {
        clean = true;
        break;
      }
    }
    requireObservation(clean);
  } catch (error) {
    fail(error);
  } finally {
    clearTimeout(timer);
    try {
      if (!clean) await worker.close();
    } catch (error) {
      fail(error);
    }
    if (wire) wire.destroy();
    input.removeListener("error", fail);
    if (output !== input) output.removeListener("error", fail);
    signal.removeEventListener("abort", interrupted);
  }
  if (failed) throw primary;
  return { status: "CLOSED", custodianRetired: false };
}
