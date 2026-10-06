import { createHash } from "node:crypto";
import { constants } from "node:fs";
import * as filesystem from "node:fs/promises";
import { posix } from "node:path";

import {
  observationDigest,
  observationObject,
  requireObservation,
} from "./observation.js";

export const PREREQUISITE_FILE_LIMITS = Object.freeze({
  bytes: 536870912,
  intentBytes: 65536,
  parents: 64,
});
const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");
const fields = [
  "dev",
  "ino",
  "uid",
  "gid",
  "mode",
  "nlink",
  "size",
  "mtimeNs",
  "ctimeNs",
];
const identity = (stat) => {
  requireObservation(
    fields.every((key) => typeof stat[key] === "bigint") &&
      stat.dev >= 0n &&
      stat.ino > 0n &&
      stat.uid >= 0n &&
      stat.gid >= 0n &&
      stat.nlink > 0n &&
      stat.size >= 0n,
  );
  return Object.fromEntries(fields.map((key) => [key, String(stat[key])]));
};
const same = (left, right) =>
  observationDigest(left) === observationDigest(right);

export function prerequisiteCreationRequest(
  root,
  file,
  bytes,
  executable = false,
) {
  requireObservation(
    bytes instanceof Uint8Array &&
      bytes.length <= PREREQUISITE_FILE_LIMITS.bytes &&
      typeof executable === "boolean",
  );
  return {
    schemaVersion: 1,
    operation: "create",
    root,
    file,
    bytes: bytes.length,
    sha256: digest(bytes),
    executable,
  };
}

/** Private Linux filesystem primitives, not a custodian/process retirement proof.
 * Creation requires a separately persisted immutable request. Failed writes
 * remain held and cannot be retried, adopted, unlinked, or admitted as assets.
 * Darwin extended ACLs are independent of mode bits. Node supplies no held ACL
 * reader, so this owner cannot admit Darwin directories, intents, or files. */
export function createPosixPrerequisiteFiles({
  root,
  ownerUid,
  controllerUid = ownerUid,
  fs = filesystem,
  platform = process.platform,
}) {
  requireObservation(
    platform === "linux" && (fs !== filesystem || process.platform === "linux"),
  );
  const canonical = (file) =>
    typeof file === "string" &&
    file.length <= 4096 &&
    posix.isAbsolute(file) &&
    posix.normalize(file) === file &&
    !/[\u0000-\u001f\u007f]/u.test(file);
  requireObservation(
    canonical(root) &&
      root !== "/" &&
      Number.isSafeInteger(ownerUid) &&
      ownerUid >= 0 &&
      Number.isSafeInteger(controllerUid) &&
      controllerUid >= 0,
  );
  requireObservation(
    Number.isInteger(constants.O_NOFOLLOW) &&
      Number.isInteger(constants.O_DIRECTORY) &&
      Number.isInteger(constants.O_NONBLOCK),
  );
  const files = new Map(),
    parents = new Map(),
    handles = new Set(),
    uncertain = new Map();
  const writers = new Set([0n, BigInt(ownerUid), BigInt(controllerUid)]);
  let fenced = false,
    pending = Promise.resolve();
  const inside = (file) => canonical(file) && file.startsWith(root + "/");
  const retain = async (file, flags, mode) => {
    const handle = await fs.open(file, flags, mode);
    handles.add(handle);
    return handle;
  };
  const release = async (handle) => {
    await handle.close();
    handles.delete(handle);
  };
  const run = (operation) => {
    requireObservation(!fenced);
    const result = pending.then(operation);
    pending = result.catch(() => {});
    return result;
  };
  const checkDirectory = async (file) => {
    let entry = parents.get(file);
    if (!entry) {
      requireObservation((await fs.realpath(file)) === file);
      const handle = await retain(
        file,
        constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW,
      );
      entry = {
        handle,
        initial: identity(await handle.stat({ bigint: true })),
      };
      parents.set(file, entry);
    }
    const held = await entry.handle.stat({ bigint: true }),
      named = await fs.lstat(file, { bigint: true });
    requireObservation(
      held.isDirectory() &&
        named.isDirectory() &&
        held.dev === named.dev &&
        held.ino === named.ino &&
        String(held.dev) === entry.initial.dev &&
        String(held.ino) === entry.initial.ino &&
        writers.has(held.uid) &&
        !(held.mode & 0o22n) &&
        held.uid === named.uid &&
        held.mode === named.mode,
    );
    if (file === root || inside(file))
      requireObservation(held.uid === BigInt(ownerUid) && !(held.mode & 0o77n));
  };
  const parentChain = async (file, create = false, signal) => {
    const chain = [];
    for (
      let current = posix.dirname(file);
      ;
      current = posix.dirname(current)
    ) {
      chain.unshift(current);
      requireObservation(chain.length <= PREREQUISITE_FILE_LIMITS.parents);
      if (current === "/") break;
    }
    for (const current of chain) {
      requireObservation(!signal?.aborted);
      if (create && inside(current)) {
        try {
          await fs.lstat(current);
        } catch (error) {
          if (error?.code !== "ENOENT") throw error;
          await fs.mkdir(current, { mode: 0o700 });
        }
      }
      await checkDirectory(current);
    }
  };
  const hold = async (
    file,
    { maximum, signal, sealed = false } = {},
    creating = false,
  ) => {
    requireObservation(
      canonical(file) &&
        !signal?.aborted &&
        Number.isSafeInteger(maximum) &&
        maximum > 0 &&
        maximum <= PREREQUISITE_FILE_LIMITS.bytes,
    );
    await parentChain(file, false, signal);
    let entry = files.get(file);
    if (!entry) {
      entry = {
        handle: await retain(
          file,
          constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
        ),
        initial: null,
        sha256: null,
        born: null,
        failed: false,
      };
      files.set(file, entry);
    }
    requireObservation(!entry.failed && (creating || !uncertain.has(file)));
    const before = await entry.handle.stat({ bigint: true }),
      named = await fs.lstat(file, { bigint: true });
    requireObservation(
      before.isFile() &&
        named.isFile() &&
        before.nlink === 1n &&
        writers.has(before.uid) &&
        !(before.mode & (sealed || entry.born ? 0o222n : 0o22n)) &&
        before.size >= 0n &&
        before.size <= BigInt(maximum) &&
        same(identity(before), identity(named)) &&
        (!entry.initial || same(entry.initial, identity(before))),
    );
    if (entry.born)
      requireObservation(
        String(before.dev) === entry.born.dev &&
          String(before.ino) === entry.born.ino,
      );
    const buffer = Buffer.alloc(Number(before.size) + 1);
    let offset = 0;
    while (offset < buffer.length) {
      requireObservation(!signal?.aborted);
      const { bytesRead } = await entry.handle.read(
        buffer,
        offset,
        buffer.length - offset,
        offset,
      );
      requireObservation(
        Number.isSafeInteger(bytesRead) &&
          bytesRead >= 0 &&
          bytesRead <= buffer.length - offset,
      );
      if (!bytesRead) break;
      offset += bytesRead;
    }
    const after = await entry.handle.stat({ bigint: true }),
      current = await fs.lstat(file, { bigint: true });
    const bytes = buffer.subarray(0, offset),
      sha256 = digest(bytes);
    requireObservation(
      !signal?.aborted &&
        offset === Number(before.size) &&
        same(identity(before), identity(after)) &&
        same(identity(before), identity(current)) &&
        (!entry.sha256 || entry.sha256 === sha256),
    );
    await parentChain(file, false, signal);
    entry.initial = identity(before);
    entry.sha256 = sha256;
    return {
      file,
      bytes,
      identity: { ...entry.initial },
      independent: true,
      held: true,
      protectedParents: true,
      birthProtected: Boolean(entry.born),
      unchanged: true,
      readExecuteOnly: !(before.mode & 0o222n),
      event: { before: identity(before), after: identity(after), sha256 },
    };
  };
  const verifyIntent = async (request, intent, signal) => {
    requireObservation(
      intent &&
        inside(intent.file) &&
        intent.file !== request.file &&
        Number.isSafeInteger(intent.bytes) &&
        intent.bytes > 0 &&
        intent.bytes <= PREREQUISITE_FILE_LIMITS.intentBytes &&
        typeof intent.sha256 === "string" &&
        /^[a-f0-9]{64}$/u.test(intent.sha256),
    );
    const observed = await hold(intent.file, {
      maximum: intent.bytes,
      sealed: true,
      signal,
    });
    requireObservation(
      observed.bytes.length === intent.bytes &&
        digest(observed.bytes) === intent.sha256 &&
        observed.identity.uid === String(ownerUid) &&
        same(JSON.parse(observed.bytes.toString("utf8")), request),
    );
    return observed;
  };
  return {
    hold: (file, options) => run(() => hold(file, options)),
    create(file, input, { executable = false, intent, signal } = {}) {
      requireObservation(
        inside(file) &&
          input instanceof Uint8Array &&
          input.length <= PREREQUISITE_FILE_LIMITS.bytes &&
          !files.has(file) &&
          !uncertain.has(file),
      );
      const bytes = Buffer.from(input),
        request = prerequisiteCreationRequest(root, file, bytes, executable);
      return run(async () => {
        requireObservation(!files.has(file) && !uncertain.has(file));
        const record = await verifyIntent(request, intent, signal);
        uncertain.set(file, request);
        await parentChain(file, true, signal);
        requireObservation(!signal?.aborted);
        const writer = await retain(
          file,
          constants.O_RDWR |
            constants.O_CREAT |
            constants.O_EXCL |
            constants.O_NOFOLLOW,
          0o600,
        );
        const entry = {
          handle: writer,
          initial: null,
          sha256: null,
          born: null,
          failed: true,
          request,
        };
        files.set(file, entry);
        const birth = await writer.stat({ bigint: true }),
          named = await fs.lstat(file, { bigint: true });
        requireObservation(
          birth.isFile() &&
            birth.nlink === 1n &&
            birth.uid === BigInt(ownerUid) &&
            !(birth.mode & 0o77n) &&
            same(identity(birth), identity(named)),
        );
        entry.born = identity(birth);
        await writer.writeFile(bytes);
        requireObservation(!signal?.aborted);
        await writer.sync();
        await writer.chmod(executable ? 0o555 : 0o444);
        const reader = await retain(
          file,
          constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
        );
        const sealed = await reader.stat({ bigint: true });
        requireObservation(
          sealed.dev === birth.dev &&
            sealed.ino === birth.ino &&
            same(
              identity(sealed),
              identity(await fs.lstat(file, { bigint: true })),
            ),
        );
        await release(writer);
        entry.handle = reader;
        entry.initial = identity(sealed);
        entry.failed = false;
        try {
          const observed = await hold(
            file,
            { maximum: Math.max(1, bytes.length), sealed: true, signal },
            true,
          );
          requireObservation(
            observed.event.sha256 === request.sha256 &&
              observed.bytes.length === request.bytes,
          );
          uncertain.delete(file);
          return {
            ...observed,
            exclusive: true,
            requestSha256: observationDigest(request),
            intentIdentitySha256: observationDigest(record.identity),
          };
        } catch (error) {
          entry.failed = true;
          throw error;
        }
      });
    },
    /** Reconstruct exclusion from a protected request, never infer birth
     * ownership from a matching name/hash or retry a possibly consumed write. */
    recover(request, { intent, signal } = {}) {
      observationObject(request, [
        "schemaVersion",
        "operation",
        "root",
        "file",
        "bytes",
        "sha256",
        "executable",
      ]);
      requireObservation(
        request?.schemaVersion === 1 &&
          request.operation === "create" &&
          request.root === root &&
          inside(request.file) &&
          Number.isSafeInteger(request.bytes) &&
          request.bytes >= 0 &&
          request.bytes <= PREREQUISITE_FILE_LIMITS.bytes &&
          typeof request.sha256 === "string" &&
          /^[a-f0-9]{64}$/u.test(request.sha256) &&
          typeof request.executable === "boolean",
      );
      request = { ...request };
      return run(async () => {
        await verifyIntent(request, intent, signal);
        uncertain.set(request.file, structuredClone(request));
        await parentChain(request.file, false, signal);
        let observation = null;
        try {
          observation = identity(
            await fs.lstat(request.file, { bigint: true }),
          );
        } catch (error) {
          if (error?.code !== "ENOENT") throw error;
        }
        await parentChain(request.file, false, signal);
        return {
          status: "RETAINED",
          requestSha256: observationDigest(request),
          observation,
          birthProtected: false,
          admitted: false,
        };
      });
    },
    async close() {
      fenced = true;
      await pending;
      const results = await Promise.allSettled([...handles].map(release));
      requireObservation(
        results.every((result) => result.status === "fulfilled") &&
          handles.size === 0,
      );
      return {
        status: "CLOSED",
        closedHandles: results.length,
        uncertainFiles: [...uncertain.keys()],
        custodianRetired: false,
      };
    },
  };
}
