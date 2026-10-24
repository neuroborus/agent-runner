import { constants } from "node:fs";
import * as filesystem from "node:fs/promises";
import { observationDigest, requireObservation } from "../observation.js";
import { createWindowsPreparationFiles } from "../win32/index.js";
import {
  providerBytesDigest,
  providerHash,
  providerPaths,
} from "./preparation.js";

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
const identity = (stat) =>
  Object.fromEntries(fields.map((key) => [key, String(stat[key])]));
const same = (a, b) => observationDigest(a) === observationDigest(b);

/** Held filesystem reads are independent of compiler output. Darwin also
 * requires the native observer's held ACL/identity/hash read; mode bits alone
 * never confer that platform's authority. Windows keeps its System owner. */
export function createProviderPreparationFiles(input, options, nativeDarwin) {
  const { job, directory, helpers } = input,
    paths = providerPaths(job.platform),
    fs = options.fs ?? filesystem,
    ownerUid = options.ownerUid ?? process.getuid?.(),
    handles = new Set(),
    parents = new Map(),
    files = new Map();
  if (job.platform === "win32") {
    const owner = createWindowsPreparationFiles(
      {
        job,
        directory,
        helpers,
        manifest: {
          windowsPreparation: {
            bootstrap: input.manifest.providerPreparation.bootstrap,
          },
        },
      },
      { ...options.fileTransport, env: options.env, receiptPrefix: "provider" },
    );
    const protect = (proof) => ({
      ...proof,
      protectedAuthority: proof.protectedDacl === true,
    });
    return {
      native: owner,
      verifyDirectory: async (request) =>
        protect(await owner.verifyDirectory(request)),
      readProtected: async (request) =>
        protect(await owner.readProtected(request)),
      writeProtected: async (request) =>
        protect(await owner.writeProtected(request)),
      async listReceipts(request) {
        const proof = await owner.verifyDirectory(request);
        return { ...protect(proof), names: await owner.readdir(directory) };
      },
      async settleFiles() {
        const declaration = owner.verification.input,
          helper = owner.verification.identity,
          bridge = owner.verification.bridge,
          taskSha256 = owner.verification.taskSha256;
        return {
          ...(await owner.settleFiles()),
          helper,
          bridge,
          nonce: declaration.nonce,
          taskSha256,
        };
      },
    };
  }
  requireObservation(Number.isSafeInteger(ownerUid) && ownerUid >= 0);
  let closed = false,
    tail = Promise.resolve();
  const run = (operation) => {
    requireObservation(!closed);
    const result = tail.then(operation);
    tail = result.catch(() => {});
    return result;
  };
  const canonical = (file) =>
    typeof file === "string" &&
    paths.isAbsolute(file) &&
    paths.normalize(file) === file &&
    !/[\u0000-\u001f\u007f]/u.test(file);
  const retain = async (file, flags, mode) => {
    const handle = await fs.open(file, flags, mode);
    handles.add(handle);
    return handle;
  };
  const release = async (handle) => {
    await handle.close();
    handles.delete(handle);
  };
  const parent = async (file) => {
    requireObservation(canonical(file) && (await fs.realpath(file)) === file);
    let held = parents.get(file);
    if (!held) {
      const handle = await retain(
        file,
        constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW,
      );
      held = { handle, stat: identity(await handle.stat({ bigint: true })) };
      parents.set(file, held);
    }
    const before = await held.handle.stat({ bigint: true }),
      named = await fs.lstat(file, { bigint: true });
    requireObservation(
      before.isDirectory() &&
        named.isDirectory() &&
        before.dev === named.dev &&
        before.ino === named.ino &&
        String(before.dev) === held.stat.dev &&
        String(before.ino) === held.stat.ino &&
        before.mode === named.mode &&
        before.uid === named.uid &&
        [0n, BigInt(ownerUid)].includes(before.uid) &&
        !(before.mode & 0o22n),
    );
    if (job.platform === "darwin" && file === helpers)
      requireObservation(
        before.uid === 0n && (before.mode & 0o7777n) === 0o555n,
      );
    else if (file === directory || file.startsWith(directory + "/"))
      requireObservation(
        before.uid === BigInt(ownerUid) && (before.mode & 0o7777n) === 0o700n,
      );
    return identity(before);
  };
  const ancestry = async (file) => {
    for (let current = file, count = 0; ; current = paths.dirname(current)) {
      requireObservation(++count <= 64);
      await parent(current);
      if (current === "/") break;
    }
  };
  const proof = (file, stat, event) => ({
    file,
    independent: true,
    held: true,
    protectedParents: true,
    protectedAuthority: true,
    identitySha256: observationDigest(stat),
    nativeEventSha256: observationDigest(event),
  });
  const read = async (
    { file, sha256, maximum, receipt = false },
    native = true,
  ) => {
    requireObservation(
      canonical(file) &&
        Number.isSafeInteger(maximum) &&
        maximum > 0 &&
        maximum <= 536870912,
    );
    await ancestry(paths.dirname(file));
    requireObservation((await fs.realpath(file)) === file);
    let held = files.get(file);
    if (!held) {
      const handle = await retain(
        file,
        constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
      );
      held = { handle, stat: identity(await handle.stat({ bigint: true })) };
      files.set(file, held);
    }
    const before = await held.handle.stat({ bigint: true }),
      stockTool =
        providerHash(sha256) &&
        input.buildManifest.tools.some(
          (tool) => tool.path === file && tool.sha256 === sha256,
        );
    requireObservation(
      before.isFile() &&
        before.nlink === 1n &&
        before.size > 0n &&
        before.size <= BigInt(maximum) &&
        [0n, BigInt(ownerUid)].includes(before.uid) &&
        !(before.mode & 0o6022n) &&
        (!(before.mode & 0o200n) ||
          (stockTool && before.uid === 0n && before.gid === 0n)) &&
        same(held.stat, identity(before)),
    );
    if (receipt)
      requireObservation(
        paths.dirname(file) === directory &&
          before.uid === BigInt(ownerUid) &&
          (before.mode & 0o7777n) === 0o400n,
      );
    const bytes = Buffer.alloc(Number(before.size) + 1);
    let offset = 0;
    while (offset < bytes.length) {
      const { bytesRead } = await held.handle.read(
        bytes,
        offset,
        bytes.length - offset,
        offset,
      );
      requireObservation(
        Number.isSafeInteger(bytesRead) &&
          bytesRead >= 0 &&
          bytesRead <= bytes.length - offset,
      );
      if (!bytesRead) break;
      offset += bytesRead;
    }
    const after = await held.handle.stat({ bigint: true }),
      named = await fs.lstat(file, { bigint: true });
    requireObservation(
      offset === Number(before.size) &&
        same(identity(before), identity(after)) &&
        same(identity(before), identity(named)) &&
        (await fs.realpath(file)) === file,
    );
    const result = bytes.subarray(0, offset),
      actual = providerBytesDigest(result);
    requireObservation(!sha256 || sha256 === actual);
    const authority =
      native && job.platform === "darwin"
        ? await nativeDarwin(file, actual, false)
        : null;
    if (authority)
      requireObservation(
        authority.object.identity.split(":")[0] === String(after.dev) &&
          authority.object.identity.split(":")[3] === String(after.ino) &&
          authority.object.bytes === Number(after.size) &&
          authority.object.uid === Number(after.uid) &&
          authority.object.gid === Number(after.gid) &&
          authority.object.mode === Number(after.mode & 0o7777n),
      );
    requireObservation(
      same(
        identity(after),
        identity(await held.handle.stat({ bigint: true })),
      ) &&
        same(identity(after), identity(await fs.lstat(file, { bigint: true }))),
    );
    await ancestry(paths.dirname(file));
    if (receipt) {
      await release(held.handle);
      files.delete(file);
    }
    return {
      ...proof(file, identity(after), {
        stat: identity(after),
        actual,
        authority,
      }),
      bytes: result,
      sha256: actual,
      unchanged: true,
      immutable: receipt,
    };
  };
  const verifyDirectory = async () => {
    await ancestry(directory);
    const actual = await parent(directory),
      authority =
        job.platform === "darwin"
          ? await nativeDarwin(directory, null, true)
          : null;
    if (authority)
      requireObservation(
        authority.object.identity.split(":")[0] === actual.dev &&
          authority.object.identity.split(":")[3] === actual.ino &&
          String(authority.object.uid) === actual.uid &&
          authority.object.mode === 0o700,
      );
    return {
      ...proof(directory, actual, { actual, authority }),
      directory,
      exclusiveWriter: true,
    };
  };
  // Raw sealed records also bootstrap Darwin's observer. Its native admission
  // verifies these pending records before acknowledging any dependent effect.
  const write = async ({ file, bytes, exclusive }, native = true) => {
    requireObservation(
      exclusive === true &&
        paths.dirname(file) === directory &&
        /^provider-[a-z0-9.-]+\.json$/u.test(paths.basename(file)) &&
        Buffer.isBuffer(bytes) &&
        bytes.length > 0 &&
        bytes.length <= 1048576 &&
        !files.has(file),
    );
    await ancestry(directory);
    const writer = await retain(
      file,
      constants.O_RDWR |
        constants.O_CREAT |
        constants.O_EXCL |
        constants.O_NOFOLLOW,
      0o600,
    );
    const birth = await writer.stat({ bigint: true });
    requireObservation(
      birth.isFile() &&
        birth.uid === BigInt(ownerUid) &&
        birth.nlink === 1n &&
        !(birth.mode & 0o77n),
    );
    await writer.writeFile(bytes);
    await writer.sync();
    await writer.chmod(0o400);
    const sealed = identity(await writer.stat({ bigint: true }));
    await release(writer);
    const actual = await read(
      {
        file,
        sha256: providerBytesDigest(bytes),
        maximum: 1048576,
        receipt: true,
      },
      native,
    );
    requireObservation(actual.identitySha256 === observationDigest(sealed));
    return { ...actual, exclusive: true, writerClosed: true };
  };
  return {
    verifyDirectory: () => run(verifyDirectory),
    readProtected: (request) => run(() => read(request)),
    writeProtected: (request) => run(() => write(request)),
    // Bootstrap persistence cannot recurse through the observer it is starting.
    writeBootstrap: (request) => write(request, false),
    async listReceipts() {
      return run(async () => {
        const before = await verifyDirectory(),
          stat = await parent(directory),
          names = await fs.readdir(directory);
        requireObservation(
          names.length <= 65536 &&
            new Set(names).size === names.length &&
            names.every((name) => /^[a-zA-Z0-9.-]{1,240}$/u.test(name)) &&
            same(stat, await parent(directory)),
        );
        return {
          ...before,
          names: names.filter((name) => /^provider-.*\.json$/u.test(name)),
        };
      });
    },
    async provisionBuild() {
      requireObservation(job.platform === "linux");
      await ancestry(directory);
      await fs.mkdir(input.providerHelpers, { mode: 0o700 });
      return parent(input.providerHelpers);
    },
    async settleFiles() {
      closed = true;
      await tail;
      const results = await Promise.allSettled([...handles].map(release));
      requireObservation(
        results.every((result) => result.status === "fulfilled") &&
          handles.size === 0,
      );
      return {
        status: "CLOSED",
        custodianRetired: false,
        closedHandles: results.length,
      };
    },
  };
}
