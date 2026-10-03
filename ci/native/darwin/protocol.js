import { createHash } from "node:crypto";
import { posix as path } from "node:path";

export const DARWIN_PROCESS_LIMIT = 32;
export const DARWIN_LITERAL_ARGUMENTS = Object.freeze([
  "",
  "space value",
  "λ雪",
  "'\"",
  "$(false); & | < > *",
]);
const HASH = /^[a-f0-9]{64}$/u;
const integer = (value, maximum = 0xffffffff) =>
  Number.isSafeInteger(value) && value >= 0 && value <= maximum;
const text = (value) =>
  typeof value === "string" &&
  !/[\u0000\uD800-\uDFFF]/u.test(value) &&
  Buffer.byteLength(value) <= 4096;
export const digest = (bytes) =>
  createHash("sha256").update(bytes).digest("hex");

export function requireDarwin(value) {
  if (!value) throw new Error("Unverified Darwin launch authority");
}

function closed(value, keys) {
  requireDarwin(
    value &&
      Object.getPrototypeOf(value) === Object.prototype &&
      Reflect.ownKeys(value).length === keys.length &&
      keys.every((key) => {
        const field = Object.getOwnPropertyDescriptor(value, key);
        return field?.enumerable && Object.hasOwn(field, "value");
      }),
  );
}

export function normalizeDarwinArguments(values) {
  requireDarwin(
    Array.isArray(values) &&
      Object.getPrototypeOf(values) === Array.prototype &&
      values.length <= 64 &&
      Reflect.ownKeys(values).length === values.length + 1,
  );
  const args = Array.from({ length: values.length }, (_, index) => {
    const field = Object.getOwnPropertyDescriptor(values, index);
    requireDarwin(
      field?.enumerable && Object.hasOwn(field, "value") && text(field.value),
    );
    return field.value;
  });
  requireDarwin(
    args.reduce((size, value) => size + Buffer.byteLength(value) + 1, 0) <=
      32768,
  );
  return args;
}

function location(value) {
  requireDarwin(
    text(value) &&
      value.startsWith("/") &&
      path.normalize(value) === value &&
      value !== "/" &&
      !value.endsWith("/"),
  );
  return value;
}
const within = (parent, child) => child.startsWith(parent + "/");

/** These are independent expected bindings, never hashes observed at launch. */
export function normalizeDarwinLaunch(value) {
  closed(value, [
    "schemaVersion",
    "candidateSha",
    "nonce",
    "uid",
    "gid",
    "custody",
    "storage",
    "workspace",
    "launcher",
    "executable",
    "policy",
    "bindings",
  ]);
  requireDarwin(
    value.schemaVersion === 1 &&
      typeof value.candidateSha === "string" &&
      /^[a-f0-9]{40}$/u.test(value.candidateSha) &&
      typeof value.nonce === "string" &&
      /^[a-f0-9]{32}$/u.test(value.nonce) &&
      integer(value.uid, 0x7fffffff) &&
      value.uid > 500 &&
      integer(value.gid, 0x7fffffff) &&
      value.gid > 500,
  );
  const result = {
    schemaVersion: 1,
    candidateSha: value.candidateSha,
    nonce: value.nonce,
    uid: value.uid,
    gid: value.gid,
  };
  for (const key of ["custody", "storage", "workspace"])
    result[key] = location(value[key]);
  requireDarwin(
    !within(result.custody, result.storage) &&
      !within(result.storage, result.custody) &&
      result.custody !== result.storage &&
      within(result.storage, result.workspace),
  );
  for (const key of ["launcher", "executable", "policy"]) {
    const entry = value[key];
    closed(
      entry,
      key === "executable" ? ["path", "sha256", "cdhash"] : ["path", "sha256"],
    );
    requireDarwin(typeof entry.sha256 === "string" && HASH.test(entry.sha256));
    result[key] = { path: location(entry.path), sha256: entry.sha256 };
    if (key === "executable") {
      requireDarwin(
        typeof entry.cdhash === "string" &&
          /^[a-f0-9]{40}$/u.test(entry.cdhash),
      );
      result[key].cdhash = entry.cdhash;
    }
  }
  requireDarwin(
    within(result.custody, result.launcher.path) &&
      within(result.custody, result.policy.path) &&
      within(result.storage, result.executable.path) &&
      !within(result.workspace, result.executable.path) &&
      result.launcher.path !== result.policy.path,
  );
  closed(value.bindings, ["system", "source", "closure", "policy"]);
  result.bindings = Object.fromEntries(
    Object.keys(value.bindings)
      .sort()
      .map((key) => {
        requireDarwin(
          typeof value.bindings[key] === "string" &&
            HASH.test(value.bindings[key]),
        );
        return [key, value.bindings[key]];
      }),
  );
  return result;
}

export const darwinLaunchDigest = (value, args) =>
  digest(
    JSON.stringify({
      request: normalizeDarwinLaunch(value),
      arguments: normalizeDarwinArguments(args),
    }),
  );

/** TASK_AUDIT_TOKEN plus independently read BSD saved IDs and start identity. */
export function normalizeDarwinIdentity(value) {
  const keys = [
    "pid",
    "pidVersion",
    "asid",
    "auid",
    "uid",
    "gid",
    "ruid",
    "rgid",
    "svuid",
    "svgid",
    "startSeconds",
    "startMicroseconds",
  ];
  closed(value, keys);
  requireDarwin(
    keys.every((key) =>
      integer(
        value[key],
        key === "startSeconds" ? Number.MAX_SAFE_INTEGER : 0xffffffff,
      ),
    ) &&
      value.pid > 0 &&
      value.pid <= 0x7fffffff &&
      value.pidVersion > 0 &&
      value.asid < 0xffffffff &&
      value.startSeconds > 0 &&
      value.startMicroseconds < 1000000,
  );
  return Object.fromEntries(keys.map((key) => [key, value[key]]));
}
export function sameDarwinIdentity(left, right) {
  try {
    return (
      JSON.stringify(normalizeDarwinIdentity(left)) ===
      JSON.stringify(normalizeDarwinIdentity(right))
    );
  } catch {
    return false;
  }
}

export function assertDarwinAuthority(value, request, record) {
  closed(value, [
    "bindings",
    "helper",
    "payload",
    "custody",
    "storage",
    "workspace",
    "cwd",
    "executable",
    "policy",
    "groups",
    "mach",
    "processLimit",
  ]);
  closed(value.bindings, Object.keys(request.bindings));
  requireDarwin(
    Object.keys(request.bindings).every(
      (key) => value.bindings[key] === request.bindings[key],
    ) &&
      sameDarwinIdentity(value.helper, record.helpers[0].identity) &&
      sameDarwinIdentity(value.payload, record.payload),
  );
  for (const [key, uid, gid, mode] of [
    ["custody", 0, 0, 0o700],
    ["storage", 0, request.gid, 0o710],
    ["workspace", request.uid, request.gid, 0o700],
    ["cwd", request.uid, request.gid, 0o700],
    ["executable", 0, request.gid, 0o550],
  ]) {
    const item = value[key];
    closed(
      item,
      key === "executable"
        ? ["dev", "ino", "uid", "gid", "mode", "nlink", "sha256", "cdhash"]
        : ["dev", "ino", "uid", "gid", "mode"],
    );
    requireDarwin(
      typeof item.dev === "string" &&
        /^(?:0|[1-9][0-9]{0,19})$/u.test(item.dev) &&
        typeof item.ino === "string" &&
        /^[1-9][0-9]{0,19}$/u.test(item.ino) &&
        item.uid === uid &&
        item.gid === gid &&
        item.mode === mode,
    );
  }
  requireDarwin(
    value.cwd.dev === value.workspace.dev &&
      value.cwd.ino === value.workspace.ino &&
      value.executable.nlink === 1 &&
      value.executable.sha256 === request.executable.sha256 &&
      value.executable.cdhash === request.executable.cdhash,
  );
  closed(value.policy, ["sha256", "compositionSha256", "installed"]);
  requireDarwin(
    value.policy.sha256 === request.policy.sha256 &&
      value.policy.compositionSha256 === request.bindings.policy &&
      value.policy.installed === true,
  );
  requireDarwin(
    Array.isArray(value.groups) &&
      value.groups.length === 1 &&
      value.groups[0] === request.gid &&
      Reflect.ownKeys(value.groups).length === 2,
  );
  closed(value.mach, [
    "bootstrap",
    "access",
    "registered",
    "exceptions",
    "foreignRights",
    "host",
  ]);
  closed(value.processLimit, ["soft", "hard"]);
  requireDarwin(
    value.processLimit.soft === DARWIN_PROCESS_LIMIT &&
      value.processLimit.hard === DARWIN_PROCESS_LIMIT &&
      value.mach.bootstrap === false &&
      value.mach.access === false &&
      value.mach.registered === 0 &&
      value.mach.exceptions === 0 &&
      value.mach.foreignRights === 0 &&
      value.mach.host === "ordinary",
  );
  return value;
}

/** Only thin x64 Mach-O, signed executable commands and explicit system loads.
 * Native signature validity/CDHash and the complete loader closure are separate. */
export function inspectDarwinMachO(bytes) {
  requireDarwin(
    Buffer.isBuffer(bytes) &&
      bytes.length >= 32 &&
      bytes.length <= 134217728 &&
      bytes.readUInt32LE(0) === 0xfeedfacf &&
      bytes.readUInt32LE(4) === 0x01000007 &&
      bytes.readUInt32LE(12) === 2,
  );
  const count = bytes.readUInt32LE(16),
    size = bytes.readUInt32LE(20);
  requireDarwin(
    count > 0 && count <= 512 && size <= 1048576 && 32 + size <= bytes.length,
  );
  let offset = 32,
    signed = false,
    loader = null;
  const libraries = [];
  for (let i = 0; i < count; i++) {
    requireDarwin(offset + 8 <= 32 + size);
    const command = bytes.readUInt32LE(offset),
      length = bytes.readUInt32LE(offset + 4);
    requireDarwin(
      length >= 8 &&
        length % 8 === 0 &&
        offset + length <= 32 + size &&
        command !== 0x8000001c &&
        command !== 0x27 &&
        ![0x6, 0x9, 0x10].includes(command),
    ); // RPATH / DYLD_ENVIRONMENT / unsupported legacy library commands.
    if ([0xc, 0x80000018, 0x8000001f, 0x20, 0x80000023].includes(command)) {
      requireDarwin(length >= 24);
      const start = bytes.readUInt32LE(offset + 8),
        end = bytes.indexOf(0, offset + start);
      requireDarwin(
        start >= 24 &&
          start < length &&
          end >= offset + start &&
          end < offset + length,
      );
      const name = new TextDecoder("utf-8", { fatal: true }).decode(
        bytes.subarray(offset + start, end),
      );
      requireDarwin(
        /^\/(?:usr\/lib|System\/Library)\//u.test(name) &&
          path.normalize(name) === name,
      );
      libraries.push(name);
    }
    if (command === 0xe) {
      requireDarwin(length >= 16 && loader === null);
      const start = bytes.readUInt32LE(offset + 8),
        end = bytes.indexOf(0, offset + start);
      requireDarwin(
        start >= 12 &&
          start < length &&
          end >= offset + start &&
          end < offset + length,
      );
      loader = bytes.subarray(offset + start, end).toString("utf8");
      requireDarwin(loader === "/usr/lib/dyld");
    }
    if (command === 0x1d) {
      requireDarwin(length === 16 && !signed);
      const start = bytes.readUInt32LE(offset + 8),
        signatureSize = bytes.readUInt32LE(offset + 12);
      requireDarwin(
        start >= 32 + size &&
          signatureSize > 0 &&
          start + signatureSize <= bytes.length,
      );
      signed = true;
    }
    offset += length;
  }
  requireDarwin(offset === 32 + size && signed && loader !== null);
  return {
    architecture: "x64",
    loader,
    libraries: [...new Set(libraries)].sort(),
    sha256: digest(bytes),
  };
}
