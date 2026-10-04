import { createHash } from "node:crypto";
import { win32 as path } from "node:path";
import { CODEX_RELEASE_REFERENCE } from "../index.js";

export const WINDOWS_PROCESS_LIMIT = 32;
export const WINDOWS_SYSTEM_SID = "S-1-5-18";
export const WINDOWS_ARGUMENT_PARSER = "msvc-ucrt-wmain-v1";
export const WINDOWS_LITERAL_ARGUMENTS = Object.freeze([
  "",
  "space value",
  "λ雪😀",
  "'\"",
  "$(false); & | < > *",
  "trailing\\",
  'backslash\\\"quote',
]);
export const WINDOWS_CREATION_PRECEDENT = Object.freeze({
  revision: CODEX_RELEASE_REFERENCE.revision,
  process: "codex-rs/windows-sandbox-rs/src/process.rs",
  attributes: "codex-rs/windows-sandbox-rs/src/proc_thread_attr.rs",
});
export const digest = (bytes) =>
  createHash("sha256").update(bytes).digest("hex");
export const hash = (value) =>
  typeof value === "string" && /^[a-f0-9]{64}$/u.test(value);
const integer = (value) =>
  Number.isSafeInteger(value) && value >= 0 && value <= 0xffffffff;
const text = (value) =>
  typeof value === "string" &&
  value.isWellFormed() &&
  !value.includes("\0") &&
  value.length <= 4096;
export function requireWindows(value) {
  if (!value) throw new Error("Unverified Windows launch authority");
}
export function closed(value, keys) {
  requireWindows(
    value &&
      Object.getPrototypeOf(value) === Object.prototype &&
      Reflect.ownKeys(value).length === keys.length &&
      keys.every((key) => {
        const field = Object.getOwnPropertyDescriptor(value, key);
        return field?.enumerable && Object.hasOwn(field, "value");
      }),
  );
}
export function dense(values, maximum) {
  requireWindows(
    Array.isArray(values) &&
      Object.getPrototypeOf(values) === Array.prototype &&
      values.length <= maximum &&
      Reflect.ownKeys(values).length === values.length + 1,
  );
  return Array.from({ length: values.length }, (_, index) => {
    const field = Object.getOwnPropertyDescriptor(values, index);
    requireWindows(field?.enumerable && Object.hasOwn(field, "value"));
    return field.value;
  });
}
export function sid(value) {
  requireWindows(
    typeof value === "string" &&
      /^S-1-[0-9]{1,15}(?:-[0-9]{1,10}){1,15}$/u.test(value),
  );
  const parts = value.split("-");
  requireWindows(
    BigInt(parts[2]) <= 0xffffffffffffn &&
      String(BigInt(parts[2])) === parts[2] &&
      parts
        .slice(3)
        .every(
          (part) =>
            BigInt(part) <= 0xffffffffn && String(BigInt(part)) === part,
        ),
  );
  return value;
}
export function normalizeWindowsArguments(values) {
  const args = dense(values, 64);
  requireWindows(
    args.every(text) &&
      args.reduce((size, arg) => size + arg.length + 1, 0) <= 16384,
  );
  return args;
}
/** Reviewed UCRT argv[1..] rules. Always quote, doubling backslashes before
 * quotes and the closing quote. No cmd.exe, shell or CommandLineToArgvW claim. */
export function quoteWindowsArgument(value) {
  requireWindows(text(value));
  return (
    '"' +
    value
      .replace(/(\\*)"/gu, (_, slashes) => slashes + slashes + '\\"')
      .replace(/(\\+)$/u, "$1$1") +
    '"'
  );
}
export function windowsCommandLine(application, args) {
  application = location(application);
  // The launcher has ten fixed control arguments in addition to the payload.
  const vector = dense(args, 74);
  requireWindows(vector.every(text));
  const command = [application, ...vector].map(quoteWindowsArgument).join(" ");
  requireWindows(command.length < 32767);
  return command;
}
function location(value) {
  requireWindows(
    text(value) &&
      /^[A-Z]:\\/u.test(value) &&
      value.length > 3 &&
      path.normalize(value) === value &&
      !value.endsWith("\\") &&
      value
        .slice(3)
        .split("\\")
        .every(
          (part) =>
            /^[A-Za-z0-9 _.-]+$/u.test(part) &&
            !/[ .]$/u.test(part) &&
            !/^(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)/iu.test(part),
        ),
  );
  return value;
}
const within = (parent, child) =>
  child.toLowerCase().startsWith(parent.toLowerCase() + "\\");
export function normalizeWindowsLaunch(value) {
  closed(value, [
    "schemaVersion",
    "candidateSha",
    "nonce",
    "restrictingSid",
    "custody",
    "storage",
    "workspace",
    "launcher",
    "executable",
    "policy",
    "bindings",
  ]);
  requireWindows(
    value.schemaVersion === 1 &&
      typeof value.candidateSha === "string" &&
      /^[a-f0-9]{40}$/u.test(value.candidateSha) &&
      typeof value.nonce === "string" &&
      /^[a-f0-9]{32}$/u.test(value.nonce),
  );
  const result = {
    schemaVersion: 1,
    candidateSha: value.candidateSha,
    nonce: value.nonce,
    restrictingSid: sid(value.restrictingSid),
  };
  requireWindows(
    /^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+$/u.test(result.restrictingSid),
  );
  for (const key of ["custody", "storage", "workspace"])
    result[key] = location(value[key]);
  requireWindows(
    result.custody.toLowerCase() !== result.storage.toLowerCase() &&
      !within(result.custody, result.storage) &&
      !within(result.storage, result.custody) &&
      within(result.storage, result.workspace),
  );
  for (const key of ["launcher", "executable"]) {
    closed(
      value[key],
      key === "executable"
        ? ["path", "sha256", "signatureSha256", "parser"]
        : ["path", "sha256", "signatureSha256"],
    );
    requireWindows(hash(value[key].sha256) && hash(value[key].signatureSha256));
    result[key] = {
      path: location(value[key].path),
      sha256: value[key].sha256,
      signatureSha256: value[key].signatureSha256,
    };
    requireWindows(/\.exe$/iu.test(result[key].path));
  }
  requireWindows(value.executable.parser === WINDOWS_ARGUMENT_PARSER);
  result.executable.parser = WINDOWS_ARGUMENT_PARSER;
  closed(value.policy, ["path", "sha256"]);
  requireWindows(hash(value.policy.sha256));
  result.policy = {
    path: location(value.policy.path),
    sha256: value.policy.sha256,
  };
  requireWindows(
    within(result.custody, result.launcher.path) &&
      within(result.custody, result.policy.path) &&
      within(result.storage, result.executable.path) &&
      !within(result.workspace, result.executable.path) &&
      result.executable.path.toLowerCase() !== result.workspace.toLowerCase() &&
      result.launcher.path.toLowerCase() !== result.policy.path.toLowerCase(),
  );
  closed(value.bindings, ["system", "source", "closure", "policy"]);
  result.bindings = Object.fromEntries(
    Object.keys(value.bindings)
      .sort()
      .map((key) => {
        requireWindows(hash(value.bindings[key]));
        return [key, value.bindings[key]];
      }),
  );
  return result;
}
export const windowsLaunchDigest = (value, args) =>
  digest(
    JSON.stringify({
      request: normalizeWindowsLaunch(value),
      arguments: normalizeWindowsArguments(args),
    }),
  );
export const windowsAccountName = (nonce) => {
  requireWindows(typeof nonce === "string" && /^[a-f0-9]{32}$/u.test(nonce));
  return "np_" + nonce.slice(0, 16);
};
export function normalizeWindowsIdentity(value) {
  closed(value, ["pid", "creationTime", "sessionId", "userSid"]);
  requireWindows(
    integer(value.pid) &&
      value.pid > 0 &&
      integer(value.sessionId) &&
      typeof value.creationTime === "string" &&
      /^[1-9][0-9]{0,19}$/u.test(value.creationTime) &&
      BigInt(value.creationTime) <= 0xffffffffffffffffn,
  );
  return {
    pid: value.pid,
    creationTime: value.creationTime,
    sessionId: value.sessionId,
    userSid: sid(value.userSid),
  };
}
export function sameWindowsIdentity(left, right) {
  try {
    return (
      JSON.stringify(normalizeWindowsIdentity(left)) ===
      JSON.stringify(normalizeWindowsIdentity(right))
    );
  } catch {
    return false;
  }
}
export function systemIdentity(value) {
  const identity = normalizeWindowsIdentity(value);
  requireWindows(
    identity.userSid === WINDOWS_SYSTEM_SID && identity.sessionId === 0,
  );
  return identity;
}
/** PE bounds and signature bytes are pure inspection, not Authenticode trust,
 * effective loader closure, publication or a callable SDK/export attestation. */
export function inspectWindowsPe(value) {
  requireWindows(
    value instanceof Uint8Array &&
      value.byteLength >= 512 &&
      value.byteLength <= 134217728,
  );
  const bytes = Buffer.from(value),
    offset = bytes.readUInt32LE(0x3c);
  requireWindows(
    bytes.readUInt16LE(0) === 0x5a4d &&
      offset >= 64 &&
      offset <= bytes.length - 264 &&
      bytes.readUInt32LE(offset) === 0x4550 &&
      bytes.readUInt16LE(offset + 4) === 0x8664 &&
      !(bytes.readUInt16LE(offset + 22) & 0x2000),
  );
  const optional = offset + 24,
    size = bytes.readUInt16LE(offset + 20),
    sections = bytes.readUInt16LE(offset + 6);
  requireWindows(
    size >= 240 &&
      size <= 4096 &&
      sections > 0 &&
      sections <= 96 &&
      optional + size + sections * 40 <= bytes.length &&
      bytes.readUInt16LE(optional) === 0x20b &&
      bytes.readUInt32LE(optional + 108) >= 5,
  );
  const certificate = bytes.readUInt32LE(optional + 144),
    length = bytes.readUInt32LE(optional + 148);
  requireWindows(
    certificate >= optional + size + sections * 40 &&
      certificate % 8 === 0 &&
      length >= 8 &&
      certificate + length <= bytes.length &&
      bytes.readUInt32LE(certificate) >= 8 &&
      bytes.readUInt32LE(certificate) <= length &&
      bytes.readUInt16LE(certificate + 4) === 0x200 &&
      bytes.readUInt16LE(certificate + 6) === 2,
  );
  return {
    architecture: "x64",
    sha256: digest(bytes),
    signatureSha256: digest(bytes.subarray(certificate, certificate + length)),
  };
}
