import { win32 as path } from "node:path";
import { normalizeNativePolicyContext } from "../index.js";
import {
  closed,
  dense,
  hash,
  sid,
  requireWindows,
  normalizeWindowsIdentity,
  windowsPrivatePath,
} from "./protocol.js";
import { normalizeWindowsFileIdentity } from "./files-protocol.js";

// Longest fixed file recipe (1,110 seconds), plus separate 30-second
// settlement and 30-second entry margin. Native header/task bounds match this.
export const WINDOWS_CUSTODY_DEADLINE_MS = 1170000;

export const integer = (value, maximum = 127) =>
  Number.isSafeInteger(value) && value >= 0 && value <= maximum;
export const location = (value) =>
  typeof value === "string" &&
  value.isWellFormed() &&
  /^[A-Z]:\\/u.test(value) &&
  path.normalize(value) === value &&
  value.length < 4096 &&
  !/[\u0000-\u001f\u007f<>"|?*]/u.test(value) &&
  !value.slice(2).includes(":");
export const encode = (value) => Buffer.from(value, "utf16le").toString("hex");
export const decode = (value) => {
  requireWindows(
    typeof value === "string" && /^(?:[a-f0-9]{4}){1,4095}$/u.test(value),
  );
  const result = new TextDecoder("utf-16le", { fatal: true }).decode(
    Buffer.from(value, "hex"),
  );
  requireWindows(!/[\u0000-\u001f\u007f]/u.test(result));
  return result;
};

/** Fixed verification lane. No shell, arbitrary native dispatch or PID-only
 * retirement is admitted. The serving owner persists these exact arguments. */
export function windowsVerificationArguments(name, values) {
  const args = dense(values, 4).map((value) => {
    requireWindows(typeof value === "string" || Number.isSafeInteger(value));
    return String(value);
  });
  const slot = (text, maximum = 127) =>
    /^(?:0|[1-9][0-9]*)$/u.test(text) && integer(Number(text), maximum);
  const birth = () =>
    args.length === 2 &&
    slot(args[0], 0xffffffff) &&
    Number(args[0]) > 0 &&
    /^[1-9][0-9]{0,19}$/u.test(args[1]);
  const task = () =>
    ["custody", "prerequisite"].includes(args[0]) &&
    /^[a-f0-9]{32}$/u.test(decode(args[1]));
  let valid = false;
  switch (name) {
    case "subjects":
      valid = args.length === 0;
      break;
    case "file":
      valid =
        args.length === 4 &&
        location(decode(args[0])) &&
        hash(args[1]) &&
        (args[2] === "-" || hash(args[2])) &&
        slot(args[3], 134217728) &&
        Number(args[3]) > 0;
      break;
    case "sharing":
      valid = args.length === 1 && location(decode(args[0]));
      break;
    case "retain":
      valid = birth();
      break;
    case "process":
    case "job":
      valid = args.length === 1 && slot(args[0]);
      break;
    case "compiler-policy":
      valid =
        args.length === 2 &&
        slot(args[0]) &&
        slot(args[1]) &&
        args[0] !== args[1];
      break;
    case "case":
      valid =
        args.length === 4 &&
        slot(args[0]) &&
        slot(args[1]) &&
        hash(args[2]) &&
        /^[1-9][0-9]{0,19}$/u.test(args[3]);
      break;
    case "case-retired":
      valid = args.length === 2 && slot(args[0]) && hash(args[1]);
      break;
    case "case-recover":
      valid =
        args.length === 4 &&
        slot(args[0]) &&
        hash(args[1]) &&
        /^[a-f0-9]{32}$/u.test(args[2]) &&
        slot(args[3], 1);
      break;
    case "recovery-object":
      valid = args.length === 1 && slot(args[0]);
      break;
    case "recovery-jobs":
      valid =
        args.length === 2 && slot(args[0]) && /^[a-f0-9]{32}$/u.test(args[1]);
      break;
    case "access":
      valid =
        args.length === 4 &&
        slot(args[0]) &&
        slot(args[1]) &&
        hash(args[2]) &&
        /^(?:[a-f0-9]{2}){1,32768}$/u.test(args[3]);
      break;
    case "access-control":
      valid =
        args.length === 4 &&
        slot(args[0]) &&
        slot(args[1]) &&
        /^[a-z0-9-]{1,63}$/u.test(args[2]) &&
        /^(?:[a-f0-9]{2}){1,32768}$/u.test(args[3]);
      break;
    case "access-peer-retired":
      valid = args.length === 2 && slot(args[0]) && slot(args[1]);
      break;
    case "access-peer-policy":
      valid =
        args.length === 4 &&
        slot(args[0]) &&
        slot(args[1]) &&
        slot(args[2]) &&
        /^(?:[a-f0-9]{2}){1,32768}$/u.test(args[3]);
      break;
    case "socket":
      valid =
        args.length === 4 &&
        slot(args[0]) &&
        hash(args[1]) &&
        /^[1-9][0-9]{0,19}$/u.test(args[2]) &&
        /^(?:[a-f0-9]{2}){1,1024}$/u.test(args[3]);
      break;
    case "receipt":
      valid =
        args.length === 3 &&
        slot(args[0]) &&
        slot(args[1], 4095) &&
        hash(args[2]);
      break;
    case "job-read":
      valid =
        args.length === 2 &&
        slot(args[0]) &&
        /^Local\\NativeProof-[a-f0-9]{32}$/u.test(decode(args[1]));
      break;
    case "image":
      valid =
        args.length === 3 && slot(args[0]) && hash(args[1]) && hash(args[2]);
      break;
    case "transfer":
      valid =
        args.length === 2 &&
        slot(args[0]) &&
        slot(args[1]) &&
        args[0] !== args[1];
      break;
    case "task":
      valid = args.length === 2 && task();
      break;
    case "task-remove":
      valid = args.length === 4 && task() && hash(args[2]) && slot(args[3]);
      break;
    case "read":
      valid =
        args.length === 3 &&
        slot(args[0], 127) &&
        slot(args[1], 8388608) &&
        slot(args[2], 32768) &&
        Number(args[2]) > 0 &&
        Number(args[1]) + Number(args[2]) <= 8388608;
      break;
    case "job-open":
      valid =
        args.length === 1 &&
        /^Local\\NativeProof-[a-f0-9]{32}$/u.test(decode(args[0]));
      break;
  }
  requireWindows(valid);
  return args;
}
const image = (value, signed = true) => {
  closed(
    value,
    signed ? ["path", "sha256", "signatureSha256"] : ["path", "sha256"],
  );
  const pathname = windowsPrivatePath(value.path);
  requireWindows(
    hash(value.sha256) && (!signed || hash(value.signatureSha256)),
  );
  return { ...structuredClone(value), path: pathname };
};
export function normalizeWindowsCustodyInput(value) {
  closed(value, [
    "context",
    "nonce",
    "reader",
    "bridge",
    "sources",
    "plan",
    "runnerSid",
    "reviewSha256",
    "sdkSha256",
    "buildSha256",
  ]);
  const context = normalizeNativePolicyContext(value.context),
    reader = image(value.reader),
    bridge = image(value.bridge),
    plan = image(value.plan, false);
  requireWindows(
    context.platform === "win32" &&
      /^[a-f0-9]{32}$/u.test(value.nonce) &&
      ["reviewSha256", "sdkSha256", "buildSha256"].every((key) =>
        hash(value[key]),
      ) &&
      path.basename(reader.path) === "custody-reader.exe" &&
      path.basename(bridge.path) === "custody-bridge.exe" &&
      path.dirname(reader.path) === path.dirname(bridge.path),
  );
  const sources = dense(value.sources, 6).map((source) => image(source, false));
  requireWindows(
    sources.length === 6 &&
      [
        "custody-reader.c",
        "custody-bridge.c",
        "custody.h",
        "effective-reader.h",
        "account.h",
        "audit-policy-remove.h",
      ].every(
        (name) =>
          sources.filter(
            (source) =>
              path.basename(source.path) === name &&
              path.dirname(source.path) === path.dirname(reader.path),
          ).length === 1,
      ),
  );
  const runnerSid = sid(value.runnerSid);
  requireWindows(runnerSid !== "S-1-5-18");
  return {
    ...structuredClone(value),
    context,
    reader,
    bridge,
    plan,
    sources,
    runnerSid,
  };
}
export function encodeWindowsCustodyPlan(value) {
  closed(value, ["candidateSha", "nonce", "entries"]);
  requireWindows(
    /^[a-f0-9]{40}$/u.test(value.candidateSha) &&
      /^[a-f0-9]{32}$/u.test(value.nonce),
  );
  const entries = dense(value.entries, 128),
    paths = new Set();
  requireWindows(entries.length > 0);
  const lines = entries.map((entry) => {
    closed(entry, ["kind", "path", "sha256", "signatureSha256"]);
    requireWindows(
      ["directory", "data", "mutable", "image", "helper", "sdk"].includes(
        entry.kind,
      ) &&
        location(entry.path) &&
        (entry.kind === "directory"
          ? entry.sha256 === null
          : hash(entry.sha256)) &&
        (["image", "helper"].includes(entry.kind)
          ? hash(entry.signatureSha256)
          : entry.signatureSha256 === null) &&
        !paths.has(entry.path.toLowerCase()),
    );
    paths.add(entry.path.toLowerCase());
    return `${entry.kind} ${entry.sha256 ?? "-"} ${entry.signatureSha256 ?? "-"} ${encode(entry.path)}`;
  });
  const bytes = Buffer.from(
    [
      `native-custody-v1 ${value.candidateSha} ${value.nonce}`,
      ...lines,
      "",
    ].join("\n"),
  );
  requireWindows(bytes.length <= 262144);
  return bytes;
}

export function fileObservation(value) {
  closed(value, [
    "identity",
    "pathHex",
    "volumeHex",
    "filesystemHex",
    "daclSha256",
    "links",
    "directory",
    "held",
    "reparse",
  ]);
  normalizeWindowsFileIdentity(value.identity);
  requireWindows(
    location(decode(value.pathHex)) &&
      /^\\\\\?\\Volume\{[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}\}\\$/iu.test(
        decode(value.volumeHex),
      ) &&
      ["NTFS", "ReFS"].includes(decode(value.filesystemHex)) &&
      hash(value.daclSha256) &&
      integer(value.links, 128) &&
      value.links > 0 &&
      typeof value.directory === "boolean" &&
      (value.directory || value.links === 1) &&
      value.held === true &&
      value.reparse === false,
  );
  return structuredClone(value);
}
export function processObservation(value) {
  closed(value, [
    "identity",
    "processDaclSha256",
    "tokenId",
    "authenticationId",
    "integritySid",
    "groups",
    "restricting",
    "privileges",
    "retired",
  ]);
  normalizeWindowsIdentity(value.identity);
  sid(value.integritySid);
  requireWindows(
    hash(value.processDaclSha256) &&
      /^[a-f0-9]{16}$/u.test(value.tokenId) &&
      /^[a-f0-9]{16}$/u.test(value.authenticationId) &&
      typeof value.retired === "boolean",
  );
  for (const group of dense(value.groups, 128)) {
    closed(group, ["sid", "attributes"]);
    sid(group.sid);
    requireWindows(integer(group.attributes, 0xffffffff));
  }
  for (const id of dense(value.restricting, 128)) sid(id);
  for (const privilege of dense(value.privileges, 128)) {
    closed(privilege, ["luid", "attributes"]);
    requireWindows(
      /^[a-f0-9]{16}$/u.test(privilege.luid) &&
        integer(privilege.attributes, 0xffffffff),
    );
  }
  return structuredClone(value);
}
export function jobObservation(value) {
  closed(value, [
    "daclSha256",
    "limitFlags",
    "processLimit",
    "uiRestrictions",
    "members",
  ]);
  requireWindows(
    hash(value.daclSha256) &&
      integer(value.limitFlags, 0xffffffff) &&
      integer(value.processLimit, 32) &&
      integer(value.uiRestrictions, 255),
  );
  const members = dense(value.members, 32).map(normalizeWindowsIdentity);
  requireWindows(
    new Set(members.map((member) => member.pid)).size === members.length,
  );
  return structuredClone(value);
}
export function decodePlan(bytes, input) {
  const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes),
    lines = text.split("\n");
  requireWindows(
    lines.shift() ===
      `native-custody-v1 ${input.context.candidateSha} ${input.nonce}` &&
      lines.pop() === "",
  );
  const entries = lines.map((line) => {
    const parts = line.split(" ");
    requireWindows(parts.length === 4);
    return {
      kind: parts[0],
      path: decode(parts[3]),
      sha256: parts[1] === "-" ? null : parts[1],
      signatureSha256: parts[2] === "-" ? null : parts[2],
    };
  });
  requireWindows(
    encodeWindowsCustodyPlan({
      candidateSha: input.context.candidateSha,
      nonce: input.nonce,
      entries,
    }).equals(bytes),
  );
  return entries;
}
