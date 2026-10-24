import { win32 as path } from "node:path";
import { normalizeNativePolicyContext, observationDigest } from "../index.js";
import {
  closed,
  dense,
  hash,
  sid,
  requireWindows,
  normalizeWindowsIdentity,
  sameWindowsIdentity,
  systemIdentity,
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
    case "cold-process":
      valid = birth();
      break;
    case "cold-jobs":
      valid =
        args.length === 3 &&
        slot(args[0], 0xffffffff) &&
        Number(args[0]) > 0 &&
        /^[1-9][0-9]{0,19}$/u.test(args[1]) &&
        /^[a-f0-9]{32}$/u.test(args[2]);
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
    case "ownership-births":
      valid = args.length === 2 && slot(args[0]) && hash(args[1]);
      break;
    case "policy-recover":
    case "audit-recover":
    case "audit-check":
      valid =
        args.length === 3 &&
        slot(args[0]) &&
        hash(args[1]) &&
        /^[a-f0-9]{32}$/u.test(args[2]);
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
    case "runtime":
      valid =
        args.length === 4 &&
        slot(args[0]) &&
        slot(args[1]) &&
        hash(args[2]) &&
        hash(args[3]);
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
    case "task-instance":
      valid =
        args.length === 2 &&
        /^[a-f0-9]{32}$/u.test(decode(args[0])) &&
        slot(args[1]);
      break;
    case "process-exit":
      valid = args.length === 1 && slot(args[0]);
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

/** Only protected, matching original birth/result receipts select cold custody.
 * Their identities remain declarations when the native census finds no PID. */
export function windowsClosedPreparationOwner(birth, result) {
  for (const value of [birth, result]) {
    closed(value, [
      "schemaVersion",
      "nonce",
      "taskSha256",
      "helper",
      "bridge",
      "status",
    ]);
    requireWindows(
      value.schemaVersion === 1 &&
        /^[a-f0-9]{32}$/u.test(value.nonce) &&
        hash(value.taskSha256),
    );
    normalizeWindowsIdentity(value.helper);
    normalizeWindowsIdentity(value.bridge);
  }
  requireWindows(
    birth.status === "POSSIBLE" &&
      result.status === "RETIRED" &&
      birth.nonce === result.nonce &&
      birth.taskSha256 === result.taskSha256 &&
      sameWindowsIdentity(birth.helper, result.helper) &&
      sameWindowsIdentity(birth.bridge, result.bridge) &&
      birth.helper.pid !== birth.bridge.pid,
  );
  systemIdentity(birth.helper);
  return {
    nonce: birth.nonce,
    identities: [birth.helper, birth.bridge].map(normalizeWindowsIdentity),
    taskSha256: birth.taskSha256,
    receiptsSha256: observationDigest({ birth, result }),
  };
}

export function coldProcessObservation(value, expected) {
  const original = value.present === true && value.original === true;
  closed(
    value,
    value.present === true
      ? [
          "complete",
          "present",
          "original",
          "identity",
          ...(original ? ["signaled", "exitCode"] : []),
        ]
      : ["complete", "present"],
  );
  requireWindows(value.complete === true && typeof value.present === "boolean");
  if (value.present) {
    const actual = normalizeWindowsIdentity(value.identity),
      declared = normalizeWindowsIdentity(expected);
    requireWindows(
      typeof value.original === "boolean" &&
        (original
          ? sameWindowsIdentity(actual, declared) &&
            value.signaled === true &&
            integer(value.exitCode, 127) &&
            value.exitCode !== 124
          : actual.pid === declared.pid &&
            BigInt(actual.creationTime) > BigInt(declared.creationTime)),
    );
  }
  return value.present
    ? {
        complete: true,
        present: true,
        original,
        identity: normalizeWindowsIdentity(value.identity),
        ...(original ? { signaled: true, exitCode: value.exitCode } : {}),
      }
    : { complete: true, present: false };
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
  return custodyInput(value, false);
}
export function normalizeWindowsExperimentCustody(value) {
  return custodyInput(value, true);
}
// Private owner dispatch does not confer independent-review admission.
export const windowsCustodyInput = (value) =>
  value?.purpose === "experiment"
    ? normalizeWindowsExperimentCustody(value)
    : normalizeWindowsCustodyInput(value);
export const windowsCustodyBinding = (value) =>
  value.purpose === "experiment" ? value.bindingSha256 : value.reviewSha256;
function custodyInput(value, experiment) {
  closed(value, [
    ...(experiment ? ["purpose"] : []),
    "context",
    "nonce",
    "reader",
    "bridge",
    "sources",
    "plan",
    "runnerSid",
    experiment ? "bindingSha256" : "reviewSha256",
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
      (!experiment || value.purpose === "experiment") &&
      [
        experiment ? "bindingSha256" : "reviewSha256",
        "sdkSha256",
        "buildSha256",
      ].every((key) => hash(value[key])) &&
      path.basename(reader.path) === "custody-reader.exe" &&
      path.basename(bridge.path) === "custody-bridge.exe" &&
      path.dirname(reader.path) === path.dirname(bridge.path),
  );
  const sources = dense(value.sources, experiment ? 7 : 6).map((source) =>
    image(source, false),
  );
  requireWindows(
    sources.length === (experiment ? 7 : 6) &&
      [
        "custody-reader.c",
        "custody-bridge.c",
        "custody.h",
        "effective-reader.h",
        "account.h",
        "audit-policy-remove.h",
        ...(experiment ? ["experiment.h"] : []),
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
  const experiment = value.purpose === "experiment";
  closed(value, [
    ...(experiment ? ["purpose"] : []),
    "candidateSha",
    "nonce",
    "entries",
  ]);
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
      `${experiment ? "native-experiment-v1" : "native-custody-v1"} ${value.candidateSha} ${value.nonce}`,
      ...lines,
      "",
    ].join("\n"),
  );
  requireWindows(bytes.length <= 262144);
  return bytes;
}

export function fileObservation(value, { stockLinks = false } = {}) {
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
      (value.directory || stockLinks || value.links === 1) &&
      value.held === true &&
      value.reparse === false,
  );
  return structuredClone(value);
}
/** Normalize a fresh held-process module census against its held main image. */
export function loaderObservation(value, purpose, image) {
  closed(value, [
    ...(purpose === "experiment" ? ["importScope"] : []),
    "loaded",
    "imports",
    "linkerMajor",
    "linkerMinor",
    "timestamp",
    "complete",
  ]);
  requireWindows(
    value.complete === true &&
      (purpose !== "experiment" || value.importScope === "private-runtime") &&
      dense(value.loaded, 128).length > 0 &&
      integer(value.linkerMajor, 255) &&
      integer(value.linkerMinor, 255) &&
      integer(value.timestamp, 0xffffffff),
  );
  for (const file of value.loaded) {
    closed(file, [
      "pathHex",
      "identity",
      "sha256",
      "signatureSha256",
      "daclSha256",
      "links",
    ]);
    requireWindows(
      location(decode(file.pathHex)) &&
        hash(file.sha256) &&
        hash(file.signatureSha256) &&
        hash(file.daclSha256) &&
        integer(file.links, 128) &&
        file.links > 0,
    );
    normalizeWindowsFileIdentity(file.identity);
  }
  for (const entry of dense(value.imports, 2048)) {
    closed(entry, ["source", "resolved", "delay", "importHex"]);
    requireWindows(
      integer(entry.source, value.loaded.length - 1) &&
        integer(entry.resolved, value.loaded.length - 1) &&
        typeof entry.delay === "boolean" &&
        /^(?:[a-f0-9]{2}){1,255}$/u.test(entry.importHex),
    );
  }
  requireWindows(
    value.loaded.some(
      (file) =>
        file.identity === image.identity &&
        file.sha256 === image.sha256 &&
        file.signatureSha256 === image.signatureSha256,
    ),
  );
  return structuredClone(value);
}

/** Fresh admission-owned image/module reads never export the owner's slots. */
export function helperRuntimeObservation(value, helper, image) {
  closed(value, ["processImage", "imageIdentity", "loader"]);
  closed(value.processImage, ["identity", "sha256", "signatureSha256"]);
  requireWindows(
    value.imageIdentity === image.identity &&
      sameWindowsIdentity(value.processImage.identity, helper) &&
      value.processImage.sha256 === image.sha256 &&
      value.processImage.signatureSha256 === image.signatureSha256,
  );
  const loader = loaderObservation(value.loader, "experiment", image);
  requireWindows(
    loader.loaded.some(
      (file) =>
        file.identity === image.identity &&
        decode(file.pathHex).toLowerCase() === image.path.toLowerCase() &&
        file.daclSha256 === image.daclSha256 &&
        file.links === image.links,
    ),
  );
  return { ...structuredClone(value), loader };
}

export function windowsTaskInstance(value) {
  closed(value, ["guid", "state", "enginePid"]);
  requireWindows(
    typeof value.guid === "string" &&
      /^\{[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}\}$/iu.test(value.guid) &&
      value.guid.replace(/[{}-]/gu, "") !== "0".repeat(32) &&
      integer(value.state, 4) &&
      integer(value.enginePid, 0xffffffff),
  );
  return { ...value, guid: value.guid.toLowerCase() };
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
      `${input.purpose === "experiment" ? "native-experiment-v1" : "native-custody-v1"} ${input.context.candidateSha} ${input.nonce}` &&
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
      ...(input.purpose === "experiment" ? { purpose: "experiment" } : {}),
      candidateSha: input.context.candidateSha,
      nonce: input.nonce,
      entries,
    }).equals(bytes),
  );
  return entries;
}
