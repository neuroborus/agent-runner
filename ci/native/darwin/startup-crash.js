import { execFile } from "node:child_process";
import { constants, watch } from "node:fs";
import { open, readdir, readFile } from "node:fs/promises";
import { homedir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import {
  nativeException,
  nativeDiagnostic,
  diagnosticCommand,
} from "../diagnostics.js";
import {
  digest,
  inspectDarwinMachO,
  normalizeDarwinIdentity,
} from "./protocol.js";

const LIMIT = 2 * 1024 * 1024;
const execute = promisify(execFile);
const UUID = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/u;
const OBSERVATIONS = new Set([
  "unavailable",
  "read-failed",
  "unusable",
  "watch-failed",
  "empty",
  "unmatched",
  "image-changed",
]);
const TIMESTAMP_REJECTIONS = [
  "timestamp-missing",
  "timestamp-type",
  "timestamp-format",
  "timestamp-timezone",
  "timestamp-precision",
  "timestamp-calendar",
];
const REJECTIONS = Object.freeze({
  "log-record": new Set([
    "encoding",
    "size",
    "json",
    "shape",
    "timestamp",
    ...TIMESTAMP_REJECTIONS,
    "message",
    "process",
    "source",
  ]),
  "crash-record": new Set([
    "encoding",
    "size",
    "json",
    "metadata",
    "shape",
    "pid",
    "path",
    "timestamp",
    ...TIMESTAMP_REJECTIONS,
    "images",
    "exception",
    "termination",
    "threads",
  ]),
  "binding-rejection": new Set([
    "input",
    "pid",
    "image",
    "birth",
    "uuid",
    "window",
    "signal",
    "termination",
    "source",
  ]),
});
const rejected = (status, kind, reason) => ({ status, kind, reason });
const LOG_FIELDS = [
  "timestamp",
  "eventMessage",
  "processID",
  "senderImagePath",
  "subsystem",
];
const FIELD_CODES = Object.freeze({
  missing: "m",
  null: "z",
  string: "s",
  number: "n",
  boolean: "b",
  array: "a",
  object: "o",
});
const PATH_CODES = Object.freeze({ absolute: "a", relative: "r", empty: "e" });
function closedRecord(value, fields, optional = []) {
  return (
    record(value) &&
    fields.every((field) => Object.hasOwn(value, field)) &&
    Reflect.ownKeys(value).every(
      (field) => fields.includes(field) || optional.includes(field),
    )
  );
}
function imageFactsDetail(facts) {
  if (
    !closedRecord(facts, [
      "form",
      "exactPath",
      "expectedFilename",
      "expectedDirectory",
    ])
  )
    return null;
  const { form, exactPath, expectedFilename, expectedDirectory } = facts;
  return typeof form === "string" &&
    Object.hasOwn(PATH_CODES, form) &&
    exactPath === false &&
    typeof expectedFilename === "boolean" &&
    typeof expectedDirectory === "boolean" &&
    !(expectedFilename && expectedDirectory) &&
    (form === "absolute" || !expectedDirectory) &&
    (form !== "empty" || !expectedFilename)
    ? `[${PATH_CODES[form]}${Number(exactPath)}${Number(expectedFilename)}${Number(expectedDirectory)}]`
    : null;
}
function logFieldsDetail(fields) {
  if (
    !Array.isArray(fields) ||
    fields.length !== LOG_FIELDS.length ||
    Reflect.ownKeys(fields).length !== LOG_FIELDS.length + 1 ||
    Object.keys(fields).join(",") !== "0,1,2,3,4"
  )
    return null;
  const types = LOG_FIELDS.map((_, index) => fields[index]);
  return types[0] === "missing" &&
    types.every(
      (type) => typeof type === "string" && Object.hasOwn(FIELD_CODES, type),
    )
    ? `[${types.map((type) => FIELD_CODES[type]).join(",")}]`
    : null;
}
function rejectedImageFacts(observed, expected) {
  const at = observed.lastIndexOf("/"),
    wanted = expected.lastIndexOf("/");
  return {
    form:
      observed === ""
        ? "empty"
        : observed.startsWith("/")
          ? "absolute"
          : "relative",
    exactPath: observed === expected,
    expectedFilename: observed.slice(at + 1) === expected.slice(wanted + 1),
    // Keep the separator: an absent directory never equals the absolute root.
    expectedDirectory:
      observed.slice(0, at + 1) === expected.slice(0, wanted + 1),
  };
}
function rejectionDetail(value) {
  if (
    !closedRecord(
      value,
      ["kind", "reason", "status"],
      ["imageChecks", "imageFacts", "logFields"],
    )
  )
    return "";
  const {
    status,
    kind,
    reason,
    imageChecks: checks,
    imageFacts,
    logFields,
  } = value;
  if (
    typeof kind !== "string" ||
    typeof reason !== "string" ||
    !Object.hasOwn(REJECTIONS, kind) ||
    !REJECTIONS[kind].has(reason) ||
    !(kind === "binding-rejection"
      ? status === "unmatched" || (status === "unusable" && reason === "input")
      : status === "unusable")
  )
    return "";
  const facts = Object.hasOwn(value, "imageFacts")
      ? imageFactsDetail(imageFacts)
      : "",
    fields = Object.hasOwn(value, "logFields")
      ? logFieldsDetail(logFields)
      : "";
  if (
    facts === null ||
    fields === null ||
    (facts && (kind !== "binding-rejection" || reason !== "image")) ||
    (fields && (kind !== "log-record" || reason !== "timestamp-missing"))
  )
    return "";
  if (!Object.hasOwn(value, "imageChecks"))
    return `; ${kind}=${reason}${facts}${fields}`;
  if (
    kind !== "binding-rejection" ||
    status !== "unmatched" ||
    !Array.isArray(checks) ||
    checks.length !== 2 ||
    Object.keys(checks).join(",") !== "0,1"
  )
    return "";
  const comparisons = checks.map((check) => {
    if (!closedRecord(check, ["image", "reason"], ["imageFacts"])) return null;
    const { image, reason, imageFacts } = check,
      detail = Object.hasOwn(check, "imageFacts")
        ? imageFactsDetail(imageFacts)
        : "";
    return ["helper", "argv-fixture"].includes(image) &&
      REJECTIONS["binding-rejection"].has(reason) &&
      detail !== null &&
      (!detail || reason === "image")
      ? { image, reason, detail }
      : null;
  });
  if (
    !comparisons.every(Boolean) ||
    new Set(comparisons.map(({ image }) => image)).size !== 2
  )
    return "";
  // The pair includes the preferred rejection; avoid repeating it within
  // the bounded cause alongside signal, log and observation-failure facts.
  return `; images=${comparisons.map(({ image, reason, detail }) => `${image}:${reason}${detail}`).join(",")}`;
}

function observationText(value, limit, kind) {
  const size = Buffer.isBuffer(value)
    ? value.length
    : typeof value === "string"
      ? Buffer.byteLength(value)
      : 0;
  if (size > limit) return rejected("unusable", kind, "size");
  try {
    const text = Buffer.isBuffer(value)
      ? new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(value)
      : value;
    return typeof text === "string" && text.isWellFormed()
      ? { text }
      : rejected("unusable", kind, "encoding");
  } catch (diagnosticError) {
    nativeException("darwin/startup-crash.js:exception", diagnosticError);
    return rejected("unusable", kind, "encoding");
  }
}

// Normalize timezone spelling and fractional seconds, never round a birth or
// widen its window. Native timestamps remain private integer microseconds.
function startupTimestamp(value) {
  if (value === undefined) return { reason: "timestamp-missing" };
  if (typeof value !== "string") return { reason: "timestamp-type" };
  const match =
    /^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})(?:\.(\d+))?(.*)$/u.exec(value);
  if (!match) return { reason: "timestamp-format" };
  if (match[3]?.length > 6) return { reason: "timestamp-precision" };
  if (!/^(?:Z| ?[+-]\d{2}:?\d{2})$/u.test(match[4]))
    return { reason: "timestamp-timezone" };
  const literal = `${match[1]}T${match[2]}`,
    milliseconds = Date.parse(`${literal}Z`);
  if (
    !Number.isFinite(milliseconds) ||
    new Date(milliseconds).toISOString().slice(0, 19) !== literal
  )
    return { reason: "timestamp-calendar" };
  const zone = match[4].replace(/[ :]/gu, ""),
    hours = Number(zone.slice(1, 3)),
    minutes = Number(zone.slice(3, 5));
  if (zone !== "Z" && (hours > 23 || minutes > 59))
    return { reason: "timestamp-timezone" };
  const offset =
    zone === "Z" ? 0 : (hours * 60 + minutes) * (zone[0] === "+" ? 1 : -1);
  return {
    time:
      BigInt(milliseconds) * 1000n -
      BigInt(offset) * 60000000n +
      BigInt((match[3] ?? "").padEnd(6, "0")),
  };
}
const startupTime = (value) => startupTimestamp(value).time ?? null;
const inWindow = (time, startedAt, endedAt) =>
  Number.isSafeInteger(startedAt) &&
  Number.isSafeInteger(endedAt) &&
  startedAt <= endedAt &&
  time >= BigInt(startedAt) * 1000n &&
  time <= BigInt(endedAt) * 1000n;

function matchingStartupCI() {
  return (
    process.platform === "darwin" &&
    process.arch === "x64" &&
    process.env.CI === "true" &&
    process.env.GITHUB_ACTIONS === "true" &&
    process.env.RUNNER_ENVIRONMENT === "github-hosted" &&
    process.env.RUNNER_OS === "macOS"
  );
}

/** Join OS crash UUIDs to the already signature-verified, exact thin image. */
export function darwinStartupImageUUID(bytes) {
  inspectDarwinMachO(bytes);
  let uuid = null,
    offset = 32;
  for (let index = 0; index < bytes.readUInt32LE(16); index++) {
    const command = bytes.readUInt32LE(offset),
      length = bytes.readUInt32LE(offset + 4);
    if (command === 0x1b) {
      if (uuid !== null || length !== 24) return null;
      const hex = bytes.subarray(offset + 8, offset + 24).toString("hex");
      uuid = `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
      if (/^0+-0+-0+-0+-0+$/u.test(uuid)) return null;
    }
    offset += length;
  }
  return uuid;
}

function startupBinding(binding) {
  try {
    const identity = normalizeDarwinIdentity(binding.identity);
    return (
      identity.pid === binding.pid &&
      typeof binding.image === "string" &&
      binding.image.isWellFormed() &&
      path.posix.isAbsolute(binding.image) &&
      path.posix.normalize(binding.image) === binding.image &&
      !/[\p{Cc}\p{Zl}\p{Zp}]/u.test(binding.image) &&
      Buffer.byteLength(binding.image) <= 4096 &&
      ["helper", "argv-fixture"].includes(path.basename(binding.image)) &&
      /^[a-f0-9]{64}$/u.test(binding.sha256) &&
      Number.isSafeInteger(binding.startedAt) &&
      Number.isSafeInteger(binding.endedAt) &&
      binding.startedAt <= binding.endedAt
    );
  } catch (diagnosticError) {
    nativeException("darwin/startup-crash.js:exception", diagnosticError);
    return false;
  }
}

function startupImages(binding) {
  if (!binding || typeof binding !== "object") return [];
  const alternatives = binding.alternatives ?? [];
  if (
    !Array.isArray(alternatives) ||
    alternatives.length > 1 ||
    !alternatives.every(
      (image) =>
        image && Object.keys(image).sort().join(",") === "image,sha256",
    )
  )
    return [];
  const images = [
    { ...binding },
    ...alternatives.map((image) => ({ ...binding, ...image })),
  ];
  if (
    !images.every(startupBinding) ||
    new Set(images.map(({ image }) => path.basename(image))).size !==
      images.length ||
    images.some(
      ({ image }) => path.dirname(image) !== path.dirname(binding.image),
    )
  )
    return [];
  return images;
}
const DENIALS = new Set([
  "file-read-data",
  "file-read-metadata",
  "file-map-executable",
  "mach-lookup",
  "syscall-vnguard",
  "syscall-sandbox",
]);

function denialEvents(text) {
  const decoded = observationText(text, 65536, "log-record");
  if (decoded.status) return decoded;
  try {
    const events = decoded.text
      .split("\n")
      .filter((line) => line.trim() !== "")
      .map((line) => JSON.parse(line));
    for (const event of events) {
      const timestampReason = record(event)
        ? startupTimestamp(event.timestamp).reason
        : null;
      let reason;
      if (!record(event)) reason = "shape";
      else if (timestampReason) reason = timestampReason;
      else if (
        typeof event.eventMessage !== "string" ||
        !event.eventMessage.isWellFormed()
      )
        reason = "message";
      else if (!Number.isSafeInteger(event.processID) || event.processID < 0)
        reason = "process";
      else if (
        !["senderImagePath", "subsystem"].every(
          (key) =>
            event[key] === undefined ||
            (typeof event[key] === "string" && event[key].isWellFormed()),
        )
      )
        reason = "source";
      if (reason)
        return {
          ...rejected("unusable", "log-record", reason),
          ...(reason === "timestamp-missing"
            ? {
                logFields: LOG_FIELDS.map((field) =>
                  !Object.hasOwn(event, field)
                    ? "missing"
                    : event[field] === null
                      ? "null"
                      : Array.isArray(event[field])
                        ? "array"
                        : typeof event[field],
                ),
              }
            : {}),
        };
    }
    return { events };
  } catch (diagnosticError) {
    nativeException("darwin/startup-crash.js:exception", diagnosticError);
    return rejected("unusable", "log-record", "json");
  }
}

/** Related kernel denials are diagnosis, not proof of the abort's cause. */
export function darwinStartupDenial(text, { pid, image, startedAt, endedAt }) {
  if (
    typeof text !== "string" ||
    typeof image !== "string" ||
    !["helper", "argv-fixture"].includes(path.basename(image)) ||
    !text.isWellFormed() ||
    Buffer.byteLength(text) > 65536 ||
    !Number.isSafeInteger(pid) ||
    pid <= 0 ||
    !Number.isSafeInteger(startedAt) ||
    !Number.isSafeInteger(endedAt) ||
    startedAt > endedAt
  )
    return null;
  const observed = denialEvents(text);
  const denial = observed.events
    ? startupDenial(observed.events, { pid, image, startedAt, endedAt })
    : null;
  return DENIALS.has(denial) ? denial : null;
}

function startupDenial(events, { pid, image, startedAt, endedAt }) {
  let rejection;
  for (const event of events) {
    const match =
      /^Sandbox: (helper|argv-fixture)\(([1-9][0-9]*)\) deny\([1-9][0-9]*\) (file-read-data|file-read-metadata|file-map-executable|mach-lookup|system-mac-syscall)(?: (.*))?$/u.exec(
        event.eventMessage,
      );
    if (!match) continue;
    let reason;
    if (Number(match[2]) !== pid) reason = "pid";
    else if (match[1] !== path.basename(image)) reason = "image";
    else if (!inWindow(startupTime(event.timestamp), startedAt, endedAt))
      reason = "window";
    else if (!(
      (event.processID === 0 && event.senderImagePath?.includes("/Sandbox")) ||
      event.subsystem === "com.apple.sandbox.reporting"
    ))
      reason = "source";
    if (reason) {
      rejection ??= rejected("unmatched", "binding-rejection", reason);
      continue;
    }
    if (match[3] !== "system-mac-syscall") return match[3];
    if (match[4] === "vnguard") return "syscall-vnguard";
    if (match[4] === "Sandbox" || /^Sandbox [0-9]+$/u.test(match[4] ?? ""))
      return "syscall-sandbox";
  }
  return rejection ?? null;
}
export function darwinStartupDenialDetail(value) {
  if (DENIALS.has(value)) return `; observed-denial=${value}`;
  if (
    value &&
    ((OBSERVATIONS.has(value.status) && value.status !== "watch-failed") ||
      value.status === "command-failed")
  ) {
    const exit =
      value.status === "command-failed" &&
      Number.isInteger(value.exitCode) &&
      value.exitCode >= 0 &&
      value.exitCode <= 255
        ? `:${value.exitCode}`
        : "";
    return `; log-read=${value.status}${exit}${rejectionDetail(value)}`;
  }
  return "";
}

export async function readDarwinStartupDenial(
  binding,
  { isMatchingCI = matchingStartupCI(), read = readFile, run = execute } = {},
) {
  if (!isMatchingCI) return { status: "unavailable" };
  const images = startupImages(binding);
  if (images.length === 0)
    return rejected("unusable", "binding-rejection", "input");
  try {
    for (const image of images)
      if (digest(await read(image.image)) !== image.sha256)
        return { status: "image-changed" };
  } catch (diagnosticError) {
    nativeException("darwin/startup-crash.js:exception", diagnosticError);
    return { status: "read-failed" };
  }
  let stdout;
  try {
    const names = images.map(({ image }) => path.basename(image));
    ({ stdout } = await diagnosticCommand("darwin-unified-log", run)(
      "/usr/bin/sudo",
      [
        "--non-interactive",
        "--",
        "/usr/bin/log",
        "show",
        "--style",
        "ndjson",
        "--last",
        "1m",
        "--info",
        "--debug",
        "--predicate",
        `(((processID == 0) AND (senderImagePath CONTAINS "/Sandbox")) OR (subsystem == "com.apple.sandbox.reporting")) AND (${names.map((name) => `(eventMessage CONTAINS "${name}(${binding.pid})")`).join(" OR ")})`,
      ],
      {
        env: { PATH: "/usr/bin:/bin", LANG: "C" },
        timeout: 12000,
        maxBuffer: 65536,
        encoding: "buffer",
      },
    ));
  } catch (error) {
    nativeException("darwin/startup-crash.js:exception", error);
    /* A missing log is not a denial or an admission witness. */
    return {
      status: "command-failed",
      exitCode:
        Number.isInteger(error?.code) && error.code >= 0 && error.code <= 255
          ? error.code
          : null,
    };
  }
  try {
    for (const image of images)
      if (digest(await read(image.image)) !== image.sha256)
        return { status: "image-changed" };
  } catch (diagnosticError) {
    nativeException("darwin/startup-crash.js:exception", diagnosticError);
    return { status: "read-failed" };
  }
  const observed = denialEvents(stdout);
  if (observed.status) return observed;
  const results = images.map((image) => startupDenial(observed.events, image));
  return (
    results.find((value) => DENIALS.has(value)) ??
    results.find(Boolean) ?? {
      status: observed.events.length === 0 ? "empty" : "unmatched",
    }
  );
}
const NAMESPACES = new Set([
  "DYLD",
  "LIBSYSTEM",
  "CODESIGNING",
  "SIGNAL",
  "GUARD",
  "SANDBOX",
]);
const FRAMES = Object.freeze({
  _libsecinit_appsandbox: "sandbox-init",
  libSystem_initializer: "system-init",
  __abort_with_payload: "abort-payload",
  abort_with_payload: "abort-payload",
});

function record(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function startupReport(text) {
  const decoded = observationText(text, LIMIT, "crash-record");
  if (decoded.status) return decoded;
  try {
    const newline = decoded.text.indexOf("\n");
    if (newline < 1) return rejected("unusable", "crash-record", "metadata");
    const metadata = JSON.parse(decoded.text.slice(0, newline)),
      report = JSON.parse(decoded.text.slice(newline + 1));
    const string = (value) => typeof value === "string" && value.isWellFormed();
    const timestampReason = record(report)
      ? (startupTimestamp(report.procLaunch).reason ??
        startupTimestamp(report.captureTime).reason)
      : null;
    let reason;
    if (!record(metadata)) reason = "metadata";
    else if (!record(report)) reason = "shape";
    else if (!Number.isSafeInteger(report.pid) || report.pid <= 0)
      reason = "pid";
    else if (!string(report.procPath)) reason = "path";
    else if (timestampReason) reason = timestampReason;
    else if (
      !Array.isArray(report.usedImages) ||
      !report.usedImages.every(
        (image) =>
          record(image) &&
          (image.path === undefined || string(image.path)) &&
          (image.uuid === undefined || string(image.uuid)),
      )
    )
      reason = "images";
    else if (!record(report.exception) || !string(report.exception.signal))
      reason = "exception";
    else if (
      report.termination !== undefined &&
      (!record(report.termination) ||
        !string(report.termination.namespace) ||
        !Number.isSafeInteger(report.termination.code))
    )
      reason = "termination";
    else if (
      (report.faultingThread !== undefined &&
        (!Number.isSafeInteger(report.faultingThread) ||
          report.faultingThread < 0)) ||
      (report.threads !== undefined &&
        (!Array.isArray(report.threads) ||
          !report.threads.every(
            (thread) =>
              record(thread) &&
              (thread.frames === undefined ||
                (Array.isArray(thread.frames) &&
                  thread.frames.every(
                    (frame) =>
                      record(frame) &&
                      (frame.symbol === undefined || string(frame.symbol)),
                  ))),
          )))
    )
      reason = "threads";
    return reason
      ? rejected("unusable", "crash-record", reason)
      : {
          report,
          launchTime: startupTime(report.procLaunch),
          captureTime: startupTime(report.captureTime),
        };
  } catch (diagnosticError) {
    nativeException("darwin/startup-crash.js:exception", diagnosticError);
    return rejected("unusable", "crash-record", "json");
  }
}

/** An OS report is diagnosis only, never an admission or retirement witness. */
export function darwinStartupCrash(text, binding) {
  const parsed = startupReport(text);
  const observed = parsed.report ? startupCrash(parsed, binding) : null;
  return observed?.namespace ? observed : null;
}

function startupCrash({ report, launchTime, captureTime }, binding) {
  try {
    const { pid, image, identity, imageUUID, startedAt, endedAt } = binding;
    if (
      typeof image !== "string" ||
      !path.posix.isAbsolute(image) ||
      !UUID.test(imageUUID ?? "") ||
      !Number.isSafeInteger(pid) ||
      pid <= 0 ||
      !Number.isSafeInteger(startedAt) ||
      !Number.isSafeInteger(endedAt) ||
      startedAt > endedAt
    )
      return rejected("unmatched", "binding-rejection", "input");
    const birth = normalizeDarwinIdentity(identity);
    let reason;
    if (report.pid !== pid || birth.pid !== pid) reason = "pid";
    else if (report.procPath !== image) reason = "image";
    else if (
      launchTime !==
      BigInt(birth.startSeconds) * 1000000n + BigInt(birth.startMicroseconds)
    )
      reason = "birth";
    else if (
      !report.usedImages.some(
        (value) =>
          value.path === image && value.uuid?.toLowerCase() === imageUUID,
      )
    )
      reason = "uuid";
    else if (!inWindow(captureTime, startedAt, endedAt)) reason = "window";
    else if (report.exception.signal !== "SIGABRT") reason = "signal";
    if (reason)
      return {
        ...rejected("unmatched", "binding-rejection", reason),
        ...(reason === "image"
          ? { imageFacts: rejectedImageFacts(report.procPath, image) }
          : {}),
      };
    const { namespace, code } = report.termination ?? {};
    if (
      !NAMESPACES.has(namespace) ||
      !Number.isSafeInteger(code) ||
      code < 0 ||
      code > 65535
    )
      return rejected("unmatched", "binding-rejection", "termination");
    const thread =
      Number.isSafeInteger(report.faultingThread) && report.faultingThread >= 0
        ? report.threads?.[report.faultingThread]
        : null;
    const symbols = new Set(
      (thread?.frames ?? []).map((frame) => frame.symbol),
    );
    const frame =
      Object.entries(FRAMES).find(([symbol]) => symbols.has(symbol))?.[1] ??
      null;
    return Object.freeze({ namespace, code, frame });
  } catch (diagnosticError) {
    nativeException("darwin/startup-crash.js:exception", diagnosticError);
    return rejected("unmatched", "binding-rejection", "input");
  }
}

export function darwinStartupCrashDetail(value) {
  if (
    value &&
    (Object.keys(value).length === 1 || rejectionDetail(value)) &&
    OBSERVATIONS.has(value.status)
  )
    return `; crash-read=${value.status}${rejectionDetail(value)}`;
  if (
    !value ||
    ![3, 4].includes(Object.keys(value).length) ||
    Object.keys(value).some(
      (key) =>
        !["namespace", "code", "frame", "observationFailure"].includes(key),
    ) ||
    (Object.hasOwn(value, "observationFailure") &&
      !["unavailable", "read-failed", "unusable", "watch-failed"].includes(
        value.observationFailure,
      )) ||
    !NAMESPACES.has(value.namespace) ||
    !Number.isSafeInteger(value.code) ||
    value.code < 0 ||
    value.code > 65535 ||
    ![null, ...Object.values(FRAMES)].includes(value.frame)
  )
    return "";
  return `; crash=${value.namespace}:${value.code}${value.frame ? `:${value.frame}` : ""}${value.observationFailure ? `; crash-read=${value.observationFailure}` : ""}`;
}

/** Read only matching CI fixture crash files; never persist their private contents. */
export async function readDarwinStartupCrash(
  binding,
  {
    isMatchingCI = matchingStartupCI(),
    read = readFile,
    list = readdir,
    openReport = open,
    observe = watch,
    now = Date.now,
    schedule = setTimeout,
    cancel = clearTimeout,
  } = {},
) {
  if (!isMatchingCI) return { status: "unavailable" };
  const images = startupImages(binding);
  if (images.length === 0)
    return rejected("unusable", "binding-rejection", "input");
  try {
    for (const image of images) {
      const bytes = await read(image.image);
      if (digest(bytes) !== image.sha256) return { status: "image-changed" };
      try {
        image.imageUUID = darwinStartupImageUUID(bytes);
      } catch (diagnosticError) {
        nativeException("darwin/startup-crash.js:exception", diagnosticError);
        return { status: "unusable" };
      }
      if (!image.imageUUID) return { status: "unusable" };
    }
  } catch (diagnosticError) {
    nativeException("darwin/startup-crash.js:exception", diagnosticError);
    return { status: "read-failed" };
  }
  const reportName = new RegExp(
    `^(?:${images.map(({ image }) => path.basename(image)).join("|")})[_-][^/]+\\.ips$`,
    "u",
  );
  const directories = [
    path.join(homedir(), "Library/Logs/DiagnosticReports"),
    "/Library/Logs/DiagnosticReports",
  ];
  // Listen for publication, keeping failed inspection distinct from absence.
  const watchers = new Set(),
    failures = new Set();
  let wake,
    timer,
    diagnosis,
    recordFailure,
    bindingFailure,
    isExpired = false,
    hasDirectory = false,
    hasInspected = false;
  const closeWatcher = (watcher) => {
    if (!watchers.delete(watcher)) return;
    try {
      watcher.close();
    } catch (diagnosticError) {
      nativeException("darwin/startup-crash.js:exception", diagnosticError);
      failures.add("watch-failed");
    }
  };
  try {
    timer = schedule(() => {
      isExpired = true;
      wake?.();
    }, 8000);
    for (const directory of directories) {
      try {
        const watcher = observe(directory, { persistent: false }, (_, name) => {
          if (typeof name === "string" && reportName.test(name)) wake?.();
        });
        watchers.add(watcher);
        watcher.on("error", () => {
          failures.add("watch-failed");
          closeWatcher(watcher);
          wake?.();
        });
      } catch (error) {
        nativeException("darwin/startup-crash.js:exception", error);
        failures.add(error?.code === "ENOENT" ? "unavailable" : "watch-failed");
      }
    }
    const window = {
      ...binding,
      endedAt: Math.max(binding.endedAt, now() + 8000),
    };
    inspection: do {
      const changed = new Promise((resolve) => {
        wake = resolve;
      });
      const candidates = [];
      for (const directory of directories) {
        let entries;
        try {
          entries = await list(directory);
          hasDirectory = true;
        } catch (error) {
          nativeException("darwin/startup-crash.js:exception", error);
          failures.add(
            error?.code === "ENOENT" ? "unavailable" : "read-failed",
          );
          continue;
        }
        candidates.push(
          ...entries
            .filter((name) => reportName.test(name))
            .sort()
            .slice(-32)
            .map((name) => path.join(directory, name)),
        );
      }
      for (const candidate of candidates) {
        let file;
        try {
          file = await openReport(
            candidate,
            constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
          );
          const before = await file.stat();
          if (
            !before.isFile() ||
            !Number.isSafeInteger(before.size) ||
            before.size < 0 ||
            before.size > LIMIT
          ) {
            failures.add("unusable");
            continue;
          }
          const bytes = Buffer.alloc(before.size);
          const { bytesRead } = await file.read(bytes, 0, bytes.length, 0);
          nativeDiagnostic("darwin-crash-report", {
            stdout: bytes.subarray(0, bytesRead),
            partial: bytesRead !== bytes.length,
          });
          if (bytesRead !== bytes.length) {
            failures.add("unusable");
            continue;
          }
          const after = await file.stat();
          if (
            before.size !== after.size ||
            before.mtimeMs !== after.mtimeMs ||
            !after.isFile()
          ) {
            failures.add("unusable");
            continue;
          }
          const parsed = startupReport(bytes);
          if (!parsed.report) {
            failures.add("unusable");
            recordFailure ??= parsed;
            continue;
          }
          hasInspected = true;
          const observed = images.map((image) =>
            startupCrash(parsed, {
              ...image,
              endedAt: window.endedAt,
            }),
          );
          const crash = observed.find((value) => value.namespace);
          if (crash) {
            diagnosis = crash;
            break inspection;
          }
          const failed =
            observed[
              images.findIndex(
                (image) => image.image === parsed.report.procPath,
              )
            ] ?? observed[0];
          bindingFailure ??= {
            ...failed,
            ...(images.length === 2
              ? {
                  imageChecks: observed.map((value, index) => ({
                    image: path.basename(images[index].image),
                    reason: value.reason,
                    ...(value.imageFacts
                      ? { imageFacts: value.imageFacts }
                      : {}),
                  })),
                }
              : {}),
          };
        } catch (diagnosticError) {
          nativeException("darwin/startup-crash.js:exception", diagnosticError);
          failures.add("read-failed");
        } finally {
          try {
            await file?.close();
          } catch (diagnosticError) {
            nativeException(
              "darwin/startup-crash.js:exception",
              diagnosticError,
            );
            failures.add("read-failed");
          }
        }
      }
      if (isExpired || !watchers.size) break;
      await changed;
    } while (!isExpired);
  } catch (diagnosticError) {
    nativeException("darwin/startup-crash.js:exception", diagnosticError);
    failures.add("read-failed");
  } finally {
    try {
      if (timer !== undefined) cancel(timer);
    } catch (diagnosticError) {
      nativeException("darwin/startup-crash.js:exception", diagnosticError);
      failures.add("watch-failed");
    }
    for (const watcher of watchers) closeWatcher(watcher);
  }
  try {
    for (const image of images)
      if (digest(await read(image.image)) !== image.sha256)
        return { status: "image-changed" };
  } catch (diagnosticError) {
    nativeException("darwin/startup-crash.js:exception", diagnosticError);
    return { status: "read-failed" };
  }
  const observationFailure = [
    "read-failed",
    "unusable",
    "watch-failed",
    "unavailable",
  ].find((status) => failures.has(status));
  return diagnosis
    ? { ...diagnosis, ...(observationFailure ? { observationFailure } : {}) }
    : (observationFailure === "unusable" && recordFailure) ||
        (!observationFailure && bindingFailure) || {
          status:
            observationFailure ??
            (hasInspected
              ? "unmatched"
              : hasDirectory
                ? "empty"
                : "unavailable"),
        };
}
