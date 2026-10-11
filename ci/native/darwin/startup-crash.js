import { execFile } from "node:child_process";
import { constants, watch } from "node:fs";
import { open, readdir, readFile } from "node:fs/promises";
import { homedir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";
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
      Number.isFinite(binding.startedAt) &&
      Number.isFinite(binding.endedAt) &&
      binding.startedAt <= binding.endedAt
    );
  } catch {
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
  if (
    typeof text !== "string" ||
    !text.isWellFormed() ||
    Buffer.byteLength(text) > 65536
  )
    return null;
  try {
    const events = text
      .split("\n")
      .filter((line) => line.trim() !== "")
      .map((line) => JSON.parse(line));
    return events.every(
      (event) =>
        event &&
        !Array.isArray(event) &&
        typeof event.timestamp === "string" &&
        Number.isFinite(Date.parse(event.timestamp)) &&
        typeof event.eventMessage === "string" &&
        Number.isSafeInteger(event.processID) &&
        event.processID >= 0 &&
        ["senderImagePath", "subsystem"].every(
          (key) => event[key] === undefined || typeof event[key] === "string",
        ),
    )
      ? events
      : null;
  } catch {
    return null;
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
    !Number.isFinite(startedAt) ||
    !Number.isFinite(endedAt) ||
    startedAt > endedAt
  )
    return null;
  try {
    const events = denialEvents(text);
    if (!events) return null;
    for (const event of events) {
      const time = Date.parse(event.timestamp);
      if (
        !Number.isFinite(time) ||
        time < startedAt ||
        time > endedAt ||
        !(
          (event.processID === 0 &&
            typeof event.senderImagePath === "string" &&
            event.senderImagePath.includes("/Sandbox")) ||
          event.subsystem === "com.apple.sandbox.reporting"
        )
      )
        continue;
      const match =
        /^Sandbox: (helper|argv-fixture)\(([1-9][0-9]*)\) deny\([1-9][0-9]*\) (file-read-data|file-read-metadata|file-map-executable|mach-lookup|system-mac-syscall)(?: (.*))?$/u.exec(
          event.eventMessage ?? "",
        );
      if (
        !match ||
        match[1] !== path.basename(image) ||
        Number(match[2]) !== pid
      )
        continue;
      if (match[3] !== "system-mac-syscall") return match[3];
      if (match[4] === "vnguard") return "syscall-vnguard";
      if (match[4] === "Sandbox" || /^Sandbox [0-9]+$/u.test(match[4] ?? ""))
        return "syscall-sandbox";
    }
  } catch {
    /* Incomplete or malformed log data cannot identify a denial. */
  }
  return null;
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
    return `; log-read=${value.status}${exit}`;
  }
  return "";
}

export async function readDarwinStartupDenial(
  binding,
  { isMatchingCI = matchingStartupCI(), read = readFile, run = execute } = {},
) {
  if (!isMatchingCI) return { status: "unavailable" };
  const images = startupImages(binding);
  if (images.length === 0) return { status: "unusable" };
  try {
    for (const image of images)
      if (digest(await read(image.image)) !== image.sha256)
        return { status: "image-changed" };
  } catch {
    return { status: "read-failed" };
  }
  let stdout;
  try {
    const names = images.map(({ image }) => path.basename(image));
    ({ stdout } = await run(
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
  } catch {
    return { status: "read-failed" };
  }
  let text;
  try {
    if (Buffer.isBuffer(stdout) && stdout.length > 65536)
      return { status: "unusable" };
    text = Buffer.isBuffer(stdout)
      ? new TextDecoder("utf-8", { fatal: true }).decode(stdout)
      : stdout;
  } catch {
    return { status: "unusable" };
  }
  const events = denialEvents(text);
  if (!events) return { status: "unusable" };
  return (
    images.map((image) => darwinStartupDenial(text, image)).find(Boolean) ?? {
      status: events.length === 0 ? "empty" : "unmatched",
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
  try {
    const newline = text.indexOf("\n");
    if (newline < 1) return null;
    const metadata = JSON.parse(text.slice(0, newline)),
      report = JSON.parse(text.slice(newline + 1));
    return record(metadata) &&
      record(report) &&
      Number.isSafeInteger(report.pid) &&
      report.pid > 0 &&
      typeof report.procPath === "string" &&
      typeof report.procLaunch === "string" &&
      Number.isFinite(Date.parse(report.procLaunch)) &&
      typeof report.captureTime === "string" &&
      Number.isFinite(Date.parse(report.captureTime)) &&
      Array.isArray(report.usedImages) &&
      report.usedImages.every(
        (image) =>
          record(image) &&
          (image.path === undefined || typeof image.path === "string") &&
          (image.uuid === undefined || typeof image.uuid === "string"),
      ) &&
      record(report.exception) &&
      typeof report.exception.signal === "string" &&
      (report.termination === undefined ||
        (record(report.termination) &&
          typeof report.termination.namespace === "string" &&
          Number.isSafeInteger(report.termination.code))) &&
      (report.faultingThread === undefined ||
        (Number.isSafeInteger(report.faultingThread) &&
          report.faultingThread >= 0)) &&
      (report.threads === undefined ||
        (Array.isArray(report.threads) &&
          report.threads.every(
            (thread) =>
              record(thread) &&
              (thread.frames === undefined ||
                (Array.isArray(thread.frames) &&
                  thread.frames.every(
                    (frame) =>
                      record(frame) &&
                      (frame.symbol === undefined ||
                        typeof frame.symbol === "string"),
                  ))),
          )))
      ? report
      : null;
  } catch {
    return null;
  }
}

/** An OS report is diagnosis only, never an admission or retirement witness. */
export function darwinStartupCrash(
  text,
  { pid, image, identity, imageUUID, startedAt, endedAt },
) {
  try {
    if (
      typeof text !== "string" ||
      Buffer.byteLength(text) > LIMIT ||
      !text.isWellFormed()
    )
      return null;
    if (
      typeof image !== "string" ||
      !path.posix.isAbsolute(image) ||
      !UUID.test(imageUUID ?? "") ||
      !Number.isFinite(startedAt) ||
      !Number.isFinite(endedAt) ||
      startedAt > endedAt
    )
      return null;
    // Modern .ips files contain a one-line metadata object followed by the report.
    const report = startupReport(text);
    if (!report) return null;
    const time = Date.parse(report.captureTime);
    const birth = normalizeDarwinIdentity(identity);
    if (
      !Number.isSafeInteger(pid) ||
      pid <= 0 ||
      report.pid !== pid ||
      report.procPath !== image ||
      birth.pid !== pid ||
      Date.parse(report.procLaunch) !==
        birth.startSeconds * 1000 +
          Math.floor(birth.startMicroseconds / 1000) ||
      !Array.isArray(report.usedImages) ||
      !report.usedImages.some(
        (value) =>
          value?.path === image &&
          typeof value.uuid === "string" &&
          value.uuid.toLowerCase() === imageUUID,
      ) ||
      !Number.isFinite(time) ||
      time < startedAt ||
      time > endedAt ||
      report.exception?.signal !== "SIGABRT"
    )
      return null;
    const { namespace, code } = report.termination ?? {};
    if (
      !NAMESPACES.has(namespace) ||
      !Number.isSafeInteger(code) ||
      code < 0 ||
      code > 65535
    )
      return null;
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
  } catch {
    return null;
  }
}

export function darwinStartupCrashDetail(value) {
  if (
    value &&
    Object.keys(value).length === 1 &&
    OBSERVATIONS.has(value.status)
  )
    return `; crash-read=${value.status}`;
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
  if (images.length === 0) return { status: "unusable" };
  try {
    for (const image of images) {
      const bytes = await read(image.image);
      if (digest(bytes) !== image.sha256) return { status: "image-changed" };
      try {
        image.imageUUID = darwinStartupImageUUID(bytes);
      } catch {
        return { status: "unusable" };
      }
      if (!image.imageUUID) return { status: "unusable" };
    }
  } catch {
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
    isExpired = false,
    hasDirectory = false,
    hasInspected = false;
  const closeWatcher = (watcher) => {
    if (!watchers.delete(watcher)) return;
    try {
      watcher.close();
    } catch {
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
          if (bytesRead !== bytes.length) {
            failures.add("unusable");
            continue;
          }
          let text;
          try {
            text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
          } catch {
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
          if (!startupReport(text)) {
            failures.add("unusable");
            continue;
          }
          hasInspected = true;
          const crash = images
            .map((image) =>
              darwinStartupCrash(text, {
                ...image,
                endedAt: window.endedAt,
              }),
            )
            .find(Boolean);
          if (crash) {
            diagnosis = crash;
            break inspection;
          }
        } catch {
          failures.add("read-failed");
        } finally {
          try {
            await file?.close();
          } catch {
            failures.add("read-failed");
          }
        }
      }
      if (isExpired || !watchers.size) break;
      await changed;
    } while (!isExpired);
  } catch {
    failures.add("read-failed");
  } finally {
    try {
      if (timer !== undefined) cancel(timer);
    } catch {
      failures.add("watch-failed");
    }
    for (const watcher of watchers) closeWatcher(watcher);
  }
  try {
    for (const image of images)
      if (digest(await read(image.image)) !== image.sha256)
        return { status: "image-changed" };
  } catch {
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
    : {
        status:
          observationFailure ??
          (hasInspected ? "unmatched" : hasDirectory ? "empty" : "unavailable"),
      };
}
