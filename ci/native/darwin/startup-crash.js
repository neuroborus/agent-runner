import { execFile } from "node:child_process";
import { constants, watch } from "node:fs";
import { open, readdir, readFile } from "node:fs/promises";
import { homedir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { digest } from "./protocol.js";

const LIMIT = 2 * 1024 * 1024;
const execute = promisify(execFile);
const DENIALS = new Set([
  "file-read-data",
  "file-read-metadata",
  "file-map-executable",
  "mach-lookup",
  "syscall-vnguard",
  "syscall-sandbox",
]);

/** Related kernel denials are diagnosis, not proof of the abort's cause. */
export function darwinStartupDenial(text, { pid, startedAt, endedAt }) {
  if (
    typeof text !== "string" ||
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
    const events = text
      .split("\n")
      .filter(Boolean)
      .map((line) => JSON.parse(line));
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
        /^Sandbox: argv-fixture\(([1-9][0-9]*)\) deny\([1-9][0-9]*\) (file-read-data|file-read-metadata|file-map-executable|mach-lookup|system-mac-syscall)(?: (.*))?$/u.exec(
          event.eventMessage ?? "",
        );
      if (!match || Number(match[1]) !== pid) continue;
      if (match[2] !== "system-mac-syscall") return match[2];
      if (match[3] === "vnguard") return "syscall-vnguard";
      if (match[3] === "Sandbox" || /^Sandbox [0-9]+$/u.test(match[3] ?? ""))
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
    ["empty", "unmatched", "command-failed", "image-changed"].includes(
      value.status,
    )
  ) {
    const exit =
      Number.isInteger(value.exitCode) &&
      value.exitCode >= 0 &&
      value.exitCode <= 255
        ? `:${value.exitCode}`
        : "";
    return `; log-read=${value.status}${exit}`;
  }
  return "";
}

export async function readDarwinStartupDenial(binding) {
  if (
    process.platform !== "darwin" ||
    process.arch !== "x64" ||
    process.env.CI !== "true" ||
    process.env.GITHUB_ACTIONS !== "true" ||
    process.env.RUNNER_ENVIRONMENT !== "github-hosted" ||
    process.env.RUNNER_OS !== "macOS"
  )
    return null;
  try {
    if (
      !Number.isSafeInteger(binding.pid) ||
      binding.pid <= 0 ||
      digest(await readFile(binding.image)) !== binding.sha256
    )
      return null;
    const { stdout } = await execute(
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
        `(((processID == 0) AND (senderImagePath CONTAINS "/Sandbox")) OR (subsystem == "com.apple.sandbox.reporting")) AND (eventMessage CONTAINS "argv-fixture(${binding.pid})")`,
      ],
      {
        env: { PATH: "/usr/bin:/bin", LANG: "C" },
        timeout: 12000,
        maxBuffer: 65536,
        encoding: "utf8",
      },
    );
    if (digest(await readFile(binding.image)) !== binding.sha256)
      return { status: "image-changed" };
    return (
      darwinStartupDenial(stdout, binding) ?? {
        status: stdout.trim() === "" ? "empty" : "unmatched",
      }
    );
  } catch (error) {
    /* A missing log is not a denial or an admission witness. */
    return {
      status: "command-failed",
      exitCode: Number.isInteger(error.code) ? error.code : null,
    };
  }
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

/** An OS report is diagnosis only, never an admission or retirement witness. */
export function darwinStartupCrash(text, { pid, image, startedAt, endedAt }) {
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
      !Number.isFinite(startedAt) ||
      !Number.isFinite(endedAt) ||
      startedAt > endedAt
    )
      return null;
    // Modern .ips files contain a one-line metadata object followed by the report.
    const newline = text.indexOf("\n");
    JSON.parse(text.slice(0, newline));
    const report = JSON.parse(text.slice(newline + 1));
    const time = Date.parse(report.captureTime);
    if (
      !Number.isSafeInteger(pid) ||
      pid <= 0 ||
      report.pid !== pid ||
      report.procPath !== image ||
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
    !value ||
    Object.keys(value).length !== 3 ||
    !NAMESPACES.has(value.namespace) ||
    !Number.isSafeInteger(value.code) ||
    value.code < 0 ||
    value.code > 65535 ||
    ![null, ...Object.values(FRAMES)].includes(value.frame)
  )
    return "";
  return `; crash=${value.namespace}:${value.code}${value.frame ? `:${value.frame}` : ""}`;
}

/** Read only matching CI fixture crash files; never persist their private contents. */
export async function readDarwinStartupCrash(binding) {
  if (
    process.platform !== "darwin" ||
    process.arch !== "x64" ||
    process.env.CI !== "true" ||
    process.env.GITHUB_ACTIONS !== "true" ||
    process.env.RUNNER_ENVIRONMENT !== "github-hosted" ||
    process.env.RUNNER_OS !== "macOS"
  )
    return null;
  try {
    if (digest(await readFile(binding.image)) !== binding.sha256) return null;
    const directories = [
      path.join(homedir(), "Library/Logs/DiagnosticReports"),
      "/Library/Logs/DiagnosticReports",
    ];
    // ReportCrash publishes asynchronously after process exit. Listen for actual
    // filesystem events, not sleeps or admission retries; absent reports stay null.
    const watchers = [];
    let wake,
      expired = false;
    const timer = setTimeout(() => {
      expired = true;
      wake?.();
    }, 8000);
    try {
      for (const directory of directories) {
        try {
          const watcher = watch(directory, { persistent: false }, (_, name) => {
            if (
              typeof name === "string" &&
              /^argv-fixture[_-][^/]+\.ips$/u.test(name)
            )
              wake?.();
          });
          watcher.on("error", () => watcher.close());
          watchers.push(watcher);
        } catch {
          /* An absent fixed OS directory supplies no diagnosis. */
        }
      }
      const window = {
        ...binding,
        endedAt: Math.max(binding.endedAt, Date.now() + 8000),
      };
      do {
        const changed = new Promise((resolve) => {
          wake = resolve;
        });
        for (const directory of directories) {
          const names = (await readdir(directory).catch(() => []))
            .filter((name) => /^argv-fixture[_-][^/]+\.ips$/u.test(name))
            .sort()
            .slice(-32);
          for (const name of names) {
            let file;
            try {
              file = await open(
                path.join(directory, name),
                constants.O_RDONLY |
                  constants.O_NOFOLLOW |
                  constants.O_NONBLOCK,
              );
              const before = await file.stat();
              if (!before.isFile() || before.size > LIMIT) continue;
              const bytes = Buffer.alloc(before.size);
              const { bytesRead } = await file.read(bytes, 0, bytes.length, 0);
              if (bytesRead !== bytes.length) continue;
              const text = new TextDecoder("utf-8", { fatal: true }).decode(
                bytes,
              );
              const after = await file.stat();
              if (
                before.size !== after.size ||
                before.mtimeMs !== after.mtimeMs
              )
                continue;
              const crash = darwinStartupCrash(text, window);
              if (
                crash &&
                digest(await readFile(binding.image)) === binding.sha256
              )
                return crash;
            } catch {
              // Missing, changing or malformed reports cannot replace the first failure.
            } finally {
              await file?.close();
            }
          }
        }
        if (expired || !watchers.length) break;
        await changed;
      } while (!expired);
    } finally {
      clearTimeout(timer);
      for (const watcher of watchers) watcher.close();
    }
  } catch {
    // Report generation is asynchronous and may be unavailable on the worker.
  }
  return null;
}
