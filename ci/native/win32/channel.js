import { AsyncLocalStorage } from "node:async_hooks";
import {
  nativeDiagnostic,
  nativeException,
  observeNativeProcess,
} from "../diagnostics.js";
import {
  closed,
  requireWindows,
  normalizeWindowsIdentity,
} from "./protocol.js";
import { WINDOWS_CUSTODY_DEADLINE_MS } from "./custody-protocol.js";

/** Control frames never share the payload pipe. Both native creation barriers
 * wait for protected callbacks, with one non-resetting admission deadline. */
export function windowsAdmissionChannel(
  child,
  nonce,
  onHelper,
  onSetup,
  {
    schedule = setTimeout,
    cancel = clearTimeout,
    materializedPolicy = false,
  } = {},
) {
  // stderr is the payload transport here; its reader retains consumption.
  observeNativeProcess("windows-admission-helper", child, undefined, []);
  let phase = "helper",
    failed = false,
    bytes = Buffer.alloc(0),
    total = 0,
    rejectFault,
    resolveReady;
  const fault = new Promise((_, reject) => {
    rejectFault = reject;
  });
  fault.catch(() => {});
  const readyValue = new Promise((resolve) => {
    resolveReady = resolve;
  });
  const wait = (value) => Promise.race([value, fault]);
  const ready = wait(readyValue);
  ready.catch(() => {});
  const close = (cause) => {
    if (cause !== undefined) nativeException("windows-admission", cause);
    if (failed) return;
    failed = true;
    cancel(timer);
    child.stdin.destroy();
    child.stdio?.[3]?.destroy();
    rejectFault(new Error("Windows admission unavailable"));
  };
  const timer = schedule(close, 30000);
  const acknowledge = (value) =>
    wait(
      new Promise((resolve, reject) =>
        child.stdin.write(value, (error) => {
          if (error) reject(error);
          else resolve();
        }),
      ),
    );
  const completion = wait(
    new Promise((resolve) =>
      child.once("close", (code, signal) => {
        if (phase !== "released") close();
        resolve({ code, signal, failed, phase });
      }),
    ),
  );
  completion.catch(() => {});
  child.once("error", close);
  child.stdin.on("error", close);
  child.stdout.on("error", close);
  child.stderr.on("error", close);
  child.stdio?.[3]?.on("error", close);
  child.stdio?.[4]?.on("error", close);
  child.stdout.on("data", (chunk) => {
    nativeDiagnostic("win32/channel.js", { stdout: chunk });
    try {
      requireWindows(
        !failed &&
          ["helper", "setup", "ready"].includes(phase) &&
          total + chunk.length <= 12288 &&
          bytes.length + chunk.length <= 4096,
      );
      total += chunk.length;
      bytes = Buffer.concat([bytes, chunk]);
      const end = bytes.indexOf(10);
      if (end < 0) return;
      requireWindows(end === bytes.length - 1);
      const value = JSON.parse(
        new TextDecoder("utf-8", { fatal: true }).decode(bytes),
      );
      bytes = Buffer.alloc(0);
      closed(value, ["nonce", "phase", "helper", "payload", "accountSid"]);
      requireWindows(
        value.nonce === nonce &&
          value.phase === phase &&
          normalizeWindowsIdentity(value.helper).pid === child.pid,
      );
      if (phase === "ready") {
        requireWindows(value.payload !== null && value.accountSid !== null);
        normalizeWindowsIdentity(value.payload);
        phase = "parked";
        resolveReady(value);
        return;
      }
      requireWindows(
        value.payload === null &&
          (phase === "helper"
            ? value.accountSid === null
            : value.accountSid !== null),
      );
      const callback = phase === "helper" ? onHelper : onSetup;
      const next = phase === "helper" ? "setup" : "ready",
        acknowledgement = phase === "helper" ? "P" : "C";
      phase = "verify";
      child.stdout.pause();
      Promise.resolve()
        .then(() => callback(value))
        .then(async (installed) => {
          requireWindows(!failed && !child.stdin.destroyed);
          let control = acknowledgement;
          if (materializedPolicy && acknowledgement === "C") {
            closed(installed, ["policySha256"]);
            requireWindows(
              typeof installed.policySha256 === "string" &&
                /^[a-f0-9]{64}$/u.test(installed.policySha256),
            );
            control += installed.policySha256 + "\n";
          }
          phase = next;
          await acknowledge(control);
          requireWindows(!failed);
          child.stdout.resume();
        })
        .catch(close);
    } catch (error) {
      close(error);
    }
  });
  return {
    ready,
    completion,
    wait,
    output: child.stderr,
    input: child.stdio?.[3] ?? null,
    errorOutput: child.stdio?.[4] ?? null,
    close,
    release() {
      requireWindows(!failed && phase === "parked" && !child.stdin.destroyed);
      phase = "releasing";
      return acknowledge("R").then(
        () => {
          requireWindows(!failed);
          phase = "released";
          cancel(timer);
        },
        (error) => {
          close();
          throw error;
        },
      );
    },
  };
}

/** Bridge exit only orders the next independent observation, never retirement. */
export async function waitForWindowsCustodyExit(channel, signal) {
  const exited = channel?.exited;
  if (!exited) return;
  const finish = signal ?? AbortSignal.timeout(30000);
  finish.throwIfAborted();
  const stopped = Promise.withResolvers(),
    abort = () => stopped.reject(finish.reason);
  finish.addEventListener("abort", abort, { once: true });
  if (finish.aborted) abort();
  try {
    return await Promise.race([exited, stopped.promise]);
  } finally {
    finish.removeEventListener("abort", abort);
  }
}

/** Dedicated private control transport; payload/helper output remains data. */
export function windowsCustodyChannel(
  child,
  {
    schedule = setTimeout,
    cancel = clearTimeout,
    deadlineMs = WINDOWS_CUSTODY_DEADLINE_MS,
  } = {},
) {
  let buffer = Buffer.alloc(0),
    pending,
    failure,
    originalFailure,
    diagnosticSeen = false,
    diagnosticComplete = false,
    finished = false,
    outputEnded = false,
    writes = 0,
    timer,
    rejectFault;
  const queue = [],
    fault = new Promise((_, reject) => {
      rejectFault = reject;
    });
  fault.catch(() => {});
  const wait = (value) => Promise.race([value, fault]);
  const publish = (owner, value) => {
    try {
      nativeDiagnostic(owner, value);
    } catch {
      // Raw publication cannot interrupt guard parsing or replace its error.
    }
  };
  observeNativeProcess(
    "windows-custody-helper",
    child,
    AsyncLocalStorage.bind(publish),
    ["stderr"],
  );
  const fail = (cause) => {
    if (cause !== undefined) publish("windows-custody", { exception: cause });
    if (failure) return;
    failure = new Error("Windows custody transport unavailable", { cause });
    if (originalFailure || cause?.custodyReaderFailure)
      failure.custodyReaderFailure =
        originalFailure ?? cause.custodyReaderFailure;
    cancel(timer);
    child.stdin.destroy();
    pending?.reject(failure);
    pending = null;
    rejectFault(failure);
  };
  requireWindows(
    Number.isSafeInteger(deadlineMs) &&
      deadlineMs > 0 &&
      deadlineMs <= WINDOWS_CUSTODY_DEADLINE_MS,
  );
  timer = schedule(fail, deadlineMs);
  // Fault rejection settles callers immediately; it does not mean the bridge
  // has exited. Recovery waits for that separate event before observing births.
  const exited = new Promise((resolve) => {
    child.once("error", fail);
    child.once("close", (code, signal) => {
      finished = true;
      if (
        diagnosticSeen ||
        pending ||
        writes ||
        buffer.length ||
        code !== 0 ||
        signal !== null
      )
        fail();
      resolve({ code, signal });
    });
  });
  const completion = wait(exited);
  completion.catch(() => {});
  child.stdin.on("error", fail);
  child.stdout.on("error", fail);
  child.stdout.once("end", () => {
    outputEnded = true;
    if (diagnosticSeen || pending || writes || buffer.length) fail();
  });
  child.stderr?.on("error", fail);
  child.stdout.on("data", (chunk) => {
    publish("win32/channel.js", { stdout: chunk });
    try {
      requireWindows(
        !failure && !finished && buffer.length + chunk.length <= 262144,
      );
      buffer = Buffer.concat([buffer, chunk]);
      // A failure-only GS frame carries collector bytes, never a reply. The
      // scheduled reader has authenticated stdout, but no bound stderr.
      const original = buffer.indexOf(0x1d),
        fatal = buffer.indexOf(0x1e);
      if (original >= 0 && (fatal < 0 || original < fatal)) {
        requireWindows(!diagnosticComplete);
        diagnosticSeen = true;
        const end = buffer.indexOf(10, original);
        if (fatal >= 0 && (end < 0 || fatal < end)) {
          requireWindows(fatal - original <= 65536);
          // An immediate short write may interrupt this frame. Its raw bytes
          // were published above; resynchronize only on the actual fatal frame.
          publish("windows-original-child", { partial: true, truncated: true });
          diagnosticComplete = true;
          buffer = buffer.subarray(fatal);
        } else {
          requireWindows(
            (end < 0 ? buffer.length : end + 1) - original <= 65536,
          );
          if (end < 0) return;
          const packet = buffer.subarray(original + 1, end);
          buffer = buffer.subarray(end + 1);
          diagnosticComplete = true;
          try {
            const value = JSON.parse(
              new TextDecoder("utf-8", { fatal: true }).decode(packet),
            );
            closed(value, [
              "phase",
              "sequence",
              "command",
              "source",
              "line",
              "lastError",
              "hex",
            ]);
            requireWindows(
              value.phase === "reader-diagnostic" &&
                Number.isInteger(value.sequence) &&
                value.sequence > 0 &&
                value.sequence <= 1048576 &&
                value.command === "ownership-output" &&
                typeof value.source === "string" &&
                /^[a-z][a-z0-9-]{0,63}\.(?:c|h)$/u.test(value.source) &&
                Number.isInteger(value.line) &&
                value.line > 0 &&
                value.line <= 100000 &&
                Number.isInteger(value.lastError) &&
                value.lastError >= 0 &&
                value.lastError <= 0xffffffff,
            );
            // Retain the first native error even if payload decoding or later
            // transport fails. Diagnostics cannot reset the admission timer.
            originalFailure = {
              phase: "reader-failure",
              sequence: value.sequence,
              command: value.command,
              source: value.source,
              line: value.line,
              lastError: value.lastError,
            };
            requireWindows(
              typeof value.hex === "string" &&
                /^(?:[a-f0-9]{2}){1,32256}$/u.test(value.hex),
            );
            const bytes = Buffer.from(value.hex, "hex"),
              text = bytes.toString("latin1"),
              lines = text.split("\n");
            const prefix = "native-windows-original-child: ";
            const resources = lines.filter((line) =>
              line.startsWith(prefix + "resource "),
            );
            const coverage = lines.filter((line) =>
              line.startsWith(prefix + "coverage "),
            );
            const coverageNames = [
              "request-status",
              "declared-imports",
              "loader-dependencies",
              "known-dll-objects",
              "token-privileges",
              "window-station-desktop",
              "inherited-pipes-job",
              "other-kernel-objects",
              "path-ancestors",
            ];
            const classes = coverage.map((line) =>
              /^native-windows-original-child: coverage class=([0-8]) name=([a-z-]+) state=(missing|observed|empty|unsupported|expired|truncated|failed) /u.exec(
                line,
              ),
            );
            const evidence = lines.filter((line) =>
              line.startsWith(prefix + "evidence "),
            );
            const roles = resources.map(
              (line) =>
                /^native-windows-original-child: resource role=(image|workspace|storage|case|custody|outer|policy) /u.exec(
                  line,
                )?.[1],
            );
            requireWindows(
              /^[\x20-\x7e\n]+$/u.test(text) &&
                lines.pop() === "" &&
                lines.length <= 83 &&
                lines[0]?.startsWith(
                  `${prefix}context command=ownership-output sequence=${value.sequence} source=${value.source} line=${value.line} error=${value.lastError} `,
                ) &&
                lines.at(-1)?.startsWith(prefix + "completion ") &&
                lines.filter((line) => line.startsWith(prefix + "record "))
                  .length +
                  evidence.length <=
                  64 &&
                (coverage.length === 0 || coverage.length === 9) &&
                (evidence.length === 0 || coverage.length === 9) &&
                classes.every(
                  (value) =>
                    value && coverageNames[Number(value[1])] === value[2],
                ) &&
                new Set(classes.map((value) => value?.[1])).size ===
                  classes.length &&
                coverage.every((line) =>
                  line.endsWith(" first-request=unobserved"),
                ) &&
                evidence.every((line) => {
                  const fact =
                    /^native-windows-original-child: evidence class=([12468]) scope=(snapshot|declared-requirements) original-request=unobserved /u.exec(
                      line,
                    );
                  return (
                    fact &&
                    fact[2] ===
                      (fact[1] === "1" ? "declared-requirements" : "snapshot")
                  );
                }) &&
                lines.filter((line) => line.startsWith(prefix + "token "))
                  .length <= 1 &&
                resources.length <= 7 &&
                roles.every((role) => role !== undefined) &&
                new Set(roles).size === roles.length &&
                lines
                  .slice(1, -1)
                  .every(
                    (line) =>
                      line.startsWith(prefix + "record ") ||
                      line.startsWith(prefix + "token ") ||
                      line.startsWith(prefix + "coverage ") ||
                      line.startsWith(prefix + "evidence ") ||
                      line.startsWith(prefix + "resource "),
                  ),
            );
            publish("windows-original-child", { stderr: bytes });
          } catch (error) {
            // A malformed diagnostic cannot replace a following native guard.
            // No reply may resolve work after any diagnostic frame was seen.
            publish("windows-original-child", { exception: error });
          }
        }
      }
      // A native guard can interrupt a partially emitted response. This record
      // separator is never valid JSON receipt data; diagnostics only fail work.
      const diagnostic = buffer.indexOf(0x1e);
      if (diagnostic >= 0) {
        const end = buffer.indexOf(10, diagnostic);
        const openContext = buffer
          .subarray(diagnostic + 1, end < 0 ? undefined : end)
          .includes('"open":{');
        const launcherContext = buffer
          .subarray(diagnostic + 1, end < 0 ? undefined : end)
          .includes('"launcher":{');
        const witnessContext = buffer
          .subarray(diagnostic + 1, end < 0 ? undefined : end)
          .includes('"witness":{');
        requireWindows(
          (end < 0 ? buffer.length : end + 1) - diagnostic <=
            (openContext
              ? 17408
              : launcherContext || witnessContext
                ? 9216
                : 2048),
        );
        if (end < 0) return;
        const value = JSON.parse(
          new TextDecoder("utf-8", { fatal: true }).decode(
            buffer.subarray(diagnostic + 1, end),
          ),
        );
        const fields = ["phase", "sequence", "command", "source", "line"];
        const uint32 = (n) => Number.isInteger(n) && n >= 0 && n <= 0xffffffff;
        requireWindows(
          end + 1 - diagnostic <=
            (Object.hasOwn(value, "open")
              ? 17408
              : Object.hasOwn(value, "launcher") ||
                  Object.hasOwn(value, "witness")
                ? 9216
                : 2048),
        );
        if (Object.hasOwn(value, "witness")) {
          closed(value, [...fields, "lastError", "witness"]);
          fields.push("witness");
          const witness = value.witness;
          closed(witness, [
            "operation",
            "result",
            "apiFailure",
            "wait",
            "exitAvailable",
            "exitCode",
            "accountingAvailable",
            "activeProcesses",
            "childBytes",
            "childShown",
            "childTruncated",
            "childHex",
          ]);
          const waiting = witness.operation === "WaitForSingleObject",
            exitQuery = witness.operation === "GetExitCodeProcess",
            childExit = witness.operation === "child-exit",
            accountingQuery = witness.operation === "QueryInformationJobObject",
            accountingSize = witness.operation === "accounting-size",
            completionQuery = witness.operation === "GetQueuedCompletionStatus",
            notification = witness.operation === "job-notification",
            active = witness.operation === "ActiveProcesses",
            accounted = active || completionQuery || notification;
          requireWindows(
            value.source === "custody-reader.c" &&
              ["ownership-witness", "ownership-outside-control"].includes(
                value.command,
              ) &&
              (waiting ||
                exitQuery ||
                childExit ||
                accountingQuery ||
                accountingSize ||
                completionQuery ||
                notification ||
                active) &&
              [
                witness.result,
                witness.wait,
                witness.exitCode,
                witness.activeProcesses,
              ].every(uint32) &&
              witness.apiFailure ===
                (waiting
                  ? witness.wait === 0xffffffff
                  : exitQuery || accountingQuery || completionQuery) &&
              (witness.apiFailure || value.lastError === 0) &&
              witness.exitAvailable === !(waiting || exitQuery) &&
              witness.accountingAvailable === accounted &&
              (waiting
                ? witness.wait !== 0 && witness.result === witness.wait
                : witness.wait === 0) &&
              (childExit
                ? witness.exitCode > 0 && witness.result === witness.exitCode
                : witness.exitCode === 0) &&
              (active
                ? witness.activeProcesses > 0 &&
                  witness.result === witness.activeProcesses
                : accounted
                  ? witness.activeProcesses > 0
                  : witness.activeProcesses === 0) &&
              (!(exitQuery || accountingQuery || completionQuery) ||
                witness.result === 0) &&
              Number.isInteger(witness.childBytes) &&
              witness.childBytes >= 0 &&
              witness.childBytes < 65536 &&
              witness.childShown === Math.min(witness.childBytes, 1024) &&
              witness.childTruncated ===
                witness.childBytes > witness.childShown &&
              typeof witness.childHex === "string" &&
              /^(?:[a-f0-9]{2}){0,1024}$/u.test(witness.childHex) &&
              witness.childHex.length === witness.childShown * 2,
          );
        }
        if (Object.hasOwn(value, "baseline")) {
          fields.push("baseline");
          const baseline = value.baseline;
          closed(baseline, [
            "operation",
            "index",
            "apiFailure",
            "cleanupFailed",
            "cleanupError",
          ]);
          requireWindows(
            value.source === "custody-reader.c" &&
              Object.hasOwn(value, "lastError") &&
              ![
                "open",
                "trust",
                "transfer",
                "loader",
                "retain",
                "scheduler",
                "cold",
                "launcher",
              ].some((field) => Object.hasOwn(value, field)) &&
              ["ReOpenFile", "FileIdInfo", "identity", "CloseHandle"].includes(
                baseline.operation,
              ) &&
              Number.isInteger(baseline.index) &&
              baseline.index >= 0 &&
              baseline.index < 6 &&
              baseline.apiFailure === (baseline.operation !== "identity") &&
              (baseline.apiFailure || value.lastError === 0) &&
              typeof baseline.cleanupFailed === "boolean" &&
              uint32(baseline.cleanupError) &&
              (baseline.cleanupFailed || baseline.cleanupError === 0),
          );
        }
        if (Object.hasOwn(value, "open")) {
          fields.push("open");
          const open = value.open;
          closed(open, [
            "operation",
            "pathUnits",
            "pathUtf16",
            "directory",
            "apiFailure",
            "attributes",
            "tag",
          ]);
          const apiFailure = [
            "CreateFileW",
            "GetFileInformationByHandleEx/FileAttributeTagInfo",
            "GetFinalPathNameByHandleW",
            "SetHandleInformation",
          ].includes(open.operation);
          requireWindows(
            Object.hasOwn(value, "lastError") &&
              !["trust", "transfer", "loader", "retain"].some((field) =>
                Object.hasOwn(value, field),
              ) &&
              [
                "CreateFileW",
                "GetFileInformationByHandleEx/FileAttributeTagInfo",
                "reparse-point",
                "file-kind",
                "GetFinalPathNameByHandleW",
                "final-path-size",
                "final-path-prefix",
                "final-path-equality",
                "SetHandleInformation",
              ].includes(open.operation) &&
              open.apiFailure === apiFailure &&
              typeof open.directory === "boolean" &&
              Number.isInteger(open.pathUnits) &&
              open.pathUnits > 0 &&
              open.pathUnits < 4096 &&
              typeof open.pathUtf16 === "string" &&
              /^(?:[a-f0-9]{4})+$/u.test(open.pathUtf16) &&
              open.pathUtf16.length === open.pathUnits * 4 &&
              (apiFailure
                ? open.attributes === null && open.tag === null
                : uint32(open.attributes) &&
                  (open.attributes & 0x400
                    ? uint32(open.tag)
                    : open.tag === null)),
          );
        }
        if (Object.hasOwn(value, "lastError")) {
          fields.push("lastError");
          requireWindows(
            uint32(value.lastError) && !Object.hasOwn(value, "trust"),
          );
        }
        if (Object.hasOwn(value, "launcher")) {
          fields.push("launcher");
          closed(value.launcher, ["hex", "complete"]);
          requireWindows(
            value.command.startsWith("ownership-") &&
              Object.hasOwn(value, "lastError") &&
              typeof value.launcher.complete === "boolean" &&
              typeof value.launcher.hex === "string" &&
              /^(?:[a-f0-9]{2}){1,4096}$/u.test(value.launcher.hex) &&
              !["trust", "transfer", "loader", "retain", "open", "cold"].some(
                (field) => Object.hasOwn(value, field),
              ),
          );
        }
        if (Object.hasOwn(value, "cold")) {
          fields.push("cold");
          const cold = value.cold;
          closed(cold, [
            "operation",
            "pid",
            "creationTime",
            "observedPid",
            "observedCreationTime",
            "census",
            "count",
            "found",
            "wait",
            "exitCode",
            "cleanupFailed",
            "cleanupError",
          ]);
          const birth = (text) =>
            typeof text === "string" &&
            /^(?:0|[1-9][0-9]{0,19})$/u.test(text) &&
            BigInt(text) <= 0xffffffffffffffffn;
          requireWindows(
            (value.source === "custody-reader.c" ||
              (value.source === "custody.h" &&
                cold.operation === "identity")) &&
              value.command === "verify-cold-process" &&
              Object.hasOwn(value, "lastError") &&
              ![
                "open",
                "trust",
                "transfer",
                "loader",
                "retain",
                "scheduler",
              ].some((field) => Object.hasOwn(value, field)) &&
              [
                "arguments",
                "snapshot",
                "first",
                "bound",
                "duplicate",
                "next",
                "census-close",
                "open",
                "pid",
                "times",
                "birth",
                "wait",
                "exit",
                "exit-code",
                "process-close",
                "identity",
              ].includes(cold.operation) &&
              uint32(cold.pid) &&
              cold.pid > 0 &&
              uint32(cold.observedPid) &&
              birth(cold.creationTime) &&
              birth(cold.observedCreationTime) &&
              Number.isInteger(cold.census) &&
              cold.census >= 0 &&
              cold.census <= 2 &&
              Number.isInteger(cold.count) &&
              cold.count >= 0 &&
              cold.count <= 65537 &&
              Number.isInteger(cold.found) &&
              cold.found >= 0 &&
              cold.found <= 2 &&
              [cold.wait, cold.exitCode].every(
                (number) =>
                  Number.isInteger(number) &&
                  number >= -1 &&
                  number <= 0xffffffff,
              ) &&
              typeof cold.cleanupFailed === "boolean" &&
              uint32(cold.cleanupError) &&
              (cold.cleanupFailed || cold.cleanupError === 0),
          );
        }
        if (Object.hasOwn(value, "scheduler")) {
          fields.push("scheduler");
          const scheduler = value.scheduler;
          closed(scheduler, [
            "operation",
            "hresult",
            "index",
            "attempt",
            "cleanupFailed",
            "cleanupError",
          ]);
          requireWindows(
            Object.hasOwn(value, "lastError") &&
              !["open", "trust", "transfer", "loader", "retain"].some((field) =>
                Object.hasOwn(value, field),
              ) &&
              (value.source === "custody-reader.c" ||
                (value.source === "custody.h" &&
                  scheduler.operation === null)) &&
              [
                "verify-task",
                "verify-task-instance",
                "verify-task-remove",
              ].includes(value.command) &&
              uint32(scheduler.cleanupError) &&
              typeof scheduler.cleanupFailed === "boolean" &&
              (scheduler.cleanupFailed || scheduler.cleanupError === 0) &&
              Number.isInteger(scheduler.index) &&
              scheduler.index >= 0 &&
              scheduler.index <= 4096 &&
              Number.isInteger(scheduler.attempt) &&
              scheduler.attempt >= 1 &&
              scheduler.attempt <= 3 &&
              (scheduler.operation === null
                ? scheduler.hresult === null && scheduler.cleanupFailed
                : [
                    "CoCreateInstance",
                    "ITaskService_Connect",
                    "ITaskService_GetFolder",
                    "ITaskFolder_GetTask",
                    "IRegisteredTask_get_Path",
                    "IRegisteredTask_get_Xml",
                    "IRegisteredTask_GetSecurityDescriptor",
                    "IRegisteredTask_GetInstances",
                    "ITaskService_GetRunningTasks",
                    "IRunningTaskCollection_get_Count",
                    "IRunningTaskCollection_get_Item",
                    "IRunningTask_get_Path",
                    "IRunningTask_Refresh",
                    "IRunningTask_get_InstanceGuid",
                    "IRunningTask_get_State",
                    "IRunningTask_get_EnginePID",
                    "ITaskFolder_DeleteTask",
                  ].includes(scheduler.operation) &&
                  /^0x[a-f0-9]{8}$/u.test(scheduler.hresult)),
          );
        }
        if (Object.hasOwn(value, "loader")) {
          fields.push("loader");
          const loader = value.loader;
          closed(loader, ["imageUnits", "imageHex", "importHex", "flags"]);
          requireWindows(
            Object.hasOwn(value, "lastError") &&
              !["trust", "transfer", "retain"].some((field) =>
                Object.hasOwn(value, field),
              ) &&
              [
                "prepare-experiment-loader",
                "release-import",
                "loader",
              ].includes(value.command) &&
              uint32(loader.imageUnits) &&
              loader.imageUnits > 0 &&
              loader.imageUnits < 4096 &&
              typeof loader.imageHex === "string" &&
              loader.imageHex.length === Math.min(loader.imageUnits, 128) * 4 &&
              /^[a-f0-9]+$/u.test(loader.imageHex) &&
              typeof loader.importHex === "string" &&
              loader.importHex.length <= 512 &&
              loader.importHex.length % 4 === 0 &&
              /^[a-f0-9]+$/u.test(loader.importHex) &&
              /^[A-Za-z0-9_.-]{1,124}\.dll$/iu.test(
                Buffer.from(loader.importHex, "hex").toString("utf16le"),
              ) &&
              loader.flags ===
                (value.command === "prepare-experiment-loader" ? 0x860 : 0x800),
          );
        }
        if (Object.hasOwn(value, "retain")) {
          fields.push("retain");
          const retain = value.retain;
          closed(retain, [
            "pid",
            "processAccess",
            "tokenAccess",
            "process",
            "observedPid",
            "matched",
            "tokenResult",
          ]);
          requireWindows(
            Object.hasOwn(value, "lastError") &&
              !["trust", "transfer", "loader"].some((field) =>
                Object.hasOwn(value, field),
              ) &&
              uint32(retain.pid) &&
              retain.pid > 0 &&
              uint32(retain.observedPid) &&
              retain.processAccess === 0x120410 &&
              retain.tokenAccess === 10 &&
              typeof retain.process === "boolean" &&
              (retain.process
                ? (retain.matched === 0 &&
                    retain.observedPid !== retain.pid &&
                    retain.tokenResult === -1) ||
                  (retain.matched === 1 &&
                    retain.observedPid === retain.pid &&
                    retain.tokenResult === 0)
                : retain.observedPid === 0 &&
                  retain.matched === -1 &&
                  retain.tokenResult === -1),
          );
        }
        if (Object.hasOwn(value, "transfer")) {
          fields.push("transfer");
          const transfer = value.transfer,
            transferFields = [
              "ordinal",
              "count",
              "type",
              "access",
              "attributes",
              "creator",
              "child",
            ];
          closed(transfer, transferFields);
          requireWindows(
            Object.hasOwn(value, "lastError") &&
              !Object.hasOwn(value, "trust") &&
              ["verify-transfer", "verify-compiler-policy"].includes(
                value.command,
              ) &&
              transferFields.every((field) => uint32(transfer[field])) &&
              transfer.ordinal < transfer.count &&
              // handle_inventory: 32 MiB, 16-byte header, 40-byte x64 entries.
              transfer.count <= Math.floor((33554432 - 16) / 40) &&
              transfer.type <= 0xffff &&
              transfer.creator < 128 &&
              transfer.child < 128 &&
              (value.command !== "verify-transfer" ||
                transfer.creator !== transfer.child),
          );
        }
        if (Object.hasOwn(value, "trust")) {
          fields.push("trust");
          const trust = value.trust;
          const trustFields = [
            "mode",
            "result",
            "closeResult",
            "entry",
            "identity",
            "sha256",
            "signatureSha256",
          ];
          if (Object.hasOwn(trust, "inputs")) {
            trustFields.push("inputs");
            requireWindows(
              Array.isArray(trust.inputs) &&
                trust.inputs.length === 20 &&
                trust.inputs.every(
                  (entry) =>
                    Number.isInteger(entry) &&
                    entry >= -1 &&
                    entry <= 0xffffffff,
                ) &&
                [2, 3, 4, 5, 11, 12, 13].every((index) =>
                  [0, 1].includes(trust.inputs[index]),
                ),
            );
          }
          if (Object.hasOwn(trust, "provider")) {
            trustFields.push("provider");
            // Compact failure fields mirror signature_provider_observe; even
            // complete provider data supplies no acceptance or retirement.
            const p = trust.provider;
            requireWindows(
              trust.result !== "0x00000000" &&
                Array.isArray(p) &&
                p.length === 13 &&
                p.every(
                  (n) => Number.isInteger(n) && n >= -1 && n <= 0xffffffff,
                ) &&
                [0, 1, 2, 3, 12].every((i) => [0, 1].includes(p[i])) &&
                (!p[2] || (p[0] === 1 && p[1] === 1)) &&
                (!p[3] || p[2] === 1),
            );
            if (!p[3]) {
              requireWindows(
                [4, 5, 6, 7, 9, 10, 11].every((i) => p[i] === -1) &&
                  p[8] === 0 &&
                  p[12] === 0,
              );
            } else {
              requireWindows(
                [4, 5, 6].every((i) => p[i] >= 0) &&
                  [0, 1].includes(p[7]) &&
                  p[8] >= 0 &&
                  p[8] <= Math.min(p[6], 64),
              );
              if (p[6] > 0 !== (p[7] === 1) || p[9] === -1) {
                requireWindows(
                  p[8] === 0 &&
                    p[9] === -1 &&
                    p[10] === -1 &&
                    p[11] === -1 &&
                    p[12] === 0,
                );
                requireWindows(p[6] > 0 || p[7] === 1);
              } else {
                requireWindows(
                  p[8] === Math.min(p[6], 64) &&
                    p[9] >= 0 &&
                    p[9] <= p[8] &&
                    (p[9] === 0
                      ? p[10] === -1 && p[11] === -1
                      : p[10] >= 0 &&
                        p[10] < p[8] &&
                        p[9] <= p[8] - p[10] &&
                        p[11] > 0) &&
                    p[12] === Number(p[8] === p[6]),
                );
              }
            }
          }
          closed(trust, trustFields);
          const hash = (pin) =>
            typeof pin === "string" && /^[a-f0-9]{64}$/u.test(pin);
          requireWindows(
            ["embedded", "catalog"].includes(trust.mode) &&
              typeof trust.result === "string" &&
              /^0x[a-f0-9]{8}$/u.test(trust.result) &&
              typeof trust.closeResult === "string" &&
              /^0x[a-f0-9]{8}$/u.test(trust.closeResult) &&
              (trust.result !== "0x00000000" ||
                trust.closeResult !== "0x00000000") &&
              (trust.entry === null ||
                (Number.isInteger(trust.entry) &&
                  trust.entry >= 0 &&
                  trust.entry < 128)) &&
              typeof trust.identity === "string" &&
              /^[a-f0-9]{16}:[a-f0-9]{32}$/u.test(trust.identity) &&
              (trust.entry === null
                ? trust.sha256 === null
                : hash(trust.sha256)) &&
              (trust.signatureSha256 === null || hash(trust.signatureSha256)),
          );
        }
        closed(value, fields);
        requireWindows(
          value.phase === "reader-failure" &&
            Number.isSafeInteger(value.sequence) &&
            value.sequence >= 0 &&
            value.sequence <= 1048576 &&
            typeof value.command === "string" &&
            /^[a-z][a-z0-9-]{0,63}$/u.test(value.command) &&
            typeof value.source === "string" &&
            /^[a-z][a-z0-9-]{0,63}\.(?:c|h)$/u.test(value.source) &&
            Number.isSafeInteger(value.line) &&
            value.line > 0 &&
            value.line <= 100000,
        );
        if (originalFailure) {
          requireWindows(
            ["sequence", "command", "source", "line", "lastError"].every(
              (key) => value[key] === originalFailure[key],
            ),
          );
          // Preserve the matching fatal frame's validated context.
          originalFailure = value;
        }
        fail(
          Object.assign(new Error("Native custody reader guard failed"), {
            custodyReaderFailure: value,
          }),
        );
        return;
      }
      if (diagnosticSeen) {
        requireWindows(buffer.length === 0);
        return;
      }
      let end;
      while ((end = buffer.indexOf(10)) >= 0) {
        const value = JSON.parse(
          new TextDecoder("utf-8", { fatal: true }).decode(
            buffer.subarray(0, end),
          ),
        );
        buffer = buffer.subarray(end + 1);
        if (pending) {
          pending.resolve(value);
          pending = null;
        } else {
          requireWindows(queue.length < 2);
          queue.push(value);
        }
      }
    } catch (error) {
      fail(error);
    }
  });
  return {
    pid: child.pid,
    wait,
    exited,
    get completion() {
      return completion.then((value) => {
        requireWindows(!failure && !writes && !queue.length && !buffer.length);
        return value;
      });
    },
    receive() {
      if (failure) return Promise.reject(failure);
      if (queue.length && !diagnosticSeen)
        return Promise.resolve(queue.shift());
      if (outputEnded) {
        fail();
        return Promise.reject(failure);
      }
      requireWindows(!pending && !finished);
      return new Promise((resolve, reject) => {
        pending = { resolve, reject };
      });
    },
    send(value) {
      requireWindows(
        !failure &&
          !diagnosticSeen &&
          !finished &&
          !outputEnded &&
          typeof value === "string" &&
          Buffer.byteLength(value) <= 262144,
      );
      writes++;
      return wait(
        new Promise((resolve, reject) => {
          child.stdin.write(value, (error) => {
            writes--;
            if (error) {
              fail(error);
              reject(failure);
            } else resolve();
          });
        }),
      );
    },
    close: fail,
    settle() {
      requireWindows(
        finished && !failure && !writes && !queue.length && !buffer.length,
      );
      cancel(timer);
    },
  };
}
