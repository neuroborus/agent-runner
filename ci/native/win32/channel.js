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
    await Promise.race([exited, stopped.promise]);
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
  observeNativeProcess("windows-custody-helper", child, undefined, ["stderr"]);
  let buffer = Buffer.alloc(0),
    pending,
    failure,
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
  const fail = (cause) => {
    if (cause !== undefined) nativeException("windows-custody", cause);
    if (failure) return;
    failure = new Error("Windows custody transport unavailable", { cause });
    if (cause?.custodyReaderFailure)
      failure.custodyReaderFailure = cause.custodyReaderFailure;
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
      if (pending || writes || buffer.length || code !== 0 || signal !== null)
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
    if (pending || writes || buffer.length) fail();
  });
  child.stderr?.on("error", fail);
  child.stdout.on("data", (chunk) => {
    nativeDiagnostic("win32/channel.js", { stdout: chunk });
    try {
      requireWindows(
        !failure && !finished && buffer.length + chunk.length <= 262144,
      );
      buffer = Buffer.concat([buffer, chunk]);
      // A native guard can interrupt a partially emitted response. This record
      // separator is never valid JSON receipt data; diagnostics only fail work.
      const diagnostic = buffer.indexOf(0x1e);
      if (diagnostic >= 0) {
        const end = buffer.indexOf(10, diagnostic);
        const openContext = buffer
          .subarray(diagnostic + 1, end < 0 ? undefined : end)
          .includes('"open":{');
        requireWindows(
          (end < 0 ? buffer.length : end + 1) - diagnostic <=
            (openContext ? 17408 : 2048),
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
          Object.hasOwn(value, "open") || end + 1 - diagnostic <= 2048,
        );
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
        fail(
          Object.assign(new Error("Native custody reader guard failed"), {
            custodyReaderFailure: value,
          }),
        );
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
      if (queue.length) return Promise.resolve(queue.shift());
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
