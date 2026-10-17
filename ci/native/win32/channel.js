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
  const completion = wait(
    new Promise((resolve) => {
      child.once("error", fail);
      child.once("close", (code, signal) => {
        finished = true;
        if (pending || writes || buffer.length || code !== 0 || signal !== null)
          fail();
        resolve({ code, signal });
      });
    }),
  );
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
        if (end < 0) return;
        const value = JSON.parse(
          new TextDecoder("utf-8", { fatal: true }).decode(
            buffer.subarray(diagnostic + 1, end),
          ),
        );
        const fields = ["phase", "sequence", "command", "source", "line"];
        if (Object.hasOwn(value, "trust")) {
          fields.push("trust");
          const trust = value.trust;
          closed(trust, [
            "mode",
            "result",
            "closeResult",
            "entry",
            "identity",
            "sha256",
            "signatureSha256",
          ]);
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
