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
  const close = () => {
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
    } catch {
      close();
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
  { schedule = setTimeout, cancel = clearTimeout } = {},
) {
  let buffer = Buffer.alloc(0),
    pending,
    failure,
    finished = false,
    writes = 0,
    timer,
    rejectFault;
  const queue = [],
    fault = new Promise((_, reject) => {
      rejectFault = reject;
    });
  fault.catch(() => {});
  const wait = (value) => Promise.race([value, fault]);
  const fail = () => {
    if (failure) return;
    failure = new Error("Windows custody transport unavailable");
    cancel(timer);
    child.stdin.destroy();
    pending?.reject(failure);
    pending = null;
    rejectFault(failure);
  };
  timer = schedule(fail, WINDOWS_CUSTODY_DEADLINE_MS);
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
  child.stderr?.on("error", fail);
  child.stdout.on("data", (chunk) => {
    try {
      requireWindows(
        !failure && !finished && buffer.length + chunk.length <= 262144,
      );
      buffer = Buffer.concat([buffer, chunk]);
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
    } catch {
      fail();
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
      requireWindows(!pending && !finished);
      return new Promise((resolve, reject) => {
        pending = { resolve, reject };
      });
    },
    send(value) {
      requireWindows(
        !failure &&
          !finished &&
          typeof value === "string" &&
          Buffer.byteLength(value) <= 262144,
      );
      writes++;
      return wait(
        new Promise((resolve, reject) => {
          child.stdin.write(value, (error) => {
            writes--;
            if (error) {
              fail();
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
