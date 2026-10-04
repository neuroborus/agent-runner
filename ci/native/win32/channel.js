import {
  closed,
  requireWindows,
  normalizeWindowsIdentity,
} from "./protocol.js";

/** Control frames never share the payload pipe. Both native creation barriers
 * wait for protected callbacks, with one non-resetting admission deadline. */
export function windowsAdmissionChannel(
  child,
  nonce,
  onHelper,
  onSetup,
  { schedule = setTimeout, cancel = clearTimeout } = {},
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
        .then(async () => {
          requireWindows(!failed && !child.stdin.destroyed);
          phase = next;
          await acknowledge(acknowledgement);
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
