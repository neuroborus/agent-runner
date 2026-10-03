import { requireDarwin } from "./protocol.js";

// Only the root launcher uses this channel. Private payload stdio is separate.
export function darwinAdmissionChannel(
  child,
  onHelper,
  { schedule = setTimeout, cancel = clearTimeout } = {},
) {
  let phase = "helper",
    failed = false,
    timer,
    rejectReady;
  const close = () => {
    if (failed) return;
    failed = true;
    cancel(timer);
    child.stdin.destroy();
    rejectReady(new Error("Darwin admission unavailable"));
  };
  const fail = close;
  const completion = new Promise((resolve, reject) => {
    child.once("error", reject);
    child.once("close", (code, signal) => resolve({ code, signal }));
  });
  completion.catch(() => {});
  const ready = new Promise((resolve, reject) => {
    rejectReady = reject;
    let bytes = Buffer.alloc(0);
    timer = schedule(fail, 30000);
    child.once("error", fail);
    child.once("close", fail);
    child.stdin.on("error", fail);
    child.stdout.on("error", fail);
    child.stdout.on("data", (chunk) => {
      try {
        requireDarwin(
          !failed &&
            ["helper", "payload"].includes(phase) &&
            bytes.length + chunk.length <= 4096,
        );
        bytes = Buffer.concat([bytes, chunk]);
        const end = bytes.indexOf(10);
        if (end < 0) return;
        requireDarwin(end === bytes.length - 1);
        const value = JSON.parse(
          new TextDecoder("utf-8", { fatal: true }).decode(bytes),
        );
        bytes = Buffer.alloc(0);
        requireDarwin(
          value &&
            Object.keys(value).length === 2 &&
            Object.hasOwn(value, "payload") &&
            value.helper?.pid === child.pid,
        );
        if (phase === "helper") {
          requireDarwin(value.payload === null);
          phase = "verify-helper";
          child.stdout.pause();
          Promise.resolve()
            .then(() => onHelper(value.helper))
            .then(() => {
              requireDarwin(!failed && !child.stdin.destroyed);
              phase = "payload";
              child.stdin.write("P");
              child.stdout.resume();
            })
            .catch(fail);
        } else {
          requireDarwin(value.payload !== null);
          phase = "ready";
          cancel(timer);
          resolve(value);
        }
      } catch {
        fail();
      }
    });
  });
  return {
    ready,
    completion,
    output: child.stdio[3],
    close,
    release() {
      requireDarwin(!failed && phase === "ready" && !child.stdin.destroyed);
      phase = "released";
      child.stdin.write("R");
    },
    settle() {
      requireDarwin(!failed && phase === "released" && !child.stdin.destroyed);
      phase = "settled";
      child.stdin.end("S");
    },
  };
}
