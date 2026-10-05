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
    child.stdio[4]?.destroy();
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
    child.stdio[4]?.on("error", fail);
    child.stdio[5]?.on("error", fail);
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
    input: child.stdio[4] ?? null,
    errorOutput: child.stdio[5] ?? null,
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

/** Fixed Git uses a separate parked frame protocol. Its deadline rejects every
 * pending operation, including completion; native owners still settle identities. */
export function darwinFixedGitChannel(
  child,
  nonce,
  { schedule = setTimeout, cancel = clearTimeout } = {},
) {
  let failed = false,
    released = false,
    finished = false,
    seenReady = false,
    bytes = Buffer.alloc(0),
    total = 0,
    rejectReady,
    rejectFault;
  const fault = new Promise((_, reject) => {
    rejectFault = reject;
  });
  fault.catch(() => {});
  const fail = () => {
    if (failed) return;
    failed = true;
    child.stdin.destroy();
    const error = new Error("Unverified fixed Git executor");
    rejectReady?.(error);
    rejectFault(error);
  };
  const timer = schedule(fail, 30000);
  const wait = (value) => Promise.race([value, fault]);
  const completion = wait(
    new Promise((resolve) =>
      child.once("close", (code, signal) =>
        resolve({
          code,
          signal,
          failed: failed || !finished || bytes.length !== 0,
        }),
      ),
    ),
  );
  completion.catch(() => {});
  let resolveReady;
  const ready = new Promise((resolve, reject) => {
    resolveReady = resolve;
    rejectReady = reject;
  });
  ready.catch(() => {});
  child.once("error", fail);
  child.stdin.on("error", fail);
  child.stdout.on("error", fail);
  child.stdout.on("data", (chunk) => {
    try {
      total += chunk.length;
      requireDarwin(
        total <= 1024 && bytes.length + chunk.length <= 512 && !failed,
      );
      bytes = Buffer.concat([bytes, chunk]);
      const end = bytes.indexOf(10);
      if (end < 0) return;
      requireDarwin(end === bytes.length - 1 && !finished);
      const message = JSON.parse(
        new TextDecoder("utf-8", { fatal: true }).decode(bytes),
      );
      bytes = Buffer.alloc(0);
      requireDarwin(
        Object.keys(message).sort().join(",") === "nonce,phase,pid" &&
          message.nonce === nonce &&
          message.pid === child.pid,
      );
      if (!released) {
        requireDarwin(message.phase === "ready" && !seenReady);
        seenReady = true;
        resolveReady(message);
      } else {
        requireDarwin(message.phase === "finished");
        finished = true;
      }
    } catch {
      fail();
    }
  });
  child.once("close", () => {
    if (!finished) fail();
  });
  return {
    ready,
    completion,
    wait,
    release() {
      requireDarwin(
        !failed && seenReady && !released && !child.stdin.destroyed,
      );
      released = true;
      child.stdin.end("P");
    },
    close() {
      fail();
    },
    dispose() {
      cancel(timer);
    },
  };
}

/** Held-file transport stays private to its root helper. Native retirement
 * remains independent of channel completion and every transport fault. */
export function darwinFileChannel(
  child,
  { schedule = setTimeout, cancel = clearTimeout } = {},
) {
  let pending,
    failure,
    rejectFault,
    buffer = Buffer.alloc(0),
    total = 0;
  const fault = new Promise((_, reject) => {
    rejectFault = reject;
  });
  fault.catch(() => {});
  const wait = (value) => Promise.race([value, fault]);
  const queue = [];
  const close = () => {
    child.stdin.destroy();
  };
  const fail = () => {
    if (failure) return;
    failure = new Error("Unverified Darwin file helper");
    close();
    pending?.reject(failure);
    pending = null;
    rejectFault(failure);
  };
  const timer = schedule(fail, 30000);
  const completion = wait(
    new Promise((resolve) =>
      child.once("close", (code, signal) =>
        resolve({
          code,
          signal,
          failed: Boolean(failure),
          remainingMessages: queue.length,
          partialBytes: buffer.length,
        }),
      ),
    ),
  );
  completion.catch(() => {});
  child.once("error", fail);
  child.stdin.on("error", fail);
  child.stdout.on("error", fail);
  child.once("close", () => {
    if (pending || buffer.length) fail();
  });
  child.stdout.on("data", (chunk) => {
    try {
      total += chunk.length;
      buffer = Buffer.concat([buffer, chunk]);
      requireDarwin(total <= 262144 && buffer.length <= 8192);
      let end;
      while ((end = buffer.indexOf(10)) >= 0) {
        requireDarwin(end < 4096 && !failure);
        const message = JSON.parse(
          new TextDecoder("utf-8", { fatal: true }).decode(
            buffer.subarray(0, end),
          ),
        );
        buffer = buffer.subarray(end + 1);
        if (pending) {
          pending.resolve(message);
          pending = null;
        } else {
          requireDarwin(queue.length < 2);
          queue.push(message);
        }
      }
    } catch {
      fail();
    }
  });
  const receive = () => {
    if (failure) return Promise.reject(failure);
    if (queue.length) return Promise.resolve(queue.shift());
    requireDarwin(!pending);
    return new Promise((resolve, reject) => {
      pending = { resolve, reject };
    });
  };
  const send = (bytes) => {
    requireDarwin(
      !failure &&
        !child.stdin.destroyed &&
        typeof bytes === "string" &&
        Buffer.byteLength(bytes) <= 9000,
    );
    return new Promise((resolve, reject) =>
      child.stdin.write(bytes, (error) => (error ? reject(error) : resolve())),
    );
  };
  return {
    receive,
    send,
    close,
    completion,
    wait,
    fail,
    dispose: () => cancel(timer),
  };
}

/** Bounded private custody frames; a deadline fences work without claiming
 * native retirement. Completion also requires consumed, complete frames. */
export function darwinCustodyChannel(
  child,
  { schedule = setTimeout, cancel = clearTimeout, deadlineMs = 120000 } = {},
) {
  requireDarwin([120000, 390000].includes(deadlineMs));
  let buffer = Buffer.alloc(0),
    pending,
    failure,
    rejectFault,
    timer,
    finished = false;
  const fault = new Promise((_, reject) => {
    rejectFault = reject;
  });
  fault.catch(() => {});
  const wait = (value) => Promise.race([value, fault]);
  const queue = [];
  const fail = () => {
    if (failure) return;
    failure = new Error("Darwin custody transport unavailable");
    cancel(timer);
    child.stdin.destroy();
    pending?.reject(failure);
    pending = null;
    rejectFault(failure);
  };
  timer = schedule(fail, deadlineMs);
  const completion = wait(
    new Promise((resolve) => {
      child.once("error", fail);
      child.once("close", (code, signal) => {
        finished = true;
        cancel(timer);
        if (pending || buffer.length) fail();
        resolve({ code, signal });
      });
    }),
  );
  completion.catch(() => {});
  child.stdin.on("error", fail);
  child.stdout.on("error", fail);
  child.stdout.on("data", (chunk) => {
    try {
      requireDarwin(
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
          requireDarwin(queue.length < 2);
          queue.push(value);
        }
      }
    } catch {
      fail();
    }
  });
  return {
    pid: child.pid,
    get completion() {
      return completion.then((result) => {
        requireDarwin(!failure && !queue.length && !buffer.length);
        return result;
      });
    },
    receive() {
      if (failure) return Promise.reject(failure);
      if (queue.length) return Promise.resolve(queue.shift());
      requireDarwin(!pending && !finished);
      return new Promise((resolve, reject) => {
        pending = { resolve, reject };
      });
    },
    send(value) {
      requireDarwin(
        !failure &&
          !finished &&
          typeof value === "string" &&
          Buffer.byteLength(value) <= 262144,
      );
      return wait(
        new Promise((resolve, reject) =>
          child.stdin.write(value, (error) =>
            error
              ? reject(new Error("Darwin custody write unavailable"))
              : resolve(),
          ),
        ),
      );
    },
    close: fail,
  };
}
