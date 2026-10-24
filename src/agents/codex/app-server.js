import { TextDecoder } from "node:util";

const MAX_PROTOCOL_LINE_BYTES = 16 * 1024 * 1024;
const MAX_CAPTURE_BYTES = 64 * 1024 * 1024;
const MAX_NOTIFICATIONS = 128;
const MAX_NOTIFICATION_BYTES = 16 * 1024 * 1024;
const RETAINED_NOTIFICATIONS = new Set(["model/rerouted", "turn/completed"]);

function isRecord(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

export function createCodexAppServerClient(
  child,
  AdapterError,
  signal,
  classifyRequestError,
  progress,
) {
  if (
    child === null ||
    typeof child !== "object" ||
    child.stdin === undefined ||
    child.stdout === undefined ||
    child.stderr === undefined
  ) {
    throw new AdapterError("Codex app-server process is invalid.", {
      code: "ERR_CODEX_PROCESS_FAILED",
    });
  }
  let nextId = 0;
  let closedError;
  let closing = false;
  let exited = false;
  const pending = new Map();
  const notifications = [];
  let notificationBytes = 0;
  let capturedBytes = 0;
  let frameBytes = 0;
  let frameBuffer = Buffer.alloc(0);
  const waiters = [];
  let resolveClosed;
  const closed = new Promise((resolvePromise) => {
    resolveClosed = resolvePromise;
  });

  function write(message) {
    if (closedError !== undefined) {
      throw closedError;
    }
    child.stdin.write(`${JSON.stringify(message)}\n`);
  }

  function rejectAll(error) {
    if (closedError === undefined) {
      closedError = error;
    }
    for (const { reject } of pending.values()) {
      reject(closedError);
    }
    pending.clear();
    frameBuffer = Buffer.alloc(0);
    frameBytes = 0;
    if (closedError?.code === "ERR_CODEX_PROTOCOL") {
      notifications.length = 0;
      notificationBytes = 0;
    }
    for (const waiter of waiters.splice(0)) {
      waiter.reject(closedError);
    }
  }

  function rejectProtocol(diagnosticClass) {
    rejectAll(
      new AdapterError("Codex protocol was rejected.", {
        code: "ERR_CODEX_PROTOCOL",
        diagnosticClass,
      }),
    );
    child.kill();
  }

  const abort = () => {
    rejectAll(signal.reason ?? new Error("Execution stopped."));
    child.kill();
  };
  signal?.addEventListener("abort", abort, { once: true });
  if (signal?.aborted) abort();

  function dispatchNotification(message, bytes) {
    try {
      progress?.notification(message);
    } catch {
      rejectAll(
        new AdapterError("Codex progress notification is invalid.", {
          code: "ERR_CODEX_PROTOCOL",
          diagnosticClass: "protocol_progress",
          method: "progress",
        }),
      );
      child.kill();
      return;
    }
    const waiterIndex = waiters.findIndex(
      (waiter) =>
        waiter.method === message.method && waiter.predicate(message.params),
    );
    if (waiterIndex !== -1) {
      waiters.splice(waiterIndex, 1)[0].resolve(message.params);
    } else if (RETAINED_NOTIFICATIONS.has(message.method)) {
      if (
        notifications.length >= MAX_NOTIFICATIONS ||
        notificationBytes + bytes > MAX_NOTIFICATION_BYTES
      ) {
        rejectProtocol("protocol_notification_limit");
        return;
      }
      notifications.push({ message, bytes });
      notificationBytes += bytes;
    }
  }

  function handleLine(buffer) {
    let message;
    try {
      message = JSON.parse(
        new TextDecoder("utf-8", { fatal: true }).decode(buffer),
      );
    } catch {
      rejectProtocol("protocol_framing");
      return;
    }
    if (
      !isRecord(message) ||
      (message.jsonrpc !== undefined && message.jsonrpc !== "2.0") ||
      (message.method !== undefined &&
        (typeof message.method !== "string" ||
          message.method.length === 0 ||
          message.method.length > 512)) ||
      (message.id !== undefined &&
        !Number.isSafeInteger(message.id) &&
        !(
          typeof message.id === "string" &&
          message.id.length > 0 &&
          message.id.length <= 512
        ))
    ) {
      rejectProtocol("protocol_envelope");
      return;
    }
    if (message.id !== undefined && typeof message.method === "string") {
      if (message.result !== undefined || message.error !== undefined) {
        rejectProtocol("protocol_envelope");
        return;
      }
      write({
        id: message.id,
        error: {
          code: -32601,
          message: "Agent Runner does not accept server-initiated requests.",
        },
      });
      return;
    }
    if (message.id !== undefined) {
      if (
        Object.hasOwn(message, "result") === Object.hasOwn(message, "error") ||
        (message.error !== undefined &&
          (!isRecord(message.error) ||
            !Number.isSafeInteger(message.error.code) ||
            typeof message.error.message !== "string"))
      ) {
        rejectProtocol("protocol_envelope");
        return;
      }
      const operation = pending.get(message.id);
      if (operation === undefined) {
        return;
      }
      pending.delete(message.id);
      if (message.error !== undefined) {
        operation.reject(
          classifyRequestError?.(message.error, operation.method) ??
            new AdapterError("Codex app-server request failed.", {
              code: "ERR_CODEX_RPC",
              method: operation.method,
            }),
        );
      } else if (message.result !== undefined) {
        try {
          progress?.response(operation.method, message.result);
          operation.resolve(message.result);
        } catch {
          operation.reject(
            new AdapterError("Codex progress response is invalid.", {
              code: "ERR_CODEX_PROTOCOL",
              diagnosticClass: "protocol_progress",
              method: "progress",
            }),
          );
        }
      } else {
        operation.reject(
          new AdapterError("Codex response is missing its result.", {
            code: "ERR_CODEX_PROTOCOL",
            diagnosticClass: "protocol_envelope",
            method: operation.method,
          }),
        );
      }
      return;
    }
    if (
      typeof message.method !== "string" ||
      message.method.length === 0 ||
      message.result !== undefined ||
      message.error !== undefined ||
      (RETAINED_NOTIFICATIONS.has(message.method) && !isRecord(message.params))
    ) {
      rejectProtocol("protocol_envelope");
      return;
    }
    dispatchNotification(message, buffer.length);
  }

  function capture(chunk) {
    if (closing || closedError !== undefined) return false;
    capturedBytes += chunk.length;
    if (capturedBytes > MAX_CAPTURE_BYTES) {
      rejectProtocol("protocol_capture_limit");
      return false;
    }
    return true;
  }

  function handleChunk(chunk) {
    if (!capture(chunk)) return;
    let start = 0;
    while (start < chunk.length && closedError === undefined) {
      const newline = chunk.indexOf(10, start);
      const end = newline === -1 ? chunk.length : newline;
      const fragment = chunk.subarray(start, end);
      const size = frameBytes + fragment.length;
      const lastByte =
        fragment.length > 0 ? fragment.at(-1) : frameBuffer[frameBytes - 1];
      // Permit one pending CR delimiter, including when CR and LF are split.
      if (
        size > MAX_PROTOCOL_LINE_BYTES &&
        !(size === MAX_PROTOCOL_LINE_BYTES + 1 && lastByte === 13)
      ) {
        rejectProtocol("protocol_frame_limit");
        return;
      }
      if (size > frameBuffer.length) {
        const expanded = Buffer.allocUnsafe(
          Math.min(
            MAX_PROTOCOL_LINE_BYTES + 1,
            Math.max(size, 4096, frameBuffer.length * 2),
          ),
        );
        frameBuffer.copy(expanded, 0, 0, frameBytes);
        frameBuffer = expanded;
      }
      fragment.copy(frameBuffer, frameBytes);
      frameBytes = size;
      if (newline === -1) return;
      const frame = frameBuffer.subarray(0, frameBytes);
      frameBytes = 0;
      handleLine(frame.at(-1) === 13 ? frame.subarray(0, -1) : frame);
      start = newline + 1;
    }
  }

  function handleOutputError(cause) {
    if (!closing) {
      rejectAll(
        new AdapterError("Cannot read from Codex app-server.", {
          cause,
          code: "ERR_CODEX_PROCESS_EXITED",
        }),
      );
    }
  }

  child.stdout.on("data", handleChunk);
  child.stdout.on("end", () => {
    if (!closing && closedError === undefined && frameBytes > 0) {
      const frame = frameBuffer.subarray(0, frameBytes);
      frameBytes = 0;
      handleLine(frame.at(-1) === 13 ? frame.subarray(0, -1) : frame);
    }
  });
  child.stdout.on("error", handleOutputError);
  child.stderr.on("error", () => {});
  child.stderr.on("data", capture);
  child.stdin.on("error", (cause) => {
    if (!closing) {
      rejectAll(
        new AdapterError("Cannot write to Codex app-server.", {
          cause,
          code: "ERR_CODEX_PROCESS_EXITED",
        }),
      );
    }
  });
  child.once("error", (cause) => {
    rejectAll(
      new AdapterError("Cannot start Codex app-server.", {
        cause,
        code: "ERR_CODEX_PROCESS_FAILED",
      }),
    );
  });
  child.once("close", () => {
    signal?.removeEventListener("abort", abort);
    exited = true;
    if (!closing) {
      rejectAll(
        new AdapterError("Codex app-server exited unexpectedly.", {
          code: "ERR_CODEX_PROCESS_EXITED",
        }),
      );
    }
    resolveClosed();
  });

  async function request(method, params) {
    try {
      progress?.begin(method, params);
    } catch {
      throw new AdapterError("Codex progress request is invalid.", {
        code: "ERR_CODEX_PROTOCOL",
        diagnosticClass: "protocol_progress",
      });
    }
    const id = nextId;
    nextId += 1;
    return new Promise((resolvePromise, rejectPromise) => {
      pending.set(id, {
        method,
        reject: rejectPromise,
        resolve: resolvePromise,
      });
      try {
        write({ id, method, params });
      } catch (cause) {
        pending.delete(id);
        rejectPromise(cause);
      }
    });
  }

  function notify(method, params) {
    write({ method, params });
  }

  async function waitForNotification(method, predicate) {
    assertProtocol();
    const index = notifications.findIndex(
      ({ message }) => message.method === method && predicate(message.params),
    );
    if (index !== -1) {
      const retained = notifications.splice(index, 1)[0];
      notificationBytes -= retained.bytes;
      return retained.message.params;
    }
    if (closedError !== undefined) throw closedError;
    return new Promise((resolvePromise, rejectPromise) => {
      waiters.push({
        method,
        predicate,
        reject: rejectPromise,
        resolve: resolvePromise,
      });
    });
  }

  function receivedNotification(method) {
    return notifications.some(({ message }) => message.method === method);
  }

  function assertProtocol() {
    if (closedError?.code === "ERR_CODEX_PROTOCOL") throw closedError;
  }

  function waitForExit(timeout) {
    if (exited) {
      return Promise.resolve(true);
    }
    return new Promise((resolvePromise) => {
      const timer = setTimeout(() => resolvePromise(false), timeout);
      closed.then(() => {
        clearTimeout(timer);
        resolvePromise(true);
      });
    });
  }

  async function close({ retainProcess = false } = {}) {
    if (closing) {
      return closed;
    }
    closing = true;
    frameBuffer = Buffer.alloc(0);
    frameBytes = 0;
    notifications.length = 0;
    notificationBytes = 0;
    let streamError;
    try {
      child.stdin.end();
    } catch (cause) {
      streamError = new AdapterError("Cannot close Codex app-server input.", {
        cause,
        code: "ERR_CODEX_PROCESS_EXITED",
      });
    }
    if (retainProcess) {
      signal?.removeEventListener("abort", abort);
      child.stdin.destroy();
      child.stdout.destroy();
      child.stderr.destroy();
      return;
    }
    if (streamError === undefined && (await waitForExit(1_000))) {
      return;
    }
    child.kill();
    if (await waitForExit(1_000)) {
      if (streamError !== undefined) {
        throw streamError;
      }
      return;
    }
    child.kill("SIGKILL");
    if (!(await waitForExit(1_000))) {
      throw new AdapterError("Codex app-server did not exit.", {
        code: "ERR_CODEX_PROCESS_EXITED",
      });
    }
    if (streamError !== undefined) {
      throw streamError;
    }
  }

  return Object.freeze({
    assertProtocol,
    close,
    notify,
    receivedNotification,
    request,
    waitForNotification,
  });
}
