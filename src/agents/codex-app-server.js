import { createInterface } from "node:readline";

const MAX_PROTOCOL_LINE_BYTES = 16 * 1024 * 1024;
const RETAINED_NOTIFICATIONS = new Set([
  "model/rerouted",
  "turn/completed",
]);

function isRecord(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

export function createCodexAppServerClient(child, AdapterError) {
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
    for (const waiter of waiters.splice(0)) {
      waiter.reject(closedError);
    }
  }

  function dispatchNotification(message) {
    const waiterIndex = waiters.findIndex(
      (waiter) =>
        waiter.method === message.method && waiter.predicate(message.params),
    );
    if (waiterIndex !== -1) {
      waiters.splice(waiterIndex, 1)[0].resolve(message.params);
    } else if (RETAINED_NOTIFICATIONS.has(message.method)) {
      notifications.push(message);
    }
  }

  function handleLine(line) {
    if (Buffer.byteLength(line) > MAX_PROTOCOL_LINE_BYTES) {
      rejectAll(
        new AdapterError("Codex protocol message is too large.", {
          code: "ERR_CODEX_PROTOCOL",
        }),
      );
      child.kill();
      return;
    }
    let message;
    try {
      message = JSON.parse(line);
    } catch (cause) {
      rejectAll(
        new AdapterError("Codex emitted invalid JSONL.", {
          cause,
          code: "ERR_CODEX_PROTOCOL",
        }),
      );
      child.kill();
      return;
    }
    if (!isRecord(message)) {
      rejectAll(
        new AdapterError("Codex emitted an invalid protocol message.", {
          code: "ERR_CODEX_PROTOCOL",
        }),
      );
      child.kill();
      return;
    }
    if (message.id !== undefined && typeof message.method === "string") {
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
      const operation = pending.get(message.id);
      if (operation === undefined) {
        return;
      }
      pending.delete(message.id);
      if (message.error !== undefined) {
        operation.reject(
          new AdapterError("Codex app-server request failed.", {
            code: "ERR_CODEX_RPC",
            method: operation.method,
          }),
        );
      } else if (message.result !== undefined) {
        operation.resolve(message.result);
      } else {
        operation.reject(
          new AdapterError("Codex response is missing its result.", {
            code: "ERR_CODEX_PROTOCOL",
            method: operation.method,
          }),
        );
      }
      return;
    }
    if (typeof message.method === "string") {
      dispatchNotification(message);
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

  const lines = createInterface({ input: child.stdout, crlfDelay: Infinity });
  // readline removes its input listener on close; keep late stream errors handled.
  child.stdout.on("error", () => {});
  lines.on("line", handleLine);
  lines.on("error", handleOutputError);
  child.stderr.on("error", () => {});
  child.stderr.resume();
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
    const index = notifications.findIndex(
      (message) =>
        message.method === method && predicate(message.params),
    );
    if (index !== -1) {
      return notifications.splice(index, 1)[0].params;
    }
    if (closedError !== undefined) {
      throw closedError;
    }
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
    return notifications.some((message) => message.method === method);
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

  async function close() {
    if (closing) {
      return closed;
    }
    closing = true;
    lines.close();
    let streamError;
    try {
      child.stdin.end();
    } catch (cause) {
      streamError = new AdapterError("Cannot close Codex app-server input.", {
        cause,
        code: "ERR_CODEX_PROCESS_EXITED",
      });
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
    close,
    notify,
    receivedNotification,
    request,
    waitForNotification,
  });
}
