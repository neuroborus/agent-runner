import { createInterface } from "node:readline";

const MAX_PROTOCOL_LINE_BYTES = 16 * 1024 * 1024;

function isRecord(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function hasDuplicateFields(source, message) {
  // The source is valid JSON. Each colon outside a string introduces a field,
  // and JSON.parse can only remove fields when it overwrites a duplicate.
  let fieldCount = 0;
  let isInString = false;
  for (const [token] of source.matchAll(/\\.|"|:/gsu)) {
    if (token === '"') isInString = !isInString;
    if (token === ":" && !isInString) fieldCount += 1;
  }
  const containers = [message];
  while (containers.length > 0) {
    const container = containers.pop();
    const values = Object.values(container);
    if (!Array.isArray(container)) fieldCount -= values.length;
    for (const value of values) {
      if (value !== null && typeof value === "object") containers.push(value);
    }
  }
  return fieldCount !== 0;
}

export function createCodexAppServerClient(
  child,
  AdapterError,
  signal,
  classifyRequestError,
  progress,
  observations,
  { trackModelReroutes = false } = {},
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
  let exitOutcome;
  let hasModelReroute = false;
  let catalogLookupActive = false;
  const pending = new Map();
  const catalogResponseIds = new Set();
  const notifications = [];
  const waiters = [];
  const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
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

  const abort = () => {
    rejectAll(signal.reason ?? new Error("Execution stopped."));
    child.kill();
  };
  signal?.addEventListener("abort", abort, { once: true });
  if (signal?.aborted) abort();

  function dispatchNotification(message) {
    try {
      observations?.notification(message);
      if (closing) return;
      progress?.notification(message);
    } catch {
      rejectAll(
        new AdapterError("Codex progress notification is invalid.", {
          code: "ERR_CODEX_PROTOCOL",
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
    } else if (message.method === "turn/completed") {
      notifications.push(message);
    }
  }

  function dispatchLine(encodedLine) {
    if (encodedLine.length > MAX_PROTOCOL_LINE_BYTES) {
      rejectAll(
        new AdapterError("Codex protocol message is too large.", {
          code: "ERR_CODEX_PROTOCOL",
        }),
      );
      child.kill();
      return;
    }
    let source;
    let message;
    try {
      source = decoder.decode(Buffer.from(encodedLine, "latin1"));
      message = JSON.parse(source);
    } catch {
      // Parser diagnostics can embed the untrusted frame.
      rejectAll(
        new AdapterError("Codex emitted invalid JSONL.", {
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
    const operation = pending.get(message.id);
    const hasMethod = typeof message.method === "string";
    const isModelReroute =
      trackModelReroutes && message.method === "model/rerouted";
    const hasResponsePayload =
      Object.hasOwn(message, "result") || Object.hasOwn(message, "error");
    const isRepeatedCatalogResponse =
      catalogResponseIds.has(message.id) && (!hasMethod || hasResponsePayload);
    const isUnmatchedCatalogResponse =
      catalogLookupActive && !hasMethod && operation === undefined;
    const invalidCatalogResponse =
      isRepeatedCatalogResponse || isUnmatchedCatalogResponse;
    if (
      (isModelReroute && Object.hasOwn(message, "id")) ||
      (hasResponsePayload && Object.hasOwn(message, "method")) ||
      invalidCatalogResponse ||
      ((trackModelReroutes || operation?.method === "model/list") &&
        hasDuplicateFields(source, message))
    ) {
      rejectAll(
        new AdapterError("Codex emitted an invalid protocol envelope.", {
          code: "ERR_CODEX_PROTOCOL",
          method: invalidCatalogResponse
            ? "model/list"
            : isModelReroute
              ? "model/rerouted"
              : operation?.method,
        }),
      );
      child.kill();
      return;
    }
    if (isModelReroute) hasModelReroute = true;
    if (message.id !== undefined && hasMethod) {
      if (closing) {
        rejectAll(
          new AdapterError("Codex emitted a request during shutdown.", {
            code: "ERR_CODEX_PROTOCOL",
          }),
        );
        child.kill();
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
      if (operation === undefined) {
        return;
      }
      pending.delete(message.id);
      if (operation.method === "model/list") catalogResponseIds.add(message.id);
      if (message.error !== undefined && message.result !== undefined) {
        operation.reject(
          new AdapterError("Codex response has conflicting results.", {
            code: "ERR_CODEX_PROTOCOL",
            method: operation.method,
          }),
        );
      } else if (message.error !== undefined) {
        operation.reject(
          classifyRequestError?.(message.error, operation.method) ??
            new AdapterError("Codex app-server request failed.", {
              code: "ERR_CODEX_RPC",
              method: operation.method,
            }),
        );
      } else if (message.result !== undefined) {
        try {
          observations?.response(operation.method, message.result);
          progress?.response(operation.method, message.result);
          operation.resolve(message.result);
        } catch {
          operation.reject(
            new AdapterError("Codex progress response is invalid.", {
              code: "ERR_CODEX_PROTOCOL",
              method: "progress",
            }),
          );
        }
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
    if (hasMethod) {
      dispatchNotification(message);
    }
  }

  function handleLine(line) {
    if (closedError !== undefined || exitOutcome !== undefined) return;
    try {
      dispatchLine(line);
    } catch {
      rejectAll(
        new AdapterError("Codex emitted an invalid protocol message.", {
          code: "ERR_CODEX_PROTOCOL",
        }),
      );
      child.kill();
    }
  }

  function needsOutputDrain() {
    return trackModelReroutes && !child.stdout.readableEnded;
  }

  function rejectOutput(cause) {
    rejectAll(
      new AdapterError("Cannot read from Codex app-server.", {
        cause,
        code: "ERR_CODEX_PROCESS_EXITED",
      }),
    );
  }

  // Split on ASCII line endings while keeping the bytes for strict decoding.
  child.stdout.setEncoding("latin1");
  const lines = createInterface({ input: child.stdout, crlfDelay: Infinity });
  // Listen on stdout because readline removes its input listener on close.
  lines.on("line", handleLine);
  lines.on("error", () => {});
  child.stdout.on("error", (cause) => {
    if (!closing || needsOutputDrain()) rejectOutput(cause);
  });
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
  child.once("close", (exitCode, exitSignal) => {
    if (closing && needsOutputDrain()) rejectOutput();
    lines.close();
    signal?.removeEventListener("abort", abort);
    exitOutcome = { type: "close", exitCode, signal: exitSignal };
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
    observations?.begin(method, params);
    progress?.begin(method, params);
    // Keep validating unmatched responses between pages and while a miss settles.
    catalogLookupActive = method === "model/list";
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
      (message) => message.method === method && predicate(message.params),
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

  function waitForExit(timeout) {
    if (exitOutcome !== undefined) {
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
    if (observations === undefined && !trackModelReroutes) lines.close();
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
      lines.close();
      signal?.removeEventListener("abort", abort);
      child.stdin.destroy();
      child.stdout.destroy();
      child.stderr.destroy();
      return;
    }
    if (streamError === undefined && (await waitForExit(1_000))) {
      if (closedError !== undefined) throw closedError;
      return;
    }
    // EOF caused by termination cannot prove that pending reroutes drained.
    if (needsOutputDrain()) rejectOutput();
    child.kill();
    if (await waitForExit(1_000)) {
      if (streamError !== undefined) {
        throw streamError;
      }
      if (closedError !== undefined) throw closedError;
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
    if (closedError !== undefined) throw closedError;
  }

  return Object.freeze({
    get usable() {
      return closedError === undefined && !closing && exitOutcome === undefined;
    },
    get exitOutcome() {
      return exitOutcome;
    },
    get hasModelReroute() {
      return hasModelReroute;
    },
    selectCompaction: (threadId, turnId) =>
      observations?.selectCompaction(threadId, turnId),
    confirmCompaction: (threadId, turnId) =>
      observations?.confirmCompaction(threadId, turnId),
    close,
    notify,
    request,
    waitForNotification,
  });
}
