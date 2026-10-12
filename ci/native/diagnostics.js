import { AsyncLocalStorage } from "node:async_hooks";
import { inspect } from "node:util";

const ordinaryCI = new AsyncLocalStorage();

/** Raw CI output is a separate sink, never a receipt or persisted evidence. */
export function createNativeDiagnosticWriter(
  write = (bytes) => process.stderr.write(bytes),
) {
  return (owner, value) => {
    const exception = value?.exception;
    const detail =
      value && Object.hasOwn(value, "exception") ? exception : value;
    const emit = (kind, bytes) => {
      write(Buffer.from(`[native-ci ${owner}] ${kind}\n`));
      write(Buffer.isBuffer(bytes) ? bytes : Buffer.from(String(bytes)));
      write(Buffer.from("\n"));
    };
    if (
      (value && Object.hasOwn(value, "exception")) ||
      detail instanceof Error ||
      detail?.message !== undefined ||
      typeof detail !== "object" ||
      detail === null
    )
      emit(
        "exception",
        inspect(detail, {
          depth: null,
          maxArrayLength: null,
          maxStringLength: null,
          customInspect: false,
        }),
      );
    const seen = new Set();
    for (
      let cause = detail;
      cause && typeof cause === "object" && !seen.has(cause);
      cause = cause.cause
    ) {
      seen.add(cause);
      for (const stream of ["stdout", "stderr"])
        if (cause[stream] !== undefined && cause[stream] !== null)
          emit(stream, cause[stream]);
      if (cause.stack !== undefined) emit("stack", cause.stack);
      const facts = Object.fromEntries(
        [
          "exitCode",
          "code",
          "signal",
          "timedOut",
          "truncated",
          "partial",
        ].flatMap((key) =>
          cause[key] === undefined ? [] : [[key, cause[key]]],
        ),
      );
      if (Object.keys(facts).length)
        emit(
          "completion/capture",
          inspect(facts, {
            depth: null,
            maxArrayLength: null,
            maxStringLength: null,
            customInspect: false,
          }),
        );
    }
  };
}

export function withNativeDiagnostics(
  action,
  diagnostics = createNativeDiagnosticWriter(),
) {
  return ordinaryCI.run(diagnostics, action);
}

export function nativeDiagnostic(owner, value) {
  ordinaryCI.getStore()?.(owner, value);
}

export function nativeException(owner, exception) {
  nativeDiagnostic(owner, { exception });
}

export function hasNativeDiagnostics() {
  return Boolean(ordinaryCI.getStore());
}

/** Observe existing streams without changing their consumers or capture limits. */
export function observeNativeProcess(
  owner,
  child,
  diagnostics = ordinaryCI.getStore(),
  streams = ["stdout", "stderr"],
) {
  if (!diagnostics) return child;
  for (const stream of streams)
    child[stream]?.on("data", (bytes) =>
      diagnostics(owner, { [stream]: bytes }),
    );
  child.on("error", (exception) => diagnostics(owner, { exception }));
  child.once("close", (exitCode, signal) =>
    diagnostics(owner, { exitCode, signal }),
  );
  return child;
}

/** execFile's existing promise exposes its child; injected runners need no child. */
export function diagnosticCommand(owner, command) {
  return (...args) => {
    if (!hasNativeDiagnostics()) return command(...args);
    const failed = (error) => {
      try {
        nativeException(owner, error);
        if (
          ["ERR_CHILD_PROCESS_STDIO_MAXBUFFER", "ENOBUFS"].includes(error?.code)
        )
          nativeDiagnostic(owner, { truncated: true, partial: true });
      } finally {
        throw error;
      }
    };
    try {
      const pending = command(...args);
      if (pending?.child) observeNativeProcess(owner, pending.child);
      const completed = (result) => {
        nativeDiagnostic(
          owner,
          pending?.child
            ? {
                exitCode: result?.exitCode ?? 0,
                signal: result?.signal ?? null,
              }
            : { ...result, exitCode: result?.exitCode ?? result?.status },
        );
        if (result?.error) {
          nativeException(owner, result.error);
          if (result.error.code === "ENOBUFS")
            nativeDiagnostic(owner, { truncated: true, partial: true });
        }
        return result;
      };
      if (!pending?.then) return completed(pending);
      const observed = pending.then(completed, failed);
      // Preserve execFile's process handle for its existing ownership/cleanup owner.
      if (pending.child) observed.child = pending.child;
      return observed;
    } catch (error) {
      return failed(error);
    }
  };
}
