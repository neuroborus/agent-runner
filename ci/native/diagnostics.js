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

// Normal compiler/linker exits exclude launch/capture failures and native crash
// statuses. Protected callers additionally verify their complete native custody.
export const settledCompilerFailure = (error) =>
  Number.isInteger(error?.code) &&
  error.code > 0 &&
  error.code <= 65535 &&
  error.signal === null &&
  !error.killed &&
  !error.timedOut &&
  !error.truncated &&
  !error.partial &&
  error.settlement === undefined;

// Retain later uncertainty without replacing or mutating the first exception.
// This fact can only withhold cleanup success; it never proves retirement.
const unsettledBuildFailures = new WeakSet();
export function hasUnsettledNativeBuild(error) {
  const seen = new Set();
  for (
    let cause = error;
    cause && typeof cause === "object" && !seen.has(cause);
    cause = cause.cause
  ) {
    if (unsettledBuildFailures.has(cause)) return true;
    seen.add(cause);
  }
  return false;
}

/** Fixed build-only recipes; diagnostics never admit an output or retire an owner. */
export async function attemptNativeBuilds(
  owner,
  recipes,
  {
    signal,
    verify = async () => {},
    settled = settledCompilerFailure,
    now = () => performance.now(),
    deadlineMs = recipes.length * 60000,
  } = {},
) {
  if (
    !recipes.length ||
    recipes.length > 32 ||
    new Set(recipes.map(({ name }) => name)).size !== recipes.length
  )
    throw new Error("Invalid fixed native build inventory");
  const until = now() + deadlineMs,
    records = [];
  const output = (value) =>
    Buffer.isBuffer(value) || typeof value === "string"
      ? Buffer.from(value)
      : Buffer.alloc(0);
  let first,
    failed = false,
    unsettled = false,
    stop;
  const report = (suffix, error) => {
    try {
      nativeException(owner + suffix, error);
    } catch {
      stop ??= "diagnostic-sink";
    }
  };
  const budget = () => {
    if (signal?.aborted)
      throw signal.reason ?? new Error("Native build cancelled");
    if (now() >= until) throw new Error("Native build deadline exhausted");
  };
  for (const recipe of recipes) {
    if (stop) {
      records.push({ name: recipe.name, status: "UNATTEMPTED", reason: stop });
      continue;
    }
    let result,
      error,
      completion,
      started = false,
      commandFailed = false,
      phase = "prerequisite";
    try {
      budget();
      await verify();
      budget();
      phase = "compiler";
      started = true;
      try {
        result = await recipe.run();
      } catch (cause) {
        error = cause;
        commandFailed = true;
        unsettled = !settled(error);
        if (unsettled) stop = "unsafe-compiler-completion";
      }
      completion = commandFailed ? error : result;
      phase = "input-verification";
      await verify();
      phase = "budget";
      budget();
    } catch (cause) {
      stop = signal?.aborted
        ? "cancelled"
        : now() >= until
          ? "deadline"
          : phase;
      if (commandFailed) report("/continuation-stop", cause);
      else {
        error = cause;
        commandFailed = true;
      }
    }
    const facts = completion;
    const stdout = output(facts?.stdout),
      stderr = output(facts?.stderr);
    records.push(
      !started
        ? { name: recipe.name, status: "UNATTEMPTED", reason: stop }
        : {
            name: recipe.name,
            status: commandFailed ? "FAIL" : "BUILT",
            exitCode: Number.isInteger(facts?.exitCode)
              ? facts.exitCode
              : Number.isInteger(facts?.code)
                ? facts.code
                : error === completion && commandFailed
                  ? null
                  : 0,
            signal: facts?.signal ?? null,
            timedOut: facts?.timedOut ?? false,
            stdout: stdout.subarray(0, 65536).toString(),
            stderr: stderr.subarray(0, 65536).toString(),
            truncated: Boolean(
              facts?.truncated ||
              stdout.length > 65536 ||
              stderr.length > 65536,
            ),
            stop: stop ?? null,
          },
    );
    if (commandFailed) {
      if (!failed) {
        first = error;
        failed = true;
      }
      report("/" + recipe.name, error);
    }
  }
  if (unsettled && first && typeof first === "object")
    unsettledBuildFailures.add(first);
  try {
    nativeDiagnostic(owner, { stderr: JSON.stringify({ builds: records }) });
  } finally {
    if (failed) throw first;
  }
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
