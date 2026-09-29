import { spawn } from "node:child_process";
import { hostname } from "node:os";
import { fileURLToPath } from "node:url";
import { readProcessIdentity } from "../agents/index.js";
import { DETACHED_RUNTIME_COMPATIBILITY_TOKEN } from "../pipeline-registry.js";
import { normalizeRecoveryDispatch, RunStoreError } from "../state/index.js";

const EXECUTABLE_PATH = fileURLToPath(
  new URL("../../bin/agent-run.js", import.meta.url),
);
export const DETACHED_RUNTIME_COMPATIBILITY_ENV =
  "AGENT_RUNNER_PARENT_RUNTIME_COMPATIBILITY";
export const DETACHED_STOP_CHECKPOINT_ENV =
  "AGENT_RUNNER_PARENT_STOP_CHECKPOINT";
const DISPATCH_ENV = "AGENT_RUNNER_PARENT_DISPATCH";
const HANDSHAKE_MS = 10_000;

export async function awaitDetachedDispatch(environment) {
  if (environment[DISPATCH_ENV] === undefined) return undefined;
  if (environment[DISPATCH_ENV] !== "1" || !process.connected)
    throw new RunStoreError("Detached dispatch channel is unavailable.", {
      code: "ERR_DETACHED_START_FAILED",
    });
  // This one-use channel must not leak into provider or validation children.
  delete environment[DISPATCH_ENV];
  return new Promise((resolve, reject) => {
    const finish = (error, value) => {
      clearTimeout(timer);
      process.removeListener("message", receive);
      process.removeListener("disconnect", disconnected);
      if (process.connected) process.disconnect();
      if (error) reject(error);
      else resolve(value);
    };
    const disconnected = () =>
      finish(
        new RunStoreError(
          "Detached dispatcher disconnected before admission.",
          { code: "ERR_DETACHED_START_FAILED" },
        ),
      );
    const receive = (message) => {
      try {
        if (message?.type !== "dispatch")
          throw new Error("Invalid dispatch message");
        finish(null, normalizeRecoveryDispatch(message.dispatch));
      } catch {
        disconnected();
      }
    };
    const timer = setTimeout(disconnected, HANDSHAKE_MS);
    process.on("message", receive);
    process.once("disconnect", disconnected);
    process.send({ type: "dispatch-listening" }, (error) => {
      if (error) disconnected();
    });
  });
}

export function launchDetachedRun(runIdValue, action = null, options = {}) {
  return createDetachedLauncher()(runIdValue, action, options);
}

function detachedArguments(executablePath, runIdValue, action) {
  const args = [executablePath, "resume", "--run", runIdValue];
  if (action?.type === "extra-fix-rounds") {
    args.push("--extra-fix-rounds", String(action.amount));
  } else if (action?.type === "override-finding") {
    args.push("--override-finding", action.findingId);
  } else if (action !== null) {
    throw new Error("Detached resume action is invalid.");
  }
  return args;
}

export function createDetachedLauncher({
  detachedCompatibilityToken = DETACHED_RUNTIME_COMPATIBILITY_TOKEN,
  spawnProcess = spawn,
  executablePath = EXECUTABLE_PATH,
  environment = process.env,
} = {}) {
  return (
    runIdValue,
    action = null,
    {
      expectedRuntimeCompatibility = detachedCompatibilityToken,
      stopCheckpointRevision = null,
      onExit,
      dispatch = null,
      onSpawn,
    } = {},
  ) =>
    new Promise((resolvePromise, rejectPromise) => {
      if (expectedRuntimeCompatibility !== detachedCompatibilityToken) {
        rejectPromise(
          new RunStoreError(
            "Detached continuation runtime does not match this launcher; " +
              "restart the Agent Runner MCP server and retry.",
            { code: "ERR_RUNTIME_VERSION_SKEW" },
          ),
        );
        return;
      }
      if (
        stopCheckpointRevision !== null &&
        (!Number.isSafeInteger(stopCheckpointRevision) ||
          stopCheckpointRevision < 1 ||
          action !== null)
      ) {
        rejectPromise(
          new RunStoreError("Detached stop checkpoint is invalid.", {
            code: "ERR_INVALID_RUNNER_INPUT",
          }),
        );
        return;
      }
      if (dispatch !== null) normalizeRecoveryDispatch(dispatch);
      const {
        [DISPATCH_ENV]: _ignoredDispatch,
        [DETACHED_STOP_CHECKPOINT_ENV]: _ignoredStopCheckpoint,
        ...childEnvironment
      } = environment;
      const child = spawnProcess(
        process.execPath,
        detachedArguments(executablePath, runIdValue, action),
        {
          detached: true,
          env: {
            ...childEnvironment,
            ...(dispatch === null ? {} : { [DISPATCH_ENV]: "1" }),
            [DETACHED_RUNTIME_COMPATIBILITY_ENV]: expectedRuntimeCompatibility,
            ...(stopCheckpointRevision === null
              ? {}
              : {
                  [DETACHED_STOP_CHECKPOINT_ENV]: String(
                    stopCheckpointRevision,
                  ),
                }),
          },
          stdio:
            dispatch === null
              ? "ignore"
              : ["ignore", "ignore", "ignore", "ipc"],
        },
      );
      let settled = false;
      let registered = false;
      let listening = false;
      let sent = false;
      const finish = (error) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        if (dispatch !== null) child.removeListener("message", onMessage);
        // An admitted child survives the control-plane lifetime. An inert child
        // gets no permission to run if registration or IPC admission failed.
        if (error && !sent) child.kill();
        child.unref();
        if (error) rejectPromise(error);
        else resolvePromise(child.pid);
      };
      const timer =
        dispatch === null
          ? null
          : setTimeout(
              () =>
                finish(
                  new RunStoreError(
                    "Detached admission timed out; retry the same key.",
                    { code: "ERR_DETACHED_OWNERSHIP_PENDING" },
                  ),
                ),
              HANDSHAKE_MS,
            );
      const send = () => {
        if (settled || !registered || !listening || sent) return;
        sent = true;
        child.send({ type: "dispatch", dispatch }, (error) => finish(error));
      };
      const onMessage = (message) => {
        if (message?.type === "dispatch-listening") {
          listening = true;
          send();
        }
      };
      if (dispatch !== null) child.on("message", onMessage);
      child.once("error", finish);
      child.once("exit", (code) => {
        onExit?.(code);
        if (dispatch !== null && !sent)
          finish(
            new RunStoreError("Detached child exited before admission.", {
              code: "ERR_DETACHED_START_FAILED",
            }),
          );
      });
      child.once("spawn", async () => {
        if (dispatch === null) return finish();
        try {
          const processIdentity = await readProcessIdentity(child.pid);
          if (processIdentity === null || typeof onSpawn !== "function")
            throw new RunStoreError("Detached child identity is unavailable.", {
              code: "ERR_DETACHED_OWNERSHIP_PENDING",
            });
          await onSpawn({
            pid: child.pid,
            hostname: hostname(),
            processIdentity,
          });
          registered = true;
          send();
        } catch (error) {
          finish(error);
        }
      });
    });
}
