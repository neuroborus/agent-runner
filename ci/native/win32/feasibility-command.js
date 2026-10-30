import { randomBytes } from "node:crypto";
import { nativeException } from "../diagnostics.js";
import {
  feasibilityFailureCause,
  unavailableFeasibilityResults,
} from "../feasibility/index.js";
import { digest, normalizeWindowsIdentity } from "./protocol.js";
import {
  createWindowsCommandEffects,
  windowsCommandBrokerSetup,
  assessWindowsCommandObservation,
} from "./feasibility-command-effects.js";

const hash = (v) => typeof v === "string" && /^[a-f0-9]{64}$/u.test(v);
const need = (value, detail, code = "missing-observation") => {
  if (!value)
    throw Object.assign(new Error("Windows command evidence rejected"), {
      feasibilityCause: { code, detail },
    });
};
export async function runWindowsFeasibilityCommand(
  dispatch,
  inputs,
  protocol,
  {
    effects = createWindowsCommandEffects(dispatch, inputs),
    now = () => performance.now(),
    timeout = (ms) => AbortSignal.timeout(ms),
  } = {},
) {
  const started = now(),
    signal = timeout(120000),
    nonce = randomBytes(16).toString("hex"),
    components = [inputs.packages.codex.component, inputs.tool],
    result = unavailableFeasibilityResults("win32").find(
      (v) => v.capability === "codex.command-exec",
    );
  let stage = "prerequisites",
    prepared,
    client,
    originalError,
    released = false,
    requests = 0;
  const bounded = async (operation, active = signal) => {
    let abort;
    const error = () =>
      Object.assign(new Error("Command deadline"), {
        code: "ERR_FEASIBILITY_DEADLINE",
      });
    if (active.aborted) throw error();
    const deadline = new Promise((_, reject) => {
      abort = () => reject(error());
      active.addEventListener("abort", abort, { once: true });
    });
    try {
      return await Promise.race([Promise.resolve().then(operation), deadline]);
    } finally {
      active.removeEventListener("abort", abort);
    }
  };
  const projectFailure = (error) => {
    const unsupported =
      error.code === "ERR_FEASIBILITY_ROUTE_UNAVAILABLE" && requests === 1;
    const cause =
      error.feasibilityCause ??
      (unsupported
        ? {
            code: "prerequisite-unavailable",
            detail: "Installed Windows release rejected the buffered route.",
          }
        : feasibilityFailureCause(
            "command",
            stage,
            error,
            [78, "ENOENT"].includes(error.code) && !released
              ? "prerequisite-unavailable"
              : "setup-failed",
          ));
    Object.assign(result, {
      status:
        cause.code === "prerequisite-unavailable" && (!released || unsupported)
          ? "BLOCKED"
          : "FAIL",
      cause,
    });
  };
  try {
    prepared = await bounded(() => effects.prepare(nonce, components, signal));
    need(
      prepared.admission === true &&
        prepared.auditInterface === true &&
        prepared.completeRetirement === true,
      "Native privileges, audit interfaces or complete Job custody is unavailable.",
      "prerequisite-unavailable",
    );
    stage = "broker-setup";
    const setup = await bounded(() => effects.setup(prepared, signal)),
      witnesses = [windowsCommandBrokerSetup(prepared, setup)];
    stage = "installed-schema";
    const schema = await bounded(() => effects.schema(prepared, signal));
    need(
      protocol.supports(schema),
      "Installed release lacks buffered commands or explicit sandbox policies.",
      "prerequisite-unavailable",
    );
    stage = "capture-admission";
    const admitted = await bounded(() => effects.arm(prepared, signal)),
      server = normalizeWindowsIdentity(admitted.identity);
    need(
      admitted.captureReady === true &&
        admitted.creationJob === true &&
        admitted.independent === true &&
        admitted.imageSha256 === inputs.packages.codex.component.sha256 &&
        admitted.token.appContainer === false &&
        admitted.token.restrictingSids === 0 &&
        admitted.token.integrity === 8192,
      "Suspended App Server lacks independent image, token or Job admission.",
    );
    stage = "permitted-control";
    const control = await bounded(() => effects.control(prepared, signal));
    witnesses.push(
      assessWindowsCommandObservation(
        {
          action: "outside",
          control: true,
          permit: true,
          target: prepared.files.outside,
          gateFile: prepared.gateFile,
          helperSha256: prepared.helperSha256,
          userSid: server.userSid,
          sessionId: server.sessionId,
          authenticationId: admitted.token.authenticationId,
        },
        control.observation,
        control.reply,
        nonce,
      ),
    );
    await bounded(() => effects.release(prepared, signal));
    released = true;
    client = protocol.open(admitted.transport, signal);
    need(
      (await bounded(() => client.initialize())).codexHome === prepared.home,
      "App Server did not acknowledge the fresh empty home.",
    );
    for (const profile of ["read-only", "workspace-write"])
      for (const action of ["inspect", "edit", "outside"]) {
        stage = "command-observation";
        const spec = {
          profile,
          action,
          control: false,
          permit:
            action === "inspect" ||
            (action === "edit" && profile === "workspace-write"),
          target: prepared.files[action],
          gateFile: prepared.gateFile,
          helperSha256: prepared.helperSha256,
          userSid: server.userSid,
          sessionId: server.sessionId,
          authenticationId: admitted.token.authenticationId,
        };
        await bounded(() => effects.begin(prepared, spec, signal));
        requests++;
        const rpc = client
          .exec(
            protocol.parameters(
              [
                prepared.helper,
                "command-case",
                prepared.gate,
                spec.target,
                action,
                nonce,
                prepared.gateFile,
                String(prepared.observer.pid),
              ],
              prepared.workspace,
              profile,
            ),
          )
          .then((reply) => {
            if (reply.exitCode !== 0)
              throw Object.assign(new Error("Buffered command failed"), {
                feasibilityCause: feasibilityFailureCause(
                  "command",
                  "buffered-reply",
                  { exitCode: reply.exitCode },
                ),
              });
            return reply;
          });
        const failure = rpc.then(() => new Promise(() => {}));
        failure.catch(() => {});
        const observation = await bounded(() =>
          Promise.race([effects.observe(prepared, spec, signal), failure]),
        );
        witnesses.push(
          assessWindowsCommandObservation(
            spec,
            observation,
            await bounded(() => rpc),
            nonce,
          ),
        );
      }
    stage = "command-close";
    await bounded(() => client.close());
    client = null;
    Object.assign(result, {
      status: "PASS",
      cause: null,
      evidence: {
        ready: true,
        positiveControl: true,
        attemptAcknowledged: true,
        independent: true,
        outcome: "DENIED",
        observationSha256: digest(JSON.stringify(witnesses)),
        sentinelsBeforeSha256: prepared.sentinelSha256,
        sentinelsAfterSha256: prepared.sentinelSha256,
      },
    });
  } catch (error) {
    nativeException("windows-model-free-command", error);
    originalError = error;
    effects.retainFailure?.(error);
    projectFailure(error);
  } finally {
    const cleanupStarted = now(),
      cleanupSignal = timeout(30000);
    try {
      if (effects.noCustody())
        result.cleanup = {
          status: "NOT_RUN",
          independent: false,
          emergency: false,
          elapsedMs: null,
          witnessSha256: null,
          cause: null,
        };
      else {
        const retired = await bounded(
          () => effects.retire(prepared, cleanupSignal),
          cleanupSignal,
        );
        if (retired.preparationOnly === true) {
          need(
            !released &&
              !client &&
              retired.independent === true &&
              retired.processesRetired === true &&
              retired.fixturesRemoved === true &&
              retired.emergency === false &&
              hash(retired.witnessSha256),
            "Owned preparation processes or temporary resources remain unsettled.",
            "cleanup-unobserved",
          );
        } else {
          need(
            retired.independent === true &&
              retired.completeDomain === true &&
              retired.admissionsClosed === true &&
              retired.serverRetired === true &&
              retired.helpersRetired === true &&
              retired.observerRetired === true &&
              retired.readerRetired === true &&
              retired.jobClosed === true &&
              retired.emergency === false &&
              retired.auditRestored === true &&
              retired.fixturesRemoved === true &&
              hash(retired.witnessSha256),
            "Complete native Job, observer, audit and fixture settlement was not independently established.",
            "cleanup-unobserved",
          );
          need(
            retired.sentinelSha256 === prepared.sentinelSha256,
            "Outside sentinel changed before complete owned retirement.",
            "observed-escape",
          );
          if (client)
            await bounded(
              () =>
                client
                  .close()
                  .catch((error) =>
                    nativeException("windows-model-free-client-cleanup", error),
                  ),
              cleanupSignal,
            );
        }
        result.cleanup = {
          status: "PASS",
          independent: true,
          emergency: false,
          elapsedMs: Math.ceil(now() - cleanupStarted),
          witnessSha256: retired.witnessSha256,
          cause: null,
        };
      }
    } catch (error) {
      nativeException("windows-model-free-cleanup", error);
      result.cleanup = {
        status: "UNCERTAIN",
        independent: false,
        emergency: error.emergency === true,
        elapsedMs: Math.ceil(now() - cleanupStarted),
        witnessSha256: null,
        cause: error.feasibilityCleanup ?? {
          code: "cleanup-unobserved",
          detail:
            "Owned Windows command custody or audit restoration remains incomplete.",
        },
      };
      if (result.status === "PASS") {
        originalError = error;
        effects.retainFailure?.(error);
        result.status = "FAIL";
        result.cause = error.feasibilityCause ?? result.cleanup.cause;
      }
    }
    if (originalError && effects.failure) {
      try {
        // Cleanup may expose the original broker refusal after a watcher failed.
        // Collect actual closure within the same cleanup budget, never a new one.
        const first = await bounded(() => effects.failure(), cleanupSignal);
        if (first) {
          if (first !== originalError) projectFailure(first);
          if (result.cleanup.status === "UNCERTAIN" && first.feasibilityCleanup)
            result.cleanup.cause = first.feasibilityCleanup;
        }
      } catch (error) {
        nativeException("windows-model-free-failure-collection", error);
        result.cleanup = {
          ...result.cleanup,
          status: "UNCERTAIN",
          independent: false,
          witnessSha256: null,
          cause: result.cleanup.cause ?? {
            code: "cleanup-unobserved",
            detail:
              "Broker failure collection did not settle within owned cleanup.",
          },
        };
      }
    }
    if (result.cleanup.elapsedMs !== null)
      result.cleanup.elapsedMs = Math.ceil(now() - cleanupStarted);
    result.components = components;
    result.elapsedMs = Math.ceil(cleanupStarted - started);
    inputs.commandCleanup = result.cleanup;
  }
  return result;
}
