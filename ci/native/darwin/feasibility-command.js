import { randomBytes } from "node:crypto";
import {
  feasibilityFailureCause,
  unavailableFeasibilityResults,
} from "../feasibility/index.js";
import { bindDarwinAuditEvent } from "./audit.js";
import {
  digest,
  normalizeDarwinIdentity,
  sameDarwinIdentity,
} from "./protocol.js";
import { createDarwinCommandEffects } from "./feasibility-command-effects.js";

const need = (value, detail, code = "missing-observation") => {
  if (!value)
    throw Object.assign(new Error("Darwin command evidence rejected"), {
      feasibilityCause: { code, detail },
    });
};
const hash = (value) =>
  typeof value === "string" && /^[a-f0-9]{64}$/u.test(value);

/** Native windows and held objects, never the buffered RPC response alone. */
export function assessDarwinCommandObservation(
  spec,
  observation,
  reply,
  nonce,
) {
  const before = normalizeDarwinIdentity(observation.before),
    after = normalizeDarwinIdentity(observation.after);
  need(
    sameDarwinIdentity(before, after) &&
      before.asid === spec.asid &&
      before.auid === spec.uid &&
      ["uid", "ruid", "svuid"].every((key) => before[key] === spec.uid) &&
      ["gid", "rgid", "svgid"].every((key) => before[key] === spec.gid) &&
      observation.imageSha256 === spec.helperSha256 &&
      observation.sandboxed === true,
    "Command identity, image or live effective policy did not join the admitted domain.",
  );
  need(
    reply.exitCode === 0 &&
      reply.stdout ===
        (spec.action === "inspect"
          ? nonce
          : spec.permit
            ? "attempt:written"
            : "attempt:denied"),
    "The fixed command attempt did not acknowledge its expected result.",
  );
  const relevant = observation.events.filter(
    (event) => event.pid === before.pid && event.target === spec.target,
  );
  need(
    relevant.length > 0 &&
      relevant.every(
        (event) =>
          event.kind === "path" &&
          event.opcode.startsWith("AUE_OPEN") &&
          (spec.permit
            ? event.error === 0 && event.result >= 0
            : [1, 13, 30].includes(event.error) && event.result === -1),
      ),
    "Native file observations did not establish the permitted control or denial.",
  );
  for (const event of relevant)
    bindDarwinAuditEvent(
      event,
      before,
      after,
      observation.object,
      observation.object.after.sha256,
      observation.barrierSha256,
    );
  const lastTarget = observation.events.findLastIndex(
      (event) => event.pid === before.pid && event.target === spec.target,
    ),
    marker = observation.events
      .slice(lastTarget + 1)
      .find(
        (event) =>
          event.pid === before.pid &&
          event.target === spec.gate &&
          event.error === 0,
      );
  need(
    marker &&
      hash(marker.id) &&
      marker.kind === "path" &&
      marker.opcode.startsWith("AUE_OPEN") &&
      marker.result >= 0 &&
      ["auid", "asid", "uid", "gid"].every(
        (key) => marker[key] === before[key],
      ) &&
      marker.time >= Math.max(...relevant.map((event) => event.time)) &&
      marker.window?.barrierSha256 === observation.barrierSha256 &&
      marker.time > marker.window.start &&
      marker.time < marker.window.end &&
      ["device", "inode", "uid", "gid", "mode"].every(
        (key) =>
          marker.nativeObject?.[key] === observation.gate.before[key] &&
          observation.gate.before[key] === observation.gate.after[key],
      ) &&
      observation.gate.before.uid === spec.uid &&
      observation.gate.before.gid === spec.gid &&
      observation.gate.before.mode === 0o600,
    "The completed command I/O did not join the held native acknowledgement gate.",
  );
  const expected = digest(
    spec.permit && ["edit", "outside"].includes(spec.action)
      ? nonce + "-edited"
      : nonce,
  );
  need(
    observation.object.before.sha256 === digest(nonce) &&
      observation.object.before.object.uid === spec.uid &&
      observation.object.before.object.gid === spec.gid &&
      observation.object.before.object.mode === 0o600 &&
      observation.object.before.object.identity ===
        observation.object.after.object.identity &&
      observation.object.after.sha256 === expected,
    "A held command sentinel changed outside its permitted operation.",
    "observed-escape",
  );
  return digest(JSON.stringify({ spec, observation }));
}

/** The provider owns schema/RPC handling; Darwin owns every native effect.
 * Missing complete custody is refused before version, schema or server release. */
export async function runDarwinFeasibilityCommand(
  dispatch,
  inputs,
  protocol,
  {
    effects = createDarwinCommandEffects(dispatch, inputs),
    now = () => performance.now(),
    timeout = (ms) => AbortSignal.timeout(ms),
  } = {},
) {
  const started = now(),
    nonce = randomBytes(16).toString("hex"),
    signal = timeout(120000),
    components = [inputs.packages.codex.component, inputs.tool],
    result = unavailableFeasibilityResults("darwin").find(
      (entry) => entry.capability === "codex.command-exec",
    );
  let stage = "prerequisites",
    prepared,
    client,
    effectsPossible = false,
    commandRequests = 0;
  const bounded = async (operation, active = signal) => {
    if (active.aborted)
      throw Object.assign(new Error("Command deadline"), {
        code: "ERR_FEASIBILITY_DEADLINE",
      });
    let reject;
    const aborted = new Promise((_, fail) => {
      reject = () =>
        fail(
          Object.assign(new Error("Command deadline"), {
            code: "ERR_FEASIBILITY_DEADLINE",
          }),
        );
      active.addEventListener("abort", reject, { once: true });
    });
    try {
      return await Promise.race([Promise.resolve().then(operation), aborted]);
    } finally {
      active.removeEventListener("abort", reject);
    }
  };
  try {
    prepared = await bounded(() => effects.prepare(nonce, components, signal));
    need(
      prepared.admission === true &&
        prepared.audit === true &&
        prepared.completeRetirement === true &&
        prepared.sessionEscapeDenied === true,
      "Native admission, audit capture or complete owned retirement is unavailable.",
      "prerequisite-unavailable",
    );
    stage = "installed-schema";
    effectsPossible = true;
    const schema = await bounded(() => effects.schema(prepared, signal));
    need(
      protocol.supports(schema),
      "The installed schema lacks the buffered route or explicit sandbox policies.",
      "prerequisite-unavailable",
    );
    stage = "capture-admission";
    const admitted = await bounded(() => effects.arm(prepared, signal));
    const server = normalizeDarwinIdentity(admitted.identity);
    need(
      admitted.captureReady === true &&
        admitted.sessionHeld === true &&
        ["uid", "ruid", "svuid", "auid"].every(
          (key) => server[key] === prepared.uid,
        ) &&
        ["gid", "rgid", "svgid"].every((key) => server[key] === prepared.gid) &&
        server.asid > 0 &&
        admitted.imageSha256 === inputs.packages.codex.component.sha256,
      "The parked server lacks independent image, audit-session or capture admission.",
    );
    await bounded(() => effects.release(prepared, signal));
    client = protocol.open(admitted.transport, signal);
    const initialized = await bounded(() => client.initialize());
    need(
      initialized.codexHome === prepared.home,
      "App Server did not acknowledge the fresh owned Codex home.",
    );
    const witnesses = [];
    stage = "permitted-controls";
    const control = await bounded(() => effects.control(prepared, signal));
    need(
      control.permitted === true,
      "The enclosing admission policy did not permit the outside write control.",
    );
    witnesses.push(
      assessDarwinCommandObservation(
        {
          action: "control",
          permit: true,
          target: prepared.files.outside,
          gate: prepared.gate,
          uid: prepared.uid,
          gid: prepared.gid,
          asid: normalizeDarwinIdentity(control.observation.before).asid,
          helperSha256: prepared.helperSha256,
        },
        control.observation,
        control.reply,
        nonce,
      ),
    );
    for (const profile of ["read-only", "workspace-write"]) {
      for (const action of ["inspect", "edit", "outside"]) {
        stage = "command-observation";
        const spec = {
          profile,
          action,
          permit:
            action === "inspect" ||
            (action === "edit" && profile === "workspace-write"),
          target: prepared.files[action],
          gate: prepared.gate,
          uid: prepared.uid,
          gid: prepared.gid,
          asid: server.asid,
          helperSha256: prepared.helperSha256,
        };
        await bounded(() => effects.begin(prepared, spec, signal));
        commandRequests++;
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
              ],
              prepared.workspace,
              profile,
            ),
          )
          .then((reply) => {
            if (reply.exitCode !== 0)
              throw Object.assign(new Error("Fixed command execution failed"), {
                feasibilityCause: feasibilityFailureCause(
                  "command",
                  "buffered-reply",
                  { exitCode: reply.exitCode },
                ),
              });
            return reply;
          });
        // A failed RPC must not be replaced by a later missing-helper failure.
        // Success still waits for the independent native observation.
        const rpcFailure = rpc.then(() => new Promise(() => {}));
        rpcFailure.catch(() => {});
        const observation = await bounded(() =>
          Promise.race([effects.observe(prepared, spec, signal), rpcFailure]),
        );
        const reply = await bounded(() => rpc);
        witnesses.push(
          assessDarwinCommandObservation(spec, observation, reply, nonce),
        );
      }
    }
    stage = "command-close";
    await bounded(() => client.close());
    client = null;
    result.status = "PASS";
    result.cause = null;
    result.evidence = {
      ready: true,
      positiveControl: true,
      attemptAcknowledged: true,
      independent: true,
      outcome: "DENIED",
      observationSha256: digest(JSON.stringify(witnesses)),
      sentinelsBeforeSha256: prepared.sentinelSha256,
      sentinelsAfterSha256: prepared.sentinelSha256,
    };
  } catch (error) {
    const routeUnavailable = error.code === "ERR_FEASIBILITY_ROUTE_UNAVAILABLE";
    const cause =
      error.feasibilityCause ??
      (routeUnavailable
        ? {
            code:
              commandRequests === 1
                ? "prerequisite-unavailable"
                : "setup-failed",
            detail:
              "Installed App Server rejected the buffered command/exec route.",
          }
        : feasibilityFailureCause(
            "command",
            stage,
            error,
            [78, "ENOENT", "ERR_FEASIBILITY_UNAVAILABLE"].includes(error.code)
              ? "prerequisite-unavailable"
              : "setup-failed",
          ));
    Object.assign(result, {
      status:
        cause.code === "prerequisite-unavailable" && !effectsPossible
          ? "BLOCKED"
          : "FAIL",
      cause,
    });
    // An unavailable buffered interface is BLOCKED, with independent cleanup.
    if (
      cause.code === "prerequisite-unavailable" &&
      (stage === "installed-schema" ||
        (routeUnavailable && commandRequests === 1))
    )
      result.status = "BLOCKED";
  } finally {
    const cleanupStarted = now(),
      cleanupSignal = timeout(30000);
    let emergency = false;
    try {
      if (!effectsPossible && effects.noCustody())
        throw new Error("No custody was admitted");
      const retired = await bounded(
        () => effects.retire(prepared, cleanupSignal),
        cleanupSignal,
      );
      emergency = retired.emergency === true;
      need(
        retired.independent === true &&
          retired.completeDomain === true &&
          retired.sessionHeldUntilEmpty === true &&
          retired.admissionsClosed === true &&
          retired.serverRetired === true &&
          retired.helpersRetired === true &&
          retired.observerRetired === true &&
          retired.emergency === false &&
          hash(retired.witnessSha256),
        "Complete native command retirement was not independently established.",
        "cleanup-unobserved",
      );
      if (client)
        await bounded(() => client.close().catch(() => {}), cleanupSignal);
      const final = await bounded(
        () => effects.finish(prepared, cleanupSignal),
        cleanupSignal,
      );
      need(
        hash(final.witnessSha256) &&
          final.sentinelSha256 === prepared.sentinelSha256,
        "An outside sentinel changed before final native retirement.",
        "observed-escape",
      );
      result.cleanup = {
        status: "PASS",
        independent: true,
        emergency: false,
        elapsedMs: Math.ceil(now() - cleanupStarted),
        witnessSha256: digest(
          JSON.stringify([retired.witnessSha256, final.witnessSha256]),
        ),
        cause: null,
      };
    } catch (error) {
      emergency ||= error.emergency === true;
      if (!effectsPossible && effects.noCustody())
        result.cleanup = {
          status: "NOT_RUN",
          independent: false,
          emergency: false,
          elapsedMs: null,
          witnessSha256: null,
          cause: null,
        };
      else {
        result.cleanup = {
          status: "UNCERTAIN",
          independent: false,
          emergency,
          elapsedMs: Math.ceil(now() - cleanupStarted),
          witnessSha256: null,
          cause: {
            code: "cleanup-unobserved",
            detail:
              "Owned command custody or sentinel settlement remains incomplete.",
          },
        };
        if (result.status === "PASS") {
          result.status = "FAIL";
          result.cause = error.feasibilityCause ?? result.cleanup.cause;
        }
      }
    }
    result.components = components;
    result.elapsedMs = Math.ceil(cleanupStarted - started);
    inputs.commandCleanup = result.cleanup;
  }
  return result;
}
