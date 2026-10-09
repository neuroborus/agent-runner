import { randomBytes } from "node:crypto";
import {
  feasibilityFailureCause,
  unavailableFeasibilityResults,
} from "../feasibility/index.js";
import {
  digest,
  normalizeWindowsIdentity,
  sameWindowsIdentity,
} from "./protocol.js";
import { createWindowsCommandEffects } from "./feasibility-command-effects.js";

const hash = (v) => typeof v === "string" && /^[a-f0-9]{64}$/u.test(v);
const need = (value, detail, code = "missing-observation") => {
  if (!value)
    throw Object.assign(new Error("Windows command evidence rejected"), {
      feasibilityCause: { code, detail },
    });
};
/** A reply cannot replace native token, held object, or Security observations. */
export function assessWindowsCommandObservation(
  spec,
  observation,
  reply,
  nonce,
) {
  const before = normalizeWindowsIdentity(observation.before),
    after = normalizeWindowsIdentity(observation.after);
  need(
    sameWindowsIdentity(before, after) &&
      before.userSid === spec.userSid &&
      before.sessionId === spec.sessionId &&
      observation.creationJob === true &&
      observation.imageSha256 === spec.helperSha256 &&
      observation.beforeToken.appContainer === false &&
      observation.beforeToken.integrity === 8192 &&
      typeof observation.beforeToken.restricted === "boolean" &&
      (spec.control || observation.beforeToken.restricted === true) &&
      Number.isInteger(observation.beforeToken.restrictingSids) &&
      observation.beforeToken.restrictingSids <= 32 &&
      (spec.control
        ? observation.beforeToken.restrictingSids === 0
        : observation.beforeToken.restrictingSids > 0) &&
      /^[a-f0-9]{8}:[a-f0-9]{8}$/u.test(spec.authenticationId) &&
      observation.beforeToken.authenticationId === spec.authenticationId &&
      hash(observation.beforeToken.restrictedSidsSha256) &&
      JSON.stringify(observation.beforeToken) ===
        JSON.stringify(observation.afterToken),
    "Command process, image, token or creation-time Job custody did not join.",
  );
  need(
    reply.exitCode === 0 &&
      reply.stdout ===
        (spec.action === "inspect"
          ? nonce
          : spec.permit
            ? "attempt:written"
            : "attempt:denied"),
    "The fixed command did not acknowledge its expected result.",
  );
  const start = BigInt(observation.start.time),
    end = BigInt(observation.end.time);
  need(
    observation.captureComplete === true &&
      end > start &&
      BigInt(before.creationTime) > start &&
      BigInt(before.creationTime) < end &&
      observation.end.sequence === observation.start.sequence + 1,
    "The acknowledged native capture window is incomplete.",
  );
  const events = observation.events.filter(
    ({ raw, time, logonId }) =>
      raw.pid === before.pid &&
      raw.subjectSid === before.userSid &&
      logonId === spec.authenticationId?.replace(":", "") &&
      BigInt(time) > start &&
      BigInt(time) < end,
  );
  const mask = spec.action === "inspect" ? 1 : 2;
  const target = events.filter(
    ({ raw }) =>
      raw.target.toLowerCase() === spec.target.toLowerCase() &&
      (raw.accessMask & mask) !== 0,
  );
  need(
    target.length > 0 &&
      target.every(({ raw }) =>
        spec.permit
          ? raw.opcode === "4663" && raw.auditFailure === false
          : raw.opcode === "4656" && raw.auditFailure === true,
      ),
    "Security object access did not establish the permitted control or denial.",
  );
  need(
    events.some(
      ({ raw, recordId, time }) =>
        raw.target.toLowerCase() === spec.gateFile.toLowerCase() &&
        raw.opcode === "4663" &&
        raw.auditFailure === false &&
        (raw.accessMask & 1) !== 0 &&
        target.every(
          (v) =>
            BigInt(recordId) > BigInt(v.recordId) &&
            BigInt(time) >= BigInt(v.time),
        ),
    ),
    "The audited held gate did not acknowledge completed target I/O.",
  );
  for (const object of [observation.object, observation.gate])
    need(
      object.before.identity === object.after.identity &&
        /^[a-f0-9]{16}:[a-f0-9]{32}$/u.test(object.before.identity) &&
        hash(object.before.daclSha256) &&
        hash(object.after.daclSha256),
      "A held file/DACL observation lost its original native identity.",
    );
  need(
    observation.gate.before.sha256 === digest(nonce) &&
      observation.gate.after.sha256 === digest(nonce) &&
      observation.gate.before.daclSha256 ===
        observation.gate.after.daclSha256 &&
      observation.object.before.sha256 === digest(nonce) &&
      observation.object.after.sha256 ===
        digest(
          spec.permit && spec.action !== "inspect" ? nonce + "-edited" : nonce,
        ) &&
      (spec.action !== "outside" ||
        observation.object.before.daclSha256 ===
          observation.object.after.daclSha256),
    "The held sentinel changed outside its permitted operation.",
    "observed-escape",
  );
  return digest(JSON.stringify({ spec, observation }));
}

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
  try {
    prepared = await bounded(() => effects.prepare(nonce, components, signal));
    need(
      prepared.admission === true &&
        prepared.audit === true &&
        prepared.completeRetirement === true,
      "Native privileges, audit coverage or complete Job custody is unavailable.",
      "prerequisite-unavailable",
    );
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
    const witnesses = [];
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
          await bounded(() => client.close().catch(() => {}), cleanupSignal);
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
      result.cleanup = {
        status: "UNCERTAIN",
        independent: false,
        emergency: error.emergency === true,
        elapsedMs: Math.ceil(now() - cleanupStarted),
        witnessSha256: null,
        cause: {
          code: "cleanup-unobserved",
          detail:
            "Owned Windows command custody or audit restoration remains incomplete.",
        },
      };
      if (result.status === "PASS") {
        result.status = "FAIL";
        result.cause = error.feasibilityCause ?? result.cleanup.cause;
      }
    }
    result.components = components;
    result.elapsedMs = Math.ceil(cleanupStarted - started);
    inputs.commandCleanup = result.cleanup;
  }
  return result;
}
