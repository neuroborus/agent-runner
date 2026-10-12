import { fork } from "node:child_process";
import { randomUUID } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { finished } from "node:stream/promises";
import { fileURLToPath } from "node:url";
import { spawnOwnedProcess } from "../../../src/agents/index.js";
import { requireFeasibility } from "../feasibility/index.js";
import { normalizeLinuxReceipt, sameLinuxIdentity } from "./protocol.js";
import { digest, processDetails, protectedReceipt } from "./inspect.js";
import { freshVerifier } from "./proof.js";
import { send } from "./channel.js";
import {
  resolveLinuxDiagnosticLauncher,
  linuxDiagnosticError,
  linuxControllerFailure,
  linuxControllerError,
} from "./diagnostics.js";

const ENTRY = fileURLToPath(import.meta.url);

/** One CI command's admitting owner. Only its real payload pipes are forwarded. */
export async function runLinuxCommandController(
  request,
  channel = process,
  {
    spawn = spawnOwnedProcess,
    details = processDetails,
    read = readFile,
    write = writeFile,
  } = {},
) {
  if (channel === process)
    requireFeasibility(
      process.platform === "linux" &&
        process.env.CI === "true" &&
        process.env.GITHUB_ACTIONS === "true" &&
        process.env.ImageOS === "ubuntu24" &&
        process.connected,
    );
  let child,
    confirmation,
    failure,
    admitting = false;
  const stop = (error = new Error("Command controller disconnected.")) => {
    failure ??= error;
    confirmation?.reject(error);
    child?.kill("SIGKILL");
  };
  const acknowledgement = (message) => {
    if (message?.type !== "receipt-ack" || !confirmation) return stop();
    if (
      message.nonce !== request.nonce ||
      message.sha256 !== child.receiptSha256
    )
      return stop(new Error("Substituted command acknowledgement."));
    confirmation.resolve();
  };
  channel.on("message", acknowledgement);
  channel.once("disconnect", stop);
  const streams = [channel.stdin, channel.stdout, channel.stderr];
  for (const stream of streams) stream.on("error", stop);
  try {
    child = spawn(request.file, request.args, {
      cwd: request.cwd,
      env: request.env,
      stdio: ["pipe", "pipe", "pipe"],
      resolveLauncher: resolveLinuxDiagnosticLauncher,
      async onProcess(pid, admission) {
        if (pid === null) return;
        admitting = true;
        const init = await details(pid),
          controller = await details(channel.pid);
        const receipt = normalizeLinuxReceipt({
          schemaVersion: 1,
          candidateSha: request.candidateSha,
          caseId: "argv",
          nonce: request.nonce,
          policyDigest: digest(
            JSON.stringify({ file: request.file, args: request.args }),
          ),
          executableDigest: digest(await read(request.file)),
          isolatedNamespace: true,
          hostSession: false,
          parentNamespaceId: controller.namespaceId,
          init: {
            pid,
            identity: init.identity,
            namespaceId: init.namespaceId,
            nspid: init.nspid,
          },
          launcher: {
            pid: child.pid,
            identity: (await details(child.pid)).identity,
          },
          controller: { pid: channel.pid, identity: controller.identity },
          admission,
        });
        const bytes = JSON.stringify(receipt);
        await write(request.receiptFile, bytes, { flag: "wx", mode: 0o400 });
        child.receiptSha256 = digest(bytes);
        confirmation = Promise.withResolvers();
        // Attach rejection before publication; disconnect cannot strand registration.
        const publication = send(channel, {
          type: "admitted",
          sha256: child.receiptSha256,
        });
        await Promise.all([publication, confirmation.promise]);
        admitting = false;
        confirmation = null;
      },
    });
    child.stdin.on("error", stop);
    channel.stdin.pipe(child.stdin);
    child.stdout.pipe(channel.stdout, { end: false });
    child.stderr.pipe(channel.stderr, { end: false });
    const { outcome } = await child.ownedCompletion;
    await Promise.all(
      streams.slice(1).map((stream) => {
        const drained = finished(stream, { readable: false, cleanup: true });
        stream.end();
        return drained;
      }),
    );
    if (failure) throw failure;
    await send(channel, { type: "completed", outcome });
    if (failure) throw failure;
  } catch (error) {
    stop(error);
    await child?.ownedCompletion.catch(() => {});
    const registered = child?.receiptSha256 && !admitting;
    const cause = linuxDiagnosticError(
      registered ? "command" : "admission",
      registered
        ? "transport-completion"
        : admitting
          ? "command-receipt-registration"
          : "owned-process-admission",
      failure,
      failure?.code === "ENOENT" ? "prerequisite-unavailable" : "setup-failed",
    );
    const cleanupCause = {
      code: "cleanup-unobserved",
      detail: "Command controller required emergency settlement.",
    };
    await send(
      channel,
      linuxControllerFailure(
        request.candidateSha,
        request.nonce,
        cause,
        child ? cleanupCause : null,
      ),
    ).catch(() => {});
    channel.exitCode = 1;
  } finally {
    channel.removeListener("message", acknowledgement);
    channel.removeListener("disconnect", stop);
    for (const stream of streams) stream.removeListener("error", stop);
    channel.stdin.unpipe(child?.stdin);
    channel.stdin.destroy();
    if (channel.connected) channel.disconnect();
  }
}

/** Receipt acknowledgement is an independent live inspection, before release.
 * Completion resolves only after the actual controller closes; it is no witness. */
export function spawnLinuxCommandController(
  request,
  {
    start = fork,
    readReceipt = protectedReceipt,
    details = processDetails,
    read = readFile,
    onReceipt = () => {},
    env = process.env,
    platform = process.platform,
  } = {},
) {
  requireFeasibility(
    platform === "linux" &&
      env.CI === "true" &&
      env.GITHUB_ACTIONS === "true" &&
      env.ImageOS === "ubuntu24",
  );
  const config = { ...request, nonce: randomUUID() };
  const controllerEnv = {
    PATH: "/usr/bin:/bin",
    LANG: "C",
    CI: env.CI,
    GITHUB_ACTIONS: env.GITHUB_ACTIONS,
    ImageOS: env.ImageOS,
  };
  const worker = start(ENTRY, [JSON.stringify(config)], {
    cwd: request.cwd,
    env: controllerEnv,
    execArgv: [],
    stdio: ["pipe", "pipe", "pipe", "ipc"],
  });
  let failure,
    outcome,
    registration = Promise.resolve();
  const refuse = (error) => {
    failure ??= error;
    worker.linuxCommandEmergency = true;
    worker.kill("SIGKILL");
  };
  worker.controllerClosed = new Promise((resolve) => {
    worker.once("close", (exitCode, signal) => {
      if (exitCode !== 0 || signal) worker.linuxCommandEmergency = true;
      resolve({ exitCode, signal });
    });
  });
  worker.on("error", refuse);
  const receive = async (message) => {
    if (message?.type === "admitted") {
      requireFeasibility(
        !worker.linuxCommandReceipt &&
          !outcome &&
          Object.keys(message).length === 2 &&
          /^[a-f0-9]{64}$/u.test(message.sha256),
      );
      worker.linuxCommandRegistering = true;
      worker.linuxCommandReceipt = {
        file: config.receiptFile,
        sha256: message.sha256,
      };
      onReceipt(worker.linuxCommandReceipt);
      const receipt = await readReceipt(config.receiptFile, message.sha256);
      const [init, launcher, controller] = await Promise.all([
        details(receipt.init.pid),
        details(receipt.launcher.pid),
        details(worker.pid),
      ]);
      requireFeasibility(
        receipt.caseId === "argv" &&
          receipt.candidateSha === config.candidateSha &&
          receipt.nonce === config.nonce &&
          receipt.controller.pid === worker.pid &&
          launcher.parent === worker.pid &&
          sameLinuxIdentity(controller.identity, receipt.controller.identity) &&
          sameLinuxIdentity(launcher.identity, receipt.launcher.identity) &&
          sameLinuxIdentity(init.identity, receipt.init.identity) &&
          init.parent === receipt.launcher.pid &&
          JSON.stringify(init.nspid) === JSON.stringify(receipt.init.nspid) &&
          init.namespaceId === receipt.init.namespaceId &&
          controller.namespaceId === receipt.parentNamespaceId &&
          launcher.namespaceId === receipt.parentNamespaceId &&
          receipt.policyDigest ===
            digest(JSON.stringify({ file: config.file, args: config.args })) &&
          receipt.executableDigest === digest(await read(config.file)),
      );
      await send(worker, {
        type: "receipt-ack",
        nonce: config.nonce,
        sha256: message.sha256,
      });
      worker.linuxCommandAdmitted = true;
      worker.linuxCommandRegistering = false;
    } else if (message?.type === "completed") {
      requireFeasibility(
        worker.linuxCommandAdmitted &&
          !outcome &&
          Object.keys(message).length === 2 &&
          Object.keys(message.outcome).sort().join() ===
            "exitCode,signal,type" &&
          message.outcome.type === "close" &&
          (message.outcome.exitCode === null ||
            Number.isInteger(message.outcome.exitCode)) &&
          (message.outcome.signal === null ||
            typeof message.outcome.signal === "string"),
      );
      outcome = message.outcome;
    } else if (message?.type === "failed") {
      throw linuxControllerError(message, config.candidateSha, config.nonce);
    } else throw new Error("Invalid command controller response.");
  };
  worker.on("message", (message) => {
    registration = registration.then(() => receive(message)).catch(refuse);
  });
  worker.ownedCompletion = worker.controllerClosed.then(async (closed) => {
    await registration;
    if (failure) throw failure;
    requireFeasibility(
      closed.exitCode === 0 &&
        !closed.signal &&
        outcome &&
        worker.linuxCommandAdmitted,
    );
    return { outcome };
  });
  return worker;
}

/** Every owner must close and retain its receipt before a fresh, distinct verifier. */
export async function verifyLinuxCommandControllers(
  children,
  { verify = freshVerifier } = {},
) {
  const observed = [];
  for (const child of children) {
    await child.controllerClosed;
    await child.ownedCompletion.catch(() => {});
    const receipt = child.linuxCommandReceipt;
    requireFeasibility(receipt);
    const value = await verify(receipt.file, receipt.sha256);
    requireFeasibility(
      value.status === "RETIRED" &&
        value.independent &&
        !value.emergencyCleanup &&
        !child.linuxCommandEmergency,
    );
    observed.push(value);
  }
  return observed;
}

if (process.argv[1] === ENTRY) {
  Promise.resolve()
    .then(() => {
      requireFeasibility(process.argv.length === 3);
      return runLinuxCommandController(JSON.parse(process.argv[2]));
    })
    .catch(() => {
      process.exitCode = 1;
      if (process.connected) process.disconnect();
    });
}
