import { ChildProcess } from "node:child_process";
import { writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { StringDecoder } from "node:string_decoder";
import {
  createNativeDiagnosticWriter,
  withNativeDiagnostics,
} from "../diagnostics.js";
import {
  spawnOwnedProcess,
  terminateOwnedProcess,
  readProcessIdentity,
} from "../../../src/agents/index.js";
import { fixtureArguments } from "./confinement.js";
import {
  digest,
  processDetails,
  protectedReceipt,
  verifyLinuxRetirement,
} from "./inspect.js";
import { normalizeLinuxReceipt, sameLinuxIdentity } from "./protocol.js";
import { messageQueue, send } from "./channel.js";
import { ACCESS_PROFILES } from "./profiles.js";
import {
  resolveLinuxDiagnosticLauncher,
  linuxDiagnosticError,
  linuxControllerFailure,
} from "./diagnostics.js";
import { feasibilityFailureCause } from "../feasibility/index.js";
import {
  encodeLinuxFileRequest,
  normalizeLinuxFileControl,
  normalizeLinuxFileMessage,
} from "./files-protocol.js";

async function control(config) {
  const deadline = performance.now() + 30000;
  const commands = messageQueue(deadline);
  process.on("message", (message) => commands.push(message));
  const report = (message) =>
    send(process, { ...message, nonce: config.nonce });
  let diagnosticForwarding = Promise.resolve();
  const diagnosticOutput = (stream, bytes) => {
    if (!config.diagnostics) return;
    child?.[stream]?.pause();
    for (let offset = 0; offset < bytes.length; offset += 1024) {
      const hex = bytes.subarray(offset, offset + 1024).toString("hex");
      diagnosticForwarding = diagnosticForwarding.then(() =>
        report({
          type: "diagnostic",
          stream,
          hex,
        }),
      );
    }
    const resume = () => child?.[stream]?.resume();
    diagnosticForwarding.then(resume, resume);
  };
  const rawFailure = config.diagnostics
    ? createNativeDiagnosticWriter((bytes) => diagnosticOutput("stderr", bytes))
    : () => {};
  const drainDiagnostics = () =>
    diagnosticForwarding.catch((error) =>
      createNativeDiagnosticWriter()("linux-diagnostic-transport", {
        exception: error,
      }),
    );
  let child;
  let launched = false;
  let closing = false;
  let fileOperation = null,
    denial = null;
  let operation = "request-validation";
  let admitting = false;
  const nativeError = [];
  const emergency = async () => {
    // Release a pending registration callback before awaiting completion.
    commands.fail();
    if (child) {
      child.kill("SIGKILL");
      await child.ownedCompletion.catch(() => {});
    }
  };
  const timer = setTimeout(() => {
    void emergency().finally(() => process.exit(124));
  }, 30000);
  process.once("disconnect", () => {
    if (!closing) {
      commands.fail();
      void emergency().finally(() => process.exit(125));
    }
  });
  try {
    if (
      (config.caseId === "file-helper") !==
      (config.fixture.fileHelper === true)
    )
      throw new Error("Mismatched helper authority");
    const fileControl = normalizeLinuxFileControl(
      config.fixture.fileControl ?? null,
    );
    if (fileControl !== null && config.caseId !== "file-helper")
      throw new Error("Foreign file control");
    const receiptFile = path.join(
      config.fixture.directory,
      "evidence",
      config.caseId === "file-helper"
        ? `file-helper-${config.nonce}.json`
        : `${config.caseId}.json`,
    );
    const helper = messageQueue(deadline);
    operation = "owned-process-launch";
    child = withNativeDiagnostics(
      () =>
        spawnOwnedProcess(
          config.fixture.launcher,
          fixtureArguments(config.fixture, config.output, config.nonce),
          {
            cwd: config.fixture.directory,
            env: { PATH: "/usr/bin:/bin", LANG: "C" },
            stdio: ["pipe", "pipe", "pipe"],
            resolveLauncher(cwd) {
              const launcher = resolveLinuxDiagnosticLauncher(cwd);
              if (
                !launcher.isolatedNamespace ||
                launcher.hostSession ||
                launcher.file !== config.fixture.launcher
              )
                throw new Error("Namespace admission unavailable");
              // CI-only preload self-terminates this real supervisor after an ack.
              // The production supervisor and its registration protocol are intact.
              if (config.caseId === "supervisor-loss") {
                const index = launcher.arguments.indexOf("-e");
                if (index < 1) throw new Error("Unknown supervisor invocation");
                launcher.arguments = [
                  ...launcher.arguments.slice(0, index),
                  "--require",
                  config.fixture.fault,
                  ...launcher.arguments.slice(index),
                ];
              }
              return launcher;
            },
            async onProcess(pid, admission) {
              if (pid === null) return; // Never discard protected recovery evidence.
              admitting = true;
              const init = await processDetails(pid);
              const parent = await processDetails(process.pid);
              const launcherIdentity = await readProcessIdentity(child.pid);
              if (
                launcherIdentity === null ||
                !sameLinuxIdentity(init.identity, admission.processIdentity)
              )
                throw new Error("Admission identity unavailable");
              const receipt = normalizeLinuxReceipt({
                schemaVersion: 1,
                candidateSha: config.candidateSha,
                caseId: config.caseId,
                nonce: config.nonce,
                policyDigest: config.fixture.policyDigest,
                executableDigest: config.fixture.executableDigest,
                isolatedNamespace: true,
                hostSession: false,
                parentNamespaceId: parent.namespaceId,
                init: {
                  pid,
                  identity: init.identity,
                  namespaceId: init.namespaceId,
                  nspid: init.nspid,
                },
                launcher: { pid: child.pid, identity: launcherIdentity },
                controller: { pid: process.pid, identity: parent.identity },
                admission,
              });
              const bytes = JSON.stringify(receipt) + "\n";
              if (Buffer.byteLength(bytes) > 1048576)
                throw new Error("Oversized admission evidence");
              await writeFile(receiptFile, bytes, { flag: "wx", mode: 0o400 });
              const sha256 = digest(bytes);
              await protectedReceipt(receiptFile, sha256);
              await report({ type: "admitted", sha256 });
              const ack = await commands.take(
                (message) => message.type === "admission-ack",
              );
              if (ack.nonce !== config.nonce)
                throw new Error("Substituted admission acknowledgement");
              launched = true;
              admitting = false;
            },
          },
        ),
      config.diagnostics ? rawFailure : null,
    );
    child.on("message", (message) => {
      if (message?.type === "native-fault-armed") helper.push(message);
    });
    child.stdin.on("error", (error) => {
      rawFailure("linux-fixture-input", { exception: error });
      commands.fail();
    });
    child.once("close", (exitCode, signal) =>
      rawFailure("linux-fixture", { exitCode, signal }),
    );
    let output = "";
    let byteCount = 0;
    let forwarding = Promise.resolve();
    const decoder = new StringDecoder("utf8");
    const consume = (text) => {
      byteCount += Buffer.byteLength(text);
      if (byteCount > 65536) {
        rawFailure("linux-fixture-capture", { truncated: true, partial: true });
        commands.fail();
        void emergency();
        return;
      }
      output += text;
      let end;
      while ((end = output.indexOf("\n")) >= 0) {
        try {
          const message = JSON.parse(output.slice(0, end));
          if (!launched || message.nonce !== config.nonce)
            throw new Error("Payload preceded admission");
          if (message.phase === "denied") {
            if (fileControl === null || denial !== null)
              throw new Error("Undeclared native denial");
            denial = normalizeLinuxFileMessage(message, config.nonce);
            if (denial.operation !== fileOperation)
              throw new Error("Foreign denial operation");
          }
          forwarding = forwarding.then(() =>
            report({ type: "payload", message }),
          );
          forwarding.catch((error) => {
            rawFailure("linux-fixture-publication", { exception: error });
            commands.fail();
          });
        } catch (diagnosticError) {
          rawFailure("linux-fixture-parser", { exception: diagnosticError });
          commands.fail();
          void emergency();
        }
        output = output.slice(end + 1);
      }
    };
    child.stdout.on("data", (bytes) => {
      diagnosticOutput("stdout", bytes);
      consume(decoder.write(bytes));
    });
    child.stdout.on("end", () => consume(decoder.end()));
    child.stderr.on("data", (bytes) => {
      diagnosticOutput("stderr", bytes);
      byteCount += bytes.length;
      if (byteCount > 65536) {
        rawFailure("linux-fixture-capture", { truncated: true, partial: true });
        commands.fail();
        void emergency();
      } else nativeError.push(Buffer.from(bytes));
    });
    const completion = child.ownedCompletion;
    completion.catch((error) => {
      rawFailure("linux-fixture", { exception: error });
      commands.fail(
        linuxDiagnosticError(
          launched ? "controller" : "admission",
          admitting
            ? "receipt-registration"
            : launched
              ? "process-settlement"
              : "owned-process-admission",
          {
            ...error,
            stderr: Buffer.concat(nativeError),
          },
        ),
      );
    });
    operation = "payload-observation";
    while (true) {
      // The registration callback alone consumes the admission acknowledgement.
      const command = await commands.take(
        (message) => message.type !== "admission-ack",
      );
      if (command.nonce !== config.nonce)
        throw new Error("Substituted controller command");
      if (command.type === "file-command") {
        if (!launched || config.caseId !== "file-helper")
          throw new Error("File operation before protected admission");
        if (
          command.message.type === "check" &&
          !["magic-link", "mount"].includes(fileControl)
        )
          throw new Error("Alias probe without closed control");
        if (command.message.type !== "continue")
          fileOperation = command.message.type;
        child.stdin.write(encodeLinuxFileRequest(command.message));
      } else if (command.type === "payload-command") {
        if (
          !launched ||
          config.caseId === "file-helper" ||
          !["release", "reparent", "arm", "finish"].includes(
            command.message?.type,
          )
        )
          throw new Error("Invalid payload command");
        child.stdin.write(
          JSON.stringify({ ...command.message, nonce: config.nonce }) + "\n",
        );
      } else if (command.type === "helper-arm") {
        if (config.caseId === "supervisor-loss") {
          await send(child, { type: "native-fault-arm", nonce: config.nonce });
          const ack = await helper.take(() => true);
          if (ack.nonce !== config.nonce)
            throw new Error("Substituted helper acknowledgement");
        }
        await report({ type: "helper-armed" });
      } else if (command.type === "fault" || command.type === "file-denial") {
        if (!launched) throw new Error("Fault before admission");
        const denied = command.type === "file-denial";
        if (denied) {
          if (
            config.caseId !== "file-helper" ||
            fileControl === null ||
            denial === null ||
            JSON.stringify(command.message) !== JSON.stringify(denial)
          )
            throw new Error("Unbound native denial");
        } else if (config.caseId === "cancel") {
          if (child.exitCode !== null || child.signalCode !== null)
            throw new Error("Cancellation target already settled");
          await terminateOwnedProcess(child.ownedPid, async () => null);
        } else if (config.caseId === "supervisor-loss")
          await send(child, { type: "native-fault-fire", nonce: config.nonce });
        else if (config.caseId === "launcher-loss") {
          // Fault this owned live handle, never a numeric PID or process group.
          if (!ChildProcess.prototype.kill.call(child, "SIGKILL"))
            throw new Error("Launcher fault not applied");
        } else if (
          config.caseId !== "argv" &&
          config.caseId !== "file-helper" &&
          !ACCESS_PROFILES.includes(config.caseId)
        )
          throw new Error("Invalid controller fault");
        operation = "process-completion";
        const result = await completion;
        if (
          (config.caseId === "argv" ||
            config.caseId === "file-helper" ||
            ACCESS_PROFILES.includes(config.caseId)) &&
          (result.outcome?.exitCode !== (denied ? 39 : 0) ||
            result.outcome?.type !== "close" ||
            (denied && result.outcome?.signal !== null))
        )
          throw linuxDiagnosticError("controller", operation, {
            ...result.outcome,
            stderr: Buffer.concat(nativeError),
          });
        if (
          config.caseId === "cancel" &&
          (result.outcome?.signal !== "SIGKILL" ||
            result.outcome?.type !== "close")
        )
          throw linuxDiagnosticError("controller", operation, result.outcome);
        operation = "settlement-acknowledgement";
        await forwarding;
        await drainDiagnostics();
        await report({ type: "settled" });
        const acknowledgement = await commands.take(
          (message) => message.type === "settlement-ack",
        );
        if (acknowledgement.nonce !== config.nonce)
          throw new Error("Substituted settlement acknowledgement");
        break;
      } else if (command.type === "emergency") {
        await emergency();
        break;
      } else throw new Error("Unknown CI controller command");
    }
  } catch (error) {
    rawFailure("linux-fixture", { exception: error });
    const first = linuxDiagnosticError("controller", operation, error);
    let cleanupCause = child
      ? {
          code: "cleanup-unobserved",
          detail:
            "Emergency controller settlement has no independent retirement witness.",
        }
      : null;
    try {
      await emergency();
    } catch (failure) {
      rawFailure("linux-fixture-cleanup", { exception: failure });
      cleanupCause = {
        code: "cleanup-failed",
        detail: feasibilityFailureCause(
          "cleanup",
          "controller-emergency",
          failure,
        ).detail,
      };
    }
    const record = linuxControllerFailure(
      config.candidateSha,
      config.nonce,
      first,
      cleanupCause,
    );
    // The parent may stop this owner as soon as it observes failure.
    await drainDiagnostics();
    await report(record).catch((error) =>
      rawFailure("linux-fixture-failure-publication", { exception: error }),
    );
    process.exitCode = 1;
  } finally {
    await drainDiagnostics();
    clearTimeout(timer);
    closing = true;
    if (process.connected) process.disconnect();
  }
}

async function main(args) {
  // Deliberately CI-only. These entry points are never ordinary test discovery.
  if (
    process.platform !== "linux" ||
    process.env.CI !== "true" ||
    process.env.GITHUB_ACTIONS !== "true"
  )
    throw new Error("Linux proof requires system CI");
  if (args[0] === "--verify" && args.length === 3) {
    process.stdout.write(
      JSON.stringify(await verifyLinuxRetirement(args[1], args[2])) + "\n",
    );
  } else if (args[0] === "--control" && args.length === 2 && process.send) {
    await control(JSON.parse(args[1]));
  } else throw new Error("Invalid Linux proof entry point");
}

if (
  process.argv[1] &&
  path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  main(process.argv.slice(2)).catch((error) => {
    createNativeDiagnosticWriter()("linux-controller-entry", {
      exception: error,
    });
    process.stderr.write(
      "Linux proof controller unavailable; exclusion retained.\n",
    );
    process.exitCode = 1;
  });
}
