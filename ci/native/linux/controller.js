import { ChildProcess } from "node:child_process";
import { writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";
import {
  spawnOwnedProcess,
  terminateOwnedProcess,
  resolveOwnedProcessLauncher,
  assertOwnedProcessLauncherProtected,
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
  let child;
  let launched = false;
  let closing = false;
  let fileOperation = null,
    denial = null;
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
    child = spawnOwnedProcess(
      config.fixture.launcher,
      fixtureArguments(config.fixture, config.output, config.nonce),
      {
        cwd: config.fixture.directory,
        env: { PATH: "/usr/bin:/bin", LANG: "C" },
        stdio: ["pipe", "pipe", "pipe"],
        resolveLauncher(cwd) {
          const launcher = resolveOwnedProcessLauncher(cwd);
          assertOwnedProcessLauncherProtected(launcher.file);
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
        },
      },
    );
    child.on("message", (message) => {
      if (message?.type === "native-fault-armed") helper.push(message);
    });
    child.stdin.on("error", () => commands.fail());
    let output = "";
    let byteCount = 0;
    let forwarding = Promise.resolve();
    child.stdout.setEncoding("utf8");
    child.stdout.on("data", (text) => {
      byteCount += Buffer.byteLength(text);
      if (byteCount > 65536) {
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
          forwarding.catch(() => commands.fail());
        } catch {
          commands.fail();
          void emergency();
        }
        output = output.slice(end + 1);
      }
    });
    child.stderr.on("data", (bytes) => {
      byteCount += bytes.length;
      if (byteCount > 65536) {
        commands.fail();
        void emergency();
      }
    });
    const completion = child.ownedCompletion;
    completion.catch(() => commands.fail());
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
        const result = await completion;
        if (
          (config.caseId === "argv" ||
            config.caseId === "file-helper" ||
            ACCESS_PROFILES.includes(config.caseId)) &&
          (result.outcome?.exitCode !== (denied ? 39 : 0) ||
            result.outcome?.type !== "close" ||
            (denied && result.outcome?.signal !== null))
        )
          throw new Error("Invalid literal argv completion");
        if (
          config.caseId === "cancel" &&
          (result.outcome?.signal !== "SIGKILL" ||
            result.outcome?.type !== "close")
        )
          throw new Error(
            "Cancellation did not observe the requested termination",
          );
        await forwarding;
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
  } catch {
    await emergency();
    await report({ type: "failed" }).catch(() => {});
    process.exitCode = 1;
  } finally {
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
  main(process.argv.slice(2)).catch(() => {
    process.stderr.write(
      "Linux proof controller unavailable; exclusion retained.\n",
    );
    process.exitCode = 1;
  });
}
