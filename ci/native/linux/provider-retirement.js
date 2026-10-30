import { spawn } from "node:child_process";
import {
  observationObject,
  observationDigest,
  requireObservation,
} from "../index.js";
import {
  linuxProviderFrames,
  writeLinuxProviderPipe,
} from "./provider-channel.js";
import {
  linuxProviderRootArguments,
  sameLinuxData as same,
} from "./provider-kernel.js";

/** One reviewed native operation, with a parked, independently read receiver.
 * A recovery worker in a different PID namespace cannot resolve the original
 * PID. This control helper runs in the controller namespace, holds a pidfd
 * before acknowledgement and has no payload, provider or arbitrary command API.
 * All payloads continue to use the ordinary owned namespace supervisor. */
export async function retireLinuxProviderIdentity(
  identity,
  session,
  { kernel, tool, options },
  { signal, persist },
) {
  requireObservation(!signal?.aborted);
  const all = await kernel.processes(),
    live = all.find((item) => item.pid === identity.pid);
  if (!live)
    return kernel.absent(identity, {
      pid: { identity: identity.namespaceId, label: identity.namespaceId },
    });
  requireObservation(
    same(live.identity, identity.identity) &&
      live.namespaceId === identity.namespaceId &&
      live.nspid.at(-1) === 1,
  );
  const image = await tool(session, session.launch.gate);
  await tool(session, "/usr/bin/sudo");
  await tool(session, "/usr/bin/env");
  const args = linuxProviderRootArguments(
    session.launch.gate,
    "--retire",
    String(live.pid),
    live.identity.startTicks,
    live.identity.bootId,
  );
  await persist({
    phase: "linux-provider-recovery-retirement-possible",
    identity,
    args,
  });
  requireObservation(!signal?.aborted);
  const child = (options.retirementSpawn ?? spawn)("/usr/bin/sudo", args, {
    cwd: session.launch.directory,
    env: {
      PATH: "/usr/bin:/bin",
      LANG: "C",
      CI: "true",
      GITHUB_ACTIONS: "true",
    },
    stdio: ["ignore", "ignore", "ignore", "pipe", "pipe"],
    shell: false,
  });
  let resolveClose,
    rejectClose,
    settled = false;
  const completion = new Promise((resolve, reject) => {
    resolveClose = resolve;
    rejectClose = reject;
  });
  completion.catch(() => {});
  child.once("error", rejectClose);
  child.once("close", (code, terminationSignal) => {
    settled = true;
    resolveClose({ code, signal: terminationSignal });
  });
  const frames = linuxProviderFrames(child.stdio[4]),
    stop = () => child.stdio[3].destroy();
  signal?.addEventListener("abort", stop, { once: true });
  // Closing this private admission descriptor makes the fixed native helper
  // exit without sending a signal. An absent/malformed receiver never gets R.
  const deadline = AbortSignal.timeout(30000),
    operation = AbortSignal.any([deadline, ...(signal ? [signal] : [])]);
  operation.addEventListener("abort", stop, { once: true });
  try {
    const frame = await Promise.race([
      frames.take(operation),
      completion.then(() => {
        throw new Error("Retirement receiver exited before acknowledgement");
      }),
    ]);
    observationObject(frame, [
      "phase",
      "pid",
      "targetPid",
      "startTicks",
      "bootId",
    ]);
    requireObservation(
      frame.phase === "retirement-held" &&
        frame.targetPid === live.pid &&
        frame.startTicks === live.identity.startTicks &&
        frame.bootId === live.identity.bootId,
    );
    const receiver = await kernel.process(frame.pid),
      controller = await kernel.process(options.pid ?? process.pid);
    const tree = new Set([child.pid]);
    for (let size = -1; size !== tree.size;) {
      size = tree.size;
      for (const item of await kernel.processes())
        if (tree.has(item.parent)) tree.add(item.pid);
    }
    requireObservation(
      tree.has(receiver.pid) &&
        receiver.namespaceId === controller.namespaceId &&
        receiver.authority.uid === 0,
    );
    const argv = (await kernel.fs.readFile(`/proc/${receiver.pid}/cmdline`))
      .toString("utf8")
      .split("\0")
      .filter(Boolean);
    requireObservation(
      same(argv, [
        session.launch.gate,
        "--retire",
        String(live.pid),
        live.identity.startTicks,
        live.identity.bootId,
      ]),
    );
    const actual = await kernel.fs.stat(`/proc/${receiver.pid}/exe`, {
        bigint: true,
      }),
      held = await image.held.handle.stat({ bigint: true });
    requireObservation(
      actual.dev === held.dev &&
        actual.ino === held.ino &&
        same((await kernel.process(live.pid)).identity, identity.identity),
    );
    await persist({
      phase: "linux-provider-recovery-retirement-held",
      identity,
      receiver,
      nativeEventSha256: observationDigest({
        frame,
        receiver,
        image: image.sha256,
      }),
    });
    requireObservation(!operation.aborted);
    await writeLinuxProviderPipe(child.stdio[3], "R");
    child.stdio[3].end();
    let interrupted;
    const interruption = new Promise((_, reject) => {
      interrupted = () =>
        reject(new Error("Retirement completion interrupted"));
      operation.addEventListener("abort", interrupted, { once: true });
      if (operation.aborted) interrupted();
    });
    let result;
    try {
      result = await Promise.race([completion, interruption]);
    } finally {
      operation.removeEventListener("abort", interrupted);
    }
    requireObservation(
      result.code === 0 &&
        result.signal === null &&
        (await frames.settle()).length === 0,
    );
    await kernel.absent(receiver);
    return kernel.absent(identity, {
      pid: { identity: identity.namespaceId, label: identity.namespaceId },
    });
  } finally {
    signal?.removeEventListener("abort", stop);
    operation.removeEventListener("abort", stop);
    child.stdio[3].destroy();
    if (!settled) completion.catch(() => {});
  }
}
