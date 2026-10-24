import { finished } from "node:stream/promises";
import {
  observationObject,
  observationDigest,
  requireObservation,
} from "../index.js";
import { linuxProviderBridgeArguments } from "./provider-launch.js";
import {
  linuxProviderFrames,
  writeLinuxProviderPipe,
} from "./provider-channel.js";
import {
  linuxProviderRootArguments,
  sameLinuxData as same,
} from "./provider-kernel.js";

const controls = [
  "transport",
  "credential-file",
  "credential-environment",
  "credential-process",
  "debug",
  "signal",
  "alternate-network",
  "alternate-ipc",
  "relay-loss",
  "bridge-loss",
];
const operations = {
  transport: "network",
  "credential-file": "read",
  "credential-environment": "read",
  "credential-process": "read",
  debug: "debug",
  signal: "signal",
  "alternate-network": "network",
  "alternate-ipc": "ipc",
};

/** Only these separately owned root processes receive transport authority.
 * Relay credentials are delivered by the existing credential custody owner,
 * after its fresh verification of the private receiving descriptor. */
export function createLinuxProviderTransport(session, effects) {
  const { kernel, guard, tool, members, retirePayload, RELAY, BRIDGE } =
      effects,
    receivers = new Map(),
    receipts = [],
    consumed = new Set(),
    sacrifices = new Set();
  let configurationSha256,
    wired = false,
    closed = false,
    retirement = null;
  const admit = (signal) => {
    guard(signal);
    requireObservation(!closed && !session.retiring && !session.payloadRetired);
  };
  const binding = () => ({
    candidateSha: session.spec.candidateSha,
    nonce: session.spec.nonce,
    configurationSha256,
  });
  const pipes = async (identity) => {
    const values = {};
    for (const fd of await kernel.fs.readdir(`/proc/${identity.pid}/fd`)) {
      const target = await kernel.fs.readlink(`/proc/${identity.pid}/fd/${fd}`);
      values[fd] = target;
    }
    requireObservation(
      ["0", "1", "2"].every((fd) =>
        /^(?:pipe|socket):\[[1-9][0-9]*\]$/u.test(values[fd]),
      ),
    );
    return values;
  };
  const find = async (worker, entry, networkId = null) => {
    requireObservation(worker.identity);
    const all = await kernel.processes(),
      tree = new Set([worker.identity.pid]);
    for (let old = -1; old !== tree.size;) {
      old = tree.size;
      for (const item of all) if (tree.has(item.parent)) tree.add(item.pid);
    }
    const candidates = [];
    for (const item of all.filter((item) => tree.has(item.pid))) {
      const argv = (await kernel.fs.readFile(`/proc/${item.pid}/cmdline`))
        .toString("utf8")
        .split("\0")
        .filter(Boolean);
      if (same(argv, [process.execPath, entry])) candidates.push(item);
    }
    requireObservation(candidates.length === 1);
    const actual = candidates[0];
    requireObservation(
      actual.authority.uid === 0 &&
        actual.namespaceId !== session.gateIdentity.namespaceId &&
        (networkId === null || actual.networkId === networkId),
    );
    const image = await tool(session, process.execPath),
      live = await kernel.fs.stat(`/proc/${actual.pid}/exe`, { bigint: true }),
      held = await image.held.handle.stat({ bigint: true });
    requireObservation(live.dev === held.dev && live.ino === held.ino);
    const env = (await kernel.fs.readFile(`/proc/${actual.pid}/environ`))
      .toString("utf8")
      .split("\0")
      .filter(Boolean);
    requireObservation(
      same(
        env.toSorted(),
        [
          "PATH=/usr/bin:/bin",
          "LANG=C",
          "CI=true",
          "GITHUB_ACTIONS=true",
        ].toSorted(),
      ),
    );
    const descriptors = await pipes(actual);
    requireObservation(
      same(await kernel.process(actual.pid), actual) &&
        same(await kernel.process(worker.identity.pid), worker.identity),
    );
    return {
      identity: actual,
      pipes: descriptors,
      envSha256: observationDigest(env),
    };
  };
  const start = async (role, signal, sacrificial = false) => {
    admit(signal);
    const entry = role === "relay" ? RELAY : BRIDGE;
    await tool(session, entry);
    await tool(session, process.execPath);
    await tool(session, "/usr/bin/sudo");
    await tool(session, "/usr/bin/env");
    const args =
      role === "relay"
        ? linuxProviderRootArguments(process.execPath, RELAY)
        : linuxProviderRootArguments(
            "/usr/bin/nsenter",
            ...linuxProviderBridgeArguments(
              process.execPath,
              BRIDGE,
              session.launch.gate,
              session.spec.nonce,
            ),
          );
    const stdio = [
      "pipe",
      "pipe",
      "pipe",
      "pipe",
      "pipe",
      ...(role === "bridge" ? [session.namespaces.net.handle.fd] : []),
    ];
    await session.persist({
      phase: "linux-provider-transport-possible",
      role,
      sacrificial,
      args,
      configurationSha256,
    });
    admit(signal);
    const worker = kernel.start("/usr/bin/sudo", args, {
      cwd: session.launch.directory,
      env: {
        PATH: "/usr/bin:/bin",
        LANG: "C",
        CI: "true",
        GITHUB_ACTIONS: "true",
      },
      stdio,
      signal,
      persist: session.persist,
    });
    const value = {
      role,
      worker,
      frames: linuxProviderFrames(worker.child.stdio[5]),
    };
    if (sacrificial) sacrifices.add(value);
    else receivers.set(role, value);
    const join = async (started) => {
      observationObject(started, ["phase", "pid"]);
      requireObservation(
        started.phase === role + "-ready" && Number.isSafeInteger(started.pid),
      );
      await worker.started;
      value.native = await find(
        worker,
        entry,
        role === "bridge" ? session.gateIdentity.networkId : null,
      );
      requireObservation(
        value.native.identity.nspid.at(-1) === started.pid &&
          ["3", "4"].every((fd) =>
            /^(?:pipe|socket):\[[1-9][0-9]*\]$/u.test(value.native.pipes[fd]),
          ) &&
          value.native.pipes["3"] !== value.native.pipes["4"],
      );
    };
    if (role === "bridge") {
      const gate = await value.frames.take(signal);
      observationObject(gate, ["phase", "nonce", "netInode"]);
      requireObservation(
        gate.phase === "bridge-loopback" &&
          gate.nonce === session.spec.nonce &&
          `net:[${gate.netInode}]` === session.namespaces.net.label,
      );
      // This reader observes the held namespace both before and after the
      // native gate acknowledges the sole loopback mutation.
      const held = await session.namespaces.net.handle.stat({ bigint: true });
      requireObservation(String(held.ino) === gate.netInode);
      admit(signal);
      await writeLinuxProviderPipe(worker.child.stdio[4], "R");
      await join(await value.frames.take(signal));
      admit(signal);
      worker.child.stdio[4].end(
        JSON.stringify({
          admitted: true,
          endpoint: session.spec.endpoint,
          nonce: session.spec.nonce,
          configurationSha256,
        }),
      );
      const ready = await value.frames.take(signal);
      observationObject(ready, ["nonce", "configurationSha256", "endpoint"]);
      requireObservation(
        ready.nonce === session.spec.nonce &&
          ready.configurationSha256 === configurationSha256 &&
          ready.endpoint === session.spec.endpoint,
      );
    } else {
      await join(await value.frames.take(signal));
    }
    value.nativeSha256 = observationDigest({
      ...value.native,
      configurationSha256,
      role,
    });
    await session.persist({
      phase: "linux-provider-transport-held",
      role,
      sacrificial,
      identity: value.native.identity,
      worker: worker.identity,
      pipes: value.native.pipes,
      nativeSha256: value.nativeSha256,
      configurationSha256,
    });
    admit(signal);
    return value;
  };
  const sameReceiver = (receiver, observed) =>
    same(receiver.native.identity, observed.identity) &&
    receiver.native.envSha256 === observed.envSha256 &&
    ["0", "1", "2", ...(receiver.role === "relay" ? ["4"] : [])].every(
      (fd) => receiver.native.pipes[fd] === observed.pipes[fd],
    );
  const verify = async () => {
    requireObservation(receivers.size === 2 && !closed);
    const relay = receivers.get("relay"),
      bridge = receivers.get("bridge"),
      freshRelay = await find(relay.worker, RELAY),
      freshBridge = await find(
        bridge.worker,
        BRIDGE,
        session.gateIdentity.networkId,
      );
    requireObservation(
      sameReceiver(relay, freshRelay) && sameReceiver(bridge, freshBridge),
    );
    const provider = await members(session);
    for (const current of provider) {
      const descriptors = await pipes(current);
      requireObservation(
        Object.values(descriptors).every(
          (target) =>
            ![relay.native.pipes["3"], relay.native.pipes["4"]].includes(
              target,
            ),
        ),
      );
    }
    const port = Number(new URL(session.spec.endpoint).port)
        .toString(16)
        .toUpperCase()
        .padStart(4, "0"),
      table = await kernel.text(`/proc/${bridge.native.identity.pid}/net/tcp`);
    const listeners = table
      .trim()
      .split("\n")
      .slice(1)
      .map((line) => line.trim().split(/\s+/u))
      .filter((item) => item[3] === "0A");
    requireObservation(
      listeners.length === 1 && listeners[0][1] === `0100007F:${port}`,
    );
    const socket = `socket:[${listeners[0][9]}]`,
      descriptors = await pipes(bridge.native.identity);
    requireObservation(Object.values(descriptors).includes(socket));
    const native = observationDigest({
      relay: relay.native,
      bridge: bridge.native,
      listener: {
        address: listeners[0][1],
        state: listeners[0][3],
        inode: listeners[0][9],
      },
      provider,
    });
    session.transportVerified = native;
    return {
      ...binding(),
      independent: true,
      packageSha256: session.spec.closureSha256,
      profile: session.spec.profile,
      endpoint: session.spec.endpoint,
      relayAdmitted: true,
      bridgeAdmitted: true,
      receiptsVerified: true,
      privatePipes: true,
      credentialCustodyProtected: true,
      providerHasNoCredential: true,
      environmentAllowlist: true,
      handleAllowlist: true,
      endpointExclusive: true,
      receivingPrincipalVerified: true,
      noInspection: true,
      noDebug: true,
      noSignalling: true,
      noFilesystemAccess: true,
      ownedChangesOnly: true,
      samePrivateNetworkNamespace: true,
      bridgeOutsidePayloadPidNamespace: true,
      credentialFreeBridge: true,
      fixedInheritedPipe: true,
      nativeSha256: native,
    };
  };
  const close = async () => {
    closed = true;
    for (const item of [...receivers.values(), ...sacrifices]) {
      item.worker.child.stdin.destroy();
      item.worker.child.stdio[4].destroy();
    }
  };
  const retire = () => {
    if (retirement) return retirement;
    retirement = (async () => {
      const payload = await retirePayload(session),
        results = [];
      for (const item of [...receivers.values(), ...sacrifices]) {
        const proof = await kernel.retire(item.worker);
        if (item.native) await kernel.absent(item.native.identity);
        results.push(proof);
      }
      const settlement = {
        ...binding(),
        independent: true,
        payloadsRetired: true,
        relayRetired: true,
        bridgeRetired: true,
        nativeSha256: observationDigest({ payload, results }),
      };
      await session.persist({
        phase: "linux-provider-transport-retired",
        settlement,
      });
      session.transportRetired = observationDigest(results);
      return settlement;
    })();
    retirement.catch(() => {
      retirement = null;
    });
    return retirement;
  };
  const requireSacrificialEOF = async (worker, signal) => {
    let unexpected = false;
    const output = worker.child.stdout,
      receive = (chunk) => {
        unexpected ||= chunk.length > 0;
      };
    output.on("data", receive);
    try {
      await finished(output, {
        signal,
        readable: true,
        writable: false,
        cleanup: true,
      });
    } finally {
      output.removeListener("data", receive);
    }
    requireObservation(!unexpected && output.readableEnded);
  };
  return {
    async review({ spec, invocation, policy, configurationSha256: sha }) {
      requireObservation(
        same(spec, session.spec) &&
          same(invocation, session.configuration.invocation) &&
          same(policy, session.bindings.relayPolicy),
      );
      configurationSha256 = sha;
      return {
        ...binding(),
        status: "MATCHED",
        independent: true,
        packageSha256: session.spec.closureSha256,
        reviewSha256: session.launch.reviewSha256,
      };
    },
    async admitTransport(role, context, ...rest) {
      requireObservation(
        context.configurationSha256 === configurationSha256 &&
          !receivers.has(role),
      );
      const signal = rest.at(-1)?.signal,
        value = await start(role, signal);
      const control = value.worker.child.stdio[4];
      control.bindingSha256 = observationDigest({
        identity: value.native.identity.identity,
        pipe: value.native.pipes["3"],
        role,
      });
      if (role === "bridge") {
        const relay = receivers.get("relay");
        requireObservation(relay && !wired);
        relay.worker.child.stdout.pipe(value.worker.child.stdin);
        value.worker.child.stdout.pipe(relay.worker.child.stdin);
        wired = true;
      }
      return {
        ...binding(),
        role,
        independent: true,
        admitted: true,
        receiptVerified: true,
        nativeSha256: value.nativeSha256,
        control,
      };
    },
    async verifyRelayCustody(receiver, context, { signal } = {}) {
      admit(signal);
      const relay = receivers.get("relay"),
        fresh = await find(relay.worker, RELAY);
      requireObservation(
        same(fresh, relay.native) &&
          receiver.control === relay.worker.child.stdio[4] &&
          context.configurationSha256 === configurationSha256 &&
          !receivers.has("bridge"),
      );
      await members(session);
      admit(signal);
      return {
        ...binding(),
        independent: true,
        privateControl: true,
        receivingPrincipalVerified: true,
        providerExcluded: true,
        bridgeExcluded: true,
        brokerUid: fresh.identity.authority.uid,
        controlSha256: receiver.control.bindingSha256,
        nativeEventSha256: observationDigest(fresh),
      };
    },
    async verifyTransport() {
      admit();
      requireObservation(!session.transportFailure);
      try {
        return await verify();
      } catch (error) {
        session.transportFailure = true;
        throw error;
      }
    },
    async controls(context, relay, bridge, { signal }) {
      admit(signal);
      requireObservation(
        context.configurationSha256 === configurationSha256 &&
          !session.transportFailure,
      );
      // A caller cannot catch a failed control and retry it into acceptance.
      session.transportFailure = true;
      observationObject(session.transportControls, controls);
      const cases = {};
      for (const id of controls) {
        const before = await effects.snapshot(session);
        let native;
        if (["relay-loss", "bridge-loss"].includes(id)) {
          // The actual relay worker waits for private admission. No secret is
          // delivered to a sacrificial worker. Its owned private channel must
          // close after independent retirement, not merely after a timeout.
          const role = id === "relay-loss" ? "relay" : "bridge";
          if (role === "bridge") {
            // A second listener in the primary namespace would be an alias.
            // Run the existing bridge entry parked on its own control pipe.
            const args = linuxProviderRootArguments(process.execPath, BRIDGE);
            await session.persist({
              phase: "linux-provider-transport-possible",
              role,
              sacrificial: true,
              args,
              configurationSha256,
            });
            admit(signal);
            const worker = kernel.start("/usr/bin/sudo", args, {
              cwd: session.launch.directory,
              env: {
                PATH: "/usr/bin:/bin",
                LANG: "C",
                CI: "true",
                GITHUB_ACTIONS: "true",
              },
              stdio: ["pipe", "pipe", "pipe", "pipe", "pipe"],
              signal,
              persist: session.persist,
            });
            const item = {
                role,
                worker,
                frames: linuxProviderFrames(worker.child.stdio[5]),
              },
              frames = item.frames;
            sacrifices.add(item);
            const started = await frames.take(signal);
            observationObject(started, ["phase", "pid"]);
            requireObservation(started.phase === "bridge-ready");
            await worker.started;
            item.native = await find(worker, BRIDGE);
            native = await kernel.retire(worker);
            await kernel.absent(item.native.identity);
            await requireSacrificialEOF(worker, signal);
          } else {
            const copy = await start("relay", signal, true);
            native = await kernel.retire(copy.worker);
            await kernel.absent(copy.native.identity);
            await requireSacrificialEOF(copy.worker, signal);
          }
        } else {
          const declaration = session.transportControls[id];
          observationObject(declaration, ["action", "expectedError"]);
          const action = structuredClone(declaration.action);
          requireObservation(action.operation === operations[id]);
          if (id === "transport")
            requireObservation(
              action.target === new URL(session.spec.endpoint).host,
            );
          if (["signal", "debug"].includes(id))
            requireObservation(action.target === "relay");
          if (id === "credential-environment")
            requireObservation(action.target === "relay-environment");
          if (id === "credential-process")
            requireObservation(action.target === "relay-memory");
          const policyBefore = await session.inventory();
          requireObservation(same(policyBefore, session.policyObserved));
          let outsideControl;
          if (
            ["relay", "relay-environment", "relay-memory"].includes(
              action.target,
            )
          ) {
            const held = receivers.get("relay").native.identity;
            requireObservation(
              same((await kernel.process(held.pid)).identity, held.identity),
            );
            const own = await members(session);
            requireObservation(
              !own.some((item) => item.nspid.at(-1) === held.pid),
            );
            if (action.target === "relay-environment") {
              const bytes = await kernel.fs.readFile(
                `/proc/${held.pid}/environ`,
              );
              outsideControl = observationDigest({
                identity: held,
                bytesSha256: observationDigest([...bytes]),
              });
              action.target = `/proc/${held.pid}/environ`;
            } else {
              outsideControl = observationDigest(held);
              action.target =
                action.target === "relay-memory"
                  ? `/proc/${held.pid}/mem`
                  : String(held.pid);
            }
          } else if (session.observer.hasOutsideControl(action.target))
            outsideControl = observationDigest(
              await session.observer.verifyOutsideControl(action.target),
            );
          else {
            const object = session.objects.get(action.target);
            if (object)
              outsideControl = observationDigest({
                identity: await kernel.inspect(object.held),
                bytes: observationDigest([...(await kernel.read(object.held))]),
              });
          }
          const observed = await session.observer.observeProbe(action, {
              signal,
            }),
            result = observed.result;
          requireObservation(
            same(await session.inventory(), policyBefore) &&
              Number.isInteger(declaration.expectedError) &&
              result.error === declaration.expectedError &&
              (id === "transport"
                ? result.result >= 0
                : outsideControl &&
                  result.result < 0 &&
                  [1, 2, 3, 13, 30, 101, 111, 113].includes(result.error)),
          );
          native = observationDigest({
            result,
            domain: session.domain,
            policyBefore,
            action,
            outsideControl,
            nativeEventSha256: observed.nativeEventSha256,
          });
        }
        requireObservation(same(before, await effects.snapshot(session)));
        cases[id] = {
          attempted: true,
          acknowledged: true,
          independent: true,
          expectedEffect: true,
          sentinelsUnchanged: true,
          nativeSha256: native,
        };
      }
      session.controlsComplete = true;
      session.transportFailure = false;
      return { ...binding(), independent: true, cases };
    },
    closeTransport: close,
    retire,
    async verifySettlement() {
      requireObservation(
        closed &&
          session.payloadRetired &&
          session.transportRetired &&
          !session.transportFailure,
      );
      requireObservation(receipts.every((item) => consumed.has(item)));
      for (const item of [...receivers.values(), ...sacrifices])
        requireObservation((await item.frames.settle()).length === 0);
      return {
        ...binding(),
        independent: true,
        ownedChangesOnly: true,
        restored: true,
        reservation: "RETAINED",
        nativeSha256: observationDigest({
          payload: session.payloadRetired,
          transport: session.transportRetired,
        }),
      };
    },
    async modelReceipts(spec, sessionId, ids, { signal }) {
      admit(signal);
      requireObservation(
        !signal?.aborted &&
          same(spec, session.spec) &&
          !session.transportFailure &&
          wired,
      );
      const relay = receivers.get("relay");
      requireObservation(sameReceiver(relay, await find(relay.worker, RELAY)));
      const matches = (item) =>
        spec.provider === "codex"
          ? item.threadId === sessionId && item.turnId === ids
          : ids.includes(item.messageId);
      for (;;) {
        relay.frames.assertHealthy();
        const result = receipts.filter(
          (item) => !consumed.has(item) && matches(item),
        );
        if (result.length && relay.frames.queued === 0) {
          requireObservation(
            sameReceiver(relay, await find(relay.worker, RELAY)),
          );
          relay.frames.assertHealthy();
          if (relay.frames.queued) continue;
          admit(signal);
          result.forEach((item) => consumed.add(item));
          return {
            ...binding(),
            independent: true,
            relaySha256: relay.nativeSha256,
            receipts: result,
          };
        }
        // Receipt traffic is read from the private pipe, not inferred from the
        // provider response. Waiting for its frame removes cross-pipe races.
        requireObservation(receipts.length < 32 && !closed);
        receipts.push(await relay.frames.take(signal));
      }
    },
  };
}
