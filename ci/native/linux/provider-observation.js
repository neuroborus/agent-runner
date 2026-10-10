import { getSystemErrorName } from "node:util";
import {
  observationObject,
  observationDigest,
  requireObservation,
  NATIVE_OBSERVER_LIMITS,
} from "../index.js";
import {
  createLinuxObserverDecoder,
  runLinuxToolObserver,
  linuxObserverConfiguration,
} from "./observer.js";
import { digest } from "./inspect.js";
import { sameLinuxData as same } from "./provider-kernel.js";
import { createLinuxProviderControls } from "./provider-controls.js";

export function linuxProviderObjectDigest(identity, selector) {
  return observationDigest({
    selector,
    ...Object.fromEntries(
      ["dev", "ino", "uid", "gid", "mode", "nlink"].map((key) => [
        key,
        identity[key],
      ]),
    ),
  });
}

/** The trace pipe is opened with the parked launch, not attached later. Native
 * records are resolved against a separate creation/object reader per window. */
export function createLinuxProviderObservation(session, effects) {
  const { kernel, snapshot, probe, retireParticipants, environment } = effects;
  let captured = false,
    ended = false,
    failed = null,
    remainder = "",
    bytes = 0,
    decoder,
    watermark,
    chain = Promise.resolve(),
    ready = false,
    restored = false;
  let endCapture, rejectCapture;
  const completion = new Promise((resolve, reject) => {
    endCapture = resolve;
    rejectCapture = reject;
  });
  completion.catch(() => {});
  const records = [],
    bindings = session.observationData.targets;
  const waiting = new Set();
  const notify = () => {
    for (const wake of [...waiting]) wake();
  };
  observationObject(session.observationData, [
    "targets",
    "pins",
    "outsideControls",
  ]);
  const outside = createLinuxProviderControls(
    session,
    kernel,
    effects.options,
    effects.guard,
  );
  requireObservation(
    Array.isArray(bindings) && bindings.length > 0 && bindings.length <= 192,
  );
  for (const item of bindings) {
    observationObject(item, [
      "routeId",
      "phase",
      "file",
      "selector",
      "opcode",
      "action",
    ]);
    requireObservation(
      ["control-permit", "control-deny", "tool"].includes(item.phase) &&
        session.objects.has(item.file),
    );
  }
  const bindingData = (item) => ({
    routeId: item.routeId,
    phase: item.phase,
    selector: item.selector,
    opcode: item.opcode,
    accessMask: null,
    filterId: null,
  });
  const objectIdentity = async (raw, process) => {
    const file = raw.target.startsWith("/")
      ? `/proc/${process.pid}/root${raw.target}`
      : /^fd:[0-9]+$/u.test(raw.target)
        ? `/proc/${process.pid}/fd/${raw.target.slice(3)}`
        : null;
    if (!file) return null;
    try {
      const stat = await kernel.fs.stat(file, { bigint: true });
      return Object.fromEntries(
        ["dev", "ino", "uid", "gid", "mode", "nlink"].map((key) => [
          key,
          String(stat[key]),
        ]),
      );
    } catch (error) {
      if (error.code === "ENOENT") return null;
      throw error;
    }
  };
  const health = () => {
    requireObservation(
      !failed && bytes > 0 && bytes <= NATIVE_OBSERVER_LIMITS.captureBytes,
    );
    return {
      complete: true,
      dropped: 0,
      truncated: 0,
      ambiguous: 0,
      overflow: false,
      bytes,
    };
  };
  const sentinel = async (file) =>
    observationDigest(
      (await snapshot(session)).filter((item) => item.file !== file),
    );
  const armTarget = async (item) => {
    const object = session.objects.get(item.file),
      identity = await kernel.inspect(object.held),
      value = await kernel.read(object.held);
    const control = outside.has(item.selector)
      ? await outside.verify(item.selector)
      : null;
    return {
      object,
      identity,
      sha256: control
        ? observationDigest({
            object: linuxProviderObjectDigest(identity, item.selector),
            socket: control.identity,
          })
        : linuxProviderObjectDigest(identity, item.selector),
      bytesSha256: digest(value),
      control,
    };
  };
  const barrier = async (signal) => {
    const receipt = await probe(
      session,
      { operation: "barrier", target: session.spec.nonce, data: "" },
      signal,
    );
    const count = () =>
      records.filter(
        ({ raw, before }) =>
          raw.opcode === "write" &&
          raw.target === "fd:6" &&
          before.pid === session.probeIdentity.pid,
      ).length;
    while (count() < receipt.sequence + 1) {
      requireObservation(!failed && !ended && !signal.aborted);
      await new Promise((resolve, reject) => {
        const wake = () => {
          waiting.delete(wake);
          signal.removeEventListener("abort", abort);
          resolve();
        };
        const abort = () => {
          waiting.delete(wake);
          reject(new Error("Provider trace barrier interrupted"));
        };
        waiting.add(wake);
        signal.addEventListener("abort", abort, { once: true });
      });
    }
    await chain;
    health();
    requireObservation(count() === receipt.sequence + 1);
  };
  const api = {
    get ready() {
      return ready;
    },
    initializeControls: outside.initialize,
    async targetDigest(item) {
      return (await armTarget(item)).sha256;
    },
    closeControls: outside.close,
    hasOutsideControl: outside.has,
    verifyOutsideControl: outside.verify,
    async observeProbe(action, { signal }) {
      requireObservation(captured && !ended && !failed);
      const opcodes = {
          read: ["open", "openat", "openat2"],
          signal: ["kill"],
          debug: ["ptrace"],
          network: ["connect"],
          ipc: ["connect"],
        }[action.operation],
        selector = ["signal", "debug"].includes(action.operation)
          ? "process:" + action.target
          : action.target;
      requireObservation(opcodes);
      decoder.select(selector);
      await barrier(signal);
      const offset = records.length,
        result = await probe(session, action, signal);
      await barrier(signal);
      const matched = records
        .slice(offset)
        .filter(
          ({ raw, before }) =>
            before.pid === session.probeIdentity.pid &&
            raw.target === selector &&
            opcodes.includes(raw.opcode),
        );
      requireObservation(matched.length === 1);
      const event = matched[0];
      requireObservation(
        [event.before, event.after].every(
          (identity) =>
            same(identity.identity, session.probeIdentity.identity) &&
            identity.namespaceId === session.domain.namespaceId,
        ) &&
          event.raw.result === result.result &&
          event.raw.errno ===
            (result.error ? getSystemErrorName(-result.error) : null),
      );
      return { result, nativeEventSha256: observationDigest(event) };
    },
    capture(pipe) {
      requireObservation(!captured);
      captured = true;
      decoder = createLinuxObserverDecoder(
        bindings.map((item) => item.selector),
      );
      watermark = createLinuxObserverDecoder(["fd:6"]);
      const fail = (error) => {
        failed ??= error;
        rejectCapture(failed);
        notify();
      };
      pipe.on("error", fail);
      pipe.on("data", (chunk) => {
        // Trace output consists only of bounded UTF-8 syscall metadata. Raw
        // read/write decoding discards pointers and never exposes buffers.
        try {
          bytes += chunk.length;
          requireObservation(bytes <= NATIVE_OBSERVER_LIMITS.captureBytes);
          remainder += chunk.toString("utf8");
          requireObservation(
            Buffer.byteLength(remainder) <= NATIVE_OBSERVER_LIMITS.captureBytes,
          );
          let end;
          while ((end = remainder.indexOf("\n")) >= 0) {
            const line = remainder.slice(0, end);
            remainder = remainder.slice(end + 1);
            const selected = decoder.line(line),
              checkpoint = watermark.line(line),
              raw = selected ?? checkpoint;
            if (!raw) continue;
            requireObservation(records.length < NATIVE_OBSERVER_LIMITS.events);
            // Begin the independent identity read as soon as the record arrives.
            // A short-lived or reused PID without this proof remains blocked.
            const reading = (async () => {
              const worker = await session.worker.started,
                level = worker.nspid.length - 1;
              const all = await kernel.processes(),
                tree = new Set([worker.pid]);
              for (let size = -1; size !== tree.size;) {
                size = tree.size;
                for (const item of all)
                  if (tree.has(item.parent)) tree.add(item.pid);
              }
              const matches = all.filter(
                (item) =>
                  tree.has(item.pid) &&
                  item.nspid[level] === raw.pid &&
                  item.nspid.length > level,
              );
              requireObservation(matches.length === 1);
              return {
                process: matches[0],
                object: selected ? await objectIdentity(raw, matches[0]) : null,
              };
            })();
            reading.catch(fail);
            chain = chain
              .then(async () => {
                const { process: before, object } = await reading,
                  after = await kernel.process(before.pid);
                requireObservation(
                  same(before.identity, after.identity) &&
                    before.namespaceId === after.namespaceId,
                );
                records.push({
                  raw: { ...raw, pid: before.pid },
                  before,
                  after,
                  object,
                });
                notify();
              })
              .catch(fail);
          }
        } catch (error) {
          fail(error);
        }
      });
      pipe.on("end", () => {
        ended = true;
        if (remainder) fail(new Error("Truncated provider trace"));
        else endCapture();
        notify();
      });
      pipe.on("close", () => {
        if (!ended) fail(new Error("Lost provider trace"));
      });
    },
    async drain() {
      requireObservation(session.payloadRetired && captured);
      await completion;
      await chain;
      if (!session.auditRetired) {
        decoder.finish();
        watermark.finish();
      }
      return health();
    },
    async observe(domain, plan, execute) {
      requireObservation(
        same(domain, session.launchDomain) && captured && !ended && !failed,
      );
      const selected = bindings.filter((item) =>
          plan.routes.some((route) => route.id === item.routeId),
        ),
        input = {
          plan,
          domain: session.domain,
          bindings: selected.map(bindingData),
          pins: session.observationData.pins,
        },
        configSha256 = observationDigest(linuxObserverConfiguration(input));
      let observerSha256, beforeSha256, installedSha256;
      const native = {
        persist: session.persist,
        async review(value, configurationSha256) {
          requireObservation(
            same(value, input) && configurationSha256 === configSha256,
          );
          const manifest = await effects.pinned(
            session.bindings.observationFile,
          );
          await kernel.close(manifest.held);
          requireObservation(
            input.pins.manifestSha256 === plan.reviewSha256 &&
              input.pins.imageSha256 ===
                session.images.get("/usr/bin/strace").sha256,
          );
          return {
            status: "MATCHED",
            candidateSha: plan.candidateSha,
            configurationSha256,
            ...input.pins,
            nativeSha256: manifest.sha256,
          };
        },
        async snapshot() {
          const current = await kernel.text(
              "/proc/sys/kernel/yama/ptrace_scope",
            ),
            sha256 = observationDigest({
              ptraceScope: current,
              scope: "owned-tracees-only",
            });
          beforeSha256 ??= sha256;
          installedSha256 = sha256;
          return {
            candidateSha: plan.candidateSha,
            nonce: plan.nonce,
            configurationSha256: configSha256,
            independent: true,
            ownedChangesOnly: true,
            exclusiveWriter: true,
            sha256,
          };
        },
        async admit() {
          requireObservation(!ready && !session.payloadReleased && !failed);
          observerSha256 = observationDigest({
            worker: session.worker.identity,
            pipe: session.tracePipeIdentity,
            configuration: configSha256,
          });
          return { observerSha256 };
        },
        async verifyAdmission() {
          requireObservation(
            !session.payloadReleased &&
              session.worker.identity &&
              session.tracePipeIdentity &&
              !failed,
          );
          await effects.members(session);
          return {
            candidateSha: plan.candidateSha,
            nonce: plan.nonce,
            configurationSha256: configSha256,
            domainSha256: plan.domainSha256,
            policySha256: plan.policySha256,
            ...input.pins,
            independent: true,
            protected: true,
            beforeProviderRelease: true,
            observerSha256,
          };
        },
        async arm(custody, binding, configurationSha256) {
          requireObservation(
            !ended &&
              !failed &&
              configurationSha256 === configSha256 &&
              custody.observerSha256 === observerSha256,
          );
          await chain;
          const item = selected.find((item) =>
            same(bindingData(item), binding),
          );
          requireObservation(item);
          const target = await armTarget(item),
            sentinels = await sentinel(item.file);
          return {
            candidateSha: plan.candidateSha,
            nonce: plan.nonce,
            configurationSha256,
            acknowledged: true,
            routeId: item.routeId,
            phase: item.phase,
            barrierSha256: observationDigest({
              identity: target.identity,
              routeId: item.routeId,
              phase: item.phase,
              sequence: records.length,
            }),
            offset: records.length,
            targetSha256: target.sha256,
            beforeSha256: target.bytesSha256,
            sentinelsSha256: sentinels,
          };
        },
        async control(custody, routeId, phase, { signal }) {
          const item = selected.find(
            (item) => item.routeId === routeId && item.phase === phase,
          );
          requireObservation(item?.action);
          const result = await probe(session, item.action, signal);
          requireObservation(
            phase === "control-permit"
              ? result.result >= 0 && result.error === 0
              : result.result < 0 &&
                  [1, 2, 13, 30, 101, 111, 113].includes(result.error),
          );
        },
        async collect(custody, binding, arm, { signal }) {
          // The acknowledgement and the syscall trace use separate pipes.
          // A second parked probe produces a native write watermark after the
          // operation, so stream scheduling cannot omit or move its records.
          await barrier(signal);
          const selected = records
            .slice(arm.offset)
            .filter(
              ({ raw }) =>
                raw.target === binding.selector &&
                raw.opcode === binding.opcode,
            );
          requireObservation(selected.length === 1);
          return { health: health(), records: selected.map(({ raw }) => raw) };
        },
        async bind(custody, raw, binding, arm) {
          const record = records.find((item) => item.raw.id === raw.id);
          requireObservation(
            record && record.before.namespaceId === session.domain.namespaceId,
          );
          const item = selected.find((item) =>
              same(bindingData(item), binding),
            ),
            target = await armTarget(item);
          requireObservation(target.sha256 === arm.targetSha256);
          if (
            !target.control &&
            (raw.target.startsWith("/") || /^fd:[0-9]+$/u.test(raw.target))
          ) {
            const actual = await objectIdentity(raw, record.after),
              expected = Object.fromEntries(
                ["dev", "ino", "uid", "gid", "mode", "nlink"].map((key) => [
                  key,
                  target.identity[key],
                ]),
              );
            if (raw.errno !== "ENOENT")
              requireObservation(
                same(record.object, expected) && same(actual, expected),
              );
            else requireObservation(record.object === null && actual === null);
          } else requireObservation(target.control);
          const creation = (value) => ({
            pid: value.pid,
            identity: value.identity,
            namespaceId: value.namespaceId,
          });
          let boundary;
          if (
            ["ENOENT", "ECONNREFUSED", "ENETUNREACH", "EHOSTUNREACH"].includes(
              raw.errno,
            )
          ) {
            const inventory = await session.inventory();
            requireObservation(
              session.policyObserved &&
                same(
                  {
                    ...inventory,
                    descriptors: session.policyObserved.descriptors,
                  },
                  session.policyObserved,
                ),
            );
            let controlSha256;
            if (target.control)
              controlSha256 = target.control.nativeEventSha256;
            else {
              requireObservation(
                raw.errno === "ENOENT" &&
                  ["open", "openat", "openat2"].includes(raw.opcode) &&
                  item.file === item.selector &&
                  target.bytesSha256 ===
                    digest(await kernel.read(target.object.held)),
              );
              let absent = false;
              try {
                await kernel.fs.lstat(
                  `/proc/${session.gateIdentity.pid}/root${item.selector}`,
                );
              } catch (error) {
                if (error.code === "ENOENT") absent = true;
                else throw error;
              }
              requireObservation(absent);
              controlSha256 = observationDigest({
                identity: target.identity,
                bytes: target.bytesSha256,
              });
            }
            boundary = {
              independent: true,
              outsideControlReady: true,
              completeInventory: true,
              objectSha256: target.sha256,
              domainSha256: input.plan.domainSha256,
              selector: binding.selector,
              nativeId: raw.id,
              controlSha256,
              nativeEventSha256: observationDigest({
                record,
                inventory: session.policyObserved,
                target: target.identity,
              }),
            };
          }
          return {
            independent: true,
            held: true,
            timeBound: true,
            nativeId: raw.id,
            selector: binding.selector,
            objectSha256: target.sha256,
            before: creation(record.before),
            after: creation(record.after),
            ...(boundary ? { boundary } : {}),
          };
        },
        async read(custody, event, arm) {
          const item = selected.find(
              (item) =>
                item.routeId === event.routeId && item.phase === event.phase,
            ),
            target = await armTarget(item),
            sentinels = await sentinel(item.file);
          const route = plan.routes.find((route) => route.id === item.routeId);
          return {
            eventSequence: event.sequence,
            routeId: event.routeId,
            phase: event.phase,
            targetSha256: target.sha256,
            barrierSha256: arm.barrierSha256,
            nonceSha256: route.nonceSha256,
            beforeSha256: arm.beforeSha256,
            afterSha256: target.bytesSha256,
            sentinelsBeforeSha256: arm.sentinelsSha256,
            sentinelsAfterSha256: sentinels,
            verifierSha256: observationDigest({
              identity: target.identity,
              nativeId: event.nativeId,
            }),
            independent: true,
          };
        },
        retirePayloads: () => retireParticipants(session),
        drain: () => api.drain(),
        async retireObserver() {
          requireObservation(
            session.payloadRetired &&
              (!session.transport || session.transportRetired) &&
              ended &&
              !failed,
          );
          await chain;
          session.auditRetired = {
            status: "RETIRED",
            independent: true,
            emergencyCleanup: false,
            noLiveMembers: true,
            drained: true,
            nativeEventSha256: observationDigest(health()),
          };
          await session.persist({
            phase: "linux-provider-audit-retired",
            health: health(),
            settlement: session.auditRetired,
          });
          return {
            candidateSha: plan.candidateSha,
            nonce: plan.nonce,
            domainSha256: plan.domainSha256,
            noLiveMembers: true,
            independent: true,
            observerSha256,
          };
        },
        async restore() {
          requireObservation(
            session.payloadRetired && session.auditRetired && !failed,
          );
          await outside.close();
          const actual = observationDigest({
            ptraceScope: await kernel.text(
              "/proc/sys/kernel/yama/ptrace_scope",
            ),
            scope: "owned-tracees-only",
          });
          requireObservation(
            actual === beforeSha256 && actual === installedSha256,
          );
          restored = true;
        },
        async verifySettlement() {
          requireObservation(restored && !failed && ended);
          return {
            candidateSha: plan.candidateSha,
            nonce: plan.nonce,
            domainSha256: plan.domainSha256,
            payloadsRetired: true,
            observersRetired: true,
            independent: true,
            verifierSha256: observationDigest(session.payloadRetired),
            beforeAuditSha256: beforeSha256,
            installedAuditSha256: installedSha256,
            restoredAuditSha256: beforeSha256,
            ownedChangesOnly: true,
            reservation: "RETAINED",
          };
        },
      };
      return runLinuxToolObserver(
        input,
        native,
        async (context) => {
          ready = true;
          return execute(context);
        },
        { env: environment },
      );
    },
  };
  return api;
}
