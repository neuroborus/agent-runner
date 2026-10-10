import {
  observationObject,
  observationDigest,
  requireObservation,
  nativePolicyLaunchData,
} from "../index.js";
import {
  digest,
  DARWIN_LITERAL_ARGUMENTS,
  normalizeDarwinIdentity,
  sameDarwinIdentity,
} from "./protocol.js";
import { runDarwinFileSession, normalizeDarwinFileInput } from "./files.js";
import { normalizeDarwinFileIdentity } from "./files-protocol.js";

const same = (a, b) => observationDigest(a) === observationDigest(b);
const names = ["base", "root", "allocation", "leaf", "temporary"];
const stateOf = (message) =>
  Object.fromEntries([...names, "alias"].map((key) => [key, message[key]]));

/** The proof owners consume native object and process reads, never a verdict
 * supplied by the fixture. Only the sealed owner mutates the private objects. */
export function createDarwinFileEffects(core) {
  const {
    current,
    reader,
    specification,
    persist,
    recover,
    witness,
    born,
    retire,
    latch,
  } = core;
  const input = normalizeDarwinFileInput(current.input),
    slots = specification.slots;
  observationObject(slots, ["base", "root", "outside", "alias", "volume"]);
  requireObservation(
    slots.base === 1 &&
      specification.entries[slots.root]?.path ===
        input.request.custody + "/files",
  );
  let channel,
    publishers,
    concurrentReader,
    control,
    cleanupRecoveryPin,
    outside = core.recovered?.history.find(
      ({ record }) => record.kind === "file-outside",
    )?.record.sha256;
  const reads = [];
  const requestSha256 = digest(JSON.stringify(input));
  const view = () => reader.operation("file-view", slots.root, slots.base);
  const foreign = async () => {
    const files = await reader.tree(slots.outside);
    requireObservation(files.length > 0);
    return observationDigest(files);
  };
  const checked = async () => {
    const actual = await foreign();
    outside ??= actual;
    requireObservation(actual === outside);
    return actual;
  };
  const evidence = async (raw) => {
    const value = {
      ...raw,
      independent: true,
      verifier: await witness(),
      requestSha256,
      nativeEventSha256: observationDigest(raw),
    };
    value.receiptSha256 = (await persist(value)).receiptSha256;
    return value;
  };
  const settlement = async (helper, extra = {}) => {
    if (channel && sameDarwinIdentity(channel.admission.helper, helper))
      await channel.completion;
    const actual = await reader.retired(helper);
    const empty = await reader.verifyOwnership(0);
    requireObservation(
      empty.enumeration.live.length === 0 &&
        empty.enumeration.zombies.length === 0,
    );
    return evidence({
      ...extra,
      helper,
      uid: input.request.uid,
      noLiveUid: true,
      helpersSettled: true,
      actual,
    });
  };
  const worker = async (identity) => {
    await born(identity, {
      sha256: current.declared.custody.reader.sha256,
      cdhash: current.declared.custody.reader.cdhash,
    });
    await reader.rootDomain(identity);
    return identity;
  };
  const volume = async (mode) => {
    observationObject(slots.volume, ["tool", "image", "cdhash"]);
    await persist({ kind: "volume-possible", mode });
    const owner = await worker(
      await reader.operation(
        "file-volume-start",
        slots.volume.tool,
        slots.volume.image,
        slots.volume.cdhash,
        mode,
      ),
    );
    const identity = await reader.operation("file-volume-worker");
    await born(identity, {
      sha256: specification.entries[slots.volume.tool].sha256,
      cdhash: slots.volume.cdhash,
    });
    requireObservation(
      (await reader.operation("file-volume-run")).exitCode === 0,
    );
    await reader.retired(identity);
    const finished = await reader.operation("file-volume-finish");
    requireObservation(finished.reaped === true);
    if (mode === 1)
      requireObservation(same(finished.mountpoint, control.mountpoint));
    await reader.retiredRootDomain(owner);
  };
  const fileEffects = (cleanup = false) => ({
    persist,
    review: latch(async (value) => {
      requireObservation(
        same(value, input) &&
          specification.approval.sha256 === input.reviewSha256,
      );
      await checked();
      return {
        approvedSha256: requestSha256,
        reviewSha256: input.reviewSha256,
      };
    }, cleanup),
    open: latch(async (value) => {
      requireObservation(same(value, input));
      await persist({ kind: "file-possible", inputSha256: requestSha256 });
      const verifier = await witness(),
        authority = await reader.operation("operation-authority");
      requireObservation(authority.noLiveUid && authority.sandboxed === false);
      channel = await reader.openFile(input, {
        helperIndex: 5,
        rootIndex: slots.root,
        baseIndex: slots.base,
        ...(cleanupRecoveryPin ? { recoveryPin: cleanupRecoveryPin } : {}),
        authority: {
          context: current.binding.context,
          base: input.base,
          root: input.root,
          held: true,
          exclusive: true,
          independent: true,
          verifier,
          verifierSha256: current.declared.custody.reader.sha256,
          nativeEventSha256: observationDigest(authority),
        },
      });
      core.subjects.push(channel.admission.helper);
      await persist({ kind: "file-admitted", admission: channel.admission });
      return channel;
    }, cleanup),
    retire: latch(async (value, record) => {
      requireObservation(same(value, input));
      return settlement(record.admission.helper);
    }, true),
    readRecovery: latch(async (pin) => {
      const record = await recover(pin);
      requireObservation(
        record.requestSha256 === requestSha256 &&
          record.candidateSha === input.request.candidateSha &&
          record.nonce === input.request.nonce &&
          record.admission,
      );
      const operation =
        record.events
          .filter(
            (event) =>
              event.operation &&
              ["publish", "replace", "cleanup", "inspect"].includes(
                event.operation.type,
              ),
          )
          .at(-1)?.operation.type ?? "inspect";
      requireObservation(
        ["publish", "replace", "cleanup", "inspect"].includes(operation),
      );
      return {
        ...record,
        status: record.status === "RUNNING" ? "INTERRUPTED" : record.status,
        operation,
        independent: true,
        receiptSha256: pin,
        stateSha256: digest(JSON.stringify(record.state)),
      };
    }, cleanup),
    verifyRetirement: latch(async (value, prior) => {
      requireObservation(same(value, input));
      return settlement(prior.admission.helper, {
        recoverySha256: prior.receiptSha256,
      });
    }, true),
  });
  const effects = {
    persist,
    fileEffects: latch(() => fileEffects()),
    observe: latch(async (value, message) => {
      requireObservation(same(value, input));
      const objects = await view();
      observationObject(objects, names);
      for (const name of names) {
        if (message[name] === null) requireObservation(objects[name] === null);
        else {
          const object = objects[name];
          requireObservation(
            normalizeDarwinFileIdentity(object?.identity) === message[name] &&
              object.namedIdentity === message[name],
          );
        }
      }
      if (concurrentReader && message.phase === "complete") {
        const read = await reader.operation("file-reader-read");
        reads.push({ ...read, nativeEventSha256: observationDigest(read) });
      }
      return evidence({
        objects,
        parentAuthority: true,
        candidateSha: input.request.candidateSha,
        nonce: input.request.nonce,
        policySha256: input.request.bindings.policy,
        outsideBeforeSha256: await checked(),
        outsideAfterSha256: await checked(),
        timedOut: false,
      });
    }),
    verifyRetirement: latch(async (value, session) => {
      requireObservation(same(value, input));
      return settlement(session.result.admission.helper, {
        sessionReceiptSha256: session.receiptSha256,
      });
    }, true),
    privateProbe: latch(async (value, message) => {
      requireObservation(same(value, input));
      await persist({ kind: "probe-possible", allocation: message.allocation });
      const identity = normalizeDarwinIdentity(
        await reader.operation("file-probe-start", slots.root),
      );
      core.subjects.push(identity);
      await persist({ kind: "probe-admitted", identity });
      requireObservation(
        sameDarwinIdentity(await reader.process(identity.pid), identity),
      );
      const result = await reader.operation("file-probe-finish");
      await reader.retired(identity, { reserved: true });
      return evidence({
        ...result,
        identity,
        uid: input.request.uid,
        allocation: message.allocation,
        ready: true,
        reachable: true,
        attempted: true,
        timedOut: false,
      });
    }),
    startPublishers: latch(async (value, message, requests) => {
      requireObservation(
        same(value, input) &&
          same(
            requests.map(({ bytes }) => bytes),
            ["006f6c64ff", "006e657700ff", "7365636f6e64"],
          ),
      );
      await persist({ kind: "publishers-possible" });
      const identities = await reader.operation("file-publishers-start");
      requireObservation(Array.isArray(identities) && identities.length === 3);
      for (const identity of identities) await worker(identity);
      const actual = await reader.operation("file-publishers-ack");
      requireObservation(
        same(
          actual,
          requests.map(({ bytes }) => bytes),
        ),
      );
      publishers = await evidence({
        ready: true,
        overlapped: true,
        reviewSha256: input.reviewSha256,
        allocation: message.allocation,
        requests: identities.map((identity, index) => ({
          identity,
          bytes: actual[index],
          acknowledged: true,
          nativeEventSha256: observationDigest({
            identity,
            bytes: actual[index],
          }),
        })),
      });
      return publishers;
    }),
    finishPublishers: latch(async (value, prior, message) => {
      requireObservation(same(value, input) && same(prior, publishers));
      requireObservation(
        (await reader.operation("file-publishers-finish")).reaped === true,
      );
      for (const { identity } of prior.requests)
        await reader.retiredRootDomain(identity);
      const result = await evidence({
        complete: true,
        settled: true,
        timedOut: false,
        publishersReceiptSha256: prior.receiptSha256,
        requests: prior.requests.map((item, index) => ({
          ...item,
          leaf: message.leaf,
          outcome: index ? "exists" : "complete",
        })),
      });
      publishers = null;
      return result;
    }, true),
    startReader: latch(async (value) => {
      requireObservation(same(value, input));
      await persist({ kind: "reader-possible" });
      const identity = await worker(
        await reader.operation("file-reader-start", slots.root),
      );
      concurrentReader = await evidence({
        identity,
        ready: true,
        reviewSha256: input.reviewSha256,
      });
      const read = await reader.operation("file-reader-read");
      reads.push({ ...read, nativeEventSha256: observationDigest(read) });
      return concurrentReader;
    }),
    finishReader: latch(async (value, prior) => {
      requireObservation(same(value, input) && same(prior, concurrentReader));
      requireObservation(
        (await reader.operation("file-reader-finish")).reaped === true,
      );
      await reader.retiredRootDomain(prior.identity);
      const result = await evidence({
        reader: prior.identity,
        readerReceiptSha256: prior.receiptSha256,
        ready: true,
        overlapped: true,
        complete: true,
        dropped: false,
        timedOut: false,
        settled: true,
        candidateSha: input.request.candidateSha,
        nonce: input.request.nonce,
        reads,
      });
      concurrentReader = null;
      return result;
    }, true),
    applyControl: latch(async (kind, value, barrier) => {
      requireObservation(same(value, input) && !control);
      const before = await view(),
        parent = ["parent", "cross-volume"].includes(kind),
        othersSha256 = observationDigest(before.temporary);
      await persist({
        kind: "control-possible",
        control: kind,
        barrier,
        before,
      });
      let applied = await reader.operation(
          "file-control-start",
          slots.root,
          kind,
        ),
        mountpoint;
      if (kind === "cross-volume") {
        requireObservation(
          applied.prepared === true && applied.mountpoint.kind === "directory",
        );
        mountpoint = applied.mountpoint;
        await persist({ kind: "mountpoint", object: mountpoint });
        await volume(0);
        applied = await reader.operation("file-control-read");
      }
      requireObservation(observationDigest(applied.temporary) === othersSha256);
      const { temporary, ...objects } = applied;
      control = await evidence({
        control: kind,
        ready: true,
        before: {
          object: parent ? before.allocation : before.leaf,
          othersSha256,
        },
        applied: { ...objects, othersSha256: observationDigest(temporary) },
        barrier,
        ...(mountpoint ? { mountpoint } : {}),
      });
      return control;
    }),
    observeDenial: latch(async (kind, value, barrier, prior, session) => {
      requireObservation(
        same(value, input) && same(prior, control) && kind === control.control,
      );
      await reader.retired(session.result.admission.helper);
      const after = await reader.operation("file-control-read");
      const { temporary, ...objects } = after;
      requireObservation(
        same(
          { ...objects, othersSha256: observationDigest(temporary) },
          prior.applied,
        ),
      );
      const outcome = await channel.completion;
      const decision =
        "reject-" +
        {
          parent: "identity",
          leaf: "identity",
          symlink: "symlink",
          hardlink: "hardlink",
          "cross-volume": "volume",
        }[kind];
      requireObservation(
        outcome.code === 126 &&
          outcome.signal === null &&
          outcome.decision === decision,
      );
      return evidence({
        ...prior,
        after: { ...objects, othersSha256: observationDigest(temporary) },
        helper: session.result.admission.helper,
        sessionReceiptSha256: session.receiptSha256,
        controlReceiptSha256: prior.receiptSha256,
        attempted: true,
        reachable: true,
        continued: true,
        timedOut: false,
        exitCode: outcome.code,
        signal: outcome.signal,
        candidateSha: input.request.candidateSha,
        nonce: input.request.nonce,
        barrierSha256: digest(JSON.stringify(barrier)),
        nativeDecision: outcome.decision,
        outsideBeforeSha256: await checked(),
        outsideAfterSha256: await checked(),
      });
    }, true),
    restoreControl: latch(async (kind, value, denial) => {
      requireObservation(
        same(value, input) &&
          kind === control?.control &&
          denial.controlReceiptSha256 === control.receiptSha256,
      );
      await reader.retired(denial.helper);
      if (kind === "cross-volume") await volume(1);
      requireObservation(
        (await reader.operation("file-control-restore")).restored === true,
      );
      const objects = await view(),
        restored = { ...stateOf(control.barrier), alias: false };
      for (const name of names)
        requireObservation(
          (objects[name]?.identity ?? null) === restored[name],
        );
      const result = await evidence({
        ownedOnly: true,
        foreignPreserved: true,
        controlReceiptSha256: control.receiptSha256,
        restoredStateSha256: digest(JSON.stringify(restored)),
      });
      control = null;
      return result;
    }, true),
    nameControl: latch(async (name, value, canonical) => {
      requireObservation(same(value, input));
      const pair = [
        ["Value", "value"],
        ["va\u0301lue", "v\u00e1lue"],
        ["../value", "value"],
      ].findIndex((pair) => same(pair, [name, canonical]));
      requireObservation(pair >= 0);
      const actual = await reader.operation("file-name", slots.alias, pair);
      requireObservation(
        actual.nativeIdentity === actual.aliasIdentity &&
          actual.beforeSha256 === actual.afterSha256,
      );
      return evidence({
        ...actual,
        suppliedName: name,
        canonicalName: canonical,
        nativeAliasObserved: true,
        rejectedBeforeCommand: true,
        ready: true,
        reachable: true,
        attempted: true,
        timedOut: false,
      });
    }),
  };
  return {
    effects,
    async prepare() {
      const actual = await reader.operation("operation-authority"),
        objects = await view();
      requireObservation(
        actual.noLiveUid &&
          actual.sandboxed === false &&
          objects.base.identity === input.base &&
          objects.root.identity === input.root &&
          objects.allocation === null,
      );
      await checked();
      await persist({ kind: "file-outside", sha256: outside });
      const policy = {
        launch: nativePolicyLaunchData(input.request, DARWIN_LITERAL_ARGUMENTS),
        policy: {
          kind: "darwin-files",
          base: { identitySha256: digest(objects.base.identity) },
          root: { identitySha256: digest(objects.root.identity) },
          authority: {
            uid: actual.identity.uid,
            gid: actual.identity.gid,
            sandboxed: actual.sandboxed,
          },
        },
      };
      return core.policy(policy, { actual, objects, outside });
    },
    async finish() {
      if (channel) {
        channel.close();
        await channel.completion;
      }
      requireObservation(!publishers && !concurrentReader);
      if (core.recovered) {
        const saved = core.history
          .filter(
            ({ record, pin }) =>
              record.control &&
              record.applied &&
              record.barrier &&
              record.ready &&
              !core.history.some(
                ({ record: later }) =>
                  later.ownedOnly && later.controlReceiptSha256 === pin.sha256,
              ),
          )
          .at(-1);
        if (saved) {
          const actual = await reader.operation(
            "file-control-rejoin",
            slots.root,
            saved.record.control,
          );
          const { temporary, ...objects } = actual;
          requireObservation(
            same(
              { ...objects, othersSha256: observationDigest(temporary) },
              saved.record.applied,
            ),
          );
          control = saved.record;
        } else
          requireObservation(
            core.history.findLastIndex(
              ({ record }) => record.kind === "control-possible",
            ) < core.history.findLastIndex(({ record }) => record.ownedOnly) ||
              !core.history.some(
                ({ record }) => record.kind === "control-possible",
              ),
          );
      }
      if (control) {
        await retire();
        if (control.control === "cross-volume") await volume(1);
        requireObservation(
          (await reader.operation("file-control-restore")).restored === true,
        );
        control = null;
      }
      const actual = await view();
      if (actual.allocation !== null) {
        const saved = core.history
          .filter(
            ({ record }) =>
              record.admission &&
              record.state?.allocation &&
              Array.isArray(record.events),
          )
          .at(-1);
        requireObservation(
          saved &&
            same(stateOf({ ...saved.record.state }), {
              base: input.base,
              root: input.root,
              allocation: actual.allocation.identity,
              leaf: actual.leaf?.identity ?? null,
              temporary: actual.temporary?.identity ?? null,
              alias:
                actual.leaf !== null &&
                actual.temporary !== null &&
                actual.leaf.identity === actual.temporary.identity,
            }),
        );
        await reader.retired(saved.record.admission.helper);
        cleanupRecoveryPin = saved.pin;
        const owner = fileEffects(true);
        const cleaned = await runDarwinFileSession(
          input,
          [
            { type: "cleanup", bytes: "" },
            { type: "finish", bytes: "" },
          ],
          {
            ...owner,
            async verify(message) {
              const objects = await view();
              for (const name of names)
                requireObservation(
                  (objects[name]?.identity ?? null) === message[name],
                );
              for (const name of ["leaf", "temporary"])
                if (objects[name]) {
                  const original = core.history.find(
                    ({ record }) =>
                      record.objects?.[name]?.identity ===
                      objects[name].identity,
                  )?.record.objects[name];
                  requireObservation(
                    original &&
                      original.bytes === objects[name].bytes &&
                      original.uid === objects[name].uid &&
                      original.gid === objects[name].gid &&
                      original.mode === objects[name].mode,
                  );
                }
              const pin = await persist({
                kind: "cleanup-read",
                message,
                objects,
                outside: await checked(),
              });
              return {
                independent: true,
                stateSha256: digest(JSON.stringify(stateOf(message))),
                receiptSha256: pin.receiptSha256,
                leafSha256: objects.leaf
                  ? digest(Buffer.from(objects.leaf.bytes, "hex"))
                  : null,
                temporarySha256: objects.temporary
                  ? digest(Buffer.from(objects.temporary.bytes, "hex"))
                  : null,
              };
            },
            barrier: async () => "continue",
          },
          { recovery: saved.pin.sha256 },
        );
        requireObservation(
          cleaned.status === "OBSERVED" &&
            cleaned.state.allocation === null &&
            cleaned.helperSettlementSha256,
        );
        cleanupRecoveryPin = null;
      }
      requireObservation((await view()).allocation === null);
      await checked();
    },
  };
}
