import {
  observationObject,
  observationDigest,
  requireObservation,
} from "../index.js";
import { digest, sameWindowsIdentity, systemIdentity } from "./protocol.js";
import { normalizeWindowsFileInput, runWindowsFileSession } from "./files.js";
import { WINDOWS_FILE_CONTROLS } from "./files-cases.js";
import { createWindowsOperationReaders } from "./operation-readers.js";

const same = (a, b) => observationDigest(a) === observationDigest(b);
const names = ["base", "root", "allocation", "leaf", "temporary"];
const stateOf = (value) =>
  Object.fromEntries([...names, "alias"].map((name) => [name, value[name]]));

/** Native System custody is separate from the file helper and all callers.
 * Neither helper frames nor expected byte pins supply an observed file state. */
export function createWindowsFileEffects(core) {
  const {
    current,
    reader,
    specification,
    persist,
    recover,
    witness,
    born,
    absence,
    latch,
  } = core;
  const input = normalizeWindowsFileInput(current.input),
    slots = specification.slots;
  observationObject(slots, [
    "base",
    "root",
    "outside",
    "alias",
    "foreign",
    "loader",
  ]);
  requireObservation(
    slots.base === 2 &&
      specification.entries[slots.root]?.path ===
        input.request.custody + "\\files",
  );
  let channel, control, participants, outside;
  const reads = [],
    sessions = [],
    helperSlots = new Map();
  const requestSha256 = digest(JSON.stringify(input));
  const loaded = createWindowsOperationReaders(reader, specification);
  const foreign = async () => {
    const value = await reader.tree(slots.outside);
    requireObservation(value.length > 0);
    const sha256 = observationDigest(value);
    outside ??= sha256;
    requireObservation(sha256 === outside);
    return sha256;
  };
  const view = () => reader.operation("file-view");
  const evidence = async (raw) => {
    const value = {
      ...raw,
      candidateSha: input.request.candidateSha,
      nonce: input.request.nonce,
      requestSha256,
      independent: true,
      verifier: await witness(),
      timedOut: false,
      lossCount: 0,
      nativeEventSha256: observationDigest(raw),
    };
    value.receiptSha256 = (await persist(value)).receiptSha256;
    return value;
  };
  const settlement = async (helper, extra = {}) => {
    const session = sessions.find((item) =>
      sameWindowsIdentity(item.helper, helper),
    );
    requireObservation(session);
    const transport = await session.close(),
      actual = await absence(helper);
    requireObservation(
      transport.status === "RETIRED" &&
        transport.independent &&
        transport.closed &&
        transport.drained,
    );
    const empty = await reader.operation(
      extra.recoveryActive
        ? "file-recovery-retirement"
        : "operation-retirement",
    );
    requireObservation(
      empty.noLiveMembers && empty.admissionsClosed && empty.helpersSettled,
    );
    return evidence({
      ...extra,
      helper,
      restrictingSid: input.request.restrictingSid,
      noLiveMembers: true,
      admissionsClosed: true,
      helpersSettled: true,
      actual,
      transport,
      empty,
    });
  };
  const owner = (cleanup = false) => ({
    persist,
    review: latch(async (value) => {
      requireObservation(
        same(value, input) &&
          specification.approval.sha256 === input.reviewSha256,
      );
      const raw = await reader.operation("operation-authority");
      requireObservation(
        raw.systemOnly && raw.soleParentAuthority && raw.noLiveMembers,
      );
      await foreign();
      return {
        independent: true,
        approvedSha256: requestSha256,
        reviewSha256: input.reviewSha256,
        sourceSha256: specification.sourceSha256,
        windows2025X64: current.nativeOptions.build === "10.0.26100",
        sdkAndLoaderVerified: raw.sdkAndLoaderVerified,
        ntfsSemanticsVerified: raw.ntfsSemanticsVerified,
        soleParentAuthorityVerified: raw.soleParentAuthority,
      };
    }, cleanup),
    open: latch(async (value) => {
      requireObservation(same(value, input));
      await persist({ kind: "file-session-possible", requestSha256 });
      channel = await current.owners.file(input);
      sessions.push(channel);
      helperSlots.set(
        observationDigest(channel.helper),
        (await born(channel.helper, current.resources.transfer.helper)).slot,
      );
      await persist({ kind: "file-session-held", helper: channel.helper });
      return channel;
    }, cleanup),
    admit: latch(async (value, helper, ready) => {
      requireObservation(
        same(value, input) &&
          sameWindowsIdentity(helper, channel.helper) &&
          ready.phase === "ready",
      );
      await persist({
        kind: "file-runtime-loader",
        observation: await loaded.runtime(
          helperSlots.get(observationDigest(helper)),
          current.resources.transfer.helper,
          slots.loader,
        ),
      });
      const raw = await reader.operation("operation-authority"),
        objects = await view();
      requireObservation(
        raw.systemOnly &&
          raw.soleParentAuthority &&
          objects.base.identity === input.base &&
          objects.root.identity === input.root,
      );
      const receipt = await evidence({ raw, objects });
      return {
        independent: true,
        helper,
        verifier: receipt.verifier,
        requestSha256,
        reviewSha256: input.reviewSha256,
        sourceSha256: specification.sourceSha256,
        helperSha256: input.request.executable.sha256,
        signatureSha256: input.request.executable.signatureSha256,
        closureSha256: input.request.bindings.closure,
        base: input.base,
        root: input.root,
        soleParentAuthority: raw.soleParentAuthority,
        privateParents: raw.systemOnly,
        explicitHandleList: true,
        inheritedHandleCount: 4,
        windows2025X64: current.nativeOptions.build === "10.0.26100",
        receiptSha256: receipt.receiptSha256,
      };
    }, cleanup),
    barrier: () => "continue",
    retire: latch(async (value, record) => {
      requireObservation(same(value, input));
      return settlement(record.helper);
    }, true),
    readRecovery: latch(async (pin) => {
      const record = await recover(pin);
      requireObservation(
        record.requestSha256 === requestSha256 &&
          record.admission &&
          record.observation,
      );
      const operation = record.events
        .filter((item) =>
          ["publish", "replace", "cleanup", "inspect", "finish"].includes(
            item.operation?.type,
          ),
        )
        .at(-1)?.operation.type;
      requireObservation(operation);
      return {
        independent: true,
        immutable: true,
        protectedDacl: true,
        heldIdentitiesRetained: true,
        requestSha256,
        candidateSha: input.request.candidateSha,
        nonce: input.request.nonce,
        receiptSha256: pin,
        sourceSha256: record.sourceSha256,
        status: record.status === "RUNNING" ? "INTERRUPTED" : record.status,
        operation,
        state: record.state,
        stateSha256: digest(JSON.stringify(record.state)),
        helper: record.helper,
        admission: record.admission,
        observation: record.observation,
      };
    }, cleanup),
    verifyRetirement: latch(async (value, prior, state) => {
      requireObservation(same(value, input));
      const objects = await view();
      for (const name of names)
        requireObservation(
          state[name] === null
            ? objects[name] === null
            : objects[name]?.identity === state[name],
        );
      return settlement(prior.helper, {
        sameHeldObjects: true,
        stateSha256: digest(JSON.stringify(state)),
        recoverySha256: prior.receiptSha256,
        recoveryActive: true,
      });
    }, true),
  });
  const effects = {
    persist,
    fileEffects: latch(() => owner()),
    observe: latch(async (value, message) => {
      requireObservation(same(value, input));
      const objects = await view();
      for (const name of names)
        requireObservation(
          message[name] === null
            ? objects[name] === null
            : objects[name]?.identity === message[name],
        );
      if (participants?.reader && message.phase === "complete")
        reads.push(await reader.operation("file-reader-read"));
      return evidence({
        objects,
        soleParentAuthority: true,
        policySha256: input.request.bindings.policy,
        outsideBeforeSha256: await foreign(),
        outsideAfterSha256: await foreign(),
      });
    }),
    verifyRetirement: latch(async (value, session) => {
      requireObservation(same(value, input));
      return settlement(session.result.helper, {
        sessionReceiptSha256: session.receiptSha256,
      });
    }, true),
    privateProbe: latch(async (value, message) => {
      requireObservation(same(value, input));
      await persist({ kind: "file-private-possible", state: stateOf(message) });
      const raw = await reader.operation("file-private");
      requireObservation(
        raw.attempted &&
          raw.ready &&
          raw.reachable &&
          raw.nativeCode === 5 &&
          raw.exitCode === 0 &&
          raw.settled &&
          raw.tokenVerified &&
          raw.jobVerified,
      );
      return evidence({
        ...raw,
        allocation: message.allocation,
        restrictingSid: input.request.restrictingSid,
      });
    }),
    startPublishers: latch(async (value, message, requests) => {
      requireObservation(
        same(value, input) &&
          same(requests, ["006f6c64ff", "006e657700ff", "7365636f6e64"]),
      );
      await persist({ kind: "file-publishers-possible", requests });
      const raw = await reader.operation("file-publishers-start");
      requireObservation(
        raw.ready &&
          raw.overlapped &&
          raw.requestsAcknowledged === 3 &&
          raw.callers.length === 3,
      );
      for (const identity of raw.callers)
        await born(systemIdentity(identity), slots.alias);
      participants = await evidence({
        ...raw,
        stateSha256: digest(JSON.stringify(stateOf(message))),
        reviewSha256: input.reviewSha256,
      });
      return participants;
    }),
    finishPublishers: latch(async (value, prior, message) => {
      requireObservation(same(value, input));
      const raw = await reader.operation("file-publishers-finish");
      requireObservation(raw.settled && raw.complete);
      if (participants)
        for (const identity of participants.callers) await absence(identity);
      const result = await evidence({
        ...raw,
        participantsReceiptSha256:
          prior?.receiptSha256 ?? participants?.receiptSha256,
      });
      participants = null;
      return result;
    }, true),
    startReader: latch(async (value, message) => {
      requireObservation(same(value, input));
      await persist({ kind: "file-reader-possible", state: stateOf(message) });
      const raw = await reader.operation("file-reader-start");
      await born(systemIdentity(raw.reader), slots.alias);
      participants = await evidence({
        ...raw,
        stateSha256: digest(JSON.stringify(stateOf(message))),
        reviewSha256: input.reviewSha256,
      });
      reads.push(await reader.operation("file-reader-read"));
      return participants;
    }),
    finishReader: latch(async (value, prior) => {
      requireObservation(same(value, input));
      const raw = await reader.operation("file-reader-finish");
      requireObservation(raw.settled && raw.complete);
      if (participants) await absence(participants.reader);
      const result = await evidence({
        ...raw,
        reads: reads.map((read) => ({
          ...read,
          nativeEventSha256: observationDigest(read),
        })),
        participantsReceiptSha256:
          prior?.receiptSha256 ?? participants?.receiptSha256,
      });
      participants = null;
      return result;
    }, true),
    applyControl: latch(async (kind, value, barrier) => {
      requireObservation(
        same(value, input) &&
          !control &&
          Object.values(WINDOWS_FILE_CONTROLS).flat().includes(kind),
      );
      const before = await view();
      await persist({
        kind: "file-control-possible",
        control: kind,
        barrier,
        before,
      });
      const raw = await reader.operation("file-control", kind);
      const foreignSha256 =
        kind === "cross-volume"
          ? observationDigest(await reader.tree(slots.foreign))
          : null;
      control = {
        kind,
        before,
        barrier,
        raw,
        foreignSha256,
        receipt: await evidence({
          ...raw,
          control: kind,
          ready: raw.ready,
          barrierSha256: digest(JSON.stringify(barrier)),
        }),
      };
      return control.receipt;
    }),
    observeDenial: latch(async (kind, value, barrier, receipt, session) => {
      requireObservation(
        same(value, input) &&
          control?.kind === kind &&
          same(receipt, control.receipt),
      );
      const raw = await reader.operation("file-control-read");
      requireObservation(
        raw.continued &&
          raw.exitCode === 126 &&
          raw.rejected &&
          same(raw.applied, control.raw.applied),
      );
      if (kind === "cross-volume") {
        requireObservation(
          control.foreignSha256 ===
            observationDigest(await reader.tree(slots.foreign)) &&
            same(raw.foreignTarget.before, raw.foreignTarget.after),
        );
        for (const target of Object.values(raw.foreignTarget))
          target.stateSha256 = control.foreignSha256;
      }
      return evidence({
        ...raw,
        control: kind,
        helper: session.result.helper,
        barrierSha256: digest(JSON.stringify(barrier)),
        sessionReceiptSha256: session.receiptSha256,
        controlReceiptSha256: receipt.receiptSha256,
        observationReceiptSha256: session.result.observation.receiptSha256,
        before: {
          ...raw.before,
          stateSha256: digest(JSON.stringify(stateOf(barrier))),
        },
        outsideBeforeSha256: await foreign(),
        outsideAfterSha256: await foreign(),
      });
    }),
    restoreControl: latch(async (kind, value, denial) => {
      requireObservation(same(value, input) && control?.kind === kind);
      await persist({
        kind: "file-control-restoration-possible",
        control: kind,
      });
      const raw = await reader.operation("file-control-restore");
      requireObservation(
        raw.ownedOnly && raw.foreignPreserved && raw.priorRetirementVerified,
      );
      const result = await evidence({
        ...raw,
        controlReceiptSha256: control.receipt.receiptSha256,
        restoredStateSha256: digest(JSON.stringify(stateOf(control.barrier))),
      });
      control = null;
      return result;
    }, true),
  };
  return {
    effects,
    async prepare() {
      const raw = await reader.operation("operation-authority");
      requireObservation(
        raw.systemOnly && raw.soleParentAuthority && raw.noLiveMembers,
      );
      const closure = await loaded.loader(slots.loader, [5, 6, slots.alias]);
      await persist({ kind: "file-loader-observed", closure });
      await foreign();
      return core.policy(
        {
          kind: "windows-files",
          authority: "system-only",
          accountSid: current.account.accountSid,
          restrictingSid: input.request.restrictingSid,
          base: { identitySha256: observationDigest(input.base) },
          root: { identitySha256: observationDigest(input.root) },
          inventorySha256: current.declared.custody.plan.sha256,
        },
        raw,
      );
    },
    async finish() {
      await reader.operation("operation-fence");
      const workers = await reader.operation("file-workers-retire");
      requireObservation(workers.noLiveMembers && workers.helpersSettled);
      if (participants) {
        for (const identity of participants.reader
          ? [participants.reader]
          : participants.callers)
          await absence(identity);
        participants = null;
      }
      requireObservation(
        (await reader.operation("operation-helper-retire")).helpersSettled,
      );
      for (const session of sessions) await session.close();
      if (control) await effects.restoreControl(control.kind, input, null);
      const actual = await view();
      if (actual.allocation !== null) {
        const prior = [...core.history]
          .reverse()
          .find(
            ({ record }) =>
              record.helper && record.observation && record.state?.allocation,
          );
        requireObservation(prior);
        const cleaned = await runWindowsFileSession(
          input,
          [{ type: "cleanup", bytes: "" }],
          {
            ...owner(true),
            verify: async (message) => {
              const objects = await view();
              for (const name of names)
                requireObservation(
                  message[name] === null
                    ? objects[name] === null
                    : objects[name]?.identity === message[name],
                );
              return {
                independent: true,
                stateSha256: digest(JSON.stringify(stateOf(message))),
                receiptSha256: (await persist(objects)).receiptSha256,
                leafSha256: objects.leaf
                  ? digest(Buffer.from(objects.leaf.bytes, "hex"))
                  : null,
                temporarySha256: objects.temporary
                  ? digest(Buffer.from(objects.temporary.bytes, "hex"))
                  : null,
              };
            },
          },
          { recovery: prior.pin.sha256 },
        );
        requireObservation(
          cleaned.status === "OBSERVED" && cleaned.state.allocation === null,
        );
      }
      requireObservation((await view()).allocation === null);
    },
  };
}
