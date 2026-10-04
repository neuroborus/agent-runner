import { performance } from "node:perf_hooks";
import {
  dense,
  digest,
  hash,
  requireWindows,
  normalizeWindowsIdentity,
  sameWindowsIdentity,
  systemIdentity,
} from "./protocol.js";
import {
  normalizeWindowsFileIdentity,
  normalizeWindowsFileMessage,
} from "./files-protocol.js";
import { normalizeWindowsFileInput, runWindowsFileSession } from "./files.js";

export const WINDOWS_FILE_CASE_IDS = Object.freeze([
  "files.private",
  "files.publish",
  "files.replace",
  "files.substitution",
  "files.aliases",
  "files.cleanup",
]);
export const WINDOWS_FILE_CONTROLS = Object.freeze({
  "files.substitution": ["root", "parent", "junction", "symlink"],
  "files.aliases": ["case", "stream", "hardlink", "short-name", "cross-volume"],
});
for (const controls of Object.values(WINDOWS_FILE_CONTROLS))
  Object.freeze(controls);
export const WINDOWS_FILE_SESSION_LIMITS = Object.freeze({
  "files.private": 2,
  "files.publish": 2,
  "files.replace": 2,
  "files.substitution": 8,
  "files.aliases": 10,
  "files.cleanup": 9,
});
const OLD = "006f6c64ff",
  NEW = "006e657700ff",
  THIRD = "7365636f6e64";
const names = ["base", "root", "allocation", "leaf", "temporary"];
const stateOf = (value) =>
  Object.fromEntries([...names, "alias"].map((key) => [key, value[key]]));
const operation = (type, bytes = "") => ({ type, bytes });

function native(value, input) {
  const verifier = systemIdentity(value?.verifier);
  requireWindows(
    value.independent === true &&
      value.candidateSha === input.request.candidateSha &&
      value.nonce === input.request.nonce &&
      value.requestSha256 === digest(JSON.stringify(input)) &&
      value.timedOut === false &&
      value.lossCount === 0 &&
      hash(value.nativeEventSha256) &&
      hash(value.receiptSha256),
  );
  return verifier;
}

/** Native held/named reads are independent of helper frames. Two links are
 * admitted only for the exact recorded publication alias, never a third name. */
export function assertWindowsFileObservation(reply, view, value, expected) {
  const input = normalizeWindowsFileInput(value),
    message = normalizeWindowsFileMessage(reply, input.request.nonce);
  const verifier = native(view, input);
  requireWindows(
    message.base === input.base &&
      message.root === input.root &&
      view.soleParentAuthority === true &&
      view.policySha256 === input.request.bindings.policy &&
      hash(view.outsideBeforeSha256) &&
      view.outsideAfterSha256 === view.outsideBeforeSha256,
  );
  for (const key of names) {
    const object = view.objects?.[key],
      id = message[key],
      directory = !["leaf", "temporary"].includes(key);
    if (id === null) {
      requireWindows(object === null);
      continue;
    }
    requireWindows(
      normalizeWindowsFileIdentity(object.identity) === id &&
        object.namedIdentity === id &&
        object.ownerSid === "S-1-5-18" &&
        object.systemOnlyDacl === true &&
        object.protectedDacl === true &&
        object.noReparse === true &&
        object.canonicalName === true &&
        object.noShortAlias === true &&
        object.defaultStreamsOnly === true &&
        object.kind === (directory ? "directory" : "file") &&
        (directory
          ? object.caseSensitive === false && object.bytes === null
          : object.links === (message.alias ? 2 : 1) &&
            typeof expected[key] === "string" &&
            object.bytes === expected[key]),
    );
  }
  return verifier;
}

export function assertWindowsFileDenial(control, barrier, evidence, value) {
  const input = normalizeWindowsFileInput(value);
  requireWindows(Object.values(WINDOWS_FILE_CONTROLS).flat().includes(control));
  barrier = normalizeWindowsFileMessage(barrier, input.request.nonce);
  native(evidence, input);
  const target =
    control === "root"
      ? "root"
      : ["parent", "junction", "cross-volume"].includes(control)
        ? "allocation"
        : "leaf";
  const original = barrier[target],
    changed = evidence.applied;
  requireWindows(
    barrier.phase === "prepared" &&
      original !== null &&
      evidence.control === control &&
      evidence.barrierSha256 === digest(JSON.stringify(barrier)) &&
      evidence.attempted === true &&
      evidence.ready === true &&
      evidence.reachable === true &&
      evidence.continued === true &&
      evidence.exitCode === 126 &&
      evidence.signal === null &&
      evidence.before.identity === original &&
      evidence.before.stateSha256 ===
        digest(JSON.stringify(stateOf(barrier))) &&
      evidence.saved.identity === original &&
      evidence.saved.bytesSha256 === evidence.before.bytesSha256 &&
      hash(evidence.before.bytesSha256) &&
      hash(evidence.othersBeforeSha256) &&
      evidence.othersAfterSha256 === evidence.othersBeforeSha256 &&
      hash(evidence.outsideBeforeSha256) &&
      evidence.outsideAfterSha256 === evidence.outsideBeforeSha256 &&
      digest(JSON.stringify(evidence.after)) ===
        digest(JSON.stringify(changed)),
  );
  normalizeWindowsFileIdentity(changed.identity);
  if (target === "leaf")
    requireWindows(
      evidence.before.links === 1 &&
        evidence.before.bytesSha256 === digest(Buffer.from(OLD, "hex")),
    );
  if (["root", "parent"].includes(control))
    requireWindows(
      changed.identity !== original &&
        changed.kind === "directory" &&
        evidence.nativeDecision === "reject-identity",
    );
  else if (control === "cross-volume") {
    // A no-follow open sees the local mount point, never its foreign target.
    const foreign = evidence.foreignTarget;
    requireWindows(
      changed.identity !== original &&
        changed.identity.slice(0, 16) === input.root.slice(0, 16) &&
        changed.kind === "directory" &&
        ["junction", "volume-mount"].includes(changed.reparse) &&
        evidence.nativeDecision === "reject-reparse" &&
        normalizeWindowsFileIdentity(foreign?.before?.identity).slice(0, 16) !==
          input.root.slice(0, 16) &&
        foreign.before.kind === "directory" &&
        changed.targetIdentity === foreign.before.identity &&
        hash(foreign.before.stateSha256) &&
        digest(JSON.stringify(foreign.after)) ===
          digest(JSON.stringify(foreign.before)),
    );
  } else if (["junction", "symlink"].includes(control))
    requireWindows(
      changed.identity !== original &&
        changed.kind === (control === "junction" ? "directory" : "file") &&
        changed.reparse === control &&
        evidence.nativeDecision === "reject-reparse",
    );
  else {
    requireWindows(
      changed.identity === original &&
        changed.bytesSha256 === evidence.before.bytesSha256 &&
        evidence.nativeDecision === "reject-" + control,
    );
    if (control === "hardlink")
      requireWindows(changed.links === 2 && evidence.saved.links === 2);
    if (control === "stream") requireWindows(changed.streams === 2);
    if (control === "case") requireWindows(changed.name === "Value");
    if (control === "short-name")
      requireWindows(changed.alternateName === "VALUE~1");
  }
  return true;
}

export function assertWindowsReplacementReads(value, oldId, newId, input) {
  input = normalizeWindowsFileInput(input);
  const verifier = native(value, input),
    reader = systemIdentity(value.reader);
  requireWindows(
    normalizeWindowsFileIdentity(oldId).slice(0, 16) ===
      input.root.slice(0, 16) &&
      normalizeWindowsFileIdentity(newId).slice(0, 16) ===
        input.root.slice(0, 16) &&
      verifier.pid !== reader.pid &&
      oldId !== newId &&
      value.ready === true &&
      value.overlapped === true &&
      value.complete === true &&
      value.settled === true &&
      value.dropped === false &&
      value.oldHeld.identity === oldId &&
      value.oldHeld.bytes === OLD &&
      [0, 1].includes(value.oldHeld.links),
  );
  const reads = dense(value.reads, 4096),
    seen = new Set();
  requireWindows(reads.length >= 2);
  for (const read of reads) {
    requireWindows(
      read.code === 0 &&
        read.links === 1 &&
        hash(read.nativeEventSha256) &&
        ((read.identity === oldId && read.bytes === OLD) ||
          (read.identity === newId && read.bytes === NEW)),
    );
    seen.add(read.identity);
  }
  requireWindows(seen.size === 2);
  return reader;
}

/** External Windows cases use the existing admitted file session. Native
 * control/reader bridges and immutable receipts are required, never fixtures. */
export async function runWindowsFileCase(
  checkId,
  value,
  effects,
  {
    now = () => performance.now(),
    schedule = setTimeout,
    cancel = clearTimeout,
  } = {},
) {
  const input = normalizeWindowsFileInput(value);
  requireWindows(
    WINDOWS_FILE_CASE_IDS.includes(checkId) &&
      typeof effects?.persist === "function",
  );
  const record = {
    schemaVersion: 1,
    checkId,
    candidateSha: input.request.candidateSha,
    nonce: input.request.nonce,
    requestSha256: digest(JSON.stringify(input)),
    status: "BLOCKED",
    reservation: "RETAINED",
    missingInputs: [],
    sessions: [],
    observations: [],
  };
  const required = ["fileEffects", "observe", "verifyRetirement"];
  if (checkId === "files.private") required.push("privateProbe");
  if (checkId === "files.publish")
    required.push("startPublishers", "finishPublishers");
  if (checkId === "files.replace") required.push("startReader", "finishReader");
  if (WINDOWS_FILE_CONTROLS[checkId])
    required.push("applyControl", "observeDenial", "restoreControl");
  for (const key of required)
    if (typeof effects[key] !== "function")
      record.missingInputs.push("windows-file-case-" + key);
  const save = () => effects.persist(structuredClone(record));
  if (record.missingInputs.length) {
    await save();
    return record;
  }
  const started = now(),
    bytes = new Map();
  const bounded = () => {
    const elapsed = now() - started;
    requireWindows(
      Number.isFinite(elapsed) &&
        elapsed >= 0 &&
        elapsed < (WINDOWS_FILE_SESSION_LIMITS[checkId] + 1) * 90000,
    );
  };
  const wait = async (action) => {
    bounded();
    let rejectDeadline;
    const deadline = new Promise((_, reject) => {
      rejectDeadline = reject;
    });
    deadline.catch(() => {});
    const timer = schedule(
      () => rejectDeadline(new Error("Windows file case phase deadline")),
      30000,
    );
    try {
      const result = await Promise.race([action(), deadline]);
      bounded();
      return result;
    } finally {
      cancel(timer);
    }
  };
  let participants,
    possibleParticipants = false,
    oldId,
    newId,
    outside,
    barrier,
    controlReceipt;
  const session = async (
    operations,
    { recovery = null, fault = null, control = null } = {},
  ) => {
    bounded();
    requireWindows(
      record.sessions.length < WINDOWS_FILE_SESSION_LIMITS[checkId],
    );
    record.possibleSession = record.sessions.length;
    await save();
    const owners = await wait(() =>
      effects.fileEffects(structuredClone(input)),
    );
    requireWindows(
      [
        "review",
        "open",
        "admit",
        "retire",
        "persist",
        "readRecovery",
        "verifyRetirement",
      ].every((key) => typeof owners?.[key] === "function"),
    );
    let receipt, helper, activeOperation;
    barrier = null;
    controlReceipt = null;
    const result = await runWindowsFileSession(
      input,
      operations,
      {
        ...owners,
        async open(request) {
          const channel = await owners.open(request);
          // The session captures the channel before validating this identity,
          // so a rejected helper still has its transport closed and disposed.
          helper = channel.helper;
          return channel;
        },
        async persist(value) {
          bounded();
          receipt = structuredClone(await owners.persist(value));
          requireWindows(
            receipt.immutable === true &&
              receipt.recordSha256 === digest(JSON.stringify(value)) &&
              hash(receipt.receiptSha256),
          );
        },
        async verify(message, request) {
          bounded();
          activeOperation = request.type;
          const expected = {
            leaf: message.leaf === null ? null : bytes.get(message.leaf),
            temporary:
              message.temporary === null ? null : bytes.get(message.temporary),
          };
          if (["publish", "replace"].includes(request.type)) {
            if (message.temporary !== null) expected.temporary = request.bytes;
            if (["linked", "published", "complete"].includes(message.phase))
              expected.leaf = request.bytes;
          }
          const view = structuredClone(
            await effects.observe(
              structuredClone(input),
              structuredClone(message),
            ),
          );
          requireWindows(
            assertWindowsFileObservation(message, view, input, expected).pid !==
              helper.pid,
          );
          outside ??= view.outsideBeforeSha256;
          requireWindows(view.outsideBeforeSha256 === outside);
          for (const key of ["leaf", "temporary"])
            if (message[key] !== null) bytes.set(message[key], expected[key]);
          record.observations.push({
            kind: message.phase,
            stateSha256: digest(JSON.stringify(stateOf(message))),
            receiptSha256: view.receiptSha256,
          });
          await save();
          if (checkId === "files.private" && message.phase === "allocated") {
            const probe = structuredClone(
              await effects.privateProbe(
                structuredClone(input),
                structuredClone(message),
              ),
            );
            const verifier = native(probe, input),
              actor = normalizeWindowsIdentity(probe.identity);
            requireWindows(
              probe.ready === true &&
                probe.reachable === true &&
                probe.attempted === true &&
                probe.allowed === false &&
                probe.nativeCode === 5 &&
                probe.exitCode === 0 &&
                probe.signal === null &&
                probe.settled === true &&
                probe.restrictingSid === input.request.restrictingSid &&
                probe.tokenVerified === true &&
                probe.jobVerified === true &&
                actor.sessionId === 0 &&
                /^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+$/u.test(actor.userSid) &&
                actor.userSid !== input.request.restrictingSid &&
                verifier.pid !== actor.pid &&
                actor.pid !== helper.pid &&
                probe.allocation === message.allocation,
            );
            record.observations.push({
              kind: "private-denial",
              receiptSha256: probe.receiptSha256,
            });
            await save();
          }
          if (
            (checkId === "files.publish" && message.phase === "allocated") ||
            (checkId === "files.replace" &&
              request.type === "publish" &&
              message.phase === "complete")
          ) {
            oldId = message.leaf;
            possibleParticipants = true;
            record.possibleParticipants = true;
            await save();
            participants = structuredClone(
              await (
                checkId === "files.publish"
                  ? effects.startPublishers
                  : effects.startReader
              )(structuredClone(input), structuredClone(message), [
                OLD,
                NEW,
                THIRD,
              ]),
            );
            const verifier = native(participants, input);
            requireWindows(
              participants.ready === true &&
                participants.stateSha256 ===
                  digest(JSON.stringify(stateOf(message))) &&
                participants.reviewSha256 === input.reviewSha256,
            );
            const actors =
              checkId === "files.publish"
                ? dense(participants.callers, 3)
                : [participants.reader];
            requireWindows(
              actors.length === (checkId === "files.publish" ? 3 : 1),
            );
            const identities = new Set();
            for (const actor of actors) {
              const identity = systemIdentity(actor),
                key = JSON.stringify(identity);
              requireWindows(
                !identities.has(key) &&
                  identity.pid !== helper.pid &&
                  verifier.pid !== identity.pid,
              );
              identities.add(key);
            }
            if (checkId === "files.publish")
              requireWindows(
                participants.overlapped === true &&
                  participants.requestsAcknowledged === 3,
              );
            record.participantsReceiptSha256 = participants.receiptSha256;
            await save();
          }
          if (
            checkId === "files.replace" &&
            request.type === "replace" &&
            message.phase === "complete"
          )
            newId = message.leaf;
          if (message.phase === "finished" && possibleParticipants) {
            const completed = structuredClone(
              await (
                checkId === "files.publish"
                  ? effects.finishPublishers
                  : effects.finishReader
              )(
                structuredClone(input),
                structuredClone(participants),
                structuredClone(message),
              ),
            );
            native(completed, input);
            requireWindows(
              completed.participantsReceiptSha256 ===
                participants.receiptSha256 &&
                completed.complete === true &&
                completed.settled === true,
            );
            if (checkId === "files.replace")
              requireWindows(
                sameWindowsIdentity(
                  assertWindowsReplacementReads(completed, oldId, newId, input),
                  participants.reader,
                ),
              );
            else {
              const acknowledgements = dense(completed.requests, 3);
              requireWindows(
                acknowledgements.length === 3 && completed.overlapped === true,
              );
              acknowledgements.forEach((item, index) =>
                requireWindows(
                  sameWindowsIdentity(
                    item.identity,
                    participants.callers[index],
                  ) &&
                    item.bytesSha256 ===
                      digest(Buffer.from([OLD, NEW, THIRD][index], "hex")) &&
                    item.leaf === message.leaf &&
                    item.outcome === (index === 0 ? "complete" : "exists") &&
                    hash(item.nativeEventSha256),
                ),
              );
            }
            possibleParticipants = false;
            record.possibleParticipants = false;
            record.observations.push({
              kind: "concurrent-proof",
              receiptSha256: completed.receiptSha256,
            });
            await save();
          }
          return {
            independent: true,
            stateSha256: digest(JSON.stringify(stateOf(message))),
            receiptSha256: view.receiptSha256,
            leafSha256:
              expected.leaf === null
                ? null
                : digest(Buffer.from(expected.leaf, "hex")),
            temporarySha256:
              expected.temporary === null
                ? null
                : digest(Buffer.from(expected.temporary, "hex")),
          };
        },
        async barrier(message) {
          bounded();
          if (message.phase === fault) {
            barrier = structuredClone(message);
            return "interrupt";
          }
          if (
            control &&
            activeOperation === "replace" &&
            message.phase === "prepared"
          ) {
            barrier = structuredClone(message);
            record.possibleControl = control;
            await save();
            controlReceipt = structuredClone(
              await effects.applyControl(
                control,
                structuredClone(input),
                structuredClone(message),
              ),
            );
            requireWindows(
              native(controlReceipt, input).pid !== helper.pid &&
                controlReceipt.ready === true &&
                controlReceipt.control === control &&
                controlReceipt.barrierSha256 ===
                  digest(JSON.stringify(message)),
            );
            record.controlReceiptSha256 = controlReceipt.receiptSha256;
            await save();
          }
          return "continue";
        },
      },
      { recovery, now, schedule, cancel },
    );
    requireWindows(receipt && hash(receipt.receiptSha256));
    const observed = { result, receiptSha256: receipt.receiptSha256 };
    record.sessions.push(observed);
    await save();
    requireWindows(
      result.status ===
        (control ? "FAIL" : fault ? "INTERRUPTED" : "OBSERVED") &&
        hash(result.helperSettlementSha256),
    );
    const retired = structuredClone(
      await wait(() =>
        effects.verifyRetirement(
          structuredClone(input),
          structuredClone(observed),
        ),
      ),
    );
    requireWindows(
      native(retired, input).pid !== helper.pid &&
        retired.noLiveMembers === true &&
        retired.admissionsClosed === true &&
        retired.helpersSettled === true &&
        retired.restrictingSid === input.request.restrictingSid &&
        sameWindowsIdentity(retired.helper, helper) &&
        retired.sessionReceiptSha256 === observed.receiptSha256,
    );
    record.observations.push({
      kind: "retirement",
      receiptSha256: retired.receiptSha256,
    });
    await save();
    return observed;
  };
  const cleanup = async (original, fault = null) => {
    const recovered = await session(
      [operation("cleanup"), operation("finish")],
      { recovery: original.receiptSha256, fault },
    );
    if (!fault) requireWindows(recovered.result.state.allocation === null);
    return recovered;
  };
  try {
    record.status = "RUNNING";
    await save();
    if (["files.private", "files.publish", "files.replace"].includes(checkId)) {
      const requests =
        checkId === "files.publish"
          ? [OLD, NEW, THIRD].map((bytes) => operation("publish", bytes))
          : [operation("publish", OLD)];
      if (checkId === "files.replace") requests.push(operation("replace", NEW));
      const original = await session([
        operation("allocate"),
        ...requests,
        operation("finish"),
      ]);
      if (checkId === "files.publish") {
        const acknowledgements = original.result.events.filter(
          (entry) =>
            entry.kind === "acknowledgement" &&
            entry.operation.type === "publish",
        );
        requireWindows(
          acknowledgements.length === 3 &&
            acknowledgements.map((entry) => entry.message.phase).join(",") ===
              "complete,exists,exists",
        );
      }
      await cleanup(original);
    } else if (checkId === "files.cleanup") {
      for (const fault of ["prepared", "linked", "published", "removing"]) {
        const original = await session(
          [
            operation("allocate"),
            operation("publish", OLD),
            operation("finish"),
          ],
          { fault: fault === "removing" ? null : fault },
        );
        const interrupted =
          fault === "removing" ? await cleanup(original, fault) : original;
        requireWindows(
          barrier && interrupted.result.state.alias === (fault === "linked"),
        );
        await cleanup(interrupted);
      }
    } else
      for (const control of WINDOWS_FILE_CONTROLS[checkId]) {
        const original = await session(
          [
            operation("allocate"),
            operation("publish", OLD),
            operation("replace", NEW),
            operation("finish"),
          ],
          { control },
        );
        const denial = structuredClone(
          await wait(() =>
            effects.observeDenial(
              control,
              structuredClone(input),
              structuredClone(barrier),
              structuredClone(controlReceipt),
              structuredClone(original),
            ),
          ),
        );
        assertWindowsFileDenial(control, barrier, denial, input);
        requireWindows(
          sameWindowsIdentity(denial.helper, original.result.helper) &&
            denial.sessionReceiptSha256 === original.receiptSha256 &&
            denial.controlReceiptSha256 === controlReceipt.receiptSha256 &&
            denial.observationReceiptSha256 ===
              original.result.observation.receiptSha256 &&
            denial.outsideBeforeSha256 === outside,
        );
        record.observations.push({
          kind: control,
          receiptSha256: denial.receiptSha256,
        });
        record.phase = "restore-intent";
        await save();
        const restored = structuredClone(
          await wait(() =>
            effects.restoreControl(
              control,
              structuredClone(input),
              structuredClone(denial),
            ),
          ),
        );
        native(restored, input);
        requireWindows(
          restored.ownedOnly === true &&
            restored.foreignPreserved === true &&
            restored.priorRetirementVerified === true &&
            restored.controlReceiptSha256 === controlReceipt.receiptSha256 &&
            restored.restoredStateSha256 ===
              digest(JSON.stringify(original.result.state)),
        );
        record.possibleControl = null;
        record.controlRestorationSha256 = restored.receiptSha256;
        record.phase = "control-restored";
        await save();
        await cleanup(original);
      }
    bounded();
    record.status = "OBSERVED";
  } catch {
    record.status =
      record.sessions.length === 1 &&
      record.sessions[0].result.status === "BLOCKED"
        ? "BLOCKED"
        : "FAIL";
  }
  if (possibleParticipants) {
    record.status = "FAIL";
    record.phase = "participant-retirement-intent";
    let rejectSettlement;
    const settlementDeadline = new Promise((_, reject) => {
      rejectSettlement = reject;
    });
    settlementDeadline.catch(() => {});
    const settlementTimer = schedule(
      () =>
        rejectSettlement(
          new Error("Windows file participant retirement deadline"),
        ),
      30000,
    );
    try {
      try {
        await Promise.race([save(), settlementDeadline]);
      } catch {
        // Best-effort retirement still runs after a ledger write fails.
      }
      await Promise.race([
        (checkId === "files.publish"
          ? effects.finishPublishers
          : effects.finishReader)(
          structuredClone(input),
          structuredClone(participants ?? null),
          null,
        ),
        settlementDeadline,
      ]);
    } catch {
      /* Possible actors stay excluded in protected custody. */
    } finally {
      cancel(settlementTimer);
    }
  }
  await save();
  return structuredClone(record);
}
