import { performance } from "node:perf_hooks";
import {
  digest,
  normalizeDarwinIdentity,
  requireDarwin,
  sameDarwinIdentity,
} from "./protocol.js";
import {
  encodeDarwinFileRequest,
  normalizeDarwinFileIdentity,
  normalizeDarwinFileMessage,
} from "./files-protocol.js";
import { normalizeDarwinFileInput, runDarwinFileSession } from "./files.js";

export const DARWIN_FILE_CASE_IDS = Object.freeze([
  "files.private",
  "files.publish",
  "files.replace",
  "files.substitution",
  "files.aliases",
  "files.cleanup",
]);
export const DARWIN_FILE_CONTROLS = Object.freeze([
  "parent",
  "leaf",
  "symlink",
  "hardlink",
  "cross-volume",
]);
const OLD = "006f6c64ff",
  NEW = "006e657700ff";
const HASH = /^[a-f0-9]{64}$/u;
const hash = (value) => typeof value === "string" && HASH.test(value);
const names = ["base", "root", "allocation", "leaf", "temporary"];
const stateOf = (value) =>
  Object.fromEntries([...names, "alias"].map((key) => [key, value[key]]));
const volume = (id) =>
  id
    .split(":")
    .filter((_, index) => [0, 1, 2, 6].includes(index))
    .join(":");
const operation = (type, bytes = "") => ({ type, bytes });
function root(value) {
  const identity = normalizeDarwinIdentity(value);
  requireDarwin(
    ["uid", "ruid", "svuid", "gid", "rgid", "svgid"].every(
      (key) => identity[key] === 0,
    ),
  );
  return identity;
}

/** Held and named native reads are outside the helper. No helper text or a
 * pathname digest substitutes for file/volume identities, link counts or bytes. */
export function assertDarwinFileObservation(message, view, value, expected) {
  const input = normalizeDarwinFileInput(value);
  message = normalizeDarwinFileMessage(message, input.request.nonce);
  const verifier = root(view?.verifier);
  requireDarwin(
    message.base === input.base &&
      message.root === input.root &&
      view.independent === true &&
      view.parentAuthority === true &&
      view.candidateSha === input.request.candidateSha &&
      view.nonce === input.request.nonce &&
      view.requestSha256 === digest(JSON.stringify(input)) &&
      view.policySha256 === input.request.bindings.policy &&
      hash(view.nativeEventSha256) &&
      hash(view.receiptSha256) &&
      hash(view.outsideBeforeSha256) &&
      view.outsideAfterSha256 === view.outsideBeforeSha256 &&
      view.timedOut === false,
  );
  for (const key of names) {
    const object = view.objects?.[key],
      id = message[key];
    if (id === null) {
      requireDarwin(object === null);
      continue;
    }
    const directory = !["leaf", "temporary"].includes(key);
    requireDarwin(
      object &&
        normalizeDarwinFileIdentity(object.identity) === id &&
        object.namedIdentity === id &&
        volume(id) === volume(input.root) &&
        object.uid === 0 &&
        object.gid === 0 &&
        object.kind === (directory ? "directory" : "file") &&
        object.mode === (directory ? 0o700 : 0o600) &&
        (directory
          ? object.bytes === null
          : object.links === (message.alias ? 2 : 1) &&
            typeof expected[key] === "string" &&
            object.bytes === expected[key]),
    );
  }
  return verifier;
}

/** A ready controlled substitute must be joined to the exact acknowledged
 * barrier and a native rejection. Exit 126 or a timeout alone proves nothing. */
export function assertDarwinFileDenial(control, barrier, evidence, value) {
  const input = normalizeDarwinFileInput(value);
  requireDarwin(DARWIN_FILE_CONTROLS.includes(control));
  barrier = normalizeDarwinFileMessage(barrier, input.request.nonce);
  const parent = ["parent", "cross-volume"].includes(control);
  const original = parent ? barrier.allocation : barrier.leaf;
  const changed = evidence?.applied?.object;
  root(evidence?.verifier);
  requireDarwin(
    barrier.phase === "prepared" &&
      original !== null &&
      evidence.independent === true &&
      evidence.control === control &&
      evidence.attempted === true &&
      evidence.ready === true &&
      evidence.reachable === true &&
      evidence.continued === true &&
      evidence.timedOut === false &&
      evidence.exitCode === 126 &&
      evidence.signal === null &&
      evidence.candidateSha === input.request.candidateSha &&
      evidence.nonce === input.request.nonce &&
      evidence.requestSha256 === digest(JSON.stringify(input)) &&
      evidence.barrierSha256 === digest(JSON.stringify(barrier)) &&
      hash(evidence.nativeEventSha256) &&
      hash(evidence.receiptSha256) &&
      evidence.before.object.identity === original &&
      evidence.before.object.bytes === (parent ? null : OLD) &&
      hash(evidence.before.othersSha256) &&
      evidence.applied.othersSha256 === evidence.before.othersSha256 &&
      (parent || evidence.before.object.links === 1) &&
      evidence.applied.saved.identity === original &&
      evidence.applied.saved.bytes === evidence.before.object.bytes &&
      JSON.stringify(evidence.after) === JSON.stringify(evidence.applied) &&
      hash(evidence.outsideBeforeSha256) &&
      evidence.outsideAfterSha256 === evidence.outsideBeforeSha256,
  );
  normalizeDarwinFileIdentity(changed.identity);
  if (control === "hardlink")
    requireDarwin(
      changed.identity === original &&
        changed.links === 2 &&
        evidence.applied.saved.links === 2 &&
        changed.bytes === OLD &&
        evidence.nativeDecision === "reject-hardlink",
    );
  else {
    requireDarwin(
      changed.identity !== original && evidence.applied.saved.links >= 1,
    );
    if (control === "symlink")
      requireDarwin(
        changed.kind === "symlink" &&
          changed.target === ".held-value" &&
          evidence.nativeDecision === "reject-symlink",
      );
    else if (control === "cross-volume")
      requireDarwin(
        changed.kind === "directory" &&
          volume(changed.identity) !== volume(input.root) &&
          evidence.nativeDecision === "reject-volume",
      );
    else
      requireDarwin(
        evidence.nativeDecision === "reject-identity" &&
          changed.kind === (control === "parent" ? "directory" : "file"),
      );
  }
  return true;
}

export function assertDarwinReplacementReads(value, oldId, newId, input) {
  root(value?.verifier);
  const reader = root(value?.reader);
  requireDarwin(
    value.independent === true &&
      value.ready === true &&
      value.overlapped === true &&
      value.complete === true &&
      value.dropped === false &&
      value.timedOut === false &&
      value.settled === true &&
      value.candidateSha === input.request.candidateSha &&
      value.nonce === input.request.nonce &&
      value.requestSha256 === digest(JSON.stringify(input)) &&
      hash(value.nativeEventSha256) &&
      hash(value.receiptSha256) &&
      value.verifier.pid !== reader.pid &&
      oldId !== newId &&
      Array.isArray(value.reads) &&
      value.reads.length >= 2 &&
      value.reads.length <= 4096,
  );
  const seen = new Set();
  for (const read of value.reads) {
    requireDarwin(
      read.code === "OK" &&
        read.links === 1 &&
        hash(read.nativeEventSha256) &&
        ((read.identity === oldId && read.bytes === OLD) ||
          (read.identity === newId && read.bytes === NEW)),
    );
    seen.add(read.identity);
  }
  requireDarwin(seen.size === 2);
  return reader;
}

/** Explicit external cases. The protected effects own native readers, fault
 * objects and immutable receipts. This owner never emits catalog PASS. */
export async function runDarwinFileCase(
  checkId,
  value,
  effects,
  { now = () => performance.now() } = {},
) {
  const input = normalizeDarwinFileInput(value);
  requireDarwin(
    DARWIN_FILE_CASE_IDS.includes(checkId) &&
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
  if (["files.substitution", "files.aliases"].includes(checkId))
    required.push("applyControl", "observeDenial", "restoreControl");
  if (checkId === "files.aliases") required.push("nameControl");
  for (const key of required)
    if (typeof effects[key] !== "function")
      record.missingInputs.push("darwin-file-case-" + key);
  const save = () => effects.persist(structuredClone(record));
  if (record.missingInputs.length) {
    await save();
    return record;
  }
  const started = now();
  const bound =
    checkId === "files.aliases"
      ? 360000
      : checkId === "files.cleanup"
        ? 240000
        : 180000;
  const bounded = () =>
    requireDarwin(
      Number.isFinite(now() - started) &&
        now() >= started &&
        now() - started <= bound,
    );
  let reader,
    publishers,
    readerStarted = false,
    publishersStarted = false,
    blocked = false,
    oldId,
    newId,
    outsideSha256,
    barrier,
    controlReceipt;
  const bytes = new Map();
  const retire = async (session) => {
    bounded();
    const proof = structuredClone(
      await effects.verifyRetirement(
        structuredClone(input),
        structuredClone(session),
      ),
    );
    const verifier = root(proof?.verifier);
    requireDarwin(
      proof.independent === true &&
        proof.noLiveUid === true &&
        proof.uid === input.request.uid &&
        proof.helpersSettled === true &&
        proof.requestSha256 === record.requestSha256 &&
        hash(proof.receiptSha256) &&
        verifier.pid !== session.result.admission.helper.pid &&
        sameDarwinIdentity(proof.helper, session.result.admission.helper) &&
        proof.sessionReceiptSha256 === session.receiptSha256 &&
        hash(session.result.helperSettlementSha256),
    );
    record.observations.push({
      kind: "retirement",
      receiptSha256: proof.receiptSha256,
    });
    await save();
  };
  const session = async (
    operations,
    { recovery = null, fault = null, control = null } = {},
  ) => {
    bounded();
    requireDarwin(record.sessions.length < 8);
    record.possibleSession = record.sessions.length;
    await save();
    const owners = await effects.fileEffects(structuredClone(input));
    requireDarwin(
      [
        "review",
        "open",
        "retire",
        "readRecovery",
        "verifyRetirement",
        "persist",
      ].every((key) => typeof owners?.[key] === "function"),
    );
    let receipt, admitted, activeOperation;
    barrier = null;
    controlReceipt = null;
    const result = await runDarwinFileSession(
      input,
      operations,
      {
        ...owners,
        async open(request) {
          const channel = await owners.open(request);
          admitted = structuredClone(channel.admission);
          return channel;
        },
        async persist(value) {
          bounded();
          const expected = digest(JSON.stringify(value));
          receipt = structuredClone(await owners.persist(value));
          requireDarwin(
            receipt.immutable === true &&
              receipt.recordSha256 === expected &&
              hash(receipt.receiptSha256),
          );
        },
        async verify(message, request) {
          bounded();
          activeOperation = request.type;
          const expected = {
            leaf: message.leaf === null ? null : bytes.get(message.leaf),
            temporary: message.temporary === null ? null : request.bytes,
          };
          if (
            ["linked", "published", "complete"].includes(message.phase) &&
            ["publish", "replace"].includes(request.type)
          )
            expected.leaf = request.bytes;
          if (request.type === "recover" && message.temporary !== null)
            expected.temporary = bytes.get(message.temporary);
          if (request.type === "cleanup" && message.temporary !== null)
            expected.temporary = bytes.get(message.temporary);
          const view = structuredClone(
            await effects.observe(
              structuredClone(input),
              structuredClone(message),
            ),
          );
          outsideSha256 ??= view.outsideBeforeSha256;
          requireDarwin(view.outsideBeforeSha256 === outsideSha256);
          requireDarwin(
            assertDarwinFileObservation(message, view, input, expected).pid !==
              admitted.helper.pid,
          );
          if (message.temporary !== null)
            bytes.set(message.temporary, expected.temporary);
          if (message.leaf !== null) bytes.set(message.leaf, expected.leaf);
          record.observations.push({
            kind: message.phase,
            nativeEventSha256: view.nativeEventSha256,
            state: stateOf(message),
          });
          await save();
          if (checkId === "files.publish" && message.phase === "allocated") {
            publishersStarted = true;
            record.possiblePublishers = true;
            await save();
            publishers = structuredClone(
              await effects.startPublishers(
                structuredClone(input),
                structuredClone(message),
                structuredClone(
                  operations.filter((item) => item.type === "publish"),
                ),
              ),
            );
            const verifier = root(publishers?.verifier),
              seen = new Set();
            requireDarwin(
              publishers.independent === true &&
                verifier.pid !== admitted.helper.pid &&
                publishers.ready === true &&
                publishers.overlapped === true &&
                publishers.requestSha256 === record.requestSha256 &&
                publishers.reviewSha256 === input.reviewSha256 &&
                publishers.allocation === message.allocation &&
                hash(publishers.receiptSha256) &&
                hash(publishers.nativeEventSha256) &&
                Array.isArray(publishers.requests) &&
                publishers.requests.length === 3,
            );
            const requests = operations.filter(
              (item) => item.type === "publish",
            );
            for (let index = 0; index < requests.length; index++) {
              const caller = publishers.requests[index],
                identity = root(caller?.identity),
                key = JSON.stringify(identity);
              requireDarwin(
                caller.bytes === requests[index].bytes &&
                  caller.acknowledged === true &&
                  hash(caller.nativeEventSha256) &&
                  verifier.pid !== identity.pid &&
                  !sameDarwinIdentity(identity, admitted.helper) &&
                  !seen.has(key),
              );
              seen.add(key);
            }
            record.publishers = publishers.requests.map((item) =>
              root(item.identity),
            );
            record.publishersReceiptSha256 = publishers.receiptSha256;
            await save();
          }
          if (checkId === "files.private" && message.phase === "allocated") {
            const probe = structuredClone(
              await effects.privateProbe(
                structuredClone(input),
                structuredClone(message),
              ),
            );
            const actor = normalizeDarwinIdentity(probe?.identity),
              verifier = root(probe?.verifier);
            requireDarwin(
              probe.independent === true &&
                probe.ready === true &&
                probe.reachable === true &&
                probe.attempted === true &&
                probe.timedOut === false &&
                ["EACCES", "EPERM"].includes(probe.code) &&
                probe.uid === input.request.uid &&
                probe.allocation === message.allocation &&
                probe.requestSha256 === record.requestSha256 &&
                hash(probe.nativeEventSha256) &&
                actor.auid === input.request.uid &&
                actor.asid > 0 &&
                verifier.pid !== actor.pid &&
                ["uid", "ruid", "svuid"].every(
                  (key) => actor[key] === input.request.uid,
                ) &&
                ["gid", "rgid", "svgid"].every(
                  (key) => actor[key] === input.request.gid,
                ),
            );
            record.observations.push({
              kind: "private-denial",
              nativeEventSha256: probe.nativeEventSha256,
            });
            await save();
          }
          if (
            checkId === "files.replace" &&
            request.type === "publish" &&
            message.phase === "complete"
          ) {
            oldId = message.leaf;
            readerStarted = true;
            record.possibleReader = true;
            await save();
            reader = structuredClone(
              await effects.startReader(
                structuredClone(input),
                structuredClone(message),
              ),
            );
            const identity = root(reader?.identity),
              verifier = root(reader?.verifier);
            requireDarwin(
              reader.independent === true &&
                reader.ready === true &&
                verifier.pid !== identity.pid &&
                identity.pid !== admitted.helper.pid &&
                reader.reviewSha256 === input.reviewSha256 &&
                reader.requestSha256 === record.requestSha256 &&
                hash(reader.receiptSha256),
            );
            record.reader = { identity, receiptSha256: reader.receiptSha256 };
            await save();
          }
          if (
            checkId === "files.replace" &&
            request.type === "replace" &&
            message.phase === "complete"
          )
            newId = message.leaf;
          if (
            message.phase === "finished" &&
            readerStarted &&
            checkId === "files.replace"
          ) {
            const reads = structuredClone(
              await effects.finishReader(
                structuredClone(input),
                structuredClone(reader),
              ),
            );
            requireDarwin(
              sameDarwinIdentity(
                assertDarwinReplacementReads(reads, oldId, newId, input),
                reader.identity,
              ) && reads.readerReceiptSha256 === reader.receiptSha256,
            );
            readerStarted = false;
            record.observations.push({
              kind: "concurrent-replacement",
              receiptSha256: reads.receiptSha256,
            });
            await save();
          }
          if (
            message.phase === "finished" &&
            publishersStarted &&
            checkId === "files.publish"
          ) {
            const completed = structuredClone(
              await effects.finishPublishers(
                structuredClone(input),
                structuredClone(publishers),
                structuredClone(message),
              ),
            );
            const verifier = root(completed?.verifier);
            requireDarwin(
              completed.independent === true &&
                completed.complete === true &&
                completed.settled === true &&
                completed.timedOut === false &&
                completed.requestSha256 === record.requestSha256 &&
                completed.publishersReceiptSha256 ===
                  publishers.receiptSha256 &&
                hash(completed.nativeEventSha256) &&
                hash(completed.receiptSha256) &&
                Array.isArray(completed.requests) &&
                completed.requests.length === 3,
            );
            for (let index = 0; index < completed.requests.length; index++) {
              const item = completed.requests[index];
              requireDarwin(
                sameDarwinIdentity(
                  item.identity,
                  publishers.requests[index].identity,
                ) &&
                  verifier.pid !== item.identity.pid &&
                  item.bytes === publishers.requests[index].bytes &&
                  item.leaf === message.leaf &&
                  item.outcome === (index === 0 ? "complete" : "exists") &&
                  hash(item.nativeEventSha256),
              );
            }
            publishersStarted = false;
            record.observations.push({
              kind: "concurrent-publication",
              receiptSha256: completed.receiptSha256,
            });
            await save();
          }
          return {
            independent: true,
            stateSha256: digest(JSON.stringify(stateOf(message))),
            receiptSha256: view.receiptSha256,
            leafSha256:
              typeof expected.leaf === "string"
                ? digest(Buffer.from(expected.leaf, "hex"))
                : null,
            temporarySha256:
              typeof expected.temporary === "string"
                ? digest(Buffer.from(expected.temporary, "hex"))
                : null,
          };
        },
        async barrier(message) {
          bounded();
          if (fault === message.phase) {
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
            requireDarwin(
              controlReceipt.ready === true &&
                hash(controlReceipt.receiptSha256),
            );
            record.controlReceipt = controlReceipt.receiptSha256;
            await save();
          }
          return "continue";
        },
      },
      { recovery, now },
    );
    requireDarwin(receipt && hash(receipt.receiptSha256));
    const observed = { result, receiptSha256: receipt.receiptSha256 };
    record.sessions.push(structuredClone(observed));
    await save();
    if (result.status === "BLOCKED" && !result.admission) {
      record.missingInputs = result.missingInputs;
      blocked =
        !record.sessions.some((item) => item.result.admission) &&
        !readerStarted &&
        !publishersStarted;
    }
    requireDarwin(
      result.status === (control ? "FAIL" : fault ? "INTERRUPTED" : "OBSERVED"),
    );
    await retire(observed);
    return observed;
  };
  const cleanup = async (original) => {
    const result = await session([operation("cleanup"), operation("finish")], {
      recovery: original.receiptSha256,
    });
    requireDarwin(
      result.result.state.allocation === null &&
        result.result.state.leaf === null &&
        result.result.state.temporary === null,
    );
  };
  try {
    record.status = "RUNNING";
    await save();
    if (["files.private", "files.publish", "files.replace"].includes(checkId)) {
      let requests = [operation("publish", OLD)];
      if (checkId === "files.publish") {
        requests = await Promise.all(
          [OLD, NEW, "7365636f6e64"].map(async (content, index) => {
            await effects.persist({
              checkId,
              kind: "concurrent-request",
              index,
              bytesSha256: digest(Buffer.from(content, "hex")),
              requestSha256: record.requestSha256,
            });
            return operation("publish", content);
          }),
        );
        record.concurrentRequestsAcknowledged = 3;
        await save(); // All requests are queued before the sole owner starts native effects.
      }
      if (checkId === "files.replace") requests.push(operation("replace", NEW));
      const original = await session([
        operation("allocate"),
        ...requests,
        operation("finish"),
      ]);
      if (checkId === "files.publish") {
        const acknowledgements = original.result.events.filter(
          (event) =>
            event.kind === "acknowledgement" &&
            event.operation.type === "publish",
        );
        requireDarwin(
          acknowledgements.length === 3 &&
            acknowledgements.filter(
              (event) => event.message.phase === "complete",
            ).length === 1 &&
            acknowledgements.filter((event) => event.message.phase === "exists")
              .length === 2 &&
            acknowledgements.every(
              (event) =>
                event.message.leaf === original.result.state.leaf &&
                event.message.temporary === null,
            ),
        );
      }
      await cleanup(original);
    } else if (checkId === "files.cleanup") {
      for (const fault of ["prepared", "linked", "published"]) {
        const original = await session(
          [
            operation("allocate"),
            operation("publish", OLD),
            operation("finish"),
          ],
          { fault },
        );
        requireDarwin(
          barrier && original.result.state.alias === (fault === "linked"),
        );
        await cleanup(original);
      }
    } else {
      const controls =
        checkId === "files.substitution"
          ? ["parent", "leaf"]
          : ["symlink", "hardlink", "cross-volume"];
      for (const control of controls) {
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
          await effects.observeDenial(
            control,
            structuredClone(input),
            structuredClone(barrier),
            structuredClone(controlReceipt),
            structuredClone(original),
          ),
        );
        assertDarwinFileDenial(control, barrier, denial, input);
        root(denial.helper);
        requireDarwin(
          sameDarwinIdentity(denial.helper, original.result.admission.helper) &&
            denial.outsideBeforeSha256 === outsideSha256 &&
            denial.sessionReceiptSha256 === original.receiptSha256 &&
            denial.controlReceiptSha256 === controlReceipt.receiptSha256,
        );
        record.observations.push({
          kind: control,
          receiptSha256: denial.receiptSha256,
        });
        await save();
        const restored = await effects.restoreControl(
          control,
          structuredClone(input),
          structuredClone(denial),
        );
        requireDarwin(
          restored.ownedOnly === true &&
            restored.foreignPreserved === true &&
            restored.independent === true &&
            restored.requestSha256 === record.requestSha256 &&
            restored.controlReceiptSha256 === controlReceipt.receiptSha256 &&
            hash(restored.nativeEventSha256) &&
            restored.restoredStateSha256 ===
              digest(JSON.stringify(original.result.state)),
        );
        await cleanup(original);
      }
      if (checkId === "files.aliases")
        for (const [name, canonical] of [
          ["Value", "value"],
          ["va\u0301lue", "v\u00e1lue"],
          ["../value", "value"],
        ]) {
          let rejected = false;
          try {
            encodeDarwinFileRequest({
              type: "publish",
              allocation: input.root,
              leaf: null,
              temporary: null,
              bytes: OLD,
              name,
            });
          } catch {
            rejected = true;
          }
          requireDarwin(rejected);
          const alias = structuredClone(
            await effects.nameControl(name, structuredClone(input), canonical),
          );
          root(alias?.verifier);
          requireDarwin(
            alias.independent === true &&
              alias.ready === true &&
              alias.reachable === true &&
              alias.attempted === true &&
              alias.nativeAliasObserved === true &&
              alias.rejectedBeforeCommand === true &&
              alias.timedOut === false &&
              alias.suppliedName === name &&
              alias.canonicalName === canonical &&
              alias.requestSha256 === record.requestSha256 &&
              hash(alias.nativeEventSha256) &&
              hash(alias.beforeSha256) &&
              alias.afterSha256 === alias.beforeSha256,
          );
          requireDarwin(
            normalizeDarwinFileIdentity(alias.nativeIdentity) ===
              normalizeDarwinFileIdentity(alias.aliasIdentity),
          );
          record.observations.push({
            kind: "name-rejection",
            nativeEventSha256: alias.nativeEventSha256,
          });
          await save();
        }
    }
    bounded();
    record.status = "OBSERVED";
  } catch {
    record.status = blocked ? "BLOCKED" : "FAIL";
  }
  if (readerStarted) {
    try {
      await effects.finishReader(
        structuredClone(input),
        structuredClone(reader),
      );
    } catch {
      /* A possible reader remains in the protected recovery ledger. */
    }
    record.status = "FAIL";
  }
  if (publishersStarted) {
    try {
      await effects.finishPublishers(
        structuredClone(input),
        structuredClone(publishers),
        null,
      );
    } catch {
      /* Possible callers remain in the protected recovery ledger. */
    }
    record.status = "FAIL";
  }
  await save();
  return structuredClone(record);
}
