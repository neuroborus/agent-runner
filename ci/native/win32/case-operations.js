import { win32 as path } from "node:path";
import {
  observationObject,
  observationDigest,
  requireObservation,
  nativePolicyLaunchData,
  normalizeNativePolicyTemplate,
  verifyNativePolicy,
} from "../index.js";
import {
  digest,
  hash,
  WINDOWS_LITERAL_ARGUMENTS,
  normalizeWindowsIdentity,
  systemIdentity,
  sameWindowsIdentity,
} from "./protocol.js";
import { createWindowsFileEffects } from "./file-effects.js";
import { createWindowsGitEffects } from "./git-effects.js";
import { createWindowsReleaseEffects } from "./release-effects.js";

const same = (a, b) => observationDigest(a) === observationDigest(b);

// Approved data selects held resources, never replacement capability code.
export async function windowsOperationPreparation(
  state,
  setup,
  binding,
  entries,
  id,
) {
  observationObject(setup.operations, ["approval"]);
  observationObject(setup.operations.approval, ["path", "sha256"]);
  const bytes = await state.read(
    setup.operations.approval.path,
    setup.operations.approval.sha256,
    262144,
  );
  const value = JSON.parse(bytes);
  observationObject(value, [
    "schemaVersion",
    "contextSha256",
    "id",
    "inputSha256",
    "assets",
    "slots",
    "sourceSha256",
  ]);
  const { reviewSha256, ...reviewed } = structuredClone(setup.input);
  if (id.startsWith("files.")) reviewed.base = reviewed.root = null;
  requireObservation(
    value.schemaVersion === 1 &&
      value.id === id &&
      value.contextSha256 === observationDigest(binding.context) &&
      hash(value.sourceSha256) &&
      value.inputSha256 === observationDigest(reviewed) &&
      reviewSha256 === setup.operations.approval.sha256 &&
      bytes.equals(Buffer.from(JSON.stringify(value) + "\n")) &&
      Array.isArray(value.assets) &&
      value.assets.length <= 119,
  );
  const source = id.startsWith("files.")
    ? "file-helper.c"
    : id.startsWith("git.")
      ? "git-fixture.c"
      : "custody-reader.c";
  requireObservation(
    value.sourceSha256 ===
      state.plan.sources.find(({ name }) => name === source)?.sha256,
  );
  const indices = new Set();
  for (const asset of value.assets) {
    observationObject(asset, ["index", "source"]);
    requireObservation(
      Number.isSafeInteger(asset.index) &&
        asset.index >= 9 &&
        entries[asset.index] &&
        !indices.has(asset.index),
    );
    indices.add(asset.index);
    const target = entries[asset.index];
    requireObservation(
      asset.source === null
        ? target.kind === "directory"
        : Number.isSafeInteger(asset.source) &&
            entries[asset.source] &&
            target.sha256 === entries[asset.source].sha256 &&
            target.signatureSha256 === entries[asset.source].signatureSha256 &&
            !entries[asset.source].path
              .toLowerCase()
              .startsWith(entries[1].path.toLowerCase() + "\\"),
    );
    requireObservation(
      target.path
        .toLowerCase()
        .startsWith(entries[1].path.toLowerCase() + "\\") &&
        entries.some(
          (entry) =>
            entry.kind === "directory" &&
            entry.path === path.dirname(target.path),
        ),
    );
  }
  return {
    ...value,
    entries,
    approval: structuredClone(setup.operations.approval),
  };
}

/** Private family lifecycle. Protected receipts retain every possible effect;
 * native readers, rather than helper output, supply the proof ingredients. */
export function createWindowsOperationEffects(state, current, save, options) {
  const { reader, recipe, binding, provisioned } = current;
  const specification = provisioned.operations;
  requireObservation(specification?.id === recipe.id);
  let failure,
    sequence = 0;
  const receipts = new Map(),
    history = [],
    subjects = new Map();
  const latch =
    (fn, cleanup = false) =>
    async (...args) => {
      try {
        if (!cleanup) {
          if (failure) throw failure;
          requireObservation(!current.admissionsClosed);
          state.guard(current.signal);
        }
        const result = await fn(...args);
        if (!cleanup) requireObservation(!current.admissionsClosed);
        if (!cleanup) state.guard(current.signal);
        return result;
      } catch (cause) {
        throw (failure ??= cause);
      }
    };
  const persist = latch(async (record) => {
    const bytes = Buffer.from(JSON.stringify(record) + "\n"),
      parts = [];
    requireObservation(bytes.length <= 262144);
    for (let offset = 0; offset < bytes.length; offset += 16384) {
      const part = bytes.subarray(offset, offset + 16384),
        pin = { index: sequence++, sha256: digest(part) };
      await save(recipe.id, { phase: "operation-receipt-possible", pin });
      requireObservation(
        (await reader.ownershipReceipt(pin.index, pin.sha256, part)).equals(
          part,
        ),
      );
      parts.push(pin);
    }
    const manifest = Buffer.from(
        JSON.stringify({ contentSha256: digest(bytes), parts }) + "\n",
      ),
      pin = { index: sequence++, sha256: digest(manifest) };
    requireObservation(
      (await reader.ownershipReceipt(pin.index, pin.sha256, manifest)).equals(
        manifest,
      ),
    );
    await save(recipe.id, {
      phase: "operation-receipt",
      pin,
      parts,
      contentSha256: digest(bytes),
    });
    receipts.set(pin.sha256, { pin, parts, contentSha256: digest(bytes) });
    history.push({ pin, record: structuredClone(record) });
    return {
      immutable: true,
      recordSha256: observationDigest(record),
      receiptSha256: pin.sha256,
    };
  }, true);
  const recover = async (sha256) => {
    const held = receipts.get(sha256);
    requireObservation(held);
    const manifest = await reader.ownershipReceipt(
      held.pin.index,
      held.pin.sha256,
    );
    requireObservation(
      same(JSON.parse(manifest), {
        contentSha256: held.contentSha256,
        parts: held.parts,
      }),
    );
    const parts = [];
    for (const pin of held.parts)
      parts.push(await reader.ownershipReceipt(pin.index, pin.sha256));
    const bytes = Buffer.concat(parts),
      record = JSON.parse(bytes);
    requireObservation(
      digest(bytes) === held.contentSha256 &&
        bytes.equals(Buffer.from(JSON.stringify(record) + "\n")),
    );
    return record;
  };
  const witness = async () => {
    const actual = await reader.verifier(current.admission.verifier);
    requireObservation(sameWindowsIdentity(actual, current.admission.verifier));
    return systemIdentity(actual);
  };
  const born = async (identity, image) => {
    identity = normalizeWindowsIdentity(identity);
    const key = observationDigest(identity);
    requireObservation(!subjects.has(key));
    await persist({ kind: "operation-birth-possible", identity, image });
    const held = await reader.retainProcess(identity);
    const loaded = await reader.processImage(held.slot, image);
    subjects.set(key, { identity, slot: held.slot, image });
    await persist({
      kind: "operation-birth-held",
      identity,
      slot: held.slot,
      image,
      loaded,
    });
    return held;
  };
  const absence = async (identity) => {
    const held = subjects.get(
      observationDigest(normalizeWindowsIdentity(identity)),
    );
    requireObservation(held);
    const actual = await reader.process(held.slot);
    requireObservation(actual.retired);
    return actual;
  };
  const policy = (parameters, raw) => {
    const complete = normalizeNativePolicyTemplate({
      ...binding.template,
      bindings: [],
      policy: {
        launch: nativePolicyLaunchData(
          current.input.request,
          WINDOWS_LITERAL_ARGUMENTS,
        ),
        policy: parameters,
      },
    }).policy;
    return {
      schemaVersion: 1,
      context: binding.context,
      templateSha256: binding.approval.manifestSha256,
      provisioningSha256: observationDigest(provisioned.provisioning),
      requestSha256: observationDigest(complete.launch),
      policy: complete,
      policySha256: observationDigest(complete),
      held: true,
      independent: true,
      complete: true,
      verifierSha256: current.declared.custody.reader.sha256,
      nativeEventSha256: observationDigest(raw),
    };
  };
  const core = {
    state,
    current,
    reader,
    specification,
    persist,
    recover,
    witness,
    born,
    absence,
    policy,
    history,
    latch,
  };
  const owner =
    recipe.group === "files"
      ? createWindowsFileEffects(core)
      : recipe.group === "release"
        ? createWindowsReleaseEffects(core)
        : createWindowsGitEffects(core);
  Object.defineProperty(owner.effects, "cause", { get: () => failure });
  return {
    effects: owner.effects,
    async prepare() {
      try {
        current.caseEffectsPossible = true;
        const observed = await owner.prepare(),
          proof = {
            provisioning: provisioned.provisioning,
            requestSha256: observed.requestSha256,
            observed,
          };
        verifyNativePolicy(
          binding.template,
          binding.approval,
          proof.provisioning,
          binding.context,
          proof.requestSha256,
          observed,
        );
        return proof;
      } catch (cause) {
        throw (failure ??= cause);
      }
    },
    async finish({ signal, closeFiles = true }) {
      try {
        current.cleanupSignal = signal;
        await options.beginCleanup?.(signal);
        await reader.beginCleanup({ signal });
        await persist({ kind: "operation-cleanup-possible" });
        await owner.finish();
        const reads = [];
        for (const { identity } of subjects.values())
          reads.push(await absence(identity));
        await persist({ kind: "operation-restored", observations: reads });
        const account = await reader.retireCase(current.custodySlot),
          custody = await reader.close();
        if (custody.cause) throw custody.cause;
        requireObservation(
          custody.status === "RETIRED" &&
            custody.independent &&
            custody.closed &&
            custody.taskRemoved,
        );
        const files = closeFiles ? await options.settleFiles() : null;
        requireObservation(
          !closeFiles ||
            (files.status === "RETIRED" &&
              files.independent &&
              files.noLiveMembers &&
              files.taskRemoved),
        );
        const result = {
          status: "RETIRED",
          independent: true,
          emergencyCleanup: false,
          nativeEventSha256: observationDigest({
            reads,
            account,
            custody,
            files,
          }),
        };
        current.retired = true;
        return result;
      } catch (cause) {
        throw (failure ??= cause);
      }
    },
  };
}
