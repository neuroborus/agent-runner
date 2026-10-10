import path from "node:path";
import {
  observationDigest,
  observationObject,
  nativePolicyLaunchData,
  requireObservation,
  verifyNativePolicy,
  normalizeNativePolicyTemplate,
} from "../index.js";
import {
  digest,
  DARWIN_LITERAL_ARGUMENTS,
  normalizeDarwinIdentity,
} from "./protocol.js";
import { createDarwinFileEffects } from "./file-effects.js";
import { createDarwinGitEffects } from "./git-effects.js";
import { createDarwinReleaseEffects } from "./release-effects.js";

const hash = (value) =>
  typeof value === "string" && /^[a-f0-9]{64}$/u.test(value);

// Extra custody is an independently approved, context-bound inventory. It is
// never reconstructed from the image, file or policy observations it approves.
export async function darwinOperationPreparation(
  state,
  setup,
  binding,
  base,
  id,
) {
  observationObject(setup.operations, ["approval"]);
  observationObject(setup.operations.approval, ["path", "sha256"]);
  const bytes = await state.read(
    setup.operations.approval.path,
    setup.operations.approval.sha256,
  );
  const value = JSON.parse(bytes);
  observationObject(value, [
    "schemaVersion",
    "contextSha256",
    "id",
    "inputSha256",
    "assets",
    "slots",
  ]);
  requireObservation(
    value.schemaVersion === 1 &&
      hash(value.inputSha256) &&
      value.id === id &&
      value.contextSha256 === observationDigest(binding.context) &&
      bytes.equals(Buffer.from(JSON.stringify(value) + "\n")),
  );
  const { reviewSha256, ...reviewed } = structuredClone(setup.input);
  if (id.startsWith("files.")) {
    reviewed.base = null;
    reviewed.root = null;
  }
  requireObservation(
    reviewSha256 === setup.operations.approval.sha256 &&
      value.inputSha256 === observationDigest(reviewed),
  );
  const entries = [...base];
  requireObservation(Array.isArray(value.assets) && value.assets.length <= 112);
  for (const asset of value.assets) {
    observationObject(asset, ["kind", "path", "sha256", "source"]);
    requireObservation(
      ["authority", "data", "image", "helper", "cache"].includes(asset.kind) &&
        (asset.kind === "authority"
          ? asset.sha256 === null
          : hash(asset.sha256)) &&
        typeof asset.path === "string" &&
        path.isAbsolute(asset.path) &&
        path.normalize(asset.path) === asset.path &&
        !/[\u0000-\u001f\u007f]/u.test(asset.path) &&
        (asset.source === null ||
          (Number.isSafeInteger(asset.source) &&
            asset.source >= 0 &&
            asset.source < entries.length)),
    );
    if (asset.source !== null)
      requireObservation(
        asset.path.startsWith(base[0].path + "/") &&
          ["data", "image", "helper"].includes(asset.kind) &&
          entries[asset.source].sha256 === asset.sha256,
      );
    const { source, ...entry } = asset;
    entries.push(entry);
  }
  requireObservation(
    entries.length <= 128 &&
      new Set(entries.map(({ path }) => path)).size === entries.length,
  );
  return {
    ...value,
    entries,
    approval: structuredClone(setup.operations.approval),
  };
}

/** Private family composition. Native commands expose observations; the
 * existing file/Git/release owners remain responsible for their full proofs. */
export function createDarwinOperationEffects(state, current, save, recovered) {
  const { reader, recipe, binding, provisioned } = current;
  const specification = provisioned.operations;
  requireObservation(specification && specification.id === recipe.id);
  let failure,
    receiptIndex = recovered?.receiptIndex ?? 0;
  const history = [...(recovered?.history ?? [])];
  const receipts = new Map(
      (recovered?.pins ?? []).map((pin) => [pin.sha256, pin]),
    ),
    subjects = [...(recovered?.subjects ?? [])];
  const latch =
    (fn, cleanup = false) =>
    async (...args) => {
      try {
        if (!cleanup) {
          if (failure) throw failure;
          state.guard(current.signal);
        }
        const result = await fn(...args);
        if (!cleanup) state.guard(current.signal);
        return result;
      } catch (cause) {
        throw (failure ??= cause);
      }
    };
  const persist = latch(async (record) => {
    const bytes = Buffer.from(JSON.stringify(record) + "\n");
    const pin = { index: receiptIndex++, sha256: digest(bytes) };
    await save(recipe.id, { phase: "operation-receipt-possible", pin });
    requireObservation(
      (await reader.ownershipReceipt(pin.index, pin.sha256, bytes)).equals(
        bytes,
      ),
    );
    await save(recipe.id, { phase: "operation-receipt", pin });
    receipts.set(pin.sha256, pin);
    history.push({ pin, record: structuredClone(record) });
    return {
      immutable: true,
      recordSha256: observationDigest(record),
      receiptSha256: pin.sha256,
    };
  }, true);
  const recover = async (sha256) => {
    const pin = receipts.get(sha256);
    requireObservation(pin);
    const bytes = await reader.ownershipReceipt(pin.index, pin.sha256);
    requireObservation(digest(bytes) === sha256);
    const record = JSON.parse(bytes);
    requireObservation(
      bytes.equals(Buffer.from(JSON.stringify(record) + "\n")),
    );
    return record;
  };
  const witness = async () => {
    const actual = await reader.witness(current.admission.helper);
    requireObservation(
      actual.subject.sha256 === current.declared.custody.reader.sha256,
    );
    return normalizeDarwinIdentity(actual.verifier);
  };
  const born = async (identity, expected) => {
    identity = normalizeDarwinIdentity(identity);
    subjects.push(identity);
    await persist({ kind: "birth", identity, expected });
    const actual = await reader.helper(identity);
    requireObservation(
      actual.sha256 === expected.sha256 &&
        (expected.cdhash === undefined ||
          actual.signature.cdhash === expected.cdhash),
    );
    return identity;
  };
  const retire = latch(async () => {
    const reads = [];
    for (const subject of subjects) {
      reads.push(
        await reader.retired(subject, { reserved: subject.uid !== 0 }),
      );
      if (
        subject.uid === 0 &&
        subject.auid === 0 &&
        subject.asid > 0 &&
        recovered?.domains?.some((domain) => domain.pid === subject.pid)
      )
        reads.push(await reader.retiredRootDomain(subject));
    }
    const empty = await reader.verifyOwnership(0);
    requireObservation(
      empty.enumeration.live.length === 0 &&
        empty.enumeration.zombies.length === 0,
    );
    return {
      verifier: empty.verifier,
      reads,
      independent: true,
      noLiveUid: true,
      helpersSettled: true,
      uid: current.input.request.uid,
    };
  }, true);
  const policy = (value, raw) => {
    const complete = normalizeNativePolicyTemplate({
      ...binding.template,
      bindings: [],
      policy: value,
    }).policy;
    return {
      schemaVersion: 1,
      context: structuredClone(binding.context),
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
    retire,
    latch,
    subjects,
    policy,
    recovered,
    history,
  };
  const owner =
    recipe.group === "files"
      ? createDarwinFileEffects(core)
      : recipe.group === "release"
        ? createDarwinReleaseEffects(core)
        : createDarwinGitEffects(core);
  return {
    effects: owner.effects,
    async prepare() {
      requireObservation(
        specification.contextSha256 === observationDigest(binding.context),
      );
      current.caseEffectsPossible = true;
      const observed = await owner.prepare();
      const request = current.input.request ?? current.input;
      const proof = {
        provisioning: provisioned.provisioning,
        requestSha256: observationDigest(
          nativePolicyLaunchData(request, DARWIN_LITERAL_ARGUMENTS),
        ),
        observed,
      };
      verifyNativePolicy(
        binding.template,
        binding.approval,
        proof.provisioning,
        binding.context,
        proof.requestSha256,
        proof.observed,
      );
      return proof;
    },
    async finish({ signal }) {
      current.cleanupSignal = signal;
      try {
        await reader.beginCleanup({ signal });
        await reader.operation("operation-authority");
        await owner.finish();
        const result = await retire();
        const objects = await reader.retireCase();
        const custody = await reader.close();
        requireObservation(
          custody.status === "RETIRED" && custody.closed && custody.independent,
        );
        current.retired = true;
        const settlement = {
          status: "RETIRED",
          independent: true,
          emergencyCleanup: false,
          nativeEventSha256: observationDigest({ result, objects, custody }),
        };
        await save(recipe.id, { phase: "operation-retired", settlement });
        return settlement;
      } catch (cause) {
        throw (failure ??= cause);
      }
    },
  };
}
