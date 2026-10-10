import path from "node:path";
import {
  observationObject,
  observationDigest,
  requireObservation,
  nativePolicyLaunchData,
} from "../index.js";
import { digest, DARWIN_LITERAL_ARGUMENTS } from "./protocol.js";
import { DARWIN_HELPER_NAMES, darwinBuildOperation } from "./build.js";

const same = (a, b) => observationDigest(a) === observationDigest(b);
const keys = ["publication", "source", "build", "license", "abi"];

/** Every release input is an already held slot in the independently approved
 * custody plan. Provider metadata and image observations never mint approval. */
export function createDarwinReleaseEffects(core) {
  const { state, current, reader, specification, persist, witness, latch } =
    core;
  const { request } = current.input,
    slots = specification.slots;
  observationObject(slots, ["components", "providers", "authority"]);
  requireObservation(
    Array.isArray(slots.components) &&
      slots.components.length > 0 &&
      slots.components.length <= 128 &&
      new Set(slots.components.map(({ id }) => id)).size ===
        slots.components.length,
  );
  const index = (value, kinds) => {
    requireObservation(
      Number.isSafeInteger(value) &&
        value >= 0 &&
        kinds.includes(specification.entries[value]?.kind),
    );
    return value;
  };
  observationObject(slots.providers, ["codex", "claude"]);
  index(slots.authority, ["data"]);
  for (const value of Object.values(slots.providers)) index(value, ["data"]);
  requireObservation(
    new Set(slots.components.map((value) => value.index)).size ===
      slots.components.length,
  );
  for (const component of slots.components) {
    observationObject(component, [
      "id",
      "index",
      "signature",
      "loader",
      "bindings",
    ]);
    requireObservation(
      typeof component.id === "string" &&
        /^[a-zA-Z0-9.-]+$/u.test(component.id),
    );
    index(component.index, ["image", "helper"]);
    observationObject(component.signature, ["cdhash", "entitlementsSha256"]);
    requireObservation(
      /^[a-f0-9]{40}$/u.test(component.signature.cdhash) &&
        /^[a-f0-9]{64}$/u.test(component.signature.entitlementsSha256),
    );
    observationObject(component.bindings, keys);
    for (const value of Object.values(component.bindings))
      index(value, ["data"]);
    requireObservation(
      Array.isArray(component.loader) &&
        new Set(component.loader.map((value) => value.path)).size ===
          component.loader.length,
    );
    for (const target of component.loader) {
      observationObject(target, [
        "id",
        "path",
        "index",
        "cache",
        "cacheUuid",
        "imageUuid",
        "signatureSha256",
      ]);
      requireObservation(
        typeof target.cache === "boolean" &&
          slots.components.some((value) => value.id === target.id),
      );
      index(target.index, target.cache ? ["cache"] : ["image", "helper"]);
    }
  }
  const handles = new Map(),
    closed = new Set(),
    observations = new Map();
  let sdkObservation;
  const sdkBuild = () =>
    (sdkObservation ??= (async () => {
      const names = await state.fs.readdir(state.directory);
      requireObservation(names.length <= 65536);
      const intents = names.filter((name) =>
        /^darwin-command-[a-f0-9]{64}-intent\.json$/u.test(name),
      );
      requireObservation(intents.length <= 2 + DARWIN_HELPER_NAMES.length * 2);
      const matches = [];
      for (const name of intents) {
        const intent = JSON.parse(
          await state.receipt(path.join(state.directory, name)),
        );
        observationObject(intent, [
          "candidateSha",
          "request",
          "requestSha256",
          "status",
          ...(Object.hasOwn(intent, "targetSha256") ? ["targetSha256"] : []),
        ]);
        const operation = darwinBuildOperation(
          intent.request,
          state.manifest,
          state.output,
        );
        if (operation.mode !== "sdk-version") continue;
        const sha256 = observationDigest(intent.request);
        requireObservation(
          intent.candidateSha === current.binding.context.candidateSha &&
            intent.requestSha256 === sha256 &&
            intent.status === "POSSIBLE" &&
            name === `darwin-command-${sha256}-intent.json` &&
            (!Object.hasOwn(intent, "targetSha256") ||
              intent.targetSha256 === null),
        );
        const result = JSON.parse(
          await state.receipt(
            path.join(state.directory, `darwin-command-${sha256}-result.json`),
          ),
        );
        requireObservation(
          result.requestSha256 === sha256 &&
            result.toolSha256 === operation.tool.sha256 &&
            result.independent === true &&
            result.exitCode === 0 &&
            result.signal === null &&
            result.timedOut === false &&
            /^[a-f0-9]{64}$/u.test(result.nativeEventSha256) &&
            result.settlement?.status === "RETIRED" &&
            result.settlement.independent === true &&
            result.settlement.emergencyCleanup === false &&
            result.bootstrapSettlement?.status === "RETIRED" &&
            result.bootstrapSettlement.independent === true &&
            result.bootstrapSettlement.closed === true &&
            typeof result.stdout === "string" &&
            result.stdout.trim() === operation.tool.version,
        );
        await reader.retired(result.identity);
        await reader.retired(result.helperIdentity);
        await reader.retiredRootDomain(result.helperIdentity);
        matches.push(result.stdout.trim());
      }
      requireObservation(matches.length === 1);
      return matches[0];
    })());
  const data = async (index) => {
    const before = await reader.inspect(index),
      bytes = await reader.read(index, 536870912),
      after = await reader.inspect(index);
    requireObservation(
      same(before, after) &&
        digest(bytes) === specification.entries[index].sha256,
    );
    return bytes;
  };
  const json = async (index) => {
    const bytes = await data(index),
      value = JSON.parse(bytes);
    requireObservation(bytes.equals(Buffer.from(JSON.stringify(value) + "\n")));
    return value;
  };
  const inspected = async (handle) => {
    requireObservation(
      handles.get(handle.id) === handle && !closed.has(handle.id),
    );
    const value = await reader.inspect(handle.index);
    requireObservation(
      !value.directory && value.uid === 0 && !(value.mode & 0o22),
    );
    return {
      identity: value.identity,
      independent: true,
      held: true,
      regular: true,
      reparse: false,
    };
  };
  const effects = {
    persist,
    openHeld: latch(async (id) => {
      const slot = slots.components.find((value) => value.id === id);
      requireObservation(slot && !handles.has(id));
      const handle = { id, index: slot.index };
      handles.set(id, handle);
      await inspected(handle);
      const signature = await reader.signature(slot.index);
      requireObservation(
        signature.valid &&
          same(
            {
              cdhash: signature.cdhash,
              entitlementsSha256: signature.entitlementsSha256,
            },
            slot.signature,
          ),
      );
      return handle;
    }),
    inspectHeld: latch(inspected),
    readHeld: latch(async (handle, maximum) => {
      await inspected(handle);
      requireObservation(maximum === 536870912);
      return data(handle.index);
    }),
    loaderClosure: latch(async (handle, bytes) => {
      await inspected(handle);
      requireObservation(
        digest(bytes) === specification.entries[handle.index].sha256,
      );
      const slot = slots.components.find((value) => value.id === handle.id),
        actual = await reader.macho(handle.index);
      requireObservation(
        actual.rpaths.length === 0 &&
          Array.isArray(slot.loader) &&
          slot.loader.length === actual.dependencies.length,
      );
      const components = [],
        reads = [];
      for (const path of actual.dependencies) {
        const target = slot.loader.find((value) => value.path === path);
        requireObservation(target && !components.includes(target.id));
        let read;
        if (target.cache) {
          read = await reader.cache(target.index, path);
          const component = slots.components.find(
            (value) => value.id === target.id,
          );
          requireObservation(component && component.index !== target.index);
          const packaged = await reader.macho(component.index);
          requireObservation(
            read.cacheUuid === target.cacheUuid &&
              read.imageUuid === target.imageUuid &&
              read.signatureSha256 === target.signatureSha256 &&
              packaged.uuid === read.imageUuid &&
              same(packaged, read.macho),
          );
        } else {
          requireObservation(
            (await reader.location(target.index)) === path &&
              target.cacheUuid === null &&
              target.imageUuid === null &&
              target.signatureSha256 === null,
          );
          read = {
            macho: await reader.macho(target.index),
            signature: await reader.signature(target.index),
            sha256: digest(await data(target.index)),
          };
          const component = slots.components.find(
            (value) => value.id === target.id,
          );
          requireObservation(
            component?.index === target.index &&
              same(
                {
                  cdhash: read.signature.cdhash,
                  entitlementsSha256: read.signature.entitlementsSha256,
                },
                component.signature,
              ),
          );
        }
        components.push(target.id);
        reads.push(read);
      }
      observations.set(handle.id, { actual, reads });
      return {
        components: components.sort(),
        independent: true,
        complete: true,
        ambiguous: false,
        nativeSha256: observationDigest({ actual, reads }),
      };
    }),
    buildBindings: latch(async (handle) => {
      await inspected(handle);
      const slot = slots.components.find((value) => value.id === handle.id),
        bindings = {};
      for (const key of keys)
        bindings[key] = digest(await data(slot.bindings[key]));
      const build = await reader.build(),
        image = await reader.macho(handle.index);
      const receipt = await json(slot.bindings.build);
      observationObject(receipt, [
        "componentSha256",
        "contextSha256",
        "osBuild",
        "sdk",
        "minimum",
        "sdkBuild",
      ]);
      requireObservation(
        receipt.componentSha256 ===
          specification.entries[handle.index].sha256 &&
          receipt.contextSha256 ===
            observationDigest(current.binding.context) &&
          receipt.osBuild === build.osBuild &&
          receipt.sdk === image.sdk &&
          receipt.minimum === image.minimum &&
          receipt.sdkBuild === (await sdkBuild()),
      );
      return { bindings, independent: true, complete: true };
    }),
    observeAuthority: latch(async () => {
      const actual = await reader.operation("operation-authority");
      observationObject(actual, ["identity", "sandboxed", "noLiveUid"]);
      requireObservation(
        ["uid", "ruid", "svuid", "gid", "rgid", "svgid"].every(
          (key) => actual.identity[key] === 0,
        ) &&
          actual.sandboxed === false &&
          actual.noLiveUid === true,
      );
      const approval = await json(slots.authority);
      observationObject(approval, [
        "schemaVersion",
        "contextSha256",
        "image",
        "sdkBuild",
        "policyTemplates",
        "privileges",
      ]);
      requireObservation(
        approval.schemaVersion === 1 &&
          approval.contextSha256 ===
            observationDigest(current.binding.context) &&
          same(approval.privileges, ["root"]) &&
          approval.image === "macos-15-intel",
      );
      const build = await reader.build();
      const sdk = await sdkBuild();
      requireObservation(approval.sdkBuild === sdk);
      requireObservation(
        Array.isArray(approval.policyTemplates) &&
          approval.policyTemplates.length > 0 &&
          new Set(approval.policyTemplates).size ===
            approval.policyTemplates.length,
      );
      const policyTemplates = [];
      for (const slot of approval.policyTemplates) {
        index(slot, ["data"]);
        policyTemplates.push(digest(await data(slot)));
      }
      return {
        candidateSha: current.binding.context.candidateSha,
        platform: "darwin",
        image: approval.image,
        osBuild: build.osBuild,
        sdkBuild: sdk,
        policyTemplates: policyTemplates.sort(),
        privileges: ["root"],
        independent: true,
        ownedChangesOnly: true,
      };
    }),
    inspectProvider: latch(async (name, held) => {
      requireObservation(["codex", "claude"].includes(name));
      const record = await json(slots.providers[name]);
      observationObject(record, ["reviewSha256", "closureSha256", "members"]);
      requireObservation(
        Array.isArray(record.members) &&
          record.members.length &&
          new Set(record.members).size === record.members.length,
      );
      const reads = [];
      for (const id of record.members) {
        const handle = held.find((value) => value.id === id);
        requireObservation(handle && observations.has(id));
        reads.push({
          id,
          identity: (await inspected(handle)).identity,
          sha256: digest(await data(handle.index)),
          loader: observations.get(id),
        });
      }
      return {
        ...record,
        independent: true,
        liveBindingSha256: observationDigest({ record, reads }),
      };
    }),
    closeHeld: latch(async (handle) => {
      await inspected(handle);
      const result = await reader.closeHeld(handle.index);
      requireObservation(result.closed && result.index === handle.index);
      closed.add(handle.id);
    }, true),
    verifyClosed: latch(async (held) => {
      requireObservation(held.every((handle) => closed.has(handle.id)));
      const reads = await reader.operation("slots-closed");
      requireObservation(held.every((handle) => reads.includes(handle.index)));
      const verifier = await witness();
      return {
        independent: true,
        closed: true,
        nativeSha256: observationDigest({ reads, verifier }),
      };
    }, true),
  };
  return {
    effects,
    async prepare() {
      const actual = await reader.operation("operation-authority");
      requireObservation(
        actual.identity.uid === 0 &&
          actual.identity.gid === 0 &&
          actual.sandboxed === false &&
          actual.noLiveUid,
      );
      const policy = {
        launch: nativePolicyLaunchData(request, DARWIN_LITERAL_ARGUMENTS),
        policy: {
          kind: "darwin-release",
          authority: {
            uid: actual.identity.uid,
            gid: actual.identity.gid,
            sandboxed: actual.sandboxed,
          },
          inventorySha256: current.declared.custody.plan.sha256,
        },
      };
      return core.policy(policy, { actual, verifier: await witness() });
    },
    async finish() {
      requireObservation([...handles.keys()].every((id) => closed.has(id)));
    },
  };
}
