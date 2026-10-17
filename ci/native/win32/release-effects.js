import {
  observationObject,
  observationDigest,
  requireObservation,
  nativePolicyTemplateDigest,
} from "../index.js";
import { digest, inspectWindowsPe } from "./protocol.js";
import { decode } from "./custody-protocol.js";

const same = (a, b) => observationDigest(a) === observationDigest(b);
const keys = ["publication", "source", "build", "license", "abi"];

/** Read-only release inspection. Every image, dependency and package member
 * comes from held, signed custody; no reproduced image is executed here. */
export function createWindowsReleaseEffects(core) {
  const { current, reader, specification, persist, witness, latch } = core;
  const slots = specification.slots;
  observationObject(slots, ["components", "providers", "authority", "sdk"]);
  observationObject(slots.providers, ["codex", "claude"]);
  const index = (slot, kinds) => {
    requireObservation(
      Number.isSafeInteger(slot) &&
        slot >= 0 &&
        kinds.includes(specification.entries[slot]?.kind),
    );
    return slot;
  };
  index(slots.authority, ["data"]);
  for (const slot of Object.values(slots.providers)) index(slot, ["data"]);
  requireObservation(
    Array.isArray(slots.sdk) &&
      slots.sdk.length > 0 &&
      slots.sdk.length <= 128 &&
      new Set(slots.sdk).size === slots.sdk.length,
  );
  for (const slot of slots.sdk) index(slot, ["sdk"]);
  requireObservation(
    same(
      [...slots.sdk].sort((a, b) => a - b),
      specification.entries.flatMap((entry, slot) =>
        entry.kind === "sdk" ? [slot] : [],
      ),
    ),
  );
  requireObservation(
    Array.isArray(slots.components) &&
      slots.components.length > 0 &&
      slots.components.length <= 128 &&
      new Set(slots.components.map(({ id }) => id)).size ===
        slots.components.length &&
      new Set(slots.components.map(({ index }) => index)).size ===
        slots.components.length,
  );
  for (const component of slots.components) {
    observationObject(component, ["id", "index", "loader", "bindings"]);
    index(component.index, ["image", "helper"]);
    observationObject(component.bindings, keys);
    for (const slot of Object.values(component.bindings)) index(slot, ["data"]);
    requireObservation(
      Array.isArray(component.loader) &&
        component.loader.length <= 256 &&
        new Set(component.loader.map(({ name }) => name.toLowerCase())).size ===
          component.loader.length,
    );
    for (const target of component.loader) {
      observationObject(target, ["name", "id", "index"]);
      index(target.index, ["image", "helper"]);
      requireObservation(
        typeof target.name === "string" &&
          /^[A-Za-z0-9_.-]+\.dll$/iu.test(target.name) &&
          slots.components.some(
            (value) => value.id === target.id && value.index === target.index,
          ),
      );
    }
  }
  const handles = new Map(),
    closed = new Set(),
    observations = new Map();
  const inspected = async (handle) => {
    requireObservation(
      handles.get(handle.id) === handle && !closed.has(handle.id),
    );
    const actual = await reader.inspect(handle.index);
    requireObservation(actual.held && !actual.directory && !actual.reparse);
    return {
      identity: actual.identity,
      independent: true,
      held: true,
      regular: true,
      reparse: false,
    };
  };
  const data = async (slot, maximum = 536870912) => {
    const before = await reader.inspect(slot),
      native = await reader.operation("release-build", slot);
    requireObservation(
      Number.isSafeInteger(native.bytes) &&
        native.bytes > 0 &&
        native.bytes <= maximum,
    );
    const chunks = [];
    for (let offset = 0; offset < native.bytes; offset += 65536)
      chunks.push(
        await reader.read(slot, offset, Math.min(65536, native.bytes - offset)),
      );
    const bytes = Buffer.concat(chunks),
      after = await reader.inspect(slot);
    requireObservation(
      same(before, after) &&
        digest(bytes) === specification.entries[slot].sha256,
    );
    return bytes;
  };
  const json = async (slot) => {
    const bytes = await data(slot, 262144),
      value = JSON.parse(bytes);
    requireObservation(bytes.equals(Buffer.from(JSON.stringify(value) + "\n")));
    return value;
  };
  const sdk = async () => {
    const native = await reader.buildBindings(),
      reads = [],
      versions = new Set();
    for (const slot of slots.sdk) {
      const entry = specification.entries[slot];
      const root = decode(native.sdkRootHex);
      requireObservation(entry.path.startsWith(root));
      const version = /^(?:Include|Lib)\\([0-9]+(?:\.[0-9]+){1,3})\\/u.exec(
        entry.path.slice(root.length),
      );
      requireObservation(version);
      versions.add(version[1]);
      reads.push({ path: entry.path, sha256: digest(await data(slot)) });
    }
    requireObservation(versions.size === 1);
    return {
      native,
      sdkBuild: [...versions][0],
      sha256: observationDigest(reads),
    };
  };
  const effects = {
    persist,
    openHeld: latch(async (id) => {
      const component = slots.components.find((value) => value.id === id);
      requireObservation(component && !handles.has(id));
      const handle = { id, index: component.index };
      handles.set(id, handle);
      await inspected(handle);
      await reader.signature(handle.index);
      return handle;
    }),
    inspectHeld: latch(inspected),
    readHeld: latch(async (handle, maximum) => {
      await inspected(handle);
      return data(handle.index, maximum);
    }),
    loaderClosure: latch(async (handle, bytes) => {
      await inspected(handle);
      requireObservation(
        digest(bytes) === specification.entries[handle.index].sha256,
      );
      const component = slots.components.find(
          (value) => value.id === handle.id,
        ),
        actual = await reader.operation("release-pe", handle.index);
      requireObservation(
        actual.complete && actual.imports.length === component.loader.length,
      );
      requireObservation(
        new Set(actual.imports.map(({ name }) => name.toLowerCase())).size ===
          actual.imports.length,
      );
      const ids = [],
        reads = [];
      for (const imported of actual.imports) {
        observationObject(imported, ["name", "host", "delay"]);
        const target = component.loader.find(
          ({ name }) => name.toLowerCase() === imported.name.toLowerCase(),
        );
        requireObservation(target);
        requireObservation(
          typeof imported.delay === "boolean" &&
            imported.host.toLowerCase() ===
              specification.entries[target.index].path
                .split("\\")
                .at(-1)
                .toLowerCase(),
        );
        const dependency = await data(target.index);
        await reader.signature(target.index);
        const pe = await reader.operation("release-pe", target.index);
        requireObservation(pe.complete && pe.dll);
        reads.push({
          index: target.index,
          identity: (await reader.inspect(target.index)).identity,
          sha256: digest(dependency),
          pe,
        });
        if (!ids.includes(target.id)) ids.push(target.id);
      }
      observations.set(handle.id, { actual, reads });
      return {
        components: ids.sort(),
        independent: true,
        complete: true,
        ambiguous: false,
        nativeSha256: observationDigest({ actual, reads }),
      };
    }),
    buildBindings: latch(async (handle) => {
      await inspected(handle);
      const component = slots.components.find(
          (value) => value.id === handle.id,
        ),
        bindings = {};
      for (const key of keys)
        bindings[key] = digest(await data(component.bindings[key], 262144));
      const receipt = await json(component.bindings.build),
        pe = await reader.operation("release-pe", handle.index),
        actual = await sdk();
      observationObject(receipt, [
        "componentSha256",
        "contextSha256",
        "osBuild",
        "sdkBuild",
        "sdkSha256",
        "linkerMajor",
        "linkerMinor",
        "timestamp",
      ]);
      requireObservation(
        receipt.componentSha256 ===
          specification.entries[handle.index].sha256 &&
          receipt.contextSha256 ===
            observationDigest(current.binding.context) &&
          receipt.osBuild ===
            `${actual.native.major}.${actual.native.minor}.${actual.native.build}` &&
          receipt.sdkBuild === actual.sdkBuild &&
          receipt.sdkSha256 === actual.sha256 &&
          receipt.linkerMajor === pe.linkerMajor &&
          receipt.linkerMinor === pe.linkerMinor &&
          receipt.timestamp === pe.timestamp,
      );
      // Executable certificate bytes are checked independently by the native
      // WinVerifyTrust reader; this parser never approves a signature itself.
      if (!pe.dll) inspectWindowsPe(await data(handle.index), 536870912);
      return { bindings, independent: true, complete: true };
    }),
    observeAuthority: latch(async () => {
      requireObservation(
        handles.size === slots.components.length &&
          observations.size === slots.components.length,
      );
      const raw = await reader.operation("operation-authority"),
        authority = await json(slots.authority),
        actual = await sdk();
      observationObject(authority, [
        "schemaVersion",
        "contextSha256",
        "image",
        "sdkBuild",
        "sdkSha256",
        "policyTemplates",
        "privileges",
      ]);
      requireObservation(
        raw.systemOnly &&
          raw.noLiveMembers &&
          authority.schemaVersion === 1 &&
          authority.contextSha256 ===
            observationDigest(current.binding.context) &&
          authority.image === "windows-2025" &&
          same(authority.privileges, ["system"]) &&
          authority.sdkBuild === actual.sdkBuild &&
          authority.sdkSha256 === actual.sha256 &&
          Array.isArray(authority.policyTemplates) &&
          authority.policyTemplates.length > 0 &&
          new Set(authority.policyTemplates).size ===
            authority.policyTemplates.length,
      );
      const policyTemplates = [];
      for (const slot of authority.policyTemplates) {
        index(slot, ["data"]);
        policyTemplates.push(nativePolicyTemplateDigest(await json(slot)));
      }
      return {
        candidateSha: current.binding.context.candidateSha,
        platform: "win32",
        image: authority.image,
        osBuild: `${actual.native.major}.${actual.native.minor}.${actual.native.build}`,
        sdkBuild: authority.sdkBuild,
        policyTemplates: policyTemplates.sort(),
        privileges: ["system"],
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
          record.members.length > 0 &&
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
      await persist({ kind: "release-close-possible", index: handle.index });
      const raw = await reader.operation("release-close", handle.index);
      requireObservation(raw.closed && raw.index === handle.index);
      closed.add(handle.id);
    }, true),
    verifyClosed: latch(async (held) => {
      requireObservation(held.every((handle) => closed.has(handle.id)));
      const raw = await reader.operation("operation-closed");
      requireObservation(held.every((handle) => raw.includes(handle.index)));
      return {
        independent: true,
        closed: true,
        nativeSha256: observationDigest({ raw, verifier: await witness() }),
      };
    }, true),
  };
  return {
    effects,
    async prepare() {
      const raw = await reader.operation("operation-authority");
      requireObservation(raw.systemOnly && raw.noLiveMembers);
      return core.policy(
        {
          kind: "windows-release",
          authority: "system-only",
          accountSid: current.account.accountSid,
          restrictingSid: current.input.request.restrictingSid,
          inventorySha256: current.declared.custody.plan.sha256,
        },
        raw,
      );
    },
    async finish() {
      // A failed open/read still owns every opened reader. Close them using
      // the admitted inventory, even without a successful release observation.
      for (const handle of handles.values())
        if (!closed.has(handle.id)) await effects.closeHeld(handle);
      await effects.verifyClosed([...handles.values()]);
    },
  };
}
