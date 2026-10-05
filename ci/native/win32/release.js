import { createHash } from "node:crypto";
import {
  normalizeReleaseClosure,
  verifyReleaseClosure,
  releaseClosureDigest,
  normalizeReviewAuthority,
  observationDigest,
  requireObservation,
} from "../index.js";
import { inspectWindowsPe } from "./protocol.js";
import { normalizeWindowsFileIdentity } from "./files-protocol.js";

/** CI-only native reads. No pathname selected by the provider is accepted.
 * The external verifier retains every opened image until the closure is read. */
export async function observeWindowsRelease(input, authority, effects) {
  const manifest = normalizeReleaseClosure(input);
  requireObservation(manifest.platform === "win32");
  normalizeReviewAuthority(authority, manifest.candidateSha, manifest.platform);
  requireObservation(
    authority.manifestSha256 === releaseClosureDigest(manifest),
  );
  for (const name of [
    "openHeld",
    "inspectHeld",
    "readHeld",
    "loaderClosure",
    "buildBindings",
    "observeAuthority",
    "inspectProvider",
    "closeHeld",
    "verifyClosed",
  ])
    requireObservation(typeof effects?.[name] === "function");
  const held = [],
    components = [];
  let authorityRead, providers, settlement;
  try {
    for (const expected of manifest.components) {
      const handle = await effects.openHeld(expected.id);
      held.push(handle);
      const before = await effects.inspectHeld(handle);
      requireObservation(
        before?.independent === true &&
          before.held === true &&
          before.reparse === false &&
          before.regular === true,
      );
      normalizeWindowsFileIdentity(before.identity);
      const bytes = await effects.readHeld(handle, 134217728);
      requireObservation(
        Buffer.isBuffer(bytes) && bytes.length > 0 && bytes.length <= 134217728,
      );
      if (expected.role !== "dependency") inspectWindowsPe(bytes);
      else {
        requireObservation(
          bytes.length >= 512 && bytes.readUInt16LE(0) === 0x5a4d,
        );
        const offset = bytes.readUInt32LE(0x3c);
        requireObservation(
          offset >= 64 &&
            offset <= bytes.length - 264 &&
            bytes.readUInt32LE(offset) === 0x4550 &&
            bytes.readUInt16LE(offset + 4) === 0x8664 &&
            (bytes.readUInt16LE(offset + 22) & 0x2000) !== 0 &&
            bytes.readUInt16LE(offset + 24) === 0x20b,
        );
      }
      // Resolve actual load commands/imports and ABI images through held native
      // reads. A list copied from the reviewed manifest is not an observation.
      const loader = await effects.loaderClosure(handle, bytes);
      requireObservation(
        loader?.independent === true &&
          loader.complete === true &&
          loader.ambiguous === false &&
          /^[a-f0-9]{64}$/u.test(loader.nativeSha256),
      );
      const build = await effects.buildBindings(handle);
      requireObservation(
        build?.independent === true && build.complete === true,
      );
      const after = await effects.inspectHeld(handle);
      requireObservation(
        after?.independent === true &&
          after.held === true &&
          after.reparse === false &&
          after.regular === true &&
          normalizeWindowsFileIdentity(after.identity) === before.identity,
      );
      components.push({
        id: expected.id,
        sha256: createHash("sha256").update(bytes).digest("hex"),
        format: expected.format,
        loader: loader.components,
        bindings: build.bindings,
        identityBefore: observationDigest(before.identity),
        identityAfter: observationDigest(after.identity),
        held: true,
        independent: true,
      });
    }
    authorityRead = await effects.observeAuthority();
    requireObservation(
      authorityRead?.independent === true &&
        authorityRead.ownedChangesOnly === true,
    );
    // Keep each reader within this held-resource lifetime. A fail-fast join
    // must never leave a second reader running while finally closes its files.
    providers = {};
    for (const name of ["codex", "claude"])
      providers[name] = await effects.inspectProvider(name, held);
  } finally {
    let closeFailed = false;
    for (const handle of held.reverse()) {
      try {
        await effects.closeHeld(handle);
      } catch {
        closeFailed = true;
      }
    }
    settlement = await effects.verifyClosed(held);
    requireObservation(
      !closeFailed &&
        settlement?.independent === true &&
        settlement.closed === true &&
        /^[a-f0-9]{64}$/u.test(settlement.nativeSha256),
    );
  }
  const observation = {
    schemaVersion: 1,
    candidateSha: authorityRead.candidateSha,
    platform: authorityRead.platform,
    image: authorityRead.image,
    osBuild: authorityRead.osBuild,
    sdkBuild: authorityRead.sdkBuild,
    policySha256: authorityRead.policySha256,
    privileges: authorityRead.privileges,
    components,
    providers,
    independent: true,
    settlementSha256: settlement.nativeSha256,
  };
  return {
    observation,
    closure: verifyReleaseClosure(manifest, observation, authority),
  };
}
