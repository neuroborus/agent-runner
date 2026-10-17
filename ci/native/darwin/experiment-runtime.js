import {
  observationDigest,
  requireObservation,
  nativePolicyLaunchData,
} from "../index.js";
import {
  digest,
  inspectDarwinMachO,
  DARWIN_LITERAL_ARGUMENTS,
} from "./protocol.js";
import { DARWIN_HELPER_NAMES } from "./build.js";

/** Held local runtime observations confer no provider, publication or licensing
 * approval. The reviewed release owner deliberately exposes a different contract. */
export function createDarwinExperimentRuntimeEffects(core) {
  const { state, current, reader, specification, persist, latch } = core,
    { build, inputs } = state.preparation,
    slots = specification.slots;
  requireObservation(
    current.binding.purpose === "experiment" &&
      slots.components.length === DARWIN_HELPER_NAMES.length &&
      new Set(slots.components.map(({ id }) => id)).size ===
        DARWIN_HELPER_NAMES.length &&
      new Set([...slots.components.map(({ index }) => index), slots.loader])
        .size ===
        DARWIN_HELPER_NAMES.length + 1 &&
      DARWIN_HELPER_NAMES.every((name) =>
        slots.components.some(({ id }) => id === name),
      ),
  );
  return {
    effects: {
      persist,
      observe: latch(async () => {
        const images = [],
          runtime = [];
        for (const { id, index } of slots.components) {
          const expected = build.helpers.find(({ name }) => name === id),
            before = await reader.inspect(index),
            bytes = await reader.read(index),
            signature = await reader.signature(index),
            macho = await reader.macho(index),
            after = await reader.inspect(index),
            parsed = inspectDarwinMachO(bytes, 134217728, "experiment");
          requireObservation(
            expected &&
              before.identity === expected.identity &&
              observationDigest(before) === observationDigest(after) &&
              before.uid === 0 &&
              !before.directory &&
              !(before.mode & 0o22) &&
              parsed.sha256 === expected.sha256 &&
              signature.valid &&
              signature.cdhash === expected.cdhash &&
              observationDigest(macho) === observationDigest(expected.macho),
          );
          requireObservation(
            parsed.libraries.every((file) =>
              build.sdk.runtime.some(({ path }) => path === file),
            ),
          );
          images.push({
            id,
            sha256: digest(bytes),
            identity: before.identity,
            macho,
          });
        }
        for (const { path, observation: prior } of build.sdk.runtime) {
          const observed = await reader.readBuildRuntime(slots.cachePath, path);
          requireObservation(
            observed.held &&
              observed.independent &&
              observed.unchanged &&
              observationDigest(observed) === observationDigest(prior),
          );
          runtime.push({ path, observed });
        }
        const loaderBefore = await reader.inspect(slots.loader),
          loader = await reader.read(slots.loader),
          loaderMacho = await reader.macho(slots.loader),
          loaderAfter = await reader.inspect(slots.loader),
          abi = await reader.build();
        requireObservation(
          digest(loader) === specification.entries[slots.loader].sha256 &&
            digest(loader) === inputs.loader.sha256 &&
            loaderBefore.identity === inputs.loader.identity &&
            loaderBefore.uid === 0 &&
            !loaderBefore.directory &&
            !(loaderBefore.mode & 0o22) &&
            observationDigest(loaderBefore) ===
              observationDigest(loaderAfter) &&
            observationDigest(loaderMacho) ===
              observationDigest(inputs.loader.macho) &&
            observationDigest(abi) === observationDigest(build.abi),
        );
        const observation = {
          purpose: "experiment",
          status: "OBSERVED",
          images,
          runtime,
          loaderSha256: digest(loader),
          abi,
          buildSha256: observationDigest(build),
        };
        await persist({ kind: "experiment-runtime", observation });
        return {
          ...observation,
          evidenceSha256: observationDigest(observation),
        };
      }),
    },
    async prepare() {
      const actual = await reader.operation("operation-authority");
      requireObservation(
        actual.noLiveUid &&
          actual.sandboxed === false &&
          actual.identity.uid === 0 &&
          actual.identity.gid === 0,
      );
      return core.policy(
        {
          launch: nativePolicyLaunchData(
            current.input.request,
            DARWIN_LITERAL_ARGUMENTS,
          ),
          policy: {
            kind: "darwin-runtime",
            inventorySha256: current.declared.custody.plan.sha256,
          },
        },
        actual,
      );
    },
    async finish() {
      await persist({ kind: "experiment-runtime-finish" });
    },
  };
}
