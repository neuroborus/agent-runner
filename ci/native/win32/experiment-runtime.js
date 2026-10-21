import { observationDigest, requireObservation } from "../index.js";
import { createWindowsOperationReaders } from "./operation-readers.js";

/** Local build/loader observations supply no release publication, provider
 * approval, source-finding closure or production GO. Reviewed release inspection
 * remains owned by createWindowsReleaseEffects/observeWindowsRelease. */
export function createWindowsExperimentRuntimeEffects(core) {
  const { current, reader, specification, witness, latch, persist } = core,
    reads = createWindowsOperationReaders(
      reader,
      specification,
      current.binding.purpose,
    );
  requireObservation(
    current.binding.purpose === "experiment" &&
      specification.slots.components.length === 13,
  );
  return {
    effects: {
      persist,
      observe: latch(async () => {
        const roots = specification.slots.components.map(({ index }) => index),
          actual = await reads.loader(specification.slots.loader, roots),
          image = specification.slots.components.find(
            ({ id }) => id === "custody-reader",
          );
        requireObservation(image);
        const { processImage, runtime } = await reads.helperRuntime(
          current.admission.helper,
          image.index,
        );
        // Dynamic System/COM loads are observed by the native held-module lane.
        // Mapped identities remain held; import edges cover private runtimes,
        // without claiming transitive hosted-system admission.
        const verifier = await witness(),
          observation = {
            purpose: "experiment",
            status: "OBSERVED",
            candidateSha: current.binding.context.candidateSha,
            actual,
            processImage,
            runtime,
            verifier,
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
      requireObservation(actual.systemOnly && actual.noLiveMembers);
      return core.policy(
        {
          kind: "windows-release",
          authority: "system-only",
          accountSid: current.account.accountSid,
          restrictingSid: current.input.request.restrictingSid,
          inventorySha256: current.declared.custody.plan.sha256,
        },
        actual,
      );
    },
    async finish() {
      // Held immutable images belong to the case custodian. Its existing
      // independent whole-domain close retires the reader before releasing them.
      await persist({ kind: "experiment-runtime-finish" });
    },
  };
}
