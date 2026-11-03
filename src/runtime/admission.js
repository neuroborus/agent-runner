import { randomUUID } from "node:crypto";

import {
  getRuntimeContext,
  prepareRuntime,
  RUNTIME_PAYLOAD_ENV,
} from "./bootstrap.js";
import { RuntimePayloadError } from "./contract.js";

function runtimeIdentity(context) {
  return Object.fromEntries(
    [
      "payloadId",
      "rootPath",
      "executablePath",
      "nodePath",
      "nodeVersion",
      "nodeIdentity",
    ].map((key) => [key, context[key]]),
  );
}

// Stay standard-library-only: the pre-import runtime index must not load state
// or providers from the replaceable outer installation. Composition supplies it.
export function createRuntimeAdmission({
  runStore,
  context = getRuntimeContext(),
}) {
  async function admissionEffect(operation) {
    try {
      return await operation();
    } catch (cause) {
      if (
        typeof cause?.code === "string" &&
        cause.code.startsWith("ERR_RUNTIME_")
      )
        throw cause;
      const error = new RuntimePayloadError(
        "Runtime admission could not be verified.",
        { cause },
      );
      error.code = "ERR_RUNTIME_ADMISSION";
      throw error;
    }
  }
  async function verifiedRuntime(candidate = context) {
    if (candidate?.mode !== "pinned")
      throw new RuntimePayloadError("A pinned runtime is required.");
    return admissionEffect(() =>
      prepareRuntime({
        rootPath: candidate.rootPath,
        environment: { [RUNTIME_PAYLOAD_ENV]: JSON.stringify(candidate) },
      }),
    );
  }

  return Object.freeze({
    async withAdmission(kind, operation, boundaries = async () => []) {
      if (context === null || context.mode === "development")
        return operation();
      const pinned = await verifiedRuntime();
      const runtime = runtimeIdentity(pinned);
      await admissionEffect(async () =>
        runStore.assertRuntimeBoundary([
          pinned.rootPath,
          pinned.installationPath,
          ...(await boundaries()),
        ]),
      );
      const id = randomUUID();
      let originalFailure;
      try {
        const admitted = await admissionEffect(() =>
          runStore.admitRuntime({ id, runtime, kind }),
        );
        if (admitted.status !== "admitted") {
          const error = new RuntimePayloadError(
            "Runtime activation is deferred until associated users retire.",
          );
          error.code = "ERR_RUNTIME_RESTART_REQUIRED";
          throw error;
        }
        return await operation();
      } catch (error) {
        originalFailure = error;
        throw error;
      } finally {
        try {
          await admissionEffect(() => runStore.releaseRuntime(id));
        } catch (error) {
          if (!originalFailure) throw error;
        }
      }
    },
    async activate(candidate, { id = randomUUID() } = {}) {
      const pinned = await verifiedRuntime(candidate);
      const runtime = runtimeIdentity(pinned);
      await admissionEffect(() =>
        runStore.assertRuntimeBoundary([
          pinned.rootPath,
          pinned.installationPath,
        ]),
      );
      return admissionEffect(() => runStore.activateRuntime({ id, runtime }));
    },
  });
}
