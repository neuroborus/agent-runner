import { join } from "node:path";

import { absolutePath, RuntimePayloadError } from "./contract.js";
import { assertOwned, bindDirectory, readRegular } from "./files.js";

// Read the state-owned projection only. Admission rechecks this selection under
// its mutation boundary before any CLI/MCP/run operation can start.
export async function readRuntimeSelection(stateRoot) {
  absolutePath(stateRoot);
  let binding;
  try {
    binding = await bindDirectory(join(stateRoot, "runtime-admission"), {
      privateParents: 1,
    });
    assertOwned(await binding.handle.stat({ bigint: true }), 0o700);
    const file = await readRegular(
      join(binding.anchor, "runtime.json"),
      256 * 1024,
    );
    assertOwned(file.metadata, 0o600);
    const state = JSON.parse(file.bytes);
    if (![1, 2].includes(state?.schemaVersion)) {
      const error = new RuntimePayloadError(
        "Runtime selection version is unsupported.",
      );
      error.code = "ERR_RUNTIME_SELECTION_VERSION";
      throw error;
    }
    if (
      Object.keys(state).sort().join() !==
        (state.schemaVersion === 2
          ? "active,activeOperation,lastOperation,pending,pendingOperation,revision,schemaVersion,users"
          : "active,lastOperation,pending,revision,schemaVersion,users") ||
      !Number.isSafeInteger(state.revision) ||
      state.revision < 1 ||
      typeof state.lastOperation !== "string" ||
      !/^(?:admit|activate|release):[a-f0-9-]{36}$/u.test(
        state.lastOperation,
      ) ||
      !Array.isArray(state.users)
    )
      throw new RuntimePayloadError("Runtime selection is invalid.");
    await binding.verify();
    for (const runtime of [state.active, state.pending]) {
      if (
        runtime !== null &&
        (!runtime ||
          typeof runtime !== "object" ||
          Array.isArray(runtime) ||
          Object.keys(runtime).sort().join() !==
            "executablePath,nodeIdentity,nodePath,nodeVersion,payloadId,rootPath")
      )
        throw new RuntimePayloadError("Selected runtime identity is invalid.");
    }
    for (const key of ["active", "pending"]) {
      const operation = state[`${key}Operation`];
      if (
        state.schemaVersion === 2 &&
        operation !== null &&
        (typeof operation !== "string" ||
          !/^[a-f0-9-]{36}$/u.test(operation) ||
          state[key] === null)
      )
        throw new RuntimePayloadError("Runtime selection proof is invalid.");
    }
    return state.schemaVersion === 2 && state.pendingOperation !== null
      ? state.pending
      : state.active;
  } catch (error) {
    if (error.code === "ENOENT") return null;
    throw error;
  } finally {
    await binding?.close();
  }
}
