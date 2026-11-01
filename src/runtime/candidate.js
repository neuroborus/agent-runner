import { assertOwned, bindDirectory } from "./files.js";
import { inspectPayload } from "./payload.js";

// Candidate effects retain the same descriptor-bound storage as startup.
export async function openRuntimeStorage(path, { create = false } = {}) {
  const binding = await bindDirectory(path, { create });
  try {
    assertOwned(await binding.handle.stat({ bigint: true }), 0o700);
    return binding;
  } catch (error) {
    await binding.close();
    throw error;
  }
}

export async function inspectRuntimeCandidate(path) {
  const payload = await inspectPayload(path);
  return {
    payloadId: payload.id,
    manifest: payload.manifest,
    metadata: JSON.parse(payload.captured.get("package.json").bytes.toString()),
  };
}
