import { inspectRuntimeArchive } from "../src/runtime/index.js";

export async function inspectReleaseArchive(path, manifest) {
  const { files, bytes } = await inspectRuntimeArchive(path, manifest);
  return Object.freeze({ files, bytes });
}
