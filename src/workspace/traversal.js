import { assertSafe } from "./paths.js";

// Progress is bounded and contains no source names or content. Awaiting the
// hook lets the execution owner supervise traversal without owning its reads.
export function traversalCheckpoints({ signal, onProgress } = {}) {
  assertSafe(
    signal === undefined || signal instanceof AbortSignal,
    "Traversal requires an AbortSignal.",
  );
  assertSafe(
    onProgress === undefined || typeof onProgress === "function",
    "Traversal progress must be a function.",
  );
  let completed = 0;
  let previousPhase;
  return async (phase) => {
    signal?.throwIfAborted();
    completed += 1;
    if (onProgress && (phase !== previousPhase || completed % 128 === 0)) {
      previousPhase = phase;
      await onProgress(Object.freeze({ phase, completed }));
      signal?.throwIfAborted();
    }
  };
}
