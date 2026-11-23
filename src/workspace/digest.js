import { createHash } from "node:crypto";

// Hash the complete ordered sequence without allocating another source-sized
// serialized string. Projection never changes capture or traversal scope.
export function hashRecords(records) {
  const digest = createHash("sha256");
  digest.update("[");
  let separator = "";
  for (const record of records) {
    digest.update(separator);
    digest.update(JSON.stringify(record));
    separator = ",";
  }
  return digest.update("]").digest("hex");
}
