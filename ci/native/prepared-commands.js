import {
  observationList,
  observationObject,
  requireObservation,
} from "./observation.js";

/** Select only the fixed compiler inventory. The verification snapshot precedes
 * its own receipt and keeps bootstrap POSSIBLE until the independent reread. */
export function preparedNativeCommands(
  preparation,
  manifest,
  nativeCount,
  { verificationPending = false } = {},
) {
  requireObservation(
    [1, 2].includes(preparation.schemaVersion) &&
      preparation.schemaVersion === manifest.schemaVersion &&
      preparation.candidateSha === manifest.candidateSha &&
      preparation.platform === manifest.platform &&
      typeof verificationPending === "boolean" &&
      Number.isSafeInteger(nativeCount) &&
      nativeCount > 0,
  );
  observationList(preparation.commands, 1024);
  const assets =
    manifest.schemaVersion === 2 ? manifest.prerequisites.assets.length : 0;
  const before = manifest.schemaVersion === 2 ? assets + 1 : 0;
  const after =
    manifest.schemaVersion === 2
      ? manifest.prerequisites.packages.length + (verificationPending ? 0 : 1)
      : 0;
  requireObservation(
    preparation.commands.length === before + nativeCount + after,
  );
  const requests = new Set();
  for (const [index, entry] of preparation.commands.entries()) {
    observationObject(entry, ["requestSha256", "status", "receiptSha256"]);
    requireObservation(
      typeof entry.requestSha256 === "string" &&
        /^[a-f0-9]{64}$/u.test(entry.requestSha256) &&
        !requests.has(entry.requestSha256),
    );
    requests.add(entry.requestSha256);
    if (manifest.schemaVersion === 2 && verificationPending && index === assets)
      requireObservation(
        entry.status === "POSSIBLE" && entry.receiptSha256 === null,
      );
    else
      requireObservation(
        entry.status === "RETIRED" &&
          typeof entry.receiptSha256 === "string" &&
          /^[a-f0-9]{64}$/u.test(entry.receiptSha256),
      );
  }
  return preparation.commands.slice(before, before + nativeCount);
}
