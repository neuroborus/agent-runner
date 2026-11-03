export const UUID =
  /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/u;
export const SRI = /^sha512-[A-Za-z0-9+/]{86}==$/u;
export const MAX_CANDIDATE_ATTEMPTS = 3;
export const fields = (value, names) =>
  value &&
  typeof value === "object" &&
  !Array.isArray(value) &&
  Object.keys(value).sort().join() === [...names].sort().join();
const ownership = (value) =>
  fields(value, ["dev", "ino", "uid"]) &&
  Object.values(value).every(
    (part) => typeof part === "string" && /^\d{1,30}$/u.test(part),
  );
const metadataFields = [
  "name",
  "version",
  "private",
  "license",
  "repository",
  "publishConfig",
  "engines",
  "agentRunnerCompatibility",
];
export const selectedMetadata = (metadata) =>
  Object.fromEntries(
    metadataFields.map((key) => [key, structuredClone(metadata[key])]),
  );
export const fail = (code) => {
  throw Object.assign(
    new Error("Candidate preparation could not be verified."),
    { code },
  );
};
export const receipt = (
  operationId,
  version,
  status,
  blockers = [],
  restartRequired = status === "validated",
) =>
  Object.freeze({
    schemaVersion: 1,
    operationId,
    version,
    status,
    blockers: Object.freeze([...blockers]),
    restartRequired,
  });

export const preparationContext = (storageRoot) => ({
  schemaVersion: 2,
  storageRoot,
  rootIdentity: null,
  selection: null,
  attempts: [],
  process: null,
  candidate: null,
  downloadedVersion: null,
  installedVersion: null,
});
export const preparationRequest = (
  operationId,
  version,
  storageRoot,
  official,
) => ({
  key: `update:${operationId}`,
  tool: "update_prepare",
  arguments: { version, storageRoot, official },
});

export function assertContext(context, root) {
  if (
    !fields(context, [
      "schemaVersion",
      "storageRoot",
      "rootIdentity",
      "selection",
      "attempts",
      "process",
      "candidate",
      ...(context?.schemaVersion === 2
        ? ["downloadedVersion", "installedVersion"]
        : []),
    ]) ||
    ![1, 2].includes(context.schemaVersion) ||
    (context.schemaVersion === 2 &&
      [context.downloadedVersion, context.installedVersion].some(
        (value) =>
          value !== null && value !== context.selection?.metadata?.version,
      )) ||
    context.storageRoot !== root ||
    (context.rootIdentity !== null && !ownership(context.rootIdentity)) ||
    !Array.isArray(context.attempts) ||
    context.attempts.length > MAX_CANDIDATE_ATTEMPTS ||
    new Set(context.attempts.map((attempt) => attempt?.id)).size !==
      context.attempts.length ||
    (context.attempts.length > 0 && context.rootIdentity === null) ||
    context.attempts.some(
      (attempt) =>
        !fields(attempt, ["id", "identity", "phase", "smokeIdentity"]) ||
        !UUID.test(attempt.id) ||
        (attempt.identity !== null && !ownership(attempt.identity)) ||
        (attempt.identity === null &&
          !["allocated", "failed"].includes(attempt.phase)) ||
        (attempt.smokeIdentity !== null && !ownership(attempt.smokeIdentity)) ||
        ![
          "allocated",
          "packing",
          "packed",
          "installing",
          "installed",
          "smoking",
          "validated",
          "failed",
        ].includes(attempt.phase),
    )
  )
    fail("storage_unverifiable");
  const process = context.process;
  if (
    process !== null &&
    (!context.attempts.length ||
      !["packing", "installing", "smoking"].includes(
        context.attempts.at(-1).phase,
      ) ||
      !fields(process, [
        "pid",
        "hostname",
        "processIdentity",
        "namespaceId",
        "observerNamespace",
      ]) ||
      !Number.isSafeInteger(process.pid) ||
      process.pid < 1 ||
      typeof process.hostname !== "string" ||
      process.hostname.length > 255 ||
      !fields(process.processIdentity, ["bootId", "startTicks"]) ||
      !/^[a-f0-9-]{36}$/u.test(process.processIdentity.bootId) ||
      !/^\d{1,30}$/u.test(process.processIdentity.startTicks) ||
      !/^pid:\[\d+\]$/u.test(process.namespaceId) ||
      !/^pid:\[\d+\]$/u.test(process.observerNamespace))
  )
    fail("process_unverifiable");
}
