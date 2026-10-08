const PLATFORMS = Object.freeze(["linux", "darwin", "win32"]);
const SHA = /^[a-f0-9]{40}$/u;
const DIGEST = /^[a-f0-9]{64}$/u;
const matches = (pattern, value) =>
  typeof value === "string" && pattern.test(value);
const STATUSES = Object.freeze(["PASS", "FAIL", "BLOCKED"]);
const CAUSES = Object.freeze([
  "unimplemented",
  "prerequisite-unavailable",
  "setup-failed",
  "crash",
  "deadline",
  "observed-escape",
  "missing-observation",
  "missing-record",
  "cleanup-failed",
  "cleanup-unobserved",
  "checkout-mismatch",
  "checkout-unobserved",
  "platform-mismatch",
  "platform-unobserved",
]);

// This experiment inventory neither narrows nor substitutes for full acceptance.
export const FEASIBILITY_CAPABILITIES = Object.freeze(
  [
    ["launch.argv", "native", "PERMITTED"],
    ["access.read-only", "native", "DENIED"],
    ["access.workspace-write", "native", "DENIED"],
    ["git.denial", "native", "DENIED"],
    ["storage.private", "native", "PERMITTED"],
    ["storage.substitution", "native", "PRESERVED"],
    ["network.tcp-denial", "native", "DENIED"],
    ["ipc.local-denial", "native", "DENIED"],
    ["ownership.cancel", "native", "RETIRED"],
    ["ownership.owner-loss", "native", "RETIRED"],
    ["ownership.final-handle-close", "native", "RETIRED", "win32"],
    ["codex.command-exec", "model-free", "DENIED"],
    ["provider.transport", "protected", "PERMITTED"],
    ["codex.command-tools", "protected", "DENIED"],
    ["codex.file-tools", "protected", "DENIED"],
    ["claude.command-tools", "protected", "DENIED"],
    ["claude.file-tools", "protected", "DENIED"],
  ].map(([id, tier, outcome, platform = null]) =>
    Object.freeze({ id, tier, outcome, platform }),
  ),
);

export class FeasibilityError extends Error {
  constructor() {
    super("Invalid native feasibility request or evidence.");
    this.code = "ERR_INVALID_NATIVE_FEASIBILITY";
  }
}

export function requireFeasibility(condition) {
  if (!condition) throw new FeasibilityError();
}

function object(value, keys) {
  requireFeasibility(
    value &&
      Object.getPrototypeOf(value) === Object.prototype &&
      Reflect.ownKeys(value).length === keys.length,
  );
  for (const key of keys) {
    const field = Object.getOwnPropertyDescriptor(value, key);
    requireFeasibility(field?.enumerable && Object.hasOwn(field, "value"));
  }
}

function text(value, maximum = 256) {
  requireFeasibility(
    typeof value === "string" &&
      value.length > 0 &&
      Buffer.byteLength(value) <= maximum &&
      value.isWellFormed() &&
      !/[\p{Cc}\p{Zl}\p{Zp}]/u.test(value),
  );
  return value;
}

function elapsed(value) {
  requireFeasibility(
    value === null || (Number.isSafeInteger(value) && value >= 0),
  );
}

function cause(value) {
  if (value === null) return null;
  object(value, ["code", "detail"]);
  requireFeasibility(CAUSES.includes(value.code));
  text(value.detail);
  // Producers provide concrete public diagnoses, never raw output or secrets.
  requireFeasibility(
    !/(?:https?:\/\/|(?:^|\s)(?:\/|[A-Za-z]:[\\/])|\b(?:authorization|password|secret|token|cookie)\s*[:=]|\bBearer\s|::)/iu.test(
      value.detail,
    ),
  );
  return Object.freeze({ ...value });
}

export function feasibilityCapabilities(platform) {
  requireFeasibility(PLATFORMS.includes(platform));
  return FEASIBILITY_CAPABILITIES.filter(
    (entry) => entry.platform === null || entry.platform === platform,
  );
}

function emptyResult(capability, status, firstCause) {
  return {
    capability,
    status,
    cause: firstCause,
    elapsedMs: null,
    components: [],
    evidence: null,
    cleanup: {
      status: "NOT_RUN",
      independent: false,
      emergency: false,
      elapsedMs: null,
      witnessSha256: null,
      cause: null,
    },
  };
}

export function unavailableFeasibilityResults(
  platform,
  firstCause = {
    code: "unimplemented",
    detail: "The experiment capability owner is not implemented.",
  },
) {
  const normalized = cause(firstCause);
  requireFeasibility(normalized !== null);
  const status = ["unimplemented", "prerequisite-unavailable"].includes(
    normalized.code,
  )
    ? "BLOCKED"
    : "FAIL";
  return feasibilityCapabilities(platform).map(({ id }) =>
    emptyResult(id, status, normalized),
  );
}

function normalizeResult(input, capability) {
  object(input, [
    "capability",
    "status",
    "cause",
    "elapsedMs",
    "components",
    "evidence",
    "cleanup",
  ]);
  requireFeasibility(
    input.capability === capability.id && STATUSES.includes(input.status),
  );
  let status = input.status;
  let firstCause = cause(input.cause);
  requireFeasibility((status === "PASS") === (firstCause === null));
  if (status === "BLOCKED")
    requireFeasibility(
      ["unimplemented", "prerequisite-unavailable"].includes(firstCause.code),
    );
  elapsed(input.elapsedMs);
  requireFeasibility(
    Array.isArray(input.components) && input.components.length <= 16,
  );
  const components = Array.from(input.components, (entry) => {
    object(entry, ["role", "name", "version", "sha256"]);
    requireFeasibility(
      ["tool", "helper"].includes(entry.role) &&
        matches(/^[a-z][a-z0-9.-]{0,63}$/u, entry.name) &&
        matches(DIGEST, entry.sha256),
    );
    text(entry.version, 128);
    return Object.freeze({ ...entry });
  });
  requireFeasibility(
    new Set(components.map(({ role, name }) => `${role}:${name}`)).size ===
      components.length,
  );
  let evidence = null;
  if (input.evidence !== null) {
    object(input.evidence, [
      "ready",
      "positiveControl",
      "attemptAcknowledged",
      "independent",
      "outcome",
      "observationSha256",
      "sentinelsBeforeSha256",
      "sentinelsAfterSha256",
    ]);
    for (const key of [
      "ready",
      "positiveControl",
      "attemptAcknowledged",
      "independent",
    ])
      requireFeasibility(typeof input.evidence[key] === "boolean");
    requireFeasibility(
      input.evidence.outcome === null ||
        ["PERMITTED", "DENIED", "PRESERVED", "RETIRED"].includes(
          input.evidence.outcome,
        ),
    );
    for (const key of [
      "observationSha256",
      "sentinelsBeforeSha256",
      "sentinelsAfterSha256",
    ])
      requireFeasibility(
        input.evidence[key] === null || matches(DIGEST, input.evidence[key]),
      );
    evidence = Object.freeze({ ...input.evidence });
  }
  const cleanup = input.cleanup;
  object(cleanup, [
    "status",
    "independent",
    "emergency",
    "elapsedMs",
    "witnessSha256",
    "cause",
  ]);
  requireFeasibility(
    ["NOT_RUN", "PASS", "FAIL", "UNCERTAIN"].includes(cleanup.status) &&
      typeof cleanup.independent === "boolean" &&
      typeof cleanup.emergency === "boolean" &&
      (cleanup.witnessSha256 === null ||
        matches(DIGEST, cleanup.witnessSha256)),
  );
  elapsed(cleanup.elapsedMs);
  let cleanupCause = cause(cleanup.cause);
  requireFeasibility(
    ["FAIL", "UNCERTAIN"].includes(cleanup.status) === (cleanupCause !== null),
  );
  if (cleanup.status === "NOT_RUN")
    requireFeasibility(
      !cleanup.independent &&
        !cleanup.emergency &&
        cleanup.elapsedMs === null &&
        cleanup.witnessSha256 === null,
    );
  if (firstCause?.code === "unimplemented")
    requireFeasibility(
      status === "BLOCKED" &&
        input.elapsedMs === null &&
        components.length === 0 &&
        evidence === null &&
        cleanup.status === "NOT_RUN",
    );
  if (status === "PASS") {
    const missing = [
      ["elapsedMs", input.elapsedMs !== null],
      ["components.tool", components.some(({ role }) => role === "tool")],
      ["components.helper", components.some(({ role }) => role === "helper")],
      ["evidence.ready", evidence?.ready],
      ["evidence.positiveControl", evidence?.positiveControl],
      ["evidence.attemptAcknowledged", evidence?.attemptAcknowledged],
      ["evidence.independent", evidence?.independent],
      ["evidence.outcome", evidence?.outcome === capability.outcome],
      ["evidence.observationSha256", Boolean(evidence?.observationSha256)],
      [
        "evidence.sentinelsBeforeSha256",
        Boolean(evidence?.sentinelsBeforeSha256),
      ],
      [
        "evidence.sentinelsAfterSha256",
        evidence?.sentinelsBeforeSha256 === evidence?.sentinelsAfterSha256,
      ],
    ].find(([, observed]) => !observed);
    if (input.elapsedMs > 120000 || missing) {
      status = "FAIL";
      firstCause = {
        code: input.elapsedMs > 120000 ? "deadline" : "missing-observation",
        detail:
          input.elapsedMs > 120000
            ? "Capability observation exceeded the 120000 ms deadline."
            : `Incomplete capability evidence: ${missing[0]}.`,
      };
    }
  }
  let cleanupStatus = cleanup.status;
  if (
    cleanup.emergency ||
    (cleanup.status === "PASS" &&
      !(
        cleanup.independent &&
        cleanup.elapsedMs !== null &&
        cleanup.elapsedMs <= 30000 &&
        cleanup.witnessSha256 !== null
      )) ||
    (cleanup.status === "NOT_RUN" &&
      (input.status === "PASS" || evidence?.attemptAcknowledged))
  ) {
    if (cleanupStatus !== "FAIL") cleanupStatus = "UNCERTAIN";
    cleanupCause ??= {
      code: "cleanup-unobserved",
      detail: cleanup.emergency
        ? "Cleanup required emergency intervention."
        : cleanup.elapsedMs > 30000
          ? "Cleanup observation exceeded the 30000 ms deadline."
          : cleanup.status === "NOT_RUN"
            ? "Cleanup was not observed after claimed or acknowledged effects."
            : !cleanup.independent
              ? "Cleanup lacks an independent observer."
              : cleanup.elapsedMs === null
                ? "Cleanup elapsed time is unobserved."
                : "Cleanup witness digest is missing.",
    };
  }
  if (["FAIL", "UNCERTAIN"].includes(cleanupStatus)) {
    status = "FAIL";
    firstCause ??= cleanupCause;
  }
  return Object.freeze({
    ...input,
    status,
    cause: Object.freeze(firstCause),
    components: Object.freeze(components),
    evidence,
    cleanup: Object.freeze({
      ...cleanup,
      status: cleanupStatus,
      cause: Object.freeze(cleanupCause),
    }),
  });
}

/** Validate supplied observations only; this pure assessment authenticates no CI
 * worker or native witness. Protected BLOCKED records are expected in PR checks. */
export function assessFeasibilityReport(
  input,
  { protectedAcceptance = false } = {},
) {
  object(input, [
    "schemaVersion",
    "expectedSha",
    "checkoutSha",
    "platform",
    "os",
    "build",
    "architecture",
    "results",
  ]);
  requireFeasibility(
    input.schemaVersion === 1 &&
      matches(SHA, input.expectedSha) &&
      (input.checkoutSha === null || matches(SHA, input.checkoutSha)) &&
      (input.os === null || PLATFORMS.includes(input.os)) &&
      (input.architecture === null ||
        ["x64", "arm64", "ia32"].includes(input.architecture)) &&
      typeof protectedAcceptance === "boolean",
  );
  if (input.build !== null) text(input.build);
  const capabilities = feasibilityCapabilities(input.platform);
  requireFeasibility(
    Array.isArray(input.results) && input.results.length <= capabilities.length,
  );
  const submitted = new Map();
  for (const entry of input.results) {
    requireFeasibility(
      entry &&
        capabilities.some(({ id }) => id === entry.capability) &&
        !submitted.has(entry.capability),
    );
    submitted.set(entry.capability, entry);
  }
  const results = capabilities.map((capability) =>
    normalizeResult(
      submitted.get(capability.id) ??
        emptyResult(capability.id, "FAIL", {
          code: "missing-record",
          detail: "A required experiment capability record is absent.",
        }),
      capability,
    ),
  );
  const issues = [];
  if (input.checkoutSha !== input.expectedSha)
    issues.push({
      code:
        input.checkoutSha === null
          ? "checkout-unobserved"
          : "checkout-mismatch",
      detail:
        "The independently observed checkout does not establish the expected revision.",
    });
  if (
    input.os !== input.platform ||
    input.architecture !== "x64" ||
    input.build === null
  )
    issues.push({
      code:
        input.os === null || input.build === null || input.architecture === null
          ? "platform-unobserved"
          : "platform-mismatch",
      detail:
        "The observed platform, build and architecture do not establish the declared worker.",
    });
  const required = results.filter(
    (_, index) =>
      protectedAcceptance || capabilities[index].tier !== "protected",
  );
  const status =
    issues.length || results.some((entry) => entry.status === "FAIL")
      ? "FAIL"
      : required.some((entry) => entry.status === "BLOCKED")
        ? "BLOCKED"
        : "PASS";
  return Object.freeze({
    report: Object.freeze({ ...input, results: Object.freeze(results) }),
    status,
    issues: Object.freeze(issues.map((entry) => Object.freeze(entry))),
  });
}
