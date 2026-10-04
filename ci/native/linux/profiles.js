import {
  NativeEvidenceError,
  LINUX_ACCESS_POLICY_ID,
  normalizeNativeResult,
  hasNativeProcessEffects,
} from "../index.js";

export const ACCESS_PROFILES = Object.freeze([
  "read-only",
  "workspace-write",
  "trusted-command",
  "commit",
]);
export {
  FIXED_SUBJECT,
  validateCommitRequest,
  validateCommitEffect,
  validateCommitMetadata,
} from "../index.js";
export const ACCESS_POLICY_ID = LINUX_ACCESS_POLICY_ID;

function requireValue(value) {
  if (!value) throw new NativeEvidenceError();
}

/** The commit grant belongs solely to a fixed protected executor. Ordinary
 * profiles all receive read-only metadata and a protected Git pointer. */
export function accessGrants(profile, storage) {
  requireValue(ACCESS_PROFILES.includes(profile));
  return [
    {
      source: storage.workspace,
      target: "/workspace",
      writable: profile !== "read-only" && profile !== "commit",
    },
    {
      source: storage.metadata,
      target: "/metadata",
      writable: profile === "commit",
    },
    { source: storage.pointer, target: "/workspace/.git", writable: false },
    { source: storage.git, target: "/proof/bin/git", writable: false },
    {
      source: storage.operation,
      target: "/proof/operation.json",
      writable: false,
    },
    { source: storage.hooks, target: "/proof/hooks", writable: false },
    ...(profile === "commit"
      ? [
          {
            source: storage.protocol,
            target: "/proof/protocol.cjs",
            writable: false,
          },
        ]
      : []),
  ];
}

export const DENIAL_IDS = Object.freeze([
  "git-add",
  "git-commit",
  "git-config",
  "git-index",
  "git-ref",
  "git-pointer",
  "outside-write",
  "credential-read",
  "checkout-read",
  "receipt-read",
  "receipt-write",
  "control-write",
  "host-loopback",
  "host-network",
  "host-socket",
  "abstract-socket",
]);

/** A failure code alone is insufficient: each attempted denial joins a ready
 * external positive control and independently unchanged protected state. */
export function validateAccessObservation(profile, value, sentinelsUnchanged) {
  requireValue(ACCESS_PROFILES.includes(profile) && profile !== "commit");
  requireValue(
    value?.type === "access-result" &&
      value.profile === profile &&
      value.inspection === true &&
      value.loopback === true &&
      value.edit === (profile === "read-only" ? "denied" : "permitted") &&
      sentinelsUnchanged === true &&
      Array.isArray(value.denials),
  );
  const ids = [
    ...DENIAL_IDS,
    ...(profile === "read-only" ? ["content-write"] : []),
  ];
  requireValue(value.denials.length === ids.length);
  const seen = new Set();
  for (const denial of value.denials) {
    requireValue(
      denial &&
        Object.getPrototypeOf(denial) === Object.prototype &&
        Reflect.ownKeys(denial).sort().join(",") ===
          "attempted,code,denied,id,positiveControl" &&
        ids.includes(denial.id) &&
        !seen.has(denial.id) &&
        denial.attempted === true &&
        denial.denied === true &&
        denial.positiveControl === true,
    );
    if (["git-add", "git-commit"].includes(denial.id)) {
      requireValue(
        typeof denial.code === "string" &&
          /^EXIT_[1-9][0-9]{0,2}$/u.test(denial.code) &&
          Number(denial.code.slice(5)) <= 255,
      );
    } else {
      const codes = [
        "host-loopback",
        "host-network",
        "host-socket",
        "abstract-socket",
      ].includes(denial.id)
        ? [
            "ENOENT",
            "EACCES",
            "EPERM",
            "ECONNREFUSED",
            "ENETUNREACH",
            "EHOSTUNREACH",
          ]
        : ["ENOENT", "EACCES", "EROFS", "EPERM", "EBUSY"];
      requireValue(codes.includes(denial.code));
    }
    seen.add(denial.id);
  }
  return value.denials.map((entry) => ({ ...entry }));
}

/** Preserve earlier attempted cases when a later fixture fails before admission.
 * Only producer-known non-admission can leave probe/cleanup unattempted. */
export function recordAccessSetupFailure(result, elapsedMs) {
  requireValue(Number.isSafeInteger(elapsedMs) && elapsedMs >= 0);
  result = normalizeNativeResult(result);
  const attempted = hasNativeProcessEffects(result);
  const notRun = () => ({
    status: "NOT_RUN",
    elapsedMs: null,
    deadlineMs: 30000,
    reason: "missing-input",
  });
  const reason = elapsedMs > 30000 ? "deadline" : "setup-failed";
  return normalizeNativeResult({
    ...result,
    admission: attempted ? "possible" : "not-started",
    status: "FAIL",
    reason,
    phases: {
      setup: { status: "FAIL", elapsedMs, deadlineMs: 30000, reason },
      probe: attempted
        ? result.phases.probe.status === "PASS"
          ? { ...result.phases.probe, status: "FAIL", reason: "setup-failed" }
          : result.phases.probe
        : notRun(),
      cleanup: attempted ? result.phases.cleanup : notRun(),
    },
    observations: result.observations,
    settlement: attempted
      ? result.settlement
      : {
          status: "RETAINED",
          independent: false,
          emergencyCleanup: false,
        },
  });
}
