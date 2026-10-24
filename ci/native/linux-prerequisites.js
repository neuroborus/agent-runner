import { NativeEvidenceError } from "./evidence.js";

export const LINUX_PREREQUISITE_IDS = Object.freeze([
  "bubblewrap-discovery",
  "bubblewrap-identity",
  "bubblewrap-protection",
  "ordinary-namespace",
  "procfs-retirement",
  "nested-namespaces",
  "private-fixture-storage",
  "protected-executable-abi",
  "bubblewrap-version",
]);
const DIAGNOSES = {
  "bubblewrap-discovery": ["absent"],
  "bubblewrap-identity": ["invalid-identity", "not-executable"],
  "bubblewrap-protection": ["protection-unavailable"],
  "ordinary-namespace": ["probe-failed", "non-isolated-fallback"],
  "procfs-retirement": [],
  "nested-namespaces": ["probe-failed", "non-isolated-fallback"],
  "private-fixture-storage": ["invalid-identity"],
  "protected-executable-abi": ["runtime-mismatch"],
  "bubblewrap-version": ["invalid-version"],
};
const ERRNOS = [
  "ENOENT",
  "ENOTDIR",
  "EACCES",
  "EPERM",
  "ELOOP",
  "EROFS",
  "ENOSPC",
  "EIO",
  "ENOEXEC",
  "ETIMEDOUT",
];
const SIGNALS = [
  "SIGTERM",
  "SIGKILL",
  "SIGABRT",
  "SIGSEGV",
  "SIGBUS",
  "SIGSYS",
];

/** Retain only directly observed, bounded process/filesystem facts. */
export function linuxPrerequisiteObservation(error = null, result = null) {
  const code = result?.error?.code ?? error?.code;
  const exitCode = result?.status;
  return {
    errno: ERRNOS.includes(code) ? code : null,
    exitCode:
      Number.isInteger(exitCode) && exitCode >= 0 && exitCode <= 255
        ? exitCode
        : null,
    signal: SIGNALS.includes(result?.signal) ? result.signal : null,
    timedOut: result
      ? code === "ETIMEDOUT"
        ? true
        : result.error === undefined
          ? false
          : null
      : null,
  };
}

function requireValue(value) {
  if (!value) throw new NativeEvidenceError();
}

function closed(value, keys) {
  requireValue(
    value !== null &&
      typeof value === "object" &&
      Object.getPrototypeOf(value) === Object.prototype,
  );
  requireValue(
    Reflect.ownKeys(value).length === keys.length &&
      keys.every((key) => {
        const descriptor = Object.getOwnPropertyDescriptor(value, key);
        return descriptor?.enumerable && Object.hasOwn(descriptor, "value");
      }),
  );
}

/** A failed prerequisite is diagnostic only; later checks were never reached. */
export function normalizeLinuxPrerequisites(value) {
  closed(value, ["schemaVersion", "status", "failedPrerequisite", "checks"]);
  const failed = LINUX_PREREQUISITE_IDS.indexOf(value.failedPrerequisite);
  requireValue(
    value.schemaVersion === 1 && value.status === "BLOCKED" && failed >= 0,
  );
  requireValue(
    Array.isArray(value.checks) &&
      Object.getPrototypeOf(value.checks) === Array.prototype &&
      value.checks.length === LINUX_PREREQUISITE_IDS.length &&
      Reflect.ownKeys(value.checks).length === value.checks.length + 1,
  );
  const checks = LINUX_PREREQUISITE_IDS.map((id, index) => {
    const descriptor = Object.getOwnPropertyDescriptor(
      value.checks,
      String(index),
    );
    requireValue(descriptor?.enumerable && Object.hasOwn(descriptor, "value"));
    const check = descriptor.value;
    closed(check, ["id", "status", "diagnosis", "observation"]);
    requireValue(
      check.id === id &&
        check.status ===
          (index < failed ? "PASS" : index === failed ? "BLOCKED" : "NOT_RUN"),
    );
    requireValue(
      index === failed
        ? ["unverifiable", ...DIAGNOSES[id]].includes(check.diagnosis)
        : check.diagnosis === null,
    );
    closed(check.observation, ["errno", "exitCode", "signal", "timedOut"]);
    const { errno, exitCode, signal, timedOut } = check.observation;
    requireValue(errno === null || ERRNOS.includes(errno));
    requireValue(
      exitCode === null ||
        (Number.isInteger(exitCode) && exitCode >= 0 && exitCode <= 255),
    );
    requireValue(signal === null || SIGNALS.includes(signal));
    requireValue(timedOut === null || typeof timedOut === "boolean");
    if (index > failed)
      requireValue(
        Object.values(check.observation).every((entry) => entry === null),
      );
    if (
      ![
        "ordinary-namespace",
        "nested-namespaces",
        "protected-executable-abi",
        "bubblewrap-version",
      ].includes(id)
    )
      requireValue(exitCode === null && signal === null && timedOut === null);
    if (index < failed)
      requireValue(
        errno === null &&
          signal === null &&
          timedOut !== true &&
          (exitCode === null || exitCode === 0),
      );
    if (check.diagnosis === "probe-failed")
      requireValue(
        exitCode === 1 &&
          signal === null &&
          errno === null &&
          timedOut === false,
      );
    if (check.diagnosis === "absent")
      requireValue(["ENOENT", "ENOTDIR"].includes(errno));
    if (check.diagnosis === "not-executable")
      requireValue(["EACCES", "EPERM"].includes(errno));
    if (timedOut === true) requireValue(errno === "ETIMEDOUT");
    return {
      id,
      status: check.status,
      diagnosis: check.diagnosis,
      observation: { errno, exitCode, signal, timedOut },
    };
  });
  return {
    schemaVersion: 1,
    status: "BLOCKED",
    failedPrerequisite: value.failedPrerequisite,
    checks,
  };
}

/** Context comes from the validated containing job, never from a diagnosis. */
export function linuxPrerequisiteEvidence(job, diagnosis) {
  return {
    schemaVersion: 1,
    candidateSha: job.candidateSha,
    checkoutSha: job.checkoutSha,
    platform: job.platform,
    declaredImage: job.declaredImage,
    observed: { ...job.observed },
    provenance: { ...job.provenance },
    versions: job.versions.map((entry) => ({ ...entry })),
    diagnosis: normalizeLinuxPrerequisites(diagnosis),
  };
}
