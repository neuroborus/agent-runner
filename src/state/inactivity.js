import { createHash } from "node:crypto";
import { isDeepStrictEqual } from "node:util";

export const DEFAULT_PROVIDER_INACTIVITY_TIMEOUT_MS = 1_800_000;
export const MAX_PROVIDER_INACTIVITY_TIMEOUT_MS = 2_147_483_647;
const FIELDS = [
  "role",
  "checkpoint",
  "attempt",
  "status",
  "reconstructionRevision",
  "configurationFingerprint",
  "contentFingerprint",
];
const HASH = /^[a-f0-9]{64}$/u;

export function normalizeProviderInactivityTimeoutMs(value) {
  if (
    !Number.isSafeInteger(value) ||
    value < 1 ||
    value > MAX_PROVIDER_INACTIVITY_TIMEOUT_MS
  ) {
    throw new TypeError(
      "Provider inactivity timeout must be an integer from 1 through 2147483647.",
    );
  }
  return value;
}

export function providerInactivityFingerprint(timeoutMs) {
  return createHash("sha256")
    .update(
      JSON.stringify({
        providerInactivityTimeoutMs:
          normalizeProviderInactivityTimeoutMs(timeoutMs),
      }),
    )
    .digest("hex");
}

export function normalizeInactivityState(state) {
  const legacy = state.schemaVersion < 17;
  const timeout = normalizeProviderInactivityTimeoutMs(
    legacy && state.providerInactivityTimeoutMs === undefined
      ? DEFAULT_PROVIDER_INACTIVITY_TIMEOUT_MS
      : state.providerInactivityTimeoutMs,
  );
  const fingerprint = providerInactivityFingerprint(timeout);
  const binding =
    legacy && state.providerInactivityFingerprint === undefined
      ? fingerprint
      : state.providerInactivityFingerprint;
  const recovery =
    legacy && state.inactivityRecovery === undefined
      ? null
      : state.inactivityRecovery;
  if (
    binding !== fingerprint ||
    (legacy &&
      (timeout !== DEFAULT_PROVIDER_INACTIVITY_TIMEOUT_MS || recovery !== null))
  ) {
    throw new TypeError(
      "Provider inactivity configuration binding is invalid.",
    );
  }
  if (
    recovery !== null &&
    (typeof recovery !== "object" ||
      Array.isArray(recovery) ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(recovery)) ||
      Reflect.ownKeys(recovery).length !== FIELDS.length ||
      FIELDS.some((key) => !Object.hasOwn(recovery, key)) ||
      typeof recovery.role !== "string" ||
      !Object.hasOwn(state.roles, recovery.role) ||
      typeof recovery.checkpoint !== "string" ||
      !/^[A-Za-z][A-Za-z0-9:._-]{0,127}$/u.test(recovery.checkpoint) ||
      ![1, 2].includes(recovery.attempt) ||
      !["expired", "reconstructing"].includes(recovery.status) ||
      (recovery.status === "reconstructing" && recovery.attempt !== 2) ||
      (recovery.attempt === 1
        ? recovery.reconstructionRevision !== null
        : !Number.isSafeInteger(recovery.reconstructionRevision) ||
          recovery.reconstructionRevision < 1 ||
          recovery.reconstructionRevision > state.revision) ||
      recovery.configurationFingerprint !== fingerprint ||
      typeof recovery.contentFingerprint !== "string" ||
      !HASH.test(recovery.contentFingerprint))
  )
    throw new TypeError("Provider inactivity recovery is invalid.");
  return {
    providerInactivityTimeoutMs: timeout,
    providerInactivityFingerprint: fingerprint,
    inactivityRecovery: recovery === null ? null : { ...recovery },
  };
}

export function inactivityActivity(recovery, kind) {
  return {
    actor: recovery.role,
    phase: "inactivity",
    kind,
    message: `${recovery.role} ${recovery.checkpoint}: provider inactivity ${kind}; attempt ${recovery.attempt} of 2.`,
  };
}

export function projectInactivityRecovery(run) {
  if (run.inactivityRecovery == null) return null;
  const { role, checkpoint, attempt, status } = run.inactivityRecovery;
  return { role, checkpoint, attempt, status };
}

export function assertInactivityContinuity(previous, current, activity) {
  const before = previous.inactivityRecovery;
  const after = current.inactivityRecovery;
  if (isDeepStrictEqual(before, after)) return;
  const validActivity =
    activity?.phase === "inactivity" &&
    activity.actor === (after ?? before).role;
  const retired =
    current.executionProcess === null && current.executionResource === null;
  if (
    !validActivity ||
    (before !== null &&
      after !== null &&
      (before.role !== after.role ||
        before.checkpoint !== after.checkpoint ||
        after.attempt < before.attempt))
  ) {
    throw new TypeError("Inactivity recovery changed checkpoint or allowance.");
  }
  if (after === null) {
    if (
      activity.kind !== "recovered" ||
      !retired ||
      current.activeTurn?.role !== before.role
    )
      throw new TypeError("Inactivity response is not reconciled.");
  } else if (after.status === "expired") {
    if (
      activity.kind !== "expired" ||
      current.activeTurn?.role !== after.role ||
      after.attempt !== (before?.attempt ?? 1) ||
      after.reconstructionRevision !== (before?.reconstructionRevision ?? null)
    )
      throw new TypeError("Inactivity expiry has no active attempt.");
  } else if (
    activity.kind !== "reconstructing" ||
    !retired ||
    after.attempt !== 2 ||
    after.reconstructionRevision !== current.revision ||
    (before === null
      ? current.activeTurn?.role !== after.role
      : current.activeTurn !== null)
  ) {
    throw new TypeError("Inactivity reconstruction is not reconciled.");
  }
}
