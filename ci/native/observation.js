import { createHash } from "node:crypto";

export const NATIVE_OBSERVER_LIMITS = Object.freeze({
  routes: 32,
  events: 4096,
  recordBytes: 65536,
  captureBytes: 8388608,
  sessionMs: 120000,
  cleanupMs: 30000,
});
const OPERATIONS = Object.freeze([
  "command",
  "read",
  "write",
  "git",
  "outside",
  "credential",
  "network",
  "ipc",
]);
const PHASES = Object.freeze(["control-permit", "control-deny", "tool"]);
const READ_KEYS = Object.freeze([
  "eventSequence",
  "routeId",
  "phase",
  "targetSha256",
  "barrierSha256",
  "nonceSha256",
  "beforeSha256",
  "afterSha256",
  "sentinelsBeforeSha256",
  "sentinelsAfterSha256",
  "verifierSha256",
  "independent",
]);
const hash = (value) =>
  typeof value === "string" && /^[a-f0-9]{64}$/u.test(value);
export const observationDigest = (value) =>
  createHash("sha256").update(JSON.stringify(value)).digest("hex");
export function requireObservation(value) {
  if (!value) throw new Error("Unverified native tool observation");
}
export function observationObject(value, keys) {
  requireObservation(
    value &&
      Object.getPrototypeOf(value) === Object.prototype &&
      Reflect.ownKeys(value).length === keys.length,
  );
  for (const key of keys) {
    const field = Object.getOwnPropertyDescriptor(value, key);
    requireObservation(field?.enumerable && Object.hasOwn(field, "value"));
  }
}
export function observationList(value, maximum) {
  requireObservation(
    Array.isArray(value) &&
      Object.getPrototypeOf(value) === Array.prototype &&
      value.length <= maximum &&
      Reflect.ownKeys(value).length === value.length + 1,
  );
  return Array.from({ length: value.length }, (_, index) => {
    const field = Object.getOwnPropertyDescriptor(value, index);
    requireObservation(field?.enumerable && Object.hasOwn(field, "value"));
    return field.value;
  });
}

/** Only synthetic identities and hashes cross the shared evidence boundary.
 * Native selectors, process APIs, transport and custody stay platform-owned. */
export function normalizeToolObservationPlan(value) {
  observationObject(value, [
    "schemaVersion",
    "candidateSha",
    "nonce",
    "domainSha256",
    "policySha256",
    "reviewSha256",
    "routes",
  ]);
  requireObservation(
    value.schemaVersion === 1 &&
      typeof value.candidateSha === "string" &&
      /^[a-f0-9]{40}$/u.test(value.candidateSha) &&
      typeof value.nonce === "string" &&
      /^(?:[a-f0-9]{32}|[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12})$/u.test(
        value.nonce,
      ),
  );
  for (const key of ["domainSha256", "policySha256", "reviewSha256"])
    requireObservation(hash(value[key]));
  const routes = observationList(
    value.routes,
    NATIVE_OBSERVER_LIMITS.routes,
  ).map((route) => {
    observationObject(route, [
      "id",
      "operation",
      "targetSha256",
      "permitTargetSha256",
      "denyTargetSha256",
      "nonceSha256",
      "beforeSha256",
      "afterSha256",
      "outcome",
    ]);
    requireObservation(
      typeof route.id === "string" &&
        /^[a-z][a-z0-9-]{0,63}$/u.test(route.id) &&
        OPERATIONS.includes(route.operation) &&
        ["permit", "deny"].includes(route.outcome),
    );
    for (const key of [
      "targetSha256",
      "permitTargetSha256",
      "denyTargetSha256",
      "nonceSha256",
      "beforeSha256",
      "afterSha256",
    ])
      requireObservation(hash(route[key]));
    requireObservation(
      new Set([
        route.targetSha256,
        route.permitTargetSha256,
        route.denyTargetSha256,
      ]).size === 3 &&
        (route.outcome !== "deny" || route.beforeSha256 === route.afterSha256),
    );
    return Object.freeze({ ...route });
  });
  requireObservation(
    routes.length > 0 &&
      new Set(routes.map((route) => route.id)).size === routes.length,
  );
  return Object.freeze({ ...value, routes: Object.freeze(routes) });
}

export function assertNativeObserverHealth(value) {
  observationObject(value, [
    "complete",
    "dropped",
    "truncated",
    "ambiguous",
    "overflow",
    "bytes",
  ]);
  requireObservation(
    value.complete === true &&
      value.dropped === 0 &&
      value.truncated === 0 &&
      value.ambiguous === 0 &&
      value.overflow === false &&
      Number.isSafeInteger(value.bytes) &&
      value.bytes > 0 &&
      value.bytes <= NATIVE_OBSERVER_LIMITS.captureBytes,
  );
}

/** Used before provider release as well as by the final join. A failed
 * positive control must stop execution, rather than fail only afterwards. */
export function assertNativeToolAttempt(input, event, read, observerSha256) {
  const plan = normalizeToolObservationPlan(input);
  observationObject(event, [
    "sequence",
    "routeId",
    "phase",
    "operation",
    "outcome",
    "nativeId",
    "subjectSha256",
    "targetSha256",
    "barrierSha256",
  ]);
  requireObservation(
    Number.isSafeInteger(event.sequence) &&
      event.sequence > 0 &&
      typeof event.nativeId === "string" &&
      /^[a-z0-9:.-]{1,128}$/u.test(event.nativeId) &&
      hash(event.barrierSha256) &&
      hash(observerSha256),
  );
  const route = plan.routes.find((item) => item.id === event.routeId);
  requireObservation(route && PHASES.includes(event.phase));
  const target =
    event.phase === "control-permit"
      ? route.permitTargetSha256
      : event.phase === "control-deny"
        ? route.denyTargetSha256
        : route.targetSha256;
  const outcome =
    event.phase === "tool"
      ? route.outcome
      : event.phase === "control-permit"
        ? "permit"
        : "deny";
  observationObject(read, READ_KEYS);
  requireObservation(
    event.subjectSha256 === plan.domainSha256 &&
      event.operation === route.operation &&
      event.outcome === outcome &&
      event.targetSha256 === target &&
      read.independent === true &&
      read.routeId === event.routeId &&
      read.phase === event.phase &&
      read.eventSequence === event.sequence &&
      read.targetSha256 === target &&
      read.barrierSha256 === event.barrierSha256 &&
      read.nonceSha256 === route.nonceSha256 &&
      hash(read.verifierSha256) &&
      read.verifierSha256 !== observerSha256 &&
      read.verifierSha256 !== plan.domainSha256 &&
      hash(read.beforeSha256) &&
      hash(read.afterSha256) &&
      hash(read.sentinelsBeforeSha256) &&
      read.sentinelsBeforeSha256 === read.sentinelsAfterSha256 &&
      (event.phase === "tool"
        ? read.beforeSha256 === route.beforeSha256 &&
          read.afterSha256 === route.afterSha256
        : outcome === "permit"
          ? read.afterSha256 === route.nonceSha256
          : read.beforeSha256 === read.afterSha256),
  );
}

/** A successful model turn or controller acknowledgement is never an event.
 * Each route needs both native controls before the tool window, an actual
 * kernel event in that window, independent bytes and complete retirement. */
export function joinNativeToolObservations(input, value) {
  const plan = normalizeToolObservationPlan(input);
  observationObject(value, [
    "candidateSha",
    "nonce",
    "domainSha256",
    "policySha256",
    "observerSha256",
    "providerStartSequence",
    "events",
    "reads",
    "health",
    "settlement",
  ]);
  for (const key of ["candidateSha", "nonce", "domainSha256", "policySha256"])
    requireObservation(value[key] === plan[key]);
  requireObservation(
    hash(value.observerSha256) &&
      Number.isSafeInteger(value.providerStartSequence) &&
      value.providerStartSequence > 0,
  );
  assertNativeObserverHealth(value.health);
  const events = observationList(value.events, NATIVE_OBSERVER_LIMITS.events);
  const reads = observationList(value.reads, NATIVE_OBSERVER_LIMITS.events);
  requireObservation(
    events.length === plan.routes.length * 3 && reads.length === events.length,
  );
  for (const read of reads) observationObject(read, READ_KEYS);
  const used = new Set(),
    identities = new Set(),
    barriers = new Set();
  let previous = 0;
  for (const event of events) {
    observationObject(event, [
      "sequence",
      "routeId",
      "phase",
      "operation",
      "outcome",
      "nativeId",
      "subjectSha256",
      "targetSha256",
      "barrierSha256",
    ]);
    requireObservation(
      Number.isSafeInteger(event.sequence) &&
        event.sequence > previous &&
        typeof event.nativeId === "string" &&
        /^[a-z0-9:.-]{1,128}$/u.test(event.nativeId) &&
        !identities.has(event.nativeId) &&
        hash(event.subjectSha256) &&
        hash(event.barrierSha256) &&
        !barriers.has(event.barrierSha256),
    );
    previous = event.sequence;
    identities.add(event.nativeId);
    barriers.add(event.barrierSha256);
    const route = plan.routes.find((item) => item.id === event.routeId);
    requireObservation(
      route &&
        PHASES.includes(event.phase) &&
        event.operation === route.operation &&
        event.subjectSha256 === plan.domainSha256,
    );
    const key = event.routeId + ":" + event.phase;
    requireObservation(!used.has(key));
    used.add(key);
    const control = event.phase !== "tool";
    requireObservation(
      control
        ? event.sequence < value.providerStartSequence
        : event.sequence >= value.providerStartSequence,
    );
    const matching = reads.filter(
      (read) => read.eventSequence === event.sequence,
    );
    requireObservation(matching.length === 1);
    assertNativeToolAttempt(plan, event, matching[0], value.observerSha256);
  }
  assertNativeObserverSettlement(plan, value.settlement, value.observerSha256);
  return Object.freeze({
    schemaVersion: 1,
    candidateSha: plan.candidateSha,
    nonce: plan.nonce,
    domainSha256: plan.domainSha256,
    policySha256: plan.policySha256,
    status: "OBSERVED",
    eventsSha256: observationDigest(events),
    readsSha256: observationDigest(reads),
    settlementSha256: observationDigest(value.settlement),
    operationIds: Object.freeze(plan.routes.map((route) => route.id)),
  });
}

export function assertNativeObserverSettlement(
  input,
  settlement,
  observerSha256,
) {
  const plan = normalizeToolObservationPlan(input);
  observationObject(settlement, [
    "candidateSha",
    "nonce",
    "domainSha256",
    "payloadsRetired",
    "observersRetired",
    "independent",
    "verifierSha256",
    "beforeAuditSha256",
    "installedAuditSha256",
    "restoredAuditSha256",
    "ownedChangesOnly",
    "reservation",
  ]);
  requireObservation(
    settlement.candidateSha === plan.candidateSha &&
      settlement.nonce === plan.nonce &&
      settlement.domainSha256 === plan.domainSha256 &&
      settlement.payloadsRetired === true &&
      settlement.observersRetired === true &&
      settlement.independent === true &&
      settlement.ownedChangesOnly === true &&
      settlement.reservation === "RETAINED" &&
      hash(settlement.verifierSha256) &&
      settlement.verifierSha256 !== observerSha256 &&
      settlement.verifierSha256 !== plan.domainSha256 &&
      hash(settlement.beforeAuditSha256) &&
      hash(settlement.installedAuditSha256) &&
      settlement.restoredAuditSha256 === settlement.beforeAuditSha256,
  );
}
