import { digest, normalizeDarwinIdentity, requireDarwin } from "./protocol.js";
import { buildDarwinPolicy, isDarwinDigest } from "./policy.js";
import { assertDarwinPolicyInstallation } from "./policy-effects.js";

export const DARWIN_ACCESS_DENIALS = Object.freeze([
  "metadata-write",
  "pointer-write",
  "pointer-unlink",
  "pointer-replace",
  "parent-replace",
  "receipt-read",
  "receipt-write",
  "checkout-read",
  "configuration-read",
  "credential-read",
  "outside-write",
  "mach",
  "unix-socket",
  "posix-shm",
  "posix-sem",
  "sysv-shm",
  "sysv-sem",
  ...["host-loopback", "wildcard", "host-network", "cross-allocation"].flatMap(
    (kind) =>
      ["inet", "inet6"].flatMap((family) =>
        ["tcp", "udp"].map((protocol) => `${kind}-${family}-${protocol}`),
      ),
  ),
]);
const root = (value) => {
  const identity = normalizeDarwinIdentity(value);
  requireDarwin(
    ["uid", "ruid", "svuid", "gid", "rgid", "svgid"].every(
      (key) => identity[key] === 0,
    ),
  );
  return identity;
};

/** Provider/fixture text never supplies native attempts. The protected observer
 * joins exact nonce bytes and native identities to ready outside controls. */
export function assertDarwinAccessObservation(value, input, admitted) {
  const plan = buildDarwinPolicy(input),
    { request } = plan.value;
  const payload = normalizeDarwinIdentity(admitted.payload);
  const inDomain = (value) => {
    const identity = normalizeDarwinIdentity(value);
    requireDarwin(
      identity.auid === request.uid &&
        identity.asid === payload.asid &&
        ["uid", "ruid", "svuid"].every(
          (key) => identity[key] === request.uid,
        ) &&
        ["gid", "rgid", "svgid"].every((key) => identity[key] === request.gid),
    );
    return identity;
  };
  inDomain(payload);
  const inspection = value?.inspectionObservation;
  inDomain(inspection?.identity);
  requireDarwin(
    inspection.attempted === true &&
      inspection.code === "OK" &&
      inspection.nativeDecision === "permit" &&
      inspection.bytesSha256 === digest(request.nonce) &&
      isDarwinDigest(inspection.nativeEventSha256),
  );
  const edit = value?.editObservation;
  inDomain(edit?.identity);
  requireDarwin(
    edit.attempted === true &&
      edit.beforeSha256 === digest(request.nonce) &&
      (plan.value.profile === "read-only"
        ? edit.afterSha256 === edit.beforeSha256 &&
          ["EPERM", "EACCES"].includes(edit.code) &&
          edit.nativeDecision === "deny"
        : edit.afterSha256 === digest(request.nonce + "-edit") &&
          edit.code === "OK" &&
          edit.nativeDecision === "permit"),
  );
  const verifier = root(value?.verifier);
  requireDarwin(
    payload.asid > 0 &&
      verifier.asid !== payload.asid &&
      value.independent === true &&
      value.candidateSha === request.candidateSha &&
      value.nonce === request.nonce &&
      value.compositionSha256 === plan.compositionSha256 &&
      value.requestSha256 === admitted.requestSha256 &&
      isDarwinDigest(value.requestSha256) &&
      value.inspectionSha256 === digest(request.nonce) &&
      value.edit ===
        (plan.value.profile === "read-only" ? "denied" : "permitted") &&
      isDarwinDigest(value.editEventSha256) &&
      value.protectedUnchanged === true &&
      value.policyPreserved === true &&
      Array.isArray(value.denials) &&
      value.denials.length === DARWIN_ACCESS_DENIALS.length &&
      Array.isArray(value.loopback) &&
      value.loopback.length === 4,
  );
  const seen = new Set();
  for (const denied of value.denials) {
    requireDarwin(
      DARWIN_ACCESS_DENIALS.includes(denied.id) &&
        !seen.has(denied.id) &&
        denied.attempted === true &&
        denied.denied === true &&
        denied.timedOut === false &&
        ["EPERM", "EACCES", "ECONNREFUSED", "MACH_DENIED"].includes(
          denied.code,
        ) &&
        isDarwinDigest(denied.nativeEventSha256) &&
        isDarwinDigest(denied.beforeSha256) &&
        denied.afterSha256 === denied.beforeSha256 &&
        denied.nativeDecision === "deny",
    );
    inDomain(denied.identity);
    const control = denied.control,
      controlIdentity = normalizeDarwinIdentity(control?.identity);
    requireDarwin(
      control.ready === true &&
        control.reachable === true &&
        control.independent === true &&
        control.nonce === request.nonce &&
        control.discretionaryAllowed === true &&
        isDarwinDigest(control.acknowledgementSha256) &&
        isDarwinDigest(control.nativeEventSha256) &&
        controlIdentity.uid !== request.uid &&
        controlIdentity.asid !== payload.asid &&
        control.targetSha256 === denied.beforeSha256,
    );
    if (denied.code === "ECONNREFUSED")
      requireDarwin(
        denied.layer === "pf" && isDarwinDigest(denied.pfDropSha256),
      );
    seen.add(denied.id);
  }
  seen.clear();
  for (const echo of value.loopback) {
    const endpoint = plan.value.endpoints.find(
      (entry) =>
        entry.family === echo.family && entry.protocol === echo.protocol,
    );
    const key = echo.family + echo.protocol;
    requireDarwin(
      endpoint &&
        !seen.has(key) &&
        echo.requestSha256 === digest(request.nonce) &&
        echo.responseSha256 === digest(request.nonce) &&
        echo.timedOut === false &&
        Array.isArray(echo.events) &&
        echo.events.length === 4,
    );
    const directions = new Set();
    for (const event of echo.events) {
      requireDarwin(
        ["request", "return"].includes(event.leg) &&
          ["out", "in"].includes(event.direction) &&
          event.decision === "permit" &&
          event.ownerUid === request.uid &&
          isDarwinDigest(event.nativeEventSha256) &&
          event.sourcePort ===
            (event.leg === "request"
              ? endpoint.clientPort
              : endpoint.serverPort) &&
          event.destinationPort ===
            (event.leg === "request"
              ? endpoint.serverPort
              : endpoint.clientPort) &&
          event.sourceAddress ===
            (endpoint.family === "inet" ? "127.0.0.1" : "::1") &&
          event.destinationAddress === event.sourceAddress,
      );
      inDomain(event.identity);
      requireDarwin(!directions.has(event.leg + event.direction));
      directions.add(event.leg + event.direction);
    }
    seen.add(key);
  }
  return verifier;
}

function retirement(value, plan, admitted) {
  const { request } = plan.value,
    verifier = root(value?.freshVerifier);
  requireDarwin(
    value.status === "RETIRED" &&
      value.helpersSettled === true &&
      value.caseHelpersSettled === true &&
      value.candidateSha === request.candidateSha &&
      value.nonce === request.nonce &&
      value.authoritySha256 === plan.compositionSha256 &&
      value.requestSha256 === admitted.requestSha256 &&
      value.domain?.uid === request.uid &&
      value.domain?.gid === request.gid &&
      value.domain?.asid === admitted.payload.asid &&
      verifier.asid !== admitted.payload.asid &&
      value.reservation === "RETAINED",
  );
  return verifier;
}

/** Explicit external composition. A failed case stays failed after cleanup;
 * policy restoration requires fresh retirement and separate helper settlement. */
export async function runDarwinAccessCase(input, effects) {
  const plan = buildDarwinPolicy(input),
    { request } = plan.value;
  requireDarwin(typeof effects?.persist === "function");
  const record = {
    schemaVersion: 1,
    candidateSha: request.candidateSha,
    nonce: request.nonce,
    profile: plan.value.profile,
    compositionSha256: plan.compositionSha256,
    status: "BLOCKED",
    phase: "preparation",
    reservation: "RETAINED",
    missingInputs: [],
  };
  for (const key of [
    "prepare",
    "verifyPolicy",
    "admit",
    "observe",
    "retire",
    "restore",
  ])
    if (typeof effects[key] !== "function")
      record.missingInputs.push("darwin-access-" + key);
  const save = () => effects.persist(structuredClone(record));
  if (record.missingInputs.length) {
    await save();
    return record;
  }
  let admitted,
    prepared,
    retired,
    retirementAttempted = false;
  const settle = async () => {
    retirementAttempted = true;
    record.phase = "retirement";
    await save();
    retired = structuredClone(
      await effects.retire(
        structuredClone(plan.value),
        structuredClone(admitted),
        structuredClone(prepared),
      ),
    );
    const verifier = retirement(retired, plan, admitted);
    record.retirementVerifier = verifier;
    record.phase = "restoration";
    await save();
    const restored = await effects.restore(
      structuredClone(plan.value),
      structuredClone(retired),
      structuredClone(prepared),
    );
    requireDarwin(
      restored.status === "RESTORED" &&
        restored.helpersSettled === true &&
        restored.candidateSha === request.candidateSha &&
        restored.nonce === request.nonce &&
        restored.compositionSha256 === plan.compositionSha256 &&
        restored.reservation === "RETAINED",
    );
    record.cleanup = { status: "RESTORED", helpersSettled: true };
  };
  try {
    record.status = "RUNNING";
    record.possiblePreparation = true;
    await save();
    prepared = structuredClone(
      await effects.prepare(structuredClone(plan.value)),
    );
    assertDarwinPolicyInstallation(prepared.policy, plan.value);
    record.phase = "admission";
    await save();
    assertDarwinPolicyInstallation(
      await effects.verifyPolicy(
        structuredClone(plan.value),
        structuredClone(prepared),
      ),
      plan.value,
    );
    const candidate = structuredClone(
      await effects.admit(
        structuredClone(plan.value),
        structuredClone(prepared),
      ),
    );
    const identity = normalizeDarwinIdentity(candidate.payload);
    requireDarwin(
      candidate.status === "ADMITTED" &&
        candidate.candidateSha === request.candidateSha &&
        candidate.nonce === request.nonce &&
        candidate.requestSha256 === prepared.launchSha256 &&
        isDarwinDigest(prepared.launchSha256) &&
        candidate.authority?.policy?.compositionSha256 ===
          plan.compositionSha256 &&
        identity.asid > 0 &&
        identity.auid === request.uid &&
        ["uid", "ruid", "svuid"].every(
          (key) => identity[key] === request.uid,
        ) &&
        ["gid", "rgid", "svgid"].every((key) => identity[key] === request.gid),
    );
    admitted = candidate;
    record.phase = "native-observation";
    await save();
    const observation = structuredClone(
      await effects.observe(
        structuredClone(plan.value),
        structuredClone(admitted),
        structuredClone(prepared),
      ),
    );
    record.verifier = assertDarwinAccessObservation(
      observation,
      plan.value,
      admitted,
    );
    record.nativeEvidence = {
      inspection: observation.inspectionObservation.nativeEventSha256,
      edit: observation.editEventSha256,
      denials: observation.denials.map((value) => ({
        id: value.id,
        event: value.nativeEventSha256,
        control: value.control.acknowledgementSha256,
        state: value.beforeSha256,
      })),
      loopback: observation.loopback.map((value) => ({
        family: value.family,
        protocol: value.protocol,
        events: value.events.map((event) => event.nativeEventSha256),
      })),
    };
    await settle();
    record.status = "OBSERVED";
    record.phase = "verified";
    await save();
    return structuredClone(record);
  } catch {
    record.status = "FAIL";
    record.cleanup = { status: "RETAINED" };
    await save();
    if (admitted && !retirementAttempted) {
      try {
        await settle();
      } catch {
        /* Unknown effects retain policy and custody. */
      }
    }
    record.status = "FAIL";
    await save();
    return structuredClone(record);
  }
}
