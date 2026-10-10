import {
  normalizeDarwinIdentity,
  normalizeDarwinLaunch,
  requireDarwin,
  sameDarwinIdentity,
} from "./protocol.js";

const isRoot = (identity) =>
  ["uid", "ruid", "svuid", "gid", "rgid", "svgid"].every(
    (key) => identity[key] === 0,
  );

function normalizeRetirement(value, request, requestSha256, asid) {
  const identity = normalizeDarwinIdentity(value?.freshVerifier);
  requireDarwin(
    value.status === "RETIRED" &&
      value.requestSha256 === requestSha256 &&
      value.candidateSha === request.candidateSha &&
      value.nonce === request.nonce &&
      value.helpersSettled === true &&
      value.domain?.uid === request.uid &&
      value.domain?.gid === request.gid &&
      asid > 0 &&
      value.domain?.asid === asid &&
      value.reservation === "RETAINED" &&
      isRoot(identity) &&
      identity.asid !== asid,
  );
  return identity;
}

export const DARWIN_OWNERSHIP_CASES = Object.freeze([
  "fork-exec",
  "double-fork",
  "reparent",
  "cancel",
  "owner-loss",
  "helper-loss",
  "receipt-recovery",
  "stale-identity",
  "process-limit",
]);

/** External native cases use private data-pipe acknowledgements, independent
 * task/file reads and protected faults. This protocol admits no catalog PASS. */
export async function runDarwinOwnershipCase(caseId, input, effects) {
  const request = normalizeDarwinLaunch(input);
  requireDarwin(
    DARWIN_OWNERSHIP_CASES.includes(caseId) &&
      typeof effects?.persist === "function",
  );
  const record = {
    schemaVersion: 1,
    caseId,
    candidateSha: request.candidateSha,
    nonce: request.nonce,
    status: "BLOCKED",
    phase: "admission",
    reservation: "RETAINED",
    missingInputs: [],
  };
  for (const key of [
    "admit",
    "observe",
    "armFault",
    "fireFault",
    "recoverAndRetire",
    "verify",
  ])
    if (typeof effects[key] !== "function")
      record.missingInputs.push("darwin-ownership-" + key);
  const save = () => effects.persist(structuredClone(record));
  if (record.missingInputs.length) {
    await save();
    return record;
  }
  let retirementAttempted = false,
    retired,
    payload;
  try {
    record.status = "RUNNING";
    await save();
    const admitted = structuredClone(
      await effects.admit(caseId, structuredClone(request)),
    );
    requireDarwin(
      admitted.status === "ADMITTED" &&
        admitted.candidateSha === request.candidateSha &&
        admitted.nonce === request.nonce &&
        typeof admitted.requestSha256 === "string" &&
        /^[a-f0-9]{64}$/u.test(admitted.requestSha256),
    );
    record.requestSha256 = admitted.requestSha256;
    payload = normalizeDarwinIdentity(admitted.payload);
    const inDomain = (identity) =>
      identity.uid === request.uid &&
      identity.ruid === request.uid &&
      identity.svuid === request.uid &&
      identity.gid === request.gid &&
      identity.rgid === request.gid &&
      identity.svgid === request.gid &&
      identity.auid === request.uid &&
      identity.asid === payload.asid;
    requireDarwin(payload.asid > 0 && inDomain(payload));
    record.phase = "observation";
    await save();
    const observation = await effects.observe(
      caseId,
      structuredClone(request),
      structuredClone(admitted),
    );
    requireDarwin(
      observation.caseId === caseId &&
        observation.nonce === request.nonce &&
        observation.attempted === true &&
        observation.independent === true &&
        observation.outsideUnchanged === true &&
        /^[a-f0-9]{64}$/u.test(observation.nativeEventSha256) &&
        /^[a-f0-9]{64}$/u.test(observation.bytesSha256) &&
        Array.isArray(observation.members) &&
        observation.members.length >= (caseId === "stale-identity" ? 1 : 2) &&
        observation.members.length <= 32,
    );
    const members = observation.members.map(normalizeDarwinIdentity);
    requireDarwin(
      new Set(members.map((value) => value.pid)).size === members.length &&
        members.every(inDomain),
    );
    if (caseId === "stale-identity") {
      const before = normalizeDarwinIdentity(observation.before),
        after = normalizeDarwinIdentity(observation.after);
      requireDarwin(
        inDomain(before) &&
          inDomain(after) &&
          before.pid === payload.pid &&
          before.startSeconds === payload.startSeconds &&
          before.startMicroseconds === payload.startMicroseconds &&
          before.pid === after.pid &&
          before.startSeconds === after.startSeconds &&
          before.startMicroseconds === after.startMicroseconds &&
          before.pidVersion !== after.pidVersion &&
          members.some((value) => sameDarwinIdentity(value, after)) &&
          observation.staleRejected === true &&
          observation.forcedPidReuse === false,
      );
    }
    if (caseId === "process-limit")
      requireDarwin(
        observation.forkError === "EAGAIN" &&
          members.length === 32 &&
          observation.softLimit === 32 &&
          observation.hardLimit === 32,
      );
    record.members = members;
    record.nativeEventSha256 = observation.nativeEventSha256;
    record.bytesSha256 = observation.bytesSha256;
    record.phase = "fault-barrier";
    await save();
    const acknowledgement = await effects.armFault(
      caseId,
      structuredClone(request),
      structuredClone(record),
    );
    requireDarwin(
      acknowledgement.caseId === caseId &&
        acknowledgement.nonce === request.nonce &&
        acknowledgement.armed === true &&
        /^[a-f0-9]{64}$/u.test(acknowledgement.receiptSha256),
    );
    record.faultSha256 = acknowledgement.receiptSha256;
    record.phase = "fault-possible";
    await save();
    await effects.fireFault(
      caseId,
      structuredClone(request),
      structuredClone(acknowledgement),
    );
    record.phase = "recovery";
    await save();
    retirementAttempted = true;
    retired = await effects.recoverAndRetire(
      structuredClone(request),
      admitted.requestSha256,
    );
    const retirementVerifier = normalizeRetirement(
      retired,
      request,
      admitted.requestSha256,
      payload.asid,
    );
    const fresh = await effects.verify(
      caseId,
      structuredClone(request),
      structuredClone(retired),
      structuredClone(record),
    );
    const verifier = normalizeDarwinIdentity(fresh.verifier);
    requireDarwin(
      fresh.independent === true &&
        fresh.noLiveMembers === true &&
        fresh.helpersSettled === true &&
        fresh.outsideUnchanged === true &&
        fresh.nonce === request.nonce &&
        fresh.requestSha256 === admitted.requestSha256 &&
        isRoot(verifier) &&
        verifier.asid !== payload.asid &&
        verifier.pid !== retirementVerifier.pid &&
        !admitted.helpers.some((entry) => entry.identity.pid === verifier.pid),
    );
    record.status = "OBSERVED";
    record.phase = "verified";
    record.verifier = verifier;
    await save();
    return structuredClone(record);
  } catch {
    record.status = "FAIL";
    record.cleanup = { status: "RETAINED" };
    await save();
    // Fault/observation failure still retires the admitted domain. Never repair
    // the failed case with cleanup or repeat an unsettled retirement execution.
    if (!retirementAttempted && record.requestSha256) {
      record.phase = "failure-retirement";
      await save();
      try {
        retired = await effects.recoverAndRetire(
          structuredClone(request),
          record.requestSha256,
        );
      } catch {
        /* The external possible-effect ledger retains unknown helpers. */
      }
    }
    try {
      normalizeRetirement(
        retired,
        request,
        record.requestSha256,
        payload?.asid,
      );
      record.cleanup = { status: "RETIRED", helpersSettled: true };
    } catch {
      /* Unbound or uncertain retirement keeps the possible effects reserved. */
    }
    await save();
    return structuredClone(record);
  }
}
